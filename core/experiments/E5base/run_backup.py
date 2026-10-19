"""E5 baseline (e), MEASURED: direct sender->recipient delivery plus an encrypted,
RS(3,5) erasure-coded backup to five independent blob stores (core/experiments/E5base/store.py), as in
Tahoe-LAFS-style encrypted backup.

Per note: the sender encrypts the same 18-element note message to the recipient's BabyJubjub key with the SAME Rust
worker as OOB (704-B ciphertext; no admission tag, no proof), sends it directly (signed notification carrying the
ciphertext and the backup locator), and uploads the 5 fragments (one per store) under a random 16-byte id in the
current bucket (time window, like an epoch). Buckets are filled to m objects with disclosed synthetic fragments.
Recovery after the recipient's mailbox copy is lost: two stores are stopped; the recipient (i) fetches its object by id
from the other three (NOT private: stores learn which object), or (ii) downloads the whole bucket from three stores
(private in the same sense as OOB's whole-epoch download), decodes, decrypts, and checks the note.
Same host, loopback. Run: benchlock .venv/bin/python -m core.experiments.E5base.run_backup [--trials 50]
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import argparse
import json
import os
import secrets
import shutil
import signal
import statistics as st
import subprocess
import sys
import time
from pathlib import Path

from nacl.signing import SigningKey
from zfec import Decoder, Encoder

from core.oobsvc.common import CORE, FIELD, ROOT, TESTBED, canon, fe_hex, free_port, get_json, http, metadata, sign, \
    verify_sig
from core.oobsvc.workers import Admission

K, N = 3, 5


def encode(c: bytes) -> list[bytes]:
    L = -(-len(c) // K)
    pad = c + bytes(K * L - len(c))
    return Encoder(K, N).encode([pad[i * L:(i + 1) * L] for i in range(K)])


def decode(frags: dict[int, bytes], length: int) -> bytes:
    idx = sorted(frags)[:K]
    return b''.join(Decoder(K, N).decode([frags[i] for i in idx], idx))[:length]


class Stores:
    def __init__(self, base: Path):
        self.base, self.procs, self.urls = base, [], []
        base.mkdir(parents=True, exist_ok=True)
        for i in range(N):
            port = free_port()
            d = base / f'store{i + 1}'
            log = open(base / f'store{i + 1}.log', 'ab')
            p = subprocess.Popen([sys.executable, '-m', 'core.experiments.E5base.store', str(port), str(d)], cwd=ROOT,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                 env=dict(os.environ, PYTHONPATH=str(ROOT)))
            self.procs.append(p)
            self.urls.append(f'http://127.0.0.1:{port}')
        for u in self.urls:
            for _ in range(200):
                try:
                    if get_json(u + '/status', timeout=2)[0] == 200:
                        break
                except Exception:
                    time.sleep(0.05)

    def stop(self, i):
        p = self.procs[i]
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()

    def close(self):
        for i in range(N):
            self.stop(i)


def put(url, bucket, oid, data):
    st_, _ = http('POST', f'{url}/obj/{bucket}/{oid.hex()}', data, 'application/octet-stream', timeout=30)
    assert st_ == 200, st_
    return len(data)


def run_bucket(tool, sk_r, pk_r, m: int, trials: int, base: Path) -> dict:
    stores = Stores(base / f'm{m}')
    notify_sk = SigningKey.generate()
    inbox = base / f'm{m}' / 'inbox'
    inbox.mkdir()
    bucket = f'b{m}'
    res = {'m': m, 'trials': []}
    try:
        # disclosed synthetic background: m - trials objects of the same size in the bucket
        t0 = time.perf_counter()
        for _ in range(max(0, m - trials)):
            oid, frags = secrets.token_bytes(16), encode(secrets.token_bytes(704))
            for i in range(N):
                put(stores.urls[i], bucket, oid, frags[i])
        res['background_fill_s'] = time.perf_counter() - t0
        notes = []
        for t in range(trials):
            msg = [pk_r[0], pk_r[1], fe_hex(10 ** 16), fe_hex(secrets.randbelow(FIELD)), fe_hex(0),
                   fe_hex(secrets.randbelow(FIELD))] + [fe_hex(secrets.randbelow(FIELD)) for _ in range(12)]
            t0 = time.perf_counter()
            enc = tool.encrypt(pk_r, msg)
            c = b''.join(bytes.fromhex(x) for x in enc['ciphertext'])
            t1 = time.perf_counter()
            oid = secrets.token_bytes(16)
            body = {'v': 'direct-backup-v1', 'c': c.hex(), 'bucket': bucket, 'id': oid.hex(), 'len': len(c)}
            raw = json.dumps({'body': body, 'sig': sign(notify_sk, b'direct-backup-v1' + canon(body)).hex()}).encode()
            (inbox / f'{t}.json').write_bytes(raw)  # direct delivery (recipient mailbox)
            t2 = time.perf_counter()
            frags = encode(c)
            up = sum(put(stores.urls[i], bucket, oid, frags[i]) for i in range(N))
            t3 = time.perf_counter()
            notes.append((t, msg, oid, len(c)))
            res['trials'].append({'encrypt_s': t1 - t0, 'direct_s': t2 - t1, 'backup_upload_s': t3 - t2,
                                  'direct_bytes': len(raw), 'ciphertext_bytes': len(c), 'fragment_bytes': up,
                                  'sender_upload_bytes': len(raw) + up})
        stat = [get_json(u + '/status')[1] for u in stores.urls]
        res['store_status'] = stat
        res['store_dir_bytes'] = [sum(f.stat().st_size for f in (base / f'm{m}' / f'store{i + 1}').rglob('*') if f.is_file())
                                  for i in range(N)]
        # ---- recipient mailbox lost; two stores lost
        shutil.rmtree(inbox)
        stores.stop(0)
        stores.stop(1)
        alive = [2, 3, 4]
        rec_id, rec_bucket = [], []
        for t, msg, oid, L in notes:
            # (i) by-id fetch from 3 stores (not private)
            t0 = time.perf_counter()
            fr, nb = {}, 0
            for i in alive:
                s_, b = http('GET', f'{stores.urls[i]}/obj/{bucket}/{oid.hex()}', timeout=30)
                if s_ == 200:
                    fr[i], nb = b, nb + len(b)
            c = decode(fr, L)
            ok = tool.decrypt(sk_r, [c[i:i + 32].hex() for i in range(0, L, 32)]) == msg
            rec_id.append({'s': time.perf_counter() - t0, 'bytes': nb, 'ok': ok})
        # (ii) whole-bucket fetch from 3 stores (private w.r.t. which object), once per bucket, then decode own object
        t, msg, oid, L = notes[0]
        t0 = time.perf_counter()
        blobs, nb = {}, 0
        for i in alive:
            s_, b = http('GET', f'{stores.urls[i]}/bucket/{bucket}', timeout=300)
            nb += len(b)
            p = 0
            while p < len(b):
                o, ln = b[p:p + 16], int.from_bytes(b[p + 16:p + 20], 'big')
                if o == oid:
                    blobs[i] = b[p + 20:p + 20 + ln]
                p += 20 + ln
        c = decode(blobs, L)
        ok = tool.decrypt(sk_r, [c[i:i + 32].hex() for i in range(0, L, 32)]) == msg
        rec_bucket.append({'s': time.perf_counter() - t0, 'bytes': nb, 'ok': ok})
        res['recovery_by_id'] = rec_id
        res['recovery_whole_bucket'] = rec_bucket
    finally:
        stores.close()
    tr = res['trials']
    med = lambda k: st.median(x[k] for x in tr)
    res['summary'] = {
        'sender_upload_bytes': med('sender_upload_bytes'), 'direct_bytes': med('direct_bytes'),
        'fragment_bytes': med('fragment_bytes'), 'ciphertext_bytes': med('ciphertext_bytes'),
        'sender_time_s': st.median(x['encrypt_s'] + x['direct_s'] + x['backup_upload_s'] for x in tr),
        'store_bytes_per_object_all_stores': sum(s['bytes'] for s in res['store_status']) / res['store_status'][0]['objects'],
        'store_disk_bytes_per_object_all_stores': sum(res['store_dir_bytes']) / res['store_status'][0]['objects'],
        'recovery_by_id_s': st.median(x['s'] for x in rec_id), 'recovery_by_id_bytes': st.median(x['bytes'] for x in rec_id),
        'recovery_by_id_ok': sum(x['ok'] for x in rec_id), 'recovery_whole_bucket_s': rec_bucket[0]['s'],
        'recovery_whole_bucket_bytes': rec_bucket[0]['bytes'], 'recovery_whole_bucket_ok': rec_bucket[0]['ok'],
        'trials': len(tr)}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--trials', type=int, default=50)
    ap.add_argument('--sizes', default='16,4096')
    a = ap.parse_args()
    ts = time.strftime('%Y%m%d-%H%M%S')
    out = CORE / 'results/E5base' / f'backup-{ts}'
    out.mkdir(parents=True)
    base = TESTBED / f'E5backup-{ts}'
    base.mkdir(parents=True)
    tool = Admission('tool', 32)
    sk_r, pk_r = tool.keypair()
    raw = {'meta': metadata({'trials': a.trials, 'sizes': a.sizes, 'k': K, 'n': N,
                             'baseline': 'direct delivery + encrypted RS(3,5) backup to 5 independent blob stores (measured)',
                             'background': 'disclosed synthetic 704-B objects fill each bucket to m'}), 'buckets': []}
    try:
        for m in map(int, a.sizes.split(',')):
            r = run_bucket(tool, sk_r, pk_r, m, min(a.trials, m), base)
            raw['buckets'].append(r)
            print(m, json.dumps(r['summary']), flush=True)
    finally:
        tool.close()
        (out / 'backup_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', out / 'backup_raw.json')


if __name__ == '__main__':
    main()
