"""E6: bounded capacity (concurrency 1, 8, 32) and storage accounting. Same-host loopback (12-core laptop).

Read throughput: SimplePIR answers on a read-ready 2^12 epoch (disclosed bulk background), K concurrent clients,
each with its own Go client worker; every decoded record is checked against the epoch bytes (fetched once).
Append throughput: verification-limited; proofs PRE-GENERATED (real Halo2 P1), verification real. Two paths:
  new    - distinct genuine notes (insert path),
  replay - identical re-submissions of those notes (same verification; idempotent lookup path) - labeled.
Client proving throughput: reported separately (1 and 4 concurrent prover workers).
Anchor gas and in-band calldata break-even (A10) from devnet receipts. Storage: per-record accounting.
Run: benchlock .venv/bin/python -m core.experiments.E6.run_e6
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse
import json
import os
import random
import statistics
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from core.oobsvc.common import (CORE, REC_BYTES, b64, canon, d_rec, finish_load, get_json, http, metadata, post_json,
                                require_real_binaries, wait_quiet)
from core.oobsvc.client import Sender, make_address
from core.oobsvc.deploy import ACCT_SENDER, Testbed
from core.oobsvc.workers import Admission, PirClient

KEYS = str(HALO_KEYS)


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else None


def summarize(lat):
    return {'n': len(lat), 'median_s': statistics.median(lat) if lat else None, 'p90_s': pct(lat, 90),
            'min_s': min(lat) if lat else None, 'max_s': max(lat) if lat else None}


def read_load(tb, url, sid, e, recs, K, duration, cache):
    d = cache / f'k{K}'
    d.mkdir(parents=True, exist_ok=True)
    st, pub = http('GET', f'{url}/pir/public/{e}')
    st, hint = http('GET', f'{url}/pir/hint/{e}', timeout=120)
    (d / 'public.json').write_bytes(pub)
    (d / 'hint.bin').write_bytes(hint)
    clients = []
    for _ in range(K):
        c = PirClient()
        c.load(d / 'public.json', d / 'hint.bin')
        clients.append(c)
    lat, fails, wrong = [], [], 0
    lock = threading.Lock()
    stop = time.perf_counter() + duration

    def worker(c):
        nonlocal wrong
        rng = random.Random()
        while time.perf_counter() < stop:
            j = rng.randrange(len(recs))
            t0 = time.perf_counter()
            try:
                q, sid_state, _ = c.query(j)
                code, ans = http('POST', f'{url}/pir/answer/{sid}/{e}', q, 'application/octet-stream', timeout=30)
                if code != 200:
                    raise RuntimeError(f'status {code}')
                rec, _ = c.recover(sid_state, ans)
                ok = rec == recs[j]
            except Exception as exc:
                with lock:
                    fails.append(str(exc))
                continue
            dt = time.perf_counter() - t0
            with lock:
                lat.append(dt)
                if not ok:
                    wrong += 1
    t0 = time.perf_counter()
    ths = [threading.Thread(target=worker, args=(c,)) for c in clients]
    [t.start() for t in ths]
    [t.join() for t in ths]
    wall = time.perf_counter() - t0
    for c in clients:
        c.close()
    return {'K': K, 'duration_s': wall, 'reads': len(lat), 'throughput_rps': len(lat) / wall, 'latency': summarize(lat),
            'latencies_s': lat, 'failures': len(fails), 'failure_samples': fails[:5], 'wrong_records': wrong,
            'query_bytes': None, 'hint_bytes': len(hint)}


def append_load(url, bodies, K):
    lat, outs = [], []
    lock = threading.Lock()

    def one(b):
        t0 = time.perf_counter()
        try:
            st, d, _ = post_json(url + '/append', b, timeout=300)
            o = d.get('outcome') if st == 200 else f'HTTP{st}:{d.get("error")}'
        except Exception as exc:
            o = f'EXC:{exc}'
        with lock:
            lat.append(time.perf_counter() - t0)
            outs.append(o)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(K) as ex:
        list(ex.map(one, bodies))
    wall = time.perf_counter() - t0
    return {'K': K, 'requests': len(bodies), 'wall_s': wall, 'throughput_rps': len(bodies) / wall, 'latency': summarize(lat),
            'latencies_s': lat, 'outcomes': {o: outs.count(o) for o in set(outs)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--notes', type=int, default=72)
    ap.add_argument('--read-seconds', type=float, default=20)
    ap.add_argument('--verifiers', type=int, default=8)
    args = ap.parse_args()
    require_real_binaries()
    ts = time.strftime('%Y%m%d-%H%M%S')
    outdir = CORE / 'results/E6' / ts
    outdir.mkdir(parents=True)
    quiet = wait_quiet()
    raw = {'meta': metadata({'notes': args.notes, 'read_seconds': args.read_seconds, 'verifier_workers': args.verifiers,
                             'epoch_records': 4096, 'concurrency': [1, 8, 32]})}
    raw['meta']['quiet_wait'] = quiet
    tb = Testbed(f'E6-{ts}', block_time=1)
    prover = Admission('prover', 32, 'full', KEYS)
    prover.info()
    tool = Admission('tool', 32)
    try:
        tb.register('A')
        A = tb.start_provider('A', T_max=5, admission={'depth': 32, 'variant': 'full', 'verifiers': args.verifiers, 'keys': KEYS})
        sid = tb.services['A']['sid']
        snd = Sender(tb.chain, prover, ACCT_SENDER, tb.dir / 'sender-retained')
        # ---------- client proving (sequential single worker) + notes for append load
        preps, prove_s = [], []
        for _ in range(args.notes):
            sk, pk = tool.keypair()
            addr = make_address(tb.chain, str(random.randrange(1, 2 ** 200)), pk)
            old, tx = snd.deposit_note()
            tb.chain.wait_final(tx['block'])
            t = snd.transfer(old, addr)
            tb.chain.wait_final(t['tx']['block'])
            t0 = time.perf_counter()
            preps.append(snd.prepare(t['message'], t['cm'], pk, addr.ob))
            prove_s.append(time.perf_counter() - t0)
        raw['proving_1_worker'] = {'proofs': len(prove_s), 'per_proof_s': summarize(prove_s), 'samples': prove_s,
                                   'throughput_proofs_per_s': len(prove_s) / sum(prove_s)}
        # parallel proving: 4 concurrent prover workers, one proof each (re-proving the same statements)
        workers = [Admission('prover', 32, 'full', KEYS) for _ in range(4)]
        for w in workers:
            w.info()
        # re-prove statement i with worker i (same statement, fresh proof randomness): measures client proving capacity
        def timed(i):
            t = time.perf_counter()
            workers[i].prove(preps[i]['public'], preps[i]['witness'])
            return time.perf_counter() - t
        t0 = time.perf_counter()
        with ThreadPoolExecutor(4) as ex:
            per = list(ex.map(timed, range(4)))
        wall = time.perf_counter() - t0
        raw['proving_4_workers'] = {'per_proof_s': per, 'wall_s': wall, 'throughput_proofs_per_s': 4 / wall}
        for w in workers:
            w.close()
        bodies = [{'sid': sid, 'h': p['h'], 'public': p['public'], 'proof': p['proof'], 'rec': b64(p['rec'])} for p in preps]
        # ---------- append throughput: new (insert) path, then replay (idempotent lookup) path
        # distinct genuine notes: 8 at c=1, then half of the rest at c=8 and half at c=32 (insert path at c=32 needs >=32)
        n8 = (len(bodies) - 8) // 2
        raw['append_new'] = [append_load(A['url'], bodies[:8], 1), append_load(A['url'], bodies[8:8 + n8], 8)]
        if len(bodies) - 8 - n8 >= 32:
            raw['append_new'].append(append_load(A['url'], bodies[8 + n8:], 32))
        raw['append_replay'] = [append_load(A['url'], bodies * reps, K) for K, reps in ((1, 1), (8, 2), (32, 4))]
        raw['append_note'] = ('verification is real for every request; "replay" requests are identical re-submissions '
                              '(idempotent outcome, no allocation) used to load verification with pre-generated proofs')
        # ---------- read throughput on a read-ready 2^12 epoch
        tb.admin('A', '/admin/bulk_load', count=4096, seed=6)
        st = tb.status('A')
        e = max(x['e'] for x in st['epochs'] if x['m_e'] == 4096)
        tb.wait_state('A', e, ('read_ready', 'sealed', 'certified'), timeout=300)
        code, data = http('GET', f"{A['url']}/epoch/{e}", timeout=120)
        recs = [data[i * REC_BYTES:(i + 1) * REC_BYTES] for i in range(len(data) // REC_BYTES)]
        raw['read_epoch'] = {'e': e, 'm_e': len(recs)}
        raw['read'] = [read_load(tb, A['url'], sid, e, recs, K, args.read_seconds, tb.dir / 'readers') for K in (1, 8, 32)]
        for r in raw['read']:
            r['latencies_s'] = r['latencies_s'][:5000]
        # ---------- anchor gas and in-band break-even (A10)
        tb.wait_state('A', e, ('certified',), timeout=300)
        st = tb.status('A')
        raw['anchor'] = [{'e': x['e'], 'm_e': x['m_e'], 'gas': x['metrics'].get('anchor_gas'),
                          'calldata_bytes': x['metrics'].get('anchor_calldata_bytes')} for x in st['epochs'] if x['metrics'].get('anchor_gas')]
        # in-band 736-B payload vs OOB (same spend proof, snapshot/revert)
        sk, pk = tool.keypair()
        addr = make_address(tb.chain, '777', pk)
        old, tx = snd.deposit_note()
        tb.chain.wait_final(tx['block'])
        h = tb.chain.finalized_height()
        path = tb.chain.call('path', cm=old.cm, height=h)
        m = snd.build_message(addr)
        ph = prover.payload_hash(m)
        cm = prover.commitment(m[5], m[3], ph)
        from core.oobsvc.client import dec
        nf = tb.chain.call('hash', values=[old.secret, old.seed])
        inputs = dict(root=path['root'], nullifier=nf, newCommitment=dec(cm), withdrawTo='0', secret=old.secret, pkHash=old.pk_hash,
                      seed=old.seed, payloadHash=old.payload_hash, newOwner=dec(m[5]), newSeed=dec(m[3]), newPayloadHash=dec(ph),
                      siblings=path['siblings'], directions=path['directions'])
        proof = tb.chain.call('prove', input=inputs)
        snap = tb.chain.call('rpc', method='evm_snapshot')
        inband = tb.chain.call('transact', args=proof['args'], payload='0x' + preps[0]['rec'].hex(), **{'from': ACCT_SENDER})
        tb.chain.call('rpc', method='evm_revert', params=[snap])
        oob = tb.chain.call('transact', args=proof['args'], **{'from': ACCT_SENDER})
        delta = int(inband['gas']) - int(oob['gas'])
        ag = [int(a['gas']) for a in raw['anchor']]
        raw['inband'] = {'transact_with_736B_payload_gas': int(inband['gas']), 'transact_oob_gas': int(oob['gas']),
                         'delta_gas_per_record': delta, 'anchor_gas_median': statistics.median(ag) if ag else None,
                         'break_even_records_per_epoch': (statistics.median(ag) / delta) if ag and delta > 0 else None,
                         'note': 'devnet (Cancun) receipts; one anchor per epoch vs 736 B calldata+event per in-band record'}
        # ---------- storage accounting
        d = Path(A['cfg']['data_dir'])
        files = {str(f.relative_to(d)): f.stat().st_size for f in d.rglob('*') if f.is_file()}
        st = tb.status('A')
        hs = [get_json(h['url'] + '/status')[1] for h in tb.holders]
        raw['storage'] = {'provider_files': files, 'provider_records': st['records'], 'provider_tags': st['tags'],
                          'epochs': [{'e': x['e'], 'm_e': x['m_e'], 'hint_bytes': x['metrics'].get('hint_bytes'),
                                      'public_bytes': x['metrics'].get('public_bytes'),
                                      'pir_worker': (x['metrics'].get('pir_worker') or {}).get('preprocessing', {}),
                                      'seal_bytes_sent': x['metrics'].get('seal_bytes_sent')} for x in st['epochs']],
                          'holders': hs}
        import sqlite3
        c = sqlite3.connect(f'file:{d}/provider.sqlite3?mode=ro', uri=True)
        raw['storage']['sqlite_dbstat'] = None
        try:
            raw['storage']['sqlite_dbstat'] = {r[0]: r[1] for r in c.execute('SELECT name, SUM(pgsize) FROM dbstat GROUP BY name')}
        except Exception as exc:
            raw['storage']['sqlite_dbstat_error'] = str(exc)
        raw['storage']['page_count'] = c.execute('PRAGMA page_count').fetchone()[0] * c.execute('PRAGMA page_size').fetchone()[0]
        c.close()
    except Exception as exc:
        raw['error'] = f'{type(exc).__name__}: {exc}'
        raw['trace'] = traceback.format_exc()
        print(raw['trace'])
    finally:
        prover.close()
        tool.close()
        tb.close()
        finish_load(raw['meta'])
        raw['meta']['self_induced_load'] = ('the c=32 phase runs 32 client worker processes + 8 verifiers on this 12-core host; '
                                            'end load is produced by the experiment itself (start load was gated <= 8)')
        (outdir / 'e6_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', outdir / 'e6_raw.json')


if __name__ == '__main__':
    main()
