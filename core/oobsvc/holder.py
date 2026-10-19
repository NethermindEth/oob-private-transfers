"""Recovery holder service (protocol v2).

Accepts a seal request only for a manifest signed by provider P's registered key (one key per provider) that pins the
holder assignment gamma current at the finalized height (k, n, q, identities). Then, by the manifest's seal mode:
- whole_epoch: receives the WHOLE epoch serialization, recomputes R_e, checks canonical records, re-encodes RS(k,n)
  and compares all n fragment hashes; keeps F_i, the m_e leaf hashes (inclusion paths) and M_e;
- fragment_kzg: receives only F_i and checks it against com_e (EC.VerifyFrag); keeps F_i and M_e.
It acknowledges only after the row is durably stored. It serves fragments, manifests and certificates to ANY requester
and slot openings computed from its data fragment . It keeps them indefinitely: there is no retention
expiry.
Run: python -m core.oobsvc.holder <config.json>
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
import time
from pathlib import Path

from nacl.signing import SigningKey

from . import kzg
from .certify import current_assignment, registry_at
from .common import Chain, H, b64, sign, ack_message, REC_BYTES
from .epoch import (RecoveryError, assignment_of, encode_fragments, epoch_root, fragment_check, inclusion_path,
                    leaf_hash, make_ack, manifest_hash, noncanonical_slots, verify_cert, verify_manifest)
from .httpserv import DropConnection, JsonLog, Reply, err, serve


class Holder:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.dir = Path(cfg['data_dir'])
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sk = SigningKey(bytes.fromhex(cfg['sk']))
        self.vk = bytes(self.sk.verify_key)
        self.db = sqlite3.connect(self.dir / 'holder.sqlite3', check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS frags(sid BLOB, e INT, i INT, data BLOB, manifest TEXT, cert TEXT, '
                        'leaves BLOB, mode TEXT, PRIMARY KEY(sid,e))')
        self.lock = threading.Lock()
        self.chain = Chain(cfg['rpc'], cfg['addresses'])
        self.chain_lock = threading.Lock()
        self.faults = dict(cfg.get('faults', {}))
        self.log = JsonLog(self.dir / 'observed.jsonl')
        self.modes = tuple(cfg.get('accept_modes', ('whole_epoch', 'fragment_kzg')))
        t0 = time.perf_counter()
        kzg.trusted_setup()  # pinned EIP-4844 SRS (sha256 checked); loaded once
        self.srs_load_s = time.perf_counter() - t0

    def q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchone()

    def handle(self, method, path, body, headers):
        if self.faults.get('offline') and not path.startswith('/admin'):
            raise DropConnection()
        if path == '/status':
            return Reply(200, self.status())
        if path == '/admin/fault' and method == 'POST':
            req = json.loads(body)
            if req.get('token') != self.cfg['admin_token']:
                return err(403, 'bad admin token')
            self.faults = req['faults']
            return Reply(200, {'faults': self.faults})
        if path == '/seal' and method == 'POST':
            if self.faults.get('silent_s'):  # nonresponder: holds the request longer than the provider's timeout
                time.sleep(float(self.faults['silent_s']))
            return self.seal(body)
        if path == '/cert' and method == 'POST':
            return self.store_cert(json.loads(body))
        if path == '/fetch' and method == 'POST':
            return self.fetch(json.loads(body))
        if path == '/meta' and method == 'POST':
            return self.meta(json.loads(body))
        if path == '/open' and method == 'POST':
            return self.open_slot(json.loads(body))
        if path == '/inclusion' and method == 'POST':
            return self.inclusion(json.loads(body))
        return err(404, 'unknown endpoint')

    def status(self):
        with self.lock:
            n = self.db.execute('SELECT COUNT(*), COALESCE(SUM(LENGTH(data)),0), COALESCE(SUM(LENGTH(leaves)),0), '
                                'COALESCE(SUM(LENGTH(manifest)+COALESCE(LENGTH(cert),0)),0) FROM frags').fetchone()
            rows = self.db.execute('SELECT sid, e, i, LENGTH(data), COALESCE(LENGTH(leaves),0), LENGTH(manifest), '
                                   'COALESCE(LENGTH(cert),0), mode FROM frags ORDER BY sid, e').fetchall()
        return {'name': self.cfg['name'], 'key': self.vk.hex(), 'fragments': n[0], 'fragment_bytes': n[1],
                'leaf_bytes': n[2], 'manifest_cert_bytes': n[3],
                'srs_load_s': self.srs_load_s, 'faults': self.faults,
                'epochs': [{'sid': r[0].hex(), 'e': r[1], 'i': r[2], 'fragment_bytes': r[3], 'leaf_bytes': r[4],
                            'manifest_bytes': r[5], 'cert_bytes': r[6], 'mode': r[7]} for r in rows]}

    # ------------------------------------------------------------------------------------------------ sealing
    def seal(self, body: bytes) -> Reply:
        t0 = time.perf_counter()
        hlen = int.from_bytes(body[:8], 'big')
        hdr = json.loads(body[8:8 + hlen])
        payload = body[8 + hlen:]
        sid, e, man = bytes.fromhex(hdr['sid']), hdr['e'], hdr['manifest']
        # Accept only manifests signed by P's key registered at the finalized height that pin the assignment gamma
        # current there .
        with self.chain_lock:
            fin = self.chain.finalized_height()
            try:
                reg = registry_at(self.chain, sid.hex(), fin)
            except RecoveryError as exc:
                return err(422, f'manifest rejected: {exc}')
            asg = current_assignment(reg)
            p_key = bytes.fromhex(reg['op_key'][2:] if reg['op_key'].startswith('0x') else reg['op_key'])
            anchored = self.chain.call('get_anchor', sid='0x' + sid.hex(), e=e)['block'] != 0
        t_reg = time.perf_counter()
        try:
            verify_manifest(man, sid, e, p_key, assignment_of(asg))
        except RecoveryError as exc:
            return err(422, f'manifest rejected: {exc}')
        if self.vk.hex() not in asg['keys']:
            return err(403, 'this holder is not in the current assignment')
        if man['mode'] not in self.modes:
            return err(422, f"seal mode {man['mode']} not accepted by this holder")
        i = asg['keys'].index(self.vk.hex()) + 1
        k, n = man['k'], man['n']
        t_man = time.perf_counter()
        leaves = None
        if man['mode'] == 'whole_epoch':
            ser = payload
            if ser[:32] != sid or int.from_bytes(ser[32:40], 'big') != e or int.from_bytes(ser[40:48], 'big') != man['m_e']:
                return err(422, 'epoch header mismatch')
            m = man['m_e']
            if len(ser) != 48 + m * REC_BYTES:
                return err(422, 'epoch length mismatch')
            recs = [ser[48 + REC_BYTES * t:48 + REC_BYTES * (t + 1)] for t in range(m)]
            if epoch_root(sid, e, recs).hex() != man['R_e']:
                return err(422, 'R_e mismatch')
            bad = noncanonical_slots(recs)
            if bad:  # A-N2 (whole_epoch mode): never acknowledge an epoch that recovery would have to reject
                return err(422, f'non-canonical record(s) at slot(s) {bad[:8]}')
            frags = encode_fragments(ser, k, n)
            if any(H(f).hex() != man['frag_hashes'][t] for t, f in enumerate(frags)):
                return err(422, 'inconsistent erasure encoding: fragment hashes do not match a valid codeword')
            frag = frags[i - 1]
            leaves = b''.join(leaf_hash(j, r) for j, r in enumerate(recs))  # m_e x 32 B: serves inclusion paths
            del ser, recs, frags
        else:
            ok, why = fragment_check(man, i, payload)  # EC.VerifyFrag against com_e (one MSM per piece)
            if not ok:
                return err(422, f'fragment rejected: {why}')
            frag = payload
        t_check = time.perf_counter() - t0
        hm = manifest_hash(man)
        with self.lock:
            cur = self.db.execute('SELECT manifest FROM frags WHERE sid=? AND e=?', (sid, e)).fetchone()
            superseded = None
            if cur and json.loads(cur[0]) != man:
                old = json.loads(cur[0])
                # Supersede rule: a stored manifest is replaced only while (sid,e) is UNANCHORED
                # and the stored one names an OLDER assignment gamma (P installed a new assignment, e.g. after a
                # failed certification).
                older = type(old.get('gamma')) is int and old['gamma'] < asg['version']
                if anchored or not older:
                    return err(409, 'a different manifest is already stored for (sid,e)')
                self.db.execute('DELETE FROM frags WHERE sid=? AND e=?', (sid, e))
                superseded, cur = {'gamma': old.get('gamma'), 'new_gamma': asg['version']}, None
            if not cur:  # a re-sent identical seal keeps the stored row (and any stored certificate)
                self.db.execute('INSERT INTO frags VALUES (?,?,?,?,?,NULL,?,?)',
                                (sid, e, i, frag, json.dumps(man), leaves, man['mode']))
        ack = make_ack(self.sk, hm, i)
        if self.faults.get('invalid_ack'):
            ack['sig'] = sign(self.sk, ack_message(H(b'wrong'), i)).hex()
        dt = time.perf_counter() - t0
        parts = {'registry_s': t_reg - t0, 'manifest_s': t_man - t_reg, 'content_check_s': t0 + t_check - t_man,
                 'store_s': dt - t_check}
        self.log.write(ev='seal', sid=sid.hex(), e=e, i=i, mode=man['mode'], bytes_received=len(body),
                       stored_fragment_bytes=len(frag), check_seconds=t_check, total_seconds=dt, parts=parts,
                       superseded_gamma=superseded and superseded['gamma'], superseded=superseded)
        return Reply(200, {'ack': ack, 'check_seconds': t_check, 'seconds': dt, 'bytes_received': len(body),
                           'check_parts': parts})

    def store_cert(self, req) -> Reply:
        sid, e, cert = bytes.fromhex(req['sid']), req['e'], req['cert']
        row = self.q('SELECT manifest FROM frags WHERE sid=? AND e=?', (sid, e))
        if not row:
            return err(404, 'no fragment for (sid,e)')
        man = json.loads(row[0])
        try:  # checked against the (verified) stored manifest: q acks at distinct coordinates of its assignment
            verify_cert(cert, man)
        except RecoveryError as exc:
            return err(422, f'certificate rejected: {exc}')
        with self.lock:
            self.db.execute('UPDATE frags SET cert=? WHERE sid=? AND e=?', (json.dumps(cert), sid, e))
        return Reply(200, {'stored': True})

    # ------------------------------------------------------------------------------------------------ serving
    def inclusion(self, req) -> Reply:
        sid, e, j = bytes.fromhex(req['sid']), req['e'], req['j']
        row = self.q('SELECT leaves, manifest FROM frags WHERE sid=? AND e=?', (sid, e))
        if not row or self.faults.get('withhold') or row[0] is None:
            return err(404, 'no epoch (or not a whole_epoch-mode epoch)')
        lv = bytes(row[0])
        leaves = [lv[t:t + 32] for t in range(0, len(lv), 32)]
        if not (type(j) is int and 0 <= j < len(leaves)):
            return err(404, 'slot outside epoch')
        return Reply(200, {'path': inclusion_path(leaves, j), 'm_e': len(leaves), 'R_e': json.loads(row[1])['R_e']})

    def meta(self, req) -> Reply:
        """I8: manifest + certificate of an epoch (discovery source independent of chain event logs)."""
        sid, e = bytes.fromhex(req['sid']), req['e']
        row = self.q('SELECT manifest, cert FROM frags WHERE sid=? AND e=?', (sid, e))
        self.log.write(ev='meta', sid=sid.hex(), e=e, found=bool(row))
        if not row or self.faults.get('withhold'):
            return err(404, 'no epoch')
        return Reply(200, {'manifest': json.loads(row[0]), 'cert': json.loads(row[1]) if row[1] else None})

    def open_slot(self, req) -> Reply:
        """I3: slot opening computed from this holder's data fragment (fragment_kzg mode, data coordinates only)."""
        sid, e, j = bytes.fromhex(req['sid']), req['e'], req['j']
        row = self.q('SELECT i, data, manifest FROM frags WHERE sid=? AND e=?', (sid, e))
        if not row or self.faults.get('withhold'):
            return err(404, 'no epoch')
        i, data, man = row[0], bytes(row[1]), json.loads(row[2])
        if man['mode'] != 'fragment_kzg':
            return err(404, 'not a fragment_kzg epoch')
        lay = kzg.layout(man['m_e'], man['k'])
        if not (type(j) is int and 0 <= j < man['m_e']) or lay.locate(j)[0] != i - 1:
            return err(404, 'slot not in this holder\'s data fragment')
        t0 = time.perf_counter()
        op = kzg.slot_opening(data, lay, j)
        return Reply(200, {'opening': op, 'i': i, 'seconds': time.perf_counter() - t0})

    def fetch(self, req) -> Reply:
        sid, e = bytes.fromhex(req['sid']), req['e']
        row = self.q('SELECT i, data, manifest, cert FROM frags WHERE sid=? AND e=?', (sid, e))
        self.log.write(ev='fetch', sid=sid.hex(), e=e, found=bool(row))
        if not row:
            return err(404, 'no fragment')
        i, data, man, cert = row[0], bytes(row[1]), json.loads(row[2]), json.loads(row[3]) if row[3] else None
        f = self.faults
        if f.get('withhold'):
            return err(404, 'no fragment (withheld)')
        if f.get('corrupt_fragment'):
            data = bytes([data[0] ^ 1]) + data[1:]
        if f.get('off_codeword'):  # canonical scalars, but one of them moved: off the committed codeword
            x = (int.from_bytes(data[32:64], 'big') + 1) % kzg.R
            data = data[:32] + x.to_bytes(32, 'big') + data[64:]
        if f.get('dup_coord'):
            i = int(f['dup_coord'])  # claims another holder's coordinate
        if f.get('wrong_manifest'):
            man = dict(man, m_e=man['m_e'] + 1)  # signature no longer valid
        if f.get('invalid_ack') and cert:
            cert = dict(cert, acks=[dict(a, sig=('00' * 64)) if a['i'] == i else a for a in cert['acks']])
        # 'h' is the holder's own claim about its bytes; readers never rely on it (hash-valid != on the codeword)
        return Reply(200, {'i': i, 'manifest': man, 'cert': cert, 'fragment': b64(data), 'h': H(data).hex()})


def main():
    cfg = json.loads(Path(sys.argv[1]).read_text())
    h = Holder(cfg)
    (Path(cfg['data_dir']) / 'READY').write_text(str(cfg['port']))
    serve(cfg['port'], h, cfg['name'])


if __name__ == '__main__':
    main()
