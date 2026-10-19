"""OOB provider = one logical service `sid`. HTTP on 127.0.0.1.

Run: python -m core.oobsvc.provider <config.json>

Endpoints (honest clients): POST /append, GET /status, GET /pir/public/<e>, GET /pir/hint/<e>,
POST /pir/answer/<sid_hex>/<e> (raw query body -> raw answer; accepts ONLY sid, e, query).
Admin endpoints (/admin/*, token-protected, never used by honest clients): fault injection, bulk load of
DISCLOSED synthetic background records, forced close (labeled "forced"), recovery retry.
"""
from __future__ import annotations

import json
import os
import queue
import random
import signal
import sqlite3
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from nacl.signing import SigningKey

from . import kzg
from .common import (Chain, FIELD, H, REC_BYTES, b64, canon, d_rec, http, post_json, receipt_message, sign,
                     split_rec, u64, unb64, verify_sig, ack_message, WorkerError)
from .epoch import SEAL_MODES, build_manifest, cert_hash, encode_fragments, manifest_hash, serialize_epoch
from .httpserv import DropConnection, JsonLog, Reply, err, serve
from .workers import Admission, PirServer

SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tags(tag BLOB PRIMARY KEY, e INT NOT NULL, j INT NOT NULL);
CREATE TABLE IF NOT EXISTS records(e INT NOT NULL, j INT NOT NULL, rec BLOB NOT NULL, d_rec BLOB NOT NULL,
  synthetic INT NOT NULL DEFAULT 0, recovered INT NOT NULL DEFAULT 0, PRIMARY KEY(e,j));
CREATE TABLE IF NOT EXISTS receipts(tag BLOB PRIMARY KEY, e INT NOT NULL, j INT NOT NULL, d_rec BLOB NOT NULL,
  sig BLOB NOT NULL, key_version INT NOT NULL, resigned INT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS epochs(e INT PRIMARY KEY, state TEXT NOT NULL, m_e INT NOT NULL DEFAULT 0,
  first_at REAL, closed_at REAL, close_reason TEXT, metrics TEXT NOT NULL DEFAULT '{}',
  manifest TEXT, cert TEXT, anchor_block INT);
CREATE TABLE IF NOT EXISTS openings(e INT NOT NULL, t INT NOT NULL, p INT NOT NULL, proofs BLOB NOT NULL, PRIMARY KEY(e,t,p));
'''
READABLE = ('read_ready', 'sealed', 'certified')


def seed_A(sid: bytes, e: int) -> bytes:
    return H(b'OOB-A', sid, u64(e))


class Provider:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.dir = Path(cfg['data_dir'])
        # mode 'replace' (protocol v2, ): a NEW provider P' (own key, own sid, registered
        # with "continues P") starts with empty storage and runs Replace(P -> P') before enabling appends.
        if cfg.get('mode', 'normal') not in ('normal', 'replace'):
            raise SystemExit(f"unknown provider mode {cfg.get('mode')!r}")
        self.replacement = cfg.get('mode') == 'replace'
        if self.replacement:
            # A replacement starts on a fresh machine: the data dir must be empty (or absent).
            if self.dir.exists() and any(self.dir.iterdir()):
                raise SystemExit(f'replacement data dir not empty: {self.dir}')
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sid = bytes.fromhex(cfg['sid'])
        self.M_max, self.T_max = int(cfg.get('M_max', 4096)), float(cfg.get('T_max', 10.0))
        self.seal_mode = cfg.get('seal_mode', 'fragment_kzg')
        if self.seal_mode not in SEAL_MODES:
            raise SystemExit(f'unknown seal_mode {self.seal_mode!r} (expected one of {SEAL_MODES})')
        if self.seal_mode == 'fragment_kzg':
            kzg.trusted_setup()  # pinned EIP-4844 SRS (sha256 checked at load)
        keyfile = self.dir / 'operator.key'
        if not keyfile.exists():
            if 'operator_sk' not in cfg:
                raise SystemExit("provider key missing (the key registered for this sid)")
            keyfile.write_text(cfg['operator_sk'])
        self.sk = SigningKey(bytes.fromhex(keyfile.read_text().strip()))
        self.vk = bytes(self.sk.verify_key)
        self.db = sqlite3.connect(self.dir / 'provider.sqlite3', check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)
        self.dblock = threading.RLock()
        self.chain = Chain(cfg['rpc'], cfg['addresses'])
        if self._meta('e_cur') is None:
            # first epoch: 0 for a fresh provider; last_P + 1 for a replacement that continues P (registry startEpoch)
            s0 = self.chain.call('service', sid='0x' + self.sid.hex())
            self._set_meta('e_cur', str(int(s0.get('start_epoch') or 0)))
        adm = cfg.get('admission', {})
        self.depth = int(adm.get('depth', 32))
        nver = int(adm.get('verifiers', 1))
        self.verifiers: queue.Queue = queue.Queue()
        self.adm_workers = []
        for _ in range(nver):
            w = Admission('verifier', self.depth, adm.get('variant', 'full'), adm.get('keys'))
            self.adm_workers.append(w)
            self.verifiers.put(w)
        self.tool = Admission('tool', self.depth, adm.get('variant', 'full'), adm.get('keys'))
        self.adm_workers.append(self.tool)
        self.pir: dict[int, PirServer] = {}
        self.faults = dict(cfg.get('faults', {}))
        self.log = JsonLog(self.dir / 'observed.jsonl')
        self.root_cache: set[tuple[str, int]] = set()
        self.wake = threading.Event()
        self.appends_enabled = not self.replacement
        self.recovery_state: dict = {}
        self.pipeline_errors: list[str] = []
        self.stop = False
        self.crash_after_commit = os.environ.get('OOB_TEST_CRASH_AFTER_COMMIT') == '1'

    # ------------------------------------------------------------------ helpers
    def _meta(self, k):
        r = self.db.execute('SELECT v FROM meta WHERE k=?', (k,)).fetchone()
        return r[0] if r else None

    def _set_meta(self, k, v):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (k, str(v)))

    def key_version(self) -> int:
        if getattr(self, '_kv', None) is not None:
            return self._kv
        s = self.chain.call('service', sid='0x' + self.sid.hex())
        if s['op_key'][2:] != self.vk.hex():
            raise RuntimeError('this operator key is not the registered key for sid')
        self._kv = int(s['version'])
        return self._kv

    def epoch_metrics(self, e) -> dict:
        with self.dblock:
            r = self.db.execute('SELECT metrics FROM epochs WHERE e=?', (e,)).fetchone()
        return json.loads(r[0]) if r else {}

    def update_epoch(self, e, **fields):
        m = fields.pop('metrics', None)
        with self.dblock:
            if m:
                cur = self.epoch_metrics(e)
                cur.update(m)
                fields['metrics'] = json.dumps(cur)
            if fields:
                sets = ','.join(f'{k}=?' for k in fields)
                self.db.execute(f'UPDATE epochs SET {sets} WHERE e=?', (*fields.values(), e))

    # ------------------------------------------------------------------ HTTP
    def handle(self, method, path, body, headers):
        t = time.time()
        if path.startswith('/admin/'):
            return self.admin(path, json.loads(body or b'{}'))
        if path == '/status':
            return Reply(200, self.status())
        if path == '/append' and method == 'POST':
            f = self.faults
            if f.get('drop_writes'):
                raise DropConnection()
            if f.get('delay_writes'):
                time.sleep(float(f['delay_writes']))
            if f.get('refuse_writes'):
                self.log.write(ev='append_refused', bytes_in=len(body))
                return err(503, 'write refused by provider policy')
            rep = self.append(json.loads(body))
            self.log.write(ev='append', bytes_in=len(body), status=rep.status, seconds=time.time() - t,
                           outcome=json.loads(rep.body).get('outcome') if rep.ctype == 'application/json' else None)
            return rep
        if path.startswith('/pir/'):
            return self.pir_endpoint(method, path, body)
        if path.startswith('/epoch/') and method == 'GET':
            refused = self._read_faults()
            e = int(path.split('/')[2])
            self.log.write(ev='epoch_download', e=e)
            if refused:
                return refused
            if not self.readable(e):
                return err(409, 'epoch not read-ready')
            data = b''.join(self.epoch_records(e))
            if self.faults.get('malformed_answers'):
                data = bytes(random.getrandbits(8) for _ in range(len(data)))
            self.log.write(ev='epoch_download_sent', e=e, bytes_out=len(data))
            return Reply(200, data)
        if path.startswith('/inclusion/') and method == 'GET':
            if self.faults.get('withhold_openings'):
                return err(404, 'inclusion path withheld (fault)')
            _, _, e, j = path.split('/')
            e, j = int(e), int(j)
            with self.dblock:
                row = self.db.execute('SELECT manifest FROM epochs WHERE e=?', (e,)).fetchone()
            if not row or not row[0]:
                return err(409, 'epoch not sealed')
            from .epoch import inclusion_path, leaf_hash
            recs = self.sealed_records(e)
            man = json.loads(row[0])
            if man.get('mode') != 'whole_epoch':
                return err(404, 'no record root in a fragment_kzg manifest; use /opening')
            if not 0 <= j < len(recs):
                return err(404, 'slot outside sealed epoch')
            return Reply(200, {'path': inclusion_path([leaf_hash(t, r) for t, r in enumerate(recs)], j),
                               'm_e': man['m_e'], 'R_e': man['R_e']})
        if path.startswith('/opening/') and method == 'GET':
            _, _, e, j = path.split('/')
            return self.opening(int(e), int(j))
        return err(404, 'unknown endpoint')

    def opening(self, e, j):
        """I3: KZG slot opening (cells + multi-point proofs) of slot j of sealed epoch e."""
        if self.faults.get('withhold_openings'):
            return err(404, 'opening withheld (fault)')
        with self.dblock:
            row = self.db.execute('SELECT manifest FROM epochs WHERE e=?', (e,)).fetchone()
        if not row or not row[0]:
            return err(409, 'epoch not sealed')
        man = json.loads(row[0])
        if man.get('mode') != 'fragment_kzg':
            return err(404, 'whole_epoch manifest: use /inclusion')
        lay = kzg.layout(man['m_e'], man['k'])
        if not 0 <= j < man['m_e']:
            return err(404, 'slot outside sealed epoch')
        t, _, p, _ = lay.locate(j)
        data = kzg.data_fragments(self.sealed_records(e), man['k'])[t]
        with self.dblock:
            pr = self.db.execute('SELECT proofs FROM openings WHERE e=? AND t=? AND p=?', (e, t, p)).fetchone()
        proofs = [bytes(pr[0])[48 * c:48 * (c + 1)] for c in range(kzg.CELLS_PER_BLOB)] if pr else None
        return Reply(200, {'opening': kzg.slot_opening(data, lay, j, proofs), 'precomputed': bool(pr)})

    def compute_openings(self, e, data, lay):
        """All cell proofs of all data pieces of epoch e, once per epoch (FK20 batches in c-kzg)."""
        t0 = time.perf_counter()
        try:
            rows = [(e, t, p, b''.join(kzg.piece_proofs(f, p))) for t, f in enumerate(data) for p in range(lay.pieces)]
            with self.dblock:
                self.db.execute('BEGIN IMMEDIATE')
                self.db.executemany('INSERT OR REPLACE INTO openings VALUES (?,?,?,?)', rows)
                self.db.execute('COMMIT')
            self.update_epoch(e, metrics={'openings_s': time.perf_counter() - t0, 'openings_pieces': len(rows),
                                          'openings_bytes': sum(len(r[3]) for r in rows)})
        except Exception as exc:
            self.pipeline_errors.append(f'openings e={e}: {type(exc).__name__}: {exc}')

    def _read_faults(self):
        f = self.faults
        if f.get('drop_reads'):
            raise DropConnection()
        if f.get('delay_reads'):
            time.sleep(float(f['delay_reads']))
        if f.get('refuse_reads'):
            return err(503, 'read refused by provider policy')
        return None

    def pir_endpoint(self, method, path, body):
        parts = path.strip('/').split('/')
        refused = self._read_faults()
        if parts[1] in ('public', 'hint') and method == 'GET' and len(parts) == 3:
            e = int(parts[2])
            self.log.write(ev=f'pir_{parts[1]}', e=e)
            if refused:
                return refused
            if not self.readable(e):
                return err(409, 'epoch not read-ready')
            f = self.dir / 'pir' / str(e) / ('public.json' if parts[1] == 'public' else 'hint.bin')
            data = f.read_bytes()
            if self.faults.get('malformed_hint') and parts[1] == 'hint':
                data = bytes(b ^ 0x5A for b in data[:64]) + data[64:]
            self.log.write(ev=f'pir_{parts[1]}_sent', e=e, bytes_out=len(data))
            return Reply(200, data)
        if parts[1] == 'answer' and method == 'POST' and len(parts) == 4:
            sid, e = parts[2], int(parts[3])
            # The provider observes only (sid, e, query bytes, timing); never the index j.
            self.log.write(ev='pir_answer', sid=sid, e=e, query_bytes=len(body))
            if refused:
                return refused
            if sid != self.sid.hex():
                return err(404, 'unknown sid')
            if not self.readable(e) or e not in self.pir:
                return err(409, 'epoch not read-ready')
            ans, secs = self.pir[e].answer(body)
            if self.faults.get('malformed_answers'):
                ans = bytes(random.getrandbits(8) for _ in range(len(ans)))
            self.log.write(ev='pir_answer_sent', e=e, bytes_out=len(ans), answer_seconds=secs)
            return Reply(200, ans)
        return err(404, 'unknown PIR endpoint')

    def readable(self, e):
        with self.dblock:  # shared connection: every access is serialized (E6 found unsynchronized reads -> spurious 409)
            r = self.db.execute('SELECT state FROM epochs WHERE e=?', (e,)).fetchone()
        return bool(r) and r[0] in READABLE and e in self.pir

    def status(self):
        with self.dblock:
            eps = [dict(e=r[0], state=r[1], m_e=r[2], first_at=r[3], closed_at=r[4], close_reason=r[5],
                        metrics=json.loads(r[6]), anchor_block=r[7])
                   for r in self.db.execute('SELECT e,state,m_e,first_at,closed_at,close_reason,metrics,anchor_block FROM epochs ORDER BY e')]
            counts = self.db.execute('SELECT COUNT(*), COALESCE(SUM(synthetic),0) FROM records').fetchone()
            ntags = self.db.execute('SELECT COUNT(*) FROM tags').fetchone()[0]
        return {'sid': self.sid.hex(), 'name': self.cfg.get('name'), 'mode': self.cfg.get('mode', 'normal'),
                'operator_key': self.vk.hex(), 'e_cur': int(self._meta('e_cur')), 'appends_enabled': self.appends_enabled,
                'M_max': self.M_max, 'T_max': self.T_max, 'seal_mode': self.seal_mode,
                'epochs': eps, 'records': counts[0], 'synthetic_records': counts[1],
                'tags': ntags, 'recovery': self.recovery_state, 'pipeline_errors': self.pipeline_errors[-5:],
                'faults': self.faults, 'pid': os.getpid()}

    # ------------------------------------------------------------------ append (section 5)
    def append(self, req) -> Reply:
        if not self.appends_enabled:
            return err(503, 'appends disabled: replacement has not restored every certified epoch', outcome='reject')
        try:
            if set(req) != {'sid', 'h', 'public', 'proof', 'rec'}:
                return err(400, 'append fields', outcome='reject')
            if req['sid'] != self.sid.hex():
                return err(400, 'wrong sid', outcome='reject')
            rec = unb64(req['rec'])
            if len(rec) != REC_BYTES:
                return err(400, 'record must be 736 bytes', outcome='reject')
            pub = req['public']
            if set(pub) != {'root', 'digest', 'tag'}:
                return err(400, 'public input fields', outcome='reject')
            nu, ct = split_rec(rec)
            if pub['tag'] != nu:
                return err(400, 'tag differs from record', outcome='reject')
            if any(int(x, 16) >= FIELD for x in [nu, *ct, pub['root'], pub['digest']]):
                return err(400, 'non-canonical field element', outcome='reject')
            t0 = time.perf_counter()
            if self.tool.digest(ct) != pub['digest']:
                return err(400, 'digest d != PoseidonChain(1003, C)', outcome='reject')
            h = req['h']
            if not self.finalized_root(pub['root'], h):
                return err(400, 'root is not a finalized pool root', outcome='reject')
            t1 = time.perf_counter()
            w = self.verifiers.get()
            try:
                v = w.verify(pub, req['proof'])
            finally:
                self.verifiers.put(w)
            t2 = time.perf_counter()
            if not v.get('valid'):
                return err(400, 'admission proof invalid', outcome='reject')
        except (ValueError, KeyError, TypeError, WorkerError) as exc:
            return err(400, f'malformed append: {exc}', outcome='reject')
        return self.commit(rec, bytes.fromhex(nu), timings=dict(checks_s=t1 - t0, verify_s=t2 - t1,
                                                                verify_worker_s=v.get('verify_seconds')))

    def finalized_root(self, root_hex: str, h) -> bool:
        if type(h) is not int or not self.chain.is_final(h):
            return False
        if (root_hex, h) in self.root_cache:
            return True
        ok = bool(self.chain.call('known_root', root=str(int(root_hex, 16)), height=h))
        if ok:
            self.root_cache.add((root_hex, h))
        return ok

    def commit(self, rec: bytes, tag: bytes, timings: dict) -> Reply:
        dr = d_rec(rec)
        t0 = time.perf_counter()
        kv = self.key_version()
        with self.dblock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row = self.db.execute('SELECT e,j FROM tags WHERE tag=?', (tag,)).fetchone()
                if row:
                    stored = self.db.execute('SELECT rec FROM records WHERE e=? AND j=?', row).fetchone()[0]
                    if bytes(stored) == rec:
                        r = self.db.execute('SELECT e,j,d_rec,sig,key_version FROM receipts WHERE tag=?', (tag,)).fetchone()
                        if r is None:  # record restored by Replace(P -> P'): sign (P', e, j) with THIS provider's key
                            sig = sign(self.sk, receipt_message(self.sid, row[0], row[1], dr))
                            self.db.execute('INSERT INTO receipts VALUES (?,?,?,?,?,?,1)', (tag, row[0], row[1], dr, sig, kv))
                            r = (row[0], row[1], dr, sig, kv)
                        self.db.execute('COMMIT')
                        return Reply(200, self._receipt_json('idempotent', *r, timings))
                    self.db.execute('ROLLBACK')
                    return err(409, 'CONFLICT: tag already admitted with different bytes', outcome='conflict',
                               e=row[0], j=row[1])
                e = int(self._meta('e_cur'))
                er = self.db.execute('SELECT m_e, state FROM epochs WHERE e=?', (e,)).fetchone()
                if er is None:
                    self.db.execute("INSERT INTO epochs(e,state,m_e,first_at) VALUES (?,?,0,?)", (e, 'open', time.time()))
                    j = 0
                else:
                    assert er[1] == 'open'
                    j = er[0]
                sig = sign(self.sk, receipt_message(self.sid, e, j, dr))
                self.db.execute('INSERT INTO tags VALUES (?,?,?)', (tag, e, j))
                self.db.execute('INSERT INTO records(e,j,rec,d_rec) VALUES (?,?,?,?)', (e, j, rec, dr))
                self.db.execute('INSERT INTO receipts(tag,e,j,d_rec,sig,key_version) VALUES (?,?,?,?,?,?)', (tag, e, j, dr, sig, kv))
                self.db.execute('UPDATE epochs SET m_e=? WHERE e=?', (j + 1, e))
                if j + 1 >= self.M_max:
                    self._close_locked(e, 'M_max')
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
        if self.crash_after_commit:  # TEST-ONLY hook (env var): die after commit, before the reply
            os.kill(os.getpid(), signal.SIGKILL)
        timings['persist_s'] = time.perf_counter() - t0
        self.wake.set()
        return Reply(200, self._receipt_json('new', e, j, dr, sig, kv, timings))

    def _receipt_json(self, outcome, e, j, dr, sig, kv, timings):
        return {'outcome': outcome, 'sid': self.sid.hex(), 'e': e, 'j': j, 'd_rec': bytes(dr).hex(),
                'receipt': {'sig': bytes(sig).hex()}, 'timings': timings}

    def _close_locked(self, e, reason):
        self.db.execute("UPDATE epochs SET state='closed', closed_at=?, close_reason=? WHERE e=? AND state='open'",
                        (time.time(), reason, e))
        self._set_meta('e_cur', e + 1)

    # ------------------------------------------------------------------ admin
    def admin(self, path, req):
        if req.get('token') != self.cfg['admin_token']:
            return err(403, 'bad admin token')
        if path == '/admin/fault':
            self.faults = req['faults']
            return Reply(200, {'faults': self.faults})
        if path == '/admin/bulk_load':
            return Reply(200, self.bulk_load(int(req['count']), int(req.get('seed', 0))))
        if path == '/admin/close':  # FORCED close: component/recovery benchmarks only
            with self.dblock:
                e = int(self._meta('e_cur'))
                self.db.execute('BEGIN IMMEDIATE')
                self._close_locked(e, 'forced')
                self.db.execute('COMMIT')
            self.wake.set()
            return Reply(200, {'closed': e, 'label': 'forced'})
        if path == '/admin/retry_recovery':
            from .recovery import recover_service
            threading.Thread(target=recover_service, args=(self,), daemon=True).start()
            return Reply(200, {'started': True})
        return err(404, 'unknown admin endpoint')

    def bulk_load(self, count, seed):
        """DISCLOSED synthetic background records (random canonical field elements); bypass admission.
        Never counted as verified ingestion. Fills the open epoch (closing it at M_max if reached)."""
        rng = random.Random(seed)
        loaded = 0
        t0 = time.perf_counter()
        with self.dblock:
            self.db.execute('BEGIN IMMEDIATE')
            while loaded < count:
                e = int(self._meta('e_cur'))
                er = self.db.execute('SELECT m_e FROM epochs WHERE e=?', (e,)).fetchone()
                if er is None:
                    self.db.execute("INSERT INTO epochs(e,state,m_e,first_at) VALUES (?,?,0,?)", (e, 'open', time.time()))
                    j = 0
                else:
                    j = er[0]
                take = min(count - loaded, self.M_max - j)
                rows, tags = [], []
                for t in range(take):
                    rec = b''.join(rng.randrange(FIELD).to_bytes(32, 'big') for _ in range(23))
                    rows.append((e, j + t, rec, d_rec(rec)))
                    tags.append((rec[:32], e, j + t))
                self.db.executemany('INSERT INTO records(e,j,rec,d_rec,synthetic) VALUES (?,?,?,?,1)', rows)
                self.db.executemany('INSERT INTO tags VALUES (?,?,?)', tags)
                self.db.execute('UPDATE epochs SET m_e=? WHERE e=?', (j + take, e))
                loaded += take
                if j + take >= self.M_max:
                    self._close_locked(e, 'M_max')
            self.db.execute('COMMIT')
        self.wake.set()
        return {'loaded': loaded, 'seconds': time.perf_counter() - t0, 'label': 'synthetic background (bulk-loaded, no admission)'}

    # ------------------------------------------------------------------ pipeline: close -> PIR -> seal -> anchor
    def pipeline(self):
        while not self.stop:
            self.wake.wait(0.02)
            self.wake.clear()
            try:
                with self.dblock:
                    todo = self.db.execute("SELECT e, state FROM epochs WHERE state IN ('closed','read_ready','sealed') ORDER BY e").fetchall()
                for e, state in todo:
                    if state == 'closed':
                        self.preprocess(e)
                # Seal/anchor strictly in epoch order (EpochAnchor enforces e == last_e + 1).
                if todo and self.cfg.get('seal', True):
                    e = min(e for e, _ in todo)
                    with self.dblock:
                        state = self.db.execute('SELECT state FROM epochs WHERE e=?', (e,)).fetchone()[0]
                    if state == 'read_ready':
                        if time.time() >= self.epoch_metrics(e).get('seal_retry_at', 0):
                            self.seal(e)
                    elif state == 'sealed':
                        self.finish_anchor(e)
            except Exception as exc:
                self.pipeline_errors.append(f'{time.time():.3f} {type(exc).__name__}: {exc}')
                traceback.print_exc()
                time.sleep(0.5)

    def closer(self):
        """Epoch-closing rule, T_max branch (M_max closes inline in the append transaction)."""
        while not self.stop:
            time.sleep(0.01)
            try:
                with self.dblock:
                    r = self.db.execute("SELECT e, first_at, m_e FROM epochs WHERE state='open'").fetchone()
                    if r and r[2] > 0 and time.time() - r[1] >= self.T_max:
                        self.db.execute('BEGIN IMMEDIATE')
                        self._close_locked(r[0], 'T_max')
                        self.db.execute('COMMIT')
                        self.wake.set()
            except Exception as exc:
                self.pipeline_errors.append(f'closer {type(exc).__name__}: {exc}')

    def epoch_records(self, e) -> list[bytes]:
        with self.dblock:
            return [bytes(r[0]) for r in self.db.execute('SELECT rec FROM records WHERE e=? ORDER BY j', (e,))]

    def preprocess(self, e, label=None):
        t0 = time.perf_counter()
        recs = self.epoch_records(e)
        d = self.dir / 'pir' / str(e)
        d.mkdir(parents=True, exist_ok=True)
        (d / 'records.bin').write_bytes(b''.join(recs))
        old = self.pir.pop(e, None)
        if old:
            old.close()
        srv = PirServer()
        res = srv.setup(d / 'records.bin', len(recs), seed_A(self.sid, e), d, epoch_id=f'{self.sid.hex()[:16]}-{e}')
        (d / 'records.bin').unlink()  # the PIR worker holds the DB in memory; records stay in SQLite
        self.pir[e] = srv
        dt = time.perf_counter() - t0
        with self.dblock:
            state = self.db.execute('SELECT state FROM epochs WHERE e=?', (e,)).fetchone()[0]
            new = {'closed': 'read_ready', 'recovered': 'certified'}.get(state, state)
            self.update_epoch(e, state=new, metrics={'pir_setup_s': dt, 'pir_worker': res, 'read_ready_at': time.time(),
                                                     'hint_bytes': (d / 'hint.bin').stat().st_size,
                                                     'public_bytes': (d / 'public.json').stat().st_size})

    def sealed_records(self, e) -> list[bytes]:
        recs = self.epoch_records(e)
        drop = self.epoch_metrics(e).get('sealed_without_tags', [])
        return [r for r in recs if r[:32].hex() not in drop]

    def seal(self, e):
        t0 = time.perf_counter()
        if self.faults.get('drop_record_on_seal'):
            # Byzantine-provider fault (A2/I3 test): omit a receipted record from the sealed/certified epoch
            self.update_epoch(e, metrics={'sealed_without_tags': list(self.faults['drop_record_on_seal'])})
        recs = self.sealed_records(e)
        self.key_version()  # P's key must be the registered one
        # Assignment (k, n, q, identities) current at the finalized height; endpoints per identity .
        from .certify import current_assignment, registry_at, resolve_holders
        from .epoch import assignment_of
        fin = self.chain.finalized_height()
        reg = registry_at(self.chain, self.sid.hex(), fin)
        asg = current_assignment(reg)
        holders = resolve_holders(reg, asg)
        k, n, q = asg['k'], asg['n'], asg['q']
        hkeys = [bytes.fromhex(h['key']) for h in holders]
        mode = self.seal_mode
        frags = None
        if self.faults.get('inconsistent_encoding') and mode == 'whole_epoch':
            # Malicious-provider fault: fragment hashes of a NON-codeword (last fragment altered).
            frags = encode_fragments(serialize_epoch(self.sid, e, recs), k, n)
            frags[-1] = bytes([frags[-1][0] ^ 1]) + frags[-1][1:]
        man, frags, aux = build_manifest(self.sk, self.sid, e, recs, assignment_of(asg), mode, frags)
        if self.faults.get('inconsistent_encoding') and mode == 'fragment_kzg':
            # Malicious-provider fault: holder n gets canonical scalars OFF the committed codeword.
            f = frags[-1]
            frags[-1] = f[:32] + ((int.from_bytes(f[32:64], 'big') + 1) % kzg.R).to_bytes(32, 'big') + f[64:]
        hm = manifest_hash(man)
        hdr = canon({'sid': self.sid.hex(), 'e': e, 'manifest': man})
        head = len(hdr).to_bytes(8, 'big') + hdr
        if mode == 'whole_epoch':
            ser = aux['ser']
            bodies = [head + ser] * n  # every holder receives the whole epoch
        else:
            bodies = [head + frags[i] for i in range(n)]  # holder u_i receives only F_i
        t1 = time.perf_counter()
        timeout = float(self.cfg.get('holder_timeout', 60))

        def send(ix):
            ts = time.perf_counter()
            if not holders[ix]['url']:
                return ix, 0, {'error': 'no endpoint record for this holder identity'}, 0.0
            try:
                st, raw = http('POST', holders[ix]['url'] + '/seal', bodies[ix], 'application/octet-stream', timeout=timeout)
                return ix, st, json.loads(raw), time.perf_counter() - ts
            except Exception as exc:
                return ix, 0, {'error': f'{type(exc).__name__}: {exc}'}, time.perf_counter() - ts
        with ThreadPoolExecutor(n) as ex:
            results = list(ex.map(send, range(n)))
        t2 = time.perf_counter()
        acks, failures = [], []
        for ix, st, data, _ in results:
            a = data.get('ack') if st == 200 else None
            if a and a.get('i') == ix + 1 and verify_sig(hkeys[ix], ack_message(hm, ix + 1), bytes.fromhex(a['sig'])):
                acks.append(a)
            else:
                failures.append({'i': ix + 1, 'status': st, 'error': data.get('error', 'invalid ack')})
        m = {'seal_mode': mode, 'k': k, 'n': n, 'q': q, 'gamma': asg['version'], 'seal_height': fin,
             'epoch_record_bytes': len(recs) * REC_BYTES, 'fragment_bytes': len(frags[0]), 'manifest_bytes': len(canon(man)),
             'seal_prepare_s': t1 - t0, 'seal_holders_s': t2 - t1,
             'seal_bytes_per_holder': [len(b) for b in bodies], 'seal_bytes_sent': sum(len(b) for b in bodies),
             'holder_check_s': [d.get('check_seconds') for _, _, d, _ in results],
             'holder_content_check_s': [(d.get('check_parts') or {}).get('content_check_s') for _, _, d, _ in results],
             'holder_seal_rtt_s': [rt for _, _, _, rt in results],
             'seal_failures': failures, 'valid_acks': len(acks),
             'seal_attempts': self.epoch_metrics(e).get('seal_attempts', 0) + 1}
        if len(acks) < q:  # AvailOK requires q distinct valid acks
            m['seal_retry_at'] = time.time() + float(self.cfg.get('seal_retry_s', 5))
            self.update_epoch(e, metrics=m)
            return
        cert = {'h_manifest': hm.hex(), 'acks': sorted(acks, key=lambda a: a['i'])}
        m['cert_formed_at'] = time.time()
        m['cert_send_failures'] = self.send_cert(e, cert, holders)
        m['holder_version'] = asg['version']
        m['certificate_s'] = time.perf_counter() - t2
        self.update_epoch(e, state='sealed', manifest=json.dumps(man), cert=json.dumps(cert), metrics=m)
        if mode == 'fragment_kzg':  # slot openings for sender release, once per epoch, off the anchoring path
            threading.Thread(target=self.compute_openings, args=(e, aux['data'], aux['layout']), daemon=True).start()
        self.finish_anchor(e)

    def send_cert(self, e, cert, holders):
        fails = []
        for ix, h in enumerate(holders):
            if not h['url']:
                fails.append({'i': ix + 1, 'status': 0, 'error': 'no endpoint'})
                continue
            try:
                st, d, _ = post_json(h['url'] + '/cert', {'sid': self.sid.hex(), 'e': e, 'cert': cert}, timeout=30)
                if st != 200:
                    fails.append({'i': ix + 1, 'status': st, 'error': d.get('error')})
            except Exception as exc:
                fails.append({'i': ix + 1, 'status': 0, 'error': str(exc)})
        return fails  # recorded (not silently ignored); the certificate is also on chain in the anchor (A1)

    def finish_anchor(self, e):
        if not self.cfg.get('anchor', True):
            return
        with self.dblock:
            man, cert, ab = self.db.execute('SELECT manifest, cert, anchor_block FROM epochs WHERE e=?', (e,)).fetchone()
        man, cert = json.loads(man), json.loads(cert)
        t0 = time.perf_counter()
        if ab is None:
            existing = self.chain.call('get_anchor', sid='0x' + self.sid.hex(), e=e)
            if existing['block'] == 0:
                tx = self.chain.call('anchor', **{'from': self.cfg['operator_eoa_index']}, sid='0x' + self.sid.hex(), e=e,
                                     manifest='0x' + canon(man).hex(), cert='0x' + canon(cert).hex())
                ab, gas = tx['block'], tx['gas']
                self.update_epoch(e, metrics={'anchor_calldata_bytes': tx['calldata_bytes'], 'anchor_log_bytes': tx['log_data_bytes']})
            else:
                ab, gas = existing['block'], None
            self.update_epoch(e, anchor_block=ab, metrics={'anchor_tx_s': time.perf_counter() - t0, 'anchor_gas': gas})
        wait = self.chain.wait_final(ab)
        now = time.time()
        formed = self.epoch_metrics(e).get('cert_formed_at')
        self.update_epoch(e, state='certified', metrics={'anchor_final_wait_s': wait, 'certified_at': now,
                                                         'cert_to_final_anchor_s': (now - formed) if formed else None})

    # ------------------------------------------------------------------ startup
    def resume(self):
        """After restart: rebuild PIR for readable epochs (deterministic from records + seed_A)."""
        rows = self.db.execute("SELECT e FROM epochs WHERE state IN ('read_ready','sealed','certified')").fetchall()
        for (e,) in rows:
            self.preprocess(e)

    def close(self):
        self.stop = True
        for p in self.pir.values():
            p.close()
        for w in self.adm_workers:
            w.close()
        self.chain.close()


def main():
    cfg = json.loads(Path(sys.argv[1]).read_text())
    p = Provider(cfg)
    if p.replacement:
        from .recovery import recover_service
        threading.Thread(target=recover_service, args=(p,), daemon=True).start()
    else:
        p.resume()
    threading.Thread(target=p.pipeline, daemon=True).start()
    threading.Thread(target=p.closer, daemon=True).start()
    (p.dir / 'READY').write_text(str(cfg['port']))
    serve(cfg['port'], p, cfg.get('name', 'provider'))


if __name__ == '__main__':
    main()
