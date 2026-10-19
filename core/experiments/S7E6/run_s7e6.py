"""S7-E6: Replace(P -> P') time vs the number E of certified epochs of P (protocol v2). Same host, loopback.

Per run: fresh Anvil + contracts + n holder processes + provider A registered with (k, n, q); E * m_e DISCLOSED
bulk-loaded synthetic records (no admission) fill E epochs that close by M_max and are PIR-preprocessed, sealed
(fragment_kzg), certified (q acks) and anchored. The harness keeps a copy of every epoch (GET /epoch/e) for the
correctness check only. Then A is killed (SIGKILL) and its data dir deleted. Replace(A -> A2): a NEW provider A2 (own
key and sid, registered with "continues A", first epoch last_A + 1) starts with an EMPTY data dir under a sandbox
profile denying access to A's destroyed dir, and runs the library's recover_service (unchanged): discovery at one
finalized height, per epoch Certified check + fetch k fragments (recovery_fetch, default 'minimal') + fragment check
(KZG against com_e) + decode, restore of the tag map U, PIR rebuild. Not tested: the provider-not-answering/failover case.

Metric (): FULL recovery time, i.e. until every one of the E certified epochs is restored
and servable by A2 (records at the same (e, j), tags in U, PIR rebuilt => epoch read-ready), with the per-epoch
breakdown of the library's recovery metrics. Time until appends are accepted is NOT measured. After completion the
harness checks servability: one complete private read (library recipient PIR client: public params + hint download,
seed check, client load, query, answer, decode) at (A2, e, j) for the first and the last restored epoch, compared with
A's original record (synthetic record: no decryption / note check), and a byte-for-byte comparison of every restored
epoch (GET /epoch/e) with A's original.
Clock: t0 = just before A2's registration transaction; A2 process start = start_provider call. Recovery start/end
come from the provider's own clock (recovery.started_at / finished_at, time.time on the same host).

Run: benchlock .venv/bin/python -m core.experiments.S7E6.run_s7e6 --epochs 1,2,4,8,16 --reps 3 --m-e 4096
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
import shutil
import time
import traceback

from core.oobsvc.client import Recipient
from core.oobsvc.common import CORE, finish_load, http, metadata, require_real_binaries, wait_quiet
from core.oobsvc.deploy import Testbed
from core.oobsvc.epoch import check_thresholds

KEYS = str(HALO_KEYS)
ADM = {'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}


def epoch_bytes(url, e):
    st, data = http('GET', f'{url}/epoch/{e}', timeout=300)
    return data if st == 200 else None


def pir_read(tb, url, sid2, e, j, want):
    """One complete private read at (A2, e, j) with the library's recipient PIR client."""
    try:
        rc = Recipient(tb.chain, None, None, None, tb.dir / f'check-recipient-{e}', [])
        m = {}
        ta = time.perf_counter()
        c = rc.pir_client({'sid': sid2, 'read_sid': sid2, 'e': e, 'j': j, 'url': url}, 60, m)
        tq = time.perf_counter()
        q, state, _ = c.query(j)
        st, ans = http('POST', f'{url}/pir/answer/{sid2}/{e}', q, 'application/octet-stream', timeout=60)
        rec, _ = c.recover(state, ans) if st == 200 else (None, None)
        t1 = time.perf_counter()
        rc.close()
        m.update(answer_status=st, query_bytes=len(q), answer_bytes=len(ans), setup_s=tq - ta,
                 query_answer_decode_s=t1 - tq, read_s=t1 - ta, e=e, j=j, ok=rec == want)
        return m
    except Exception as exc:
        return {'e': e, 'j': j, 'ok': False, 'error': f'{type(exc).__name__}: {exc}'}


def run_one(E, k, n, q, m_e, rep, args) -> dict:
    tb = Testbed(f'S7E6-E{E}-k{k}n{n}q{q}-m{m_e}-{rep}-{time.strftime("%H%M%S")}', block_time=1, n_holders=n,
                 seal_mode='fragment_kzg')
    out = {'E': E, 'k': k, 'n': n, 'q': q, 'm_e': m_e, 'rep': rep, 'seal_mode': 'fragment_kzg',
           'recovery_fetch': args.fetch, 'testbed': str(tb.dir)}
    try:
        tb.register('A', k=k, q=q)
        A = tb.start_provider('A', M_max=m_e, T_max=10 ** 6, seal_retry_s=5, holder_timeout=args.holder_timeout,
                              admission=ADM)
        sidA = tb.services['A']['sid']
        t1 = time.perf_counter()
        tb.admin('A', '/admin/bulk_load', count=E * m_e, seed=1000 * rep + E)
        for e in range(E):
            tb.wait_state('A', e, ('certified',), timeout=args.cert_timeout)
        out['load_and_certify_s'] = time.perf_counter() - t1
        orig = {e: epoch_bytes(A['url'], e) for e in range(E)}
        assert all(v and len(v) == m_e * 736 for v in orig.values())
        out['anchors_A'] = tb.chain.call('list_anchors', sid='0x' + sidA)
        # ---- failure of A: process killed, storage deleted
        adir = A['cfg']['data_dir']
        tb.kill(A['proc'])
        shutil.rmtree(adir)
        out['A_dir_exists_after_delete'] = os.path.exists(adir)
        out['quiet_before_replace'] = wait_quiet(max_load=args.max_load, timeout=300)
        out['load_before_replace'] = os.getloadavg()
        # ---- Replace(A -> A2)
        t0 = time.perf_counter()
        t0_wall = time.time()
        svc2 = tb.register('A2', continues='A')
        out['register_s'] = time.perf_counter() - t0
        out['register_gas'] = tb.gas.get('register_A2')
        out['start_epoch_A2'] = svc2['start_epoch']
        ts = time.perf_counter()
        ts_wall = time.time()
        R = tb.start_provider('A2', mode='replace', forbidden_paths=[adir], sandbox_deny=[adir], admission=ADM,
                              M_max=m_e, T_max=10 ** 6, seal_retry_s=5, holder_timeout=args.holder_timeout,
                              recovery_fetch=args.fetch)
        out['start_provider_returned_s'] = time.perf_counter() - t0
        sid2 = tb.services['A2']['sid']
        while True:
            s = tb.status('A2')
            if s['recovery'].get('phase') in ('complete', 'read_only_partial', 'failed', 'isolation_violation'):
                break
            if time.perf_counter() - t0 > args.replace_timeout:
                raise TimeoutError('replacement did not finish')
            time.sleep(0.02)
        out['phase_seen_s'] = time.perf_counter() - t0
        rs = s['recovery']
        out['recovery'] = rs
        # the provider's own clock (same host wall clock)
        out['recovery_started_after_t0_s'] = rs.get('started_at', 0) - t0_wall if rs.get('started_at') else None
        out['recovery_finished_after_t0_s'] = rs.get('finished_at', 0) - t0_wall if rs.get('finished_at') else None
        out['process_start_after_t0_s'] = ts - t0
        out['process_start_to_recovery_start_s'] = rs.get('started_at', 0) - ts_wall if rs.get('started_at') else None
        eps = rs.get('epochs') or {}
        comp = {}
        for key in ('certify_check_s', 'fetch_s', 'validate_s', 'decode_s', 'u_restore_s', 'pir_rebuild_s', 'total_s',
                    'fetch_bytes', 'fragment_bytes_valid'):
            comp[key] = sum((v.get(key) or 0) for v in eps.values())
        comp['epochs_ok'] = sum(1 for v in eps.values() if v.get('ok'))
        comp['needed_decode'] = [v.get('needed_decode') for v in eps.values()]
        comp['discovery_and_other_s'] = (rs.get('total_s') or 0) - comp['total_s'] - comp['certify_check_s']
        out['breakdown'] = comp
        st2 = tb.status('A2')
        out['A2_status'] = {x: st2[x] for x in ('appends_enabled', 'records', 'tags', 'e_cur')}
        rng = random.Random(rep)
        out['servable_check'] = [pir_read(tb, R['url'], sid2, e, j, orig[e][j * 736:(j + 1) * 736])
                                 for e in sorted({min(orig), max(orig)}) for j in [rng.randrange(m_e)]]
        out['data_matches'] = all(epoch_bytes(R['url'], e) == orig[e] for e in orig)
    except Exception as exc:
        out['error'] = f'{type(exc).__name__}: {exc}'
        out['trace'] = traceback.format_exc()
    finally:
        tb.close()
        if args.delete_testbed:
            shutil.rmtree(tb.dir, ignore_errors=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--epochs', default='1,2,4,8,16')
    ap.add_argument('--config', default='4,8,6')
    ap.add_argument('--m-e', type=int, default=4096)
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--fetch', default='minimal', help="Replace's recovery_fetch policy (all | minimal)")
    ap.add_argument('--holder-timeout', type=float, default=120)
    ap.add_argument('--cert-timeout', type=float, default=1800)
    ap.add_argument('--replace-timeout', type=float, default=1800)
    ap.add_argument('--max-load', type=float, default=8.0)
    ap.add_argument('--delete-testbed', action='store_true')
    ap.add_argument('--label', default='')
    ap.add_argument('--out', default='')
    args = ap.parse_args()
    k, n, q = (int(x) for x in args.config.split(','))
    check_thresholds(k, n, q)
    require_real_binaries()
    outdir = CORE / 'results/S7E6' / (args.out or time.strftime('%Y%m%d-%H%M%S'))
    outdir.mkdir(parents=True, exist_ok=True)
    raw = {'meta': metadata({'harness': 'S7E6 Replace time vs number of certified epochs', 'epochs': args.epochs,
                             'config': [k, n, q], 'm_e': args.m_e, 'reps': args.reps, 'recovery_fetch': args.fetch,
                             'seal_mode': 'fragment_kzg', 'label': args.label,
                             'records': 'bulk-loaded synthetic records (no admission), disclosed',
                             'same_host': 'all holders/providers are processes on ONE host (one fault domain); loopback'}),
           'results': []}
    raw['meta']['quiet_wait'] = wait_quiet()
    try:
        for E in [int(x) for x in args.epochs.split(',')]:
            for rep in range(args.reps):
                t = time.time()
                la0 = os.getloadavg()
                r = run_one(E, k, n, q, args.m_e, rep, args)
                r['wall_s'] = time.time() - t
                r['load_before'] = la0
                r['load_after'] = os.getloadavg()
                raw['results'].append(r)
                print(f'E={E} rep={rep}', 'ERROR ' + r['error'] if r.get('error') else 'ok',
                      f"full={r.get('recovery_finished_after_t0_s')} reads_ok={[x.get('ok') for x in r.get('servable_check') or []]}",
                      f"rec_total={(r.get('recovery') or {}).get('total_s')} match={r.get('data_matches')}",
                      f"{r['wall_s']:.0f}s load={r['load_after'][0]:.1f}", flush=True)
                (outdir / 's7e6_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    finally:
        finish_load(raw['meta'])
        (outdir / 's7e6_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', outdir / 's7e6_raw.json')


if __name__ == '__main__':
    main()
