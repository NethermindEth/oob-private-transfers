"""E7: holder-configuration sweep over (k, n, q) x seal mode x epoch size (sealing, certification, storage, recovery).

For each configuration: fresh Anvil + contracts + n holder processes + provider A registered with assignment (k, n, q);
one epoch of m_e DISCLOSED synthetic records (bulk load, no admission: sealing cost does not depend on admission) is
closed by M_max, PIR-preprocessed, sealed (seal mode), certified (q acks) and anchored. Recorded per run:
  sealing   : bytes sent per holder and in total, fragment and manifest bytes, per-holder check time (holder-reported,
              total and content-check part), provider prepare time (encode + commit), holder round trip, certificate
              time, slot-opening precomputation time (fragment_kzg)
  anchoring : anchor gas, calldata bytes, event-log bytes, anchor tx time, finality wait, certificate-formed ->
              final-anchor time
  storage   : per-holder stored bytes (fragment, leaf hashes, manifest, certificate; from the holder's /status) and
              data-dir bytes
  release   : sender slot check (Certified + opening/inclusion path) time and proof bytes for three slots
  recovery  : open reconstruction by a node holding NO fragment (this harness process): time and fetched bytes, with
              fetch policy 'all' (ask all n holders) and 'minimal' (ask k, data coordinates first)
  replace   : (optional, --replace) Replace(A -> A2) wall time and per-stage recovery metrics
Everything runs on ONE host (all holders are processes on the same machine: one fault domain, loopback network).
Numbers of different configurations are separate runs; nothing is extrapolated.

Run: benchlock .venv/bin/python -m core.experiments.E7.run_e7
     --configs 3,5,5:4,8,6:8,16,12:16,32,24 --modes fragment_kzg,whole_epoch --m-e 4096 --reps 3 [--replace]
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse
import json
import os
import shutil
import time
import traceback

from core.oobsvc.common import CORE, RSSSampler, finish_load, get_json, http, metadata, require_real_binaries, wait_quiet
from core.oobsvc.client import Sender
from core.oobsvc.deploy import Testbed
from core.oobsvc.epoch import check_thresholds
from core.oobsvc.recovery import recipient_recover

KEYS = str(HALO_KEYS)
ADM = {'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}


def dir_bytes(p):
    return sum(f.stat().st_size for f in Path(p).rglob('*') if f.is_file()) if Path(p).exists() else 0


def records(tb, name, e):
    st, data = http('GET', f"{tb.providers[name]['url']}/epoch/{e}", timeout=120)
    assert st == 200, st
    return [data[i * 736:(i + 1) * 736] for i in range(len(data) // 736)]


def run_one(k, n, q, mode, m_e, rep, args) -> dict:
    tb = Testbed(f'E7-k{k}n{n}q{q}-{mode[:5]}-m{m_e}-{rep}-{time.strftime("%H%M%S")}', block_time=1, n_holders=n,
                 seal_mode=mode)
    out = {'k': k, 'n': n, 'q': q, 'f_r': q - k, 'f_w': n - q, 'seal_mode': mode, 'm_e': m_e, 'rep': rep,
           'testbed': str(tb.dir), 'gas': {}}
    try:
        t0 = time.perf_counter()
        tb.register('A', k=k, q=q)
        A = tb.start_provider('A', M_max=m_e, T_max=10 ** 6, seal_retry_s=5, holder_timeout=args.holder_timeout,
                              admission=ADM)
        out['setup_s'] = time.perf_counter() - t0
        # peak RSS (process + children, i.e. incl. each process's Node chain worker / Rust / Go workers), sampled 20/s
        rss = RSSSampler({f"holder{i + 1}": tb.procs[tb.holders[i]['name']].pid for i in tb.holder_sets['A']}
                         | {'provider': tb.procs[A['proc']].pid})
        rss.start()
        sid = tb.services['A']['sid']
        e = tb.status('A')['e_cur']
        tb.admin('A', '/admin/bulk_load', count=m_e, seed=rep)
        t1 = time.perf_counter()
        _, ep = tb.wait_state('A', e, ('certified',), timeout=args.cert_timeout)
        out['close_to_certified_s'] = time.perf_counter() - t1
        m = ep['metrics']
        if mode == 'fragment_kzg':  # openings are computed off the anchoring path; wait for them (recorded)
            t2 = time.time()
            while 'openings_s' not in m and time.time() - t2 < 600:
                time.sleep(0.2)
                m = {x['e']: x for x in tb.status('A')['epochs']}[e]['metrics']
        out['epoch_metrics'] = m
        peak = rss.stop()
        hp = [v for k_, v in peak.items() if k_.startswith('holder')]
        out['peak_rss_bytes'] = {'provider_tree': peak.get('provider'), 'holder_tree_max': max(hp) if hp else None,
                                 'holder_tree_mean': sum(hp) / len(hp) if hp else None, 'per_process': peak,
                                 'window': 'provider start -> openings done'}
        keys = ('seal_bytes_per_holder', 'seal_bytes_sent', 'epoch_record_bytes', 'fragment_bytes', 'manifest_bytes',
                'holder_check_s', 'holder_content_check_s', 'holder_seal_rtt_s', 'seal_prepare_s', 'seal_holders_s',
                'certificate_s', 'valid_acks', 'seal_attempts', 'anchor_gas', 'anchor_calldata_bytes', 'anchor_log_bytes',
                'anchor_tx_s', 'anchor_final_wait_s', 'cert_to_final_anchor_s', 'openings_s', 'openings_bytes',
                'pir_setup_s')
        out['seal'] = {x: m.get(x) for x in keys}
        out['gas'] = dict(tb.gas)
        hs = []
        for h in tb.holder_list('A'):
            try:
                s = get_json(h['url'] + '/status', timeout=10)[1]
                row = [x for x in s['epochs'] if x['sid'] == sid and x['e'] == e]
                hs.append({'i': h['i'], 'stored': row[0] if row else None, 'srs_load_s': s.get('srs_load_s')})
            except Exception as exc:
                hs.append({'i': h['i'], 'error': str(exc)})
        out['holder_storage'] = hs
        out['holder_dir_bytes'] = [dir_bytes(tb.holders[i]['data_dir']) for i in tb.holder_sets['A']]
        out['provider_dir_bytes'] = dir_bytes(A['cfg']['data_dir'])
        # ---- sender release check (Certified + slot opening / inclusion path) for three slots
        recs = records(tb, 'A', e)
        snd = Sender(tb.chain, None, 0, tb.dir / 'sender')
        rel = []
        for j in sorted({0, m_e // 2, m_e - 1}):
            en = {'name': 'A', 'sid': sid, 'url': A['url'], 'e': e, 'j': j}
            ta = time.perf_counter()
            r = snd.check_durable(en, recs[j])
            dt = time.perf_counter() - ta
            path = (f"/opening/{e}/{j}" if mode == 'fragment_kzg' else f"/inclusion/{e}/{j}")
            st, body = http('GET', A['url'] + path, timeout=60)
            rel.append({'j': j, 'durable': r['durable'], 'via': r.get('via'), 'check_s': dt, 'proof_response_bytes': len(body)})
        out['release'] = rel
        # ---- open reconstruction by a fragment-less node (this process)
        out['recover'] = {}
        for pol in args.policies.split(','):
            ta = time.perf_counter()
            got, rm = recipient_recover(tb.chain, sid, e, policy=pol, timeout=args.holder_timeout)
            out['recover'][pol] = {'ok': got == recs, 'wall_s': time.perf_counter() - ta,
                                   **{x: rm.get(x) for x in ('fetch_s', 'fetch_bytes', 'validate_s', 'decode_s', 'certify_check_s',
                                                             'coordinates_asked', 'valid_fragments', 'needed_decode',
                                                             'fragment_bytes_valid', 'anchor_bytes', 'reason')}}
        # ---- optional Replace(A -> A2)
        if args.replace:
            adir = A['cfg']['data_dir']
            tb.kill(A['proc'])
            shutil.rmtree(adir)
            ta = time.perf_counter()
            tb.register('A2', continues='A')
            tb.start_provider('A2', mode='replace', forbidden_paths=[adir], admission=ADM, M_max=m_e, T_max=10 ** 6,
                              holder_timeout=args.holder_timeout)
            while tb.status('A2')['recovery'].get('phase') not in ('complete', 'read_only_partial', 'failed', 'isolation_violation'):
                time.sleep(0.05)
            rs = tb.status('A2')['recovery']
            out['replace'] = {'wall_s': time.perf_counter() - ta, 'phase': rs.get('phase'), 'total_s': rs.get('total_s'),
                              'epochs': rs.get('epochs'), 'register_gas': tb.gas.get('register_A2')}
    except Exception as exc:
        out['error'] = f'{type(exc).__name__}: {exc}'
        out['trace'] = traceback.format_exc()
    finally:
        tb.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--configs', default='3,5,5:4,8,6:8,16,12:16,32,24', help='k,n,q separated by ":"')
    ap.add_argument('--modes', default='fragment_kzg,whole_epoch')
    ap.add_argument('--m-e', default='4096', help='comma-separated epoch sizes')
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--policies', default='all,minimal')
    ap.add_argument('--replace', action='store_true')
    ap.add_argument('--holder-timeout', type=float, default=120)
    ap.add_argument('--cert-timeout', type=float, default=1800)
    ap.add_argument('--label', default='')
    args = ap.parse_args()
    configs = [tuple(int(x) for x in c.split(',')) for c in args.configs.split(':')]
    for c in configs:
        check_thresholds(*c)
    require_real_binaries()
    ts = time.strftime('%Y%m%d-%H%M%S')
    outdir = CORE / 'results/E7' / ts
    outdir.mkdir(parents=True)
    quiet = wait_quiet()
    raw = {'meta': metadata({'configs': configs, 'modes': args.modes, 'm_e': args.m_e, 'reps': args.reps,
                             'policies': args.policies, 'replace': args.replace, 'label': args.label,
                             'records': 'bulk-loaded synthetic records (no admission), disclosed',
                             'same_host': 'all holders/providers are processes on ONE host (one fault domain); loopback'}),
           'results': []}
    raw['meta']['quiet_wait'] = quiet
    try:
        for (k, n, q) in configs:
            for mode in args.modes.split(','):
                for m_e in [int(x) for x in args.m_e.split(',')]:
                    for rep in range(args.reps):
                        t0 = time.time()
                        r = run_one(k, n, q, mode, m_e, rep, args)
                        r['wall_s'] = time.time() - t0
                        r['load_after'] = os.getloadavg()
                        raw['results'].append(r)
                        s = r.get('seal') or {}
                        print(f"k={k} n={n} q={q} {mode} m_e={m_e} rep={rep}", 'ERROR ' + r['error'] if r.get('error') else 'ok',
                              f"seal_bytes={s.get('seal_bytes_sent')} gas={s.get('anchor_gas')} {r['wall_s']:.0f}s", flush=True)
                        (outdir / 'e7_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    finally:
        finish_load(raw['meta'])
        (outdir / 'e7_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', outdir / 'e7_raw.json')


if __name__ == '__main__':
    main()
