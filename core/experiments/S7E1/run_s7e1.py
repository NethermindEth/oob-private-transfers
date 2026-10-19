"""S7-E1: fragment size, sealing and reconstruction vs (k, n, q) -- thin wrapper around the E7 harness.

Calls core.experiments.E7.run_e7.run_one unchanged (fresh Anvil + contracts + n holder processes + provider A with
assignment (k, n, q); one epoch of m_e DISCLOSED bulk-loaded synthetic records, 736 B each; seal, certify, anchor,
openings, release check, open reconstruction by a fragment-less node) and writes raw JSON to core/results/S7E1/<ts>/.

The only addition is one extra recovery policy, injected by wrapping the module-level `recipient_recover` that run_one
calls (no shared code is edited):
  minimal_parity : ask exactly k holders, taking the LAST k coordinates first (as many parity fragments as possible),
                   so the reader must really erasure-decode (with 'minimal' all k fragments are the systematic data
                   fragments 1..k and decoding is a copy).
Policies 'all' and 'minimal' are the library's own.

Run: benchlock .venv/bin/python -m core.experiments.S7E1.run_s7e1 --configs 4,8,6:4,16,10 --m-e 4096 --reps 3
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import argparse
import json
import os
import time

import core.experiments.E7.run_e7 as e7
from core.oobsvc.common import CORE, finish_load, metadata, require_real_binaries, wait_quiet
from core.oobsvc.epoch import check_thresholds
from core.oobsvc.recovery import fetch_and_decode, recipient_recover

_orig = recipient_recover


def recover_with_parity(chain, sid_hex, e, timeout=30.0, policy='all', meta_source='auto'):
    if policy != 'minimal_parity':
        return _orig(chain, sid_hex, e, timeout=timeout, policy=policy, meta_source=meta_source)
    from core.oobsvc.certify import certified, registry_at
    t0 = time.perf_counter()
    fin = chain.finalized_height()
    reg = registry_at(chain, sid_hex, fin)
    c = certified(chain, sid_hex, e, fin, reg, meta_source=meta_source)
    t1 = time.perf_counter()
    if not c['certified']:
        return None, {'ok': False, 'reason': c['reason'], 'certify_check_s': t1 - t0}
    holders = sorted(c['holders'], key=lambda h: -h['i'])  # coordinates n, n-1, ... first
    recs, m = fetch_and_decode(holders, bytes.fromhex(sid_hex), e, c['manifest'], timeout, 'minimal')
    m['certify_check_s'] = t1 - t0
    m['anchor_bytes'] = c.get('anchor_bytes')
    m['fetch_policy'] = 'minimal_parity'
    return recs, m


e7.recipient_recover = recover_with_parity


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--configs', default='4,8,6:4,16,10:8,16,12:12,16,14:16,32,24', help='k,n,q separated by ":"')
    ap.add_argument('--modes', default='fragment_kzg')
    ap.add_argument('--m-e', default='4096', help='comma-separated epoch sizes')
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--policies', default='all,minimal,minimal_parity')
    ap.add_argument('--replace', action='store_true')
    ap.add_argument('--holder-timeout', type=float, default=120)
    ap.add_argument('--cert-timeout', type=float, default=1800)
    ap.add_argument('--label', default='')
    ap.add_argument('--cooldown-load', type=float, default=0,
                    help='if > 0: before each run wait until the 1-min load <= this (recorded per run)')
    ap.add_argument('--out', default='', help='output dir name under core/results/S7E1 (default: timestamp)')
    args = ap.parse_args()
    configs = [tuple(int(x) for x in c.split(',')) for c in args.configs.split(':')]
    for c in configs:
        check_thresholds(*c)
    require_real_binaries()
    outdir = CORE / 'results/S7E1' / (args.out or time.strftime('%Y%m%d-%H%M%S'))
    outdir.mkdir(parents=True, exist_ok=True)
    quiet = wait_quiet()
    raw = {'meta': metadata({'harness': 'S7E1 wrapper around core.experiments.E7.run_e7.run_one',
                             'configs': configs, 'modes': args.modes, 'm_e': args.m_e, 'reps': args.reps,
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
                        cool = wait_quiet(max_load=args.cooldown_load, timeout=600) if args.cooldown_load > 0 else None
                        t0 = time.time()
                        la0 = os.getloadavg()
                        r = e7.run_one(k, n, q, mode, m_e, rep, args)
                        r['wall_s'] = time.time() - t0
                        r['load_before'] = la0
                        r['cooldown'] = cool
                        r['load_after'] = os.getloadavg()
                        raw['results'].append(r)
                        s = r.get('seal') or {}
                        rec = r.get('recover') or {}
                        print(f"k={k} n={n} q={q} {mode} m_e={m_e} rep={rep}",
                              'ERROR ' + r['error'] if r.get('error') else 'ok',
                              f"prep={s.get('seal_prepare_s')} c2c={r.get('close_to_certified_s')}",
                              {p: (v.get('ok'), round(v.get('wall_s') or 0, 2)) for p, v in rec.items()},
                              f"{r['wall_s']:.0f}s load={r['load_after'][0]:.1f}", flush=True)
                        (outdir / 's7e1_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    finally:
        finish_load(raw['meta'])
        (outdir / 's7e1_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', outdir / 's7e1_raw.json')


if __name__ == '__main__':
    main()
