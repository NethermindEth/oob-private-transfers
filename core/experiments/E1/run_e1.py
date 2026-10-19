"""E1: real operational path, end to end, on one implementation (same-host loopback).

finalized transact output -> Halo2 admission proof (P1, depth 32) -> provider verification -> persistent append ->
signed receipt -> notification -> epoch closes by the rule (M_max=4096 or T_max=10 s) -> SimplePIR preprocessing ->
PIR read -> digest/receipt validation -> decryption + note consistency (finalized leaf).

Background: each epoch contains DISCLOSED bulk-loaded synthetic records (no admission) so it has 4096 slots;
the measured transfer itself is genuine. Variants:
  mmax: 4095 background records first, genuine record is #4096 -> closes by M_max immediately.
  tmax: genuine record first, then 4094 background -> closes by T_max (10 s after the first record).
Run: benchlock .venv/bin/python -m core.experiments.E1.run_e1 --runs 10
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse
import json
import os
import statistics
import time

from core.oobsvc.common import CORE, RSSSampler, finish_load, metadata, require_real_binaries, wait_quiet
from core.oobsvc.client import Recipient, Sender, make_address
from core.oobsvc.deploy import ACCT_SENDER, Testbed
from core.oobsvc.workers import Admission

KEYS = str(HALO_KEYS)


def one_run(tb, snd, tool, variant, idx, sampler):
    r = {'variant': variant, 'run': idx}
    sk, pk = tool.keypair()
    secret = str(int.from_bytes(os.urandom(31), 'big'))
    addr = make_address(tb.chain, secret, pk)
    old, dtx = snd.deposit_note()
    tb.chain.wait_final(dtx['block'])
    st = tb.status('A')
    e = st['e_cur']
    t = snd.transfer(old, addr)
    r['transfer'] = {'timings': t['timings'], 'gas': int(t['tx']['gas']), 'block': t['tx']['block'],
                     'calldata_bytes': t['tx']['calldata_bytes']}
    fw = time.perf_counter()
    r['finality_wait_s'] = tb.chain.wait_final(t['tx']['block'])  # devnet block time; NOT OOB latency
    T0 = time.perf_counter()  # finality observed by the sender: start of post-finality OOB latency
    prep = snd.prepare(t['message'], t['cm'], pk, addr.ob)
    T1 = time.perf_counter()
    excluded = 0.0  # harness-only bulk loading of disclosed background records; excluded from wall time
    if variant == 'mmax':
        b0 = time.perf_counter()
        r['background'] = tb.admin('A', '/admin/bulk_load', count=4095, seed=1000 + idx)[1]
        excluded += time.perf_counter() - b0
    T1b = time.perf_counter()
    ap = snd.append([tb.pdesc('A')], prep, r=1, policy='sequential', T_w=60)
    T2 = time.perf_counter()
    assert ap['complete'], ap
    en = ap['entries'][0]
    assert en['e'] == e, (en, e)
    if variant == 'tmax':
        b0 = time.perf_counter()
        r['background'] = tb.admin('A', '/admin/bulk_load', count=4094, seed=2000 + idx)[1]
        overlap = time.perf_counter() - b0  # NOT excluded: it elapses inside the T_max window that runs anyway
    else:
        overlap = 0.0
    T2b = time.perf_counter()
    n = snd.notify(tb.dir / 'inbox', ap['entries'], t['cm'], t['tx']['block'])
    T3 = time.perf_counter()
    rc = Recipient(tb.chain, tool, sk, addr, tb.dir / f'recipient-{variant}-{idx}', [bytes(snd.notify_sk.verify_key).hex()])
    sampler.add(f'recipient_pir_client_{variant}_{idx}', os.getpid())
    body = rc.load_notification(n['path'])
    res = rc.receive(body, T_r=60, max_wait=120, policy='pir')  # principal measured path: real SimplePIR read (cold)
    T4 = time.perf_counter()
    assert res['ok'], res
    for name, c in rc.clients.items():
        sampler.add('recipient_pir_client', c.pid)
    # warm read: same epoch, cached public params + hint (reusable setup)
    w0 = time.perf_counter()
    warm = rc.read_entry(body['entries'][0], policy='pir')
    r['warm_read'] = warm['metrics']
    r['warm_read_s'] = time.perf_counter() - w0
    rc.close()
    # A7 read policy decision on public sizes + the whole-epoch download path, measured on the same record
    rd = Recipient(tb.chain, tool, sk, addr, tb.dir / f'recipient-dl-{variant}-{idx}', [])
    d0 = time.perf_counter()
    dl = rd.read_entry(body['entries'][0], policy='auto')
    r['auto_read'] = dl['metrics']
    r['auto_read_s'] = time.perf_counter() - d0
    rd.close()
    r['prepare'] = prep['timings']
    r['proof_bytes'] = prep['proof_bytes']
    r['append'] = ap
    r['notification'] = {'bytes': n['bytes'], 'notify_s': n['notify_s']}
    r['read'] = res['metrics']
    r['wall'] = {'finality_to_validated_note_s': T4 - T0 - excluded, 'prepare_s': T1 - T0, 'append_s': T2 - T1b,
                 'notify_s': T3 - T2b, 'receive_s': T4 - T3, 'excluded_bulk_load_s': excluded}
    # single-run trace: contiguous stages whose durations add up to the measured wall clock (A10)
    rm = res['metrics']
    stages = [('encrypt', prep['timings']['encrypt_s']), ('tag_digest', prep['timings']['tag_digest_s']),
              ('merkle_path', prep['timings']['path_s']), ('admission_prove', prep['timings']['prove_s']),
              ('prepare_other', (T1 - T0) - sum(prep['timings'][k] for k in ('encrypt_s', 'tag_digest_s', 'path_s', 'prove_s'))),
              ('append_rtt(verify+persist+receipt)', T2 - T1b),
              ('background_bulk_load(harness; inside T_max window)', overlap), ('notify', T3 - T2b),
              ('epoch_close+pir_preprocess_wait', rm['epoch_wait_s']), ('policy/status', rm.get('choose_s', 0)),
              ('download_public+hint', rm.get('download_public_hint_s', 0)), ('pir_client_load', rm.get('client_load_s', 0)),
              ('pir_query', rm['query_s']), ('pir_answer_rtt', rm['answer_rtt_s']), ('pir_recover', rm['recover_s']),
              ('validate_digest_receipt', rm['validate_digest_receipt_s']), ('decrypt', rm['decrypt_s']),
              ('note_consistency', rm['note_check_s'])]
    acc = sum(d for _, d in stages)
    stages.append(('other(recipient bookkeeping)', r['wall']['finality_to_validated_note_s'] - acc))
    wall0 = time.time() - (time.perf_counter() - T0)
    trace, cur = [], wall0
    for name, d in stages:
        trace.append({'stage': name, 'start_unix': cur, 'end_unix': cur + d, 'seconds': d})
        cur += d
    r['trace'] = trace
    r['trace_note'] = ('stage durations are measured; bulk-load of background records (harness only) is excluded; '
                       'start/end are cumulative from the finality timestamp')
    # provider-side epoch metrics (close reason, wait, PIR setup)
    dt, ep = tb.wait_state('A', e, ('certified',), timeout=180)
    r['epoch'] = ep
    r['epoch_close_wait_after_append_s'] = ep['closed_at'] - (time.time() - (time.perf_counter() - T2))
    r['ok'] = res['ok'] and warm['ok'] and warm['cm'] == t['cm'] and res['cm'] == t['cm']
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=int, default=10)
    ap.add_argument('--variants', default='mmax,tmax')
    ap.add_argument('--block-time', type=float, default=1.0)
    args = ap.parse_args()
    require_real_binaries()
    ts = time.strftime('%Y%m%d-%H%M%S')
    out = CORE / 'results/E1' / ts
    out.mkdir(parents=True)
    cfg = {'runs': args.runs, 'variants': args.variants, 'M_max': 4096, 'T_max': 10.0, 'depth': 32, 'variant': 'full (P1)',
           'block_time_s': args.block_time, 'finality_rule': 'c=1 successor block', 'policy': 'sequential r=1',
           'background': 'bulk-loaded synthetic records (no admission), disclosed'}
    quiet = wait_quiet()
    meta = metadata(cfg)
    meta['quiet_wait'] = quiet
    tb = Testbed(f'E1-{ts}', block_time=args.block_time)
    raw = {'meta': meta, 'runs': [], 'failures': []}
    try:
        tb.register('A')
        t0 = time.perf_counter()
        tb.start_provider('A', admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS})
        raw['provider_start_s'] = time.perf_counter() - t0
        t0 = time.perf_counter()
        prover = Admission('prover', 32, 'full', KEYS)
        info = prover.info()
        raw['prover_setup'] = {'wall_s': time.perf_counter() - t0, 'info': info,
                               'note': 'reusable setup: params loaded from cache dir (first-use generation reported in info.setup)'}
        tool = Admission('tool', 32)
        snd = Sender(tb.chain, prover, ACCT_SENDER, tb.dir / 'sender-retained')
        import psutil
        pp = tb.procs[tb.providers['A']['proc']].pid
        sampler = RSSSampler({'provider_tree': pp, 'prover_worker': prover.pid, 'harness_client': os.getpid(),
                              **{h['name']: tb.procs[h['name']].pid for h in tb.holders}})
        sampler.start()
        raw['gas'] = dict(tb.gas)
        for variant in args.variants.split(','):
            for i in range(args.runs):
                try:
                    r = one_run(tb, snd, tool, variant, i, sampler)
                    raw['runs'].append(r)
                    print(variant, i, 'ok' if r['ok'] else 'FAIL', f"{r['wall']['finality_to_validated_note_s']:.2f}s", flush=True)
                except Exception as exc:
                    import traceback
                    raw['failures'].append({'variant': variant, 'run': i, 'error': f'{type(exc).__name__}: {exc}',
                                            'trace': traceback.format_exc()})
                    print(variant, i, 'EXC', exc, flush=True)
        raw['peak_rss_bytes'] = sampler.stop()
        st = tb.status('A')
        raw['provider_final_status'] = {k: st[k] for k in ('records', 'synthetic_records', 'tags', 'e_cur')}
        db = Path(tb.providers['A']['cfg']['data_dir'])
        raw['storage'] = {f.name: f.stat().st_size for f in db.glob('provider.sqlite3*')}
        raw['storage']['pir_dir_bytes'] = sum(f.stat().st_size for f in (db / 'pir').rglob('*') if f.is_file())
        raw['gas'].update({'anchor': [ep['metrics'].get('anchor_gas') for ep in st['epochs']]})
        prover.close()
        tool.close()
    finally:
        raw['meta']['wall_time_s'] = time.time() - time.mktime(time.strptime(meta['started_at'][:19], '%Y-%m-%dT%H:%M:%S'))
        finish_load(raw['meta'])
        (out / 'e1_raw.json').write_text(json.dumps(raw, indent=1, default=str))
        tb.close()
    print('wrote', out / 'e1_raw.json')


if __name__ == '__main__':
    main()
