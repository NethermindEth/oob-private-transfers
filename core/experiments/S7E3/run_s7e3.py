"""S7-E3: time until a payload is retrievable (read-ready -> received) and certified, measured from finality.

One testbed per epoch size m_e: Anvil (1 s blocks, finality = 1 successor block), contracts, n holders, provider A
registered with (k, n, q) and seal_mode (default fragment_kzg). Epochs close ONLY at the fixed size m_e (M_max = m_e,
T_max = 1e9 s, i.e. never). Per repetition (one epoch each):
  1. m_e - 1 DISCLOSED synthetic payloads are bulk-loaded into the open epoch (no admission; harness only, before t0);
  2. one REAL transfer: deposit -> shielded-pool transact (Groth16 spend) -> finality of the transfer block;
     t0 = finality observed by the sender (the admission proof needs a finalized root rt in W);
  3. sender: encrypt, tag/digest, finalized path, Halo2 admission proof (T_prove); Append (verify + persist +
     receipt, T_append); the payload is slot m_e - 1, so its epoch closes inside the append transaction
     (T_fill = 0 in the measurement; T_fill is MODELED separately); notification;
  4. provider: PIR preprocessing of the closed epoch -> read_ready_at; recipient (cold, PIR policy) polls status,
     downloads public params + hint, queries, validates (digest, receipt, decrypt, note) -> received;
  5. provider (concurrently with 4): Seal (encode + commit, send, holder checks, q acks, certificate to holders) ->
     anchor tx -> anchor final -> certified_at; an independent reader then evaluates Certified(A, e) from chain data.
  6. off the measured path: wait for the slot-opening precomputation (fragment_kzg) so it does not overlap the next
     repetition; an isolated cold PIR read after certification (fresh recipient; no concurrent sealing).
All stamps are time.time() on one host (same clock for every process). Rep 0 of each m_e is a warm-up (labelled,
excluded from tables). Run under benchlock:
  $B $PY -m core.experiments.S7E3.run_s7e3 --m-e 1024,4096 --reps 5 --k 4 --n 8 --q 6 --seal-mode fragment_kzg
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse
import json
import os
import time
import traceback

from core.oobsvc.certify import certified
from core.oobsvc.client import Recipient, Sender, make_address
from core.oobsvc.common import CORE, RSSSampler, finish_load, metadata, require_real_binaries, wait_quiet
from core.oobsvc.deploy import ACCT_SENDER, Testbed
from core.oobsvc.workers import Admission

KEYS = str(HALO_KEYS)
ADM = {'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}


def epoch_of(tb, e):
    return {x['e']: x for x in tb.status('A')['epochs']}.get(e)


def one_rep(tb, snd, tool, m_e, rep, args):
    r = {'m_e': m_e, 'rep': rep, 'warmup': rep < args.warmup, 'load_start': os.getloadavg()}
    e = tb.status('A')['e_cur']
    r['e'] = e
    # 1. background (harness only, before t0)
    b0 = time.perf_counter()
    r['background'] = tb.admin('A', '/admin/bulk_load', count=m_e - 1, seed=10_000 * m_e + rep)[1]
    r['background_s'] = time.perf_counter() - b0
    ep = epoch_of(tb, e)
    assert ep and ep['state'] == 'open' and ep['m_e'] == m_e - 1, ep
    # 2. real transfer to a fresh recipient address
    sk, pk = tool.keypair()
    secret = str(int.from_bytes(os.urandom(31), 'big'))
    addr = make_address(tb.chain, secret, pk)
    old, dtx = snd.deposit_note()
    tb.chain.wait_final(dtx['block'])
    t = snd.transfer(old, addr)
    r['transfer'] = {'timings': t['timings'], 'gas': int(t['tx']['gas']), 'block': t['tx']['block']}
    r['transfer_finality_wait_s'] = tb.chain.wait_final(t['tx']['block'])  # devnet; before t0 by definition
    S = {'t0_final': time.time()}
    # 3. sender write path
    prep = snd.prepare(t['message'], t['cm'], pk, addr.ob)
    S['proved'] = time.time()
    ap = snd.append([tb.pdesc('A')], prep, r=1, policy='sequential', T_w=120)
    S['accepted'] = time.time()
    assert ap['complete'], ap
    en = ap['entries'][0]
    assert en['e'] == e and en['j'] == m_e - 1, (en, e, m_e)
    n = snd.notify(tb.dir / 'inbox', ap['entries'], t['cm'], t['tx']['block'])
    S['notified'] = time.time()
    # 4. recipient (cold client), concurrently with the provider's sealing
    rc = Recipient(tb.chain, tool, sk, addr, tb.dir / f'recipient-{m_e}-{rep}', [bytes(snd.notify_sk.verify_key).hex()])
    body = rc.load_notification(n['path'])
    S['recipient_start'] = time.time()
    res = rc.receive(body, T_r=120, max_wait=600, policy='pir')
    S['received'] = time.time()
    assert res['ok'] and res['cm'] == t['cm'], res
    rc.close()
    # 5. certification
    _, ep = tb.wait_state('A', e, ('certified',), timeout=args.cert_timeout)
    S['provider_certified_seen'] = time.time()
    c0 = time.perf_counter()
    c = certified(tb.chain, tb.services['A']['sid'], e)
    r['certified_check_s'] = time.perf_counter() - c0
    S['certified_checked'] = time.time()
    r['certified_check'] = {k: c.get(k) for k in ('certified', 'reason', 'block', 'height', 'meta_source', 'anchor_bytes')}
    assert c['certified'], c
    m = ep['metrics']
    for k in ('closed_at', 'first_at'):
        S[k] = ep[k]
    for k in ('read_ready_at', 'cert_formed_at', 'certified_at'):
        S[k] = m.get(k)
    r['close_reason'] = ep['close_reason']
    assert ep['close_reason'] == 'M_max', ep['close_reason']
    # 6. off-path: openings precomputation, then an isolated cold read (no concurrent sealing)
    t6 = time.time()
    while args.seal_mode == 'fragment_kzg' and 'openings_s' not in m and time.time() - t6 < 600:
        time.sleep(0.2)
        m = epoch_of(tb, e)['metrics']
    r['epoch_metrics'] = m
    ri = Recipient(tb.chain, tool, sk, addr, tb.dir / f'recipient-iso-{m_e}-{rep}', [])
    i0 = time.perf_counter()
    iso = ri.read_entry(ri.resolve(en), T_r=120, max_wait=60, policy='pir')
    r['isolated_read_s'] = time.perf_counter() - i0
    r['isolated_read'] = iso['metrics']
    assert iso['ok'] and iso['cm'] == t['cm']
    ri.close()
    r['stamps'] = S
    r['prepare'] = prep['timings']
    r['proof_bytes'] = prep['proof_bytes']
    r['append'] = {'latency_s': ap['attempts'][0]['latency_s'], 'server_timings': ap['attempts'][0].get('server_timings'),
                   'bytes_up': ap['attempts'][0]['bytes_up'], 'append_total_s': ap['append_total_s']}
    r['notify'] = {'bytes': n['bytes'], 'notify_s': n['notify_s']}
    r['read'] = res['metrics']
    r['load_end'] = os.getloadavg()
    return r


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--m-e', default='1024,4096')
    p.add_argument('--reps', type=int, default=5, help='measured repetitions per m_e (after the warm-up)')
    p.add_argument('--warmup', type=int, default=1)
    p.add_argument('--k', type=int, default=4)
    p.add_argument('--n', type=int, default=8)
    p.add_argument('--q', type=int, default=6)
    p.add_argument('--seal-mode', default='fragment_kzg')
    p.add_argument('--holder-timeout', type=float, default=60)
    p.add_argument('--cert-timeout', type=float, default=600)
    p.add_argument('--label', default='')
    p.add_argument('--out', default=None)
    args = p.parse_args()
    require_real_binaries()
    ts = time.strftime('%Y%m%d-%H%M%S')
    out = CORE / 'results/S7E3' / (args.out or ts)
    out.mkdir(parents=True)
    cfg = {'m_e': args.m_e, 'reps': args.reps, 'warmup': args.warmup, 'k': args.k, 'n': args.n, 'q': args.q,
           'seal_mode': args.seal_mode, 'M_max': 'm_e (fixed-size close)', 'T_max': 1e9, 'depth': 32,
           'admission': 'Halo2 P1 full', 'block_time_s': 1, 'finality_rule': 'c=1 successor block',
           'policy': 'sequential r=1, recipient PIR (cold)', 'label': args.label,
           'background': 'm_e-1 bulk-loaded synthetic payloads (no admission), disclosed; the real payload is slot m_e-1'}
    quiet = wait_quiet()
    meta = metadata(cfg)
    meta['quiet_wait'] = quiet
    raw = {'meta': meta, 'testbeds': [], 'runs': [], 'failures': []}
    try:
        for m_e in [int(x) for x in args.m_e.split(',')]:
            tb = Testbed(f'S7E3-m{m_e}-{ts}', block_time=1, n_holders=args.n, seal_mode=args.seal_mode)
            tbinfo = {'m_e': m_e, 'dir': str(tb.dir)}
            prover = tool = None
            try:
                tb.register('A', k=args.k, q=args.q)
                t0 = time.perf_counter()
                A = tb.start_provider('A', M_max=m_e, T_max=1e9, holder_timeout=args.holder_timeout, seal_retry_s=5,
                                      admission=ADM)
                tbinfo['provider_start_s'] = time.perf_counter() - t0
                prover = Admission('prover', 32, 'full', KEYS)
                tbinfo['prover_info'] = prover.info()
                tool = Admission('tool', 32)
                snd = Sender(tb.chain, prover, ACCT_SENDER, tb.dir / 'sender-retained')
                rss = RSSSampler({'provider_tree': tb.procs[A['proc']].pid, 'prover_worker': prover.pid})
                rss.start()
                for rep in range(args.warmup + args.reps):
                    try:
                        r = one_rep(tb, snd, tool, m_e, rep, args)
                        raw['runs'].append(r)
                        S = r['stamps']
                        print(f"m_e={m_e} rep={rep}{' (warm-up)' if r['warmup'] else ''}: read_ready "
                              f"{S['read_ready_at'] - S['t0_final']:.2f}s received {S['received'] - S['t0_final']:.2f}s "
                              f"certified {S['certified_at'] - S['t0_final']:.2f}s load {r['load_end'][0]:.1f}", flush=True)
                    except Exception as exc:
                        raw['failures'].append({'m_e': m_e, 'rep': rep, 'error': f'{type(exc).__name__}: {exc}',
                                                'trace': traceback.format_exc()})
                        print('m_e', m_e, 'rep', rep, 'EXC', exc, flush=True)
                tbinfo['peak_rss_bytes'] = rss.stop()
                tbinfo['gas'] = dict(tb.gas)
                tbinfo['pipeline_errors'] = tb.status('A')['pipeline_errors']
            finally:
                for w in (prover, tool):
                    if w:
                        w.close()
                tb.close()
                raw['testbeds'].append(tbinfo)
            (out / 's7e3_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    finally:
        finish_load(raw['meta'])
        (out / 's7e3_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', out / 's7e3_raw.json')


if __name__ == '__main__':
    main()
