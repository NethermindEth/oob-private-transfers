"""E3: independent-provider censorship (same-host loopback; injected faults, not Internet censorship).

Three genuinely separate providers A, B, C (own SQLite DBs, own U, epochs, PIR state) with different background
records (disclosed bulk loads), insertion orders and positions. A and B seal/certify/anchor; C is configured to NEVER
seal/anchor (row "refuses reads and never anchors"). Genuine notes: real transact + real Halo2 P1 proofs, generated
up front (proof cost excluded from write latency; reported separately).

Run: benchlock .venv/bin/python -m core.experiments.E3.run_e3
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from core.paths import HALO_KEYS
import argparse
import base64
import json
import os
import random
import shutil
import statistics
import time
import traceback

from core.oobsvc.common import CORE, finish_load, get_json, metadata, post_json, require_real_binaries, wait_quiet
from core.oobsvc.client import Recipient, Sender, make_address
from core.oobsvc.deploy import ACCT_SENDER, Testbed
from core.oobsvc.workers import Admission

KEYS = str(HALO_KEYS)
ADM = {'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}
T_W, T_R = 2.0, 2.0


class Note:
    pass


def make_note(tb, snd, tool):
    n = Note()
    n.sk, pk = tool.keypair()
    n.addr = make_address(tb.chain, str(random.randrange(1, 2 ** 200)), pk)
    old, tx = snd.deposit_note()
    tb.chain.wait_final(tx['block'])
    n.t = snd.transfer(old, n.addr)
    tb.chain.wait_final(n.t['tx']['block'])
    t0 = time.perf_counter()
    n.prep = snd.prepare(n.t['message'], n.t['cm'], pk, n.addr.ob)
    n.prove_s = time.perf_counter() - t0
    n.entries = {}
    return n


def fault(tb, name, **f):
    tb.admin(name, '/admin/fault', faults=f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--notes', type=int, default=32)
    args = ap.parse_args()
    require_real_binaries()
    ts = time.strftime('%Y%m%d-%H%M%S')
    outdir = CORE / 'results/E3' / ts
    outdir.mkdir(parents=True)
    quiet = wait_quiet()
    raw = {'meta': metadata({'T_w': T_W, 'T_r': T_R, 'notes': args.notes, 'M_max': 4096, 'T_max': 10,
                             'providers': {'A': 'seal+anchor', 'B': 'seal+anchor', 'C': 'never seals/anchors'},
                             'background': {'A': 1000, 'B': 2000, 'C': 3000}}), 'scenarios': {}}
    raw['meta']['quiet_wait'] = quiet
    tb = Testbed(f'E3-{ts}', block_time=1)
    prover = Admission('prover', 32, 'full', KEYS)
    prover.info()
    tool = Admission('tool', 32)
    S = raw['scenarios']
    try:
        for nm in 'ABC':
            tb.register(nm)
        P = {'A': tb.start_provider('A', T_max=10, admission=ADM), 'B': tb.start_provider('B', T_max=10, admission=ADM),
             'C': tb.start_provider('C', T_max=10, admission=ADM, seal=False, anchor=False)}
        for nm, cnt in (('A', 1000), ('B', 2000), ('C', 3000)):
            tb.admin(nm, '/admin/bulk_load', count=cnt, seed=ord(nm))
        D = {nm: tb.pdesc(nm) for nm in 'ABC'}
        snd = Sender(tb.chain, prover, ACCT_SENDER, tb.dir / 'sender-retained')
        t0 = time.perf_counter()
        notes = [make_note(tb, snd, tool) for _ in range(args.notes)]
        raw['note_generation'] = {'count': len(notes), 'wall_s': time.perf_counter() - t0,
                                  'prove_s': [n.prove_s for n in notes]}
        g1, g2, g3, g4 = notes[0:8], notes[8:16], notes[16:24], notes[24:32]

        def rows(nm):
            s = tb.status(nm)
            return {'records': s['records'], 'tags': s['tags']}

        # ---- S1: A rejects a valid write (503 refusal or delay beyond T_w); B cooperates
        s1 = []
        tagsA0 = tb.status('A')['tags']
        for mode, grp in (('refuse', g1), ('delay', g2)):
            if mode == 'delay':
                tagsA_delay0 = tb.status('A')['tags']
            fault(tb, 'A', **({'refuse_writes': True} if mode == 'refuse' else {'delay_writes': 5.0}))
            for k, n in enumerate(grp):
                pol = 'sequential' if k % 2 == 0 else 'hedged'
                before = {nm: rows(nm) for nm in 'AB'}
                res = snd.append([D['A'], D['B']], n.prep, r=1, policy=pol, T_w=T_W)
                after = {nm: rows(nm) for nm in 'AB'}
                for en in res['entries']:
                    n.entries[en['name']] = en
                s1.append({'mode': mode, 'policy': pol, 'complete': res['complete'], 'attempts': len(res['attempts']),
                           'latency_s': res['append_total_s'], 'contacted': res['providers_contacted'],
                           'outcomes': [(a['provider'], a.get('outcome'), a.get('status')) for a in res['attempts']],
                           'bytes_up': sum(a['bytes_up'] for a in res['attempts']),
                           'bytes_down': sum(a.get('bytes_down', 0) for a in res['attempts']),
                           'alloc_A': after['A']['tags'] - before['A']['tags'], 'alloc_B': after['B']['tags'] - before['B']['tags']})
            fault(tb, 'A')
            if mode == 'delay':  # timeout != rejection: count late commits at A after the delayed handlers finish
                time.sleep(6)
                S['S1_late_commits_at_A'] = {'refuse_block': tagsA_delay0 - tagsA0,
                                             'delay_block': tb.status('A')['tags'] - tagsA_delay0, 'trials': len(grp)}
        S['S1_write_refused_at_A'] = s1

        # ---- S2: repeat the same entitlement at A (idempotent / CONFLICT, no extra allocation) and submit at C
        s2 = []
        for k, n in enumerate(g1):
            b0 = rows('A')
            r1 = snd.append_one(D['A'], n.prep, 30)
            b1 = rows('A')
            r2 = snd.append_one(D['A'], n.prep, 30)
            b2 = rows('A')
            item = {'first': r1.get('outcome'), 'retry': r2.get('outcome'), 'alloc_first': b1['tags'] - b0['tags'],
                    'alloc_retry': b2['tags'] - b1['tags'],
                    'same_locator': (r1.get('entry') or {}).get('j') == (r2.get('entry') or {}).get('j'),
                    'same_receipt': (r1.get('entry') or {}).get('receipt') == (r2.get('entry') or {}).get('receipt')}
            if 'entry' in r1:
                n.entries['A'] = r1['entry']
            if k < 3:  # randomized re-submission: re-encryption with a fresh proof -> CONFLICT
                prep2 = snd.prepare(n.t['message'], n.t['cm'], n.addr.pk, n.addr.ob)
                r3 = snd.append_one(D['A'], prep2, 30)
                item.update(conflict=r3.get('outcome'), alloc_conflict=rows('A')['tags'] - b2['tags'])
            c0 = rows('C')
            r4 = snd.append_one(D['C'], n.prep, 30)
            item.update(at_C=r4.get('outcome'), alloc_C=rows('C')['tags'] - c0['tags'],
                        loc_A=(r1.get('entry') or {}).get('e'), loc_C=((r4.get('entry') or {}).get('e'), (r4.get('entry') or {}).get('j')),
                        pos_A=(r1.get('entry') or {}).get('j'), pos_B=(n.entries.get('B') or {}).get('j'))
            if 'entry' in r4:
                n.entries['C'] = r4['entry']
            s2.append(item)
        S['S2_repeat_at_A_submit_at_C'] = s2
        # g3: r=1 at A only (for "B healthy but lacks payload"); g4: r=1 at C only (never anchored)
        for n in g3:
            r = snd.append([D['A']], n.prep, r=1)
            n.entries.update({e['name']: e for e in r['entries']})
        for n in g4:
            r = snd.append([D['C']], n.prep, r=1)
            n.entries.update({e['name']: e for e in r['entries']})
        # replication-policy storage: r = number of accepted copies of the same record
        raw['placement'] = [{nm: (en['e'], en['j']) for nm, en in n.entries.items()} for n in notes]
        time.sleep(12)  # let every open epoch close by T_max (10 s) and become read-ready
        for nm in 'ABC':
            for ep in tb.status(nm)['epochs']:
                if ep['state'] == 'closed':
                    tb.wait_state(nm, ep['e'], ('read_ready', 'sealed', 'certified'), timeout=120)
        for nm in 'AB':  # certified epochs needed for recovery rows
            for ep in tb.status(nm)['epochs']:
                tb.wait_state(nm, ep['e'], ('certified',), timeout=300)

        def read(n, order, **kw):
            rc = Recipient(tb.chain, tool, n.sk, n.addr, tb.dir / f'rc-{random.randrange(10**9)}', [bytes(snd.notify_sk.verify_key).hex()])
            body = {'entries': [n.entries[o] for o in order if o in n.entries]}
            t0 = time.perf_counter()
            r = rc.receive(body, T_r=T_R, max_wait=5, **kw)
            rc.close()
            return {'ok': r['ok'], 'via': r.get('via'), 'latency_s': time.perf_counter() - t0,
                    'attempts': [(a.get('provider'), a.get('path', 'provider'), a['ok'], a.get('error')) for a in r['attempts']],
                    'read_path': (r.get('metrics') or {}).get('read_path'),
                    'bytes_down': (r.get('metrics') or {}).get('hint_bytes', 0) + (r.get('metrics') or {}).get('public_bytes', 0)
                    + (r.get('metrics') or {}).get('answer_bytes', 0) + (r.get('metrics') or {}).get('download_bytes', 0)
                    + (r.get('metrics') or {}).get('fetch_bytes', 0)}

        # ---- S3: A refuses reads but stays live; B holds the payload -> switch to B's locator, actual PIR read
        fault(tb, 'A', refuse_reads=True)
        S['S3_A_refuses_reads_B_holds'] = [read(n, ['A', 'B'], policy='pir') for n in g1]
        # ---- S4: A refuses; B healthy but LACKS the payload -> failure, or explicit recovery path (A3)
        S['S4_A_refuses_B_lacks_no_recovery'] = [read(n, ['A'], policy='pir') for n in g3]
        S['S4_A_refuses_B_lacks_recipient_recovery'] = [read(n, ['A'], policy='pir', recovery=True) for n in g3]
        fault(tb, 'A')
        # ---- S4b: provider refuses reads and NEVER anchors (C): no certification -> no recovery path
        fault(tb, 'C', refuse_reads=True)
        S['S4b_C_refuses_never_anchored'] = [read(n, ['C'], policy='pir', recovery=True) for n in g4]
        fault(tb, 'C')
        # ---- S5: delays beyond deadline, malformed responses, all refuse
        fault(tb, 'A', delay_reads=5.0)
        S['S5_A_delay_reads'] = [read(n, ['A', 'B'], policy='pir') for n in g1]
        fault(tb, 'A', malformed_answers=True)
        S['S5_A_malformed_answers'] = [read(n, ['A', 'B'], policy='pir') for n in g1]
        for nm in 'ABC':
            fault(tb, nm, refuse_reads=True)
        S['S5_all_refuse_reads'] = [read(n, ['A', 'B', 'C'], policy='pir') for n in g1]
        for nm in 'ABC':
            fault(tb, nm, refuse_writes=True)
        w = []
        for n in g1[:4]:
            b = {nm: rows(nm)['tags'] for nm in 'ABC'}
            res = snd.append([D['A'], D['B'], D['C']], n.prep, r=1, policy='sequential', T_w=T_W)
            w.append({'complete': res['complete'], 'attempts': len(res['attempts']), 'latency_s': res['append_total_s'],
                      'alloc': {nm: rows(nm)['tags'] - b[nm] for nm in 'ABC'}})
        S['S5_all_refuse_writes'] = w
        for nm in 'ABC':
            fault(tb, nm)
        # ---- S6: A fails and is replaced by A2 (protocol v2: new key and sid, "continues A"): the tags restored into
        # A2's U enforce the duplicate policy for A's certified records at the same (e, j)
        adir = P['A']['cfg']['data_dir']
        tb.kill(P['A']['proc'])
        shutil.rmtree(adir)
        tb.register('A2', continues='A')
        R = tb.start_provider('A2', mode='replace', admission=ADM, forbidden_paths=[adir], sandbox_deny=[adir], T_max=10)
        t0 = time.perf_counter()
        while tb.status('A2')['recovery'].get('phase') not in ('complete', 'read_only_partial', 'failed', 'isolation_violation'):
            time.sleep(0.1)
        rs = tb.status('A2')
        # The sender learns A2 from the harness (outside the protocol) and resolves its endpoint in the registry.
        from core.oobsvc.client import resolve_endpoint
        DR = {'name': 'A2', 'sid': tb.services['A2']['sid'], 'url': resolve_endpoint(tb.chain, tb.services['A2']['sid'])}
        assert DR['url'] == R['url'], (DR['url'], R['url'])
        s6 = {'recovery_phase': rs['recovery']['phase'], 'recovery_s': time.perf_counter() - t0,
              'appends_enabled': rs['appends_enabled'], 'tags_restored': rs['tags'], 'trials': []}
        for k, n in enumerate(g1 + g3):
            b = tb.status('A2')['tags']
            r = snd.append_one(DR, n.prep, 30)
            s6['trials'].append({'outcome': r.get('outcome'), 'alloc': tb.status('A2')['tags'] - b,
                                 'same_locator': (r.get('entry') or {}).get('j') == n.entries['A']['j'] and
                                 (r.get('entry') or {}).get('e') == n.entries['A']['e']})
        prep2 = snd.prepare(g1[0].t['message'], g1[0].t['cm'], g1[0].addr.pk, g1[0].addr.ob)
        b = tb.status('A2')['tags']
        r = snd.append_one(DR, prep2, 30)
        s6['conflict_after_recovery'] = {'outcome': r.get('outcome'), 'alloc': tb.status('A2')['tags'] - b}
        S['S6_A_replaced_restored_U'] = s6
        # storage per provider (DB + PIR state)
        raw['storage'] = {}
        for nm in 'BC':
            d = P[nm]['cfg']['data_dir']
            raw['storage'][nm] = {'status': {k: tb.status(nm)[k] for k in ('records', 'synthetic_records', 'tags')},
                                  'files': {str(f.relative_to(d)): f.stat().st_size for f in __import__('pathlib').Path(d).rglob('*') if f.is_file()}}
        raw['observed_A_B'] = {nm: sum(1 for _ in open(os.path.join(P[nm]['cfg']['data_dir'], 'observed.jsonl'))) for nm in 'BC'}
    except Exception as exc:
        raw['error'] = f'{type(exc).__name__}: {exc}'
        raw['trace'] = traceback.format_exc()
        print(raw['trace'])
    finally:
        prover.close()
        tool.close()
        tb.close()
        finish_load(raw['meta'])
        (outdir / 'e3_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', outdir / 'e3_raw.json')


if __name__ == '__main__':
    main()
