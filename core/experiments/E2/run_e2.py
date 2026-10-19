"""E2: destructive availability and recovery (protocol v2). Same-host loopback; destructive work only in testbed/.

Configuration per run: --k --n --q (holder assignment thresholds; default the old (3,5,5)), --seal-mode
(fragment_kzg | whole_epoch), --m-e (records per principal epoch, default 4096).

Per case: fresh Anvil + contracts + n holders + provider A registered with (k, n, q); one GENUINE transfer (real
Groth16 transact + Halo2 P1 admission proof) appended among DISCLOSED bulk-loaded synthetic background records
(epoch of m_e records); the epoch closes by M_max, is PIR-preprocessed, sealed to the n holders (seal mode), certified
(q acks) and anchored (manifest + certificate in calldata). Recipient stays offline. Then A's data dir (SQLite, PIR
state, key) and the sender's retained copy are DELETED and deletion is verified. Replace(A -> A2): a NEW provider A2
(own key and sid, registered with "continues A", first epoch last_A + 1) starts under sandbox-exec with an EMPTY dir
and a profile denying any access to the destroyed paths, reconstructs A's certified epochs from A's anchors + the
surviving holders at the same (e, j); the recipient reads (A2, e, j) (the successor mapping A -> A2 is a harness
parameter: announcing a replacement is outside the protocol) and validates against A's notified digest/receipt; a
replay of the original record at A2 is idempotent; then a fresh genuine append at A2 and its first own epoch
(last_A + 1) is certified under A2's anchors.

Every case records its expectation (derived from k, n, q) and whether the observed outcome matches ('pass').

Run: benchlock .venv/bin/python -m core.experiments.E2.run_e2 [--k 4 --n 8 --q 6] [--seal-mode fragment_kzg]
     [--cases ...] [--reps 5] [--m-e 4096]
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
import time
import traceback

from core.oobsvc.common import CORE, finish_load, get_json, http, metadata, post_json, require_real_binaries, wait_quiet
from core.oobsvc.client import Recipient, Sender, make_address, resolve_endpoint
from core.oobsvc.deploy import ACCT_SENDER, Testbed
from core.oobsvc.epoch import check_thresholds
from core.oobsvc.workers import Admission

KEYS = str(HALO_KEYS)
ADM = {'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}


class Ctx:
    pass


def genuine(tb, prover, tool, sender_dir):
    """One real private transfer to a fresh recipient address, proven for admission (not yet appended)."""
    c = Ctx()
    c.sk, pk = tool.keypair()
    c.addr = make_address(tb.chain, str(random.randrange(1, 2 ** 200)), pk)
    c.snd = Sender(tb.chain, prover, ACCT_SENDER, sender_dir)
    old, tx = c.snd.deposit_note()
    tb.chain.wait_final(tx['block'])
    c.t = c.snd.transfer(old, c.addr)
    tb.chain.wait_final(c.t['tx']['block'])
    c.prep = c.snd.prepare(c.t['message'], c.t['cm'], pk, c.addr.ob)
    return c


def wait_phase(tb, name, timeout=900):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        s = tb.status(name)
        if s['recovery'].get('phase') in ('complete', 'read_only_partial', 'failed', 'isolation_violation'):
            return s, time.perf_counter() - t0
        time.sleep(0.05)
    raise TimeoutError('recovery did not finish')


def pir_digests(url, e):
    """SHA-256 of the served PIR public parameters and hint of epoch e."""
    import hashlib
    out = {}
    for part in ('public', 'hint'):
        try:
            st, body = http('GET', f'{url}/pir/{part}/{e}', timeout=60)
            out[part] = hashlib.sha256(body).hexdigest() if st == 200 else f'status {st}'
        except Exception as exc:
            out[part] = f'error {exc}'
    return out


def dir_bytes(p):
    return sum(f.stat().st_size for f in Path(p).rglob('*') if f.is_file()) if Path(p).exists() else 0


def append_raw(url, sid, prep):
    return post_json(url + '/append', {'sid': sid, 'h': prep['h'], 'public': prep['public'], 'proof': prep['proof'],
                                       'rec': base64.b64encode(prep['rec']).decode()}, timeout=120)


def run_case(case: dict, cfg: dict, prover, tool, rep: int) -> dict:
    k, n, q, mode = cfg['k'], cfg['n'], cfg['q'], cfg['seal_mode']
    name = f"E2-{case['id']}-{k}-{n}-{q}-{mode[:5]}-{rep}-{time.strftime('%H%M%S')}"
    tb = Testbed(name, block_time=1, n_holders=n, seal_mode=mode)
    out = {'case': case, 'config': cfg, 'rep': rep, 'testbed': str(tb.dir)}
    try:
        m = case.get('m_e', cfg['m_e'])
        tb.register('A', k=k, q=q)
        A = tb.start_provider('A', M_max=m, T_max=case.get('T_max', 600), seal_retry_s=2, admission=ADM,
                              holder_timeout=case.get('holder_timeout', 60), faults=case.get('provider_faults_seal', {}))
        sidA = tb.services['A']['sid']
        for i, f in case.get('holder_faults_seal', {}).items():
            tb.holder_fault(int(i), f)
        g = genuine(tb, prover, tool, tb.dir / 'sender-retained')
        pos = case.get('pos', m // 2)
        n_epochs = case.get('epochs', 1)
        if n_epochs > 1:  # sweep: n_epochs small epochs, the genuine record is in the LAST one
            tb.admin('A', '/admin/bulk_load', count=m * (n_epochs - 1), seed=rep)
        tb.admin('A', '/admin/bulk_load', count=pos, seed=10_000 + rep)
        ap = g.snd.append([tb.pdesc('A')], g.prep, r=1, T_w=120)
        assert ap['complete'], ap
        en = ap['entries'][0]
        out['entry'] = {k_: en[k_] for k_ in ('e', 'j', 'd_rec')}
        note = g.snd.notify(tb.dir / 'recipient-inbox', ap['entries'], g.t['cm'], g.t['tx']['block'])
        if case.get('drop_genuine'):  # Byzantine provider omits the receipted record from the sealed epoch
            tb.admin('A', '/admin/fault', faults={'drop_record_on_seal': [g.prep['nu']]})
        if not case.get('kill_before_cert'):
            tb.admin('A', '/admin/bulk_load', count=m - pos - 1, seed=20_000 + rep)
            t0 = time.perf_counter()
            try:
                _, ep = tb.wait_state('A', en['e'], ('certified',), timeout=case.get('cert_timeout', 300))
                out['certified'] = True
            except TimeoutError:
                ep = {x['e']: x for x in tb.status('A')['epochs']}.get(en['e'])
                out['certified'] = False
            if case.get('replace_holders') and not out['certified']:
                # the holders offline at sealing are permanently lost: A itself installs a new assignment in which
                # new holders take their coordinates -> the stuck epoch is resealed and certified
                t1 = time.perf_counter()
                lost = case['replace_holders']
                idx = list(range(n))
                for c_, ix in enumerate(lost):
                    tb.start_holder(n + c_)
                    idx[ix] = n + c_
                r = tb.set_assignment('A', idx, k=k, q=q)
                tb.chain.wait_final(r['block'])
                _, ep = tb.wait_state('A', en['e'], ('certified',), timeout=300)
                out['certified'] = True
                out['holder_replacement'] = {'set_assignment_gas': int(r['gas']), 'to_certified_s': time.perf_counter() - t1,
                                             'stuck_for_s': t1 - t0, 'new_assignment': idx}
            out['seal_to_certified_s'] = time.perf_counter() - t0
            out['epoch_metrics'] = ep and ep.get('metrics')
            out['durable_check'] = g.snd.check_durable(en, g.prep['rec'])
        else:
            out['certified'] = False
        if out.get('certified'):
            out['pir_before'] = pir_digests(A['url'], en['e'])

        def hstat(h):
            try:
                return get_json(h['url'] + '/status', timeout=5)[1]
            except Exception as exc:  # e.g. a holder that is offline in this case
                return {'error': f'{type(exc).__name__}'}
        out['holder_storage'] = [hstat(h) for h in tb.holders]
        out['holder_dir_bytes'] = [dir_bytes(h['data_dir']) for h in tb.holders]
        out['provider_dir_bytes_before'] = dir_bytes(A['cfg']['data_dir'])
        # ---------------- failure of provider A
        failure = case.get('failure', 'destroy')
        adir, sdir = A['cfg']['data_dir'], str(g.snd.retention)
        if failure == 'destroy':
            tb.kill(A['proc'])
            shutil.rmtree(adir)
            if (out.get('durable_check') or {}).get('durable'):
                shutil.rmtree(sdir)  # certified + slot check passed: the sender deleted its copy (release rule)
            out['deleted'] = {'provider_dir_exists': os.path.exists(adir), 'sender_copy_exists': os.path.exists(sdir)}
            assert not out['deleted']['provider_dir_exists']
        elif failure == 'refuse':  # A stays live but refuses reads -> recipient-side recovery from holders
            tb.admin('A', '/admin/fault', faults={'refuse_reads': True})
            rc0 = Recipient(tb.chain, tool, g.sk, g.addr, tb.dir / 'recipient-refused', [bytes(g.snd.notify_sk.verify_key).hex()])
            t0 = time.perf_counter()
            r0 = rc0.receive(rc0.load_notification(note['path']), T_r=30, recovery=True)
            out['refusal_read'] = {'ok': r0['ok'], 'via': r0.get('via'), 'attempts': r0['attempts'], 's': time.perf_counter() - t0}
            rc0.close()
            if not case.get('also_replace'):
                return out
            tb.kill(A['proc'])  # A is abandoned; a replacement A2 takes over its certified epochs
        if case.get('clear_holder_faults'):  # the faulty holder is repaired before A2 seals its own epochs
            for i in case.get('holder_faults_seal', {}):
                tb.holder_fault(int(i), {})
        for i, f in case.get('holder_faults_recovery', {}).items():
            tb.holder_fault(int(i), f)
        for i in case.get('holders_down', []):
            tb.kill(tb.holders[i]['name'])
        out['services_available'] = {'chain': True, 'holders_up': [h['i'] for h in tb.holders if h['name'] in tb.procs],
                                     'provider_A': 'refusing reads' if failure == 'refuse' else 'destroyed',
                                     'sender_copy': os.path.exists(sdir)}
        # ---------------- Replace(A -> A2): new key, new sid, empty sandboxed dir
        rdir = tb.dir / 'replacement-A2'
        forbidden = [adir, sdir, str(tb.dir / 'recipient-inbox')]
        t_start = time.perf_counter()
        adm_r = dict(ADM)
        if case.get('fresh_params'):  # replacement without the shared (public) Halo2 params cache
            adm_r['keys'] = str(tb.dir / 'replacement-halo2-keys')
        out['replacement_params'] = 'fresh (generated by the replacement)' if case.get('fresh_params') else f'cached ({KEYS})'
        # A2's OWN assignment (for the epochs it seals itself): A's current holders, with every holder that is dead or
        # faulty in this case replaced by a freshly started one (A2's choice; A's epochs are still fetched from A's
        # assignment, found through A's anchors).
        bad = set(case.get('holders_down', [])) | set(int(i) for i in case.get('holder_faults_recovery', {}))
        if not case.get('clear_holder_faults'):
            bad |= set(int(i) for i in case.get('holder_faults_seal', {}))
        idx2 = list(tb.holder_sets['A'])
        for c_, ix in enumerate(idx2):
            if ix in bad:
                tb.start_holder(len(tb.holders))
                idx2[c_] = len(tb.holders) - 1
        out['replacement_assignment'] = {'holders': idx2, 'replaced': sorted(bad & set(tb.holder_sets['A']))}
        svc2 = tb.register('A2', k=k, q=q, idx=idx2, continues='A')
        out['replacement_registration'] = {'start_epoch': svc2['start_epoch'], 'gas': tb.gas.get('register_A2'),
                                           'register_s': time.perf_counter() - t_start}
        R = tb.start_provider('A2', mode='replace', data_dir=rdir, forbidden_paths=forbidden, sandbox_deny=forbidden,
                              admission=adm_r, M_max=m, T_max=5, seal_retry_s=2, holder_timeout=case.get('holder_timeout', 60))
        out['replacement_start_s'] = time.perf_counter() - t_start
        out['sandbox_profile'] = R.get('sandbox_profile')
        sid2 = tb.services['A2']['sid']
        s, dt = wait_phase(tb, 'A2')
        out['recovery_wall_s'] = time.perf_counter() - t_start
        out['recovery'] = s['recovery']
        out['replacement_status'] = {k_: s[k_] for k_ in ('appends_enabled', 'records', 'tags', 'e_cur')}
        if out.get('pir_before') and not s['recovery'].get('temporarily_unrecoverable'):
            after = pir_digests(R['url'], en['e'])
            out['pir_after'] = after  # A2 serves under its own identity: seed from A2's sid (differs from A's)
        # ---------------- recipient comes online, reads (A2, e, j) and validates against A's notification
        rc = Recipient(tb.chain, tool, g.sk, g.addr, tb.dir / 'recipient-cache', [bytes(g.snd.notify_sk.verify_key).hex()])
        body = rc.load_notification(note['path'])
        out['notified'] = {'sid': body['entries'][0]['sid'], 'url': body['entries'][0]['url']}
        out['replacement'] = {'sid': sid2, 'url': R['url'], 'registry_url': resolve_endpoint(tb.chain, sid2)}
        t0 = time.perf_counter()
        rr = rc.receive(body, T_r=60, max_wait=30, policy='pir', recovery=case.get('recipient_recovery', False),
                        successors={sidA: sid2})
        out['read'] = {'ok': rr['ok'], 'via': rr.get('via'), 'attempts': rr['attempts'], 's': time.perf_counter() - t0}
        out['time_to_first_private_read_s'] = time.perf_counter() - t_start if rr['ok'] else None
        rc.close()
        if rr['ok']:
            out['read_matches_original'] = rr['cm'] == g.t['cm']
        # ---------------- tag set restored at A2: replay must not allocate; a lost record re-appends
        n0 = tb.status('A2')['tags']
        t_app = time.perf_counter()
        st, d, _ = append_raw(R['url'], sid2, g.prep)
        out['replay'] = {'status': st, 'outcome': d.get('outcome'), 'e': d.get('e'), 'j': d.get('j'), 'sid': d.get('sid'),
                         'same_e_j': (d.get('e'), d.get('j')) == (en['e'], en['j']),
                         'tags_before': n0, 'tags_after': tb.status('A2')['tags'],
                         'first_append_s': time.perf_counter() - t_app,
                         'first_append_since_replacement_start_s': time.perf_counter() - t_start}
        if not rr['ok'] and os.path.exists(sdir) and st == 200 and d.get('outcome') == 'new':
            t0 = time.perf_counter()
            en2 = {'name': 'A2', 'sid': d['sid'], 'url': R['url'], 'e': d['e'], 'j': d['j'], 'd_rec': d['d_rec'], 'receipt': d['receipt']}
            note2 = g.snd.notify(tb.dir / 'recipient-inbox2', [en2], g.t['cm'], g.t['tx']['block'])
            rc2 = Recipient(tb.chain, tool, g.sk, g.addr, tb.dir / 'recipient-cache2', [bytes(g.snd.notify_sk.verify_key).hex()])
            r2 = rc2.receive(rc2.load_notification(note2['path']), T_r=60, max_wait=60, policy='pir')
            rc2.close()
            out['reappend_read'] = {'ok': r2['ok'], 'attempts': r2['attempts'], 's': time.perf_counter() - t0,
                                    'note': 'sender re-appended its retained rec (uncertified at failure) to A2'}
            t0 = time.perf_counter()
            try:
                tb.wait_state('A2', en2['e'], ('certified',), timeout=case.get('recert_timeout', 120))
                out['reappend_certified'] = True
            except TimeoutError:
                out['reappend_certified'] = False
            out['reappend_certify_s'] = time.perf_counter() - t0
            rel = g.snd.try_release([en2], g.prep['rec'])
            out['reappend_release'] = {'released': rel['released'], 'checks': rel['checks'],
                                       'sender_copy_exists_after': os.path.exists(Path(sdir) / f"{g.prep['nu']}.rec")}
        # ---------------- a fresh genuine append at A2 and A2's own first epoch (last_A + 1)
        if tb.status('A2')['appends_enabled'] and not case.get('skip_fresh'):
            try:
                g2 = genuine(tb, prover, tool, tb.dir / 'sender2-retained')
                t0 = time.perf_counter()
                ap2 = g2.snd.append([tb.pdesc('A2')], g2.prep, r=1, T_w=120)
                en3 = ap2['entries'][0] if ap2['complete'] else None
                fresh = {'append_ok': bool(en3), 'e': en3 and en3['e'], 'start_epoch': svc2['start_epoch']}
                if en3:
                    tb.wait_state('A2', en3['e'], ('certified',), timeout=180)
                    fresh['certified_s'] = time.perf_counter() - t0
                    fresh['anchors_A2'] = tb.chain.call('list_anchors', sid='0x' + sid2)
                    fresh['first_A2_anchor_is_start'] = bool(fresh['anchors_A2']) and fresh['anchors_A2'][0] == svc2['start_epoch']
                    fresh['durable'] = g2.snd.check_durable(en3, g2.prep['rec']).get('durable')
                out['fresh_epoch'] = fresh
            except Exception as exc:
                out['fresh_epoch'] = {'error': f'{type(exc).__name__}: {exc}'}
        out['replacement_dir_bytes'] = dir_bytes(rdir)
        out['isolation'] = s['recovery'].get('isolation')
    except Exception as exc:
        out['error'] = f'{type(exc).__name__}: {exc}'
        out['trace'] = traceback.format_exc()
    finally:
        tb.close()
    out['observed'] = observed(out)
    out['pass'] = judge(case.get('expect', {}), out['observed'])
    return out


def observed(r: dict) -> dict:
    rec = r.get('recovery') or {}
    return {'error': r.get('error'), 'certified': r.get('certified'),
            'durable_at_A': (r.get('durable_check') or {}).get('durable'),
            'read_ok': (r.get('read') or {}).get('ok'), 'read_via': (r.get('read') or {}).get('via'),
            'refusal_read_ok': (r.get('refusal_read') or {}).get('ok'),
            'recovery_phase': rec.get('phase'), 'unrecoverable': bool(rec.get('temporarily_unrecoverable')),
            'replay': (r.get('replay') or {}).get('outcome'),
            'reappend_certified': r.get('reappend_certified'),
            'reappend_released': (r.get('reappend_release') or {}).get('released'),
            'fresh_first_anchor_is_start': (r.get('fresh_epoch') or {}).get('first_A2_anchor_is_start')}


def judge(expect: dict, obs: dict) -> bool:
    if obs.get('error'):
        return False
    return all(obs.get(k) == v for k, v in expect.items())


def make_cases(k, n, q) -> dict:
    """Case set for thresholds (k, n, q). f_r = q - k, f_w = n - q."""
    th = check_thresholds(k, n, q)
    fr, fw = th['f_r'], th['f_w']
    ok = {'certified': True, 'read_ok': True, 'replay': 'idempotent', 'fresh_first_anchor_is_start': True}
    lost = {'certified': False, 'read_ok': False, 'replay': 'new', 'reappend_certified': True, 'reappend_released': True}
    C = {
        'ok5': {'desc': f'certified; A + sender copy destroyed; {n}/{n} holders', 'expect': ok},
        'ok4': {'desc': f'certified; {n - 1}/{n} holders (holder 1 killed)', 'holders_down': [0], 'expect': ok},
        'ok3': {'desc': f'certified; exactly k={k} of {n} holders (n-k killed)', 'holders_down': list(range(n - k)), 'expect': ok},
        'fail2': {'desc': f'certified; only k-1={k - 1} holders -> temporarily unrecoverable', 'holders_down': list(range(n - k + 1)),
                  'recipient_recovery': True,
                  'expect': {'certified': True, 'read_ok': False, 'unrecoverable': True, 'recovery_phase': 'read_only_partial'}},
        'corrupt1': {'desc': '1 corrupted fragment, others honest -> recovers from the honest ones',
                     'holder_faults_recovery': {0: {'corrupt_fragment': True}}, 'expect': ok},
        'corrupt3': {'desc': f'n-k+1={n - k + 1} holders return corrupted fragments (k-1 honest) -> must not recover',
                     'holder_faults_recovery': {i: {'corrupt_fragment': True} for i in range(n - k + 1)},
                     'expect': {'certified': True, 'read_ok': False, 'unrecoverable': True}},
        'offcode': {'desc': f'n-k+1 holders serve canonical off-codeword fragments -> must not recover',
                    'holder_faults_recovery': {i: {'off_codeword': True} for i in range(n - k + 1)},
                    'expect': {'certified': True, 'read_ok': False, 'unrecoverable': True}},
        'dupcoord': {'desc': f'n-k+1 holders claim coordinate 1 (duplicate coordinate) -> must not recover',
                     'holder_faults_recovery': {i: {'dup_coord': 1} for i in range(1, n - k + 2)},
                     'expect': {'certified': True, 'read_ok': False, 'unrecoverable': True}},
        'badack': {'desc': f'n-q+1={n - q + 1} holders return invalid acks at sealing -> never certified; record lost at A',
                   'holder_faults_seal': {i: {'invalid_ack': True} for i in range(2, 2 + n - q + 1)}, 'cert_timeout': 20,
                   'clear_holder_faults': True, 'expect': lost},
        'inconsistent': {'desc': 'A sends holder n an off-codeword fragment (whole_epoch: hashes of a non-codeword) -> '
                         f"holder n refuses; {'certified with n-1 >= q acks' if n - 1 >= q else 'never certified'}",
                         'provider_faults_seal': {'inconsistent_encoding': True}, 'cert_timeout': 20,
                         'expect': ok if n - 1 >= q else lost},
        'precert': {'desc': 'A destroyed BEFORE certification (open epoch) -> record lost; sender re-appends to A2',
                    'kill_before_cert': True, 'expect': dict(lost, certified=False)},
        'dropped': {'desc': 'A drops the receipted record from the sealed epoch -> slot check fails; sender keeps rec and '
                    're-appends to A2', 'drop_genuine': True,
                    'expect': {'certified': True, 'durable_at_A': False, 'read_ok': False, 'replay': 'new',
                               'reappend_certified': True, 'reappend_released': True}},
        'refuse': {'desc': 'A live but refuses reads -> recipient-side recovery from holders, then Replace(A -> A2)',
                   'failure': 'refuse', 'also_replace': True, 'expect': dict(ok, refusal_read_ok=True)},
        'holder_replaced': {'desc': f'n-q+1={n - q + 1} holders permanently lost before sealing -> stuck; A installs a new '
                            'assignment with new holders -> certified; then A + sender copy destroyed, recovery from the '
                            'NEW assignment', 'holder_faults_seal': {i: {'offline': True} for i in range(n - q + 1)},
                            'cert_timeout': 20, 'replace_holders': list(range(n - q + 1)), 'expect': ok},
        'silent_fw': {'desc': f'f_w={fw} holders offline at sealing (certified with q acks); then f_r={fr} acknowledged '
                      'holders killed -> exactly k acknowledged fragments remain',
                      'holder_faults_seal': {i: {'offline': True} for i in range(n - fw, n)},
                      'holders_down': list(range(fr)), 'expect': ok},
        'ok5_fresh': {'desc': 'as ok5, A2 starts WITHOUT the Halo2 params cache', 'fresh_params': True, 'expect': ok},
        'sweep1': {'desc': 'epoch-count sweep: 1 epoch of 16', 'm_e': 16, 'pos': 8, 'epochs': 1, 'expect': ok},
        'sweep10': {'desc': 'epoch-count sweep: 10 epochs of 16', 'm_e': 16, 'pos': 8, 'epochs': 10, 'expect': ok},
        'sweep100': {'desc': 'epoch-count sweep: 100 epochs of 16', 'm_e': 16, 'pos': 8, 'epochs': 100, 'cert_timeout': 900,
                     'expect': ok},
        'ok5_65536': {'desc': '2^16 records, all holders', 'm_e': 65536, 'cert_timeout': 900, 'expect': ok},
    }
    for cid, c in C.items():
        c['id'] = cid
    return C


DEFAULT_CASES = ('ok5,ok4,ok3,fail2,corrupt1,corrupt3,offcode,dupcoord,badack,inconsistent,precert,dropped,refuse,'
                 'holder_replaced,silent_fw,ok5_fresh,sweep1,sweep10,sweep100')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cases', default=DEFAULT_CASES)
    ap.add_argument('--reps', type=int, default=5, help='repetitions of the principal case ok5')
    ap.add_argument('--k', type=int, default=3)
    ap.add_argument('--n', type=int, default=5)
    ap.add_argument('--q', type=int, default=None, help='default n')
    ap.add_argument('--seal-mode', default='fragment_kzg', choices=('fragment_kzg', 'whole_epoch'))
    ap.add_argument('--m-e', type=int, default=4096, help='records per principal epoch (sweeps use 16)')
    ap.add_argument('--label', default='', help='free-text label stored in the raw file (e.g. "correctness smoke")')
    args = ap.parse_args()
    q = args.n if args.q is None else args.q
    th = check_thresholds(args.k, args.n, q)
    cfg = {'k': args.k, 'n': args.n, 'q': q, 'f_r': th['f_r'], 'f_w': th['f_w'], 'seal_mode': args.seal_mode, 'm_e': args.m_e}
    CASES = make_cases(args.k, args.n, q)
    require_real_binaries()
    ts = time.strftime('%Y%m%d-%H%M%S')
    outdir = CORE / 'results/E2' / f'{ts}-k{args.k}n{args.n}q{q}-{args.seal_mode}'
    outdir.mkdir(parents=True)
    quiet = wait_quiet()
    raw = {'meta': metadata(dict(cfg, cases=args.cases, reps_ok5=args.reps, label=args.label, depth=32,
                                 background='bulk-loaded synthetic records (no admission), disclosed; 1 genuine record per case',
                                 isolation='replacement A2: new key/sid, empty dir + sandbox-exec deny profile + deletion '
                                           'check + open-files scan',
                                 same_host='all holders and providers are processes on ONE host (one fault domain)')),
           'results': []}
    raw['meta']['quiet_wait'] = quiet
    prover = Admission('prover', 32, 'full', KEYS)
    raw['prover_info'] = prover.info()
    tool = Admission('tool', 32)
    try:
        for cid in args.cases.split(','):
            reps = args.reps if cid == 'ok5' else 1
            for rep in range(reps):
                t0 = time.time()
                r = run_case(CASES[cid], cfg, prover, tool, rep)
                r['wall_s'] = time.time() - t0
                raw['results'].append(r)
                print(cid, rep, 'PASS' if r['pass'] else 'FAIL', 'read_ok' if (r.get('read') or {}).get('ok') else 'read_FAIL',
                      r.get('error', ''), f"{r['wall_s']:.0f}s", flush=True)
                (outdir / 'e2_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    finally:
        prover.close()
        tool.close()
        finish_load(raw['meta'])
        raw['summary'] = {'cases': len(raw['results']), 'pass': sum(1 for r in raw['results'] if r['pass']),
                          'fail': [f"{r['case']['id']}#{r['rep']}" for r in raw['results'] if not r['pass']]}
        (outdir / 'e2_raw.json').write_text(json.dumps(raw, indent=1, default=str))
    print('wrote', outdir / 'e2_raw.json', json.dumps(raw['summary']))


if __name__ == '__main__':
    main()
