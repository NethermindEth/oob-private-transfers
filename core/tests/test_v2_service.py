"""Protocol-v2 service tests on real processes (Anvil + contracts, provider, 8+ holders), (k, n, q) = (4, 8, 6):
f_r = 2, f_w = 2. Seal mode from $OOB_SEAL_MODE (default fragment_kzg); run_e4svc.py runs both modes.

Records here are DISCLOSED synthetic records (provider /admin/bulk_load, reproduced locally from the same seed); the
"sender" release checks use them as the sender's retained copy (release needs only Certified + slot check, not
admission). Genuine admission-proved records are exercised by test_e4_service.py. Same-host processes: one fault
domain; these tests check implementation behaviour, not cryptographic security.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.paths import HALO_KEYS
import json
import os
import random
import shutil
import subprocess
import time

import pytest

from core.oobsvc.common import FIELD, HALO_BIN, PIR_BIN, Chain, WorkerError, canon, get_json, http, post_json
from core.oobsvc.certify import certified, current_assignment, registry_at
from core.oobsvc.client import Sender
from core.oobsvc.deploy import GOV, OPS, Testbed
from core.oobsvc.epoch import assignment_of, build_manifest
from core.oobsvc.recovery import recipient_recover

KEYS = str(HALO_KEYS)
ADM = {'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}
pytestmark = pytest.mark.skipif(not (HALO_BIN.exists() and PIR_BIN.exists()), reason='real workers not built')
K, N, Q = 4, 8, 6
M = 8  # records per epoch (M_max)


def synth(seed, count):
    """The provider's bulk_load generator (same seed -> same records)."""
    rng = random.Random(seed)
    return [b''.join(rng.randrange(FIELD).to_bytes(32, 'big') for _ in range(23)) for _ in range(count)]


def wait(pred, timeout, what):
    t0 = time.time()
    while True:
        v = pred()
        if v:
            return v
        assert time.time() - t0 < timeout, f'timeout: {what}'
        time.sleep(0.2)


class Env:
    pass


@pytest.fixture(scope='module')
def T():
    ts = time.strftime('%Y%m%d-%H%M%S')
    tb = Testbed(f'V2svc-{ts}-{os.getpid()}', block_time=1, n_holders=N)
    E = Env()
    E.tb = tb
    try:
        tb.register('A', k=K, q=Q)
        E.A = tb.start_provider('A', M_max=M, T_max=600, seal_retry_s=1, holder_timeout=5, admission=ADM)
        E.sid = tb.services['A']['sid']
        E.snd = Sender(tb.chain, None, 0, tb.dir / 'sender-retained')
        E.recs = {}
        yield E
    finally:
        tb.close()


def load_epoch(E, seed, name='A'):
    """Bulk-load one full epoch (M records) and return (e, records)."""
    e = E.tb.status(name)['e_cur']
    E.tb.admin(name, '/admin/bulk_load', count=M, seed=seed)
    recs = synth(seed, M)
    E.recs[(name, e)] = recs
    return e, recs


def entry(E, e, j, name='A'):
    p = E.tb.providers[name]
    return {'name': name, 'sid': E.tb.services[name]['sid'], 'url': p['url'], 'e': e, 'j': j}


def epoch_metrics(E, e, name='A'):
    return {x['e']: x for x in E.tb.status(name)['epochs']}[e]['metrics']


def test_registry_rejects_invalid_configurations(T):
    tb = T.tb
    keys = ['0x' + h['key'] for h in tb.holders]
    urls = [h['url'] for h in tb.holders]
    reg = lambda **kw: tb.chain.call('register', **{'from': GOV['C']}, op_key='0x' + '11' * 32, endpoint='x',
                                     **dict(dict(holder_keys=keys, holder_urls=urls, k=4, q=6), **kw))
    for b, msg in [(dict(k=4, q=9), 'q > n'), (dict(k=4, q=3), 'q < k'), (dict(k=0, q=0), 'k < 1'), (dict(k=9, q=9), 'q > n'),
                   (dict(holder_keys=keys[:3] + keys[:1], holder_urls=urls[:4], k=2, q=3), 'distinct'),
                   (dict(holder_urls=urls[:3]), 'urls length'), (dict(holder_keys=[], holder_urls=[], k=1, q=1), 'n out of range'),
                   (dict(start_epoch=5), 'fresh provider starts at epoch 0'),
                   (dict(continues='0x' + '33' * 32, start_epoch=5), 'continued provider not registered')]:
        with pytest.raises(WorkerError, match=msg):
            reg(**b)
    with pytest.raises(WorkerError, match="only the provider's own account"):
        tb.chain.call('set_assignment', **{'from': OPS['A']}, sid='0x' + T.sid, holder_keys=keys, holder_urls=urls, k=4, q=6)
    with pytest.raises(WorkerError, match='q > n'):
        tb.chain.call('set_assignment', **{'from': GOV['A']}, sid='0x' + T.sid, holder_keys=keys, holder_urls=urls, k=4, q=9)
    with pytest.raises(WorkerError, match='unknown holder'):
        tb.chain.call('set_holder_endpoint', **{'from': GOV['A']}, sid='0x' + T.sid, holder_key='0x' + '22' * 32, url='x')
    reg = registry_at(tb.chain, T.sid, tb.chain.finalized_height())
    a = current_assignment(reg)
    assert (a['version'], a['k'], a['n'], a['q']) == (0, K, N, Q)


def test_certification_with_n_minus_q_nonresponders(T):
    """f_w = n - q = 2 holders offline while sealing: q = 6 valid acks certify the epoch."""
    tb = T.tb
    tb.holder_fault(6, {'offline': True})
    tb.holder_fault(7, {'offline': True})
    try:
        e, _ = load_epoch(T, 100)
        tb.wait_state('A', e, ('certified',), timeout=120)
    finally:
        tb.holder_fault(6, {})
        tb.holder_fault(7, {})
    c = certified(tb.chain, T.sid, e)
    assert c['certified'], c
    assert sorted(a['i'] for a in c['cert']['acks']) == [1, 2, 3, 4, 5, 6]
    m = epoch_metrics(T, e)
    assert m['valid_acks'] == Q and sorted(f['i'] for f in m['seal_failures']) == [7, 8]
    assert m['seal_mode'] == tb.seal_mode and (m['k'], m['n'], m['q']) == (K, N, Q)
    T.e_partial = e  # coordinates 7, 8 hold nothing for this epoch


def test_fewer_than_q_acks_not_certified(T):
    """n - q + 1 = 3 nonresponders (two offline, one silent past the provider's 5 s timeout): 5 < q acks, the epoch
    stays uncertified (no anchor) and is retried; after one holder returns it is certified."""
    tb = T.tb
    tb.holder_fault(5, {'silent_s': 8})
    tb.holder_fault(6, {'offline': True})
    tb.holder_fault(7, {'offline': True})
    try:
        e, _ = load_epoch(T, 101)
        wait(lambda: epoch_metrics(T, e).get('seal_attempts', 0) >= 2, 120, 'two seal attempts')
        m = epoch_metrics(T, e)
        st = {x['e']: x for x in tb.status('A')['epochs']}[e]['state']
        assert st == 'read_ready' and m['valid_acks'] == Q - 1, (st, m.get('valid_acks'))
        assert tb.chain.call('get_anchor', sid='0x' + T.sid, e=e)['block'] == 0
        assert not certified(tb.chain, T.sid, e)['certified']
        assert any('timed out' in (f.get('error') or '') for f in m['seal_failures']), m['seal_failures']
    finally:
        tb.holder_fault(5, {})
        tb.holder_fault(6, {})
    tb.wait_state('A', e, ('certified',), timeout=120)
    tb.holder_fault(7, {})
    c = certified(tb.chain, T.sid, e)
    assert c['certified'] and len(c['cert']['acks']) >= Q
    T.e_full = e


def test_recovery_exactly_k_valid_and_k_minus_1(T):
    """Reconstruction by a node holding no fragment (this test process): with exactly k = 4 reachable acknowledged
    coordinates it succeeds; with k - 1 it reports 'temporarily unrecoverable' and returns nothing."""
    tb = T.tb
    e = T.e_partial  # acked by 1..6; 7 and 8 hold no fragment
    for i in (0, 1):
        tb.holder_fault(i, {'offline': True})  # f_r = q - k = 2 acknowledged coordinates fail
    try:
        for pol in ('all', 'minimal'):
            recs, m = recipient_recover(tb.chain, T.sid, e, policy=pol)
            assert recs == T.recs[('A', e)], m.get('reason')
            assert m['valid_fragments'] == [3, 4, 5, 6] and m['needed_decode']
        tb.holder_fault(2, {'offline': True})
        recs, m = recipient_recover(tb.chain, T.sid, e)
        assert recs is None and 'temporarily unrecoverable' in m['reason'] and m['valid_fragments'] == [4, 5, 6]
    finally:
        for i in (0, 1, 2):
            tb.holder_fault(i, {})
    recs, m = recipient_recover(tb.chain, T.sid, e, policy='minimal')
    assert recs == T.recs[('A', e)] and m['coordinates_asked'] == [1, 2, 3, 4] and not m['needed_decode']


def test_byzantine_fragments_rejected(T):
    """Holders serving off-codeword (canonical, with a matching self-reported hash), bit-flipped or relabeled
    fragments are rejected by the reader's fragment check; the rest decode the epoch. With only k-1 honest ones,
    nothing is returned."""
    tb = T.tb
    e = T.e_full
    bad = {0: {'off_codeword': True}, 1: {'corrupt_fragment': True}, 2: {'dup_coord': 4}}
    for i, f in bad.items():
        tb.holder_fault(i, f)
    try:
        recs, m = recipient_recover(tb.chain, T.sid, e)
        assert recs == T.recs[('A', e)], m.get('reason')
        assert sorted(r['i'] for r in m['rejected']) == [1, 2, 3], m['rejected']
        why = {r['i']: r['why'] for r in m['rejected']}
        if tb.seal_mode == 'fragment_kzg':
            assert 'off the committed codeword' in why[1]
        tb.holder_fault(3, {'off_codeword': True})
        tb.holder_fault(4, {'off_codeword': True})
        recs, m = recipient_recover(tb.chain, T.sid, e)
        assert recs is None and 'temporarily unrecoverable' in m['reason']
    finally:
        for i in range(5):
            tb.holder_fault(i, {})


def test_release_after_slot_check_and_from_holder_when_provider_withholds(T):
    tb = T.tb
    e = T.e_full
    recs = T.recs[('A', e)]
    for j in (0, M - 1):
        r = T.snd.check_durable(entry(T, e, j), recs[j])
        assert r['durable'] and r['via'] == 'provider', r
    tb.admin('A', '/admin/fault', faults={'withhold_openings': True})
    try:
        r = T.snd.check_durable(entry(T, e, 3), recs[3])
        assert r['durable'] and r['via'] == 'holder', r
    finally:
        tb.admin('A', '/admin/fault', faults={})
    assert not T.snd.check_durable(entry(T, e, 3), recs[4])['durable']  # wrong record at that slot


def test_release_refused_when_committed_epoch_omits_record(T):
    """The provider receipted a record but commits to an epoch without it (App. B.3 iii): the epoch is certified,
    but the slot check for (j, rec) fails, so the sender keeps its copy."""
    tb = T.tb
    seed = 102
    recs = synth(seed, M)
    victim = 2
    tb.admin('A', '/admin/fault', faults={'drop_record_on_seal': [recs[victim][:32].hex()]})
    try:
        e, _ = load_epoch(T, seed)
        tb.wait_state('A', e, ('certified',), timeout=120)
    finally:
        tb.admin('A', '/admin/fault', faults={})
    c = certified(tb.chain, T.sid, e)
    assert c['certified'] and c['manifest']['m_e'] == M - 1
    (T.snd.retention / 'victim.rec').write_bytes(recs[victim])
    rel = T.snd.try_release([entry(T, e, victim)], recs[victim])
    assert rel['released'] is False, rel
    assert (T.snd.retention / 'victim.rec').exists()
    assert T.snd.check_durable(entry(T, e, victim), recs[victim + 1])['durable']  # slot 2 now holds the next record


def test_manifest_with_stale_assignment_refused(T):
    """I6: after P installs assignment gamma = 1, a manifest pinning gamma = 0 (validly signed by P's key) is refused by
    holders; the provider seals the next epoch under gamma = 1."""
    from nacl.signing import SigningKey
    tb = T.tb
    r = tb.set_assignment('A', list(range(N)), k=K, q=Q)  # same identities, new version
    tb.chain.wait_final(r['block'])
    fin = tb.chain.finalized_height()
    reg = registry_at(tb.chain, T.sid, fin)
    assert current_assignment(reg)['version'] == 1
    old = assignment_of(reg['assignments'][0])
    sk = SigningKey(bytes.fromhex(tb.services['A']['operator_sk']))
    e = 10 ** 6
    man, frags, aux = build_manifest(sk, bytes.fromhex(T.sid), e, synth(7, 3), old, tb.seal_mode)
    hdr = canon({'sid': T.sid, 'e': e, 'manifest': man})
    body = len(hdr).to_bytes(8, 'big') + hdr + (aux['ser'] if tb.seal_mode == 'whole_epoch' else frags[0])
    st, raw = http('POST', tb.holders[0]['url'] + '/seal', body, 'application/octet-stream', timeout=60)
    assert st == 422 and 'assignment version' in json.loads(raw)['error'], raw[:300]
    e2, _ = load_epoch(T, 103)
    tb.wait_state('A', e2, ('certified',), timeout=120)
    c = certified(tb.chain, T.sid, e2)
    assert c['certified'] and c['manifest']['gamma'] == 1 and c['gamma'] == 1
    assert certified(tb.chain, T.sid, T.e_full)['manifest']['gamma'] == 0  # old epochs keep their assignment


def test_endpoint_move_old_epoch_recovered(T):
    """I7: holder identity 1 moves to a new endpoint. Before P updates its endpoint record, recovery cannot
    reach coordinate 1; afterwards it can (same identity and coordinate, for an epoch certified before the move)."""
    tb = T.tb
    e = T.e_full
    old_url = tb.holders[0]['url']
    tb.move_holder(0)
    assert tb.holders[0]['url'] != old_url
    recs, m = recipient_recover(tb.chain, T.sid, e)
    assert recs == T.recs[('A', e)]
    assert {r['i']: r['status'] for r in m['holder_responses']}[1] == 0  # old endpoint is dead
    r = tb.set_holder_endpoint('A', 0)
    tb.chain.wait_final(r['block'])
    c = certified(tb.chain, T.sid, e)
    assert c['holders'][0]['url'] == tb.holders[0]['url'] and c['gamma'] == 0
    recs, m = recipient_recover(tb.chain, T.sid, e)
    assert recs == T.recs[('A', e)] and {r['i']: r['status'] for r in m['holder_responses']}[1] == 200
    # the endpoint record changed; the assignment (identities, thresholds) did not
    reg = registry_at(tb.chain, T.sid, tb.chain.finalized_height())
    assert len(reg['assignments']) == 2


def test_discovery_without_event_logs(T):
    """I8: manifest + certificate from holders, authenticated by the hashes in contract state; a chain worker whose
    event-log reads are disabled falls back automatically."""
    tb = T.tb
    e = T.e_full
    c = certified(tb.chain, T.sid, e, meta_source='holders')
    assert c['certified'] and c['meta_source'] == 'holders'
    os.environ['OOB_NO_EVENT_LOGS'] = '1'  # inherited by this chain worker only
    try:
        ch = Chain(tb.rpc, tb.addresses)
    finally:
        del os.environ['OOB_NO_EVENT_LOGS']
    try:
        with pytest.raises(WorkerError, match='event logs unavailable'):
            ch.call('anchor_data', sid='0x' + T.sid, e=e)
        c2 = certified(ch, T.sid, e)
        assert c2['certified'] and c2['meta_source'] == 'holders'
        recs, m = recipient_recover(ch, T.sid, e)
        assert recs == T.recs[('A', e)] and m['meta_source'] == 'holders'
    finally:
        ch.close()


def test_equivocating_manifests_holder_keeps_one(T):
    """I1/App. B.3 (v): P sends two different validly signed manifests for the same unanchored (sid, e) under the same
    assignment: a holder stores the first and refuses the second (409), so it acknowledges at most one."""
    from nacl.signing import SigningKey
    tb = T.tb
    fin = tb.chain.finalized_height()
    reg = registry_at(tb.chain, T.sid, fin)
    cur = assignment_of(current_assignment(reg))
    sk = SigningKey(bytes.fromhex(tb.services['A']['operator_sk']))
    e = 10 ** 6 + 7
    replies = []
    for seed in (21, 22):
        man, frags, aux = build_manifest(sk, bytes.fromhex(T.sid), e, synth(seed, 3), cur, tb.seal_mode)
        hdr = canon({'sid': T.sid, 'e': e, 'manifest': man})
        body = len(hdr).to_bytes(8, 'big') + hdr + (aux['ser'] if tb.seal_mode == 'whole_epoch' else frags[0])
        st, raw = http('POST', tb.holders[0]['url'] + '/seal', body, 'application/octet-stream', timeout=60)
        replies.append((st, json.loads(raw)))
    assert replies[0][0] == 200 and 'ack' in replies[0][1], replies[0]
    assert replies[1][0] == 409 and 'different manifest' in replies[1][1]['error'], replies[1]


def test_independent_service_lacking_payload_cannot_satisfy_retrieval(T):
    """A healthy, independent provider C that never received the record cannot satisfy a read of A's locator: whatever
    it serves at (e, j) fails the digest check against the notified d_rec (and C's recipient-side recovery returns
    C's epoch, which does not contain it)."""
    from core.oobsvc.client import ReadFailure, Recipient
    from core.oobsvc.common import d_rec
    tb = T.tb
    e = T.e_full
    rec = T.recs[('A', e)][3]
    tb.register('C', k=K, q=Q)
    tb.start_provider('C', M_max=M, T_max=600, seal_retry_s=1, holder_timeout=5, admission=ADM)
    sidC = tb.services['C']['sid']
    for _ in range(e + 1):  # C's epochs 0..e hold other records
        eC = tb.status('C')['e_cur']
        tb.admin('C', '/admin/bulk_load', count=M, seed=900 + eC)
    tb.wait_state('C', e, ('certified',), timeout=180)
    rc = Recipient(tb.chain, None, None, None, tb.dir / 'rc-C', [])
    en = {'name': 'C', 'sid': T.sid, 'e': e, 'j': 3, 'd_rec': d_rec(rec).hex(), 'receipt': {'sig': '00' * 64}}
    en = rc.resolve(en, successors={T.sid: sidC})  # the harness points the locator at the wrong provider
    assert en['url'] == tb.providers['C']['url']
    with pytest.raises(ReadFailure, match='digest mismatch'):
        rc.read_entry(en, T_r=30, max_wait=30, policy='download')
    recs, m = recipient_recover(tb.chain, sidC, e)
    assert recs is not None and rec not in recs
    rc.close()


def test_replace_rebuilds_certified_epochs(T):
    """Replace(A -> A2): A loses its storage; A2 (own key and sid, "continues A", empty storage) rebuilds every
    certified (non-void) epoch of A from A's anchors + holders at the same (e, j) (records byte-identical, tags
    restored), serves them under its own identity (PIR seed from A2's sid), enables appends, and seals + certifies its
    own first epoch last_A + 1 under its own anchors."""
    tb = T.tb
    anchored = tb.chain.call('list_anchors', sid='0x' + T.sid, height=tb.chain.finalized_height())
    adir = tb.providers['A']['cfg']['data_dir']
    tb.kill(tb.providers['A']['proc'])
    shutil.rmtree(adir)
    tb.register('A2', k=K, q=Q, continues='A')
    for bad_e in (0, max(anchored), max(anchored) + 2):  # A2's first anchor must be last_A + 1 (EpochAnchor)
        with pytest.raises(WorkerError, match='consecutive'):
            tb.chain.call('anchor', **{'from': tb.services['A2']['op_eoa_index']}, sid='0x' + tb.services['A2']['sid'],
                          e=bad_e, manifest='0x01', cert='0x01')
    R = tb.start_provider('A2', mode='replace', forbidden_paths=[adir], admission=ADM, M_max=M, T_max=600,
                          seal_retry_s=1, holder_timeout=5)
    wait(lambda: tb.status('A2')['recovery'].get('phase') in ('complete', 'read_only_partial', 'failed', 'isolation_violation'),
         180, 'A2 recovery')
    rs = tb.status('A2')
    assert rs['recovery']['phase'] == 'complete' and rs['appends_enabled'], rs['recovery']
    assert rs['recovery']['mode'] == 'replace' and rs['e_cur'] == max(anchored) + 1
    assert sorted(rs['recovery']['anchored_epochs']) == sorted(anchored)
    sid2 = tb.services['A2']['sid']
    for (name, e), recs in T.recs.items():
        if name != 'A' or e not in anchored:
            continue
        st, data = http('GET', f"{R['url']}/epoch/{e}")
        c = certified(tb.chain, T.sid, e)
        got = [data[i * 736:(i + 1) * 736] for i in range(len(data) // 736)]
        assert st == 200 and got == c_records(c, recs), e
        st, pub = http('GET', f"{R['url']}/pir/public/{e}")
        from core.oobsvc.provider import seed_A
        assert json.loads(pub)['seed_A'] == seed_A(bytes.fromhex(sid2), e).hex()
    T.sid, T.A = sid2, R
    e_new = tb.status('A2')['e_cur']
    tb.admin('A2', '/admin/bulk_load', count=M, seed=104)
    tb.wait_state('A2', e_new, ('certified',), timeout=120)
    c = certified(tb.chain, sid2, e_new)
    assert c['certified'] and e_new == max(anchored) + 1
    assert tb.chain.call('list_anchors', sid='0x' + sid2) == [e_new]
    assert not certified(tb.chain, sid2, anchored[0])['certified']  # old epochs stay certified by A's anchors only
    assert certified(tb.chain, tb.services['A']['sid'], anchored[0])['certified']


def c_records(c, recs):
    """Records the certified epoch contains (the omission test dropped one)."""
    if c['manifest']['m_e'] == len(recs):
        return recs
    return [r for r in recs if r != recs[2]]
