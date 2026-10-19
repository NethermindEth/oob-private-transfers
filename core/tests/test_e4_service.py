"""E4 service-level adversarial regressions against the REAL provider process (Rust verifier, Go PIR, Anvil).

Checks byte-level DB allocation (row counts, slot contents), not only HTTP codes. These tests check implementation
behaviour; they do not prove zero knowledge, privacy or unforgeability.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.paths import HALO_KEYS
import copy
import json
import os
import shutil
import sqlite3
import threading
import time

import pytest

from core.oobsvc.common import FIELD, HALO_BIN, PIR_BIN, b64, canon, d_rec, fe_hex, http, post_json, split_rec, make_rec
from core.oobsvc.client import Address, Recipient, Sender, check_receipt, make_address
from core.oobsvc.deploy import ACCT_SENDER, Testbed
from core.oobsvc.workers import Admission

KEYS = str(HALO_KEYS)
pytestmark = pytest.mark.skipif(not (HALO_BIN.exists() and PIR_BIN.exists()), reason='real workers not built')


def db_rows(data_dir):
    c = sqlite3.connect(f'file:{data_dir}/provider.sqlite3?mode=ro', uri=True)
    try:
        return {t: c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ('tags', 'records', 'receipts')}, c
    except Exception:
        c.close()
        raise


def counts(data_dir):
    n, c = db_rows(data_dir)
    c.close()
    return n


def slot(data_dir, tag_hex):
    c = sqlite3.connect(f'file:{data_dir}/provider.sqlite3?mode=ro', uri=True)
    r = c.execute('SELECT t.e, t.j, r.rec, rc.sig FROM tags t JOIN records r ON r.e=t.e AND r.j=t.j '
                  'LEFT JOIN receipts rc ON rc.tag=t.tag WHERE t.tag=?', (bytes.fromhex(tag_hex),)).fetchall()
    c.close()
    return r


def seal_body(tb, sk, sid, e, recs):
    """A seal request as a (possibly Byzantine) operator would send it, for the testbed's seal mode and the
    assignment current at the finalized height. Returns (manifest, per-holder bodies)."""
    from core.oobsvc.certify import current_assignment, registry_at
    from core.oobsvc.epoch import assignment_of, build_manifest
    fin = tb.chain.finalized_height()
    asg = current_assignment(registry_at(tb.chain, sid.hex(), fin))
    man, frags, aux = build_manifest(sk, sid, e, recs, assignment_of(asg), tb.seal_mode)
    hdr = canon({'sid': sid.hex(), 'e': e, 'manifest': man})
    head = len(hdr).to_bytes(8, 'big') + hdr
    if tb.seal_mode == 'whole_epoch':
        return man, [head + aux['ser']] * len(frags)
    return man, [head + f for f in frags]


class Env:
    pass


@pytest.fixture(scope='module')
def env():
    ts = time.strftime('%Y%m%d-%H%M%S')
    tb = Testbed(f'E4svc-{ts}-{os.getpid()}', block_time=1)
    E = Env()
    E.tb = tb
    try:
        tb.register('A')
        tb.register('B')
        E.A = tb.start_provider('A', M_max=3, T_max=3, seal_retry_s=1,
                                admission={'depth': 32, 'variant': 'full', 'verifiers': 2, 'keys': KEYS})
        E.adir = E.A['cfg']['data_dir']
        E.prover = Admission('prover', 32, 'full', KEYS)
        E.prover.info()
        E.tool = Admission('tool', 32)
        E.snd = Sender(tb.chain, E.prover, ACCT_SENDER, tb.dir / 'sender-retained')
        sk, pk = E.tool.keypair()
        E.sk, E.pk = sk, pk
        E.addr = make_address(tb.chain, '424242', pk)
        E.notes = []

        def fresh():
            old, tx = E.snd.deposit_note()
            tb.chain.wait_final(tx['block'])
            t = E.snd.transfer(old, E.addr)
            tb.chain.wait_final(t['tx']['block'])
            prep = E.snd.prepare(t['message'], t['cm'], pk, E.addr.ob)
            return t, prep
        E.fresh = fresh
        E.t1, E.p1 = fresh()
        yield E
    finally:
        for w in ('prover', 'tool'):
            if hasattr(E, w):
                getattr(E, w).close()
        tb.close()


def body(E, prep, **over):
    b = {'sid': E.tb.services[getattr(E, 'cur_name', 'A')]['sid'], 'h': prep['h'], 'public': dict(prep['public']), 'proof': prep['proof'],
         'rec': b64(prep['rec'])}
    b.update(over)
    return b


def append(E, b, url=None):
    return post_json((url or E.A['url']) + '/append', b, timeout=120)


@pytest.fixture
def E(env):
    return env


def test_invalid_root(E):
    before = counts(E.adir)
    b = body(E, E.p1)
    b['public']['root'] = fe_hex(12345)
    st, data, _ = append(E, b)
    assert st == 400 and 'finalized' in data['error']
    # non-finalized height (tip has no successor)
    b = body(E, E.p1, h=E.tb.chain.tip() + 5)
    st, data, _ = append(E, b)
    assert st == 400
    assert counts(E.adir) == before


def test_altered_public_input(E):
    before = counts(E.adir)
    # another genuine, finalized root (the pool root at an earlier height) -> proof fails
    old_root = fe_hex(int(E.tb.chain.call('root', height=E.p1['h'] - 3)))
    b = body(E, E.p1)
    b['public']['root'] = old_root
    st, data, _ = append(E, b, )
    assert st == 400 and 'proof invalid' in data['error'], data
    # altered tag (also in the record so the cheap check passes) -> proof fails
    nu, C = split_rec(E.p1['rec'])
    t2 = fe_hex((int(nu, 16) + 1) % FIELD)
    b = body(E, E.p1, rec=b64(make_rec(t2, C)))
    b['public']['tag'] = t2
    st, data, _ = append(E, b)
    assert st == 400 and 'proof invalid' in data['error'], data
    # flipped proof byte
    pr = bytearray(bytes.fromhex(E.p1['proof']))
    pr[100] ^= 1
    st, data, _ = append(E, body(E, E.p1, proof=pr.hex()))
    assert st == 400
    assert counts(E.adir) == before


def test_substituted_ciphertext_or_digest(E):
    before = counts(E.adir)
    nu, C = split_rec(E.p1['rec'])
    # re-encryption of the same note: valid ciphertext, but digest/proof are for the original
    enc = E.prover.encrypt(E.pk, E.t1['message'])
    st, data, _ = append(E, body(E, E.p1, rec=b64(make_rec(nu, enc['ciphertext']))))
    assert st == 400 and 'digest' in data['error']
    # consistent (ciphertext, digest) of the re-encryption but the proof is for another record
    b = body(E, E.p1, rec=b64(make_rec(nu, enc['ciphertext'])))
    b['public']['digest'] = E.prover.digest(enc['ciphertext'])
    st, data, _ = append(E, b)
    assert st == 400 and 'proof invalid' in data['error']
    assert counts(E.adir) == before


def test_inconsistent_recipient_binding(E):
    """Ciphertext to a DIFFERENT key than the committed pk_R: the honest prover refuses, and the provider rejects
    the substituted bytes under the original proof."""
    sk2, pk2 = E.tool.keypair()
    m = E.t1['message']
    enc = E.prover.w.call('encrypt', pk=pk2, message=m, allow_pk_mismatch=True)
    C = enc['ciphertext']
    d = E.prover.digest(C)
    nu = split_rec(E.p1['rec'])[0]
    pub = {'root': E.p1['public']['root'], 'digest': d, 'tag': nu}
    path = E.tb.chain.call('path', cm=str(int(E.t1['cm'], 16)), height=E.p1['h'])
    wit = {'message': m, 'ob': fe_hex(E.addr.ob), 'randomness': enc['randomness'], 'nonce': enc['nonce'], 'ciphertext': C,
           'siblings': [fe_hex(s) for s in path['siblings']], 'directions': path['directions']}
    with pytest.raises(Exception):
        E.prover.prove(pub, wit)
    before = counts(E.adir)
    b = body(E, E.p1, rec=b64(make_rec(nu, C)))
    b['public']['digest'] = d
    st, data, _ = append(E, b)
    assert st == 400 and 'proof invalid' in data['error']
    assert counts(E.adir) == before


def test_new_then_idempotent_retry_same_receipt_bytes(E):
    before = counts(E.adir)
    st, d1, _ = append(E, body(E, E.p1))
    assert st == 200 and d1['outcome'] == 'new'
    after = counts(E.adir)
    assert after == {k: v + 1 for k, v in before.items()}
    rows = slot(E.adir, E.p1['nu'])
    assert len(rows) == 1 and bytes(rows[0][2]) == E.p1['rec'] and (rows[0][0], rows[0][1]) == (d1['e'], d1['j'])
    assert bytes(rows[0][3]).hex() == d1['receipt']['sig']
    assert check_receipt(E.tb.chain, d1['sid'], d1['e'], d1['j'], d1['d_rec'], d1['receipt'])
    for _ in range(3):
        st, d2, _ = append(E, body(E, E.p1))
        assert st == 200 and d2['outcome'] == 'idempotent'
        assert (d2['e'], d2['j'], d2['d_rec'], d2['receipt']) == (d1['e'], d1['j'], d1['d_rec'], d1['receipt'])
    assert counts(E.adir) == after
    E.first = d1


def test_conflict_reencryption_same_note(E):
    """Randomized re-submission of the same note: new ciphertext + valid proof, same tag -> CONFLICT, no allocation."""
    before = counts(E.adir)
    prep2 = E.snd.prepare(E.t1['message'], E.t1['cm'], E.pk, E.addr.ob)
    assert prep2['nu'] == E.p1['nu'] and prep2['rec'] != E.p1['rec']
    st, d, _ = append(E, body(E, prep2))
    assert st == 409 and d['outcome'] == 'conflict'
    assert counts(E.adir) == before
    rows = slot(E.adir, E.p1['nu'])
    assert len(rows) == 1 and bytes(rows[0][2]) == E.p1['rec']
    # acceptance at A does not consume the entitlement at independent provider B
    B = E.tb.start_provider('B', M_max=3, T_max=3, admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS})
    bb = body(E, prep2, sid=E.tb.services['B']['sid'])
    st, dB, _ = append(E, bb, url=B['url'])
    assert st == 200 and dB['outcome'] == 'new' and dB['sid'] != E.first['sid']
    assert counts(B['cfg']['data_dir'])['tags'] == 1
    E.B = B


def test_concurrent_duplicates_one_allocation(E):
    t, prep = E.fresh()
    before = counts(E.adir)
    N = 12
    results = [None] * N
    bar = threading.Barrier(N)

    def go(i):
        bar.wait()
        results[i] = append(E, body(E, prep))
    ths = [threading.Thread(target=go, args=(i,)) for i in range(N)]
    [x.start() for x in ths]
    [x.join() for x in ths]
    outs = [r[1].get('outcome') for r in results]
    assert outs.count('new') == 1 and outs.count('idempotent') == N - 1, outs
    assert len({(r[1]['e'], r[1]['j'], r[1]['receipt']['sig']) for r in results}) == 1
    assert counts(E.adir) == {k: v + 1 for k, v in before.items()}
    assert len(slot(E.adir, prep['nu'])) == 1


def test_crash_after_commit_before_reply(E):
    """kill -9 inside the provider after COMMIT and before the reply (env-guarded test hook); retry -> same receipt."""
    t, prep = E.fresh()
    tb = E.tb
    tb.kill(E.A['proc'])
    A2 = tb.start_provider('A', data_dir=E.adir, env={'OOB_TEST_CRASH_AFTER_COMMIT': '1'}, tag='crash',
                           M_max=3, T_max=3, seal_retry_s=1, admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS})
    before = counts(E.adir)
    with pytest.raises(OSError):
        append(E, body(E, prep), url=A2['url'])
    time.sleep(0.5)
    assert tb.procs[A2['proc']].poll() is not None  # provider died
    persisted = counts(E.adir)
    assert persisted == {k: v + 1 for k, v in before.items()}  # committed before the crash
    rows = slot(E.adir, prep['nu'])
    assert len(rows) == 1
    tb.procs.pop(A2['proc'], None)
    A3 = tb.start_provider('A', data_dir=E.adir, M_max=3, T_max=3, seal_retry_s=1,
                           admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS})
    E.A = A3
    st, d, _ = append(E, body(E, prep))
    assert st == 200 and d['outcome'] == 'idempotent'
    assert d['receipt']['sig'] == bytes(rows[0][3]).hex() and (d['e'], d['j']) == (rows[0][0], rows[0][1])
    assert counts(E.adir) == persisted
    E.crash_prep = prep


def test_post_recovery_replay(E):
    """Replace(P -> P') (protocol v2): P = A loses its storage; a NEW provider P' = A2 (own key and sid, registered with
    "continues A", first epoch last_A + 1) rebuilds every certified epoch of A from A's anchors + holders at the same
    (e, j). Replayed tag at A2 -> no allocation (idempotent, same (e, j), receipt signed by A2 for (A2, e, j); or
    CONFLICT for a re-encryption); a record of an uncertified lost epoch of A is re-appended with a NEW allocation at
    an epoch >= last_A + 1."""
    tb = E.tb
    e0 = E.first['e']
    tb.wait_state('A', e0, ('certified',), timeout=120)
    # an extra record that stays in the OPEN (uncertified) epoch at failure time
    t, lost = E.fresh()
    tb.admin('A', '/admin/fault', faults={})
    st, dl, _ = append(E, body(E, lost))
    assert st == 200
    s = tb.status('A')
    certified = [x['e'] for x in s['epochs'] if x['state'] == 'certified']
    # A's storage is destroyed; A2 (new key, new sid, empty storage) replaces it
    tb.kill(E.A['proc'])
    shutil.rmtree(E.adir)
    assert not os.path.exists(E.adir)
    last_A = max(tb.chain.call('list_anchors', sid='0x' + tb.services['A']['sid'], height=tb.chain.finalized_height()))
    tb.register('A2', continues='A')
    assert tb.services['A2']['start_epoch'] == last_A + 1
    R = tb.start_provider('A2', mode='replace', forbidden_paths=[E.adir, str(tb.dir / 'sender-retained')],
                          admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS}, M_max=3, T_max=3,
                          seal_retry_s=1)
    t0 = time.time()
    while tb.status('A2')['recovery'].get('phase') not in ('complete', 'read_only_partial', 'failed', 'isolation_violation'):
        assert time.time() - t0 < 120
        time.sleep(0.2)
    rs = tb.status('A2')
    assert rs['recovery']['phase'] == 'complete', rs['recovery']
    assert rs['recovery']['mode'] == 'replace' and rs['recovery']['predecessors'] == [tb.services['A']['sid']]
    assert rs['recovery']['isolation']['ok']
    assert rs['appends_enabled'] and rs['e_cur'] == last_A + 1
    E.cur_name = 'A2'
    rdir = R['cfg']['data_dir']
    assert set(rs['recovery']['anchored_epochs']) >= set(certified)
    n0 = counts(rdir)
    # 1) identical replay of a recovered record: same (e, j), no allocation, receipt by A2 for (A2, e, j)
    st, d, _ = append(E, body(E, E.p1), url=R['url'])
    assert st == 200 and d['outcome'] == 'idempotent' and (d['e'], d['j']) == (E.first['e'], E.first['j'])
    assert d['sid'] == tb.services['A2']['sid'] != E.first['sid']
    assert check_receipt(tb.chain, d['sid'], d['e'], d['j'], d['d_rec'], d['receipt'])
    assert not check_receipt(tb.chain, E.first['sid'], d['e'], d['j'], d['d_rec'], d['receipt'])
    assert check_receipt(tb.chain, E.first['sid'], E.first['e'], E.first['j'], E.first['d_rec'], E.first['receipt'])
    # 2) re-encryption of a recovered note -> CONFLICT
    prep2 = E.snd.prepare(E.t1['message'], E.t1['cm'], E.pk, E.addr.ob)
    st, d2, _ = append(E, body(E, prep2), url=R['url'])
    assert st == 409 and d2['outcome'] == 'conflict'
    n1 = counts(rdir)
    assert n1['tags'] == n0['tags'] and n1['records'] == n0['records']
    # 3) record lost with the uncertified epoch: sender still retains rec -> new allocation above anchored epochs
    st, d3, _ = append(E, body(E, lost), url=R['url'])
    assert st == 200 and d3['outcome'] == 'new', d3
    assert d3['e'] > max(rs['recovery']['anchored_epochs'])
    assert counts(rdir)['tags'] == n0['tags'] + 1
    E.R = R


def test_replacement_appends_disabled_while_epoch_unrecoverable(E):
    """Replace(A2 -> A3) with an anchored epoch temporarily unrecoverable (k-1 holders reachable): A3 must also rebuild
    A's epochs (A2 continued A), stays read-only for recovered epochs with appends disabled; after the holders return
    and recovery is retried, appends are enabled."""
    tb = E.tb
    for i in (0, 1, 2):
        tb.holder_fault(i, {'offline': True})
    R = E.R
    tb.kill(R['proc'])
    shutil.rmtree(R['cfg']['data_dir'])
    tb.register('A3', continues='A2')
    R2 = tb.start_provider('A3', mode='replace', admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS},
                           M_max=3, T_max=3, seal_retry_s=1)
    t0 = time.time()
    while tb.status('A3')['recovery'].get('phase') not in ('complete', 'read_only_partial', 'failed'):
        assert time.time() - t0 < 120
        time.sleep(0.2)
    rs = tb.status('A3')
    assert rs['recovery']['predecessors'] == [tb.services['A2']['sid'], tb.services['A']['sid']], rs['recovery']
    assert rs['recovery']['phase'] == 'read_only_partial'
    assert rs['recovery']['temporarily_unrecoverable'] == rs['recovery']['anchored_epochs']
    assert rs['appends_enabled'] is False
    E.cur_name = 'A3'
    t, prep = E.fresh()
    st, d, _ = append(E, body(E, prep), url=R2['url'])
    assert st == 503 and counts(R2['cfg']['data_dir'])['tags'] == 0
    # holders come back; retry recovery -> complete -> appends enabled
    for i in (0, 1, 2):
        tb.holder_fault(i, {})
    tb.admin('A3', '/admin/retry_recovery')
    t0 = time.time()
    while not tb.status('A3')['appends_enabled']:
        assert time.time() - t0 < 120
        time.sleep(0.2)
    st, d, _ = append(E, body(E, prep), url=R2['url'])
    assert st == 200 and d['outcome'] == 'new'
    E.cur_url, E.cur_dir = R2['url'], R2['cfg']['data_dir']


def test_a11_pay_owner_field_but_encrypt_to_own_key(E):
    """A11: m[5] is R's owner field but (m[0], m[1]) is the SENDER's key (consistent encryption to itself).
    Under P1 constraint 1b (m[5] = Poseidon2(ob, Poseidon2(m[0], m[1]))) no admission is possible. (Under the weak
    variant W1 such a record WOULD be admissible; W1 is not run in the service.)"""
    sk_s, pk_s = E.tool.keypair()
    old, tx = E.snd.deposit_note()
    E.tb.chain.wait_final(tx['block'])
    m = E.snd.build_message(E.addr)
    m[0], m[1] = pk_s  # sender's own key; owner field m[5] still pays R
    from core.oobsvc.client import dec
    ph = E.prover.payload_hash(m)
    cm = E.prover.commitment(m[5], m[3], ph)
    h = E.tb.chain.finalized_height()
    path = E.tb.chain.call('path', cm=old.cm, height=h)
    nf = E.tb.chain.call('hash', values=[old.secret, old.seed])
    inputs = dict(root=path['root'], nullifier=nf, newCommitment=dec(cm), withdrawTo='0', secret=old.secret, pkHash=old.pk_hash,
                  seed=old.seed, payloadHash=old.payload_hash, newOwner=dec(m[5]), newSeed=dec(m[3]), newPayloadHash=dec(ph),
                  siblings=path['siblings'], directions=path['directions'])
    tx = E.tb.chain.call('transact', args=E.tb.chain.call('prove', input=inputs)['args'], **{'from': ACCT_SENDER})
    E.tb.chain.wait_final(tx['block'])  # the output IS a finalized leaf paying R's owner field
    before = counts(E.cur_dir)
    try:
        prep = E.snd.prepare(m, cm, pk_s, E.addr.ob)  # honest prover's native check must refuse (constraint 1b)
    except Exception as exc:
        E.a11_error = str(exc)
        assert counts(E.cur_dir) == before
        return
    # if a proof was produced (relation without 1b), the provider must still reject it under P1
    st, d, _ = append(E, body(E, prep), url=E.cur_url)
    assert st != 200, 'A11 violated: record encrypted to the sender key admitted for an output paying R'
    assert counts(E.cur_dir) == before


def test_a4_restore_duplicate_tag_rule(tmp_path):
    """A4: the earliest anchored (e, j) owns a tag; later duplicates stay readable but allocate nothing."""
    from core.oobsvc.provider import SCHEMA
    from core.oobsvc.recovery import restore_records
    rng = __import__('random').Random(3)
    mk = lambda: b''.join(rng.randrange(FIELD).to_bytes(32, 'big') for _ in range(23))
    shared = mk()
    e0 = [mk(), shared, mk()]
    dup = shared[:32] + mk()[32:]  # same tag, different bytes (Byzantine predecessor planted it)
    e1 = [dup, mk()]
    db = sqlite3.connect(tmp_path / 'r.sqlite3', isolation_level=None)
    db.executescript(SCHEMA)
    assert restore_records(db, 0, e0, {}, {}, 10) == 0
    assert restore_records(db, 1, e1, {}, {}, 11) == 1
    assert db.execute('SELECT e, j FROM tags WHERE tag=?', (shared[:32],)).fetchone() == (0, 1)
    assert db.execute('SELECT COUNT(*) FROM records').fetchone()[0] == 5  # duplicate kept readable
    assert db.execute('SELECT COUNT(*) FROM tags').fetchone()[0] == 4


def test_a2_dropped_receipted_record_sender_keeps_and_reappends(E):
    """A Byzantine provider drops a receipted record from the sealed epoch: the epoch is certified, but the sender's
    inclusion check for (j, rec) fails, so it keeps rec and re-appends elsewhere."""
    tb = E.tb
    t, prep = E.fresh()
    B = E.B
    tb.admin('B', '/admin/fault', faults={'drop_record_on_seal': [prep['nu']]})
    tb.admin('B', '/admin/bulk_load', count=1, seed=99)  # another record in the same epoch (disclosed synthetic)
    bb = body(E, prep, sid=tb.services['B']['sid'])
    st, dB, _ = append(E, bb, url=B['url'])
    assert st == 200 and dB['outcome'] == 'new'
    tb.wait_state('B', dB['e'], ('certified',), timeout=120)
    en = {'name': 'B', 'sid': dB['sid'], 'url': B['url'], 'e': dB['e'], 'j': dB['j'], 'd_rec': dB['d_rec'], 'receipt': dB['receipt']}
    from core.oobsvc.certify import certified
    assert certified(tb.chain, dB['sid'], dB['e'])['certified']
    rel = E.snd.try_release([en], prep['rec'], tb.holder_list())
    assert rel['released'] is False
    assert (E.snd.retention / f"{prep['nu']}.rec").exists()  # sender keeps rec
    tb.admin('B', '/admin/fault', faults={})
    E.a2_release = rel


def test_manifest_not_signed_by_p_key_refused(E):
    """A manifest for P's sid that
    is not signed by P's registered key is refused by every holder and never stored, so it cannot lock (sid, e)."""
    from nacl.signing import SigningKey
    tb = E.tb
    sid = bytes.fromhex(tb.services['A']['sid'])
    other = SigningKey.generate()
    e = 10 ** 6  # a future, unanchored epoch
    man, bodies = seal_body(tb, other, sid, e, [bytes(736)])
    for h, b in zip(tb.holder_list('A'), bodies):
        st, raw = http('POST', h['url'] + '/seal', b, 'application/octet-stream', timeout=60)
        assert st == 422 and "not P's registered key" in json.loads(raw)['error'], raw[:200]
    c = sqlite3.connect(f"file:{tb.holders[0]['data_dir']}/holder.sqlite3?mode=ro", uri=True)
    assert c.execute('SELECT COUNT(*) FROM frags WHERE e=?', (e,)).fetchone()[0] == 0
    c.close()


def test_a4_restore_duplicate_tag_rule_out_of_order(tmp_path):
    """the earliest (e, j) owns a tag even if the earlier epoch is restored LAST."""
    from core.oobsvc.provider import SCHEMA
    from core.oobsvc.recovery import restore_records
    rng = __import__('random').Random(4)
    mk = lambda: b''.join(rng.randrange(FIELD).to_bytes(32, 'big') for _ in range(23))
    shared = mk()
    e0 = [mk(), shared, mk()]
    e1 = [shared[:32] + mk()[32:], mk()]
    db = sqlite3.connect(tmp_path / 'r.sqlite3', isolation_level=None)
    db.executescript(SCHEMA)
    assert restore_records(db, 1, e1, {}, {}, 11) == 0
    assert restore_records(db, 0, e0, {}, {}, 10) == 1
    assert db.execute('SELECT e, j FROM tags WHERE tag=?', (shared[:32],)).fetchone() == (0, 1)
    assert db.execute('SELECT COUNT(*) FROM tags').fetchone()[0] == 4


def test_a_n2_holder_refuses_noncanonical_record(E):
    """A Byzantine operator seals an epoch with a non-canonical BN254 field element.
    whole_epoch mode: holders see every record and refuse to acknowledge (such an epoch is never certified).
    fragment_kzg mode : holders see only their fragment and cannot check records; the scalar is
    < the BLS12-381 modulus, so the fragment is on the committed codeword and IS acknowledged; recovery stores the slot
    verbatim (junk is inherited, never validated by a recipient). A scalar >= the BLS12-381 modulus cannot be committed."""
    from nacl.signing import SigningKey
    tb = E.tb
    sid = bytes.fromhex(tb.services['B']['sid'])
    sk = SigningKey(bytes.fromhex(tb.services['B']['operator_sk']))
    e = 10 ** 6
    good = b''.join((i + 1).to_bytes(32, 'big') for i in range(23))
    bad = FIELD.to_bytes(32, 'big') + good[32:]  # tag = p (non-canonical BN254)
    recs = [good, bad]
    man, bodies = seal_body(tb, sk, sid, e, recs)
    for h, b in zip(tb.holder_list('B'), bodies):
        st, raw = http('POST', h['url'] + '/seal', b, 'application/octet-stream', timeout=60)
        if tb.seal_mode == 'whole_epoch':
            assert st == 422 and 'non-canonical' in json.loads(raw)['error'], (st, raw[:200])
        else:
            assert st == 200 and 'ack' in json.loads(raw), (st, raw[:200])
    if tb.seal_mode == 'fragment_kzg':
        from core.oobsvc.epoch import build_manifest
        with pytest.raises(Exception):  # >= BLS12-381 r: not embeddable, no commitment exists
            build_manifest(sk, sid, e + 1, [b'\xff' * 736], {'version': man['gamma'], 'k': man['k'], 'n': man['n'],
                           'q': man['q'], 'keys': [bytes.fromhex(x) for x in man['holders']]}, 'fragment_kzg')


def _wait(pred, timeout, what):
    t0 = time.time()
    while True:
        v = pred()
        if v:
            return v
        assert time.time() - t0 < timeout, f'timeout: {what}'
        time.sleep(0.2)


def test_bn2_holder_replacement_unblocks_certification(E):
    """A permanently lost holder blocks certification (q = n acks). P itself replaces it
    with setHolders; the stuck epoch is resealed to the new set and certified; earlier epochs stay verifiable against
    the set active at their anchor block; the sender releases and anyone recovers the epoch from the new set."""
    from core.oobsvc.certify import certified
    from core.oobsvc.recovery import recipient_recover
    tb = E.tb
    name = E.cur_name  # the provider currently serving (A3 after the replacements above)
    sid = tb.services[name]['sid']
    tb.holder_fault(0, {'offline': True})  # holder 1 "permanently lost"
    try:
        t, prep = E.fresh()
        st, d, _ = append(E, body(E, prep), url=E.cur_url)
        assert st == 200 and d['outcome'] == 'new'
        e = d['e']
        ep = lambda: {x['e']: x for x in tb.status(name)['epochs']}.get(e)
        _wait(lambda: (ep() or {}).get('metrics', {}).get('seal_attempts', 0) >= 1, 120, 'first seal attempt')
        assert ep()['state'] == 'read_ready' and not certified(tb.chain, sid, e)['certified']  # stuck
        old_anchored = tb.chain.call('list_anchors', sid='0x' + sid)
        tb.start_holder(5)  # holder 6 replaces holder 1
        r = tb.set_holders(name, [5, 1, 2, 3, 4])  # P itself installs a new assignment
        tb.chain.wait_final(r['block'])
        tb.wait_state(name, e, ('certified',), timeout=120)
        c = certified(tb.chain, sid, e)
        assert c['certified'] and c['holders'][0]['key'] == tb.holders[5]['key']
        for e0 in old_anchored:  # anchored under the old set: still Certified
            assert certified(tb.chain, sid, e0)['certified'], e0
        en = {'name': name, 'sid': sid, 'url': E.cur_url, 'e': e, 'j': d['j'], 'd_rec': d['d_rec'], 'receipt': d['receipt']}
        assert E.snd.try_release([en], prep['rec'])['released']
        recs, m = recipient_recover(tb.chain, sid, e)
        assert recs is not None and recs[d['j']] == prep['rec'], m
    finally:
        tb.holder_fault(0, {})


def test_b1_void_anchor_sender_keeps_record_and_replacement_appends(E):
    """A Byzantine operator writes a bogus anchor for its next epoch.
    Readers treat it as VOID: (i) the sender does not release its record; (ii) a replacement B2 (continues B) skips
    the void epoch, enables appends, starts its own numbering after it, and the re-appended record is certified and
    released. B2's endpoint is found via the registry."""
    from core.oobsvc.certify import certified
    from core.oobsvc.client import resolve_endpoint
    tb = E.tb
    sid = tb.services['B']['sid']
    anchored = tb.chain.call('list_anchors', sid='0x' + sid)
    e_next = len(anchored)
    assert anchored == list(range(e_next))
    _wait(lambda: all(x['state'] == 'certified' for x in tb.status('B')['epochs'] if x['m_e'] > 0 and x['e'] < e_next), 120,
          'B idle')
    op_idx = tb.services['B']['op_eoa_index']
    bogus = tb.chain.call('anchor', **{'from': op_idx}, sid='0x' + sid, e=e_next, manifest='0x' + b'{"bogus":1}'.hex(),
                          cert='0x' + b'{"bogus":1}'.hex())
    tb.chain.wait_final(bogus['block'])
    t, prep = E.fresh()
    st, d, _ = append(E, body(E, prep, sid=sid), url=E.B['url'])
    assert st == 200 and d['outcome'] == 'new' and d['e'] == e_next, d
    tb.wait_state('B', e_next, ('certified',), timeout=120)  # the provider adopts the existing (bogus) anchor
    c = certified(tb.chain, sid, e_next)
    assert not c['certified'] and 'VOID' in c['reason'], c
    en = {'name': 'B', 'sid': sid, 'url': E.B['url'], 'e': e_next, 'j': d['j'], 'd_rec': d['d_rec'], 'receipt': d['receipt']}
    rel = E.snd.try_release([en], prep['rec'])
    assert rel['released'] is False and (E.snd.retention / f"{prep['nu']}.rec").exists()  # (i)
    # (ii) B loses its storage; B2 (own key and sid, "continues B") replaces it
    tb.kill(E.B['proc'])
    shutil.rmtree(E.B['cfg']['data_dir'])
    tb.register('B2', continues='B')
    assert tb.services['B2']['start_epoch'] == e_next + 1  # the void anchor still counts for numbering
    R = tb.start_provider('B2', mode='replace', admission={'depth': 32, 'variant': 'full', 'verifiers': 1, 'keys': KEYS},
                          M_max=3, T_max=3)
    _wait(lambda: tb.status('B2')['recovery'].get('phase') in ('complete', 'read_only_partial', 'failed'), 180, 'B2 recovery')
    rs = tb.status('B2')
    assert rs['recovery']['phase'] == 'complete' and rs['appends_enabled'] and e_next in rs['recovery']['void'], rs['recovery']
    sid2 = tb.services['B2']['sid']
    url = resolve_endpoint(tb.chain, sid2)
    assert url == R['url']  # found through the registry, not deployment config
    st, d2, _ = append(E, body(E, prep, sid=sid2), url=url)
    assert st == 200 and d2['outcome'] == 'new' and d2['e'] == e_next + 1, d2
    tb.wait_state('B2', d2['e'], ('certified',), timeout=120)
    en2 = {'name': 'B2', 'sid': sid2, 'url': url, 'e': d2['e'], 'j': d2['j'], 'd_rec': d2['d_rec'], 'receipt': d2['receipt']}
    assert E.snd.try_release([en2], prep['rec'])['released']
    E.B = R
