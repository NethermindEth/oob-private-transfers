"""Protocol-v2 library tests (no services): (k, n, q) parameterization, KZG erasure-code commitment , open
decoding by a fragment-less node , slot openings for sender release , SRS pin, assignment pinning in the manifest ;
no retention expiry (holders retain fragments indefinitely). Fixtures: (3,5,5) (old), (4,8,6), (8,16,12), (16,32,24) -- TEST configurations, same host."""
import itertools
import random
import shutil

import pytest
from nacl.signing import SigningKey

from core.oobsvc import kzg
from core.oobsvc.common import FIELD, H
from core.oobsvc.epoch import (ConfigError, RecoveryError, build_manifest, check_thresholds, decode_epoch,
                               fragment_check, make_ack, manifest_hash, slot_check, verify_cert, verify_manifest)

SID = H(b'v2-sid')
FIXTURES = [(3, 5, 5), (4, 8, 6), (8, 16, 12), (16, 32, 24)]
MODES = ('whole_epoch', 'fragment_kzg')


def mkrec(rng, bound=FIELD):
    return b''.join(rng.randrange(bound).to_bytes(32, 'big') for _ in range(23))


def make_epoch(k, n, q, mode, m_e=200, seed=1, recs=None):
    rng = random.Random(seed)
    recs = recs or [mkrec(rng) for _ in range(m_e)]
    op = SigningKey.generate()
    hs = [SigningKey.generate() for _ in range(n)]
    asg = {'version': 0, 'keys': [bytes(h.verify_key) for h in hs], 'k': k, 'n': n, 'q': q}
    man, frags, aux = build_manifest(op, SID, 5, recs, asg, mode)
    return dict(recs=recs, op=op, opk=bytes(op.verify_key), hs=hs, asg=asg, man=man, frags=frags, aux=aux, rng=rng)


_cache = {}


def ep(k, n, q, mode):
    key = (k, n, q, mode)
    if key not in _cache:
        _cache[key] = make_epoch(k, n, q, mode)
    return _cache[key]


# ------------------------------------------------------------------------------------------------ thresholds
@pytest.mark.parametrize('k,n,q', FIXTURES + [(1, 1, 1), (1, 3, 1), (2, 3, 3)])
def test_valid_thresholds(k, n, q):
    t = check_thresholds(k, n, q)
    assert (t['f_r'], t['f_w']) == (q - k, n - q)


@pytest.mark.parametrize('k,n,q', [(3, 5, 6), (3, 5, 2), (0, 5, 5), (4, 3, 3), (3, 0, 0), (3, 256, 200), (3.0, 5, 5),
                                   (3, 5, None)])
def test_invalid_thresholds_rejected(k, n, q):
    with pytest.raises(ConfigError):
        check_thresholds(k, n, q)


def test_build_manifest_rejects_invalid_assignment():
    with pytest.raises(ConfigError):
        make_epoch(4, 8, 9, 'fragment_kzg', m_e=4)
    with pytest.raises(ConfigError):
        make_epoch(4, 8, 3, 'whole_epoch', m_e=4)


# ------------------------------------------------------------------------------------------------ decoding
@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('k,n,q', FIXTURES)
def test_any_k_decode_and_k_minus_1_fails(k, n, q, mode):
    E = ep(k, n, q, mode)
    man = E['man']
    verify_manifest(man, SID, 5, E['opk'], E['asg'])
    rng = random.Random(k * 1000 + n)
    subsets = [tuple(range(1, k + 1)), tuple(range(n - k + 1, n + 1))] + [tuple(rng.sample(range(1, n + 1), k)) for _ in range(3)]
    for S in subsets:  # includes the all-parity subset when n - k >= k (a node that holds no data fragment)
        assert decode_epoch(man, {i: E['frags'][i - 1] for i in S}) == E['recs'], S
    with pytest.raises(RecoveryError):
        decode_epoch(man, {i: E['frags'][i - 1] for i in rng.sample(range(1, n + 1), k - 1)})


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('k,n,q', FIXTURES)
def test_certificate_needs_q_distinct_valid_acks(k, n, q, mode):
    E = ep(k, n, q, mode)
    man, hm = E['man'], manifest_hash(E['man'])
    acks = [make_ack(h, hm, i + 1) for i, h in enumerate(E['hs'])]
    rng = random.Random(n)
    present = sorted(rng.sample(range(n), q))  # n - q nonresponders
    verify_cert({'h_manifest': hm.hex(), 'acks': [acks[i] for i in present]}, man)
    with pytest.raises(RecoveryError):  # q - 1
        verify_cert({'h_manifest': hm.hex(), 'acks': [acks[i] for i in present[:-1]]}, man)
    with pytest.raises(RecoveryError):  # a duplicate does not count
        verify_cert({'h_manifest': hm.hex(), 'acks': [acks[i] for i in present[:-1]] + [acks[present[0]]]}, man)
    bad = [dict(acks[i]) for i in present]
    bad[0]['sig'] = '00' * 64
    with pytest.raises(RecoveryError):  # an invalid ack does not count
        verify_cert({'h_manifest': hm.hex(), 'acks': bad}, man)
    wrong = [make_ack(E['hs'][i], H(b'other manifest'), i + 1) for i in present]
    with pytest.raises(RecoveryError):
        verify_cert({'h_manifest': hm.hex(), 'acks': wrong}, man)


# ------------------------------------------------------------------------------------------------ KZG fragment check
@pytest.mark.parametrize('k,n,q', FIXTURES)
def test_kzg_altered_fragments_rejected(k, n, q):
    E = ep(k, n, q, 'fragment_kzg')
    man = E['man']
    for i in (1, k, k + 1, n):
        f = E['frags'][i - 1]
        assert fragment_check(man, i, f)[0]
        for pos in (0, len(f) // 32 - 1):  # first and last scalar
            x = (int.from_bytes(f[32 * pos:32 * pos + 32], 'big') + 1) % kzg.R
            g = f[:32 * pos] + x.to_bytes(32, 'big') + f[32 * pos + 32:]
            ok, why = fragment_check(man, i, g)
            assert not ok and 'off the committed codeword' in why, (i, pos, why)
        assert not fragment_check(man, i, f[:-32])[0]  # truncated
        assert not fragment_check(man, i, b'\xff' * len(f))[0]  # non-canonical scalars
        if i < n:
            assert not fragment_check(man, i, E['frags'][i])[0]  # another coordinate's (valid) fragment


def test_kzg_hash_valid_off_codeword_fragment_rejected():
    """A Byzantine holder serves F' together with a matching hash H(F') (so any hash-based check passes); the reader
    checks against com_e only and rejects it; decoding from the honest fragments still returns the epoch."""
    E = ep(4, 8, 6, 'fragment_kzg')
    man, frags = E['man'], E['frags']
    f = frags[5]
    fprime = f[:64] + ((int.from_bytes(f[64:96], 'big') + 7) % kzg.R).to_bytes(32, 'big') + f[96:]
    claimed = H(fprime)
    assert claimed == H(fprime) and kzg.canonical(fprime)
    assert not fragment_check(man, 6, fprime)[0]
    good = {i: frags[i - 1] for i in (1, 2, 3, 6, 7, 8) if fragment_check(man, i, frags[i - 1] if i != 6 else fprime)[0]}
    assert 6 not in good and decode_epoch(man, dict(itertools.islice(good.items(), 4))) == E['recs']


def test_kzg_manifest_with_different_com_is_void():
    E = ep(4, 8, 6, 'fragment_kzg')
    man, hm = E['man'], manifest_hash(E['man'])
    cert = {'h_manifest': hm.hex(), 'acks': [make_ack(h, hm, i + 1) for i, h in enumerate(E['hs'])]}
    other = dict(man, com=[list(reversed(r)) if len(r) > 1 else r for r in man['com'][::-1]])
    with pytest.raises(RecoveryError):  # not re-signed: signature fails
        verify_manifest(other, SID, 5, E['opk'], E['asg'])
    body = {x: y for x, y in other.items() if x != 'sig'}
    from core.oobsvc.common import canon, sign
    body['sig'] = sign(E['op'], b'OOB-manifest-v2' + canon(body)).hex()  # re-signed by the (equivocating) operator
    verify_manifest(body, SID, 5, E['opk'], E['asg'])
    with pytest.raises(RecoveryError):  # the certificate for the original manifest does not certify it
        verify_cert(cert, body)
    assert not all(fragment_check(body, i, E['frags'][i - 1])[0] for i in range(1, 9))


def test_kzg_parity_commitments_by_linearity_match_direct_commitments():
    E = ep(8, 16, 12, 'fragment_kzg')
    lay = E['aux']['layout']
    for i in (9, 12, 16):
        direct = kzg.commit_fragment(E['frags'][i - 1], lay)
        assert kzg.expected_commitments(E['man']['com'], i, 16) == direct


def test_lincomb_matches_naive():
    rng = random.Random(5)
    frags = [b''.join(rng.randrange(kzg.R).to_bytes(32, 'big') for _ in range(50)) for _ in range(16)]
    coeffs = [rng.randrange(kzg.R) for _ in range(16)]
    got = kzg.lincomb(frags, coeffs)
    for l in range(50):
        want = sum(c * int.from_bytes(f[32 * l:32 * l + 32], 'big') for c, f in zip(coeffs, frags)) % kzg.R
        assert int.from_bytes(got[32 * l:32 * l + 32], 'big') == want


def test_kzg_slots_stored_verbatim():
    """I2: fragment_kzg recovery stores decoded slots verbatim, even scalars that are not canonical BN254 elements
    (a Byzantine operator's junk is inherited, never validated)."""
    rng = random.Random(9)
    recs = [mkrec(rng) for _ in range(20)]
    recs[3] = FIELD.to_bytes(32, 'big') + recs[3][32:]  # tag = BN254 modulus: not canonical BN254, < BLS12-381 r
    E = make_epoch(4, 8, 6, 'fragment_kzg', recs=recs)
    assert decode_epoch(E['man'], {i: E['frags'][i - 1] for i in (5, 6, 7, 8)})[3] == recs[3]


# ------------------------------------------------------------------------------------------------ slot openings
@pytest.mark.parametrize('k,n,q,m_e', [(3, 5, 5, 600), (4, 8, 6, 200), (16, 32, 24, 100)])
def test_slot_opening_valid_and_invalid(k, n, q, m_e):
    E = make_epoch(k, n, q, 'fragment_kzg', m_e=m_e, seed=m_e)
    man, lay, data = E['man'], E['aux']['layout'], E['aux']['data']
    js = sorted({0, 1, 2, 177, 178, lay.s - 1, lay.s, m_e - 1, m_e // 2} & set(range(m_e)))
    for j in js:
        t = lay.locate(j)[0]
        op = kzg.slot_opening(data[t], lay, j)
        assert slot_check(man, j, E['recs'][j], op) == (True, 'ok'), j
        assert not slot_check(man, j, E['recs'][(j + 1) % m_e], op)[0]  # another record
        assert not slot_check(man, (j + 1) % m_e, E['recs'][j], op)[0]  # opening for another slot
        bad = dict(op, cells=[dict(c) for c in op['cells']])
        bad['cells'][0]['proof'] = kzg.slot_opening(data[t], lay, (j + 178) % m_e)['cells'][0]['proof']
        assert not slot_check(man, j, E['recs'][j], bad)[0] or bad['cells'][0]['proof'] == op['cells'][0]['proof']
    assert not slot_check(man, m_e, E['recs'][0], kzg.slot_opening(data[0], lay, 0))[0]  # j >= m_e


def test_release_refused_when_committed_epoch_omits_record():
    """The operator commits to an epoch WITHOUT the receipted record (slot j now holds the next record): every
    opening the sender can obtain for slot j fails its check (App. B.3 case iii)."""
    rng = random.Random(11)
    recs = [mkrec(rng) for _ in range(50)]
    j = 17
    committed = recs[:j] + recs[j + 1:]
    E = make_epoch(4, 8, 6, 'fragment_kzg', recs=committed)
    lay, data = E['aux']['layout'], E['aux']['data']
    op = kzg.slot_opening(data[lay.locate(j)[0]], lay, j)
    ok, why = slot_check(E['man'], j, recs[j], op)
    assert not ok and 'differs from the record' in why
    last = len(committed)  # the sender's slot may also lie beyond m_e
    ok, why = slot_check(E['man'], last, recs[-1], op)
    assert not ok


# ------------------------------------------------------------------------------------------------ SRS pin
def test_srs_hash_pinned(tmp_path):
    assert kzg.file_sha256(kzg.SETUP_FILE) == kzg.SETUP_SHA256
    alt = tmp_path / 'ts.txt'
    shutil.copy(kzg.SETUP_FILE, alt)
    lines = alt.read_text().splitlines()
    lines[2] = lines[3]  # swap in another valid point
    alt.write_text('\n'.join(lines) + '\n')
    with pytest.raises(kzg.KZGSetupError):
        kzg.trusted_setup(alt)


# ------------------------------------------------------------------------------------------------ pinning in manifest
def test_manifest_pins_assignment_and_thresholds_no_expiry():
    E = ep(4, 8, 6, 'fragment_kzg')
    man = E['man']
    assert (man['gamma'], man['k'], man['n'], man['q']) == (0, 4, 8, 6) and 'exp' not in man
    with pytest.raises(RecoveryError, match='expiry'):  # an expiry field is not part of the v2 manifest
        verify_manifest(dict(man, exp=10 ** 6), SID, 5, E['opk'], E['asg'])
    other = dict(E['asg'], version=1)
    with pytest.raises(RecoveryError, match='assignment version'):
        verify_manifest(man, SID, 5, E['opk'], other)
    with pytest.raises(RecoveryError):
        verify_manifest(man, SID, 5, E['opk'], dict(E['asg'], q=7))
    with pytest.raises(RecoveryError):
        verify_manifest(man, SID, 5, E['opk'], dict(E['asg'], keys=E['asg']['keys'][::-1]))
