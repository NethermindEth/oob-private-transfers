"""Recovery negatives at the library level (no services), for BOTH seal modes with the old (k,n,q) = (3,5,5):
malformed data must never become a recovered epoch."""
import random

import pytest
from nacl.signing import SigningKey

from core.oobsvc import kzg
from core.oobsvc.common import FIELD, H
from core.oobsvc.epoch import (RecoveryError, build_manifest, check_consistency, decode_epoch, decode_raw,
                               encode_fragments, fragment_ok, make_ack, manifest_hash, serialize_epoch, verify_cert,
                               verify_manifest)

SID = H(b'test-sid')
MODES = ('whole_epoch', 'fragment_kzg')


def rec(rng):
    return b''.join(rng.randrange(FIELD).to_bytes(32, 'big') for _ in range(23))


@pytest.fixture(scope='module', params=MODES)
def epoch(request):
    rng = random.Random(7)
    recs = [rec(rng) for _ in range(37)]
    op = SigningKey.generate()
    holders = [SigningKey.generate() for _ in range(5)]
    hk = [bytes(h.verify_key) for h in holders]
    asg = {'version': 0, 'keys': hk, 'k': 3, 'n': 5, 'q': 5}
    man, frags, aux = build_manifest(op, SID, 3, recs, asg, request.param)
    cert = {'h_manifest': manifest_hash(man).hex(), 'acks': [make_ack(h, manifest_hash(man), i + 1) for i, h in enumerate(holders)]}
    return dict(mode=request.param, recs=recs, op=op, opk=bytes(op.verify_key), holders=holders, hk=hk, asg=asg, man=man,
                frags=frags, cert=cert)


def test_valid_manifest_and_cert(epoch):
    verify_manifest(epoch['man'], SID, 3, epoch['opk'], epoch['asg'])
    verify_cert(epoch['cert'], epoch['man'])


@pytest.mark.parametrize('coords', [(1, 2, 3), (3, 4, 5), (1, 3, 5), (1, 2, 3, 4), (1, 2, 3, 4, 5), (4, 5, 2)])
def test_any_k_fragments_recover_exactly(epoch, coords):
    got = decode_epoch(epoch['man'], {i: epoch['frags'][i - 1] for i in coords})
    assert got == epoch['recs']


@pytest.mark.parametrize('coords', [(), (1,), (2, 5), (4, 5)])
def test_fewer_than_k_unavailable(epoch, coords):
    with pytest.raises(RecoveryError):
        decode_epoch(epoch['man'], {i: epoch['frags'][i - 1] for i in coords})


def test_corrupted_fragment_rejected(epoch):
    for i in (1, 5):  # a data and a parity coordinate
        f = bytearray(epoch['frags'][i - 1])
        f[10] ^= 1
        assert not fragment_ok(epoch['man'], i, bytes(f))
        assert fragment_ok(epoch['man'], i, epoch['frags'][i - 1])


def test_duplicate_coordinate_rejected(epoch):
    # fragment 2 relabeled as coordinate 1 fails the check; a dict can hold only one entry per coordinate
    assert not fragment_ok(epoch['man'], 1, epoch['frags'][1])
    frags = {1: epoch['frags'][0]}
    frags.setdefault(1, epoch['frags'][1])
    frags.setdefault(2, epoch['frags'][1])
    with pytest.raises(RecoveryError):
        decode_epoch(epoch['man'], {i: f for i, f in frags.items() if fragment_ok(epoch['man'], i, f)})  # two valid only


def test_invalid_ack_rejected(epoch):
    bad = dict(epoch['cert'], acks=[dict(a, sig='00' * 64) if a['i'] == 3 else a for a in epoch['cert']['acks']])
    with pytest.raises(RecoveryError):
        verify_cert(bad, epoch['man'])
    dup = dict(epoch['cert'], acks=epoch['cert']['acks'][:4] + [epoch['cert']['acks'][0]])
    with pytest.raises(RecoveryError):
        verify_cert(dup, epoch['man'])
    four = dict(epoch['cert'], acks=epoch['cert']['acks'][:4])
    with pytest.raises(RecoveryError):
        verify_cert(four, epoch['man'])  # q = 5 required


@pytest.mark.parametrize('mut', ['m_e', 'sig', 'holder', 'root_or_com', 'key_version', 'sid', 'gamma', 'q'])
def test_invalid_manifest_rejected(epoch, mut):
    man = dict(epoch['man'])
    if mut == 'm_e':
        man['m_e'] += 1
    elif mut == 'sig':
        man['sig'] = SigningKey.generate().sign(b'x').signature.hex()
    elif mut == 'holder':
        man['holders'] = list(man['holders'])
        man['holders'][0] = bytes(SigningKey.generate().verify_key).hex()
    elif mut == 'root_or_com':
        if epoch['mode'] == 'whole_epoch':
            man['R_e'] = '00' * 32
        else:
            man['com'] = [list(r) for r in man['com']]
            man['com'][0][0] = man['com'][1][0]
    elif mut == 'key_version':
        man['key_version'] = 1
    elif mut == 'sid':
        man['sid'] = H(b'other').hex()
    elif mut == 'gamma':
        man['gamma'] = 1
    elif mut == 'q':
        man['q'] = 4
    with pytest.raises(RecoveryError):
        verify_manifest(man, SID, 3, epoch['opk'], epoch['asg'])


def test_inconsistent_encoding_never_recovers(epoch):
    """whole_epoch: a validly signed manifest over fragment hashes of a NON-codeword (malicious operator + forged
    acks) never decodes. fragment_kzg: a non-codeword cannot even be committed (parity commitments are derived), and
    an off-codeword fragment is rejected by the fragment check of holders and readers alike."""
    if epoch['mode'] == 'whole_epoch':
        ser = serialize_epoch(SID, 3, epoch['recs'])
        frags = encode_fragments(ser, 3, 5)
        frags[4] = bytes([frags[4][0] ^ 1]) + frags[4][1:]
        man, _, _ = build_manifest(epoch['op'], SID, 3, epoch['recs'], epoch['asg'], 'whole_epoch', frags)
        verify_manifest(man, SID, 3, epoch['opk'], epoch['asg'])  # signature is fine
        for coords in [(1, 2, 3), (1, 2, 5), (3, 4, 5), (2, 4, 5)]:
            fr = {i: frags[i - 1] for i in coords}
            assert all(fragment_ok(man, i, d) for i, d in fr.items())
            with pytest.raises(RecoveryError):
                decode_epoch(man, fr)
    else:
        for i in range(1, 6):
            f = epoch['frags'][i - 1]
            off = f[:32] + ((int.from_bytes(f[32:64], 'big') + 1) % kzg.R).to_bytes(32, 'big') + f[64:]
            assert kzg.canonical(off) and not fragment_ok(epoch['man'], i, off)
