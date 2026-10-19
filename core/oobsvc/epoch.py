"""Epoch serialization, erasure coding, manifests (v2) and availability certificates.

Thresholds (k, n, q) belong to the registry holder assignment gamma and are pinned, with gamma, in the manifest:
k = decoding threshold, n = assigned coordinates, q = acknowledgments needed to certify; f_r = q - k tolerated failed
acknowledged coordinates after certification, f_w = n - q tolerated nonresponders while sealing.

Two seal modes (provider config `seal_mode`), both with manifest v2:
- `whole_epoch` (baseline for side-by-side measurement): every holder receives the WHOLE epoch
  serialization, recomputes the record root R_e, checks canonical records, re-encodes RS(k,n) (zfec) and compares all n
  fragment hashes; sealing sends n*B bytes. Release check: Merkle path under R_e.
- `fragment_kzg` (fragment verification): holder u_i receives only (manifest, F_i) and checks F_i against
  the KZG erasure-code commitment com_e in the manifest (core/oobsvc/kzg.py); sealing sends about n*B/k bytes plus
  n manifests. Release check: KZG slot opening. Recovery stores decoded slots verbatim.
"""
from __future__ import annotations

from nacl.signing import SigningKey
from zfec import Decoder, Encoder

from . import kzg
from .common import FIELD, H, REC_BYTES, canon, u64, sign, verify_sig, ack_message

SEAL_MODES = ('whole_epoch', 'fragment_kzg')
MAN_V = 'OOB-manifest-v2'
MAN_DOMAIN = b'OOB-manifest-v2'  # also hard-coded in EpochAnchor.sol (anchor hash)
CERT_DOMAIN = b'OOB-cert-v1'
MAX_N = kzg.MAX_N


class RecoveryError(Exception):
    pass


class ConfigError(ValueError):
    pass


def check_thresholds(k, n, q) -> dict:
    """Reject invalid (k, n, q). Returns the derived fault budgets f_r = q - k and f_w = n - q."""
    if not all(type(x) is int for x in (k, n, q)):
        raise ConfigError(f'thresholds must be integers: (k,n,q)=({k!r},{n!r},{q!r})')
    if k < 1:
        raise ConfigError(f'k={k} < 1')
    if n < 1 or n > MAX_N:
        raise ConfigError(f'n={n} outside 1..{MAX_N}')
    if q > n:
        raise ConfigError(f'q={q} > n={n}')
    if q < k:
        raise ConfigError(f'q={q} < k={k} (a certified epoch might have fewer than k stored fragments)')
    return {'k': k, 'n': n, 'q': q, 'f_r': q - k, 'f_w': n - q}


def serialize_epoch(sid: bytes, e: int, recs: list[bytes]) -> bytes:
    assert len(sid) == 32 and all(len(r) == REC_BYTES for r in recs)
    return sid + u64(e) + u64(len(recs)) + b''.join(recs)


EMPTY_LEAF = H(b'OOB-leaf-empty-v1')


def leaf_hash(j: int, rec: bytes) -> bytes:
    return H(b'OOB-leaf-v1', u64(j), rec)


def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    size = 1
    while size < len(leaves):
        size *= 2
    lvl = list(leaves) + [EMPTY_LEAF] * (size - len(leaves))
    levels = [lvl]
    while len(lvl) > 1:
        lvl = [H(b'OOB-node-v1', lvl[i], lvl[i + 1]) for i in range(0, len(lvl), 2)]
        levels.append(lvl)
    return levels


def epoch_root(sid: bytes, e: int, recs: list[bytes]) -> bytes:
    """R_e (whole_epoch mode): SHA-256 Merkle root over leaf_j = H("OOB-leaf-v1" || j || rec_j), slot order, padded to
    a power of two with a fixed empty leaf. sid, e and m_e are bound by the signed manifest."""
    return merkle_levels([leaf_hash(j, r) for j, r in enumerate(recs)])[-1][0]


def inclusion_path(leaves: list[bytes], j: int) -> list[str]:
    levels = merkle_levels(leaves)
    path, idx = [], j
    for lvl in levels[:-1]:
        path.append(lvl[idx ^ 1].hex())
        idx //= 2
    return path


def verify_inclusion(root_hex: str, m_e: int, j: int, rec: bytes, path: list[str]) -> bool:
    if not (type(j) is int and 0 <= j < m_e):
        return False
    size = 1
    while size < m_e:
        size *= 2
    if len(path) != size.bit_length() - 1:
        return False
    cur, idx = leaf_hash(j, rec), j
    for sib in path:
        s = bytes.fromhex(sib)
        cur = H(b'OOB-node-v1', s, cur) if idx & 1 else H(b'OOB-node-v1', cur, s)
        idx //= 2
    return cur.hex() == root_hex


def encode_fragments(ser: bytes, k: int, n: int) -> list[bytes]:
    """whole_epoch mode: zfec RS(k, n) of the zero-padded serialization."""
    size = (len(ser) + k - 1) // k
    padded = ser + bytes(size * k - len(ser))
    blocks = [padded[i * size:(i + 1) * size] for i in range(k)]
    return list(Encoder(k, n).encode(blocks))


def whole_frag_len(m_e: int, k: int) -> int:
    return (8 * 2 + 32 + m_e * REC_BYTES + k - 1) // k


def build_manifest(sk: SigningKey, sid: bytes, e: int, recs: list[bytes], assignment: dict,
                   mode: str, fragments: list[bytes] | None = None) -> tuple[dict, list[bytes], dict]:
    """man_e = (sid, e, m_e, gamma, com_e) signed by P's key (no operator version, P is its
    own operator; no retention expiry). assignment = {'version': gamma, 'keys': [32-byte holder keys in coordinate order], 'k', 'n',
    'q'} from the registry; the manifest also repeats (k, n, q), the identities and the seal mode.
    `fragments` overrides the honest fragments (fault injection only). Returns (manifest, n fragments, aux)."""
    k, n, q = assignment['k'], assignment['n'], assignment['q']
    check_thresholds(k, n, q)
    if mode not in SEAL_MODES:
        raise ConfigError(f'unknown seal mode {mode!r}')
    if len(assignment['keys']) != n:
        raise ConfigError('assignment key list length != n')
    man = {'v': MAN_V, 'sid': sid.hex(), 'e': e, 'm_e': len(recs), 'gamma': assignment['version'], 'k': k, 'n': n, 'q': q, 'holders': [h.hex() for h in assignment['keys']],
           'mode': mode}
    aux = {}
    if mode == 'whole_epoch':
        ser = serialize_epoch(sid, e, recs)
        frags = fragments if fragments is not None else encode_fragments(ser, k, n)
        man.update(R_e=epoch_root(sid, e, recs).hex(), frag_len=len(frags[0]), frag_hashes=[H(f).hex() for f in frags])
        aux['ser'] = ser
    else:
        lay = kzg.layout(len(recs), k)
        data = kzg.data_fragments(recs, k)
        com = [[c.hex() for c in kzg.commit_fragment(f, lay)] for f in data]
        frags = fragments if fragments is not None else kzg.encode(data, n)
        man.update(layout=lay.to_dict(), com=com, frag_len=lay.frag_bytes, srs_sha256=kzg.SETUP_SHA256,
                   code='RS-systematic over BLS12-381 F_r, points x_i=i')
        aux.update(data=data, layout=lay)
    man['sig'] = sign(sk, MAN_DOMAIN + canon(man)).hex()
    return man, frags, aux


def manifest_hash(man: dict) -> bytes:
    return H(MAN_DOMAIN, canon(man))


def cert_hash(cert: dict) -> bytes:
    return H(CERT_DOMAIN, canon(cert))


def assignment_of(reg_assignment: dict) -> dict:
    """Registry assignment record (from certify.registry_at) -> the dict used by manifests."""
    return {'version': reg_assignment['version'], 'keys': [bytes.fromhex(x) for x in reg_assignment['keys']],
            'k': reg_assignment['k'], 'n': reg_assignment['n'], 'q': reg_assignment['q']}


def verify_manifest(man: dict, sid: bytes, e: int, p_key: bytes, assignment: dict) -> None:
    """p_key: P's registered Ed25519 key (the one registered at the finalized height for a holder; at the anchor block
    for a reader). assignment: the registry assignment the manifest must pin (current at the finalized height for a
    holder; active at the anchor block for a reader)."""
    try:
        body = {k: v for k, v in man.items() if k != 'sig'}
        if body.get('v') != MAN_V or body['sid'] != sid.hex() or body['e'] != e:
            raise RecoveryError('manifest identity mismatch')
        k, n, q, m_e = body['k'], body['n'], body['q'], body['m_e']
        try:
            check_thresholds(k, n, q)
        except ConfigError as exc:
            raise RecoveryError(f'manifest thresholds invalid: {exc}')
        if type(m_e) is not int or m_e < 1 or body['mode'] not in SEAL_MODES:
            raise RecoveryError('manifest parameters')
        if 'exp' in body:
            raise RecoveryError('manifest carries an expiry field (no retention expiry in protocol v2)')
        if 'key_version' in body:
            raise RecoveryError('manifest carries an operator version field (not in the v2 manifest)')
        if not verify_sig(p_key, MAN_DOMAIN + canon(body), bytes.fromhex(man['sig'])):
            raise RecoveryError("invalid manifest signature (not P's registered key)")
        if body['gamma'] != assignment['version']:
            raise RecoveryError(f"manifest pins assignment version {body['gamma']} != {assignment['version']}")
        if (k, n, q) != (assignment['k'], assignment['n'], assignment['q']):
            raise RecoveryError('manifest (k,n,q) differs from the assignment')
        if [bytes.fromhex(h) for h in body['holders']] != list(assignment['keys']):
            raise RecoveryError('holder list differs from the assignment')
        if body['mode'] == 'whole_epoch':
            if body['frag_len'] != whole_frag_len(m_e, k) or len(body['frag_hashes']) != n or len(body['R_e']) != 64:
                raise RecoveryError('whole_epoch fields inconsistent with m_e/k/n')
        else:
            lay = kzg.layout(m_e, k)
            if body['layout'] != lay.to_dict() or body['frag_len'] != lay.frag_bytes:
                raise RecoveryError('fragment layout inconsistent with m_e/k')
            if body['srs_sha256'] != kzg.SETUP_SHA256:
                raise RecoveryError('manifest names another SRS')
            com = body['com']
            if len(com) != k or any(len(row) != lay.pieces or any(len(c) != 96 for c in row) for row in com):
                raise RecoveryError('commitment list shape')
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise RecoveryError(f'malformed manifest: {exc}') from exc


def noncanonical_slots(recs: list[bytes]) -> list[int]:
    """Slots whose record is not 23 canonical BN254 elements (whole_epoch mode: holders refuse such epochs)."""
    return [j for j, r in enumerate(recs)
            if len(r) != REC_BYTES or any(int.from_bytes(r[i:i + 32], 'big') >= FIELD for i in range(0, REC_BYTES, 32))]


def make_ack(sk: SigningKey, h_manifest: bytes, i: int) -> dict:
    return {'i': i, 'sig': sign(sk, ack_message(h_manifest, i)).hex()}


def valid_acks(cert: dict, man: dict) -> list[int]:
    """Distinct coordinates with a valid ack on H(man); raises on duplicates/invalid entries."""
    hm = manifest_hash(man)
    if cert['h_manifest'] != hm.hex():
        raise RecoveryError('certificate bound to another manifest')
    keys = [bytes.fromhex(h) for h in man['holders']]
    seen = []
    for a in cert['acks']:
        i = a['i']
        if type(i) is not int or not 1 <= i <= man['n'] or i in seen:
            raise RecoveryError('duplicate/invalid ack coordinate')
        if not verify_sig(keys[i - 1], ack_message(hm, i), bytes.fromhex(a['sig'])):
            raise RecoveryError(f'invalid ack from coordinate {i}')
        seen.append(i)
    return seen


def verify_cert(cert: dict, man: dict, need: int | None = None) -> None:
    """AvailOK iff >= q (the manifest's) distinct-coordinate valid acks on the same H(M_e)."""
    try:
        need = man['q'] if need is None else need
        seen = valid_acks(cert, man)
        if len(seen) < need:
            raise RecoveryError(f'only {len(seen)} valid acks; need q={need}')
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryError(f'malformed certificate: {exc}') from exc


def fragment_check(man: dict, i: int, data: bytes) -> tuple[bool, str]:
    if not (type(i) is int and 1 <= i <= man['n']):
        return False, 'coordinate outside 1..n'
    if man['mode'] == 'whole_epoch':
        if len(data) != man['frag_len']:
            return False, 'length mismatch'
        return (True, 'ok') if H(data).hex() == man['frag_hashes'][i - 1] else (False, 'hash mismatch')
    return kzg.verify_fragment(man['com'], i, data, kzg.layout(man['m_e'], man['k']), man['n'])


def fragment_ok(man: dict, i: int, data: bytes) -> bool:
    return fragment_check(man, i, data)[0]


def decode_epoch(man: dict, frags: dict[int, bytes]) -> list[bytes]:
    """frags: coordinate -> data, already checked with fragment_check. Returns the records."""
    if len(frags) < man['k']:
        raise RecoveryError(f"fewer than k={man['k']} valid distinct fragments ({len(frags)})")
    if man['mode'] == 'whole_epoch':
        return check_consistency(man, decode_raw(man, frags))
    try:
        return kzg.decode(frags, kzg.layout(man['m_e'], man['k']), man['n'])  # slots verbatim 
    except Exception as exc:
        raise RecoveryError(f'decode failed: {exc}') from exc


def decode_raw(man: dict, frags: dict[int, bytes]) -> bytes:
    k, n = man['k'], man['n']
    if len(frags) < k:
        raise RecoveryError(f'fewer than k={k} valid distinct fragments ({len(frags)})')
    idx = sorted(frags)[:k]
    try:
        blocks = Decoder(k, n).decode([frags[i] for i in idx], [i - 1 for i in idx])
    except Exception as exc:
        raise RecoveryError(f'decode failed: {exc}') from exc
    return b''.join(blocks)


def check_consistency(man: dict, raw: bytes) -> list[bytes]:
    """whole_epoch mode: header, padding, R_e and a full re-encoding against all n fragment hashes."""
    m_e = man['m_e']
    length = 48 + m_e * REC_BYTES
    if any(raw[length:]):
        raise RecoveryError('nonzero padding')
    sid, e, count = raw[:32], int.from_bytes(raw[32:40], 'big'), int.from_bytes(raw[40:48], 'big')
    if sid.hex() != man['sid'] or e != man['e'] or count != m_e:
        raise RecoveryError('decoded header mismatch')
    recs = [raw[48 + i * REC_BYTES:48 + (i + 1) * REC_BYTES] for i in range(m_e)]
    if epoch_root(sid, e, recs).hex() != man['R_e']:
        raise RecoveryError('R_e mismatch after decoding (inconsistent encoding)')
    re = encode_fragments(raw[:length], man['k'], man['n'])
    if any(H(f).hex() != man['frag_hashes'][i] for i, f in enumerate(re)):
        raise RecoveryError('re-encoding does not match manifest (inconsistent encoding)')
    return recs


def slot_check(man: dict, j: int, rec: bytes, proof) -> tuple[bool, str]:
    """Sender release check: whole_epoch -> Merkle path under R_e; fragment_kzg -> EC.VerifySlot (KZG opening)."""
    if man['mode'] == 'whole_epoch':
        ok = verify_inclusion(man['R_e'], man['m_e'], j, rec, proof)
        return ok, 'ok' if ok else 'no valid inclusion path under R_e'
    return kzg.verify_slot(man['com'], kzg.layout(man['m_e'], man['k']), j, rec, proof)
