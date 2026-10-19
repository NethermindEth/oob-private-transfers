"""Erasure-code commitment EC for seal_mode = fragment_kzg (paper App. A, intended instantiation).

KZG polynomial commitments over BLS12-381 with the structured reference string of Ethereum's EIP-4844 setup
ceremony (`core/kzg/trusted_setup_4096.txt`, sha256 pinned below; no locally generated SRS is used anywhere).
Libraries: `ckzg` (c-kzg-4844 Python bindings: blob commitments, EIP-7594 cell proofs) and `py_arkworks_bls12381`
(G1 arithmetic for the linear combination of commitments).

Layout. An epoch of m_e records (23 BN254 scalars each; the BN254 scalar modulus is smaller than the BLS12-381 scalar
modulus r, so every element embeds unchanged as a 32-byte big-endian BLS12-381 scalar) is split into k data fragments
of s = ceil(m_e / k) slots: data fragment t (0-based) holds slots t*s .. t*s+s-1; slots >= m_e are zero. A fragment is
s*23 scalars = s*736 bytes, on the wire and at rest. It is committed in P = ceil(s / 178) pieces: piece p holds the
fragment's slots p*178 .. p*178+177 (178*23 = 4094 scalars) followed by zeros up to the 4096-scalar blob, committed in
Lagrange form (`blob_to_kzg_commitment`, one MSM). com_e is the k x P list of data piece commitments; it is carried in
the signed manifest.

Code. Systematic Reed-Solomon over F_r with evaluation points x_i = i (i = 1..n): fragment i = sum_t L_t(i) * F_t
coordinate-wise, L_t the Lagrange basis on {1..k}. By linearity the piece commitments of fragment i are
sum_t L_t(i) * com_e[t][p], so VerifyFrag(com_e, i, F) recomputes the P piece commitments of F and compares them with
that combination (pi_i is empty); anyone can check any fragment against the manifest alone. Every fragment has zeros at
the same blob positions (the padding), which the verifier inserts itself, so accepted fragments of one com_e lie on one
codeword whose padding is zero (code binding under t-SDH and an unknown ceremony trapdoor).

Slot opening. A record's 23 scalars lie in one piece, in at most two consecutive 64-scalar cells of the EIP-7594 cell
layout (cells 0..63 of the extended blob are the blob itself). An opening is those cells with their KZG multi-point
(coset) proofs; VerifySlot checks them against com_e[t][p] with `verify_cell_kzg_proof_batch` and compares the record's
scalars. The provider computes all cell proofs of all data pieces once per epoch; a data-fragment holder can compute
the openings of its own slots.
"""
from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001  # BLS12-381 scalar field
BLOB_ELEMS = 4096
FE = 32
BLOB_BYTES = BLOB_ELEMS * FE
REC_ELEMS = 23
REC_BYTES = REC_ELEMS * FE  # 736
SLOTS_PER_PIECE = BLOB_ELEMS // REC_ELEMS  # 178
CELL_ELEMS = 64
CELLS_PER_BLOB = BLOB_ELEMS // CELL_ELEMS  # 64 cells of the original blob (128 in the extended blob)
LANE = 66  # bytes per lane in the packed linear combination (k * r * 2^256 < 2^528 for k <= 256)
MAX_N = 255

SETUP_FILE = Path(__file__).resolve().parents[1] / 'kzg' / 'trusted_setup_4096.txt'
SETUP_SHA256 = 'd39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7'

_ts = None
_ts_lock = threading.Lock()


class KZGSetupError(Exception):
    pass


def file_sha256(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def trusted_setup(path: Path | None = None, expect: str = SETUP_SHA256):
    """Load the EIP-4844 SRS once per process, refusing any file whose sha256 differs from the pinned hash."""
    global _ts
    import ckzg
    if path is not None:  # explicit path (tests of the hash pin): never cached
        if file_sha256(path) != expect:
            raise KZGSetupError(f'trusted setup {path} does not have the pinned sha256 {expect}')
        return ckzg.load_trusted_setup(str(path), 0)
    with _ts_lock:
        if _ts is None:
            got = file_sha256(SETUP_FILE)
            if got != expect:
                raise KZGSetupError(f'trusted setup {SETUP_FILE} sha256 {got} != pinned {expect}')
            _ts = ckzg.load_trusted_setup(str(SETUP_FILE), 0)
        return _ts


def versions() -> dict:
    from importlib.metadata import version
    out = {'srs_file': str(SETUP_FILE), 'srs_sha256_pinned': SETUP_SHA256}
    for m in ('ckzg', 'py-arkworks-bls12381'):
        try:
            out[m] = version(m)
        except Exception:
            out[m] = None
    return out


# ----------------------------------------------------------------------------------------------------- layout
@dataclass(frozen=True)
class Layout:
    m_e: int
    k: int
    s: int
    pieces: int

    @property
    def frag_elems(self) -> int:
        return self.s * REC_ELEMS

    @property
    def frag_bytes(self) -> int:
        return self.s * REC_BYTES

    def locate(self, j: int) -> tuple[int, int, int, int]:
        """slot j -> (data fragment t (0-based), slot r within it, piece p, scalar offset of the record in the blob)."""
        t, r = divmod(j, self.s)
        p, q = divmod(r, SLOTS_PER_PIECE)
        return t, r, p, q * REC_ELEMS

    def cells_of(self, j: int) -> list[int]:
        off = self.locate(j)[3]
        return list(range(off // CELL_ELEMS, (off + REC_ELEMS - 1) // CELL_ELEMS + 1))

    def to_dict(self) -> dict:
        return {'s': self.s, 'pieces': self.pieces, 'slots_per_piece': SLOTS_PER_PIECE, 'blob_elems': BLOB_ELEMS,
                'rec_elems': REC_ELEMS, 'cell_elems': CELL_ELEMS}


def layout(m_e: int, k: int) -> Layout:
    if not (type(m_e) is int and m_e >= 1 and type(k) is int and k >= 1):
        raise ValueError('layout needs m_e >= 1 and k >= 1')
    s = math.ceil(m_e / k)
    return Layout(m_e, k, s, math.ceil(s / SLOTS_PER_PIECE))


def data_fragments(recs: list[bytes], k: int) -> list[bytes]:
    lay = layout(len(recs), k)
    buf = b''.join(recs) + bytes((k * lay.s - len(recs)) * REC_BYTES)
    return [buf[t * lay.frag_bytes:(t + 1) * lay.frag_bytes] for t in range(k)]


def piece_blob(frag: bytes, p: int) -> bytes:
    chunk = frag[p * SLOTS_PER_PIECE * REC_BYTES:(p + 1) * SLOTS_PER_PIECE * REC_BYTES]
    return chunk + bytes(BLOB_BYTES - len(chunk))


def commit_fragment(frag: bytes, lay: Layout) -> list[bytes]:
    """Piece commitments of one fragment (raises on a non-canonical scalar)."""
    import ckzg
    ts = trusted_setup()
    return [bytes(ckzg.blob_to_kzg_commitment(piece_blob(frag, p), ts)) for p in range(lay.pieces)]


# ----------------------------------------------------------------------------------------------------- code
def lagrange_coeffs(points: list[int], x: int) -> list[int]:
    """L_i(x) for the Lagrange basis on `points` (distinct field elements), mod r."""
    out = []
    for i, xi in enumerate(points):
        num, den = 1, 1
        for m, xm in enumerate(points):
            if m != i:
                num = num * (x - xm) % R
                den = den * (xi - xm) % R
        out.append(num * pow(den, -1, R) % R)
    return out


@lru_cache(maxsize=64)
def generator(k: int, n: int) -> tuple[tuple[int, ...], ...]:
    """G[i-1][t] = L_t(i) on {1..k}; rows 1..k are unit vectors (systematic)."""
    if not 1 <= k <= n <= MAX_N:
        raise ValueError(f'invalid code parameters k={k}, n={n}')
    pts = list(range(1, k + 1))
    return tuple(tuple(lagrange_coeffs(pts, i)) for i in range(1, n + 1))


def _pack(frag: bytes) -> int:
    L = len(frag) // FE
    a = np.zeros((L, LANE), dtype=np.uint8)
    a[:, LANE - FE:] = np.frombuffer(frag, dtype=np.uint8).reshape(L, FE)
    return int.from_bytes(a.tobytes(), 'big')


def lincomb(frags: list[bytes], coeffs: list[int]) -> bytes:
    """Coordinate-wise sum_t coeffs[t] * frags[t] mod r (scalars as 32-byte big-endian). Lane packing: one big-integer
    multiply per input fragment, then one reduction per output scalar."""
    L = len(frags[0]) // FE
    assert all(len(f) == L * FE for f in frags) and len(frags) <= 256
    nz = [(c % R, f) for c, f in zip(coeffs, frags) if c % R]
    if not nz:
        return bytes(L * FE)
    if len(nz) == 1 and nz[0][0] == 1:
        return bytes(nz[0][1])
    acc = 0
    for c, f in nz:
        acc += c * _pack(f)
    b = acc.to_bytes(L * LANE, 'big')
    out = bytearray(L * FE)
    fb = int.from_bytes
    for l in range(L):
        out[l * FE:(l + 1) * FE] = (fb(b[l * LANE:(l + 1) * LANE], 'big') % R).to_bytes(FE, 'big')
    return bytes(out)


def encode(data: list[bytes], n: int) -> list[bytes]:
    k = len(data)
    G = generator(k, n)
    return list(data) + [lincomb(data, list(G[i])) for i in range(k, n)]


def canonical(frag: bytes) -> bool:
    return all(int.from_bytes(frag[x:x + FE], 'big') < R for x in range(0, len(frag), FE))


# ----------------------------------------------------------------------------------------------------- commitments
@lru_cache(maxsize=65536)
def _point(c: bytes):
    from py_arkworks_bls12381 import G1Point
    return G1Point.from_compressed_bytes(c)  # checked decoding (on curve, in subgroup)


def expected_commitments(com: list[list[str]], i: int, n: int) -> list[bytes]:
    """Piece commitments of coordinate i derived from the data piece commitments com (k x P hex)."""
    from py_arkworks_bls12381 import Scalar
    k = len(com)
    if i <= k:
        return [bytes.fromhex(c) for c in com[i - 1]]
    g = generator(k, n)[i - 1]
    out = []
    for p in range(len(com[0])):
        acc = None
        for t in range(k):
            if g[t]:
                term = _point(bytes.fromhex(com[t][p])) * Scalar(g[t])
                acc = term if acc is None else acc + term
        out.append(bytes(acc.to_compressed_bytes()))
    return out


def verify_fragment(com: list[list[str]], i: int, frag: bytes, lay: Layout, n: int) -> tuple[bool, str]:
    """EC.VerifyFrag: does `frag` equal coordinate i of the codeword committed by com?"""
    if not (type(i) is int and 1 <= i <= n):
        return False, 'coordinate outside 1..n'
    if len(frag) != lay.frag_bytes:
        return False, f'fragment length {len(frag)} != {lay.frag_bytes}'
    if len(com) != lay.k or any(len(c) != lay.pieces for c in com):
        return False, 'commitment list shape inconsistent with layout'
    try:
        want = expected_commitments(com, i, n)
    except Exception as exc:
        return False, f'invalid commitment in manifest: {type(exc).__name__}: {exc}'
    try:
        got = commit_fragment(frag, lay)
    except Exception as exc:
        return False, f'fragment is not a vector of canonical BLS12-381 scalars: {exc}'
    for p, (a, b) in enumerate(zip(got, want)):
        if a != b:
            return False, f'piece {p}: commitment of the fragment does not match com_e (off the committed codeword)'
    return True, 'ok'


def decode(frags: dict[int, bytes], lay: Layout, n: int) -> list[bytes]:
    """Records (slots 0..m_e-1, verbatim) from any k verified fragments {coordinate: bytes}."""
    k = lay.k
    if len(frags) < k:
        raise ValueError(f'fewer than k={k} fragments')
    S = sorted(frags)[:k]
    data = []
    for t in range(1, k + 1):
        if t in frags:
            data.append(frags[t])
        else:
            data.append(lincomb([frags[i] for i in S], lagrange_coeffs(S, t)))
    buf = b''.join(data)
    return [buf[j * REC_BYTES:(j + 1) * REC_BYTES] for j in range(lay.m_e)]


# ----------------------------------------------------------------------------------------------------- openings
def piece_proofs(frag: bytes, p: int) -> list[bytes]:
    """Cell proofs of cells 0..63 (the blob itself) of piece p (FK20 batch inside c-kzg)."""
    import ckzg
    _, proofs = ckzg.compute_cells_and_kzg_proofs(piece_blob(frag, p), trusted_setup())
    return [bytes(x) for x in proofs[:CELLS_PER_BLOB]]


def slot_opening(frag: bytes, lay: Layout, j: int, proofs: list[bytes] | None = None) -> dict:
    """EC.OpenSlot from the data fragment that holds slot j (proofs: precomputed cell proofs of its piece)."""
    t, r, p, off = lay.locate(j)
    blob = piece_blob(frag, p)
    proofs = proofs if proofs is not None else piece_proofs(frag, p)
    return {'j': j, 't': t, 'p': p,
            'cells': [{'c': c, 'data': blob[c * CELL_ELEMS * FE:(c + 1) * CELL_ELEMS * FE].hex(), 'proof': proofs[c].hex()}
                      for c in lay.cells_of(j)]}


def verify_slot(com: list[list[str]], lay: Layout, j: int, rec: bytes, opening: dict) -> tuple[bool, str]:
    """EC.VerifySlot(com_e, j, rec, sigma)."""
    import ckzg
    try:
        if not (type(j) is int and 0 <= j < lay.m_e):
            return False, 'slot outside the committed epoch (j >= m_e)'
        if len(rec) != REC_BYTES:
            return False, 'record length'
        t, r, p, off = lay.locate(j)
        if opening.get('j') != j or opening.get('t') != t or opening.get('p') != p:
            return False, 'opening names another slot/piece'
        cells = opening['cells']
        want = lay.cells_of(j)
        if [c['c'] for c in cells] != want:
            return False, f'opening cells {[c["c"] for c in cells]} != {want}'
        data = [bytes.fromhex(c['data']) for c in cells]
        proofs = [bytes.fromhex(c['proof']) for c in cells]
        if any(len(d) != CELL_ELEMS * FE for d in data) or any(len(x) != 48 for x in proofs):
            return False, 'malformed cell/proof'
        C = bytes.fromhex(com[t][p])
        if not ckzg.verify_cell_kzg_proof_batch([C] * len(cells), want, data, proofs, trusted_setup()):
            return False, 'cell proof does not verify against com_e'
        base = want[0] * CELL_ELEMS
        got = b''.join(data)[(off - base) * FE:(off - base + REC_ELEMS) * FE]
        if got != rec:
            return False, 'committed slot differs from the record (omitted, moved or altered)'
        return True, 'ok'
    except Exception as exc:
        return False, f'malformed opening: {type(exc).__name__}: {exc}'
