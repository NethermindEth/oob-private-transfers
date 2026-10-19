//! Native (out-of-circuit) implementations that match the circuit exactly:
//! circomlib Poseidon (t = 3, 4), the width-4 Poseidon permutation, PoseidonChain,
//! BabyJubjub (circomlibjs Base8 / subOrder), ECDH, and the zk-kit Poseidon cipher
//! (encrypt / decrypt with authentication-tag check).
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use std::cmp::Ordering;
use std::sync::OnceLock;

/// Pool denomination: 0.01 ETH in wei (m[2]).
pub const DENOMINATION: u64 = 10_000_000_000_000_000;
pub const MESSAGE_LEN: usize = 18;
pub const CIPHERTEXT_LEN: usize = 22;

pub fn from_hex(s: &str) -> Fr {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.into() };
    let bytes = hex::decode(s).unwrap();
    let mut acc = Fr::ZERO;
    for b in bytes {
        acc = acc * Fr::from(256) + Fr::from(b as u64)
    }
    acc
}

#[derive(Deserialize)]
struct RawConstants {
    #[serde(rename = "C")]
    c: Vec<Vec<String>>,
    #[serde(rename = "M")]
    m: Vec<Vec<Vec<String>>>,
}
pub struct Constants {
    pub c: Vec<Vec<Fr>>,
    pub m: Vec<Vec<Vec<Fr>>>,
}
/// circomlibjs 0.1.7 poseidon_constants.json, widths t=3 (index 0) and t=4 (index 1).
pub fn constants() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(|| {
        let r: RawConstants =
            serde_json::from_str(include_str!("../poseidon_constants.json")).unwrap();
        Constants {
            c: r.c.iter().map(|r| r.iter().map(|s| from_hex(s)).collect()).collect(),
            m: r.m
                .iter()
                .map(|m| m.iter().map(|r| r.iter().map(|s| from_hex(s)).collect()).collect())
                .collect(),
        }
    })
}

fn permutation(mut state: Vec<Fr>) -> Vec<Fr> {
    let t = state.len();
    assert!(t == 3 || t == 4);
    let idx = t - 3;
    let c = constants();
    let rounds = if t == 3 { 65 } else { 64 };
    for r in 0..rounds {
        for j in 0..t {
            state[j] += c.c[idx][r * t + j];
            if r < 4 || r >= rounds - 4 || j == 0 {
                state[j] = state[j].pow_vartime([5]);
            }
        }
        state = (0..t)
            .map(|i| (0..t).map(|j| c.m[idx][i][j] * state[j]).sum())
            .collect();
    }
    state
}

/// circomlib Poseidon(n) for n = 2, 3.
pub fn poseidon(xs: &[Fr]) -> Fr {
    let mut state = vec![Fr::ZERO];
    state.extend_from_slice(xs);
    permutation(state)[0]
}

/// Width-4 permutation (circomlibjs `poseidon(inputs, initState, 4)` all outputs).
pub fn permute4(state: [Fr; 4]) -> [Fr; 4] {
    permutation(state.to_vec()).try_into().unwrap()
}

pub fn chain(domain: u64, values: &[Fr]) -> Fr {
    values.iter().fold(Fr::from(domain), |acc, v| poseidon(&[acc, *v]))
}
pub fn payload_hash(m: &[Fr; 18]) -> Fr {
    chain(1001, m)
}
pub fn commitment(owner: Fr, seed: Fr, payload_hash: Fr) -> Fr {
    poseidon(&[owner, seed, payload_hash])
}
pub fn note_commitment(m: &[Fr; 18]) -> Fr {
    commitment(m[5], m[3], payload_hash(m))
}
/// Owner field of address (ob, pk_R): Poseidon2(ob, Poseidon2(pk.x, pk.y)) (owner binding).
pub fn owner_field(ob: Fr, pk: &Point) -> Fr {
    poseidon(&[ob, poseidon(&[pk.0, pk.1])])
}
pub fn tag(cm: Fr, seed: Fr) -> Fr {
    poseidon(&[Fr::from(1002), cm, seed])
}
pub fn digest(c: &[Fr; 22]) -> Fr {
    chain(1003, c)
}
/// Root from leaf and path; direction 1 means the current node is the right child
/// (matches Spend.circom and ShieldedPool.sol: index bit i).
pub fn merkle_root(leaf: Fr, siblings: &[Fr], directions: &[bool]) -> Fr {
    let mut cur = leaf;
    for (s, d) in siblings.iter().zip(directions) {
        cur = if *d { poseidon(&[*s, cur]) } else { poseidon(&[cur, *s]) };
    }
    cur
}

// ---------------------------------------------------------------- BabyJubjub
pub type Point = (Fr, Fr);
const A: u64 = 168700;
const D: u64 = 168696;

pub fn subgroup_order() -> Fr {
    Fr::from_str_vartime(
        "2736030358979909402780800718157159386076813972158567259200215660948447373041",
    )
    .unwrap()
}
/// circomlibjs Base8, generator of the prime-order subgroup.
pub fn base8() -> Point {
    (
        from_hex("0bb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051"),
        from_hex("25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b"),
    )
}
pub fn on_curve(p: &Point) -> bool {
    let xx = p.0.square();
    let yy = p.1.square();
    Fr::from(A) * xx + yy == Fr::ONE + Fr::from(D) * xx * yy
}
pub fn add(p: &Point, q: &Point) -> Point {
    let xx = p.0 * q.0;
    let yy = p.1 * q.1;
    let dxy = Fr::from(D) * xx * yy;
    let x = (p.0 * q.1 + p.1 * q.0) * (Fr::ONE + dxy).invert().unwrap();
    let y = (yy - Fr::from(A) * xx) * (Fr::ONE - dxy).invert().unwrap();
    (x, y)
}
/// Double-and-add over the little-endian bits of `k` (all 256 bits of its repr).
pub fn mul(p: &Point, k: &Fr) -> Point {
    let bytes = k.to_repr();
    let mut acc = (Fr::ZERO, Fr::ONE);
    let mut base = *p;
    for i in 0..256 {
        if (bytes[i / 8] >> (i % 8)) & 1 == 1 {
            acc = add(&acc, &base);
        }
        base = add(&base, &base);
    }
    acc
}
pub fn in_subgroup(p: &Point) -> bool {
    mul(p, &subgroup_order()) == (Fr::ZERO, Fr::ONE)
}
/// Recipient-key validity exactly as constrained in the full circuit.
pub fn valid_key(p: &Point) -> bool {
    on_curve(p) && p.0 != Fr::ZERO && in_subgroup(p)
}
/// Integer comparison of canonical field elements.
pub fn cmp_int(a: &Fr, b: &Fr) -> Ordering {
    let mut x = a.to_repr();
    let mut y = b.to_repr();
    x.reverse();
    y.reverse();
    x.cmp(&y)
}
/// Uniform sample from [1, l) by rejection over 251-bit strings (l < 2^251).
pub fn random_scalar() -> Fr {
    let l = subgroup_order();
    loop {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        b[31] &= 0x07;
        let s = Fr::from_repr(b).unwrap();
        if s != Fr::ZERO && cmp_int(&s, &l) == Ordering::Less {
            return s;
        }
    }
}
/// Uniform nonce < 2^128.
pub fn random_nonce() -> Fr {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b[..16]);
    Fr::from_repr(b).unwrap()
}
pub fn two_128() -> Fr {
    Fr::from(2).pow_vartime([128])
}
pub fn keypair() -> (Fr, Point) {
    let sk = random_scalar();
    (sk, mul(&base8(), &sk))
}

// ---------------------------------------------------------------- Poseidon cipher
/// Encrypt with explicit randomness r and nonce. Returns C = (epk.x, epk.y, nonce, c1..c18, auth).
pub fn encrypt_with(pk: &Point, m: &[Fr; 18], r: Fr, nonce: Fr) -> Result<[Fr; 22], String> {
    if !valid_key(pk) {
        return Err("invalid recipient key (curve/subgroup/x!=0)".into());
    }
    if cmp_int(&nonce, &two_128()) != Ordering::Less {
        return Err("nonce >= 2^128".into());
    }
    if r == Fr::ZERO || cmp_int(&r, &subgroup_order()) != Ordering::Less {
        return Err("randomness outside [1, l)".into());
    }
    Ok(encrypt_unchecked(pk, m, r, nonce))
}
/// The cipher without any input validation. ONLY for adversarial tests (e.g. nonce >= 2^128,
/// invalid keys); honest code uses `encrypt` / `encrypt_with`.
pub fn encrypt_unchecked(pk: &Point, m: &[Fr; 18], r: Fr, nonce: Fr) -> [Fr; 22] {
    let epk = mul(&base8(), &r);
    let k = mul(pk, &r);
    let mut out = vec![epk.0, epk.1, nonce];
    let mut state = [Fr::ZERO, k.0, k.1, nonce + Fr::from(18) * two_128()];
    for chunk in m.chunks(3) {
        state = permute4(state);
        for j in 0..3 {
            state[j + 1] += chunk[j];
            out.push(state[j + 1]);
        }
    }
    state = permute4(state);
    out.push(state[1]);
    out.try_into().unwrap()
}
/// Encrypt with fresh OS randomness: r uniform in [1, l), nonce uniform < 2^128.
pub fn encrypt(pk: &Point, m: &[Fr; 18]) -> Result<([Fr; 22], Fr, Fr), String> {
    let r = random_scalar();
    let nonce = random_nonce();
    Ok((encrypt_with(pk, m, r, nonce)?, r, nonce))
}
#[derive(Debug, PartialEq)]
pub enum DecryptError {
    Malformed(String),
    Auth,
}
pub fn decrypt(sk: &Fr, c: &[Fr; 22]) -> Result<[Fr; 18], DecryptError> {
    let epk = (c[0], c[1]);
    if !valid_key(&epk) {
        return Err(DecryptError::Malformed("epk not a valid subgroup point".into()));
    }
    let nonce = c[2];
    if cmp_int(&nonce, &two_128()) != Ordering::Less {
        return Err(DecryptError::Malformed("nonce >= 2^128".into()));
    }
    let k = mul(&epk, sk);
    let mut state = [Fr::ZERO, k.0, k.1, nonce + Fr::from(18) * two_128()];
    let mut m = Vec::with_capacity(18);
    for i in 0..6 {
        state = permute4(state);
        for j in 0..3 {
            let ct = c[3 + 3 * i + j];
            m.push(ct - state[j + 1]);
            state[j + 1] = ct;
        }
    }
    state = permute4(state);
    if state[1] != c[21] {
        return Err(DecryptError::Auth);
    }
    Ok(m.try_into().unwrap())
}

/// Public statement (rt_h, d, nu_adm) implied by a witness.
pub fn statement(
    m: &[Fr; 18],
    c: &[Fr; 22],
    siblings: &[Fr],
    directions: &[bool],
) -> (Fr, Fr, Fr) {
    let cm = note_commitment(m);
    (merkle_root(cm, siblings, directions), digest(c), tag(cm, m[3]))
}
