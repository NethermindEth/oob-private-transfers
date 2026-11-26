//! Bitsliced AES-128-CTR with a zero IV, written once over [`Ops`] so the same
//! code runs natively on `u64` words (test oracle) and in circuit on wires.
//!
//! Layout: lane `l` of every word is CTR block `l` (up to 64 blocks per
//! evaluation). The 128 state words are indexed by [`idx`]`(p, i)` = bit `i` of
//! state byte `p` (FIPS-197 byte order, column-major). The index is chosen so
//! that transposing each 64-word half yields, per lane, the two big-endian
//! 32-bit words of that half of the block: after the transpose, lane `l`'s
//! word holds block bytes `4q..4q+4` big-endian in its low half and bytes
//! `4q+4..4q+8` in its high half.
//!
//! Measured costs (64-bit AND constraints): the Boyar-Peralta S-box is 34 AND
//! for 64 parallel evaluations; ShiftRows is a renaming and MixColumns is XORs,
//! both free; round keys are broadcast words (free to build); the whole
//! keystream (10 rounds + key schedule) is 6,698; each 64x64 transpose is 192;
//! extracting the 32-bit words costs about 6 per block.

#![allow(clippy::needless_range_loop)] // bit-index loops read better as loops

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// Word operations shared by the native and circuit evaluations.
pub trait Ops {
    type T: Copy;
    fn xor(&self, a: Self::T, b: Self::T) -> Self::T;
    fn and(&self, a: Self::T, b: Self::T) -> Self::T;
    fn not(&self, a: Self::T) -> Self::T;
    fn shl(&self, a: Self::T, n: u32) -> Self::T;
    fn shr(&self, a: Self::T, n: u32) -> Self::T;
    fn sar(&self, a: Self::T, n: u32) -> Self::T;
    fn constant(&self, v: u64) -> Self::T;
    /// All-ones if bit `bit` of `w` is set, else zero.
    fn broadcast(&self, w: Self::T, bit: u32) -> Self::T {
        self.sar(self.shl(w, 63 - bit), 63)
    }
}

pub struct Native;

impl Ops for Native {
    type T = u64;
    fn xor(&self, a: u64, b: u64) -> u64 {
        a ^ b
    }
    fn and(&self, a: u64, b: u64) -> u64 {
        a & b
    }
    fn not(&self, a: u64) -> u64 {
        !a
    }
    fn shl(&self, a: u64, n: u32) -> u64 {
        a << n
    }
    fn shr(&self, a: u64, n: u32) -> u64 {
        a >> n
    }
    fn sar(&self, a: u64, n: u32) -> u64 {
        ((a as i64) >> n) as u64
    }
    fn constant(&self, v: u64) -> u64 {
        v
    }
}

impl Ops for &CircuitBuilder {
    type T = Wire;
    fn xor(&self, a: Wire, b: Wire) -> Wire {
        self.bxor(a, b)
    }
    fn and(&self, a: Wire, b: Wire) -> Wire {
        self.band(a, b)
    }
    fn not(&self, a: Wire) -> Wire {
        self.bnot(a)
    }
    fn shl(&self, a: Wire, n: u32) -> Wire {
        CircuitBuilder::shl(self, a, n)
    }
    fn shr(&self, a: Wire, n: u32) -> Wire {
        CircuitBuilder::shr(self, a, n)
    }
    fn sar(&self, a: Wire, n: u32) -> Wire {
        CircuitBuilder::sar(self, a, n)
    }
    fn constant(&self, v: u64) -> Wire {
        self.add_constant(Word(v))
    }
}

type State<T> = [T; 128];

/// Word index of bit `i` of state byte `p`.
const fn idx(p: usize, i: usize) -> usize {
    64 * (p / 8) + 32 * ((p % 8) / 4) + 8 * (3 - p % 4) + i
}

fn byte<T: Copy>(s: &State<T>, p: usize) -> [T; 8] {
    std::array::from_fn(|i| s[idx(p, i)])
}

fn set_byte<T: Copy>(s: &mut State<T>, p: usize, v: [T; 8]) {
    for (i, b) in v.into_iter().enumerate() {
        s[idx(p, i)] = b;
    }
}

/// AES S-box, Boyar-Peralta 113-gate circuit (32 AND). `u[i]` is bit `i` (LSB = 0).
#[rustfmt::skip]
fn sbox<O: Ops>(o: &O, u: [O::T; 8]) -> [O::T; 8] {
    let x = |a, b| o.xor(a, b);
    let m = |a, b| o.and(a, b);
    let xn = |a, b| o.not(o.xor(a, b));
    // Boyar-Peralta number inputs MSB first.
    let (u0, u1, u2, u3, u4, u5, u6, u7) = (u[7], u[6], u[5], u[4], u[3], u[2], u[1], u[0]);
    let t1 = x(u0, u3);   let t2 = x(u0, u5);   let t3 = x(u0, u6);   let t4 = x(u3, u5);
    let t5 = x(u4, u6);   let t6 = x(t1, t5);   let t7 = x(u1, u2);   let t8 = x(u7, t6);
    let t9 = x(u7, t7);   let t10 = x(t6, t7);  let t11 = x(u1, u5);  let t12 = x(u2, u5);
    let t13 = x(t3, t4);  let t14 = x(t6, t11); let t15 = x(t5, t11); let t16 = x(t5, t12);
    let t17 = x(t9, t16); let t18 = x(u3, u7);  let t19 = x(t7, t18); let t20 = x(t1, t19);
    let t21 = x(u6, u7);  let t22 = x(t7, t21); let t23 = x(t2, t22); let t24 = x(t2, t10);
    let t25 = x(t20, t17); let t26 = x(t3, t16); let t27 = x(t1, t12);
    let m1 = m(t13, t6);  let m2 = m(t23, t8);  let m3 = x(t14, m1);  let m4 = m(t19, u7);
    let m5 = x(m4, m1);   let m6 = m(t3, t16);  let m7 = m(t22, t9);  let m8 = x(t26, m6);
    let m9 = m(t20, t17); let m10 = x(m9, m6);  let m11 = m(t1, t15); let m12 = m(t4, t27);
    let m13 = x(m12, m11); let m14 = m(t2, t10); let m15 = x(m14, m11); let m16 = x(m3, m2);
    let m17 = x(m5, t24); let m18 = x(m8, m7);  let m19 = x(m10, m15); let m20 = x(m16, m13);
    let m21 = x(m17, m15); let m22 = x(m18, m13); let m23 = x(m19, t25); let m24 = x(m22, m23);
    let m25 = m(m22, m20); let m26 = x(m21, m25); let m27 = x(m20, m21); let m28 = x(m23, m25);
    let m29 = m(m28, m27); let m30 = m(m26, m24); let m31 = m(m20, m23); let m32 = m(m27, m31);
    let m33 = x(m27, m25); let m34 = m(m21, m22); let m35 = m(m24, m34); let m36 = x(m24, m25);
    let m37 = x(m21, m29); let m38 = x(m32, m33); let m39 = x(m23, m30); let m40 = x(m35, m36);
    let m41 = x(m38, m40); let m42 = x(m37, m39); let m43 = x(m37, m38); let m44 = x(m39, m40);
    let m45 = x(m42, m41);
    let m46 = m(m44, t6);  let m47 = m(m40, t8);  let m48 = m(m39, u7);  let m49 = m(m43, t16);
    let m50 = m(m38, t9);  let m51 = m(m37, t17); let m52 = m(m42, t15); let m53 = m(m45, t27);
    let m54 = m(m41, t10); let m55 = m(m44, t13); let m56 = m(m40, t23); let m57 = m(m39, t19);
    let m58 = m(m43, t3);  let m59 = m(m38, t22); let m60 = m(m37, t20); let m61 = m(m42, t1);
    let m62 = m(m45, t4);  let m63 = m(m41, t2);
    let l0 = x(m61, m62);  let l1 = x(m50, m56);  let l2 = x(m46, m48);  let l3 = x(m47, m55);
    let l4 = x(m54, m58);  let l5 = x(m49, m61);  let l6 = x(m62, l5);   let l7 = x(m46, l3);
    let l8 = x(m51, m59);  let l9 = x(m52, m53);  let l10 = x(m53, l4);  let l11 = x(m60, l2);
    let l12 = x(m48, m51); let l13 = x(m50, l0);  let l14 = x(m52, m61); let l15 = x(m55, l1);
    let l16 = x(m56, l0);  let l17 = x(m57, l1);  let l18 = x(m58, l8);  let l19 = x(m63, l4);
    let l20 = x(l0, l1);   let l21 = x(l1, l7);   let l22 = x(l3, l12);  let l23 = x(l18, l2);
    let l24 = x(l15, l9);  let l25 = x(l6, l10);  let l26 = x(l7, l9);   let l27 = x(l8, l10);
    let l28 = x(l11, l14); let l29 = x(l11, l17);
    let s0 = x(l6, l24);   let s1 = xn(l16, l26); let s2 = xn(l19, l28); let s3 = x(l6, l21);
    let s4 = x(l20, l22);  let s5 = x(l25, l29);  let s6 = xn(l13, l27); let s7 = xn(l6, l23);
    [s7, s6, s5, s4, s3, s2, s1, s0]
}

fn sub_bytes<O: Ops>(o: &O, s: &mut State<O::T>) {
    for p in 0..16 {
        set_byte(s, p, sbox(o, byte(s, p)));
    }
}

/// `s'[r][c] = s[r][(c + r) % 4]`, byte `p = r + 4c`.
fn shift_rows<T: Copy>(s: &State<T>) -> State<T> {
    let mut out = *s;
    for r in 0..4 {
        for c in 0..4 {
            set_byte(&mut out, r + 4 * c, byte(s, r + 4 * ((c + r) % 4)));
        }
    }
    out
}

/// `2 * a` in GF(2^8).
fn xtime<O: Ops>(o: &O, a: [O::T; 8]) -> [O::T; 8] {
    [
        a[7],
        o.xor(a[0], a[7]),
        a[1],
        o.xor(a[2], a[7]),
        o.xor(a[3], a[7]),
        a[4],
        a[5],
        a[6],
    ]
}

fn xor8<O: Ops>(o: &O, a: [O::T; 8], b: [O::T; 8]) -> [O::T; 8] {
    std::array::from_fn(|i| o.xor(a[i], b[i]))
}

fn mix_columns<O: Ops>(o: &O, s: &mut State<O::T>) {
    for c in 0..4 {
        let a: [[O::T; 8]; 4] = std::array::from_fn(|r| byte(s, r + 4 * c));
        let all = xor8(o, xor8(o, a[0], a[1]), xor8(o, a[2], a[3]));
        for r in 0..4 {
            // b_r = 2 a_r + 3 a_{r+1} + a_{r+2} + a_{r+3} = a_r + all + 2 (a_r + a_{r+1})
            let two = xtime(o, xor8(o, a[r], a[(r + 1) % 4]));
            set_byte(s, r + 4 * c, xor8(o, xor8(o, a[r], all), two));
        }
    }
}

fn add_round_key<O: Ops>(o: &O, s: &mut State<O::T>, rk: &State<O::T>) {
    for j in 0..128 {
        s[j] = o.xor(s[j], rk[j]);
    }
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128 key schedule on a bitsliced (broadcast) key; round key `r` is laid
/// out like a state, byte `p` = byte `p % 4` of word `4r + p / 4`.
fn key_schedule<O: Ops>(o: &O, key: State<O::T>) -> [State<O::T>; 11] {
    let mut rk = [key; 11];
    let mut words: Vec<[[O::T; 8]; 4]> = (0..4)
        .map(|w| std::array::from_fn(|r| byte(&key, 4 * w + r)))
        .collect();
    for i in 4..44 {
        let mut temp = words[i - 1];
        if i % 4 == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]].map(|b| sbox(o, b));
            for bit in 0..8 {
                if (RCON[i / 4 - 1] >> bit) & 1 == 1 {
                    temp[0][bit] = o.not(temp[0][bit]);
                }
            }
        }
        words.push(std::array::from_fn(|r| xor8(o, words[i - 4][r], temp[r])));
    }
    for (r, round_key) in rk.iter_mut().enumerate() {
        for p in 0..16 {
            set_byte(round_key, p, words[4 * r + p / 4][p % 4]);
        }
    }
    rk
}

/// Bitsliced keystream for blocks `0..64`: AES-128 of the counter block
/// `BE128(l)` in lane `l`, under the key given as 4 big-endian 32-bit words.
fn keystream_bitsliced<O: Ops>(o: &O, key_words: [O::T; 4]) -> State<O::T> {
    let zero = o.constant(0);
    let mut key = [zero; 128];
    for p in 0..16 {
        for i in 0..8 {
            key[idx(p, i)] = o.broadcast(key_words[p / 4], (8 * (3 - p % 4) + i) as u32);
        }
    }
    let rk = key_schedule(o, key);

    // Counter block of lane l is BE128(l): only byte 15 is non-zero, and its bit i
    // across lanes is the pattern "bit i of l".
    let mut s = [zero; 128];
    for i in 0..6 {
        let period = 1u64 << i;
        let mut pattern = 0u64;
        for l in 0..64u64 {
            if (l / period) % 2 == 1 {
                pattern |= 1 << l;
            }
        }
        s[idx(15, i)] = o.constant(pattern);
    }

    add_round_key(o, &mut s, &rk[0]);
    for round in 1..=10 {
        sub_bytes(o, &mut s);
        s = shift_rows(&s);
        if round < 10 {
            mix_columns(o, &mut s);
        }
        add_round_key(o, &mut s, &rk[round]);
    }
    s
}

/// In-place 64x64 bit transpose: afterwards `x[r]` bit `c` is the old `x[c]` bit `r`.
fn transpose64<O: Ops>(o: &O, x: &mut [O::T; 64]) {
    let mut j = 32;
    let mut mask = 0x0000_0000_FFFF_FFFFu64;
    while j != 0 {
        let m = o.constant(mask);
        for k in (0..64).filter(|k| k & j == 0) {
            // swap the high bits of row k with the low bits of row k + j
            let t = o.and(o.xor(o.shr(x[k], j as u32), x[k + j]), m);
            x[k + j] = o.xor(x[k + j], t);
            x[k] = o.xor(x[k], o.shl(t, j as u32));
        }
        j >>= 1;
        mask ^= mask << j;
    }
}

/// AES-128-CTR keystream for `n_blocks <= 64` blocks as big-endian 32-bit words
/// (4 per block, high halves zero).
pub fn ctr_keystream_words<O: Ops>(o: &O, key_words: [O::T; 4], n_blocks: usize) -> Vec<O::T> {
    assert!(n_blocks <= 64, "one bitsliced evaluation covers 64 blocks");
    let s = keystream_bitsliced(o, key_words);
    let mut halves: [[O::T; 64]; 2] = [s[..64].try_into().unwrap(), s[64..].try_into().unwrap()];
    transpose64(o, &mut halves[0]);
    transpose64(o, &mut halves[1]);
    let lo = o.constant(0xFFFF_FFFF);
    let mut out = Vec::with_capacity(4 * n_blocks);
    for l in 0..n_blocks {
        for h in &halves {
            out.push(o.and(h[l], lo));
            out.push(o.shr(h[l], 32));
        }
    }
    out
}

/// `ct = pt XOR AES-128-CTR keystream`, both as big-endian 32-bit words.
pub fn aes128_ctr<O: Ops>(o: &O, key_words: [O::T; 4], pt_words: &[O::T]) -> Vec<O::T> {
    assert!(pt_words.len().is_multiple_of(4), "whole blocks only");
    let ks = ctr_keystream_words(o, key_words, pt_words.len() / 4);
    pt_words.iter().zip(ks).map(|(p, k)| o.xor(*p, k)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::tests::{check, n_and};
    use crate::hashes::{inout_bytes32, populate_words, witness_words};
    use crate::reference::enc::{aes128_ctr_keystream, encrypt};
    use crate::reference::note::{NOTE_LEN, Note, Recipient};
    use crate::reference::vectors;
    use binius_frontend::CircuitStat;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0;
        for _ in 0..8 {
            if b & 1 == 1 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    fn sbox_table(x: u8) -> u8 {
        let inv = if x == 0 {
            0
        } else {
            (1..=255u8).find(|&y| gf_mul(x, y) == 1).unwrap()
        };
        let mut s = inv;
        for k in 1..5 {
            s ^= inv.rotate_left(k);
        }
        s ^ 0x63
    }

    #[test]
    fn sbox_matches_fips197_for_all_inputs() {
        for batch in 0..4u64 {
            // lane l carries input 64*batch + l
            let u: [u64; 8] = std::array::from_fn(|i| {
                (0..64)
                    .filter(|l| ((64 * batch + l) >> i) & 1 == 1)
                    .fold(0, |w, l| w | 1 << l)
            });
            let s = sbox(&Native, u);
            for l in 0..64u64 {
                let got = (0..8).fold(0u8, |v, i| v | (((s[i] >> l) & 1) as u8) << i);
                assert_eq!(got, sbox_table((64 * batch + l) as u8));
            }
        }
    }

    #[test]
    fn transpose_is_a_transpose() {
        let mut rng = StdRng::seed_from_u64(30);
        let x: [u64; 64] = std::array::from_fn(|_| rng.next_u64());
        let mut t = x;
        transpose64(&Native, &mut t);
        for r in 0..64 {
            for c in 0..64 {
                assert_eq!((t[r] >> c) & 1, (x[c] >> r) & 1);
            }
        }
    }

    fn key_words(key: &[u8; 16]) -> [u64; 4] {
        std::array::from_fn(|w| {
            u32::from_be_bytes(key[4 * w..4 * w + 4].try_into().unwrap()) as u64
        })
    }

    #[test]
    fn native_keystream_matches_aes_crate() {
        let mut rng = StdRng::seed_from_u64(31);
        let mut random_key = [0u8; 16];
        rng.fill_bytes(&mut random_key);
        for key in [vectors::AES128_KEY, random_key] {
            let words = ctr_keystream_words(&Native, key_words(&key), 64);
            let expected = aes128_ctr_keystream(&key, 64);
            for (w, c) in words.iter().zip(expected.chunks(4)) {
                assert_eq!(*w, u32::from_be_bytes(c.try_into().unwrap()) as u64);
            }
        }
    }

    #[test]
    fn circuit_ctr_matches_reference_encryption() {
        let mut rng = StdRng::seed_from_u64(32);
        let r = Recipient::random(&mut rng);
        {
            let b = CircuitBuilder::new();
            let key: [Wire; 4] = std::array::from_fn(|_| b.add_witness());
            let pt = witness_words(&b, NOTE_LEN);
            let ct = aes128_ctr(&&b, key, &pt);
            let expected: Vec<Wire> = (0..ct.len()).map(|_| b.add_inout()).collect();
            for (i, (c, e)) in ct.iter().zip(&expected).enumerate() {
                b.assert_eq(format!("ct[{i}]"), *c, *e);
            }
            let circuit = b.build();
            let stat = CircuitStat::collect(&circuit);
            // Measured: keystream 6,698 (the S-box measures 34 AND, not 32), 2 transposes x 192,
            // then ~6 per block to extract the four 32-bit words. Pinned so a change is noticed.
            assert_eq!(stat.n_and_constraints, 7092);

            let note = Note::random(&r.address(), &mut rng);
            let enc = encrypt(&note, &mut rng).unwrap();
            let fill = |w: &mut binius_frontend::WitnessFiller<'_>, ct_bytes: &[u8]| {
                for (wire, v) in key.iter().zip(key_words(&enc.key)) {
                    w[*wire] = Word(v);
                }
                populate_words(w, &pt, &note.to_bytes());
                populate_words(w, &expected, ct_bytes);
            };
            check(&circuit, |w| fill(w, &enc.ct)).unwrap();
            let mut bad = enc.ct.clone();
            bad[NOTE_LEN - 1] ^= 1;
            assert!(check(&circuit, |w| fill(w, &bad)).is_err());
        }
    }

    #[test]
    fn garbage_in_high_halves_of_witness_words_is_ignored() {
        // Both the AES layer and SHA-256 must read only the low 32 bits of a word.
        let b = CircuitBuilder::new();
        let key: [Wire; 4] = std::array::from_fn(|_| b.add_witness());
        let pt = witness_words(&b, 16);
        let ct = aes128_ctr(&&b, key, &pt);
        let d = crate::hashes::h_ct(&b, &ct);
        let e = inout_bytes32(&b);
        crate::hashes::assert_bytes32_eq(&b, "d", &d, &e);
        let circuit = b.build();
        let _ = n_and(&circuit);
        let ks = aes128_ctr_keystream(&vectors::AES128_KEY, 1);
        let ct_bytes: Vec<u8> = vectors::AES128_PT
            .iter()
            .zip(&ks)
            .map(|(a, b)| a ^ b)
            .collect();
        let d_bytes = crate::reference::hashes::h_ct(&ct_bytes);
        check(&circuit, |w| {
            for (wire, v) in key.iter().zip(key_words(&vectors::AES128_KEY)) {
                w[*wire] = Word(v | 0xDEAD_BEEF << 32);
            }
            populate_words(w, &pt, &vectors::AES128_PT);
            for wire in &pt {
                w[*wire] = Word(w[*wire].0 | 0xBAD0 << 48);
            }
            populate_words(w, &e, &d_bytes);
        })
        .unwrap();
    }
}
