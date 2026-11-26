//! The key agreement of condition 3: `epk = x([esk] G)` and `ss = x([esk] pk_R)` on
//! secp256k1, using Binius64's GLV windowed scalar multiplication. Keys are
//! x-only; the recipient's `y` is a witness checked against the curve equation,
//! which is sound because x-only ECDH is sign-agnostic (see `reference::enc`).

use binius_circuits::bignum::{BigUint, biguint_lt};
use binius_circuits::ecdsa::scalar_mul::scalar_mul;
use binius_circuits::secp256k1::{Secp256k1, Secp256k1Affine};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, WitnessFiller};

use crate::hashes::Bytes32;
use crate::reference::enc::{lift_x, point_y};

/// secp256k1 field prime as little-endian limbs.
const P: [u64; 4] = [0xFFFF_FFFE_FFFF_FC2F, u64::MAX, u64::MAX, u64::MAX];

/// 8 big-endian 32-bit words -> 4 little-endian 64-bit limbs; reads low halves only.
fn words_to_limbs(b: &CircuitBuilder, w: &Bytes32) -> BigUint {
    let m32 = b.add_constant(Word(0xFFFF_FFFF));
    let limbs = (0..4)
        .map(|i| b.bxor(b.shl(w[2 * (3 - i)], 32), b.band(w[2 * (3 - i) + 1], m32)))
        .collect();
    BigUint { limbs }
}

/// Inverse of [`words_to_limbs`] (high halves zero).
fn limbs_to_words(b: &CircuitBuilder, x: &BigUint) -> Bytes32 {
    let m32 = b.add_constant(Word(0xFFFF_FFFF));
    std::array::from_fn(|j| {
        let limb = x.limbs[3 - j / 2];
        if j % 2 == 0 {
            b.shr(limb, 32)
        } else {
            b.band(limb, m32)
        }
    })
}

/// Big-endian 32 bytes -> little-endian 64-bit limbs.
pub fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_be_bytes(bytes[24 - 8 * i..32 - 8 * i].try_into().unwrap()))
}

pub struct Ecdh {
    pk_y: BigUint,
    pub epk: Bytes32,
    pub ss: Bytes32,
}

impl Ecdh {
    /// `esk` is the encryption randomness, a big-endian scalar the prover
    /// chooses freely (must be in `[1, n-1]`, or no witness exists; only the
    /// low halves of its words are read); `pk_x` the note's `pk_R`. Enforces that `pk_R` is a valid key:
    /// canonical `x < p` and on the curve.
    pub fn build(b: &CircuitBuilder, esk: &Bytes32, pk_x: &Bytes32) -> Self {
        let curve = Secp256k1::new(b);
        let esk = words_to_limbs(b, esk);
        let pk_y = BigUint::new_witness(b, 4);
        let pk = Secp256k1Affine {
            x: words_to_limbs(b, pk_x),
            y: pk_y.clone(),
            is_point_at_infinity: b.add_constant(Word::ZERO),
        };
        let p = BigUint {
            limbs: P.iter().map(|&l| b.add_constant_64(l)).collect(),
        };
        b.assert_true("pk_x_canonical", biguint_lt(b, &pk.x, &p));
        curve.assert_on_curve(b, &pk);

        let epk = scalar_mul(
            &b.subcircuit("epk"),
            &curve,
            &esk,
            Secp256k1Affine::generator(b),
        );
        let ss = scalar_mul(&b.subcircuit("ss"), &curve, &esk, pk);
        b.assert_false("epk_finite", epk.is_point_at_infinity);
        b.assert_false("ss_finite", ss.is_point_at_infinity);
        Ecdh {
            pk_y,
            epk: limbs_to_words(b, &epk.x),
            ss: limbs_to_words(b, &ss.x),
        }
    }

    /// Fills `y(pk_R)`. An off-curve `pk_x` gets `y = 0`, which the circuit rejects.
    pub fn populate(&self, w: &mut WitnessFiller<'_>, pk_x: &[u8; 32]) {
        let y = lift_x(pk_x).map(|p| point_y(&p)).unwrap_or([0; 32]);
        self.pk_y.populate_limbs(w, &bytes_to_limbs(&y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::tests::check;
    use crate::hashes::{assert_bytes32_eq, inout_bytes32, populate_words, witness_bytes32};
    use crate::reference::enc::encrypt;
    use crate::reference::note::{Note, Recipient};
    use binius_frontend::CircuitStat;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn matches_reference_and_rejects_bad_keys() {
        let b = CircuitBuilder::new();
        let (esk, pk_x) = (witness_bytes32(&b), witness_bytes32(&b));
        let (want_epk, want_ss) = (inout_bytes32(&b), inout_bytes32(&b));
        let e = Ecdh::build(&b, &esk, &pk_x);
        assert_bytes32_eq(&b, "epk", &e.epk, &want_epk);
        assert_bytes32_eq(&b, "ss", &e.ss, &want_ss);
        let circuit = b.build();
        let stat = CircuitStat::collect(&circuit);
        println!(
            "ecdh: AND={} BMUL={} IMUL={} internal={}",
            stat.n_and_constraints,
            stat.n_bmul_constraints,
            stat.n_imul_constraints,
            stat.n_internal
        );

        let mut rng = StdRng::seed_from_u64(50);
        let r = Recipient::random(&mut rng);
        let n = Note::random(&r.address(), &mut rng);
        let enc = encrypt(&n, &mut rng).unwrap();
        let e = &e;
        let fill = |esk_v: [u8; 32], pk_v: [u8; 32], epk_v: [u8; 32], ss_v: [u8; 32]| {
            move |w: &mut WitnessFiller<'_>| {
                populate_words(w, &esk, &esk_v);
                populate_words(w, &pk_x, &pk_v);
                populate_words(w, &want_epk, &epk_v);
                populate_words(w, &want_ss, &ss_v);
                e.populate(w, &pk_v);
            }
        };
        check(&circuit, fill(enc.esk, n.pk_r, enc.epk, enc.ss)).unwrap();
        let mut bad = enc.esk;
        bad[31] ^= 1;
        assert!(
            check(&circuit, fill(bad, n.pk_r, enc.epk, enc.ss)).is_err(),
            "esk"
        );
        let off = (1u8..)
            .map(|i| [i; 32])
            .find(|x| lift_x(x).is_none())
            .unwrap();
        assert!(
            check(&circuit, fill(enc.esk, off, enc.epk, enc.ss)).is_err(),
            "off-curve pk"
        );
        let mut ss = enc.ss;
        ss[0] ^= 1;
        assert!(
            check(&circuit, fill(enc.esk, n.pk_r, enc.epk, ss)).is_err(),
            "ss"
        );
    }
}
