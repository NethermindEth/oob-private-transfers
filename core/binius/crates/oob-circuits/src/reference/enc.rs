//! Note encryption
//!
//! ```text
//! esk <-$ [1, n-1]                     (fresh per encryption; big-endian scalar)
//! epk = x([esk] G)                     ss = x([esk] lift_x(pk_R))
//! k   = H_kdf(ss, epk)[0..16]
//! ct  = AES-128-CTR(k, iv = 0^128, N)
//! C   = epk || ct
//! ```

use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{Context, Result, ensure};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
pub use k256::{AffinePoint as Point, Scalar};

use rand::Rng;

use super::hashes::h_kdf;
use super::note::{AES_BLOCK, EPK_LEN, Note};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// All intermediate values of one encryption; the circuit witness needs every one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encryption {
    /// The encryption randomness `rho`: a big-endian scalar in `[1, n-1]`.
    pub esk: [u8; 32],
    pub epk: [u8; 32],
    /// x-coordinate of the shared point.
    pub ss: [u8; 32],
    pub key: [u8; 16],
    /// `ct = AES-128-CTR(k, N)`, same length as the note.
    pub ct: Vec<u8>,
}

impl Encryption {
    /// `C = epk || ct`
    pub fn ciphertext(&self) -> Vec<u8> {
        let mut c = Vec::with_capacity(EPK_LEN + self.ct.len());
        c.extend_from_slice(&self.epk);
        c.extend_from_slice(&self.ct);
        c
    }
}

/// A point with x-coordinate `x` (either sign), or `None` if `x` is not on the curve.
pub fn lift_x(x: &[u8; 32]) -> Option<Point> {
    Point::decompress(&(*x).into(), Choice::from(0)).into()
}

pub fn point_x(p: &Point) -> [u8; 32] {
    p.x().into()
}

pub fn point_y(p: &Point) -> [u8; 32] {
    p.y().into()
}

/// Big-endian scalar in `[1, n-1]`.
pub fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).filter(|s| !bool::from(s.is_zero()))
}

pub fn mul(k: &Scalar, p: &Point) -> Point {
    (*p * k).to_affine()
}

/// Fresh ephemeral scalar, uniform in `[1, n-1]` (rejection sampling; a retry
/// happens with probability about 2^-128).
pub fn random_esk(rng: &mut impl Rng) -> [u8; 32] {
    loop {
        let mut esk = [0u8; 32];
        rng.fill_bytes(&mut esk);
        if scalar(&esk).is_some() {
            return esk;
        }
    }
}

/// AES-128-CTR keystream of `n_blocks` blocks with a zero IV.
pub fn aes128_ctr_keystream(key: &[u8; 16], n_blocks: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n_blocks * AES_BLOCK];
    Aes128Ctr::new(key.into(), &[0u8; 16].into()).apply_keystream(&mut buf);
    buf
}

/// AES-128-CTR with a zero IV (encryption and decryption are the same operation).
pub fn aes128_ctr(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    Aes128Ctr::new(key.into(), &[0u8; 16].into()).apply_keystream(&mut buf);
    buf
}

/// Encrypt `note` to `note.pk_r` with fresh randomness `rho = esk` drawn from
/// `rng`, so two encryptions of one note differ. Fails if `pk_R` is not on the
/// curve (the paper's "pk_R is a valid encryption key").
pub fn encrypt(note: &Note, rng: &mut impl Rng) -> Result<Encryption> {
    encrypt_with(note, &random_esk(rng))
}

/// `Enc(pk_R, N; rho)` with explicit randomness `rho = esk`, which must be a
/// big-endian scalar in `[1, n-1]`. Never reuse an `esk`: with the same `pk_R`
/// it repeats the AES key and keystream.
pub fn encrypt_with(note: &Note, esk_bytes: &[u8; 32]) -> Result<Encryption> {
    let esk = scalar(esk_bytes).context("esk is not a scalar in [1, n-1]")?;
    let pk = lift_x(&note.pk_r).context("pk_R is not on secp256k1")?;
    let epk = point_x(&mul(&esk, &Point::GENERATOR));
    let ss = point_x(&mul(&esk, &pk));
    let key = h_kdf(&ss, &epk);
    let ct = aes128_ctr(&key, &note.to_bytes());
    Ok(Encryption {
        esk: *esk_bytes,
        epk,
        ss,
        key,
        ct,
    })
}

/// Recipient-side decryption of `C = epk || ct` with `sk_R`. Returns the note;
/// the caller checks `cm`, `lock` and `d` against what it expects.
pub fn decrypt(sk_r: &Scalar, c: &[u8]) -> Result<Note> {
    ensure!(c.len() > EPK_LEN, "ciphertext too short");
    let epk: [u8; 32] = c[..EPK_LEN].try_into().unwrap();
    let e = lift_x(&epk).context("epk is not on secp256k1")?;
    let key = h_kdf(&point_x(&mul(sk_r, &e)), &epk);
    let pt = aes128_ctr(&key, &c[EPK_LEN..]);
    Note::from_bytes(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::note::{AES_BLOCKS, CIPHERTEXT_LEN, NOTE_LEN, Recipient};
    use crate::reference::vectors;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn aes128_fips197_vector() {
        let cipher = Aes128::new((&vectors::AES128_KEY).into());
        let mut block = vectors::AES128_PT;
        cipher.encrypt_block((&mut block).into());
        assert_eq!(block, vectors::AES128_CT);
    }

    #[test]
    fn ctr_keystream_is_aes_of_big_endian_counters() {
        let key = vectors::AES128_KEY;
        let ks = aes128_ctr_keystream(&key, 3);
        let cipher = Aes128::new((&key).into());
        for i in 0..3u128 {
            let mut block = i.to_be_bytes();
            cipher.encrypt_block((&mut block).into());
            assert_eq!(&ks[16 * i as usize..16 * (i as usize + 1)], &block);
        }
    }

    #[test]
    fn secp256k1_two_g_vector_and_x_only_lift() {
        let two = mul(&Scalar::from(2u64), &Point::GENERATOR);
        assert_eq!(point_x(&two), vectors::SECP256K1_2G_X);
        assert_eq!(point_y(&two), vectors::SECP256K1_2G_Y);
        let lifted = lift_x(&vectors::SECP256K1_2G_X).unwrap();
        assert!(lifted == two || lifted == -two);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = StdRng::seed_from_u64(2);
        let r = Recipient::random(&mut rng);
        let n = Note::random(&r.address(), &mut rng);
        let e = encrypt(&n, &mut rng).unwrap();
        let c = e.ciphertext();
        assert_eq!(c.len(), CIPHERTEXT_LEN);
        assert_eq!(e.ct.len(), NOTE_LEN);
        // keystream relation the circuit will prove
        let ks = aes128_ctr_keystream(&e.key, AES_BLOCKS);
        let xored: Vec<u8> = n.to_bytes().iter().zip(&ks).map(|(a, b)| a ^ b).collect();
        assert_eq!(xored, e.ct);
        assert_eq!(decrypt(&r.sk_r, &c).unwrap(), n);
        // explicit randomness reproduces the ciphertext
        assert_eq!(encrypt_with(&n, &e.esk).unwrap(), e);
    }

    #[test]
    fn wrong_recipient_does_not_decrypt_to_the_note() {
        let mut rng = StdRng::seed_from_u64(3);
        let r = Recipient::random(&mut rng);
        let other = Recipient::random(&mut rng);
        let n = Note::random(&r.address(), &mut rng);
        let c = encrypt(&n, &mut rng).unwrap().ciphertext();
        let got = decrypt(&other.sk_r, &c).unwrap();
        assert_ne!(got, n);
    }

    #[test]
    fn off_curve_pk_is_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let r = Recipient::random(&mut rng);
        let mut n = Note::random(&r.address(), &mut rng);
        // about half of all x values have no point; find one
        n.pk_r = (1u8..)
            .map(|i| [i; 32])
            .find(|x| lift_x(x).is_none())
            .unwrap();
        assert!(encrypt(&n, &mut rng).is_err());
    }

    #[test]
    fn encryption_is_randomized() {
        let mut rng = StdRng::seed_from_u64(5);
        let r = Recipient::random(&mut rng);
        let n = Note::random(&r.address(), &mut rng);
        let (a, b) = (encrypt(&n, &mut rng).unwrap(), encrypt(&n, &mut rng).unwrap());
        assert_ne!(a.esk, b.esk);
        assert_ne!(a.epk, b.epk);
        assert_ne!(a.key, b.key);
        assert_ne!(a.ct, b.ct);
        for e in [&a, &b] {
            assert_eq!(decrypt(&r.sk_r, &e.ciphertext()).unwrap(), n);
        }
    }

    #[test]
    fn out_of_range_esk_is_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        let r = Recipient::random(&mut rng);
        let n = Note::random(&r.address(), &mut rng);
        assert!(encrypt_with(&n, &[0u8; 32]).is_err());
        assert!(encrypt_with(&n, &[0xff; 32]).is_err()); // >= n
    }
}
