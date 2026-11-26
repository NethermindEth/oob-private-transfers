//! Note layout, addresses and recipients.
//!
//! `N = pk_R (32) || val (8, big-endian) || salt (32) || lock (32) || memo (568)`, 672 bytes.

use anyhow::{Result, ensure};
use k256::elliptic_curve::ops::Reduce;
use rand::Rng;

use super::enc::{Point, Scalar, mul, point_x};
use super::hashes::{Hash32, h_cm, h_lock, h_sec};

pub const PK_LEN: usize = 32;
pub const VAL_LEN: usize = 8;
pub const SALT_LEN: usize = 32;
pub const LOCK_LEN: usize = 32;
/// Bytes before the memo.
pub const NOTE_HEADER_LEN: usize = PK_LEN + VAL_LEN + SALT_LEN + LOCK_LEN;
pub const AES_BLOCK: usize = 16;
pub const EPK_LEN: usize = 32;
pub const TAG_LEN: usize = 32;

/// Note length: 736-byte record as in the paper (`TAG_LEN + EPK_LEN + NOTE_LEN`).
pub const NOTE_LEN: usize = 672;
pub const MEMO_LEN: usize = NOTE_LEN - NOTE_HEADER_LEN;
pub const AES_BLOCKS: usize = NOTE_LEN / AES_BLOCK;
const _: () = assert!(
    NOTE_LEN.is_multiple_of(AES_BLOCK) && AES_BLOCKS <= 64,
    "must fit the 64-lane AES"
);
/// `|C| = |epk| + |ct|`
pub const CIPHERTEXT_LEN: usize = EPK_LEN + NOTE_LEN;
/// `|pl| = |nu_adm| + |C|`
pub const RECORD_LEN: usize = TAG_LEN + CIPHERTEXT_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub pk_r: [u8; PK_LEN],
    pub val: u64,
    pub salt: [u8; SALT_LEN],
    pub lock: [u8; LOCK_LEN],
    pub memo: Vec<u8>,
}

impl Note {
    /// Encoded length in bytes.
    pub fn byte_len(&self) -> usize {
        NOTE_HEADER_LEN + self.memo.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len());
        out.extend_from_slice(&self.pk_r);
        out.extend_from_slice(&self.val.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.lock);
        out.extend_from_slice(&self.memo);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == NOTE_LEN,
            "note length {} is not {NOTE_LEN}",
            bytes.len()
        );
        let mut off = 0;
        let mut take = |n: usize| {
            let s = &bytes[off..off + n];
            off += n;
            s
        };
        let pk_r = take(PK_LEN).try_into().unwrap();
        let val = u64::from_be_bytes(take(VAL_LEN).try_into().unwrap());
        let salt = take(SALT_LEN).try_into().unwrap();
        let lock = take(LOCK_LEN).try_into().unwrap();
        let memo = bytes[off..].to_vec();
        Ok(Note {
            pk_r,
            val,
            salt,
            lock,
            memo,
        })
    }

    /// `cm = H_cm(N)`
    pub fn commitment(&self) -> Hash32 {
        h_cm(&self.to_bytes())
    }

    /// Build a note paying `addr`, with `lock = H_lock(h_s, pk_R)`.
    pub fn new(addr: &Address, val: u64, salt: [u8; SALT_LEN], memo: Vec<u8>) -> Self {
        assert_eq!(memo.len(), MEMO_LEN, "memo length");
        Note {
            pk_r: addr.pk_r,
            val,
            salt,
            lock: h_lock(&addr.h_s, &addr.pk_r),
            memo,
        }
    }

    /// Random note for `addr`.
    pub fn random(addr: &Address, rng: &mut impl Rng) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut memo = vec![0u8; MEMO_LEN];
        rng.fill_bytes(&mut memo);
        Note::new(addr, rng.next_u64(), salt, memo)
    }
}

/// Shielded address `(h_s, pk_R)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub h_s: Hash32,
    pub pk_r: [u8; PK_LEN],
}

/// A recipient: spending secret `s`, `h_s = H_sec(s)`, secp256k1 key pair; the
/// address carries only `x(pk_R)`.
#[derive(Clone)]
pub struct Recipient {
    pub s: [u8; 32],
    pub h_s: Hash32,
    pub sk_r: Scalar,
    pub pk_r: Point,
}

impl Recipient {
    pub fn from_seeds(s: [u8; 32], sk_bytes: [u8; 32]) -> Self {
        let sk_r = <Scalar as Reduce<k256::FieldBytes>>::reduce(&sk_bytes.into());
        assert!(!bool::from(sk_r.is_zero()), "zero secret key");
        let pk_r = mul(&sk_r, &Point::GENERATOR);
        Recipient {
            s,
            h_s: h_sec(&s),
            sk_r,
            pk_r,
        }
    }

    pub fn random(rng: &mut impl Rng) -> Self {
        let mut s = [0u8; 32];
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut s);
        rng.fill_bytes(&mut sk);
        Self::from_seeds(s, sk)
    }

    pub fn address(&self) -> Address {
        Address {
            h_s: self.h_s,
            pk_r: point_x(&self.pk_r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn sizes_match_the_paper() {
        assert_eq!(AES_BLOCKS, 42);
        assert_eq!(CIPHERTEXT_LEN, 704);
        assert_eq!(RECORD_LEN, 736);
    }

    #[test]
    fn note_roundtrip_and_lock() {
        let mut rng = StdRng::seed_from_u64(1);
        let r = Recipient::random(&mut rng);
        let n = Note::random(&r.address(), &mut rng);
        assert_eq!(n.byte_len(), NOTE_LEN);
        let bytes = n.to_bytes();
        assert_eq!(Note::from_bytes(&bytes).unwrap(), n);
        assert!(Note::from_bytes(&bytes[..NOTE_LEN - 16]).is_err());
        assert_eq!(n.lock, h_lock(&r.h_s, &r.address().pk_r));
        assert_eq!(n.commitment(), h_cm(&bytes));
    }

    #[test]
    fn deterministic_recipient() {
        let a = Recipient::from_seeds([1; 32], [2; 32]);
        let b = Recipient::from_seeds([1; 32], [2; 32]);
        assert_eq!(a.address(), b.address());
        assert_eq!(a.h_s, h_sec(&[1; 32]));
    }
}
