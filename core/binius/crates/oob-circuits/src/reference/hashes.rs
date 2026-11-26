//! Domain-separated SHA-256 instances: `H_a(x) = SHA256(a || x)`.

use sha2::{Digest, Sha256};

/// Length of every domain constant, in bytes.
pub const DOMAIN_LEN: usize = 8;

pub const DOM_SEC: &[u8; DOMAIN_LEN] = b"oob/sec\0";
pub const DOM_CM: &[u8; DOMAIN_LEN] = b"oob/cm\0\0";
pub const DOM_LOCK: &[u8; DOMAIN_LEN] = b"oob/lock";
pub const DOM_TAG: &[u8; DOMAIN_LEN] = b"oob/tag\0";
pub const DOM_CT: &[u8; DOMAIN_LEN] = b"oob/ct\0\0";
pub const DOM_KDF: &[u8; DOMAIN_LEN] = b"oob/kdf\0";

pub type Hash32 = [u8; 32];

/// `a || parts[0] || parts[1] || ...`
pub fn preimage(domain: &[u8; DOMAIN_LEN], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_LEN + parts.iter().map(|p| p.len()).sum::<usize>());
    out.extend_from_slice(domain);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

pub fn sha256(bytes: &[u8]) -> Hash32 {
    Sha256::digest(bytes).into()
}

fn h(domain: &[u8; DOMAIN_LEN], parts: &[&[u8]]) -> Hash32 {
    sha256(&preimage(domain, parts))
}

/// `h_s = H_sec(s)`: public address component derived from the spending secret.
/// Not part of the admission relation (the circuit takes `h_s` as a witness).
pub fn h_sec(s: &[u8; 32]) -> Hash32 {
    h(DOM_SEC, &[s])
}

/// `cm = H_cm(N)` over the note's byte encoding.
pub fn h_cm(note_bytes: &[u8]) -> Hash32 {
    h(DOM_CM, &[note_bytes])
}
pub fn h_cm_preimage(note_bytes: &[u8]) -> Vec<u8> {
    preimage(DOM_CM, &[note_bytes])
}

/// `lock = H_lock(h_s, pk_R)`: binds the spending authority to the encryption key.
pub fn h_lock(h_s: &Hash32, pk_r: &[u8; 32]) -> Hash32 {
    h(DOM_LOCK, &[h_s, pk_r])
}
pub fn h_lock_preimage(h_s: &Hash32, pk_r: &[u8; 32]) -> Vec<u8> {
    preimage(DOM_LOCK, &[h_s, pk_r])
}

/// `nu_adm = H_tag(cm, salt)`: the admission tag, one per shielded output.
pub fn h_tag(cm: &Hash32, salt: &[u8; 32]) -> Hash32 {
    h(DOM_TAG, &[cm, salt])
}
pub fn h_tag_preimage(cm: &Hash32, salt: &[u8; 32]) -> Vec<u8> {
    preimage(DOM_TAG, &[cm, salt])
}

/// `d = H_ct(C)`: digest of the note ciphertext `C = epk || ct`.
pub fn h_ct(c: &[u8]) -> Hash32 {
    h(DOM_CT, &[c])
}
pub fn h_ct_preimage(c: &[u8]) -> Vec<u8> {
    preimage(DOM_CT, &[c])
}

/// `k = H_kdf(ss, epk)[0..16]`: AES-128 key from the ECDH shared x-coordinate and the
/// ephemeral public key (mirrors `KDF^Sapling(sharedSecret, ephemeralKey)`).
pub fn h_kdf(ss: &[u8; 32], epk: &[u8; 32]) -> [u8; 16] {
    let full = h(DOM_KDF, &[ss, epk]);
    full[..16].try_into().expect("16 bytes")
}
pub fn h_kdf_preimage(ss: &[u8; 32], epk: &[u8; 32]) -> Vec<u8> {
    preimage(DOM_KDF, &[ss, epk])
}

/// Merkle node, full variant: `SHA256(left || right)` (2 compressions).
pub fn merkle_node(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// SHA-256 initial state (FIPS 180-4, 5.3.3).
pub const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Merkle node, compress-only variant: one SHA-256 compression of the 64-byte
/// block `left || right` from the IV, without padding (1 compression). Used as a
/// sensitivity point in the benchmark; not a standard SHA-256 tree.
pub fn merkle_node_compress_only(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    let mut state = SHA256_IV;
    sha2::block_api::compress256(&mut state, &[block]);
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::vectors;

    #[test]
    fn sha256_nist_abc() {
        assert_eq!(sha256(b"abc"), vectors::SHA256_ABC);
    }

    #[test]
    fn domains_are_distinct_and_8_bytes() {
        let all = [DOM_SEC, DOM_CM, DOM_LOCK, DOM_TAG, DOM_CT, DOM_KDF];
        for (i, a) in all.iter().enumerate() {
            assert_eq!(a.len(), DOMAIN_LEN);
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn preimages_match_hashes() {
        let x = [7u8; 32];
        let y = [9u8; 32];
        assert_eq!(h_lock(&x, &y), sha256(&h_lock_preimage(&x, &y)));
        assert_eq!(h_tag(&x, &y), sha256(&h_tag_preimage(&x, &y)));
        assert_eq!(h_cm(&x), sha256(&h_cm_preimage(&x)));
        assert_eq!(h_ct(&x), sha256(&h_ct_preimage(&x)));
        assert_eq!(h_kdf(&x, &y)[..], sha256(&h_kdf_preimage(&x, &y))[..16]);
    }

    #[test]
    fn compress_only_node_is_one_compression_of_the_block() {
        // compress(IV, "abc" padded) must equal SHA256("abc"): checks our state
        // serialisation against the library's own padding path.
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 0x18;
        let left: Hash32 = block[..32].try_into().unwrap();
        let right: Hash32 = block[32..].try_into().unwrap();
        assert_eq!(
            merkle_node_compress_only(&left, &right),
            vectors::SHA256_ABC
        );
        assert_ne!(merkle_node(&left, &right), vectors::SHA256_ABC);
    }
}
