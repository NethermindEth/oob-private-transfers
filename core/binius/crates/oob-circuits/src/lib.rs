//! Circuits for the proof-carrying append of the OOB private data plane
//! (paper, Section 5.2, relation R_adm), instantiated
//! with SHA-256 as the hash family, AES-128-CTR as the data-encapsulation
//! cipher and Binius64 as the proof system.
//!
//! Module layout:
//! - `aes`        bitsliced AES-128-CTR (S-box, key schedule, rounds, 64x64 transposes)
//! - `ecdh`       secp256k1 x-only ECDH: `epk = x([esk]G)`, `ss = x([esk]pk_R)` (full binding)
//! - `hashes`     domain-separated SHA-256 instances H_cm, H_lock, H_tag, H_ct, H_kdf
//! - `merkle`     SHA-256 Merkle authentication path (depth 32)
//! - `admission`  the full R_adm circuit and its witness filler
//! - `reference`  native (non-circuit) implementations used to build witnesses and test vectors

pub mod admission;
pub mod aes;
pub mod ecdh;
pub mod hashes;
pub mod merkle;
pub mod reference;
