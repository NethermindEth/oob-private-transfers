//! Native (non-circuit) implementation of the protocol objects the admission
//! circuit proves statements about. Every circuit gadget is tested against this
//! module, and the witness filler in `admission` is built from
//! [`instance::AdmissionInstance`].
//!
//! Instantiation:
//! - all hashes are domain-separated SHA-256, `H_a(x) = SHA256(a || x)` with an
//!   8-byte ASCII domain `a`;
//! - note encryption follows Zcash Sapling/Orchard note encryption with the
//!   primitives swapped: secp256k1 x-only ECDH, SHA-256 KDF, AES-128-CTR with a zero
//!   nonce, `C = epk || ct`;
//! - the Merkle tree has depth 32 and `node = SHA256(left || right)`.

pub mod enc;
pub mod hashes;
pub mod instance;
pub mod merkle;
pub mod note;
pub mod vectors;

pub use enc::{Encryption, decrypt, encrypt};
pub use instance::{AdmissionInstance, Condition, PublicInputs, Witness};
pub use merkle::{MerklePath, NodeHash, SparseMerkleTree};
pub use note::{Address, Note, Recipient};
