//! OOB admission relation R_adm (admission specification) for halo2_proofs 0.3.5 (IPA over BN254).
//! See README.md and AUDIT.md.
pub mod adversarial;
pub mod gadgets;
pub mod native;
pub mod relation;
pub mod setup;
pub mod wire;

pub use relation::{AdmissionCircuit, AdmissionWitness, Variant};
pub use setup::Keys;
