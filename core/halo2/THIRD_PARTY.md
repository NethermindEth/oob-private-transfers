# Sources and implementation choices

- Halo paper: Sean Bowe, Jack Grigg and Daira Hopwood, *Recursive Proof Composition without a Trusted Setup*, https://eprint.iacr.org/2019/1021 . This backend is a standalone Halo 2 proof, not an implementation of the paper's recursive composition protocol.
- `halo2_proofs` 0.3.5: Zcash's IPA-based implementation, https://github.com/zcash/halo2 , MIT OR Apache-2.0. Cargo.lock pins the complete dependency tree. This does not use the PSE/Axiom KZG proving-system fork.
- `halo2curves` 0.6.1 supplies BN254 curve arithmetic (MIT OR Apache-2.0). BN254 is used so the arithmetic circuit can match the existing pool's scalar-field Poseidon commitments. This is a custom curve instantiation of the upstream IPA backend, not Zcash's deployed Pasta configuration. Pairings/KZG are not used; recursive composition is not implemented. No claim of equivalent security to a Pasta instantiation is made.
- `poseidon_constants.json` contains the width-three and width-four constants from `circomlibjs` 0.1.7 `src/poseidon_constants.json`, https://github.com/iden3/circomlibjs . Upstream declares GPL-3.0; its notice/license applies to that data. The license text is included as `CIRCOMLIBJS-GPL-3.0.txt`. The Cargo manifest describes the Rust code's license, not third-party data. The independent test vector uses the pinned npm dependency.
- `sha2` hashes parameter files and verification-key identifiers; admission hashes are constrained Poseidon operations.


Parameters and verification keys are derived locally from the fixed circuit and upstream deterministic `Params::new(k)` for the circuit size. There is no secret setup contribution, externally supplied verification key, Groth16 ceremony, or `MockProver` acceptance in the Halo network verification path. `MockProver` is only a negative-test tool.
