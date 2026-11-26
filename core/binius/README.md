# OOB admission relation on Binius64

Benchmark re-instantiated with SHA-256 for every hash and the Merkle tree, AES-128-CTR under a secp256k1 x-only ECDH key for the payload encryption, and the Binius64 binary-field SNARK in its zero-knowledge mode.

## What is benchmarked

The admission relation `R_adm` (paper, Definition 1). Public `x = (rt, d, nu_adm)`, witness
`(N, h_s, rho, C, path)`; for `cm = H_cm(N)` the circuit proves

1. `Member(rt, cm, path)`: depth-32 SHA-256 Merkle path;
2. `N.lock = H_lock(h_s, N.pk_R)`: the note's key is the one bound to the address;
3. `C = Enc(N.pk_R, N; rho)`: ECIES-style note encryption with fresh randomness `rho = esk`,
   a scalar in `[1, n-1]` that the sender samples per encryption and the circuit takes as a
   free witness: `epk = x([esk]G)`, `ss = x([esk] pk_R)`, `k = H_kdf(ss, epk)`,
   `C = epk || AES-128-CTR(k, N)`;
4. `d = H_ct(C)`;
5. `nu_adm = H_tag(cm, N.salt)`.


- **`--node-hash full | compress-only`.** A Merkle node is `SHA256(left || right)`, two
  compressions because of padding, or a single call of the SHA-256 compression function on the
  64-byte input. The pool's tree dictates which one applies; compress-only halves the Merkle
  cost.

The note is 672 bytes (`pk_R || val || salt || lock || memo`), so the stored record
`nu_adm || epk || ct` is the paper's 736 bytes; the size is a constant, not a parameter.

Proof-system knobs: `--log-inv-rate` (FRI rate, proof size vs. prover time; the matrix uses 1,
2 and 4) and `RAYON_NUM_THREADS`. Binius64 pads the committed witness to a power of two, so
variants with similar sizes land in the same bucket and cost the same; the admission circuit
sits at 2^19 hidden words.

## Build

```sh
cd core/binius
RUSTFLAGS="-C target-cpu=native" cargo build --release --locked
RUSTFLAGS="-C target-cpu=native" cargo test --release --locked
target/release/oob-bench --help
```

## Benchmark

```sh
target/release/oob-bench --repeat 5 [--log-inv-rate 2] admission --node-hash {full,compress-only}

# or the full matrix, from the repository root; rows go to core/results/S7E2binius/<timestamp>/results.jsonl
scripts/benchlock core/experiments/S7E2binius/matrix.sh
```

## Layout

```
core/binius/
  Cargo.toml, Cargo.lock     workspace; Binius64 pinned by commit
  rust-toolchain.toml        1.98.1 (Binius64's pin)
  crates/oob-circuits/       gadgets + the admission circuit
    src/reference/           native note/enc/hash/merkle code (sha2, aes, ctr, k256); builds witnesses and test vectors
    src/hashes.rs            H_cm, H_lock, H_tag, H_ct, H_kdf over sha256_fixed; byte-packing helpers
    src/merkle.rs            depth-N SHA-256 authentication path (full and compress-only variants)
    src/aes.rs               bitsliced AES-128: sbox, round, key schedule, ctr_keystream, 64x64 transposes
    src/ecdh.rs              secp256k1 x-only ECDH on Binius64's scalar_mul gadget
    src/admission.rs         AdmissionCircuit { build(builder, node_hash) ; populate(witness, instance) }
  crates/oob-bench/          CLI: build / prove / verify / stats, one JSON row per run
core/experiments/S7E2binius/ benchmark matrix driver
```
