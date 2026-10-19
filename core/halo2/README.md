# core/halo2: OOB admission relation (`oob-admission`)

This crate implements the admission relation `R_adm` on `halo2_proofs` 0.3.5 (IPA over BN254 G1, Blake2b Fiat–Shamir, non-recursive). Two
variants exist:

- **P1 (full binding)** is the principal relation.
- **W1 (weak: digest only)** is measured for comparison and always labelled as weak.

The Poseidon constants come from circomlibjs 0.1.7
(GPL-3.0 data; see `THIRD_PARTY.md` and `CIRCOMLIBJS-GPL-3.0.txt`). The audit is in `AUDIT.md`.

## Build and run

```sh
cd core/halo2
cargo build --release --locked
# JSON-lines worker (one request per line on stdin, one reply per line on stdout)
target/release/oob-admission --keys ../../.cache/halo2-keys --depth 32 --variant full --role prover
echo '{"op":"info"}' | target/release/oob-admission --role tool --depth 32 --variant full
# Tests
cargo test --release --test native_vectors --test gadget_soundness
cargo test --release --test adversarial -- --test-threads 1
# E4 (whole driver under the lock), then the table
../../scripts/benchlock ../../.venv/bin/python ../experiments/E4/run_e4.py
../../.venv/bin/python ../experiments/E4/make_table.py
```

Flags:
- `--depth 8|16|32` sets the Merkle depth. It is a runtime parameter; `k` is chosen minimally from an exact
  row count.
- `--variant full|weak`
- `--role prover|verifier|tool`. A verifier builds no pk. `tool` builds no keys and serves native ops only.
- `--keys DIR` caches `params_k{k}.bin` together with its SHA-256, and pins the vk digest in
  `vk_<relation>_d<depth>_k<k>.sha256`.

halo2_proofs 0.3.5 cannot serialize pk/vk, so both are regenerated at start-up (about 5 s at k=17).

## Interface

Field elements are 64 lowercase hex characters (32-byte big-endian canonical encoding, no `0x`). Replies are
`{"result": ...}` or `{"error": ...}`.

| op | request | result |
|---|---|---|
| `info` | – | `relation, variant, variant_label, depth, k, rows, advice_columns, gate_degree, proof_bytes_expected, vk_sha256, setup{...}` |
| `keypair` | – | `sk` (uniform in [1, l)), `pk:[x,y]` = sk·Base8 |
| `owner` (A11) | `ob, pk:[x,y]` | `owner` = Poseidon2(ob, Poseidon2(pk.x, pk.y)) |
| `payload_hash` | `message[18]` | `payload_hash` = PoseidonChain(1001, m) |
| `commitment` | `owner, seed, payload_hash` | `cm` = Poseidon3(owner, seed, payload_hash) |
| `tag` | `cm, seed` | `nu` = Poseidon3(1002, cm, seed) |
| `digest` | `ciphertext[22]` | `d` = PoseidonChain(1003, C) |
| `encrypt` | `pk, message[18]` (`allow_pk_mismatch` for tests only) | `ciphertext[22], randomness, nonce` (r uniform in [1, l), nonce < 2^128, OS RNG) |
| `decrypt` | `sk, ciphertext[22]` | `message[18]`, or error `auth` (tag check) / `malformed: ...` |
| `prove` | `public{root,digest,tag}`, `witness{message, ob, randomness, nonce, ciphertext, siblings[depth], directions[depth]}` | `proof` (hex), `prove_seconds`, `proof_bytes` |
| `verify` | `public, proof` | `valid` (false for any malformed or invalid proof; never errors), `verify_seconds` |
| extra | `hash{values[2\|3]}`, `merkle_root{leaf,siblings,directions}`, `statement{message,ciphertext,siblings,directions}` | circomlib-compatible helpers |

- `prove` checks the witness natively first and returns a named error ("owner field ... (A11)", "root mismatch",
  ...). After proving it verifies its own proof.
- Merkle direction 1 means the current node is the right child (index bit i), as in `ShieldedPool.sol` and
  `Spend.circom`.
- W1 ignores `ob`, `randomness`, `nonce` and `ciphertext`.

## What the relation proves

For public `(rt, d, ν)`, P1 proves knowledge of `(m, ob, r, nonce, C, path)` such that:

1. `cm = Poseidon3(m[5], m[3], PoseidonChain(1001, m))` and `m[2]` = 0.01 ETH.
2. **1b (A11):** `m[5] = Poseidon2(ob, Poseidon2(m[0], m[1]))`.
3. `cm` lies under root `rt` along a depth-D path with boolean directions.
4. `ν = Poseidon3(1002, cm, m[3])`.
5. `pk_R = (m[0], m[1])` is on BabyJubjub, has x ≠ 0, and lies in the prime-order subgroup. `epk = r·Base8`
   with epk.x ≠ 0, and `K = r·pk_R`. `C = (epk, nonce, PoseidonCipher_K(m; nonce), auth)` with nonce < 2^128.
6. `d = PoseidonChain(1003, C)`.

Together these give: the admitted bytes decrypt, under the encryption key of the address that the output
pays, to the committed note. W1 proves only items 1, 3 and 4. It has no 1b, and its `d` is public but
unconstrained. Anyone who knows the note opening can prove W1 for **any** `d`.

## What it does NOT establish
- **No simulation-extractability or non-malleability claim.** Providers see proofs. P1 relies on knowledge
  soundness via the composite-prover argument (`AUDIT.md`). W1's binding of `d` would need non-malleability,
  which it lacks.
- Tests exercise implementation behavior. They do not prove soundness, zero knowledge or unforgeability.
- Security level: DL in BN254 G1, about 100–110 bits (the embedding degree 12 bounds it). This is not 128-bit.
  The IPA setup is transparent.
- The provider must recompute `d` from the submitted bytes, and must check that the tag matches `rec` and
  that the root is finalized. The relation alone does not ensure these (see `AUDIT.md`, "Provider-side checks").

## Tests

| file | what it checks | result |
|---|---|---|
| `tests/native_vectors.rs` | Native Poseidon, Base8, sk·Base8, ECDH and the Poseidon cipher reproduce the circomlibjs/zk-kit vector `friendly-vector.json` bit for bit. Poseidon3 and the Merkle path match `hybrid-test-vector.json`. Random encrypt→decrypt round trip. Wrong key gives `auth`. Tampering with any of elements 3..21 is detected. Invalid keys are rejected. | Run with the commands above |
| `tests/gadget_soundness.rs` | MockProver: Merkle direction ∈ {2, 4, 5, 2^31} is unsatisfiable; recipient-key checks reject identity, the order-2 point, pk + T2 (order 2l) and off-curve points. | Run with the commands above |
| `tests/adversarial.rs` | The full suite (`src/adversarial.rs`) for P1 and W1 at depth 32, plus encrypt→prove→verify→decrypt at depths 8 and 16. | Run with the commands above |

In the adversarial suite, P1 **rejects** all of the following:
- altered root;
- another tree's valid root, with the same proof and with a fresh forged proof;
- altered tag;
- altered digest;
- proof A presented with note B's publics;
- truncated, half, empty, trailing-byte, bit-flipped (12 positions) and random proofs;
- the infinity-flag re-encoding (F2);
- a substituted ciphertext (valid encryption of another message, with a fresh or the original digest);
- a random 22-element C;
- C encrypted to a key other than `m[0..1]`;
- an arbitrary `d`;
- a wrong tag;
- a wrong amount;
- invalid keys: identity, order 2, pk + torsion;
- nonce ≥ 2^128;
- r = 0;
- **A11:** an output that pays R's owner field while `m[0..1]` and C use the attacker's key, under either `ob`.

W1 also rejects all the public-input and proof-byte mutations, the non-member root, the wrong tag and the
wrong amount. It **accepts** (documenting the weakness) every ciphertext, key and digest forgery, including
the A11 attack.

Both variants: two encryptions of the same note have the **same tag** and different digests, so the
provider's per-tag rule rejects the second one as CONFLICT. The raw per-case JSON, with MockProver
satisfiability for every forged witness, is in `core/results/E4/<ts>/adversarial_{full,weak}_d32.json`.
