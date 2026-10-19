# Admission implementation and security notes

Scope: `src/gadgets.rs`, `src/relation.rs`, and the proof verifier in `src/setup.rs`.

## Implementation properties

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | **Critical (relation level)** | The full relation binds the encryption key `pk_R = (m[0], m[1])` to the owner field `m[5]`. Without this constraint, a sender could pay the recipient's owner field while encrypting to another key. | **Enforced**: owner binding constraint 1b `m[5] = Poseidon2(ob, Poseidon2(m[0], m[1]))` with witness `ob`, full variant only. Regression tests: `forge_owner_pays_R_encrypts_to_attacker` and `forge_owner_pays_R_attacker_random_ob` (P1 rejects, W1 accepts). |
| F2 | Medium (implementation) | **Proof malleability.** halo2curves 0.6.1 `G1Affine::from_bytes` reads bit 7 of byte 31 as the infinity flag but ignores it when x ≠ 0. halo2_proofs' Blake2b transcript absorbs point *coordinates*, not bytes. So a proof with that bit flipped in any point decodes to the same points and **verifies for the same statement**. This is not a soundness break (same statement, same points). But proof bytes are not unique, and a verifier would accept byte-different submissions. | **Canonical verification**: `setup::CanonicalRead` re-encodes every point and rejects any mismatch. Scalars are already range-checked. `Keys::verify_stock` keeps the upstream behavior so a test can document it (`infinity_flag_malleability_stock_verifier` = accept, `..._canonical_verifier` = reject). Deduplication never relies on proof bytes (per-tag rule). |
| F3 | Info | The weak variant (W1) leaves instance row 1 (`d`) unconstrained. `d` is bound only through the Fiat–Shamir transcript: instance commitments are absorbed (`halo2_proofs` prover.rs l.103, verifier.rs l.109–115). Anyone who knows a note opening can produce a valid W1 proof for **any** `d` (tests `forge_arbitrary_digest`, `forge_random_ciphertext`, `forge_substituted_ciphertext*`, `forge_wrong_recipient_key`: all accepted by W1). W1 also lacks 1b and item 4. | By design (labelled weak). No non-malleability or SE claim. |
| F4 | Info | `mux` constrains `bits[1] = 0` of the direction word. This is redundant: booleanity of the direction comes from the extra `bitpack` row applying `b(b−1)=0` to the packed value. | Redundant constraint. Test `merkle_direction_must_be_boolean` shows that directions 2, 4, 5 and 2^31 are unsatisfiable. |
| F5 | Info | `r` is range-checked to 252 bits and is **not reduced mod l**. `epk` and `K` use the same bits, so `r` and `r + l` give identical `(epk, K)`. The relation is therefore "∃ integer r < 2^252 with epk = rG, K = r·pk", which is equivalent to `r mod l`. `r ≡ 0 (mod l)` gives `epk = O`, which the `epk.x ≠ 0` check rejects. | The honest encryptor samples r uniformly in [1, l). The native pre-check is stricter than the circuit (it requires r < l). |
| F6 | Info | `divide(num, den)` assigns inv = 0 when den = 0. The constraint `den·inv = 1` then fails, so the circuit is unsatisfiable. This affects completeness only, never soundness. For curve points the denominators `1 ± d·x1x2y1y2` never vanish, because a = 168700 is a square and d = 168696 a non-square in F_p (complete twisted-Edwards law). `pk` is constrained on-curve before any addition, so every intermediate point is on the curve. | OK |
| F7 | Info | halo2_proofs 0.3.5 has no pk/vk serialization. `--keys` therefore caches only `params_k{k}.bin`, with a SHA-256 check against an accidentally corrupted file (the directory is trusted local storage). vk and pk are regenerated deterministically at start-up (~2.2 s + ~2.5 s at k=17). `vk_<relation>_d<depth>_k<k>.sha256` pins the vk digest: a changed circuit with the same file name is refused. | Documented. A verifier that distrusts its disk can regenerate params (`Params::new` is transparent and deterministic, ~40 s at k=17). |
| F8 | Info | Poseidon1 (t=2) is not implemented: this crate only ships t=3/t=4 constants. `ob = Poseidon1(secret)` is computed by the wallet or pool side (circomlibjs). The circuit takes `ob` as a witness, which is exactly what A11 specifies. | Documented. |

## Constraint-by-constraint table (full variant P1; W1 = rows marked "both")

| # | Constraint (admission relation) | Where (`src/relation.rs` unless noted) | Variant | Status | Note |
|---|---|---|---|---|---|
| 1 | 18 message slots are advice witnesses. Every use is a copy constraint into the hash chain or the key checks. | `m.push(b.witness(..))` | both | OK | – |
| 2 | `m[2] = 10^16` (denomination) | `constrain_constant(m[2])` | both | OK | – |
| 3 | `payloadHash = PoseidonChain(1001, m)`: domain is a fixed constant, 18× Poseidon2 | `hash_chain(1001, m)` | both | OK | – |
| 4 | `cm = Poseidon3(m[5], m[3], payloadHash)`, matches `Spend.circom`/`ShieldedPool.sol` | `hash([m5, m3, payload])` | both | OK. Vector test `hybrid_vector_poseidon3_and_merkle`. | – |
| 5 | **1b (A11)** `m[5] = Poseidon2(ob, Poseidon2(m[0], m[1]))` | after the key checks | full | Enforced | F1 |
| 6 | Merkle level: `(l, r) = dir ? (sib, cur) : (cur, sib)`; `delta = sib − cur`, `neg = −delta` constrained; outputs by mul-add | `gadgets::mux` | both | OK | – |
| 7 | Direction booleanity `dir(dir−1) = 0` on the packed value | `gadgets::mux` (2nd row, `bitpack` gate) | both | OK. Test `merkle_direction_must_be_boolean`. | – |
| 8 | Node `= Poseidon2(l, r)` for `depth` levels (runtime 8/16/32) | loop over `depth` | both | OK | runtime depth parameter |
| 9 | Root → instance row 0 | `constrain_instance(.., 0)` | both | OK | – |
| 10 | `ν_adm = Poseidon3(1002, cm, m[3])` → instance row 2 | `hash([1002, cm, m3])`, `constrain_instance(.., 2)` | both | OK | – |
| 11 | `pk_R` on curve: `a x² + y² = 1 + d x² y²` | `gadgets::curve` | full | OK | – |
| 12 | `pk_R.x ≠ 0` (inverse witness, `x·inv = 1`) | `divide(1, pk.x)` | full | OK (excludes identity (0,1) and (0,−1)) | – |
| 13 | `pk_R` in prime-order subgroup: `l·pk = O` with the 252 constant bits of l | `scalar_mul(pk, orderbits)`, `constrain_constant` | full | OK. Test `recipient_key_checks` rejects identity, order 2, pk + T2 (order 2l) and off-curve points. | – |
| 14 | `r < 2^252`: 8×32 boolean bits, packed = r, top 4 bits constrained 0, no wrap since 2^252 < p | `gadgets::range_bits(r, 252)` | full | OK (see F5) | – |
| 15 | `epk = r·Base8` (constant generator cells) | `scalar_mul(G, bits)` | full | OK. Base8 checked against circomlibjs in the vector test. | – |
| 16 | `epk.x ≠ 0` | `divide(1, epk.x)` | full | OK (excludes r ≡ 0 mod l) | – |
| 17 | `K = r·pk_R`, same bit cells as `epk` | `scalar_mul(pk, bits)` | full | OK | – |
| 18 | `nonce < 2^128` (4 words, exact) | `range_bits(nonce, 128)` | full | OK. Test `forge_nonce_ge_2_128`. | – |
| 19 | Sponge init `[0, K.x, K.y, nonce + 18·2^128]` | `plus(nonce, length)` | full | OK (zk-kit `poseidonEncrypt` layout) | – |
| 20 | 6 absorb/output rounds: `state = P4(state)`; `c_{3i+j} = state[j+1] + m_{3i+j}` | `permute4` + `plus` | full | OK. Native ciphertext equals the zk-kit vector. | – |
| 21 | Auth element `= P4(state)[1]` | final `permute4` | full | OK | – |
| 22 | Width-4 permutation: 8 full + 56 partial rounds, circomlibjs t=4 constants, ARK in fixed columns, x^5 S-box, MDS | `gadgets::rounds` + Poseidon gate | both | OK | – |
| 23 | Width-3 Poseidon: 8 full + 57 partial rounds | same | both | OK | – |
| 24 | Every one of the 22 ciphertext witness elements equals the computed record element | `b.equal(c, &actual)` loop | full | OK. Redundant with 25, but keeps the witness `C` bound. | – |
| 25 | `d = PoseidonChain(1003, C)` over the **computed** record → instance row 1 | `hash_chain(1003, record)`, `constrain_instance(.., 1)` | full | OK | – |
| 26 | Instance row 1 in W1 | none | weak | **unconstrained** (transcript-bound only) | F3 (by design) |
| 27 | Constants: `assign_advice_from_constant` / `constrain_constant` go to the equality-enabled fixed `constant` column | `gadgets` | both | OK | – |
| 28 | Proof decoding: canonical points and scalars, no trailing bytes | `setup::CanonicalRead`, `Keys::verify` | both | Enforced | F2 |

Items 11–25 are absent from W1, and so are 1b and item 4. W1 proves only items 1–3 (opening, amount,
membership, tag) with a public but unconstrained `d`.

## Transcript and public-input binding
- The verifier absorbs `vk.hash_into` first. It covers the pinned constraint system, the fixed commitments and
  the permutation commitments, so a proof is bound to this exact circuit, variant and depth. Next come the
  instance-column commitments, computed by the verifier from the supplied `(root, d, tag)`, then every proof
  element. Changing any public input changes the challenges. All public-input mutation tests reject.
- The instance polynomial is committed without blinding. That is standard for public inputs.
- The verifier rejects instance vectors longer than `n − (blinding + 1)`. Only rows 0–2 are non-zero.

## Proof-system assumptions (what is and is not claimed)
- Halo2 PLONKish arithmetization with the IPA polynomial commitment over BN254 G1 (`halo2_proofs` 0.3.5,
  non-recursive), with Fiat–Shamir via Blake2b (modelled as a random oracle). `Params::new(k)` is transparent:
  hash-to-curve generators, no trusted setup. We use this configuration off-spec: upstream targets the Pasta
  curves. Knowledge soundness in the ROM rests on the discrete-log assumption in G1. BN254 G1 DL is
  upper-bounded by the embedding-degree-12 target group (roughly 100–110-bit security after exTNFS
  estimates). This configuration does not provide a 128-bit security level.
- **Claimed:** knowledge soundness of this configuration in the ROM, and zero knowledge with blinding
  (halo2 default).
- **Not claimed:** simulation extractability or non-malleability. **Providers do see proofs** (the sender
  submits `π` to each provider), so the adversary can observe other users' proofs. For **P1** the argument is
  the *composite-prover* one. An adversary that outputs an accepting `(x, π)` after seeing honest proofs, run
  together with the honest provers it observed, is a single prover. Knowledge soundness then yields a witness
  for `x`, possibly an honest party's witness. Theorem 2 only needs "∃ w: R_adm(x, w) = 1", i.e. the accepted
  bytes (fixed by `d = PoseidonChain(1003, C)`, which the provider recomputes from the submitted bytes) decrypt,
  under the key of the address the output pays (1b), to the committed note. For **W1**, binding the stored bytes
  to the entitlement would need non-malleability of the proof with respect to `d`. W1 does not have it and we do
  not claim it: an honest witness holder can already prove any `d`.
- The tests in `tests/` and in `core/results/E4/*/adversarial_*.json` check implementation behavior. They
  do not prove soundness, zero knowledge or unforgeability.

## Provider-side checks the relation relies on (for the Python service)
1. `d == PoseidonChain(1003, C)` recomputed from the submitted `rec` bytes (op `digest`). Without this check, a
   P1 proof for `(root, d, tag)` could be paired with different bytes. See `forge_substituted_ciphertext_orig_digest`.
2. `ν_adm` taken from `rec` equals the public tag.
3. `root` is a finalized pool root (the relation proves only membership under the given root; see
   `other_valid_root_same_proof` and `forge_nonmember_root`).
4. Per-tag allocation rule: a re-encryption of the same note has the same tag
   (`reencryption_same_tag`) and must get CONFLICT.

