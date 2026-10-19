//! Adversarial regression suite (E4). Each case records what was attempted, what the
//! implementation did, and whether that matches the expected behavior for the variant.
//! These are implementation-behavior tests; they do not establish soundness or ZK.
use crate::native::{self, Point};
use crate::relation::{AdmissionCircuit, AdmissionWitness, Variant};
use crate::setup::Keys;
use ff::Field;
use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use rand_core::OsRng;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct Note {
    pub sk: Fr,
    pub ob: Fr,
    pub pk: Point,
    pub m: [Fr; 18],
    pub r: Fr,
    pub nonce: Fr,
    pub c: [Fr; 22],
    pub siblings: Vec<Fr>,
    pub directions: Vec<bool>,
}

impl Note {
    pub fn random(depth: usize) -> Note {
        let (sk, pk) = native::keypair();
        let mut m = [Fr::ZERO; 18];
        m[0] = pk.0;
        m[1] = pk.1;
        m[2] = Fr::from(native::DENOMINATION);
        for i in 3..18 {
            m[i] = Fr::random(OsRng);
        }
        let ob = Fr::random(OsRng);
        m[5] = native::owner_field(ob, &pk);
        let (c, r, nonce) = native::encrypt(&pk, &m).unwrap();
        let siblings = (0..depth).map(|_| Fr::random(OsRng)).collect();
        let directions = (0..depth).map(|_| rand_core::RngCore::next_u32(&mut OsRng) & 1 == 1).collect();
        Note { sk, ob, pk, m, r, nonce, c, siblings, directions }
    }
    pub fn witness(&self) -> AdmissionWitness {
        AdmissionWitness {
            message: self.m,
            ob: self.ob,
            randomness: self.r,
            nonce: self.nonce,
            ciphertext: self.c,
            siblings: self.siblings.clone(),
            directions: self.directions.clone(),
        }
    }
    pub fn public(&self) -> [Fr; 3] {
        let (a, b, c) = native::statement(&self.m, &self.c, &self.siblings, &self.directions);
        [a, b, c]
    }
    pub fn cm(&self) -> Fr {
        native::note_commitment(&self.m)
    }
}

pub struct Suite<'a> {
    pub keys: &'a Keys,
    pub cases: Vec<Value>,
    pub mock: bool,
}

impl<'a> Suite<'a> {
    fn record(&mut self, name: &str, expect_accept: bool, accepted: bool, detail: Value) {
        let pass = expect_accept == accepted;
        self.cases.push(json!({
            "case": name,
            "variant": self.keys.variant.name(),
            "depth": self.keys.depth,
            "expected": if expect_accept {"accept"} else {"reject"},
            "observed": if accepted {"accept"} else {"reject"},
            "pass": pass,
            "detail": detail,
        }));
    }
    /// Verify an existing proof against public inputs.
    fn verify_case(&mut self, name: &str, public: &[Fr; 3], proof: &[u8], expect: bool, detail: Value) {
        let ok = self.keys.verify(public, proof);
        self.record(name, expect, ok, detail);
    }
    /// A (possibly malicious) prover tries to prove `public` with witness `w`, skipping the
    /// native pre-check. Accepted iff the resulting proof verifies. Optionally also runs
    /// MockProver to report whether the circuit is satisfiable at all.
    fn forge_case(&mut self, name: &str, public: [Fr; 3], w: AdmissionWitness, expect: bool, why: &str) {
        let native_check = self.keys.check_witness(&public, &w).err();
        let satisfiable = if self.mock {
            let c = AdmissionCircuit { variant: self.keys.variant, depth: self.keys.depth, witness: Some(w.clone()) };
            MockProver::run(self.keys.shape.k, &c, vec![public.to_vec()]).map(|p| p.verify().is_ok()).ok()
        } else {
            None
        };
        let (accepted, proof_err) = match self.keys.prove_unchecked(&public, w) {
            Ok(p) => (self.keys.verify(&public, &p), None),
            Err(e) => (false, Some(e)),
        };
        self.record(name, expect, accepted, json!({
            "why": why,
            "native_precheck_error": native_check,
            "mockprover_satisfied": satisfiable,
            "create_proof_error": proof_err,
        }));
    }

    pub fn run(&mut self) {
        let depth = self.keys.depth;
        let full = self.keys.variant == Variant::Full;
        let a = Note::random(depth);
        let pa = a.public();
        let proof = self.keys.prove(&pa, a.witness()).expect("honest proof");
        self.verify_case("honest", &pa, &proof, true, json!({"proof_bytes": proof.len()}));

        // --- public-input mutations against the honest proof
        let mut x = pa;
        x[0] += Fr::ONE;
        self.verify_case("altered_root", &x, &proof, false, json!({}));
        let b = Note::random(depth);
        let other_root = b.public()[0]; // a genuine root of a different tree (not containing cm_A)
        let x = [other_root, pa[1], pa[2]];
        self.verify_case("other_valid_root_same_proof", &x, &proof, false, json!({"note": "non-member / unfinalized root"}));
        let mut x = pa;
        x[2] += Fr::ONE;
        self.verify_case("altered_tag", &x, &proof, false, json!({}));
        let mut x = pa;
        x[1] += Fr::ONE;
        self.verify_case("altered_digest_same_proof", &x, &proof, false, json!({}));
        let pb = b.public();
        self.verify_case("proof_A_with_publics_B", &pb, &proof, false, json!({}));
        let mut x = pb;
        x[1] = pa[1];
        self.verify_case("proof_A_root_tag_B_digest_A", &x, &proof, false, json!({}));

        // --- proof-byte corruption
        self.verify_case("truncated_proof", &pa, &proof[..proof.len() - 1], false, json!({}));
        self.verify_case("half_proof", &pa, &proof[..proof.len() / 2], false, json!({}));
        self.verify_case("empty_proof", &pa, &[], false, json!({}));
        let mut ext = proof.clone();
        ext.push(0);
        self.verify_case("trailing_byte", &pa, &ext, false, json!({}));
        for pos in [0usize, 31, 32, proof.len() / 2, proof.len() - 33, proof.len() - 1] {
            for bit in [0u8, 7] {
                let mut bad = proof.clone();
                bad[pos] ^= 1 << bit;
                self.verify_case(&format!("bitflip_byte{pos}_bit{bit}"), &pa, &bad, false, json!({}));
            }
        }
        // Document the upstream malleability: set the unused infinity flag (bit 7 of byte 31)
        // of the first point. Stock verifier accepts; our canonical verifier rejects.
        let mut mal = proof.clone();
        mal[31] ^= 0x80;
        let stock = self.keys.verify_stock(&pa, &mal);
        self.record("infinity_flag_malleability_stock_verifier", true, stock, json!({
            "note": "upstream halo2_proofs 0.3.5 + halo2curves 0.6.1 accept this byte-different proof (same statement); informational"}));
        self.verify_case("infinity_flag_malleability_canonical_verifier", &pa, &mal, false, json!({}));
        let garbage: Vec<u8> = (0..proof.len()).map(|_| rand_core::RngCore::next_u32(&mut OsRng) as u8).collect();
        self.verify_case("random_bytes_proof", &pa, &garbage, false, json!({}));

        // --- forged statements (malicious prover, fresh proofs)
        // (i) membership under a root that does not contain cm
        self.forge_case("forge_nonmember_root", [other_root, pa[1], pa[2]], a.witness(), false,
            "prove cm_A under another tree's root");
        // (ii) substituted ciphertext: valid encryption of a different message to the same key,
        //      provider recomputes d from the submitted bytes
        let mut m2 = a.m;
        m2[6] += Fr::ONE;
        let (c2, _, _) = native::encrypt(&a.pk, &m2).unwrap();
        let mut w = a.witness();
        w.ciphertext = c2;
        self.forge_case("forge_substituted_ciphertext", [pa[0], native::digest(&c2), pa[2]], w.clone(), !full,
            "C' = Enc(pk_R, m') with m' != note; d = PoseidonChain(1003, C')");
        // same substitution but keep the ORIGINAL digest (provider's d check would also reject)
        self.forge_case("forge_substituted_ciphertext_orig_digest", pa, w, !full,
            "C' in witness, public d of the original C (weak: d unconstrained so fresh proof verifies; provider must check d = H(C'))");
        // (iii) random 22-element vector
        let rnd: [Fr; 22] = std::array::from_fn(|_| Fr::random(OsRng));
        let mut w = a.witness();
        w.ciphertext = rnd;
        self.forge_case("forge_random_ciphertext", [pa[0], native::digest(&rnd), pa[2]], w, !full,
            "22 random field elements as C");
        // (iv) ciphertext of the note encrypted to a different key than m[0..2]
        let (_, pk_other) = native::keypair();
        let (c3, r3, n3) = native::encrypt(&pk_other, &a.m).unwrap();
        let mut w = a.witness();
        w.ciphertext = c3;
        w.randomness = r3;
        w.nonce = n3;
        self.forge_case("forge_wrong_recipient_key", [pa[0], native::digest(&c3), pa[2]], w, !full,
            "C = Enc(pk', m) with pk' != (m[0], m[1]) committed in the note");
        // (v) arbitrary digest (weak variant: any d is provable)
        self.forge_case("forge_arbitrary_digest", [pa[0], Fr::random(OsRng), pa[2]], a.witness(), !full,
            "fresh proof for a random d");
        // (vi) tag for a different seed / commitment
        self.forge_case("forge_wrong_tag", [pa[0], pa[1], native::tag(a.cm(), a.m[3] + Fr::ONE)], a.witness(), false,
            "nu = Poseidon(1002, cm, seed+1)");
        // (vii) amount != denomination (note re-committed so membership holds)
        let mut n = a.clone();
        n.m[2] = Fr::from(native::DENOMINATION + 1);
        n.c = native::encrypt_with(&n.pk, &n.m, n.r, n.nonce).unwrap();
        self.forge_case("forge_wrong_amount", n.public(), n.witness(), false, "m[2] = denomination + 1");
        // (viii) invalid recipient keys committed in the note (full variant must reject)
        for (label, pk) in [
            ("identity_0_1", (Fr::ZERO, Fr::ONE)),
            ("order2_0_minus1", (Fr::ZERO, -Fr::ONE)),
            ("pk_plus_order2_torsion", (-a.pk.0, -a.pk.1)),
        ] {
            let mut n = a.clone();
            n.m[0] = pk.0;
            n.m[1] = pk.1;
            n.c = native::encrypt_unchecked(&pk, &n.m, n.r, n.nonce);
            self.forge_case(&format!("forge_invalid_key_{label}"), n.public(), n.witness(), !full,
                "recipient key not a nonzero-x prime-order-subgroup point");
        }
        // (ix) nonce >= 2^128 and r = 0
        let mut n = a.clone();
        n.nonce = native::two_128() + Fr::from(5);
        n.c = native::encrypt_unchecked(&n.pk, &n.m, n.r, n.nonce);
        self.forge_case("forge_nonce_ge_2_128", n.public(), n.witness(), !full, "nonce = 2^128 + 5");
        let mut n = a.clone();
        n.r = Fr::ZERO;
        n.c = native::encrypt_unchecked(&n.pk, &n.m, n.r, n.nonce);
        self.forge_case("forge_r_zero", n.public(), n.witness(), !full, "r = 0 (epk = identity, K = identity)");
        // (xi) A11: output pays R's owner field, but the note's key slots (and the ciphertext)
        //      are the attacker's key. Encryption is internally consistent (to pk_A).
        let (_, pk_att) = native::keypair();
        let mut n = a.clone(); // m[5] = owner_field(ob_R, pk_R) stays
        n.m[0] = pk_att.0;
        n.m[1] = pk_att.1;
        n.c = native::encrypt_with(&pk_att, &n.m, n.r, n.nonce).unwrap();
        self.forge_case("forge_owner_pays_R_encrypts_to_attacker", n.public(), n.witness(), !full,
            "m[5] = owner field of address (ob_R, pk_R); m[0..1] = pk_attacker; C = Enc(pk_attacker, m) (A11 constraint 1b)");
        let mut w = n.witness();
        w.ob = Fr::random(OsRng);
        self.forge_case("forge_owner_pays_R_attacker_random_ob", n.public(), w, !full,
            "same as above with a different ob witness");
        // (x) non-boolean Merkle directions: see tests/gadget_soundness.rs (MockProver).

        // --- randomized re-submission of the same note: same tag, different C and d
        let (c4, r4, n4) = native::encrypt(&a.pk, &a.m).unwrap();
        let mut a2 = a.clone();
        a2.c = c4;
        a2.r = r4;
        a2.nonce = n4;
        let pa2 = a2.public();
        let proof2 = self.keys.prove(&pa2, a2.witness()).expect("second honest proof");
        let ok2 = self.keys.verify(&pa2, &proof2);
        self.record("reencryption_same_note_valid_proof", true, ok2, json!({}));
        self.record("reencryption_same_tag", true, pa2[2] == pa[2], json!({
            "tag_1": crate::wire::hex_fe(&pa[2]), "tag_2": crate::wire::hex_fe(&pa2[2]),
            "digest_differs": pa2[1] != pa[1],
            "note": "provider's per-tag rule (allocation rule) rejects the second submission as CONFLICT"}));
        self.record("reencryption_digest_differs", true, pa2[1] != pa[1], json!({}));
    }
}

pub fn summary(cases: &[Value]) -> Value {
    let total = cases.len();
    let passed = cases.iter().filter(|c| c["pass"] == json!(true)).count();
    json!({"total": total, "passed": passed, "failed": total - passed})
}
