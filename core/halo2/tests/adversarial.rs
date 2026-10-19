//! Adversarial regression tests (admission specification, E4). Uses the params cache in
//! $OOB_HALO_KEYS (default repository .cache/halo2-keys). Full variant at depth 32 (k=17).
use oob_admission::adversarial::{Note, Suite};
use oob_admission::{Keys, Variant};
use std::path::PathBuf;

fn keys_dir() -> PathBuf {
    std::env::var("OOB_HALO_KEYS").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.cache/halo2-keys")
    })
}

fn run(variant: Variant, depth: usize) {
    let keys = Keys::setup(variant, depth, Some(&keys_dir()), true).unwrap();
    let mut s = Suite { keys: &keys, cases: Vec::new(), mock: false };
    s.run();
    let failed: Vec<_> = s.cases.iter().filter(|c| c["pass"] != true).collect();
    for c in &s.cases {
        eprintln!("{} {} expected={} observed={}", c["variant"], c["case"], c["expected"], c["observed"]);
    }
    assert!(failed.is_empty(), "unexpected outcomes: {failed:#?}");
}

#[test]
fn full_depth32_adversarial() {
    run(Variant::Full, 32);
}

#[test]
fn weak_depth32_adversarial() {
    run(Variant::Weak, 32);
}

#[test]
fn encrypt_prove_verify_decrypt_depth8_16() {
    for depth in [8, 16] {
        let keys = Keys::setup(Variant::Full, depth, Some(&keys_dir()), true).unwrap();
        let n = Note::random(depth);
        let p = n.public();
        let proof = keys.prove(&p, n.witness()).unwrap();
        assert!(keys.verify(&p, &proof));
        assert_eq!(oob_admission::native::decrypt(&n.sk, &n.c).unwrap(), n.m);
        // the checked prover refuses an inconsistent witness
        let mut w = n.witness();
        w.ciphertext[5] += halo2curves::bn256::Fr::from(1);
        assert!(keys.prove(&p, w).is_err());
    }
}
