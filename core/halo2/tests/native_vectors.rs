//! Native implementations vs the circomlibjs / zk-kit vectors.
use ff::Field;
use halo2curves::bn256::Fr;
use oob_admission::native::*;
use oob_admission::wire::*;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("../friendly-vector.json")).unwrap()
}

#[test]
fn friendly_vector_matches_native() {
    let v = vector();
    let m = fes::<18>(&v["message"], "m").unwrap();
    let rec = fes::<22>(&v["ciphertext"], "c").unwrap();
    let r = fe(v["randomness"].as_str().unwrap()).unwrap();
    let nonce = fe(v["nonce"].as_str().unwrap()).unwrap();
    let g = fes::<2>(&v["generator"], "g").unwrap();
    assert_eq!((g[0], g[1]), base8());
    assert_eq!(v["subgroup_order"].as_str().unwrap(), "2736030358979909402780800718157159386076813972158567259200215660948447373041");
    // recipientSecret = 123456789 in friendly_vector.mjs
    let sk = Fr::from(123456789u64);
    let pk = mul(&base8(), &sk);
    assert_eq!(pk, (m[0], m[1]), "pk = sk*Base8 matches circomlibjs");
    assert!(valid_key(&pk));
    let c = encrypt_with(&pk, &m, r, nonce).unwrap();
    assert_eq!(c, rec, "ciphertext matches zk-kit poseidonEncrypt + circomlibjs ECDH");
    assert_eq!(decrypt(&sk, &c).unwrap(), m);
    let public = fe_vec(&v["public"], "public").unwrap();
    let sib = fe_vec(&v["siblings"], "s").unwrap();
    let dirs: Vec<bool> = v["directions"].as_array().unwrap().iter().map(|d| d.as_u64() == Some(1)).collect();
    let (root, d, t) = statement(&m, &c, &sib, &dirs);
    assert_eq!([root, d, t], [public[0], public[1], public[2]]);
}

#[test]
fn hybrid_vector_poseidon3_and_merkle() {
    // integration/halo2/test-vector.json (circomlibjs-generated): cm = Poseidon3(owner, seed mod p, payload)
    let v: Value = serde_json::from_str(include_str!("../hybrid-test-vector.json")).unwrap();
    let w = &v["witness"];
    let owner = fe(w["owner"].as_str().unwrap()).unwrap();
    let seed = from_hex(w["seed"].as_str().unwrap()); // reduced mod p, as the circuit packs it
    let ph = fe(w["payload_hash"].as_str().unwrap()).unwrap();
    let cm = fe(w["commitment"].as_str().unwrap()).unwrap();
    assert_eq!(commitment(owner, seed, ph), cm);
    let sib = fe_vec(&w["siblings"], "s").unwrap();
    let dirs: Vec<bool> = w["directions"].as_array().unwrap().iter().map(|d| d.as_u64() == Some(1)).collect();
    assert_eq!(merkle_root(cm, &sib, &dirs), fe(v["public"]["root"].as_str().unwrap()).unwrap());
}

#[test]
fn random_roundtrip_and_auth() {
    let (sk, pk) = keypair();
    assert!(valid_key(&pk));
    let mut m = [Fr::ZERO; 18];
    m[0] = pk.0;
    m[1] = pk.1;
    m[2] = Fr::from(DENOMINATION);
    for i in 3..18 {
        m[i] = Fr::random(rand_core::OsRng);
    }
    let (c, _r, nonce) = encrypt(&pk, &m).unwrap();
    assert!(cmp_int(&nonce, &two_128()).is_lt());
    assert_eq!(decrypt(&sk, &c).unwrap(), m);
    let (sk2, _) = keypair();
    assert_eq!(decrypt(&sk2, &c), Err(DecryptError::Auth));
    for i in 3..22 {
        let mut bad = c;
        bad[i] += Fr::ONE;
        assert!(decrypt(&sk, &bad).is_err(), "tamper at {i} detected");
    }
    // randomized re-encryption changes C and d but not the tag
    let (c2, _, _) = encrypt(&pk, &m).unwrap();
    assert_ne!(c, c2);
    assert_ne!(digest(&c), digest(&c2));
    let cm = note_commitment(&m);
    assert_eq!(tag(cm, m[3]), tag(note_commitment(&m), m[3]));
}

#[test]
fn invalid_keys_rejected() {
    assert!(!valid_key(&(Fr::ZERO, Fr::ONE))); // identity
    assert!(!valid_key(&(Fr::ZERO, -Fr::ONE))); // order-2 point
    let (_, pk) = keypair();
    assert!(!valid_key(&(pk.0, pk.1 + Fr::ONE))); // off curve
}
