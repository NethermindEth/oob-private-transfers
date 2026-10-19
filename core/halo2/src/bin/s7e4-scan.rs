//! S7-E4 scanning baseline: per-payload trial-decryption cost with the implementation's decryption
//! (`native::decrypt`, the same function the recipient's `--role tool decrypt` op calls), for a FAILING trial
//! (a valid ciphertext to another key, so the tag check fails, as for all but one payload in a scan).
//! Also times the components (subgroup check, ECDH scalar multiplication, Poseidon permutations) and a lean variant
//! without the subgroup check. Writes one JSON document to stdout.
//!
//! s7e4-scan [--n 200] [--batch 4000]
use ff::Field;
use halo2curves::bn256::Fr;
use oob_admission::native;
use rand_core::OsRng;
use rayon::prelude::*;
use serde_json::json;
use std::time::Instant;

fn arg(name: &str, d: usize) -> usize {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn quant(mut xs: Vec<f64>) -> serde_json::Value {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |p: f64| xs[((p * (xs.len() - 1) as f64) + 0.5) as usize];
    json!({"min": xs[0], "p10": q(0.1), "median": q(0.5), "p90": q(0.9), "max": xs[xs.len()-1], "n": xs.len()})
}

/// decrypt without the subgroup check on epk (on-curve and x != 0 kept): ECDH + 7 permutations + tag compare.
fn decrypt_lean(sk: &Fr, c: &[Fr; 22]) -> bool {
    let epk = (c[0], c[1]);
    if !native::on_curve(&epk) || epk.0 == Fr::ZERO {
        return false;
    }
    let k = native::mul(&epk, sk);
    let mut state = [Fr::ZERO, k.0, k.1, c[2] + Fr::from(18) * native::two_128()];
    for i in 0..6 {
        state = native::permute4(state);
        for j in 0..3 {
            state[j + 1] = c[3 + 3 * i + j];
        }
    }
    state = native::permute4(state);
    state[1] == c[21]
}

fn main() {
    let n = arg("--n", 200);
    let batch = arg("--batch", 4000);
    let (_sk_other, pk_other) = native::keypair();
    let (sk_me, pk_me) = native::keypair();
    let mk = |pk: &native::Point| {
        let mut m = [Fr::ZERO; 18];
        for x in m.iter_mut() {
            *x = Fr::random(OsRng);
        }
        m[0] = pk.0;
        m[1] = pk.1;
        native::encrypt(pk, &m).unwrap().0
    };
    let cts: Vec<[Fr; 22]> = (0..n).map(|_| mk(&pk_other)).collect();
    let mine = mk(&pk_me);
    // sanity: own ciphertext decrypts, others fail with Auth
    assert!(native::decrypt(&sk_me, &mine).is_ok());
    assert!(decrypt_lean(&sk_me, &mine));
    // warm-up
    for c in cts.iter().take(5) {
        let _ = native::decrypt(&sk_me, c);
    }
    let mut t_dec = Vec::new();
    let mut auth_fail = 0;
    for c in &cts {
        let t = Instant::now();
        let r = native::decrypt(&sk_me, c);
        t_dec.push(t.elapsed().as_secs_f64());
        if matches!(r, Err(native::DecryptError::Auth)) {
            auth_fail += 1;
        }
    }
    let mut t_lean = Vec::new();
    for c in &cts {
        let t = Instant::now();
        let ok = decrypt_lean(&sk_me, c);
        t_lean.push(t.elapsed().as_secs_f64());
        assert!(!ok);
    }
    let mut t_sub = Vec::new();
    let mut t_mul = Vec::new();
    let mut t_perm = Vec::new();
    for c in cts.iter().take(50) {
        let epk = (c[0], c[1]);
        let t = Instant::now();
        let v = native::in_subgroup(&epk);
        t_sub.push(t.elapsed().as_secs_f64());
        assert!(v);
        let t = Instant::now();
        let k = native::mul(&epk, &sk_me);
        t_mul.push(t.elapsed().as_secs_f64());
        let mut s = [Fr::ZERO, k.0, k.1, c[2]];
        let t = Instant::now();
        for _ in 0..7 {
            s = native::permute4(s);
        }
        t_perm.push(t.elapsed().as_secs_f64());
        std::hint::black_box(s);
    }
    // all-core throughput over a batch (the scan is embarrassingly parallel)
    let big: Vec<[Fr; 22]> = (0..batch).map(|i| cts[i % n]).collect();
    let threads = rayon::current_num_threads();
    let t = Instant::now();
    let fails = big.par_iter().filter(|c| native::decrypt(&sk_me, c).is_err()).count();
    let par_s = t.elapsed().as_secs_f64();
    assert_eq!(fails, batch);
    let t = Instant::now();
    let fails2 = big.par_iter().filter(|c| !decrypt_lean(&sk_me, c)).count();
    let par_lean_s = t.elapsed().as_secs_f64();
    assert_eq!(fails2, batch);
    let doc = json!({
        "kind": "measured: implementation decryption (native::decrypt, zk-kit Poseidon cipher over BabyJubjub, BN254 Fr), failing trials",
        "payload_bytes": 736, "ciphertext_field_elements": 22,
        "n_single_thread": n, "auth_failures": auth_fail,
        "decrypt_single_thread_seconds": quant(t_dec),
        "decrypt_lean_no_subgroup_check_single_thread_seconds": quant(t_lean),
        "components_single_thread_seconds": {"in_subgroup": quant(t_sub), "ecdh_mul": quant(t_mul), "seven_permutations": quant(t_perm)},
        "parallel": {"threads": threads, "batch": batch, "decrypt_seconds_total": par_s, "decrypt_per_payload_seconds": par_s / batch as f64,
                     "lean_seconds_total": par_lean_s, "lean_per_payload_seconds": par_lean_s / batch as f64},
        "note": "BabyJubjub scalar multiplication in native.rs is affine double-and-add with a field inversion per add (reference code, not optimized)",
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
