//! E4 measurement / adversarial driver. Writes one JSON document to --out (or stdout).
//!
//! e4-bench bench --variant full|weak --depth D --runs N [--keys DIR] [--fresh-params] [--out F]
//! e4-bench adversarial --variant full|weak --depth D [--keys DIR] [--mock] [--out F]
use oob_admission::adversarial::{summary, Note, Suite};
use oob_admission::setup::{load_params, Keys};
use oob_admission::Variant;
use serde_json::json;
use std::path::PathBuf;
use std::time::Instant;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

fn main() {
    let t_total = Instant::now();
    let mode = std::env::args().nth(1).unwrap_or_default();
    let variant = Variant::parse(&arg("--variant").unwrap_or("full".into())).expect("--variant");
    let depth: usize = arg("--depth").unwrap_or("32".into()).parse().unwrap();
    let keys_dir = arg("--keys").map(PathBuf::from);
    let threads = rayon::current_num_threads();
    let doc = match mode.as_str() {
        "bench" => {
            let runs: usize = arg("--runs").unwrap_or("10".into()).parse().unwrap();
            // Fresh parameter generation timing (Params::new), independent of the cache.
            let fresh = if flag("--fresh-params") {
                let shape = oob_admission::setup::shape(variant, depth);
                let (_, secs, _, _) = load_params(None, shape.k).unwrap();
                Some(secs)
            } else {
                None
            };
            let keys = Keys::setup(variant, depth, keys_dir.as_deref(), true).expect("setup");
            let params_file_bytes = keys.params_path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len());
            let mut samples = Vec::new();
            let mut failures = Vec::new();
            for i in 0..runs {
                let note = Note::random(depth);
                let public = note.public();
                let w = note.witness();
                let t = Instant::now();
                let proof = match keys.prove_unchecked(&public, w) {
                    Ok(p) => p,
                    Err(e) => {
                        failures.push(json!({"run": i, "error": e}));
                        continue;
                    }
                };
                let prove_s = t.elapsed().as_secs_f64();
                let t = Instant::now();
                let ok = keys.verify(&public, &proof);
                let verify_s = t.elapsed().as_secs_f64();
                // outside timing: the same proof must fail on a mutated public input
                let mut bad = public;
                bad[1] += halo2curves::bn256::Fr::from(1);
                let neg_rejected = !keys.verify(&bad, &proof);
                if !ok || !neg_rejected {
                    failures.push(json!({"run": i, "valid": ok, "negative_rejected": neg_rejected}));
                }
                samples.push(json!({"run": i, "prove_seconds": prove_s, "verify_seconds": verify_s,
                                    "proof_bytes": proof.len(), "valid": ok, "negative_rejected": neg_rejected}));
                eprintln!("run {i}: prove {prove_s:.3}s verify {:.1}ms valid={ok}", verify_s * 1e3);
            }
            json!({
                "mode": "bench",
                "variant": variant.name(),
                "variant_label": if variant == Variant::Full {"P1 (full binding)"} else {"W1 (weak: digest only)"},
                "relation": variant.relation(),
                "depth": depth,
                "k": keys.shape.k,
                "rows_used": keys.shape.rows,
                "rows_available": (1usize << keys.shape.k) - keys.shape.blinding_rows,
                "blinding_rows": keys.shape.blinding_rows,
                "advice_columns": keys.shape.advice_columns,
                "fixed_columns_non_selector": keys.shape.fixed_columns,
                "instance_columns": keys.shape.instance_columns,
                "gate_degree": keys.shape.degree,
                "vk_sha256": keys.vk_sha256,
                "rayon_threads": threads,
                "setup": {
                    "params_generate_seconds_fresh": fresh,
                    "params_seconds_this_run": keys.timings.params_seconds,
                    "params_source_this_run": keys.timings.params_source,
                    "params_file_bytes": params_file_bytes,
                    "keygen_vk_seconds": keys.timings.keygen_vk_seconds,
                    "keygen_pk_seconds": keys.timings.keygen_pk_seconds,
                    "pk_on_disk": "not serializable in halo2_proofs 0.3.5; regenerated from params at start-up (keygen_pk_seconds)",
                },
                "runs_requested": runs,
                "samples": samples,
                "failures": failures,
                "rng": "OS RNG (unseeded): note contents, keys, r, nonce, Merkle siblings/directions, proof blinding",
                "wall_seconds": t_total.elapsed().as_secs_f64(),
            })
        }
        "adversarial" => {
            let keys = Keys::setup(variant, depth, keys_dir.as_deref(), true).expect("setup");
            let mut s = Suite { keys: &keys, cases: Vec::new(), mock: flag("--mock") };
            s.run();
            json!({
                "mode": "adversarial",
                "variant": variant.name(),
                "variant_label": if variant == Variant::Full {"P1 (full binding)"} else {"W1 (weak: digest only)"},
                "depth": depth,
                "k": keys.shape.k,
                "vk_sha256": keys.vk_sha256,
                "rayon_threads": threads,
                "mockprover": flag("--mock"),
                "summary": summary(&s.cases),
                "cases": s.cases,
                "rng": "OS RNG (unseeded)",
                "wall_seconds": t_total.elapsed().as_secs_f64(),
            })
        }
        _ => {
            eprintln!("usage: e4-bench bench|adversarial --variant full|weak --depth D ...");
            std::process::exit(2)
        }
    };
    let text = serde_json::to_string_pretty(&doc).unwrap();
    match arg("--out") {
        Some(p) => std::fs::write(p, text).unwrap(),
        None => println!("{text}"),
    }
}
