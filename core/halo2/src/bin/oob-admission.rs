//! JSON-lines admission worker.
//!
//! oob-admission [--keys DIR] [--depth 8|16|32] [--variant full|weak] [--role prover|verifier|tool]
//! One request per line on stdin: {"op": ...}; one reply per line: {"result": ...} | {"error": ...}.
use ff::Field;
use halo2curves::bn256::Fr;
use oob_admission::{native, wire::*, AdmissionWitness, Keys, Variant};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Instant;

struct Opts {
    keys: Option<PathBuf>,
    depth: usize,
    variant: Variant,
    role: String,
}

fn parse_args() -> Result<Opts, String> {
    let a: Vec<String> = std::env::args().collect();
    let get = |n: &str| a.iter().position(|x| x == n).and_then(|i| a.get(i + 1).cloned());
    let depth: usize = get("--depth").unwrap_or("32".into()).parse().map_err(|_| "bad --depth")?;
    if ![8, 16, 32].contains(&depth) {
        return Err("--depth must be 8, 16 or 32".into());
    }
    let variant = Variant::parse(&get("--variant").unwrap_or("full".into())).ok_or("--variant must be full|weak")?;
    let role = get("--role").unwrap_or("prover".into());
    if !["prover", "verifier", "tool"].contains(&role.as_str()) {
        return Err("--role must be prover|verifier|tool".into());
    }
    Ok(Opts {
        keys: get("--keys").map(PathBuf::from),
        depth,
        variant,
        role,
    })
}

fn public3(v: &Value) -> Result<[Fr; 3], String> {
    let p = v.get("public").ok_or("missing public")?;
    let g = |n: &str| -> Result<Fr, String> {
        fe(p.get(n).and_then(|x| x.as_str()).ok_or(format!("missing public.{n}"))?)
            .map_err(|e| format!("public.{n}: {e}"))
    };
    Ok([g("root")?, g("digest")?, g("tag")?])
}

fn get_fe(v: &Value, n: &str) -> Result<Fr, String> {
    fe(v.get(n).and_then(|x| x.as_str()).ok_or(format!("missing {n}"))?).map_err(|e| format!("{n}: {e}"))
}

fn witness(v: &Value, variant: Variant, depth: usize) -> Result<AdmissionWitness, String> {
    let w = v.get("witness").ok_or("missing witness")?;
    let message = fes::<18>(w.get("message").ok_or("missing witness.message")?, "message")?;
    let opt_fe = |n: &str| -> Result<Fr, String> {
        match w.get(n) {
            Some(_) => get_fe(w, n),
            None if variant == Variant::Weak => Ok(Fr::ZERO),
            None => Err(format!("missing witness.{n}")),
        }
    };
    let ob = opt_fe("ob")?;
    let randomness = opt_fe("randomness")?;
    let nonce = opt_fe("nonce")?;
    let ciphertext = match w.get("ciphertext") {
        Some(c) => fes::<22>(c, "ciphertext")?,
        None if variant == Variant::Weak => [Fr::ZERO; 22],
        None => return Err("missing witness.ciphertext".into()),
    };
    let siblings = fe_vec(w.get("siblings").ok_or("missing witness.siblings")?, "siblings")?;
    let directions = w
        .get("directions")
        .and_then(|d| d.as_array())
        .ok_or("missing witness.directions")?
        .iter()
        .map(|d| match d.as_u64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err("directions must be 0/1".to_string()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if siblings.len() != depth || directions.len() != depth {
        return Err(format!("siblings/directions must have length {depth}"));
    }
    Ok(AdmissionWitness {
        message,
        ob,
        randomness,
        nonce,
        ciphertext,
        siblings,
        directions,
    })
}

fn handle(v: &Value, o: &Opts, keys: Option<&Keys>, last_proof_len: &mut Option<usize>) -> Result<Value, String> {
    let op = v.get("op").and_then(|x| x.as_str()).ok_or("missing op")?;
    match op {
        "info" => {
            let shape = keys.map(|k| k.shape.clone()).unwrap_or_else(|| oob_admission::setup::shape(o.variant, o.depth));
            Ok(json!({
                "relation": o.variant.relation(),
                "variant": o.variant.name(),
                "variant_label": if o.variant == Variant::Full {"P1 (full binding)"} else {"W1 (weak: digest only)"},
                "encryption_constrained": o.variant == Variant::Full,
                "depth": o.depth,
                "k": shape.k,
                "rows": shape.rows,
                "advice_columns": shape.advice_columns,
                "gate_degree": shape.degree,
                "role": o.role,
                "proof_bytes_expected": last_proof_len.clone(),
                "vk_sha256": keys.map(|k| k.vk_sha256.clone()),
                "setup": keys.map(|k| json!({
                    "params_seconds": k.timings.params_seconds,
                    "params_source": k.timings.params_source,
                    "keygen_vk_seconds": k.timings.keygen_vk_seconds,
                    "keygen_pk_seconds": k.timings.keygen_pk_seconds,
                })),
                "backend": "halo2_proofs 0.3.5 (zcash), IPA over BN254 G1, Blake2b Fiat-Shamir, non-recursive",
                "public_inputs": ["root (instance row 0)", "digest (row 1)", "tag (row 2)"],
                "simulation_extractability_claimed": false,
            }))
        }
        "keypair" => {
            let (sk, pk) = native::keypair();
            Ok(json!({"sk": hex_fe(&sk), "pk": [hex_fe(&pk.0), hex_fe(&pk.1)]}))
        }
        "payload_hash" => {
            let m = fes::<18>(v.get("message").ok_or("missing message")?, "message")?;
            Ok(json!({"payload_hash": hex_fe(&native::payload_hash(&m))}))
        }
        "commitment" => {
            let cm = native::commitment(get_fe(v, "owner")?, get_fe(v, "seed")?, get_fe(v, "payload_hash")?);
            Ok(json!({"cm": hex_fe(&cm)}))
        }
        "owner" => {
            let pk = fes::<2>(v.get("pk").ok_or("missing pk")?, "pk")?;
            Ok(json!({"owner": hex_fe(&native::owner_field(get_fe(v, "ob")?, &(pk[0], pk[1])))}))
        }
        "tag" => Ok(json!({"nu": hex_fe(&native::tag(get_fe(v, "cm")?, get_fe(v, "seed")?))})),
        "digest" => {
            let c = fes::<22>(v.get("ciphertext").ok_or("missing ciphertext")?, "ciphertext")?;
            Ok(json!({"d": hex_fe(&native::digest(&c))}))
        }
        "hash" => {
            let xs = fe_vec(v.get("values").ok_or("missing values")?, "values")?;
            if xs.len() != 2 && xs.len() != 3 {
                return Err("hash arity must be 2 or 3".into());
            }
            Ok(json!({"h": hex_fe(&native::poseidon(&xs))}))
        }
        "merkle_root" => {
            let leaf = get_fe(v, "leaf")?;
            let sib = fe_vec(v.get("siblings").ok_or("missing siblings")?, "siblings")?;
            let dirs: Vec<bool> = v
                .get("directions")
                .and_then(|d| d.as_array())
                .ok_or("missing directions")?
                .iter()
                .map(|d| d.as_u64() == Some(1))
                .collect();
            if dirs.len() != sib.len() {
                return Err("length mismatch".into());
            }
            Ok(json!({"root": hex_fe(&native::merkle_root(leaf, &sib, &dirs))}))
        }
        "encrypt" => {
            let pk = fes::<2>(v.get("pk").ok_or("missing pk")?, "pk")?;
            let m = fes::<18>(v.get("message").ok_or("missing message")?, "message")?;
            let allow = v.get("allow_pk_mismatch").and_then(|x| x.as_bool()).unwrap_or(false);
            if !allow && (m[0] != pk[0] || m[1] != pk[1]) {
                return Err("message slots m[0],m[1] must equal pk (set allow_pk_mismatch only for adversarial tests)".into());
            }
            let (c, r, nonce) = native::encrypt(&(pk[0], pk[1]), &m)?;
            Ok(json!({"ciphertext": hex_all(&c), "randomness": hex_fe(&r), "nonce": hex_fe(&nonce)}))
        }
        "decrypt" => {
            let sk = get_fe(v, "sk")?;
            if sk == Fr::ZERO || native::cmp_int(&sk, &native::subgroup_order()) != std::cmp::Ordering::Less {
                return Err("sk outside [1, l)".into());
            }
            let c = fes::<22>(v.get("ciphertext").ok_or("missing ciphertext")?, "ciphertext")?;
            match native::decrypt(&sk, &c) {
                Ok(m) => Ok(json!({"message": hex_all(&m)})),
                Err(native::DecryptError::Auth) => Err("auth".into()),
                Err(native::DecryptError::Malformed(e)) => Err(format!("malformed: {e}")),
            }
        }
        "statement" => {
            let m = fes::<18>(v.get("message").ok_or("missing message")?, "message")?;
            let c = fes::<22>(v.get("ciphertext").ok_or("missing ciphertext")?, "ciphertext")?;
            let sib = fe_vec(v.get("siblings").ok_or("missing siblings")?, "siblings")?;
            let dirs: Vec<bool> = v
                .get("directions")
                .and_then(|d| d.as_array())
                .ok_or("missing directions")?
                .iter()
                .map(|d| d.as_u64() == Some(1))
                .collect();
            let (root, d, t) = native::statement(&m, &c, &sib, &dirs);
            Ok(json!({"root": hex_fe(&root), "digest": hex_fe(&d), "tag": hex_fe(&t),
                      "cm": hex_fe(&native::note_commitment(&m))}))
        }
        "prove" => {
            let keys = keys.ok_or("no keys in this role")?;
            let public = public3(v)?;
            let w = witness(v, o.variant, o.depth)?;
            let t = Instant::now();
            let proof = keys.prove(&public, w)?;
            let secs = t.elapsed().as_secs_f64();
            *last_proof_len = Some(proof.len());
            Ok(json!({"proof": hex::encode(&proof), "prove_seconds": secs, "proof_bytes": proof.len()}))
        }
        "verify" => {
            let keys = keys.ok_or("no keys in this role")?;
            let t = Instant::now();
            let public = match public3(v) {
                Ok(p) => p,
                Err(e) => return Ok(json!({"valid": false, "verify_seconds": 0.0, "reason": e})),
            };
            let proof = match v.get("proof").and_then(|p| p.as_str()).map(hex::decode) {
                Some(Ok(p)) if p.len() <= 65536 => p,
                _ => return Ok(json!({"valid": false, "verify_seconds": 0.0, "reason": "malformed proof"})),
            };
            let valid = keys.verify(&public, &proof);
            Ok(json!({"valid": valid, "verify_seconds": t.elapsed().as_secs_f64()}))
        }
        _ => Err(format!("unknown op {op}")),
    }
}

fn main() {
    let o = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    };
    let keys = if o.role == "tool" {
        None
    } else {
        match Keys::setup(o.variant, o.depth, o.keys.as_deref(), o.role == "prover") {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("setup failed: {e}");
                std::process::exit(1)
            }
        }
    };
    if let Some(k) = &keys {
        eprintln!(
            "oob-admission ready: variant={} depth={} k={} rows={} vk_sha256={} params={} ({:.2}s) vk {:.2}s pk {:.2}s",
            o.variant.name(), o.depth, k.shape.k, k.shape.rows, k.vk_sha256,
            k.timings.params_source, k.timings.params_seconds, k.timings.keygen_vk_seconds, k.timings.keygen_pk_seconds
        );
    }
    std::panic::set_hook(Box::new(|_| {}));
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut last_proof_len = None;
    for line in io::stdin().lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = if line.len() > 1 << 20 {
            json!({"error": "request too large"})
        } else {
            match serde_json::from_str::<Value>(&line) {
                Err(e) => json!({"error": format!("bad json: {e}")}),
                Ok(v) => {
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle(&v, &o, keys.as_ref(), &mut last_proof_len)
                    }));
                    match r {
                        Ok(Ok(res)) => json!({"result": res}),
                        Ok(Err(e)) => json!({"error": e}),
                        Err(_) => json!({"error": "internal panic"}),
                    }
                }
            }
        };
        if writeln!(out, "{reply}").is_err() || out.flush().is_err() {
            break;
        }
    }
}
