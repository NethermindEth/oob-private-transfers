//! S7-E2 admission-cost driver (new file; does not change the relation or the library).
//!
//! s7e2-bench bench --depth D --prove-runs N --verify-runs M [--keys DIR] [--fresh-params]
//!                  [--dump FILE] [--out FILE]
//!     P1 (variant full) only. Proves N random notes (timed: create_proof = Keys::prove_unchecked),
//!     then verifies M times cycling over the N proofs (timed: Keys::verify, canonical reader).
//!     --dump writes the proofs + public statements in the worker wire format (for the
//!     multi-process verifier-throughput run).
//! s7e2-bench batchverify --depth D --proofs FILE --batches 1,8,32,128 --reps R [--keys DIR] [--out FILE]
//!     halo2_proofs::plonk::BatchVerifier (stock Blake2b reader) over batches built by cycling through
//!     the dumped proofs; times add_proof + finalize per batch; negative check outside timing.
//! s7e2-bench breakdown --depth D [--out FILE]
//!     Rows and assigned advice cells per relation condition, from an instrumented copy of
//!     `AdmissionCircuit::synthesize` (P1) run through a counting `Assignment` backend. The copy is
//!     cross-checked against the real circuit: total rows must equal `setup::shape(Full, D).rows`
//!     and total cells must equal those of the real circuit under the same backend.
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Any, Assigned, Assignment, Circuit, Column, ConstraintSystem, Error, Fixed, FloorPlanner,
        Instance, Selector,
    },
};
use halo2curves::bn256::Fr;
use oob_admission::adversarial::Note;
use oob_admission::gadgets::{Builder, Cell, Config, Point};
use oob_admission::native::{self, DENOMINATION};
use oob_admission::setup::{load_params, shape, Keys};
use oob_admission::wire::hex_fe;
use oob_admission::{AdmissionCircuit, AdmissionWitness, Variant};
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

// ------------------------------------------------------------------ counting backend
#[derive(Default)]
struct CellCounter {
    max_row: usize,
    advice: HashSet<(Column<Advice>, usize)>,
    fixed: HashSet<(Column<Fixed>, usize)>,
    selectors: usize,
    copies: usize,
}
impl CellCounter {
    fn touch(&mut self, row: usize) {
        self.max_row = self.max_row.max(row);
    }
    fn advice_in(&self, lo: usize, hi: usize) -> usize {
        self.advice.iter().filter(|(_, r)| *r >= lo && *r < hi).count()
    }
}
impl Assignment<Fr> for CellCounter {
    fn enter_region<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }
    fn exit_region(&mut self) {}
    fn enable_selector<A, AR>(&mut self, _: A, _: &Selector, row: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.touch(row);
        self.selectors += 1;
        Ok(())
    }
    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<Fr>, Error> {
        Ok(Value::unknown())
    }
    fn assign_advice<V, VR, A, AR>(&mut self, _: A, c: Column<Advice>, row: usize, _: V) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fr>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.touch(row);
        self.advice.insert((c, row));
        Ok(())
    }
    fn assign_fixed<V, VR, A, AR>(&mut self, _: A, c: Column<Fixed>, row: usize, _: V) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fr>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.touch(row);
        self.fixed.insert((c, row));
        Ok(())
    }
    fn copy(&mut self, _: Column<Any>, a: usize, _: Column<Any>, b: usize) -> Result<(), Error> {
        self.touch(a);
        self.touch(b);
        self.copies += 1;
        Ok(())
    }
    fn fill_from_row(&mut self, _: Column<Fixed>, row: usize, _: Value<Assigned<Fr>>) -> Result<(), Error> {
        self.touch(row);
        Ok(())
    }
    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }
    fn pop_namespace(&mut self, _: Option<String>) {}
}

// ------------------------------------------------------------------ instrumented copy of P1
/// Verbatim copy of `AdmissionCircuit::synthesize` for `Variant::Full` with row checkpoints
/// (`mark`). Only the checkpoints are added; gadget calls and their order are unchanged.
struct Instrumented {
    depth: usize,
    marks: RefCell<Vec<(String, usize)>>,
}
impl Circuit<Fr> for Instrumented {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Instrumented { depth: self.depth, marks: RefCell::new(Vec::new()) }
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        Config::configure(meta)
    }
    fn synthesize(&self, cfg: Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let depth = self.depth;
        let marks = &self.marks;
        let outputs = layouter.assign_region(
            || "oob admission relation",
            |mut region| {
                marks.borrow_mut().clear();
                let mut b = Builder { region: &mut region, cfg: &cfg, row: 0 };
                let mark = |label: &str, row: usize| marks.borrow_mut().push((label.to_string(), row));
                let val = || Value::<Fr>::unknown();
                mark("start", b.row);
                let mut m: Vec<Cell> = Vec::new();
                for _ in 0..18 {
                    m.push(b.witness(val())?);
                }
                b.constrain_constant(&m[2], Fr::from(DENOMINATION))?;
                mark("note_witness", b.row);
                let payload = b.hash_chain(1001, &m)?;
                mark("cm_payload_chain", b.row);
                let cm = b.hash(&[m[5].clone(), m[3].clone(), payload])?;
                mark("cm_poseidon3", b.row);
                let domain = b.constant(Fr::from(1002))?;
                let tag = b.hash(&[domain, cm.clone(), m[3].clone()])?;
                mark("tag", b.row);
                let mut root = cm;
                for _ in 0..depth {
                    let sib = b.witness(val())?;
                    let (l, r) = b.mux(&root, &sib, Value::unknown())?;
                    root = b.hash(&[l, r])?;
                }
                mark("merkle", b.row);
                let pk = Point { x: m[0].clone(), y: m[1].clone() };
                b.curve(&pk)?;
                let one = b.constant(Fr::ONE)?;
                let _ = b.divide(&one, &pk.x)?;
                mark("key_on_curve_xnonzero", b.row);
                let orderbytes = native::subgroup_order().to_repr();
                let orderbits = (0..252)
                    .map(|i| b.constant(Fr::from(((orderbytes[i / 8] >> (i % 8)) & 1) as u64)))
                    .collect::<Result<Vec<_>, _>>()?;
                mark("key_order_constants", b.row);
                let check = b.scalar_mul(&pk, &orderbits)?;
                b.constrain_constant(&check.x, Fr::ZERO)?;
                b.constrain_constant(&check.y, Fr::ONE)?;
                mark("key_subgroup_scalarmul", b.row);
                let ob = b.witness(val())?;
                let pkh = b.hash(&[m[0].clone(), m[1].clone()])?;
                let own = b.hash(&[ob, pkh])?;
                b.equal(&own, &m[5])?;
                mark("lock", b.row);
                let r = b.witness(val())?;
                let bits = b.range_bits(&r, 252)?;
                mark("enc_r_bits", b.row);
                let (gx, gy) = native::base8();
                let g = Point { x: b.constant(gx)?, y: b.constant(gy)? };
                let epk = b.scalar_mul(&g, &bits)?;
                let _ = b.divide(&one, &epk.x)?;
                mark("enc_epk_scalarmul", b.row);
                let shared = b.scalar_mul(&pk, &bits)?;
                mark("enc_ecdh_scalarmul", b.row);
                let nonce = b.witness(val())?;
                b.range_bits(&nonce, 128)?;
                mark("enc_nonce_range", b.row);
                let mut record = vec![epk.x, epk.y, nonce.clone()];
                let length = b.constant(Fr::from(18) * Fr::from(2).pow_vartime([128]))?;
                let init = b.plus(&nonce, &length)?;
                let mut state = vec![b.constant(Fr::ZERO)?, shared.x, shared.y, init];
                for chunk in m.chunks(3) {
                    state = b.permute4(&state)?;
                    for j in 0..3 {
                        state[j + 1] = b.plus(&state[j + 1], &chunk[j])?;
                        record.push(state[j + 1].clone());
                    }
                }
                state = b.permute4(&state)?;
                record.push(state[1].clone());
                mark("enc_sponge", b.row);
                for c in record.iter() {
                    let actual = b.witness(val())?;
                    b.equal(c, &actual)?;
                }
                mark("enc_ciphertext_witness", b.row);
                let digest = b.hash_chain(1003, &record)?;
                mark("digest", b.row);
                Ok((root, tag, digest))
            },
        )?;
        layouter.constrain_instance(outputs.0.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(outputs.1.cell(), cfg.instance, 2)?;
        layouter.constrain_instance(outputs.2.cell(), cfg.instance, 1)?;
        Ok(())
    }
}

fn count<C: Circuit<Fr, Config = Config>>(c: &C) -> CellCounter {
    let mut cs = ConstraintSystem::<Fr>::default();
    let config = C::configure(&mut cs);
    let mut counter = CellCounter::default();
    <C as Circuit<Fr>>::FloorPlanner::synthesize(&mut counter, c, config.clone(), vec![config.constant])
        .expect("synthesize");
    counter
}

fn breakdown(depth: usize) -> serde_json::Value {
    let inst = Instrumented { depth, marks: RefCell::new(Vec::new()) };
    let ci = count(&inst);
    let real = count(&AdmissionCircuit::shape(Variant::Full, depth));
    let sh = shape(Variant::Full, depth);
    let marks = inst.marks.borrow().clone();
    let total_rows = ci.max_row + 1;
    let mut sections = Vec::new();
    for w in marks.windows(2) {
        let (lo, hi) = (w[0].1, w[1].1);
        sections.push(json!({"section": w[1].0, "row_start": lo, "rows": hi - lo,
                             "advice_cells": ci.advice_in(lo, hi)}));
    }
    let last = marks.last().unwrap().1;
    json!({
        "mode": "breakdown",
        "variant": "full",
        "depth": depth,
        "k": sh.k,
        "rows_total_instrumented": total_rows,
        "rows_total_real_circuit_shape": sh.rows,
        "rows_last_mark": last,
        "advice_cells_instrumented": ci.advice.len(),
        "advice_cells_real_circuit": real.advice.len(),
        "fixed_cells_instrumented": ci.fixed.len(),
        "fixed_cells_real_circuit": real.fixed.len(),
        "selectors_enabled": real.selectors,
        "copy_constraints": real.copies,
        "cross_check_ok": total_rows == sh.rows && last == sh.rows && ci.advice.len() == real.advice.len()
            && ci.fixed.len() == real.fixed.len() && ci.copies == real.copies,
        "advice_columns": sh.advice_columns,
        "rows_available": (1usize << sh.k) - sh.blinding_rows,
        "blinding_rows": sh.blinding_rows,
        "sections": sections,
    })
}

fn main() {
    let t_total = Instant::now();
    let mode = std::env::args().nth(1).unwrap_or_default();
    let depth: usize = arg("--depth").unwrap_or("32".into()).parse().unwrap();
    let threads = rayon::current_num_threads();
    let doc = match mode.as_str() {
        "breakdown" => breakdown(depth),
        "batchverify" => {
            use halo2_proofs::plonk::BatchVerifier;
            use halo2curves::bn256::G1Affine;
            let keys_dir = arg("--keys").map(PathBuf::from);
            let keys = Keys::setup(Variant::Full, depth, keys_dir.as_deref(), false).expect("setup");
            let items: Vec<serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(arg("--proofs").expect("--proofs")).unwrap()).unwrap();
            let proofs: Vec<([Fr; 3], Vec<u8>)> = items
                .iter()
                .map(|it| {
                    let p = &it["public"];
                    let f = |n: &str| oob_admission::wire::fe(p[n].as_str().unwrap()).unwrap();
                    ([f("root"), f("digest"), f("tag")], hex::decode(it["proof"].as_str().unwrap()).unwrap())
                })
                .collect();
            let batches: Vec<usize> = arg("--batches").unwrap_or("1,8,32,128".into())
                .split(',').map(|x| x.parse().unwrap()).collect();
            let reps: usize = arg("--reps").unwrap_or("5".into()).parse().unwrap();
            let mut out = Vec::new();
            for &n in &batches {
                let mut samples = Vec::new();
                for rep in 0..reps {
                    let t = Instant::now();
                    let mut bv = BatchVerifier::<G1Affine>::new();
                    for i in 0..n {
                        let (pb, pr) = &proofs[(i + rep) % proofs.len()];
                        bv.add_proof(vec![vec![pb.to_vec()]], pr.clone());
                    }
                    let ok = bv.finalize(&keys.params, &keys.vk);
                    let s = t.elapsed().as_secs_f64();
                    // negative: same batch with one public input altered (not timed)
                    let mut bv = BatchVerifier::<G1Affine>::new();
                    for i in 0..n {
                        let (pb, pr) = &proofs[(i + rep) % proofs.len()];
                        let mut pb = *pb;
                        if i == n / 2 { pb[1] += Fr::ONE; }
                        bv.add_proof(vec![vec![pb.to_vec()]], pr.clone());
                    }
                    let neg = !bv.finalize(&keys.params, &keys.vk);
                    eprintln!("batch {n} rep {rep}: {s:.3}s ({:.1} ms/proof) valid={ok} neg_rejected={neg}", s * 1e3 / n as f64);
                    samples.push(json!({"rep": rep, "seconds": s, "per_proof_seconds": s / n as f64,
                                        "valid": ok, "negative_rejected": neg}));
                }
                out.push(json!({"batch": n, "samples": samples}));
            }
            json!({"mode": "batchverify", "variant": "full", "depth": depth, "k": keys.shape.k,
                   "rayon_threads": threads, "distinct_proofs": proofs.len(),
                   "reader": "stock Blake2bRead inside BatchVerifier (no canonical-encoding / trailing-byte check)",
                   "results": out, "wall_seconds": t_total.elapsed().as_secs_f64()})
        }
        "bench" => {
            let variant = Variant::Full;
            let keys_dir = arg("--keys").map(PathBuf::from);
            let prove_runs: usize = arg("--prove-runs").unwrap_or("10".into()).parse().unwrap();
            let verify_runs: usize = arg("--verify-runs").unwrap_or("20".into()).parse().unwrap();
            let fresh = if flag("--fresh-params") {
                let sh = shape(variant, depth);
                let (_, secs, _, _) = load_params(None, sh.k).unwrap();
                Some(secs)
            } else {
                None
            };
            let keys = Keys::setup(variant, depth, keys_dir.as_deref(), true).expect("setup");
            let mut prove = Vec::new();
            let mut proofs: Vec<([Fr; 3], Vec<u8>)> = Vec::new();
            let mut failures = Vec::new();
            for i in 0..prove_runs {
                let note = Note::random(depth);
                let public = note.public();
                let w: AdmissionWitness = note.witness();
                let t = Instant::now();
                let chk = keys.check_witness(&public, &w);
                let check_s = t.elapsed().as_secs_f64();
                if let Err(e) = chk {
                    failures.push(json!({"run": i, "error": e}));
                    continue;
                }
                let t = Instant::now();
                let proof = match keys.prove_unchecked(&public, w) {
                    Ok(p) => p,
                    Err(e) => {
                        failures.push(json!({"run": i, "error": e}));
                        continue;
                    }
                };
                let prove_s = t.elapsed().as_secs_f64();
                eprintln!("prove {i}: {prove_s:.3}s ({} B)", proof.len());
                prove.push(json!({"run": i, "prove_seconds": prove_s, "native_check_seconds": check_s,
                                  "proof_bytes": proof.len()}));
                proofs.push((public, proof));
            }
            let mut verify = Vec::new();
            for i in 0..verify_runs {
                let (public, proof) = &proofs[i % proofs.len()];
                let t = Instant::now();
                let ok = keys.verify(public, proof);
                let s = t.elapsed().as_secs_f64();
                let mut bad = *public;
                bad[1] += Fr::ONE;
                let neg = !keys.verify(&bad, proof);
                if !ok || !neg {
                    failures.push(json!({"verify_run": i, "valid": ok, "negative_rejected": neg}));
                }
                verify.push(json!({"run": i, "proof_index": i % proofs.len(), "verify_seconds": s,
                                   "valid": ok, "negative_rejected": neg}));
            }
            if let Some(p) = arg("--dump") {
                let items: Vec<_> = proofs
                    .iter()
                    .map(|(pb, pr)| json!({"public": {"root": hex_fe(&pb[0]), "digest": hex_fe(&pb[1]),
                                                      "tag": hex_fe(&pb[2])}, "proof": hex::encode(pr)}))
                    .collect();
                std::fs::write(p, serde_json::to_string(&items).unwrap()).unwrap();
            }
            json!({
                "mode": "bench",
                "variant": "full",
                "variant_label": "P1 (full binding)",
                "relation": variant.relation(),
                "depth": depth,
                "k": keys.shape.k,
                "rows_used": keys.shape.rows,
                "rows_available": (1usize << keys.shape.k) - keys.shape.blinding_rows,
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
                    "keygen_vk_seconds": keys.timings.keygen_vk_seconds,
                    "keygen_pk_seconds": keys.timings.keygen_pk_seconds,
                },
                "timed_prove": "Keys::prove_unchecked = halo2 create_proof incl. witness synthesis (native check timed separately)",
                "timed_verify": "Keys::verify = verify_proof with the canonical-encoding reader (as in the provider's worker)",
                "prove": prove,
                "verify": verify,
                "failures": failures,
                "rng": "OS RNG (unseeded)",
                "wall_seconds": t_total.elapsed().as_secs_f64(),
            })
        }
        _ => {
            eprintln!("usage: s7e2-bench bench|breakdown --depth D ...");
            std::process::exit(2)
        }
    };
    let text = serde_json::to_string_pretty(&doc).unwrap();
    match arg("--out") {
        Some(p) => std::fs::write(p, text).unwrap(),
        None => println!("{text}"),
    }
}
