//! `oob-bench`: build a circuit, fill its witness, prove and verify with
//! Binius64 in zero-knowledge mode, and print one JSON row of sizes and timings.
//!
//! Threads are controlled by `RAYON_NUM_THREADS`. Build with
//! `RUSTFLAGS="-C target-cpu=native"`.

use std::time::Instant;

use anyhow::Result;
use binius_core::word::Word;
use binius_frontend::{Circuit, CircuitBuilder, CircuitStat, WitnessFiller};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};
use clap::{Parser, Subcommand, ValueEnum};
use oob_circuits::admission::AdmissionCircuit;
use oob_circuits::aes::aes128_ctr;
use oob_circuits::hashes::{populate_words, witness_words};
use oob_circuits::merkle::MerkleCircuit;
use oob_circuits::reference::enc::aes128_ctr as native_aes128_ctr;
use oob_circuits::reference::instance::AdmissionInstance;
use oob_circuits::reference::merkle::{DEPTH, NodeHash, SparseMerkleTree};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::Serialize;

#[derive(Parser)]
#[command(about = "Prove and verify OOB admission circuits with Binius64 (zero-knowledge proofs)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Reed-Solomon log inverse rate (proof size vs prover time).
    #[arg(long, default_value_t = 1)]
    log_inv_rate: usize,
    /// Prove/verify this many times; the row reports the median.
    #[arg(long, default_value_t = 1)]
    repeat: usize,
}

#[derive(Subcommand)]
enum Cmd {
    Merkle {
        #[arg(long, value_enum, default_value_t = NodeHashArg::Full)]
        node_hash: NodeHashArg,
    },
    Aes {
        #[arg(long, default_value_t = 42)]
        blocks: usize,
    },
    Admission {
        #[arg(long, value_enum, default_value_t = NodeHashArg::Full)]
        node_hash: NodeHashArg,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum NodeHashArg {
    Full,
    CompressOnly,
}

impl From<NodeHashArg> for NodeHash {
    fn from(a: NodeHashArg) -> Self {
        match a {
            NodeHashArg::Full => NodeHash::Full,
            NodeHashArg::CompressOnly => NodeHash::CompressOnly,
        }
    }
}

#[derive(Serialize)]
struct Row {
    circuit: String,
    params: String,
    log_inv_rate: usize,
    threads: usize,
    n_and: usize,
    n_bmul: usize,
    n_imul: usize,
    n_witness: usize,
    n_inout: usize,
    build_ms: f64,
    witness_ms: f64,
    setup_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    repeat: usize,
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn run(
    cli: &Cli,
    name: &str,
    params: &str,
    build: impl FnOnce(&CircuitBuilder) -> Box<dyn FnOnce(&mut WitnessFiller<'_>)>,
) -> Result<()> {
    let t = Instant::now();
    let b = CircuitBuilder::new();
    let fill = build(&b);
    let circuit: Circuit = b.build();
    let build_ms = t.elapsed().as_secs_f64() * 1e3;
    let stat = CircuitStat::collect(&circuit);

    let t = Instant::now();
    let mut w = circuit.new_witness_filler();
    fill(&mut w);
    circuit.populate_wire_witness(&mut w)?;
    let witness = w.into_value_vec();
    let witness_ms = t.elapsed().as_secs_f64() * 1e3;
    let cs = circuit.constraint_system().clone();
    cs.verify(&witness)?;

    let (mut prove, mut verify) = (Vec::new(), Vec::new());
    let mut proof_bytes = 0;
    let t = Instant::now();
    let verifier = ZKVerifier::<StdHashSuite>::setup(cs, cli.log_inv_rate)?;
    let prover = ZKProver::<OptimalPackedB128, StdHashSuite>::setup(&verifier)?;
    let setup_ms = t.elapsed().as_secs_f64() * 1e3;
    for _ in 0..cli.repeat {
        let t = Instant::now();
        let mut pt = ProverTranscript::new(StdChallenger::default());
        prover.prove(&witness, rand::rng(), &mut pt)?;
        let proof = pt.finalize();
        prove.push(t.elapsed().as_secs_f64() * 1e3);
        proof_bytes = proof.len();
        let t = Instant::now();
        let mut vt = VerifierTranscript::new(StdChallenger::default(), proof);
        verifier.verify(witness.inout(), &mut vt)?;
        vt.finalize()?;
        verify.push(t.elapsed().as_secs_f64() * 1e3);
    }

    let row = Row {
        circuit: name.into(),
        params: params.into(),
        log_inv_rate: cli.log_inv_rate,
        threads: rayon_threads(),
        n_and: stat.n_and_constraints,
        n_bmul: stat.n_bmul_constraints,
        n_imul: stat.n_imul_constraints,
        n_witness: stat.n_witness,
        n_inout: stat.n_inout,
        build_ms,
        witness_ms,
        setup_ms,
        prove_ms: median(&mut prove),
        verify_ms: median(&mut verify),
        proof_bytes,
        repeat: cli.repeat,
    };
    println!("{}", serde_json::to_string(&row)?);
    Ok(())
}

fn rayon_threads() -> usize {
    std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Merkle { node_hash } => {
            let nh: NodeHash = node_hash.into();
            run(&cli, "merkle", nh.name(), |b| {
                let mc = MerkleCircuit::build(b, DEPTH, nh);
                let mut rng = StdRng::seed_from_u64(42);
                let mut tree = SparseMerkleTree::new(DEPTH, nh);
                let mut leaf = [0u8; 32];
                rng.fill_bytes(&mut leaf);
                let index = rng.next_u64() & ((1 << DEPTH) - 1);
                tree.insert(index, leaf);
                let (path, root) = (tree.path(index), tree.root());
                Box::new(move |w| mc.populate(w, &leaf, &path, &root))
            })
        }
        Cmd::Aes { blocks } => run(&cli, "aes", &format!("{blocks} blocks"), |b| {
            let key: [_; 4] = std::array::from_fn(|_| b.add_witness());
            let pt = witness_words(b, 16 * blocks);
            let ct = aes128_ctr(&b, key, &pt);
            let expected: Vec<_> = (0..ct.len()).map(|_| b.add_inout()).collect();
            for (i, (c, e)) in ct.iter().zip(&expected).enumerate() {
                b.assert_eq(format!("ct[{i}]"), *c, *e);
            }
            let mut rng = StdRng::seed_from_u64(42);
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            let mut pt_bytes = vec![0u8; 16 * blocks];
            rng.fill_bytes(&mut pt_bytes);
            let ct_bytes = native_aes128_ctr(&key_bytes, &pt_bytes);
            Box::new(move |w| {
                for (wire, c) in key.iter().zip(key_bytes.chunks(4)) {
                    w[*wire] = Word(u32::from_be_bytes(c.try_into().unwrap()) as u64);
                }
                populate_words(w, &pt, &pt_bytes);
                populate_words(w, &expected, &ct_bytes);
            })
        }),
        Cmd::Admission { node_hash } => {
            let nh: NodeHash = node_hash.into();
            run(&cli, "admission", nh.name(), |b| {
                let ac = AdmissionCircuit::build(b, nh);
                let inst = AdmissionInstance::generate(nh, &mut StdRng::seed_from_u64(42));
                Box::new(move |w| ac.populate(w, &inst))
            })
        }
    }
}
