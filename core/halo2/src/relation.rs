//! The admission relation R_adm of admission specification (P1 = full binding) and the weak
//! variant W1 (digest only). Derived from `integration/halo2/src/friendly.rs` (MIT) with the
//! Merkle depth as a runtime parameter.
//!
//! Instance column rows: 0 = rt_h, 1 = d, 2 = nu_adm.
use crate::gadgets::{Builder, Cell, Config, Point};
use crate::native::{self, DENOMINATION};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::bn256::Fr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// P1 "Var-Full": items 1, 1b (A11), 2-5 of admission specification.
    Full,
    /// W1 "Var-Bind" (weak: digest only): items 1-3 (no 1b, no 4, no 5); d is a public input
    /// bound only via the Fiat-Shamir transcript, not by any constraint.
    Weak,
}

impl Variant {
    pub fn parse(s: &str) -> Option<Variant> {
        match s {
            "full" => Some(Variant::Full),
            "weak" => Some(Variant::Weak),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Full => "full",
            Variant::Weak => "weak",
        }
    }
    pub fn relation(&self) -> &'static str {
        match self {
            Variant::Full => "oob-adm-v2/P1-full-binding+A11",
            Variant::Weak => "oob-adm-v2/W1-weak-digest-only",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdmissionWitness {
    pub message: [Fr; 18],
    /// Address component ob = Poseidon1(secret) (owner binding); used by the full variant only.
    pub ob: Fr,
    pub randomness: Fr,
    pub nonce: Fr,
    pub ciphertext: [Fr; 22],
    pub siblings: Vec<Fr>,
    pub directions: Vec<bool>,
}

#[derive(Clone, Debug)]
pub struct AdmissionCircuit {
    pub variant: Variant,
    pub depth: usize,
    pub witness: Option<AdmissionWitness>,
}

impl AdmissionCircuit {
    pub fn shape(variant: Variant, depth: usize) -> Self {
        AdmissionCircuit {
            variant,
            depth,
            witness: None,
        }
    }
}

impl Circuit<Fr> for AdmissionCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::shape(self.variant, self.depth)
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        Config::configure(meta)
    }
    fn synthesize(&self, cfg: Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        if let Some(w) = &self.witness {
            if w.siblings.len() != self.depth || w.directions.len() != self.depth {
                return Err(Error::Synthesis);
            }
        }
        let full = self.variant == Variant::Full;
        let depth = self.depth;
        let outputs = layouter.assign_region(
            || "oob admission relation",
            |mut region| {
                let mut b = Builder {
                    region: &mut region,
                    cfg: &cfg,
                    row: 0,
                };
                let w = self.witness.as_ref();
                let val = |f: &dyn Fn(&AdmissionWitness) -> Fr| -> Value<Fr> {
                    w.map(|w| Value::known(f(w))).unwrap_or(Value::unknown())
                };
                // (1) message slots, amount, payload hash, commitment
                let mut m: Vec<Cell> = Vec::new();
                for i in 0..18 {
                    m.push(b.witness(val(&|w| w.message[i]))?);
                }
                b.constrain_constant(&m[2], Fr::from(DENOMINATION))?;
                let payload = b.hash_chain(1001, &m)?;
                let cm = b.hash(&[m[5].clone(), m[3].clone(), payload])?;
                // (3) admission tag
                let domain = b.constant(Fr::from(1002))?;
                let tag = b.hash(&[domain, cm.clone(), m[3].clone()])?;
                // (2) Merkle path (direction 1 = current node is the right child)
                let mut root = cm;
                for i in 0..depth {
                    let sib = b.witness(val(&|w| w.siblings[i]))?;
                    let dir = w
                        .map(|w| Value::known(w.directions[i]))
                        .unwrap_or(Value::unknown());
                    let (l, r) = b.mux(&root, &sib, dir)?;
                    root = b.hash(&[l, r])?;
                }
                let mut digest = None;
                if full {
                    // (4) recipient key: on curve, x != 0, prime-order subgroup
                    let pk = Point {
                        x: m[0].clone(),
                        y: m[1].clone(),
                    };
                    b.curve(&pk)?;
                    let one = b.constant(Fr::ONE)?;
                    let _ = b.divide(&one, &pk.x)?;
                    let orderbytes = native::subgroup_order().to_repr();
                    let orderbits = (0..252)
                        .map(|i| b.constant(Fr::from(((orderbytes[i / 8] >> (i % 8)) & 1) as u64)))
                        .collect::<Result<Vec<_>, _>>()?;
                    let check = b.scalar_mul(&pk, &orderbits)?;
                    b.constrain_constant(&check.x, Fr::ZERO)?;
                    b.constrain_constant(&check.y, Fr::ONE)?;
                    // (1b, owner binding) owner field binds the encryption key:
                    // m[5] = Poseidon2(ob, Poseidon2(m[0], m[1]))
                    let ob = b.witness(val(&|w| w.ob))?;
                    let pkh = b.hash(&[m[0].clone(), m[1].clone()])?;
                    let own = b.hash(&[ob, pkh])?;
                    b.equal(&own, &m[5])?;
                    // epk = r*G, K = r*pk (r < 2^252, epk.x != 0 excludes r = 0 mod l)
                    let r = b.witness(val(&|w| w.randomness))?;
                    let bits = b.range_bits(&r, 252)?;
                    let (gx, gy) = native::base8();
                    let g = Point {
                        x: b.constant(gx)?,
                        y: b.constant(gy)?,
                    };
                    let epk = b.scalar_mul(&g, &bits)?;
                    let _ = b.divide(&one, &epk.x)?;
                    let shared = b.scalar_mul(&pk, &bits)?;
                    // nonce < 2^128
                    let nonce = b.witness(val(&|w| w.nonce))?;
                    b.range_bits(&nonce, 128)?;
                    // Poseidon-sponge authenticated encryption (zk-kit poseidon-cipher layout)
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
                    // C (witness) must equal the computed record element by element
                    for (i, c) in record.iter().enumerate() {
                        let actual = b.witness(val(&|w| w.ciphertext[i]))?;
                        b.equal(c, &actual)?;
                    }
                    // (5) d = PoseidonChain(1003, C)
                    digest = Some(b.hash_chain(1003, &record)?);
                }
                Ok((root, tag, digest))
            },
        )?;
        layouter.constrain_instance(outputs.0.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(outputs.1.cell(), cfg.instance, 2)?;
        if let Some(d) = outputs.2 {
            layouter.constrain_instance(d.cell(), cfg.instance, 1)?;
        }
        Ok(())
    }
}

