//! Gate configuration and low-level gadgets for the OOB admission relation.
//!
//! Derived from `integration/halo2/src/circuit.rs` and `integration/halo2/src/friendly.rs`
//! (MIT). The SHA-256 gates of the excluded "staged hybrid" circuit are removed; every gate
//! and gadget used by the BabyJubjub + Poseidon-cipher relation is kept unchanged.
use crate::native::constants;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

pub type Cell = AssignedCell<Fr, Fr>;

/// Number of advice columns (Poseidon t=4 needs 4 inputs + 4 outputs per row).
pub const ADVICE_COLUMNS: usize = 8;

#[derive(Clone, Debug)]
pub struct Config {
    pub a: [Column<Advice>; ADVICE_COLUMNS],
    pub f: [Column<Fixed>; 4],
    pub constant: Column<Fixed>,
    pub instance: Column<Instance>,
    pub bitpack: Selector,
    pub select: Selector,
    pub poseidon: [[Selector; 2]; 2],
}

impl Config {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        let a: [Column<Advice>; ADVICE_COLUMNS] = std::array::from_fn(|_| meta.advice_column());
        for col in a {
            meta.enable_equality(col);
        }
        let f = std::array::from_fn(|_| meta.fixed_column());
        let constant = meta.fixed_column();
        meta.enable_constant(constant);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let bitpack = meta.selector();
        let select = meta.selector();
        let ps: [[Selector; 2]; 2] = std::array::from_fn(|_| std::array::from_fn(|_| meta.selector()));
        // acc = 2*prev + b, b boolean.
        meta.create_gate("pack bits", |m| {
            let q = m.query_selector(bitpack);
            let b = m.query_advice(a[3], Rotation::cur());
            let prev = m.query_advice(a[4], Rotation::cur());
            let acc = m.query_advice(a[5], Rotation::cur());
            vec![
                q.clone() * (acc - prev * Fr::from(2) - b.clone()),
                q * b.clone() * (b - Expression::Constant(Fr::ONE)),
            ]
        });
        // out = a + b*c.
        meta.create_gate("mul add", |m| {
            let q = m.query_selector(select);
            let a0 = m.query_advice(a[0], Rotation::cur());
            let b = m.query_advice(a[1], Rotation::cur());
            let c = m.query_advice(a[2], Rotation::cur());
            let out = m.query_advice(a[3], Rotation::cur());
            vec![q * (a0 + b * c - out)]
        });
        // One Poseidon round (ARK, S-box, MDS) per row; idx 0: t=3, idx 1: t=4;
        // mode 0: full round, mode 1: partial round (S-box on state[0] only).
        for idx in 0..2 {
            let t = idx + 3;
            for mode in 0..2 {
                let selector = ps[idx][mode];
                meta.create_gate("BN254 Poseidon round", |m| {
                    let q = m.query_selector(selector);
                    let state: Vec<_> = (0..t)
                        .map(|j| {
                            let x = m.query_advice(a[j], Rotation::cur()) + m.query_fixed(f[j]);
                            if mode == 0 || j == 0 {
                                x.clone() * x.clone() * x.clone() * x.clone() * x
                            } else {
                                x
                            }
                        })
                        .collect();
                    (0..t)
                        .map(|i| {
                            let sum = (0..t)
                                .map(|j| state[j].clone() * constants().m[idx][i][j])
                                .reduce(|a, b| a + b)
                                .unwrap();
                            q.clone() * (m.query_advice(a[4 + i], Rotation::cur()) - sum)
                        })
                        .collect::<Vec<_>>()
                });
            }
        }
        Config {
            a,
            f,
            constant,
            instance,
            bitpack,
            select,
            poseidon: ps,
        }
    }
}

#[derive(Clone)]
pub struct Word {
    pub bits: Vec<Cell>,
    pub packed: Cell,
}

#[derive(Clone)]
pub struct Point {
    pub x: Cell,
    pub y: Cell,
}

pub struct Builder<'a, 'b> {
    pub region: &'a mut Region<'b, Fr>,
    pub cfg: &'a Config,
    pub row: usize,
}

impl<'a, 'b> Builder<'a, 'b> {
    pub fn witness(&mut self, v: Value<Fr>) -> Result<Cell, Error> {
        let c = self
            .region
            .assign_advice(|| "private", self.cfg.a[0], self.row, || v)?;
        self.row += 1;
        Ok(c)
    }
    pub fn constant(&mut self, v: Fr) -> Result<Cell, Error> {
        let c = self
            .region
            .assign_advice_from_constant(|| "constant", self.cfg.a[0], self.row, v)?;
        self.row += 1;
        Ok(c)
    }
    fn constant_at(&mut self, v: Fr, col: usize) -> Result<Cell, Error> {
        self.region
            .assign_advice_from_constant(|| "constant", self.cfg.a[col], self.row, v)
    }
    fn copy(&mut self, c: &Cell, col: usize) -> Result<Cell, Error> {
        c.copy_advice(|| "copy", self.region, self.cfg.a[col], self.row)
    }
    fn output(&mut self, col: usize, v: Value<Fr>) -> Result<Cell, Error> {
        self.region
            .assign_advice(|| "result", self.cfg.a[col], self.row, || v)
    }
    /// 32 boolean-constrained bits packed MSB-first into `packed`.
    pub fn word(&mut self, value: Value<u32>) -> Result<Word, Error> {
        let mut bits: Vec<Cell> = Vec::new();
        let mut acc = self.constant(Fr::ZERO)?;
        for j in (0..32).rev() {
            self.cfg.bitpack.enable(self.region, self.row)?;
            let bit = self.output(3, value.map(|v| Fr::from(((v >> j) & 1) as u64)))?;
            self.copy(&acc, 4)?;
            acc = self.output(
                5,
                acc.value()
                    .zip(bit.value())
                    .map(|(a, b)| *a * Fr::from(2) + b),
            )?;
            bits.push(bit);
            self.row += 1;
        }
        bits.reverse();
        Ok(Word { bits, packed: acc })
    }
    /// sum_i words[i] * 2^(32*(len-1-i)) (first word most significant).
    pub fn field_from_words(&mut self, words: &[Word]) -> Result<Cell, Error> {
        let mut acc = self.constant(Fr::ZERO)?;
        for word in words {
            self.cfg.select.enable(self.region, self.row)?;
            self.copy(&word.packed, 0)?;
            self.copy(&acc, 1)?;
            self.constant_at(Fr::from(1u64 << 32), 2)?;
            acc = self.output(
                3,
                acc.value()
                    .zip(word.packed.value())
                    .map(|(a, b)| *a * Fr::from(1u64 << 32) + b),
            )?;
            self.row += 1;
        }
        Ok(acc)
    }
    /// circomlib Poseidon(inputs) for 2 or 3 inputs (t = 3 or 4).
    pub fn hash(&mut self, inputs: &[Cell]) -> Result<Cell, Error> {
        let t = inputs.len() + 1;
        assert!(t == 3 || t == 4);
        let idx = t - 3;
        let rounds = if t == 3 { 65 } else { 64 };
        let mut state = vec![self.constant(Fr::ZERO)?];
        state.extend_from_slice(inputs);
        let state = self.rounds(idx, rounds, state)?;
        Ok(state[0].clone())
    }
    /// The width-4 Poseidon permutation (all four output lanes), as used by the cipher.
    pub fn permute4(&mut self, initial: &[Cell]) -> Result<Vec<Cell>, Error> {
        assert_eq!(initial.len(), 4);
        self.rounds(1, 64, initial.to_vec())
    }
    fn rounds(&mut self, idx: usize, rounds: usize, mut state: Vec<Cell>) -> Result<Vec<Cell>, Error> {
        let t = idx + 3;
        let c = constants();
        for r in 0..rounds {
            let full = r < 4 || r >= rounds - 4;
            self.cfg.poseidon[idx][if full { 0 } else { 1 }].enable(self.region, self.row)?;
            for j in 0..t {
                self.copy(&state[j], j)?;
                self.region.assign_fixed(
                    || "round constant",
                    self.cfg.f[j],
                    self.row,
                    || Value::known(c.c[idx][r * t + j]),
                )?;
            }
            let mut next = Vec::new();
            for i in 0..t {
                let v = (0..t).fold(Value::known(Fr::ZERO), |acc, j| {
                    acc.zip(state[j].value()).map(|(acc, v)| {
                        let x = *v + c.c[idx][r * t + j];
                        acc + c.m[idx][i][j]
                            * if full || j == 0 { x.pow_vartime([5]) } else { x }
                    })
                });
                next.push(self.output(4 + i, v)?);
            }
            state = next;
            self.row += 1;
        }
        Ok(state)
    }
    /// Conditional swap: bit=0 -> (a,b), bit=1 -> (b,a). The bit is constrained boolean
    /// by the bitpack gate row below (b*(b-1)=0 applied to the packed value).
    pub fn mux(&mut self, a: &Cell, b: &Cell, bit: Value<bool>) -> Result<(Cell, Cell), Error> {
        self.mux_raw(a, b, bit.map(|v| v as u32))
    }
    /// `mux` with the direction given as a raw u32 (tests use non-boolean values to check
    /// that the circuit rejects them).
    pub fn mux_raw(&mut self, a: &Cell, b: &Cell, bit: Value<u32>) -> Result<(Cell, Cell), Error> {
        let bit = self.word(bit)?;
        self.region.constrain_constant(bit.bits[1].cell(), Fr::ZERO)?;
        let delta = self.witness(a.value().zip(b.value()).map(|(a, b)| *b - a))?;
        // a + delta*1 = b
        self.cfg.select.enable(self.region, self.row)?;
        self.copy(a, 0)?;
        self.copy(&delta, 1)?;
        self.constant_at(Fr::ONE, 2)?;
        self.copy(b, 3)?;
        self.row += 1;
        // packed = 2*0 + packed, packed*(packed-1) = 0  => direction is boolean
        self.cfg.bitpack.enable(self.region, self.row)?;
        self.copy(&bit.packed, 3)?;
        self.constant_at(Fr::ZERO, 4)?;
        self.copy(&bit.packed, 5)?;
        self.row += 1;
        self.cfg.select.enable(self.region, self.row)?;
        self.copy(a, 0)?;
        self.copy(&delta, 1)?;
        self.copy(&bit.packed, 2)?;
        let left = self.output(
            3,
            a.value()
                .zip(delta.value())
                .zip(bit.packed.value())
                .map(|((a, d), b)| *a + *d * b),
        )?;
        self.row += 1;
        let negative = self.witness(delta.value().map(|v| -v))?;
        // delta + negative*1 = 0
        self.cfg.select.enable(self.region, self.row)?;
        self.copy(&delta, 0)?;
        self.copy(&negative, 1)?;
        self.constant_at(Fr::ONE, 2)?;
        self.constant_at(Fr::ZERO, 3)?;
        self.row += 1;
        self.cfg.select.enable(self.region, self.row)?;
        self.copy(b, 0)?;
        self.copy(&negative, 1)?;
        self.copy(&bit.packed, 2)?;
        let right = self.output(
            3,
            b.value()
                .zip(negative.value())
                .zip(bit.packed.value())
                .map(|((a, d), b)| *a + *d * b),
        )?;
        self.row += 1;
        Ok((left, right))
    }
    pub fn madd(&mut self, a: &Cell, b: &Cell, c: &Cell) -> Result<Cell, Error> {
        self.cfg.select.enable(self.region, self.row)?;
        self.copy(a, 0)?;
        self.copy(b, 1)?;
        self.copy(c, 2)?;
        let out = self.output(
            3,
            a.value()
                .zip(b.value())
                .zip(c.value())
                .map(|((a, b), c)| *a + *b * c),
        )?;
        self.row += 1;
        Ok(out)
    }
    pub fn plus(&mut self, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        let one = self.constant(Fr::ONE)?;
        self.madd(a, b, &one)
    }
    pub fn times(&mut self, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        let zero = self.constant(Fr::ZERO)?;
        self.madd(&zero, a, b)
    }
    pub fn scale(&mut self, a: &Cell, v: Fr) -> Result<Cell, Error> {
        let c = self.constant(v)?;
        self.times(a, &c)
    }
    /// num/den with den*inv = 1 enforced (unsatisfiable when den = 0).
    pub fn divide(&mut self, num: &Cell, den: &Cell) -> Result<Cell, Error> {
        let inv = self.witness(den.value().map(|x| x.invert().unwrap_or(Fr::ZERO)))?;
        let check = self.times(den, &inv)?;
        self.region.constrain_constant(check.cell(), Fr::ONE)?;
        self.times(num, &inv)
    }
    pub fn equal(&mut self, a: &Cell, b: &Cell) -> Result<(), Error> {
        self.region.constrain_equal(a.cell(), b.cell())
    }
    pub fn constrain_constant(&mut self, a: &Cell, v: Fr) -> Result<(), Error> {
        self.region.constrain_constant(a.cell(), v)
    }
    /// BabyJubjub (twisted Edwards, a=168700, d=168696): a x^2 + y^2 = 1 + d x^2 y^2.
    pub fn curve(&mut self, p: &Point) -> Result<(), Error> {
        let xx = self.times(&p.x, &p.x)?;
        let yy = self.times(&p.y, &p.y)?;
        let ax = self.scale(&xx, Fr::from(168700))?;
        let lhs = self.plus(&ax, &yy)?;
        let xy = self.times(&xx, &yy)?;
        let dxy = self.scale(&xy, Fr::from(168696))?;
        let one = self.constant(Fr::ONE)?;
        let rhs = self.plus(&one, &dxy)?;
        self.equal(&lhs, &rhs)
    }
    /// Complete twisted Edwards addition (a square, d non-square in F_p).
    pub fn point_add(&mut self, p: &Point, q: &Point) -> Result<Point, Error> {
        let xx = self.times(&p.x, &q.x)?;
        let yy = self.times(&p.y, &q.y)?;
        let xy = self.times(&p.x, &q.y)?;
        let yx = self.times(&p.y, &q.x)?;
        let prod = self.times(&xx, &yy)?;
        let d = self.scale(&prod, Fr::from(168696))?;
        let nd = self.scale(&d, -Fr::ONE)?;
        let one = self.constant(Fr::ONE)?;
        let dx = self.plus(&one, &d)?;
        let dy = self.plus(&one, &nd)?;
        let nx = self.plus(&xy, &yx)?;
        let ax = self.scale(&xx, -Fr::from(168700))?;
        let ny = self.plus(&yy, &ax)?;
        Ok(Point {
            x: self.divide(&nx, &dx)?,
            y: self.divide(&ny, &dy)?,
        })
    }
    /// bit ? p : identity (bit must already be boolean-constrained).
    fn choose_point(&mut self, p: &Point, bit: &Cell) -> Result<Point, Error> {
        let x = self.times(&p.x, bit)?;
        let minus_one = self.constant(-Fr::ONE)?;
        let y_minus_one = self.plus(&p.y, &minus_one)?;
        let one = self.constant(Fr::ONE)?;
        let y = self.madd(&one, &y_minus_one, bit)?;
        Ok(Point { x, y })
    }
    /// sum_i bits[i] * 2^i * p (LSB first); bits must be boolean.
    pub fn scalar_mul(&mut self, p: &Point, bits: &[Cell]) -> Result<Point, Error> {
        let mut acc = Point {
            x: self.constant(Fr::ZERO)?,
            y: self.constant(Fr::ONE)?,
        };
        let mut base = p.clone();
        for bit in bits {
            let selected = self.choose_point(&base, bit)?;
            acc = self.point_add(&acc, &selected)?;
            base = self.point_add(&base, &base)?;
        }
        Ok(acc)
    }
    /// Decompose x into `bits` boolean cells (LSB first) and prove x < 2^bits.
    /// Requires bits <= 252 so the packing cannot wrap modulo p.
    pub fn range_bits(&mut self, x: &Cell, bits: usize) -> Result<Vec<Cell>, Error> {
        assert!(bits <= 252);
        let words = (bits + 31) / 32;
        let mut ws = Vec::new();
        for i in (0..words).rev() {
            let v = x
                .value()
                .map(|v| u32::from_le_bytes(v.to_repr()[4 * i..4 * i + 4].try_into().unwrap()));
            ws.push(self.word(v)?);
        }
        let packed = self.field_from_words(&ws)?;
        self.equal(x, &packed)?;
        let all: Vec<_> = ws.iter().rev().flat_map(|w| w.bits.clone()).collect();
        for bit in &all[bits..] {
            self.region.constrain_constant(bit.cell(), Fr::ZERO)?;
        }
        Ok(all[..bits].to_vec())
    }
    /// PoseidonChain(domain, v) = H(...H(H(domain, v0), v1)..., v_{n-1}).
    pub fn hash_chain(&mut self, domain: u64, values: &[Cell]) -> Result<Cell, Error> {
        let mut acc = self.constant(Fr::from(domain))?;
        for v in values {
            acc = self.hash(&[acc, v.clone()])?;
        }
        Ok(acc)
    }
}
