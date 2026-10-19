//! MockProver checks of individual gadgets against malicious assignments.
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::bn256::Fr;
use oob_admission::gadgets::{Builder, Config, Point};
use oob_admission::native;

#[derive(Clone, Default)]
struct MuxCircuit {
    dir: u32,
}
impl Circuit<Fr> for MuxCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        Config::configure(meta)
    }
    fn synthesize(&self, cfg: Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "mux",
            |mut region| {
                let mut b = Builder { region: &mut region, cfg: &cfg, row: 0 };
                let x = b.witness(Value::known(Fr::from(5)))?;
                let y = b.witness(Value::known(Fr::from(9)))?;
                let (l, r) = b.mux_raw(&x, &y, Value::known(self.dir))?;
                let _ = b.hash(&[l, r])?;
                Ok(())
            },
        )
    }
}

#[test]
fn merkle_direction_must_be_boolean() {
    for (dir, ok) in [(0u32, true), (1, true), (2, false), (4, false), (5, false), (0x8000_0000, false)] {
        let p = MockProver::run(10, &MuxCircuit { dir }, vec![vec![]]).unwrap();
        assert_eq!(p.verify().is_ok(), ok, "direction {dir}");
    }
}

#[derive(Clone, Default)]
struct KeyCircuit {
    pk: (Fr, Fr),
}
impl Circuit<Fr> for KeyCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        Config::configure(meta)
    }
    fn synthesize(&self, cfg: Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        use ff::PrimeField;
        layouter.assign_region(
            || "key",
            |mut region| {
                let mut b = Builder { region: &mut region, cfg: &cfg, row: 0 };
                // same sequence as relation.rs item (4)
                let pk = Point { x: b.witness(Value::known(self.pk.0))?, y: b.witness(Value::known(self.pk.1))? };
                b.curve(&pk)?;
                let one = b.constant(Fr::ONE)?;
                let _ = b.divide(&one, &pk.x)?;
                let ob = native::subgroup_order().to_repr();
                let bits = (0..252)
                    .map(|i| b.constant(Fr::from(((ob[i / 8] >> (i % 8)) & 1) as u64)))
                    .collect::<Result<Vec<_>, _>>()?;
                let check = b.scalar_mul(&pk, &bits)?;
                b.constrain_constant(&check.x, Fr::ZERO)?;
                b.constrain_constant(&check.y, Fr::ONE)?;
                Ok(())
            },
        )
    }
}

#[test]
fn recipient_key_checks() {
    let (_, pk) = native::keypair();
    let cases = [
        (pk, true),
        ((Fr::ZERO, Fr::ONE), false),         // identity (x = 0)
        ((Fr::ZERO, -Fr::ONE), false),        // order 2
        ((-pk.0, -pk.1), false),              // pk + (0,-1): on curve, order 2l
        ((pk.0, pk.1 + Fr::ONE), false),      // off curve
    ];
    for (i, (p, ok)) in cases.iter().enumerate() {
        let res = std::panic::catch_unwind(|| {
            MockProver::run(17, &KeyCircuit { pk: *p }, vec![vec![]]).map(|m| m.verify().is_ok()).unwrap_or(false)
        });
        assert_eq!(res.unwrap_or(false), *ok, "case {i}");
    }
}
