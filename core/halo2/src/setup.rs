//! Circuit sizing (minimal k), parameter caching, key generation, proving and verification.
use crate::native;
use crate::relation::{AdmissionCircuit, AdmissionWitness, Variant};
use halo2_proofs::{
    circuit::Value,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Any, Assigned, Assignment,
        Circuit, Column, ConstraintSystem, Error, Fixed, FloorPlanner, Instance, ProvingKey,
        Selector, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, Transcript, TranscriptRead},
};
use group::GroupEncoding;
use halo2curves::bn256::{Fr, G1Affine};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Proof reader that accepts only canonical encodings. halo2curves 0.6.1 decodes a G1 point
/// whose (unused) infinity flag bit is set when x != 0 as the ordinary point, and the Blake2b
/// transcript absorbs coordinates rather than bytes, so such a byte-altered proof would verify
/// for the same statement (proof malleability; found by the bit-flip regression test). We
/// re-encode every point and reject any mismatch; scalars are already range-checked by
/// `Fr::from_repr`. Transcript absorption is delegated to `Blake2bRead` unchanged.
pub struct CanonicalRead<'a> {
    bytes: &'a [u8],
    inner: Blake2bRead<&'a [u8], G1Affine, Challenge255<G1Affine>>,
}
impl<'a> CanonicalRead<'a> {
    pub fn init(bytes: &'a [u8]) -> Self {
        CanonicalRead { bytes, inner: Blake2bRead::init(&[][..]) }
    }
    fn take(&mut self, n: usize) -> std::io::Result<&'a [u8]> {
        if self.bytes.len() < n {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short proof"));
        }
        let (h, t) = self.bytes.split_at(n);
        self.bytes = t;
        Ok(h)
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len()
    }
}
impl<'a> Transcript<G1Affine, Challenge255<G1Affine>> for CanonicalRead<'a> {
    fn squeeze_challenge(&mut self) -> Challenge255<G1Affine> {
        self.inner.squeeze_challenge()
    }
    fn common_point(&mut self, p: G1Affine) -> std::io::Result<()> {
        self.inner.common_point(p)
    }
    fn common_scalar(&mut self, s: Fr) -> std::io::Result<()> {
        self.inner.common_scalar(s)
    }
}
impl<'a> TranscriptRead<G1Affine, Challenge255<G1Affine>> for CanonicalRead<'a> {
    fn read_point(&mut self) -> std::io::Result<G1Affine> {
        let raw = self.take(32)?;
        let mut repr = <G1Affine as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(raw);
        let bad = || std::io::Error::new(std::io::ErrorKind::Other, "invalid or non-canonical point");
        let p: G1Affine = Option::from(G1Affine::from_bytes(&repr)).ok_or_else(bad)?;
        if p.to_bytes().as_ref() != raw {
            return Err(bad());
        }
        self.inner.common_point(p)?;
        Ok(p)
    }
    fn read_scalar(&mut self) -> std::io::Result<Fr> {
        use ff::PrimeField;
        let raw = self.take(32)?;
        let mut repr = <Fr as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(raw);
        let s: Fr = Option::from(Fr::from_repr(repr))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "non-canonical scalar"))?;
        self.inner.common_scalar(s)?;
        Ok(s)
    }
}

/// Assignment backend that only records the highest row touched (for sizing).
#[derive(Default)]
struct RowCounter {
    max_row: usize,
}
impl RowCounter {
    fn touch(&mut self, row: usize) {
        self.max_row = self.max_row.max(row);
    }
}
impl Assignment<Fr> for RowCounter {
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
        Ok(())
    }
    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<Fr>, Error> {
        Ok(Value::unknown())
    }
    fn assign_advice<V, VR, A, AR>(&mut self, _: A, _: Column<Advice>, row: usize, _: V) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fr>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.touch(row);
        Ok(())
    }
    fn assign_fixed<V, VR, A, AR>(&mut self, _: A, _: Column<Fixed>, row: usize, _: V) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fr>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.touch(row);
        Ok(())
    }
    fn copy(&mut self, _: Column<Any>, a: usize, _: Column<Any>, b: usize) -> Result<(), Error> {
        self.touch(a);
        self.touch(b);
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

#[derive(Clone, Debug)]
pub struct Shape {
    pub rows: usize,
    pub blinding_rows: usize,
    pub k: u32,
    pub advice_columns: usize,
    pub fixed_columns: usize,
    pub instance_columns: usize,
    pub degree: usize,
}

/// Rows used (all columns, including the constants column) and the minimal k such that
/// rows + blinding_factors + 1 <= 2^k.
pub fn shape(variant: Variant, depth: usize) -> Shape {
    let mut cs = ConstraintSystem::<Fr>::default();
    let config = AdmissionCircuit::configure(&mut cs);
    let circuit = AdmissionCircuit::shape(variant, depth);
    let mut counter = RowCounter::default();
    <AdmissionCircuit as Circuit<Fr>>::FloorPlanner::synthesize(
        &mut counter,
        &circuit,
        config.clone(),
        vec![config.constant],
    )
    .expect("row counting");
    let rows = counter.max_row + 1;
    let blinding_rows = cs.blinding_factors() + 1;
    let mut k = 1u32;
    while (1usize << k) < rows + blinding_rows || (1usize << k) < cs.minimum_rows() {
        k += 1;
    }
    Shape {
        rows,
        blinding_rows,
        k,
        advice_columns: crate::gadgets::ADVICE_COLUMNS,
        fixed_columns: 4 + 1, // round constants + constants column (selectors counted separately)
        instance_columns: 1,
        degree: cs.degree(),
    }
}

#[derive(Clone, Debug, Default)]
pub struct SetupTimings {
    pub params_seconds: f64,
    pub params_source: String,
    pub keygen_vk_seconds: f64,
    pub keygen_pk_seconds: f64,
}

pub struct Keys {
    pub variant: Variant,
    pub depth: usize,
    pub shape: Shape,
    pub params: Params<G1Affine>,
    pub vk: VerifyingKey<G1Affine>,
    pub pk: Option<ProvingKey<G1Affine>>,
    pub vk_sha256: String,
    pub timings: SetupTimings,
    pub params_path: Option<PathBuf>,
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Load `params_k{k}.bin` from `dir` (checked against its stored SHA-256) or generate it with
/// the deterministic `Params::new(k)` and store it.
pub fn load_params(dir: Option<&Path>, k: u32) -> Result<(Params<G1Affine>, f64, String, Option<PathBuf>), String> {
    let t = Instant::now();
    if let Some(dir) = dir {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("params_k{k}.bin"));
        let hpath = dir.join(format!("params_k{k}.sha256"));
        if path.exists() && hpath.exists() {
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            let want = std::fs::read_to_string(&hpath).map_err(|e| e.to_string())?;
            if sha256_hex(&bytes) != want.trim() {
                return Err(format!("cached params {} fail SHA-256 check", path.display()));
            }
            let p = Params::<G1Affine>::read(&mut &bytes[..]).map_err(|e| e.to_string())?;
            if p.k() != k {
                return Err("cached params have wrong k".into());
            }
            return Ok((p, t.elapsed().as_secs_f64(), "cache".into(), Some(path)));
        }
        let p = Params::<G1Affine>::new(k);
        let secs = t.elapsed().as_secs_f64();
        let mut bytes = Vec::new();
        p.write(&mut bytes).map_err(|e| e.to_string())?;
        let tmp = dir.join(format!("params_k{k}.bin.tmp{}", std::process::id()));
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        std::fs::write(&hpath, sha256_hex(&bytes)).map_err(|e| e.to_string())?;
        return Ok((p, secs, "generated".into(), Some(path)));
    }
    let p = Params::<G1Affine>::new(k);
    Ok((p, t.elapsed().as_secs_f64(), "generated".into(), None))
}

impl Keys {
    /// Parameters (cached), vk and (if `prover`) pk. halo2_proofs 0.3.5 has no pk/vk
    /// serialization, so keys are regenerated deterministically at start-up; the vk digest is
    /// recorded in `<dir>/vk_<variant>_d<depth>_k<k>.sha256` and must match on later runs.
    pub fn setup(variant: Variant, depth: usize, dir: Option<&Path>, prover: bool) -> Result<Keys, String> {
        let shape = shape(variant, depth);
        let k = shape.k;
        let (params, params_seconds, params_source, params_path) = load_params(dir, k)?;
        let empty = AdmissionCircuit::shape(variant, depth);
        let t = Instant::now();
        let vk = keygen_vk(&params, &empty).map_err(|e| format!("keygen_vk: {e:?}"))?;
        let keygen_vk_seconds = t.elapsed().as_secs_f64();
        let vk_sha256 = sha256_hex(format!("{:?}", vk.pinned()).as_bytes());
        if let Some(dir) = dir {
            let tagname = variant.relation().replace('/', "_").replace('+', "_");
            let p = dir.join(format!("vk_{}_d{}_k{}.sha256", tagname, depth, k));
            if p.exists() {
                let want = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
                if want.trim() != vk_sha256 {
                    return Err(format!("vk digest mismatch with {}", p.display()));
                }
            } else {
                std::fs::write(&p, &vk_sha256).map_err(|e| e.to_string())?;
            }
        }
        let t = Instant::now();
        let pk = if prover {
            Some(keygen_pk(&params, vk.clone(), &empty).map_err(|e| format!("keygen_pk: {e:?}"))?)
        } else {
            None
        };
        let keygen_pk_seconds = if prover { t.elapsed().as_secs_f64() } else { 0.0 };
        Ok(Keys {
            variant,
            depth,
            shape,
            params,
            vk,
            pk,
            vk_sha256,
            timings: SetupTimings {
                params_seconds,
                params_source,
                keygen_vk_seconds,
                keygen_pk_seconds,
            },
            params_path,
        })
    }

    pub fn circuit(&self, w: AdmissionWitness) -> AdmissionCircuit {
        AdmissionCircuit {
            variant: self.variant,
            depth: self.depth,
            witness: Some(w),
        }
    }

    /// Check the witness natively against the public statement (errors name the failing item).
    pub fn check_witness(&self, public: &[Fr; 3], w: &AdmissionWitness) -> Result<(), String> {
        if w.siblings.len() != self.depth || w.directions.len() != self.depth {
            return Err(format!("Merkle path must have length {}", self.depth));
        }
        if w.message[2] != Fr::from(native::DENOMINATION) {
            return Err("m[2] != denomination".into());
        }
        let cm = native::note_commitment(&w.message);
        if native::merkle_root(cm, &w.siblings, &w.directions) != public[0] {
            return Err("root mismatch (commitment not under root with this path)".into());
        }
        if native::tag(cm, w.message[3]) != public[2] {
            return Err("tag mismatch".into());
        }
        if self.variant == Variant::Full {
            let pk = (w.message[0], w.message[1]);
            if native::owner_field(w.ob, &pk) != w.message[5] {
                return Err("owner field m[5] != Poseidon2(ob, Poseidon2(m[0], m[1])) (A11)".into());
            }
            let c = native::encrypt_with(&pk, &w.message, w.randomness, w.nonce)
                .map_err(|e| format!("encryption witness invalid: {e}"))?;
            if c != w.ciphertext {
                return Err("ciphertext is not Enc_{r*pk_R}(m; nonce)".into());
            }
            if native::digest(&w.ciphertext) != public[1] {
                return Err("digest mismatch".into());
            }
        }
        Ok(())
    }

    /// Create a proof WITHOUT native checks (tests use this to try unsatisfying witnesses).
    pub fn prove_unchecked(&self, public: &[Fr; 3], w: AdmissionWitness) -> Result<Vec<u8>, String> {
        let pk = self.pk.as_ref().ok_or("verifier role does not prove")?;
        let c = self.circuit(w);
        let inst: &[Fr] = &public[..];
        let mut tr = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof(&self.params, pk, &[c], &[&[inst]], OsRng, &mut tr)
            .map_err(|e| format!("create_proof: {e:?}"))?;
        Ok(tr.finalize())
    }

    /// Checked proving: native relation check, proof, then self-verification.
    pub fn prove(&self, public: &[Fr; 3], w: AdmissionWitness) -> Result<Vec<u8>, String> {
        self.check_witness(public, &w)?;
        let proof = self.prove_unchecked(public, w)?;
        if !self.verify(public, &proof) {
            return Err("self-verification failed".into());
        }
        Ok(proof)
    }

    /// Stock halo2_proofs verifier (Blake2bRead), without the canonical-encoding check.
    /// Used only by the regression test that documents the malleability.
    pub fn verify_stock(&self, public: &[Fr; 3], proof: &[u8]) -> bool {
        let inst: &[Fr] = &public[..];
        let mut slice = proof;
        let ok = {
            let mut rd = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&mut slice);
            verify_proof(&self.params, &self.vk, SingleVerifier::new(&self.params), &[&[inst]], &mut rd).is_ok()
        };
        ok && slice.is_empty()
    }

    /// Returns false for any malformed or invalid proof (never panics); trailing bytes and
    /// non-canonical encodings rejected.
    pub fn verify(&self, public: &[Fr; 3], proof: &[u8]) -> bool {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let inst: &[Fr] = &public[..];
            let mut rd = CanonicalRead::init(proof);
            let ok = verify_proof(&self.params, &self.vk, SingleVerifier::new(&self.params), &[&[inst]], &mut rd)
                .is_ok();
            ok && rd.remaining() == 0
        }));
        matches!(r, Ok(true))
    }
}
