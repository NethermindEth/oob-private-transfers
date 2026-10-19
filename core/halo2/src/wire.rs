//! Wire encoding: field elements are lowercase hex of the 32-byte big-endian canonical
//! encoding, no `0x`.
use ff::PrimeField;
use halo2curves::bn256::Fr;

pub fn fe(s: &str) -> Result<Fr, String> {
    if s.len() != 64 {
        return Err(format!("field element must be 64 hex chars, got {}", s.len()));
    }
    let mut b: [u8; 32] = hex::decode(s)
        .map_err(|_| "invalid hex".to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())?;
    b.reverse();
    Option::<Fr>::from(Fr::from_repr(b)).ok_or_else(|| "non-canonical field element".to_string())
}
pub fn hex_fe(f: &Fr) -> String {
    let mut b = f.to_repr();
    b.reverse();
    hex::encode(b)
}
pub fn fes<const N: usize>(v: &serde_json::Value, what: &str) -> Result<[Fr; N], String> {
    let a = v.as_array().ok_or_else(|| format!("{what}: expected array"))?;
    if a.len() != N {
        return Err(format!("{what}: expected {N} elements, got {}", a.len()));
    }
    let mut out = [Fr::from(0); N];
    for (i, x) in a.iter().enumerate() {
        out[i] = fe(x.as_str().ok_or_else(|| format!("{what}[{i}]: expected string"))?)
            .map_err(|e| format!("{what}[{i}]: {e}"))?;
    }
    Ok(out)
}
pub fn fe_vec(v: &serde_json::Value, what: &str) -> Result<Vec<Fr>, String> {
    let a = v.as_array().ok_or_else(|| format!("{what}: expected array"))?;
    a.iter()
        .enumerate()
        .map(|(i, x)| {
            fe(x.as_str().ok_or_else(|| format!("{what}[{i}]: expected string"))?)
                .map_err(|e| format!("{what}[{i}]: {e}"))
        })
        .collect()
}
pub fn hex_all(v: &[Fr]) -> Vec<String> {
    v.iter().map(hex_fe).collect()
}
