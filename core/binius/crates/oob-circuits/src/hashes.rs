//! Domain-separated SHA-256 in circuit, on top of `binius_circuits::sha256`.
//!
//! Byte strings are carried as big-endian 32-bit words, one per 64-bit wire with
//! the high half zero, which is the input layout of `sha256_fixed`. Every
//! protocol value here is a multiple of 4 bytes, so no partial words occur.
//!
//! Soundness note on witness words: `sha256_fixed` documents that the low half of
//! its result depends only on the low halves of its inputs, so garbage a
//! malicious prover puts in the high half of a witness word cannot change a
//! digest. Any other consumer of witness words (the AES layer) must likewise
//! read low halves only.

use binius_circuits::sha256::sha256_fixed;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::reference::hashes::{DOM_CM, DOM_CT, DOM_KDF, DOM_LOCK, DOM_TAG, DOMAIN_LEN};

/// A 32-byte value as 8 big-endian 32-bit words.
pub type Bytes32 = [Wire; 8];

/// Witness wires for `n_bytes` bytes (`n_bytes % 4 == 0`).
pub fn witness_words(b: &CircuitBuilder, n_bytes: usize) -> Vec<Wire> {
    assert!(n_bytes.is_multiple_of(4));
    (0..n_bytes / 4).map(|_| b.add_witness()).collect()
}

pub fn witness_bytes32(b: &CircuitBuilder) -> Bytes32 {
    std::array::from_fn(|_| b.add_witness())
}

pub fn inout_bytes32(b: &CircuitBuilder) -> Bytes32 {
    std::array::from_fn(|_| b.add_inout())
}

fn constant_words(b: &CircuitBuilder, bytes: &[u8]) -> Vec<Wire> {
    bytes
        .chunks(4)
        .map(|c| b.add_constant(Word(u32::from_be_bytes(c.try_into().unwrap()) as u64)))
        .collect()
}

/// Fill `wires` with `bytes` (4 bytes per wire, big-endian).
pub fn populate_words(w: &mut WitnessFiller<'_>, wires: &[Wire], bytes: &[u8]) {
    assert_eq!(wires.len() * 4, bytes.len(), "wire/byte length mismatch");
    for (wire, c) in wires.iter().zip(bytes.chunks(4)) {
        w[*wire] = Word(u32::from_be_bytes(c.try_into().unwrap()) as u64);
    }
}

/// `H_a(parts) = SHA256(a || parts[0] || parts[1] || ...)`
pub fn sha256_domain(b: &CircuitBuilder, domain: &[u8; DOMAIN_LEN], parts: &[&[Wire]]) -> Bytes32 {
    let mut msg = constant_words(b, domain);
    for p in parts {
        msg.extend_from_slice(p);
    }
    let len = msg.len() * 4;
    sha256_fixed(b, &msg, len)
}

/// `cm = H_cm(N)` over the note's words.
pub fn h_cm(b: &CircuitBuilder, note: &[Wire]) -> Bytes32 {
    sha256_domain(b, DOM_CM, &[note])
}

/// `H_lock(h_s, pk_R)`
pub fn h_lock(b: &CircuitBuilder, h_s: &Bytes32, pk_r: &Bytes32) -> Bytes32 {
    sha256_domain(b, DOM_LOCK, &[h_s, pk_r])
}

/// `nu_adm = H_tag(cm, salt)`
pub fn h_tag(b: &CircuitBuilder, cm: &Bytes32, salt: &Bytes32) -> Bytes32 {
    sha256_domain(b, DOM_TAG, &[cm, salt])
}

/// `d = H_ct(C)` over the ciphertext words.
pub fn h_ct(b: &CircuitBuilder, c: &[Wire]) -> Bytes32 {
    sha256_domain(b, DOM_CT, &[c])
}

/// `k = H_kdf(ss, epk)[0..16]`: the AES-128 key as 4 words.
pub fn h_kdf(b: &CircuitBuilder, ss: &Bytes32, epk: &Bytes32) -> [Wire; 4] {
    let d = sha256_domain(b, DOM_KDF, &[ss, epk]);
    [d[0], d[1], d[2], d[3]]
}

pub fn assert_bytes32_eq(b: &CircuitBuilder, name: &str, x: &Bytes32, y: &Bytes32) {
    for i in 0..8 {
        b.assert_eq(format!("{name}[{i}]"), x[i], y[i]);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::reference::hashes as native;
    use crate::reference::note::{CIPHERTEXT_LEN, NOTE_LEN};
    use binius_frontend::{Circuit, CircuitStat};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// Fill, propagate and check constraints; `Err` if an assertion fails.
    pub(crate) fn check(
        circuit: &Circuit,
        fill: impl FnOnce(&mut WitnessFiller<'_>),
    ) -> anyhow::Result<()> {
        let mut w = circuit.new_witness_filler();
        fill(&mut w);
        circuit.populate_wire_witness(&mut w)?;
        circuit.constraint_system().verify(&w.into_value_vec())?;
        Ok(())
    }

    pub(crate) fn n_and(circuit: &Circuit) -> usize {
        CircuitStat::collect(circuit).n_and_constraints
    }

    fn rand_bytes(rng: &mut StdRng, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        rng.fill_bytes(&mut v);
        v
    }

    #[test]
    fn domain_hashes_match_native() {
        let mut rng = StdRng::seed_from_u64(20);
        {
            let b = CircuitBuilder::new();
            let note = witness_words(&b, NOTE_LEN);
            let c = witness_words(&b, CIPHERTEXT_LEN);
            let (x, y) = (witness_bytes32(&b), witness_bytes32(&b));
            let outs = [
                h_cm(&b, &note),
                h_lock(&b, &x, &y),
                h_tag(&b, &x, &y),
                h_ct(&b, &c),
            ];
            let kdf = h_kdf(&b, &x, &y);
            let expected: Vec<Bytes32> = (0..5).map(|_| inout_bytes32(&b)).collect();
            for (o, e) in outs.iter().zip(&expected) {
                assert_bytes32_eq(&b, "h", o, e);
            }
            for i in 0..4 {
                b.assert_eq("kdf", kdf[i], expected[4][i]);
            }
            let circuit = b.build();

            let note_v = rand_bytes(&mut rng, NOTE_LEN);
            let c_v = rand_bytes(&mut rng, CIPHERTEXT_LEN);
            let x_v: [u8; 32] = rand_bytes(&mut rng, 32).try_into().unwrap();
            let y_v: [u8; 32] = rand_bytes(&mut rng, 32).try_into().unwrap();
            let mut kdf_full = native::sha256(&native::h_kdf_preimage(&x_v, &y_v));
            assert_eq!(kdf_full[..16], native::h_kdf(&x_v, &y_v));
            kdf_full[16..].fill(0); // only the first 4 words are asserted; the rest are left unset
            let vals = [
                native::h_cm(&note_v),
                native::h_lock(&x_v, &y_v),
                native::h_tag(&x_v, &y_v),
                native::h_ct(&c_v),
                kdf_full,
            ];
            check(&circuit, |w| {
                populate_words(w, &note, &note_v);
                populate_words(w, &c, &c_v);
                populate_words(w, &x, &x_v);
                populate_words(w, &y, &y_v);
                for (e, v) in expected.iter().zip(&vals) {
                    populate_words(w, e, v);
                }
            })
            .unwrap();
            // wrong digest is rejected
            assert!(
                check(&circuit, |w| {
                    populate_words(w, &note, &note_v);
                    populate_words(w, &c, &c_v);
                    populate_words(w, &x, &x_v);
                    populate_words(w, &y, &y_v);
                    let mut bad = vals;
                    bad[0][31] ^= 1;
                    for (e, v) in expected.iter().zip(&bad) {
                        populate_words(w, e, v);
                    }
                })
                .is_err()
            );
        }
    }

    #[test]
    fn and_cost_is_364_per_compression() {
        // H_lock: 8 + 64 = 72 bytes -> 2 blocks; H_cm(paper): 8 + 672 = 680 bytes -> 11 blocks.
        for (bytes, blocks) in [(72usize, 2usize), (680, 11)] {
            let b = CircuitBuilder::new();
            let m = witness_words(&b, bytes - DOMAIN_LEN);
            let d = sha256_domain(&b, DOM_CM, &[&m]);
            let e = inout_bytes32(&b);
            assert_bytes32_eq(&b, "d", &d, &e);
            assert_eq!(n_and(&b.build()), 364 * blocks, "{bytes} bytes");
        }
    }
}
