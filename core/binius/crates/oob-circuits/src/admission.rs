//! The admission relation `R_adm` (paper, Definition 1) in circuit.
//!
//! Public `x = (rt, d, nu_adm)`; witness `N, h_s, rho = esk, y(pk_R), path`. For
//! `cm = H_cm(N)` the circuit enforces
//! (1) `Member(rt, cm, path)`, (2) `N.lock = H_lock(h_s, N.pk_R)`,
//! (3) `pk_R` on the curve, `epk = x([esk]G)` for the free witness scalar `esk`,
//!     `ss = x([esk]pk_R)`, `C = epk || AES-128-CTR(H_kdf(ss, epk), N)`,
//! (4) `d = H_ct(C)`, (5) `nu_adm = H_tag(cm, N.salt)`.
//!
//! `esk` is the paper's encryption randomness `rho`: it is not derived from the
//! note, so encryption is randomized and the relation is Definition 1 as written.

use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::aes::aes128_ctr;
use crate::ecdh::Ecdh;
use crate::hashes::{
    Bytes32, assert_bytes32_eq, h_cm, h_ct, h_kdf, h_lock, h_tag, inout_bytes32,
    populate_words, witness_bytes32, witness_words,
};
use crate::merkle::{MerklePathWires, merkle_root};
use crate::reference::instance::AdmissionInstance;
use crate::reference::merkle::{DEPTH, NodeHash};
use crate::reference::note::{LOCK_LEN, NOTE_LEN, PK_LEN, SALT_LEN, VAL_LEN};

pub struct AdmissionCircuit {
    pub node_hash: NodeHash,
    pub rt: Bytes32,
    pub d: Bytes32,
    pub tag: Bytes32,
    note: Vec<Wire>,
    h_s: Bytes32,
    /// The encryption randomness `rho`, a free witness.
    esk: Bytes32,
    /// Derives `ss` and `epk` from `esk` and the note's `pk_R`.
    ecdh: Ecdh,
    path: MerklePathWires,
}

/// Word range of a note field, from its byte range.
const fn words(start: usize, len: usize) -> std::ops::Range<usize> {
    start / 4..(start + len) / 4
}
const PK_R: std::ops::Range<usize> = words(0, PK_LEN);
const SALT: std::ops::Range<usize> = words(PK_LEN + VAL_LEN, SALT_LEN);
const LOCK: std::ops::Range<usize> = words(PK_LEN + VAL_LEN + SALT_LEN, LOCK_LEN);

impl AdmissionCircuit {
    pub fn build(b: &CircuitBuilder, node_hash: NodeHash) -> Self {
        let (rt, d, tag) = (inout_bytes32(b), inout_bytes32(b), inout_bytes32(b));
        let note = witness_words(b, NOTE_LEN);
        let h_s = witness_bytes32(b);
        let path = MerklePathWires::witness(b, DEPTH);
        let field = |r: std::ops::Range<usize>| -> Bytes32 { note[r].try_into().unwrap() };
        // (3) key agreement: pk_R on the curve, epk and ss from esk
        let esk = witness_bytes32(b);
        let ecdh = Ecdh::build(&b.subcircuit("ecdh"), &esk, &field(PK_R));
        let (ss, epk) = (ecdh.ss, ecdh.epk);

        let cm = h_cm(&b.subcircuit("h_cm"), &note);
        // (1)
        let root = merkle_root(&b.subcircuit("merkle"), &cm, &path, node_hash);
        assert_bytes32_eq(b, "member", &root, &rt);
        // (2)
        let lock = h_lock(&b.subcircuit("h_lock"), &h_s, &field(PK_R));
        assert_bytes32_eq(b, "lock", &lock, &field(LOCK));
        // (3) key derivation and encryption
        let key = h_kdf(&b.subcircuit("h_kdf"), &ss, &epk);
        let ct = aes128_ctr(&&b.subcircuit("aes"), key, &note);
        let c: Vec<Wire> = epk.iter().copied().chain(ct).collect();
        // (4)
        let digest = h_ct(&b.subcircuit("h_ct"), &c);
        assert_bytes32_eq(b, "digest", &digest, &d);
        // (5)
        let computed_tag = h_tag(&b.subcircuit("h_tag"), &cm, &field(SALT));
        assert_bytes32_eq(b, "tag", &computed_tag, &tag);

        AdmissionCircuit {
            node_hash,
            rt,
            d,
            tag,
            note,
            h_s,
            esk,
            ecdh,
            path,
        }
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, inst: &AdmissionInstance) {
        assert_eq!(inst.node_hash, self.node_hash);
        let (x, wit) = (&inst.public, &inst.witness);
        populate_words(w, &self.rt, &x.rt);
        populate_words(w, &self.d, &x.d);
        populate_words(w, &self.tag, &x.tag);
        populate_words(w, &self.note, &wit.note.to_bytes());
        populate_words(w, &self.h_s, &wit.h_s);
        populate_words(w, &self.esk, &wit.enc.esk);
        self.ecdh.populate(w, &wit.note.pk_r);
        self.path.populate(w, &wit.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::tests::check;
    use crate::reference::enc::{aes128_ctr as native_ctr, encrypt};
    use crate::reference::hashes::{h_ct, h_kdf};
    use binius_frontend::CircuitStat;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn accepts_valid_instances_and_rejects_each_broken_condition() {
        let mut rng = StdRng::seed_from_u64(40);
        for nh in [NodeHash::Full, NodeHash::CompressOnly] {
            let b = CircuitBuilder::new();
            let ac = AdmissionCircuit::build(&b, nh);
            let circuit = b.build();
            let base = AdmissionInstance::generate(nh, &mut rng);
            check(&circuit, |w| ac.populate(w, &base)).unwrap();

            let mut i = base.clone();
            i.witness.path.siblings[3][0] ^= 1;
            assert!(
                check(&circuit, |w| ac.populate(w, &i)).is_err(),
                "membership"
            );
            let mut i = base.clone();
            i.witness.h_s[0] ^= 1;
            assert!(check(&circuit, |w| ac.populate(w, &i)).is_err(), "lock");

            // Randomized encryption: a second encryption of the same note is
            // another valid statement (new d, same tag).
            let mut i = base.clone();
            i.witness.enc = encrypt(&i.witness.note, &mut rng).unwrap();
            assert_ne!(i.witness.enc.esk, base.witness.enc.esk);
            i.public.d = h_ct(&i.witness.enc.ciphertext());
            assert_eq!(i.public.tag, base.public.tag);
            check(&circuit, |w| ac.populate(w, &i)).unwrap();
            // esk is bound to epk and ss: another scalar does not fit this C
            let mut i = base.clone();
            i.witness.enc.esk[31] ^= 1;
            assert!(check(&circuit, |w| ac.populate(w, &i)).is_err(), "esk");
            // out-of-range randomness has no witness
            for bad in [[0u8; 32], [0xff; 32]] {
                let mut i = base.clone();
                i.witness.enc.esk = bad;
                assert!(
                    check(&circuit, |w| ac.populate(w, &i)).is_err(),
                    "esk range"
                );
            }

            let mut i = base.clone();
            i.public.d[0] ^= 1;
            assert!(check(&circuit, |w| ac.populate(w, &i)).is_err(), "digest");
            let mut i = base.clone();
            i.public.tag[0] ^= 1;
            assert!(check(&circuit, |w| ac.populate(w, &i)).is_err(), "tag");
            let mut i = base.clone();
            i.witness.note.val ^= 1;
            assert!(check(&circuit, |w| ac.populate(w, &i)).is_err(), "note");

            // An undecryptable payload: the note encrypted under a key that does not
            // come from ECDH with pk_R, with ct and d made consistent. The circuit
            // derives ss itself, so the statement has no witness.
            let mut i = base.clone();
            i.witness.enc.ss[0] ^= 1;
            i.witness.enc.key = h_kdf(&i.witness.enc.ss, &i.witness.enc.epk);
            i.witness.enc.ct = native_ctr(&i.witness.enc.key, &i.witness.note.to_bytes());
            i.public.d = h_ct(&i.witness.enc.ciphertext());
            assert!(
                check(&circuit, |w| ac.populate(w, &i)).is_err(),
                "undecryptable payload"
            );
        }
    }

    #[test]
    fn cost_snapshot() {
        // 364 per SHA-256 compression (11+2+2+12+2 hashes + 64 Merkle = 93; compress-only
        // Merkle saves 32) + AES (7,092) + the ECDH gadget (ECDH_AND). esk is a free
        // witness, so it costs no hash.
        const ECDH_AND: usize = 165_066;
        for (nh, and) in [
            (NodeHash::Full, 93 * 364 + 7092 + ECDH_AND),
            (NodeHash::CompressOnly, 61 * 364 + 7092 + ECDH_AND),
        ] {
            let b = CircuitBuilder::new();
            AdmissionCircuit::build(&b, nh);
            let stat = CircuitStat::collect(&b.build());
            println!(
                "{}: AND={} BMUL={} IMUL={} internal={}",
                nh.name(),
                stat.n_and_constraints,
                stat.n_bmul_constraints,
                stat.n_imul_constraints,
                stat.n_internal
            );
            assert_eq!(stat.n_and_constraints, and, "{}", nh.name());
        }
    }
}
