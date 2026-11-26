//! A complete admission instance: public statement `x = (rt, d, nu_adm)` and
//! private witness `w = (N, h_s, rho, C, path)` plus every intermediate value the
//! circuit needs, with a native checker of the five conditions of `R_adm`.

use super::enc::{Encryption, Point, aes128_ctr, encrypt, lift_x, mul, point_x, scalar};
use super::hashes::{Hash32, h_ct, h_kdf, h_lock, h_tag};
use super::merkle::{DEPTH, MerklePath, NodeHash, SparseMerkleTree};
use super::note::{Note, Recipient};
use anyhow::{Result, bail};
use rand::Rng;

/// `x = (rt, d, nu_adm)`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub rt: Hash32,
    pub d: Hash32,
    pub tag: Hash32,
}

/// `w = (N, h_s, rho, C, path)` with fresh randomness `rho = esk` and the derived values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub note: Note,
    pub h_s: Hash32,
    pub enc: Encryption,
    pub path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct AdmissionInstance {
    pub node_hash: NodeHash,
    pub public: PublicInputs,
    pub witness: Witness,
}

/// The conditions of Definition 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    /// (1) `Member(rt, cm, path)`
    Membership,
    /// (2) `N.lock = H_lock(h_s, N.pk_R)`
    Lock,
    /// (3) `pk_R` on the curve, `epk = x([esk]G)`, `ss = x([esk] pk_R)`,
    /// `C = epk || AES-CTR(H_kdf(ss, epk), N)`
    Encryption,
    /// (4) `d = H_ct(C)`
    Digest,
    /// (5) `nu_adm = H_tag(cm, N.salt)`
    Tag,
}

impl AdmissionInstance {
    /// Random instance: a fresh recipient, a depth-32 tree holding `n_other`
    /// random leaves plus the note at a random index.
    pub fn generate(node_hash: NodeHash, rng: &mut impl Rng) -> Self {
        let recipient = Recipient::random(rng);
        Self::generate_for(&recipient, node_hash, 8, rng)
    }

    pub fn generate_for(
        recipient: &Recipient,
        node_hash: NodeHash,
        n_other: usize,
        rng: &mut impl Rng,
    ) -> Self {
        let note = Note::random(&recipient.address(), rng);
        let enc = encrypt(&note, rng).expect("a random recipient key is on the curve");
        let cm = note.commitment();

        let mask = (1u64 << DEPTH) - 1;
        let mut tree = SparseMerkleTree::new(DEPTH, node_hash);
        for _ in 0..n_other {
            let mut leaf = [0u8; 32];
            rng.fill_bytes(&mut leaf);
            tree.insert(rng.next_u64() & mask, leaf);
        }
        let index = rng.next_u64() & mask;
        tree.insert(index, cm);
        let path = tree.path(index);

        let public = PublicInputs {
            rt: tree.root(),
            d: h_ct(&enc.ciphertext()),
            tag: h_tag(&cm, &note.salt),
        };
        let witness = Witness {
            note,
            h_s: recipient.h_s,
            enc,
            path,
        };
        AdmissionInstance {
            node_hash,
            public,
            witness,
        }
    }

    pub fn ciphertext(&self) -> Vec<u8> {
        self.witness.enc.ciphertext()
    }

    /// The stored record `pl = nu_adm || C`.
    pub fn record(&self) -> Vec<u8> {
        let mut pl = self.public.tag.to_vec();
        pl.extend_from_slice(&self.ciphertext());
        pl
    }

    /// Check the five conditions.
    pub fn check(&self) -> Result<()> {
        let w = &self.witness;
        let x = &self.public;
        let cm = w.note.commitment();

        if !w.path.member(&x.rt, &cm, self.node_hash) {
            bail!("{:?} failed", Condition::Membership);
        }
        if w.note.lock != h_lock(&w.h_s, &w.note.pk_r) {
            bail!("{:?} failed", Condition::Lock);
        }
        let (Some(esk), Some(pk)) = (scalar(&w.enc.esk), lift_x(&w.note.pk_r)) else {
            bail!("{:?} failed: esk or pk_R invalid", Condition::Encryption);
        };
        if point_x(&mul(&esk, &Point::GENERATOR)) != w.enc.epk {
            bail!("{:?} failed: epk", Condition::Encryption);
        }
        if point_x(&mul(&esk, &pk)) != w.enc.ss {
            bail!("{:?} failed: ss", Condition::Encryption);
        }
        let key = h_kdf(&w.enc.ss, &w.enc.epk);
        if key != w.enc.key || aes128_ctr(&key, &w.note.to_bytes()) != w.enc.ct {
            bail!("{:?} failed", Condition::Encryption);
        }
        if x.d != h_ct(&w.enc.ciphertext()) {
            bail!("{:?} failed", Condition::Digest);
        }
        if x.tag != h_tag(&cm, &w.note.salt) {
            bail!("{:?} failed", Condition::Tag);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::enc::decrypt;
    use crate::reference::note::RECORD_LEN;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn generated_instances_satisfy_every_condition() {
        let mut rng = StdRng::seed_from_u64(7);
        for nh in [NodeHash::Full, NodeHash::CompressOnly] {
            let r = Recipient::random(&mut rng);
            let inst = AdmissionInstance::generate_for(&r, nh, 3, &mut rng);
            inst.check().unwrap();
            assert_eq!(inst.record().len(), RECORD_LEN);
            assert_eq!(inst.witness.path.depth(), DEPTH);
            // the recipient recovers the note and recomputes the statement
            let n = decrypt(&r.sk_r, &inst.ciphertext()).unwrap();
            assert_eq!(n, inst.witness.note);
            assert_eq!(h_tag(&n.commitment(), &n.salt), inst.public.tag);
            assert_eq!(n.lock, h_lock(&r.h_s, &r.address().pk_r));
        }
    }

    #[test]
    fn each_condition_is_checked() {
        let mut rng = StdRng::seed_from_u64(8);
        let base = AdmissionInstance::generate(NodeHash::Full, &mut rng);

        let mut i = base.clone();
        i.witness.path.siblings[0][0] ^= 1;
        assert!(i.check().unwrap_err().to_string().contains("Membership"));

        let mut i = base.clone();
        i.witness.h_s[0] ^= 1;
        assert!(i.check().unwrap_err().to_string().contains("Lock"));

        let mut i = base.clone();
        i.witness.enc.ss[0] ^= 1;
        assert!(i.check().unwrap_err().to_string().contains("Encryption"));

        let mut i = base.clone();
        i.witness.enc.ct[5] ^= 1; // ciphertext changes, d is stale
        assert!(i.check().unwrap_err().to_string().contains("Encryption"));

        let mut i = base.clone();
        i.public.d[0] ^= 1;
        assert!(i.check().unwrap_err().to_string().contains("Digest"));

        let mut i = base.clone();
        i.public.tag[0] ^= 1;
        assert!(i.check().unwrap_err().to_string().contains("Tag"));

        let mut i = base.clone();
        i.witness.enc.esk[31] ^= 1;
        assert!(i.check().unwrap_err().to_string().contains("Encryption"));

        // an undecryptable payload: wrong ss, with key, ct and d made consistent
        let mut i = base.clone();
        i.witness.enc.ss[0] ^= 1;
        i.witness.enc.key = h_kdf(&i.witness.enc.ss, &i.witness.enc.epk);
        i.witness.enc.ct = aes128_ctr(&i.witness.enc.key, &i.witness.note.to_bytes());
        i.public.d = h_ct(&i.witness.enc.ciphertext());
        assert!(i.check().unwrap_err().to_string().contains("Encryption"));
    }
}
