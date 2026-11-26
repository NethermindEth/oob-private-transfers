//! SHA-256 Merkle authentication path in circuit (depth 32 in the benchmark).

use binius_circuits::sha256::{State, sha256_compress, sha256_fixed};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::hashes::{Bytes32, assert_bytes32_eq, inout_bytes32, populate_words, witness_bytes32};
use crate::reference::merkle::{MerklePath, NodeHash};

/// Witness wires of a path: siblings from the leaf up, and the leaf index whose
/// bit `i` says whether the node at level `i` is the right child.
pub struct MerklePathWires {
    pub siblings: Vec<Bytes32>,
    pub index: Wire,
}

impl MerklePathWires {
    pub fn witness(b: &CircuitBuilder, depth: usize) -> Self {
        MerklePathWires {
            siblings: (0..depth).map(|_| witness_bytes32(b)).collect(),
            index: b.add_witness(),
        }
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, path: &MerklePath) {
        assert_eq!(path.depth(), self.siblings.len());
        for (wires, sib) in self.siblings.iter().zip(&path.siblings) {
            populate_words(w, wires, sib);
        }
        w[self.index] = Word(path.index);
    }
}

/// Two-to-one node hash of `left || right` (64 bytes).
fn node(b: &CircuitBuilder, node_hash: NodeHash, left: &Bytes32, right: &Bytes32) -> Bytes32 {
    let m: [Wire; 16] = std::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] });
    match node_hash {
        NodeHash::Full => sha256_fixed(b, &m, 64),
        NodeHash::CompressOnly => sha256_compress(b, State::iv(b), m).0,
    }
}

/// Hash `leaf` up the path and return the root.
pub fn merkle_root(
    b: &CircuitBuilder,
    leaf: &Bytes32,
    path: &MerklePathWires,
    node_hash: NodeHash,
) -> Bytes32 {
    let mut cur = *leaf;
    for (level, sib) in path.siblings.iter().enumerate() {
        // `select` tests the MSB: move bit `level` of the index there.
        let is_right = b.shl(path.index, 63 - level as u32);
        let left: Bytes32 = std::array::from_fn(|i| b.select(is_right, sib[i], cur[i]));
        let right: Bytes32 = std::array::from_fn(|i| b.select(is_right, cur[i], sib[i]));
        cur = node(
            &b.subcircuit(format!("merkle[{level}]")),
            node_hash,
            &left,
            &right,
        );
    }
    cur
}

/// Standalone statement `root = MerkleRoot(leaf, path)` with a public root: the
/// phase-2 benchmark circuit.
pub struct MerkleCircuit {
    pub leaf: Bytes32,
    pub path: MerklePathWires,
    pub root: Bytes32,
}

impl MerkleCircuit {
    pub fn build(b: &CircuitBuilder, depth: usize, node_hash: NodeHash) -> Self {
        let leaf = witness_bytes32(b);
        let path = MerklePathWires::witness(b, depth);
        let root = inout_bytes32(b);
        let computed = merkle_root(b, &leaf, &path, node_hash);
        assert_bytes32_eq(b, "root", &computed, &root);
        MerkleCircuit { leaf, path, root }
    }

    pub fn populate(
        &self,
        w: &mut WitnessFiller<'_>,
        leaf: &[u8; 32],
        path: &MerklePath,
        root: &[u8; 32],
    ) {
        populate_words(w, &self.leaf, leaf);
        self.path.populate(w, path);
        populate_words(w, &self.root, root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::tests::check;
    use crate::reference::merkle::{DEPTH, SparseMerkleTree};
    use binius_frontend::{Circuit, CircuitStat};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn circuit(node_hash: NodeHash) -> (Circuit, MerkleCircuit) {
        let b = CircuitBuilder::new();
        let mc = MerkleCircuit::build(&b, DEPTH, node_hash);
        (b.build(), mc)
    }

    #[test]
    fn depth_32_path_matches_native_and_rejects_tampering() {
        let mut rng = StdRng::seed_from_u64(21);
        for nh in [NodeHash::Full, NodeHash::CompressOnly] {
            let (circuit, mc) = circuit(nh);
            let mut tree = SparseMerkleTree::new(DEPTH, nh);
            let mut leaf_v = [0u8; 32];
            rng.fill_bytes(&mut leaf_v);
            let index = rng.next_u64() & ((1 << DEPTH) - 1);
            tree.insert(rng.next_u64() & ((1 << DEPTH) - 1), [7u8; 32]);
            tree.insert(index, leaf_v);
            let path_v = tree.path(index);
            let root_v = tree.root();

            let fill = |w: &mut WitnessFiller<'_>, path_v: &MerklePath, root_v: &[u8; 32]| {
                mc.populate(w, &leaf_v, path_v, root_v);
            };
            check(&circuit, |w| fill(w, &path_v, &root_v)).unwrap();

            let mut bad = path_v.clone();
            bad.siblings[13][0] ^= 1;
            assert!(check(&circuit, |w| fill(w, &bad, &root_v)).is_err());
            let mut bad = path_v.clone();
            bad.index ^= 1 << 5;
            assert!(check(&circuit, |w| fill(w, &bad, &root_v)).is_err());
            let mut bad_root = root_v;
            bad_root[0] ^= 1;
            assert!(check(&circuit, |w| fill(w, &path_v, &bad_root)).is_err());
        }
    }

    #[test]
    fn cost_snapshot() {
        // Pinned after measurement; a change here means the gadget's cost changed.
        // Full: 2 compressions per level; compress-only: 1. The 16 selects per level are
        // BMUL constraints, not AND.
        for (nh, and) in [
            (NodeHash::Full, 2 * DEPTH * 364),
            (NodeHash::CompressOnly, DEPTH * 364),
        ] {
            let stat = CircuitStat::collect(&circuit(nh).0);
            assert_eq!(
                (stat.n_and_constraints, stat.n_bmul_constraints),
                (and, 16 * DEPTH),
                "{}",
                nh.name()
            );
        }
    }
}
