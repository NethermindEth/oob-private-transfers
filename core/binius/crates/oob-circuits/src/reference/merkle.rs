//! Sparse SHA-256 Merkle tree of note commitments and authentication paths.
//!
//! Leaves are 32-byte commitments at level 0; an empty leaf is `0^32`; the node
//! at level `l+1` is `node_hash(left, right)` of its children. The root is at
//! level `depth`. Only non-empty nodes are stored.

use std::collections::HashMap;

use super::hashes::{Hash32, merkle_node, merkle_node_compress_only};

/// Depth of the shielded pool's commitment tree (the paper's prototype uses 32).
pub const DEPTH: usize = 32;

/// Which two-to-one hash the tree uses (see the crate README, `--node-hash`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeHash {
    /// `SHA256(left || right)`, 2 compressions per level.
    Full,
    /// `compress(IV, left || right)`, 1 compression per level.
    CompressOnly,
}

impl NodeHash {
    pub fn hash(self, left: &Hash32, right: &Hash32) -> Hash32 {
        match self {
            NodeHash::Full => merkle_node(left, right),
            NodeHash::CompressOnly => merkle_node_compress_only(left, right),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            NodeHash::Full => "full",
            NodeHash::CompressOnly => "compress-only",
        }
    }
}

/// Authentication path of a leaf: siblings from the leaf's level up to the
/// level below the root, plus the leaf index whose bits give the directions
/// (bit `i` set means the current node is the right child at level `i`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<Hash32>,
    pub index: u64,
}

impl MerklePath {
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// `true` if, at level `i`, the node on the path is the right child.
    pub fn is_right(&self, level: usize) -> bool {
        (self.index >> level) & 1 == 1
    }

    /// Hash `leaf` up the path.
    pub fn root(&self, leaf: &Hash32, node_hash: NodeHash) -> Hash32 {
        let mut cur = *leaf;
        for (level, sib) in self.siblings.iter().enumerate() {
            cur = if self.is_right(level) {
                node_hash.hash(sib, &cur)
            } else {
                node_hash.hash(&cur, sib)
            };
        }
        cur
    }

    /// `Member(rt, cm, path)`
    pub fn member(&self, rt: &Hash32, leaf: &Hash32, node_hash: NodeHash) -> bool {
        self.root(leaf, node_hash) == *rt
    }
}

#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    depth: usize,
    node_hash: NodeHash,
    /// (level, index) -> node value, for non-empty nodes only.
    nodes: HashMap<(usize, u64), Hash32>,
    /// `zeros[l]` is the value of an empty subtree of height `l`.
    zeros: Vec<Hash32>,
}

impl SparseMerkleTree {
    pub fn new(depth: usize, node_hash: NodeHash) -> Self {
        assert!(depth <= 64);
        let mut zeros = vec![[0u8; 32]];
        for l in 0..depth {
            let z = zeros[l];
            zeros.push(node_hash.hash(&z, &z));
        }
        SparseMerkleTree {
            depth,
            node_hash,
            nodes: HashMap::new(),
            zeros,
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
    pub fn node_hash(&self) -> NodeHash {
        self.node_hash
    }

    fn node(&self, level: usize, index: u64) -> Hash32 {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// Set the leaf at `index` and recompute its ancestors.
    pub fn insert(&mut self, index: u64, leaf: Hash32) {
        assert!(
            self.depth == 64 || index < (1u64 << self.depth),
            "index out of range"
        );
        self.nodes.insert((0, index), leaf);
        let mut idx = index;
        for level in 0..self.depth {
            let (l, r) = if idx & 1 == 0 {
                (self.node(level, idx), self.node(level, idx ^ 1))
            } else {
                (self.node(level, idx ^ 1), self.node(level, idx))
            };
            idx >>= 1;
            self.nodes
                .insert((level + 1, idx), self.node_hash.hash(&l, &r));
        }
    }

    pub fn root(&self) -> Hash32 {
        self.node(self.depth, 0)
    }

    pub fn leaf(&self, index: u64) -> Hash32 {
        self.node(0, index)
    }

    pub fn path(&self, index: u64) -> MerklePath {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            siblings.push(self.node(level, idx ^ 1));
            idx >>= 1;
        }
        MerklePath { siblings, index }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn rand_hash(rng: &mut StdRng) -> Hash32 {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        h
    }

    #[test]
    fn empty_tree_root_is_zero_hash_chain() {
        let t = SparseMerkleTree::new(4, NodeHash::Full);
        let mut z = [0u8; 32];
        for _ in 0..4 {
            z = merkle_node(&z, &z);
        }
        assert_eq!(t.root(), z);
    }

    #[test]
    fn small_dense_tree_matches_naive_computation() {
        let mut rng = StdRng::seed_from_u64(5);
        let depth = 3;
        let leaves: Vec<Hash32> = (0..8).map(|_| rand_hash(&mut rng)).collect();
        for nh in [NodeHash::Full, NodeHash::CompressOnly] {
            let mut t = SparseMerkleTree::new(depth, nh);
            for (i, l) in leaves.iter().enumerate() {
                t.insert(i as u64, *l);
            }
            // naive
            let mut level = leaves.clone();
            while level.len() > 1 {
                level = level.chunks(2).map(|p| nh.hash(&p[0], &p[1])).collect();
            }
            assert_eq!(t.root(), level[0]);
            for i in 0..8u64 {
                let p = t.path(i);
                assert_eq!(p.depth(), depth);
                assert!(p.member(&t.root(), &leaves[i as usize], nh));
                assert!(!p.member(&t.root(), &leaves[(i as usize + 1) % 8], nh));
            }
        }
    }

    #[test]
    fn depth_32_paths_verify_and_detect_tampering() {
        let mut rng = StdRng::seed_from_u64(6);
        let mut t = SparseMerkleTree::new(DEPTH, NodeHash::Full);
        let idxs: Vec<u64> = (0..5)
            .map(|_| rng.next_u64() & ((1 << DEPTH) - 1))
            .collect();
        let leaves: Vec<Hash32> = idxs.iter().map(|_| rand_hash(&mut rng)).collect();
        for (i, l) in idxs.iter().zip(&leaves) {
            t.insert(*i, *l);
        }
        let rt = t.root();
        for (i, l) in idxs.iter().zip(&leaves) {
            let p = t.path(*i);
            assert_eq!(p.depth(), DEPTH);
            assert!(p.member(&rt, l, NodeHash::Full));
            assert!(!p.member(&rt, l, NodeHash::CompressOnly));
            let mut bad = p.clone();
            bad.siblings[7][0] ^= 1;
            assert!(!bad.member(&rt, l, NodeHash::Full));
            let mut bad = p.clone();
            bad.index ^= 1 << 3;
            assert!(!bad.member(&rt, l, NodeHash::Full));
        }
        // inserting another leaf changes the root and keeps old paths invalid
        t.insert(12345, rand_hash(&mut rng));
        assert_ne!(t.root(), rt);
        assert!(!t.path(idxs[0]).member(&rt, &leaves[0], NodeHash::Full));
        assert!(
            t.path(idxs[0])
                .member(&t.root(), &leaves[0], NodeHash::Full)
        );
    }
}
