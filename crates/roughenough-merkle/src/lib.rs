//!
//! Merkle Tree implementation that uses the Roughtime leaf and node tweak values.
//!

// The merkle crate uses only safe Rust.
#![forbid(unsafe_code)]

use aws_lc_rs::digest;
// Re-export the MerklePath from protocol for convenience
pub use roughenough_protocol::tags::MerklePath;

/// RFC 5.3: For leaf nodes, the byte 0x00 is prepended to the full value of the client's
/// request packet, including the "ROUGHTIM" header, before applying the hash function.
const LEAF_TWEAK: &[u8] = &[0x00];

/// RFC 5.3: For all other nodes, the byte 0x01 is concatenated with first the left and
/// then the right child node value before applying the hash function.
const NODE_TWEAK: &[u8] = &[0x01];

/// RFC 5.3: The values of all nodes are calculated from the leaf nodes and up
/// towards the root node using the first 32 bytes of SHA-512.
///
/// Output is the most-significant 32-bytes (256-bits) of SHA-512, e.g. `SHA-512[0:32]`
const OUTPUT_LEN: usize = 32;

type Hash = [u8; OUTPUT_LEN];

const ZERO: Hash = [0; OUTPUT_LEN];

/// RFC 5.3: A Merkle tree is a binary tree where the value of each non-
/// leaf node is a hash value derived from its two children. The root of
/// the tree is thus dependent on all leaf nodes.
///
/// In Roughtime, each leaf node in the Merkle tree represents one
/// request. Leaf nodes are indexed left to right, beginning with zero.
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Create a new empty Merkle Tree. Output is the most-significant 32-bytes (256-bits),
    /// e.g. `SHA-512[0:32]`
    pub fn new() -> MerkleTree {
        MerkleTree {
            levels: vec![vec![]],
        }
    }

    pub fn push_leaf(&mut self, data: &[u8]) {
        let hash = self.hash_leaf(data);
        self.levels[0].push(hash);
    }

    /// Pre-allocate capacity for the given number of leaves, rounding up
    /// to the next power of two.
    pub fn reserve(&mut self, num_leaves: usize) {
        if num_leaves == 0 {
            return;
        }

        let mut capacity = num_leaves.next_power_of_two();
        let max_levels = capacity.trailing_zeros() as usize + 1;

        // Pre-allocate levels
        self.levels
            .reserve(max_levels.saturating_sub(self.levels.len()));

        // Pre-allocate capacity for each level
        for level in 0..max_levels {
            if level >= self.levels.len() {
                self.levels.push(Vec::new());
            }

            let current_len = self.levels[level].len();
            let additional_capacity = capacity.saturating_sub(current_len);
            if additional_capacity > 0 {
                self.levels[level].reserve(additional_capacity);
            }

            capacity = capacity.div_ceil(2); // Next level has half the nodes (rounded up)
        }
    }

    pub fn get_paths(&self, index: usize) -> MerklePath {
        let mut path = MerklePath::default();
        self.get_paths_to(index, &mut path);
        path
    }

    pub fn get_paths_to(&self, mut index: usize, path: &mut MerklePath) {
        debug_assert!(path.is_empty(), "path must be empty");

        for level in &self.levels {
            if level.len() <= 1 {
                break; // root (or an empty level left over from a larger earlier batch)
            }
            let sibling = level.get(index ^ 1).unwrap_or(&ZERO);
            path.push_element(sibling);
            index /= 2;
        }

        // RFC 5.2.4: The PATH MUST NOT contain more than 32 hash values.
        assert!(path.depth() <= 32, "impossible: PATH depth exceeds 32");
    }

    pub fn compute_root(&mut self) -> Hash {
        assert!(
            !self.levels[0].is_empty(),
            "Must have at least one leaf to hash!"
        );

        let mut level = 0;
        while self.levels[level].len() > 1 {
            if self.levels.len() == level + 1 {
                self.levels.push(Vec::new());
            }
            let (lower, upper) = self.levels.split_at_mut(level + 1);
            let (prev, next) = (&lower[level], &mut upper[0]);
            next.clear();
            // RFC 5.3 leaves odd-sized levels unspecified; this implementation
            // pairs the last node with an all-zero hash
            for pair in prev.chunks(2) {
                next.push(hash_parts(&[
                    NODE_TWEAK,
                    &pair[0],
                    pair.get(1).unwrap_or(&ZERO),
                ]));
            }
            level += 1;
        }
        self.levels[level][0]
    }

    pub fn clear(&mut self) {
        for level in &mut self.levels {
            level.clear();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    fn hash_leaf(&self, leaf: &[u8]) -> Hash {
        hash_parts(&[LEAF_TWEAK, leaf])
    }
}

/// Reconstruct the root hash from a leaf's data, its index, and its Merkle path.
///
/// Returns `None` if any bits of `index` remain nonzero after all path elements
/// are consumed. RFC 5.3.1: "if any of the remaining bits of INDX is non-zero,
/// the algorithm fails."
pub fn root_from_paths(mut index: usize, init_data: &[u8], paths: &MerklePath) -> Option<Hash> {
    let mut hash = hash_parts(&[LEAF_TWEAK, init_data]);

    for path in paths.elements() {
        hash = if index & 1 == 0 {
            // Left
            hash_parts(&[NODE_TWEAK, &hash, path])
        } else {
            // Right
            hash_parts(&[NODE_TWEAK, path, &hash])
        };
        index >>= 1;
    }

    if index != 0 {
        return None;
    }

    Some(hash)
}

/// First 32 bytes of SHA-512 over the concatenated parts (RFC 5.3).
fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut ctx = digest::Context::new(&digest::SHA512);
    for part in parts {
        ctx.update(part);
    }
    let mut result = [0u8; OUTPUT_LEN];
    result.copy_from_slice(&ctx.finish().as_ref()[..OUTPUT_LEN]);
    result
}

#[cfg(test)]
mod test {
    use data_encoding::HEXLOWER;

    use crate::{MerklePath, MerkleTree, root_from_paths};

    fn test_paths_with_num(num: usize) {
        let mut tree = MerkleTree::new();

        for i in 0..num {
            tree.push_leaf(&[i as u8]);
        }

        let root = tree.compute_root();

        for i in 0..num {
            let paths = tree.get_paths(i);
            let computed_root = root_from_paths(i, &[i as u8], &paths).unwrap();

            assert_eq!(
                root, computed_root,
                "inequality: {root:?} {computed_root:?} {i:?}"
            );
        }
    }

    #[test]
    fn paths_verify_for_every_size_up_to_64() {
        for num in 1..=64 {
            test_paths_with_num(num);
        }
    }

    fn tree_of_single_bytes(num: usize) -> MerkleTree {
        let mut tree = MerkleTree::new();
        for i in 0..num {
            tree.push_leaf(&[i as u8]);
        }
        tree
    }

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn path_elements(path: &MerklePath) -> Vec<Vec<u8>> {
        path.elements().map(<[u8]>::to_vec).collect()
    }

    /// Expected values computed independently with Python hashlib:
    /// H(x) = sha512(x)[:32], leaf H(0x00 || leaf), node H(0x01 || l || r),
    /// and odd levels pair the last node with 32 zero bytes. Clients verify
    /// PATH against ROOT, so any change in these values breaks interoperability.
    #[test]
    fn known_answer_vectors() {
        let zero = vec![0u8; 32];

        let mut tree = tree_of_single_bytes(1);
        let root = tree.compute_root();
        assert_eq!(
            root.to_vec(),
            hex("5ea71dc6d0b4f57bf39aadd07c208c35f06cd2bac5fde210397f70de11d439c6")
        );
        let paths = tree.get_paths(0);
        assert!(paths.is_empty());

        let mut tree = tree_of_single_bytes(3);
        let root = tree.compute_root();
        assert_eq!(
            root.to_vec(),
            hex("14af9ec3cdfa4460aaca243445c9c71b935cd5c72d87333e9c9ca2e1c18a99bc")
        );
        let paths = tree.get_paths(2);
        assert_eq!(
            path_elements(&paths),
            vec![
                zero.clone(),
                hex("c5f0a11c52e09310307de83fe995d2bde445a6fccc5bc11d323d3f11c8290de3"),
            ]
        );

        let mut tree = tree_of_single_bytes(5);
        let root = tree.compute_root();
        assert_eq!(
            root.to_vec(),
            hex("93cbcafd0d6b14ac00f5e17f10061ae5987e230aa1d82da7a3c84dd1efe7dc7b")
        );
        let paths = tree.get_paths(4);
        assert_eq!(
            path_elements(&paths),
            vec![
                zero.clone(),
                zero,
                hex("eb621c416bdcd5a7304645b2f5b80ac1cc1ccb865e895644feb7ab5b0c162a69"),
            ]
        );
    }

    #[test]
    fn push_leaf_after_compute_root_matches_fresh_tree() {
        for (before, after) in [(3, 4), (5, 6)] {
            let mut tree = tree_of_single_bytes(before);
            tree.compute_root();
            for i in before..after {
                tree.push_leaf(&[i as u8]);
            }

            let expected = tree_of_single_bytes(after).compute_root();
            let root = tree.compute_root();
            assert_eq!(
                root, expected,
                "{before} -> {after} leaves differs from a fresh tree"
            );
        }
    }

    #[test]
    fn compute_root_does_not_change_leaf_count() {
        let mut tree = tree_of_single_bytes(3);
        tree.compute_root();
        assert_eq!(tree.levels[0].len(), 3);
    }

    #[test]
    #[should_panic(expected = "Must have at least one leaf to hash!")]
    fn empty_tree_panics() {
        let mut tree = MerkleTree::new();
        tree.compute_root(); // panics
    }

    #[test]
    fn single_leaf() {
        let mut tree = MerkleTree::new();
        let test_data = vec![1, 2, 3, 4];
        tree.push_leaf(&test_data);
        let root = tree.compute_root();

        // The root should be the hash of the leaf
        let expected = tree.hash_leaf(&test_data);
        assert_eq!(
            root, expected,
            "Root of single-leaf tree should be the leaf hash"
        );
    }

    #[test]
    fn different_leaf_order() {
        let mut tree = MerkleTree::new();
        tree.push_leaf(&[1, 2, 3]);
        tree.push_leaf(&[4, 5, 6]);
        let root1 = tree.compute_root();

        tree.clear();
        tree.push_leaf(&[4, 5, 6]);
        tree.push_leaf(&[1, 2, 3]);

        let root2 = tree.compute_root();

        assert_ne!(
            root1, root2,
            "Trees with different leaf order should have different roots"
        );
    }

    #[test]
    fn clear_tree() {
        let mut tree = MerkleTree::new();
        tree.push_leaf(&[1, 2, 3]);
        tree.push_leaf(&[4, 5, 6]);

        let root = tree.compute_root();
        assert!(!root.is_empty(), "Root of tree has data");

        tree.clear();

        // After reset, the tree should be empty
        assert!(tree.is_empty(), "Root of reset tree should be empty");
    }

    #[test]
    fn path_verification() {
        let mut tree = MerkleTree::new();
        let leaves = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            vec![9, 10, 11, 12],
            vec![13, 14, 15, 16],
        ];

        for leaf in &leaves {
            tree.push_leaf(leaf);
        }

        // Compute the root
        let expected_root = tree.compute_root();

        // For each leaf, get its path and verify it
        for (idx, leaf) in leaves.iter().enumerate() {
            let paths = tree.get_paths(idx);
            let verified_root = root_from_paths(idx, leaf, &paths).unwrap();

            assert_eq!(
                verified_root, expected_root,
                "Root derived from paths for leaf {idx} should match the tree root"
            );
        }
    }

    #[test]
    fn add_leaves_after_computing_root() {
        let mut tree = MerkleTree::new();
        tree.push_leaf(&[1, 2, 3]);
        let root1 = tree.compute_root();

        tree.push_leaf(&[4, 5, 6]);
        let root2 = tree.compute_root();

        assert_ne!(root1, root2, "Root should change after adding new leaves");
    }

    #[test]
    fn reserve_prevents_reallocation_during_first_batch() {
        for n in 1..=64usize {
            let mut tree = MerkleTree::new();
            tree.reserve(n);

            for i in 0..n {
                tree.push_leaf(&[i as u8]);
            }

            let num_levels = tree.levels.len();
            let capacities: Vec<usize> = tree.levels.iter().map(|level| level.capacity()).collect();

            tree.compute_root();

            assert_eq!(tree.levels.len(), num_levels, "level list grew for n={n}");
            for (idx, level) in tree.levels.iter().enumerate() {
                assert_eq!(
                    level.capacity(),
                    capacities[idx],
                    "level {idx} reallocated during compute_root for n={n}"
                );
            }
        }
    }

    #[test]
    fn reserve_capacity() {
        let mut tree = MerkleTree::new();

        // Reserve for 64 leaves
        tree.reserve(64);

        // Check that the first level has capacity for 64 leaves
        assert!(
            tree.levels[0].capacity() >= 64,
            "Level 0 should have capacity for 64 leaves"
        );

        // Add leaves and verify no reallocations occur by checking capacity
        for i in 0..64 {
            let initial_capacity = tree.levels[0].capacity();
            tree.push_leaf(&[i as u8]);
            assert_eq!(
                initial_capacity,
                tree.levels[0].capacity(),
                "Capacity should not change during push"
            );
        }

        let root = tree.compute_root();
        assert!(!root.is_empty(), "Root should be computed successfully");
    }
}
