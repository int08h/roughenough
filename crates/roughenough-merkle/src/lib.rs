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

/// RFC 5.3: A Merkle tree is a binary tree where the value of each non-
/// leaf node is a hash value derived from its two children. The root of
/// the tree is thus dependent on all leaf nodes.
///
/// In Roughtime, each leaf node in the Merkle tree represents one
/// request. Leaf nodes are indexed left to right, beginning with zero.
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
    algorithm: &'static digest::Algorithm,
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
            algorithm: &digest::SHA512,
        }
    }

    pub fn push_leaf(&mut self, data: &[u8]) {
        let hash = self.hash_leaf(data);
        self.levels[0].push(hash);
    }

    /// Pre-allocate capacity for the given number of leaves
    pub fn reserve(&mut self, num_leaves: usize) {
        if num_leaves == 0 {
            return;
        }

        // Calculate required levels: log2(num_leaves) + 1
        let max_levels = if num_leaves.is_power_of_two() {
            num_leaves.trailing_zeros() as usize + 1
        } else {
            (num_leaves - 1).ilog2() as usize + 2
        };

        // Pre-allocate levels
        self.levels
            .reserve(max_levels.saturating_sub(self.levels.len()));

        // Pre-allocate capacity for each level
        let mut capacity = num_leaves;
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

        let mut level = 0;

        while !self.levels[level].is_empty() {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };

            // Check if sibling exists - if not, we've reached the root level
            if sibling >= self.levels[level].len() {
                break;
            }

            // Write directly into the path
            path.push_element(&self.levels[level][sibling]);

            level += 1;
            index /= 2;
        }

        // RFC 5.2.4: The PATH MUST NOT contain more than 32 hash values.
        assert!(level <= 32, "impossible: PATH depth {level} exceeds 32");
    }

    pub fn compute_root(&mut self) -> Hash {
        assert!(
            !self.levels[0].is_empty(),
            "Must have at least one leaf to hash!"
        );

        let mut level = 0;
        let mut node_count = self.levels[0].len();

        while node_count > 1 {
            level += 1;

            // Ensure we have enough levels
            if self.levels.len() < level + 1 {
                self.levels.push(Vec::new());
            }

            // Clear previous computation results at this level
            self.levels[level].clear();

            if !node_count.is_multiple_of(2) {
                // Add a padding node
                self.levels[level - 1].push([0; OUTPUT_LEN]);
                node_count += 1;
            }

            node_count /= 2;

            // Pre-allocate capacity if not already reserved
            self.levels[level].reserve(node_count);

            for i in 0..node_count {
                let hash = self.hash_nodes(
                    &self.levels[level - 1][i * 2],
                    &self.levels[level - 1][(i * 2) + 1],
                );
                self.levels[level].push(hash);
            }
        }

        assert_eq!(self.levels[level].len(), 1);
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
        self.hash(&[LEAF_TWEAK, leaf])
    }

    fn hash_nodes(&self, first: &[u8], second: &[u8]) -> Hash {
        self.hash(&[NODE_TWEAK, first, second])
    }

    fn hash(&self, to_hash: &[&[u8]]) -> Hash {
        let mut ctx = digest::Context::new(self.algorithm);
        for &data in to_hash {
            ctx.update(data);
        }
        let mut result = [0u8; OUTPUT_LEN];
        result.copy_from_slice(&ctx.finish().as_ref()[..OUTPUT_LEN]);
        result
    }

    pub fn root_from_paths(&self, mut index: usize, init_data: &[u8], paths: &MerklePath) -> Hash {
        let mut hash = self.hash_leaf(init_data);

        for path in paths.elements() {
            let mut ctx = digest::Context::new(self.algorithm);
            ctx.update(NODE_TWEAK);

            if index & 1 == 0 {
                // Left
                ctx.update(&hash);
                ctx.update(path);
            } else {
                // Right
                ctx.update(path);
                ctx.update(&hash);
            }

            let mut result = [0u8; OUTPUT_LEN];
            result.copy_from_slice(&ctx.finish().as_ref()[..OUTPUT_LEN]);
            hash = result;
            index >>= 1;
        }

        hash
    }
}

#[cfg(test)]
mod test {
    use crate::MerkleTree;

    fn test_paths_with_num(num: usize) {
        let mut tree = MerkleTree::new();

        for i in 0..num {
            tree.push_leaf(&[i as u8]);
        }

        let root = tree.compute_root();

        for i in 0..num {
            let paths = tree.get_paths(i);
            let computed_root = tree.root_from_paths(i, &[i as u8], &paths);

            assert_eq!(
                root, computed_root,
                "inequality: {root:?} {computed_root:?} {i:?}"
            );
        }
    }

    #[test]
    fn power_of_two() {
        test_paths_with_num(2);
        test_paths_with_num(4);
        test_paths_with_num(8);
        test_paths_with_num(16);
    }

    #[test]
    fn not_power_of_two() {
        test_paths_with_num(1);
        test_paths_with_num(19);
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
            let verified_root = tree.root_from_paths(idx, leaf, &paths);

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
