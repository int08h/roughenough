// Copyright 2017-2022 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//!
//! Merkle Tree implementation that uses the Roughtime leaf and node tweak values.
//!

use crate::version::Version;
use crate::version::Version::{Google, RfcDraft13};
use ring::digest;

use super::{TREE_LEAF_TWEAK, TREE_NODE_TWEAK};

type Data = Vec<u8>;
type Hash = Data;

///
/// Merkle Tree implementation that uses the Roughtime leaf and node tweak values.
///
pub struct MerkleTree {
    levels: Vec<Vec<Data>>,
    algorithm: &'static digest::Algorithm,
    version: Version,
}

impl MerkleTree {
    ///
    /// Create a new empty Merkle Tree based on SHA-512. The size of the final output
    /// is controlled by the `version` argument:
    ///
    /// * IETF => Output is the most-significant 32-bytes (256-bits), `SHA-512[0:32]`
    /// * Google => Output is 64-bytes (512 bits)
    ///
    pub fn new(version: Version) -> MerkleTree {
        match version {
            Google => MerkleTree::new_sha512_google(),
            RfcDraft13 => MerkleTree::new_sha512_ietf(),
        }
    }

    ///
    /// Create a new empty Merkle Tree based on SHA-512.
    /// Output is the most-significant 32-bytes (256-bits), `SHA-512[0:32]`
    ///
    fn new_sha512_ietf() -> MerkleTree {
        MerkleTree {
            levels: vec![vec![]],
            algorithm: &digest::SHA512,
            version: RfcDraft13,
        }
    }

    ///
    /// Create a new empty Merkle Tree based on SHA-512
    /// Output is 64-bytes (512 bits)
    ///
    fn new_sha512_google() -> MerkleTree {
        MerkleTree {
            levels: vec![vec![]],
            algorithm: &digest::SHA512,
            version: Google,
        }
    }

    pub fn push_leaf(&mut self, data: &[u8]) {
        let hash = self.hash_leaf(data);
        self.levels[0].push(hash);
    }

    pub fn get_paths(&self, mut index: usize) -> Vec<u8> {
        let mut paths = Vec::with_capacity(self.levels.len() * self.algorithm.output_len());
        let mut level = 0;

        while !self.levels[level].is_empty() {
            let sibling = if index % 2 == 0 { index + 1 } else { index - 1 };

            paths.extend(self.levels[level][sibling].clone());
            level += 1;
            index /= 2;
        }

        // for PATH to have a depth of >32 levels, we'd have to be processing
        // a batch of >2^32 responses
        assert!(level <= 32, "impossible: PATH depth {} exceeds 32", level);

        paths
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

            if self.levels.len() < level + 1 {
                self.levels.push(vec![]);
            }

            if node_count % 2 != 0 {
                self.levels[level - 1].push(vec![0; self.algorithm.output_len()]);
                node_count += 1;
            }

            node_count /= 2;

            for i in 0..node_count {
                let hash = self.hash_nodes(
                    &self.levels[level - 1][i * 2],
                    &self.levels[level - 1][(i * 2) + 1],
                );
                self.levels[level].push(hash);
            }
        }

        assert_eq!(self.levels[level].len(), 1);
        let result = self.levels[level].pop().unwrap();

        self.finalize_output(result)
    }

    pub fn reset(&mut self) {
        for level in &mut self.levels {
            level.clear();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    fn hash_leaf(&self, leaf: &[u8]) -> Data {
        self.hash(&[TREE_LEAF_TWEAK, leaf])
    }

    fn hash_nodes(&self, first: &[u8], second: &[u8]) -> Data {
        self.hash(&[TREE_NODE_TWEAK, first, second])
    }

    fn hash(&self, to_hash: &[&[u8]]) -> Data {
        let mut ctx = digest::Context::new(self.algorithm);
        for data in to_hash {
            ctx.update(data);
        }
        Data::from(ctx.finish().as_ref())
    }

    pub fn root_from_paths(&self, mut index: usize, data: &[u8], paths: &[u8]) -> Hash {
        let mut hash = self.hash_leaf(data);

        assert_eq!(paths.len() % self.algorithm.output_len(), 0);

        for path in paths.chunks(self.algorithm.output_len()) {
            let mut ctx = digest::Context::new(self.algorithm);
            ctx.update(TREE_NODE_TWEAK);

            if index & 1 == 0 {
                // Left
                ctx.update(&hash);
                ctx.update(path);
            } else {
                // Right
                ctx.update(path);
                ctx.update(&hash);
            }

            hash = Hash::from(ctx.finish().as_ref());
            index >>= 1;
        }

        self.finalize_output(hash)
    }

    #[inline]
    fn finalize_output(&self, data: Hash) -> Hash {
        match self.version {
            RfcDraft13 => data[0..32].into(),
            Google => data,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::merkle::*;

    // Helper function to run tests with both implementations (Google and IETF)
    fn for_both_versions<F>(mut test_fn: F)
    where
        F: FnMut(MerkleTree),
    {
        test_fn(MerkleTree::new_sha512_ietf());
        test_fn(MerkleTree::new_sha512_google());
    }

    fn test_paths_with_num(num: usize) {
        for_both_versions(|mut tree| {
            for i in 0..num {
                tree.push_leaf(&[i as u8]);
            }

            let root = tree.compute_root();

            for i in 0..num {
                let paths: Vec<u8> = tree.get_paths(i);
                let computed_root = tree.root_from_paths(i, &[i as u8], &paths);

                assert_eq!(
                    root, computed_root,
                    "inequality: {:?} {:?} {:?}",
                    root, computed_root, i
                );
            }
        });
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
        test_paths_with_num(20);
    }
}
