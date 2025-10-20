#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use merkle::MerkleTree;
    use protocol::tags::{MerklePath, MerkleRoot, Nonce};

    // Helper to create a nonce from hex string
    fn nonce_from_hex(hex: &str) -> Nonce {
        let bytes = HEXLOWER.decode(hex.as_bytes()).unwrap();
        Nonce::from(bytes.as_slice())
    }

    #[test]
    fn valid_merkle_proof_single_leaf() {
        // Single leaf tree - path should be empty
        let mut tree = MerkleTree::new();
        let nonce =
            nonce_from_hex("4c16c619d7716fae49552b3393fd07cff4c6f16a1ab5a2f7ce5240f94a6d1f29");

        tree.push_leaf(nonce.as_ref());
        let root = tree.compute_root();

        // For single leaf, path should be empty
        let path = tree.get_paths(0);
        assert_eq!(path.depth(), 0);

        // Verify we can reconstruct the root
        let computed_root = tree.root_from_paths(0, nonce.as_ref(), &path);
        assert_eq!(computed_root, root);
    }

    #[test]
    fn valid_merkle_proof_two_leaves() {
        let mut tree = MerkleTree::new();
        let nonce1 =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce2 =
            nonce_from_hex("1111111111111111111111111111111111111111111111111111111111111111");

        tree.push_leaf(nonce1.as_ref());
        tree.push_leaf(nonce2.as_ref());
        let root = tree.compute_root();

        // Get paths for first leaf
        let path0 = tree.get_paths(0);
        assert_eq!(path0.depth(), 1);

        // Verify reconstruction
        let computed_root0 = tree.root_from_paths(0, nonce1.as_ref(), &path0);
        assert_eq!(computed_root0, root);

        // Get paths for second leaf
        let path1 = tree.get_paths(1);
        assert_eq!(path1.depth(), 1);

        // Verify reconstruction
        let computed_root1 = tree.root_from_paths(1, nonce2.as_ref(), &path1);
        assert_eq!(computed_root1, root);
    }

    #[test]
    fn invalid_merkle_proof_wrong_index() {
        let mut tree = MerkleTree::new();
        let nonce1 =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce2 =
            nonce_from_hex("1111111111111111111111111111111111111111111111111111111111111111");

        tree.push_leaf(nonce1.as_ref());
        tree.push_leaf(nonce2.as_ref());
        let root = tree.compute_root();

        // Get path for index 0
        let path = tree.get_paths(0);

        // Try to verify with wrong index
        let computed_root = tree.root_from_paths(1, nonce1.as_ref(), &path);

        // Should NOT match the actual root
        assert_ne!(computed_root, root);
    }

    #[test]
    fn invalid_merkle_proof_wrong_leaf_data() {
        let mut tree = MerkleTree::new();
        let nonce1 =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce2 =
            nonce_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
        let wrong_nonce =
            nonce_from_hex("2222222222222222222222222222222222222222222222222222222222222222");

        tree.push_leaf(nonce1.as_ref());
        tree.push_leaf(nonce2.as_ref());
        let root = tree.compute_root();

        // Get valid path for index 0
        let path = tree.get_paths(0);

        // Try to verify with wrong leaf data
        let computed_root = tree.root_from_paths(0, wrong_nonce.as_ref(), &path);

        // Should NOT match the actual root
        assert_ne!(computed_root, root);
    }

    #[test]
    fn invalid_merkle_proof_corrupted_path() {
        let mut tree = MerkleTree::new();
        let nonce1 =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce2 =
            nonce_from_hex("1111111111111111111111111111111111111111111111111111111111111111");

        tree.push_leaf(nonce1.as_ref());
        tree.push_leaf(nonce2.as_ref());
        let root = tree.compute_root();

        // Get valid path
        let path = tree.get_paths(0);

        // Corrupt the path by modifying a byte
        let mut corrupted_path = MerklePath::default();
        for elem in path.elements() {
            let mut corrupted_elem = [0u8; 32];
            corrupted_elem.copy_from_slice(elem);
            corrupted_elem[1] ^= 0xFF; // Flip bits in second byte
            corrupted_path.push_element(&corrupted_elem);
        }

        // Try to verify with corrupted path
        let computed_root = tree.root_from_paths(0, nonce1.as_ref(), &corrupted_path);

        // Should NOT match the actual root
        assert_ne!(computed_root, root);
    }

    #[test]
    fn merkle_proof_larger_tree() {
        let mut tree = MerkleTree::new();

        // Create 8 leaves
        let nonces: Vec<Nonce> = (0..8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i as u8;
                Nonce::from(bytes)
            })
            .collect();

        for nonce in &nonces {
            tree.push_leaf(nonce.as_ref());
        }

        let root = tree.compute_root();

        // Verify proof for each leaf
        for (index, nonce) in nonces.iter().enumerate() {
            let path = tree.get_paths(index);
            let computed_root = tree.root_from_paths(index, nonce.as_ref(), &path);
            assert_eq!(computed_root, root, "Failed for index {index}");

            // Path length should be log2(8) = 3
            assert_eq!(path.depth(), 3, "Wrong path length for index {index}");
        }
    }

    #[test]
    fn merkle_proof_non_power_of_two() {
        let mut tree = MerkleTree::new();

        // Create 5 leaves (non-power-of-2)
        let nonces: Vec<Nonce> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i as u8;
                Nonce::from(bytes)
            })
            .collect();

        for nonce in &nonces {
            tree.push_leaf(nonce.as_ref());
        }

        let root = tree.compute_root();

        // Verify proof for each leaf
        for (index, nonce) in nonces.iter().enumerate() {
            let path = tree.get_paths(index);
            let computed_root = tree.root_from_paths(index, nonce.as_ref(), &path);
            assert_eq!(computed_root, root, "Failed for index {index}");
        }
    }

    #[test]
    fn path_too_long_for_index() {
        let mut tree = MerkleTree::new();

        // Create a small tree
        tree.push_leaf(&[0u8; 32]);
        tree.push_leaf(&[1u8; 32]);
        let _root = tree.compute_root();

        // Get valid path for index 0 (should have length 1)
        let path = tree.get_paths(0);
        assert_eq!(path.depth(), 1);

        // Manually create a path that's too long
        let mut long_path = MerklePath::default();
        for _ in 0..5 {
            long_path.push_element(&[0u8; 32]);
        }

        // This should still compute something, but won't match the actual root
        let computed_root = tree.root_from_paths(0, &[0u8; 32], &long_path);
        let actual_root = tree.compute_root();
        assert_ne!(computed_root, actual_root);
    }

    #[test]
    fn adversarial_path_attempts() {
        let mut tree = MerkleTree::new();

        // Create a specific tree structure
        let target_nonce =
            nonce_from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let other_nonce =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000000");

        tree.push_leaf(other_nonce.as_ref());
        tree.push_leaf(target_nonce.as_ref());
        let root = tree.compute_root();

        // Get the valid path for the target
        let valid_path = tree.get_paths(1);

        // Try to use the valid path with a different nonce at the same index
        let fake_nonce =
            nonce_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let computed_root = tree.root_from_paths(1, fake_nonce.as_ref(), &valid_path);

        // Should NOT produce the same root
        assert_ne!(computed_root, root);

        // Try to use the valid path with wrong index
        let computed_root2 = tree.root_from_paths(0, target_nonce.as_ref(), &valid_path);
        assert_ne!(computed_root2, root);
    }

    #[test]
    fn collision_resistance() {
        // Test that slightly different inputs produce very different roots
        let mut tree1 = MerkleTree::new();
        let mut tree2 = MerkleTree::new();

        let nonce1 =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce2 =
            nonce_from_hex("0000000000000000000000000000000000000000000000000000000000000001"); // Only last bit different

        tree1.push_leaf(nonce1.as_ref());
        tree2.push_leaf(nonce2.as_ref());

        let root1 = tree1.compute_root();
        let root2 = tree2.compute_root();

        // Roots should be completely different
        assert_ne!(root1, root2);

        // Count differing bits
        let differing_bits: u32 = root1
            .iter()
            .zip(root2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();

        // Hello future test failure investigator.
        //
        // If you see a **very** occasional test failure for no clear reason, it's ok. We expect
        // this to happen now and then. This is a probabilistic test that will randomly fail
        // once in every ~4.7 billion runs.
        //
        // The threshold 77 is chosen because popcount(SAMPLE) follows Binomial(256, 0.5).
        // We require P(popcount <= N) <= 2^-32, meaning the probability of 77 or fewer bits set
        // is at most 1 in 2^32.
        //
        // Using the normal approximation: Z = (N - 128) / 8, and for tail probability 2^-32 ~= 2.3e-10,
        // the corresponding Z-score is about -6.4. Solving for N gives N ~= 77.
        // This ensures the test fails with probability no greater than 2^-32.
        const THRESHOLD: u32 = 77;
        assert!(
            differing_bits > THRESHOLD,
            "{differing_bits} bits differing, expected {THRESHOLD}; see comment in this test for explanation"
        );
    }

    #[test]
    fn merkle_root_type_conversion() {
        // Test that MerkleRoot type properly handles the computed root
        let mut tree = MerkleTree::new();
        let nonce =
            nonce_from_hex("4c16c619d7716fae49552b3393fd07cff4c6f16a1ab5a2f7ce5240f94a6d1f29");

        tree.push_leaf(nonce.as_ref());
        let computed_root = tree.compute_root();

        // Convert to MerkleRoot type
        let merkle_root = MerkleRoot::from(computed_root);

        // Should be able to compare directly
        assert_eq!(merkle_root.as_ref(), &computed_root);
    }
}
