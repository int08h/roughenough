use roughenough_merkle::{MerklePath, MerkleTree, root_from_paths};

fn two_leaf_tree() -> (MerkleTree, [u8; 32], [u8; 32], [u8; 32]) {
    let leaf0 = [0x00; 32];
    let leaf1 = [0x11; 32];
    let mut tree = MerkleTree::new();
    tree.push_leaf(&leaf0);
    tree.push_leaf(&leaf1);
    let root = tree.compute_root();
    (tree, leaf0, leaf1, root)
}

#[test]
fn leftover_index_bits_rejected() {
    // RFC 5.3.1: "If they are not, or if any of the remaining bits of INDX is
    // non-zero, the algorithm fails." An index with set bits beyond the PATH
    // length must not reconstruct the root.
    let (tree, leaf0, _, _) = two_leaf_tree();

    // Path for leaf 0 has depth 1; index 2 (0b10) has a bit beyond the path
    let path = tree.get_paths(0);
    assert_eq!(path.depth(), 1);

    let computed_root = root_from_paths(2, &leaf0, &path);
    assert_eq!(
        computed_root, None,
        "an INDX with leftover nonzero bits must fail the root check"
    );

    // Same with an empty path (single-leaf tree): any nonzero index must fail
    let mut single = MerkleTree::new();
    single.push_leaf(&leaf0);
    let _single_root = single.compute_root();
    let empty_path = single.get_paths(0);
    assert_eq!(empty_path.depth(), 0);

    let computed_root = root_from_paths(1, &leaf0, &empty_path);
    assert_eq!(
        computed_root, None,
        "a nonzero INDX with an empty PATH must fail the root check"
    );
}

#[test]
fn invalid_merkle_proof_wrong_index() {
    let (tree, leaf0, _, root) = two_leaf_tree();
    let path = tree.get_paths(0);

    let computed_root = root_from_paths(1, &leaf0, &path);
    assert_ne!(computed_root, Some(root));
}

#[test]
fn invalid_merkle_proof_wrong_leaf_data() {
    let (tree, _, _, root) = two_leaf_tree();
    let path = tree.get_paths(0);

    let computed_root = root_from_paths(0, &[0x22; 32], &path);
    assert_ne!(computed_root, Some(root));
}

#[test]
fn invalid_merkle_proof_corrupted_path() {
    let (tree, leaf0, _, root) = two_leaf_tree();
    let path = tree.get_paths(0);

    let mut corrupted_path = MerklePath::default();
    for elem in path.elements() {
        let mut corrupted_elem = [0u8; 32];
        corrupted_elem.copy_from_slice(elem);
        corrupted_elem[1] ^= 0xFF;
        corrupted_path.push_element(&corrupted_elem);
    }

    let computed_root = root_from_paths(0, &leaf0, &corrupted_path);
    assert_ne!(computed_root, Some(root));
}

#[test]
fn path_too_long_for_index() {
    let (tree, leaf0, _, root) = two_leaf_tree();
    let path = tree.get_paths(0);
    assert_eq!(path.depth(), 1);

    let mut long_path = MerklePath::default();
    for _ in 0..5 {
        long_path.push_element(&[0u8; 32]);
    }

    // Index 0 has no leftover bits, so this computes a root, just not the right one
    let computed_root = root_from_paths(0, &leaf0, &long_path);
    assert_ne!(computed_root, Some(root));
}

#[test]
fn adversarial_path_attempts() {
    let (tree, _, target, root) = two_leaf_tree();
    let valid_path = tree.get_paths(1);

    // The valid path with a different leaf at the same index
    let computed_root = root_from_paths(1, &[0xff; 32], &valid_path);
    assert_ne!(computed_root, Some(root));

    // The valid path and leaf at the wrong index
    let computed_root = root_from_paths(0, &target, &valid_path);
    assert_ne!(computed_root, Some(root));
}
