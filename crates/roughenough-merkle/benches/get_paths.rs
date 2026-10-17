use divan::Bencher;
use roughenough_merkle::{MerklePath, MerkleTree};

fn main() {
    divan::main();
}

#[divan::bench(args = [1, 8, 16, 32, 64], min_time = 0.250)]
fn get_paths(bencher: Bencher, batch_size: usize) {
    let mut tree = MerkleTree::new();
    for i in 0..batch_size {
        tree.push_leaf(&i.to_le_bytes());
    }
    tree.compute_root();

    bencher.with_inputs(|| 0..batch_size).bench_refs(|range| {
        for index in range.clone() {
            let _path = tree.get_paths(index);
            divan::black_box(_path);
        }
    });
}

#[divan::bench(args = [1, 3, 8, 31, 33, 63, 64], min_time = 0.250)]
fn push_and_compute_root(bencher: Bencher, n: usize) {
    let leaves: Vec<[u8; 8]> = (0..n).map(|i| i.to_le_bytes()).collect();
    let mut tree = MerkleTree::with_capacity(n);
    bencher.bench_local(|| {
        tree.clear();
        for leaf in &leaves {
            tree.push_leaf(leaf);
        }
        divan::black_box(tree.compute_root())
    });
}

#[divan::bench(args = [1, 8, 16, 32, 64], min_time = 0.250)]
fn get_paths_to(bencher: Bencher, batch_size: usize) {
    let mut tree = MerkleTree::new();
    for i in 0..batch_size {
        tree.push_leaf(&i.to_le_bytes());
    }
    tree.compute_root();

    bencher
        .with_inputs(|| (0..batch_size, MerklePath::default()))
        .bench_refs(|(range, path)| {
            for index in range.clone() {
                path.clear();
                tree.get_paths_to(index, path);
                divan::black_box(&path);
            }
        });
}
