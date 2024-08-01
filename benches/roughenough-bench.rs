#[macro_use]
extern crate criterion;
extern crate roughenough;

use criterion::Throughput::Elements;
use criterion::{black_box, BenchmarkId, Criterion, SamplingMode};
use std::time::SystemTime;

use roughenough::key::OnlineKey;
use roughenough::merkle::MerkleTree;
use roughenough::version::Version;
use roughenough::{RtMessage, Tag};

fn create_signed_srep_tags(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let mut key = OnlineKey::new();
    let now = SystemTime::now();
    let data = [8u8; 32];

    group.throughput(Elements(1));
    group.bench_function("create signed SREP tag", |b| {
        b.iter(|| black_box(key.make_srep(Version::Rfc, now, &data)))
    });
    group.finish();
}

fn create_empty_message(c: &mut Criterion) {
    c.bench_function("create empty message", |b| {
        b.iter(|| RtMessage::with_capacity(0))
    });
}

fn create_two_field_message(c: &mut Criterion) {
    c.bench_function("create two field message", |b| {
        b.iter(|| {
            let mut msg = RtMessage::with_capacity(2);
            msg.add_field(Tag::NONC, "1234".as_bytes()).unwrap();
            msg.add_field(Tag::PAD, "abcd".as_bytes()).unwrap();
        })
    });
}

fn create_four_field_message(c: &mut Criterion) {
    c.bench_function("create four field message", |b| {
        b.iter(|| {
            let mut msg = RtMessage::with_capacity(4);
            msg.add_field(Tag::SIG, "0987".as_bytes()).unwrap();
            msg.add_field(Tag::NONC, "wxyz".as_bytes()).unwrap();
            msg.add_field(Tag::DELE, "1234".as_bytes()).unwrap();
            msg.add_field(Tag::PATH, "abcd".as_bytes()).unwrap();
        })
    });
}
static SIZES: &[u32] = &[1, 3, 20, 200, 2000];
static DATA: &[u8] = &[1u8; 64];

fn create_new_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("create new Merkle tree");
    group.sampling_mode(SamplingMode::Flat);

    for size in SIZES.iter() {
        group.throughput(Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let mut tree = MerkleTree::new_sha512_classic();
                for _ in 0..size {
                    tree.push_leaf(DATA);
                }
                black_box(tree.compute_root())
            })
        });
    }
    group.finish();
}

fn reuse_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("reuse Merkle tree");
    group.sampling_mode(SamplingMode::Flat);

    let mut tree = MerkleTree::new_sha512_classic();

    for size in SIZES.iter() {
        group.throughput(Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                tree.reset();
                for _ in 0..size {
                    tree.push_leaf(DATA);
                }
                black_box(tree.compute_root())
            })
        });
    }
    group.finish();
}

criterion_group!(message_singing, create_signed_srep_tags,);

criterion_group!(
    message_creation,
    create_empty_message,
    create_two_field_message,
    create_four_field_message,
);

criterion_group!(merkle_tree, create_new_merkle_tree, reuse_merkle_tree);

criterion_main!(message_singing, message_creation, merkle_tree);
