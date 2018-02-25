#[macro_use]
extern crate criterion;
extern crate roughenough;
extern crate ring;
extern crate byteorder;
extern crate time;

use ring::digest;
use ring::rand::SecureRandom;
use byteorder::{LittleEndian, WriteBytesExt};
use criterion::{Criterion, black_box};

use roughenough::{RtMessage, Tag};
use roughenough::{SIGNED_RESPONSE_CONTEXT, TREE_LEAF_TWEAK};
use roughenough::sign::Signer;

fn single_field(data: &[u8]) -> RtMessage {
  let mut msg = RtMessage::new(1);
  msg.add_field(Tag::NONC, &data[0..63]).unwrap();
  msg
}

fn two_fields(data: &[u8]) -> RtMessage {
  let mut msg = RtMessage::new(2);
  msg.add_field(Tag::NONC, &data[0..63]).unwrap();
  msg.add_field(Tag::PAD, &data[64..127]).unwrap();
  msg
}

// Full-sized server response
fn five_fields(data: &[u8]) -> RtMessage {
  let mut response = RtMessage::new(5);
  response.add_field(Tag::SIG, &data[0..63]).unwrap();
  response.add_field(Tag::PATH, &data[64..127]).unwrap();
  response.add_field(Tag::SREP, &data[128..191]).unwrap();
  response.add_field(Tag::CERT, &data[192..255]).unwrap();
  response.add_field(Tag::INDX, &data[256..319]).unwrap();

  response
}

/// Random data for composing a response
fn make_data(len: usize) -> Vec<u8> {
  let rng = ring::rand::SystemRandom::new();
  let mut tmp = vec![1u8; len];
  rng.fill(&mut tmp).unwrap();

  tmp
}

fn message_creation(c: &mut Criterion) {
  let data = make_data(320);

  // TODO(stuart) .to_vec()'s below because I'm fighting the borrow-checker.
  // Tried iter_with_setup(), but haven't found the right combo of 'move'
  // and reference lifetime(s) yet.

  let d1 = data.to_vec();
  c.bench_function("single field",
    move |b| b.iter(|| black_box(single_field(&d1))),
  );

  let d2 = data.to_vec();
  c.bench_function("two fields",
    move |b| b.iter(|| black_box(two_fields(&d2))),
  );

  let d3 = data.to_vec();
  c.bench_function("five fields",
    move |b| b.iter(|| black_box(five_fields(&d3))),
  );
}

/// TODO(stuart) straight-up copied form src/bin/server.rs, not ideal at all
fn make_response(ephemeral_key: &mut Signer, cert_bytes: &[u8], nonce: &[u8]) -> RtMessage {
  let path = [0u8; 0];
  let zeros = [0u8; 4];

  let mut radi: Vec<u8> = Vec::with_capacity(4);
  let mut midp: Vec<u8> = Vec::with_capacity(8);

  // one second (in microseconds)
  radi.write_u32::<LittleEndian>(1_000_000).unwrap();

  // current epoch time in microseconds
  let now = {
    let tv = time::get_time();
    let secs = (tv.sec as u64) * 1_000_000;
    let nsecs = (tv.nsec as u64) / 1_000;

    secs + nsecs
  };
  midp.write_u64::<LittleEndian>(now).unwrap();

  // Signed response SREP
  let srep_bytes = {
    // hash request nonce
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(TREE_LEAF_TWEAK);
    ctx.update(nonce);
    let digest = ctx.finish();

    let mut srep_msg = RtMessage::new(3);
    srep_msg.add_field(Tag::RADI, &radi).unwrap();
    srep_msg.add_field(Tag::MIDP, &midp).unwrap();
    srep_msg.add_field(Tag::ROOT, digest.as_ref()).unwrap();

    srep_msg.encode().unwrap()
  };

  // signature on SREP
  let srep_signature = {
    ephemeral_key.update(SIGNED_RESPONSE_CONTEXT.as_bytes());
    ephemeral_key.update(&srep_bytes);
    ephemeral_key.sign()
  };

  let mut response = RtMessage::new(5);
  response.add_field(Tag::SIG, &srep_signature).unwrap();
  response.add_field(Tag::PATH, &path).unwrap();
  response.add_field(Tag::SREP, &srep_bytes).unwrap();
  response.add_field(Tag::CERT, cert_bytes).unwrap();
  response.add_field(Tag::INDX, &zeros).unwrap();

  response
}

fn response_creation(c: &mut Criterion) {
  let nonce = make_data(64);
  let cert = make_data(152);
  let seed = make_data(32);
  let mut signer = Signer::new(&seed);

  c.bench_function("server response",
    move |b| b.iter(|| black_box(make_response(&mut signer, &cert, &nonce))),
  );
}

criterion_group!(benches, message_creation, response_creation);
criterion_main!(benches);

