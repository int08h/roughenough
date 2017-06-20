//!
//! Roughtime server
//!

extern crate core;
extern crate ring;
extern crate untrusted;
extern crate roughenough;

use core::ptr;

use untrusted::Input;
use roughenough::{RtMessage, Tag, Error};
use roughenough::hex::*;

use ring::{digest, rand};
use ring::rand::SecureRandom;
use ring::signature::Ed25519KeyPair;

/// Zero all bytes in dst
#[inline]
pub fn zero(dst: &mut [u8]) {
    unsafe {
        ptr::write_bytes(dst.as_mut_ptr(), 0u8, dst.len());
    }
}

fn main() {
    // Read long-term key
    let long_term_key = {
        let mut seed = [b'x'; 32];

        let lt_key = Ed25519KeyPair::from_seed_unchecked(Input::from(&seed)).unwrap();
        println!("Long-term public key: {}", lt_key.public_key_bytes().to_hex());

        lt_key
    };

    // Create DELE
    let ephemeral_key = {
        let rng = rand::SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).unwrap();

        let eph_key = Ed25519KeyPair::from_seed_unchecked(Input::from(&seed)).unwrap();
        println!("Ephemeral public key: {}", eph_key.public_key_bytes().to_hex());

        eph_key
    };

    let zeros = [0u8; 8];
    let max = [0xff; 8];

    let mut dele_msg = RtMessage::new(3);
    dele_msg.add_field(Tag::PUBK, &ephemeral_key.public_key_bytes()).unwrap();
    dele_msg.add_field(Tag::MINT, &zeros).unwrap();
    dele_msg.add_field(Tag::MAXT, &max).unwrap();

    let dele_bytes = dele_msg.encode().unwrap();

    println!("{}", dele_bytes.to_hex());

    // Sign it with long-term key
    // Create CERT

    // Wipe long-term key

    // loop:
    //   read request
    //   validate request or goto loop
    //   create SREP
    //   sign SREP
    //   create response:
    //    - SIG
    //    - PATH (always 0)
    //    - SREP
    //    - CERT (pre-created)
    //    - INDX (always 0)
    //   send response

}
