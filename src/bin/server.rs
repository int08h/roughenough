//!
//! Roughtime server
//!

extern crate byteorder;
extern crate core;
extern crate ring;
extern crate roughenough;
extern crate time;
extern crate untrusted;

use std::io;

use std::net::UdpSocket;
use std::time::Duration;

use untrusted::Input;

use roughenough::{RtMessage, Tag, Error};
use roughenough::hex::*;
use roughenough::{CERTIFICATE_CONTEXT, SIGNED_RESPONSE_CONTEXT, TREE_LEAF_TWEAK};

use ring::{digest, error, rand};
use ring::rand::SecureRandom;
use ring::signature::Ed25519KeyPair;

use byteorder::{LittleEndian, WriteBytesExt};

fn get_long_term_key() -> Result<Ed25519KeyPair, error::Unspecified> {
    // TODO: read from config
    let seed = [b'x'; 32];
    Ed25519KeyPair::from_seed_unchecked(Input::from(&seed))
}

fn make_ephemeral_key() -> Result<Ed25519KeyPair, error::Unspecified> {
    let rng = rand::SystemRandom::new();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).unwrap();

    Ed25519KeyPair::from_seed_unchecked(Input::from(&seed))
}

fn make_dele_bytes(ephemeral_key: &Ed25519KeyPair) -> Result<Vec<u8>, Error> {
    let zeros = [0u8; 8];
    let max = [0xff; 8];

    let mut dele_msg = RtMessage::new(3);
    dele_msg.add_field(Tag::PUBK, &ephemeral_key.public_key_bytes())?;
    dele_msg.add_field(Tag::MINT, &zeros)?;
    dele_msg.add_field(Tag::MAXT, &max)?;

    dele_msg.encode()
}

fn make_cert(long_term_key: &Ed25519KeyPair, ephemeral_key: &Ed25519KeyPair) -> RtMessage {
    // Make DELE and sign it with long-term key
    let dele_bytes = make_dele_bytes(&ephemeral_key).unwrap();
    let dele_signature = {
        let mut sha_ctx = digest::Context::new(&digest::SHA512);
        sha_ctx.update(CERTIFICATE_CONTEXT.as_bytes());
        sha_ctx.update(&dele_bytes);
        let digest = sha_ctx.finish();

        long_term_key.sign(digest.as_ref())
    };

    // Create CERT
    let mut cert_msg = RtMessage::new(2);
    cert_msg.add_field(Tag::SIG, dele_signature.as_ref()).unwrap();
    cert_msg.add_field(Tag::DELE, &dele_bytes).unwrap();

    cert_msg
}

fn make_response(ephemeral_key: &Ed25519KeyPair, cert_bytes: &[u8], request: &[u8]) -> RtMessage {
    //   create SREP
    //   sign SREP
    //   create response:
    //    - SIG
    //    - PATH (always 0)
    //    - SREP
    //    - CERT (pre-created)
    //    - INDX (always 0)

    let path = [0u8; 0];
    let zeros = [0u8; 4];

    let mut radi: Vec<u8> = Vec::with_capacity(4);
    let mut midp: Vec<u8> = Vec::with_capacity(8);

    // TODO: populate
    let mut nonce = vec![0u8; 64];

    // one second (in microseconds)
    radi.write_u32::<LittleEndian>(1000000).unwrap();

    // current epoch time in microseconds
    let now = {
        let tv = time::get_time();
        let secs = (tv.sec as u64) * 1000000;
        let nsecs = (tv.nsec as u64) / 1000;

        secs + nsecs
    };
    midp.write_u64::<LittleEndian>(now).unwrap();

    // Signed response SREP
    let srep_bytes = {
        // hash request nonce
        let mut ctx = digest::Context::new(&digest::SHA512);
        ctx.update(&TREE_LEAF_TWEAK);
        ctx.update(&nonce);
        let digest = ctx.finish();

        let mut srep_msg = RtMessage::new(3);
        srep_msg.add_field(Tag::RADI, &radi).unwrap();
        srep_msg.add_field(Tag::MIDP, &midp).unwrap();
        srep_msg.add_field(Tag::ROOT, digest.as_ref()).unwrap();

        srep_msg.encode().unwrap()
    };

    // signature on SREP
    let srep_signature = {
        let mut sha_ctx = digest::Context::new(&digest::SHA512);
        sha_ctx.update(SIGNED_RESPONSE_CONTEXT.as_bytes());
        sha_ctx.update(&srep_bytes);
        let digest = sha_ctx.finish();

        ephemeral_key.sign(digest.as_ref())
    };

    let mut response = RtMessage::new(5);
    response.add_field(Tag::SIG, srep_signature.as_ref()).unwrap();
    response.add_field(Tag::PATH, &path).unwrap();
    response.add_field(Tag::SREP, &srep_bytes).unwrap();
    response.add_field(Tag::CERT, cert_bytes).unwrap();
    response.add_field(Tag::INDX, &zeros).unwrap();

    response
}

fn main() {
    let lt_key = get_long_term_key().expect("failed to obtain long-term key");
    let ephemeral_key = make_ephemeral_key().expect("failed to create ephemeral key");

    println!("Long-term public key: {}", lt_key.public_key_bytes().to_hex());
    println!("Ephemeral public key: {}", ephemeral_key.public_key_bytes().to_hex());

    let cert_msg = make_cert(&lt_key, &ephemeral_key);
    let cert_bytes = cert_msg.encode().unwrap();

    let mut socket = UdpSocket::bind("127.0.0.1:8686").expect("failed to bind to socket");
    socket.set_read_timeout(Some(Duration::from_secs(1))).expect("could not set read timeout");

    let mut buf = [0u8; 65536];
    let mut loops = 0u64;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((num_bytes, src_addr)) => { 
                println!("{} bytes from {}", num_bytes, src_addr);
                let resp = make_response(&ephemeral_key, &cert_bytes, &buf[..num_bytes]);
                println!("response {:?}", resp.encode().unwrap().to_hex());
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => loops += 1,
            Err(ref e) => println!("Error {:?}: {:?}", e.kind(), e)
        }
    }


    // loop:
    //   read request
    //   validate request or goto loop
    //   send response

}
