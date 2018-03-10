#[macro_use]
extern crate clap;
extern crate roughenough;
extern crate ring;
extern crate time;
extern crate chrono;
extern crate byteorder;
extern crate hex;

use ring::rand;
use ring::rand::SecureRandom;
use ring::digest;

use byteorder::{LittleEndian, ReadBytesExt};

use chrono::TimeZone;
use chrono::offset::Utc;

use std::iter::Iterator;
use std::collections::HashMap;
use std::net::{UdpSocket, ToSocketAddrs};

use roughenough::{RtMessage, Tag, TREE_NODE_TWEAK, TREE_LEAF_TWEAK, CERTIFICATE_CONTEXT, SIGNED_RESPONSE_CONTEXT};
use roughenough::sign::Verifier;
use clap::{Arg, App};

fn create_nonce() -> [u8; 64] {
    let rng = rand::SystemRandom::new();
    let mut nonce = [0u8; 64];
    rng.fill(&mut nonce).unwrap();

    nonce
}

fn make_request(nonce: &[u8]) -> Vec<u8> {
    let mut msg = RtMessage::new(1);
    msg.add_field(Tag::NONC, nonce).unwrap();
    msg.pad_to_kilobyte();

    msg.encode().unwrap()
}

fn receive_response(sock: &mut UdpSocket) -> RtMessage {
    let mut buf = [0; 744];
    let resp_len = sock.recv_from(&mut buf).unwrap().0;
    RtMessage::from_bytes(&buf[0..resp_len]).unwrap()
}


struct ResponseHandler {
    pub_key: Option<Vec<u8>>,
    msg: HashMap<Tag, Vec<u8>>,
    srep: HashMap<Tag, Vec<u8>>,
    cert: HashMap<Tag, Vec<u8>>,
    dele: HashMap<Tag, Vec<u8>>,
    nonce: [u8; 64]
}

impl ResponseHandler {
    pub fn new(pub_key: Option<Vec<u8>>, response: RtMessage, nonce: [u8; 64]) -> ResponseHandler {
        let msg = response.into_hash_map();
        let srep = RtMessage::from_bytes(&msg[&Tag::SREP]).unwrap().into_hash_map();
        let cert = RtMessage::from_bytes(&msg[&Tag::CERT]).unwrap().into_hash_map();

        let dele = RtMessage::from_bytes(&cert[&Tag::DELE]).unwrap().into_hash_map();

        ResponseHandler {
            pub_key,
            msg,
            srep,
            cert,
            dele,
            nonce
        }
    }

    pub fn extract_time(&self) -> (u64, u32) {
        let midpoint = self.srep[&Tag::MIDP].as_slice().read_u64::<LittleEndian>().unwrap();
        let radius = self.srep[&Tag::RADI].as_slice().read_u32::<LittleEndian>().unwrap();

        if self.pub_key.is_some() {
            self.validate_dele();
            self.validate_srep();
            self.validate_merkle();
            self.validate_midpoint(midpoint);
        }

        (midpoint, radius)
    }

    fn validate_dele(&self) {
        let mut full_cert = Vec::from(CERTIFICATE_CONTEXT.as_bytes());
        full_cert.extend(&self.cert[&Tag::DELE]);

        assert!(self.validate_sig(self.pub_key.as_ref().unwrap(), &self.cert[&Tag::SIG], &full_cert),
                "Invalid signature on DELE tag!");
    }

    fn validate_srep(&self) {
        let mut full_srep = Vec::from(SIGNED_RESPONSE_CONTEXT.as_bytes());
        full_srep.extend(&self.msg[&Tag::SREP]);

        assert!(self.validate_sig(&self.dele[&Tag::PUBK], &self.msg[&Tag::SIG], &full_srep),
                "Invalid signature on SREP tag!");
    }

    fn validate_merkle(&self) {
        let srep = RtMessage::from_bytes(&self.msg[&Tag::SREP]).unwrap().into_hash_map();
        let mut index = self.msg[&Tag::INDX].as_slice().read_u32::<LittleEndian>().unwrap();
        let paths = &self.msg[&Tag::PATH];

        let mut hash = sha_512(TREE_LEAF_TWEAK, &self.nonce);

        assert_eq!(paths.len() % 64, 0);

        for path in paths.chunks(64) {
            let mut ctx = digest::Context::new(&digest::SHA512);
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
            hash = Vec::from(ctx.finish().as_ref());

            index >>= 1;
        }

        assert_eq!(hash, srep[&Tag::ROOT], "Nonce not in merkle tree!");

    }

    fn validate_midpoint(&self, midpoint: u64) {
        let mint = self.dele[&Tag::MINT].as_slice().read_u64::<LittleEndian>().unwrap();
        let maxt = self.dele[&Tag::MAXT].as_slice().read_u64::<LittleEndian>().unwrap();

        assert!(midpoint >= mint, "Response midpoint {} lies before delegation span ({}, {})");
        assert!(midpoint <= maxt, "Response midpoint {} lies after delegation span ({}, {})");
    }

    fn validate_sig(&self, public_key: &[u8], sig: &[u8], data: &[u8]) -> bool {
        let mut verifier = Verifier::new(public_key);
        verifier.update(data);
        verifier.verify(sig)
    }
}

fn sha_512(prefix: &[u8], data: &[u8]) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(prefix);
    ctx.update(data);
    Vec::from(ctx.finish().as_ref())
}

fn main() {
    let matches = App::new("roughenough client")
                      .version("0.1.1")
                      .arg(Arg::with_name("host")
                           .required(true)
                           .help("The Roughtime server to connect to")
                           .takes_value(true))
                      .arg(Arg::with_name("port")
                           .required(true)
                           .help("The Roughtime server port to connect to")
                           .takes_value(true))
                      .arg(Arg::with_name("public-key")
                           .short("p")
                           .long("public-key")
                           .takes_value(true)
                           .help("The server public key used to validate responses. If unset, no validation will be performed"))
                      .arg(Arg::with_name("time-format")
                           .short("f")
                           .long("time-format")
                           .takes_value(true)
                           .help("The strftime format string used to print the time recieved from the server")
                           .default_value("%b %d %Y %H:%M:%S")
                        )
                      .arg(Arg::with_name("num-requests")
                           .short("n")
                           .long("num-requests")
                           .takes_value(true)
                           .help("The number of requests to make to the server (each from a different source port). This is mainly useful for testing batch response handling")
                           .default_value("1")
                        )
                      .get_matches();

    let host = matches.value_of("host").unwrap();
    let port = value_t_or_exit!(matches.value_of("port"), u16);
    let num_requests = value_t_or_exit!(matches.value_of("num-requests"), u16) as usize;
    let pub_key = matches.value_of("public-key").map(|pkey| hex::decode(pkey).expect("Error parsing public key!"));
    let time_format = matches.value_of("time-format").unwrap();

    println!("Requesting time from: {:?}:{:?}", host, port);

    let addrs: Vec<_> = (host, port).to_socket_addrs().unwrap().collect();

    let mut requests = Vec::with_capacity(num_requests);

    for _ in 0..num_requests {
        let nonce = create_nonce();
        let mut socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't open UDP socket");
        let request = make_request(&nonce);

        requests.push((nonce, request, socket));
    }

    for &mut (_, ref request, ref mut socket) in requests.iter_mut() {
        socket.send_to(request, addrs.as_slice()).unwrap();
    }

    for (nonce, _, mut socket) in requests {
        let resp = receive_response(&mut socket);

        let (midpoint, radius) = ResponseHandler::new(pub_key.clone(), resp, nonce).extract_time();

        let seconds = midpoint / 10_u64.pow(6);
        let spec = Utc.timestamp(seconds as i64, ((midpoint - (seconds * 10_u64.pow(6))) * 10_u64.pow(3)) as u32);
        let out = spec.format(time_format).to_string();

        println!("Recieved time from server: midpoint={:?}, radius={:?}", out, radius);
    }
}
