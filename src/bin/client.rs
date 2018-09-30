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

extern crate byteorder;
extern crate chrono;
#[macro_use]
extern crate clap;
extern crate hex;
extern crate ring;
extern crate roughenough;
extern crate time;

use ring::rand;
use ring::rand::SecureRandom;

use byteorder::{LittleEndian, ReadBytesExt};

use chrono::offset::Utc;
use chrono::TimeZone;

use std::collections::HashMap;
use std::iter::Iterator;
use std::net::{ToSocketAddrs, UdpSocket};

use clap::{App, Arg};
use roughenough::merkle::root_from_paths;
use roughenough::sign::Verifier;
use roughenough::{RtMessage, Tag, CERTIFICATE_CONTEXT, SIGNED_RESPONSE_CONTEXT, VERSION};

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
    nonce: [u8; 64],
}

struct ParsedResponse {
    verified: bool,
    midpoint: u64,
    radius: u32,
}

impl ResponseHandler {
    pub fn new(pub_key: Option<Vec<u8>>, response: RtMessage, nonce: [u8; 64]) -> ResponseHandler {
        let msg = response.into_hash_map();
        let srep = RtMessage::from_bytes(&msg[&Tag::SREP])
            .unwrap()
            .into_hash_map();
        let cert = RtMessage::from_bytes(&msg[&Tag::CERT])
            .unwrap()
            .into_hash_map();
        let dele = RtMessage::from_bytes(&cert[&Tag::DELE])
            .unwrap()
            .into_hash_map();

        ResponseHandler {
            pub_key,
            msg,
            srep,
            cert,
            dele,
            nonce,
        }
    }

    pub fn extract_time(&self) -> ParsedResponse {
        let midpoint = self.srep[&Tag::MIDP]
            .as_slice()
            .read_u64::<LittleEndian>()
            .unwrap();
        let radius = self.srep[&Tag::RADI]
            .as_slice()
            .read_u32::<LittleEndian>()
            .unwrap();
        let mut verified = false;

        if self.pub_key.is_some() {
            self.validate_dele();
            self.validate_srep();
            self.validate_merkle();
            self.validate_midpoint(midpoint);
            verified = true;
        }

        ParsedResponse {
            verified,
            midpoint,
            radius,
        }
    }

    fn validate_dele(&self) {
        let mut full_cert = Vec::from(CERTIFICATE_CONTEXT.as_bytes());
        full_cert.extend(&self.cert[&Tag::DELE]);

        assert!(
            self.validate_sig(
                self.pub_key.as_ref().unwrap(),
                &self.cert[&Tag::SIG],
                &full_cert
            ),
            "Invalid signature on DELE tag!"
        );
    }

    fn validate_srep(&self) {
        let mut full_srep = Vec::from(SIGNED_RESPONSE_CONTEXT.as_bytes());
        full_srep.extend(&self.msg[&Tag::SREP]);

        assert!(
            self.validate_sig(&self.dele[&Tag::PUBK], &self.msg[&Tag::SIG], &full_srep),
            "Invalid signature on SREP tag!"
        );
    }

    fn validate_merkle(&self) {
        let srep = RtMessage::from_bytes(&self.msg[&Tag::SREP])
            .unwrap()
            .into_hash_map();
        let index = self.msg[&Tag::INDX]
            .as_slice()
            .read_u32::<LittleEndian>()
            .unwrap();
        let paths = &self.msg[&Tag::PATH];

        let hash = root_from_paths(index as usize, &self.nonce, paths);

        assert_eq!(
            Vec::from(hash),
            srep[&Tag::ROOT],
            "Nonce not in merkle tree!"
        );
    }

    fn validate_midpoint(&self, midpoint: u64) {
        let mint = self.dele[&Tag::MINT]
            .as_slice()
            .read_u64::<LittleEndian>()
            .unwrap();
        let maxt = self.dele[&Tag::MAXT]
            .as_slice()
            .read_u64::<LittleEndian>()
            .unwrap();

        assert!(
            midpoint >= mint,
            "Response midpoint {} lies before delegation span ({}, {})"
        );
        assert!(
            midpoint <= maxt,
            "Response midpoint {} lies after delegation span ({}, {})"
        );
    }

    fn validate_sig(&self, public_key: &[u8], sig: &[u8], data: &[u8]) -> bool {
        let mut verifier = Verifier::new(public_key);
        verifier.update(data);
        verifier.verify(sig)
    }
}

fn main() {
    let matches = App::new("roughenough client")
    .version(VERSION)
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
    .arg(Arg::with_name("stress")
      .short("s")
      .long("stress")
      .help("Stress-tests the server by sending the same request as fast as possible. Please only use this on your own server")
    )
    .get_matches();

    let host = matches.value_of("host").unwrap();
    let port = value_t_or_exit!(matches.value_of("port"), u16);
    let num_requests = value_t_or_exit!(matches.value_of("num-requests"), u16) as usize;
    let time_format = matches.value_of("time-format").unwrap();
    let stress = matches.is_present("stress");
    let pub_key = matches
        .value_of("public-key")
        .map(|pkey| hex::decode(pkey).expect("Error parsing public key!"));

    println!("Requesting time from: {:?}:{:?}", host, port);

    let addr = (host, port).to_socket_addrs().unwrap().next().unwrap();

    if stress {
        if !addr.ip().is_loopback() {
            println!(
                "ERROR: Cannot use non-loopback address {} for stress testing",
                addr.ip()
            );
            return;
        }

        println!("Stress-testing!");

        let nonce = create_nonce();
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't open UDP socket");
        let request = make_request(&nonce);

        loop {
            socket.send_to(&request, addr).unwrap();
        }
    }

    let mut requests = Vec::with_capacity(num_requests);

    for _ in 0..num_requests {
        let nonce = create_nonce();
        let mut socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't open UDP socket");
        let request = make_request(&nonce);

        requests.push((nonce, request, socket));
    }

    for &mut (_, ref request, ref mut socket) in requests.iter_mut() {
        socket.send_to(request, addr).unwrap();
    }

    for (nonce, _, mut socket) in requests {
        let resp = receive_response(&mut socket);

        let ParsedResponse {
            verified,
            midpoint,
            radius,
        } = ResponseHandler::new(pub_key.clone(), resp.clone(), nonce).extract_time();

        let map = resp.into_hash_map();
        let index = map[&Tag::INDX]
            .as_slice()
            .read_u32::<LittleEndian>()
            .unwrap();

        let seconds = midpoint / 10_u64.pow(6);
        let nsecs = (midpoint - (seconds * 10_u64.pow(6))) * 10_u64.pow(3);
        let spec = Utc.timestamp(seconds as i64, nsecs as u32);
        let out = spec.format(time_format).to_string();

        println!(
            "Received time from server: midpoint={:?}, radius={:?} (merkle_index={}, verified={})",
            out, radius, index, verified
        );
    }
}
