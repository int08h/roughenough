// Copyright 2017-2021 int08h LLC

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

// for value_t_or_exit!()
#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::File;
use std::io::ErrorKind::WouldBlock;
use std::io::{Cursor, Write};
use std::iter::Iterator;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time;

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::offset::Utc;
use chrono::{Local, TimeZone};
use clap::{App, Arg};
use data_encoding::{Encoding, BASE64, HEXLOWER_PERMISSIVE};
use ring::rand;
use ring::rand::SecureRandom;
use roughenough::key::LongTermKey;
use roughenough::merkle::MerkleTree;
use roughenough::sign::Verifier;
use roughenough::version::Version;
use roughenough::{
    roughenough_version, Error, RtMessage, Tag, CERTIFICATE_CONTEXT, REQUEST_FRAMING_BYTES,
    SIGNED_RESPONSE_CONTEXT,
};

const HEX: Encoding = HEXLOWER_PERMISSIVE;

type Nonce = Vec<u8>;

fn create_nonce(ver: Version) -> Nonce {
    let rng = rand::SystemRandom::new();
    match ver {
        Version::Classic => {
            let mut nonce = [0u8; 64];
            rng.fill(&mut nonce).unwrap();
            nonce.to_vec()
        }
        Version::Rfc | Version::RfcDraft11 => {
            let mut nonce = [0u8; 32];
            rng.fill(&mut nonce).unwrap();
            nonce.to_vec()
        }
    }
}

fn make_request(ver: Version, nonce: &Nonce, text_dump: bool, pub_key: &Option<Vec<u8>>) -> Vec<u8> {
    let mut msg = RtMessage::with_capacity(3);

    let srv_value = match pub_key {
        None => None,
        Some(ref pk) => Some(LongTermKey::calc_srv_value(&pk)),
    };

    match ver {
        Version::Classic => {
            msg.add_field(Tag::NONC, nonce).unwrap();
            msg.add_field(Tag::PAD, &[]).unwrap();

            let padding_needed = msg.calculate_padding_length();
            let padding: Vec<u8> = (0..padding_needed).map(|_| 0).collect();

            msg.clear();
            msg.add_field(Tag::NONC, nonce).unwrap();
            msg.add_field(Tag::PAD, &padding).unwrap();

            if text_dump {
                eprintln!("Request = {}", msg);
            }

            msg.encode().unwrap()
        }
        Version::Rfc | Version::RfcDraft11 => {
            if srv_value.is_some() {
                let val = srv_value.as_ref().unwrap();
                msg.add_field(Tag::SRV, val).unwrap();
            }
            msg.add_field(Tag::VER, ver.wire_bytes()).unwrap();
            msg.add_field(Tag::NONC, nonce).unwrap();
            msg.add_field(Tag::ZZZZ, &[]).unwrap();

            let padding_needed = msg.calculate_padding_length();
            let padding: Vec<u8> = (0..padding_needed).map(|_| 0).collect();

            msg.clear();

            if srv_value.is_some() {
                let val = srv_value.as_ref().unwrap();
                msg.add_field(Tag::SRV, val).unwrap();
            }
            msg.add_field(Tag::VER, ver.wire_bytes()).unwrap();
            msg.add_field(Tag::NONC, nonce).unwrap();
            msg.add_field(Tag::ZZZZ, &padding).unwrap();

            if text_dump {
                eprintln!("Request = {}", msg);
            }

            msg.encode_framed().unwrap()
        }
    }
}

fn receive_response(ver: Version, buf: &[u8], buf_len: usize) -> RtMessage {
    match ver {
        Version::Classic => RtMessage::from_bytes(&buf[0..buf_len]).unwrap(),
        Version::Rfc | Version::RfcDraft11 => {
            verify_framing(&buf).unwrap();
            RtMessage::from_bytes(&buf[12..buf_len]).unwrap()
        }
    }
}

fn verify_framing(buf: &[u8]) -> Result<(), Error> {
    if &buf[0..8] != REQUEST_FRAMING_BYTES {
        eprintln!("RFC response is missing framing header bytes");
        return Err(Error::InvalidResponse);
    }

    let mut cur = Cursor::new(&buf[8..12]);
    let reported_len = cur.read_u32::<LittleEndian>()?;

    if (reported_len as usize) > buf.len() - 12 {
        eprintln!("buflen = {}, reported_len = {}", buf.len(), reported_len);
        return Err(Error::MessageTooShort);
    }

    Ok(())
}

fn stress_test_forever(ver: Version, addr: &SocketAddr) -> ! {
    if !addr.ip().is_loopback() {
        panic!(
            "Cannot use non-loopback address {} for stress testing",
            addr.ip()
        );
    }

    println!("Stress testing!");

    let nonce = create_nonce(ver);
    let socket = UdpSocket::bind(if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
        .expect("Couldn't open UDP socket");
    let request = make_request(ver, &nonce, false, &None);
    loop {
        socket.send_to(&request, addr).unwrap();
    }
}

struct ResponseHandler {
    pub_key: Option<Vec<u8>>,
    msg: HashMap<Tag, Vec<u8>>,
    srep: HashMap<Tag, Vec<u8>>,
    cert: HashMap<Tag, Vec<u8>>,
    dele: HashMap<Tag, Vec<u8>>,
    nonce: Nonce,
    version: Version,
}

struct ParsedResponse {
    verified: bool,
    midpoint: u64,
    radius: u32,
}

impl ResponseHandler {
    pub fn new(
        version: Version,
        pub_key: Option<Vec<u8>>,
        response: RtMessage,
        nonce: Nonce,
    ) -> ResponseHandler {
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
            version,
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

        self.validate_merkle();
        self.validate_midpoint(midpoint);

        let verified = if self.pub_key.is_some() {
            self.validate_dele();
            self.validate_srep();
            true
        } else {
            false
        };

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
                &full_cert,
            ),
            "Invalid signature on DELE tag, response may not be authentic"
        );
    }

    fn validate_srep(&self) {
        let mut full_srep = Vec::from(SIGNED_RESPONSE_CONTEXT.as_bytes());
        full_srep.extend(&self.msg[&Tag::SREP]);

        assert!(
            self.validate_sig(&self.dele[&Tag::PUBK], &self.msg[&Tag::SIG], &full_srep),
            "Invalid signature on SREP tag, response may not be authentic"
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

        let hash = match self.version {
            Version::Classic => MerkleTree::new_sha512_classic(),
            Version::Rfc | Version::RfcDraft11 => MerkleTree::new_sha512_ietf(),
        }
        .root_from_paths(index as usize, &self.nonce, paths);

        assert_eq!(
            hash,
            srep[&Tag::ROOT],
            "Nonce is not present in the response's merkle tree"
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
            "Response midpoint {} lies *before* delegation span ({}, {})",
            midpoint,
            mint,
            maxt
        );
        assert!(
            midpoint <= maxt,
            "Response midpoint {} lies *after* delegation span ({}, {})",
            midpoint,
            mint,
            maxt
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
        .version(&*roughenough_version())
        .arg(Arg::with_name("host")
            .required(true)
            .help("The Roughtime server to connect to.")
            .takes_value(true))
        .arg(Arg::with_name("port")
            .required(true)
            .help("The Roughtime server port to connect to.")
            .takes_value(true))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Output additional details about the server's response."))
        .arg(Arg::with_name("dump")
            .short("d")
            .long("dump")
            .help("Pretty text dump of the exchanged Roughtime messages."))
        .arg(Arg::with_name("json")
            .short("j")
            .long("json")
            .help("Output the server's response in JSON format."))
        .arg(Arg::with_name("public-key")
            .short("k")
            .long("public-key")
            .takes_value(true)
            .help("The server public key used to validate responses. When set, will add SRV tag to request to bind request to the expected public key. If unset, no validation will be performed."))
        .arg(Arg::with_name("time-format")
            .short("f")
            .long("time-format")
            .takes_value(true)
            .help("The strftime format string used to print the time received from the server.")
            .default_value("%b %d %Y %H:%M:%S %Z")
        )
        .arg(Arg::with_name("num-requests")
            .short("n")
            .long("num-requests")
            .takes_value(true)
            .help("The number of requests to make to the server (each from a different source port). This is mainly useful for testing batch response handling.")
            .default_value("1")
        )
        .arg(Arg::with_name("stress")
            .short("s")
            .long("stress")
            .help("Stress test the server by sending the same request as fast as possible. Please only use this on your own server.")
        )
        .arg(Arg::with_name("output-requests")
            .short("o")
            .long("output-requests")
            .takes_value(true)
            .help("Writes all requests to the specified file, in addition to sending them to the server. Useful for generating fuzzer inputs.")
        )
        .arg(Arg::with_name("output-responses")
            .short("O")
            .long("output-responses")
            .takes_value(true)
            .help("Writes all server responses to the specified file, in addition to processing them. Useful for generating fuzzer inputs.")
        )
        .arg(Arg::with_name("protocol")
            .short("p")
            .long("protocol")
            .takes_value(true)
            .help("Roughtime protocol version to use (0 = classic, 1 = rfc, 8 = draft8)")
            .default_value("0")
        )
        .arg(Arg::with_name("timeout")
            .short("t")
            .long("timeout")
            .takes_value(true)
            .help("Seconds to wait for server response")
            .default_value("10")
        )
        .arg(Arg::with_name("zulu")
            .short("z")
            .long("zulu")
            .help("Display time in UTC (default is local time zone)")
        )
        .get_matches();

    let host = matches.value_of("host").unwrap();
    let port = value_t_or_exit!(matches.value_of("port"), u16);
    let verbose = matches.is_present("verbose");
    let text_dump = matches.is_present("dump");
    let json = matches.is_present("json");
    let num_requests = value_t_or_exit!(matches.value_of("num-requests"), u16) as usize;
    let timeout_secs = value_t_or_exit!(matches.value_of("timeout"), u64);
    let time_format = matches.value_of("time-format").unwrap();
    let stress = matches.is_present("stress");
    let pub_key = matches.value_of("public-key").map(|pkey| {
        HEX.decode(pkey.as_ref())
            .or_else(|_| BASE64.decode(pkey.as_ref()))
            .expect("Error parsing public key!")
    });
    let output_requests = matches.value_of("output-requests");
    let output_responses = matches.value_of("output-responses");
    let protocol = value_t_or_exit!(matches.value_of("protocol"), u8);
    let use_utc = matches.is_present("zulu");

    if verbose {
        eprintln!("Requesting time from: {:?}:{:?}", host, port);
    }

    let version = match protocol {
        0 => Version::Classic,
        1 => Version::Rfc,
        11 => Version::RfcDraft11,
        _ => panic!(
            "Invalid protocol '{}'; valid values are 0, 1, or 8",
            protocol
        ),
    };

    let addr = (host, port).to_socket_addrs().unwrap().next().unwrap();

    if stress {
        stress_test_forever(version, &addr)
    }

    let mut requests = Vec::with_capacity(num_requests);
    let mut file_for_requests =
        output_requests.map(|o| File::create(o).expect("Failed to create file!"));
    let mut file_for_responses =
        output_responses.map(|o| File::create(o).expect("Failed to create file!"));

    for _ in 0..num_requests {
        let nonce = create_nonce(version);
        let socket = UdpSocket::bind(if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
            .expect("Couldn't open UDP socket");
        let request = make_request(version, &nonce, text_dump, &pub_key);

        if let Some(f) = file_for_requests.as_mut() {
            f.write_all(&request).expect("Failed to write to file!")
        }

        requests.push((nonce, request, socket));
    }

    for &mut (_, ref request, ref mut socket) in &mut requests {
        socket.send_to(request, addr).unwrap();
    }

    for (nonce, _, socket) in requests {
        let duration = time::Duration::from_secs(timeout_secs);
        socket
            .set_read_timeout(Some(duration))
            .expect("Failed setting send timeout");

        let mut buf = [0u8; 4096];

        let resp_len = match socket.recv_from(&mut buf) {
            Ok((resp_len, _)) => resp_len,
            Err(e) if e.kind() == WouldBlock => {
                eprintln!("Timeout waiting for response");
                return;
            }
            Err(e) => panic!("{}", e),
        };

        if let Some(f) = file_for_responses.as_mut() {
            f.write_all(&buf[0..resp_len])
                .expect("Failed to write to file!")
        }

        let resp = receive_response(version, &buf, resp_len);

        if text_dump {
            eprintln!("Response = {}", resp);
        }

        let ParsedResponse {
            verified,
            midpoint,
            radius,
        } = ResponseHandler::new(version, pub_key.clone(), resp.clone(), nonce.clone())
            .extract_time();

        let map = resp.into_hash_map();
        let index = map[&Tag::INDX]
            .as_slice()
            .read_u32::<LittleEndian>()
            .unwrap();

        let (seconds, nsecs) = match version {
            Version::Classic => {
                let seconds = midpoint / 10_u64.pow(6);
                let nsecs = (midpoint - (seconds * 10_u64.pow(6))) * 10_u64.pow(3);
                (seconds, nsecs as u32)
            }
            Version::Rfc | Version::RfcDraft11 => (midpoint, 0),
        };

        let verify_str = if verified { "Yes" } else { "No" };

        let out = if use_utc {
            let ts = Utc.timestamp_opt(seconds as i64, nsecs).unwrap();
            ts.format(time_format).to_string()
        } else {
            let ts = Local.timestamp_opt(seconds as i64, nsecs).unwrap();
            ts.format(time_format).to_string()
        };

        if verbose {
            eprintln!(
                "Received time from server: midpoint={:?}, radius={:?}, verified={} (merkle_index={})",
                out, radius, verify_str, index
            );
        }

        if json {
            println!(
                r#"{{ "midpoint": {:?}, "radius": {:?}, "verified": {}, "merkle_index": {} }}"#,
                out, radius, verified, index
            );
        } else {
            println!("{}", out);
        }
    }
}
