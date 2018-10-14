use std::env;
use std::io::ErrorKind;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;
use hex;
use time;

use byteorder::{LittleEndian, WriteBytesExt};


use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::Timer;

use config;
use config::ServerConfig;
use kms;
use key::{LongTermKey, OnlineKey};
use merkle::MerkleTree;
use {Error, RtMessage, Tag};
use {MIN_REQUEST_LENGTH, VERSION};


macro_rules! check_ctrlc {
    ($keep_running:expr) => {
        if !$keep_running.load(Ordering::Acquire) {
            warn!("Ctrl-C caught, exiting...");
            return true;
        }
    }
}

const MESSAGE: Token = Token(0);
const STATUS: Token = Token(1);

fn make_response(srep: &RtMessage, cert_bytes: &[u8], path: &[u8], idx: u32) -> RtMessage {
    let mut index = [0; 4];
    (&mut index as &mut [u8])
        .write_u32::<LittleEndian>(idx)
        .unwrap();

    let sig_bytes = srep.get_field(Tag::SIG).unwrap();
    let srep_bytes = srep.get_field(Tag::SREP).unwrap();

    let mut response = RtMessage::new(5);
    response.add_field(Tag::SIG, sig_bytes).unwrap();
    response.add_field(Tag::PATH, path).unwrap();
    response.add_field(Tag::SREP, srep_bytes).unwrap();
    response.add_field(Tag::CERT, cert_bytes).unwrap();
    response.add_field(Tag::INDX, &index).unwrap();

    response
}

// extract the client's nonce from its request
fn nonce_from_request(buf: &[u8], num_bytes: usize) -> Result<&[u8], Error> {
    if num_bytes < MIN_REQUEST_LENGTH as usize {
        return Err(Error::RequestTooShort);
    }

    let tag_count = &buf[..4];
    let expected_nonc = &buf[8..12];
    let expected_pad = &buf[12..16];

    let tag_count_is_2 = tag_count == [0x02, 0x00, 0x00, 0x00];
    let tag1_is_nonc = expected_nonc == Tag::NONC.wire_value();
    let tag2_is_pad = expected_pad == Tag::PAD.wire_value();

    if tag_count_is_2 && tag1_is_nonc && tag2_is_pad {
        Ok(&buf[0x10..0x50])
    } else {
        Err(Error::InvalidRequest)
    }
}

pub struct Server {
    config: Box<ServerConfig>,
    online_key: OnlineKey,
    cert_bytes: Vec<u8>,

    response_counter: AtomicUsize,
    num_bad_requests: u64,

    socket: UdpSocket,
    keep_running: Arc<AtomicBool>,
    poll_duration: Option<Duration>,
    timer: Timer<()>,
    poll: Poll,
    events: Events,
    merkle: MerkleTree,
    requests: Vec<(Vec<u8>, SocketAddr)>,
    buf: [u8; 65_536],

    public_key: String,
}

impl Server {
    pub fn new(config: Box<ServerConfig>) -> Server {

        let mut online_key = OnlineKey::new();
        let public_key: String;

        let cert_bytes = {
            let seed = kms::load_seed(&config).unwrap();
            let mut long_term_key = LongTermKey::new(&seed);
            public_key = hex::encode(long_term_key.public_key());

            long_term_key.make_cert(&online_key).encode().unwrap()
        };

        let response_counter = AtomicUsize::new(0);
        let keep_running = Arc::new(AtomicBool::new(true));

        let sock_addr = config.socket_addr().expect("");
        let socket = UdpSocket::bind(&sock_addr).expect("failed to bind to socket");
        let poll_duration = Some(Duration::from_millis(100));

        let mut timer: Timer<()> = Timer::default();
        timer.set_timeout(config.status_interval(), ());

        let poll = Poll::new().unwrap();
        poll.register(&socket, MESSAGE, Ready::readable(), PollOpt::edge())
            .unwrap();
        poll.register(&timer, STATUS, Ready::readable(), PollOpt::edge())
            .unwrap();

        let mut merkle = MerkleTree::new();
        let mut requests = Vec::with_capacity(config.batch_size() as usize);


        Server {
            config,
            online_key,
            cert_bytes,

            response_counter,
            num_bad_requests: 0,
            socket,
            keep_running,
            poll_duration,
            timer,
            poll,
            events: Events::with_capacity(32),
            merkle,
            requests,
            buf: [0u8; 65_536],

            public_key
        }

    }

    pub fn get_keep_running(&self) -> Arc<AtomicBool> {
        return self.keep_running.clone()
    }

    pub fn process_events(&mut self) -> bool {
        self.poll.poll(&mut self.events, self.poll_duration).expect("poll failed");

        for event in self.events.iter() {
            match event.token() {
                MESSAGE => {
                    let mut done = false;

                    'process_batch: loop {
                        check_ctrlc!(self.keep_running);

                        self.merkle.reset();
                        self.requests.clear();

                        let resp_start = self.response_counter.load(Ordering::SeqCst);

                        for i in 0..self.config.batch_size() {
                            match self.socket.recv_from(&mut self.buf) {
                                Ok((num_bytes, src_addr)) => {
                                    if let Ok(nonce) = nonce_from_request(&self.buf, num_bytes) {
                                        self.requests.push((Vec::from(nonce), src_addr));
                                        self.merkle.push_leaf(nonce);
                                    } else {
                                        self.num_bad_requests += 1;
                                        info!(
                                            "Invalid request ({} bytes) from {} (#{} in batch, resp #{})",
                                            num_bytes, src_addr, i, resp_start + i as usize
                                        );
                                    }
                                }
                                Err(e) => match e.kind() {
                                    ErrorKind::WouldBlock => {
                                        done = true;
                                        break;
                                    }
                                    _ => {
                                        error!(
                                            "Error receiving from socket: {:?}: {:?}",
                                            e.kind(),
                                            e
                                        );
                                        break;
                                    }
                                },
                            };
                        }

                        if self.requests.is_empty() {
                            break 'process_batch;
                        }

                        let merkle_root = self.merkle.compute_root();
                        let srep = self.online_key.make_srep(time::get_time(), &merkle_root);

                        for (i, &(ref nonce, ref src_addr)) in self.requests.iter().enumerate() {
                            let paths = self.merkle.get_paths(i);

                            let resp = make_response(&srep, &self.cert_bytes, &paths, i as u32);
                            let resp_bytes = resp.encode().unwrap();

                            let bytes_sent = self.socket
                                .send_to(&resp_bytes, &src_addr)
                                .expect("send_to failed");
                            let num_responses = self.response_counter.fetch_add(1, Ordering::SeqCst);

                            info!(
                                "Responded {} bytes to {} for '{}..' (#{} in batch, resp #{})",
                                bytes_sent,
                                src_addr,
                                hex::encode(&nonce[0..4]),
                                i,
                                num_responses
                            );
                        }
                        if done {
                            break 'process_batch;
                        }
                    }
                }

                STATUS => {
                    info!(
                        "responses {}, invalid requests {}",
                        self.response_counter.load(Ordering::SeqCst),
                        self.num_bad_requests
                    );

                    self.timer.set_timeout(self.config.status_interval(), ());
                }

                _ => unreachable!(),
            }
        }
        false
    }

    pub fn send_to_self(&mut self, data: &[u8]) {
        self.socket.send_to(data, &self.socket.local_addr().unwrap());
    }

    pub fn get_public_key(&self) -> &str {
        return &self.public_key
    }

    pub fn get_online_key(&self) -> &OnlineKey {
        return &self.online_key
    }

    pub fn get_config(&self) -> &Box<ServerConfig> {
        return &self.config
    }
}
