//! Linux-only: checks the kernel applies `filter::PROGRAM` as the
//! interpreter in `filter.rs` predicts. See `doc/BPF-FILTER.md`.
#![cfg(target_os = "linux")]

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use roughenough_protocol::request::{MAX_REQUEST_SIZE, REQUEST_SIZE, Request};
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::wire::ToFrame;
use roughenough_server::filter;
use socket2::{Domain, Socket, Type};

fn filtered_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;
    filter::attach(&socket)?;
    socket.bind(&addr.into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(Duration::from_millis(300)))?;
    Ok(socket)
}

fn valid_request(len: usize) -> Vec<u8> {
    let mut request = Request::new(&Nonce::from([7; 32]))
        .as_frame_bytes()
        .unwrap();
    request.resize(len, 0);
    request
}

/// Send every datagram, then return the lengths of those that arrive
fn delivered_lengths(server: &UdpSocket, client: &UdpSocket, datagrams: &[Vec<u8>]) -> Vec<usize> {
    let server_addr = server.local_addr().unwrap();
    for datagram in datagrams {
        client.send_to(datagram, server_addr).unwrap();
    }

    let mut lengths = Vec::new();
    let mut buf = vec![0u8; 65_536];
    loop {
        match server.recv_from(&mut buf) {
            Ok((n, _)) => lengths.push(n),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return lengths;
            }
            Err(e) => panic!("recv_from: {e}"),
        }
    }
}

fn check_filter(loopback: &str) {
    let addr: SocketAddr = format!("{loopback}:0").parse().unwrap();
    let server = match filtered_socket(addr) {
        Ok(s) => s,
        Err(e) if loopback.contains(':') => {
            eprintln!("skipping IPv6 check, {loopback} unavailable: {e}");
            return;
        }
        Err(e) => panic!("filtered socket: {e}"),
    };
    let client = UdpSocket::bind(addr).unwrap();

    let mut bad_magic = valid_request(REQUEST_SIZE);
    bad_magic[0] = b'X';

    let datagrams = [
        vec![0u8; 100],                      // runt
        valid_request(REQUEST_SIZE - 1),     // one byte short
        bad_magic,                           // right size, wrong magic
        valid_request(MAX_REQUEST_SIZE + 1), // oversized
        valid_request(8_000),                // fragmented on a 1500 MTU
        valid_request(REQUEST_SIZE),         // accepted
        valid_request(MAX_REQUEST_SIZE),     // accepted
    ];

    let lengths = delivered_lengths(&server, &client, &datagrams);
    assert_eq!(lengths, vec![REQUEST_SIZE, MAX_REQUEST_SIZE], "{loopback}");
}

#[test]
fn kernel_drops_invalid_datagrams_ipv4() {
    check_filter("127.0.0.1");
}

#[test]
fn kernel_drops_invalid_datagrams_ipv6() {
    check_filter("[::1]");
}
