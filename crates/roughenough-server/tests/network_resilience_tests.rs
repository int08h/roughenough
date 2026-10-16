use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::UdpSocket as MioUdpSocket;
use roughenough_protocol::request::{MAX_REQUEST_SIZE, Request};
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::wire::ToFrame;
use roughenough_server::network::CollectResult::Empty;
use roughenough_server::network::NetworkHandler;

struct SocketSet {
    server_socket: MioUdpSocket,
    client_socket: UdpSocket,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
}

fn create_socket_set() -> SocketSet {
    let server_socket = MioUdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client_addr = client_socket.local_addr().unwrap();

    SocketSet {
        server_socket,
        client_socket,
        server_addr,
        client_addr,
    }
}

/// Collect until `expected_count` packets arrive or `timeout_ms` passes
fn wait_for_packets(
    handler: &mut NetworkHandler,
    server_sock: &mut MioUdpSocket,
    expected_count: usize,
    timeout_ms: u64,
) -> Vec<(Vec<u8>, SocketAddr)> {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut received = Vec::new();

    while received.len() < expected_count && start.elapsed() < timeout {
        let before = received.len();
        handler.collect_requests(server_sock, |data, addr| {
            received.push((data.to_vec(), addr));
        });

        if received.len() == before {
            thread::sleep(Duration::from_millis(5));
        }
    }

    received
}

#[test]
fn wouldblock_handling() {
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(10);

    // Try to receive when no data is available
    let mut received_count = 0;
    let drained = handler.collect_requests(&mut socket_set.server_socket, |_data, _addr| {
        received_count += 1;
    });

    // Should return `Empty` (socket drained) with no data received
    assert_eq!(drained, Empty);
    assert_eq!(received_count, 0);
    assert_eq!(handler.metrics().num_recv_wouldblock, 1);
}

#[test]
fn partial_batch_collection() {
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(10);

    for i in 0..3 {
        let data = vec![i; 100];
        socket_set
            .client_socket
            .send_to(&data, socket_set.server_addr)
            .unwrap();
    }

    let received = wait_for_packets(&mut handler, &mut socket_set.server_socket, 3, 500);

    assert_eq!(
        received.len(),
        3,
        "Expected 3 packets, got {}",
        received.len()
    );

    // loopback UDP preserves send order
    for (i, (data, addr)) in received.iter().enumerate() {
        assert_eq!(*data, vec![i as u8; 100], "packet {i} not delivered intact");
        assert_eq!(*addr, socket_set.client_addr);
    }
}

/// Valid framed request padded with zeros to `total_len` bytes
fn padded_request(nonce_value: u8, total_len: usize) -> Vec<u8> {
    let nonce = Nonce::from([nonce_value; 32]);
    let mut bytes = Request::new(&nonce).as_frame_bytes().unwrap();
    assert!(bytes.len() <= total_len);
    bytes.resize(total_len, 0);
    bytes
}

#[test]
fn oversized_datagrams_are_dropped_without_callback() {
    // Datagrams larger than MAX_REQUEST_SIZE would be silently truncated
    // by recv_from; answering the truncated bytes would Merkle-hash a leaf
    // differing from the packet the client sent. They must be dropped
    // entirely, never delivered to the request path.
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(10);

    // both datagrams begin with a valid framed request
    let just_over = padded_request(1, MAX_REQUEST_SIZE + 1);
    let way_over = padded_request(2, 2024);

    socket_set
        .client_socket
        .send_to(&just_over, socket_set.server_addr)
        .unwrap();
    socket_set
        .client_socket
        .send_to(&way_over, socket_set.server_addr)
        .unwrap();

    // dropped datagrams never reach the callback, so poll the drop metric
    let start = Instant::now();
    let mut delivered = 0;
    while handler.metrics().num_oversized_dropped < 2
        && start.elapsed() < Duration::from_millis(500)
    {
        handler.collect_requests(&mut socket_set.server_socket, |_data, _addr| {
            delivered += 1;
        });
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(handler.metrics().num_oversized_dropped, 2);
    assert_eq!(
        delivered, 0,
        "truncated datagrams must not reach the request path"
    );
}

#[test]
fn max_size_datagram_is_delivered() {
    // Regression for the oversized-drop change: exactly MAX_REQUEST_SIZE
    // bytes is a legal request and must still be delivered intact
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(10);

    let request = padded_request(3, MAX_REQUEST_SIZE);
    socket_set
        .client_socket
        .send_to(&request, socket_set.server_addr)
        .unwrap();

    let start = Instant::now();
    let mut received = Vec::new();
    while received.is_empty() && start.elapsed() < Duration::from_millis(500) {
        handler.collect_requests(&mut socket_set.server_socket, |data, _addr| {
            received.push(data.to_vec());
        });
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(received.len(), 1);
    assert_eq!(received[0].len(), MAX_REQUEST_SIZE);
    assert_eq!(received[0], request);
    assert_eq!(handler.metrics().num_oversized_dropped, 0);
}

#[test]
fn full_batch_of_queued_responses_all_arrive() {
    // The batched flush (sendmmsg on Linux, send_to loop elsewhere) must
    // deliver every queued response; loopback with a default receive
    // buffer holds 64 small datagrams without loss
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(64);
    socket_set
        .client_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    for i in 0..64u8 {
        let payload = [i; 600];
        handler.queue_response(&payload, socket_set.client_addr);
    }
    handler.flush_responses(&mut socket_set.server_socket);

    assert_eq!(handler.metrics().num_successful_sends, 64);
    assert_eq!(handler.metrics().num_failed_sends, 0);

    let mut buf = [0u8; 1500];
    for i in 0..64u8 {
        let (nbytes, _) = socket_set
            .client_socket
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("datagram {i} missing: {e}"));
        assert_eq!(nbytes, 600);
        // loopback UDP preserves send order
        assert!(
            buf[..nbytes].iter().all(|b| *b == i),
            "datagram {i} corrupt"
        );
    }
}

#[test]
fn flush_with_empty_queue_is_a_no_op() {
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(8);

    handler.flush_responses(&mut socket_set.server_socket);

    assert_eq!(handler.metrics().num_successful_sends, 0);
    assert_eq!(handler.metrics().num_failed_sends, 0);
}

#[test]
fn queued_response_is_delivered() {
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(10);
    socket_set
        .client_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let response_data = b"test response";
    handler.queue_response(response_data, socket_set.client_addr);
    handler.flush_responses(&mut socket_set.server_socket);

    assert_eq!(handler.metrics().num_successful_sends, 1);
    assert_eq!(handler.metrics().num_failed_sends, 0);

    let mut buf = [0u8; 1500];
    let (nbytes, from) = socket_set
        .client_socket
        .recv_from(&mut buf)
        .expect("queued response was not delivered");
    assert_eq!(&buf[..nbytes], response_data);
    assert_eq!(from, socket_set.server_addr);
}

#[test]
fn concurrent_request_handling() {
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(10);

    // Spawn multiple client threads
    let num_clients = 5;
    let packets_per_client = 20;

    let threads: Vec<_> = (0..num_clients)
        .map(|client_id| {
            thread::spawn(move || {
                let client = UdpSocket::bind("127.0.0.1:0").unwrap();
                for packet_id in 0..packets_per_client {
                    let data = vec![client_id as u8, packet_id as u8];
                    let _ = client.send_to(&data, socket_set.server_addr); // Ignore errors
                    thread::sleep(Duration::from_micros(500));
                }
            })
        })
        .collect();

    // Wait for all clients to finish
    for t in threads {
        t.join().unwrap();
    }

    // Collect packets with generous timeout
    let received = wait_for_packets(
        &mut handler,
        &mut socket_set.server_socket,
        num_clients * packets_per_client,
        2000,
    )
    .len();

    // Allow some packet loss in concurrent scenario
    assert!(
        received >= (num_clients * packets_per_client) * 9 / 10,
        "Expected at least 90% of {} packets, got {}",
        num_clients * packets_per_client,
        received
    );
}

#[test]
fn metrics_accumulation() {
    let mut socket_set = create_socket_set();
    let mut handler = NetworkHandler::new(2);

    // Generate various operations

    // Some successful receives
    for i in 0..5 {
        socket_set
            .client_socket
            .send_to(&[i], socket_set.server_addr)
            .unwrap();
    }

    // Wait for packets
    let received = wait_for_packets(&mut handler, &mut socket_set.server_socket, 5, 500);
    assert!(!received.is_empty(), "Should have received some packets");

    // Some successful sends
    for _ in 0..3 {
        handler.queue_response(b"response", socket_set.client_addr);
    }
    handler.flush_responses(&mut socket_set.server_socket);

    // Record some failed polls
    handler.record_failed_poll();
    handler.record_failed_poll();

    // Check accumulated metrics
    let metrics = handler.metrics();
    assert!(metrics.num_recv_wouldblock >= 1); // At least one from draining
    assert_eq!(metrics.num_successful_sends, 3);
    assert_eq!(metrics.num_failed_polls, 2);

    // Reset and verify
    handler.reset_metrics();
    let metrics = handler.metrics();
    assert_eq!(metrics.num_recv_wouldblock, 0);
    assert_eq!(metrics.num_successful_sends, 0);
    assert_eq!(metrics.num_failed_polls, 0);
}
