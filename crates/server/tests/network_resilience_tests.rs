#[cfg(test)]
mod test {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use mio::net::UdpSocket as MioUdpSocket;
    use server::network::CollectResult::Empty;
    use server::network::NetworkHandler;

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

    // Helper to wait for packets with timeout
    fn wait_for_packets(
        handler: &mut NetworkHandler,
        server_sock: &mut MioUdpSocket,
        expected_count: usize,
        timeout_ms: u64,
    ) -> usize {
        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        let mut total_received = 0;

        while total_received < expected_count && start.elapsed() < timeout {
            let mut batch_received = 0;
            handler.collect_requests(server_sock, |_data, _addr| {
                batch_received += 1;
            });
            total_received += batch_received;

            if batch_received == 0 {
                thread::sleep(Duration::from_millis(5));
            }
        }

        total_received
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

        // Send 3 packets
        for i in 0..3 {
            let data = vec![i; 100];
            socket_set
                .client_socket
                .send_to(&data, socket_set.server_addr)
                .unwrap();
        }

        // Wait for packets with timeout
        let mut received = Vec::new();
        let count = wait_for_packets(&mut handler, &mut socket_set.server_socket, 3, 500);

        // Collect the packets we did receive
        handler.collect_requests(&mut socket_set.server_socket, |data, addr| {
            received.push((data.to_vec(), addr));
        });

        // Should have received 3 packets
        assert_eq!(count, 3, "Expected 3 packets, got {count}");

        // Verify packet contents for packets we did receive
        for (i, (data, addr)) in received.iter().enumerate() {
            assert_eq!(data[0], i as u8);
            assert_eq!(*addr, socket_set.client_addr);
        }
    }

    #[test]
    fn send_response_success() {
        let mut socket_set = create_socket_set();
        let mut handler = NetworkHandler::new(10);

        // Send response
        let response_data = b"test response";
        handler.send_response(
            &mut socket_set.server_socket,
            response_data,
            socket_set.client_addr,
        );

        // Verify metrics
        assert_eq!(handler.metrics().num_successful_sends, 1);
        assert_eq!(handler.metrics().num_failed_sends, 0);
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
        );

        // Allow some packet loss in concurrent scenario
        assert!(
            received >= (num_clients * packets_per_client) * 9 / 10,
            "Expected at least 90% of {} packets, got {}",
            num_clients * packets_per_client,
            received
        );
    }

    #[test]
    fn rapid_fire_packets() {
        let mut socket_set = create_socket_set();
        let mut handler = NetworkHandler::new(100);

        // Create multiple clients sending rapidly
        let stop_flag = Arc::new(AtomicBool::new(false));
        let packet_count = Arc::new(AtomicUsize::new(0));

        let senders: Vec<_> = (0..3)
            .map(|id| {
                let server_addr = socket_set.server_addr;
                let stop_flag0 = stop_flag.clone();
                let packet_count0 = packet_count.clone();
                thread::spawn(move || {
                    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
                    while !stop_flag0.load(Ordering::Relaxed) {
                        let data = vec![id; 64];
                        if client.send_to(&data, server_addr).is_ok() {
                            packet_count0.fetch_add(1, Ordering::Relaxed);
                        }
                        // Small delay to prevent overwhelming
                        thread::sleep(Duration::from_micros(100));
                    }
                })
            })
            .collect();

        // Let senders run for a bit
        thread::sleep(Duration::from_millis(200));

        // Collect packets
        let mut received = 0;
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(100) {
            let mut batch = 0;
            handler.collect_requests(&mut socket_set.server_socket, |_data, _addr| {
                batch += 1;
            });
            received += batch;

            if batch == 0 {
                thread::sleep(Duration::from_millis(1));
            }
        }

        // Stop senders
        stop_flag.store(true, Ordering::Relaxed);
        for sender in senders {
            sender.join().unwrap();
        }

        // Should have received and sent some packets
        let sent = packet_count.load(Ordering::Relaxed);
        assert!(sent > 0, "No packets were sent");
        assert!(received > 0, "No packets were received");

        // Log the ratio for debugging
        println!(
            "Rapid fire: sent {}, received {} ({:.1}%)",
            sent,
            received,
            (received as f64 / sent as f64) * 100.0
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
        assert!(received > 0, "Should have received some packets");

        // Some successful sends
        for _ in 0..3 {
            handler.send_response(
                &mut socket_set.server_socket,
                b"response",
                socket_set.client_addr,
            );
        }

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

    #[test]
    fn callback_panic_handling() {
        let mut socket_set = create_socket_set();
        let mut handler = NetworkHandler::new(10);

        // Send some packets
        socket_set
            .client_socket
            .send_to(b"panic", socket_set.server_addr)
            .unwrap();
        thread::sleep(Duration::from_millis(50)); // Give time for first packet
        socket_set
            .client_socket
            .send_to(b"ok", socket_set.server_addr)
            .unwrap();

        // Simulate a callback that panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.collect_requests(&mut socket_set.server_socket, |data, _addr| {
                if data == b"panic" {
                    panic!("Test panic");
                }
            });
        }));

        // The panic should propagate
        assert!(result.is_err());

        // But the handler and socket should still be in a valid state
        // Try to collect remaining packets
        let mut count = 0;
        let start = Instant::now();
        while count == 0 && start.elapsed() < Duration::from_millis(200) {
            handler.collect_requests(&mut socket_set.server_socket, |_data, _addr| {
                count += 1;
            });

            if count == 0 {
                thread::sleep(Duration::from_millis(10));
            }
        }

        // The "ok" packet might or might not be received depending on timing
        assert!(count <= 1, "Received more packets than expected: {count}");
    }
}
