use std::io;
use std::net::SocketAddr;

use mio::net::UdpSocket as MioUdpSocket;

use crate::metrics::types::NetworkMetrics;
use crate::network::CollectResult::{Empty, MoreData};

#[derive(Debug, Default)]
pub struct NetworkHandler {
    batch_size: usize,
    metrics: NetworkMetrics,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CollectResult {
    /// Socket was drained, no more data
    Empty,
    /// There may be more data left
    MoreData,
}

impl NetworkHandler {
    const RECV_BUFFER_SIZE: usize = 1024;

    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            metrics: NetworkMetrics::default(),
        }
    }

    pub fn collect_requests<F>(&mut self, sock: &mut MioUdpSocket, mut callback: F) -> CollectResult
    where
        F: FnMut(&mut [u8], SocketAddr),
    {
        let mut buf = [0u8; Self::RECV_BUFFER_SIZE];

        for _ in 0..self.batch_size {
            match sock.recv_from(&mut buf) {
                Ok((nbytes, src_addr)) => {
                    callback(&mut buf[..nbytes], src_addr);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.metrics.num_recv_wouldblock += 1;
                    return Empty;
                }
                Err(_) => {
                    self.metrics.num_failed_recvs += 1;
                    return MoreData;
                }
            }
        }
        MoreData
    }

    pub fn send_response(&mut self, sock: &mut MioUdpSocket, data: &[u8], addr: SocketAddr) {
        match sock.send_to(data, addr) {
            Ok(_) => {
                self.metrics.num_successful_sends += 1;
            }
            Err(_) => {
                self.metrics.num_failed_sends += 1;
            }
        }
    }

    pub fn metrics(&self) -> NetworkMetrics {
        self.metrics
    }

    pub fn reset_metrics(&mut self) {
        self.metrics = NetworkMetrics::default();
    }

    pub fn record_failed_poll(&mut self) {
        self.metrics.num_failed_polls += 1;
    }
}

#[cfg(test)]
mod tests {}
