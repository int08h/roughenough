//! Network I/O backend abstraction layer.
//!
//! This module provides a trait-based abstraction for network I/O operations,
//! allowing different backend implementations (mio, recvmmsg, io_uring) to be
//! swapped at runtime.
//!
//! # Backend Selection
//!
//! Backends are selected via the `--io-backend` CLI argument or the
//! `ROUGHENOUGH_IO_BACKEND` environment variable. Available backends:
//!
//! - `mio` (default): Poll-based I/O using the mio crate
//! - `recvmmsg` (Linux only): Batched syscalls using recvmmsg/sendmmsg

use std::net::SocketAddr;
use std::time::Duration;

use crate::metrics::network::NetworkMetrics;

/// Result of collecting requests from the network.
#[derive(Debug, Eq, PartialEq)]
pub enum CollectResult {
    /// Socket was drained, no more data available
    Empty,
    /// There may be more data available
    MoreData,
}

/// Trait abstracting network I/O operations.
///
/// Implementations provide different strategies for receiving and sending
/// UDP packets. The trait uses generics for the callback parameter, which
/// means implementations must be used with generic type parameters rather
/// than trait objects (`Box<dyn NetworkBackend>` won't work).
///
/// # Example
///
/// ```ignore
/// fn process_requests<B: NetworkBackend>(backend: &mut B) {
///     loop {
///         let result = backend.collect_requests(|data, addr| {
///             // Process each received packet
///         });
///         if result == CollectResult::Empty {
///             break;
///         }
///     }
/// }
/// ```
pub trait NetworkBackend {
    /// Collect incoming requests, calling the callback for each received packet.
    ///
    /// The callback receives a mutable reference to the packet data and the
    /// source address. Implementations may receive multiple packets per call
    /// (e.g., recvmmsg) or a single packet (e.g., mio).
    ///
    /// Returns `CollectResult::Empty` when no more data is available, or
    /// `CollectResult::MoreData` when additional data may be pending.
    fn collect_requests<F>(&mut self, callback: F) -> CollectResult
    where
        F: FnMut(&mut [u8], SocketAddr);

    /// Queue a response for sending to the given address.
    ///
    /// Implementations may send immediately (mio) or buffer for batched
    /// sending (recvmmsg with sendmmsg). Call `flush()` after queuing
    /// all responses to ensure they are sent.
    fn send_response(&mut self, data: &[u8], addr: SocketAddr);

    /// Flush any pending sends.
    ///
    /// Called after `generate_responses` completes to ensure all queued
    /// responses are transmitted. For backends that send immediately,
    /// this is a no-op.
    fn flush(&mut self);

    /// Wait for network events with the given timeout.
    ///
    /// Returns `true` if events are pending and ready to be processed,
    /// `false` if the timeout expired or an error occurred.
    fn wait_for_events(&mut self, timeout: Duration) -> bool;

    /// Get the current metrics snapshot.
    fn metrics(&self) -> NetworkMetrics;

    /// Reset all metrics counters to zero.
    fn reset_metrics(&mut self);
}

pub mod mio_backend;

#[cfg(target_os = "linux")]
pub mod recvmmsg_backend;

// Re-export backends for convenience
pub use mio_backend::MioBackend;
#[cfg(target_os = "linux")]
pub use recvmmsg_backend::RecvmmsgBackend;
