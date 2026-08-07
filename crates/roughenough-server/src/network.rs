use std::io;
use std::net::SocketAddr;
use std::ops::Range;

use mio::net::UdpSocket as MioUdpSocket;
use roughenough_protocol::request;

use crate::metrics::types::NetworkMetrics;
use crate::network::CollectResult::{Empty, MoreData};

/// One response staged for a batched flush: its bytes live in
/// `NetworkHandler::send_bufs` at `range`.
struct QueuedResponse {
    range: Range<usize>,
    addr: SocketAddr,
}

pub struct NetworkHandler {
    batch_size: usize,
    metrics: NetworkMetrics,
    /// Receive buffer, one byte larger than the largest valid request:
    /// recv_from silently truncates bigger datagrams, and answering a
    /// truncated request would Merkle-hash bytes differing from what the
    /// client sent (RFC 5.3 hashes the full request packet), manufacturing a
    /// false proof of malfeasance. The extra byte distinguishes "exactly
    /// MAX_REQUEST_SIZE" from "truncated". A field rather than a
    /// `collect_requests` local so the 1473 bytes are not re-zeroed on every
    /// call (up to 8x per wakeup).
    recv_buf: [u8; request::MAX_REQUEST_SIZE + 1],
    /// Flat storage for queued response bytes, drained by `flush_responses`
    send_bufs: Vec<u8>,
    send_msgs: Vec<QueuedResponse>,
    #[cfg(target_os = "linux")]
    mmsg_state: mmsg::MmsgState,
}

impl std::fmt::Debug for NetworkHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkHandler")
            .field("batch_size", &self.batch_size)
            .field("metrics", &self.metrics)
            .field("queued_responses", &self.send_msgs.len())
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CollectResult {
    /// Socket was drained, no more data
    Empty,
    /// There may be more data left
    MoreData,
}

impl NetworkHandler {
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            metrics: NetworkMetrics::default(),
            recv_buf: [0u8; request::MAX_REQUEST_SIZE + 1],
            // sized so a full batch of maximum-size responses queues without
            // reallocating: the worker loop must stay allocation-free in
            // steady state (tests/alloc_tests.rs)
            send_bufs: Vec::with_capacity(batch_size * crate::responses::RESPONSE_BUF_SIZE),
            send_msgs: Vec::with_capacity(batch_size),
            #[cfg(target_os = "linux")]
            mmsg_state: mmsg::MmsgState::with_capacity(batch_size),
        }
    }

    pub fn collect_requests<F>(&mut self, sock: &mut MioUdpSocket, mut callback: F) -> CollectResult
    where
        F: FnMut(&mut [u8], SocketAddr),
    {
        for _ in 0..self.batch_size {
            match sock.recv_from(&mut self.recv_buf) {
                Ok((nbytes, _)) if nbytes > request::MAX_REQUEST_SIZE => {
                    // dropped with no response, matching the RFC posture of
                    // ignoring invalid requests (see `recv_buf` for why the
                    // size cutoff exists)
                    self.metrics.num_oversized_dropped += 1;
                }
                Ok((nbytes, src_addr)) => {
                    callback(&mut self.recv_buf[..nbytes], src_addr);
                }
                Err(e) => return self.record_recv_error(&e),
            }
        }
        MoreData
    }

    /// Both error classes send the worker loop back to `poll`: WouldBlock
    /// means the socket is drained, and any other error must not re-enter the
    /// receive loop without polling, which would busy-spin a worker at 100%
    /// CPU if the error is persistent. Deliberately not logged (a persistent
    /// error would flood the logs); the counters surface it through the
    /// periodic metrics reporting.
    fn record_recv_error(&mut self, error: &io::Error) -> CollectResult {
        if error.kind() == io::ErrorKind::WouldBlock {
            self.metrics.num_recv_wouldblock += 1;
        } else {
            self.metrics.num_failed_recvs += 1;
        }
        Empty
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

    /// Stage a response for the next `flush_responses`. Batching the sends
    /// lets Linux deliver a whole batch with one `sendmmsg` syscall instead
    /// of one `send_to` per response.
    pub fn queue_response(&mut self, data: &[u8], addr: SocketAddr) {
        let start = self.send_bufs.len();
        self.send_bufs.extend_from_slice(data);
        self.send_msgs.push(QueuedResponse {
            range: start..self.send_bufs.len(),
            addr,
        });
    }

    /// Send every queued response. On Linux the queue goes out via
    /// `sendmmsg`, resuming after partial sends; a send error drops the
    /// remaining queued responses (UDP is best-effort, and the plausible
    /// errors on an unconnected nonblocking socket would fail the rest of
    /// the batch too). Elsewhere each response is sent individually.
    pub fn flush_responses(&mut self, sock: &mut MioUdpSocket) {
        #[cfg(target_os = "linux")]
        {
            let bufs = &self.send_bufs;
            let state = &mut self.mmsg_state;
            let (sent, failed) =
                drain_queue(&self.send_msgs, |msgs| state.send_batch(sock, bufs, msgs));
            self.metrics.num_successful_sends += sent;
            self.metrics.num_failed_sends += failed;
        }

        #[cfg(not(target_os = "linux"))]
        for msg in &self.send_msgs {
            match sock.send_to(&self.send_bufs[msg.range.clone()], msg.addr) {
                Ok(_) => self.metrics.num_successful_sends += 1,
                Err(_) => self.metrics.num_failed_sends += 1,
            }
        }

        self.send_msgs.clear();
        self.send_bufs.clear();
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

/// Drive `send_batch` until the queue is empty or a send fails, resuming from
/// the first unsent message after a partial send. Returns `(sent, failed)`.
#[cfg(target_os = "linux")]
fn drain_queue<F>(msgs: &[QueuedResponse], mut send_batch: F) -> (usize, usize)
where
    F: FnMut(&[QueuedResponse]) -> io::Result<usize>,
{
    let mut sent = 0;
    while sent < msgs.len() {
        match send_batch(&msgs[sent..]) {
            // a zero return without an error cannot make progress; treat the
            // remainder as failed rather than spinning
            Ok(0) | Err(_) => break,
            Ok(n) => sent += n,
        }
    }
    (sent, msgs.len() - sent)
}

/// `sendmmsg` support. The only unsafe code in this crate lives here; the
/// crate-level `#![deny(unsafe_code)]` is relaxed for this module alone.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod mmsg {
    use std::io;
    use std::os::fd::AsRawFd;

    use mio::net::UdpSocket as MioUdpSocket;

    use super::QueuedResponse;

    /// Reusable `sendmmsg` argument storage, preallocated so steady-state
    /// flushes never allocate.
    pub(super) struct MmsgState {
        addrs: Vec<socket2::SockAddr>,
        iovecs: Vec<libc::iovec>,
        hdrs: Vec<libc::mmsghdr>,
    }

    // SAFETY: `iovec`/`mmsghdr` are !Send only because they hold raw
    // pointers. Those pointers are created and consumed within a single
    // `send_batch` call while `&mut self` is held; between calls they are
    // stale and never dereferenced, so moving this storage to another thread
    // cannot race or alias anything.
    unsafe impl Send for MmsgState {}

    impl MmsgState {
        pub(super) fn with_capacity(batch_size: usize) -> Self {
            Self {
                addrs: Vec::with_capacity(batch_size),
                iovecs: Vec::with_capacity(batch_size),
                hdrs: Vec::with_capacity(batch_size),
            }
        }

        /// Send `msgs` (whose payloads live in `bufs`) with one `sendmmsg`
        /// call. Returns the number of messages actually sent.
        ///
        /// SAFETY contract upheld by construction:
        /// - every `iovec` points into `bufs`, which outlives the call and is
        ///   not mutated while the pointers exist;
        /// - every `msg_name` points at a `socket2::SockAddr` held alive in
        ///   `self.addrs` for the duration of the call, with `msg_namelen`
        ///   taken from that same address;
        /// - `msg_iov` points at the corresponding element of `self.iovecs`,
        ///   which is not resized between pointer creation and the syscall
        ///   (both Vecs are filled to `msgs.len()` before any pointer is
        ///   taken);
        /// - the fd comes from a live `MioUdpSocket` borrowed for the call.
        pub(super) fn send_batch(
            &mut self,
            sock: &MioUdpSocket,
            bufs: &[u8],
            msgs: &[QueuedResponse],
        ) -> io::Result<usize> {
            let Self {
                addrs,
                iovecs,
                hdrs,
            } = self;

            addrs.clear();
            iovecs.clear();
            hdrs.clear();

            for msg in msgs {
                addrs.push(socket2::SockAddr::from(msg.addr));
                let payload = &bufs[msg.range.clone()];
                iovecs.push(libc::iovec {
                    iov_base: payload.as_ptr() as *mut libc::c_void,
                    iov_len: payload.len(),
                });
            }

            for (addr, iovec) in addrs.iter().zip(iovecs.iter_mut()) {
                // zeroed: msghdr has platform-dependent padding fields
                let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
                msg_hdr.msg_name = addr.as_ptr() as *mut libc::c_void;
                msg_hdr.msg_namelen = addr.len();
                msg_hdr.msg_iov = iovec;
                msg_hdr.msg_iovlen = 1;
                hdrs.push(libc::mmsghdr {
                    msg_hdr,
                    msg_len: 0,
                });
            }

            let rc = unsafe {
                libc::sendmmsg(
                    sock.as_raw_fd(),
                    hdrs.as_mut_ptr(),
                    hdrs.len() as libc::c_uint,
                    0,
                )
            };

            if rc < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(rc as usize)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wouldblock_recv_error_returns_empty_and_is_counted() {
        let mut handler = NetworkHandler::new(4);
        let error = io::Error::from(io::ErrorKind::WouldBlock);

        assert_eq!(handler.record_recv_error(&error), Empty);
        assert_eq!(handler.metrics().num_recv_wouldblock, 1);
        assert_eq!(handler.metrics().num_failed_recvs, 0);
    }

    #[test]
    fn non_wouldblock_recv_error_returns_empty_and_is_counted() {
        // Returning the WouldBlock variant (Empty) sends the loop back to
        // poll; MoreData would unconditionally re-enter the receive loop and
        // spin on a persistent socket error
        let mut handler = NetworkHandler::new(4);
        let error = io::Error::other("injected receive failure");

        assert_eq!(handler.record_recv_error(&error), Empty);
        assert_eq!(handler.metrics().num_failed_recvs, 1);
        assert_eq!(handler.metrics().num_recv_wouldblock, 0);
    }

    #[cfg(target_os = "linux")]
    fn queued(n: usize) -> Vec<QueuedResponse> {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        (0..n)
            .map(|i| QueuedResponse {
                range: i..i + 1,
                addr,
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drain_queue_resumes_after_partial_sends() {
        let msgs = queued(7);
        let mut offsets_seen = Vec::new();

        let (sent, failed) = drain_queue(&msgs, |remaining| {
            offsets_seen.push(msgs.len() - remaining.len());
            // partial send: at most 3 messages per call
            Ok(remaining.len().min(3))
        });

        assert_eq!((sent, failed), (7, 0));
        // resumed from the first unsent message each time
        assert_eq!(offsets_seen, vec![0, 3, 6]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drain_queue_counts_remainder_as_failed_on_error() {
        let msgs = queued(5);
        let mut calls = 0;

        let (sent, failed) = drain_queue(&msgs, |remaining| {
            calls += 1;
            if calls == 1 {
                Ok(remaining.len().min(2))
            } else {
                Err(io::Error::other("injected send failure"))
            }
        });

        assert_eq!((sent, failed), (2, 3));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drain_queue_stops_on_zero_progress() {
        let msgs = queued(4);
        let mut calls = 0;

        let (sent, failed) = drain_queue(&msgs, |_| {
            calls += 1;
            Ok(0)
        });

        assert_eq!((sent, failed), (0, 4));
        assert_eq!(calls, 1, "a zero return must not be retried");
    }
}
