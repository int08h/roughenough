//! Recvmmsg-based network I/O backend (Linux only).
//!
//! This backend uses the `recvmmsg` syscall to receive multiple UDP packets
//! in a single syscall, reducing syscall overhead under high load.
//!
//! # Requirements
//!
//! - Linux 2.6.33 or later
//!
//! # Performance
//!
//! On a busy server, this backend can receive and send up to `batch_size` packets
//! per syscall compared to the mio backend's one packet per syscall. This reduces
//! context switching and improves throughput.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::Duration;

use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use tracing::warn;

use super::{CollectResult, NetworkBackend};
use crate::metrics::network::NetworkMetrics;

const READER: Token = Token(0);
const MAX_BATCH: usize = 64;
const BUF_SIZE: usize = 1024;
/// Maximum response size for batch_size=64 (tree depth 6): 404 + 6*32 = 596 bytes.
/// Use 800 for safety margin.
const MAX_RESPONSE_SIZE: usize = 800;

/// Pre-allocated storage for a single message in recvmmsg batch.
///
/// This struct is designed for stable memory addresses - once allocated,
/// the addresses of its fields don't change.
#[repr(C)]
struct RecvBuffer {
    /// Buffer for packet data
    data: [u8; BUF_SIZE],
    /// Source address storage (length is stored in mmsghdr.msg_hdr.msg_namelen)
    addr: libc::sockaddr_storage,
}

impl Default for RecvBuffer {
    fn default() -> Self {
        Self {
            data: [0u8; BUF_SIZE],
            // SAFETY: sockaddr_storage is a C struct with only primitive types,
            // zero-initialization is valid.
            addr: unsafe { std::mem::zeroed() },
        }
    }
}

/// Pre-allocated storage for a single message in sendmmsg batch.
struct SendBuffer {
    /// Buffer for response data
    data: [u8; MAX_RESPONSE_SIZE],
    /// Length of data in buffer
    len: usize,
    /// Destination address in Rust format (for fallback to individual sends)
    std_addr: SocketAddr,
    /// Destination address in C format (for sendmmsg)
    c_addr: libc::sockaddr_storage,
    /// Length of the C address
    c_addr_len: libc::socklen_t,
}

impl Default for SendBuffer {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_RESPONSE_SIZE],
            len: 0,
            std_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            // SAFETY: sockaddr_storage is a C struct with only primitive types,
            // zero-initialization is valid.
            c_addr: unsafe { std::mem::zeroed() },
            c_addr_len: 0,
        }
    }
}

/// Recvmmsg/sendmmsg-based network backend using batched syscalls.
///
/// This backend receives and sends multiple packets per syscall using Linux's
/// `recvmmsg` and `sendmmsg` system calls, reducing syscall overhead when
/// processing high volumes of requests.
pub struct RecvmmsgBackend {
    socket: MioUdpSocket,
    poll: Poll,
    events: Events,
    batch_size: usize,
    metrics: NetworkMetrics,

    /// Pre-allocated receive buffers - boxed for stable addresses
    recv_buffers: Box<[RecvBuffer; MAX_BATCH]>,
    /// iovec structures pointing to recv_buffers
    recv_iovecs: Box<[libc::iovec; MAX_BATCH]>,
    /// msghdr structures for recvmmsg
    recv_msghdrs: Box<[libc::mmsghdr; MAX_BATCH]>,

    /// Pre-allocated send buffers - boxed for stable addresses
    send_buffers: Box<[SendBuffer; MAX_BATCH]>,
    /// iovec structures pointing to send_buffers
    send_iovecs: Box<[libc::iovec; MAX_BATCH]>,
    /// msghdr structures for sendmmsg
    send_msghdrs: Box<[libc::mmsghdr; MAX_BATCH]>,
    /// Number of responses queued for sending
    pending_sends: usize,
}

impl RecvmmsgBackend {
    /// Create a new RecvmmsgBackend wrapping the given socket.
    ///
    /// # Arguments
    ///
    /// * `socket` - A non-blocking UDP socket
    /// * `batch_size` - Maximum packets to receive per syscall (capped at 64)
    pub fn new(socket: MioUdpSocket, batch_size: usize) -> io::Result<Self> {
        let poll = Poll::new()?;
        let mut sock = socket;
        poll.registry()
            .register(&mut sock, READER, Interest::READABLE)?;

        let batch_size = batch_size.min(MAX_BATCH);

        // Allocate all receive structures with stable addresses
        let recv_buffers: Box<[RecvBuffer; MAX_BATCH]> =
            Box::new(std::array::from_fn(|_| RecvBuffer::default()));
        // SAFETY: iovec/mmsghdr contain only pointers and integers, zero is valid.
        // All pointers are overwritten in init_recv_structures() before use.
        let recv_iovecs: Box<[libc::iovec; MAX_BATCH]> = Box::new(unsafe { std::mem::zeroed() });
        let recv_msghdrs: Box<[libc::mmsghdr; MAX_BATCH]> = Box::new(unsafe { std::mem::zeroed() });

        // Allocate all send structures with stable addresses
        let send_buffers: Box<[SendBuffer; MAX_BATCH]> =
            Box::new(std::array::from_fn(|_| SendBuffer::default()));
        // SAFETY: Same as above - zeroed pointers overwritten in init_send_structures().
        let send_iovecs: Box<[libc::iovec; MAX_BATCH]> = Box::new(unsafe { std::mem::zeroed() });
        let send_msghdrs: Box<[libc::mmsghdr; MAX_BATCH]> = Box::new(unsafe { std::mem::zeroed() });

        let mut backend = Self {
            socket: sock,
            poll,
            events: Events::with_capacity(1),
            batch_size,
            metrics: NetworkMetrics::default(),
            recv_buffers,
            recv_iovecs,
            recv_msghdrs,
            send_buffers,
            send_iovecs,
            send_msghdrs,
            pending_sends: 0,
        };

        // Initialize pointers after allocation (addresses are now stable)
        backend.init_recv_structures();
        backend.init_send_structures();

        Ok(backend)
    }

    /// Initialize iovec and msghdr pointers to point to recv_buffers.
    ///
    /// This must be called after the Box allocations are complete so that
    /// the addresses are stable.
    fn init_recv_structures(&mut self) {
        for i in 0..MAX_BATCH {
            // SAFETY: Box provides stable heap addresses. These pointers remain valid
            // for the lifetime of RecvmmsgBackend since the Box fields are never replaced.
            self.recv_iovecs[i].iov_base =
                self.recv_buffers[i].data.as_mut_ptr() as *mut libc::c_void;
            self.recv_iovecs[i].iov_len = BUF_SIZE;

            self.recv_msghdrs[i].msg_hdr.msg_name =
                &mut self.recv_buffers[i].addr as *mut _ as *mut libc::c_void;
            self.recv_msghdrs[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            self.recv_msghdrs[i].msg_hdr.msg_iov = &mut self.recv_iovecs[i];
            self.recv_msghdrs[i].msg_hdr.msg_iovlen = 1;
            self.recv_msghdrs[i].msg_hdr.msg_control = std::ptr::null_mut();
            self.recv_msghdrs[i].msg_hdr.msg_controllen = 0;
            self.recv_msghdrs[i].msg_hdr.msg_flags = 0;
        }
    }

    /// Initialize iovec and msghdr pointers to point to send_buffers.
    ///
    /// This must be called after the Box allocations are complete so that
    /// the addresses are stable.
    fn init_send_structures(&mut self) {
        for i in 0..MAX_BATCH {
            // SAFETY: Box provides stable heap addresses. These pointers remain valid
            // for the lifetime of RecvmmsgBackend since the Box fields are never replaced.
            self.send_iovecs[i].iov_base =
                self.send_buffers[i].data.as_mut_ptr() as *mut libc::c_void;
            self.send_iovecs[i].iov_len = 0; // Set per-send in send_response

            self.send_msghdrs[i].msg_hdr.msg_name =
                &mut self.send_buffers[i].c_addr as *mut _ as *mut libc::c_void;
            self.send_msghdrs[i].msg_hdr.msg_namelen = 0; // Set per-send in send_response
            self.send_msghdrs[i].msg_hdr.msg_iov = &mut self.send_iovecs[i];
            self.send_msghdrs[i].msg_hdr.msg_iovlen = 1;
            self.send_msghdrs[i].msg_hdr.msg_control = std::ptr::null_mut();
            self.send_msghdrs[i].msg_hdr.msg_controllen = 0;
            self.send_msghdrs[i].msg_hdr.msg_flags = 0;
        }
    }

    /// Reset the address length fields before calling recvmmsg.
    ///
    /// The kernel writes the actual address length, so we need to reset
    /// these to the maximum size before each call.
    fn reset_recv_addr_lengths(&mut self) {
        let max_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        for i in 0..self.batch_size {
            self.recv_msghdrs[i].msg_hdr.msg_namelen = max_len;
        }
    }

    /// Convert a sockaddr_storage to a SocketAddr.
    fn sockaddr_to_std(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        if len == 0 {
            return None;
        }

        // Safety: we check the family field to determine the actual type
        let family = storage.ss_family as libc::c_int;

        match family {
            libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
                // Safety: we verified the family and length
                let sin: &libc::sockaddr_in =
                    unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
                // Safety: we verified the family and length
                let sin6: &libc::sockaddr_in6 =
                    unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }

    /// Convert a SocketAddr to sockaddr_storage.
    ///
    /// Returns the length of the address written to storage.
    fn std_to_sockaddr(addr: SocketAddr, storage: &mut libc::sockaddr_storage) -> libc::socklen_t {
        // SAFETY: sockaddr_storage is designed to hold any sockaddr type with proper
        // alignment. We have exclusive mutable access via &mut storage. We write the
        // entire struct to ensure no uninitialized padding bytes.
        match addr {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*v4.ip()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::write(storage as *mut _ as *mut libc::sockaddr_in, sin);
                }
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    },
                    sin6_scope_id: v6.scope_id(),
                };
                unsafe {
                    std::ptr::write(storage as *mut _ as *mut libc::sockaddr_in6, sin6);
                }
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }

    /// Send a single response individually (fallback for partial sendmmsg).
    ///
    /// This is used when sendmmsg returns WouldBlock, indicating the socket
    /// buffer is full. Individual sends may also fail with WouldBlock.
    fn send_individual(&mut self, idx: usize) {
        let buf = &self.send_buffers[idx];
        self.metrics.num_send_syscalls += 1;
        match self.socket.send_to(&buf.data[..buf.len], buf.std_addr) {
            Ok(_) => self.metrics.num_successful_sends += 1,
            Err(_) => self.metrics.num_failed_sends += 1,
        }
    }
}

impl NetworkBackend for RecvmmsgBackend {
    fn collect_requests<F>(&mut self, mut callback: F) -> CollectResult
    where
        F: FnMut(&mut [u8], SocketAddr),
    {
        // Reset address lengths before receiving
        self.reset_recv_addr_lengths();

        self.metrics.num_recv_syscalls += 1;

        // SAFETY: recv_msghdrs was initialized in init_recv_structures() with valid pointers
        // to recv_buffers. batch_size is capped at MAX_BATCH (64), matching array size.
        let n = unsafe {
            libc::recvmmsg(
                self.socket.as_raw_fd(),
                self.recv_msghdrs.as_mut_ptr(),
                self.batch_size as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(), // no timeout
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::WouldBlock => {
                    self.metrics.num_recv_wouldblock += 1;
                    return CollectResult::Empty;
                }
                io::ErrorKind::Interrupted => {
                    // EINTR: interrupted by signal, try again later
                    return CollectResult::MoreData;
                }
                _ => {
                    self.metrics.num_failed_recvs += 1;
                    return CollectResult::MoreData;
                }
            }
        }

        let count = n as usize;

        // Process each received message
        for i in 0..count {
            let msg_len = self.recv_msghdrs[i].msg_len as usize;
            let addr_len = self.recv_msghdrs[i].msg_hdr.msg_namelen;

            if let Some(addr) = Self::sockaddr_to_std(&self.recv_buffers[i].addr, addr_len) {
                callback(&mut self.recv_buffers[i].data[..msg_len], addr);
            }
        }

        // If we received a full batch, there may be more data
        if count >= self.batch_size {
            CollectResult::MoreData
        } else {
            CollectResult::Empty
        }
    }

    fn send_response(&mut self, data: &[u8], addr: SocketAddr) {
        // Auto-flush if buffer is full
        if self.pending_sends >= self.batch_size {
            self.flush();
        }

        let idx = self.pending_sends;
        let buf = &mut self.send_buffers[idx];

        // Copy response data (truncate if too large, though this shouldn't happen)
        let len = data.len().min(MAX_RESPONSE_SIZE);
        buf.data[..len].copy_from_slice(&data[..len]);
        buf.len = len;

        // Store both address formats: Rust for fallback, C for sendmmsg
        buf.std_addr = addr;
        buf.c_addr_len = Self::std_to_sockaddr(addr, &mut buf.c_addr);

        // Update iovec and msghdr inline (avoids loop in flush)
        self.send_iovecs[idx].iov_len = len;
        self.send_msghdrs[idx].msg_hdr.msg_namelen = buf.c_addr_len;

        self.pending_sends += 1;
    }

    fn flush(&mut self) {
        if self.pending_sends == 0 {
            return;
        }

        let mut remaining = self.pending_sends;
        let mut offset = 0;

        while remaining > 0 {
            self.metrics.num_send_syscalls += 1;

            // SAFETY: send_msghdrs was initialized in init_send_structures() with valid
            // pointers to send_buffers. offset + remaining <= pending_sends <= batch_size
            // <= MAX_BATCH, so we stay within bounds.
            debug_assert!(offset + remaining <= MAX_BATCH);
            let sent = unsafe {
                libc::sendmmsg(
                    self.socket.as_raw_fd(),
                    self.send_msghdrs[offset..].as_mut_ptr(),
                    remaining as libc::c_uint,
                    0,
                )
            };

            if sent < 0 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::Interrupted => {
                        // EINTR: retry immediately
                        continue;
                    }
                    io::ErrorKind::WouldBlock => {
                        // Socket buffer full - fall back to individual sends
                        for i in offset..(offset + remaining) {
                            self.send_individual(i);
                        }
                        break;
                    }
                    _ => {
                        self.metrics.num_failed_sends += remaining;
                        break;
                    }
                }
            } else if sent == 0 {
                // No messages sent (shouldn't happen, but handle it)
                self.metrics.num_failed_sends += remaining;
                break;
            } else {
                let sent = sent as usize;
                self.metrics.num_successful_sends += sent;
                offset += sent;
                remaining -= sent;
            }
        }

        self.pending_sends = 0;
    }

    fn wait_for_events(&mut self, timeout: Duration) -> bool {
        // Safety flush: ensure no responses are orphaned if caller forgot to flush
        if self.pending_sends > 0 {
            warn!(
                pending = self.pending_sends,
                "Safety flush: pending sends not explicitly flushed"
            );
            self.flush();
        }

        match self.poll.poll(&mut self.events, Some(timeout)) {
            Ok(_) => !self.events.is_empty(),
            Err(_) => {
                self.metrics.num_failed_polls += 1;
                false
            }
        }
    }

    fn metrics(&self) -> NetworkMetrics {
        self.metrics
    }

    fn reset_metrics(&mut self) {
        self.metrics = NetworkMetrics::default();
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    #[test]
    fn test_recvmmsg_backend_creation() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        let backend = RecvmmsgBackend::new(mio_socket, 64);
        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!(backend.batch_size, 64);
        assert_eq!(backend.metrics.num_recv_syscalls, 0);
    }

    #[test]
    fn test_recvmmsg_backend_empty_socket() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        let mut backend = RecvmmsgBackend::new(mio_socket, 64).expect("create backend");

        let result = backend.collect_requests(|_data, _addr| {
            panic!("should not receive any data");
        });

        assert_eq!(result, CollectResult::Empty);
        assert_eq!(backend.metrics.num_recv_wouldblock, 1);
        assert_eq!(backend.metrics.num_recv_syscalls, 1);
    }

    #[test]
    fn test_sockaddr_conversion_ipv4() {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sin: &mut libc::sockaddr_in =
            unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };

        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 8080u16.to_be();
        sin.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let addr = RecvmmsgBackend::sockaddr_to_std(&storage, len);

        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 8080);
        match addr {
            SocketAddr::V4(v4) => {
                assert_eq!(*v4.ip(), Ipv4Addr::new(127, 0, 0, 1));
            }
            _ => panic!("expected IPv4 address"),
        }
    }

    #[test]
    fn test_sockaddr_roundtrip_ipv4() {
        let original: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

        let len = RecvmmsgBackend::std_to_sockaddr(original, &mut storage);
        let converted = RecvmmsgBackend::sockaddr_to_std(&storage, len);

        assert!(converted.is_some());
        assert_eq!(converted.unwrap(), original);
    }

    #[test]
    fn test_sockaddr_roundtrip_ipv6() {
        let original: SocketAddr = "[::1]:8080".parse().unwrap();
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

        let len = RecvmmsgBackend::std_to_sockaddr(original, &mut storage);
        let converted = RecvmmsgBackend::sockaddr_to_std(&storage, len);

        assert!(converted.is_some());
        assert_eq!(converted.unwrap(), original);
    }

    #[test]
    fn test_send_response_queues_into_buffer() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        let mut backend = RecvmmsgBackend::new(mio_socket, 64).expect("create backend");

        assert_eq!(backend.pending_sends, 0);

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let data = [0u8; 100];

        backend.send_response(&data, addr);
        assert_eq!(backend.pending_sends, 1);
        assert_eq!(backend.send_buffers[0].len, 100);

        backend.send_response(&data, addr);
        assert_eq!(backend.pending_sends, 2);

        // Flush should reset pending_sends
        backend.flush();
        assert_eq!(backend.pending_sends, 0);
    }

    #[test]
    fn test_auto_flush_when_buffer_full() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        // Use small batch size to test auto-flush
        let mut backend = RecvmmsgBackend::new(mio_socket, 4).expect("create backend");

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let data = [0u8; 100];

        // Fill the buffer
        for _ in 0..4 {
            backend.send_response(&data, addr);
        }
        assert_eq!(backend.pending_sends, 4);

        // This should trigger auto-flush and then queue
        backend.send_response(&data, addr);
        assert_eq!(backend.pending_sends, 1); // Auto-flushed, then queued new one
    }

    #[test]
    fn test_flush_empty_does_nothing() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        let mut backend = RecvmmsgBackend::new(mio_socket, 64).expect("create backend");

        // Flush with nothing queued should be a no-op
        backend.flush();
        assert_eq!(backend.metrics.num_send_syscalls, 0);
    }
}
