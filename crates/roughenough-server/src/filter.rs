//! Classic BPF socket filter for early, in-kernel drop of datagrams which are
//! definitely not valid requests. Evaluated prior to the packet being queued on
//! the worker's socket.
//!
//! This is 'classic' BPF and not eBPF as classic doesn't require elevated
//! privileges or capability grants.
//!
//! See `doc/BPF-FILTER.md` for design notes and how to test on Linux.

use roughenough_protocol::request::{MAX_REQUEST_SIZE, REQUEST_SIZE};
use roughenough_protocol::wire::FRAME_MAGIC;

/// A classic BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16, // OR'ed together: instruction class, operand size, and addressing mode/jump test
    pub jt: u8,    // # of instructions to skip when conditional jump test is true
    pub jf: u8,    // # of instructions to skip when conditional jump test is false
    pub k: u32,    // Constant operand: load offset, value to compare against, or return value
}

// Opcode bits from linux/filter.h. Defined here so the program builds and
// tests on every platform. A Linux test checks them against libc.
pub(crate) const BPF_LD: u16 = 0x00;
pub(crate) const BPF_JMP: u16 = 0x05;
pub(crate) const BPF_RET: u16 = 0x06;
pub(crate) const BPF_W: u16 = 0x00;
pub(crate) const BPF_ABS: u16 = 0x20;
pub(crate) const BPF_LEN: u16 = 0x80;
pub(crate) const BPF_JEQ: u16 = 0x10;
pub(crate) const BPF_JGT: u16 = 0x20;
pub(crate) const BPF_JGE: u16 = 0x30;
pub(crate) const BPF_K: u16 = 0x00;

const UDP_HEADER_LEN: u32 = 8;

const MIN_LEN: u32 = UDP_HEADER_LEN + REQUEST_SIZE as u32;
const MAX_LEN: u32 = UDP_HEADER_LEN + MAX_REQUEST_SIZE as u32;
const MAGIC_HI: u32 = (FRAME_MAGIC >> 32) as u32; // "ROUG"
const MAGIC_LO: u32 = FRAME_MAGIC as u32; // "HTIM"

/// Return value that keeps the whole datagram; 0 drops it.
const ACCEPT: u32 = u32::MAX;
const DROP: u32 = 0;

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

/// Accept only datagrams whose UDP payload is 1024 to 1472 bytes and begins
/// with the `ROUGHTIM` magic and drop everything else. Jump offsets count
/// instructions skipped after the jump.
#[rustfmt::skip]
pub const PROGRAM: [Insn; 9] = [
    insn(BPF_LD  | BPF_W   | BPF_LEN, 0, 0, 0),
    insn(BPF_JMP | BPF_JGT | BPF_K  , 6, 0, MAX_LEN),
    insn(BPF_JMP | BPF_JGE | BPF_K  , 0, 5, MIN_LEN),
    insn(BPF_LD  | BPF_W   | BPF_ABS, 0, 0, UDP_HEADER_LEN),
    insn(BPF_JMP | BPF_JEQ | BPF_K  , 0, 3, MAGIC_HI),
    insn(BPF_LD  | BPF_W   | BPF_ABS, 0, 0, UDP_HEADER_LEN + 4),
    insn(BPF_JMP | BPF_JEQ | BPF_K  , 0, 1, MAGIC_LO),
    insn(BPF_RET | BPF_K            , 0, 0, ACCEPT),
    insn(BPF_RET | BPF_K            , 0, 0, DROP),
];

/// Attach [`PROGRAM`] to `socket`. Call before `bind` so no datagram is
/// queued unfiltered.
#[cfg(target_os = "linux")]
pub fn attach(socket: &socket2::Socket) -> std::io::Result<()> {
    let program = PROGRAM.map(|i| socket2::SockFilter::new(i.code, i.jt, i.jf, i.k));
    socket.attach_filter(&program)
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::request::Request;
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::wire::ToFrame;

    use super::*;

    /// Minimal interpreter for the instructions [`PROGRAM`] uses, following
    /// the kernel's semantics: big-endian absolute loads, and an
    /// out-of-bounds load drops the packet.
    fn run(program: &[Insn], packet: &[u8]) -> u32 {
        let mut acc = 0u32;
        let mut pc = 0usize;

        loop {
            let i = program[pc];
            pc += 1;

            match i.code {
                c if c == BPF_LD | BPF_W | BPF_LEN => acc = packet.len() as u32,
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    let off = i.k as usize;
                    let Some(bytes) = packet.get(off..off + 4) else {
                        return DROP;
                    };
                    acc = u32::from_be_bytes(bytes.try_into().unwrap());
                }
                c if c & 0x07 == BPF_JMP => {
                    let taken = match c & 0xf0 {
                        BPF_JEQ => acc == i.k,
                        BPF_JGT => acc > i.k,
                        BPF_JGE => acc >= i.k,
                        op => panic!("unsupported jump {op:#x}"),
                    };
                    pc += usize::from(if taken { i.jt } else { i.jf });
                }
                c if c == BPF_RET | BPF_K => return i.k,
                c => {
                    panic!("unsupported opcode {c:#x}")
                }
            }
        }
    }

    /// A UDP datagram as the filter sees it: header, then `payload`
    fn datagram(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; UDP_HEADER_LEN as usize];
        packet.extend_from_slice(payload);
        packet
    }

    fn valid_request() -> Vec<u8> {
        Request::new(&Nonce::from([7; 32]))
            .as_frame_bytes()
            .unwrap()
    }

    #[test]
    fn valid_request_is_accepted() {
        assert_eq!(run(&PROGRAM, &datagram(&valid_request())), ACCEPT);
    }

    #[test]
    fn size_bounds_match_userspace_limits() {
        let mut payload = valid_request();

        payload.truncate(REQUEST_SIZE - 1);
        assert_eq!(run(&PROGRAM, &datagram(&payload)), DROP, "runt");

        payload.resize(MAX_REQUEST_SIZE, 0);
        assert_eq!(run(&PROGRAM, &datagram(&payload)), ACCEPT, "full MTU");

        payload.push(0);
        assert_eq!(run(&PROGRAM, &datagram(&payload)), DROP, "oversized");
    }

    #[test]
    fn wrong_magic_is_dropped() {
        for idx in [0, 3, 4, 7] {
            let mut payload = valid_request();
            payload[idx] ^= 0x20;
            assert_eq!(run(&PROGRAM, &datagram(&payload)), DROP, "byte {idx}");
        }
    }

    #[test]
    fn tiny_and_empty_datagrams_are_dropped() {
        for len in [0, 1, 4, 12] {
            assert_eq!(run(&PROGRAM, &datagram(&vec![0; len])), DROP, "{len}");
        }
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        for (pc, i) in PROGRAM.iter().enumerate() {
            if i.code & 0x07 == BPF_JMP {
                for off in [i.jt, i.jf] {
                    assert!(pc + 1 + usize::from(off) < PROGRAM.len(), "pc {pc}");
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opcodes_match_libc() {
        assert_eq!(u32::from(BPF_LD), libc::BPF_LD);
        assert_eq!(u32::from(BPF_JMP), libc::BPF_JMP);
        assert_eq!(u32::from(BPF_RET), libc::BPF_RET);
        assert_eq!(u32::from(BPF_W), libc::BPF_W);
        assert_eq!(u32::from(BPF_ABS), libc::BPF_ABS);
        assert_eq!(u32::from(BPF_LEN), libc::BPF_LEN);
        assert_eq!(u32::from(BPF_JEQ), libc::BPF_JEQ);
        assert_eq!(u32::from(BPF_JGT), libc::BPF_JGT);
        assert_eq!(u32::from(BPF_JGE), libc::BPF_JGE);
        assert_eq!(u32::from(BPF_K), libc::BPF_K);
    }
}
