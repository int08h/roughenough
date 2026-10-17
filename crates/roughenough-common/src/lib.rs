//! Shared cryptographic and decoding helpers, and the clock source, used by multiple
//! roughenough crates.

#![forbid(unsafe_code)]

pub mod clocksource;
pub mod crypto;
pub mod encoding;
