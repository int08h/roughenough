//! This crate provides shared functionality used by multiple crates in the project,
//! including cryptographic utilities, encoding/decoding helpers, and the clock source.

#![forbid(unsafe_code)]

pub mod clocksource;
pub mod crypto;
pub mod encoding;
