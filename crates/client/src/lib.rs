//! Client library is unsafe-free. Note that main.rs uses unsafe for
//! clock manipulation via libc::clock_settime, but that is isolated
//! to the binary and not part of the library interface.

#![forbid(unsafe_code)]

pub mod args;
pub mod client;
pub mod measurement;
pub mod reporting;
pub mod sequence;
pub mod server_list;
pub mod transport;
pub mod validation;

pub use client::*;
pub use reporting::{MalfeasanceReport, ReportEntry};
pub use validation::*;
