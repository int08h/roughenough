#![deny(unsafe_code)]

/// Upper bound for `--batch-size`: the most requests one signature covers
pub const MAX_BATCH_SIZE: usize = 64;

#[doc(hidden)]
pub mod args;
#[doc(hidden)]
pub mod filter;
#[doc(hidden)]
pub mod keysource;
#[doc(hidden)]
pub mod metrics;
#[doc(hidden)]
pub mod network;
#[doc(hidden)]
pub mod requests;
#[doc(hidden)]
pub mod responses;
#[doc(hidden)]
pub mod worker;

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_utils;
