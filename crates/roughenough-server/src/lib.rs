// deny, not forbid: network.rs carries one Linux-gated `#[allow(unsafe_code)]`
// module wrapping `sendmmsg` (see the safety contract there); everything else
// in this crate is safe Rust
#![deny(unsafe_code)]

// Every module is `pub` only because this crate's binary, benches, tests/,
// and example are separate compilation units that must reach them
// (`pub(crate)` would not compile); none of it is a supported external API,
// so the whole surface is hidden from the documented interface.
#[doc(hidden)]
pub mod args;
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
