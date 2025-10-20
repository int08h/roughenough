// The protocol crate uses only safe Rust.
#![forbid(unsafe_code)]

pub mod cursor;
pub mod error;
pub mod header;
pub mod request;
pub mod response;
pub mod tag;
pub mod tags;
pub mod util;
pub mod wire;

// Re-export commonly used types
pub use wire::{FromFrame, FromWire, FromWireN, ToFrame, ToWire};
