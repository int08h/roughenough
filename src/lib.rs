//!
//! An implementation of the [Roughtime](https://roughtime.googlesource.com/roughtime) 
//! secure time synchronization protocol.
//!

extern crate byteorder;

mod error;
mod tag;
mod message;
mod sign;

pub mod hex;

pub use error::Error;
pub use tag::Tag;
pub use message::RtMessage;

//  Constants and magic numbers of the Roughtime protocol

/// Minimum size (in bytes) of a client request
pub const MIN_REQUEST_LENGTH: u32 = 1024;

/// Minimum size (in bytes) of seeds used to derive private keys
pub const MIN_SEED_LENGTH: u32 = 32;

/// Size (in bytes) of an Ed25519 public key
pub const PUBKEY_LENGTH: u32 = 32;

/// Size (in bytes) of the client's nonce
pub const NONCE_LENGTH: u32 = 64;

/// Size (in bytes) of an Ed25519 signature
pub const SIGNATURE_LENGTH: u32 = 64;

/// Size (in bytes) of server's timestamp value
pub const TIMESTAMP_LENGTH: u32 = 8;

/// Size (in bytes) of server's time uncertainty value
pub const RADIUS_LENGTH: u32 = 4;

/// Prefixed to the server's certificate before generating or verifying certificate's signature
pub const CERTIFICATE_CONTEXT: &str = "RoughTime v1 delegation signature--\x00";

/// Prefixed to the server's response before generating or verifying the server's signature
pub const SIGNED_RESPONSE_CONTEXT: &str = "RoughTime v1 response signature\x00";

/// Value prepended to leaves prior to hashing
pub const TREE_LEAF_TWEAK: &[u8] = &[0x00];

/// Value prepended to nodes prior to hashing
pub const TREE_NODE_TWEAK: &[u8] = &[0x01];
