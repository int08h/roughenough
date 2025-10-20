use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("request size is not 1012 bytes: {0} bytes")]
    BadRequestSize(usize),

    #[error("buffer too small: {0} bytes needed, {1} bytes available")]
    BufferTooSmall(usize, usize),

    #[error("invalid tag: {0:#08x}")]
    InvalidTag(u32),

    #[error("invalid version: {0:#08x}")]
    InvalidVersion(u32),

    #[error("invalid message type: {0:#08x}")]
    InvalidMessageType(u32),

    #[error("mismatched number of tags: expected {0}, got {1}")]
    MismatchedNumTags(u32, u32),

    #[error("magic value was not 'ROUGHTIM' (0x544f55474854494d): {0:#016x}")]
    UnexpectedMagic(u64),

    #[error("frame length invalid: {0}")]
    UnexpectedFraming(usize),

    #[error("tags found in the message are not what was expected")]
    UnexpectedTags,

    #[error("tag is less than prior tag: index {0}, value {1:#08x}")]
    UnorderedTag(u32, u32),

    #[error("offsets found in the message are not what was expected")]
    UnexpectedOffsets,

    #[error("offset value less than prior offset: index {0}, value {1:#08x}")]
    UnorderedOffset(u32, u32),

    #[error("offset is not 4-byte aligned: index {0}, value {1:#08x}")]
    UnalignedOffset(u32, u32),

    #[error("offset is beyond the end of the message: index {0}, value {1:#08x}")]
    OutOfBoundsOffset(u32, u32),

    #[error("version value is less than prior version: index {0}, value {1:#08x}")]
    UnorderedVersion(u32, u32),

    #[error("no supported versions (empty VERS tag)")]
    NoSupportedVersions,

    #[error("PATH length not a multiple of 32-bytes: length {0}")]
    InvalidPathLength(u32),

    #[error("wrong tag size: expected {0} bytes, got {1} bytes")]
    WrongTagSize(usize, usize),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
