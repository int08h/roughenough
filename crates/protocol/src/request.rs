use std::fmt::Debug;
use std::mem::size_of;

use Error::{
    BadRequestSize, BufferTooSmall, InvalidMessageType, UnexpectedOffsets, UnexpectedTags,
};
use Request::{Plain, Srv};

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::header::{Header4, Header5};
use crate::tag::Tag;
use crate::tags::{MessageType, Nonce, SrvCommitment, Version};
use crate::util::as_hex;
use crate::wire::{FromFrame, FromWire, ToFrame, ToWire};

/// RFC 5.1: The size of the request message SHOULD be at least 1024 bytes when
/// the UDP transport mode is used.
///
/// In Roughenough, a Request must be exactly 1024 bytes inclusive of framing
pub const REQUEST_SIZE: usize = 1024;

#[derive(Clone, Eq, PartialEq)]
pub enum Request {
    Plain(RequestPlain),
    Srv(RequestSrv),
}

impl Request {
    pub fn new(nonce: &Nonce) -> Self {
        Plain(RequestPlain::new(nonce))
    }

    // TODO(stuart) choose from RFC and Google variants
    // pub fn new_with_version(nonce: &Nonce, version: &Version) -> Self {
    //     // Plain(RequestPlain::new_with_version(nonce, version))
    // }

    pub fn new_with_server(nonce: &Nonce, server: &SrvCommitment) -> Self {
        Srv(RequestSrv::new(nonce, server))
    }

    pub fn ver(&self) -> &Version {
        match self {
            Plain(req) => req.ver(),
            Srv(req) => req.ver(),
        }
    }

    pub fn nonc(&self) -> &Nonce {
        match self {
            Plain(req) => req.nonc(),
            Srv(req) => req.nonc(),
        }
    }

    pub fn msg_type(&self) -> MessageType {
        match self {
            Plain(req) => req.msg_type(),
            Srv(req) => req.msg_type(),
        }
    }

    pub fn srv(&self) -> Option<&SrvCommitment> {
        match self {
            Plain(_) => None,
            Srv(req) => Some(req.srv()),
        }
    }
}

impl ToWire for Request {
    fn wire_size(&self) -> usize {
        match self {
            Plain(req) => req.wire_size(),
            Srv(req) => req.wire_size(),
        }
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        match self {
            Plain(req) => req.to_wire(cursor),
            Srv(req) => req.to_wire(cursor),
        }
    }
}

impl ToFrame for Request {}

impl FromWire for Request {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        if cursor.remaining() != 1012 {
            return Err(BadRequestSize(cursor.remaining()));
        }

        // Distinguish the SRV variant by peeking at the number of tags.
        // RequestPlain has 4 tags, RequestSrv has 5 tags
        let saved_pos = cursor.position();
        let num_tags = cursor.try_get_u32_le()?;
        cursor.set_position(saved_pos);

        match num_tags {
            4 => Ok(Plain(RequestPlain::from_wire(cursor)?)),
            5 => Ok(Srv(RequestSrv::from_wire(cursor)?)),
            _ => Err(Error::MismatchedNumTags(4, num_tags)),
        }
    }
}

impl FromFrame for Request {}

impl Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Plain(req) => req.fmt(f),
            Srv(req) => req.fmt(f),
        }
    }
}

/// RFC 5.1: A request MUST contain the tags VER, NONC, and TYPE. It SHOULD
/// include the tag SRV.
#[repr(C)]
#[derive(Clone, Eq, PartialEq)]
pub struct RequestPlain {
    header: Header4,
    version: Version,
    nonce: Nonce,
    msg_type: MessageType,
    padding: [u8; 940],
}

impl RequestPlain {
    const NONCE_OFFSET: u32 = size_of::<Version>() as u32;
    const MSG_TYPE_OFFSET: u32 = Self::NONCE_OFFSET + (size_of::<Nonce>() as u32);
    const PADDING_OFFSET: u32 = Self::MSG_TYPE_OFFSET + (size_of::<MessageType>() as u32);
    const OFFSETS: [u32; 3] = [
        Self::NONCE_OFFSET,
        Self::MSG_TYPE_OFFSET,
        Self::PADDING_OFFSET,
    ];
    const TAGS: [Tag; 4] = [Tag::VER, Tag::NONC, Tag::TYPE, Tag::ZZZZ];

    pub fn new(nonce: &Nonce) -> Self {
        Self {
            nonce: *nonce,
            ..Self::default()
        }
    }

    pub fn ver(&self) -> &Version {
        &self.version
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }
}

impl FromWire for RequestPlain {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        if cursor.remaining() < size_of::<Self>() {
            return Err(BufferTooSmall(size_of::<Self>(), cursor.remaining()));
        }

        let req = RequestPlain {
            header: Header4::from_wire(cursor)?,
            version: Version::from_wire(cursor)?,
            nonce: Nonce::from_wire(cursor)?,
            msg_type: MessageType::from_wire(cursor)?,
            ..Self::default()
        };

        if req.msg_type != MessageType::Request {
            return Err(InvalidMessageType(req.msg_type as u32));
        }

        if req.header.offsets != Self::OFFSETS {
            return Err(UnexpectedOffsets);
        }

        if req.header.tags != Self::TAGS {
            return Err(UnexpectedTags);
        }

        Ok(req)
    }
}

impl ToWire for RequestPlain {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        cursor.put_slice(&self.padding);

        Ok(())
    }
}

impl Default for RequestPlain {
    fn default() -> Self {
        let mut request = Self {
            header: Header4::default(),
            version: Version::RfcDraft14,
            nonce: Nonce::default(),
            msg_type: MessageType::Request,
            padding: [0; 940],
        };

        request.header.offsets = Self::OFFSETS;
        request.header.tags = Self::TAGS;
        request
    }
}

impl Debug for RequestPlain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestPlain")
            .field("VER", &self.version)
            .field("NONC", &self.nonce)
            .field("TYPE", &self.msg_type)
            .field("ZZZZ", &as_hex(&self.padding))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RequestSrv {
    header: Header5,
    version: Version,
    server: SrvCommitment,
    nonce: Nonce,
    msg_type: MessageType,
    padding: [u8; 900],
}

impl RequestSrv {
    const SERVER_OFFSET: u32 = size_of::<Version>() as u32;
    const NONCE_OFFSET: u32 = Self::SERVER_OFFSET + (size_of::<SrvCommitment>() as u32);
    const MSG_TYPE_OFFSET: u32 = Self::NONCE_OFFSET + (size_of::<Nonce>() as u32);
    const PADDING_OFFSET: u32 = Self::MSG_TYPE_OFFSET + (size_of::<MessageType>() as u32);
    const OFFSETS: [u32; 4] = [
        Self::SERVER_OFFSET,
        Self::NONCE_OFFSET,
        Self::MSG_TYPE_OFFSET,
        Self::PADDING_OFFSET,
    ];
    const TAGS: [Tag; 5] = [Tag::VER, Tag::SRV, Tag::NONC, Tag::TYPE, Tag::ZZZZ];

    pub fn new(nonce: &Nonce, server: &SrvCommitment) -> Self {
        Self {
            server: server.clone(),
            nonce: *nonce,
            ..Self::default()
        }
    }

    pub fn ver(&self) -> &Version {
        &self.version
    }

    pub fn srv(&self) -> &SrvCommitment {
        &self.server
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }
}

impl Default for RequestSrv {
    fn default() -> Self {
        let mut request = Self {
            header: Header5::default(),
            version: Version::RfcDraft14,
            server: SrvCommitment::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Request,
            padding: [0; 900],
        };

        request.header.offsets = Self::OFFSETS;
        request.header.tags = Self::TAGS;
        request
    }
}

impl FromWire for RequestSrv {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        if cursor.remaining() < size_of::<Self>() {
            return Err(BufferTooSmall(size_of::<Self>(), cursor.remaining()));
        }

        let req = RequestSrv {
            header: Header5::from_wire(cursor)?,
            version: Version::from_wire(cursor)?,
            server: SrvCommitment::from_wire(cursor)?,
            nonce: Nonce::from_wire(cursor)?,
            msg_type: MessageType::from_wire(cursor)?,
            ..Self::default()
        };

        if req.msg_type != MessageType::Request {
            return Err(InvalidMessageType(req.msg_type as u32));
        }

        if req.header.offsets != Self::OFFSETS {
            return Err(UnexpectedOffsets);
        }

        if req.header.tags != Self::TAGS {
            return Err(UnexpectedTags);
        }

        Ok(req)
    }
}

impl ToWire for RequestSrv {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.server.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        cursor.put_slice(&self.padding);

        Ok(())
    }
}

impl Debug for RequestSrv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSrv")
            .field("VER", &self.version)
            .field("SRV", &self.server)
            .field("NONC", &self.nonce)
            .field("TYPE", &self.msg_type)
            .field("ZZZZ", &as_hex(&self.padding))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn request_plain_wire_roundtrip() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestPlain::new(&nonce);

        let mut buf = vec![0u8; size_of::<RequestPlain>()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            req.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let decoded = RequestPlain::from_wire(&mut cursor).unwrap();

        assert_eq!(decoded.ver(), req.ver());
        assert_eq!(decoded.nonc(), req.nonc());
        assert_eq!(decoded.msg_type(), req.msg_type());
        assert_eq!(decoded.padding, req.padding);
        assert_eq!(decoded.header, req.header);
    }

    #[test]
    fn request_plain_wire_error() {
        let req = RequestPlain::default();
        let mut small_buf = [0u8; 10];
        let mut cursor = ParseCursor::new(&mut small_buf);
        let result = req.to_wire(&mut cursor);

        assert!(result.is_err());
    }

    #[test]
    fn request_plain_defaults() {
        let req = RequestPlain::default();
        assert_eq!(req.version, Version::RfcDraft14);
        assert_eq!(req.msg_type, MessageType::Request);
        assert_eq!(req.nonce, Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; 940]);

        // Verify offsets and tags
        assert_eq!(req.header.offsets[0], size_of::<Version>() as u32);
        assert_eq!(
            req.header.offsets[1],
            size_of::<Version>() as u32 + size_of::<Nonce>() as u32
        );
        assert_eq!(req.header.tags, [Tag::VER, Tag::NONC, Tag::TYPE, Tag::ZZZZ]);
    }

    #[test]
    fn request_plain_wire() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestPlain::new(&nonce);

        let mut buf = vec![0u8; size_of::<RequestPlain>()];
        let mut cursor = ParseCursor::new(&mut buf);
        req.to_wire(&mut cursor).unwrap();
        assert_eq!(cursor.position(), size_of::<RequestPlain>());
        assert_eq!(&buf[36..68], nonce.as_ref());
    }

    #[test]
    fn request_srv_defaults() {
        let req = RequestSrv::default();
        assert_eq!(req.ver(), &Version::RfcDraft14);
        assert_eq!(req.msg_type(), MessageType::Request);
        assert_eq!(req.srv(), &SrvCommitment::from([0u8; 32]));
        assert_eq!(req.nonc(), &Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; 900]);

        assert_eq!(req.header.offsets[0], size_of::<Version>() as u32);
        assert_eq!(
            req.header.offsets[1],
            size_of::<Version>() as u32 + size_of::<SrvCommitment>() as u32
        );
        assert_eq!(
            req.header.tags,
            [Tag::VER, Tag::SRV, Tag::NONC, Tag::TYPE, Tag::ZZZZ]
        );
    }

    #[test]
    fn request_srv_wire() {
        let nonce = Nonce::from([0x42; 32]);
        let server = SrvCommitment::from([0xbb; 32]);
        let req = RequestSrv::new(&nonce, &server);

        let mut buf = vec![0u8; size_of::<RequestSrv>()];
        let mut cursor = ParseCursor::new(&mut buf);
        req.to_wire(&mut cursor).unwrap();
        assert_eq!(cursor.position(), size_of::<RequestSrv>());
        assert_eq!(&buf[44..76], server.as_ref());
        assert_eq!(&buf[76..108], nonce.as_ref());
    }

    #[test]
    fn from_wire_known_bytes() {
        // Request = RtMessage|4|{
        //   VER(4) = 0c000080
        //   NONC(32) = 071039e5723323191eaa7449e64e0b839b7a11028cbd943c31b28bfb93fadb32
        //   TYPE(4) = 00000000
        //   ZZZZ(940) = 0000000...
        // }
        let raw = include_bytes!("../testdata/rfc-request.071039e5");

        // skip 12 framing bytes as we're constructing a concrete RequestPlain
        let mut data = raw[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        let request = RequestPlain::from_wire(&mut cursor).unwrap();

        assert_eq!(request.version, Version::RfcDraft14);
        assert_eq!(
            request.nonce.as_ref()[..8],
            [0x07, 0x10, 0x39, 0xe5, 0x72, 0x33, 0x23, 0x19]
        );
        assert_eq!(request.msg_type, MessageType::Request);
        assert_eq!(request.padding, [0u8; 940]);
    }

    #[test]
    fn request_from_wire_selects_correct_impl() {
        let raw = include_bytes!("../testdata/rfc-request.SRV.417aa962");
        let mut data = raw.to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        let result = Request::from_frame(&mut cursor);
        assert!(result.is_ok());

        match result {
            Ok(Srv(req)) => {
                assert_eq!(
                    req.nonc().as_ref()[..8],
                    [0x41, 0x7a, 0xa9, 0x62, 0xcd, 0x46, 0xe1, 0xe5]
                );
                assert_eq!(
                    req.server.as_ref()[..8],
                    [0xee, 0xf0, 0x88, 0xf0, 0x68, 0x4d, 0xe2, 0x1f]
                );
            }
            Ok(Plain(_)) => panic!("Expected SRV variant"),
            Err(e) => panic!("No error should have been returned: {e:?}"),
        }
    }

    #[test]
    fn wrong_msg_type_is_detected() {
        let mut raw = include_bytes!("../testdata/rfc-request.071039e5").to_vec();
        // 12 bytes framing + 32 bytes nonce = 44 = offset to message_type; set it to an invalid value
        raw[RequestPlain::MSG_TYPE_OFFSET as usize + 44] = 0xaa;

        let result = Request::from_frame(&mut ParseCursor::new(&mut raw));
        match result {
            Err(InvalidMessageType(actual)) => assert_eq!(actual, 0xaa),
            Err(e) => panic!("Expected InvalidMessageType error, got: {e:?}"),
            Ok(r) => panic!("Expected InvalidMessageType error, got: Ok {r:?}"),
        }
    }
}
