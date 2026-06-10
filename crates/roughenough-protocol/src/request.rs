use std::fmt::Debug;

use Error::{BadRequestSize, BufferTooSmall, InvalidMessageType, MissingTag};
use Request::{Plain, Srv};

use crate::FromWireN;
use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::header::{Header4, Header5, RawHeader};
use crate::tag::Tag;
use crate::tags::ver::RequestedVersions;
use crate::tags::{MessageType, Nonce, ProtocolVersion, SrvCommitment};
use crate::util::as_hex;
use crate::wire::{FRAME_OVERHEAD, FromFrame, FromWire, ToFrame, ToWire};

/// RFC 5.1: The size of the request message SHOULD be at least 1024 bytes when
/// the UDP transport mode is used.
///
/// Requests built by this implementation are exactly 1024 bytes inclusive of
/// framing; the server accepts incoming requests of at least this size up to MAX_REQUEST_SIZE.
pub const REQUEST_SIZE: usize = 1024;

/// Largest request the server accepts: a full Ethernet-MTU UDP payload
/// (1500 - 20 IP - 8 UDP), so any non-fragmented datagram can be received.
pub const MAX_REQUEST_SIZE: usize = 1472;

#[derive(Clone, Eq, PartialEq)]
pub enum Request {
    /// A `Plain` request has VER, NONC, TYPE, and ZZZZ tags (missing an SRV tag)
    Plain(RequestPlain),
    /// An `Srv` request has VER, NONC, SRV, TYPE, and ZZZZ tags
    Srv(RequestSrv),
}

impl Request {
    pub fn new(nonce: &Nonce) -> Self {
        Plain(RequestPlain::new(nonce))
    }

    pub fn new_with_server(nonce: &Nonce, server: &SrvCommitment) -> Self {
        Srv(RequestSrv::new(nonce, server))
    }

    /// Build a request offering the given protocol versions instead of the
    /// default. `versions` must be non-empty and sorted in ascending wire order
    /// (RFC 5.1.1).
    pub fn new_with_versions(nonce: &Nonce, versions: &[ProtocolVersion]) -> Self {
        assert!(!versions.is_empty(), "at least one version is required");
        Plain(RequestPlain::from_parts(
            RequestedVersions::new(versions),
            *nonce,
            MessageType::Request,
        ))
    }

    /// Build a request with an SRV commitment, offering the given protocol
    /// versions instead of the default. `versions` must be non-empty and sorted
    /// in ascending wire order (RFC 5.1.1).
    pub fn new_with_server_and_versions(
        nonce: &Nonce,
        server: &SrvCommitment,
        versions: &[ProtocolVersion],
    ) -> Self {
        assert!(!versions.is_empty(), "at least one version is required");
        Srv(RequestSrv::from_parts(
            RequestedVersions::new(versions),
            server.clone(),
            *nonce,
            MessageType::Request,
        ))
    }

    pub fn ver(&self) -> &RequestedVersions {
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
        const RAW_VER: u32 = Tag::VER as u32;
        const RAW_SRV: u32 = Tag::SRV as u32;
        const RAW_NONC: u32 = Tag::NONC as u32;
        const RAW_TYPE: u32 = Tag::TYPE as u32;

        if cursor.remaining() < REQUEST_SIZE - FRAME_OVERHEAD {
            return Err(BadRequestSize(cursor.remaining()));
        }

        let header = RawHeader::from_wire(cursor)?;

        let mut version: Option<RequestedVersions> = None;
        let mut server: Option<SrvCommitment> = None;
        let mut nonce: Option<Nonce> = None;
        let mut msg_type: Option<MessageType> = None;

        for (raw_tag, value_len) in header.entries() {
            let value_start = cursor.position();

            match raw_tag {
                RAW_VER => version = Some(RequestedVersions::from_wire_n(cursor, value_len)?),
                RAW_SRV => server = Some(SrvCommitment::from_wire_n(cursor, value_len)?),
                RAW_NONC => nonce = Some(Nonce::from_wire_n(cursor, value_len)?),
                RAW_TYPE => msg_type = Some(MessageType::from_wire_n(cursor, value_len)?),
                // RFC 5.1: "Unknown tags MUST be ignored by the server."
                // Padding tags (ZZZZ/PAD) are skipped the same way.
                _ => {}
            }

            // Advance to the next value regardless of how many bytes the tag
            // parser consumed (skipped tags, short VER lists, etc.)
            cursor.set_position(value_start + value_len);
        }

        // RFC 5.1: requests not containing the three mandatory tags MUST be ignored
        let Some(version) = version else {
            return Err(MissingTag("VER"));
        };
        let Some(nonce) = nonce else {
            return Err(MissingTag("NONC"));
        };
        let Some(msg_type) = msg_type else {
            return Err(MissingTag("TYPE"));
        };

        // RFC 5.1.3: requests with a TYPE other than 0 MUST be ignored
        if msg_type != MessageType::Request {
            return Err(InvalidMessageType(msg_type as u32));
        }

        match server {
            Some(server) => Ok(Srv(RequestSrv::from_parts(
                version, server, nonce, msg_type,
            ))),
            None => Ok(Plain(RequestPlain::from_parts(version, nonce, msg_type))),
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
    version: RequestedVersions,
    nonce: Nonce,
    msg_type: MessageType,
    padding: [u8; Self::MAX_PADDING],
}

impl RequestPlain {
    const TAGS: [Tag; 4] = [Tag::VER, Tag::NONC, Tag::TYPE, Tag::ZZZZ];

    /// ZZZZ padding when the VER list is empty; each version offered uses 4 of
    /// these bytes so the message stays exactly 1012 bytes (1024 framed)
    const MAX_PADDING: usize = REQUEST_SIZE
        - FRAME_OVERHEAD
        - size_of::<Header4>()
        - size_of::<Nonce>()
        - size_of::<MessageType>();

    /// The ZZZZ length needed to pad this request to exactly 1024 bytes
    fn padding_len(&self) -> usize {
        Self::MAX_PADDING - self.version.wire_size()
    }

    pub fn new(nonce: &Nonce) -> Self {
        Self {
            nonce: *nonce,
            ..Self::default()
        }
    }

    /// Build from parsed fields. The header offsets are recomputed so a
    /// re-serialized request reflects the parsed values.
    fn from_parts(version: RequestedVersions, nonce: Nonce, msg_type: MessageType) -> Self {
        let mut req = Self {
            version,
            nonce,
            msg_type,
            ..Self::default()
        };
        req.recompute_offsets();
        req
    }

    fn recompute_offsets(&mut self) {
        self.header.offsets[0] = self.version.wire_size() as u32;
        self.header.offsets[1] = self.header.offsets[0] + self.nonce.wire_size() as u32;
        self.header.offsets[2] = self.header.offsets[1] + self.msg_type.wire_size() as u32;
    }

    pub fn ver(&self) -> &RequestedVersions {
        &self.version
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }
}

impl ToWire for RequestPlain {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + self.nonce.wire_size()
            + self.msg_type.wire_size()
            + self.padding_len()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        cursor.put_slice(&self.padding[..self.padding_len()]);

        Ok(())
    }
}

impl Default for RequestPlain {
    fn default() -> Self {
        let mut request = Self {
            header: Header4::default(),
            version: RequestedVersions::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Request,
            padding: [0; Self::MAX_PADDING],
        };

        request.header.tags = Self::TAGS;
        request.recompute_offsets();

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
    version: RequestedVersions,
    server: SrvCommitment,
    nonce: Nonce,
    msg_type: MessageType,
    padding: [u8; Self::MAX_PADDING],
}

impl RequestSrv {
    const TAGS: [Tag; 5] = [Tag::VER, Tag::SRV, Tag::NONC, Tag::TYPE, Tag::ZZZZ];

    /// ZZZZ padding when the VER list is empty; each version offered uses 4 of
    /// these bytes so the message stays exactly 1012 bytes (1024 framed)
    const MAX_PADDING: usize = REQUEST_SIZE
        - FRAME_OVERHEAD
        - size_of::<Header5>()
        - size_of::<SrvCommitment>()
        - size_of::<Nonce>()
        - size_of::<MessageType>();

    /// The ZZZZ length needed to pad this request to exactly 1024 bytes
    fn padding_len(&self) -> usize {
        Self::MAX_PADDING - self.version.wire_size()
    }

    pub fn new(nonce: &Nonce, server: &SrvCommitment) -> Self {
        Self {
            server: server.clone(),
            nonce: *nonce,
            ..Self::default()
        }
    }

    /// Build from parsed fields. The header offsets are recomputed so a
    /// re-serialized request reflects the parsed values.
    fn from_parts(
        version: RequestedVersions,
        server: SrvCommitment,
        nonce: Nonce,
        msg_type: MessageType,
    ) -> Self {
        let mut req = Self {
            version,
            server,
            nonce,
            msg_type,
            ..Self::default()
        };
        req.recompute_offsets();
        req
    }

    fn recompute_offsets(&mut self) {
        self.header.offsets[0] = self.version.wire_size() as u32;
        self.header.offsets[1] = self.header.offsets[0] + self.server.wire_size() as u32;
        self.header.offsets[2] = self.header.offsets[1] + self.nonce.wire_size() as u32;
        self.header.offsets[3] = self.header.offsets[2] + self.msg_type.wire_size() as u32;
    }

    pub fn ver(&self) -> &RequestedVersions {
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
            version: RequestedVersions::default(),
            server: SrvCommitment::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Request,
            padding: [0; Self::MAX_PADDING],
        };

        request.header.tags = Self::TAGS;
        request.recompute_offsets();

        request
    }
}

impl ToWire for RequestSrv {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + self.server.wire_size()
            + self.nonce.wire_size()
            + self.msg_type.wire_size()
            + self.padding_len()
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
        cursor.put_slice(&self.padding[..self.padding_len()]);

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
    use crate::protocol_ver::ProtocolVersion;

    #[test]
    fn request_plain_wire_roundtrip() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestPlain::new(&nonce);

        let mut buf = vec![0u8; req.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            req.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let decoded = match Request::from_wire(&mut cursor).unwrap() {
            Plain(req) => req,
            Srv(_) => panic!("expected Plain variant"),
        };

        assert_eq!(decoded.ver(), req.ver());
        assert_eq!(decoded.nonc(), req.nonc());
        assert_eq!(decoded.msg_type(), req.msg_type());
        assert_eq!(decoded.padding, req.padding);
        assert_eq!(decoded.header, req.header);
    }

    /// Build a framed message from raw (tag, value) entries. The caller is
    /// responsible for tag ordering and for sizing values so the message body
    /// totals 1012 bytes (1024 with framing).
    fn raw_frame(entries: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&(entries.len() as u32).to_le_bytes());

        let mut acc = 0u32;
        for (_, value) in &entries[..entries.len() - 1] {
            acc += value.len() as u32;
            msg.extend_from_slice(&acc.to_le_bytes());
        }
        for (tag, _) in entries {
            msg.extend_from_slice(*tag);
        }
        for (_, value) in entries {
            msg.extend_from_slice(value);
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"ROUGHTIM");
        out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        out.extend_from_slice(&msg);
        out
    }

    fn ver_value() -> Vec<u8> {
        ProtocolVersion::DRAFT.as_u32().to_le_bytes().to_vec()
    }

    fn parse_frame(bytes: &mut [u8]) -> Result<Request, crate::error::Error> {
        use crate::wire::FromFrame;
        let mut cursor = ParseCursor::new(bytes);
        Request::from_frame(&mut cursor)
    }

    #[test]
    fn request_with_unknown_tag_is_parsed() {
        // RFC 5.1: "Unknown tags MUST be ignored by the server."
        // Tag order by little-endian value: VER < NONC < TYPE < GREZ < ZZZZ
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"GREZ", vec![0xaa; 4]),
            (b"ZZZZ", vec![0; 928]),
        ]);
        assert_eq!(bytes.len(), 1024);

        let parsed = parse_frame(&mut bytes).unwrap();
        assert_eq!(parsed.ver().versions(), &[ProtocolVersion::DRAFT]);
        assert_eq!(parsed.nonc(), &Nonce::from([0x42; 32]));
        assert!(parsed.srv().is_none());
    }

    #[test]
    fn oversized_request_is_parsed() {
        // A full-MTU request: the declared frame length covers all 1460
        // message bytes via an enlarged ZZZZ value
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; MAX_REQUEST_SIZE - 84]),
        ]);
        assert_eq!(bytes.len(), MAX_REQUEST_SIZE);

        let parsed = parse_frame(&mut bytes).unwrap();
        assert_eq!(parsed.nonc(), &Nonce::from([0x42; 32]));
    }

    #[test]
    fn undersized_request_is_rejected() {
        // One byte short: a 1023-byte frame carries a 1011-byte message
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 939]),
        ]);
        assert_eq!(bytes.len(), 1023);

        match parse_frame(&mut bytes) {
            Err(Error::BadRequestSize(1011)) => (), // ok, expected
            other => panic!("expected BadRequestSize(1011), got {other:?}"),
        }
    }

    #[test]
    fn trailing_bytes_beyond_declared_length_are_ignored() {
        // Parsing is bounded by the declared frame length: garbage after a
        // valid 1024-byte frame must not change the parse result
        let frame_bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 940]),
        ]);
        assert_eq!(frame_bytes.len(), 1024);

        let expected = parse_frame(&mut frame_bytes.clone()).unwrap();

        let mut oversized = frame_bytes;
        oversized.resize(MAX_REQUEST_SIZE, 0xff);
        let parsed = parse_frame(&mut oversized).unwrap();

        assert_eq!(parsed, expected);
    }

    #[test]
    fn request_with_srv_and_unknown_tag_is_parsed() {
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"SRV\x00", vec![0x77; 32]),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"GREZ", vec![0xaa; 4]),
            (b"ZZZZ", vec![0; 888]),
        ]);
        assert_eq!(bytes.len(), 1024);

        let parsed = parse_frame(&mut bytes).unwrap();
        assert_eq!(parsed.srv(), Some(&SrvCommitment::from([0x77; 32])));
        assert_eq!(parsed.nonc(), &Nonce::from([0x42; 32]));
    }

    #[test]
    fn request_padded_with_unknown_tag_is_parsed() {
        // No ZZZZ at all; an unknown tag provides the padding to 1024 bytes
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"GREZ", vec![0; 940]),
        ]);
        assert_eq!(bytes.len(), 1024);

        let parsed = parse_frame(&mut bytes).unwrap();
        assert_eq!(parsed.nonc(), &Nonce::from([0x42; 32]));
    }

    #[test]
    fn request_missing_mandatory_tag_is_rejected() {
        // RFC 5.1: requests not containing VER, NONC, and TYPE MUST be ignored.
        // This one has no NONC.
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 980]),
        ]);
        assert_eq!(bytes.len(), 1024);

        assert!(parse_frame(&mut bytes).is_err());
    }

    #[test]
    fn request_with_nonzero_type_is_rejected() {
        // RFC 5.1.3: requests with a TYPE other than 0 MUST be ignored
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 1u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 940]),
        ]);
        assert_eq!(bytes.len(), 1024);

        assert!(parse_frame(&mut bytes).is_err());
    }

    #[test]
    fn request_with_duplicate_tag_is_rejected() {
        // RFC 4.2: a tag MUST NOT appear more than once in a header
        let mut bytes = raw_frame(&[
            (b"VER\x00", ver_value()),
            (b"NONC", vec![0x42; 32]),
            (b"NONC", vec![0x43; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 900]),
        ]);
        assert_eq!(bytes.len(), 1024);

        assert!(parse_frame(&mut bytes).is_err());
    }

    #[test]
    fn unknown_versions_in_request_are_ignored() {
        use crate::wire::{FromFrame, ToFrame};

        let nonce = Nonce::from([0x42; 32]);
        let request = Request::new(&nonce);
        let mut bytes = request.as_frame_bytes().unwrap();

        // The VER value is the first entry in the message values section:
        // 12 bytes framing + 32 bytes header (4 tags). Overwrite the single
        // version entry with a value unknown to this implementation.
        let ver_offset = 12 + 32;
        bytes[ver_offset..ver_offset + 4].copy_from_slice(&0x00000005u32.to_le_bytes());

        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Request::from_frame(&mut cursor).unwrap();

        // RFC 5.1.1: unknown version numbers are ignored, not an error
        assert!(parsed.ver().versions().is_empty());
    }

    #[test]
    fn request_offering_multiple_versions_is_1024_bytes() {
        use crate::wire::{FromFrame, ToFrame};

        let nonce = Nonce::from([0x42; 32]);
        let versions = [ProtocolVersion::RFC, ProtocolVersion::DRAFT];

        let request = Request::new_with_versions(&nonce, &versions);
        let mut bytes = request.as_frame_bytes().unwrap();
        assert_eq!(bytes.len(), super::REQUEST_SIZE);

        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Request::from_frame(&mut cursor).unwrap();
        assert_eq!(parsed.ver().versions(), &versions);
        assert_eq!(parsed.nonc(), &Nonce::from([0x42; 32]));

        // SRV variant as well
        let srv = SrvCommitment::from([0x77; 32]);
        let request = Request::new_with_server_and_versions(&nonce, &srv, &versions);
        let mut bytes = request.as_frame_bytes().unwrap();
        assert_eq!(bytes.len(), super::REQUEST_SIZE);

        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Request::from_frame(&mut cursor).unwrap();
        assert_eq!(parsed.ver().versions(), &versions);
        assert_eq!(parsed.srv(), Some(&srv));
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
        assert_eq!(req.version, RequestedVersions::default());
        assert_eq!(req.msg_type, MessageType::Request);
        assert_eq!(req.nonce, Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; RequestPlain::MAX_PADDING]);
        assert_eq!(req.padding_len(), 940);

        // Verify offsets and tags
        assert_eq!(req.header.offsets[0], size_of::<ProtocolVersion>() as u32);
        assert_eq!(
            req.header.offsets[1],
            size_of::<ProtocolVersion>() as u32 + size_of::<Nonce>() as u32
        );
        assert_eq!(req.header.tags, [Tag::VER, Tag::NONC, Tag::TYPE, Tag::ZZZZ]);
    }

    #[test]
    fn request_plain_wire() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestPlain::new(&nonce);

        let mut buf = vec![0u8; req.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        req.to_wire(&mut cursor).unwrap();
        assert_eq!(cursor.position(), req.wire_size());
        assert_eq!(&buf[36..68], nonce.as_ref());
    }

    #[test]
    fn request_srv_defaults() {
        let req = RequestSrv::default();
        assert_eq!(req.ver(), &RequestedVersions::default());
        assert_eq!(req.msg_type(), MessageType::Request);
        assert_eq!(req.srv(), &SrvCommitment::from([0u8; 32]));
        assert_eq!(req.nonc(), &Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; RequestSrv::MAX_PADDING]);
        assert_eq!(req.padding_len(), 900);

        assert_eq!(req.header.offsets[0], req.ver().wire_size() as u32);
        assert_eq!(
            req.header.offsets[1],
            req.ver().wire_size() as u32 + req.srv().wire_size() as u32
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

        let mut buf = vec![0u8; req.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        req.to_wire(&mut cursor).unwrap();
        assert_eq!(cursor.position(), req.wire_size());
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

        // skip 12 framing bytes to parse the message directly
        let mut data = raw[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        let request = match Request::from_wire(&mut cursor).unwrap() {
            Plain(req) => req,
            Srv(_) => panic!("expected Plain variant"),
        };

        assert_eq!(request.version, RequestedVersions::default());
        assert_eq!(
            request.nonce.as_ref()[..8],
            [0x07, 0x10, 0x39, 0xe5, 0x72, 0x33, 0x23, 0x19]
        );
        assert_eq!(request.msg_type, MessageType::Request);
        assert_eq!(request.padding_len(), 940);
    }

    #[test]
    fn request_from_wire_selects_correct_impl() {
        let raw = include_bytes!("../testdata/rfc-request.SRV.417aa962");
        let mut data = raw.to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        match Request::from_frame(&mut cursor) {
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
        raw[80] = 0xaa;

        let result = Request::from_frame(&mut ParseCursor::new(&mut raw));
        match result {
            Err(InvalidMessageType(actual)) => assert_eq!(actual, 0xaa),
            Err(e) => panic!("Expected InvalidMessageType error, got: {e:?}"),
            Ok(r) => panic!("Expected InvalidMessageType error, got: Ok {r:?}"),
        }
    }
}
