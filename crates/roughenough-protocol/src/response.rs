use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::BufferTooSmall;
use crate::header::{Header, Header7, RawHeader};
use crate::tag::Tag;
use crate::tags::srep::SignedResponse;
use crate::tags::{Certificate, MerklePath, MessageType, Nonce, Signature};
use crate::wire::{FromFrame, FromWire, FromWireN, ToFrame, ToWire};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    header: Header7,
    signature: Signature,
    nonce: Nonce,
    msg_type: MessageType,
    path: MerklePath,
    srep: SignedResponse,
    cert: Certificate,
    index: u32,
}

impl Response {
    /// All responses will be *at least* this many bytes, and could be longer as the PATH and SREP
    /// values are variable-length.
    pub const MINIMUM_SIZE: usize = 404;

    /// RFC 5.2: A response MUST contain the tags SIG, NONC, TYPE, PATH, SREP, CERT,
    /// and INDX.
    const TAGS: [Tag; 7] = [
        Tag::SIG,
        Tag::NONC,
        Tag::TYPE,
        Tag::PATH,
        Tag::SREP,
        Tag::CERT,
        Tag::INDX,
    ];

    pub fn header(&self) -> &impl Header {
        &self.header
    }

    pub fn sig(&self) -> &Signature {
        &self.signature
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    pub fn path(&self) -> &MerklePath {
        &self.path
    }

    pub fn srep(&self) -> &SignedResponse {
        &self.srep
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn indx(&self) -> u32 {
        self.index
    }

    pub fn set_sig(&mut self, sig: Signature) {
        self.signature = sig;
    }

    pub fn set_nonc(&mut self, nonce: Nonce) {
        self.nonce = nonce;
    }

    /// Overwrite this Response's MerklePath with the provided one
    pub fn set_path(&mut self, path: MerklePath) {
        self.path = path;
        self.update_offsets();
    }

    /// Copy the contents of another MerklePath into this one, overwriting any existing data.
    pub fn copy_path(&mut self, path: &MerklePath) {
        self.path.copy_from(path);
        self.update_offsets();
    }

    pub fn set_srep(&mut self, srep: SignedResponse) {
        self.srep = srep;
        self.update_offsets()
    }

    pub fn set_cert(&mut self, cert: Certificate) {
        self.cert = cert;
    }

    pub fn set_indx(&mut self, index: u32) {
        self.index = index;
    }

    /// Refresh offsets based on the current values of the fields
    fn update_offsets(&mut self) {
        self.header.offsets[0] = self.signature.wire_size() as u32;
        self.header.offsets[1] = self.header.offsets[0] + self.nonce.wire_size() as u32;
        self.header.offsets[2] = self.header.offsets[1] + self.msg_type.wire_size() as u32;
        self.header.offsets[3] = self.header.offsets[2] + self.path.wire_size() as u32;
        self.header.offsets[4] = self.header.offsets[3] + self.srep.wire_size() as u32;
        self.header.offsets[5] = self.header.offsets[4] + self.cert.wire_size() as u32;
    }
}

impl Default for Response {
    fn default() -> Self {
        let mut response = Self {
            header: Header7::default(),
            signature: Signature::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Response,
            path: MerklePath::default(),
            srep: SignedResponse::default(),
            cert: Certificate::default(),
            index: 0,
        };

        response.header.tags = Self::TAGS;
        // offsets are calculated in set_path() and set_srep()

        response
    }
}

impl FromWire for Response {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        const RAW_SIG: u32 = Tag::SIG as u32;
        const RAW_NONC: u32 = Tag::NONC as u32;
        const RAW_TYPE: u32 = Tag::TYPE as u32;
        const RAW_PATH: u32 = Tag::PATH as u32;
        const RAW_SREP: u32 = Tag::SREP as u32;
        const RAW_CERT: u32 = Tag::CERT as u32;
        const RAW_INDX: u32 = Tag::INDX as u32;

        let header = RawHeader::from_wire(cursor)?;

        let mut signature: Option<Signature> = None;
        let mut nonce: Option<Nonce> = None;
        let mut msg_type: Option<MessageType> = None;
        let mut path: Option<MerklePath> = None;
        let mut srep: Option<SignedResponse> = None;
        let mut cert: Option<Certificate> = None;
        let mut index: Option<u32> = None;

        for (raw_tag, value_len) in header.entries() {
            let value_start = cursor.position();

            match raw_tag {
                RAW_SIG => signature = Some(Signature::from_wire_n(cursor, value_len)?),
                RAW_NONC => nonce = Some(Nonce::from_wire_n(cursor, value_len)?),
                RAW_TYPE => msg_type = Some(MessageType::from_wire_n(cursor, value_len)?),
                RAW_PATH => path = Some(MerklePath::from_wire_n(cursor, value_len)?),
                RAW_SREP => srep = Some(SignedResponse::from_wire_n(cursor, value_len)?),
                RAW_CERT => cert = Some(Certificate::from_wire_n(cursor, value_len)?),
                RAW_INDX => {
                    if value_len != size_of::<u32>() {
                        return Err(Error::WrongTagSize(size_of::<u32>(), value_len));
                    }
                    index = Some(cursor.try_get_u32_le()?);
                }
                // RFC 7: "Clients MUST properly ignore undefined tags"
                _ => {}
            }

            cursor.set_position(value_start + value_len);
        }

        // RFC 5.2: a response contains the tags SIG, NONC, TYPE, PATH, SREP,
        // CERT, and INDX
        let Some(msg_type) = msg_type else {
            return Err(Error::MissingTag("TYPE"));
        };

        // RFC 5.2.3: responses with a TYPE other than 1 MUST be ignored
        if msg_type != MessageType::Response {
            return Err(Error::InvalidMessageType(msg_type as u32));
        }

        let mut response = Response::default();
        response.set_sig(signature.ok_or(Error::MissingTag("SIG"))?);
        response.set_nonc(nonce.ok_or(Error::MissingTag("NONC"))?);
        response.set_path(path.ok_or(Error::MissingTag("PATH"))?);
        response.set_srep(srep.ok_or(Error::MissingTag("SREP"))?);
        response.set_cert(cert.ok_or(Error::MissingTag("CERT"))?);
        response.set_indx(index.ok_or(Error::MissingTag("INDX"))?);

        Ok(response)
    }
}

impl FromFrame for Response {}

impl ToWire for Response {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.signature.wire_size()
            + self.nonce.wire_size()
            + self.msg_type.wire_size()
            + self.path.wire_size()
            + self.srep.wire_size()
            + self.cert.wire_size()
            + size_of::<u32>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.capacity() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.capacity()));
        }

        self.header.to_wire(cursor)?;
        self.signature.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        self.path.to_wire(cursor)?;
        self.srep.to_wire(cursor)?;
        self.cert.to_wire(cursor)?;
        cursor.put_u32_le(self.index);

        Ok(())
    }
}

impl ToFrame for Response {}

#[cfg(test)]
mod tests {
    use crate::cursor::ParseCursor;
    use crate::header::Header;
    use crate::response::Response;
    use crate::tag::Tag;
    use crate::tags::{
        MerklePath, MessageType, ProtocolVersion, SignedResponse, SupportedVersions,
    };
    use crate::util::test_utils::{frame, insert_tag, replace_value, value_range};
    use crate::wire::FromFrame;

    #[test]
    fn response_with_unknown_tag_is_parsed() {
        // RFC 7: "Clients MUST properly ignore undefined tags"
        let raw = include_bytes!("../testdata/rfc-response.path8.index2.4c16c619");
        let msg = &raw[12..];

        // GREZ sorts after INDX at the top level
        let greased = insert_tag(msg, *b"GREZ", &[0xaa; 4]);
        let mut framed = frame(&greased);

        let mut cursor = ParseCursor::new(&mut framed);
        let response = Response::from_frame(&mut cursor).unwrap();

        assert_eq!(response.indx(), 2);
        assert_eq!(response.msg_type(), MessageType::Response);
        assert_eq!(
            response.nonc().as_ref()[..8],
            [0x4c, 0x16, 0xc6, 0x19, 0xd7, 0x71, 0x6f, 0xae]
        );
        assert_eq!(*response.srep().ver(), ProtocolVersion::DRAFT);
    }

    #[test]
    fn srep_with_unknown_tag_is_parsed() {
        // RFC 9.2: new tags SHOULD be added to the SREP tag whenever possible,
        // so clients must tolerate unknown tags inside SREP
        let raw = include_bytes!("../testdata/rfc-response.path8.index2.4c16c619");
        let msg = &raw[12..];

        let srep_range = value_range(msg, *b"SREP");
        let new_srep = insert_tag(&msg[srep_range.clone()], *b"GREZ", &[0xbb; 8]);

        // Rebuild the top-level message with the larger SREP value so the
        // top-level offsets stay correct
        let rebuilt = replace_value(msg, *b"SREP", &new_srep);
        let mut framed = frame(&rebuilt);

        let mut cursor = ParseCursor::new(&mut framed);
        let response = Response::from_frame(&mut cursor).unwrap();

        assert_eq!(*response.srep().ver(), ProtocolVersion::DRAFT);
        assert_eq!(response.srep().radi(), 5);
        assert_eq!(response.srep().midp(), 1748359193);
    }

    #[test]
    fn from_wire_on_known_bytes() {
        let mut raw = include_bytes!("../testdata/rfc-response.path8.index2.4c16c619").to_vec();

        let mut cursor = ParseCursor::new(&mut raw);
        let response = Response::from_frame(&mut cursor).unwrap();

        // Response {
        //     header: Header7 {
        //         num_tags: 7,
        //         offsets: [ 64, 96, 100, 356, 452, 604, ],
        //         tags: [ SIG, NONC, TYPE, PATH, SREP, CERT, INDX, ],
        //     },
        //     signature: SIG(72c53051ad9773f484c6bdfd27e6595ce40a117ec3b86a41887b7135bd93f3238ef445939bd7d9c262f31e6a306ebeb41a4e436ef81ff21c8b9e0d3be22ae50a),
        //     nonce: NONC(4c16c619d7716fae49552b3393fd07cff4c6f16a1ab5a2f7ce5240f94a6d1f29),
        //     msg_type: Response,
        //     path: PATH { num_paths: 8, data: 7148a705f7c562f0cb1f278aabca93133269453042eb8d554da4d6f0a1fbd7202cd76bb0939d911c623831205caef0602e9a62a115de2117a869eb3775a481edbb6f543d60a509f50560885423496fd085d0f2a63787b91d0ade26fdf3a6352807b417d43fbde735f33fbb36b7f8fa9cc68b6462e17629e88086ee8b7aefee74f8dd1237cf5b5d6ab8409278374639298404fd21561ba7caca142b9d0e5d574ec56a648e3393c8c612281516cea5af523660d40b3fe57141af51646b60b98a3a761ecd09f131bedf9ecf9c557d9b511b28a1e6c7950f854c3febc71b7f01d5f616d0ea810ac7d01f8c412203a49821bc4befa651e413b352fef04c97f1ef5730 },
        //     srep: SignedResponse {
        //         header: Header5 {
        //             num_tags: 5,
        //             offsets: [ 4, 8, 16, 24, ],
        //             tags: [ VER, RADI, MIDP, VERS, ROOT, ],
        //         },
        //         version: Draft(0x8000000c),
        //         radius: 5,
        //         midpoint: 1748359193,
        //         supported_versions: VERS {
        //             // on the wire: [0x00000000, 0x8000000c]; 0x00000000 is
        //             // unknown to this implementation and ignored when parsing
        //             num_versions: 1,
        //             versions: [ Draft(0x8000000c), ],
        //         },
        //         merkle_root: ROOT(1ecf2ead5837a00dc01d2875bdb16c2be094da36115dce7966e320e31345bb97),
        //     },
        //     cert: CERT {
        //         header: Header2 {
        //             num_tags: 2,
        //             offsets: [ 64, ],
        //             tags: [ SIG, DELE, ],
        //         },
        //         signature: SIG(2df7d5397611739c683f54b95359b11781d079b28b09bcf13d42d85868db48b8bafcbf0492ca836f615d3d88775c455c9443368f959cb90644c7093430ed4502),
        //         delegation: DELE {
        //             header: Header3 {
        //                 num_tags: 3,
        //                 offsets: [ 32, 40, ],
        //                 tags: [ PUBK, MINT, MAXT, ],
        //             },
        //             public_key: PUBK(254e5d6fa2453dac9931cb7ae84c4e2790a69b390bac8f68b332db0d1c7dd6c7),
        //             min_time: 0,
        //             max_time: 18446744073709551615,
        //         },
        //     },
        //     index: 2
        // }

        // Header offsets reflect the reconstructed canonical form: the original
        // wire bytes carry a two-entry VERS [0x0, 0x8000000c] whose unknown 0x0
        // entry is dropped during parsing, shrinking SREP by 4 bytes (the wire
        // offsets were [64, 96, 100, 356, 452, 604])
        assert_eq!(response.header().offsets(), [64, 96, 100, 356, 448, 600]);
        assert_eq!(
            response.header().tags(),
            [
                Tag::SIG,
                Tag::NONC,
                Tag::TYPE,
                Tag::PATH,
                Tag::SREP,
                Tag::CERT,
                Tag::INDX
            ]
        );
        assert_eq!(response.msg_type(), MessageType::Response);
        assert_eq!(response.path().as_ref().len(), 256);
        assert_eq!(response.indx(), 2);

        assert_eq!(
            response.sig().as_ref()[..8],
            [0x72, 0xc5, 0x30, 0x51, 0xad, 0x97, 0x73, 0xf4]
        );
        assert_eq!(
            response.nonc().as_ref()[..8],
            [0x4c, 0x16, 0xc6, 0x19, 0xd7, 0x71, 0x6f, 0xae]
        );
        assert_eq!(
            response.path().as_ref()[..8],
            [0x71, 0x48, 0xa7, 0x05, 0xf7, 0xc5, 0x62, 0xf0]
        );

        let srep = response.srep();
        // [4, 8, 16, 24] on the wire; the reconstructed VERS holds one entry
        assert_eq!(srep.header().offsets(), [4, 8, 16, 20]);
        assert_eq!(
            srep.header().tags(),
            [Tag::VER, Tag::RADI, Tag::MIDP, Tag::VERS, Tag::ROOT]
        );
        assert_eq!(*srep.ver(), ProtocolVersion::DRAFT);
        assert_eq!(srep.radi(), 5);
        assert_eq!(srep.midp(), 1748359193);
        assert_eq!(srep.vers().versions(), &[ProtocolVersion::DRAFT]);
        assert_eq!(srep.root().as_ref().len(), 32);
        assert_eq!(
            srep.root().as_ref()[..8],
            [0x1e, 0xcf, 0x2e, 0xad, 0x58, 0x37, 0xa0, 0x0d]
        );

        let cert = response.cert();
        assert_eq!(cert.header().offsets(), [64]);
        assert_eq!(cert.header().tags(), [Tag::SIG, Tag::DELE]);
        assert_eq!(cert.sig().as_ref().len(), 64);
        assert_eq!(
            cert.sig().as_ref()[..8],
            [0x2d, 0xf7, 0xd5, 0x39, 0x76, 0x11, 0x73, 0x9c]
        );

        let dele = cert.dele();
        assert_eq!(dele.header().offsets(), [32, 40]);
        assert_eq!(dele.header().tags(), [Tag::PUBK, Tag::MINT, Tag::MAXT]);
        assert_eq!(dele.pubk().as_ref().len(), 32);
        assert_eq!(
            dele.pubk().as_ref()[..8],
            [0x25, 0x4e, 0x5d, 0x6f, 0xa2, 0x45, 0x3d, 0xac]
        );
        assert_eq!(dele.mint(), 0);
        assert_eq!(dele.maxt(), u64::MAX);
    }

    #[test]
    fn offsets_are_calculated_correctly() {
        let mut response = Response::default();
        assert_eq!(response.header.offsets, [0, 0, 0, 0, 0, 0]);

        let path = MerklePath::try_from([0x4e; 192].as_slice()).unwrap();
        response.set_path(path);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 380, 532]);

        // Only the VERS wire size matters here; duplicate the entry to test the
        // two-version offsets
        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[
            ProtocolVersion::DRAFT,
            ProtocolVersion::DRAFT,
        ]));
        response.set_srep(srep);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 388, 540]);

        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[ProtocolVersion::DRAFT]));
        response.set_srep(srep);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 384, 536]);
    }
}
