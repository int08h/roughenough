use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{BufferTooSmall, UnexpectedTags};
use crate::header::{Header, Header7};
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
        let header = Header7::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut response = Response {
            header,
            ..Default::default()
        };

        response.signature = Signature::from_wire(cursor)?;
        response.nonce = Nonce::from_wire(cursor)?;

        let msg_type = MessageType::from_wire(cursor)?;
        if msg_type != MessageType::Response {
            return Err(Error::InvalidMessageType(msg_type as u32));
        }

        let path_len = (response.header.offsets[3] - response.header.offsets[2]) as usize;
        response.path = MerklePath::from_wire_n(cursor, path_len)?;

        response.srep = SignedResponse::from_wire(cursor)?;
        response.cert = Certificate::from_wire(cursor)?;

        // cursor holds remainder of message
        response.index = cursor.try_get_u32_le()?;

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
    use crate::tags::ProtocolVersion::{Google, RfcDraft14};
    use crate::tags::{MerklePath, MessageType, SignedResponse, SupportedVersions};
    use crate::wire::FromFrame;

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
        //         version: RfcDraft14,
        //         radius: 5,
        //         midpoint: 1748359193,
        //         supported_versions: VERS {
        //             num_versions: 2,
        //             versions: [ Google, RfcDraft14, ],
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

        assert_eq!(response.header().offsets(), [64, 96, 100, 356, 452, 604]);
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
        assert_eq!(srep.header().offsets(), [4, 8, 16, 24]);
        assert_eq!(
            srep.header().tags(),
            [Tag::VER, Tag::RADI, Tag::MIDP, Tag::VERS, Tag::ROOT]
        );
        assert_eq!(*srep.ver(), RfcDraft14);
        assert_eq!(srep.radi(), 5);
        assert_eq!(srep.midp(), 1748359193);
        assert_eq!(srep.vers().versions(), &[Google, RfcDraft14]);
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

        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[Google, RfcDraft14]));
        response.set_srep(srep);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 388, 540]);

        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[RfcDraft14]));
        response.set_srep(srep);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 384, 536]);
    }
}
