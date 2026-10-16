#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::error::Error;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{
    Certificate, Delegation, MerklePath, Nonce, ProtocolVersion, PublicKey, Signature,
    SignedResponse, SrvCommitment, SupportedVersions,
};
use roughenough_protocol::wire::{FromFrame, FromWire, ToFrame, ToWire};

// Arbitrary implementations for structured fuzzing

#[derive(Arbitrary, Debug, Clone)]
struct FuzzVersion {
    version: u8,
}

impl From<FuzzVersion> for ProtocolVersion {
    fn from(fuzz: FuzzVersion) -> Self {
        match fuzz.version % 3 {
            0 => ProtocolVersion::RFC,
            1 => ProtocolVersion::DRAFT,
            _ => ProtocolVersion::INVALID,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzMerklePath {
    elements: Vec<[u8; 32]>,
}

impl FuzzMerklePath {
    fn to_merkle_path(&self) -> MerklePath {
        let mut path = MerklePath::default();
        for element in self.elements.iter().take(MerklePath::MAX_PATHS) {
            path.push_element(element);
        }
        path
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzSupportedVersions {
    versions: Vec<FuzzVersion>,
}

impl FuzzSupportedVersions {
    fn to_supported_versions(&self) -> SupportedVersions {
        let mut versions: Vec<ProtocolVersion> = self
            .versions
            .iter()
            .take(roughenough_protocol::version_list::VersionList::MAX_VERSIONS)
            .map(|v| ProtocolVersion::from(v.clone()))
            .filter(|v| *v != ProtocolVersion::INVALID)
            .collect();

        // VERS must be in ascending order with no duplicates (RFC 5.1.1, 5.2.5)
        versions.sort_by_key(|v| v.as_u32());
        versions.dedup_by_key(|v| v.as_u32());

        if versions.is_empty() {
            SupportedVersions::from(&[ProtocolVersion::RFC][..])
        } else {
            SupportedVersions::from(&versions[..])
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzRequest {
    nonce: [u8; 32],
    srv: Option<[u8; 32]>,
}

impl FuzzRequest {
    fn to_request(&self) -> Request {
        let nonce = Nonce::from(self.nonce);
        match self.srv {
            Some(srv) => {
                let srv = SrvCommitment::from(srv);
                Request::new_with_server(&nonce, &srv)
            }
            None => Request::new(&nonce),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDelegation {
    public_key: [u8; 32],
    min_time: u64,
    max_time: u64,
}

impl FuzzDelegation {
    // The codec does not require MINT <= MAXT, so both are taken as given
    fn to_delegation(&self) -> Delegation {
        let pubk = PublicKey::from(self.public_key);
        let mut dele = Delegation::default();
        dele.set_pubk(pubk);
        dele.set_mint(self.min_time);
        dele.set_maxt(self.max_time);
        dele
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzSignedResponse {
    version: FuzzVersion,
    radius: u32,
    midpoint: u64,
    supported_versions: FuzzSupportedVersions,
    merkle_root: [u8; 32],
}

impl FuzzSignedResponse {
    fn to_signed_response(&self) -> SignedResponse {
        let mut srep = SignedResponse::default();
        srep.set_ver(ProtocolVersion::from(self.version.clone()));
        srep.set_radi(self.radius);
        srep.set_midp(self.midpoint);
        srep.set_vers(&self.supported_versions.to_supported_versions());
        srep.set_root(&self.merkle_root.into());
        srep
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzCertificate {
    signature: [u8; 64],
    delegation: FuzzDelegation,
}

impl FuzzCertificate {
    fn to_certificate(&self) -> Certificate {
        let sig = Signature::from(self.signature);
        let dele = self.delegation.to_delegation();
        Certificate::new(sig, dele)
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzResponse {
    signature: [u8; 64],
    nonce: [u8; 32],
    path: FuzzMerklePath,
    srep: FuzzSignedResponse,
    cert: FuzzCertificate,
    index: u32,
}

impl FuzzResponse {
    fn to_response(&self) -> Response {
        let mut response = Response::default();
        response.set_sig(Signature::from(self.signature));
        response.set_nonc(Nonce::from(self.nonce));
        response.set_path(self.path.to_merkle_path());
        response.set_srep(self.srep.to_signed_response());
        response.set_cert(self.cert.to_certificate());
        response.set_indx(self.index);
        response
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_req) = FuzzRequest::arbitrary(&mut u) {
        let request = fuzz_req.to_request();
        let mut bytes = request.as_frame_bytes().expect("request serializes");
        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Request::from_frame(&mut cursor).expect("request reparses");
        assert_eq!(parsed, request);
    }

    if let Ok(fuzz_dele) = FuzzDelegation::arbitrary(&mut u) {
        let dele = fuzz_dele.to_delegation();
        let mut bytes = dele.as_bytes().expect("dele serializes");
        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Delegation::from_wire(&mut cursor).expect("dele reparses");
        assert_eq!(parsed, dele);
    }

    // An INVALID version serializes but can never parse back
    if let Ok(fuzz_srep) = FuzzSignedResponse::arbitrary(&mut u) {
        let srep = fuzz_srep.to_signed_response();
        let mut bytes = srep.as_bytes().expect("srep serializes");
        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = SignedResponse::from_wire(&mut cursor);
        if *srep.ver() == ProtocolVersion::INVALID {
            assert!(matches!(parsed, Err(Error::InvalidVersion(0xffff_ffff))));
        } else {
            assert_eq!(parsed.expect("srep reparses"), srep);
        }
    }

    if let Ok(fuzz_resp) = FuzzResponse::arbitrary(&mut u) {
        let response = fuzz_resp.to_response();
        let mut bytes = response.as_bytes().expect("response serializes");
        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Response::from_wire(&mut cursor);
        if *response.srep().ver() == ProtocolVersion::INVALID {
            assert!(matches!(parsed, Err(Error::InvalidVersion(0xffff_ffff))));
        } else {
            assert_eq!(parsed.expect("response reparses"), response);
        }
    }

    if let Ok(fuzz_cert) = FuzzCertificate::arbitrary(&mut u) {
        let cert = fuzz_cert.to_certificate();
        let mut bytes = cert.as_bytes().expect("cert serializes");
        let mut cursor = ParseCursor::new(&mut bytes);
        let parsed = Certificate::from_wire(&mut cursor).expect("cert reparses");
        assert_eq!(parsed, cert);
    }
});
