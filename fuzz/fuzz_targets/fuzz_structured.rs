#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use protocol::cursor::ParseCursor;
use protocol::request::{Request, REQUEST_SIZE};
use protocol::response::Response;
use protocol::tags::{
    Certificate, Delegation, MerklePath, Nonce, PublicKey, 
    Signature, SignedResponse, SrvCommitment, SupportedVersions, Version
};
use protocol::wire::{FromWire, ToWire};

// Arbitrary implementations for structured fuzzing

#[derive(Arbitrary, Debug, Clone)]
struct FuzzVersion {
    version: u8,
}

impl From<FuzzVersion> for Version {
    fn from(fuzz: FuzzVersion) -> Self {
        match fuzz.version % 3 {
            0 => Version::Google,
            1 => Version::RfcDraft14,
            _ => Version::Invalid,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzNonce {
    data: [u8; 32],
}

impl From<FuzzNonce> for Nonce {
    fn from(fuzz: FuzzNonce) -> Self {
        Nonce::from(fuzz.data)
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzPublicKey {
    data: [u8; 32],
}

impl From<FuzzPublicKey> for PublicKey {
    fn from(fuzz: FuzzPublicKey) -> Self {
        PublicKey::from(fuzz.data)
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzSignature {
    data: [u8; 64],
}

impl From<FuzzSignature> for Signature {
    fn from(fuzz: FuzzSignature) -> Self {
        Signature::from(fuzz.data)
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzSrvCommitment {
    data: [u8; 32],
}

impl From<FuzzSrvCommitment> for SrvCommitment {
    fn from(fuzz: FuzzSrvCommitment) -> Self {
        SrvCommitment::from(fuzz.data)
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzMerklePath {
    // Limit path elements to reasonable size
    elements: Vec<[u8; 32]>,
}

impl FuzzMerklePath {
    fn to_merkle_path(&self) -> MerklePath {
        // Limit to max 32 elements (2^5 leaves), per protocol spec
        let limited_elements: Vec<[u8; 32]> = self.elements
            .iter()
            .take(MerklePath::MAX_PATHS)
            .cloned()
            .collect();
        
        let mut path = MerklePath::default();
        for element in limited_elements {
            path.push_element(&element);
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
        let versions: Vec<Version> = self.versions
            .iter()
            .take(SupportedVersions::MAX_VERSIONS) // Limit number of versions
            .map(|v| Version::from(v.clone()))
            .filter(|v| *v != Version::Invalid)
            .collect();
        
        if versions.is_empty() {
            SupportedVersions::from(&[Version::RfcDraft14][..])
        } else {
            SupportedVersions::from(&versions[..])
        }
    }
}

// Structured request fuzzing
#[derive(Arbitrary, Debug)]
struct FuzzRequest {
    nonce: FuzzNonce,
    srv: Option<FuzzSrvCommitment>,
}

impl FuzzRequest {
    fn to_request(&self) -> Request {
        let nonce = Nonce::from(self.nonce.clone());
        if self.srv.is_some() {
            let srv = SrvCommitment::from(self.srv.clone().unwrap());
            Request::new_with_server(&nonce, &srv)
        } else {
            Request::new(&nonce)
        }
    }
}

// Structured delegation fuzzing
#[derive(Arbitrary, Debug)]
struct FuzzDelegation {
    public_key: FuzzPublicKey,
    min_time: u64,
    max_time: u64,
}

impl FuzzDelegation {
    fn to_delegation(&self) -> Delegation {
        let pubk = PublicKey::from(self.public_key.clone());
        // Ensure max_time >= min_time
        let max_time = self.min_time.saturating_add(self.max_time.saturating_sub(self.min_time));
        Delegation::new(pubk, self.min_time, std::time::Duration::from_secs(max_time - self.min_time))
    }
}

// Structured SREP fuzzing
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
        srep.set_ver(Version::from(self.version.clone()));
        srep.set_radi(self.radius.min(10)); // Cap at 10 seconds
        srep.set_midp(self.midpoint);
        srep.set_vers(&self.supported_versions.to_supported_versions());
        srep.set_root(&self.merkle_root.into());
        srep
    }
}

// Structured Certificate fuzzing
#[derive(Arbitrary, Debug)]
struct FuzzCertificate {
    signature: FuzzSignature,
    delegation: FuzzDelegation,
}

impl FuzzCertificate {
    fn to_certificate(&self) -> Certificate {
        let sig = Signature::from(self.signature.clone());
        let dele = self.delegation.to_delegation();
        Certificate::new(sig, dele)
    }
}

// Structured Response fuzzing
#[derive(Arbitrary, Debug)]
struct FuzzResponse {
    signature: FuzzSignature,
    nonce: FuzzNonce,
    path: FuzzMerklePath,
    srep: FuzzSignedResponse,
    cert: FuzzCertificate,
    index: u32,
}

impl FuzzResponse {
    fn to_response(&self) -> Response {
        let mut response = Response::default();
        response.set_sig(Signature::from(self.signature.clone()));
        response.set_nonc(Nonce::from(self.nonce.clone()));
        response.set_path(self.path.to_merkle_path());
        response.set_srep(self.srep.to_signed_response());
        response.set_cert(self.cert.to_certificate());
        response.set_indx(self.index);
        response
    }
}

// Main fuzz target
fuzz_target!(|data: &[u8]| {
    // Try to parse the data as structured input
    let mut u = Unstructured::new(data);
    
    // Fuzz Request parsing and encoding
    if let Ok(fuzz_req) = FuzzRequest::arbitrary(&mut u) {
        let request = fuzz_req.to_request();
        
        // Test encoding
        let mut buffer = vec![0u8; REQUEST_SIZE];
        let mut cursor = ParseCursor::new(&mut buffer);
        
        // Write frame header
        // Write ROUGHTIM magic in big-endian
        cursor.put_slice(&[0x52, 0x4f, 0x55, 0x47, 0x48, 0x54, 0x49, 0x4d]);
        cursor.put_u32_le(1012); // Fixed frame length for requests
        
        // Write request
        if request.to_wire(&mut cursor).is_ok() {
            // Try to parse it back
            let mut parse_cursor = ParseCursor::new(&mut buffer);
            let _ = Request::from_wire(&mut parse_cursor);
        }
    }
    
    // Fuzz Delegation
    if let Ok(fuzz_dele) = FuzzDelegation::arbitrary(&mut u) {
        let delegation = fuzz_dele.to_delegation();
        
        // Test round-trip
        if let Ok(encoded) = delegation.as_bytes() {
            let mut encoded_copy = encoded.clone();
            let mut cursor = ParseCursor::new(&mut encoded_copy);
            let _ = Delegation::from_wire(&mut cursor);
        }
    }
    
    // Fuzz SignedResponse
    if let Ok(fuzz_srep) = FuzzSignedResponse::arbitrary(&mut u) {
        let srep = fuzz_srep.to_signed_response();
        
        // Test encoding
        if let Ok(encoded) = srep.as_bytes() {
            let mut encoded_copy = encoded.clone();
            let mut cursor = ParseCursor::new(&mut encoded_copy);
            let _ = SignedResponse::from_wire(&mut cursor);
        }
    }
    
    // Fuzz Response
    if let Ok(fuzz_resp) = FuzzResponse::arbitrary(&mut u) {
        let response = fuzz_resp.to_response();
        
        // Test encoding
        if let Ok(encoded) = response.as_bytes() {
            let mut encoded_copy = encoded.clone();
            let mut cursor = ParseCursor::new(&mut encoded_copy);
            let _ = Response::from_wire(&mut cursor);
        }
    }
    
    // Fuzz Certificate
    if let Ok(fuzz_cert) = FuzzCertificate::arbitrary(&mut u) {
        let cert = fuzz_cert.to_certificate();
        
        // Test round-trip
        if let Ok(encoded) = cert.as_bytes() {
            let mut encoded_copy = encoded.clone();
            let mut cursor = ParseCursor::new(&mut encoded_copy);
            let _ = Certificate::from_wire(&mut cursor);
        }
    }
});