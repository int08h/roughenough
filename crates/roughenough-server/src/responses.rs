use std::net::SocketAddr;

use roughenough_keys::online::onlinekey::OnlineKey;
use roughenough_merkle::{MerklePath, MerkleTree};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{MerkleRoot, Nonce, ProtocolVersion, PublicKey};
use roughenough_protocol::wire::ToFrame;

use crate::keysource::KeySource;
use crate::metrics::types::ResponseMetrics;

/// Serialization buffer for one framed response.
pub(crate) const RESPONSE_BUF_SIZE: usize = 1024;

// Largest framed response:
//   12 (framing) + 56 (7-tag header) + 64 (SIG) + 32 (NONC) + 4 (TYPE)
//   + 8 * 32 (PATH) + 120 (SREP with an 8-entry VERS) + 152 (CERT) + 4 (INDX)
const MAX_FRAMED_RESPONSE_SIZE: usize = 700;
const _: () = assert!(RESPONSE_BUF_SIZE >= MAX_FRAMED_RESPONSE_SIZE);

#[derive(Debug)]
pub struct PendingRequest {
    nonce: Nonce,
    src_addr: SocketAddr,
    /// The protocol version negotiated for this request's response
    version: ProtocolVersion,
}

/// Per-version response template. CERT persists until key rotation.
/// SREP and SIG are re-signed once per batch (`batch_id` tracks which
/// batch last signed them); PATH, NONC, and INDX are overwritten
/// per request.
struct VersionTemplate {
    version: ProtocolVersion,
    batch_id: u64,
    response: Response,
}

pub struct ResponseHandler {
    batch_size: usize,
    merkle_tree: MerkleTree,
    merkle_path: MerklePath,
    key_source: KeySource,
    online_key: OnlineKey,
    response_metrics: ResponseMetrics,
    requests: Vec<PendingRequest>,
    batch_versions: Vec<ProtocolVersion>,
    version_templates: Vec<VersionTemplate>,
    batch_id: u64,
    response_buf: [u8; RESPONSE_BUF_SIZE],
}

impl ResponseHandler {
    /// Maximum distinct protocol versions signed per batch.
    pub const MAX_VERSIONS_PER_BATCH: usize = 4;

    /// Off-list draft versions compete for the slots left after reserving a slot
    /// for each advertised version.
    const MAX_OFFLIST_VERSIONS: usize =
        Self::MAX_VERSIONS_PER_BATCH - ProtocolVersion::ADVERTISED.len();

    pub fn new(batch_size: u8, key_source: KeySource) -> Self {
        let batch_size = batch_size as usize;
        let online_key = key_source.make_online_key();
        let mut merkle_tree = MerkleTree::new();

        merkle_tree.reserve(batch_size);

        Self {
            batch_size,
            merkle_tree,
            key_source,
            online_key,
            merkle_path: MerklePath::default(),
            response_metrics: ResponseMetrics::default(),
            requests: Vec::with_capacity(batch_size),
            batch_versions: Vec::with_capacity(Self::MAX_VERSIONS_PER_BATCH),
            version_templates: Vec::with_capacity(Self::MAX_VERSIONS_PER_BATCH),
            batch_id: 0,
            response_buf: [0u8; RESPONSE_BUF_SIZE],
        }
    }

    /// Add a request to the pending batch. Returns `false` (and does not add
    /// the request) when its negotiated version would exceed the batch's
    /// distinct versions cap; advertised versions always fit.
    #[must_use = "the request is dropped when the batch's distinct versions cap is reached"]
    pub fn add_request(
        &mut self,
        request_bytes: &[u8],
        request: Request,
        version: ProtocolVersion,
        src_addr: SocketAddr,
    ) -> bool {
        debug_assert!(self.requests.len() < self.batch_size, "Batch size exceeded");

        if !self.batch_versions.contains(&version) {
            if self.would_exceed_offlist_cap(&version) {
                return false;
            }
            self.batch_versions.push(version);
        }

        self.merkle_tree.push_leaf(request_bytes);
        self.requests.push(PendingRequest {
            nonce: *request.nonc(),
            src_addr,
            version,
        });
        true
    }

    /// Returns `true` if the batch contains more than `MAX_OFFLIST_VERSIONS`
    /// non-advertised versions.
    fn would_exceed_offlist_cap(&self, version: &ProtocolVersion) -> bool {
        // Advertised versions are always allowed.
        if ProtocolVersion::ADVERTISED.contains(version) {
            return false;
        }

        let num_offlist = self
            .batch_versions
            .iter()
            .filter(|v| !ProtocolVersion::ADVERTISED.contains(v))
            .count();

        num_offlist >= Self::MAX_OFFLIST_VERSIONS
    }

    pub fn replace_online_key(&mut self) {
        self.online_key = self.key_source.make_online_key();
        self.version_templates.clear();
    }

    /// Process all responses. `callback` receives each response as a borrowed slice that's
    /// valid only during the callback.
    pub fn process_responses<F>(&mut self, mut callback: F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        if self.requests.is_empty() {
            return;
        }

        self.response_metrics
            .add_batch_size(self.requests.len() as u8);

        let root_hash: [u8; 32] = self.merkle_tree.compute_root();
        let merkle_root = MerkleRoot::from(root_hash);

        self.batch_id += 1;

        for index in 0..self.requests.len() {
            let version = self.requests[index].version;
            let slot = self.template_slot_for(version, &merkle_root);

            self.merkle_path.clear();
            self.merkle_tree.get_paths_to(index, &mut self.merkle_path);

            let nonce = self.requests[index].nonce;
            let response = &mut self.version_templates[slot].response;
            response.copy_path(&self.merkle_path);
            response.set_nonc(nonce);
            response.set_indx(index as u32);

            let mut cursor = ParseCursor::new(&mut self.response_buf);
            response
                .to_frame(&mut cursor)
                .expect("to_frame(ParseCursor) should be infallible");

            let frame_size = response.frame_size();
            self.response_metrics.add_bytes_sent(frame_size);

            callback(
                self.requests[index].src_addr,
                &self.response_buf[..frame_size],
            );
        }
    }

    /// Return the index of a template carrying this batch's SREP and SIG for
    /// `version`, signing it if this batch has not yet done so.
    fn template_slot_for(&mut self, version: ProtocolVersion, merkle_root: &MerkleRoot) -> usize {
        let existing = self
            .version_templates
            .iter()
            .position(|t| t.version == version);

        let slot = match existing {
            Some(slot) => {
                if self.version_templates[slot].batch_id == self.batch_id {
                    return slot;
                }
                slot
            }
            None if self.version_templates.len() < Self::MAX_VERSIONS_PER_BATCH => {
                let mut response = Response::default();
                response.set_cert(self.online_key.cert().clone());
                self.version_templates.push(VersionTemplate {
                    version,
                    batch_id: 0,
                    response,
                });
                self.version_templates.len() - 1
            }
            None => {
                let slot = self
                    .version_templates
                    .iter()
                    .position(|t| t.batch_id != self.batch_id)
                    .expect("distinct-version cap guarantees a stale slot");
                self.version_templates[slot].version = version;
                slot
            }
        };

        let (srep, sig) = self.online_key.make_srep(version, merkle_root);
        let template = &mut self.version_templates[slot];
        template.response.set_srep(srep);
        template.response.set_sig(sig);
        template.batch_id = self.batch_id;
        slot
    }

    pub fn public_key(&self) -> PublicKey {
        self.online_key.public_key()
    }

    pub fn long_term_public_key(&self) -> PublicKey {
        self.key_source.public_key()
    }

    pub fn clear(&mut self) {
        self.merkle_tree.clear();
        self.requests.clear();
        self.batch_versions.clear();
    }

    #[allow(dead_code)] // used in worker metrics collection
    pub fn metrics(&self) -> ResponseMetrics {
        self.response_metrics
    }

    #[allow(dead_code)] // used in worker metrics collection
    pub fn reset_metrics(&mut self) {
        self.response_metrics.reset_metrics();
    }

    #[cfg(test)]
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    #[cfg(test)]
    pub fn num_pending(&self) -> usize {
        self.requests.len()
    }
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::cursor::ParseCursor;
    use roughenough_protocol::request::Request;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::wire::{FromWire, ToWire};

    use super::*;
    use crate::test_utils::new_response_handler;

    fn create_test_request(nonce_value: u8) -> Request {
        let nonce = Nonce::from([nonce_value; 32]);
        Request::new(&nonce)
    }

    #[test]
    fn pending_request_stays_small() {
        assert!(
            size_of::<PendingRequest>() < 128,
            "PendingRequest grew to {} bytes",
            size_of::<PendingRequest>()
        );
    }

    #[test]
    fn clear_state() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Add a request
        let request = create_test_request(42);
        assert!(responder.add_request(
            &request.as_bytes().unwrap(),
            request,
            ProtocolVersion::DRAFT,
            addr,
        ));

        assert_eq!(responder.num_pending(), 1);
        assert!(!responder.merkle_tree().is_empty());

        responder.clear();

        assert_eq!(responder.num_pending(), 0);
        assert!(responder.merkle_tree().is_empty());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn batch_size_limit_exceeded_panics() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Add requests up to batch size
        for i in 0..64 {
            let request = create_test_request(i as u8);
            assert!(responder.add_request(
                &request.as_bytes().unwrap(),
                request,
                ProtocolVersion::DRAFT,
                addr,
            ));
        }

        assert_eq!(responder.num_pending(), 64);

        // This should trigger the batch size limit debug assertion in add_request
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let request = create_test_request(100);
            assert!(responder.add_request(
                &request.as_bytes().unwrap(),
                request,
                ProtocolVersion::DRAFT,
                addr,
            ));
        }));

        assert!(result.is_err(), "Should panic when batch size is exceeded");
    }

    #[test]
    fn single_request_response_roundtrips() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request(42);
        let expected_nonce = *request.nonc();
        assert!(responder.add_request(
            &request.as_bytes().unwrap(),
            request,
            ProtocolVersion::DRAFT,
            addr,
        ));

        let mut responses = Vec::new();
        responder.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);
        assert!(response_bytes.starts_with(b"ROUGHTIM"));

        let mut response_data = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut response_data);
        let resp = Response::from_wire(&mut cursor).unwrap();
        assert_eq!(resp.nonc(), &expected_nonce);
    }

    #[test]
    fn multiple_requests_responses_roundtrip() {
        let mut responder = new_response_handler();

        let num_requests = 5;
        let mut expected_addrs = Vec::new();
        let mut expected_nonces = Vec::new();

        // Add multiple requests
        for i in 0..num_requests {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8080 + i).parse().unwrap();
            let request = create_test_request(i as u8);

            expected_addrs.push(addr);
            expected_nonces.push(*request.nonc());
            assert!(responder.add_request(
                &request.as_bytes().unwrap(),
                request,
                ProtocolVersion::DRAFT,
                addr,
            ));
        }

        let mut responses = Vec::new();
        responder.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), num_requests);

        for (idx, (response_addr, response_bytes)) in responses.iter().enumerate() {
            assert_eq!(*response_addr, expected_addrs[idx]);
            assert!(response_bytes.starts_with(b"ROUGHTIM"));

            // Parse and verify the response
            let mut response_data = response_bytes[12..].to_vec();
            let mut cursor = ParseCursor::new(&mut response_data);
            let resp = Response::from_wire(&mut cursor).unwrap();
            assert_eq!(resp.nonc(), &expected_nonces[idx]);
            assert_eq!(resp.indx(), idx as u32);
        }
    }

    #[test]
    fn consecutive_batches_do_not_bleed_state_through_reused_templates() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let run_batch = |responder: &mut ResponseHandler,
                         requests: &[(u8, ProtocolVersion)]|
         -> Vec<Response> {
            for (nonce_byte, version) in requests {
                let request = create_test_request(*nonce_byte);
                assert!(responder.add_request(
                    &request.as_bytes().unwrap(),
                    request,
                    *version,
                    addr,
                ));
            }
            let mut responses = Vec::new();
            responder.process_responses(|_, bytes| {
                let mut data = bytes.to_vec();
                let mut cursor = ParseCursor::new(&mut data);
                use roughenough_protocol::wire::FromFrame;
                responses.push(Response::from_frame(&mut cursor).unwrap());
            });
            responder.clear();
            responses
        };

        let batch1 = run_batch(&mut responder, &[(1, ProtocolVersion::DRAFT)]);
        let batch2 = run_batch(
            &mut responder,
            &[(2, ProtocolVersion::RFC), (3, ProtocolVersion::DRAFT)],
        );

        assert_eq!(batch1.len(), 1);
        assert_eq!(batch2.len(), 2);

        // batch 2 responses must commit to batch 2's root, not batch 1's,
        // including the response using the template slot batch 1 created
        assert_ne!(batch1[0].srep().root(), batch2[0].srep().root());
        assert_eq!(batch2[0].srep().root(), batch2[1].srep().root());

        assert_eq!(*batch1[0].srep().ver(), ProtocolVersion::DRAFT);
        assert_eq!(*batch2[0].srep().ver(), ProtocolVersion::RFC);
        assert_eq!(*batch2[1].srep().ver(), ProtocolVersion::DRAFT);

        assert_eq!(batch1[0].nonc(), &Nonce::from([1u8; 32]));
        assert_eq!(batch2[0].nonc(), &Nonce::from([2u8; 32]));
        assert_eq!(batch2[1].nonc(), &Nonce::from([3u8; 32]));

        assert_eq!(batch2[0].indx(), 0);
        assert_eq!(batch2[1].indx(), 1);

        // distinct versions in one batch get distinct signatures; the reused
        // DRAFT slot must have been re-signed for batch 2's root
        assert_ne!(batch2[0].sig(), batch2[1].sig());
        assert_ne!(batch1[0].sig(), batch2[1].sig());
    }

    #[test]
    fn key_rotation_invalidates_reused_templates() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let one_response = |responder: &mut ResponseHandler, nonce_byte: u8| -> Response {
            let request = create_test_request(nonce_byte);
            assert!(responder.add_request(
                &request.as_bytes().unwrap(),
                request,
                ProtocolVersion::DRAFT,
                addr,
            ));
            let mut responses = Vec::new();
            responder.process_responses(|_, bytes| {
                let mut data = bytes.to_vec();
                let mut cursor = ParseCursor::new(&mut data);
                use roughenough_protocol::wire::FromFrame;
                responses.push(Response::from_frame(&mut cursor).unwrap());
            });
            responder.clear();
            responses.pop().unwrap()
        };

        let before = one_response(&mut responder, 1);
        responder.replace_online_key();
        let after = one_response(&mut responder, 2);

        assert_ne!(
            before.cert().dele().pubk(),
            after.cert().dele().pubk(),
            "post-rotation response must carry the new online key's CERT"
        );
    }

    #[test]
    fn worst_case_response_fits_in_response_buf() {
        use roughenough_protocol::tags::{ProtocolVersion, SignedResponse, SupportedVersions};

        let path_bytes = [0u8; 8 * 32];
        let path = roughenough_protocol::tags::MerklePath::try_from(path_bytes.as_slice()).unwrap();

        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[ProtocolVersion::DRAFT; 8]));

        let mut response = Response::default();
        response.set_path(path);
        response.set_srep(srep);

        assert_eq!(response.frame_size(), MAX_FRAMED_RESPONSE_SIZE);
    }

    #[test]
    fn responder_does_nothing_with_no_requests() {
        let mut responder = new_response_handler();

        let mut call_count = 0;
        responder.process_responses(|_addr, _bytes| {
            call_count += 1;
        });

        assert_eq!(call_count, 0);
    }
}
