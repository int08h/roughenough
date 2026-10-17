use std::net::SocketAddr;

use roughenough_common::clocksource::ClockSource;
use roughenough_keys::online::OnlineKey;
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
    negotiated_version: ProtocolVersion,
}

/// Per-version response template:
///  - CERT persists until key rotation.
///  - SREP and SIG are re-signed once per batch (`batch_id` tracks which batch last signed them).
///  - PATH, NONC, and INDX are overwritten per request.
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
    version_templates: Vec<VersionTemplate>,
    batch_id: u64,
    response_buf: [u8; RESPONSE_BUF_SIZE],
}

impl ResponseHandler {
    pub fn new(batch_size: u8, key_source: KeySource) -> Self {
        let batch_size = batch_size as usize;
        let online_key = key_source.make_online_key();
        let merkle_tree = MerkleTree::with_capacity(batch_size);

        Self {
            batch_size,
            merkle_tree,
            key_source,
            online_key,
            merkle_path: MerklePath::default(),
            response_metrics: ResponseMetrics::default(),
            requests: Vec::with_capacity(batch_size),
            version_templates: Vec::with_capacity(ProtocolVersion::ADVERTISED.len()),
            batch_id: 0,
            response_buf: [0u8; RESPONSE_BUF_SIZE],
        }
    }

    /// Add a request to the pending batch.
    pub fn add_request(
        &mut self,
        request_bytes: &[u8],
        request: Request,
        negotiated_version: ProtocolVersion,
        src_addr: SocketAddr,
    ) {
        debug_assert!(self.requests.len() < self.batch_size, "Batch size exceeded");
        debug_assert!(
            ProtocolVersion::ADVERTISED.contains(&negotiated_version),
            "{negotiated_version:?} is not advertised"
        );

        self.merkle_tree.push_leaf(request_bytes);
        self.requests.push(PendingRequest {
            nonce: *request.nonc(),
            src_addr,
            negotiated_version,
        });
    }

    pub fn replace_online_key(&mut self) {
        self.online_key = self.key_source.make_online_key();
        self.version_templates.clear();
    }

    /// Process all responses, then clear the batch. `callback` receives each response as a
    /// borrowed slice that's valid only during the callback.
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
            let version = self.requests[index].negotiated_version;
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

        self.merkle_tree.clear();
        self.requests.clear();
    }

    /// Return the index of a template carrying this batch's SREP and SIG for
    /// `version`, signing it if this batch has not yet done so.
    fn template_slot_for(&mut self, version: ProtocolVersion, merkle_root: &MerkleRoot) -> usize {
        let existing = self
            .version_templates
            .iter()
            .position(|t| t.version == version);

        // At most one template per advertised version
        let slot = match existing {
            Some(slot) if self.version_templates[slot].batch_id == self.batch_id => return slot,
            Some(slot) => slot,
            None => {
                let mut response = Response::default();
                response.set_cert(self.online_key.cert().clone());
                self.version_templates.push(VersionTemplate {
                    version,
                    batch_id: 0,
                    response,
                });
                self.version_templates.len() - 1
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

    /// The online key's delegation span, (MINT, MAXT)
    pub fn key_validity(&self) -> (u64, u64) {
        let dele = self.online_key.cert().dele();
        (dele.mint(), dele.maxt())
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn clock(&self) -> &ClockSource {
        self.key_source.clock()
    }

    pub fn long_term_public_key(&self) -> PublicKey {
        self.key_source.public_key()
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
    use roughenough_protocol::request::Request;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::wire::FromFrame;

    use super::*;
    use crate::test_utils::new_response_handler;

    /// Adds a version-1 request, hashing its framed bytes as the server does
    fn add(responder: &mut ResponseHandler, nonce: u8, addr: SocketAddr) {
        let nonce = Nonce::from([nonce; 32]);
        let request = Request::new(&nonce);
        let request_bytes = request.as_frame_bytes().unwrap();
        responder.add_request(&request_bytes, request, ProtocolVersion::RFC, addr);
    }

    fn drain(responder: &mut ResponseHandler) -> Vec<(SocketAddr, Response)> {
        let mut responses = Vec::new();
        responder.process_responses(|addr, bytes| {
            let response = Response::from_frame_bytes(bytes).unwrap();
            responses.push((addr, response));
        });
        responses
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
    fn process_responses_leaves_handler_empty() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        add(&mut responder, 42, addr);

        assert_eq!(responder.num_pending(), 1);
        assert!(!responder.merkle_tree().is_empty());

        responder.process_responses(|_, _| {});

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
            add(&mut responder, i, addr);
        }

        assert_eq!(responder.num_pending(), 64);

        // This should trigger the batch size limit debug assertion in add_request
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            add(&mut responder, 100, addr);
        }));

        assert!(result.is_err(), "Should panic when batch size is exceeded");
    }

    #[test]
    fn single_request_response_roundtrips() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        add(&mut responder, 42, addr);

        let responses = drain(&mut responder);
        assert_eq!(responses.len(), 1);
        let (response_addr, response) = &responses[0];
        assert_eq!(*response_addr, addr);
        assert_eq!(response.nonc(), &Nonce::from([42; 32]));
    }

    #[test]
    fn multiple_requests_responses_roundtrip() {
        let mut responder = new_response_handler();

        let num_requests = 5;
        let mut expected_addrs = Vec::new();

        for i in 0..num_requests {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8080 + i).parse().unwrap();
            expected_addrs.push(addr);
            add(&mut responder, i as u8, addr);
        }

        let responses = drain(&mut responder);
        assert_eq!(responses.len(), num_requests);

        for (idx, (response_addr, response)) in responses.iter().enumerate() {
            assert_eq!(*response_addr, expected_addrs[idx]);
            assert_eq!(response.nonc(), &Nonce::from([idx as u8; 32]));
            assert_eq!(response.indx(), idx as u32);
        }
    }

    #[test]
    fn response_vers_contains_negotiated_ver() {
        // RFC 5.2.5: VERS MUST contain VER. Our client rejects a response that breaks this.
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        for version in ProtocolVersion::ADVERTISED {
            let mut responder = new_response_handler();
            let request = Request::new_with_versions(&Nonce::from([7; 32]), &[version]);
            let request_bytes = request.as_frame_bytes().unwrap();
            responder.add_request(&request_bytes, request, version, addr);

            let responses = drain(&mut responder);
            assert_eq!(responses.len(), 1);

            let srep = responses[0].1.srep();
            assert_eq!(*srep.ver(), version);
            assert!(
                srep.vers().versions().contains(srep.ver()),
                "VERS {:?} omits VER {version:?}",
                srep.vers()
            );
        }
    }

    #[test]
    fn consecutive_batches_do_not_bleed_state_through_reused_templates() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        add(&mut responder, 1, addr);
        let batch1: Vec<Response> = drain(&mut responder).into_iter().map(|(_, r)| r).collect();
        add(&mut responder, 2, addr);
        add(&mut responder, 3, addr);
        let batch2: Vec<Response> = drain(&mut responder).into_iter().map(|(_, r)| r).collect();

        assert_eq!(batch1.len(), 1);
        assert_eq!(batch2.len(), 2);

        // batch 2 responses must commit to batch 2's root, not batch 1's,
        // even though they reuse the template batch 1 created
        assert_ne!(batch1[0].srep().root(), batch2[0].srep().root());
        assert_eq!(batch2[0].srep().root(), batch2[1].srep().root());

        for response in batch1.iter().chain(&batch2) {
            assert_eq!(*response.srep().ver(), ProtocolVersion::RFC);
        }

        assert_eq!(batch1[0].nonc(), &Nonce::from([1u8; 32]));
        assert_eq!(batch2[0].nonc(), &Nonce::from([2u8; 32]));
        assert_eq!(batch2[1].nonc(), &Nonce::from([3u8; 32]));

        assert_eq!(batch2[0].indx(), 0);
        assert_eq!(batch2[1].indx(), 1);

        // one SREP signature per batch; the reused template must have been
        // re-signed for batch 2's root
        assert_eq!(batch2[0].sig(), batch2[1].sig());
        assert_ne!(batch1[0].sig(), batch2[0].sig());
    }

    #[test]
    fn key_rotation_invalidates_reused_templates() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        add(&mut responder, 1, addr);
        let (_, before) = drain(&mut responder).pop().unwrap();
        responder.replace_online_key();
        add(&mut responder, 2, addr);
        let (_, after) = drain(&mut responder).pop().unwrap();

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
