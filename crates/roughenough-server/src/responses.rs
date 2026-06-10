use std::net::SocketAddr;

use roughenough_keys::online::onlinekey::OnlineKey;
use roughenough_merkle::{MerklePath, MerkleTree};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{MerkleRoot, ProtocolVersion, PublicKey};
use roughenough_protocol::wire::ToFrame;

use crate::keysource::KeySource;
use crate::metrics::types::ResponseMetrics;

#[derive(Debug)]
pub struct PendingRequest {
    request: Request,
    src_addr: SocketAddr,
    /// The protocol version negotiated for this request's response
    version: ProtocolVersion,
}

pub struct ResponseHandler {
    batch_size: usize,
    merkle_tree: MerkleTree,
    merkle_path: MerklePath,
    key_source: KeySource,
    online_key: OnlineKey,
    response_metrics: ResponseMetrics,
    requests: Vec<PendingRequest>,
    /// Distinct negotiated versions in the pending batch, bounded by
    /// `MAX_VERSIONS_PER_BATCH`
    batch_versions: Vec<ProtocolVersion>,
    /// Per-version response templates; the Vec is reused across batches to
    /// avoid re-allocating the template storage
    version_templates: Vec<(ProtocolVersion, Response)>,
    response_buf: [u8; 1024],
}

impl ResponseHandler {
    /// Maximum distinct protocol versions signed per batch. Each distinct
    /// version requires its own SREP signature; without a bound, an adversary
    /// offering a unique draft version per request would force one signature
    /// per request.
    pub const MAX_VERSIONS_PER_BATCH: usize = 4;

    /// Off-list draft versions compete for the slots left after reserving a slot
    /// for each advertised version, so a flood of unique draft values can never
    /// starve clients requesting an advertised version.
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
            response_buf: [0u8; 1024],
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
            request,
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

        // One Merkle tree commits to every request in the batch. CERT, SREP,
        // and SIG are shared by all responses with the same negotiated version;
        // a template (and one signature) is created lazily per distinct version
        // present in the batch, so a homogeneous batch still signs exactly once.
        let root_hash: [u8; 32] = self.merkle_tree.compute_root();
        let merkle_root = MerkleRoot::from(root_hash);
        let cert = self.online_key.cert().clone();

        self.version_templates.clear();

        for (index, pending_req) in self.requests.iter().enumerate() {
            let slot = match self
                .version_templates
                .iter()
                .position(|(version, _)| *version == pending_req.version)
            {
                Some(slot) => slot,
                None => {
                    let (srep, sig) = self.online_key.make_srep(pending_req.version, &merkle_root);
                    let mut template = Response::default();
                    template.set_cert(cert.clone());
                    template.set_srep(srep);
                    template.set_sig(sig);
                    self.version_templates.push((pending_req.version, template));
                    self.version_templates.len() - 1
                }
            };

            // Build the Merkle path for this Request's position in the tree
            self.merkle_path.clear();
            self.merkle_tree.get_paths_to(index, &mut self.merkle_path);

            // Copy the common response as a template and set the elements unique to this response
            // (merkle path, nonce, and index)
            let mut response = self.version_templates[slot].1.clone();
            response.copy_path(&self.merkle_path);
            response.set_nonc(*pending_req.request.nonc());
            response.set_indx(index as u32);

            // Wire-encode the response
            let mut cursor = ParseCursor::new(&mut self.response_buf);
            response
                .to_frame(&mut cursor)
                .expect("to_frame(ParseCursor) should be infallible");

            let frame_size = response.frame_size();
            self.response_metrics.add_bytes_sent(frame_size);

            callback(pending_req.src_addr, &self.response_buf[..frame_size]);
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.online_key.public_key()
    }

    /// The server's long-term identity public key (the key clients commit to
    /// with the SRV tag)
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
        self.response_metrics.clone()
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
    fn responder_does_nothing_with_no_requests() {
        let mut responder = new_response_handler();

        let mut call_count = 0;
        responder.process_responses(|_addr, _bytes| {
            call_count += 1;
        });

        assert_eq!(call_count, 0);
    }
}
