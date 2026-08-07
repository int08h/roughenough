use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use data_encoding::BASE64;
use roughenough_client::measurement::MeasurementBuilder;
use roughenough_client::{CausalityViolation, MalfeasanceReport, REPORT_MEDIA_TYPE};
use roughenough_common::crypto::calculate_chained_nonce;
use roughenough_protocol::ToFrame;
use roughenough_protocol::tags::Nonce;
use roughenough_reporting_server::storage::{InMemoryStorage, ReportStorage};
use roughenough_reporting_server::{AppState, CreationResponse};
use roughenough_server::test_utils::TestContext;
use tokio::task::JoinHandle;

/// Finds an available port by binding to port 0
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Test server instance that runs in the background
struct TestServer {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl TestServer {
    /// Spawn a new test server on an available port
    async fn spawn() -> Self {
        Self::spawn_with_storage(Arc::new(InMemoryStorage::new())).await
    }

    /// Spawn a test server with specific storage
    async fn spawn_with_storage(storage: Arc<dyn ReportStorage>) -> Self {
        let port = find_available_port();
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();

        let state = AppState { storage };

        let app = roughenough_reporting_server::create_app(state);

        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        TestServer { addr, handle }
    }

    /// Get the base URL for this test server
    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Abort the server task when the test ends
        self.handle.abort();
    }
}

fn create_chained_report(midpoints: &[u64], first_rand: Option<[u8; 32]>) -> MalfeasanceReport {
    let mut prior_response: Option<Vec<u8>> = None;
    let mut measurements = Vec::new();

    for (i, &midpoint) in midpoints.iter().enumerate() {
        // one context per exchange; all contexts share a seed, so the
        // measurements present one server identity
        let mut ctx = TestContext::new(1);

        let (nonce, rand_value) = match prior_response.as_deref() {
            Some(prior) => {
                let rand = [0x22u8 + i as u8; 32];
                (calculate_chained_nonce(prior, &rand), Some(rand))
            }
            None => (Nonce::from([0x11u8; 32]), first_rand),
        };

        let (request, response) = ctx.create_interaction_pair_with_nonce(midpoint, &nonce);
        let response_bytes = response.as_frame_bytes().unwrap();

        let measurement = MeasurementBuilder::new()
            .server("127.0.0.1:8080".parse().unwrap())
            .hostname("test-server".to_string())
            .public_key(Some(ctx.key_source.public_key()))
            .request(request)
            .response(response)
            .response_bytes(response_bytes.clone())
            .rand_value(rand_value)
            .build()
            .unwrap();

        prior_response = Some(response_bytes);
        measurements.push(measurement);
    }

    let violation = CausalityViolation::new(&measurements, 0, measurements.len() - 1);
    MalfeasanceReport::from_violation(&violation)
}

fn create_test_malfeasance_report() -> MalfeasanceReport {
    let current_time = TestContext::new(1).clock.epoch_seconds();
    create_chained_report(&[current_time + 2_000_000, current_time], None)
}

#[tokio::test]
async fn test_health_endpoint() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/health", server.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "OK");
}

#[tokio::test]
async fn test_submit_valid_report() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();
    let report = create_test_malfeasance_report();

    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&report)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 201);

    let create_response: CreationResponse = response.json().await.unwrap();
    assert!(!create_response.id.is_empty());
}

#[tokio::test]
async fn test_retrieve_report() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();
    let report = create_test_malfeasance_report();

    // Submit report
    let submit_response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&report)
        .send()
        .await
        .unwrap();

    let create_response: CreationResponse = submit_response.json().await.unwrap();
    let report_id = create_response.id;

    // Retrieve report
    let get_response = client
        .get(format!(
            "{}/api/v1/reports/{}",
            server.base_url(),
            report_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(get_response.status(), 200);

    let stored_report: serde_json::Value = get_response.json().await.unwrap();

    // Verify stored report structure
    assert_eq!(stored_report["id"].as_str().unwrap(), report_id);
    assert!(stored_report["timestamp"].is_string());
    assert!(stored_report["source_ip"].is_string());
    assert!(stored_report["report"]["responses"].is_array());
    assert_eq!(
        stored_report["report"]["responses"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn test_invalid_report_missing_entries() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // Create report with only one entry
    let mut ctx = TestContext::new(1);
    let current_time = ctx.clock.epoch_seconds();
    let nonce = Nonce::from([0x33u8; 32]);
    let (request, response) = ctx.create_interaction_pair_with_nonce(current_time, &nonce);
    let public_key = ctx.key_source.public_key();

    let measurement = MeasurementBuilder::new()
        .server("127.0.0.1:8080".parse().unwrap())
        .hostname("test-server".to_string())
        .public_key(Some(public_key))
        .request(request)
        .response(response.clone())
        .response_bytes(response.as_frame_bytes().unwrap())
        .rand_value(None)
        .build()
        .unwrap();

    // Manually create a report with only one entry
    let report_json = serde_json::json!({
        "responses": [{
            "request": BASE64.encode(&measurement.request().as_frame_bytes().unwrap()),
            "response": BASE64.encode(&measurement.response().as_frame_bytes().unwrap()),
            "publicKey": BASE64.encode(measurement.public_key().unwrap().as_ref())
        }]
    });

    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&report_json)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_invalid_report_bad_chaining() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // First Request/Response pair, nonce = [0x44; 32]
    let mut ctx1 = TestContext::new(1);
    let current_time = ctx1.clock.epoch_seconds();
    let nonce1 = Nonce::from([0x44u8; 32]);
    let public_key = ctx1.key_source.public_key();
    let (request1, response1) = ctx1.create_interaction_pair_with_nonce(current_time, &nonce1);

    // Second Request/Response pair, nonce = [0x55; 32]
    let mut ctx2 = TestContext::new(1);
    let nonce2 = Nonce::from([0x55u8; 32]);
    let (request2, response2) =
        ctx2.create_interaction_pair_with_nonce(current_time + 1000, &nonce2);

    // Create report with incorrect chaining
    let report_json = serde_json::json!({
        "responses": [
            {
                "request": BASE64.encode(&request1.as_frame_bytes().unwrap()),
                "response": BASE64.encode(&response1.as_frame_bytes().unwrap()),
                "publicKey": BASE64.encode(public_key.as_ref())
            },
            {
                "rand": BASE64.encode(&[0x66u8; 32]), // WRONG rand value (should be [0x55; 32])
                "request": BASE64.encode(&request2.as_frame_bytes().unwrap()),
                "response": BASE64.encode(&response2.as_frame_bytes().unwrap()),
                "publicKey": BASE64.encode(public_key.as_ref())
            }
        ]
    });

    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&report_json)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_nonexistent_report() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "{}/api/v1/reports/nonexistent-id",
            server.base_url()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_report_validation_directly() {
    use roughenough_reporting_server::validation::validate_report;

    let report = create_test_malfeasance_report();
    // Should validate successfully
    validate_report(&report).expect("Valid report should pass validation");
}

#[tokio::test]
async fn test_multiple_reports_storage() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let mut report_ids = Vec::new();

    // Submit multiple reports
    for _i in 0..3 {
        let report = create_test_malfeasance_report();

        let response = client
            .post(format!("{}/api/v1/reports", server.base_url()))
            .json(&report)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 201);

        let create_response: CreationResponse = response.json().await.unwrap();
        report_ids.push(create_response.id);
    }

    // Verify all reports can be retrieved
    for id in report_ids {
        let response = client
            .get(format!("{}/api/v1/reports/{}", server.base_url(), id))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }
}

#[tokio::test]
async fn test_chained_report_without_violation_rejected() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // Correctly chained, causally consistent times: no malfeasance shown
    let current_time = TestContext::new(1).clock.epoch_seconds();
    let report = create_chained_report(&[current_time, current_time + 1_000], None);

    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&report)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("no causality violation demonstrated"),
        "unexpected error body: {body}"
    );
}

#[tokio::test]
async fn test_first_entry_with_rand_accepted() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // RFC 8.4.1: rand MAY be omitted from the first entry; carrying one is
    // not an error
    let current_time = TestContext::new(1).clock.epoch_seconds();
    let report = create_chained_report(
        &[current_time + 2_000_000, current_time],
        Some([0x77u8; 32]),
    );

    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&report)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
}

#[tokio::test]
async fn test_storage_cap_returns_503() {
    let storage = Arc::new(InMemoryStorage::with_limits(
        2,
        100,
        Duration::from_secs(60),
    ));
    let server = TestServer::spawn_with_storage(storage).await;
    let client = reqwest::Client::new();

    for _ in 0..2 {
        let response = client
            .post(format!("{}/api/v1/reports", server.base_url()))
            .json(&create_test_malfeasance_report())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
    }

    // cap+1: the store is full and rejects rather than evicting
    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&create_test_malfeasance_report())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
}

#[tokio::test]
async fn test_rate_limit_returns_429() {
    let storage = Arc::new(InMemoryStorage::with_limits(
        100,
        2,
        Duration::from_secs(3600),
    ));
    let server = TestServer::spawn_with_storage(storage).await;
    let client = reqwest::Client::new();

    for _ in 0..2 {
        let response = client
            .post(format!("{}/api/v1/reports", server.base_url()))
            .json(&create_test_malfeasance_report())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
    }

    // A burst from one source trips the fixed-window limit. Cross-source
    // isolation is covered by the storage unit tests: over loopback HTTP
    // every request shares the same source IP.
    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .json(&create_test_malfeasance_report())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
}

#[tokio::test]
async fn test_registered_media_type_accepted() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();
    let body = serde_json::to_vec(&create_test_malfeasance_report()).unwrap();

    // RFC 8.4.1 registered media type
    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .header("content-type", REPORT_MEDIA_TYPE)
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
}

#[tokio::test]
async fn test_plain_json_media_type_accepted() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();
    let body = serde_json::to_vec(&create_test_malfeasance_report()).unwrap();

    // application/json remains accepted for compatibility
    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
}

#[tokio::test]
async fn test_oversized_body_rejected() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // Larger than MAX_REPORT_BODY_BYTES; must be refused before JSON parsing
    let body = vec![b'x'; roughenough_reporting_server::MAX_REPORT_BODY_BYTES + 1];

    let response = client
        .post(format!("{}/api/v1/reports", server.base_url()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
}
