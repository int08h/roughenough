use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use data_encoding::BASE64;
use roughenough_client::measurement::MeasurementBuilder;
use roughenough_client::{CausalityViolation, MalfeasanceReport};
use roughenough_common::crypto::calculate_chained_nonce;
use roughenough_protocol::ToFrame;
use roughenough_protocol::tags::Nonce;
use roughenough_reporting_server::storage::InMemoryStorage;
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
        let port = find_available_port();
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();

        // Create the app state with in-memory storage
        let state = AppState {
            storage: Arc::new(InMemoryStorage::new()),
        };

        // Build the actual server router (no reimplementation!)
        let app = roughenough_reporting_server::create_app(state);

        // Create the TCP listener
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        // Spawn the server in the background
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

/// Create a test malfeasance report with proper chaining
fn create_test_malfeasance_report() -> MalfeasanceReport {
    // Create first context and request/response pair
    let mut ctx1 = TestContext::new(1);
    let nonce1 = Nonce::from([0x11u8; 32]);
    // Use current time for valid delegation
    let current_time = ctx1.clock.epoch_seconds();
    // First measurement will have a later time (measurement_i)
    let (request1, response1) =
        ctx1.create_interaction_pair_with_nonce(current_time + 2_000_000, &nonce1);

    // rand value for chaining
    let rand_value = [0x22u8; 32];

    // Calculate nonce for second request: SHA512(response1 || rand)[0:32]
    let nonce2 = calculate_chained_nonce(&response1, &rand_value);

    // Create second context with same seed for same keys
    let mut ctx2 = TestContext::new(1);
    // Second measurement will have an earlier time (measurement_j) - this creates the causality violation
    let (request2, response2) = ctx2.create_interaction_pair_with_nonce(current_time, &nonce2);

    // Get the public key from the long-term key (same for both contexts due to same seed)
    let public_key = ctx1.key_source.public_key();

    let measurement1 = MeasurementBuilder::new()
        .server("127.0.0.1:8080".parse().unwrap())
        .hostname("test-server".to_string())
        .public_key(Some(public_key.clone()))
        .request(request1)
        .response(response1.clone())
        .rand_value(None)
        .prior_response(None)
        .build()
        .unwrap();

    let measurement2 = MeasurementBuilder::new()
        .server("127.0.0.1:8080".parse().unwrap())
        .hostname("test-server".to_string())
        .public_key(Some(public_key))
        .request(request2)
        .response(response2)
        .rand_value(Some(rand_value))
        .prior_response(Some(response1))
        .build()
        .unwrap();

    // Create the report - the order in CausalityViolation affects the report order
    // We need measurement1 first, measurement2 second
    let violation = CausalityViolation::new(measurement1, measurement2);
    MalfeasanceReport::from_violation(&violation)
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
        .response(response)
        .rand_value(None)
        .prior_response(None)
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
