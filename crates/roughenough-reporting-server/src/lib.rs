//! Web server that collects and stores Roughtime malfeasance reports.
//!
//! Report storage is in-memory and non-durable: all stored reports are lost
//! when the process exits. The listen address defaults to `0.0.0.0:3000` and
//! is configurable with `--listen <ADDR:PORT>`.

#![forbid(unsafe_code)]

pub mod storage;
pub mod validation;

// Re-export types needed by tests and main
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use roughenough_client::MalfeasanceReport;
use serde::{Deserialize, Serialize};

pub use crate::storage::{InMemoryStorage, ReportStorage, StorageError, StoredReport};
pub use crate::validation::validate_report;

/// Explicit request body cap. Report entries are bounded by the client's
/// measurement rounds, so the largest plausible report is far below this;
/// anything bigger is rejected before JSON parsing.
pub const MAX_REPORT_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn ReportStorage>,
}

#[derive(Serialize, Deserialize)]
pub struct CreationResponse {
    pub id: String,
}

pub async fn handle_report(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(report): Json<MalfeasanceReport>,
) -> Result<(StatusCode, Json<CreationResponse>), (StatusCode, String)> {
    // Validate
    validate_report(&report).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Store. A full store rejects the submission (503) instead of evicting,
    // so a report flood cannot displace stored evidence; per-source rate
    // limiting maps to 429.
    let id = state
        .storage
        .store(report, addr.ip().to_string())
        .await
        .map_err(|e| {
            let status = match e {
                StorageError::Full => StatusCode::SERVICE_UNAVAILABLE,
                StorageError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                StorageError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })?;

    Ok((StatusCode::CREATED, Json(CreationResponse { id })))
}

pub async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<StoredReport>, StatusCode> {
    state
        .storage
        .get(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn health_check() -> &'static str {
    "OK"
}

/// Create the Axum router with all routes configured.
///
/// The `Json` extractor accepts both `application/json` and any
/// `application/*+json`, which covers the registered
/// `application/roughtime-malfeasance+json` media type (RFC 12.4.2).
pub fn create_app(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/reports", axum::routing::post(handle_report))
        .route("/api/v1/reports/{id}", axum::routing::get(get_report))
        .route("/health", axum::routing::get(health_check))
        .layer(DefaultBodyLimit::max(MAX_REPORT_BODY_BYTES))
        .with_state(state)
}
