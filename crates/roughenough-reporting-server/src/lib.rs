//! Web server that collects and stores Roughtime malfeasance reports.
//!
//! The listen address defaults to `0.0.0.0:3000` and is configurable with `--listen <ADDR:PORT>`.
//!
//! TODO(stuart): Report storage is in-memory only

#![forbid(unsafe_code)]

pub mod storage;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use roughenough_client::MalfeasanceReport;
use serde::{Deserialize, Serialize};

pub use crate::storage::{InMemoryStorage, StorageError, StoredReport};

pub const MAX_REPORT_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<InMemoryStorage>,
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
    report
        .verify()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Store. A full store rejects the submission (503) instead of evicting,
    // so a report flood cannot displace stored evidence; per-source rate
    // limiting maps to 429.
    let id = state
        .storage
        .store(report, addr.ip().to_string())
        .map_err(|e| {
            let status = match e {
                StorageError::Full => StatusCode::SERVICE_UNAVAILABLE,
                StorageError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
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
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn health_check() -> &'static str {
    "OK"
}

pub fn create_app(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/reports", axum::routing::post(handle_report))
        .route("/api/v1/reports/{id}", axum::routing::get(get_report))
        .route("/health", axum::routing::get(health_check))
        .layer(DefaultBodyLimit::max(MAX_REPORT_BODY_BYTES))
        .with_state(state)
}
