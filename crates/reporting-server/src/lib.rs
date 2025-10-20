#![forbid(unsafe_code)]

pub mod storage;
pub mod validation;

// Re-export types needed by tests and main
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use client::MalfeasanceReport;
use serde::{Deserialize, Serialize};

pub use crate::storage::{InMemoryStorage, ReportStorage, StoredReport};
pub use crate::validation::validate_report;

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

    // Store
    let id = state
        .storage
        .store(report, addr.ip().to_string())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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

/// Create the Axum router with all routes configured
pub fn create_app(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/reports", axum::routing::post(handle_report))
        .route("/api/v1/reports/{id}", axum::routing::get(get_report))
        .route("/health", axum::routing::get(health_check))
        .with_state(state)
}
