use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use data_encoding::HEXLOWER;
use roughenough_client::MalfeasanceReport;
use roughenough_common::crypto::random_bytes;
use serde::Serialize;

/// Hard cap on stored reports.
pub const MAX_STORED_REPORTS: usize = 10_000;

/// Fixed-window per-source submission limit: at most this many stores per
/// source IP within [`RATE_LIMIT_WINDOW`].
pub const MAX_REPORTS_PER_SOURCE_PER_WINDOW: u32 = 10;

/// Length of the fixed rate-limiting window.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Stored report with metadata
#[derive(Debug, Clone, Serialize)]
pub struct StoredReport {
    pub id: String,
    pub timestamp: jiff::Timestamp,
    pub source_ip: String,
    pub report: MalfeasanceReport,
}

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("Storage operation failed: {0}")]
    Internal(String),

    #[error("report storage is full")]
    Full,

    #[error("too many reports from this source; retry later")]
    RateLimited,
}

#[async_trait]
pub trait ReportStorage: Send + Sync {
    async fn store(
        &self,
        report: MalfeasanceReport,
        source_ip: String,
    ) -> Result<String, StorageError>;

    async fn get(&self, id: &str) -> Result<Option<StoredReport>, StorageError>;

    async fn list(&self, limit: usize) -> Result<Vec<StoredReport>, StorageError>;
}

/// Per-source submission counts within the current fixed window.
struct RateWindow {
    started: Instant,
    counts: HashMap<String, u32>,
}

pub struct InMemoryStorage {
    reports: Mutex<HashMap<String, StoredReport>>,
    rate_window: Mutex<RateWindow>,
    max_reports: usize,
    max_per_source: u32,
    window_length: Duration,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::with_limits(
            MAX_STORED_REPORTS,
            MAX_REPORTS_PER_SOURCE_PER_WINDOW,
            RATE_LIMIT_WINDOW,
        )
    }

    pub fn with_limits(max_reports: usize, max_per_source: u32, window_length: Duration) -> Self {
        Self {
            reports: Mutex::new(HashMap::new()),
            rate_window: Mutex::new(RateWindow {
                started: Instant::now(),
                counts: HashMap::new(),
            }),
            max_reports,
            max_per_source,
            window_length,
        }
    }

    fn check_rate_limit(&self, source_ip: &str) -> Result<(), StorageError> {
        let mut window = self.rate_window.lock().unwrap();

        if window.started.elapsed() >= self.window_length {
            window.started = Instant::now();
            window.counts.clear();
        }

        let count = window.counts.entry(source_ip.to_string()).or_insert(0);
        if *count >= self.max_per_source {
            return Err(StorageError::RateLimited);
        }
        *count += 1;

        Ok(())
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReportStorage for InMemoryStorage {
    async fn store(
        &self,
        report: MalfeasanceReport,
        source_ip: String,
    ) -> Result<String, StorageError> {
        self.check_rate_limit(&source_ip)?;

        let mut reports = self.reports.lock().unwrap();
        if reports.len() >= self.max_reports {
            return Err(StorageError::Full);
        }

        // an opaque unique identifier; nothing parses or orders by it
        let id = HEXLOWER.encode(&random_bytes::<16>());
        let stored = StoredReport {
            id: id.clone(),
            timestamp: jiff::Timestamp::now(),
            source_ip,
            report,
        };

        reports.insert(id.clone(), stored);
        Ok(id)
    }

    async fn get(&self, id: &str) -> Result<Option<StoredReport>, StorageError> {
        Ok(self.reports.lock().unwrap().get(id).cloned())
    }

    async fn list(&self, limit: usize) -> Result<Vec<StoredReport>, StorageError> {
        let reports = self.reports.lock().unwrap();
        let mut items: Vec<_> = reports.values().cloned().collect();
        items.sort_by_key(|a| a.timestamp);
        items.truncate(limit);
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report() -> MalfeasanceReport {
        serde_json::from_str(r#"{"responses": []}"#).unwrap()
    }

    #[tokio::test]
    async fn full_storage_rejects_new_reports() {
        let storage = InMemoryStorage::with_limits(2, 100, Duration::from_secs(60));

        storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap();
        storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap();

        let err = storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::Full));
    }

    #[tokio::test]
    async fn rate_limit_applies_per_source() {
        let storage = InMemoryStorage::with_limits(100, 2, Duration::from_secs(3600));

        storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap();
        storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap();

        // The burst source is limited
        let err = storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::RateLimited));

        // An unrelated source is unaffected
        storage
            .store(empty_report(), "2.2.2.2".into())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rate_limit_window_resets() {
        // Window must be long enough that test-runner scheduling delays
        // cannot expire it between the two back-to-back stores
        let storage = InMemoryStorage::with_limits(100, 1, Duration::from_millis(500));

        storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap();
        let err = storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::RateLimited));

        tokio::time::sleep(Duration::from_millis(600)).await;
        storage
            .store(empty_report(), "1.1.1.1".into())
            .await
            .unwrap();
    }
}
