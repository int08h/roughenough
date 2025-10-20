use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use client::MalfeasanceReport;
use serde::Serialize;

/// Stored report with metadata
#[derive(Debug, Clone, Serialize)]
pub struct StoredReport {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_ip: String,
    pub report: MalfeasanceReport,
}

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("Storage operation failed: {0}")]
    Internal(String),
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

#[async_trait]
impl ReportStorage for InMemoryStorage {
    async fn store(
        &self,
        report: MalfeasanceReport,
        source_ip: String,
    ) -> Result<String, StorageError> {
        let id = ulid::Ulid::new().to_string();
        let stored = StoredReport {
            id: id.clone(),
            timestamp: chrono::Utc::now(),
            source_ip,
            report,
        };

        self.reports.lock().unwrap().insert(id.clone(), stored);
        Ok(id)
    }

    async fn get(&self, id: &str) -> Result<Option<StoredReport>, StorageError> {
        Ok(self.reports.lock().unwrap().get(id).cloned())
    }

    async fn list(&self, limit: usize) -> Result<Vec<StoredReport>, StorageError> {
        let reports = self.reports.lock().unwrap();
        let mut items: Vec<_> = reports.values().cloned().collect();
        items.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        items.truncate(limit);
        Ok(items)
    }
}

pub struct InMemoryStorage {
    reports: Arc<Mutex<HashMap<String, StoredReport>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            reports: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}
