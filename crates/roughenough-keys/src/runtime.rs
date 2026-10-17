//! Bridges the cloud SDKs' async APIs to this crate's synchronous storage API.

use std::future::Future;

/// Panics if called from within another tokio runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(future)
}
