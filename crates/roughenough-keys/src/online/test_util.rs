use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

use tracing_subscriber::util::SubscriberInitExt;

#[allow(dead_code)]
static ONCE: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)]
pub(crate) fn enable_logging() {
    #[allow(deprecated)]
    if !ONCE.compare_and_swap(false, true, SeqCst) {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .compact()
            .set_default();
    };
}
