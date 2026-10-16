pub(crate) fn enable_logging() {
    // try_init installs a global subscriber once; later calls are harmless no-ops
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .compact()
        .try_init();
}
