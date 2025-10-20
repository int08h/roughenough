use std::net::SocketAddr;
use std::sync::Arc;

use reporting_server::{AppState, InMemoryStorage, create_app};
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = AppState {
        storage: Arc::new(InMemoryStorage::new()),
    };

    let app = create_app(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Reporting server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server failed");
}
