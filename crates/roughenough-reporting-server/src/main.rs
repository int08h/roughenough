use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use roughenough_reporting_server::{AppState, InMemoryStorage, create_app};
use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about = "Roughenough malfeasance reporting server")]
struct Args {
    /// Address and port to listen on
    #[clap(
        short = 'l',
        long,
        value_name = "ADDR:PORT",
        env = "ROUGHENOUGH_REPORTING_LISTEN",
        default_value = "0.0.0.0:3000"
    )]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let state = AppState {
        storage: Arc::new(InMemoryStorage::new()),
    };

    let app = create_app(state);

    info!("Reporting server listening on {}", args.listen);
    info!("Report storage is in-memory and non-durable; reports are lost on restart");

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .expect("Failed to bind to address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_address() {
        let args = Args::try_parse_from(["prog"]).unwrap();
        assert_eq!(args.listen, "0.0.0.0:3000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn listen_accepts_v4_and_v6_and_rejects_garbage() {
        let args = Args::try_parse_from(["prog", "--listen", "127.0.0.1:8080"]).unwrap();
        assert_eq!(args.listen, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());

        let args = Args::try_parse_from(["prog", "-l", "[::1]:8080"]).unwrap();
        assert_eq!(args.listen, "[::1]:8080".parse::<SocketAddr>().unwrap());

        assert!(Args::try_parse_from(["prog", "-l", "not-an-addr"]).is_err());
    }
}
