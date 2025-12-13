FROM rust:1.92-slim-trixie AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/roughenough-client/Cargo.toml crates/roughenough-client/
COPY crates/roughenough-common/Cargo.toml crates/roughenough-common/
COPY crates/roughenough-integration/Cargo.toml crates/roughenough-integration/
COPY crates/roughenough-keys/Cargo.toml crates/roughenough-keys/
COPY crates/roughenough-merkle/Cargo.toml crates/roughenough-merkle/
COPY crates/roughenough-protocol/Cargo.toml crates/roughenough-protocol/
COPY crates/roughenough-server/Cargo.toml crates/roughenough-server/

# Create stub lib.rs files to satisfy cargo
RUN for crate in roughenough-client roughenough-common roughenough-integration \
    roughenough-keys roughenough-merkle roughenough-protocol roughenough-server; do \
    mkdir -p crates/$crate/src && touch crates/$crate/src/lib.rs; \
    done

# Build dependencies only (cached unless Cargo.toml changes)
RUN cargo build --profile release-lto --bin roughenough_server --all-features 2>/dev/null || true

# Copy actual source and build
COPY crates crates
RUN cargo build --profile release-lto --bin roughenough_server --all-features

# Runtime stage - minimal distroless (no shell)
FROM gcr.io/distroless/cc-debian13

# Copy binary from correct profile path
COPY --from=builder /app/target/release-lto/roughenough_server /roughenough_server

EXPOSE 2003/udp

ENTRYPOINT ["/roughenough_server"]
CMD ["--interface", "0.0.0.0", "--port", "2003"]
