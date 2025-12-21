FROM rust:1.92-slim-trixie AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests first for caching
COPY Cargo.toml Cargo.lock ./
COPY crates/roughenough-protocol/Cargo.toml crates/roughenough-protocol/
COPY crates/roughenough-server/Cargo.toml crates/roughenough-server/
COPY crates/roughenough-client/Cargo.toml crates/roughenough-client/
COPY crates/roughenough-common/Cargo.toml crates/roughenough-common/
COPY crates/roughenough-merkle/Cargo.toml crates/roughenough-merkle/
COPY crates/roughenough-keys/Cargo.toml crates/roughenough-keys/
COPY crates/roughenough-integration/Cargo.toml crates/roughenough-integration/

# Create dummy source files to build dependencies
RUN mkdir -p src crates/roughenough-protocol/src crates/roughenough-server/src crates/roughenough-client/src \
    crates/roughenough-common/src crates/roughenough-merkle/src crates/roughenough-keys/src crates/roughenough-integration/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > crates/roughenough-protocol/src/lib.rs \
    && echo "fn main() {}" > crates/roughenough-server/src/main.rs \
    && echo "fn main() {}" > crates/roughenough-client/src/main.rs \
    && echo "" > crates/roughenough-common/src/lib.rs \
    && echo "" > crates/roughenough-merkle/src/lib.rs \
    && echo "" > crates/roughenough-keys/src/lib.rs \
    && echo "" > crates/roughenough-integration/src/lib.rs

# Build dependencies only
RUN cargo build --profile release-lto --bin roughenough_server --all-features 2>/dev/null || true

# Copy actual source and rebuild
COPY . .
RUN touch crates/*/src/*.rs src/main.rs \
    && cargo build --release --bin roughenough_server --all-features

# Runtime stage
FROM gcr.io/distroless/cc-debian13:debug

LABEL org.opencontainers.image.source="https://github.com/int08h/roughenough"
LABEL org.opencontainers.image.description="Roughtime protocol server"

COPY --from=builder /app/target/release/roughenough_server /roughenough_server

USER nonroot:nonroot

EXPOSE 2003/udp

ENTRYPOINT ["/roughenough_server"]
CMD ["--interface", "0.0.0.0", "--port", "2003"]
