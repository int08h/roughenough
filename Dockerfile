# Locked dependencies (AWS SDK crates) require rustc >= 1.94.1
FROM rust:1.94-slim-trixie AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests first for better caching. Every workspace member's
# manifest must be present or cargo refuses to load the workspace.
COPY Cargo.toml Cargo.lock ./
COPY crates/roughenough-client/Cargo.toml crates/roughenough-client/
COPY crates/roughenough-common/Cargo.toml crates/roughenough-common/
COPY crates/roughenough-integration/Cargo.toml crates/roughenough-integration/
COPY crates/roughenough-keys/Cargo.toml crates/roughenough-keys/
COPY crates/roughenough-merkle/Cargo.toml crates/roughenough-merkle/
COPY crates/roughenough-protocol/Cargo.toml crates/roughenough-protocol/
COPY crates/roughenough-server/Cargo.toml crates/roughenough-server/
COPY crates/roughenough-reporting-server/Cargo.toml crates/roughenough-reporting-server/

# Stub every declared lib, bin, and bench target so cargo can resolve the
# workspace and build dependencies without the real sources
RUN for crate in roughenough-client roughenough-common roughenough-integration \
    roughenough-keys roughenough-merkle roughenough-protocol roughenough-server \
    roughenough-reporting-server; do \
    mkdir -p crates/$crate/src && touch crates/$crate/src/lib.rs; \
    done \
    && echo 'fn main() {}' > crates/roughenough-client/src/main.rs \
    && echo 'fn main() {}' > crates/roughenough-server/src/main.rs \
    && echo 'fn main() {}' > crates/roughenough-reporting-server/src/main.rs \
    && echo 'fn main() {}' > crates/roughenough-integration/src/main.rs \
    && echo 'fn main() {}' > crates/roughenough-integration/src/load_gen.rs \
    && mkdir -p crates/roughenough-keys/bin \
    && echo 'fn main() {}' > crates/roughenough-keys/bin/keys.rs \
    && mkdir -p crates/roughenough-server/benches crates/roughenough-merkle/benches \
       crates/roughenough-protocol/benches \
    && echo 'fn main() {}' > crates/roughenough-server/benches/server_ops.rs \
    && echo 'fn main() {}' > crates/roughenough-merkle/benches/get_paths.rs \
    && echo 'fn main() {}' > crates/roughenough-protocol/benches/message_ops.rs

# Build dependencies only (cached unless a manifest or Cargo.lock changes).
# This must fail loudly if the stub setup is ever incomplete.
RUN cargo build --profile release-lto --bin roughenough_server --all-features

# Copy actual source and build. Touch the sources so cargo sees them as newer
# than the stub-built artifacts (COPY preserves context mtimes, which may
# predate the stub build and would otherwise skip recompilation).
COPY crates crates
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --profile release-lto --bin roughenough_server --all-features

# Runtime stage - minimal distroless (no shell)
FROM gcr.io/distroless/cc-debian13

# Copy binary from correct profile path
COPY --from=builder /app/target/release-lto/roughenough_server /roughenough_server

EXPOSE 2003/udp

# The server requires a seed file. Mount a mode-0400/0600 regular file
# and append `--seed-file /run/secrets/roughenough.seed`, or set
# ROUGHENOUGH_SEED_FILE to a valid seed file.
ENTRYPOINT ["/roughenough_server"]
CMD ["--interface", "0.0.0.0", "--port", "2003"]
