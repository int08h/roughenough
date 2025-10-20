FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy all source files
COPY . .

# Build the server in release mode with all features enabled
RUN cargo build --release --bin roughenough_server --all-features

# Runtime stage - using distroless with shell
FROM gcr.io/distroless/cc-debian12:debug

# Copy the binary from builder
COPY --from=builder /app/target/release/roughenough_server /roughenough_server

# Expose the default Roughenough port
EXPOSE 2003/udp

# Set the entrypoint
ENTRYPOINT ["/roughenough_server"]

# Args for testing, need to set real args for prod
CMD ["--interface", "0.0.0.0", "--port", "2003"]
