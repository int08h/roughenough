#
# Example multi-stage docker build for running a Roughenough server
#

# Stage 1: build

FROM rust:1.34.1 AS stage1

ARG ROUGHENOUGH_RELEASE=1.1.4
ARG ROUGHENOUGH_FEATURES="default" 
# Uncomment and replace above if you want KMS support
#ARG ROUGHENOUGH_FEATURES="awskms"
#ARG ROUGHENOUGH_FEATURES="gcpkms"

RUN git clone -b ${ROUGHENOUGH_RELEASE} https://github.com/int08h/roughenough.git \
    && cd /roughenough \ 
    && cargo build --release --features ${ROUGHENOUGH_FEATURES}

# Stage 2: runtime image

FROM gcr.io/distroless/cc

WORKDIR /roughenough

COPY --from=stage1 /roughenough/target/release/roughenough-server /roughenough
COPY roughenough.cfg /roughenough
COPY creds.json /roughenough

ENV RUST_BACKTRACE 1
ENV GOOGLE_APPLICATION_CREDENTIALS /roughenough/creds.json

EXPOSE 2002/udp 

CMD ["/roughenough/roughenough-server", "/roughenough/roughenough.cfg"]
