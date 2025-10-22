# Multi-stage build
FROM rust:1.80-slim AS builder
WORKDIR /app
COPY . .
# Build the demo only (will build lib via workspace)
RUN cargo build -p otto-crypt-demo --release

FROM debian:12-slim
WORKDIR /app
COPY --from=builder /app/target/release/otto-crypt-demo /usr/local/bin/otto-crypt-demo
# runtime deps (none for static Rust std, but include ca-certificates just in case)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
# default command shows help
CMD ["otto-crypt-demo", "--help"]
