# Multi-stage Dockerfile for building a static File Analyzer
FROM rust:slim AS builder

# Install build dependencies including musl tools
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    musl-tools \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build statically linked executable using musl
RUN rustup target add x86_64-unknown-linux-musl
# Use musl-gcc as the C compiler for the musl target
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl

# Use a minimal base for the final image
FROM scratch

# Copy the built binary from builder stage
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/file_analyzer /file_analyzer

# Set entrypoint
ENTRYPOINT ["/file_analyzer"] 