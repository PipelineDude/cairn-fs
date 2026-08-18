# Builder stage
FROM rust:alpine AS builder

# Install necessary build dependencies for static compilation
# We need musl-dev, gcc, make for C-extensions (like FastCDC, sqlcipher)
# We need openssl-dev and openssl-libs-static for static crypto
# We need fuse3-dev for FUSE support
RUN apk add --no-cache \
    musl-dev \
    gcc \
    make \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    fuse3-dev \
    fuse3-static \
    sqlite-dev \
    sqlcipher-dev

WORKDIR /usr/src/cairn

# Copy the entire workspace
COPY . .

# Set environment variables to enforce fully static linking
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV PKG_CONFIG_ALL_STATIC=1
ENV OPENSSL_STATIC=1
ENV OPENSSL_DIR=/usr

# Build the binary statically for musl
RUN cargo build --release

# Final scratch image
FROM scratch

# Copy CA certificates so opendal (S3/GCS) can verify TLS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically compiled binary
COPY --from=builder /usr/src/cairn/target/release/cairn /cairn

# Set the entrypoint
ENTRYPOINT ["/cairn"]
