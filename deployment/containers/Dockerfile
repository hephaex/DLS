# CLAUDE DLS Multi-stage Docker Build
# Production-ready container for CLAUDE Diskless Boot System

# Build stage - Rust compilation
FROM rust:1.80-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build application with optimizations
ENV CARGO_TARGET_DIR=/app/target
RUN cargo build --release --bin claude-server --bin claude-cli

# Runtime stage - Minimal Debian base
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libpq5 \
    ca-certificates \
    curl \
    iputils-ping \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd -r claude && useradd -r -g claude claude

# Create application directories
RUN mkdir -p /opt/claude_dls/{bin,config,data,logs} \
    && mkdir -p /var/lib/claude_dls/{images,tftp,dhcp} \
    && chown -R claude:claude /opt/claude_dls /var/lib/claude_dls

# Copy binaries from builder stage
COPY --from=builder /app/target/release/claude-server /opt/claude_dls/bin/
COPY --from=builder /app/target/release/claude-cli /opt/claude_dls/bin/

# Copy configuration files
COPY deployment/configs/production.toml /opt/claude_dls/config/
COPY deployment/configs/logging.toml /opt/claude_dls/config/

# Set permissions
RUN chmod +x /opt/claude_dls/bin/claude-server \
    && chmod +x /opt/claude_dls/bin/claude-cli

# Switch to application user
USER claude

# Set working directory
WORKDIR /opt/claude_dls

# Environment variables
ENV RUST_LOG=info
ENV CLAUDE_CONFIG_PATH=/opt/claude_dls/config
ENV CLAUDE_DATA_PATH=/var/lib/claude_dls
ENV BIND_ADDRESS=0.0.0.0:8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 67/udp 69/udp 3260

# Default command
CMD ["/opt/claude_dls/bin/claude-server"]

# Labels for metadata
LABEL maintainer="Mario Cho <hephaex@gmail.com>" \
      version="0.1.0" \
      description="CLAUDE DLS - Cloud-Linked Agile Unified Diskless Environment" \
      org.opencontainers.image.title="CLAUDE DLS" \
      org.opencontainers.image.description="Modern diskless boot system built in Rust" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.authors="Mario Cho <hephaex@gmail.com>" \
      org.opencontainers.image.source="https://github.com/hephaex/DLS" \
      org.opencontainers.image.licenses="MIT"