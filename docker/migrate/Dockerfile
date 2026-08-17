# ── Stage 1: Build sqlx-cli ───────────────────────────────────────────────────
FROM rust:1.90-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Keep this version in sync with the `sqlx` dependency in Cargo.toml — the CLI
# and the library must agree on the migrations table and .sqlx offline format.
RUN cargo install sqlx-cli \
    --version 0.8.6 \
    --locked \
    --no-default-features \
    --features postgres,native-tls

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/sqlx
COPY migrations /migrations

# DATABASE_URL must be injected at runtime — never bake credentials into the image
CMD ["sqlx", "migrate", "run", "--source", "/migrations"]

