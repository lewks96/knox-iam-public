# ── Stage 1: Dependency planner ───────────────────────────────────────────────
FROM lukemathwalker/cargo-chef:latest-rust-1.90-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: Dependency builder ───────────────────────────────────────────────
# Shared with the server image — if both are built in the same BuildKit session
# the compiled-deps layer is reused from cache.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin knox-bootstrap

# ── Stage 3: Minimal runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/knox-bootstrap /app/knox-bootstrap

RUN useradd --no-create-home --shell /bin/false knox
USER knox

ENTRYPOINT ["/app/knox-bootstrap"]

