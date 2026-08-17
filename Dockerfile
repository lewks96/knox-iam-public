# ── Stage 1: Dependency planner ───────────────────────────────────────────────
# cargo-chef captures only what's needed to resolve and compile dependencies,
# so the compiled-deps layer is cached independently of your source changes.
FROM lukemathwalker/cargo-chef:latest-rust-1.90-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: Dependency builder ───────────────────────────────────────────────
# Only re-executes when Cargo.toml / Cargo.lock change — not on every source edit.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
# sqlx offline mode — query metadata lives in .sqlx/ (committed to the repo)
# so no live database is required at build time.
ENV SQLX_OFFLINE=true
# Version info baked into the binary by server/build.rs. .git is excluded from
# the build context (.dockerignore), so the SHA must be passed in as a build-arg.
ARG KNOX_GIT_SHA
ARG KNOX_BUILD_TIME
ENV KNOX_GIT_SHA=${KNOX_GIT_SHA}
ENV KNOX_BUILD_TIME=${KNOX_BUILD_TIME}
RUN cargo build --release --bin server

# ── Stage 3: Minimal runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/server /app/server

# Never run as root in production
RUN useradd --no-create-home --shell /bin/false knox
USER knox

EXPOSE 8080
ENTRYPOINT ["/app/server"]

