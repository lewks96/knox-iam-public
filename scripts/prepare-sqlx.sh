#!/usr/bin/env bash
# scripts/prepare-sqlx.sh
#
# Spins up the compose Postgres, generates sqlx offline query files, then
# tears Postgres back down.  Run this whenever you add or modify a query
# (sqlx::query!, query_as!, etc.) before committing.
#
# Usage:
#   ./scripts/prepare-sqlx.sh          # normal run
#   ./scripts/prepare-sqlx.sh --keep   # leave Postgres running afterwards

set -euo pipefail

KEEP=false
for arg in "$@"; do
  [[ "$arg" == "--keep" ]] && KEEP=true
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── Ensure sqlx-cli is installed ─────────────────────────────────────────────
if ! command -v cargo-sqlx &>/dev/null && ! cargo sqlx --version &>/dev/null 2>&1; then
  echo "➜  Installing sqlx-cli…"
  cargo install sqlx-cli --no-default-features --features postgres,native-tls
fi

# ── Start Postgres ────────────────────────────────────────────────────────────
echo "➜  Starting Postgres…"
docker compose up postgres -d

echo "➜  Waiting for Postgres to be healthy…"
until docker compose exec postgres pg_isready -U admin -d knox -q; do
  sleep 1
done

# ── Run migrations so the schema is current ───────────────────────────────────
echo "➜  Running migrations…"
export DATABASE_URL="postgres://admin:password@localhost:5432/knox"
cargo sqlx migrate run --source migrations

# ── Generate offline query metadata ───────────────────────────────────────────
echo "➜  Generating .sqlx offline files…"
cargo sqlx prepare --workspace

echo ""
echo "✅  .sqlx/ is up to date — stage and commit it."
echo "    git add .sqlx && git commit -m 'chore: update sqlx offline files'"

# ── Tear down unless --keep ───────────────────────────────────────────────────
if [[ "$KEEP" == false ]]; then
  echo "➜  Stopping Postgres…"
  docker compose stop postgres
fi

