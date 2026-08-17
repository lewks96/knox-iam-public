#!/usr/bin/env bash
# setup.sh — generate the local env files from their committed templates.
#
#   ./setup.sh          # create anything missing, leave existing files alone
#   ./setup.sh --force  # overwrite existing files (backs each one up first)
#
# Creates:
#   .env             server on the host   (cargo run -p server, cargo run -p knox-bootstrap)
#   .env.compose     compose containers   (docker compose up migrate)
#   ui/.env.local    Next.js dev server
#
# One AES_MASTER_KEY is generated and shared by .env and .env.compose so the
# host server and the containers can read the same tenant keys. It wraps every
# tenant's RSA signing key: change it after tenants exist and their keys are
# unreadable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

FORCE=false
[ "${1:-}" = "--force" ] && FORCE=true
if [ -n "${1:-}" ] && [ "$1" != "--force" ]; then
  echo "usage: $0 [--force]" >&2
  exit 64
fi

command -v openssl >/dev/null 2>&1 || {
  echo "✗ openssl not found — needed to generate AES_MASTER_KEY" >&2
  exit 1
}

AES_MASTER_KEY="$(openssl rand -base64 32)"

# from_template <template> <destination> [--with-key]
from_template() {
  template="$1"
  dest="$2"
  with_key="${3:-}"

  if [ ! -f "$template" ]; then
    echo "✗ missing template: $template" >&2
    return 1
  fi

  if [ -f "$dest" ]; then
    if [ "$FORCE" != true ]; then
      echo "•  $dest exists — skipped (--force to replace)"
      return 0
    fi
    backup="${dest}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$dest" "$backup"
    echo "•  backed up $dest → $backup"
  fi

  if [ "$with_key" = "--with-key" ]; then
    # The key is base64 and can contain / and +, so use a delimiter that
    # base64 never produces.
    sed "s|^AES_MASTER_KEY=REPLACE_ME$|AES_MASTER_KEY=${AES_MASTER_KEY}|" \
      "$template" > "$dest"
    if grep -q "REPLACE_ME" "$dest"; then
      echo "⚠  $dest still contains REPLACE_ME — fill it in by hand" >&2
    fi
  else
    cp "$template" "$dest"
  fi

  echo "✅ $dest"
}

echo "▶  Knox — generating local env files"
from_template .env.example         .env          --with-key
from_template .env.compose.example .env.compose  --with-key
from_template ui/.env.example      ui/.env.local

cat <<EOF

Done. AES_MASTER_KEY is shared by .env and .env.compose; keep it if you want
your existing local tenants to stay readable.

Next:
  docker compose up -d postgres redis
  docker compose up migrate --exit-code-from migrate
  cargo run -p knox-bootstrap        # prints the admin credentials
  cargo run -p server
  cd ui && npm install && npm run dev

Then open http://knox-root.lvh.me:3000
EOF
