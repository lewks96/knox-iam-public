#!/bin/sh
# docker/ui/entrypoint.sh
#
# Replaces build-time placeholder strings in the compiled Next.js bundles with
# values from runtime environment variables, then starts the server.
#
# NEXT_PUBLIC_* vars are baked into client JS at build time. We work around
# this by building with known placeholder strings and sed-patching them here,
# which allows a single Docker image to work across dev / staging / production.
#
# Variables consumed:
#   NEXT_PUBLIC_MANAGEMENT_CLIENT_ID  — OAuth management client UUID
#   NEXT_PUBLIC_MANAGEMENT_TENANT_ID  — Platform tenant slug (e.g. knox-root)

set -e

replace() {
  local placeholder="$1"
  local value="$2"

  if [ -z "$value" ]; then
    echo "⚠  WARNING: env var for placeholder '${placeholder}' is empty — skipping replacement"
    return
  fi

  # Patch client bundles (static chunks) and server-side renders
  find /app/.next -type f \( -name "*.js" -o -name "*.json" \) \
    -exec sed -i "s|${placeholder}|${value}|g" {} \;
}

echo "▶  Knox UI — injecting runtime config…"
replace "__MANAGEMENT_CLIENT_ID__" "${NEXT_PUBLIC_MANAGEMENT_CLIENT_ID:-}"
replace "__MANAGEMENT_TENANT_ID__"  "${NEXT_PUBLIC_MANAGEMENT_TENANT_ID:-}"
replace "__base_domain__"          "${NEXT_PUBLIC_BASE_DOMAIN:-}"
echo "   ✅  Config injected."

exec node server.js

