#!/usr/bin/env bash
# scripts/docker.sh
#
# Build and/or push all Knox images.
#
#   build → host-arch only, loaded into local Docker (for local k3d testing)
#   push  → multi-arch (linux/amd64 + linux/arm64), pushed to a registry
#   all   → alias for push (multi-arch build+push in one step)
#
# `build` is the one you need for k3d — nothing is published anywhere, and
# k3d-setup.sh imports straight from your local Docker daemon.
#
# Images are tagged with both `latest` and the current git SHA.
#
# Usage:
#   ./scripts/docker.sh build              # local host-arch build
#   ./scripts/docker.sh push               # multi-arch build + push
#   ./scripts/docker.sh all                # same as push
#   ./scripts/docker.sh push server        # single image, multi-arch
#
# To roll deployments after a push, use: ./scripts/k3d-setup.sh restart
#
# Environment:
#   DOCKER_ORG  — image name prefix           (default: knox)
#                 A registry host may be included, e.g.
#                 DOCKER_ORG=ghcr.io/<user>. `push` requires setting this to
#                 somewhere you can actually write; the default is a local-only
#                 placeholder and matches what the k8s manifests name.
#   IMAGE_TAG   — override the SHA tag        (default: current git SHA short)
#   PLATFORMS   — override target platforms   (default: linux/amd64,linux/arm64)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── Config ────────────────────────────────────────────────────────────────────
DOCKER_ORG="${DOCKER_ORG:-knox}"
SHA_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD)}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

ALL_IMAGES=(server postgres migrate ui bootstrap pgbouncer)

# ── Lookup helpers (avoids associative arrays — macOS ships bash 3.2) ─────────
image_name()   {
  case "$1" in
    server)     echo "${DOCKER_ORG}/knox-iam-server"     ;;
    postgres)   echo "${DOCKER_ORG}/knox-iam-postgres"   ;;
    migrate)    echo "${DOCKER_ORG}/knox-iam-migrate"    ;;
    ui)         echo "${DOCKER_ORG}/knox-iam-ui"         ;;
    bootstrap)  echo "${DOCKER_ORG}/knox-iam-bootstrap"  ;;
    pgbouncer)  echo "${DOCKER_ORG}/knox-iam-pgbouncer"  ;;
  esac
}

dockerfile()   {
  case "$1" in
    server)     echo "Dockerfile"                         ;;
    postgres)   echo "docker/postgres/Dockerfile"         ;;
    migrate)    echo "docker/migrate/Dockerfile"          ;;
    ui)         echo "docker/ui/Dockerfile"               ;;
    bootstrap)  echo "docker/bootstrap/Dockerfile"        ;;
    pgbouncer)  echo "docker/pgbouncer/Dockerfile"        ;;
  esac
}

build_context() {
  case "$1" in
    server)     echo "."                  ;;
    postgres)   echo "docker/postgres"    ;;
    migrate)    echo "."                  ;;
    ui)         echo "."                  ;;
    bootstrap)  echo "."                  ;;
    pgbouncer)  echo "docker/pgbouncer"   ;;
  esac
}

is_valid_target() {
  case "$1" in
    server|postgres|migrate|ui|bootstrap|pgbouncer) return 0 ;;
    *) return 1 ;;
  esac
}

# ── Helpers ───────────────────────────────────────────────────────────────────

# Local-only build: host arch, loaded into the docker daemon for `docker run` /
# k3d image import. Multi-arch manifests cannot be `--load`ed, so we deliberately
# use only the host platform here.
build_local() {
  local key="$1"
  local name; name="$(image_name "$key")"
  local ctx;  ctx="$(build_context "$key")"
  local file; file="$(dockerfile "$key")"

  echo ""
  echo "▶  Building (local, host-arch) ${key} → ${name}:${SHA_TAG}"
  docker buildx build \
    --file "${file}" \
    --tag "${name}:latest" \
    --tag "${name}:${SHA_TAG}" \
    --build-arg "KNOX_GIT_SHA=${SHA_TAG}" \
    --build-arg "KNOX_BUILD_TIME=${BUILD_TIME}" \
    --load \
    "${ctx}"
}

# Multi-arch build + push in a single step. buildx assembles a manifest list
# covering all PLATFORMS and pushes it directly — there is no intermediate
# local image, so this cannot be split into separate build/push phases.
build_and_push_multiarch() {
  local key="$1"
  local name; name="$(image_name "$key")"
  local ctx;  ctx="$(build_context "$key")"
  local file; file="$(dockerfile "$key")"

  echo ""
  echo "▶  Building + pushing (${PLATFORMS}) ${key} → ${name}:${SHA_TAG}"
  docker buildx build \
    --platform "${PLATFORMS}" \
    --file "${file}" \
    --tag "${name}:latest" \
    --tag "${name}:${SHA_TAG}" \
    --build-arg "KNOX_GIT_SHA=${SHA_TAG}" \
    --build-arg "KNOX_BUILD_TIME=${BUILD_TIME}" \
    --push \
    "${ctx}"
}

# ── Parse arguments ───────────────────────────────────────────────────────────
ACTION="${1:-all}"
TARGET="${2:-}"

if [[ -n "$TARGET" ]] && ! is_valid_target "$TARGET"; then
  echo "❌  Unknown image target: ${TARGET}"
  echo "    Valid targets: ${ALL_IMAGES[*]}"
  exit 1
fi

TARGETS=("${ALL_IMAGES[@]}")
[[ -n "$TARGET" ]] && TARGETS=("$TARGET")

# ── Ensure buildx builder exists (needed for multi-arch) ──────────────────────
ensure_builder() {
  if ! docker buildx inspect knox-builder &>/dev/null; then
    echo "➜  Creating buildx builder 'knox-builder' (docker-container driver)…"
    docker buildx create --name knox-builder --driver docker-container --use
    docker buildx inspect knox-builder --bootstrap
  fi
  docker buildx use knox-builder
}

# ── Execute ───────────────────────────────────────────────────────────────────
case "$ACTION" in
  build)
    ensure_builder
    for t in "${TARGETS[@]}"; do build_local "$t"; done
    ;;
  push|all)
    # The default org is a placeholder that matches the k8s manifests; it is
    # nobody's namespace on any registry, so pushing to it can only fail.
    if [[ "${DOCKER_ORG}" == "knox" ]]; then
      echo "❌  DOCKER_ORG is still the default placeholder 'knox'."
      echo "    Set it to a namespace you can push to, e.g."
      echo "      DOCKER_ORG=ghcr.io/<github-user> $0 ${ACTION}"
      echo "      DOCKER_ORG=<dockerhub-user>      $0 ${ACTION}"
      exit 1
    fi
    ensure_builder
    for t in "${TARGETS[@]}"; do build_and_push_multiarch "$t"; done
    ;;
  *)
    echo "Usage: $0 {build|push|all} [${ALL_IMAGES[*]// /|}]"
    exit 1
    ;;
esac

echo ""
echo "✅  Done.  SHA tag: ${SHA_TAG}  (org: ${DOCKER_ORG})"
