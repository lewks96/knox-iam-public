#!/usr/bin/env bash
# scripts/k3d-setup.sh
#
# Bootstrap a local Knox IAM development cluster using k3d.
#
# Prerequisites (install once):
#   brew install k3d kubectl kustomize
#
# Usage:
#   ./scripts/k3d-setup.sh            # full setup: create + deploy + bootstrap
#   ./scripts/k3d-setup.sh setup      # the same thing, named (alias: `all`)
#   ./scripts/k3d-setup.sh create     # create the k3d cluster + install operators
#   ./scripts/k3d-setup.sh deploy     # (re)deploy Knox manifests onto existing cluster
#   ./scripts/k3d-setup.sh bootstrap  # run the one-shot bootstrap Job
#   ./scripts/k3d-setup.sh observe    # port-forward the Aspire dashboard
#   ./scripts/k3d-setup.sh tls        # (re)create the knox-tls secret (auto-runs in deploy)
#   ./scripts/k3d-setup.sh restart    # rollout-restart all knox deployments (forces :latest re-pull)
#   ./scripts/k3d-setup.sh restart server   # restart a single deployment
#   ./scripts/k3d-setup.sh delete     # tear down the local cluster entirely
#
#   --local is accepted on any of the above and pins KNOX_BASE_DOMAIN=lvh.me
#   (→ 127.0.0.1). That is the default now, so it only matters if you have
#   KNOX_BASE_DOMAIN exported to something else.
#
#   Two ways to get images into the cluster:
#
#   1. Published (nothing to build — pulls ghcr.io/lewks96/knox-iam-*:main):
#        ./scripts/k3d-setup.sh --published setup
#
#   2. Local (runs YOUR working tree; build first, every time):
#        ./scripts/docker.sh build
#        ./scripts/k3d-setup.sh setup
#
#   Root console then lives at https://knox-root.lvh.me:8443
#
# TLS:
#   By default, `tls` generates a self-signed cert covering *.${KNOX_BASE_DOMAIN}
#   (cached at .local-tls/, regenerated when the SAN list changes). To use your
#   own cert, export both TLS_CERT_FILE and TLS_KEY_FILE before running.
#   Override the SAN list with TLS_HOSTS=host1,host2,...
#
# Addressing:
#   Every tenant is a SUBDOMAIN — there is no path-based tenant prefix and no
#   bare-hostname entry point. With the default base domain the root tenant's
#   console is at:
#     https://knox-root.lvh.me:8443
#
# Environment:
#   CLUSTER_NAME       (default: knox-local)
#   KNOX_BASE_DOMAIN   — tenants are subdomains of this   (default: lvh.me)
#   KNOX_IMAGE_SOURCE  — local | published                 (default: local)
#   IMAGE_TAG          — override the tag  (local: git SHA; published: main)
#   DOCKER_ORG         — image name prefix; must match whatever
#                        ./scripts/docker.sh built            (default: knox)
#   KNOX_PUBLIC_PORT   — HTTPS port the ingress answers on (default: 8443)
#   DB_PASSWORD        — postgres password              (default: devpassword)
#   AES_KEY            — 32-byte base64 AES master key  (auto-generated if absent)
#   ADMIN_EMAIL        — root tenant admin email        (default: admin@knox.local)
#   ADMIN_PASSWORD     — root tenant admin password     (auto-generated if absent)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── Flags ─────────────────────────────────────────────────────────────────────
# --local : run against a k3d cluster on THIS machine. Points the base domain at
#   lvh.me (*.lvh.me → 127.0.0.1), so every tenant subdomain resolves to
#   localhost with no /etc/hosts work. That is also the default, so this flag is
#   only useful for overriding a KNOX_BASE_DOMAIN you have exported. Note it
#   wins over the environment, unlike everything else here.
# Stripped here so the subcommand dispatch below still sees $1/$2 unchanged.
_args=()
for _arg in "$@"; do
  case "$_arg" in
    --local)     KNOX_BASE_DOMAIN="${KNOX_BASE_DOMAIN:-lvh.me}" ;;
    --published) KNOX_IMAGE_SOURCE=published ;;
    *)           _args+=("$_arg") ;;
  esac
done
set -- ${_args[@]+"${_args[@]}"}

# ── Config ────────────────────────────────────────────────────────────────────
CLUSTER_NAME="${CLUSTER_NAME:-knox-local}"
DB_PASSWORD="${DB_PASSWORD:-devpassword}"

# ── Where the images come from ────────────────────────────────────────────────
# local     — built from this working tree by ./scripts/docker.sh build, tagged
#             with the current git SHA, and imported straight into the cluster.
#             What you want while developing: the cluster runs your changes.
# published — pulled from GHCR. Nothing to build, so a clean checkout can stand
#             the whole thing up in one command, but you get whatever `main`
#             was last pushed, not your working tree.
KNOX_IMAGE_SOURCE="${KNOX_IMAGE_SOURCE:-local}"
case "${KNOX_IMAGE_SOURCE}" in
  local)
    DOCKER_ORG="${DOCKER_ORG:-knox}"
    SHA_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo latest)}"
    OVERLAY_DIR="${ROOT}/k8s/overlays/local"
    ;;
  published)
    DOCKER_ORG="${DOCKER_ORG:-ghcr.io/lewks96}"
    SHA_TAG="${IMAGE_TAG:-main}"
    OVERLAY_DIR="${ROOT}/k8s/overlays/quickstart"
    ;;
  *)
    echo "❌  KNOX_IMAGE_SOURCE must be 'local' or 'published' (got '${KNOX_IMAGE_SOURCE}')" >&2
    exit 64
    ;;
esac
# Management OAuth client — must match a registered client in Knox.
# For local dev the default "management" client is created by migrations/seed.
MANAGEMENT_CLIENT_ID="${MANAGEMENT_CLIENT_ID:-management}"
MANAGEMENT_TENANT_ID="${MANAGEMENT_TENANT_ID:-knox-root}"
# Bootstrap admin user — used by the one-shot bootstrap Job.
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@knox.local}"
# Leave ADMIN_PASSWORD unset to have bootstrap auto-generate one.
# The generated password is captured and stored in the knox-bootstrap-output Secret.

# ── Tenant addressing ─────────────────────────────────────────────────────────
# Tenants are SUBDOMAINS: knox-root lives at knox-root.${KNOX_BASE_DOMAIN}, and
# both the server and the UI derive the tenant by stripping this suffix from the
# Host header. Nothing is reachable on a bare hostname any more.
#
# The default is lvh.me, which resolves *.lvh.me to 127.0.0.1 — right when k3d
# runs on this machine, which is the usual case. A tenant created tomorrow
# resolves without touching DNS. A hosts file cannot substitute here: it has no
# wildcards, so every new tenant would need a new line.
#
# k3d on another host (a VM, say): use sslip.io, which resolves any name
# embedding an IP straight to that IP. Dashes for dots —
#   KNOX_BASE_DOMAIN=192-168-64-7.sslip.io  →  192.168.64.7
#
# Offline alternative: set KNOX_BASE_DOMAIN to a made-up name and add one
# /etc/hosts line per tenant (127.0.0.1 knox-root.knox-vm).
KNOX_BASE_DOMAIN="${KNOX_BASE_DOMAIN:-lvh.me}"
KNOX_SCHEME="${KNOX_SCHEME:-https}"
# The ingress answers HTTPS on 8443 locally, and the port is part of the issuer.
KNOX_PUBLIC_PORT="${KNOX_PUBLIC_PORT:-8443}"
# Where the root tenant's console lives, derived rather than hardcoded.
ROOT_TENANT_URL="${KNOX_SCHEME}://${MANAGEMENT_TENANT_ID}.${KNOX_BASE_DOMAIN}:${KNOX_PUBLIC_PORT}"

# TLS — self-signed by default; override with TLS_CERT_FILE/TLS_KEY_FILE.
# The wildcard entry is the load-bearing one: every tenant is a subdomain, so a
# cert naming only the bare host fails SNI for the host you actually browse.
TLS_HOSTS="${TLS_HOSTS:-*.${KNOX_BASE_DOMAIN},${KNOX_BASE_DOMAIN},localhost}"
TLS_DIR="${ROOT}/.local-tls"

# NOTE: AES_KEY is deliberately NOT generated here. It is resolved inside
# cmd_deploy, which reuses whatever the cluster already holds — see
# resolve_generated_secrets. Minting one at parse time would rotate it on every
# invocation, including `tls` and `restart`.

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo ""; echo "▶  $*"; }
ok()   { echo "   ✅  $*"; }

# Reads a key out of an existing Secret, empty if absent.
existing_secret() {
  kubectl get secret "$1" -n knox -o jsonpath="{.data.$2}" 2>/dev/null | base64 -d 2>/dev/null || true
}

# Values that are generated once and must then never change.
#
# AES_MASTER_KEY is the one that bites: every tenant's signing keys are stored
# encrypted under it, and Postgres here is backed by a PVC that outlives any
# redeploy. Minting a fresh key on re-run leaves those rows undecryptable, and
# the failure surfaces far from the cause — login returns 500 with
# "Key decryption failed (bad key or tampered data)" and the cluster looks
# broken for no visible reason.
#
# So: an explicit AES_KEY wins, otherwise reuse the cluster's, otherwise mint.
resolve_generated_secrets() {
  if [[ -z "${AES_KEY:-}" ]]; then
    AES_KEY="$(existing_secret knox-app-secret AES_MASTER_KEY)"
    if [[ -n "$AES_KEY" ]]; then
      ok "Reusing the cluster's existing AES master key."
    else
      AES_KEY="$(openssl rand -base64 32)"
      ok "No existing AES master key — generated one."
    fi
  else
    ok "Using AES_KEY from the environment."
  fi

  # Rotating these only costs you the dashboard login, but there is no reason to.
  OTLP_API_KEY="$(existing_secret knox-aspire-secret OTLP_API_KEY)"
  [[ -n "$OTLP_API_KEY" ]] || OTLP_API_KEY="$(openssl rand -hex 32)"
  DASHBOARD_UI_TOKEN="$(existing_secret knox-aspire-secret DASHBOARD_UI_TOKEN)"
  [[ -n "$DASHBOARD_UI_TOKEN" ]] || DASHBOARD_UI_TOKEN="$(openssl rand -hex 32)"
}
warn() { echo "   ⚠️   $*"; }

require() {
  for cmd in "$@"; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "❌  Required tool not found: ${cmd}"
      echo "    Install with: brew install ${cmd}"
      exit 1
    fi
  done
}

cluster_exists() {
  k3d cluster list 2>/dev/null | grep -q "^${CLUSTER_NAME}"
}

# ── Sub-commands ──────────────────────────────────────────────────────────────

cmd_create() {
  require k3d kubectl

  if cluster_exists; then
    warn "Cluster '${CLUSTER_NAME}' already exists — skipping creation."
    warn "Run './scripts/k3d-setup.sh delete' first if you want a fresh cluster."
    return
  fi

  log "Creating k3d cluster '${CLUSTER_NAME}'…"
  # - Port 8080:80 — maps host:8080 → cluster HTTP ingress
  # - Port 8443:443 — maps host:8443 → cluster HTTPS ingress
  # - 1 server + 2 agents to simulate a multi-node setup
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 \
    --agents 2 \
    --port "8080:80@loadbalancer" \
    --port "8443:443@loadbalancer" \
    --k3s-arg "--disable=traefik@server:0" \
    --wait

  ok "Cluster '${CLUSTER_NAME}' is up."

  log "Merging kubeconfig…"
  k3d kubeconfig merge "${CLUSTER_NAME}" --kubeconfig-merge-default
  kubectl config use-context "k3d-${CLUSTER_NAME}"
  ok "kubectl context set to k3d-${CLUSTER_NAME}."

  cmd_install_operators
}

cmd_install_operators() {
  require kubectl

  # ── NGINX Ingress Controller ───────────────────────────────────────────────
  log "Installing NGINX Ingress Controller…"
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/cloud/deploy.yaml
  log "Waiting for ingress-nginx to be ready (up to 90s)…"
  kubectl wait --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=90s
  ok "NGINX Ingress ready."
  # Note: CloudNativePG is NOT installed locally — the local overlay uses a plain
  # postgres Deployment instead (no CNPG Cluster resource). Install CNPG only
  # for staging/production clusters per the instructions in k8s/postgres/cluster.yaml.
}

# Create or refresh the knox-tls Secret. Self-signed by default, or use a
# user-supplied PEM pair via TLS_CERT_FILE / TLS_KEY_FILE (production path).
# Idempotent: regenerates the self-signed material only if missing or expired
# within 7 days.
cmd_tls() {
  require kubectl

  local cert_file key_file generated=false

  if [[ -n "${TLS_CERT_FILE:-}" && -n "${TLS_KEY_FILE:-}" ]]; then
    cert_file="$TLS_CERT_FILE"
    key_file="$TLS_KEY_FILE"
    log "Using TLS cert from ${cert_file}"
    [[ -f "$cert_file" && -f "$key_file" ]] || {
      echo "❌  TLS_CERT_FILE or TLS_KEY_FILE not readable"; exit 1;
    }
  else
    require openssl
    cert_file="${TLS_DIR}/tls.crt"
    key_file="${TLS_DIR}/tls.key"
    mkdir -p "$TLS_DIR"

    # Regenerate if missing, expiring within 7 days, or covering a different set
    # of hosts. That last check matters: changing KNOX_BASE_DOMAIN silently
    # reuses a cached cert with the old SANs otherwise, and the failure surfaces
    # much later as an SNI mismatch in the browser.
    local sans_file="${TLS_DIR}/.san-list"
    local need_gen=false
    if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
      need_gen=true
    elif ! openssl x509 -in "$cert_file" -checkend 604800 -noout &>/dev/null; then
      warn "Existing self-signed cert expires within 7 days — regenerating."
      need_gen=true
    elif [[ ! -f "$sans_file" || "$(cat "$sans_file")" != "$TLS_HOSTS" ]]; then
      warn "Cert SAN list changed — regenerating for: ${TLS_HOSTS}"
      need_gen=true
    fi

    if $need_gen; then
      log "Generating self-signed cert for: ${TLS_HOSTS}"
      # Build openssl SAN string: DNS:host1,DNS:host2,IP:127.0.0.1
      local san="" h
      IFS=',' read -ra _hosts <<<"$TLS_HOSTS"
      for h in "${_hosts[@]}"; do
        h="$(echo "$h" | xargs)"   # trim
        [[ -z "$h" ]] && continue
        if [[ "$h" =~ ^[0-9.]+$ ]]; then
          san+="IP:${h},"
        else
          san+="DNS:${h},"
        fi
      done
      san+="IP:127.0.0.1"

      openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "$key_file" \
        -out    "$cert_file" \
        -subj   "/CN=${KNOX_BASE_DOMAIN}/O=Knox IAM Local Dev" \
        -addext "subjectAltName=${san}" \
        -addext "extendedKeyUsage=serverAuth" \
        >/dev/null 2>&1
      printf '%s' "$TLS_HOSTS" > "$sans_file"
      ok "Self-signed cert written to ${TLS_DIR}/"
      generated=true
    else
      ok "Self-signed cert at ${TLS_DIR}/ is still valid — reusing."
    fi
  fi

  log "Applying knox-tls Secret to namespace knox…"
  kubectl apply -f k8s/base/namespace.yaml >/dev/null
  kubectl create secret tls knox-tls \
    --namespace knox \
    --cert="$cert_file" \
    --key="$key_file" \
    --dry-run=client -o yaml | kubectl apply -f -
  ok "knox-tls secret applied."

  if $generated; then
    warn "First-run note: your browser will warn about the self-signed cert."
    warn "On macOS you can trust it with:"
    warn "  sudo security add-trusted-cert -d -r trustRoot \\"
    warn "       -k /Library/Keychains/System.keychain ${cert_file}"
  fi
}

# The base domain has to resolve to wherever the cluster actually answers, and
# getting it wrong fails in a confusing place — the browser reports a bad
# certificate rather than a bad name, because nginx cannot match the SNI to a
# server block and serves its fake cert. Say so up front instead.
check_base_domain() {
  local probe="${MANAGEMENT_TENANT_ID}.${KNOX_BASE_DOMAIN}"
  if ! host "$probe" &>/dev/null && ! nslookup "$probe" &>/dev/null; then
    warn "${probe} does not resolve."
    warn "Set KNOX_BASE_DOMAIN to a wildcard domain pointing at this cluster:"
    warn "  k3d on this Mac      → KNOX_BASE_DOMAIN=lvh.me          (*.lvh.me → 127.0.0.1)"
    warn "  k3d on another host  → KNOX_BASE_DOMAIN=<ip-with-dashes>.sslip.io"
    warn "Continuing anyway — deploy will succeed, but you will not reach it."
  fi
}

cmd_deploy() {
  require kubectl kustomize

  check_base_domain

  log "Ensuring kubectl context is k3d-${CLUSTER_NAME}…"
  kubectl config use-context "k3d-${CLUSTER_NAME}"

  # Must run AFTER the context switch — it reads secrets out of this cluster.
  resolve_generated_secrets

  # ── TLS Secret (self-signed by default, or user-supplied) ─────────────────
  cmd_tls

  # ── Images ────────────────────────────────────────────────────────────────
  # In `local` mode the cluster is fed from the local Docker daemon:
  # `docker.sh build` tags each image with the current git SHA, and the overlay
  # is pinned to that same SHA below. Nothing is published to a registry, so a
  # missing image is a hard stop rather than a pull that would 404 — set
  # KNOX_ALLOW_REMOTE_IMAGES=true if you genuinely do have them pullable.
  #
  # In `published` mode there is nothing to import: the overlay names GHCR and
  # the kubelet pulls.
  if [[ "${KNOX_IMAGE_SOURCE}" == "published" ]]; then
    log "Using published images from ${DOCKER_ORG} (tag: ${SHA_TAG}) — nothing to build."
  else
    log "Importing Knox images into the k3d cluster…"
    local missing=()
    for img in server migrate postgres ui pgbouncer; do
      local_img="${DOCKER_ORG}/knox-iam-${img}:${SHA_TAG}"
      if docker image inspect "${local_img}" &>/dev/null; then
        echo "   Importing ${local_img}…"
        k3d image import "${local_img}" --cluster "${CLUSTER_NAME}"
      else
        missing+=("${img}")
        warn "Image ${local_img} not found locally."
      fi
    done

    if (( ${#missing[@]} > 0 )); then
      if [[ "${KNOX_ALLOW_REMOTE_IMAGES:-false}" == "true" ]]; then
        warn "Continuing anyway — the cluster will try to pull: ${missing[*]}"
      else
        echo ""
        echo "❌  Missing local images: ${missing[*]}"
        echo "    They are built from this working tree and tagged ${SHA_TAG}:"
        echo ""
        echo "      ./scripts/docker.sh build"
        echo ""
        echo "    Then re-run this script. Or skip building entirely and use the"
        echo "    published images:  ./scripts/k3d-setup.sh --published setup"
        exit 1
      fi
    fi
  fi

  # ── Apply namespace early so secrets can be created ───────────────────────
  log "Creating namespace…"
  kubectl apply -f k8s/base/namespace.yaml

  # ── Seed secrets (dev values only — do NOT do this in production) ─────────
  # We manage secrets imperatively here so we can inject real values and avoid
  # committing credentials. The kustomize overlay includes secrets.yaml only as
  # a last-resort fallback; we delete + recreate to handle the immutable `type`
  # field on knox-db-credentials.
  log "Seeding dev secrets…"

  # DB credentials — must be type kubernetes.io/basic-auth for CNPG compat
  # Delete first so we can cleanly apply (type field is immutable once created)
  kubectl delete secret knox-db-credentials --namespace knox --ignore-not-found
  kubectl create secret generic knox-db-credentials \
    --namespace knox \
    --type=kubernetes.io/basic-auth \
    --from-literal=username=knox \
    --from-literal=password="${DB_PASSWORD}"

  # App secret — Opaque, safe to upsert
  # DATABASE_URL → PgBouncer (transaction pooling, handles burst load)
  # DATABASE_RO_URL → Postgres direct (no read replica locally, same host)
  # DATABASE_MIGRATE_URL → Postgres direct (sqlx advisory locks need a real connection)
  DB_URL="postgresql://knox:${DB_PASSWORD}@knox-pgbouncer.knox.svc.cluster.local:5432/knox"
  DB_RO_URL="postgresql://knox:${DB_PASSWORD}@knox-db-rw.knox.svc.cluster.local:5432/knox"
  DB_MIGRATE_URL="postgresql://knox:${DB_PASSWORD}@knox-db-rw.knox.svc.cluster.local:5432/knox"
  kubectl create secret generic knox-app-secret \
    --namespace knox \
    --from-literal=AES_MASTER_KEY="${AES_KEY}" \
    --from-literal=DATABASE_URL="${DB_URL}" \
    --from-literal=DATABASE_RO_URL="${DB_RO_URL}" \
    --from-literal=DATABASE_MIGRATE_URL="${DB_MIGRATE_URL}" \
    --from-literal=REDIS_URL="redis://knox-redis.knox.svc.cluster.local:6379" \
    --dry-run=client -o yaml | kubectl apply -f -

  ok "Secrets applied."

  # ── Seed Aspire Dashboard credentials ─────────────────────────────────────
  # Values come from resolve_generated_secrets, which reuses the cluster's.
  log "Seeding Aspire Dashboard credentials…"
  kubectl create secret generic knox-aspire-secret \
    --namespace knox \
    --from-literal=OTLP_API_KEY="${OTLP_API_KEY}" \
    --from-literal=OTLP_AUTH_HEADER="Authorization=ApiKey ${OTLP_API_KEY}" \
    --from-literal=DASHBOARD_UI_TOKEN="${DASHBOARD_UI_TOKEN}" \
    --dry-run=client -o yaml | kubectl apply -f -
  ok "Aspire credentials seeded."
  echo "   Dashboard UI token: ${DASHBOARD_UI_TOKEN}"
  echo "   (reach it with './scripts/k3d-setup.sh observe' — the Aspire dashboard"
  echo "    is not on the ingress, so it is port-forwarded rather than routed)"

  # ── Pin image tags to the current SHA ─────────────────────────────────────
  # Only in `local` mode: the quickstart overlay names a published tag and must
  # not be rewritten to a SHA that exists on nobody's machine but this one.
  #
  # Use sed rather than `kustomize edit set image` — the kustomize CLI rewrites
  # the entire kustomization.yaml when editing, which corrupts the `|-` literal
  # block scalars on inline patches and silently breaks them.
  if [[ "${KNOX_IMAGE_SOURCE}" == "local" ]]; then
    log "Pinning image tags to ${SHA_TAG}…"
    if [[ "$(uname)" == "Darwin" ]]; then
      sed -i '' "s/newTag: .*/newTag: ${SHA_TAG}/" \
          "${ROOT}/k8s/overlays/local/kustomization.yaml"
    else
      sed -i "s/newTag: .*/newTag: ${SHA_TAG}/" \
          "${ROOT}/k8s/overlays/local/kustomization.yaml"
    fi
  fi

  log "Applying kustomize manifests (local overlay)…"
  # Remove the old knox-server-ingress if it exists — it was replaced by
  # knox-api-ingress + knox-ui-ingress and nginx rejects duplicate host/path rules.
  kubectl delete ingress knox-server-ingress -n knox --ignore-not-found 2>/dev/null || true
  # --load-restrictor=LoadRestrictionsNone allows the overlay (inside k8s/overlays/)
  # to reference files in the sibling k8s/ directories without triggering the
  # kustomize security boundary check.
  kustomize build --load-restrictor=LoadRestrictionsNone "${OVERLAY_DIR}" \
    | kubectl apply --server-side --force-conflicts -f -

  ok "Manifests applied."

  # ── Localise tenant addressing ────────────────────────────────────────────
  # Applied AFTER the kustomize apply, not before: these ConfigMaps also exist
  # in base, so anything seeded earlier is overwritten by the apply above. A
  # strategic merge touches only these keys and leaves the rest of base intact.
  #
  # The server and the UI must agree on the base domain or the tenant resolves
  # on one side and 404s on the other, so both are patched from the same
  # variable.
  log "Localising tenant addressing to ${KNOX_BASE_DOMAIN}…"
  kubectl patch configmap knox-app-config -n knox --type merge -p "$(cat <<EOF
{"data":{"KNOX_SCHEME":"${KNOX_SCHEME}","KNOX_BASE_DOMAIN":"${KNOX_BASE_DOMAIN}","KNOX_PUBLIC_PORT":"${KNOX_PUBLIC_PORT}"}}
EOF
)"
  kubectl patch configmap knox-ui-config -n knox --type merge -p "$(cat <<EOF
{"data":{"MANAGEMENT_CLIENT_ID":"${MANAGEMENT_CLIENT_ID}","MANAGEMENT_TENANT_ID":"${MANAGEMENT_TENANT_ID}","BASE_DOMAIN":"${KNOX_BASE_DOMAIN}"}}
EOF
)"
  ok "Tenant addressing applied (base=${KNOX_BASE_DOMAIN}, client=${MANAGEMENT_CLIENT_ID})."

  # ── Point the ingress at this base domain, with TLS ───────────────────────
  # The rule host and the TLS host must be set together and must match.
  # ingress-nginx builds a server block per `spec.rules[].host` and attaches the
  # TLS secret to those server names; a `spec.tls[].hosts` entry that no rule
  # matches binds to nothing, and nginx serves its fake certificate for that SNI.
  #
  # `*.${KNOX_BASE_DOMAIN}` matches exactly one label, which is precisely the
  # tenant-per-subdomain shape: knox-root.${KNOX_BASE_DOMAIN} matches, and the
  # bare domain deliberately does not — it names no tenant.
  # A JSON patch, not a merge patch: a merge patch replaces arrays wholesale, so
  # writing `rules` would discard every path/backend defined in base.
  log "Pointing the ingress at *.${KNOX_BASE_DOMAIN} with TLS…"
  kubectl patch ingress knox-ingress -n knox --type json -p "$(cat <<EOF
[
  {"op":"replace","path":"/spec/rules/0/host","value":"*.${KNOX_BASE_DOMAIN}"},
  {"op":"add","path":"/spec/tls","value":[{"hosts":["*.${KNOX_BASE_DOMAIN}"],"secretName":"knox-tls"}]}
]
EOF
)"
  ok "Ingress TLS attached for *.${KNOX_BASE_DOMAIN}."

  # env-from-ConfigMap is resolved at pod start, so the patches above are
  # invisible to pods already running from a previous deploy.
  log "Restarting workloads to pick up config…"
  kubectl rollout restart deployment/knox-server deployment/knox-ui -n knox >/dev/null

  log "Waiting for Knox server to be ready (up to 3 minutes)…"
  kubectl rollout status deployment/knox-server -n knox --timeout=180s || {
    warn "knox-server not ready yet — check with: kubectl get pods -n knox"
  }

  log "Waiting for Knox UI to be ready (up to 3 minutes)…"
  kubectl rollout status deployment/knox-ui -n knox --timeout=180s || {
    warn "knox-ui not ready yet — check with: kubectl get pods -n knox"
  }

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ✅  Knox IAM deployed!"
  echo ""
  echo "  UI:         ${ROOT_TENANT_URL}"
  echo "  API:        ${ROOT_TENANT_URL}/api"
  echo "  Health:     ${ROOT_TENANT_URL}/api/sys/health"
  echo ""
  echo "  ℹ️   Every tenant is a subdomain of ${KNOX_BASE_DOMAIN}. There is no"
  echo "      bare-hostname entry point — a host naming no tenant is a 404."
  echo ""
  echo "  ℹ️   HTTP on :8080 redirects to HTTPS on :8443 automatically."
  echo "      The cert is self-signed — accept the browser warning once."
  echo ""
  echo "  ℹ️   Run './scripts/k3d-setup.sh bootstrap' to create the root tenant"
  echo "      and admin user, then log in at ${ROOT_TENANT_URL}/login"
  echo ""
  echo "  📊  Run './scripts/k3d-setup.sh observe' to open the Aspire telemetry dashboard"
  echo ""
  echo "  Useful commands:"
  echo "    kubectl get pods -n knox"
  echo "    kubectl logs -n knox -l app=knox-ui -f"
  echo "    kubectl logs -n knox -l app=knox-server -f"
  echo "    kubectl logs -n knox -l app=knox-server -c migrate"
  echo "    k3d cluster delete ${CLUSTER_NAME}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

cmd_observe() {
  require kubectl

  # Retrieve the dashboard token from the secret so the user can paste it in.
  local token
  token="$(kubectl get secret knox-aspire-secret -n knox \
             -o jsonpath='{.data.DASHBOARD_UI_TOKEN}' 2>/dev/null \
             | base64 -d 2>/dev/null || echo '<not found — run deploy first>')"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Aspire Dashboard — forwarding to http://localhost:18888"
  echo ""
  echo "  UI token: ${token}"
  echo ""
  echo "  Open http://localhost:18888 and paste the token when prompted."
  echo "  Press Ctrl+C to stop the port-forward."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  kubectl port-forward svc/aspire-dashboard 18888:18888 -n knox
}

# Restart knox deployments to force a fresh image pull. Server/UI use
# imagePullPolicy: Always, so a rollout restart picks up the newest :latest
# from Docker Hub. `migrate` and `bootstrap` run as init containers / Jobs and
# are intentionally skipped.
cmd_restart() {
  require kubectl

  local target="${1:-}"

  deployment_for() {
    case "$1" in
      server)    echo "knox-server" ;;
      ui)        echo "knox-ui"     ;;
      postgres)  echo "postgres"    ;;
      pgbouncer) echo "pgbouncer"   ;;
      *)         echo ""            ;;
    esac
  }

  local keys=(server ui postgres pgbouncer)
  if [[ -n "$target" ]]; then
    if [[ -z "$(deployment_for "$target")" ]]; then
      echo "❌  Unknown restart target: ${target}"
      echo "    Valid targets: ${keys[*]}"
      exit 1
    fi
    keys=("$target")
  fi

  for key in "${keys[@]}"; do
    local dep; dep="$(deployment_for "$key")"
    if ! kubectl get deployment "$dep" -n knox &>/dev/null; then
      warn "Skipping ${dep} (not found in namespace knox)"
      continue
    fi
    log "Restarting deployment/${dep}…"
    kubectl rollout restart "deployment/${dep}" -n knox
    kubectl rollout status  "deployment/${dep}" -n knox --timeout=180s || {
      warn "${dep} did not become ready within 180s"
    }
    ok "${dep} restarted."
  done
}

cmd_delete() {
  require k3d
  log "Deleting cluster '${CLUSTER_NAME}'…"
  k3d cluster delete "${CLUSTER_NAME}"
  ok "Cluster deleted."
}

cmd_bootstrap() {
  require kubectl

  log "Checking bootstrap status…"

  # Idempotency — skip if the output Secret already exists.
  if kubectl get secret knox-bootstrap-output -n knox &>/dev/null; then
    warn "knox-bootstrap-output secret already exists — bootstrap was previously run."
    warn "To re-bootstrap: kubectl delete secret knox-bootstrap-output -n knox"
    warn "                 then re-run: ./scripts/k3d-setup.sh bootstrap"
    return
  fi

  # ── Seed the bootstrap config Secret ────────────────────────────────────────
  # Stored as a Secret (not ConfigMap) because it contains the admin password.
  local admin_pass="${ADMIN_PASSWORD:-}"
  local pass_was_generated=false
  if [[ -z "$admin_pass" ]]; then
    admin_pass="$(openssl rand -base64 16 | tr -d '=' | tr '+/' 'Aa')1!"
    pass_was_generated=true
    warn "ADMIN_PASSWORD not set — generated a random password (stored in knox-bootstrap-output)."
  fi

  # KNOX_HOST/KNOX_HOSTS are gone — the bootstrap binary derives the root
  # tenant's issuer and callback from KNOX_SCHEME/KNOX_BASE_DOMAIN/
  # KNOX_PUBLIC_PORT, which the Job now reads straight from knox-app-config so
  # it cannot disagree with the server. This Secret carries only the credentials.
  kubectl create secret generic knox-bootstrap-config \
    --namespace knox \
    --from-literal=ADMIN_EMAIL="${ADMIN_EMAIL}" \
    --from-literal=ADMIN_PASSWORD="${admin_pass}" \
    --dry-run=client -o yaml | kubectl apply -f -
  ok "Bootstrap config secret seeded."

  # The Job reads knox-app-config, so a bootstrap run before deploy would mint
  # the root tenant's issuer from base's placeholder domain — and the issuer is
  # immutable once written.
  if ! kubectl get configmap knox-app-config -n knox &>/dev/null; then
    echo "❌  knox-app-config not found — run './scripts/k3d-setup.sh deploy' first."
    echo "    Bootstrapping without it would write an unusable issuer onto the root tenant."
    exit 1
  fi
  local cm_domain
  cm_domain="$(kubectl get configmap knox-app-config -n knox -o jsonpath='{.data.KNOX_BASE_DOMAIN}')"
  if [[ "$cm_domain" != "$KNOX_BASE_DOMAIN" ]]; then
    warn "Cluster base domain is '${cm_domain}' but this run wants '${KNOX_BASE_DOMAIN}'."
    warn "Re-run deploy first, or the root tenant's issuer will not match the host you browse."
  fi

  # ── Import the bootstrap image ───────────────────────────────────────────────
  local bootstrap_img="${DOCKER_ORG}/knox-iam-bootstrap:${SHA_TAG}"
  if docker image inspect "${bootstrap_img}" &>/dev/null; then
    log "Importing bootstrap image into cluster…"
    k3d image import "${bootstrap_img}" --cluster "${CLUSTER_NAME}"
  elif [[ "${KNOX_IMAGE_SOURCE}" == "published" || "${KNOX_ALLOW_REMOTE_IMAGES:-false}" == "true" ]]; then
    log "Bootstrap image ${bootstrap_img} will be pulled by the cluster."
  else
    echo ""
    echo "❌  Bootstrap image ${bootstrap_img} not found locally."
    echo "    Build it first:  ./scripts/docker.sh build bootstrap"
    exit 1
  fi

  # ── Apply the Job (with the current SHA tag patched in) ──────────────────────
  log "Applying bootstrap Job…"
  # Delete any previous completed/failed Job so we can re-apply cleanly.
  kubectl delete job knox-bootstrap -n knox --ignore-not-found

  # Patch the image, and the pull policy when it has to come from a registry.
  local bootstrap_pull_policy="IfNotPresent"
  [[ "${KNOX_IMAGE_SOURCE}" == "published" ]] && bootstrap_pull_policy="Always"

  kubectl apply -f <(
    sed -e "s|knox/knox-iam-bootstrap:latest|${bootstrap_img}|g" \
        -e "s|imagePullPolicy: IfNotPresent|imagePullPolicy: ${bootstrap_pull_policy}|" \
        "${ROOT}/k8s/base/bootstrap/job.yaml"
  )

  # ── Wait for completion ───────────────────────────────────────────────────────
  log "Waiting for bootstrap Job to complete (up to 3 minutes)…"
  if ! kubectl wait --for=condition=complete job/knox-bootstrap \
       -n knox --timeout=180s 2>/dev/null; then
    warn "Bootstrap Job did not complete — checking for failure…"
    kubectl describe job knox-bootstrap -n knox || true
    kubectl logs -n knox -l job-name=knox-bootstrap --tail=50 || true
    return 1
  fi

  # ── Capture output → K8s Secret ──────────────────────────────────────────────
  log "Capturing bootstrap output…"
  local json_output
  json_output="$(kubectl logs -n knox -l job-name=knox-bootstrap --tail=100 2>/dev/null \
                 | grep '^{' | tail -1)"

  if [[ -z "$json_output" ]]; then
    warn "No JSON output captured from bootstrap Job — the root tenant may already exist."
    warn "Check logs: kubectl logs -n knox -l job-name=knox-bootstrap"
    return
  fi

  # Store the full JSON in a Secret so credentials survive pod cleanup.
  # Merge the admin password in at this level — the binary only echoes
  # admin_password_generated when IT generated the password, but the script
  # may have generated it instead. Storing it here means there is always
  # one place to look: knox-bootstrap-output.
  local full_json
  full_json="$(echo "$json_output" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['admin_password'] = '${admin_pass}'
print(json.dumps(d))
")"

  kubectl create secret generic knox-bootstrap-output \
    --namespace knox \
    --from-literal=json="${full_json}" \
    --dry-run=client -o yaml | kubectl apply -f -

  ok "Credentials stored in Secret 'knox-bootstrap-output'."
  ok "Retrieve later: kubectl get secret knox-bootstrap-output -n knox -o jsonpath='{.data.json}' | base64 -d | python3 -m json.tool"

  # ── Pretty-print summary ──────────────────────────────────────────────────────
  local tenant_id m2m_secret display_pass
  tenant_id="$(   echo "$full_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tenant_id','?'))")"
  m2m_secret="$(  echo "$full_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('m2m_client_secret','?'))")"
  display_pass="$(echo "$full_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('admin_password','?'))")"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ✅  Knox root tenant bootstrapped!"
  echo ""
  echo "  Tenant ID:       ${tenant_id}"
  echo "  Admin login:     ${ROOT_TENANT_URL}/login"
  echo "  Admin email:     ${ADMIN_EMAIL}"
  echo "  Admin password:  ${display_pass}"
  echo ""
  echo "  M2M client ID:   management"
  echo "  M2M secret:      ${m2m_secret}"
  echo ""
  echo "  All credentials saved to Secret: knox-bootstrap-output (namespace: knox)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── Main ──────────────────────────────────────────────────────────────────────
ACTION="${1:-all}"
TARGET="${2:-}"

case "$ACTION" in
  create)      cmd_create ;;
  deploy)      cmd_deploy ;;
  bootstrap)   cmd_bootstrap ;;
  observe)     cmd_observe ;;
  tls)         cmd_tls ;;
  restart)     cmd_restart "$TARGET" ;;
  delete)      cmd_delete ;;
  # `setup` is the name every doc uses for the whole run, `all` is what this
  # script has always called it. Both, rather than making one of them a lie.
  all|setup)   cmd_create && cmd_deploy && cmd_bootstrap ;;
  *)
    echo "Usage: $0 {setup|create|deploy|bootstrap|observe|tls|restart|delete} [target]"
    echo ""
    echo "  setup      create + deploy + bootstrap (same as 'all', and the default)"
    echo "  create     the k3d cluster and the ingress controller"
    echo "  deploy     (re)apply the manifests"
    echo "  bootstrap  the one-shot Job seeding the root tenant and admin"
    echo "  observe    port-forward the Aspire dashboard"
    echo "  tls        regenerate the self-signed wildcard cert"
    echo "  restart    rollout-restart all knox deployments, or one"
    echo "  delete     tear the cluster down"
    echo ""
    echo "Flags: --published (pull images from GHCR)  --local (base domain lvh.me)"
    exit 1
    ;;
esac













