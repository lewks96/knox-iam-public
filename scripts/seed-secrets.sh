#!/bin/sh
# Re-seeds the dev secrets into an already-running knox namespace.
# Safe to run multiple times.
set -e

DB_PASSWORD="$(openssl rand -base64 16 | tr -d '/+=' | head -c 20)"
AES_KEY="$(openssl rand -base64 32)"
OTLP_API_KEY="$(openssl rand -hex 32)"
DASHBOARD_UI_TOKEN="$(openssl rand -hex 32)"
DB_URL="postgresql://knox:${DB_PASSWORD}@knox-pgbouncer.knox.svc.cluster.local:5432/knox"
DB_RO_URL="postgresql://knox:${DB_PASSWORD}@knox-db-rw.knox.svc.cluster.local:5432/knox"
DB_MIGRATE_URL="postgresql://knox:${DB_PASSWORD}@knox-db-rw.knox.svc.cluster.local:5432/knox"

kubectl delete secret knox-db-credentials --namespace knox --ignore-not-found

kubectl create secret generic knox-db-credentials \
  --namespace knox \
  --type=kubernetes.io/basic-auth \
  --from-literal=username=knox \
  --from-literal=password="${DB_PASSWORD}"

kubectl create secret generic knox-app-secret \
  --namespace knox \
  --from-literal=AES_MASTER_KEY="${AES_KEY}" \
  --from-literal=DATABASE_URL="${DB_URL}" \
  --from-literal=DATABASE_RO_URL="${DB_RO_URL}" \
  --from-literal=DATABASE_MIGRATE_URL="${DB_MIGRATE_URL}" \
  --from-literal=REDIS_URL="redis://knox-redis.knox.svc.cluster.local:6379" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic knox-aspire-secret \
  --namespace knox \
  --from-literal=OTLP_API_KEY="${OTLP_API_KEY}" \
  --from-literal=OTLP_AUTH_HEADER="Authorization=ApiKey ${OTLP_API_KEY}" \
  --from-literal=DASHBOARD_UI_TOKEN="${DASHBOARD_UI_TOKEN}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secrets seeded."
echo "  DB password:          ${DB_PASSWORD}"
echo "  Dashboard UI token:   ${DASHBOARD_UI_TOKEN}"
echo ""
echo "Restarting affected deployments..."
kubectl rollout restart deployment/knox-postgres deployment/aspire-dashboard deployment/knox-server deployment/pgbouncer -n knox

