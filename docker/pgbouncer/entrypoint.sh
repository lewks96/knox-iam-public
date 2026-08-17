#!/bin/sh
# Generates /tmp/pgbouncer/pgbouncer.ini and /tmp/pgbouncer/userlist.txt
# from environment variables, then execs pgbouncer.
set -e

# Required
: "${DB_HOST:?DB_HOST is required}"
: "${DB_NAME:?DB_NAME is required}"
: "${DB_USER:?DB_USER is required}"
: "${DB_PASSWORD:?DB_PASSWORD is required}"

# Optional with defaults
DB_PORT="${DB_PORT:-5432}"
POOL_MODE="${POOL_MODE:-session}"
DEFAULT_POOL_SIZE="${DEFAULT_POOL_SIZE:-20}"
MAX_CLIENT_CONN="${MAX_CLIENT_CONN:-200}"
RESERVE_POOL_SIZE="${RESERVE_POOL_SIZE:-5}"
RESERVE_POOL_TIMEOUT="${RESERVE_POOL_TIMEOUT:-1}"
SERVER_IDLE_TIMEOUT="${SERVER_IDLE_TIMEOUT:-60}"
SERVER_LIFETIME="${SERVER_LIFETIME:-3600}"
# auth_type = scram-sha-256 + auth_query is the proper approach:
# PgBouncer fetches the SCRAM verifier from pg_authid at connect time,
# so userlist.txt only needs the auth_user plaintext password (used to
# run the lookup query — not exposed to clients).
AUTH_TYPE="${AUTH_TYPE:-scram-sha-256}"
# auth_user: the Postgres user PgBouncer connects as to run auth_query.
# Must be able to read pg_authid (i.e. a superuser).
AUTH_USER="${AUTH_USER:-${DB_USER}}"
AUTH_QUERY="${AUTH_QUERY:-SELECT rolname, rolpassword FROM pg_authid WHERE rolname=\$1}"

# Write to /tmp — always writable regardless of user
CFG_DIR="/tmp/pgbouncer"
mkdir -p "${CFG_DIR}"

cat > "${CFG_DIR}/pgbouncer.ini" <<EOF
[databases]
${DB_NAME} = host=${DB_HOST} port=${DB_PORT} dbname=${DB_NAME} user=${DB_USER} password=${DB_PASSWORD}

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 5432

; auth_query lets PgBouncer fetch the real SCRAM verifier from pg_authid
; so clients authenticate with proper SCRAM-SHA-256 end-to-end.
auth_type = ${AUTH_TYPE}
auth_file = ${CFG_DIR}/userlist.txt
auth_user = ${AUTH_USER}
auth_query = ${AUTH_QUERY}

; sqlx (via libpq) sends extra_float_digits=2 in every startup packet.
; PgBouncer must ignore it or it rejects the connection with 08P01.
; application_name is also commonly sent by drivers — ignore that too.
ignore_startup_parameters = extra_float_digits,application_name

pool_mode = ${POOL_MODE}
default_pool_size = ${DEFAULT_POOL_SIZE}
max_client_conn = ${MAX_CLIENT_CONN}
reserve_pool_size = ${RESERVE_POOL_SIZE}
reserve_pool_timeout = ${RESERVE_POOL_TIMEOUT}
server_idle_timeout = ${SERVER_IDLE_TIMEOUT}
server_lifetime = ${SERVER_LIFETIME}

; DISCARD ALL clears all session state (prepared statements, temp tables,
; advisory locks, etc.) when a client disconnects and the backend is returned
; to the free pool. In session mode this is safe: sqlx holds the TCP connection
; open for the pool connection lifetime, so DISCARD ALL never fires mid-query.
server_reset_query = DISCARD ALL

; Logging — bump to 1 to debug connection issues
log_connections = 0
log_disconnections = 0
log_pooler_errors = 1
EOF

# userlist.txt only needs the auth_user's plaintext password.
# PgBouncer uses this to connect to Postgres and run auth_query —
# it is never sent to clients. Clients are verified via the SCRAM
# hash returned by auth_query.
cat > "${CFG_DIR}/userlist.txt" <<EOF
"${AUTH_USER}" "${DB_PASSWORD}"
EOF

chmod 600 "${CFG_DIR}/userlist.txt" "${CFG_DIR}/pgbouncer.ini"


exec pgbouncer "${CFG_DIR}/pgbouncer.ini"
