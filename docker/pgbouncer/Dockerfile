    # PgBouncer image — built from the official pgbouncer Alpine base.
    # Configures entirely via environment variables using the entrypoint below.
    # Ref: https://hub.docker.com/r/pgbouncer/pgbouncer
    #
    # Supported env vars (set in k8s/overlays/local/pgbouncer.yaml):
    #   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
    #   POOL_MODE, DEFAULT_POOL_SIZE, MAX_CLIENT_CONN
    FROM alpine:3.21

    RUN apk add --no-cache pgbouncer \
        && adduser -S -D -H -u 999 pgbouncer 2>/dev/null || true

    # then execs pgbouncer. Keeps the image stateless and secrets out of layers.
    COPY entrypoint.sh /entrypoint.sh
    RUN chmod +x /entrypoint.sh

    USER pgbouncer
    EXPOSE 5432
    ENTRYPOINT ["/entrypoint.sh"]
