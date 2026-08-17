CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule(
    'prune-refresh-tokens',
    '*/10 * * * *',
    $$
        DELETE FROM refresh_tokens
        WHERE expires_at < now()
           OR revoked_at IS NOT NULL
    $$
);


