-- The tenant's canonical OIDC issuer.
--
-- Stored rather than derived from configuration because the issuer is a tenant's
-- permanent identity: every relying party pins it, so it must not change when a
-- deployment-level environment variable does. Keeping it in the row makes a
-- base-domain move an explicit, auditable backfill, lets tenants live in
-- different regions, and makes a future custom-domain promotion a row update.
--
-- Every statement is idempotent. This runs from a Kubernetes init container that
-- is retried on failure, and the schema may also have been applied by hand
-- against an environment whose base domain differs from the backfill below — in
-- either case re-running must converge rather than fail.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS issuer TEXT;

-- Backfill only rows that have no issuer yet, so an environment that already set
-- its own (e.g. a different base domain, or a local dev host) is left alone.
--
-- The base domain must match the host the tenant is actually reachable on, or
-- discovery will be rejected by any compliant relying party. Set it for the
-- session before running migrations if the default is wrong:
--
--   SET knox.base_domain = 'knox.example.com';
--
-- Pre-existing tenants are only a concern on a database that predates this
-- column; a fresh install has no rows to backfill.
UPDATE tenants
SET issuer = 'https://' || slug || '.'
    || COALESCE(NULLIF(current_setting('knox.base_domain', true), ''), 'lvh.me')
WHERE issuer IS NULL;

ALTER TABLE tenants ALTER COLUMN issuer SET NOT NULL;

-- Two tenants sharing an issuer would make their tokens mutually acceptable.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_issuer_unique ON tenants (LOWER(issuer));
