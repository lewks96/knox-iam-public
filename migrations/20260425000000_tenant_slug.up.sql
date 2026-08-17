ALTER TABLE tenants
    ADD COLUMN slug TEXT NOT NULL DEFAULT '';

-- Backfill: generate slug from name for any existing rows (shouldn't be any in prod)
UPDATE tenants
SET slug = LOWER(REGEXP_REPLACE(name, '[^a-zA-Z0-9]+', '-', 'g'));

-- Remove the default now that it's backfilled
ALTER TABLE tenants
    ALTER COLUMN slug DROP DEFAULT;

CREATE UNIQUE INDEX idx_tenants_slug ON tenants (slug);

