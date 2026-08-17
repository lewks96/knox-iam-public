DROP INDEX IF EXISTS idx_tenants_issuer_unique;
ALTER TABLE tenants DROP COLUMN IF EXISTS issuer;
