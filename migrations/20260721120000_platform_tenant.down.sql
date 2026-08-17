DROP INDEX IF EXISTS idx_tenants_single_platform;
ALTER TABLE tenants DROP COLUMN IF EXISTS is_platform;
