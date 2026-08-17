DROP TRIGGER IF EXISTS update_identities_updated_at ON identities;
DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;

DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS tenants;

DROP TYPE IF EXISTS IDENTITY_KIND;
DROP TYPE IF EXISTS STATUS;

DROP FUNCTION IF EXISTS update_updated_at_column;