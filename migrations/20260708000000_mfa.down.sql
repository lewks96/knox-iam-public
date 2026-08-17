DROP TRIGGER IF EXISTS update_mfa_methods_updated_at ON mfa_methods;
DROP TABLE IF EXISTS mfa_backup_codes;
DROP TABLE IF EXISTS mfa_methods;
DROP TYPE IF EXISTS MFA_METHOD;
