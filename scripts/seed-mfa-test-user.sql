-- Seeds the test user for scripts/mfa-flow-test.py into the knox-root tenant.
-- Password is 'Test@1234!' (Argon2id). Safe to re-run: does nothing if the
-- user already exists.
--
--   docker compose exec -T postgres psql -U admin -d knox < scripts/seed-mfa-test-user.sql

-- The identity must land in the same pool as the client the test logs in
-- through. mfa-flow-test.py uses `management`, which binds to the tenant's
-- staff pool, so a user seeded anywhere else is invisible to that login.
WITH t AS (SELECT id FROM tenants WHERE slug = 'knox-root'),
p AS (SELECT id FROM pools WHERE slug = 'staff' AND tenant_id = (SELECT id FROM t)),
u AS (
    INSERT INTO identities (tenant_id, pool_id, kind, username, email, password_hash, email_verified, status)
    SELECT t.id, p.id, 'human', 'mfa.e2e@knox.test', 'mfa.e2e@knox.test',
           '$argon2id$v=19$m=19456,t=2,p=1$o7h/xGTYjsVxz2plqJ/DVQ$0KJAIvu8DfPsFPvaEItU1+SNHKAz5Ge2HnIh5YvdfT8',
           true, 'active'
    FROM t, p
    ON CONFLICT DO NOTHING
    RETURNING id, tenant_id
)
INSERT INTO identity_roles (identity_id, role_id)
SELECT u.id, r.id
FROM u
JOIN roles r ON r.tenant_id = u.tenant_id AND r.name IN ('IdentitySelf', 'AuditViewer');

-- Reset any MFA state so the flow test starts clean. Usernames are unique per
-- pool rather than per tenant now, so this scopes by pool and uses IN — a bare
-- scalar subquery on username would error the moment the same address exists
-- in a customer pool.
CREATE TEMP VIEW seeded_identity AS
SELECT i.id
FROM identities i
JOIN pools p ON p.id = i.pool_id
JOIN tenants t ON t.id = p.tenant_id
WHERE t.slug = 'knox-root' AND p.slug = 'staff' AND i.username = 'mfa.e2e@knox.test';

DELETE FROM mfa_methods WHERE identity_id IN (SELECT id FROM seeded_identity);
DELETE FROM mfa_backup_codes WHERE identity_id IN (SELECT id FROM seeded_identity);

DROP VIEW seeded_identity;
