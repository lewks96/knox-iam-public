SELECT cron.unschedule('prune-audit-events');
DROP TABLE IF EXISTS audit_events;

DELETE
FROM role_permissions rp USING permissions p
WHERE rp.permission_id = p.id
  AND p.key = 'AuditRead';
DELETE
FROM roles
WHERE name = 'AuditViewer'
  AND kind = 'system';
DELETE
FROM permissions
WHERE key = 'AuditRead';

UPDATE clients
SET allowed_scopes = array_remove(allowed_scopes, 'AuditRead')
WHERE 'AuditRead' = ANY (allowed_scopes);
