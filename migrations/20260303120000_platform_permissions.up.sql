-- Add platform-level permissions for global admin operations
-- These permissions allow the global admin tenant to manage resources across all tenants

INSERT INTO permissions (kind, key, description)
VALUES 
    -- Platform-wide tenant management
    ('system', 'PlatformTenantCreate', 'Can create tenants across the platform'),
    ('system', 'PlatformTenantRead', 'Can read any tenant information'),
    ('system', 'PlatformTenantUpdate', 'Can update any tenant'),
    ('system', 'PlatformTenantDelete', 'Can delete any tenant'),
    ('system', 'PlatformTenantList', 'Can list all tenants'),

    -- Platform-wide identity management
    ('system', 'PlatformIdentityCreate', 'Can create identities in any tenant'),
    ('system', 'PlatformIdentityRead', 'Can read any identity across tenants'),
    ('system', 'PlatformIdentityUpdate', 'Can update any identity across tenants'),
    ('system', 'PlatformIdentityDelete', 'Can delete any identity across tenants'),
    ('system', 'PlatformIdentityList', 'Can list identities across tenants'),

    -- Platform-wide client management
    ('system', 'PlatformClientCreate', 'Can create clients in any tenant'),
    ('system', 'PlatformClientRead', 'Can read any client across tenants'),
    ('system', 'PlatformClientUpdate', 'Can update any client across tenants'),
    ('system', 'PlatformClientDelete', 'Can delete any client across tenants'),
    ('system', 'PlatformClientList', 'Can list clients across tenants'),

    -- Platform-wide role management
    ('system', 'PlatformRoleCreate', 'Can create roles in any tenant'),
    ('system', 'PlatformRoleRead', 'Can read any role across tenants'),
    ('system', 'PlatformRoleUpdate', 'Can update any role across tenants'),
    ('system', 'PlatformRoleDelete', 'Can delete any role across tenants'),
    ('system', 'PlatformRoleList', 'Can list roles across tenants'),

    -- Platform configuration and monitoring
    ('system', 'PlatformConfigRead', 'Can read platform configuration'),
    ('system', 'PlatformConfigWrite', 'Can modify platform configuration'),
    ('system', 'PlatformMetricsRead', 'Can read platform metrics'),
    ('system', 'PlatformAuditRead', 'Can read platform audit logs'),

    -- Within-tenant client management (missing from original rbac migration)
    ('system', 'ClientCreate', 'Can create OAuth clients in own tenant'),
    ('system', 'ClientRead', 'Can read OAuth clients in own tenant'),
    ('system', 'ClientUpdate', 'Can update OAuth clients in own tenant'),
    ('system', 'ClientDelete', 'Can delete OAuth clients in own tenant')
ON CONFLICT (key) DO NOTHING;
