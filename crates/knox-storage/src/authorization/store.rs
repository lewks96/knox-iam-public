use async_trait::async_trait;
use knox_common::authorization::{Permission, Role, RoleKind};
use knox_common::error::RepositoryError;
use sqlx::{PgPool, QueryBuilder};
use time::OffsetDateTime;
use uuid::Uuid;

// Internal DB struct for Role (flat)
#[derive(sqlx::FromRow)]
struct DbRole {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    kind: RoleKind,
    description: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[async_trait]
pub trait AuthorizationStore: Send + Sync {
    // Role Management
    async fn create_role(
        &self,
        tenant_id: Uuid,
        name: &str,
        permissions: &[Uuid],
        kind: RoleKind,
    ) -> Result<Role, RepositoryError>;

    async fn get_permission_id(&self, permission_key: &str) -> Result<Uuid, RepositoryError>;

    async fn get_role_with_permissions(
        &self,
        role_id: Uuid,
    ) -> Result<Option<Role>, RepositoryError>;

    async fn get_role_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Role>, RepositoryError>;
    async fn delete_role(&self, role_id: Uuid) -> Result<(), RepositoryError>;
    // ------------------------------------

    async fn get_permissions_for_identity(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError>;
    /// Every role defined in a tenant, with its permissions — the set an admin
    /// may choose from when granting.
    async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError>;
    /// Role names held by an identity, scoped to a tenant so a stray identity id
    /// cannot read assignments from elsewhere.
    async fn roles_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError>;
    async fn assign_role(&self, identity_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;

    async fn remove_role(&self, identity_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;
}

#[derive(Clone)]
pub struct PgAuthorizationStore {
    pool: PgPool,
}

impl PgAuthorizationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthorizationStore for PgAuthorizationStore {
    async fn create_role(
        &self,
        tenant_id: Uuid,
        name: &str,
        permissions: &[Uuid],
        kind: RoleKind,
    ) -> Result<Role, RepositoryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        // 1. Create Role
        let role_id = Uuid::new_v4();
        let role = sqlx::query_as!(
            DbRole,
            r#"
            INSERT INTO roles (id, tenant_id, name, kind)
            VALUES ($1, $2, $3, $4)
            RETURNING id, tenant_id, kind as "kind: RoleKind" , name, description, created_at, updated_at
            "#,
            role_id,
            tenant_id,
            name,
            kind as RoleKind
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        // 2. Assign Permissions
        if !permissions.is_empty() {
            let mut query =
                QueryBuilder::new("INSERT INTO role_permissions (role_id, permission_id) ");
            query.push_values(permissions, |mut b, perm_id| {
                b.push_bind(role_id);
                b.push_bind(perm_id);
            });
            query
                .build()
                .execute(&mut *tx)
                .await
                .map_err(|e| RepositoryError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(Role {
            id: role.id,
            tenant_id: role.tenant_id,
            name: role.name,
            description: role.description,
            kind: role.kind,
            permissions: vec![], // Optimization: Skip returning perms on create
            created_at: role.created_at,
            updated_at: role.updated_at,
        })
    }

    async fn get_permission_id(&self, permission_key: &str) -> Result<Uuid, RepositoryError> {
        let rec = sqlx::query!("SELECT id FROM permissions WHERE key = $1", permission_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        rec.map(|r| r.id).ok_or_else(|| RepositoryError::NotFound)
    }
    async fn assign_role(&self, identity_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError> {
        // Derive tenant_id from the two parent rows and insert only when they
        // agree. The composite foreign keys added by the migration make the
        // invariant impossible to bypass from any other writer as well.
        let tenant_matches = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM identities i
                JOIN roles r ON r.id = $2
                WHERE i.id = $1 AND i.tenant_id = r.tenant_id
            )
            "#,
        )
        .bind(identity_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        if !tenant_matches {
            return Err(RepositoryError::NotFound);
        }

        sqlx::query(
            r#"
            INSERT INTO identity_roles (identity_id, role_id, tenant_id)
            SELECT i.id, r.id, i.tenant_id
            FROM identities i
            JOIN roles r ON r.id = $2 AND r.tenant_id = i.tenant_id
            WHERE i.id = $1
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(identity_id)
        .bind(role_id)
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    async fn get_permissions_for_identity(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError> {
        let perms = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT p.key
            FROM identity_roles ir
            JOIN identities i
              ON i.id = ir.identity_id
             AND i.tenant_id = ir.tenant_id
            JOIN roles r
              ON r.id = ir.role_id
             AND r.tenant_id = ir.tenant_id
            JOIN role_permissions rp ON ir.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ir.identity_id = $1
            "#,
        )
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(perms)
    }

    async fn get_role_with_permissions(
        &self,
        role_id: Uuid,
    ) -> Result<Option<Role>, RepositoryError> {
        // Fetch the role itself first
        let role = sqlx::query_as!(
            DbRole,
            r#"
        SELECT id, tenant_id, kind as "kind: RoleKind", name, description, created_at, updated_at
        FROM roles
        WHERE id = $1
        "#,
            role_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        let role = match role {
            Some(r) => r,
            None => return Ok(None),
        };

        let permissions = sqlx::query!(
            r#"
                SELECT p.id, p.key, p.description
                FROM role_permissions rp
                JOIN permissions p ON rp.permission_id = p.id
                WHERE rp.role_id = $1
                "#,
            role_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?
        .into_iter()
        .map(|r| Permission {
            id: r.id,
            key: r.key,
            description: r.description,
        })
        .collect();

        Ok(Some(Role {
            id: role.id,
            tenant_id: role.tenant_id,
            name: role.name,
            description: role.description,
            kind: role.kind,
            permissions,
            created_at: role.created_at,
            updated_at: role.updated_at,
        }))
    }

    async fn get_role_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Role>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbRole,
            r#"SELECT id, tenant_id, name, kind as "kind: RoleKind", description, created_at, updated_at FROM roles WHERE tenant_id = $1 AND name = $2"#,
            tenant_id, name
        )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|r| Role {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            kind: r.kind,
            description: r.description,
            permissions: vec![],
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn delete_role(&self, role_id: Uuid) -> Result<(), RepositoryError> {
        let res = sqlx::query!("DELETE FROM roles WHERE id = $1", role_id)
            .execute(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn remove_role(&self, identity_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError> {
        sqlx::query(
            r#"
            DELETE FROM identity_roles ir
            USING identities i, roles r
            WHERE ir.identity_id = $1
              AND ir.role_id = $2
              AND i.id = ir.identity_id
              AND r.id = ir.role_id
              AND i.tenant_id = r.tenant_id
              AND ir.tenant_id = i.tenant_id
            "#,
        )
        .bind(identity_id)
        .bind(role_id)
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError> {
        // One row per (role, permission) collapsed in Rust — cheaper than N+1
        // and the per-tenant role count is small and bounded in practice.
        let rows = sqlx::query!(
            r#"
            SELECT r.id, r.tenant_id, r.name, r.description,
                   r.kind as "kind: RoleKind",
                   r.created_at, r.updated_at,
                   p.id as "perm_id?", p.key as "perm_key?", p.description as "perm_desc?"
            FROM roles r
            LEFT JOIN role_permissions rp ON rp.role_id = r.id
            LEFT JOIN permissions p ON p.id = rp.permission_id
            WHERE r.tenant_id = $1
            ORDER BY r.name, p.key
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        let mut roles: Vec<Role> = Vec::new();
        for row in rows {
            let role = match roles.last_mut() {
                Some(r) if r.id == row.id => r,
                _ => {
                    roles.push(Role {
                        id: row.id,
                        tenant_id: row.tenant_id,
                        name: row.name,
                        kind: row.kind,
                        description: row.description,
                        permissions: Vec::new(),
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    });
                    roles.last_mut().expect("just pushed")
                }
            };
            if let (Some(id), Some(key)) = (row.perm_id, row.perm_key) {
                role.permissions.push(Permission {
                    id,
                    key,
                    description: row.perm_desc,
                });
            }
        }
        Ok(roles)
    }

    async fn roles_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT r.name
            FROM identity_roles ir
            JOIN identities i
              ON i.id = ir.identity_id
             AND i.tenant_id = ir.tenant_id
            JOIN roles r
              ON r.id = ir.role_id
             AND r.tenant_id = ir.tenant_id
            WHERE ir.identity_id = $1 AND ir.tenant_id = $2
            ORDER BY r.name
            "#,
        )
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rows)
    }
}
