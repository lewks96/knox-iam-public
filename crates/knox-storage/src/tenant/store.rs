use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::Status;
use knox_common::tenant::{Tenant, TenantConfiguration, TenantUpdates};
use serde_json::Value;
use sqlx::{PgPool, QueryBuilder};
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct DbTenant {
    id: Uuid,
    name: String,
    slug: String,
    issuer: String,
    description: Option<String>,
    is_platform: bool,
    status: Status,
    config: Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<DbTenant> for Tenant {
    fn from(db: DbTenant) -> Self {
        let config = serde_json::from_value(db.config).unwrap_or_default();
        Tenant {
            id: db.id,
            name: db.name,
            slug: db.slug,
            issuer: db.issuer,
            description: db.description,
            is_platform: db.is_platform,
            status: db.status,
            config,
            created_at: db.created_at,
            updated_at: db.updated_at,
        }
    }
}

#[async_trait]
pub trait TenantStore: Send + Sync {
    async fn create(
        &self,
        name: &str,
        slug: &str,
        issuer: &str,
        description: Option<String>,
        is_platform: bool,
        config: TenantConfiguration,
    ) -> Result<Tenant, RepositoryError>;
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError>;
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError>;
    async fn update(&self, id: Uuid, updates: &TenantUpdates) -> Result<Tenant, RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn list(&self, page: u32, page_size: u32) -> Result<(Vec<Tenant>, u64), RepositoryError>;
}

// Postgres Implementation
pub struct PgTenantStore {
    pool: PgPool,
}

impl PgTenantStore {
    #[instrument(skip(pool))]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantStore for PgTenantStore {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: &str,
        slug: &str,
        issuer: &str,
        description: Option<String>,
        is_platform: bool,
        config: TenantConfiguration,
    ) -> Result<Tenant, RepositoryError> {
        let config = serde_json::to_value(config)
            .map_err(|e| RepositoryError::Database(format!("Failed to serialize config: {}", e)))?;

        let rec = sqlx::query_as!(
            DbTenant,
            r#"
            INSERT INTO tenants (name, slug, issuer, description, is_platform, status, config)
            VALUES ($1, $2, $3, $4, $5, 'active', $6)
            RETURNING
                id, name, slug, issuer, description, is_platform,
                status as "status: Status",
                config,
                created_at, updated_at
            "#,
            name,
            slug,
            issuer,
            description,
            is_platform,
            config
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbTenant,
            r#"
            SELECT
                id, name, slug, issuer, description, is_platform, config,
                status as "status: Status",
                created_at, updated_at
            FROM tenants WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|t| t.into()))
    }

    #[instrument(skip(self))]
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbTenant,
            r#"
            SELECT
                id, name, slug, issuer, description, is_platform, config,
                status as "status: Status",
                created_at, updated_at
            FROM tenants WHERE slug = $1
            "#,
            slug
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|t| t.into()))
    }

    #[instrument(skip(self))]
    async fn update(&self, id: Uuid, updates: &TenantUpdates) -> Result<Tenant, RepositoryError> {
        let mut builder = QueryBuilder::new("UPDATE tenants SET ");
        let mut separated = builder.separated(", ");

        if let Some(name) = &updates.name {
            separated.push("name = ");
            separated.push_bind_unseparated(name);
        }
        if let Some(desc) = &updates.description {
            separated.push("description = ");
            separated.push_bind_unseparated(desc);
        }
        if let Some(status) = updates.status {
            separated.push("status = ");
            separated.push_bind_unseparated(status as Status);
        }
        if let Some(config) = &updates.config {
            let config_val = serde_json::to_value(config).map_err(|_| RepositoryError::NotFound)?;
            separated.push("config = ");
            separated.push_bind_unseparated(config_val);
        }

        separated.push("updated_at = now()");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(
            r#"
            RETURNING
                id, name, slug, issuer, description, is_platform,
                status,
                config,
                created_at, updated_at
        "#,
        );

        let rec = builder
            .build_query_as::<DbTenant>()
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        let res = sqlx::query!("DELETE FROM tenants WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list(&self, page: u32, page_size: u32) -> Result<(Vec<Tenant>, u64), RepositoryError> {
        let limit = page_size as i64;
        let offset = ((page - 1) * page_size) as i64;

        let tenants = sqlx::query_as!(
            DbTenant,
            r#"
            SELECT
                id, name, slug, issuer, description, is_platform,
                status as "status: Status",
                config,
                created_at, updated_at
            FROM tenants
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?
        .into_iter()
        .map(|t| t.into())
        .collect();

        let count = sqlx::query!("SELECT COUNT(*) as count FROM tenants")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?
            .count
            .unwrap_or(0);

        Ok((tenants, count as u64))
    }
}
