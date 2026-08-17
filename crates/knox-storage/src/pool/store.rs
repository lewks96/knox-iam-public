use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::Status;
use knox_common::pool::{CreatePool, IdentityPool, PoolKind, PoolRepository};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Postgres-backed pool directory.
///
/// Deliberately uncached: pools are read at tenant creation and by admin
/// surfaces, never on the request hot path. The per-request pool identity that
/// `RequireAuth` checks travels in the token instead — see `JwtClaims::pool_id`.
#[derive(Clone)]
pub struct PgPoolStore {
    pool: PgPool,
}

impl PgPoolStore {
    #[instrument(skip(pool))]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PoolRepository for PgPoolStore {
    #[instrument(skip(self))]
    async fn create(&self, req: &CreatePool) -> Result<IdentityPool, RepositoryError> {
        sqlx::query_as!(
            IdentityPool,
            r#"
            INSERT INTO pools (tenant_id, slug, name, kind, description)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id, tenant_id, slug, name,
                kind as "kind: PoolKind",
                description, config,
                status as "status: Status",
                created_at, updated_at
            "#,
            req.tenant_id,
            req.slug,
            req.name,
            req.kind as PoolKind,
            req.description
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sql_error)
    }

    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<IdentityPool>, RepositoryError> {
        sqlx::query_as!(
            IdentityPool,
            r#"
            SELECT
                id, tenant_id, slug, name,
                kind as "kind: PoolKind",
                description, config,
                status as "status: Status",
                created_at, updated_at
            FROM pools WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)
    }

    #[instrument(skip(self))]
    async fn get_in_tenant(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<IdentityPool>, RepositoryError> {
        sqlx::query_as!(
            IdentityPool,
            r#"
            SELECT
                id, tenant_id, slug, name,
                kind as "kind: PoolKind",
                description, config,
                status as "status: Status",
                created_at, updated_at
            FROM pools WHERE id = $1 AND tenant_id = $2
            "#,
            id,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)
    }

    #[instrument(skip(self))]
    async fn get_by_slug(
        &self,
        tenant_id: Uuid,
        slug: &str,
    ) -> Result<Option<IdentityPool>, RepositoryError> {
        sqlx::query_as!(
            IdentityPool,
            r#"
            SELECT
                id, tenant_id, slug, name,
                kind as "kind: PoolKind",
                description, config,
                status as "status: Status",
                created_at, updated_at
            FROM pools WHERE tenant_id = $1 AND slug = $2
            "#,
            tenant_id,
            slug
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)
    }

    #[instrument(skip(self))]
    async fn get_staff_pool(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<IdentityPool>, RepositoryError> {
        // A partial unique index caps this at one row per tenant.
        sqlx::query_as!(
            IdentityPool,
            r#"
            SELECT
                id, tenant_id, slug, name,
                kind as "kind: PoolKind",
                description, config,
                status as "status: Status",
                created_at, updated_at
            FROM pools WHERE tenant_id = $1 AND kind = 'staff'
            "#,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)
    }

    #[instrument(skip(self))]
    async fn list(&self, tenant_id: Uuid) -> Result<Vec<IdentityPool>, RepositoryError> {
        sqlx::query_as!(
            IdentityPool,
            r#"
            SELECT
                id, tenant_id, slug, name,
                kind as "kind: PoolKind",
                description, config,
                status as "status: Status",
                created_at, updated_at
            FROM pools WHERE tenant_id = $1 ORDER BY created_at ASC
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sql_error)
    }

    #[instrument(skip(self))]
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError> {
        let result = sqlx::query!(
            "DELETE FROM pools WHERE id = $1 AND tenant_id = $2",
            id,
            tenant_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }
}

#[instrument]
fn map_sql_error(e: sqlx::Error) -> RepositoryError {
    match e {
        sqlx::Error::RowNotFound => RepositoryError::NotFound,
        sqlx::Error::Database(db_err) => {
            if db_err.constraint().is_some() {
                RepositoryError::Duplicate(db_err.message().to_string())
            } else {
                RepositoryError::Database(db_err.message().to_string())
            }
        }
        _ => RepositoryError::Database(e.to_string()),
    }
}
