use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::token::{RefreshToken, RefreshTokenStore};
use sqlx::PgPool;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

// Internal DB Struct matching Postgres rows
#[derive(sqlx::FromRow)]
struct DbRefreshToken {
    id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    identity_id: Uuid,
    token_hash: String,
    scopes: Vec<String>,
    amr: Vec<String>,
    auth_time: Option<OffsetDateTime>,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    family_id: Uuid,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<DbRefreshToken> for RefreshToken {
    fn from(db: DbRefreshToken) -> Self {
        RefreshToken {
            id: db.id,
            tenant_id: db.tenant_id,
            client_id: db.client_id,
            identity_id: db.identity_id,
            token_hash: db.token_hash,
            scopes: db.scopes,
            amr: db.amr,
            auth_time: db.auth_time,
            expires_at: db.expires_at,
            revoked_at: db.revoked_at,
            family_id: db.family_id,
            created_at: db.created_at,
            updated_at: db.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct PgRefreshTokenStore {
    pool: PgPool,
}

impl PgRefreshTokenStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RefreshTokenStore for PgRefreshTokenStore {
    #[instrument(skip(self))]
    async fn create(&self, token: &RefreshToken) -> Result<RefreshToken, RepositoryError> {
        let rec = sqlx::query_as!(
            DbRefreshToken,
            r#"
            INSERT INTO refresh_tokens (
                id, tenant_id, client_id, identity_id, token_hash, 
                scopes, amr, auth_time, expires_at, revoked_at, family_id, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
            token.id,
            token.tenant_id,
            token.client_id,
            token.identity_id,
            token.token_hash,
            &token.scopes,
            &token.amr,
            token.auth_time,
            token.expires_at,
            token.revoked_at,
            token.family_id,
            token.created_at,
            token.updated_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn get_by_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        // Notice we do NOT filter by `revoked_at IS NULL`.
        // The Service layer needs to know if a revoked token was used so it can
        // trigger a `revoke_family` (Theft Detection).
        let rec = sqlx::query_as!(
            DbRefreshToken,
            "SELECT * FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2",
            tenant_id,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn revoke(&self, id: Uuid) -> Result<(), RepositoryError> {
        // Soft delete: We mark it as revoked instead of deleting the row.
        // This gives us an audit trail of token usage.
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = now(), updated_at = now() WHERE id = $1 AND revoked_at IS NULL",
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), RepositoryError> {
        // CRITICAL SECURITY FEATURE: Token Theft Detection.
        // If a stolen, already-revoked refresh token is used, we immediately
        // nuke every token sharing its family_id.
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = now(), updated_at = now() WHERE family_id = $1 AND revoked_at IS NULL",
            family_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_all_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError> {
        // Used for "Sign out of all devices" or when a user's password is changed/reset.
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = now(), updated_at = now() WHERE tenant_id = $1 AND identity_id = $2 AND revoked_at IS NULL",
            tenant_id,
            identity_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }
}
