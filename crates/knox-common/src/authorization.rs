use crate::error::RepositoryError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "role_kind", rename_all = "snake_case")
)]
pub enum RoleKind {
    System,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Permission {
    pub id: Uuid,
    pub key: String, // e.g. "users:read"
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub kind: RoleKind,
    pub description: Option<String>,
    pub permissions: Vec<Permission>, // Eager load permissions often makes sense
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleUpdates {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<Uuid>>, // Update list of permission IDs
}

#[async_trait]
pub trait AuthorizationRepository: Send + Sync {
    // Role Management
    async fn create_role(
        &self,
        tenant_id: Uuid,
        name: &str,
        permissions: &Vec<String>,
        kind: RoleKind,
    ) -> Result<Role, RepositoryError>;
    async fn get_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Option<Role>, RepositoryError>;
    async fn delete_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;

    // Assignment
    async fn assign_role(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        role_name: &str,
    ) -> Result<(), RepositoryError>;
    async fn remove_role(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        role_name: &str,
    ) -> Result<(), RepositoryError>;

    /// Every role defined in this tenant, with its permissions.
    async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError>;
    /// Role names currently held by an identity within this tenant.
    async fn get_identity_roles(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError>;

    // The "Golden Query" - Used on every API call
    async fn get_permissions(&self, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
}
