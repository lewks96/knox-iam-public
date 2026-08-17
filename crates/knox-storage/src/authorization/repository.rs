use crate::authorization::cache::AuthorizationCache;
use crate::authorization::store::AuthorizationStore;
use async_trait::async_trait;
use knox_common::authorization::{AuthorizationRepository, Role, RoleKind};
use knox_common::error::RepositoryError;
use tracing::{debug, error, instrument};
use uuid::Uuid;

#[derive(Clone)]
pub struct KnoxAuthorizationRepository<S, C> {
    store: S,
    cache: C,
}

impl<S, C> KnoxAuthorizationRepository<S, C>
where
    S: AuthorizationStore + Send + Sync,
    C: AuthorizationCache + Send + Sync,
{
    pub fn new(store: S, cache: C) -> Self {
        Self { store, cache }
    }

    pub async fn get_permission_id(&self, permission_key: &str) -> Result<Uuid, RepositoryError> {
        self.store
            .get_permission_id(permission_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))
    }
}

#[async_trait]
impl<S, C> AuthorizationRepository for KnoxAuthorizationRepository<S, C>
where
    S: AuthorizationStore + Send + Sync,
    C: AuthorizationCache + Send + Sync,
{
    #[instrument(skip(self))]
    async fn create_role(
        &self,
        tenant_id: Uuid,
        name: &str,
        permissions: &Vec<String>,
        kind: RoleKind,
    ) -> Result<Role, RepositoryError> {
        debug!("Creating role '{}' for tenant {}", name, tenant_id);
        let mut perm_ids = Vec::with_capacity(permissions.len());
        for perm in permissions {
            let id = self.get_permission_id(perm.as_str()).await?;
            perm_ids.push(id);
        }
        self.store
            .create_role(tenant_id, name, perm_ids.as_slice(), kind)
            .await
    }

    #[instrument(skip(self))]
    async fn get_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Option<Role>, RepositoryError> {
        debug!("Fetching role {} for tenant {}", role_id, tenant_id);
        let role = self.store.get_role_with_permissions(role_id).await?;
        if let Some(r) = &role
            && r.tenant_id != tenant_id
        {
            return Ok(None);
        }
        Ok(role)
    }

    #[instrument(skip(self))]
    async fn delete_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError> {
        debug!("Deleting role {} for tenant {}", role_id, tenant_id);
        let role = self.store.get_role_with_permissions(role_id).await?;
        if !matches!(role, Some(ref role) if role.tenant_id == tenant_id) {
            return Err(RepositoryError::NotFound);
        }
        self.store.delete_role(role_id).await
    }

    #[instrument(skip(self))]
    async fn assign_role(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        role_name: &str,
    ) -> Result<(), RepositoryError> {
        let role = self
            .store
            .get_role_by_name(tenant_id, role_name)
            .await?
            .ok_or(RepositoryError::NotFound)?;

        debug!(
            "Assigning role '{}' to user {} in tenant {}",
            role_name, identity_id, tenant_id
        );
        self.store.assign_role(identity_id, role.id).await?;

        if let Err(e) = self.cache.invalidate(identity_id).await {
            error!(
                "Auth cache invalidation failed for user {}: {}",
                identity_id, e
            );
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_role(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        role_name: &str,
    ) -> Result<(), RepositoryError> {
        let role = self
            .store
            .get_role_by_name(tenant_id, role_name)
            .await?
            .ok_or(RepositoryError::NotFound)?;
        debug!(
            "Removing role '{}' from user {} in tenant {}",
            role_name, identity_id, tenant_id
        );

        self.store.remove_role(identity_id, role.id).await?;

        if let Err(e) = self.cache.invalidate(identity_id).await {
            error!(
                "Auth cache invalidation failed for user {}: {}",
                identity_id, e
            );
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError> {
        self.store.list_roles(tenant_id).await
    }

    async fn get_identity_roles(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError> {
        self.store.roles_for_identity(tenant_id, identity_id).await
    }

    async fn get_permissions(&self, identity_id: Uuid) -> Result<Vec<String>, RepositoryError> {
        debug!("Fetching permissions for user {}", identity_id);
        if let Some(cached_perms) = self.cache.get_permissions(identity_id).await? {
            return Ok(cached_perms);
        }

        let perms = self.store.get_permissions_for_identity(identity_id).await?;
        debug!("Permissions for user {}: {:?}", identity_id, perms);

        if let Err(e) = self.cache.set_permissions(identity_id, &perms).await {
            error!("Auth cache set failed for user {}: {}", identity_id, e);
        }

        Ok(perms)
    }
}
