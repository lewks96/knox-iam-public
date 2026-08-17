use crate::identity::{IdentityCache, IdentityStore};
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::{
    Identity, IdentityFilter, IdentityHandle, IdentityRepository, IdentityUpdates,
};
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

#[derive(Clone)]
pub struct KnoxIdentityRepository<S, C> {
    store: S,
    cache: C,
}

impl<S, C> KnoxIdentityRepository<S, C>
where
    S: IdentityStore + Send + Sync,
    C: IdentityCache + Send + Sync,
{
    pub fn new(store: S, cache: C) -> Self {
        Self { store, cache }
    }
}

#[async_trait]
impl<S, C> IdentityRepository for KnoxIdentityRepository<S, C>
where
    S: IdentityStore + Send + Sync,
    C: IdentityCache + Send + Sync,
{
    #[instrument(skip(self, identity))]
    async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError> {
        let created = self.store.create(identity).await?;
        if let Err(e) = self.cache.set(&created).await {
            error!("Cache set failed on create: {}", e);
        }
        Ok(created)
    }

    #[instrument(skip(self))]
    async fn get(
        &self,
        pool_id: Uuid,
        handle: IdentityHandle,
    ) -> Result<Option<Identity>, RepositoryError> {
        debug!(
            "Looking up identity. Pool: {}, Handle: {:?}",
            pool_id,
            debug(&handle)
        );

        // Only id lookups can be served from cache; handle lookups go to the
        // unique index in Postgres so a renamed identity can never resolve from
        // its old name.
        if let IdentityHandle::Id(id) = &handle
            && let Some(identity) = self.cache.get_by_id(pool_id, *id).await?
        {
            debug!("Cache hit for ID: {}", id);
            return Ok(Some(identity));
        }

        debug!("DB lookup for handle: {:?}", handle);
        let identity = match &handle {
            IdentityHandle::Id(id) => self.store.get_by_id(pool_id, *id).await?,
            IdentityHandle::Email(email) => self.store.get_by_email(pool_id, email).await?,
            IdentityHandle::Username(username) => {
                self.store.get_by_username(pool_id, username).await?
            }
        };

        if let Some(i) = &identity
            && let Err(e) = self.cache.set(i).await
        {
            error!("Cache set failed for user '{}' on DB fallback: {}", i.id, e);
        }

        Ok(identity)
    }

    #[instrument(skip(self))]
    async fn delete(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<(), RepositoryError> {
        let id = match handle {
            IdentityHandle::Id(id) => id,
            _ => match self.get(pool_id, handle).await? {
                Some(i) => i.id,
                None => return Ok(()),
            },
        };

        info!("Deleting identity. Pool: {}, ID: {}", pool_id, id);
        self.store.delete(pool_id, id).await?;

        if let Err(e) = self.cache.delete(pool_id, id).await {
            error!(
                "Cache delete failed for user '{}' after DB delete: {}",
                id, e
            );
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        pool_id: Uuid,
        handle: IdentityHandle,
        updates: &IdentityUpdates,
    ) -> Result<Identity, RepositoryError> {
        let id = match handle {
            IdentityHandle::Id(id) => id,
            _ => {
                let ident = self
                    .get(pool_id, handle)
                    .await?
                    .ok_or(RepositoryError::NotFound)?;
                ident.id
            }
        };

        debug!(
            "Updating identity. Pool: {}, ID: {}, Updates: {:?}",
            pool_id, id, updates
        );

        let updated = self.store.update(pool_id, id, updates).await?;
        if let Err(e) = self.cache.set(&updated).await {
            error!("Cache set failed for user '{}' after update: {}", id, e);
            let _ = self.cache.delete(pool_id, id).await;
        }

        Ok(updated)
    }

    #[instrument(skip(self))]
    async fn exists(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<bool, RepositoryError> {
        let result = self.get(pool_id, handle).await?;
        Ok(result.is_some())
    }

    #[instrument(skip(self))]
    async fn list(&self, filter: IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError> {
        self.store.list(&filter).await
    }

    #[instrument(skip(self))]
    async fn count(&self, tenant_id: Uuid, filter: Option<String>) -> Result<u64, RepositoryError> {
        let list_filter = IdentityFilter {
            tenant_id,
            pool_id: None,
            page: 1,
            page_size: 1,
            status: None,
            query: filter,
        };

        let (_, total) = self.store.list(&list_filter).await?;
        Ok(total)
    }
}
