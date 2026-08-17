use crate::client::cache::ClientCache;
use crate::client::store::ClientStore;
use async_trait::async_trait;
use knox_common::client::{Client, ClientFilter, ClientRepository, ClientUpdates};
use knox_common::error::RepositoryError;
use tracing::{debug, error, instrument, trace};
use uuid::Uuid;

pub struct KnoxClientRepository<S, C> {
    store: S,
    cache: C,
}

impl<S, C> Clone for KnoxClientRepository<S, C>
where
    S: Clone,
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl<S, C> KnoxClientRepository<S, C>
where
    S: ClientStore + Send + Sync,
    C: ClientCache + Send + Sync,
{
    #[instrument(skip(store, cache))]
    pub fn new(store: S, cache: C) -> Self {
        Self { store, cache }
    }
}

#[async_trait]
impl<S, C> ClientRepository for KnoxClientRepository<S, C>
where
    S: ClientStore + Send + Sync,
    C: ClientCache + Send + Sync,
{
    #[instrument(skip(self))]
    async fn create(&self, client: &Client) -> Result<Client, RepositoryError> {
        let created = self.store.create(client).await?;

        if let Err(e) = self.cache.set(&created).await {
            error!("Failed to cache newly created client {}: {}", created.id, e);
        }
        debug!(
            "Client created with ID {} and cached successfully",
            created.id
        );
        Ok(created)
    }

    #[instrument(skip(self))]
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError> {
        if let Some(cached_client) = self.cache.get(tenant_id, id).await? {
            trace!("Cache hit for client {} in tenant {}", id, tenant_id);
            return Ok(Some(cached_client));
        }

        trace!("Cache miss for client {} in tenant {}", id, tenant_id);
        let db_client = self.store.get(tenant_id, id).await?;

        if let Some(client) = &db_client
            && let Err(e) = self.cache.set(client).await
        {
            error!("Failed to cache client {} after DB fetch: {}", id, e);
        }
        Ok(db_client)
    }

    #[instrument(skip(self))]
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Client>, RepositoryError> {
        if let Some(cached) = self.cache.get_by_name(tenant_id, name).await? {
            trace!(
                "Cache hit for client name '{}' in tenant {}",
                name, tenant_id
            );
            return Ok(Some(cached));
        }

        trace!(
            "Cache miss for client name '{}' in tenant {}",
            name, tenant_id
        );
        let db_client = self.store.get_by_name(tenant_id, name).await?;

        if let Some(client) = &db_client
            && let Err(e) = self.cache.set(client).await
        {
            error!("Failed to cache client '{}' after DB fetch: {}", name, e);
        }
        Ok(db_client)
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        updates: &ClientUpdates,
    ) -> Result<Client, RepositoryError> {
        trace!("Updating client {} in tenant {}", id, tenant_id);
        let updated = self.store.update(tenant_id, id, updates).await?;

        if let Err(e) = self.cache.set(&updated).await {
            error!("Failed to update cache for client {}: {}", id, e);
        }
        Ok(updated)
    }

    #[instrument(skip(self))]
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError> {
        debug!("Deleting client {} in tenant {}", id, tenant_id);
        self.store.delete(tenant_id, id).await?;
        if let Err(e) = self.cache.delete(tenant_id, id).await {
            error!("Failed to delete cache for client {}: {}", id, e);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list(&self, filter: &ClientFilter) -> Result<(Vec<Client>, u64), RepositoryError> {
        self.store.list(filter).await
    }
}
