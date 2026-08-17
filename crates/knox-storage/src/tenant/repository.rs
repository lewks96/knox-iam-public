use crate::tenant::cache::TenantCache;
use crate::tenant::store::TenantStore;
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::tenant::{Tenant, TenantConfiguration, TenantRepository, TenantUpdates};
use tracing::{debug, error, instrument};
use uuid::Uuid;

pub struct KnoxTenantRepository<S, C> {
    store: S,
    cache: C,
}

impl<S, C> KnoxTenantRepository<S, C>
where
    S: TenantStore + Send + Sync,
    C: TenantCache + Send + Sync,
{
    pub fn new(store: S, cache: C) -> Self {
        Self { store, cache }
    }
}

#[async_trait]
impl<S, C> TenantRepository for KnoxTenantRepository<S, C>
where
    S: TenantStore + Send + Sync,
    C: TenantCache + Send + Sync,
{
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: &str,
        slug: &str,
        issuer: &str,
        description: Option<String>,
        is_platform: bool,
    ) -> Result<Tenant, RepositoryError> {
        let tenant = self
            .store
            .create(
                name,
                slug,
                issuer,
                description,
                is_platform,
                TenantConfiguration::default(),
            )
            .await?;
        debug!("New tenant created: {}", tenant.id);
        if let Err(e) = self.cache.set(&tenant).await {
            error!("Tenant cache set failed after creation: {}", e);
        }
        debug!("Tenant cached after creation: {}", tenant.id);
        Ok(tenant)
    }

    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError> {
        if let Some(cached) = self.cache.get(id).await? {
            debug!("Get tenant cache hit: {}", id);
            return Ok(Some(cached));
        }

        debug!("Get tenant cache miss, checking store: {}", id);
        let tenant = self.store.get(id).await?;
        if let Some(t) = &tenant
            && let Err(e) = self.cache.set(t).await
        {
            error!("Tenant cache set failed after get: {}", e);
        }

        Ok(tenant)
    }

    #[instrument(skip(self))]
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError> {
        if let Some(cached) = self.cache.get_by_slug(slug).await? {
            debug!("Get tenant by slug cache hit: {}", slug);
            return Ok(Some(cached));
        }

        debug!("Get tenant by slug cache miss, checking store: {}", slug);
        let tenant = self.store.get_by_slug(slug).await?;
        if let Some(t) = &tenant
            && let Err(e) = self.cache.set(t).await
        {
            error!("Tenant cache set failed after get_by_slug: {}", e);
        }

        Ok(tenant)
    }

    #[instrument(skip(self))]
    async fn update(&self, id: Uuid, updates: &TenantUpdates) -> Result<Tenant, RepositoryError> {
        debug!("Updating tenant: {}", id);
        let updated = self.store.update(id, updates).await?;

        if let Err(e) = self.cache.set(&updated).await {
            eprintln!("Tenant cache update failed: {}", e);
            let _ = self.cache.delete(id).await;
        }

        Ok(updated)
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        debug!("Deleting tenant: {}", id);
        self.store.delete(id).await?;
        let _ = self.cache.delete(id).await;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list(&self, page: u32, page_size: u32) -> Result<(Vec<Tenant>, u64), RepositoryError> {
        debug!("Listing tenants: page {}, page_size {}", page, page_size);
        self.store.list(page, page_size).await
    }
}
