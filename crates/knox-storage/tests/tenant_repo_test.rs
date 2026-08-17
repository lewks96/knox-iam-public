use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::Status;
use knox_common::tenant::{Tenant, TenantConfiguration, TenantRepository, TenantUpdates};
use knox_storage::tenant::cache::TenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::TenantStore;
use mockall::{mock, predicate::*};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub TenantStore {}
    #[async_trait]
    impl TenantStore for TenantStore {
        async fn create(&self, name: &str, slug: &str, issuer: &str, description: Option<String>, is_platform: bool, config: TenantConfiguration) -> Result<Tenant, RepositoryError>;
        async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError>;
        async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError>;
        async fn update(&self, id: Uuid, updates: &TenantUpdates) -> Result<Tenant, RepositoryError>;
        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn list(&self, page: u32, page_size: u32) -> Result<(Vec<Tenant>, u64), RepositoryError>;
    }
}

mock! {
    pub TenantCache {}
    #[async_trait]
    impl TenantCache for TenantCache {
        async fn set(&self, tenant: &Tenant) -> Result<(), RepositoryError>;
        async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError>;
        async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError>;
        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

fn make_tenant() -> Tenant {
    Tenant {
        id: Uuid::new_v4(),
        name: format!("Corp {}", Uuid::new_v4()),
        slug: format!("corp-{}", Uuid::new_v4()),
        issuer: format!("https://corp-{}.example.test", Uuid::new_v4()),
        description: Some("A test tenant".into()),
        is_platform: false,
        status: Status::Active,
        config: TenantConfiguration::default(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

fn make_repo(
    store: MockTenantStore,
    cache: MockTenantCache,
) -> KnoxTenantRepository<MockTenantStore, MockTenantCache> {
    KnoxTenantRepository::new(store, cache)
}

// ---------------------------------------------------------------------------
// create tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_persists_to_store_and_warms_cache() {
    init_tracing();
    let tenant = make_tenant();
    let cloned = tenant.clone();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_, _, _, _, _, _| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo
        .create(
            &tenant.name,
            &tenant.slug,
            &tenant.issuer,
            tenant.description.clone(),
            tenant.is_platform,
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, tenant.id);
}

#[tokio::test]
async fn test_create_store_error_does_not_call_cache() {
    init_tracing();
    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(|_, _, _, _, _, _| Err(RepositoryError::Database("DB write failed".into())));

    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let result = repo
        .create(
            "New Corp",
            "new-corp",
            "https://new-corp.example.test",
            None,
            false,
        )
        .await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_create_cache_failure_is_non_fatal() {
    init_tracing();
    let tenant = make_tenant();
    let cloned = tenant.clone();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_, _, _, _, _, _| Ok(cloned));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo
        .create(&tenant.name, &tenant.slug, &tenant.issuer, None, false)
        .await;

    assert!(
        result.is_ok(),
        "Cache failure on create should not fail the operation"
    );
}

#[tokio::test]
async fn test_create_with_no_description() {
    init_tracing();
    let tenant = make_tenant();
    let cloned = tenant.clone();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_create()
        .withf(|_, _, _, desc: &Option<String>, _, _| desc.is_none())
        .times(1)
        .return_once(move |_, _, _, _, _, _| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo
        .create(&tenant.name, &tenant.slug, &tenant.issuer, None, false)
        .await;

    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// get tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_cache_hit_does_not_call_store() {
    init_tracing();
    let tenant = make_tenant();
    let cloned = tenant.clone();
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    cache
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store.expect_get().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_cache_miss_falls_back_to_store_and_backfills() {
    init_tracing();
    let tenant = make_tenant();
    let cloned = tenant.clone();
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    cache
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_cache_miss_store_returns_none() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    cache.expect_get().times(1).return_once(|_| Ok(None));

    store.expect_get().times(1).return_once(|_| Ok(None));

    // No backfill when store returns None
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_cache_error_propagates() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    cache
        .expect_get()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Cache error".into())));

    store.expect_get().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_get_store_error_propagates() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    cache.expect_get().times(1).return_once(|_| Ok(None));

    store
        .expect_get()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_get_store_fallback_backfill_failure_is_non_fatal() {
    init_tracing();
    let tenant = make_tenant();
    let cloned = tenant.clone();
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    cache.expect_get().times(1).return_once(|_| Ok(None));

    store
        .expect_get()
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok(), "Backfill failure should not fail the get");
    assert_eq!(result.unwrap().unwrap().id, id);
}

// ---------------------------------------------------------------------------
// update tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_calls_store_and_refreshes_cache() {
    init_tracing();
    let tenant = make_tenant();
    let mut updated = tenant.clone();
    updated.name = "Updated Corp".into();
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_update()
        .with(eq(id), always())
        .times(1)
        .return_once(move |_, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = TenantUpdates {
        name: Some("Updated Corp".into()),
        description: None,
        status: None,
        config: None,
    };
    let result = repo.update(id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().name, "Updated Corp");
}

#[tokio::test]
async fn test_update_store_error_does_not_touch_cache() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    cache.expect_set().times(0);
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    let result = repo.update(id, &TenantUpdates::default()).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_update_cache_set_failure_falls_back_to_cache_delete() {
    init_tracing();
    let tenant = make_tenant();
    let updated = tenant.clone();
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _| Ok(updated));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis write failed".into())));

    // Falls back to delete to keep cache consistent
    cache
        .expect_delete()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.update(id, &TenantUpdates::default()).await;

    assert!(
        result.is_ok(),
        "Update should succeed even if cache refresh fails"
    );
}

#[tokio::test]
async fn test_update_status_to_suspended() {
    init_tracing();
    let tenant = make_tenant();
    let mut updated = tenant.clone();
    updated.status = Status::Suspended;
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = TenantUpdates {
        name: None,
        description: None,
        status: Some(Status::Suspended),
        config: None,
    };
    let result = repo.update(id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, Status::Suspended);
}

#[tokio::test]
async fn test_update_description() {
    init_tracing();
    let tenant = make_tenant();
    let mut updated = tenant.clone();
    updated.description = Some("New description".into());
    let id = tenant.id;

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = TenantUpdates {
        name: None,
        description: Some("New description".into()),
        status: None,
        config: None,
    };
    let result = repo.update(id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().description, Some("New description".into()));
}

// ---------------------------------------------------------------------------
// delete tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_calls_store_then_invalidates_cache() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_delete()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));

    cache
        .expect_delete()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.delete(id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_store_error_propagates() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_delete()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Store error".into())));

    // Cache delete must NOT be called if store delete fails
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    let result = repo.delete(id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_delete_cache_invalidation_failure_is_non_fatal() {
    // The implementation uses `let _ = self.cache.delete(id).await` — errors are swallowed
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store.expect_delete().times(1).returning(|_| Ok(()));

    cache
        .expect_delete()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis gone".into())));

    let repo = make_repo(store, cache);
    let result = repo.delete(id).await;

    assert!(
        result.is_ok(),
        "Cache invalidation failure should not fail delete"
    );
}

// ---------------------------------------------------------------------------
// list tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_delegates_to_store() {
    init_tracing();
    let tenants = vec![make_tenant(), make_tenant()];
    let total = 2u64;

    let mut store = MockTenantStore::new();
    let cache = MockTenantCache::new();

    store
        .expect_list()
        .with(eq(1u32), eq(10u32))
        .times(1)
        .return_once(move |_, _| Ok((tenants, total)));

    let repo = make_repo(store, cache);
    let result = repo.list(1, 10).await;

    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_list_empty_returns_zero() {
    init_tracing();
    let mut store = MockTenantStore::new();
    let cache = MockTenantCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_, _| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let result = repo.list(1, 10).await;

    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert!(list.is_empty());
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_list_passes_correct_page_and_page_size() {
    init_tracing();
    let mut store = MockTenantStore::new();
    let cache = MockTenantCache::new();

    store
        .expect_list()
        .with(eq(3u32), eq(25u32))
        .times(1)
        .return_once(|_, _| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let _ = repo.list(3, 25).await;
}

#[tokio::test]
async fn test_list_store_error_propagates() {
    init_tracing();
    let mut store = MockTenantStore::new();
    let cache = MockTenantCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let result = repo.list(1, 10).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_list_does_not_interact_with_cache() {
    // list is store-only, cache is never touched
    init_tracing();
    let mut store = MockTenantStore::new();
    let mut cache = MockTenantCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_, _| Ok((vec![], 0)));

    cache.expect_get().times(0);
    cache.expect_set().times(0);
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    let _ = repo.list(1, 10).await;
}
