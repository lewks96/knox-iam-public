use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::{
    Identity, IdentityFilter, IdentityHandle, IdentityKind, IdentityRepository, IdentityUpdates,
    Status,
};
use knox_storage::identity::repository::KnoxIdentityRepository;
use knox_storage::identity::{IdentityCache, IdentityStore};
use mockall::{mock, predicate::*};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub IdentityStore {}
    #[async_trait]
    impl IdentityStore for IdentityStore {
        async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError>;
        async fn get_by_id(&self, pool_id: Uuid, id: Uuid) -> Result<Option<Identity>, RepositoryError>;
        async fn get_by_email(&self, pool_id: Uuid, email: &str) -> Result<Option<Identity>, RepositoryError>;
        async fn get_by_username(&self, pool_id: Uuid, username: &str) -> Result<Option<Identity>, RepositoryError>;
        async fn update(&self, pool_id: Uuid, id: Uuid, updates: &IdentityUpdates) -> Result<Identity, RepositoryError>;
        async fn delete(&self, pool_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
        async fn list(&self, filter: &IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError>;
    }
}

mock! {
    pub IdentityCache {}
    #[async_trait]
    impl IdentityCache for IdentityCache {
        async fn set(&self, identity: &Identity) -> Result<(), RepositoryError>;
        async fn get_by_id(&self, pool_id: Uuid, id: Uuid) -> Result<Option<Identity>, RepositoryError>;
        async fn delete(&self, pool_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
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

fn make_identity(tenant_id: Uuid, pool_id: Uuid) -> Identity {
    Identity {
        id: Uuid::new_v4(),
        tenant_id,
        pool_id,
        kind: IdentityKind::Human,
        username: format!("user_{}", Uuid::new_v4()),
        email: Some(format!("{}@knox.com", Uuid::new_v4())),
        password_hash: Some("$argon2id$v=19$...".into()),
        email_verified: true,
        status: Status::Active,
        first_name: Some("Jane".into()),
        last_name: Some("Doe".into()),
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

fn make_repo(
    store: MockIdentityStore,
    cache: MockIdentityCache,
) -> KnoxIdentityRepository<MockIdentityStore, MockIdentityCache> {
    KnoxIdentityRepository::new(store, cache)
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_persists_to_store_and_warms_cache() {
    init_tracing();
    let identity = make_identity(Uuid::new_v4(), Uuid::new_v4());
    let cloned = identity.clone();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));
    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.create(&identity).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, identity.id);
}

#[tokio::test]
async fn test_create_store_error_propagates_and_cache_not_called() {
    init_tracing();
    let identity = make_identity(Uuid::new_v4(), Uuid::new_v4());

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("DB write failed".into())));
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.create(&identity).await,
        Err(RepositoryError::Database(_))
    ));
}

#[tokio::test]
async fn test_create_cache_failure_does_not_fail_the_operation() {
    init_tracing();
    let identity = make_identity(Uuid::new_v4(), Uuid::new_v4());
    let cloned = identity.clone();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));
    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    assert!(
        repo.create(&identity).await.is_ok(),
        "Cache write failure should not fail create"
    );
}

// ---------------------------------------------------------------------------
// get — IdentityHandle::Id (the only cached path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_by_id_cache_hit_does_not_call_store() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let id = identity.id;

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .with(eq(pool_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    store.expect_get_by_id().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(pool_id, IdentityHandle::Id(id)).await;

    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_by_id_cache_miss_falls_back_to_store_and_backfills_cache() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let id = identity.id;

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .with(eq(pool_id), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .with(eq(pool_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    assert_eq!(
        repo.get(pool_id, IdentityHandle::Id(id))
            .await
            .unwrap()
            .unwrap()
            .id,
        id
    );
}

#[tokio::test]
async fn test_get_by_id_cache_miss_store_returns_none() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    assert!(
        repo.get(pool_id, IdentityHandle::Id(id))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_get_by_id_cache_error_propagates() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Redis timeout".into())));
    store.expect_get_by_id().times(0);

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.get(pool_id, IdentityHandle::Id(id)).await,
        Err(RepositoryError::Database(_))
    ));
}

#[tokio::test]
async fn test_get_by_id_store_error_propagates() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.get(pool_id, IdentityHandle::Id(id)).await,
        Err(RepositoryError::Database(_))
    ));
}

#[tokio::test]
async fn test_get_by_id_store_fallback_cache_backfill_failure_is_non_fatal() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let id = identity.id;

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.get(pool_id, IdentityHandle::Id(id)).await;

    assert_eq!(
        result.unwrap().unwrap().id,
        id,
        "Backfill failure should not fail the get"
    );
}

// ---------------------------------------------------------------------------
// get — handle lookups always go to the store
//
// The cache holds no username/email pointers: an un-invalidated pointer would
// resolve a renamed identity from its old name, which is not acceptable for the
// thing that decides who you are.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_by_email_never_consults_cache_and_backfills_from_store() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let email = identity.email.clone().unwrap();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache.expect_get_by_id().times(0);
    store
        .expect_get_by_email()
        .with(eq(pool_id), eq(email.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    assert!(
        repo.get(pool_id, IdentityHandle::Email(email))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_get_by_username_never_consults_cache_and_backfills_from_store() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let username = identity.username.clone();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache.expect_get_by_id().times(0);
    store
        .expect_get_by_username()
        .with(eq(pool_id), eq(username.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    assert!(
        repo.get(pool_id, IdentityHandle::Username(username))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_get_by_username_not_found() {
    init_tracing();
    let pool_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_get_by_username()
        .times(1)
        .return_once(|_, _| Ok(None));
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    assert!(
        repo.get(pool_id, IdentityHandle::Username("nobody".into()))
            .await
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Pool isolation — the property this whole change exists for
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_same_username_in_two_pools_resolves_to_different_identities() {
    // The console's `management` client is bound to the staff pool. If a lookup
    // for a shared username could return the end user, an end user could log
    // into the console; if it could return the staff member, an end user could
    // log in *as* an admin. Neither is reachable: the pool is part of the query.
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let staff_pool = Uuid::new_v4();
    let customer_pool = Uuid::new_v4();

    let shared_username = "alice@acme.com".to_string();

    let mut staff = make_identity(tenant_id, staff_pool);
    staff.username = shared_username.clone();
    let staff_id = staff.id;

    let mut customer = make_identity(tenant_id, customer_pool);
    customer.username = shared_username.clone();
    let customer_id = customer.id;

    assert_ne!(staff_id, customer_id);

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    let staff_clone = staff.clone();
    store
        .expect_get_by_username()
        .with(eq(staff_pool), eq(shared_username.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(staff_clone)));

    let customer_clone = customer.clone();
    store
        .expect_get_by_username()
        .with(eq(customer_pool), eq(shared_username.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(customer_clone)));

    cache.expect_set().times(2).returning(|_| Ok(()));

    let repo = make_repo(store, cache);

    let from_staff = repo
        .get(
            staff_pool,
            IdentityHandle::Username(shared_username.clone()),
        )
        .await
        .unwrap()
        .unwrap();
    let from_customer = repo
        .get(customer_pool, IdentityHandle::Username(shared_username))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(from_staff.id, staff_id);
    assert_eq!(from_customer.id, customer_id);
}

#[tokio::test]
async fn test_cache_lookup_is_keyed_by_pool_not_tenant() {
    // Two identities in one tenant can now share a username, so a tenant-keyed
    // cache entry would be ambiguous — a cross-pool bypass that never touches
    // the SQL predicates. The pool must reach the cache verbatim.
    init_tracing();
    let staff_pool = Uuid::new_v4();
    let customer_pool = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .with(eq(customer_pool), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .with(eq(customer_pool), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));

    let repo = make_repo(store, cache);
    let result = repo.get(customer_pool, IdentityHandle::Id(id)).await;

    assert!(result.unwrap().is_none());
    // The staff pool was never consulted; mockall's `with` would have failed
    // the expectation had the wrong scope been forwarded.
    let _ = staff_pool;
}

#[tokio::test]
async fn test_id_lookup_in_wrong_pool_returns_none() {
    // `get_by_id` used to be `WHERE id = $1` with no scope at all, so any admin
    // could read any identity on the deployment by UUID.
    init_tracing();
    let wrong_pool = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .with(eq(wrong_pool), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));

    let repo = make_repo(store, cache);
    assert!(
        repo.get(wrong_pool, IdentityHandle::Id(id))
            .await
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_by_id_calls_store_and_invalidates_cache() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_delete()
        .with(eq(pool_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));
    cache
        .expect_delete()
        .with(eq(pool_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    assert!(repo.delete(pool_id, IdentityHandle::Id(id)).await.is_ok());
}

#[tokio::test]
async fn test_delete_by_email_resolves_id_first_then_deletes() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let id = identity.id;
    let email = identity.email.clone().unwrap();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_get_by_email()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    cache.expect_set().times(1).returning(|_| Ok(()));
    store
        .expect_delete()
        .with(eq(pool_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));
    cache
        .expect_delete()
        .with(eq(pool_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    assert!(
        repo.delete(pool_id, IdentityHandle::Email(email))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_delete_by_email_not_found_is_noop() {
    init_tracing();
    let pool_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_get_by_email()
        .times(1)
        .return_once(|_, _| Ok(None));
    store.expect_delete().times(0);
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    assert!(
        repo.delete(pool_id, IdentityHandle::Email("ghost@knox.com".into()))
            .await
            .is_ok(),
        "Delete of non-existent identity should be a no-op"
    );
}

#[tokio::test]
async fn test_delete_store_error_propagates() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_delete()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Cannot delete".into())));
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.delete(pool_id, IdentityHandle::Id(id)).await,
        Err(RepositoryError::Database(_))
    ));
}

#[tokio::test]
async fn test_delete_cache_invalidation_failure_is_non_fatal() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store.expect_delete().times(1).returning(|_, _| Ok(()));
    cache
        .expect_delete()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Redis gone".into())));

    let repo = make_repo(store, cache);
    assert!(
        repo.delete(pool_id, IdentityHandle::Id(id)).await.is_ok(),
        "Cache invalidation failure should not fail delete"
    );
}

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_by_id_calls_store_and_updates_cache() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let mut updated = identity.clone();
    updated.first_name = Some("Updated".into());
    let id = identity.id;

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_update()
        .with(eq(pool_id), eq(id), always())
        .times(1)
        .return_once(move |_, _, _| Ok(updated));
    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = IdentityUpdates {
        first_name: Some("Updated".into()),
        ..Default::default()
    };

    assert_eq!(
        repo.update(pool_id, IdentityHandle::Id(id), &updates)
            .await
            .unwrap()
            .first_name,
        Some("Updated".into())
    );
}

#[tokio::test]
async fn test_update_by_email_resolves_id_first() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let id = identity.id;
    let cloned_for_get = identity.clone();
    let mut updated = identity.clone();
    updated.last_name = Some("Smith".into());
    let email = identity.email.clone().unwrap();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_get_by_email()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned_for_get)));
    store
        .expect_update()
        .with(eq(pool_id), eq(id), always())
        .times(1)
        .return_once(move |_, _, _| Ok(updated));
    cache.expect_set().times(2).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = IdentityUpdates {
        last_name: Some("Smith".into()),
        ..Default::default()
    };

    assert_eq!(
        repo.update(pool_id, IdentityHandle::Email(email), &updates)
            .await
            .unwrap()
            .last_name,
        Some("Smith".into())
    );
}

#[tokio::test]
async fn test_update_by_non_id_handle_not_found_returns_not_found_error() {
    init_tracing();
    let pool_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_get_by_email()
        .times(1)
        .return_once(|_, _| Ok(None));
    store.expect_update().times(0);
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let updates = IdentityUpdates::default();

    assert!(matches!(
        repo.update(
            pool_id,
            IdentityHandle::Email("nobody@knox.com".into()),
            &updates
        )
        .await,
        Err(RepositoryError::NotFound)
    ));
}

#[tokio::test]
async fn test_update_store_error_propagates() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(|_, _, _| Err(RepositoryError::Database("Store error".into())));
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let updates = IdentityUpdates {
        first_name: Some("Jane".into()),
        ..Default::default()
    };

    assert!(matches!(
        repo.update(pool_id, IdentityHandle::Id(id), &updates).await,
        Err(RepositoryError::Database(_))
    ));
}

#[tokio::test]
async fn test_update_cache_set_failure_falls_back_to_cache_delete() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let updated = identity.clone();
    let id = identity.id;

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(updated));
    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis write failed".into())));
    cache
        .expect_delete()
        .with(eq(pool_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let updates = IdentityUpdates {
        first_name: Some("Jane".into()),
        ..Default::default()
    };

    assert!(
        repo.update(pool_id, IdentityHandle::Id(id), &updates)
            .await
            .is_ok(),
        "Update should succeed even if cache set fails"
    );
}

#[tokio::test]
async fn test_update_password_hash_is_persisted() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let id = identity.id;
    let mut updated = identity.clone();
    updated.password_hash = Some("$argon2id$v=19$new_hash".into());

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    store
        .expect_update()
        .withf(|_, _, upd: &IdentityUpdates| upd.password_hash.is_some())
        .times(1)
        .return_once(move |_, _, _| Ok(updated));
    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = IdentityUpdates {
        password_hash: Some("$argon2id$v=19$new_hash".into()),
        ..Default::default()
    };

    assert!(
        repo.update(pool_id, IdentityHandle::Id(id), &updates)
            .await
            .unwrap()
            .password_hash
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// exists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exists_returns_true_when_identity_found() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let identity = make_identity(Uuid::new_v4(), pool_id);
    let cloned = identity.clone();
    let id = identity.id;

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));
    store.expect_get_by_id().times(0);

    let repo = make_repo(store, cache);
    assert!(repo.exists(pool_id, IdentityHandle::Id(id)).await.unwrap());
}

#[tokio::test]
async fn test_exists_returns_false_when_identity_not_found() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));
    store
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Ok(None));

    let repo = make_repo(store, cache);
    assert!(!repo.exists(pool_id, IdentityHandle::Id(id)).await.unwrap());
}

#[tokio::test]
async fn test_exists_error_propagates() {
    init_tracing();
    let pool_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let mut cache = MockIdentityCache::new();

    cache
        .expect_get_by_id()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Cache error".into())));
    store.expect_get_by_id().times(0);

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.exists(pool_id, IdentityHandle::Id(id)).await,
        Err(RepositoryError::Database(_))
    ));
}

// ---------------------------------------------------------------------------
// list / count
// ---------------------------------------------------------------------------

fn filter(tenant_id: Uuid) -> IdentityFilter {
    IdentityFilter {
        tenant_id,
        pool_id: None,
        page: 1,
        page_size: 10,
        status: None,
        query: None,
    }
}

#[tokio::test]
async fn test_list_delegates_to_store_and_returns_results() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let pool_id = Uuid::new_v4();
    let identities = vec![
        make_identity(tenant_id, pool_id),
        make_identity(tenant_id, pool_id),
    ];

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(move |_| Ok((identities, 2)));

    let repo = make_repo(store, cache);
    let (list, count) = repo.list(filter(tenant_id)).await.unwrap();

    assert_eq!(list.len(), 2);
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_list_forwards_pool_filter() {
    // The console is a staff surface; a listing that silently included a
    // tenant's end users would be both a leak and unusable at CIAM scale.
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let pool_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .withf(move |f: &IdentityFilter| f.pool_id == Some(pool_id))
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let mut f = filter(tenant_id);
    f.pool_id = Some(pool_id);

    assert!(repo.list(f).await.is_ok());
}

#[tokio::test]
async fn test_list_with_status_filter_delegates_correctly() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .withf(|f: &IdentityFilter| f.status == Some(Status::Active))
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let mut f = filter(tenant_id);
    f.status = Some(Status::Active);

    assert!(repo.list(f).await.is_ok());
}

#[tokio::test]
async fn test_list_with_query_filter_delegates_correctly() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .withf(|f: &IdentityFilter| f.query.as_deref() == Some("john"))
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let mut f = filter(tenant_id);
    f.query = Some("john".into());

    assert!(repo.list(f).await.is_ok());
}

#[tokio::test]
async fn test_list_store_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.list(filter(tenant_id)).await,
        Err(RepositoryError::Database(_))
    ));
}

#[tokio::test]
async fn test_count_delegates_to_store_list_and_extracts_total() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .withf(|f: &IdentityFilter| f.page_size == 1 && f.page == 1)
        .times(1)
        .return_once(|_| Ok((vec![], 42)));

    let repo = make_repo(store, cache);
    assert_eq!(repo.count(tenant_id, None).await.unwrap(), 42);
}

#[tokio::test]
async fn test_count_with_query_filter() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .withf(|f: &IdentityFilter| f.query.as_deref() == Some("jane"))
        .times(1)
        .return_once(|_| Ok((vec![], 7)));

    let repo = make_repo(store, cache);
    assert_eq!(repo.count(tenant_id, Some("jane".into())).await.unwrap(), 7);
}

#[tokio::test]
async fn test_count_store_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockIdentityStore::new();
    let cache = MockIdentityCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    assert!(matches!(
        repo.count(tenant_id, None).await,
        Err(RepositoryError::Database(_))
    ));
}
