use async_trait::async_trait;
use knox_common::authorization::{AuthorizationRepository, Role, RoleKind};
use knox_common::error::RepositoryError;
use knox_storage::authorization::cache::AuthorizationCache;
use knox_storage::authorization::repository::KnoxAuthorizationRepository;
use knox_storage::authorization::store::AuthorizationStore;
use mockall::{mock, predicate::*};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub AuthorizationStore {}
    #[async_trait]
    impl AuthorizationStore for AuthorizationStore {
        async fn create_role(&self, tenant_id: Uuid, name: &str, permissions: &[Uuid], kind: RoleKind) -> Result<Role, RepositoryError>;
        async fn get_permission_id(&self, key: &str) -> Result<Uuid, RepositoryError>;
        async fn get_role_with_permissions(&self, role_id: Uuid) -> Result<Option<Role>, RepositoryError>;
        async fn get_role_by_name(&self, tenant_id: Uuid, name: &str) -> Result<Option<Role>, RepositoryError>;
        async fn delete_role(&self, role_id: Uuid) -> Result<(), RepositoryError>;
        async fn assign_role(&self, identity_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;
        async fn remove_role(&self, identity_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;
        async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError>;
        async fn roles_for_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
        async fn get_permissions_for_identity(&self, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
    }
}

mock! {
    pub AuthorizationCache {}
    #[async_trait]
    impl AuthorizationCache for AuthorizationCache {
        async fn get_permissions(&self, identity_id: Uuid) -> Result<Option<Vec<String>>, RepositoryError>;
        async fn set_permissions(&self, identity_id: Uuid, permissions: &[String]) -> Result<(), RepositoryError>;
        async fn invalidate(&self, identity_id: Uuid) -> Result<(), RepositoryError>;
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

fn make_role(tenant_id: Uuid) -> Role {
    Role {
        id: Uuid::new_v4(),
        tenant_id,
        name: format!("Role_{}", Uuid::new_v4()),
        description: None,
        permissions: vec![],
        kind: RoleKind::Custom,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    }
}

fn make_repo(
    store: MockAuthorizationStore,
    cache: MockAuthorizationCache,
) -> KnoxAuthorizationRepository<MockAuthorizationStore, MockAuthorizationCache> {
    KnoxAuthorizationRepository::new(store, cache)
}

// ---------------------------------------------------------------------------
// create_role tests
//
// The repository's create_role takes &Vec<String> permission keys, resolves
// each to a Uuid via store.get_permission_id(), then passes &[Uuid] to
// store.create_role(). Tests must mock get_permission_id for any non-empty
// permissions vec.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_role_no_permissions_delegates_to_store() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let role_id = role.id;
    let cloned = role.clone();
    let tenant_id_cmp = tenant_id;
    let role_name_cmp = role.name.clone();

    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    // No permissions — get_permission_id must never be called
    store.expect_get_permission_id().times(0);

    store
        .expect_create_role()
        .withf(move |tid, n, ids: &[Uuid], _: &RoleKind| {
            *tid == tenant_id_cmp && *n == role_name_cmp && ids.is_empty()
        })
        .times(1)
        .return_once(move |_, _, _, _| Ok(cloned));

    let repo = make_repo(store, cache);
    let result = repo
        .create_role(tenant_id, &role.name, &vec![], RoleKind::Custom)
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, role_id);
}

#[tokio::test]
async fn test_create_role_resolves_permission_keys_to_uuids() {
    // Repository must call get_permission_id once per permission key and pass
    // the resolved UUIDs to the store — not the raw strings.
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let perm_id_a = Uuid::new_v4();
    let perm_id_b = Uuid::new_v4();
    let role = make_role(tenant_id);
    let cloned = role.clone();
    let expected_ids = vec![perm_id_a, perm_id_b];
    let expected_ids_clone = expected_ids.clone();

    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_permission_id()
        .with(eq("users:read"))
        .times(1)
        .return_once(move |_| Ok(perm_id_a));

    store
        .expect_get_permission_id()
        .with(eq("users:write"))
        .times(1)
        .return_once(move |_| Ok(perm_id_b));

    store
        .expect_create_role()
        .withf(move |_, _, ids: &[Uuid], _: &RoleKind| ids == expected_ids_clone.as_slice())
        .times(1)
        .return_once(move |_, _, _, _| Ok(cloned));

    let repo = make_repo(store, cache);
    let perm_strs = vec!["users:read".to_string(), "users:write".to_string()];
    let result = repo
        .create_role(tenant_id, &role.name, &perm_strs, RoleKind::Custom)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_role_get_permission_id_error_propagates() {
    // If any permission key cannot be resolved, create_role must abort and propagate the error.
    // Note: the repository wraps store errors via map_err(|e| RepositoryError::Database(e.to_string())),
    // so any error from get_permission_id surfaces as Database at the repository boundary.
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_permission_id()
        .times(1)
        .return_once(|_| Err(RepositoryError::NotFound));

    // store.create_role must NOT be called if resolution fails
    store.expect_create_role().times(0);

    let repo = make_repo(store, cache);
    let result = repo
        .create_role(
            Uuid::new_v4(),
            "Admin",
            &vec!["unknown:perm".to_string()],
            RoleKind::Custom,
        )
        .await;

    assert!(
        matches!(result, Err(RepositoryError::Database(_))),
        "Expected Database error wrapping the store's NotFound, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_create_role_store_error_propagates() {
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    // No permissions — skips get_permission_id entirely
    store.expect_get_permission_id().times(0);

    store
        .expect_create_role()
        .times(1)
        .return_once(|_, _, _, _| Err(RepositoryError::Database("DB error".into())));

    let repo = make_repo(store, cache);
    let result = repo
        .create_role(Uuid::new_v4(), "Admin", &vec![], RoleKind::Custom)
        .await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

// ---------------------------------------------------------------------------
// get_role tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_role_returns_role_for_correct_tenant() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let role_id = role.id;
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_with_permissions()
        .with(eq(role_id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    let repo = make_repo(store, cache);
    let result = repo.get_role(tenant_id, role_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, role_id);
}

#[tokio::test]
async fn test_get_role_returns_none_for_wrong_tenant() {
    // The repository enforces tenant isolation: if the role's tenant_id doesn't
    // match the requested tenant_id, it returns None instead of the role
    init_tracing();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let role = make_role(tenant_a); // role belongs to tenant_a
    let role_id = role.id;
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_with_permissions()
        .with(eq(role_id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    let repo = make_repo(store, cache);
    // Requesting with tenant_b — should be rejected
    let result = repo.get_role(tenant_b, role_id).await;

    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "Should not return a role belonging to a different tenant"
    );
}

#[tokio::test]
async fn test_get_role_store_returns_none() {
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_with_permissions()
        .times(1)
        .return_once(|_| Ok(None));

    let repo = make_repo(store, cache);
    let result = repo.get_role(Uuid::new_v4(), Uuid::new_v4()).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_role_store_error_propagates() {
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_with_permissions()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let result = repo.get_role(Uuid::new_v4(), Uuid::new_v4()).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

// ---------------------------------------------------------------------------
// delete_role tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_role_delegates_to_store() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    let role = make_role(tenant_id);
    let role_id = role.id;
    store
        .expect_get_role_with_permissions()
        .with(eq(role_id))
        .times(1)
        .return_once(move |_| Ok(Some(role)));

    store
        .expect_delete_role()
        .with(eq(role_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.delete_role(tenant_id, role_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_role_store_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let role_id = role.id;
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_with_permissions()
        .with(eq(role_id))
        .times(1)
        .return_once(move |_| Ok(Some(role)));

    store
        .expect_delete_role()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let result = repo.delete_role(tenant_id, role_id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

// ---------------------------------------------------------------------------
// assign_role tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_assign_role_resolves_role_by_name_then_assigns_and_invalidates_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let role_id = role.id;
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .with(eq(tenant_id), eq(role.name.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store
        .expect_assign_role()
        .with(eq(identity_id), eq(role_id))
        .times(1)
        .returning(|_, _| Ok(()));

    cache
        .expect_invalidate()
        .with(eq(identity_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.assign_role(tenant_id, identity_id, &role.name).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_assign_role_role_not_found_returns_not_found_error() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(|_, _| Ok(None));

    // assign_role and cache invalidation must NOT be called
    store.expect_assign_role().times(0);
    cache.expect_invalidate().times(0);

    let repo = make_repo(store, cache);
    let result = repo
        .assign_role(tenant_id, identity_id, "NonExistentRole")
        .await;

    assert!(
        matches!(result, Err(RepositoryError::NotFound)),
        "Expected NotFound when role name doesn't exist, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_assign_role_get_role_by_name_error_propagates() {
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    store.expect_assign_role().times(0);

    let repo = make_repo(store, cache);
    let result = repo
        .assign_role(Uuid::new_v4(), Uuid::new_v4(), "Admin")
        .await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_assign_role_store_assign_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store
        .expect_assign_role()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Assign failed".into())));

    // Cache must NOT be invalidated if the store assign fails
    cache.expect_invalidate().times(0);

    let repo = make_repo(store, cache);
    let result = repo.assign_role(tenant_id, identity_id, &role.name).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_assign_role_cache_invalidation_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store.expect_assign_role().times(1).returning(|_, _| Ok(()));

    cache
        .expect_invalidate()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.assign_role(tenant_id, identity_id, &role.name).await;

    assert!(
        result.is_ok(),
        "Cache invalidation failure should not fail assign_role"
    );
}

// ---------------------------------------------------------------------------
// remove_role tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_remove_role_resolves_role_by_name_then_removes_and_invalidates_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let role_id = role.id;
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .with(eq(tenant_id), eq(role.name.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store
        .expect_remove_role()
        .with(eq(identity_id), eq(role_id))
        .times(1)
        .returning(|_, _| Ok(()));

    cache
        .expect_invalidate()
        .with(eq(identity_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.remove_role(tenant_id, identity_id, &role.name).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_remove_role_role_not_found_returns_not_found_error() {
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(|_, _| Ok(None));

    store.expect_remove_role().times(0);
    cache.expect_invalidate().times(0);

    let repo = make_repo(store, cache);
    let result = repo
        .remove_role(Uuid::new_v4(), Uuid::new_v4(), "Ghost")
        .await;

    assert!(matches!(result, Err(RepositoryError::NotFound)));
}

#[tokio::test]
async fn test_remove_role_get_role_by_name_error_propagates() {
    init_tracing();
    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    store.expect_remove_role().times(0);

    let repo = make_repo(store, cache);
    let result = repo
        .remove_role(Uuid::new_v4(), Uuid::new_v4(), "Admin")
        .await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_remove_role_store_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store
        .expect_remove_role()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Remove failed".into())));

    // Cache must NOT be invalidated if the store remove fails
    cache.expect_invalidate().times(0);

    let repo = make_repo(store, cache);
    let result = repo.remove_role(tenant_id, identity_id, &role.name).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_remove_role_cache_invalidation_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let role = make_role(tenant_id);
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    store
        .expect_get_role_by_name()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store.expect_remove_role().times(1).returning(|_, _| Ok(()));

    cache
        .expect_invalidate()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.remove_role(tenant_id, identity_id, &role.name).await;

    assert!(
        result.is_ok(),
        "Cache invalidation failure should not fail remove_role"
    );
}

// ---------------------------------------------------------------------------
// get_permissions tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_permissions_cache_hit_does_not_call_store() {
    init_tracing();
    let identity_id = Uuid::new_v4();
    let perms = vec!["users:read".to_string(), "users:write".to_string()];
    let cloned = perms.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .with(eq(identity_id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store.expect_get_permissions_for_identity().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), perms);
}

#[tokio::test]
async fn test_get_permissions_cache_miss_calls_store_and_backfills() {
    init_tracing();
    let identity_id = Uuid::new_v4();
    let perms = vec!["users:read".to_string()];
    let cloned = perms.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get_permissions_for_identity()
        .with(eq(identity_id))
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache
        .expect_set_permissions()
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), perms);
}

#[tokio::test]
async fn test_get_permissions_cache_miss_empty_permissions_still_backfills() {
    // A user with no permissions is valid — the empty vec should still be cached
    init_tracing();
    let identity_id = Uuid::new_v4();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get_permissions_for_identity()
        .times(1)
        .return_once(|_| Ok(vec![]));

    cache
        .expect_set_permissions()
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_get_permissions_cache_error_propagates() {
    init_tracing();
    let identity_id = Uuid::new_v4();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Cache error".into())));

    store.expect_get_permissions_for_identity().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_get_permissions_store_error_propagates() {
    init_tracing();
    let identity_id = Uuid::new_v4();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get_permissions_for_identity()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_get_permissions_cache_backfill_failure_is_non_fatal() {
    init_tracing();
    let identity_id = Uuid::new_v4();
    let perms = vec!["users:read".to_string()];
    let cloned = perms.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get_permissions_for_identity()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache
        .expect_set_permissions()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(
        result.is_ok(),
        "Cache backfill failure should not fail get_permissions"
    );
    assert_eq!(result.unwrap(), perms);
}

#[tokio::test]
async fn test_get_permissions_returns_multiple_permissions() {
    init_tracing();
    let identity_id = Uuid::new_v4();
    let perms = vec![
        "users:read".to_string(),
        "users:write".to_string(),
        "users:delete".to_string(),
        "tenants:read".to_string(),
    ];
    let cloned = perms.clone();

    let mut store = MockAuthorizationStore::new();
    let mut cache = MockAuthorizationCache::new();

    cache
        .expect_get_permissions()
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store.expect_get_permissions_for_identity().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get_permissions(identity_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 4);
}

// ---------------------------------------------------------------------------
// Cross-cutting: tenant isolation in get_role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_role_same_id_different_tenant_is_rejected() {
    // Even if someone guesses a role_id from another tenant, they get None
    init_tracing();
    let owner_tenant = Uuid::new_v4();
    let attacker_tenant = Uuid::new_v4();

    let role = make_role(owner_tenant);
    let role_id = role.id;
    let cloned = role.clone();

    let mut store = MockAuthorizationStore::new();
    let cache = MockAuthorizationCache::new();

    store
        .expect_get_role_with_permissions()
        .with(eq(role_id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    let repo = make_repo(store, cache);
    let result = repo.get_role(attacker_tenant, role_id).await;

    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "Cross-tenant role access should be denied"
    );
}
