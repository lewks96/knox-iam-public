use knox_common::authorization::{AuthorizationRepository, RoleKind};
use knox_common::identity::{Identity, IdentityKind, IdentityRepository, Status};
use knox_common::tenant::TenantRepository;
use knox_storage::authorization::cache::RedisAuthorizationCache;
use knox_storage::authorization::repository::KnoxAuthorizationRepository;
use knox_storage::authorization::store::PgAuthorizationStore;
use knox_storage::identity::cache::RedisIdentityCache;
use knox_storage::identity::repository::KnoxIdentityRepository;
use knox_storage::identity::store::PgIdentityStore;
use knox_storage::tenant::cache::RedisTenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::PgTenantStore;
use redis::Client;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::env;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async fn setup() -> (
    impl AuthorizationRepository,
    impl IdentityRepository,
    impl TenantRepository,
    sqlx::PgPool,
) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:password@localhost:5432/knox".to_string());
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .unwrap();
    let client = Client::open(redis_url).unwrap();
    let manager = client.get_connection_manager().await.unwrap();

    let t_repo = KnoxTenantRepository::new(
        PgTenantStore::new(pool.clone()),
        RedisTenantCache::new(manager.clone()),
    );
    let i_repo = KnoxIdentityRepository::new(
        PgIdentityStore::new(pool.clone(), pool.clone()),
        RedisIdentityCache::new(manager.clone()),
    );
    let a_repo = KnoxAuthorizationRepository::new(
        PgAuthorizationStore::new(pool.clone()),
        RedisAuthorizationCache::new(manager),
    );

    (a_repo, i_repo, t_repo, pool)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct TestTenant {
    id: Uuid,
    pool_id: Uuid,
}

async fn create_tenant(tenant_repo: &impl TenantRepository, db: &sqlx::PgPool) -> TestTenant {
    let suffix = Uuid::new_v4();
    let tenant = tenant_repo
        .create(
            &format!("Corp {suffix}"),
            &format!("corp-{suffix}"),
            &format!("https://corp-{suffix}.example.test"),
            None,
            false,
        )
        .await
        .expect("Failed to create tenant");
    let pool_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO pools (tenant_id, slug, name, kind) VALUES ($1, 'staff', 'Staff', 'staff') RETURNING id",
    )
    .bind(tenant.id)
    .fetch_one(db)
    .await
    .expect("Failed to create staff pool");
    TestTenant {
        id: tenant.id,
        pool_id,
    }
}

async fn create_user(identity_repo: &impl IdentityRepository, tenant: &TestTenant) -> Identity {
    let user_id = Uuid::new_v4();
    let identity = Identity {
        id: user_id,
        tenant_id: tenant.id,
        pool_id: tenant.pool_id,
        kind: IdentityKind::Human,
        username: format!("user_{}", user_id),
        email: Some(format!("{}@knox.com", user_id)),
        password_hash: None,
        email_verified: true,
        first_name: None,
        last_name: None,
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        status: Status::Active,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    };
    identity_repo
        .create(&identity)
        .await
        .expect("Failed to create user");
    identity
}

async fn insert_permission(pool: &sqlx::PgPool, key: &str) -> String {
    let perm_id = Uuid::new_v4();
    sqlx::query("INSERT INTO permissions (id, key, description) VALUES ($1, $2, $3)")
        .bind(perm_id)
        .bind(key)
        .bind("Test permission")
        .execute(pool)
        .await
        .expect("Failed to insert permission");
    key.to_string()
}

// ---------------------------------------------------------------------------
// RBAC lifecycle (existing, retained)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_rbac_lifecycle() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;

    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_key = format!("users:delete:{}", Uuid::new_v4());
    let perm_id = insert_permission(&pool, &perm_key).await;

    let role_name = format!("SuperAdmin_{}", Uuid::new_v4());
    let role = auth_repo
        .create_role(tenant.id, &role_name, &vec![perm_id], RoleKind::Custom)
        .await
        .expect("Failed to create role");

    let perms_before = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        perms_before.is_empty(),
        "User should have no permissions yet"
    );

    auth_repo
        .assign_role(tenant.id, user.id, &role_name)
        .await
        .expect("Failed to assign role");

    let perms_after = auth_repo.get_permissions(user.id).await.unwrap();
    assert_eq!(perms_after.len(), 1);
    assert_eq!(perms_after[0], perm_key);

    let perms_cached = auth_repo.get_permissions(user.id).await.unwrap();
    assert_eq!(perms_cached[0], perm_key);

    auth_repo
        .remove_role(tenant.id, user.id, &role_name)
        .await
        .expect("Failed to remove role");

    let perms_gone = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        perms_gone.is_empty(),
        "Permissions should be gone after revoke"
    );

    let _ = role;
}

// ---------------------------------------------------------------------------
// create_role
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_create_role_with_no_permissions() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let role_name = format!("EmptyRole_{}", Uuid::new_v4());
    let role = auth_repo
        .create_role(tenant.id, &role_name, &vec![], RoleKind::Custom)
        .await
        .expect("Creating role with no permissions should succeed");

    assert_eq!(role.name, role_name);
    assert_eq!(role.tenant_id, tenant.id);
    assert!(role.permissions.is_empty());
}

#[tokio::test]
#[serial]
async fn test_create_role_with_multiple_permissions() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let perm_a = insert_permission(&pool, &format!("res:read:{}", Uuid::new_v4())).await;
    let perm_b = insert_permission(&pool, &format!("res:write:{}", Uuid::new_v4())).await;

    let role_name = format!("MultiPermRole_{}", Uuid::new_v4());
    let role = auth_repo
        .create_role(
            tenant.id,
            &role_name,
            &vec![perm_a.clone(), perm_b.clone()],
            RoleKind::Custom,
        )
        .await
        .expect("Creating role with multiple permissions should succeed");

    let fetched = auth_repo
        .get_role(tenant.id, role.id)
        .await
        .expect("get_role should not error")
        .expect("Role should be found");

    assert_eq!(fetched.permissions.len(), 2);
}

#[tokio::test]
#[serial]
async fn test_create_role_returns_unique_ids() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let role_a = auth_repo
        .create_role(
            tenant.id,
            &format!("RoleA_{}", Uuid::new_v4()),
            &vec![],
            RoleKind::Custom,
        )
        .await
        .unwrap();
    let role_b = auth_repo
        .create_role(
            tenant.id,
            &format!("RoleB_{}", Uuid::new_v4()),
            &vec![],
            RoleKind::Custom,
        )
        .await
        .unwrap();

    assert_ne!(role_a.id, role_b.id);
}

// ---------------------------------------------------------------------------
// get_role
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_role_returns_correct_role() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let role_name = format!("Fetchable_{}", Uuid::new_v4());
    let created = auth_repo
        .create_role(tenant.id, &role_name, &vec![], RoleKind::Custom)
        .await
        .unwrap();

    let fetched = auth_repo
        .get_role(tenant.id, created.id)
        .await
        .expect("get_role should not error")
        .expect("Role should be found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, role_name);
    assert_eq!(fetched.tenant_id, tenant.id);
}

#[tokio::test]
#[serial]
async fn test_get_role_nonexistent_returns_none() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let result = auth_repo
        .get_role(tenant.id, Uuid::new_v4())
        .await
        .expect("get_role should not error");

    assert!(result.is_none());
}

#[tokio::test]
#[serial]
async fn test_get_role_wrong_tenant_returns_none() {
    // Tenant isolation: fetching a role with the wrong tenant_id returns None
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant_a = create_tenant(&tenant_repo, &pool).await;
    let tenant_b = create_tenant(&tenant_repo, &pool).await;

    let role = auth_repo
        .create_role(
            tenant_a.id,
            &format!("IsolatedRole_{}", Uuid::new_v4()),
            &vec![],
            RoleKind::Custom,
        )
        .await
        .unwrap();

    let result = auth_repo
        .get_role(tenant_b.id, role.id)
        .await
        .expect("get_role should not error");

    assert!(
        result.is_none(),
        "Role belonging to tenant_a should not be visible to tenant_b"
    );
}

#[tokio::test]
#[serial]
async fn test_get_role_includes_permissions() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let perm_id = insert_permission(&pool, &format!("perm:view:{}", Uuid::new_v4())).await;

    let role_name = format!("RoleWithPerms_{}", Uuid::new_v4());
    let created = auth_repo
        .create_role(
            tenant.id,
            &role_name,
            &vec![perm_id.clone()],
            RoleKind::Custom,
        )
        .await
        .unwrap();

    let fetched = auth_repo
        .get_role(tenant.id, created.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(fetched.permissions.len(), 1);
}

// ---------------------------------------------------------------------------
// delete_role
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_delete_role_removes_it() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let role = auth_repo
        .create_role(
            tenant.id,
            &format!("DeleteMe_{}", Uuid::new_v4()),
            &vec![],
            RoleKind::Custom,
        )
        .await
        .unwrap();

    auth_repo
        .delete_role(tenant.id, role.id)
        .await
        .expect("delete_role should succeed");

    let gone = auth_repo.get_role(tenant.id, role.id).await.unwrap();
    assert!(gone.is_none(), "Role should not be findable after deletion");
}

#[tokio::test]
#[serial]
async fn test_delete_nonexistent_role_behaviour() {
    let (auth_repo, _, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;

    let result = auth_repo.delete_role(tenant.id, Uuid::new_v4()).await;

    match result {
        Ok(()) => {}
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("NotFound") || msg.contains("not found") || msg.contains("0 rows"),
                "Unexpected error deleting nonexistent role: {}",
                msg
            );
        }
    }
}

// ---------------------------------------------------------------------------
// assign_role
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_assign_role_grants_permissions() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_key = format!("resource:action:{}", Uuid::new_v4());
    let perm_id = insert_permission(&pool, &perm_key).await;

    let role_name = format!("GrantRole_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_name, &vec![perm_id], RoleKind::Custom)
        .await
        .unwrap();

    let before = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(before.is_empty());

    auth_repo
        .assign_role(tenant.id, user.id, &role_name)
        .await
        .expect("assign_role should succeed");

    let after = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        after.contains(&perm_key),
        "Permission should be granted after role assignment"
    );
}

#[tokio::test]
#[serial]
async fn test_assign_nonexistent_role_returns_not_found() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let result = auth_repo
        .assign_role(tenant.id, user.id, "RoleThatDoesNotExist")
        .await;

    assert!(
        matches!(result, Err(knox_common::error::RepositoryError::NotFound)),
        "Assigning a nonexistent role should return NotFound"
    );
}

#[tokio::test]
#[serial]
async fn test_assign_role_invalidates_permissions_cache() {
    // Verifies that assigning a role clears the stale cached permissions
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    // Warm the permissions cache with an empty result
    let _ = auth_repo.get_permissions(user.id).await.unwrap();

    let perm_key = format!("cache:invalidation:{}", Uuid::new_v4());
    let perm_id = insert_permission(&pool, &perm_key).await;
    let role_name = format!("InvalidationRole_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_name, &vec![perm_id], RoleKind::Custom)
        .await
        .unwrap();

    auth_repo
        .assign_role(tenant.id, user.id, &role_name)
        .await
        .unwrap();

    // If cache wasn't invalidated, this would return the old empty result
    let perms = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        perms.contains(&perm_key),
        "Cache should be invalidated after assign so fresh permissions are returned"
    );
}

#[tokio::test]
#[serial]
async fn test_assign_multiple_roles_accumulates_permissions() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_a_key = format!("perm:a:{}", Uuid::new_v4());
    let perm_b_key = format!("perm:b:{}", Uuid::new_v4());
    let perm_a = insert_permission(&pool, &perm_a_key).await;
    let perm_b = insert_permission(&pool, &perm_b_key).await;

    let role_a = format!("RoleA_{}", Uuid::new_v4());
    let role_b = format!("RoleB_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_a, &vec![perm_a], RoleKind::Custom)
        .await
        .unwrap();
    auth_repo
        .create_role(tenant.id, &role_b, &vec![perm_b], RoleKind::Custom)
        .await
        .unwrap();

    auth_repo
        .assign_role(tenant.id, user.id, &role_a)
        .await
        .unwrap();
    auth_repo
        .assign_role(tenant.id, user.id, &role_b)
        .await
        .unwrap();

    let perms = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        perms.contains(&perm_a_key),
        "Permission from role A should be present"
    );
    assert!(
        perms.contains(&perm_b_key),
        "Permission from role B should be present"
    );
}

// ---------------------------------------------------------------------------
// remove_role
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_remove_role_revokes_permissions() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_key = format!("revoke:me:{}", Uuid::new_v4());
    let perm_id = insert_permission(&pool, &perm_key).await;
    let role_name = format!("RevokeRole_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_name, &vec![perm_id], RoleKind::Custom)
        .await
        .unwrap();

    auth_repo
        .assign_role(tenant.id, user.id, &role_name)
        .await
        .unwrap();
    let before = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(before.contains(&perm_key));

    auth_repo
        .remove_role(tenant.id, user.id, &role_name)
        .await
        .expect("remove_role should succeed");

    let after = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        !after.contains(&perm_key),
        "Permission should be revoked after role removal"
    );
}

#[tokio::test]
#[serial]
async fn test_remove_nonexistent_role_returns_not_found() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let result = auth_repo
        .remove_role(tenant.id, user.id, "RoleThatDoesNotExist")
        .await;

    assert!(
        matches!(result, Err(knox_common::error::RepositoryError::NotFound)),
        "Removing a nonexistent role should return NotFound"
    );
}

#[tokio::test]
#[serial]
async fn test_remove_role_invalidates_permissions_cache() {
    // Warm the cache with permissions, then revoke, verify stale cache is cleared
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_key = format!("stale:cache:{}", Uuid::new_v4());
    let perm_id = insert_permission(&pool, &perm_key).await;
    let role_name = format!("StaleRole_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_name, &vec![perm_id], RoleKind::Custom)
        .await
        .unwrap();

    auth_repo
        .assign_role(tenant.id, user.id, &role_name)
        .await
        .unwrap();

    // Warm the cache
    let cached = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(cached.contains(&perm_key));

    auth_repo
        .remove_role(tenant.id, user.id, &role_name)
        .await
        .unwrap();

    // Cache should be invalidated — this should not return the stale cached permission
    let after = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        !after.contains(&perm_key),
        "Stale cached permissions should be cleared after remove_role"
    );
}

#[tokio::test]
#[serial]
async fn test_remove_one_role_preserves_other_role_permissions() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_a_key = format!("keep:a:{}", Uuid::new_v4());
    let perm_b_key = format!("remove:b:{}", Uuid::new_v4());
    let perm_a = insert_permission(&pool, &perm_a_key).await;
    let perm_b = insert_permission(&pool, &perm_b_key).await;

    let role_a = format!("KeepRole_{}", Uuid::new_v4());
    let role_b = format!("RemoveRole_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_a, &vec![perm_a], RoleKind::Custom)
        .await
        .unwrap();
    auth_repo
        .create_role(tenant.id, &role_b, &vec![perm_b], RoleKind::Custom)
        .await
        .unwrap();

    auth_repo
        .assign_role(tenant.id, user.id, &role_a)
        .await
        .unwrap();
    auth_repo
        .assign_role(tenant.id, user.id, &role_b)
        .await
        .unwrap();

    // Remove only role_b
    auth_repo
        .remove_role(tenant.id, user.id, &role_b)
        .await
        .unwrap();

    let perms = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(
        perms.contains(&perm_a_key),
        "Permission from role_a should still be present"
    );
    assert!(
        !perms.contains(&perm_b_key),
        "Permission from role_b should be removed"
    );
}

// ---------------------------------------------------------------------------
// get_permissions
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_permissions_empty_for_new_user() {
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perms = auth_repo.get_permissions(user.id).await.unwrap();
    assert!(perms.is_empty(), "New user should have no permissions");
}

#[tokio::test]
#[serial]
async fn test_get_permissions_consistent_across_repeated_calls() {
    // Verifies cache coherence across multiple reads
    let (auth_repo, identity_repo, tenant_repo, pool) = setup().await;
    let tenant = create_tenant(&tenant_repo, &pool).await;
    let user = create_user(&identity_repo, &tenant).await;

    let perm_key = format!("consistent:{}", Uuid::new_v4());
    let perm_id = insert_permission(&pool, &perm_key).await;
    let role_name = format!("ConsistentRole_{}", Uuid::new_v4());
    auth_repo
        .create_role(tenant.id, &role_name, &vec![perm_id], RoleKind::Custom)
        .await
        .unwrap();
    auth_repo
        .assign_role(tenant.id, user.id, &role_name)
        .await
        .unwrap();

    let first = auth_repo.get_permissions(user.id).await.unwrap();
    let second = auth_repo.get_permissions(user.id).await.unwrap(); // cache hit
    let third = auth_repo.get_permissions(user.id).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(second, third);
    assert!(first.contains(&perm_key));
}

#[tokio::test]
#[serial]
async fn test_get_permissions_unknown_user_returns_empty() {
    // A user that has never existed should return empty permissions, not error
    let (auth_repo, _, _, _) = setup().await;

    let result = auth_repo.get_permissions(Uuid::new_v4()).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}
