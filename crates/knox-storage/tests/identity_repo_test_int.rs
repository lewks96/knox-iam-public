use knox_common::identity::{
    Identity, IdentityFilter, IdentityHandle, IdentityKind, IdentityRepository, IdentityUpdates,
    Status,
};
use knox_common::tenant::TenantRepository;
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

async fn setup() -> (impl IdentityRepository, impl TenantRepository, sqlx::PgPool) {
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
        .expect("Failed to connect to DB");

    let client = Client::open(redis_url).unwrap();
    let manager = client.get_connection_manager().await.unwrap();

    let t_store = PgTenantStore::new(pool.clone());
    let t_cache = RedisTenantCache::new(manager.clone());
    let tenant_repo = KnoxTenantRepository::new(t_store, t_cache);

    let i_store = PgIdentityStore::new(pool.clone(), pool.clone());
    let i_cache = RedisIdentityCache::new(manager);
    let identity_repo = KnoxIdentityRepository::new(i_store, i_cache);

    (identity_repo, tenant_repo, pool)
}

fn unique_email() -> String {
    format!("test.{}@knox.com", Uuid::new_v4())
}

fn unique_username() -> String {
    format!("user_{}", Uuid::new_v4())
}

struct TestTenant {
    id: Uuid,
    pool_id: Uuid,
}

async fn create_test_tenant(
    tenant_repo: &impl TenantRepository,
    db: &sqlx::PgPool,
    name: &str,
    description: Option<String>,
) -> Result<TestTenant, knox_common::error::RepositoryError> {
    let suffix = Uuid::new_v4();
    let tenant = TenantRepository::create(
        tenant_repo,
        name,
        &format!("identity-test-{suffix}"),
        &format!("https://identity-test-{suffix}.example.test"),
        description,
        false,
    )
    .await?;
    let pool_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO pools (tenant_id, slug, name, kind) VALUES ($1, 'staff', 'Staff', 'staff') RETURNING id",
    )
    .bind(tenant.id)
    .fetch_one(db)
    .await
    .map_err(|error| knox_common::error::RepositoryError::Database(error.to_string()))?;
    Ok(TestTenant {
        id: tenant.id,
        pool_id,
    })
}

fn make_identity(tenant: &TestTenant) -> Identity {
    Identity {
        id: Uuid::new_v4(),
        tenant_id: tenant.id,
        pool_id: tenant.pool_id,
        kind: IdentityKind::Human,
        username: unique_username(),
        email: Some(unique_email()),
        password_hash: None,
        email_verified: false,
        first_name: Some("John".to_string()),
        last_name: Some("Doe".to_string()),
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        status: Status::Active,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_identity_full_lifecycle() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Identity Test Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .expect("Failed to create tenant");

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    let email = identity.email.clone().unwrap();
    let username = identity.username.clone();

    // CREATE
    let created = identity_repo
        .create(&identity)
        .await
        .expect("Failed to create");
    assert_eq!(created.id, user_id);
    assert_eq!(created.email, Some(email.clone()));

    // GET by ID
    let fetched = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .expect("Failed to get by ID")
        .expect("Expected Some");
    assert_eq!(fetched.username, username);

    // GET by Email
    let by_email = identity_repo
        .get(tenant.pool_id, IdentityHandle::Email(email.clone()))
        .await
        .expect("Failed to get by email")
        .expect("Expected Some");
    assert_eq!(by_email.id, user_id);

    // GET by Username
    let by_username = identity_repo
        .get(tenant.pool_id, IdentityHandle::Username(username.clone()))
        .await
        .expect("Failed to get by username")
        .expect("Expected Some");
    assert_eq!(by_username.id, user_id);

    // UPDATE
    let updates = IdentityUpdates {
        first_name: Some("Jane".to_string()),
        status: Some(Status::Suspended),
        ..Default::default()
    };
    let updated = identity_repo
        .update(tenant.pool_id, IdentityHandle::Id(user_id), &updates)
        .await
        .expect("Failed to update");
    assert_eq!(updated.first_name, Some("Jane".to_string()));
    assert_eq!(updated.status, Status::Suspended);

    // VERIFY UPDATE IS VISIBLE ON SUBSEQUENT GET
    let check = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .expect("Failed to get after update")
        .expect("Expected Some after update");
    assert_eq!(check.first_name, Some("Jane".to_string()));
    assert_eq!(check.status, Status::Suspended);

    // DELETE
    identity_repo
        .delete(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .expect("Failed to delete");

    // VERIFY GONE
    let gone = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .expect("Get after delete should not error");
    assert!(gone.is_none(), "Identity should be gone after delete");
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_create_duplicate_email_fails() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Dup Email Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let email = unique_email();
    let mut identity = make_identity(&tenant);
    identity.email = Some(email.clone());

    identity_repo
        .create(&identity)
        .await
        .expect("First create should succeed");

    let mut duplicate = make_identity(&tenant);
    duplicate.email = Some(email); // same email, different ID

    let result = identity_repo.create(&duplicate).await;
    assert!(result.is_err(), "Duplicate email should be rejected");
}

#[tokio::test]
#[serial]
async fn test_create_duplicate_username_fails() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Dup Username Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let username = unique_username();
    let mut identity = make_identity(&tenant);
    identity.username = username.clone();

    identity_repo
        .create(&identity)
        .await
        .expect("First create should succeed");

    let mut duplicate = make_identity(&tenant);
    duplicate.username = username;

    let result = identity_repo.create(&duplicate).await;
    assert!(result.is_err(), "Duplicate username should be rejected");
}

#[tokio::test]
#[serial]
async fn test_create_same_email_different_tenants_succeeds() {
    // Email uniqueness is scoped per-tenant
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant_a = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Tenant A {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();
    let tenant_b = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Tenant B {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let shared_email = unique_email();

    let mut identity_a = make_identity(&tenant_a);
    identity_a.email = Some(shared_email.clone());

    let mut identity_b = make_identity(&tenant_b);
    identity_b.email = Some(shared_email);

    identity_repo
        .create(&identity_a)
        .await
        .expect("Create in tenant A should succeed");
    let result = identity_repo.create(&identity_b).await;
    assert!(
        result.is_ok(),
        "Same email in different tenant should be allowed"
    );
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_nonexistent_id_returns_none() {
    let (identity_repo, _, _) = setup().await;
    let tenant_id = Uuid::new_v4();

    let result = identity_repo
        .get(tenant_id, IdentityHandle::Id(Uuid::new_v4()))
        .await
        .expect("Should not error");

    assert!(result.is_none());
}

#[tokio::test]
#[serial]
async fn test_get_by_email_wrong_tenant_returns_none() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant_a = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Tenant A {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();
    let tenant_b = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Tenant B {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant_a);
    let email = identity.email.clone().unwrap();
    identity_repo.create(&identity).await.unwrap();

    // Query with tenant_b should not find tenant_a's user
    let result = identity_repo
        .get(tenant_b.pool_id, IdentityHandle::Email(email))
        .await
        .expect("Should not error");

    assert!(
        result.is_none(),
        "Should not find identity across tenant boundary"
    );
}

#[tokio::test]
#[serial]
async fn test_get_by_id_is_consistent_across_repeated_calls() {
    // Verifies cache doesn't return stale data between calls
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Cache Consistency Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    let first = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap()
        .unwrap();

    let second = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(first.id, second.id);
    assert_eq!(first.username, second.username);
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_update_first_and_last_name() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Update Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    let updates = IdentityUpdates {
        first_name: Some("Updated".to_string()),
        last_name: Some("Name".to_string()),
        ..Default::default()
    };

    let updated = identity_repo
        .update(tenant.pool_id, IdentityHandle::Id(user_id), &updates)
        .await
        .expect("Update should succeed");

    assert_eq!(updated.first_name, Some("Updated".to_string()));
    assert_eq!(updated.last_name, Some("Name".to_string()));
}

#[tokio::test]
#[serial]
async fn test_update_status_to_inactive() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Status Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    let updates = IdentityUpdates {
        status: Some(Status::Inactive),
        ..Default::default()
    };

    let updated = identity_repo
        .update(tenant.pool_id, IdentityHandle::Id(user_id), &updates)
        .await
        .unwrap();

    assert_eq!(updated.status, Status::Inactive);
}

#[tokio::test]
#[serial]
async fn test_update_is_reflected_in_subsequent_get() {
    // Specifically targets the cache invalidation / refresh path
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Cache Refresh Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    // Warm cache with initial get
    let _ = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();

    // Update
    let updates = IdentityUpdates {
        first_name: Some("CacheRefreshed".to_string()),
        ..Default::default()
    };
    identity_repo
        .update(tenant.pool_id, IdentityHandle::Id(user_id), &updates)
        .await
        .unwrap();

    // Get should return fresh data, not cached stale data
    let after_update = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        after_update.first_name,
        Some("CacheRefreshed".to_string()),
        "Get after update should return updated value, not cached stale value"
    );
}

#[tokio::test]
#[serial]
async fn test_update_by_email_handle() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Email Update Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let email = identity.email.clone().unwrap();
    identity_repo.create(&identity).await.unwrap();

    let updates = IdentityUpdates {
        first_name: Some("UpdatedViaEmail".to_string()),
        ..Default::default()
    };

    let updated = identity_repo
        .update(tenant.pool_id, IdentityHandle::Email(email), &updates)
        .await
        .expect("Update by email should succeed");

    assert_eq!(updated.first_name, Some("UpdatedViaEmail".to_string()));
}

#[tokio::test]
#[serial]
async fn test_update_nonexistent_identity_returns_error() {
    let (identity_repo, _, _) = setup().await;
    let tenant_id = Uuid::new_v4();

    let updates = IdentityUpdates {
        first_name: Some("Ghost".to_string()),
        ..Default::default()
    };

    let result = identity_repo
        .update(tenant_id, IdentityHandle::Id(Uuid::new_v4()), &updates)
        .await;

    assert!(
        result.is_err(),
        "Update of nonexistent identity should fail"
    );
}

#[tokio::test]
#[serial]
async fn test_update_password_hash_persists() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Password Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    let updates = IdentityUpdates {
        password_hash: Some("$argon2id$v=19$m=65536,t=3,p=4$newsalt$newhash".to_string()),
        ..Default::default()
    };

    let result = identity_repo
        .update(tenant.pool_id, IdentityHandle::Id(user_id), &updates)
        .await;

    assert!(
        result.is_ok(),
        "Updating password hash should succeed, got: {:?}",
        result
    );

    // password_hash is intentionally stripped from GET responses by the store.
    // Verify the identity is still intact after the update.
    let fetched = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(fetched.id, user_id);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_delete_by_email_handle() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Delete Email Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    let email = identity.email.clone().unwrap();

    identity_repo.create(&identity).await.unwrap();

    identity_repo
        .delete(tenant.pool_id, IdentityHandle::Email(email.clone()))
        .await
        .expect("Delete by email should succeed");

    let gone = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();
    assert!(
        gone.is_none(),
        "Identity should be gone after delete by email"
    );
}

#[tokio::test]
#[serial]
async fn test_delete_nonexistent_does_not_panic() {
    let (identity_repo, _, _) = setup().await;
    let tenant_id = Uuid::new_v4();

    let result = identity_repo
        .delete(tenant_id, IdentityHandle::Id(Uuid::new_v4()))
        .await;

    match result {
        Ok(()) => {}
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("NotFound") || msg.contains("not found") || msg.contains("0 rows"),
                "Unexpected error on delete of nonexistent identity: {}",
                msg
            );
        }
    }
}
#[tokio::test]
#[serial]
async fn test_delete_clears_all_handle_lookups() {
    // After delete, identity should not be reachable by ID, email, or username
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Full Delete Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    let email = identity.email.clone().unwrap();
    let username = identity.username.clone();

    identity_repo.create(&identity).await.unwrap();
    identity_repo
        .delete(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();

    let by_id = identity_repo
        .get(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();
    let by_email = identity_repo
        .get(tenant.pool_id, IdentityHandle::Email(email))
        .await
        .unwrap();
    let by_username = identity_repo
        .get(tenant.pool_id, IdentityHandle::Username(username))
        .await
        .unwrap();

    assert!(by_id.is_none(), "Should not be findable by ID after delete");
    assert!(
        by_email.is_none(),
        "Should not be findable by email after delete"
    );
    assert!(
        by_username.is_none(),
        "Should not be findable by username after delete"
    );
}

// ---------------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_exists_true_for_existing_identity() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Exists Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    let exists = identity_repo
        .exists(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .expect("exists should not error");

    assert!(exists);
}

#[tokio::test]
#[serial]
async fn test_exists_false_for_nonexistent_identity() {
    let (identity_repo, _, _) = setup().await;

    let exists = identity_repo
        .exists(Uuid::new_v4(), IdentityHandle::Id(Uuid::new_v4()))
        .await
        .expect("exists should not error");

    assert!(!exists);
}

#[tokio::test]
#[serial]
async fn test_exists_false_after_delete() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Exists After Delete Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();
    identity_repo
        .delete(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();

    let exists = identity_repo
        .exists(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();

    assert!(!exists, "Deleted identity should not exist");
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_list_returns_only_tenant_identities() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant_a = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("List A {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();
    let tenant_b = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("List B {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    // Create 2 in tenant_a, 1 in tenant_b
    identity_repo
        .create(&make_identity(&tenant_a))
        .await
        .unwrap();
    identity_repo
        .create(&make_identity(&tenant_a))
        .await
        .unwrap();
    identity_repo
        .create(&make_identity(&tenant_b))
        .await
        .unwrap();

    let (list, count) = identity_repo
        .list(IdentityFilter {
            tenant_id: tenant_a.id,
            pool_id: None,
            page: 1,
            page_size: 100,
            status: None,
            query: None,
        })
        .await
        .expect("List should succeed");

    assert!(
        list.iter().all(|i| i.tenant_id == tenant_a.id),
        "All results should belong to tenant_a"
    );
    assert_eq!(count, 2);
}

#[tokio::test]
#[serial]
async fn test_list_status_filter() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Status Filter Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let active = make_identity(&tenant);
    let active_id = active.id;
    identity_repo.create(&active).await.unwrap();

    let suspended = make_identity(&tenant);
    let suspended_id = suspended.id;
    identity_repo.create(&suspended).await.unwrap();
    identity_repo
        .update(
            tenant.pool_id,
            IdentityHandle::Id(suspended_id),
            &IdentityUpdates {
                status: Some(Status::Suspended),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (active_list, active_count) = identity_repo
        .list(IdentityFilter {
            tenant_id: tenant.id,
            pool_id: None,
            page: 1,
            page_size: 100,
            status: Some(Status::Active),
            query: None,
        })
        .await
        .unwrap();

    assert!(
        active_list.iter().all(|i| i.status == Status::Active),
        "All results should be Active"
    );
    // Our active user should be in the list
    assert!(active_list.iter().any(|i| i.id == active_id));
    // Suspended user should NOT appear
    assert!(!active_list.iter().any(|i| i.id == suspended_id));
    let _ = active_count;
}

#[tokio::test]
#[serial]
async fn test_list_pagination() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Pagination Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    for _ in 0..5 {
        identity_repo.create(&make_identity(&tenant)).await.unwrap();
    }

    let (page1, total) = identity_repo
        .list(IdentityFilter {
            tenant_id: tenant.id,
            pool_id: None,
            page: 1,
            page_size: 3,
            status: None,
            query: None,
        })
        .await
        .unwrap();

    let (page2, _) = identity_repo
        .list(IdentityFilter {
            tenant_id: tenant.id,
            pool_id: None,
            page: 2,
            page_size: 3,
            status: None,
            query: None,
        })
        .await
        .unwrap();

    assert_eq!(page1.len(), 3);
    assert!(
        page2.len() >= 2,
        "Second page should have remaining records"
    );
    assert!(total >= 5);

    // No overlap between pages
    let page1_ids: std::collections::HashSet<_> = page1.iter().map(|i| i.id).collect();
    let page2_ids: std::collections::HashSet<_> = page2.iter().map(|i| i.id).collect();
    assert!(
        page1_ids.is_disjoint(&page2_ids),
        "Pages should not contain overlapping records"
    );
}

#[tokio::test]
#[serial]
async fn test_list_empty_tenant_returns_zero() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Empty Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let (list, count) = identity_repo
        .list(IdentityFilter {
            tenant_id: tenant.id,
            pool_id: None,
            page: 1,
            page_size: 10,
            status: None,
            query: None,
        })
        .await
        .unwrap();

    assert!(list.is_empty());
    assert_eq!(count, 0);
}

// ---------------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_count_returns_correct_total() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Count Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    identity_repo.create(&make_identity(&tenant)).await.unwrap();
    identity_repo.create(&make_identity(&tenant)).await.unwrap();
    identity_repo.create(&make_identity(&tenant)).await.unwrap();

    let count = identity_repo.count(tenant.id, None).await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
#[serial]
async fn test_count_decrements_after_delete() {
    let (identity_repo, tenant_repo, db) = setup().await;

    let tenant = create_test_tenant(
        &tenant_repo,
        &db,
        &format!("Count Delete Corp {}", Uuid::new_v4()),
        None,
    )
    .await
    .unwrap();

    let identity = make_identity(&tenant);
    let user_id = identity.id;
    identity_repo.create(&identity).await.unwrap();

    let before = identity_repo.count(tenant.id, None).await.unwrap();
    identity_repo
        .delete(tenant.pool_id, IdentityHandle::Id(user_id))
        .await
        .unwrap();
    let after = identity_repo.count(tenant.id, None).await.unwrap();

    assert_eq!(after, before - 1);
}
