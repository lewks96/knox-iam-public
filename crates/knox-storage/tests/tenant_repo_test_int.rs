use knox_common::identity::Status;
use knox_common::tenant::{TenantRepository, TenantUpdates};
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

async fn setup() -> impl TenantRepository {
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

    let client = Client::open(redis_url).expect("Invalid Redis URL");
    let manager = client
        .get_connection_manager()
        .await
        .expect("Failed to connect to Redis");

    let store = PgTenantStore::new(pool);
    let cache = RedisTenantCache::new(manager);
    KnoxTenantRepository::new(store, cache)
}

fn unique_name() -> String {
    format!("Test Corp {}", Uuid::new_v4())
}

async fn create_test_tenant(
    repo: &impl TenantRepository,
    name: &str,
    description: Option<String>,
) -> Result<knox_common::tenant::Tenant, knox_common::error::RepositoryError> {
    let suffix = Uuid::new_v4();
    TenantRepository::create(
        repo,
        name,
        &format!("test-tenant-{suffix}"),
        &format!("https://test-tenant-{suffix}.example.test"),
        description,
        false,
    )
    .await
}

// ---------------------------------------------------------------------------
// Lifecycle (existing, retained)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_tenant_lifecycle() {
    let repo = setup().await;
    let name = unique_name();

    let created = create_test_tenant(&repo, &name, Some("A test tenant".to_string()))
        .await
        .expect("Failed to create tenant");
    assert_eq!(created.name, name);
    assert_eq!(created.status, Status::Active);

    let fetched = repo
        .get(created.id)
        .await
        .expect("Failed to get tenant")
        .expect("Tenant not found");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, name);

    let update_name = unique_name();
    let updates = TenantUpdates {
        name: Some(update_name.clone()),
        description: None,
        status: Some(Status::Suspended),
        config: None,
    };
    let updated = repo
        .update(created.id, &updates)
        .await
        .expect("Failed to update");
    assert_eq!(updated.name, update_name);
    assert_eq!(updated.status, Status::Suspended);

    let fetched_again = repo.get(created.id).await.unwrap().unwrap();
    assert_eq!(fetched_again.name, update_name);

    repo.delete(created.id).await.expect("Failed to delete");

    let gone = repo.get(created.id).await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
#[serial]
async fn test_tenant_pagination() {
    let repo = setup().await;

    for i in 0..3 {
        create_test_tenant(&repo, &format!("Page Test {} {}", i, Uuid::new_v4()), None)
            .await
            .unwrap();
    }

    let (tenants, total) = repo.list(1, 2).await.expect("Failed to list");
    assert_eq!(tenants.len(), 2);
    assert!(total >= 3);
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_create_with_no_description() {
    let repo = setup().await;
    let name = unique_name();

    let created = create_test_tenant(&repo, &name, None)
        .await
        .expect("Create with no description should succeed");

    assert_eq!(created.name, name);
    assert!(created.description.is_none());
    assert_eq!(created.status, Status::Active);
}

#[tokio::test]
#[serial]
async fn test_create_with_description() {
    let repo = setup().await;
    let name = unique_name();

    let created = create_test_tenant(&repo, &name, Some("My description".into()))
        .await
        .unwrap();

    assert_eq!(created.description, Some("My description".into()));
}

#[tokio::test]
#[serial]
async fn test_create_returns_unique_ids() {
    let repo = setup().await;

    let a = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();
    let b = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    assert_ne!(a.id, b.id, "Each tenant should have a unique ID");
}

#[tokio::test]
#[serial]
async fn test_create_is_immediately_fetchable() {
    // Verifies write-through cache: a get immediately after create should succeed
    let repo = setup().await;
    let name = unique_name();

    let created = create_test_tenant(&repo, &name, None).await.unwrap();

    let fetched = repo
        .get(created.id)
        .await
        .expect("Get after create should not error")
        .expect("Tenant should be immediately fetchable after create");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, name);
}

#[tokio::test]
#[serial]
async fn test_create_default_status_is_active() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    assert_eq!(created.status, Status::Active);
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_nonexistent_returns_none() {
    let repo = setup().await;

    let result = repo
        .get(Uuid::new_v4())
        .await
        .expect("Get of nonexistent tenant should not error");

    assert!(result.is_none());
}

#[tokio::test]
#[serial]
async fn test_get_is_consistent_across_repeated_calls() {
    // Verifies cache coherence — repeated gets return the same data
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    let first = repo.get(created.id).await.unwrap().unwrap();
    let second = repo.get(created.id).await.unwrap().unwrap();
    let third = repo.get(created.id).await.unwrap().unwrap();

    assert_eq!(first.id, second.id);
    assert_eq!(second.id, third.id);
    assert_eq!(first.name, third.name);
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_update_name() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    let new_name = unique_name();
    let updates = TenantUpdates {
        name: Some(new_name.clone()),
        description: None,
        status: None,
        config: None,
    };
    let updated = repo.update(created.id, &updates).await.unwrap();

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.id, created.id);
}

#[tokio::test]
#[serial]
async fn test_update_description() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), Some("Old desc".into()))
        .await
        .unwrap();

    let updates = TenantUpdates {
        name: None,
        description: Some("New desc".into()),
        status: None,
        config: None,
    };
    let updated = repo.update(created.id, &updates).await.unwrap();

    assert_eq!(updated.description, Some("New desc".into()));
}

#[tokio::test]
#[serial]
async fn test_update_status_suspended() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();
    assert_eq!(created.status, Status::Active);

    let updates = TenantUpdates {
        name: None,
        description: None,
        status: Some(Status::Suspended),
        config: None,
    };
    let updated = repo.update(created.id, &updates).await.unwrap();

    assert_eq!(updated.status, Status::Suspended);
}

#[tokio::test]
#[serial]
async fn test_update_is_reflected_in_subsequent_get() {
    // Cache coherence: get after update should return fresh data, not stale cached data
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    // Warm the cache
    let _ = repo.get(created.id).await.unwrap();

    let post_update_name = unique_name();
    let updates = TenantUpdates {
        name: Some(post_update_name.clone()),
        description: None,
        status: None,
        config: None,
    };
    repo.update(created.id, &updates).await.unwrap();

    let after = repo.get(created.id).await.unwrap().unwrap();
    assert_eq!(
        after.name, post_update_name,
        "Get after update should return fresh data, not stale cached value"
    );
}

#[tokio::test]
#[serial]
async fn test_update_nonexistent_tenant_returns_error() {
    let repo = setup().await;

    let result = repo
        .update(
            Uuid::new_v4(),
            &TenantUpdates {
                name: Some("Ghost".into()),
                description: None,
                status: None,
                config: None,
            },
        )
        .await;

    assert!(result.is_err(), "Updating nonexistent tenant should fail");
}

#[tokio::test]
#[serial]
async fn test_update_multiple_fields_at_once() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), Some("Old desc".into()))
        .await
        .unwrap();

    let multi_name = unique_name();
    let updates = TenantUpdates {
        name: Some(multi_name.clone()),
        description: Some("New desc".into()),
        status: Some(Status::Inactive),
        config: None,
    };
    let updated = repo.update(created.id, &updates).await.unwrap();

    assert_eq!(updated.name, multi_name);
    assert_eq!(updated.description, Some("New desc".into()));
    assert_eq!(updated.status, Status::Inactive);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_delete_removes_from_store() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    repo.delete(created.id)
        .await
        .expect("Delete should succeed");

    let gone = repo.get(created.id).await.unwrap();
    assert!(gone.is_none(), "Tenant should not be findable after delete");
}

#[tokio::test]
#[serial]
async fn test_delete_removes_from_cache() {
    // After delete, a subsequent get should go to the store and find nothing —
    // if the cache entry wasn't cleared, it would return the old tenant
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    // Warm the cache explicitly
    let _ = repo.get(created.id).await.unwrap().unwrap();

    repo.delete(created.id).await.unwrap();

    // This get would return the stale cached entry if cache wasn't invalidated
    let gone = repo.get(created.id).await.unwrap();
    assert!(gone.is_none(), "Cache should be invalidated after delete");
}

#[tokio::test]
#[serial]
async fn test_delete_nonexistent_behaviour() {
    // Like the identity repo, the store may either Ok(()) or error on 0 rows affected
    let repo = setup().await;

    let result = repo.delete(Uuid::new_v4()).await;

    match result {
        Ok(()) => {}
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("NotFound") || msg.contains("not found") || msg.contains("0 rows"),
                "Unexpected error on delete of nonexistent tenant: {}",
                msg
            );
        }
    }
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_list_page_size_is_respected() {
    let repo = setup().await;

    // Ensure at least 5 tenants exist
    for _ in 0..5 {
        create_test_tenant(&repo, &unique_name(), None)
            .await
            .unwrap();
    }

    let (page, _) = repo.list(1, 3).await.expect("List should succeed");
    assert_eq!(
        page.len(),
        3,
        "Page size of 3 should return exactly 3 results"
    );
}

#[tokio::test]
#[serial]
async fn test_list_pages_do_not_overlap() {
    let repo = setup().await;

    for _ in 0..6 {
        create_test_tenant(&repo, &unique_name(), None)
            .await
            .unwrap();
    }

    let (page1, total) = repo.list(1, 3).await.unwrap();
    let (page2, _) = repo.list(2, 3).await.unwrap();

    assert!(total >= 6);

    let page1_ids: std::collections::HashSet<_> = page1.iter().map(|t| t.id).collect();
    let page2_ids: std::collections::HashSet<_> = page2.iter().map(|t| t.id).collect();

    assert!(
        page1_ids.is_disjoint(&page2_ids),
        "Pages should not contain overlapping records"
    );
}

#[tokio::test]
#[serial]
async fn test_list_total_reflects_created_tenants() {
    let repo = setup().await;

    let (_, before) = repo.list(1, 1).await.unwrap();

    create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();
    create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    let (_, after) = repo.list(1, 1).await.unwrap();

    assert_eq!(
        after,
        before + 2,
        "Total should increase by the number of tenants created"
    );
}

#[tokio::test]
#[serial]
async fn test_list_total_decrements_after_delete() {
    let repo = setup().await;

    let created = create_test_tenant(&repo, &unique_name(), None)
        .await
        .unwrap();

    let (_, before) = repo.list(1, 1).await.unwrap();

    repo.delete(created.id).await.unwrap();

    let (_, after) = repo.list(1, 1).await.unwrap();

    assert_eq!(after, before - 1, "Total should decrement after delete");
}

#[tokio::test]
#[serial]
async fn test_list_out_of_bounds_page_returns_empty() {
    let repo = setup().await;

    let (results, _) = repo
        .list(999999, 10)
        .await
        .expect("Out-of-bounds page should not error");

    assert!(
        results.is_empty(),
        "Out-of-bounds page should return empty list"
    );
}
