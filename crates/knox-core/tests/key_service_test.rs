use async_trait::async_trait;
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::key::{
    CreateKeyParams, KeyAlgorithm, KeyEncryptionError, KeyEncryptionProvider, KeyRepository,
    KeyState, TenantKey,
};
use knox_core::key::{CreateKeyRequest, KeyService, LocalKeyEncryptionProvider, RotateKeysRequest};
use mockall::{mock, predicate::*};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub KeyRepo {}
    #[async_trait]
    impl KeyRepository for KeyRepo {
        async fn create(&self, params: CreateKeyParams) -> Result<TenantKey, RepositoryError>;
        async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
        async fn get_by_kid(&self, tenant_id: Uuid, kid: &str) -> Result<Option<TenantKey>, RepositoryError>;
        async fn get_active_for_tenant(&self, tenant_id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
        async fn list_for_jwks(&self, tenant_id: Uuid) -> Result<Vec<TenantKey>, RepositoryError>;
        async fn list(&self, tenant_id: Uuid, page: u32, page_size: u32) -> Result<(Vec<TenantKey>, u64), RepositoryError>;
        async fn update_state(&self, id: Uuid, new_state: KeyState) -> Result<TenantKey, RepositoryError>;
        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
    }
}

struct MockKmsProvider {
    encrypt_result: Result<Vec<u8>, KeyEncryptionError>,
    decrypt_result: Result<String, KeyEncryptionError>,
}

impl MockKmsProvider {
    fn new() -> Self {
        Self {
            encrypt_result: Ok(vec![1, 2, 3, 4, 5]),
            decrypt_result: Ok("decrypted_key".to_string()),
        }
    }

    fn with_encrypt_error(mut self, err: &str) -> Self {
        self.encrypt_result = Err(KeyEncryptionError(err.to_string()));
        self
    }

    fn with_decrypt_error(mut self, err: &str) -> Self {
        self.decrypt_result = Err(KeyEncryptionError(err.to_string()));
        self
    }

    fn with_decrypt_result(mut self, result: &str) -> Self {
        self.decrypt_result = Ok(result.to_string());
        self
    }
}

#[async_trait]
impl KeyEncryptionProvider for MockKmsProvider {
    async fn encrypt(
        &self,
        _plaintext: &str,
        _context: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyEncryptionError> {
        self.encrypt_result.clone()
    }

    async fn decrypt(
        &self,
        _encrypted: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<String, KeyEncryptionError> {
        self.decrypt_result.clone()
    }

    fn provider_id(&self) -> &str {
        "mock-kms"
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

fn make_tenant_key(tenant_id: Uuid, kid: &str, state: KeyState) -> TenantKey {
    TenantKey {
        id: Uuid::new_v4(),
        tenant_id,
        kid: kid.to_string(),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
            .to_string(),
        x509_cert_pem: None,
        encrypted_private_key: vec![1, 2, 3, 4, 5],
        state,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::days(365),
    }
}

fn make_rsa_tenant_key(tenant_id: Uuid, kid: &str, state: KeyState) -> TenantKey {
    // A minimal valid RSA public key PEM for testing JWKS conversion
    let public_key_pem = include_str!("fixtures/test_rsa_public_key.pem").to_string();
    TenantKey {
        id: Uuid::new_v4(),
        tenant_id,
        kid: kid.to_string(),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem,
        x509_cert_pem: None,
        encrypted_private_key: vec![1, 2, 3, 4, 5],
        state,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::days(365),
    }
}

// ---------------------------------------------------------------------------
// create_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_key_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_create()
        .withf(move |params| {
            params.tenant_id == tenant_id
                && params.alg == "RS256"
                && params.kty == "RSA"
                && params.use_type == "sig"
        })
        .times(1)
        .returning(move |params| {
            Ok(make_tenant_key(
                params.tenant_id,
                &params.kid,
                KeyState::Active,
            ))
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = CreateKeyRequest {
        kid: None,
        algorithm: None,
        validity_days: None,
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(result.is_ok());
    let key = result.unwrap();
    assert_eq!(key.tenant_id, tenant_id);
    assert_eq!(key.state, KeyState::Active);
}

#[tokio::test]
async fn test_create_key_with_custom_kid() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_create()
        .withf(|params| params.kid == "my-custom-kid")
        .times(1)
        .returning(move |params| {
            Ok(make_tenant_key(
                params.tenant_id,
                &params.kid,
                KeyState::Active,
            ))
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = CreateKeyRequest {
        kid: Some("my-custom-kid".to_string()),
        algorithm: None,
        validity_days: None,
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().kid, "my-custom-kid");
}

#[tokio::test]
async fn test_create_key_with_rs384_algorithm() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_create()
        .withf(|params| params.alg == "RS384")
        .times(1)
        .returning(move |params| {
            Ok(make_tenant_key(
                params.tenant_id,
                &params.kid,
                KeyState::Active,
            ))
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = CreateKeyRequest {
        kid: None,
        algorithm: Some(KeyAlgorithm::RS384),
        validity_days: None,
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_key_with_custom_validity() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_create()
        .withf(|params| {
            // Check that expires_at is approximately 30 days from now
            let expected = OffsetDateTime::now_utc() + Duration::days(30);
            (params.expires_at - expected).abs() < Duration::seconds(5)
        })
        .times(1)
        .returning(move |params| {
            Ok(make_tenant_key(
                params.tenant_id,
                &params.kid,
                KeyState::Active,
            ))
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = CreateKeyRequest {
        kid: None,
        algorithm: None,
        validity_days: Some(30),
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_key_kid_too_long_fails_validation() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();
    repo.expect_create().times(0);

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = CreateKeyRequest {
        kid: Some("a".repeat(65)), // > 64 chars
        algorithm: None,
        validity_days: None,
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_key_encryption_failure() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let repo = MockKeyRepo::new();

    let kep = MockKmsProvider::new().with_encrypt_error("KMS unavailable");

    let service = KeyService::new(repo, kep);
    let req = CreateKeyRequest {
        kid: None,
        algorithm: None,
        validity_days: None,
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(matches!(result, Err(ServiceError::Internal(_))));
}

#[tokio::test]
async fn test_create_key_repository_error() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_create()
        .returning(|_| Err(RepositoryError::Database("connection lost".into())));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = CreateKeyRequest {
        kid: None,
        algorithm: None,
        validity_days: None,
    };

    let result = service.create_key(tenant_id, req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// rotate_keys tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rotate_keys_no_existing_key() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    // No existing active key
    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(None));

    // Create new key
    repo.expect_create().times(1).returning(move |params| {
        Ok(make_tenant_key(
            params.tenant_id,
            &params.kid,
            KeyState::Active,
        ))
    });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = RotateKeysRequest {
        algorithm: None,
        validity_days: None,
        revoke_existing: false,
    };

    let result = service.rotate_keys(tenant_id, req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_rotate_keys_graceful_rotation() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let old_key = make_tenant_key(tenant_id, "old-kid", KeyState::Active);
    let old_key_id = old_key.id;
    let mut repo = MockKeyRepo::new();

    // Return existing active key
    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(Some(old_key)));

    // Create new key
    repo.expect_create().times(1).returning(move |params| {
        Ok(make_tenant_key(
            params.tenant_id,
            &params.kid,
            KeyState::Active,
        ))
    });

    // Old key should be expired (not revoked)
    repo.expect_update_state()
        .with(eq(old_key_id), eq(KeyState::Expired))
        .times(1)
        .returning(|id, state| {
            let mut key = make_tenant_key(Uuid::new_v4(), "old-kid", state);
            key.id = id;
            Ok(key)
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = RotateKeysRequest {
        algorithm: None,
        validity_days: None,
        revoke_existing: false,
    };

    let result = service.rotate_keys(tenant_id, req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_rotate_keys_emergency_revoke() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let old_key = make_tenant_key(tenant_id, "compromised-kid", KeyState::Active);
    let old_key_id = old_key.id;
    let mut repo = MockKeyRepo::new();

    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(Some(old_key)));

    repo.expect_create().times(1).returning(move |params| {
        Ok(make_tenant_key(
            params.tenant_id,
            &params.kid,
            KeyState::Active,
        ))
    });

    // Old key should be REVOKED (emergency)
    repo.expect_update_state()
        .with(eq(old_key_id), eq(KeyState::Revoked))
        .times(1)
        .returning(|id, state| {
            let mut key = make_tenant_key(Uuid::new_v4(), "compromised-kid", state);
            key.id = id;
            Ok(key)
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let req = RotateKeysRequest {
        algorithm: None,
        validity_days: None,
        revoke_existing: true,
    };

    let result = service.rotate_keys(tenant_id, req).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// get_active_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_active_key_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id, "active-kid", KeyState::Active);
    let mut repo = MockKeyRepo::new();

    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(Some(key)));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_active_key(tenant_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_get_active_key_not_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(None));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_active_key(tenant_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// get_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_key_by_id() {
    init_tracing();
    let key_id = Uuid::new_v4();
    let key = make_tenant_key(Uuid::new_v4(), "kid-1", KeyState::Active);
    let mut repo = MockKeyRepo::new();

    repo.expect_get()
        .with(eq(key_id))
        .times(1)
        .return_once(move |_| Ok(Some(key)));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_key(key_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_get_key_not_found() {
    init_tracing();
    let key_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_get()
        .with(eq(key_id))
        .times(1)
        .returning(|_| Ok(None));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_key(key_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// get_key_by_kid tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_key_by_kid_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let kid = "tenant-key-123";
    let key = make_tenant_key(tenant_id, kid, KeyState::Active);
    let mut repo = MockKeyRepo::new();

    repo.expect_get_by_kid()
        .with(eq(tenant_id), eq(kid))
        .times(1)
        .return_once(move |_, _| Ok(Some(key)));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_key_by_kid(tenant_id, kid).await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    assert_eq!(found.kid, kid);
}

#[tokio::test]
async fn test_get_key_by_kid_not_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_get_by_kid().returning(|_, _| Ok(None));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_key_by_kid(tenant_id, "nonexistent").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// list_keys tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_keys_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let keys = vec![
        make_tenant_key(tenant_id, "kid-1", KeyState::Active),
        make_tenant_key(tenant_id, "kid-2", KeyState::Expired),
    ];
    let mut repo = MockKeyRepo::new();

    repo.expect_list()
        .with(eq(tenant_id), eq(1), eq(10))
        .times(1)
        .return_once(move |_, _, _| Ok((keys, 2)));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.list_keys(tenant_id, 1, 10).await;

    assert!(result.is_ok());
    let (keys, total) = result.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(total, 2);
}

#[tokio::test]
async fn test_list_keys_empty() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_list()
        .with(eq(tenant_id), eq(1), eq(10))
        .times(1)
        .returning(|_, _, _| Ok((vec![], 0)));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.list_keys(tenant_id, 1, 10).await;

    assert!(result.is_ok());
    let (keys, total) = result.unwrap();
    assert!(keys.is_empty());
    assert_eq!(total, 0);
}

// ---------------------------------------------------------------------------
// expire_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_expire_key_success() {
    init_tracing();
    let key_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_update_state()
        .with(eq(key_id), eq(KeyState::Expired))
        .times(1)
        .returning(|id, state| {
            let mut key = make_tenant_key(Uuid::new_v4(), "kid", state);
            key.id = id;
            Ok(key)
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.expire_key(key_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().state, KeyState::Expired);
}

// ---------------------------------------------------------------------------
// revoke_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_key_success() {
    init_tracing();
    let key_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_update_state()
        .with(eq(key_id), eq(KeyState::Revoked))
        .times(1)
        .returning(|id, state| {
            let mut key = make_tenant_key(Uuid::new_v4(), "kid", state);
            key.id = id;
            Ok(key)
        });

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.revoke_key(key_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().state, KeyState::Revoked);
}

// ---------------------------------------------------------------------------
// revoke_all_keys tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_all_keys_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_revoke_all_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(()));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.revoke_all_keys(tenant_id).await;

    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// delete_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_key_success() {
    init_tracing();
    let key_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_delete()
        .with(eq(key_id))
        .times(1)
        .returning(|_| Ok(()));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.delete_key(key_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_key_not_found() {
    init_tracing();
    let key_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_delete()
        .with(eq(key_id))
        .times(1)
        .returning(|_| Err(RepositoryError::NotFound));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.delete_key(key_id).await;

    assert!(matches!(
        result,
        Err(ServiceError::Repository(RepositoryError::NotFound))
    ));
}

// ---------------------------------------------------------------------------
// get_jwks tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_jwks_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let keys = vec![
        make_rsa_tenant_key(tenant_id, "kid-1", KeyState::Active),
        make_rsa_tenant_key(tenant_id, "kid-2", KeyState::Expired),
    ];
    let mut repo = MockKeyRepo::new();

    repo.expect_list_for_jwks()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(keys));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_jwks(tenant_id).await;

    assert!(result.is_ok());
    let jwks = result.unwrap();
    assert_eq!(jwks.keys.len(), 2);
    assert!(jwks.keys.iter().any(|k| k.kid == "kid-1"));
    assert!(jwks.keys.iter().any(|k| k.kid == "kid-2"));
}

#[tokio::test]
async fn test_get_jwks_empty() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_list_for_jwks()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(vec![]));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_jwks(tenant_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().keys.is_empty());
}

#[tokio::test]
async fn test_get_jwks_filters_invalid_keys() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    // One valid RSA key, one with invalid public key PEM
    let valid_key = make_rsa_tenant_key(tenant_id, "valid-kid", KeyState::Active);
    let mut invalid_key = make_tenant_key(tenant_id, "invalid-kid", KeyState::Active);
    invalid_key.public_key_pem = "not a valid PEM".to_string();

    let keys = vec![valid_key, invalid_key];
    let mut repo = MockKeyRepo::new();

    repo.expect_list_for_jwks()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(keys));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_jwks(tenant_id).await;

    assert!(result.is_ok());
    let jwks = result.unwrap();
    // Only the valid key should appear
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid, "valid-kid");
}

// ---------------------------------------------------------------------------
// decrypt_private_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_decrypt_private_key_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id, "kid", KeyState::Active);
    let repo = MockKeyRepo::new();

    let kep = MockKmsProvider::new()
        .with_decrypt_result("-----BEGIN PRIVATE KEY-----\nABC...\n-----END PRIVATE KEY-----");

    let service = KeyService::new(repo, kep);
    let result = service.decrypt_private_key(&key).await;

    assert!(result.is_ok());
    assert!(result.unwrap().contains("BEGIN PRIVATE KEY"));
}

#[tokio::test]
async fn test_decrypt_private_key_revoked_fails() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id, "revoked-kid", KeyState::Revoked);
    let repo = MockKeyRepo::new();

    // Decryption should not even be attempted for revoked keys
    let kep = MockKmsProvider::new();

    let service = KeyService::new(repo, kep);
    let result = service.decrypt_private_key(&key).await;

    assert!(matches!(result, Err(ServiceError::Forbidden)));
}

#[tokio::test]
async fn test_decrypt_private_key_decryption_failure() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id, "kid", KeyState::Active);
    let repo = MockKeyRepo::new();

    let kep = MockKmsProvider::new().with_decrypt_error("KMS key rotation in progress");

    let service = KeyService::new(repo, kep);
    let result = service.decrypt_private_key(&key).await;

    assert!(matches!(result, Err(ServiceError::Internal(_))));
}

// ---------------------------------------------------------------------------
// get_signing_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_signing_key_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id, "signing-kid", KeyState::Active);
    let mut repo = MockKeyRepo::new();

    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(Some(key)));

    let kep = MockKmsProvider::new().with_decrypt_result("decrypted_private_key_pem");

    let service = KeyService::new(repo, kep);
    let result = service.get_signing_key(tenant_id).await;

    assert!(result.is_ok());
    let (key, decrypted) = result.unwrap();
    assert_eq!(key.kid, "signing-kid");
    assert_eq!(decrypted, "decrypted_private_key_pem");
}

#[tokio::test]
async fn test_get_signing_key_no_active_key() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockKeyRepo::new();

    repo.expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(None));

    let service = KeyService::new(repo, MockKmsProvider::new());
    let result = service.get_signing_key(tenant_id).await;

    assert!(matches!(result, Err(ServiceError::Internal(_))));
}

// ---------------------------------------------------------------------------
// LocalKeyEncryptionProvider tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_local_kep_encrypt_decrypt_roundtrip() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    let plaintext = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBAD...\n-----END PRIVATE KEY-----";
    let context = b"tenant-context";

    let encrypted = provider.encrypt(plaintext, Some(context)).await.unwrap();
    let decrypted = provider.decrypt(&encrypted, Some(context)).await.unwrap();

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_local_kep_wrong_context_fails() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    let plaintext = "secret key";
    let encrypted = provider
        .encrypt(plaintext, Some(b"context-a"))
        .await
        .unwrap();

    let result = provider.decrypt(&encrypted, Some(b"context-b")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_local_kep_no_context_roundtrip() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    let plaintext = "secret";
    let encrypted = provider.encrypt(plaintext, None).await.unwrap();
    let decrypted = provider.decrypt(&encrypted, None).await.unwrap();

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_local_kep_short_blob_fails() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    let short_blob = vec![0x01, 0x02, 0x03]; // Too short
    let result = provider.decrypt(&short_blob, None).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_local_kep_wrong_version_fails() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    // Create a blob with wrong version
    let mut invalid_blob = vec![0xFF]; // Wrong version
    invalid_blob.extend_from_slice(&[0u8; 12]); // Nonce
    invalid_blob.extend_from_slice(&[0u8; 32]); // Some ciphertext

    let result = provider.decrypt(&invalid_blob, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_local_kep_tampered_ciphertext_fails() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    let plaintext = "secret key";
    let mut encrypted = provider.encrypt(plaintext, None).await.unwrap();

    // Tamper with ciphertext
    if let Some(byte) = encrypted.last_mut() {
        *byte ^= 0xFF;
    }

    let result = provider.decrypt(&encrypted, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_local_kep_provider_id() {
    init_tracing();
    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let provider = LocalKeyEncryptionProvider::new(&master_key);

    assert_eq!(provider.provider_id(), "local-aes-256-gcm");
}

#[tokio::test]
async fn test_local_kep_from_base64() {
    init_tracing();
    use base64::{Engine, engine::general_purpose::STANDARD};

    let master_key = LocalKeyEncryptionProvider::generate_master_key();
    let master_key_b64 = STANDARD.encode(&master_key);

    let provider = LocalKeyEncryptionProvider::from_base64(&master_key_b64).unwrap();

    let plaintext = "test";
    let encrypted = provider.encrypt(plaintext, None).await.unwrap();
    let decrypted = provider.decrypt(&encrypted, None).await.unwrap();

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_local_kep_from_base64_invalid() {
    init_tracing();
    let result = LocalKeyEncryptionProvider::from_base64("not-valid-base64!!!");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_local_kep_from_base64_wrong_length() {
    init_tracing();
    use base64::{Engine, engine::general_purpose::STANDARD};

    let short_key = STANDARD.encode(&[0u8; 16]); // Only 16 bytes, need 32
    let result = LocalKeyEncryptionProvider::from_base64(&short_key);
    assert!(result.is_err());
}
