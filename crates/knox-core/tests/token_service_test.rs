use async_trait::async_trait;
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::key::{
    CreateKeyParams, KeyEncryptionError, KeyEncryptionProvider, KeyRepository, KeyState, TenantKey,
};
use knox_common::pool::PoolKind;
use knox_common::token::{AuthCodeContext, RefreshToken, TokenRepository};
use knox_core::key::KeyService;
use knox_core::token::{JwtClaims, TokenService, TransientKind};
use mockall::{mock, predicate::*};
use rsa::pkcs8::LineEnding;
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};
use spki::EncodePublicKey;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

mock! {
    pub TokenRepo {}
    #[async_trait]
    #[allow(deprecated)]
    impl TokenRepository for TokenRepo {
        async fn store_transient_string(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> Result<(), RepositoryError>;
        async fn read_transient_string(
            &self,
            key: &str,
        ) -> Result<Option<String>, RepositoryError>;
        async fn get_and_delete_transient_string(
            &self,
            key: &str,
        ) -> Result<Option<String>, RepositoryError>;
        async fn increment_transient_counter(
            &self,
            key: &str,
            ttl_seconds: u64,
        ) -> Result<u64, RepositoryError>;
        async fn touch_transient(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError>;
        async fn save_auth_code(
            &self,
            hashed_code: &str,
            context: &AuthCodeContext,
            ttl_seconds: u64,
        ) -> Result<(), RepositoryError>;
        async fn exchange_auth_code(
            &self,
            hashed_code: &str,
        ) -> Result<Option<AuthCodeContext>, RepositoryError>;
        async fn save_refresh_token(&self, token: &RefreshToken) -> Result<RefreshToken, RepositoryError>;
        async fn get_refresh_token(
            &self,
            tenant_id: Uuid,
            token_hash: &str,
        ) -> Result<Option<RefreshToken>, RepositoryError>;
        async fn revoke_refresh_token(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_all_for_identity(
            &self,
            tenant_id: Uuid,
            identity_id: Uuid,
        ) -> Result<(), RepositoryError>;
    }
}

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
    decrypt_result: String,
}

impl MockKmsProvider {
    fn new(decrypt_result: String) -> Self {
        Self { decrypt_result }
    }
}

#[async_trait]
impl KeyEncryptionProvider for MockKmsProvider {
    async fn encrypt(
        &self,
        _plaintext: &str,
        _context: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyEncryptionError> {
        Ok(vec![1, 2, 3])
    }

    async fn decrypt(
        &self,
        _encrypted: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<String, KeyEncryptionError> {
        Ok(self.decrypt_result.clone())
    }

    fn provider_id(&self) -> &str {
        "mock-kms"
    }
}

type TestTokenService = TokenService<MockTokenRepo, MockKeyRepo, MockKmsProvider>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

/// A tenant's stored issuer. TokenService no longer derives issuers — callers
/// pass the tenant's own, so tests supply one directly.
const TEST_ISSUER: &str = "https://acme.knox.dev";
/// A different tenant on the same deployment.
const OTHER_TENANT_ISSUER: &str = "https://other.knox.dev";

fn generate_rsa_keypair() -> (String, String) {
    let private_key =
        RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("RSA key generation failed");
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key")
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode public key");
    (private_pem, public_pem)
}

fn make_tenant_key_with_id(id: Uuid, tenant_id: Uuid, public_key_pem: &str) -> TenantKey {
    TenantKey {
        id,
        tenant_id,
        kid: id.to_string(),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem: public_key_pem.to_string(),
        x509_cert_pem: None,
        encrypted_private_key: vec![1, 2, 3],
        state: KeyState::Active,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(365),
    }
}

fn make_service(repo: MockTokenRepo) -> TestTokenService {
    let key_repo = MockKeyRepo::new();
    let kms = MockKmsProvider::new(String::new());
    let key_service = KeyService::new(key_repo, kms);
    TokenService::new(repo, key_service)
}

fn make_jwt_service(
    repo: MockTokenRepo,
    key_repo: MockKeyRepo,
    private_pem: &str,
) -> TestTokenService {
    let kms = MockKmsProvider::new(private_pem.to_string());
    let key_service = KeyService::new(key_repo, kms);
    TokenService::new(repo, key_service)
}

/// Retained for tests that mint under a *different* issuer; the issuer is now
/// passed at mint time, so this differs from `make_jwt_service` only in intent.
fn make_jwt_service_with_issuer(
    repo: MockTokenRepo,
    key_repo: MockKeyRepo,
    private_pem: &str,
    _issuer: &str,
) -> TestTokenService {
    let kms = MockKmsProvider::new(private_pem.to_string());
    let key_service = KeyService::new(key_repo, kms);
    TokenService::new(repo, key_service)
}

fn make_claims(sub: Uuid, tenant_id: Uuid) -> JwtClaims {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    JwtClaims {
        iss: TEST_ISSUER.to_string(),
        sub: sub.to_string(),
        aud: "knox-api".to_string(),
        exp: now + 3600,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        client_id: Some("test-client".into()),
        amr: vec!["pwd".into()],
        acr: Some("urn:knox:loa:pwd".into()),
        auth_time: Some(now),
        tenant_id,
        pool_id: Uuid::new_v4(),
        pool_kind: PoolKind::Staff,
        scopes: vec!["openid".into(), "profile".into()],
        token_version: 1,
    }
}

fn make_refresh_token(tenant_id: Uuid, identity_id: Uuid) -> RefreshToken {
    RefreshToken {
        id: Uuid::new_v4(),
        tenant_id,
        identity_id,
        client_id: Uuid::new_v4(),
        family_id: Uuid::new_v4(),
        token_hash: format!("sha256_{}", Uuid::new_v4()),
        scopes: vec!["openid".into(), "offline_access".into()],
        amr: vec!["pwd".into(), "otp".into(), "mfa".into()],
        auth_time: Some(OffsetDateTime::now_utc()),
        revoked_at: None,
        updated_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(30),
        created_at: OffsetDateTime::now_utc(),
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct TestPayload {
    value: String,
    number: u32,
}

// ---------------------------------------------------------------------------
// generate_opaque_token tests (pure, no repo)
// ---------------------------------------------------------------------------

#[test]
fn test_generate_opaque_token_correct_length() {
    let svc = make_service(MockTokenRepo::new());
    let token = svc.generate_opaque_token(40);
    assert_eq!(token.len(), 40);
}

#[test]
fn test_generate_opaque_token_is_alphanumeric() {
    let svc = make_service(MockTokenRepo::new());
    let token = svc.generate_opaque_token(64);
    assert!(
        token.chars().all(|c| c.is_alphanumeric()),
        "Token should contain only alphanumeric characters, got: {}",
        token
    );
}

#[test]
fn test_generate_opaque_token_different_lengths() {
    let svc = make_service(MockTokenRepo::new());
    for len in [16, 32, 40, 64, 128] {
        let token = svc.generate_opaque_token(len);
        assert_eq!(
            token.len(),
            len,
            "Token length mismatch for requested length {}",
            len
        );
    }
}

#[test]
fn test_generate_opaque_token_uniqueness() {
    // Two consecutive calls must not produce the same token
    let svc = make_service(MockTokenRepo::new());
    let t1 = svc.generate_opaque_token(40);
    let t2 = svc.generate_opaque_token(40);
    assert_ne!(t1, t2, "Each generated token should be unique");
}

// ---------------------------------------------------------------------------
// hash_token tests (pure, no repo)
// ---------------------------------------------------------------------------

#[test]
fn test_hash_token_produces_hex_string() {
    let hash = TestTokenService::hash_token("some_plaintext");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash should be a hex string, got: {}",
        hash
    );
}

#[test]
fn test_hash_token_is_sha256_length() {
    let hash = TestTokenService::hash_token("some_plaintext");
    // SHA-256 produces 32 bytes = 64 hex characters
    assert_eq!(hash.len(), 64, "SHA-256 hex hash should be 64 characters");
}

#[test]
fn test_hash_token_is_deterministic() {
    let input = "deterministic_input";
    let h1 = TestTokenService::hash_token(input);
    let h2 = TestTokenService::hash_token(input);
    assert_eq!(h1, h2, "Same input must always produce the same hash");
}

#[test]
fn test_hash_token_different_inputs_produce_different_hashes() {
    let h1 = TestTokenService::hash_token("token_a");
    let h2 = TestTokenService::hash_token("token_b");
    assert_ne!(h1, h2);
}

#[test]
fn test_hash_token_avalanche_effect() {
    // A single character difference must produce a completely different hash
    let h1 = TestTokenService::hash_token("token1");
    let h2 = TestTokenService::hash_token("token2");
    assert_ne!(h1, h2);
}

#[test]
fn test_hash_and_generate_workflow() {
    // Simulate the typical usage: generate a plaintext token, hash it for storage
    let svc = make_service(MockTokenRepo::new());
    let plaintext = svc.generate_opaque_token(40);
    let hash = TestTokenService::hash_token(&plaintext);

    assert_eq!(hash.len(), 64);
    assert_ne!(hash, plaintext, "Hash must not equal the plaintext");
    // Verify determinism of the hash given the plaintext
    assert_eq!(hash, TestTokenService::hash_token(&plaintext));
}

// ---------------------------------------------------------------------------
// Helper: build a mock key repo that returns a TenantKey for mint/verify
// ---------------------------------------------------------------------------

fn mock_key_repo_for_mint(tenant_id: Uuid, key_id: Uuid, public_pem: &str) -> MockKeyRepo {
    let tenant_key = make_tenant_key_with_id(key_id, tenant_id, public_pem);
    let mut key_repo = MockKeyRepo::new();
    key_repo
        .expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .returning(move |_| Ok(Some(tenant_key.clone())));
    key_repo
}

fn mock_key_repo_for_mint_and_verify(
    tenant_id: Uuid,
    key_id: Uuid,
    public_pem: &str,
) -> MockKeyRepo {
    let tenant_key = make_tenant_key_with_id(key_id, tenant_id, public_pem);
    let tk1 = tenant_key.clone();
    let tk2 = tenant_key.clone();
    let kid_str = key_id.to_string();
    let mut key_repo = MockKeyRepo::new();
    key_repo
        .expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .returning(move |_| Ok(Some(tk1.clone())));
    key_repo
        .expect_get_by_kid()
        .withf(move |tid, k| *tid == tenant_id && k == kid_str)
        .returning(move |_, _| Ok(Some(tk2.clone())));
    key_repo
}

// ---------------------------------------------------------------------------
// mint_jwt tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mint_jwt_produces_three_part_token() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let key_repo = mock_key_repo_for_mint(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);
    let claims = make_claims(Uuid::new_v4(), tenant_id);

    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .expect("Minting should succeed");
    let parts: Vec<&str> = token.split('.').collect();

    assert_eq!(
        parts.len(),
        3,
        "JWT should have exactly 3 dot-separated parts"
    );
}

#[tokio::test]
async fn test_mint_jwt_is_verifiable() {
    let sub = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let key_repo = mock_key_repo_for_mint_and_verify(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);
    let claims = make_claims(sub, tenant_id);

    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();
    let verified = service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, Some("knox-api"))
        .await
        .expect("Freshly minted token should verify");

    assert_eq!(verified.sub, sub.to_string());
    assert_eq!(verified.tenant_id, tenant_id);
}

#[tokio::test]
async fn test_mint_jwt_preserves_claims() {
    let sub = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let key_repo = mock_key_repo_for_mint_and_verify(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);
    let claims = make_claims(sub, tenant_id);
    let expected_scopes = claims.scopes.clone();

    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();
    let verified = service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, Some("knox-api"))
        .await
        .unwrap();

    // The issuer is scoped to the tenant, not the bare deployment base.
    assert_eq!(verified.iss, TEST_ISSUER);
    assert_eq!(verified.aud, "knox-api");
    assert_eq!(verified.scopes, expected_scopes);
}

// ---------------------------------------------------------------------------
// verify_jwt tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_verify_jwt_wrong_key_is_rejected() {
    let tenant_id = Uuid::new_v4();
    let (mint_private_pem, mint_public_pem) = generate_rsa_keypair();
    let (_other_private_pem, other_public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    // Mint with one key pair
    let mint_key_repo = mock_key_repo_for_mint(tenant_id, key_id, &mint_public_pem);
    let mint_service = make_jwt_service(MockTokenRepo::new(), mint_key_repo, &mint_private_pem);
    let claims = make_claims(Uuid::new_v4(), tenant_id);
    let token = mint_service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();

    // Verify with a different public key (same key_id so it finds the key, but wrong public key)
    let mut verify_key_repo = MockKeyRepo::new();
    let wrong_key = make_tenant_key_with_id(key_id, tenant_id, &other_public_pem);
    let kid_str = key_id.to_string();
    verify_key_repo
        .expect_get_by_kid()
        .withf(move |tid, k| *tid == tenant_id && k == kid_str)
        .returning(move |_, _| Ok(Some(wrong_key.clone())));
    let verify_service = make_jwt_service(MockTokenRepo::new(), verify_key_repo, &mint_private_pem);

    let result = verify_service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, Some("knox-api"))
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Token verified with a different key must be rejected"
    );
}

#[tokio::test]
async fn test_verify_jwt_expired_token_is_rejected() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let key_repo = mock_key_repo_for_mint_and_verify(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);

    let expired_claims = JwtClaims {
        iss: TEST_ISSUER.to_string(),
        sub: Uuid::new_v4().to_string(),
        aud: "knox-api".to_string(),
        exp: now - 3600, // expired 1 hour ago
        iat: now - 7200,
        client_id: Some("test-client".into()),
        amr: vec!["pwd".into()],
        acr: Some("urn:knox:loa:pwd".into()),
        auth_time: Some(now - 7200),
        pool_id: Uuid::new_v4(),
        pool_kind: PoolKind::Staff,
        jti: Uuid::new_v4().to_string(),
        tenant_id,
        scopes: vec![],
        token_version: 1,
    };

    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, expired_claims)
        .await
        .unwrap();
    let result = service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, Some("knox-api"))
        .await;

    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expired token should be rejected"
    );
}

#[tokio::test]
async fn test_verify_jwt_wrong_issuer_is_rejected() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    // Mint with a different issuer
    let mint_key_repo = mock_key_repo_for_mint(tenant_id, key_id, &public_pem);
    let evil_service = make_jwt_service_with_issuer(
        MockTokenRepo::new(),
        mint_key_repo,
        &private_pem,
        "https://evil.attacker.com",
    );

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = JwtClaims {
        iss: "https://evil.attacker.com".to_string(),
        sub: Uuid::new_v4().to_string(),
        aud: "knox-api".to_string(),
        exp: now + 3600,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        client_id: Some("test-client".into()),
        amr: vec!["pwd".into()],
        acr: Some("urn:knox:loa:pwd".into()),
        auth_time: Some(now),
        tenant_id,
        pool_id: Uuid::new_v4(),
        pool_kind: PoolKind::Staff,
        scopes: vec![],
        token_version: 1,
    };

    let token = evil_service
        .mint_jwt(tenant_id, "https://evil.attacker.com", claims)
        .await
        .unwrap();

    // Verify with the legit issuer service (same key so signature is valid, but issuer differs)
    let mut verify_key_repo = MockKeyRepo::new();
    let verify_key = make_tenant_key_with_id(key_id, tenant_id, &public_pem);
    let kid_str = key_id.to_string();
    verify_key_repo
        .expect_get_by_kid()
        .withf(move |tid, k| *tid == tenant_id && k == kid_str)
        .returning(move |_, _| Ok(Some(verify_key.clone())));
    let legit_service = make_jwt_service(MockTokenRepo::new(), verify_key_repo, &private_pem);
    let result = legit_service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, Some("knox-api"))
        .await;

    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Token from a different issuer should be rejected"
    );
}

/// The reason the issuer is per-tenant: a token minted for one tenant must not
/// verify against another tenant's issuer, even when the signature is valid.
/// Without the slug in `iss`, a relying party configured for tenant B would
/// accept tenant A's token — standard OIDC clients check `iss` and the
/// signature, never our custom `tenant_id` claim.
#[tokio::test]
async fn test_verify_jwt_rejects_token_issued_for_another_tenant() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let mint_key_repo = mock_key_repo_for_mint(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), mint_key_repo, &private_pem);

    // Minted under the "acme" tenant.
    let claims = make_claims(Uuid::new_v4(), tenant_id);
    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();

    // Same deployment, same signing key, same tenant_id claim — but verified as
    // a different tenant, so the expected issuer differs.
    let mut verify_key_repo = MockKeyRepo::new();
    let verify_key = make_tenant_key_with_id(key_id, tenant_id, &public_pem);
    let kid_str = key_id.to_string();
    verify_key_repo
        .expect_get_by_kid()
        .withf(move |tid, k| *tid == tenant_id && k == kid_str)
        .returning(move |_, _| Ok(Some(verify_key.clone())));
    let verifier = make_jwt_service(MockTokenRepo::new(), verify_key_repo, &private_pem);

    let result = verifier
        .verify_jwt(tenant_id, OTHER_TENANT_ISSUER, &token, Some("knox-api"))
        .await;

    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Token issued for one tenant must not verify against another tenant's issuer"
    );
}

#[tokio::test]
async fn test_verify_jwt_wrong_audience_is_rejected() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let key_repo = mock_key_repo_for_mint_and_verify(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);
    let claims = make_claims(Uuid::new_v4(), tenant_id);
    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();

    let result = service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, Some("different-audience"))
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Token with wrong audience should be rejected"
    );
}

#[tokio::test]
async fn test_verify_jwt_no_audience_check_when_none() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let key_repo = mock_key_repo_for_mint_and_verify(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);
    let claims = make_claims(Uuid::new_v4(), tenant_id);
    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();

    // When expected_audience is None, audience validation is skipped
    let result = service
        .verify_jwt(tenant_id, TEST_ISSUER, &token, None)
        .await;
    assert!(
        result.is_ok(),
        "No audience check should succeed when None is passed"
    );
}

#[tokio::test]
async fn test_verify_jwt_tampered_token_is_rejected() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();

    let key_repo = mock_key_repo_for_mint_and_verify(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);
    let claims = make_claims(Uuid::new_v4(), tenant_id);
    let token = service
        .mint_jwt(tenant_id, TEST_ISSUER, claims)
        .await
        .unwrap();

    // Flip a character in the signature (last part)
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let sig = parts[2].clone();
    let tampered_sig: String = sig
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 0 {
                if c == 'A' { 'B' } else { 'A' }
            } else {
                c
            }
        })
        .collect();
    parts[2] = tampered_sig;
    let tampered_token = parts.join(".");

    let result = service
        .verify_jwt(tenant_id, TEST_ISSUER, &tampered_token, Some("knox-api"))
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Tampered token should be rejected"
    );
}

#[tokio::test]
async fn test_verify_jwt_garbage_input_is_rejected() {
    let tenant_id = Uuid::new_v4();
    let service = make_service(MockTokenRepo::new());

    for garbage in &["not-a-jwt", "", "a.b", "a.b.c.d"] {
        let result = service
            .verify_jwt(tenant_id, TEST_ISSUER, garbage, None)
            .await;
        assert!(
            result.is_err(),
            "Garbage input '{}' should be rejected",
            garbage
        );
    }
}

/// Replaces `test_get_issuer_returns_configured_issuer`: TokenService no longer
/// holds an issuer at all. What matters now is that the issuer supplied at mint
/// time is the one that lands in the token, so a tenant's stored issuer flows
/// through unchanged.
#[tokio::test]
async fn test_mint_uses_the_supplied_issuer_verbatim() {
    let tenant_id = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();
    let key_id = Uuid::new_v4();
    let key_repo = mock_key_repo_for_mint(tenant_id, key_id, &public_pem);
    let service = make_jwt_service(MockTokenRepo::new(), key_repo, &private_pem);

    let stored_issuer = "https://tenant-from-the-database.example";
    let token = service
        .mint_jwt(
            tenant_id,
            stored_issuer,
            make_claims(Uuid::new_v4(), tenant_id),
        )
        .await
        .unwrap();

    let payload = token.split('.').nth(1).unwrap();
    let padded = format!("{}{}", payload, "=".repeat((4 - payload.len() % 4) % 4));
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, padded).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(claims["iss"], stored_issuer);
}

// ---------------------------------------------------------------------------
// store_transient_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_store_transient_token_prefixes_key_with_kind() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    // Key should be prefixed: "auth_code:{key}"
    repo.expect_store_transient_string()
        .withf(|key: &str, _, _| key.starts_with("auth_code:"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = make_service(repo);
    let payload = TestPayload {
        value: "test".into(),
        number: 42,
    };
    let result = service
        .store_transient_token(
            TransientKind::AuthCode,
            "mykey",
            &payload,
            time::Duration::minutes(10),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_store_transient_token_uses_correct_prefix_per_kind() {
    init_tracing();
    for (kind, expected_prefix) in [
        ("auth_code", "auth_code:"),
        ("pwd_reset", "pwd_reset:"),
        ("magic_link", "magic_link:"),
    ] {
        let mut repo = MockTokenRepo::new();
        let prefix = expected_prefix.to_string();

        repo.expect_store_transient_string()
            .withf(move |key: &str, _, _| key.starts_with(&prefix))
            .times(1)
            .returning(|_, _, _| Ok(()));

        let service = make_service(repo);
        let payload = TestPayload {
            value: "x".into(),
            number: 1,
        };
        let transient_kind = match kind {
            "auth_code" => TransientKind::AuthCode,
            "pwd_reset" => TransientKind::PasswordReset,
            _ => TransientKind::MagicLink,
        };
        let _ = service
            .store_transient_token(transient_kind, "key", &payload, time::Duration::minutes(5))
            .await;
    }
}

#[tokio::test]
async fn test_store_transient_token_converts_ttl_to_seconds() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    // 10 minutes = 600 seconds
    repo.expect_store_transient_string()
        .withf(|_, _, ttl: &u64| *ttl == 600)
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = make_service(repo);
    let payload = TestPayload {
        value: "x".into(),
        number: 1,
    };
    let _ = service
        .store_transient_token(
            TransientKind::AuthCode,
            "k",
            &payload,
            time::Duration::minutes(10),
        )
        .await;
}

#[tokio::test]
async fn test_store_transient_token_serializes_payload_as_json() {
    init_tracing();
    let mut repo = MockTokenRepo::new();
    let payload = TestPayload {
        value: "hello".into(),
        number: 99,
    };

    repo.expect_store_transient_string()
        .withf(|_, json: &str, _| {
            serde_json::from_str::<TestPayload>(json)
                .map(|p| p.value == "hello" && p.number == 99)
                .unwrap_or(false)
        })
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = make_service(repo);
    let _ = service
        .store_transient_token(
            TransientKind::AuthCode,
            "k",
            &payload,
            time::Duration::minutes(5),
        )
        .await;
}

// ---------------------------------------------------------------------------
// Session epoch tests — the O(1) revocation primitive behind password change.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_current_sso_epoch_absent_reads_as_zero() {
    init_tracing();
    let tenant = Uuid::new_v4();
    let identity = Uuid::new_v4();
    let mut repo = MockTokenRepo::new();

    // A never-revoked identity has no counter; that must read as 0, the same
    // value freshly minted sessions carry, so they validate.
    repo.expect_read_transient_string()
        .withf(move |key: &str| key == format!("sso_epoch:{}:{}", tenant, identity))
        .times(1)
        .returning(|_| Ok(None));

    let service = make_service(repo);
    let epoch = service.current_sso_epoch(tenant, identity).await.unwrap();
    assert_eq!(epoch, 0);
}

#[tokio::test]
async fn test_current_sso_epoch_reads_stored_counter() {
    init_tracing();
    let mut repo = MockTokenRepo::new();
    // Redis INCR stores an integer; GET returns it as a bare string.
    repo.expect_read_transient_string()
        .times(1)
        .returning(|_| Ok(Some("7".to_string())));

    let service = make_service(repo);
    let epoch = service
        .current_sso_epoch(Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(epoch, 7);
}

#[tokio::test]
async fn test_bump_sso_epoch_increments_and_refreshes_ttl() {
    init_tracing();
    let tenant = Uuid::new_v4();
    let identity = Uuid::new_v4();
    let expected_key = format!("sso_epoch:{}:{}", tenant, identity);
    let mut repo = MockTokenRepo::new();

    let k1 = expected_key.clone();
    repo.expect_increment_transient_counter()
        .withf(move |key: &str, ttl: &u64| key == k1 && *ttl == 3600)
        .times(1)
        .returning(|_, _| Ok(3));
    // INCR sets the TTL only on creation, so the epoch is explicitly refreshed —
    // it must outlive every session that still carries the pre-bump value.
    let k2 = expected_key.clone();
    repo.expect_touch_transient()
        .withf(move |key: &str, ttl: &u64| key == k2 && *ttl == 3600)
        .times(1)
        .returning(|_, _| Ok(()));

    let service = make_service(repo);
    let next = service
        .bump_sso_epoch(tenant, identity, time::Duration::seconds(3600))
        .await
        .unwrap();
    assert_eq!(next, 3);
}

#[tokio::test]
async fn test_touch_sso_epoch_only_refreshes_ttl() {
    init_tracing();
    let mut repo = MockTokenRepo::new();
    repo.expect_touch_transient()
        .withf(|key: &str, _| key.starts_with("sso_epoch:"))
        .times(1)
        .returning(|_, _| Ok(()));

    let service = make_service(repo);
    let result = service
        .touch_sso_epoch(Uuid::new_v4(), Uuid::new_v4(), time::Duration::seconds(60))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_take_transient_token_reads_and_deletes() {
    init_tracing();
    let mut repo = MockTokenRepo::new();
    repo.expect_get_and_delete_transient_string()
        .withf(|key: &str| key.starts_with("pwd_reset:"))
        .times(1)
        .returning(|_| Ok(Some(r#"{"value":"v","number":5}"#.to_string())));

    let service = make_service(repo);
    let got: Option<TestPayload> = service
        .take_transient_token(TransientKind::PasswordReset, "abc")
        .await
        .unwrap();
    assert_eq!(
        got,
        Some(TestPayload {
            value: "v".into(),
            number: 5
        })
    );
}

#[tokio::test]
async fn test_store_transient_token_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_store_transient_string()
        .times(1)
        .returning(|_, _, _| Err(RepositoryError::Database("Redis down".into())));

    let service = make_service(repo);
    let payload = TestPayload {
        value: "x".into(),
        number: 1,
    };
    let result = service
        .store_transient_token(
            TransientKind::AuthCode,
            "k",
            &payload,
            time::Duration::minutes(5),
        )
        .await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// retrieve_transient_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_retrieve_transient_token_found() {
    init_tracing();
    let mut repo = MockTokenRepo::new();
    let payload = TestPayload {
        value: "hello".into(),
        number: 42,
    };
    let json = serde_json::to_string(&payload).unwrap();

    repo.expect_read_transient_string()
        .withf(|key: &str| key.starts_with("auth_code:"))
        .times(1)
        .return_once(move |_| Ok(Some(json)));

    let service = make_service(repo);
    let result: Option<TestPayload> = service
        .retrieve_transient_token(TransientKind::AuthCode, "mykey")
        .await
        .unwrap();

    assert!(result.is_some());
    let retrieved = result.unwrap();
    assert_eq!(retrieved.value, "hello");
    assert_eq!(retrieved.number, 42);
}

#[tokio::test]
async fn test_retrieve_transient_token_not_found_returns_none() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_read_transient_string()
        .times(1)
        .return_once(|_| Ok(None));

    let service = make_service(repo);
    let result: Option<TestPayload> = service
        .retrieve_transient_token(TransientKind::AuthCode, "missing")
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_retrieve_transient_token_prefixes_key_with_kind() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_read_transient_string()
        .withf(|key: &str| key == "pwd_reset:reset-key-123")
        .times(1)
        .return_once(|_| Ok(None));

    let service = make_service(repo);
    let _: Option<TestPayload> = service
        .retrieve_transient_token(TransientKind::PasswordReset, "reset-key-123")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_retrieve_transient_token_corrupt_json_returns_internal_error() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_read_transient_string()
        .times(1)
        .return_once(|_| Ok(Some("not valid json {{{".to_string())));

    let service = make_service(repo);
    let result: Result<Option<TestPayload>, _> = service
        .retrieve_transient_token(TransientKind::AuthCode, "k")
        .await;

    assert!(
        matches!(result, Err(ServiceError::Internal(_))),
        "Corrupt JSON should return an Internal error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_retrieve_transient_token_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_read_transient_string()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Redis down".into())));

    let service = make_service(repo);
    let result: Result<Option<TestPayload>, _> = service
        .retrieve_transient_token(TransientKind::AuthCode, "k")
        .await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

#[tokio::test]
async fn test_store_and_retrieve_round_trip() {
    // Verifies that a stored payload can be retrieved with the same key and kind
    init_tracing();
    let payload = TestPayload {
        value: "round-trip".into(),
        number: 7,
    };
    let json = serde_json::to_string(&payload).unwrap();
    let json_clone = json.clone();

    let mut repo = MockTokenRepo::new();

    repo.expect_store_transient_string()
        .with(eq("magic_link:verify-abc"), always(), eq(300u64))
        .times(1)
        .returning(|_, _, _| Ok(()));

    repo.expect_read_transient_string()
        .with(eq("magic_link:verify-abc"))
        .times(1)
        .return_once(move |_| Ok(Some(json_clone)));

    let service = make_service(repo);

    service
        .store_transient_token(
            TransientKind::MagicLink,
            "verify-abc",
            &payload,
            time::Duration::minutes(5),
        )
        .await
        .unwrap();

    let retrieved: Option<TestPayload> = service
        .retrieve_transient_token(TransientKind::MagicLink, "verify-abc")
        .await
        .unwrap();

    assert_eq!(retrieved.unwrap(), payload);
}

// ---------------------------------------------------------------------------
// save_refresh_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_save_refresh_token_delegates_to_repo() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let token = make_refresh_token(tenant_id, Uuid::new_v4());
    let cloned = token.clone();
    let mut repo = MockTokenRepo::new();

    repo.expect_save_refresh_token()
        .times(1)
        .return_once(move |_| Ok(cloned));

    let service = make_service(repo);
    let result = service.save_refresh_token(&token).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, token.id);
}

#[tokio::test]
async fn test_save_refresh_token_repo_error_propagates() {
    init_tracing();
    let token = make_refresh_token(Uuid::new_v4(), Uuid::new_v4());
    let mut repo = MockTokenRepo::new();

    repo.expect_save_refresh_token()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo);
    let result = service.save_refresh_token(&token).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// get_refresh_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_refresh_token_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let token = make_refresh_token(tenant_id, Uuid::new_v4());
    let hash = token.token_hash.clone();
    let cloned = token.clone();
    let mut repo = MockTokenRepo::new();

    repo.expect_get_refresh_token()
        .with(eq(tenant_id), eq(hash.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    let service = make_service(repo);
    let result = service.get_refresh_token(tenant_id, &hash).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, token.id);
}

#[tokio::test]
async fn test_get_refresh_token_not_found_returns_none() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_get_refresh_token()
        .times(1)
        .return_once(|_, _| Ok(None));

    let service = make_service(repo);
    let result = service.get_refresh_token(Uuid::new_v4(), "unknown").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_refresh_token_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_get_refresh_token()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo);
    let result = service.get_refresh_token(Uuid::new_v4(), "hash").await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// revoke_refresh_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_refresh_token_success() {
    init_tracing();
    let id = Uuid::new_v4();
    let mut repo = MockTokenRepo::new();

    repo.expect_revoke_refresh_token()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));

    let service = make_service(repo);
    let result = service.revoke_refresh_token(id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_refresh_token_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_revoke_refresh_token()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo);
    let result = service.revoke_refresh_token(Uuid::new_v4()).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// revoke_token_family tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_token_family_success() {
    init_tracing();
    let family_id = Uuid::new_v4();
    let mut repo = MockTokenRepo::new();

    repo.expect_revoke_token_family()
        .with(eq(family_id))
        .times(1)
        .returning(|_| Ok(()));

    let service = make_service(repo);
    let result = service.revoke_token_family(family_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_token_family_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_revoke_token_family()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo);
    let result = service.revoke_token_family(Uuid::new_v4()).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// revoke_all_for_identity tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_all_for_identity_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let mut repo = MockTokenRepo::new();

    repo.expect_revoke_all_for_identity()
        .with(eq(tenant_id), eq(identity_id))
        .times(1)
        .returning(|_, _| Ok(()));

    let service = make_service(repo);
    let result = service
        .revoke_all_for_identity(tenant_id, identity_id)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_all_for_identity_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTokenRepo::new();

    repo.expect_revoke_all_for_identity()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo);
    let result = service
        .revoke_all_for_identity(Uuid::new_v4(), Uuid::new_v4())
        .await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}
