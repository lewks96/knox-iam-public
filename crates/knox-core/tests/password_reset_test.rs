//! Security-critical coverage for the MFA-aware password reset flow.
//!
//! The properties that matter here, and are hard to eyeball:
//!   * a reset never sets the password while an enrolled second factor stands in
//!     the way — it hands back a challenge instead;
//!   * a login MFA token cannot complete a reset, and a reset MFA token cannot
//!     complete a login (scope isolation);
//!   * a reset token is single-use and bound to its tenant.
//!
//! The happy path where a *correct* MFA code finishes a reset needs real TOTP
//! secret decryption and is exercised end-to-end in the browser instead; these
//! tests deliberately stop at the point each guard fires.

use async_trait::async_trait;
use knox_common::audit::AuditContext;
use knox_common::authorization::{AuthorizationRepository, Role, RoleKind};
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::identity::{
    Identity, IdentityFilter, IdentityHandle, IdentityKind, IdentityRepository, IdentityUpdates,
    MfaOption, Status,
};
use knox_common::key::{
    CreateKeyParams, KeyEncryptionError, KeyEncryptionProvider, KeyRepository, KeyState, TenantKey,
};
use knox_common::mfa::{MfaMethod, MfaMethodKind, MfaRepository, NewMfaMethod};
use knox_common::tenant::TenantConfiguration;
use knox_common::token::{AuthCodeContext, RefreshToken, TokenRepository};
use knox_core::audit::AuditService;
use knox_core::authentication::{
    AuthenticationService, MFA_SCOPE, PWD_RESET_MFA_SCOPE, PasswordResetContext,
    PasswordResetOutcome,
};
use knox_core::identity::IdentityService;
use knox_core::key::KeyService;
use knox_core::mfa::MfaService;
use knox_core::token::TokenService;
use mockall::{mock, predicate::*};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use spki::EncodePublicKey;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub IdentityRepo {}
    #[async_trait]
    impl IdentityRepository for IdentityRepo {
        async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError>;
        async fn get(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<Option<Identity>, RepositoryError>;
        async fn delete(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<(), RepositoryError>;
        async fn update(&self, pool_id: Uuid, handle: IdentityHandle, updates: &IdentityUpdates) -> Result<Identity, RepositoryError>;
        async fn exists(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<bool, RepositoryError>;
        async fn list(&self, filter: IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError>;
        async fn count(&self, tenant_id: Uuid, filter: Option<String>) -> Result<u64, RepositoryError>;
    }
}

mock! {
    pub AuthRepo {}
    #[async_trait]
    impl AuthorizationRepository for AuthRepo {
        async fn create_role(&self, tenant_id: Uuid, name: &str, permissions: &Vec<String>, kind: RoleKind) -> Result<Role, RepositoryError>;
        async fn get_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Option<Role>, RepositoryError>;
        async fn delete_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;
        async fn assign_role(&self, tenant_id: Uuid, identity_id: Uuid, role_name: &str) -> Result<(), RepositoryError>;
        async fn remove_role(&self, tenant_id: Uuid, identity_id: Uuid, role_name: &str) -> Result<(), RepositoryError>;
        async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError>;
        async fn get_identity_roles(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
        async fn get_permissions(&self, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
    }
}

mock! {
    pub TokenRepo {}
    #[async_trait]
    #[allow(deprecated)]
    impl TokenRepository for TokenRepo {
        async fn store_transient_string(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), RepositoryError>;
        async fn read_transient_string(&self, key: &str) -> Result<Option<String>, RepositoryError>;
        async fn get_and_delete_transient_string(&self, key: &str) -> Result<Option<String>, RepositoryError>;
        async fn increment_transient_counter(&self, key: &str, ttl_seconds: u64) -> Result<u64, RepositoryError>;
        async fn touch_transient(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError>;
        async fn save_auth_code(&self, hashed_code: &str, context: &AuthCodeContext, ttl_seconds: u64) -> Result<(), RepositoryError>;
        async fn exchange_auth_code(&self, hashed_code: &str) -> Result<Option<AuthCodeContext>, RepositoryError>;
        async fn save_refresh_token(&self, token: &RefreshToken) -> Result<RefreshToken, RepositoryError>;
        async fn get_refresh_token(&self, tenant_id: Uuid, token_hash: &str) -> Result<Option<RefreshToken>, RepositoryError>;
        async fn revoke_refresh_token(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_all_for_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), RepositoryError>;
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

mock! {
    pub MfaRepo {}
    #[async_trait]
    impl MfaRepository for MfaRepo {
        async fn create_method(&self, method: &NewMfaMethod) -> Result<MfaMethod, RepositoryError>;
        async fn get_method(&self, tenant_id: Uuid, identity_id: Uuid, method_id: Uuid) -> Result<Option<MfaMethod>, RepositoryError>;
        async fn get_method_by_kind(&self, tenant_id: Uuid, identity_id: Uuid, kind: MfaMethodKind) -> Result<Option<MfaMethod>, RepositoryError>;
        async fn list_methods(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<MfaMethod>, RepositoryError>;
        async fn list_verified_methods(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<MfaMethod>, RepositoryError>;
        async fn mark_verified(&self, tenant_id: Uuid, method_id: Uuid) -> Result<MfaMethod, RepositoryError>;
        async fn delete_method(&self, tenant_id: Uuid, identity_id: Uuid, method_id: Uuid) -> Result<(), RepositoryError>;
        async fn claim_totp_step(&self, tenant_id: Uuid, method_id: Uuid, step: i64) -> Result<bool, RepositoryError>;
        async fn replace_backup_codes(&self, tenant_id: Uuid, identity_id: Uuid, code_hashes: &[String]) -> Result<(), RepositoryError>;
        async fn consume_backup_code(&self, tenant_id: Uuid, identity_id: Uuid, code_hash: &str) -> Result<bool, RepositoryError>;
        async fn count_unused_backup_codes(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<u64, RepositoryError>;
        async fn delete_backup_codes(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), RepositoryError>;
    }
}

/// KMS mock that returns a fixed plaintext on decrypt — the tenant's RSA private
/// PEM — so JWT signing and verification work end to end. TOTP secret decryption
/// is deliberately not meaningful here; no test reaches a successful code check.
struct MockKms {
    decrypt_result: String,
}

#[async_trait]
impl KeyEncryptionProvider for MockKms {
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_ISSUER: &str = "https://acme.knox.dev";

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

type TestAuthService = AuthenticationService<
    MockIdentityRepo,
    MockAuthRepo,
    MockTokenRepo,
    MockKeyRepo,
    MockKms,
    MockMfaRepo,
>;

fn generate_rsa_keypair() -> (String, String) {
    let private_key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("RSA keygen");
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    (private_pem, public_pem)
}

fn make_tenant_key(tenant_id: Uuid, public_pem: &str) -> TenantKey {
    let id = Uuid::new_v4();
    TenantKey {
        id,
        tenant_id,
        kid: id.to_string(),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem: public_pem.to_string(),
        x509_cert_pem: None,
        encrypted_private_key: vec![1, 2, 3],
        state: KeyState::Active,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(365),
    }
}

/// A key repo that hands back the same signing key for both minting
/// (`get_active_for_tenant`) and verification (`get_by_kid`).
fn signing_key_repo(tenant_id: Uuid, public_pem: &str) -> MockKeyRepo {
    let key = make_tenant_key(tenant_id, public_pem);
    let mut repo = MockKeyRepo::new();
    let k1 = key.clone();
    repo.expect_get_active_for_tenant()
        .returning(move |_| Ok(Some(k1.clone())));
    let k2 = key.clone();
    repo.expect_get_by_kid()
        .returning(move |_, _| Ok(Some(k2.clone())));
    repo
}

fn build_service(
    id_repo: MockIdentityRepo,
    token_repo: MockTokenRepo,
    key_repo: MockKeyRepo,
    mfa_repo: MockMfaRepo,
    private_pem: &str,
) -> TestAuthService {
    let identity_service = IdentityService::new(id_repo, MockAuthRepo::new());
    let key_service = KeyService::new(
        key_repo,
        MockKms {
            decrypt_result: private_pem.to_string(),
        },
    );
    let token_service = TokenService::new(token_repo, key_service);
    let mfa_service = MfaService::new(
        mfa_repo,
        MockKms {
            decrypt_result: private_pem.to_string(),
        },
    );
    let (audit, _rx) = AuditService::new(1024);
    // Receiver dropped: `record` uses try_send and is non-fatal without one.
    std::mem::forget(_rx);
    AuthenticationService::new(identity_service, token_service, mfa_service, audit)
}

fn make_identity(pool_id: Uuid, identity_id: Uuid) -> Identity {
    Identity {
        id: identity_id,
        tenant_id: Uuid::new_v4(),
        pool_id,
        kind: IdentityKind::Human,
        username: "user".into(),
        email: Some("user@example.com".into()),
        password_hash: Some("$argon2id$v=19$m=1,t=1,p=1$abc$abc".into()),
        email_verified: true,
        first_name: None,
        last_name: None,
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        status: Status::Active,
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

fn make_totp_method(tenant_id: Uuid, identity_id: Uuid) -> MfaMethod {
    MfaMethod {
        id: Uuid::new_v4(),
        tenant_id,
        identity_id,
        method: MfaMethodKind::Totp,
        secret_enc: Some(vec![1, 2, 3]),
        public_data: serde_json::json!({"algorithm": "SHA1", "digits": 6, "step": 30}),
        last_used_step: None,
        verified_at: Some(OffsetDateTime::now_utc()),
        last_used_at: None,
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

fn reset_context_json(tenant_id: Uuid, pool_id: Uuid, identity_id: Uuid) -> String {
    serde_json::to_string(&PasswordResetContext {
        tenant_id,
        pool_id,
        identity_id,
        created_at: OffsetDateTime::now_utc(),
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// No second factor: the reset sets the password and revokes sessions.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reset_without_mfa_sets_password_and_revokes_sessions() {
    init_tracing();
    let tenant = Uuid::new_v4();
    let pool = Uuid::new_v4();
    let identity = Uuid::new_v4();

    let mut token_repo = MockTokenRepo::new();
    // Presenting the token consumes it (get_and_delete), single-use.
    token_repo
        .expect_get_and_delete_transient_string()
        .withf(|key: &str| key.starts_with("pwd_reset:"))
        .times(1)
        .returning(move |_| Ok(Some(reset_context_json(tenant, pool, identity))));
    // Session revocation: refresh tokens killed, epoch bumped + kept alive.
    token_repo
        .expect_revoke_all_for_identity()
        .times(1)
        .returning(|_, _| Ok(()));
    token_repo
        .expect_increment_transient_counter()
        .withf(|key: &str, _| key.starts_with("sso_epoch:"))
        .times(1)
        .returning(|_, _| Ok(1));
    token_repo.expect_touch_transient().returning(|_, _| Ok(()));

    let mut mfa_repo = MockMfaRepo::new();
    // No verified method → MFA not required.
    mfa_repo
        .expect_list_verified_methods()
        .returning(|_, _| Ok(vec![]));

    let mut id_repo = MockIdentityRepo::new();
    // set_password writes the new hash.
    id_repo
        .expect_update()
        .withf(|_, _, updates: &IdentityUpdates| updates.password_hash.is_some())
        .times(1)
        .returning(move |_, _, _| Ok(make_identity(pool, identity)));

    let (private_pem, _public_pem) = generate_rsa_keypair();
    let service = build_service(
        id_repo,
        token_repo,
        MockKeyRepo::new(),
        mfa_repo,
        &private_pem,
    );

    let outcome = service
        .reset_password_with_token(
            tenant,
            TEST_ISSUER,
            "raw-reset-token",
            "brand-new-password",
            &TenantConfiguration::default(),
            &AuditContext::default(),
        )
        .await
        .expect("reset should succeed");

    assert!(matches!(outcome, PasswordResetOutcome::Completed));
}

// ---------------------------------------------------------------------------
// Second factor enrolled: the reset returns a challenge and does NOT touch the
// password. (No expect_update on the identity repo — a call would panic.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reset_with_mfa_returns_challenge_and_leaves_password_untouched() {
    init_tracing();
    let tenant = Uuid::new_v4();
    let pool = Uuid::new_v4();
    let identity = Uuid::new_v4();

    let mut token_repo = MockTokenRepo::new();
    token_repo
        .expect_get_and_delete_transient_string()
        .times(1)
        .returning(move |_| Ok(Some(reset_context_json(tenant, pool, identity))));
    // No revocation on this branch: nothing has changed yet.

    let mut mfa_repo = MockMfaRepo::new();
    mfa_repo
        .expect_list_verified_methods()
        .returning(move |_, _| Ok(vec![make_totp_method(tenant, identity)]));
    mfa_repo
        .expect_count_unused_backup_codes()
        .returning(|_, _| Ok(0));

    // No expect_update: if the password were written, the strict mock panics.
    let id_repo = MockIdentityRepo::new();

    let (private_pem, public_pem) = generate_rsa_keypair();
    let service = build_service(
        id_repo,
        token_repo,
        signing_key_repo(tenant, &public_pem),
        mfa_repo,
        &private_pem,
    );

    let outcome = service
        .reset_password_with_token(
            tenant,
            TEST_ISSUER,
            "raw-reset-token",
            "brand-new-password",
            &TenantConfiguration::default(),
            &AuditContext::default(),
        )
        .await
        .expect("reset should return a challenge");

    match outcome {
        PasswordResetOutcome::MfaRequired(details) => {
            assert!(details.options.contains(&MfaOption::Totp));
        }
        PasswordResetOutcome::Completed => panic!("password was set despite an enrolled factor"),
    }
}

// ---------------------------------------------------------------------------
// A reset token is single-use and tenant-bound.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reset_token_replay_is_rejected() {
    init_tracing();
    let mut token_repo = MockTokenRepo::new();
    // Already consumed → gone.
    token_repo
        .expect_get_and_delete_transient_string()
        .times(1)
        .returning(|_| Ok(None));

    let (private_pem, _public_pem) = generate_rsa_keypair();
    let service = build_service(
        MockIdentityRepo::new(),
        token_repo,
        MockKeyRepo::new(),
        MockMfaRepo::new(),
        &private_pem,
    );

    let err = service
        .reset_password_with_token(
            Uuid::new_v4(),
            TEST_ISSUER,
            "spent-token",
            "brand-new-password",
            &TenantConfiguration::default(),
            &AuditContext::default(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, ServiceError::InvalidResetToken));
}

#[tokio::test]
async fn reset_token_for_another_tenant_is_rejected() {
    init_tracing();
    let token_tenant = Uuid::new_v4();
    let request_tenant = Uuid::new_v4();
    let pool = Uuid::new_v4();
    let identity = Uuid::new_v4();

    let mut token_repo = MockTokenRepo::new();
    token_repo
        .expect_get_and_delete_transient_string()
        .times(1)
        .returning(move |_| Ok(Some(reset_context_json(token_tenant, pool, identity))));

    let (private_pem, _public_pem) = generate_rsa_keypair();
    let service = build_service(
        MockIdentityRepo::new(),
        token_repo,
        MockKeyRepo::new(),
        MockMfaRepo::new(),
        &private_pem,
    );

    let err = service
        .reset_password_with_token(
            request_tenant, // different tenant than the token was minted for
            TEST_ISSUER,
            "cross-tenant-token",
            "brand-new-password",
            &TenantConfiguration::default(),
            &AuditContext::default(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, ServiceError::InvalidResetToken));
}

// ---------------------------------------------------------------------------
// Scope isolation: the login and reset challenges are not interchangeable.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_mfa_token_cannot_complete_a_reset() {
    init_tracing();
    let tenant = Uuid::new_v4();
    let pool = Uuid::new_v4();
    let identity = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();

    let service = build_service(
        MockIdentityRepo::new(),
        MockTokenRepo::new(),
        signing_key_repo(tenant, &public_pem),
        MockMfaRepo::new(),
        &private_pem,
    );

    // A genuine *login* challenge (MFA_SCOPE).
    let details = service
        .mint_mfa_challenge(
            tenant,
            pool,
            TEST_ISSUER,
            identity,
            MFA_SCOPE,
            vec![MfaOption::Totp],
            &TenantConfiguration::default(),
        )
        .await
        .unwrap();

    // Presented to the reset completion, which demands PWD_RESET_MFA_SCOPE.
    let err = service
        .complete_password_reset_mfa(
            tenant,
            TEST_ISSUER,
            &details.token,
            MfaOption::Totp,
            "000000",
            "brand-new-password",
            &TenantConfiguration::default(),
            &AuditContext::default(),
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidMfaToken),
        "a login token must not be spendable to reset a password"
    );
}

#[tokio::test]
async fn reset_mfa_token_cannot_complete_a_login() {
    init_tracing();
    let tenant = Uuid::new_v4();
    let pool = Uuid::new_v4();
    let identity = Uuid::new_v4();
    let (private_pem, public_pem) = generate_rsa_keypair();

    let service = build_service(
        MockIdentityRepo::new(),
        MockTokenRepo::new(),
        signing_key_repo(tenant, &public_pem),
        MockMfaRepo::new(),
        &private_pem,
    );

    // A genuine *reset* challenge (PWD_RESET_MFA_SCOPE).
    let details = service
        .mint_mfa_challenge(
            tenant,
            pool,
            TEST_ISSUER,
            identity,
            PWD_RESET_MFA_SCOPE,
            vec![MfaOption::Totp],
            &TenantConfiguration::default(),
        )
        .await
        .unwrap();

    // Presented to the login completion, which demands MFA_SCOPE.
    let err = service
        .authenticate_user_mfa(
            tenant,
            pool,
            TEST_ISSUER,
            &details.token,
            MfaOption::Totp,
            "000000",
            &TenantConfiguration::default(),
            &AuditContext::default(),
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, ServiceError::InvalidMfaToken),
        "a reset token must not mint a session"
    );
}
