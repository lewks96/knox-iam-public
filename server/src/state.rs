use knox_core::audit::AuditService;
use knox_core::authentication::AuthenticationService;
use knox_core::key::{KeyService, LocalKeyEncryptionProvider};
use knox_core::mfa::MfaService;
use knox_core::tenant::TenantService;
use knox_core::{client::ClientService, identity::IdentityService, token::TokenService};
use knox_services::OIDCService;
use knox_storage::audit::repository::KnoxAuditRepository;
use knox_storage::audit::store::PgAuditStore;
use knox_storage::authorization::cache::RedisAuthorizationCache;
use knox_storage::authorization::repository::KnoxAuthorizationRepository;
use knox_storage::authorization::store::PgAuthorizationStore;
use knox_storage::client::cache::RedisClientCache;
use knox_storage::client::repository::KnoxClientRepository;
use knox_storage::client::store::PgClientStore;
use knox_storage::identity::cache::RedisIdentityCache;
use knox_storage::identity::repository::KnoxIdentityRepository;
use knox_storage::identity::store::PgIdentityStore;
use knox_storage::key::cache::RedisKeyCache;
use knox_storage::key::repository::KnoxKeyRepository;
use knox_storage::key::store::PgKeyStore;
use knox_storage::mfa::cache::RedisMfaCache;
use knox_storage::mfa::repository::KnoxMfaRepository;
use knox_storage::mfa::store::PgMfaStore;
use knox_storage::pool::PgPoolStore;
use knox_storage::tenant::cache::RedisTenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::PgTenantStore;
use knox_storage::token::cache::RedisAuthCodeCache;
use knox_storage::token::repository::KnoxTokenRepository;
use knox_storage::token::store::PgRefreshTokenStore;
use std::sync::Arc;

pub type AppIdentityRepo = KnoxIdentityRepository<PgIdentityStore, RedisIdentityCache>;
pub type AppClientRepo = KnoxClientRepository<PgClientStore, RedisClientCache>;
pub type AppTokenRepo = KnoxTokenRepository<RedisAuthCodeCache, PgRefreshTokenStore>;
pub type AppAuthRepo = KnoxAuthorizationRepository<PgAuthorizationStore, RedisAuthorizationCache>;
pub type AppTenantRepo = KnoxTenantRepository<PgTenantStore, RedisTenantCache>;
pub type AppKeyRepo = KnoxKeyRepository<PgKeyStore, RedisKeyCache>;
pub type AppKeyProvider = LocalKeyEncryptionProvider;
pub type AppMfaRepo = KnoxMfaRepository<PgMfaStore, RedisMfaCache>;
pub type AppAuditRepo = KnoxAuditRepository<PgAuditStore>;
pub type AppPoolRepo = PgPoolStore;
pub type AppOIDCService = OIDCService<
    AppIdentityRepo,
    AppAuthRepo,
    AppClientRepo,
    AppTokenRepo,
    AppKeyRepo,
    AppKeyProvider,
    AppMfaRepo,
    AppPoolRepo,
>;

pub struct AppState {
    pub identity_service: IdentityService<AppIdentityRepo, AppAuthRepo>,
    pub client_service: ClientService<AppClientRepo>,
    pub token_service: TokenService<AppTokenRepo, AppKeyRepo, AppKeyProvider>,
    pub tenant_service: TenantService<
        AppTenantRepo,
        AppAuthRepo,
        AppKeyRepo,
        AppKeyProvider,
        AppClientRepo,
        AppIdentityRepo,
        AppPoolRepo,
    >,
    pub key_service: KeyService<AppKeyRepo, AppKeyProvider>,
    pub mfa_service: MfaService<AppMfaRepo, AppKeyProvider>,
    pub auth_service: AuthenticationService<
        AppIdentityRepo,
        AppAuthRepo,
        AppTokenRepo,
        AppKeyRepo,
        AppKeyProvider,
        AppMfaRepo,
    >,
    pub oidc_service: AppOIDCService,
    /// Write side of the audit log (buffered; see run_audit_writer).
    pub audit_service: AuditService,
    /// Read side for the tenant audit query API.
    pub audit_repo: AppAuditRepo,
}

pub type SharedState = Arc<AppState>;
