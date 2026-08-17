//! Knox Bootstrap CLI
//!
//! Bootstraps the Knox IAM platform by creating the `knox-root` tenant with:
//!   - An M2M client ("management") supporting both client_credentials AND
//!     authorization_code (PKCE) so the management UI can log in
//!   - An admin user for human login via the Knox management UI
//!
//! Designed to run as a one-shot Kubernetes Job. All inputs come from environment
//! variables so no interactive prompts or port-forwarding is required.
//!
//! Environment variables:
//!   DATABASE_URL        — postgres connection string      (required)
//!   REDIS_URL           — redis connection string         (required)
//!   AES_MASTER_KEY      — base64-encoded 32-byte AES key  (required)
//!   KNOX_HOST           — public base URL, no trailing slash
//!                         e.g. https://knox.example.com or http://localhost:8080
//!                         (default: http://localhost:8080)
//!   KNOX_HOSTS          — comma-separated list of public base URLs for which
//!                         to register OAuth redirect URIs. Use this when the
//!                         platform is reachable on more than one hostname
//!                         (e.g. "https://knox-local:8443,https://gentoo-vm:8443").
//!                         If set, takes precedence over KNOX_HOST.
//!   ADMIN_EMAIL         — admin user email  (default: admin@knox.local)
//!   ADMIN_PASSWORD      — admin user password (auto-generated if absent)
//!   ADMIN_FIRST_NAME    — admin first name   (optional)
//!   ADMIN_LAST_NAME     — admin last name    (optional)

use clap::Parser;
use knox_common::error::ServiceError;
use knox_core::client::ClientService;
use knox_core::identity::IdentityService;
use knox_core::key::{KeyService, LocalKeyEncryptionProvider};
use knox_core::tenant::IssuerConfig;
use knox_core::tenant::{AdminUserRequest, CreateTenantRequest, TenantService};
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
use knox_storage::pool::PgPoolStore;
use knox_storage::tenant::cache::RedisTenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::PgTenantStore;
use sqlx::postgres::PgPoolOptions;
use std::{env, time::Duration};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

pub const ROOT_TENANT_NAME: &str = "Knox Root";
pub const ROOT_TENANT_SLUG: &str = "knox-root";

use knox_core::roles::{TENANT_CREATE_SCOPE, platform_admin_role};

/// Reported in the bootstrap output for operator reference. The management
/// client's actual allowed_scopes is derived from the roles `create_tenant`
/// provisions, not from this.
fn root_client_scopes() -> Vec<String> {
    let mut scopes = vec![TENANT_CREATE_SCOPE.to_string()];
    scopes.extend(platform_admin_role().scopes().iter().cloned());
    scopes
}

#[derive(Parser, Debug)]
#[command(name = "knox-bootstrap")]
#[command(about = "Bootstrap Knox IAM with a root tenant, M2M client, and admin user")]
#[command(version)]
struct Args {
    /// Output format: "json" (machine-readable, default) or "text" (human-readable).
    /// JSON emits a single line to stdout — easy to capture via `kubectl logs`.
    #[arg(long, default_value = "json")]
    output: String,
}

#[derive(serde::Serialize)]
struct BootstrapOutput {
    tenant_id: Uuid,
    tenant_slug: String,
    knox_host: String,
    /// M2M client — supports both client_credentials (M2M) and
    /// authorization_code+PKCE (UI login).
    m2m_client_id: String,
    m2m_client_secret: String,
    /// Registered redirect URIs on the management client.
    redirect_uris: Vec<String>,
    /// Human admin — use to log in at /<tenant_slug>/login in the UI.
    admin_email: String,
    /// Only present when ADMIN_PASSWORD was not supplied and was auto-generated.
    admin_password_generated: Option<String>,
    scopes: Vec<String>,
}

/// Generate a random password without adding any new dependencies.
/// Combines process entropy and time to produce a 24-char string that
/// meets typical "upper + lower + digit + symbol" password policies.
fn generate_password() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let pid = std::process::id();

    let mut h = DefaultHasher::new();
    nanos.hash(&mut h);
    pid.hash(&mut h);
    let a = h.finish();
    nanos.wrapping_add(1).hash(&mut h);
    let b = h.finish();
    nanos.wrapping_add(2).hash(&mut h);
    let c = h.finish();

    // 24 hex chars mixed-case + suffix satisfies most password policies
    format!("{:08X}{:08x}{:08X}@1", a as u32, b as u32, c as u32)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let log_level = env::var("KNOX_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    // ── Redirect URI ──────────────────────────────────────────────────────────
    // The root tenant lives on its own subdomain, so its callback is at the root
    // of that host. Derived from the same three vars the server mints issuers
    // from, so bootstrap and the server always agree.
    //
    //   KNOX_SCHEME=https KNOX_BASE_DOMAIN=knox.example.com
    //     → https://knox-root.knox.example.com/callback
    //
    // The old KNOX_HOST/KNOX_HOSTS list existed only to cover several hostnames
    // for one deployment (knox-local, gentoo-vm, localhost); with wildcard DNS
    // each tenant has exactly one canonical host, so it is gone.
    let issuer_config = IssuerConfig::from_env();
    let knox_host = issuer_config.issuer_for_slug(ROOT_TENANT_SLUG);
    let redirect_uris: Vec<String> = vec![format!("{}/callback", knox_host)];
    let redirect_uri = redirect_uris.first().cloned().unwrap_or_default();

    info!("Root tenant host: {}", knox_host);
    info!("Management client redirect URIs: {:?}", redirect_uris);

    // ── Admin user config ─────────────────────────────────────────────────────
    let admin_email = env::var("ADMIN_EMAIL").unwrap_or_else(|_| "admin@knox.local".to_string());

    let (admin_password, password_was_generated) = match env::var("ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => (p, false),
        _ => {
            warn!("ADMIN_PASSWORD not set — generating a random password");
            (generate_password(), true)
        }
    };

    let admin_first_name = env::var("ADMIN_FIRST_NAME").ok();
    let admin_last_name = env::var("ADMIN_LAST_NAME").ok();

    // ── Infrastructure ────────────────────────────────────────────────────────
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let master_key = env::var("AES_MASTER_KEY").expect("AES_MASTER_KEY must be set");

    info!("Knox Bootstrap — connecting to infrastructure…");

    let redis_client = redis::Client::open(redis_url)?;
    let redis_manager = redis_client.get_connection_manager().await?;
    info!("Redis connected");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;
    info!("PostgreSQL connected");

    info!("Running database migrations…");
    sqlx::migrate!("../migrations").run(&pool).await?;
    info!("Migrations complete");

    // ── Services ──────────────────────────────────────────────────────────────
    let tenant_repo = KnoxTenantRepository::new(
        PgTenantStore::new(pool.clone()),
        RedisTenantCache::new(redis_manager.clone()),
    );
    let client_repo = KnoxClientRepository::new(
        PgClientStore::new(pool.clone()),
        RedisClientCache::new(redis_manager.clone()),
    );
    let auth_repo = KnoxAuthorizationRepository::new(
        PgAuthorizationStore::new(pool.clone()),
        RedisAuthorizationCache::new(redis_manager.clone()),
    );
    let identity_repo = KnoxIdentityRepository::new(
        PgIdentityStore::new(pool.clone(), pool.clone()),
        RedisIdentityCache::new(redis_manager.clone()),
    );
    let key_repo = KnoxKeyRepository::new(
        PgKeyStore::new(pool.clone()),
        RedisKeyCache::new(redis_manager.clone()),
    );
    let pool_repo = PgPoolStore::new(pool.clone());
    let key_provider = LocalKeyEncryptionProvider::from_base64(&master_key)
        .expect("Failed to initialise master key");

    let key_service = KeyService::new(key_repo, key_provider);
    let client_service = ClientService::new(client_repo);
    let identity_service = IdentityService::new(identity_repo, auth_repo.clone());
    let tenant_service = TenantService::new(
        tenant_repo,
        pool_repo,
        auth_repo,
        key_service,
        client_service,
        identity_service,
        issuer_config.clone(),
    );

    // ── Bootstrap ─────────────────────────────────────────────────────────────
    info!("Creating root tenant '{}'…", ROOT_TENANT_SLUG);

    let result = tenant_service
        .create_tenant(CreateTenantRequest {
            name: ROOT_TENANT_NAME.to_string(),
            slug: ROOT_TENANT_SLUG.to_string(),
            description: Some(
                "Knox Root Tenant — platform provisioning and management".to_string(),
            ),
            management_redirect_uris: Some(redirect_uris.clone()),
            admin_user: Some(AdminUserRequest {
                email: admin_email.clone(),
                password: admin_password.clone(),
                first_name: admin_first_name,
                last_name: admin_last_name,
            }),
            // The one tenant that owns cross-tenant operations. Everything
            // Platform*-scoped is reachable only from here.
            is_platform: true,
        })
        .await;

    let (tenant, client_secret) = match result {
        Ok(r) => {
            info!("Root tenant created (id={})", r.tenant.id);
            (
                r.tenant,
                r.admin_client_secret.expect("client secret must exist"),
            )
        }
        // Already bootstrapped — exit cleanly so the K8s Job completes
        // rather than entering a CrashLoopBackOff on re-deploy.
        Err(ServiceError::Repository(ref e)) if e.to_string().contains("duplicate") => {
            warn!("Root tenant already exists — bootstrap was previously run, exiting cleanly.");
            std::process::exit(0);
        }
        Err(ServiceError::Validation(ref msg)) if msg.contains("Reserved") => {
            error!("Tenant name blocked by reserved-name validation");
            return Err("Reserved tenant name".into());
        }
        Err(e) => {
            error!("Failed to create root tenant: {:?}", e);
            return Err(e.into());
        }
    };

    let output = BootstrapOutput {
        tenant_id: tenant.id,
        tenant_slug: ROOT_TENANT_SLUG.to_string(),
        knox_host: knox_host.clone(),
        m2m_client_id: "management".to_string(),
        m2m_client_secret: client_secret.clone(),
        redirect_uris: redirect_uris.clone(),
        admin_email: admin_email.clone(),
        admin_password_generated: if password_was_generated {
            Some(admin_password.clone())
        } else {
            None
        },
        scopes: root_client_scopes(),
    };

    if args.output == "json" {
        // Single line — captured by `kubectl logs job/knox-bootstrap | grep '^{'`
        println!("{}", serde_json::to_string(&output)?);
    } else {
        let pass_line = if password_was_generated {
            format!("Password (generated): {}", admin_password)
        } else {
            "Password: (as supplied via ADMIN_PASSWORD)".to_string()
        };
        println!();
        println!("╔═══════════════════════════════════════════════════════════════╗");
        println!("║           KNOX ROOT TENANT BOOTSTRAPPED                       ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  IMPORTANT: Save these credentials — secret shown only once.  ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  Tenant slug: {:<49} ║", ROOT_TENANT_SLUG);
        println!("║  Tenant ID:   {}                ║", tenant.id);
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!(
            "║  Admin user  (login at /{}/login)          ║",
            ROOT_TENANT_SLUG
        );
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  Email:   {:<53} ║", admin_email);
        println!("║  {:<63} ║", pass_line);
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  M2M client  (client_credentials + authorization_code/PKCE)   ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  Client ID:     management                                    ║");
        println!("║  Client Secret: {:<47} ║", client_secret);
        println!("║  Redirect URI:  {:<47} ║", redirect_uri);
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!();
    }

    info!("Bootstrap complete!");
    Ok(())
}
