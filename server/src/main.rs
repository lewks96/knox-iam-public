extern crate core;

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod state;
pub mod version;

use axum::middleware::from_fn;
use axum::routing::get;
use axum::{
    Json, Router,
    http::{Method, header},
};
use axum_tracing_opentelemetry::middleware::OtelAxumLayer;
use knox_core::audit::{AuditService, DEFAULT_AUDIT_BUFFER_SIZE, run_audit_writer};
use knox_core::client::ClientService;
use knox_core::identity::IdentityService;
use knox_core::key::{KeyService, LocalKeyEncryptionProvider};
use knox_core::mfa::MfaService;
use knox_core::tenant::{IssuerConfig, TenantService};
use knox_core::token::TokenService;
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
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;

use knox_core::authentication::AuthenticationService;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::{
    env,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, instrument};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::handlers::audit::audit_routes;
use crate::handlers::authentication::authentication_routes;
use crate::handlers::client::client_routes;
use crate::handlers::identity::{identity_routes, role_routes};
use crate::handlers::mfa::mfa_routes;
use crate::handlers::oidc::oidc_routes;
use crate::handlers::pool::pool_routes;
use crate::handlers::tenant::tenant_routes;
use crate::middleware::tracing::inject_correlation_id;
use state::{AppState, SharedState};

fn get_resource() -> Resource {
    static RESOURCE: OnceLock<Resource> = OnceLock::new();
    RESOURCE
        .get_or_init(|| {
            Resource::builder()
                .with_service_name("knox-platform")
                .build()
        })
        .clone()
}

fn init_traces() -> SdkTracerProvider {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("Failed to create span exporter");
    SdkTracerProvider::builder()
        .with_resource(get_resource())
        .with_batch_exporter(exporter)
        .build()
}

fn init_metrics() -> SdkMeterProvider {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .build()
        .expect("Failed to create metric exporter");

    SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .with_resource(get_resource())
        .build()
}

fn init_logs() -> SdkLoggerProvider {
    let exporter = LogExporter::builder()
        .with_tonic()
        .build()
        .expect("Failed to create log exporter");

    SdkLoggerProvider::builder()
        .with_resource(get_resource())
        .with_batch_exporter(exporter)
        .build()
}

#[instrument(skip(_state))]
async fn health_check(
    axum::extract::State(_state): axum::extract::State<SharedState>,
) -> Json<Value> {
    info!("Health check pinged!");
    Json(json!({
        "status": "ok",
        "version": version::PKG_VERSION,
        "git_sha": version::GIT_SHA,
    }))
}

async fn version_handler() -> Json<version::VersionInfo> {
    Json(version::info())
}

pub fn public_status_routes() -> Router<SharedState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/version", get(version_handler))
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let tracer_provider = init_traces();
    let logger_provider = init_logs();
    let meter_provider = init_metrics();

    global::set_tracer_provider(tracer_provider.clone());
    global::set_meter_provider(meter_provider.clone());
    global::set_text_map_propagator(TraceContextPropagator::new());

    let tracer = tracer_provider.tracer("knox-platform");
    let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
    let fmt_layer = tracing_subscriber::fmt::layer().with_thread_names(true);

    let log_level = env::var("KNOX_LOG").unwrap_or_else(|_| "info".to_string());
    let global_filter = EnvFilter::new(log_level)
        .add_directive("knox::audit=info".parse().unwrap())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("tower=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap())
        .add_directive("opentelemetry_sdk=error".parse().unwrap());

    tracing_subscriber::registry()
        .with(global_filter)
        .with(fmt_layer)
        .with(otel_trace_layer)
        .with(otel_log_layer)
        .init();

    info!(
        version = version::PKG_VERSION,
        git_sha = version::GIT_SHA,
        build_time = version::BUILD_TIME,
        "Knox starting!"
    );

    if env::var("KNOX_ISSUER").is_ok() {
        panic!(
            "KNOX_ISSUER is no longer used. Issuers are per-tenant and stored on \
             the tenant row. Set KNOX_SCHEME, KNOX_BASE_DOMAIN and (optionally) \
             KNOX_PUBLIC_PORT instead; existing tenants keep the issuer already \
             in their row."
        );
    }
    let issuer_config = IssuerConfig::from_env();
    info!(
        scheme = %issuer_config.scheme,
        base_domain = %issuer_config.base_domain,
        port = ?issuer_config.port,
        "New tenants will be issued subdomain issuers"
    );

    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    info!("Connecting to Redis...");
    let redis_client = redis::Client::open(redis_url).expect("Invalid Redis URL");
    let redis_manager = redis_client
        .get_connection_manager()
        .await
        .expect("Failed to create Redis connection manager");

    info!("Connecting to Postgres...");
    let max_connections = env::var("MAX_CONNECTIONS")
        .unwrap_or_else(|_| "20".into())
        .parse()
        .unwrap_or(20);
    let min_connections = env::var("MIN_CONNECTIONS")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .unwrap_or(1);
    let acquire_timeout = env::var("ACQUIRE_TIMEOUT")
        .unwrap_or_else(|_| "5".into())
        .parse()
        .unwrap_or(5);
    let idle_timeout = env::var("IDLE_TIMEOUT")
        .unwrap_or_else(|_| "300".into())
        .parse()
        .unwrap_or(300);
    let max_lifetime = env::var("MAX_LIFETIME")
        .unwrap_or_else(|_| "1800".into())
        .parse()
        .unwrap_or(1800);

    let statement_cache_capacity = env::var("STATEMENT_CACHE_CAPACITY")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap_or(0);

    let connect_options = database_url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .expect("Invalid DATABASE_URL")
        .statement_cache_capacity(statement_cache_capacity);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(Duration::from_secs(acquire_timeout))
        .idle_timeout(Duration::from_secs(idle_timeout))
        .max_lifetime(Duration::from_secs(max_lifetime))
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to the database");
    info!("DB pool connected");

    // 6. Build the Data Layer (Repositories)
    let identity_repo = KnoxIdentityRepository::new(
        PgIdentityStore::new(pool.clone(), pool.clone()),
        RedisIdentityCache::new(redis_manager.clone()),
    );

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

    let token_repo = KnoxTokenRepository::new(
        RedisAuthCodeCache::new(redis_manager.clone()),
        PgRefreshTokenStore::new(pool.clone()),
    );

    let key_repo = KnoxKeyRepository::new(
        PgKeyStore::new(pool.clone()),
        RedisKeyCache::new(redis_manager.clone()),
    );

    let mfa_repo = KnoxMfaRepository::new(
        PgMfaStore::new(pool.clone()),
        RedisMfaCache::new(redis_manager.clone()),
    );

    let audit_repo = KnoxAuditRepository::new(PgAuditStore::new(pool.clone()));

    let pool_repo = PgPoolStore::new(pool.clone());

    let master_key_b64 = env::var("AES_MASTER_KEY").expect("MASTER_KEY must be set");
    let key_provider = LocalKeyEncryptionProvider::from_base64(&master_key_b64)
        .expect("Failed to initialize Master Key");

    let audit_buffer = env::var("AUDIT_BUFFER_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_AUDIT_BUFFER_SIZE);
    let (audit_service, audit_rx) = AuditService::new(audit_buffer);
    tokio::spawn(run_audit_writer(audit_repo.clone(), audit_rx));

    let identity_service = IdentityService::new(identity_repo.clone(), auth_repo.clone());
    let client_service = ClientService::new(client_repo);
    let mfa_service = MfaService::new(mfa_repo, key_provider.clone());
    let key_service = KeyService::new(key_repo, key_provider);
    let token_service = TokenService::new(token_repo, key_service.clone());
    let tenant_service = TenantService::new(
        tenant_repo,
        pool_repo.clone(),
        auth_repo.clone(),
        key_service.clone(),
        client_service.clone(),
        identity_service.clone(),
        issuer_config,
    );

    let auth_service = AuthenticationService::new(
        identity_service.clone(),
        token_service.clone(),
        mfa_service.clone(),
        audit_service.clone(),
    );

    let oidc_service = knox_services::OIDCService::new(
        client_service.clone(),
        token_service.clone(),
        auth_service.clone(),
        identity_service.clone(),
        pool_repo.clone(),
        audit_service.clone(),
    );

    let app_state: SharedState = Arc::new(AppState {
        identity_service,
        client_service,
        token_service,
        key_service,
        mfa_service,
        tenant_service,
        oidc_service,
        auth_service,
        audit_service,
        audit_repo,
    });

    info!("Core services initialized");

    let allowed_headers = [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::COOKIE,
    ];

    let allowed_methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];

    let oidc_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers);

    // Cap concurrent in-flight API requests so memory growth from queued
    let max_in_flight = env::var("MAX_IN_FLIGHT_REQUESTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(64);
    info!(
        "API concurrency limit: {} (override with MAX_IN_FLIGHT_REQUESTS)",
        max_in_flight
    );

    let api_routes = Router::new()
        .merge(oidc_routes().layer(oidc_cors))
        .nest("/api/clients", client_routes())
        .nest("/api/identity", identity_routes())
        .nest("/api/authenticate", authentication_routes())
        .nest("/api/mfa", mfa_routes())
        .nest("/api/audit", audit_routes())
        .nest("/api/tenant", tenant_routes())
        .nest("/api/pools", pool_routes())
        .nest("/api/roles", role_routes())
        .nest("/api/sys", public_status_routes())
        .layer(tower::limit::ConcurrencyLimitLayer::new(max_in_flight));

    let app = Router::new()
        .merge(api_routes)
        .layer(from_fn(inject_correlation_id))
        .layer(OtelAxumLayer::default())
        .with_state(app_state);

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let bind_addr = format!("{}:{}", host, port);

    info!("Starting API server at: {}", bind_addr);
    let listener = TcpListener::bind(bind_addr).await.unwrap();

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("Failed to start server");
}
