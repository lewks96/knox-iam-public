# Knox IAM

A multi-tenant identity and access management platform written in Rust. Knox issues and validates OAuth 2.0 / OIDC tokens, manages identities and their roles, and keeps a per-tenant audit trail — with each tenant isolated behind its own subdomain, signing key, and issuer.

## ⚠️ Please don't use this

This is a **hobby project and a work in progress**. It is published because building an
IAM platform is an interesting problem and the code may be interesting to read — not
because it is ready for anyone to depend on.

Concretely:

- **It has never been through a security review or audit.** It is authentication code
  written by one person for fun. Assume there are vulnerabilities, because there probably
  are.
- **Parts of this were written with AI**, mainly the DevOps side — the Kubernetes
  manifests, the scripts, CI, and this documentation. It has been run and tested, not
  audited. Those are different things.
- **Nothing is stable.** The API surface, the database schema, and the config all move
  without notice. There is no migration path between versions and no deprecation policy.
- **It is unfinished.** Several things a real IAM needs are missing or half-built — see
  [docs/roadmap.md](docs/roadmap.md) for the honest list. There is no email delivery, no
  `/oauth2/revoke` or `/introspect`, no device code grant, and no RP-initiated logout.
- **It is not operated anywhere.** The Kubernetes manifests target a local k3d cluster.
  CI builds container images off `main` so the k3d quickstart works, but there is no
  release process, no versioned images, and no support.
- **There is no one on call.** Issues and PRs may be ignored. Security reports have
  nowhere to go.

If you need identity for something real, use Keycloak, Ory, Zitadel, Authentik, Auth0,
Entra ID, or Cognito. Read this for ideas; don't put it in front of users.

> **Status:** pre-1.0 (`0.1.1`), and the leading `0.` is doing a lot of work.

## What it does

- **OAuth 2.0 / OIDC provider** — `client_credentials`, `authorization_code` with PKCE, and `refresh_token` grants, plus a JWKS endpoint for token verification.
- **Multi-tenancy by subdomain** — `acme.knox.example.com` resolves to tenant `acme`. Every tenant gets its own OIDC issuer and its own RSA signing key, encrypted at rest with an AES master key.
- **Identity & RBAC** — users, roles, and role assignments per tenant, with token scopes derived from the caller's grants.
- **MFA** — TOTP enrollment and verification, with recoverable backup codes.
- **Identity pools** — grouping of identities within a tenant.
- **Audit log** — authentication and administrative events, written asynchronously off the request path.
- **Management UI** — a Next.js console for administering tenants, clients, and identities.

## Architecture

The Rust workspace splits into four library crates behind two binaries, layered so that domain logic never talks to Postgres or Redis directly:

| Crate | Role |
| --- | --- |
| `knox-common` | Shared domain types and error enums. No I/O. |
| `knox-storage` | Persistence. Each domain has a Postgres store, a Redis cache, and a repository composing the two. |
| `knox-core` | Domain services — identity, client, tenant, token, key, MFA, roles, audit. |
| `knox-services` | Protocol layer; currently the OIDC service that maps grants onto core services. |

| Binary | Role |
| --- | --- |
| `server` | The axum HTTP API. |
| `knox-bootstrap` | One-shot CLI that creates the `knox-root` platform tenant, a management client, and an admin user. Lives in `bootstrap/`, ships as the `knox-iam-bootstrap` image, and is designed to run as a Kubernetes Job. |

Backing services are **Postgres 16** (with `pg_cron`, which drives refresh-token pruning) and **Redis 7** (caching and short-lived auth codes). Traces, metrics, and logs are exported over OTLP.

```mermaid
flowchart TB
    subgraph svc["knox-services — protocol layer"]
        OIDC["OIDCService<br/>/oauth2, /.well-known"]
    end

    subgraph core["knox-core — domain services"]
        direction LR
        AUTHN[AuthenticationService]
        IDENT[IdentityService]
        CLIENT[ClientService]
        TOKEN[TokenService]
        TENANT[TenantService]
        KEY[KeyService]
        MFA[MfaService]
        AUDIT[AuditService]
    end

    subgraph strg["knox-storage — repositories"]
        direction LR
        IR[IdentityRepository]
        AR[AuthorizationRepository]
        CR[ClientRepository]
        TR[TokenRepository]
        TNR[TenantRepository]
        KR[KeyRepository]
        MR[MfaRepository]
        AUR[AuditRepository]
        PR[PoolRepository]
        KP[KeyEncryptionProvider]
    end

    PG[("Postgres 16<br/>+ pg_cron")]
    RD[("Redis 7")]

    OIDC --> IDENT & CLIENT & TOKEN & AUTHN & AUDIT & PR

    AUTHN --> IR & AR & TR & KR & MR & KP
    IDENT --> IR & AR
    CLIENT --> CR
    TOKEN --> TR & KR & KP
    TENANT --> TNR & AR & KR & CR & IR & PR & KP
    KEY --> KR & KP
    MFA --> MR & KP
    AUDIT --> AUR

    IR & AR & CR & TR & TNR & KR & MR & AUR & PR --> PG
    IR & AR & CR & TR & TNR & KR & MR --> RD
```

Every repository except `AuditRepository` and `PoolRepository` composes a Postgres store with a Redis cache behind one trait — services depend on the trait, never on `sqlx` or `redis`:

```mermaid
flowchart LR
    S["Domain service<br/>(knox-core)"] --> R["Knox&lt;Domain&gt;Repository"]
    R --> ST["Pg&lt;Domain&gt;Store<br/>sqlx"] --> PG[("Postgres")]
    R --> CA["Redis&lt;Domain&gt;Cache<br/>ConnectionManager"] --> RD[("Redis")]
```

### Request surface

Tenant identity comes from the `Host` header, not the URL path — the tenant subdomain is stripped against `KNOX_BASE_DOMAIN` and resolved before the handler runs. The paths themselves are tenant-agnostic:

```
/.well-known/jwks.json     /oauth2/token     /oauth2/authorize

/api/authenticate   /api/identity   /api/clients   /api/tenant
/api/mfa            /api/pools      /api/roles     /api/audit   /api/sys
```

Full endpoint documentation — including the Authorization Code + PKCE sequence — is in [docs/api-reference.md](docs/api-reference.md).

## Repository layout

```
server/        axum HTTP API (handlers, middleware, state)
bootstrap/     one-shot platform bootstrap CLI
crates/        knox-common, knox-storage, knox-core, knox-services
migrations/    sqlx migrations (.up.sql / .down.sql)
ui/            Next.js 16 management console
docker/        Dockerfiles: postgres (pg_cron), migrate, ui, bootstrap, pgbouncer
k8s/           kustomize base + local and quickstart (k3d) overlays
scripts/       build, cluster, sqlx-prepare, and load-test helpers
.github/       one workflow: multi-arch image builds pushed to GHCR
k6/            k6 load and auth-flow tests
docs/          API reference and roadmap
```

## Getting started

### Prerequisites

- Rust **1.90+** (what the Docker images pin)
- Docker with Compose
- Node.js 22+ (for the UI)
- `sqlx-cli` **0.8.6** — must match the `sqlx` library version:
  ```bash
  cargo install sqlx-cli --version 0.8.6 --no-default-features --features postgres,native-tls --locked
  ```

### 1. Generate the env files

```bash
./setup.sh
```

This copies `.env.example` → `.env`, `.env.compose.example` → `.env.compose`, and
`ui/.env.example` → `ui/.env.local`, generating one shared `AES_MASTER_KEY` for the first
two. Existing files are left alone unless you pass `--force`. Doing it by hand works too —
the only value that must be filled in is `AES_MASTER_KEY` (`openssl rand -base64 32`).

`AES_MASTER_KEY` wraps every tenant's RSA signing key. Changing it after tenants exist
leaves those keys unreadable.

The defaults give you working tenant subdomains via `lvh.me`, which resolves `*.lvh.me`
to `127.0.0.1` without touching `/etc/hosts`. `.env` reaches the backing services on
`localhost`; `.env.compose` uses compose service names.

> **`KNOX_TRUST_FORWARDED_HOST` must stay `false` outside local dev.** It exists because
> Next's rewrite proxy overwrites `Host` with the destination, pushing the tenant
> subdomain into `X-Forwarded-Host`. In a cluster nginx preserves `Host`, and trusting the
> forwarded header there would let a caller choose which tenant they resolve as.

### 2. Start the backing services

```bash
docker compose up -d postgres redis
```

Postgres is built from `docker/postgres/`, which installs `pg_cron` — the stock
`postgres:16` image will fail on the `20260424140000_refresh_token_cron` migration.

### 3. Apply migrations

```bash
docker compose up migrate --exit-code-from migrate
```

Or directly, against the compose database:

```bash
DATABASE_URL=postgres://admin:password@localhost:5432/knox sqlx migrate run --source migrations
```

### 4. Bootstrap the platform tenant

```bash
cargo run -p knox-bootstrap
```

This creates the `knox-root` tenant, a `management` client supporting both
`client_credentials` and `authorization_code`, and an admin user. Set `ADMIN_EMAIL` /
`ADMIN_PASSWORD` to choose credentials — otherwise a password is generated and printed.

### 5. Run the server and UI

```bash
cargo run -p server
```

```bash
cd ui && npm install && npm run dev
```

The UI proxies `/api`, `/oauth2`, and `/.well-known` to the API so both share one origin
in development. Open the console at a tenant subdomain — e.g. `http://knox-root.lvh.me:3000`.

## Common tasks

**Regenerate sqlx offline query data.** Required whenever you add or change a `query!` /
`query_as!` macro — `.sqlx/` is committed so the workspace builds without a database:

```bash
./scripts/prepare-sqlx.sh
```

**Run the tests:**

```bash
cargo test --workspace
```

**Load tests** live in `k6/` — `load_test.js` and `auth_flow_test.js`.

## Running it on k3d

Compose plus `cargo run` is the development loop. k3d is for seeing the actual multi-pod
topology — ingress, HPA, PgBouncer, the migrate init container, the bootstrap Job — and
comes in two flavours.

Both need `k3d`, `kubectl` and `kustomize`:

```bash
brew install k3d kubectl kustomize
```

### Kicking the tyres — published images

Nothing to build. The cluster pulls prebuilt images from GHCR:

```bash
./scripts/k3d-setup.sh --published setup
```

This creates the cluster, generates its secrets, issues a self-signed wildcard
certificate, applies `k8s/overlays/quickstart`, and runs the bootstrap Job. It ends by
printing the admin credentials and a URL — `https://knox-root.lvh.me:8443`, with a
certificate warning to click through.

You get the tip of `main` (tag `main`, rebuilt by
[`.github/workflows/publish-images.yml`](.github/workflows/publish-images.yml) on every
push), not your working tree. It is not a release and carries no stability promise; the
warning at the top of this README applies with full force. `IMAGE_TAG=<short-sha>` pins a
specific build instead.

### Developing against it — local images

Run the cluster on your own code. Build first, every time:

```bash
./scripts/docker.sh build
```

```bash
./scripts/k3d-setup.sh setup
```

`docker.sh build` produces host-arch images in your local Docker daemon tagged with both
`latest` and the current git short SHA; `k3d-setup.sh` side-loads those into the cluster
with `k3d image import` and pins `k8s/overlays/local` to that SHA. Nothing is pulled. If an
image is missing it stops and tells you, rather than leaving you with an
`ImagePullBackOff` against a tag that only exists on your laptop.

That SHA pinning rewrites `newTag:` in `k8s/overlays/local/kustomization.yaml`, so expect
that one file to show as modified after a run — it is committed as `latest`.

After a code change: rebuild, then `./scripts/k3d-setup.sh deploy`.

### Either way

Useful subcommands — `deploy`, `restart [service]`, `bootstrap`, `tls`, and `delete` to
tear the cluster down. Flags and environment carry across all of them: `--published`
selects the image source (or `KNOX_IMAGE_SOURCE=published`), `KNOX_BASE_DOMAIN` moves the
whole thing off `lvh.me` (use `<ip-with-dashes>.sslip.io` when k3d runs on another host),
and `AES_KEY` is reused from the cluster if one is already there — a fresh key would leave
every existing tenant's signing key undecryptable.

Details and the configuration surface: [k8s/README.md](k8s/README.md). There is no cloud
overlay — see the warning at the top.

## Further reading

- [docs/api-reference.md](docs/api-reference.md) — endpoints, grants, the auth-code flow, and the scope reference
- [docs/roadmap.md](docs/roadmap.md) — what is not built yet
- [k8s/README.md](k8s/README.md) — cluster topology and the two k3d paths

That is deliberately all of it. Design notes, historical change summaries and the
drawio sources they were drawn from lived here at one point and were removed rather
than left to rot: the diagrams that matter are Mermaid, inline, in the document that
needs them, and `migrations/` is the authoritative description of the schema.

## License

[MIT](LICENSE) — do what you like with it, keep the copyright notice and license text in
copies. No warranty, and given the top of this README, take that literally.
