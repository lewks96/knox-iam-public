# Knox management console

Next.js 16 / React 19 admin UI for Knox IAM, plus the hosted login page each tenant's
users see during the OAuth authorization flow.

See the [repository README](../README.md) for the platform as a whole and
[docs/api-reference.md](../docs/api-reference.md) for the API this talks to.

## Running it

```bash
npm install
npm run dev
```

Open a **tenant subdomain**, not bare localhost — the API resolves the tenant from the
`Host` header:

```
http://knox-root.lvh.me:3000
```

`lvh.me` resolves `*.lvh.me` to `127.0.0.1`, so tenant subdomains work with no
`/etc/hosts` editing. The server must be running on `:8080` (`cargo run -p server`) and
the platform tenant bootstrapped (`cargo run -p knox-bootstrap`).

## Why the dev proxy exists

`next.config.ts` rewrites `/api/*`, `/oauth2/*` and `/.well-known/*` to
`KNOX_API_ORIGIN` (default `http://127.0.0.1:8080`).

Deployed, the ingress puts the UI and the API on **one origin** — that is what makes the
SSO cookie first-party and lets Knox redirect an unauthenticated `/oauth2/authorize` to
the login page with a host-relative `return_to`. The rewrites make local dev mirror that
topology instead of being a special case.

> This is also why `KNOX_TRUST_FORWARDED_HOST=true` is needed locally and must stay
> `false` everywhere else: the rewrite proxy overwrites `Host` with the destination and
> pushes the tenant subdomain into `X-Forwarded-Host`. In a cluster nginx preserves
> `Host`, and trusting the forwarded header there would let a caller pick their tenant.

## Layout

```
src/app/
  login/            hosted login page (password, MFA challenge)
  callback/         OAuth redirect handler — exchanges code for tokens
  setup/            first-run / bootstrap flow
  tenants/          tenant switcher
  (protected)/      authenticated console
    dashboard/  identities/  clients/  tenant/  audit/  account/
src/lib/
  api/              one module per API surface (identity, clients, mfa, pools, roles, audit, tenants, system)
  api-client.ts     fetch wrapper — auth header, refresh, error shape
  auth-store.ts     token/session state
  oauth.ts, pkce.ts authorization-code + PKCE client
  tenant.ts         subdomain → tenant resolution (client and server halves)
```

State is TanStack Query; components are shadcn / Base UI on Tailwind; JWTs are verified
with `jose`.

## Configuration

| Variable | Purpose |
|----------|---------|
| `KNOX_API_ORIGIN` | Where the dev rewrites point (default `http://127.0.0.1:8080`) |
| `BASE_DOMAIN` | Base domain that tenants are subdomains of |
| `MANAGEMENT_TENANT_ID` | Platform tenant the console authenticates against |
| `MANAGEMENT_CLIENT_ID` | OAuth client the console uses |

In-cluster these come from the `knox-ui-config` ConfigMap, filled in by
`scripts/k3d-setup.sh` or the azure overlay.

## Build

```bash
npm run build   # standalone output, what docker/ui/Dockerfile ships
npm start
```

> **Next.js 16:** see [AGENTS.md](AGENTS.md) — this version has breaking changes from
> earlier conventions. Check `node_modules/next/dist/docs/` before writing code.
