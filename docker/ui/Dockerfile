# ── Stage 1: Install dependencies ────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app

COPY ui/package.json ui/package-lock.json ./
RUN npm ci --frozen-lockfile

# ── Stage 2: Build ────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY ui/ .

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

# API is always served behind /api/ via the nginx ingress rewrite — constant
# across all environments, no runtime replacement needed.
ENV NEXT_PUBLIC_API_BASE_URL=/api

# These three are deployment-specific and will be replaced by entrypoint.sh at
# container startup using sed against the baked JS bundles. The placeholder
# strings must be unique enough that they won't collide with real content.
ENV NEXT_PUBLIC_MANAGEMENT_CLIENT_ID=management
ENV NEXT_PUBLIC_MANAGEMENT_TENANT_ID=__MANAGEMENT_TENANT_ID__
# Placeholder swapped at container start — the UI reads the tenant from its host.
#
# Deliberately lowercase: tenant.ts calls .toLowerCase() on this value, and the
# bundler constant-folds that at build time. An upper-case placeholder would be
# baked as "__base_domain__" and the entrypoint's sed would never match it.
ENV NEXT_PUBLIC_BASE_DOMAIN=__base_domain__

RUN npm run build

# ── Stage 3: Minimal runtime ──────────────────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

# standalone/ contains server.js + traced node_modules — no npm install needed.
# Files are owned by nextjs so the entrypoint can sed-patch them at startup.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --chown=nextjs:nodejs docker/ui/entrypoint.sh ./entrypoint.sh

RUN chmod +x ./entrypoint.sh

USER nextjs
EXPOSE 3000

ENTRYPOINT ["./entrypoint.sh"]

