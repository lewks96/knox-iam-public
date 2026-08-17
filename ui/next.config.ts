import type { NextConfig } from "next";

/**
 * Where the axum server listens in local development. In deployed environments
 * the ingress puts the UI and the API on one origin, so these rewrites are a
 * dev-only stand-in for that.
 */
const KNOX_API_ORIGIN = process.env.KNOX_API_ORIGIN ?? "http://127.0.0.1:8080";

const nextConfig: NextConfig = {
  output: "standalone",

  /**
   * Serve the OAuth and discovery endpoints from the same origin as the UI.
   *
   * Knox redirects an unauthenticated `/oauth2/authorize` to the login page with
   * a host-relative `return_to`, which only resolves if both live on one origin —
   * which is true in every deployed environment but not when `next dev` is on
   * :3000 and axum on :8080. Proxying here makes local development mirror the
   * deployed topology instead of being a special case.
   *
   * Returning an array applies these before dynamic routes, so they take
   * precedence over the `[tenant]` segment without shadowing `/[tenant]/login`.
   */
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${KNOX_API_ORIGIN}/api/:path*` },
      { source: "/oauth2/:path*", destination: `${KNOX_API_ORIGIN}/oauth2/:path*` },
      {
        source: "/.well-known/:path*",
        destination: `${KNOX_API_ORIGIN}/.well-known/:path*`,
      },
    ];
  },
};

export default nextConfig;
