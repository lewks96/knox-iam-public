"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { exchangeCodeForTokens } from "@/lib/api/auth";
import { useAuthStore } from "@/lib/auth-store";

export default function CallbackPage() {
  const router = useRouter();
  const { setTokens } = useAuthStore();
  const handled = useRef(false);

  useEffect(() => {
    // Prevent double-run in React Strict Mode
    if (handled.current) return;
    handled.current = true;

    async function handleCallback() {
      const params = new URLSearchParams(window.location.search);
      const code = params.get("code");
      const returnedState = params.get("state");
      const errorParam = params.get("error");

      if (errorParam) {
        router.replace(
          `/login?error=${encodeURIComponent(errorParam)}`
        );
        return;
      }

      if (!code || !returnedState) {
        router.replace("/");
        return;
      }

      // Retrieve stored PKCE values
      const storedState = sessionStorage.getItem("knox_pkce_state");
      const verifier = sessionStorage.getItem("knox_pkce_verifier");
      const tenantId = sessionStorage.getItem("knox_pkce_tenant");

      if (!storedState || !verifier || !tenantId) {
        router.replace("/");
        return;
      }

      // CSRF check
      if (returnedState !== storedState) {
        console.error("State mismatch — possible CSRF attack");
        router.replace(`/login?error=state_mismatch`);
        return;
      }

      // Clean up sessionStorage
      sessionStorage.removeItem("knox_pkce_state");
      sessionStorage.removeItem("knox_pkce_verifier");
      sessionStorage.removeItem("knox_pkce_tenant");

      try {
        // Must exactly match the redirect_uri sent at /oauth2/authorize.
        // The login form uses window.location.origin, so we do too.
        const redirectUri = `${window.location.origin}/callback`;

        const tokens = await exchangeCodeForTokens(
          tenantId,
          code,
          verifier,
          redirectUri
        );

        setTokens(
          tokens.access_token,
          tenantId,
          tokens.expires_in,
          tokens.scope ? tokens.scope.split(" ") : []
        );

        // Persist refresh token separately
        if (tokens.refresh_token) {
          sessionStorage.setItem("knox_refresh_token", tokens.refresh_token);
        }

        router.replace(`/dashboard`);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "token_exchange_failed";
        router.replace(`/login?error=${encodeURIComponent(message)}`);
      }
    }

    handleCallback();
  }, [router, setTokens]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-3 text-muted-foreground">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-current border-t-transparent" />
        <p className="text-sm">Completing sign-in…</p>
      </div>
    </div>
  );
}
