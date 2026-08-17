"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { authenticate, verifyMfa, type MfaOption } from "@/lib/api/auth";
import { startAuthorization } from "@/lib/oauth";
import { MfaChallenge } from "@/components/auth/mfa-challenge";

interface LoginFormProps {
  tenantId: string;
  /**
   * Set when Knox redirected here from `/oauth2/authorize` — it is the original
   * authorize URL to resume once the SSO cookie exists. Present for third-party
   * relying parties; absent when a user opens the dashboard login directly.
   */
  returnTo?: string;
}

/**
 * `return_to` arrives in the query string, so treat it as untrusted: only a
 * host-relative path may be followed. Anything absolute (`https://evil.com`) or
 * protocol-relative (`//evil.com`) would turn the login page into an open
 * redirect — a credential-phishing primitive on an IdP.
 */
function safeReturnTo(value: string | undefined): string | null {
  if (!value) return null;
  if (!value.startsWith("/") || value.startsWith("//")) return null;
  return value;
}

interface Challenge {
  token: string;
  methods: MfaOption[];
}

export function LoginForm({ tenantId, returnTo }: LoginFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);

  /**
   * Runs once the SSO cookie exists, from either the password-only or the MFA
   * path — the two are indistinguishable from here on, which is the point:
   * Knox sets the same cookie either way.
   */
  async function completeLogin() {
    // If we got here from `/oauth2/authorize`, some other application started
    // this flow and is waiting for its code. Resume that request instead of
    // starting our own — the second pass now finds the cookie and redirects
    // the user back to the relying party. Starting a fresh PKCE flow here
    // would authenticate the user into the dashboard and silently strand the
    // application that sent them.
    const resume = safeReturnTo(returnTo);
    if (resume) {
      window.location.href = resume;
      return;
    }

    // Otherwise this is a direct dashboard login: start our own PKCE flow.
    // Browser redirect — Knox validates the ssotoken cookie and returns a code.
    await startAuthorization(tenantId);
  }

  /** Drops the challenge and returns to the password step. */
  function resetToPassword(message: string) {
    setChallenge(null);
    setPassword("");
    setError(message);
    setLoading(false);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const result = await authenticate(tenantId, username, password);

      if (result.mfa_token) {
        // Raw methods; `MfaChallenge` filters to the ones it can verify.
        setChallenge({ token: result.mfa_token, methods: result.methods ?? [] });
        setLoading(false);
        return;
      }

      // No MFA enrolled — the SSO cookie is already set.
      await completeLogin();
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
    }
  }

  if (challenge) {
    return (
      <MfaChallenge
        offeredMethods={challenge.methods}
        verify={(method, code) => verifyMfa(challenge.token, method, code).then(() => {})}
        onVerified={completeLogin}
        onDead={resetToPassword}
        onCancel={() => resetToPassword("")}
      />
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-1">
        <Label htmlFor="username">Email</Label>
        <Input
          id="username"
          type="email"
          autoComplete="email"
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="admin@example.com"
          disabled={loading}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
          disabled={loading}
        />
      </div>

      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? "Signing in…" : "Sign in"}
      </Button>

      {/*
        Self-service reset is off by default and has no mailer behind it yet, so
        the honest instruction today is to ask an administrator — who can issue a
        one-time reset link from the console. When `self_service_password_reset`
        ships with email, this becomes a link to a request form.
      */}
      <p className="text-center text-xs text-muted-foreground">
        Forgot your password? Contact your administrator.
      </p>
    </form>
  );
}
