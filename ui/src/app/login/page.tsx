import { getTenant } from "@/lib/tenant-server";
import { LoginForm } from "@/components/auth/login-form";
import { ShieldCheck } from "lucide-react";

interface LoginPageProps {
  searchParams: Promise<{ return_to?: string; prompt?: string; reason?: string }>;
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const tenant = await getTenant();
  // Set when Knox bounced an unauthenticated /oauth2/authorize here.
  const { return_to: returnTo, prompt, reason } = await searchParams;
  // Knox asks for `prompt=login` when the application demanded a fresh
  // credential check — via `prompt=login` or an exceeded `max_age`. The user is
  // already signed in, so without a word of explanation the form looks like the
  // session was silently lost.
  const isReauth = prompt === "login";
  // A password change revokes every session, so the user lands back here on
  // purpose. Say so, rather than let it read as an unexplained sign-out.
  const passwordChanged = reason === "password_changed";

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30">
      <div className="w-full max-w-sm space-y-6 px-4">
        {/* Logo / Brand */}
        <div className="flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-tight">Knox IAM</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Identity &amp; Access Management
            </p>
          </div>
        </div>

        {/* Login Card */}
        <div className="rounded-xl border bg-card p-7 shadow-sm">
          <div className="mb-5">
            <h2 className="text-base font-semibold">
              {isReauth ? "Confirm it's you" : "Sign in"}
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isReauth
                ? "The application you're opening asked us to check your credentials again."
                : null}
            </p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Tenant:{" "}
              <span className="font-mono text-foreground/80">{tenant}</span>
            </p>
          </div>
          {passwordChanged && (
            <div className="mb-4 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-400">
              Your password was changed. Please sign in again.
            </div>
          )}
          <LoginForm tenantId={tenant} returnTo={returnTo} />
        </div>
      </div>
    </div>
  );
}
