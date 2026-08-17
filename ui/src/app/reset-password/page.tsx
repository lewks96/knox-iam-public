import { ShieldCheck } from "lucide-react";
import { ResetPasswordClient } from "./reset-password-client";

interface ResetPasswordPageProps {
  searchParams: Promise<{ token?: string }>;
}

/**
 * Public route — reached from a one-time reset link, so the user is not signed
 * in. Outside `(protected)` deliberately. The token arrives in the query string
 * and is handed to the client, which drives the reset (and its second-factor
 * step, when the account has one).
 */
export default async function ResetPasswordPage({
  searchParams,
}: ResetPasswordPageProps) {
  const { token } = await searchParams;

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30">
      <div className="w-full max-w-sm space-y-6 px-4">
        <div className="flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-tight">Knox IAM</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Reset your password
            </p>
          </div>
        </div>

        <div className="rounded-xl border bg-card p-7 shadow-sm">
          <ResetPasswordClient token={token ?? null} />
        </div>
      </div>
    </div>
  );
}
