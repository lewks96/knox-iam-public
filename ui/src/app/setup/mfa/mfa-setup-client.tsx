"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { KeyRound, LogOut, ShieldCheck, Smartphone } from "lucide-react";
import {
  listMfaMethods,
  startTotpEnrollment,
  type StartTotpEnrollmentResponse,
} from "@/lib/api/mfa";
import { useAuthStore } from "@/lib/auth-store";
import { isSelfServiceOnly } from "@/lib/config";
import { startAuthorization } from "@/lib/oauth";
import { BackupCodes } from "@/components/mfa/backup-codes";
import { TotpEnrollmentPanel } from "@/components/mfa/totp-enrollment-panel";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

/**
 * First-run second-factor setup for the console.
 *
 * Deliberately not dismissible and deliberately outside the app shell: an
 * administrator who has not enrolled has no console to go back to, so offering
 * navigation would only produce dead ends. The two ways out are finishing
 * enrollment and signing out.
 *
 * It closes with a fresh authorization rather than a token refresh. When the
 * tenant sets `require_admin_mfa`, the session that arrives here has had its
 * administrative scopes withheld, and the refresh token records that narrowed
 * set — so only a new authorization re-evaluates what the identity may now
 * hold. The SSO cookie is still valid, which is what makes that a redirect
 * rather than another password prompt.
 */
export function MfaSetupClient({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const { hydrate, isAuthenticated, clearTokens } = useAuthStore();
  const scopes = useAuthStore((s) => s.scopes);
  const [hydrated, setHydrated] = useState(false);
  const [enrollment, setEnrollment] =
    useState<StartTotpEnrollmentResponse | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [finishing, setFinishing] = useState(false);

  useEffect(() => {
    hydrate();
    setHydrated(true);
  }, [hydrate]);

  const authed = hydrated && isAuthenticated();

  useEffect(() => {
    if (hydrated && !isAuthenticated()) router.replace("/login");
  }, [hydrated, isAuthenticated, router]);

  const { data: methods, isLoading } = useQuery({
    queryKey: ["mfa-methods"],
    queryFn: listMfaMethods,
    enabled: authed,
  });

  const verified = Boolean(methods?.some((m) => m.verified_at));
  // Scopes beyond self-service were withheld: the tenant requires a second
  // factor and this session predates the enrollment.
  const restricted = isSelfServiceOnly(scopes);

  // Complementary to the shell's gate, which sends unenrolled or restricted
  // sessions here — so there is no state in which the two bounce each other.
  useEffect(() => {
    if (verified && !restricted && !backupCodes) router.replace("/dashboard");
  }, [verified, restricted, backupCodes, router]);

  const startMutation = useMutation({
    // An abandoned attempt needs no cleanup: the server drops any unverified
    // enrollment of the same kind before inserting a new one.
    mutationFn: startTotpEnrollment,
    onSuccess: setEnrollment,
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Could not start setup"),
  });

  function finish() {
    setFinishing(true);
    startAuthorization(tenantId);
  }

  function signOut() {
    clearTokens();
    router.replace("/login");
  }

  const body = () => {
    if (!authed || isLoading) return <Loading label="Checking your account…" />;
    if (finishing) return <Loading label="Finishing sign-in…" />;

    if (backupCodes) {
      return (
        <Step
          title="Save your backup codes"
          description="Each code signs you in once if you lose your authenticator."
        >
          <BackupCodes
            codes={backupCodes}
            onDone={finish}
            doneLabel="Continue to the console"
          />
        </Step>
      );
    }

    if (verified) {
      // Enrolled, but the token in hand was minted before that and is still
      // missing the scopes it was denied. One authorization round-trip fixes it.
      return (
        <Step
          title="Two-factor authentication is on"
          description="Your permissions were withheld while no second factor was enrolled. Continue to pick them up."
        >
          <Button className="w-full" onClick={finish}>
            Continue to the console
          </Button>
        </Step>
      );
    }

    if (enrollment) {
      return (
        <Step
          title="Scan the QR code"
          description="Open your authenticator app, scan this code, then enter the 6-digit code it shows."
        >
          <TotpEnrollmentPanel
            enrollment={enrollment}
            onConfirmed={(codes) => setBackupCodes(codes)}
          />
        </Step>
      );
    }

    return (
      <Step
        title="Set up two-factor authentication"
        description={
          restricted
            ? "This tenant requires a second factor before an account can use its administrative permissions. Yours are being withheld until you set one up."
            : "The console requires a second factor. It takes about a minute, and you will need it every time you sign in."
        }
      >
        <ul className="space-y-3 text-sm text-muted-foreground">
          <Bullet icon={Smartphone}>
            You will need an authenticator app — 1Password, Authy, and Google
            Authenticator all work.
          </Bullet>
          <Bullet icon={ShieldCheck}>
            We will show backup codes at the end. Save them: they are the way
            back in if you lose your phone.
          </Bullet>
        </ul>
        <Button
          className="w-full"
          onClick={() => startMutation.mutate()}
          disabled={startMutation.isPending}
        >
          {startMutation.isPending ? "Starting…" : "Set up authenticator app"}
        </Button>
      </Step>
    );
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30 px-6 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="flex items-center justify-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <span className="text-sm font-bold tracking-tight">Knox IAM</span>
        </div>

        <div className="rounded-xl border bg-card p-6 shadow-sm">{body()}</div>

        <div className="flex items-center justify-center">
          <Button
            variant="ghost"
            size="sm"
            className="gap-2 text-muted-foreground hover:text-foreground"
            onClick={signOut}
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </div>
    </div>
  );
}

function Step({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-5">
      <div className="space-y-2 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary">
          <KeyRound className="h-6 w-6" />
        </div>
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          {description}
        </p>
      </div>
      <Separator />
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function Bullet({
  icon: Icon,
  children,
}: {
  icon: React.ElementType;
  children: React.ReactNode;
}) {
  return (
    <li className="flex gap-3">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground/70" />
      <span className="leading-relaxed">{children}</span>
    </li>
  );
}

function Loading({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-3 py-8 text-muted-foreground">
      <div className="h-8 w-8 animate-spin rounded-full border-4 border-current border-t-transparent" />
      <p className="text-sm">{label}</p>
    </div>
  );
}
