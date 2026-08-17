"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard,
  Users,
  AppWindow,
  Building2,
  LogOut,
  ScrollText,
  ShieldCheck,
  KeyRound,
  Settings,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useAuthStore } from "@/lib/auth-store";
import { listMfaMethods } from "@/lib/api/mfa";
import { PLATFORM_SCOPE, isSelfServiceOnly } from "@/lib/config";
import { startAuthorization } from "@/lib/oauth";
import { cn } from "@/lib/utils";
import { VersionFooter } from "@/components/layout/version-footer";
import { ThemeToggle } from "@/components/layout/theme-toggle";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  exact?: boolean;
}

function NavLink({ item }: { item: NavItem }) {
  const pathname = usePathname();
  const href = item.href;
  const isActive = item.exact ? pathname === href : pathname.startsWith(href);

  return (
    <Link
      href={href}
      className={cn(
        "group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-150",
        isActive
          ? "bg-sidebar-accent text-sidebar-accent-foreground before:absolute before:left-0 before:top-1/2 before:h-4 before:w-0.5 before:-translate-y-1/2 before:rounded-full before:bg-foreground"
          : "text-sidebar-foreground/60 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
      )}
    >
      <item.icon className={cn("h-4 w-4 shrink-0 transition-colors", isActive ? "text-foreground" : "text-sidebar-foreground/50")} />
      <span>{item.label}</span>
    </Link>
  );
}

interface AppShellProps {
  children: React.ReactNode;
  tenantId: string;
}

const tenantNavItems: NavItem[] = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
    exact: true,
  },
  { label: "Customers", href: "/identities", icon: Users },
  { label: "Clients", href: "/clients", icon: AppWindow },
  { label: "Audit Log", href: "/audit", icon: ScrollText },
  // Administrators, directories and sign-in policy — everything that is about
  // the tenant itself rather than about its end users.
  { label: "Tenant", href: "/tenant", icon: Settings, exact: true },
];

const platformNavItems: NavItem[] = [
  { label: "Tenants", href: "/tenants", icon: Building2 },
];

/**
 * Self-service, not administration — these act on the signed-in identity
 * rather than on the tenant, so they sit with sign-out rather than in the nav
 * above. Everything here works with the `IdentitySelf` role alone.
 */
const accountNavItems: NavItem[] = [
  { label: "Security", href: "/account/security", icon: KeyRound },
];

/**
 * Shown when a session holds only self-service scopes despite having a verified
 * second factor.
 *
 * Two ways to arrive: the token predates the enrollment and can be reissued, or
 * the identity genuinely holds nothing but `IdentitySelf`. Reissuing is one
 * redirect, and it is harmless in the second case — which is why this is a
 * button rather than an automatic bounce that could loop.
 */
function RestrictedGate({ tenantId }: { tenantId: string }) {
  return (
    <div className="flex h-full items-center justify-center px-6">
      <div className="w-full max-w-md space-y-5 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
          <KeyRound className="h-7 w-7" />
        </div>
        <div className="space-y-2">
          <h1 className="text-xl font-semibold tracking-tight">
            No administrative permissions
          </h1>
          <p className="text-sm text-muted-foreground">
            This session can act on your own account and nothing else. If you
            have just set up two-factor authentication, your permissions are
            waiting for a new sign-in.
          </p>
        </div>
        <Button className="w-full" onClick={() => startAuthorization(tenantId)}>
          Reload my permissions
        </Button>
      </div>
    </div>
  );
}

export function AppShell({ children, tenantId }: AppShellProps) {
  const router = useRouter();
  const pathname = usePathname();
  const { isAuthenticated, clearTokens, hydrate } = useAuthStore();
  // Driven by the token's scopes, not the route param: platform sections should
  // reflect what the signed-in session can actually do.
  const isPlatform = useAuthStore((s) => s.scopes.includes(PLATFORM_SCOPE));
  // A tenant with `require_admin_mfa` withholds every administrative scope
  // until a second factor is enrolled, so the session is real but can do
  // nothing here. Hide what it cannot use and say why.
  const restricted = useAuthStore((s) => isSelfServiceOnly(s.scopes));
  const inAccount = pathname.startsWith("/account");

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace(`/login`);
    }
  }, [isAuthenticated, router, tenantId]);

  // The console requires a second factor of everyone who signs in to it, not
  // only of tenants that set `require_admin_mfa` — that policy decides what a
  // *token* may carry, and defaults off, so on its own it would leave most
  // consoles unprotected. Checking the enrolled methods asks the question
  // directly. `IdentitySelf` grants this call, so even a session narrowed to
  // nothing can answer it.
  const { data: mfaMethods, isLoading: mfaLoading } = useQuery({
    queryKey: ["mfa-methods"],
    queryFn: listMfaMethods,
    enabled: isAuthenticated(),
    staleTime: 5 * 60 * 1000,
  });
  const needsMfaSetup = Boolean(mfaMethods && !mfaMethods.some((m) => m.verified_at));

  useEffect(() => {
    if (needsMfaSetup) router.replace("/setup/mfa");
  }, [needsMfaSetup, router]);

  function handleSignOut() {
    clearTokens();
    router.replace(`/login`);
  }

  if (!isAuthenticated()) return null;

  // Hold the console back until enrollment is known: rendering it first would
  // flash the nav at someone who is about to be sent to setup.
  if (mfaLoading || needsMfaSetup) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-muted-foreground/40 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-muted/30">
      {/* Sidebar */}
      <aside className="flex w-[220px] flex-col border-r bg-sidebar">
        {/* Brand */}
        <div className="flex h-14 items-center gap-2.5 px-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <span className="text-sm font-bold tracking-tight">Knox IAM</span>
        </div>

        <Separator />

        {/* Tenant info */}
        <div className="px-4 py-3">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70">
            Tenant
          </p>
          <p className="mt-1.5 inline-flex max-w-full items-center gap-1.5 rounded-md border border-sidebar-border bg-sidebar-accent/40 px-2 py-1 font-mono text-[11px] text-foreground/80">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" />
            <span className="truncate">{tenantId}</span>
          </p>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-3 py-2 space-y-0.5">
          {!restricted &&
            tenantNavItems.map((item) => (
              <NavLink key={item.href} item={item} />
            ))}

          {!restricted && isPlatform && (
            <div className="pt-4">
              <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70">
                Platform
              </p>
              {platformNavItems.map((item) => (
                <NavLink key={item.href} item={item} />
              ))}
            </div>
          )}
        </nav>

        <Separator />

        {/* Account + theme + sign out */}
        <div className="p-3 space-y-0.5">
          {accountNavItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
          <ThemeToggle />
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start gap-2 text-muted-foreground hover:text-foreground"
            onClick={handleSignOut}
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex flex-1 flex-col overflow-hidden bg-background">
        <div className="flex-1 overflow-y-auto">
          {restricted && !inAccount ? (
            <RestrictedGate tenantId={tenantId} />
          ) : (
            children
          )}
        </div>
        <VersionFooter />
      </main>
    </div>
  );
}
