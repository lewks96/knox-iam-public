"use client";

import { AppShell } from "@/components/layout/app-shell";
import { useAuthStore } from "@/lib/auth-store";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { PLATFORM_SCOPE } from "@/lib/config";

export default function TenantsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { hydrate, isAuthenticated, tenantId, hasScope } = useAuthStore();
  const router = useRouter();
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    hydrate();
    setHydrated(true);
  }, [hydrate]);

  useEffect(() => {
    // Tenants is a platform-level section. Gate on the platform scope actually
    // present in the token rather than on which tenant issued it — the server
    // now returns only the caller's own tenant to a non-platform session, so
    // rendering this section for them would show a single self-row, which is
    // worse than not offering it. Wait for hydration first: on a hard
    // navigation the store is empty until hydrate() has run, and redirecting
    // before then bounces authenticated users to login.
    if (!hydrated) return;
    if (!isAuthenticated() || !hasScope(PLATFORM_SCOPE)) {
      router.replace("/dashboard");
    }
  }, [hydrated, isAuthenticated, hasScope, tenantId, router]);

  if (!hydrated || !isAuthenticated() || !hasScope(PLATFORM_SCOPE)) return null;

  return <AppShell tenantId={tenantId!}>{children}</AppShell>;
}
