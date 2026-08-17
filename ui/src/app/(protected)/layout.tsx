import { AppShell } from "@/components/layout/app-shell";
import { getTenant } from "@/lib/tenant-server";

export default async function TenantLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const tenant = await getTenant();
  return <AppShell tenantId={tenant}>{children}</AppShell>;
}
