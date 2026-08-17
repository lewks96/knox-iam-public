import { getTenant } from "@/lib/tenant-server";
import { AuditPageClient } from "./audit-client";

interface AuditPageProps {
  searchParams: Promise<{ actor?: string }>;
}

export default async function AuditPage({ searchParams }: AuditPageProps) {
  const tenant = await getTenant();
  const { actor } = await searchParams;
  return <AuditPageClient tenantId={tenant} initialActorId={actor} />;
}
