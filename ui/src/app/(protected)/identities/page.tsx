import { getTenant } from "@/lib/tenant-server";
import { IdentitiesPageClient } from "./identities-client";

interface IdentitiesPageProps {
  searchParams: Promise<{ pool?: string }>;
}

export default async function IdentitiesPage({ searchParams }: IdentitiesPageProps) {
  const [tenant, { pool }] = await Promise.all([getTenant(), searchParams]);
  return <IdentitiesPageClient tenantId={tenant} initialPoolId={pool} />;
}
