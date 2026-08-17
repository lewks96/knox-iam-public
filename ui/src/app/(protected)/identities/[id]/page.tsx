import { getTenant } from "@/lib/tenant-server";
import { IdentityDetailClient } from "./identity-detail-client";

interface IdentityDetailPageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ pool?: string }>;
}

export default async function IdentityDetailPage({
  params,
  searchParams,
}: IdentityDetailPageProps) {
  const [{ id }, { pool }, tenant] = await Promise.all([
    params,
    searchParams,
    getTenant(),
  ]);
  return (
    <IdentityDetailClient tenantId={tenant} identityId={id} poolId={pool} />
  );
}
