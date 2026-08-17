import { getTenant } from "@/lib/tenant-server";
import { TenantClient } from "./tenant-client";

export default async function TenantPage() {
  const tenant = await getTenant();
  return <TenantClient tenantId={tenant} />;
}
