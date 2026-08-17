import { getTenant } from "@/lib/tenant-server";
import { ClientsPageClient } from "./clients-client";

export default async function ClientsPage() {
  const tenant = await getTenant();
  return <ClientsPageClient tenantId={tenant} />;
}
