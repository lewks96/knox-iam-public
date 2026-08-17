import { getTenant } from "@/lib/tenant-server";
import { MfaSetupClient } from "./mfa-setup-client";

/**
 * Outside the `(protected)` group on purpose: this screen replaces the console
 * rather than sitting inside it, so it must not render the app shell whose gate
 * sends people here.
 */
export default async function MfaSetupPage() {
  const tenant = await getTenant();
  return <MfaSetupClient tenantId={tenant} />;
}
