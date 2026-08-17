"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/auth-store";

/**
 * The tenant is the host now, so there is nothing to choose here — this is just
 * the front door for `https://{tenant}.{base}/`. It replaces the old
 * enter-your-tenant-slug landing page, which had no meaning once the slug moved
 * out of the path.
 */
export default function Home() {
  const router = useRouter();

  useEffect(() => {
    const store = useAuthStore.getState();
    router.replace(store.isAuthenticated() ? "/dashboard" : "/login");
  }, [router]);

  return null;
}
