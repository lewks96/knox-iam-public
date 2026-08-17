"use client";

import { useQuery } from "@tanstack/react-query";
import { getHealth } from "@/lib/api/system";
import { useAuthStore } from "@/lib/auth-store";
import { PLATFORM_SCOPE } from "@/lib/config";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, Server, ShieldCheck } from "lucide-react";

export default function DashboardPage() {
  const { data: health, isLoading, isError } = useQuery({
    queryKey: ["health"],
    queryFn: getHealth,
    refetchInterval: 30_000,
  });
  // Platform-level shortcuts only make sense for a session that actually holds
  // the platform scope — for everyone else /tenants shows nothing they can act
  // on. Same rule as the sidebar's Platform section.
  const isManagement = useAuthStore((s) => s.scopes.includes(PLATFORM_SCOPE));

  return (
    <div className="p-8 space-y-8">
      <div className="border-b pb-6">
        <h1 className="text-xl font-bold">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Platform overview and system health.
        </p>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card className="shadow-none">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">API Health</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading && (
              <div className="h-5 w-16 animate-pulse rounded-md bg-muted" />
            )}
            {isError && <Badge variant="destructive">Unreachable</Badge>}
            {health && (
              <Badge
                variant={health.status === "ok" ? "default" : "destructive"}
                className="text-xs"
              >
                {health.status}
              </Badge>
            )}
          </CardContent>
        </Card>

        <Card className="shadow-none">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Server Version</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading && (
              <div className="h-6 w-20 animate-pulse rounded-md bg-muted" />
            )}
            {health && (
              <p className="font-mono text-xl font-bold">{health.version}</p>
            )}
            {isError && <p className="text-sm text-muted-foreground">—</p>}
          </CardContent>
        </Card>

        <Card className="shadow-none">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Platform</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <p className="text-xl font-bold">Knox</p>
            <p className="text-xs text-muted-foreground">Identity &amp; Access Management</p>
          </CardContent>
        </Card>
      </div>

      {/* Quick links */}
      <div>
        <h2 className="text-sm font-semibold mb-3">Quick navigation</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            { label: "Manage Customers", description: "Create, update, and delete your applications' end users.", href: "/identities" },
            { label: "Manage Clients", description: "Configure OAuth2 clients and rotate secrets.", href: "/clients" },
            { label: "Tenant Settings", description: "Administrators, directories, and sign-in policy.", href: "/tenant" },
            ...(isManagement
              ? [{ label: "Manage Tenants", description: "Create and administer platform tenants.", href: "/tenants" }]
              : []),
          ].map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="group flex flex-col gap-1 rounded-xl border bg-card p-4 hover:bg-accent transition-colors shadow-none"
            >
              <p className="text-sm font-semibold group-hover:text-accent-foreground">
                {link.label}
              </p>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {link.description}
              </p>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
