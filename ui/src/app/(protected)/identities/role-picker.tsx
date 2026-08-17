"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import {
  listRoles,
  canGrant,
  missingFor,
  ADMIN_ROLES,
  IMPLICIT_ROLE,
  type Role,
} from "@/lib/api/roles";
import { useAuthStore } from "@/lib/auth-store";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";

/**
 * Loads the tenant's roles and reports which the signed-in session may grant.
 *
 * The rule is the server's: you cannot grant a role carrying permissions you do
 * not hold. Evaluating it here too means an admin is never offered a choice that
 * would be refused — the server still decides.
 */
export function useGrantableRoles() {
  const scopes = useAuthStore((s) => s.scopes);

  const { data: roles, isLoading, isError } = useQuery({
    queryKey: ["roles"],
    queryFn: listRoles,
  });

  return useMemo(() => {
    const all = (roles ?? [])
      // Granted to everyone at creation, so it is never a decision.
      .filter((r) => r.name !== IMPLICIT_ROLE)
      .sort((a, b) => a.name.localeCompare(b.name));

    return {
      roles: all,
      isLoading,
      isError,
      grantable: (r: Role) => canGrant(r, scopes),
      missing: (r: Role) => missingFor(r, scopes),
      /** The admin preset, minus anything this session cannot grant. */
      adminPreset: all
        .filter((r) => (ADMIN_ROLES as readonly string[]).includes(r.name))
        .filter((r) => canGrant(r, scopes))
        .map((r) => r.name),
    };
  }, [roles, isLoading, isError, scopes]);
}

interface RolePickerProps {
  selected: string[];
  onChange: (roles: string[]) => void;
  idPrefix?: string;
}

export function RolePicker({ selected, onChange, idPrefix = "role" }: RolePickerProps) {
  const { roles, isLoading, isError, grantable, missing, adminPreset } =
    useGrantableRoles();

  function toggle(name: string, on: boolean) {
    onChange(on ? [...selected, name] : selected.filter((r) => r !== name));
  }

  const adminApplied =
    adminPreset.length > 0 && adminPreset.every((r) => selected.includes(r));

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-8 animate-pulse rounded-md bg-muted" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <p className="text-xs text-muted-foreground">
        Could not load roles. The identity will be created with{" "}
        <code className="font-mono">{IMPLICIT_ROLE}</code> only.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Every identity gets{" "}
          <code className="font-mono">{IMPLICIT_ROLE}</code>. Anything below is
          additional.
        </p>
        {adminPreset.length > 0 && (
          <Button
            type="button"
            variant={adminApplied ? "secondary" : "outline"}
            size="sm"
            className="h-7 text-xs"
            onClick={() =>
              onChange(
                adminApplied
                  ? selected.filter((r) => !adminPreset.includes(r))
                  : Array.from(new Set([...selected, ...adminPreset]))
              )
            }
          >
            <ShieldCheck className="mr-1.5 h-3 w-3" />
            {adminApplied ? "Clear administrator" : "Make administrator"}
          </Button>
        )}
      </div>

      <div className="space-y-1.5 rounded-md border p-3">
        {roles.map((role) => {
          const allowed = grantable(role);
          const id = `${idPrefix}-${role.name}`;
          return (
            <div key={role.id} className="flex items-start gap-2">
              <Checkbox
                id={id}
                className="mt-0.5"
                disabled={!allowed}
                checked={selected.includes(role.name)}
                onCheckedChange={(c) => toggle(role.name, !!c)}
              />
              <div className="min-w-0 flex-1">
                <Label
                  htmlFor={id}
                  className={`font-normal ${allowed ? "" : "text-muted-foreground"}`}
                >
                  {role.name}
                  {role.kind === "custom" && (
                    <Badge variant="outline" className="ml-2 text-[10px]">
                      custom
                    </Badge>
                  )}
                </Label>
                <p className="mt-0.5 font-mono text-[10px] leading-relaxed text-muted-foreground">
                  {role.permissions.map((p) => p.key).join(" · ") || "no permissions"}
                </p>
                {!allowed && (
                  <p className="mt-0.5 text-[10px] text-amber-600 dark:text-amber-500">
                    You cannot grant this — you do not hold{" "}
                    {missing(role).join(", ")}.
                  </p>
                )}
              </div>
            </div>
          );
        })}

        {roles.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No additional roles defined in this tenant.
          </p>
        )}
      </div>
    </div>
  );
}
