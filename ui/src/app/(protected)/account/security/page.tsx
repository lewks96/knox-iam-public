import { SecurityClient } from "./security-client";
import { ChangePasswordCard } from "@/components/account/change-password-card";

export default function SecurityPage() {
  return (
    <div className="mx-auto w-full max-w-2xl px-6 py-8">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">Security</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Manage the password and second factor used to sign in to your account.
        </p>
      </div>
      <div className="space-y-4">
        <ChangePasswordCard />
        <SecurityClient />
      </div>
    </div>
  );
}
