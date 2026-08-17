import { create } from "zustand";

interface AuthState {
  accessToken: string | null;
  tenantId: string | null;
  scopes: string[];
  expiresAt: number | null; // Unix timestamp (ms)

  setTokens: (
    accessToken: string,
    tenantId: string,
    expiresIn: number,
    scopes?: string[]
  ) => void;
  clearTokens: () => void;
  hydrate: () => void;
  isAuthenticated: () => boolean;
  /// Platform surfaces gate on this rather than on the tenant slug: the scopes
  /// the server actually granted are authoritative, and `knox-root` was only
  /// ever a convention the client had no way to verify.
  hasScope: (scope: string) => boolean;
}

const STORAGE_KEY = "knox_auth";

interface StoredAuth {
  accessToken: string;
  tenantId: string;
  scopes: string[];
  expiresAt: number;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  accessToken: null,
  tenantId: null,
  scopes: [],
  expiresAt: null,

  setTokens: (accessToken, tenantId, expiresIn, scopes = []) => {
    const expiresAt = Date.now() + expiresIn * 1000;
    set({ accessToken, tenantId, expiresAt, scopes });

    // Persist to sessionStorage so reloads stay authenticated
    const stored: StoredAuth = { accessToken, tenantId, expiresAt, scopes };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
  },

  clearTokens: () => {
    set({ accessToken: null, tenantId: null, expiresAt: null, scopes: [] });
    sessionStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem("knox_pkce_verifier");
    sessionStorage.removeItem("knox_pkce_state");
    sessionStorage.removeItem("knox_pkce_tenant");
  },

  hydrate: () => {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return;

      const stored: StoredAuth = JSON.parse(raw);
      if (!stored.accessToken || !stored.tenantId || !stored.expiresAt) return;

      // Only restore if token hasn't expired (with a 30-second buffer)
      if (stored.expiresAt - 30_000 > Date.now()) {
        set({
          accessToken: stored.accessToken,
          tenantId: stored.tenantId,
          expiresAt: stored.expiresAt,
          scopes: stored.scopes ?? [],
        });
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // Ignore malformed storage
    }
  },

  isAuthenticated: () => {
    const { accessToken, expiresAt } = get();
    return !!accessToken && !!expiresAt && expiresAt - 30_000 > Date.now();
  },

  hasScope: (scope: string) => get().scopes.includes(scope),
}));
