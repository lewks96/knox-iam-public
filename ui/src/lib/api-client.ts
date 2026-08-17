import { useAuthStore } from "./auth-store";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: { error: string; message?: string; trace_id?: string }
  ) {
    // Knox emits two body shapes: `AppError::{BadRequest,Unauthorized,Forbidden}`
    // put the reason in `message` and a generic status name in `error`, while
    // `ServiceError` puts the reason in `error` and has no `message`. Preferring
    // `message` picks the specific half of both — otherwise a rejected login
    // surfaces as "Unauthorized" rather than "Invalid credentials".
    super(body.message ?? body.error ?? `HTTP ${status}`);
    this.name = "ApiError";
  }
}

type RequestOptions = Omit<RequestInit, "body"> & {
  body?: unknown;
  params?: Record<string, string | number | boolean | undefined>;
  /** Skip the Authorization header (e.g. for token endpoint) */
  skipAuth?: boolean;
  /**
   * Treat a 401 as an ordinary error instead of an expired session.
   *
   * The default handling — clear tokens, bounce to `/login` — is correct for the
   * management API, where 401 can only mean the access token died. It is wrong
   * for the credential endpoints: `/authenticate` answers 401 for a bad
   * password and `/authenticate/mfa` answers it for a bad code. Redirecting
   * there discards the half-finished login (including the single-use MFA token,
   * which cannot be reissued without re-entering the password) and reports
   * "Session expired" for what is really "wrong code".
   */
  noSessionRedirect?: boolean;
};

export async function apiRequest<T = unknown>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  const { body, params, skipAuth, noSessionRedirect, ...rest } = options;

  // Build URL with query params
  let url = `${API_BASE}${path}`;
  if (params) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) qs.set(k, String(v));
    }
    const s = qs.toString();
    if (s) url += `?${s}`;
  }

  // Build headers
  const headers: Record<string, string> = {
    ...(rest.headers as Record<string, string>),
  };

  // Skip auth for form-encoded token requests
  if (!skipAuth) {
    const token = useAuthStore.getState().accessToken;
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  if (body !== undefined && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const resp = await fetch(url, {
    ...rest,
    headers,
    credentials: "include", // Include cookies (ssotoken)
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (resp.status === 401 && !noSessionRedirect) {
    useAuthStore.getState().clearTokens();
    if (typeof window !== "undefined") {
      const tenantId = useAuthStore.getState().tenantId;
      window.location.href = tenantId ? `/login` : "/";
    }
    throw new ApiError(401, { error: "Session expired" });
  }

  if (!resp.ok) {
    let errBody: { error: string; trace_id?: string };
    try {
      errBody = await resp.json();
    } catch {
      errBody = { error: `HTTP ${resp.status}` };
    }
    throw new ApiError(resp.status, errBody);
  }

  // 204 No Content
  if (resp.status === 204) return undefined as T;

  return resp.json() as Promise<T>;
}

/**
 * POST application/x-www-form-urlencoded — the OAuth token endpoint.
 *
 * Deliberately does NOT prefix `API_BASE`: OIDC endpoints live at the root of
 * the tenant host, because the issuer is `https://{tenant}.{base}` with no path
 * and discovery must resolve directly beneath it. `API_BASE` (`/api`) is only
 * for the management surface.
 */
export async function formPost<T = unknown>(
  path: string,
  fields: Record<string, string>
): Promise<T> {
  const body = new URLSearchParams(fields).toString();
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    credentials: "include",
    body,
  });

  if (!resp.ok) {
    let errBody: { error: string; trace_id?: string };
    try {
      errBody = await resp.json();
    } catch {
      errBody = { error: `HTTP ${resp.status}` };
    }
    throw new ApiError(resp.status, errBody);
  }

  return resp.json() as Promise<T>;
}
