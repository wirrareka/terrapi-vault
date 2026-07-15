// Thin typed fetch wrapper for the console backend API. Session is a cookie (OIDC RP login),
// so every request sends credentials. A 401 bounces to the login endpoint.

import { MOCK, mockGet } from "@/lib/mock";

// API base derives from the Vite base path so calls land under the app's mount
// prefix behind the Beast/Kalista gateway (`import.meta.env.BASE_URL` is
// `/apps/vesta/` there → `/apps/vesta/api/v1`) and stay host-relative for the
// standalone vault-console binary (`BASE_URL` is `/` → `/api/v1`). Kalista
// strips the `/apps/vesta` prefix before proxying, so the backend keeps its
// native `/api/v1` paths. VITE_API_BASE still overrides for custom setups.
// BASE_URL always ends in a slash, so `${BASE_URL}api/v1` composes cleanly.
const BASE = import.meta.env.VITE_API_BASE ?? `${import.meta.env.BASE_URL}api/v1`;

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Params = Record<string, string | number | undefined>;

export async function apiGet<T>(path: string, params?: Params): Promise<T> {
  if (MOCK) {
    // Standalone demo: serve fixtures with a small delay so loading states render.
    await new Promise((r) => setTimeout(r, 120));
    return mockGet<T>(path);
  }
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url, {
    credentials: "include",
    headers: { accept: "application/json" },
  });
  if (res.status === 401) {
    // Not authenticated → start the OIDC login flow on the backend.
    window.location.assign(`${BASE}/auth/login`);
    throw new ApiError(401, "authentication required");
  }
  if (!res.ok) {
    throw new ApiError(res.status, `${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

/** POST for the (P2) management/logout actions. */
export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(new URL(BASE + path, window.location.origin), {
    method: "POST",
    credentials: "include",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}
