// Thin typed fetch wrapper for the console backend API. Session is a cookie (OIDC RP login),
// so every request sends credentials. A 401 bounces to the login endpoint.

import { MOCK, mockGet } from "@/lib/mock";

const BASE = import.meta.env.VITE_API_BASE ?? "/api/v1";

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
