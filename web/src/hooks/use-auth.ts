import { useQuery } from "@tanstack/react-query";
import { apiGet, apiPost } from "@/lib/api";
import type { CurrentUser } from "@/lib/types";

/** The authenticated operator (console backend `/api/v1/auth/me`). A 401 in `apiGet` bounces to login. */
export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: () => apiGet<CurrentUser>("/auth/me"),
    retry: false,
    staleTime: 60_000,
  });
}

/**
 * Log out: POST (not a GET link) so it can't be CSRF-triggered, then reload at `/`. The backend
 * clears the session cookie and returns JSON. We navigate regardless of the result so a stale
 * session never leaves the operator stuck on the console.
 */
export async function logout(): Promise<void> {
  try {
    await apiPost("/auth/logout");
  } catch {
    // ignore — clear the client view either way
  }
  window.location.assign("/");
}
