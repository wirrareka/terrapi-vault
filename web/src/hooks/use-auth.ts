import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
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

/** Backend logout endpoint (clears the session cookie, then redirects). */
export function logoutUrl(): string {
  const base = import.meta.env.VITE_API_BASE ?? "/api/v1";
  return `${base}/auth/logout`;
}
