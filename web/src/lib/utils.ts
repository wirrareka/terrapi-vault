import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn class-merge helper. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format a unix-seconds timestamp as a short local datetime. */
export function fmtUnix(secs: number): string {
  return new Date(secs * 1000).toLocaleString();
}

/** Case-insensitive substring match of `query` against any of `fields`; empty query matches all. */
export function matches(query: string, ...fields: (string | undefined)[]): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return fields.some((f) => (f ?? "").toLowerCase().includes(q));
}

/** Seconds-from-now until `expires_at` (unix secs), as a compact "in 2h 5m" / "expired". */
export function untilExpiry(expiresAt: number, now: number): string {
  const d = expiresAt - now;
  if (d <= 0) return "expired";
  const h = Math.floor(d / 3600);
  const m = Math.floor((d % 3600) / 60);
  return h > 0 ? `in ${h}h ${m}m` : `in ${m}m`;
}
