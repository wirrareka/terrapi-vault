import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import type {
  AuditResponse,
  Broker,
  KmsResponse,
  LeasesResponse,
  ObjectStoreResponse,
  RolesResponse,
  SessionsResponse,
  SshResponse,
} from "@/lib/types";

// Read-only observe views poll on a modest interval (operator dashboard, not real-time).
const POLL_MS = 10_000;

export function useBrokers() {
  return useQuery({
    queryKey: ["brokers"],
    queryFn: () => apiGet<Broker[]>("/brokers"),
    refetchInterval: POLL_MS,
  });
}

export function useLeases() {
  return useQuery({
    queryKey: ["observe", "leases"],
    queryFn: () => apiGet<LeasesResponse>("/observe/leases"),
    refetchInterval: POLL_MS,
  });
}

export function useSessions() {
  return useQuery({
    queryKey: ["observe", "sessions"],
    queryFn: () => apiGet<SessionsResponse>("/observe/sessions"),
    refetchInterval: POLL_MS,
  });
}

export function useRoles() {
  return useQuery({
    queryKey: ["observe", "roles"],
    queryFn: () => apiGet<RolesResponse>("/observe/roles"),
  });
}

export function useSsh() {
  return useQuery({
    queryKey: ["observe", "ssh"],
    queryFn: () => apiGet<SshResponse>("/observe/ssh"),
    refetchInterval: POLL_MS,
  });
}

export function useKms() {
  return useQuery({
    queryKey: ["observe", "kms"],
    queryFn: () => apiGet<KmsResponse>("/observe/kms"),
  });
}

export function useObjectStore() {
  return useQuery({
    queryKey: ["observe", "object-store"],
    queryFn: () => apiGet<ObjectStoreResponse>("/observe/object-store"),
  });
}

export function useAudit(since: number, limit: number) {
  return useQuery({
    queryKey: ["observe", "audit", since, limit],
    queryFn: () => apiGet<AuditResponse>("/observe/audit", { since, limit }),
    refetchInterval: POLL_MS,
  });
}
