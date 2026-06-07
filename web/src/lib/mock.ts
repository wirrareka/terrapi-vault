// Fixture data for standalone demo / tests (no console backend). Activated by VITE_MOCK=1.
// Shapes match src/lib/types.ts (the console API contract). Two eu brokers so the broker filter
// + per-broker aggregation are visible.

import type {
  AuditResponse,
  Broker,
  CurrentUser,
  KmsResponse,
  LeasesResponse,
  ObjectStoreResponse,
  RolesResponse,
  SessionsResponse,
  SshResponse,
} from "@/lib/types";

export const MOCK = import.meta.env.VITE_MOCK === "1";

// Fixed clock so relative-expiry rendering is stable in tests.
const NOW = 1_780_000_000;
const B1 = "vault-eu-1";
const B2 = "vault-eu-2";
const T1 = "11111111-1111-4111-8111-111111111111";
const T2 = "22222222-2222-4222-8222-222222222222";

const brokers: Broker[] = [
  { id: B1, addr: "10.200.0.101:8200", group: "eu", sealed: false, reachable: true, version: "0.1.7" },
  { id: B2, addr: "10.200.0.103:8200", group: "eu", sealed: false, reachable: true, version: "0.1.7" },
];

const me: CurrentUser = { subject: "ops@proximi.io", email: "ops@proximi.io", role: "operator" };

const leases: LeasesResponse = {
  now: NOW,
  leases: [
    { broker: B1, lease_id: "ls-a1", parent_session: "se-1", expires_at: NOW + 1800, max_deadline: NOW + 28800, renewable: true, role: "audit-writer" },
    { broker: B1, lease_id: "ls-a2", parent_session: "se-1", expires_at: NOW + 600, max_deadline: NOW + 3600, renewable: false },
    { broker: B2, lease_id: "ls-b1", parent_session: "se-2", expires_at: NOW + 7200, max_deadline: NOW + 28800, renewable: true, role: "tile-publish" },
  ],
};

const sessions: SessionsResponse = {
  now: NOW,
  sessions: [
    { broker: B1, session_id: "se-1", principal: "demon-operator.eu.proximi.internal", expires_at: NOW + 25200, idle_deadline: NOW + 1500, child_count: 2 },
    { broker: B2, session_id: "se-2", principal: "demon-operator.eu.proximi.internal", expires_at: NOW + 26000, idle_deadline: NOW + 1700, child_count: 1 },
  ],
};

const roles: RolesResponse = {
  roles: [
    { broker: B1, san: "demon-operator.eu.proximi.internal", role: "demon-operator", caps: ["ssh-sign", "creds", "session", "leases"] },
    { broker: B1, san: "aether-backup.eu.proximi.internal", role: "aether-backup", caps: ["kms", "snapshot"] },
    { broker: B2, san: "proximiio-outer-map.eu.proximi.internal", role: "outer-map-publish", caps: ["object-store"] },
  ],
};

const ssh: SshResponse = {
  issued: [
    { broker: B1, lease_id: "ls-a2", serial: 4471 },
    { broker: B2, lease_id: "ls-b9", serial: 4472 },
  ],
  revoked: [{ broker: B1, serial: 4099 }],
};

const kms: KmsResponse = {
  keys: [
    { broker: B1, tenant_id: T1, key_id: "aether-fra1", current_version: 2 },
    { broker: B2, tenant_id: T2, key_id: "aether-fra1", current_version: 1 },
  ],
};

const objectStore: ObjectStoreResponse = {
  brokers: [
    { broker: B1, configured: true },
    { broker: B2, configured: false },
  ],
};

const audit: AuditResponse = {
  records: [
    { broker: B1, seq: 41, event: { ts: "2026-06-06T18:00:01Z", source: "vault", action: "creds.issue", outcome: "success", target: { kind: "creds", id: "role=audit-writer;tenant=" + T1 } } },
    { broker: B1, seq: 42, event: { ts: "2026-06-06T18:01:10Z", source: "vault", action: "object_store.presign", outcome: "success", target: { kind: "object-store", id: "key=t/" + T1 + "/berlin/v3.pmtiles" } } },
    { broker: B2, seq: 17, event: { ts: "2026-06-06T18:02:30Z", source: "vault", action: "ssh.sign", outcome: "success", target: { kind: "ssh", id: "serial=4472" } } },
  ],
  next_seq: 43,
};

const routes: Record<string, unknown> = {
  "/brokers": brokers,
  "/auth/me": me,
  "/observe/leases": leases,
  "/observe/sessions": sessions,
  "/observe/roles": roles,
  "/observe/ssh": ssh,
  "/observe/kms": kms,
  "/observe/object-store": objectStore,
  "/observe/audit": audit,
};

/** Return fixture data for `path` (query string ignored). Throws on an unknown route. */
export function mockGet<T>(path: string): T {
  const key = path.split("?")[0];
  if (key in routes) return routes[key] as T;
  throw new Error(`mock: no fixture for ${key}`);
}
