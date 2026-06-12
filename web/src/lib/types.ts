// Console API types — mirror the broker observe DTOs (spec/broker-openapi.yaml 1.4.0) with a
// per-broker `broker` tag added by the console's fan-out aggregator. The console backend
// (services/vesta-console — not yet built; pending infra port + identity OIDC) implements
// /api/v1/* by calling each broker's /v1/.../observe/* over mTLS and tagging results by broker.
// Raw broker types can be regenerated with `pnpm gen:api` (→ broker-openapi.d.ts).

export interface Broker {
  id: string;
  addr: string;
  group: string;
  sealed: boolean;
  reachable: boolean;
  version?: string;
}

export interface Lease {
  broker: string;
  lease_id: string;
  parent_session: string;
  expires_at: number;
  max_deadline: number;
  renewable: boolean;
  role?: string;
}
export interface LeasesResponse {
  now: number;
  leases: Lease[];
}

export interface Session {
  broker: string;
  session_id: string;
  principal?: string;
  expires_at: number;
  idle_deadline: number;
  child_count: number;
}
export interface SessionsResponse {
  now: number;
  sessions: Session[];
}

export interface Role {
  broker: string;
  san: string;
  role: string;
  caps: string[];
}
export interface RolesResponse {
  roles: Role[];
}

export interface SshSerial {
  broker: string;
  lease_id: string;
  serial: number;
}
export interface SshRevoked {
  broker: string;
  serial: number;
}
export interface SshResponse {
  issued: SshSerial[];
  revoked: SshRevoked[];
}

export interface KmsKey {
  broker: string;
  tenant_id: string;
  key_id: string;
  current_version: number;
}
export interface KmsResponse {
  keys: KmsKey[];
}

export interface ObjectStoreStatus {
  broker: string;
  configured: boolean;
}
export interface ObjectStoreResponse {
  brokers: ObjectStoreStatus[];
}

export interface AuditRecord {
  broker: string;
  seq: number;
  event: Record<string, unknown>;
}
export interface AuditResponse {
  records: AuditRecord[];
  next_seq: number;
}

/** The authenticated operator (OIDC subject), surfaced by the console's /api/v1/auth/me. */
export interface CurrentUser {
  subject: string;
  email?: string;
  role: "operator";
}
