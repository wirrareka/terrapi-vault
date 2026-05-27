# Changelog

terrapi-vault — the secrets boundary for the quanto / proximi.io stack: a network
secrets **broker** (Path A) plus the embedded at-rest SQLCipher library it grew from.

## 0.1.0

First release of the **vault-broker** (Path A), feature-complete for the planned scope.
EU-first deploy on `medina`.

### Broker (services/vault-broker)
- **Daemon auth** — mutual TLS over WireGuard vs the fleet Root CA; verified peer SAN
  `dNSName` → role; **per-role capability authorization** (`ssh-ca`/`ssh-sign`/`creds`/
  `session`/`leases`/`kms`/`snapshot`) from `VAULT_ROLES_CONFIG` (deny-all if unset).
- **Master-key unseal** — operator passphrase (env or mode-600 file) → Argon2id → the
  at-rest SQLCipher store; mutating ops `503` until unsealed (`GET /v1/sys/seal-status`).
- **SSH-CA** — `GET /v1/{group}/ssh/ca`, `POST /v1/{group}/ssh/sign` (short-TTL OpenSSH
  certs, CA key never leaves the store); `GET /v1/{group}/ssh/revoked` revocation list.
- **Dynamic creds** — `POST /v1/{group}/{tenant_id}/creds/{role}`: ephemeral OpenSearch
  RBAC user (`audit-writer`), deleted on revoke/expiry.
- **KMS** — `POST …/kms/{key_id}/{wrap,unwrap,rotate}`: per-target AES-256-GCM KEK
  (versioned), never exported (aether fleet-backup keys).
- **Sessions + leases** — session-bound issuance keyed by mTLS principal; TTL/idle
  **expiry sweeper**; cascade-revoke on session end.
- **Audit** — canonical B3 (`source:"vault"`) to a tamper-evident **hash-chained** local
  store, best-effort shipped to group-local OpenSearch (replay via a durable cursor).
- **Store snapshot** — `POST /v1/sys/store-snapshot` (online `VACUUM INTO`, ciphertext).
- **Metrics** — Prometheus on a loopback/WG listener (`vault_sealed`, audit counters).
- v1 OpenAPI: `spec/broker-openapi.yaml`. FreeBSD deploy module: `deploy/`.

### Library (root crate, unchanged API)
- Embedded SQLCipher at-rest vault (Argon2id KDF, key rotation) — consumed by memento /
  probe; stays dependency-neutral on its 1.83 MSRV. (`derive_key` re-exported for the broker.)
