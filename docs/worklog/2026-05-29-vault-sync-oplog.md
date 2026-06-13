# worklog — vault-sync oplog server (#1) (2026-05-29)

Backlog item #1. Owner chose the **row-level oplog** model over pragmatic blob-sync (see the
memory `vault-sync-oplog-decision` and `docs/planning/02-vesta-sync-oplog.md`).

## Key finding that shaped the design

memento-core's `SyncProvider` trait is **whole-file blob** today (`push/pull(vault_path)`;
`GitSync` real, `MementoCloud` a stub). The oplog needs a **new client provider** in
memento-core — out of scope for this repo. So this turn delivers the **server + the published
wire contract**; the memento-core client is a separate, coordinated cross-repo effort.

## Built — `services/vault-sync` (was a print-only skeleton)

Server-blind row-level oplog. The server stores only `vault_id`, an enrolment verifier,
device ed25519 pubkeys, and opaque encrypted ops; it never holds the vesta key or plaintext.

- `store.rs` — SQLite (the lib's `rusqlite`; plain sqlite, payloads already E2E). Tables
  `accounts` / `devices` / `ops`; per-vesta monotonic `seq` allocated in the push tx;
  idempotent dedupe by `(vault_id, op_id)`; per-vesta isolation.
- `auth.rs` — raw ed25519 verify; versioned canonical sig string
  (`v1\n{method}\n{path?query}\n{vault_id}\n{ts}\n{nonce}\n{sha256(body)}`); enrolment-proof
  check (constant-time SHA-256 of the client's Argon2 secret); in-memory `ReplayGuard`
  (±300 s skew).
- `http.rs` — axum: `account` / `enroll-challenge` / `enroll` / `push` / `pull` / `status` /
  `healthz`. Device-signed (registered devices) + self-signed (account/enroll, proves key
  possession); `DefaultBodyLimit`. A device may only author ops under its own id.
- `config.rs` — env (`VAULT_SYNC_BIND` 8300, `VAULT_SYNC_DB`, `VAULT_SYNC_MAX_BODY_BYTES`,
  `VAULT_SYNC_MAX_PULL`). `main.rs` — `axum::serve` + graceful shutdown.

## Deps

Added `ed25519-dalek` to the services workspace (raw device-sig verification). No platform
deps entered vault-sync (no OpenSearch/tenants/residency) — Svet B firewall intact. Lib stays
neutral; vault-sync reuses the lib only for its `rusqlite` re-export.

## Verification

12 tests pass (store unit + auth unit + full two-device HTTP `oneshot` flow + unsigned-401 +
replay-401). `cargo clippy -p vault-sync --all-targets -- -D warnings` clean; `cargo fmt
--check` clean; whole services workspace builds (broker unaffected).

## Artifacts

- `spec/sync-openapi.yaml` (v1.0.0) — published wire contract.
- `docs/planning/02-vesta-sync-oplog.md` — design + status.
- Memory `vault-sync-oplog-decision`.

## Coordination

None in `proximiio-infra/coordination/` — vault-sync is **personal** (Svet B), not a platform
service in the identity/vault/kalista/vulture/infra circle. The consumer is memento-core (a
path-dep sibling); the client-provider contract lives in `spec/sync-openapi.yaml` +
`02-vesta-sync-oplog.md` for memento to implement. No `CONTRACTS.md` row (that file tracks the
platform "Secrets broker" boundary, not personal sync).

## Next

memento-core client `SyncProvider` (op capture + AEAD payloads + LWW apply); WS tail;
server-DB SQLCipher-at-rest; `deploy/` + TLS guidance; CRDT text-merge (Phase 4).
