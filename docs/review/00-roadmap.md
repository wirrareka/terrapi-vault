# terrapi-vault — Deep-analysis roadmap (2026-05-30)

Synthesis of four parallel agent reviews. Source reports:
[`security.md`](security.md) · [`performance.md`](performance.md) ·
[`architecture.md`](architecture.md) · [`api-dx.md`](api-dx.md).

Overall: the crypto core and the broker's design (mTLS, residency extractor, lease cascade,
hash-chained audit, route-template metrics) are **sound**. The weak edges are all in
**vault-sync** (newest crate, least hardened) and in a few **cross-cutting hygiene** gaps.
Severity uses the worst rating any agent assigned.

## Convergent findings (flagged by ≥2 agents — fix first)

| # | Theme | Agents | Where |
|---|-------|--------|-------|
| C1 | **Internal errors leak to clients** (`e.to_string()` on rusqlite/backend) — both a security info-leak AND an un-typed DX wire contract | security S5, architecture H1, api-dx High | `vault-broker/src/http.rs:520,629`; `vault-sync/src/http.rs:37` |
| C2 | **vault-sync unbounded in-memory state** (replay `seen`, `tails`, rate buckets) + single `Mutex<Connection>` choke | security S2/S7, performance High×3 | `vault-sync/src/{auth.rs:104,state.rs:23,store.rs}`; `hardening.rs:30` |
| C3 | **vault-sync lacks the broker's hardening** (no timeout/concurrency/rate-limit, no `vault_id` validation) | security S2, architecture Med | `vault-sync/src/http.rs` |

## Prioritized series

### P0 — Ship-blockers (security + a data-loss bug) — ✅ DONE 2026-05-30
- **R1. ✅ Brick-bug fixed**: `Store::create_account` now strict-decodes the verifier and
  returns `AccountError::InvalidVerifier` (hash must be 32-byte SHA-256) instead of
  `unwrap_or_default()`; the handler maps it to `400 bad_verifier`. `store.rs`, `http.rs`.
  Test `malformed_verifier_is_rejected_not_bricked`.
- **R2. ✅ vault_id validated + state bounded**: new `VaultId` `FromRequestParts` extractor
  (lowercase-UUIDv4) on every sync route → `400 bad_vault_id` before any store/map touch;
  `ReplayGuard.seen` hard-capped (`MAX_SEEN_NONCES`); `tails` map prunes 0-receiver channels
  on subscribe; broker rate-limit `buckets` evict idle entries at `MAX_BUCKETS`.
  `http.rs`, `auth.rs`, `state.rs`, `hardening.rs`. Test `non_uuid_vault_id_is_400`.
- **R3. ✅ enroll-challenge rate-limited + create proof-gated**: new `ratelimit::RateBucket`
  guards the unauthenticated `enroll-challenge` (`429 rate_limited`); `create_account` now
  requires `proof_b64` and checks `SHA-256(proof) == enroll.hash_b64`. _Note:_ for the **first**
  device this is an **enrollability/integrity** guarantee (the verifier is genuinely derivable;
  a 2nd device with the same passphrase can always enrol), not authentication — the real
  anti-squat control is the high-entropy UUIDv4 `vault_id` (R2) + rate-limiting. `http.rs`,
  `dto.rs`, `ratelimit.rs`, `spec/sync-openapi.yaml`. Test `create_with_mismatched_proof_is_401`.
- **R4. ✅ dev footguns fenced**: broker refuses to start when `VAULT_ALLOW_INSECURE_DEV=1`
  with a non-loopback bind; `VAULT_OS_INSECURE_TLS=1` is refused unless insecure-dev (engine
  stays disabled → creds 404, fail-closed). `main.rs`, `opensearch.rs`.

_Verification: `cargo build/clippy -D warnings/test/fmt` all clean; 51 tests pass (3 new)._

### P1 — Robustness  (✅ ALL DONE 2026-05-30)
- **R5. ✅ Internal error strings no longer leak** (C1): broker `internal()`/`backend()` helpers
  log the real rusqlite/backend/IO detail server-side and return a stable code + generic message
  (6 sites: ssh revoked-list, ssh sign, snapshot mkdir/vacuum/read, creds backend, kms store);
  vault-sync `db_err` does the same. `http.rs` (both), `opensearch.rs` untouched here.
- **R6. ✅ SQLite off the async runtime + WAL reader pool**: `Store` now holds a dedicated writer
  connection + a pool of `VAULT_SYNC_READERS` (default 4) read-only (`query_only`) connections;
  writes serialise on the writer, reads (`pull`/`status`/tail fan-out) round-robin across the pool.
  `AppState.store` is `Arc<Store>` (no outer mutex); every handler drives the store via a
  `store_op` helper over `spawn_blocking`, so SQLite I/O no longer stalls tokio workers and pooled
  reads run in parallel. `store.rs`, `state.rs`, `config.rs`, `http.rs`, `main.rs`. New test
  `file_store_with_reader_pool_reads_after_write`. _(chosen: writer + N-reader pool)_
- **R7. ✅ Audit shipper bounded**: `read_new_records` reads ≤ `MAX_SHIP_BYTES` (4 MiB) per tick
  and parses only up to the last complete line; `collect_backlog` caps at `MAX_SHIP_ITEMS` (500),
  advancing the cursor partially so a post-outage backlog drains incrementally. `audit_ship.rs`.
- **R8. ✅ vault-sync timeout + concurrency**: new `harden.rs` (concurrency cap → 503, request
  timeout → 408; WS upgrade returns before the budget so live tails are unaffected), env-tunable
  (`VAULT_SYNC_MAX_CONCURRENCY`/`_REQUEST_TIMEOUT_SECS`). `harden.rs`, `config.rs`, `state.rs`, `http.rs`.
- **R9. ✅ KMS nonce safety**: switched the envelope from AES-256-GCM (96-bit nonce) to
  **XChaCha20-Poly1305** (192-bit/24-byte nonce) — collision-safe under random nonces at any
  realistic wrap volume, so the long-lived KEK needs no wrap counter. Blob format is now
  `version(4 LE) || nonce(24) || ct+tag`; no migration (KMS not yet live). `kms.rs`,
  `Cargo.toml` (×2), `spec/broker-openapi.yaml`. _(chosen: algorithm swap over counter+rotate)_

### P2 — DX / contract / maintainability  (✅ ALL DONE 2026-05-30)
- **R10. ✅ Typed error contract**: `ErrorBody.error` (sync) and `Error.error` (broker) are now
  enums of every stable code with per-code status/meaning; both note that 5xx/502 details are
  generic. `spec/sync-openapi.yaml`, `spec/broker-openapi.yaml`. _(X-Request-Id correlation
  deferred — small follow-up, folded into R13's shared helpers if/when added.)_
- **R11. ✅ Hard-to-implement bits specified**: `info.description` now fully documents the
  ed25519 canonical string, base64 variant, GET/empty-body hashing, ±300 s skew + nonce scope,
  and ships a **real test vector** (seed `[7;32]` → pubkey/body-hash/canonical/sig) pinned by the
  `signing_test_vector_is_stable` unit test; `/tail` frames specified via the new `TailFrame`
  schema (`StoredOp` | `{"resync":true}`). `spec/sync-openapi.yaml`, `auth.rs`.
- **R12. ✅ Pagination + idempotency documented**: `pull` describes `limit` cap + `since`/`latest_seq`
  cursor loop; `push` documents `op_id` idempotency (`accepted+duplicates==len`, no seq consumed
  on dup) and `latest_seq`. `spec/sync-openapi.yaml`.
- **R13. ✅ De-dup into vault-transport**: new `vault_transport::http` holds the shared
  `ErrorBody`/`Ack` (serde) + `env_parse` (std); both services re-export them from their `dto.rs`
  and use `env_parse` in `from_env`. `vault-transport` stays axum/time-free (the axum-coupled
  `err()` and `time`-based `now_unix` stay per-service). `vault-transport/src/http.rs` (+3 tests),
  `vault-broker/src/{dto,config}.rs`, `vault-sync/src/{dto,config}.rs`.
- **R14. ✅ Test gaps closed**: broker `principal_extractor_maps_verified_san_to_role` covers the
  prod mTLS `ClientSan`→role/403/401 path; vault-sync `tail_websocket_receives_pushed_op` is a real
  end-to-end WS test (signed upgrade → push fan-out → client receives the frame). `http.rs` (both).

### P3 — Hardening polish  (✅ ALL DONE 2026-05-30)
- **R15. ✅ ReplayGuard retention widened to 2·SKEW** (S8): a captured request stays
  skew-acceptable up to `2·MAX_SKEW_SECS` after first record, so the nonce is now kept that long
  (`NONCE_RETENTION_SECS`) — pruning at `SKEW` left a same-`ts` replay hole. `vault-sync/src/auth.rs`.
- **R16. ✅ Constant-time key compare in `rotate_key`** (S10): the old-vs-current derived-key
  check is now an XOR-accumulate over all 32 bytes (`constant_time_eq`, no new crate — root lib
  stays neutral). `src/vault.rs` (+ unit test).
- **R17. ✅ Opaque snapshot handle (S11)**: aether confirmed (2026-05-30) it consumes **no**
  path from `store-snapshot` (case 2), so `StoreSnapshotResponse` now returns an opaque
  `snapshot_id` (filename only) + `sha256` + `bytes` — the absolute `snapshot_path`/`meta_path`
  host paths are gone from the wire (kept server-side for audit/IR only). `http.rs`, `dto.rs`,
  `spec/broker-openapi.yaml`. Coordinated via `inbox/aether/vault-snapshot-path-opaque-handle.md`.
- **R18. ✅ Metadata threat-model documented** (S9): new "Threat model — what the server learns"
  section in `docs/planning/02-vault-sync-oplog.md` — enumerates the metadata an
  honest-but-curious server sees (op/device counts, timing, sizes, cleartext `collection_id`) vs.
  what stays blind, and the revisit list (mandatory HMAC `collection_id` + size padding) if it
  ever serves others' data.

## Suggested execution order
R1 → R2 → R3 → R4  (P0, mostly vault-sync; ~1 focused session)
then R5–R9 (P1), then the DX/spec batch R10–R14, then polish.
P0+P1 are almost entirely additive guards — low blast radius, no contract breaks.
R10/R11 are spec-only and unblock the memento client implementer.
