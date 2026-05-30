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

### P1 — Robustness
- **R5. Stop leaking internal error strings** (C1): map rusqlite/backend errors to a generic
  client message + stable code; log detail locally. Pairs with R10.
- **R6. SQLite off the async runtime**: wrap blocking DB + base64 in `spawn_blocking`; move to
  a small WAL reader pool so a large `pull` can't starve live-tail. _(perf High)_
- **R7. Bound the audit shipper**: cap bytes/events per `_bulk` tick and drain incrementally so
  a post-outage backlog can't OOM or wedge the cursor. _(perf High)_
- **R8. Add timeout + concurrency limits to vault-sync** (mirror `hardening.rs`). _(arch, S2)_
- **R9. KMS nonce safety**: per-KEK wrap counter + auto-rotate, or switch to AES-GCM-SIV /
  XChaCha20-Poly1305. _(S6)_

### P2 — DX / contract / maintainability
- **R10. Typed error contract**: promote `ErrorBody.error` to an enum in both `spec/*.yaml`
  with per-status examples; add `X-Request-Id` correlation on both services. _(api-dx High/Med)_
- **R11. Specify the hard-to-implement bits**: publish the ed25519 canonical-string + a test
  vector, document skew/nonce-scope/base64-variant, and add the `/tail` WS frame shapes
  (`StoredOp` vs `{"resync":true}`) to `sync-openapi.yaml`. _(api-dx High)_
- **R12. Document `pull` pagination** (limit cap + next-cursor) and the `op_id` idempotency /
  `latest_seq` semantics in the spec. _(api-dx Med)_
- **R13. De-dup into vault-transport**: `ErrorBody`/`Ack`/`err()`/`env_parse`/`now_unix` are
  copy-pasted across both services — promote to the shared base. _(arch Med)_
- **R14. Close test gaps**: vault-sync has 1 oneshot HTTP test; auth/replay/WS-tail and the
  prod mTLS branch are end-to-end untested. _(arch Med)_

### P3 — Hardening polish
- R15. ReplayGuard prune-window strictly wider than accept-window (S8).
- R16. Constant-time key compare in `rotate_key` (S10).
- R17. Opaque snapshot handles instead of host paths (S11).
- R18. Threat-model doc for vault-sync metadata (op/device counts, `collection_id`, sizes);
  consider HMAC'd `collection_id` + size padding (S9).

## Suggested execution order
R1 → R2 → R3 → R4  (P0, mostly vault-sync; ~1 focused session)
then R5–R9 (P1), then the DX/spec batch R10–R14, then polish.
P0+P1 are almost entirely additive guards — low blast radius, no contract breaks.
R10/R11 are spec-only and unblock the memento client implementer.
