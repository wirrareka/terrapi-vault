# terrapi-vault — Architecture & Code-Quality Review

Reviewed 2026-05-30. Scope: root lib crate (`src/`) + the 3-member services
workspace (`services/vault-transport`, `vault-broker`, `vault-sync`).
Verdict: the dependency firewall is **intact and well-defended**; the issues below
are quality/consistency refinements, not boundary breaches.

Each finding: **Impact** · location · issue · concrete refactor.

---

## 1. Module boundaries & the dependency firewall

### 1.1 — Firewall holds (no action) · GOOD
- `services/vault-sync/Cargo.toml` carries **zero** platform deps; the only mentions
  of `opensearch/tenant/residency` in `vault-sync/src/` are *negative* doc comments
  (`config.rs:2`, `main.rs:7-8`). Verified by grep — clean.
- Root `src/` pulls in **no** `axum/tokio/reqwest/hyper/rustls` — neutrality preserved;
  consumers (memento/probe) stay unconstrained.
- `vault-transport/src/{lib,lease,audit}.rs` import no async runtime — the lease engine
  is explicitly "time-aware but clock-free" (`lease.rs:7`), storage-agnostic and
  in-memory. This is the correct shared base, **not** a junk drawer: every item
  (`ResidencyGroup`, `Hlc`, `LeaseEngine`, `AuditEvent`) is opt-in and genuinely shared.

### 1.2 — `Hlc` is a stub but is on every wire/storage path · **Med**
- `vault-transport/src/lib.rs` — `Hlc { wall_ms, counter }` is `Ord` but the doc says
  "Real impl in Phase 1/3". Meanwhile `vault-sync/src/dto.rs:18`, `store.rs:248/300`,
  and `http.rs:592` already persist and serialize it as the per-row LWW key.
- Risk: there is no constructor / `tick()` / merge logic, so HLC *generation* lives
  entirely client-side and the server treats it as an opaque pair. That is fine for
  server-blind sync, but the "shared by the broker lease tree" claim (`lib.rs` doc) is
  currently false — the broker lease tree uses raw `u64` unix seconds, not `Hlc`.
- Refactor: either (a) drop the "shared by the lease tree" sentence and re-scope `Hlc`
  as a sync-only ordering pair, or (b) add the `tick`/`merge` impl and actually thread
  it through `lease.rs`. Don't leave a primitive whose doc over-claims its reach.

### 1.3 — `ResidencyGroup` lives in transport but only the broker uses it · Low
- `vault-transport/src/lib.rs` exposes `ResidencyGroup`; `vault-sync` never references
  it (correct). It is shared *only* in the sense that transport is the broker's base.
  Acceptable, but if vault-transport is ever consumed by a third (non-broker) service,
  move residency into a `vault-broker`-private module to keep transport tenant-agnostic.

---

## 2. Code quality

### 2.1 — Internal error text leaks to clients · **High**
- `vault-broker/src/http.rs:520` — `backend_error` detail = `&e.to_string()` of the
  cred-engine/OpenSearch error.
- `vault-broker/src/http.rs:629` (`map_kms_err`) and the generic `store_error` arms —
  surface raw `rusqlite`/SQLCipher/store error strings in the JSON `detail` field.
- `vault-sync/src/http.rs:37` (`db_err`) — same: `INTERNAL_SERVER_ERROR` body carries
  `e.to_string()` of the rusqlite error to the device.
- These reach an authenticated-but-not-fully-trusted peer (a daemon / a personal device)
  and can disclose schema, paths, and backend internals.
- Refactor: log the full error server-side (it is already counted in metrics); return a
  **stable opaque** `detail` (e.g. `"backend unavailable"`, `"internal store error"`).
  The `KmsError::Crypto` arm (`http.rs:625`) already does this correctly — follow that
  pattern everywhere. Keep `BadInput`/validation details (those are caller-actionable).

### 2.2 — `ErrorBody`, `Ack`, and `err()` are triplicated across the firewall · **Med**
- `ErrorBody` is defined in **both** `vault-broker/src/dto.rs:7` and
  `vault-sync/src/dto.rs` (the latter's doc literally says "mirrors the broker's shape").
- `Ack { ok: bool }` defined in both DTO files.
- The `fn err(status, error, detail) -> (StatusCode, Json<ErrorBody>)` helper is
  copy-pasted: `vault-broker/src/http.rs:27` and `vault-sync/src/http.rs:27` are nearly
  identical.
- This is genuinely shared *wire shape* with no platform content — exactly what
  `vault-transport` is for.
- Refactor: add `vault_transport::http` (feature-gated behind an `axum` optional dep, or
  a plain `ErrorBody`/`Ack` in transport with the `err()` helper in each service if you
  want transport to stay axum-free). At minimum hoist `ErrorBody`/`Ack` structs into
  transport so the two specs cannot drift in field names.

### 2.3 — Silent data corruption on malformed base64 in the account path · **High**
- `vault-sync/src/store.rs:99-100` — `create_account` does
  `b64().decode(...).unwrap_or_default()` for `enroll_salt` and `enroll_hash`. A client
  that sends a malformed `salt_b64`/`hash_b64` gets an **empty `Vec`** stored silently,
  permanently bricking enrolment for that vesta (the verifier hash becomes `[]`, so no
  future device can ever pass `verify_enroll_proof`).
- `store.rs:101/128` — `serde_json` of `KdfParams` `unwrap_or_default()` likewise hides
  serialization failure.
- Contrast: the `push_ops` path (`store.rs`) correctly returns `PushError::InvalidPayload`
  on bad base64. The account path should be just as strict.
- Refactor: decode in the handler (or return a `CreateAccountError`) and reject with
  `400 bad_body` before the INSERT, mirroring the push path. Never `unwrap_or_default()`
  a security verifier.

### 2.4 — Magic numbers: skew/capacity centralized unevenly · Low
- Good: `vault-broker/src/config.rs:15-19` centralizes all hardening defaults as
  `pub const` + env override; `vault-sync/src/config.rs:8-10` does the same for its two.
- Stragglers: `MAX_SKEW_SECS` (`vault-sync/src/auth.rs:24`) and `TAIL_CAPACITY`
  (`vault-sync/src/state.rs`) are hard-coded `const` with no env override. The replay
  window and tail buffer are operationally relevant; lift them into `config.rs` for
  consistency with the rest of the service's "everything tunable via env" stance.

### 2.5 — `Op`/`StoredOp`/`seq` model is clear · GOOD (minor)
- `vault-sync/src/dto.rs` — `Op` (client→server, no seq) vs `StoredOp { seq, #[flatten] op }`
  (server→client) is a clean, well-documented split; `seq` is unambiguously the per-vesta
  pull cursor. The `i64`↔`u64` boundary conversions in `store.rs` (SQLite is i64-native)
  are defensive but verbose; a small `fn seq_to_db/db_to_seq` helper would DRY the four
  `try_from(...).unwrap_or(...)` sites and document the clamp policy once.

### 2.6 — Dead code is honestly annotated · Low
- The four `#[allow(dead_code)]` sites (`dto.rs:22` `SshSignRequest`, `creds.rs:27`,
  `state.rs:155`, `http.rs:64` `Group`) are all "fixed v1 contract, consumed when X lands"
  — deliberate forward-declarations, correctly commented. No stale dead code found. Keep
  a tracking note so they don't outlive their phase.

---

## 3. Broker ↔ sync consistency (where they diverge unnecessarily)

### 3.1 — sync has **no** request hardening; broker has a full stack · **Med**
- `vault-broker` applies timeout + concurrency cap + **per-principal token-bucket rate
  limit** + body cap via `hardening.rs` (208 LOC).
- `vault-sync/src/http.rs:59` applies **only** `DefaultBodyLimit::max(...)` — no timeout,
  no concurrency cap, no rate limit. A single device (or a stolen device key) can hammer
  push/pull unbounded against the personal server's single `Mutex<Store>`.
- These are not platform-specific; the timeout/concurrency/body middleware in
  `hardening.rs` is generic. Refactor: extract the non-rate-limit middleware (timeout,
  concurrency, body) into `vault-transport` and have both routers apply it. Keep the
  per-SAN rate limiter broker-private (sync has one principal — a per-device limiter is
  the analog and could share the token-bucket type).

### 3.2 — config-from-env pattern diverges · Low
- `vault-broker/src/config.rs:69` has a reusable `fn env_parse<T: FromStr>(key)`;
  `vault-sync/src/config.rs` inlines `std::env::var(...).ok().and_then(parse)` three times.
- Refactor: hoist `env_parse` into `vault-transport` (pure, no deps) and use it in both.

### 3.3 — state shape diverges appropriately · GOOD
- `vault-broker` `AppState` carries `LeaseEngine`, `CredEngines`, `Metrics`, seal
  `AtomicBool`; `vault-sync` `AppState` carries `Store`, `ReplayGuard`, per-vesta
  broadcast `tails`. Both correctly wrap the `!Sync` rusqlite connection in `Arc<Mutex>`.
  Divergence here is intrinsic to the two domains — do not unify.

### 3.4 — `now`/time helpers diverge · Low
- `vault-sync/src/store.rs:11` defines `fn now_unix()` (`time` crate); the broker injects
  `now_unix()` into the lease engine too but from its own site. Both ultimately want
  "unix seconds for the injected clock". Hoist a single `vault_transport::now_unix()` so
  the clock-injection convention (lease engine takes `now`) has one source.

---

## 4. Testability & maintainability

### 4.1 — Uneven HTTP test depth · **Med**
- `vault-broker/src/http.rs` has ~10 `oneshot` integration tests (seal, body-limit, group
  mismatch, auth 401/403, etc.) — good coverage of the middleware/auth surface.
- `vault-sync/src/http.rs` has **1** `oneshot` test (4 test fns total). The signed-header
  auth path, skew rejection, replay rejection, and the WS `tail` endpoint are largely
  exercised only at the unit level (`auth.rs` tests are solid) but not end-to-end through
  the router. Add oneshot tests for: signed push happy-path, stale-ts 401, replayed-nonce
  401, wrong-device-sig 401, and a pull cursor walk.
- The WS `tail` endpoint (`http.rs:58`) has no test at all — hardest to test (needs a WS
  client harness), and currently the riskiest untested path (broadcast lag → resync).

### 4.2 — Store logic is well-isolated and well-tested · GOOD
- `vault-sync/src/store.rs` tests cover monotonic seq, dedupe, per-vesta isolation,
  idempotent account create, malformed-payload rejection. `open_memory()` makes the store
  trivially testable. `lease.rs` is pure + clock-injected → fully unit-testable. This is
  the maintainability high-water mark of the repo; mirror it.

### 4.3 — No cross-service / cross-process integration test · Low
- `tests/` at the root covers the lib only. There is no test that boots a router and
  drives the *real* client signing flow (sync) or the mTLS extractor (broker) end-to-end.
  The mTLS path (`tls.rs`, `auth.rs` production branch) is only reachable via the
  `X-Client-Cert-SAN` dev header in tests — the cert→SAN extraction in the TLS accept loop
  is effectively untested. Add an `rcgen`-based mTLS integration test (the dev-dep is
  already present) to cover the production auth branch.

---

## 5. Spec ↔ code drift

### 5.1 — Sync spec matches code · GOOD
- `spec/sync-openapi.yaml` paths (account, enroll-challenge, enroll, push, pull, status,
  tail) map 1:1 to `vault-sync/src/http.rs:48-58`. DTOs in `dto.rs` match the documented
  request/response shapes.

### 5.2 — Broker spec matches code · GOOD
- `spec/broker-openapi.yaml` paths (healthz, seal-status, store-snapshot, ssh ca/revoked/
  sign, creds, kms wrap/unwrap/rotate, session, leases renew/revoke) all have matching
  routes (`http.rs:127-146`, incl. the multi-line `kms/.../rotate` → `kms_rotate` at
  `http.rs:139`). No phantom or missing endpoints found.

### 5.3 — `/metrics` intentionally absent from spec · GOOD
- `/metrics` (`http.rs:166`) is served on the separate loopback `8201` listener and is
  documented in the spec prose as *not* on the mTLS surface — correct by design, not drift.

### 5.4 — Watch item · Low
- The duplicated `ErrorBody` (§2.2) means each spec's error schema can drift from the
  other independently. Hoisting the struct (§2.2) closes this.

---

## Top 5 (do these first)

1. **Stop leaking internal error strings to clients** (§2.1) — `vault-broker/src/http.rs:520,629`
   + `db_err`, `vault-sync/src/http.rs:37`. Log full, return opaque `detail`. *High.*
2. **Fix silent base64-default in `create_account`** (§2.3) — `vault-sync/src/store.rs:99-101`.
   Malformed input permanently bricks a vesta's enrolment. Validate + `400` like the push
   path. *High.*
3. **Give vault-sync request hardening** (§3.1) — extract timeout/concurrency/body
   middleware from `vault-broker/src/hardening.rs` into `vault-transport`; apply in both.
   Sync currently has only a body cap. *Med.*
4. **Hoist shared wire types/helpers into `vault-transport`** (§2.2, §3.2, §3.4) —
   `ErrorBody`, `Ack`, `err()`, `env_parse`, `now_unix`. Stops the two services drifting and
   removes the "mirrors the broker" copy-paste. *Med.*
5. **Resolve the `Hlc` over-claim + broker integration test gaps** (§1.2, §4.1, §4.3) —
   either implement `Hlc::tick/merge` and thread it into the lease tree or re-scope it as
   sync-only; add sync auth/replay oneshot tests and an `rcgen` mTLS integration test for
   the untested production auth branch. *Med.*
