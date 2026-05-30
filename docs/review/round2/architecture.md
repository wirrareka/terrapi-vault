# terrapi-vault — Round 2 Architecture & Code-Quality Review (2026-05-30)

Scope: the **new** surface added since Round 1 (`vault-sync/src/{metrics,harden,ratelimit}.rs`,
the WAL reader pool + `store_op`, `vault_transport::http`, the broker hardening stack) plus the
boundary/cohesion questions Round 1 did not re-open. Round 1's own findings (C1/R1–R18) are
**not** repeated here; they are verified-applied.

**Headline:** the dependency firewall is still **fully intact** and the security-critical paths
are sound. The one real regression Round 1 *introduced* is **convergent divergence**: both
services were independently hardened in the same shapes (Metrics, concurrency/timeout/metrics
middleware, token bucket, `is_uuid_v4_lower`, `now_unix`), and R13 only hoisted the three
*trivial* items (`ErrorBody`/`Ack`/`env_parse`). The substantive duplication that hardening
*created* was left behind. That is the bulk of this report.

Each finding: **Impact** · location · issue · concrete refactor.

---

## 0. Firewall & neutrality re-verification (the explicit asks) · GOOD

- **vault-sync carries no platform/broker coupling.** `Cargo.toml` deps = axum/tokio/
  ed25519/serde/sha2/time/`vault-transport`/`terrapi-vault` — **zero** opensearch/residency/
  tenant. The new `metrics.rs`/`harden.rs`/`ratelimit.rs` import only `axum`/`tokio`/`std` +
  `crate::{dto,state}`. No leak. `metrics.rs:1-4` even documents *why* the series stay
  loopback-only (op/device counts are exactly the at-rest threat-model metadata) — correct.
- **vault-transport stayed axum/time-free after `http.rs`.** Deps = serde/serde_json/sha2/
  thiserror only. `vault_transport::http` is serde+std (`ErrorBody`/`Ack`/`env_parse`). Clean.
- **Root lib still neutral after the `constant_time_eq` + at-rest-adjacent work.** `src/`
  pulls in no axum/tokio/network. `constant_time_eq` (`vault.rs:325`) is a private hand-rolled
  XOR-accumulate — **no new crate**, so neutrality + MSRV are untouched. `verify_enroll_proof`
  (`auth.rs:92`) is likewise constant-time. Security-critical compares are correct.

So: nothing in the new code breached the boundary. Everything below is quality/consistency.

---

## 1. Convergent divergence — hardening was duplicated, not shared · **High**

Round 1's R8 ("give vault-sync hardening") was implemented by **copying** the broker's
middleware into a new `harden.rs` rather than extracting it. The two now drift in lockstep.
Concrete twins:

| Concern | broker | sync | Delta |
|---|---|---|---|
| `Metrics` struct + `ReqKey` + `record_request`/`inflight_add`/`render` | `state.rs:26-146` | `metrics.rs:11-138` | only the series **prefix** (`vault_` vs `vault_sync_`) and which domain gauges (`sealed`/`events` vs `tail`/`ops`) differ; ~90 % byte-identical |
| `reject(status,error,detail)->Response` | `hardening.rs:86` | `harden.rs:14` | identical |
| `concurrency_limit` middleware | `hardening.rs:135` | `harden.rs:28` | identical but for the detail string ("broker"/"server") and where the semaphore lives (`harden.sem` vs `state.sem`) |
| `timeout` middleware | `hardening.rs:154` | `harden.rs:67` | identical |
| `record_metrics` route_layer | `hardening.rs:167` | `harden.rs:49` | identical |
| token bucket | `hardening.rs:40-83` (per-principal, map+evict) | `ratelimit.rs:15-53` (single shared) | same refill math, different keying |

**Why it matters:** the metrics exposition format and the back-pressure semantics are now a
*de-facto contract* with the ops/Prometheus side, defined twice. A fix to one (e.g. add a
`status` bucket, change the 503/408 body) silently skews the other; this is precisely the
drift class R13 set out to kill, left half-done.

**Refactor (the big one):**
1. Hoist a **generic `Metrics` core** into `vault_transport::metrics`: the `ReqKey` +
   `requests`/`latency`/`inflight` maps + `record_request`/`inflight_add` + a
   `render_http(prefix, extra_lines: &str)` that emits the shared `{prefix}_http_*` series and
   lets each service append its own domain gauges (`sealed`/`events` vs `tail`/`ops`). Each
   service keeps a thin wrapper owning only its domain counters.
2. Hoist the **generic middleware** (`reject`, `concurrency_limit`, `timeout`, `record_metrics`)
   into `vault_transport::middleware` parameterised over a small trait
   (`fn semaphore(&self)`, `fn metrics(&self)`, `fn request_timeout(&self)`) that both
   `AppState`s implement. This is axum-coupled, so gate it behind an **optional `axum`
   feature** on vault-transport (the crate stays axum-free by default → root-lib consumers
   and the lease/audit base are unaffected). Per-principal rate-limit stays broker-private;
   the bucket *type* can move to `vault_transport` and both services key it differently.

This single refactor removes ~250 LOC of twins and makes the metrics format authoritative.

---

## 2. Smaller duplications R13 also missed · **Med**

- **`is_uuid_v4_lower` is copy-pasted** verbatim: `vault-broker/src/http.rs:108` and
  `vault-sync/src/http.rs:74`. Both validate the same wire convention (lowercase UUIDv4 for
  `tenant_id`/`vault_id`). Hoist to `vault_transport::http` (pure std, no deps) — exactly the
  kind of shared *wire-shape* validator that crate already holds (`env_parse` sits there).
- **`now_unix` exists three times** with three signatures: `vault-broker/src/state.rs:194`
  (`u64`), `vault-sync/src/store.rs:15` (`i64`), and conceptually `AppState::now_ts` (RFC3339).
  Round 1's Top-5 #4 explicitly listed "hoist `now_unix` into transport" — **not done**. The
  `u64`/`i64` split is a real footgun (sync stores `i64`, broker drives the lease clock with
  `u64`). Add `vault_transport::now_unix_secs() -> u64` once; sync converts at its single SQLite
  boundary. Document the clock-injection convention in one place.
- **`reject`/`err` are still two families.** `vault_transport::http` holds the *struct*
  (`ErrorBody`) but each service re-implements both `err()` (handler) and `reject()`
  (middleware) — four near-identical fns. Fold `reject` into the §1 middleware move; leave
  `err` per-service only if you keep the per-service `ErrResp` alias.

---

## 3. Cohesion — both `http.rs` are now god-modules · **Med**

`vault-sync/src/http.rs` is **1088 lines**; ~680 are non-test and mix four distinct concerns:
auth plumbing (`signed_headers:183`, `check_skew:229`, `verify_signed:242`, `auth_registered:280`,
`is_uuid_v4_lower:74`, `VaultId` extractor `109-133`), the `store_op` spawn-blocking bridge
(`53`), and **9 route handlers**. `vault-broker/src/http.rs` is **1195 lines** with the same
smell (the `Group` extractor, `check_group`, `require_cap`, `kms_preflight`, `map_kms_err`,
`system_actor`, `tear_down_creds` all living alongside 15 handlers).

**Impact:** every change touches a 1.1k-line file; the extractor/auth glue is impossible to
unit-test in isolation from the handlers; new contributors can't find the route table.

**Refactor (low risk, mechanical):**
- vault-sync: move the auth helpers + `SignedHeaders`/`VaultId` extractor into the existing
  `auth.rs` (it already owns `verify_signed`/`ReplayGuard` — the extractor belongs with them),
  and move `store_op` next to `Store` in `store.rs` (or a `store_op.rs`). `http.rs` then holds
  only `router()` + handlers (~400 LOC).
- vault-broker: split into `http/mod.rs` (router) + `http/{ssh,kms,creds,session}.rs` handler
  groups; move `Group`/`check_group`/`require_cap` to `auth.rs`.
- Keep the existing tests with their handlers (or in a sibling `tests` module) so coverage
  doesn't move.

---

## 4. Error handling consistency · mostly GOOD, two rough edges · Low

The wire mapping is **exhaustive and intentional**: `map_kms_err` (`http.rs:617`) covers all
three `KmsError` arms with the right caller-vs-internal split (`BadInput`→400, `Crypto`→400
`unwrap_failed`, `Store`→`internal`); `CaError` (`ssh_ca.rs:18`) is matched arm-by-arm with
`BadRequest`→400 and `other`→`internal("sign_failed")`; `PushError`/`AccountError`
(`store.rs:369/381`) cleanly separate `Db`(→`db_err` opaque) from `InvalidPayload`/
`InvalidVerifier`(→400). R5's redaction holds throughout. Edges:

- **`CredError` is a one-variant enum** (`creds.rs:24`, `#[allow(dead_code)]` on the only arm)
  collapsed to a generic `backend("creds issue", e)` (`http.rs:517`). Fine today (only
  `MockEngine` exists, which never errs), but when the real OpenSearch adapter lands, *every*
  failure (auth, quota, network, role-not-found) becomes an indistinguishable `502`. Pre-shape
  `CredError` now (`Backend`/`Unauthorized`/`NotFound`/`Throttled`) so the handler can map
  quota→429 and not-found→404 without a later wire-contract change.
- **`KmsError::Store(String)` and `CaError::Store(String)` carry a `String`**, not the source
  error — the redaction happens at *construction* (stringify) not at the handler, so the
  real `rusqlite` error is stringified into a field that `internal()` then mostly discards.
  Minor: prefer `#[from] rusqlite::Error` + redact at the single `internal()` site, so the
  full detail reaches the server log, not a lossy pre-baked string.

---

## 5. Testability, config story, magic numbers · Low–Med

- **Still-hard-to-test (unchanged from R1, acknowledge as accepted risk):** the **prod TLS
  serve loop** (`tls.rs` accept → SAN extraction) is covered only at the extractor level
  (`principal_extractor_maps_verified_san_to_role`), not through a real rustls handshake; the
  **sweeper timing** (`sweeper.rs`, 95 LOC) has no test that advances the clock and asserts a
  lease expired + cascaded; **audit shipping** (`audit_ship.rs`, 380 LOC with the R7 byte/item
  caps) has no test feeding a partial-line file and asserting the cursor advances to the last
  *complete* line. These are the three highest-LOC untested paths. At minimum add a
  clock-injected sweeper test (the lease engine is already clock-injectable) and a
  `read_new_records` partial-line unit test — both are pure/loopback, no network needed.
- **Config sprawl is real:** ~30 `VAULT_*` broker env vars + 9 `VAULT_SYNC_*`. Two concrete
  problems: (a) **prefix inconsistency** — the broker's hardening vars are bare
  `VAULT_MAX_CONCURRENCY`/`VAULT_REQUEST_TIMEOUT_SECS`/`VAULT_MAX_BODY_BYTES` while sync's are
  `VAULT_SYNC_*`; pick one convention (`VAULT_BROKER_*` to match `VAULT_SYNC_*`). (b) there is
  **no config doc** — the env surface lives only in two `config.rs` files. Generate/maintain a
  `docs/config.md` table (name · default · service · meaning) from the `pub const` defaults;
  ops cannot currently discover the knobs without reading source.
- **Magic numbers mostly centralized** (R1's praise holds): hardening defaults are `pub const`
  + env. Remaining hard-coded-without-env: `MAX_SEEN_NONCES`/`NONCE_RETENTION_SECS`
  (`auth.rs`), `TAIL_CAPACITY` (`state.rs`), `MAX_BUCKETS` (`hardening.rs:37`),
  `MAX_SHIP_BYTES`/`MAX_SHIP_ITEMS` (`audit_ship.rs`). These are operationally relevant under
  load; lift the replay/tail/ship caps into `config.rs` for the "everything tunable" stance.

---

## 6. Workspace ↔ root-lib boundary · GOOD (one stale doc-claim persists)

No new circular coupling. Services depend on the root lib (path-pinned) and on
vault-transport; the root lib depends on neither — the DAG is clean. The §1/§2 refactors
*add* shared code to vault-transport (the correct sink), not to the root lib, so they don't
threaten root-lib neutrality (gate the axum middleware behind an optional feature so the
default build of transport stays axum-free).

**Stale claim (carried over from R1 §1.2, still unaddressed):** `vault_transport::lib.rs`
documents `Hlc` as "shared by the broker lease tree," but the lease engine still drives on raw
`u64` unix seconds (`state.rs:194`, `lease.rs`), while `Hlc` is used *only* by vault-sync
(`dto.rs`, `store.rs`). Either implement `Hlc::tick/merge` and thread it through `lease.rs`, or
re-scope the doc to "sync-only ordering pair." A primitive whose doc over-claims its reach is a
maintenance trap.

---

## Top 5 (do these first)

1. **Hoist the duplicated hardening stack into `vault-transport`** (§1) — generic `Metrics`
   core + `concurrency_limit`/`timeout`/`record_metrics`/`reject` middleware behind an optional
   `axum` feature; both services wrap it. Removes ~250 LOC of lockstep twins and makes the
   Prometheus exposition format authoritative instead of defined-twice. *High.*
2. **Finish R13: hoist `is_uuid_v4_lower`, `now_unix`, and `reject`** (§2) — the three items
   Round 1's own Top-5 listed but left copy-pasted; `now_unix`'s `u64`/`i64` split is an active
   footgun. *Med.*
3. **Break up the two 1.1k-line `http.rs` god-modules** (§3) — move auth helpers + extractors
   into `auth.rs`, `store_op` into `store.rs`, broker handlers into `http/{ssh,kms,creds}.rs`.
   Mechanical, low-risk, unlocks isolated extractor/auth tests. *Med.*
4. **Pre-shape `CredError` before the OpenSearch adapter lands** (§4) — a one-variant enum
   collapsed to `502` will erase quota/not-found/auth distinctions on the wire; widen it now to
   avoid a later contract break. *Med.*
5. **Tame the config surface** (§5) — unify the broker prefix to `VAULT_BROKER_*`, generate a
   `docs/config.md` table from the `pub const` defaults, and lift the remaining replay/tail/ship
   caps to env. Plus add the two cheapest missing tests (clock-injected sweeper expiry;
   `audit_ship` partial-line cursor). *Low–Med.*

**Honest bottom line:** Round 1 fixed everything load-bearing. Round 2 finds **no new
boundary breach and no new security gap** — only the consistency debt that the hardening work
itself created (duplication R13 didn't finish) and pre-existing cohesion/config-doc sprawl.
The codebase is in good shape; these are tidy-up, not rescue.
