# terrapi-vault — Round 2 deep-analysis roadmap (2026-05-30)

Second 4-agent pass, run AFTER round 1 (R1–R18 + at-rest + metrics, all shipped). The agents
were given the round-1 baseline and asked for **new** findings only. Reports:
[`security.md`](security.md) · [`performance.md`](performance.md) ·
[`architecture.md`](architecture.md) · [`api-dx.md`](api-dx.md).

**Honest framing:** round 1 was thorough, so round 2 is narrower — but it surfaced **2 real HIGH
security issues** (verified against the code) that defeat vesta's central short-TTL model, plus a
durability gap on the audit path and a worthwhile dedup. No Critical, no round-1 regressions.

## Convergent findings (flagged by ≥2 agents)
| Theme | Agents | Where |
|---|---|---|
| **`/metrics` loopback not enforced** (could bind public, unauth metadata) | security M1, api-dx | both `main.rs` metrics-bind |
| **push fan-out read-after-write** (push_ops should return the StoredOps) | performance, (supersedes round-1 self-review fix) | `vault-sync/http.rs:525`, `store.rs push_ops` |
| **Convergent divergence** — vault-sync copied broker's Metrics + hardening middleware instead of sharing | architecture, api-dx (Error/ErrorBody names) | `metrics.rs` vs broker `state.rs`; `harden.rs` vs `hardening.rs` |

## R2-P0 — Security: restore the short-TTL model + close exposure — ✅ DONE 2026-05-30
- **R2-1. ✅ SSH cert TTL capped**: `ttl_secs.unwrap_or(default).clamp(1, SSH_CERT_MAX_TTL_SECS)`
  (3600 s) in `ssh_sign`; `ssh_ca::sign` now refuses `valid_before <= valid_after` (defense in
  depth). `http.rs`, `state.rs`, `ssh_ca.rs` (+ test `nonpositive_validity_window_rejected`), spec.
- **R2-2. ✅ Session TTL + idle capped**: `ttl.clamp(1, MAX_SESSION_TTL_SECS)` (8 h) and
  `idle.clamp(1, ttl)` in `session_open`. `http.rs`, `state.rs`, spec.
- **R2-3. ✅ `/metrics` loopback enforced** (both services): `metrics_bind_allowed()` disables the
  listener on a non-loopback bind (fail-closed; unparseable → refused) unless
  `VAULT_*_METRICS_ALLOW_PUBLIC=1`. `main.rs` (×2, + test `metrics_bind_loopback_allowed_public_refused`),
  env sample.

_Verified: clippy -D warnings + fmt clean; broker 38 tests, sync 23 (4 new)._

## R2-P1 — Durability / correctness — ✅ DONE 2026-05-30
- **R2-4. ✅ Audit sink durability**: `HashChainSink` now holds the append handle (one `open`, not
  per event) and `sync_all` (fsync)s each record to disk; the chain advances only iff `write_all`
  succeeds (integrity), with best-effort fsync for power-loss durability — the "durably appended"
  comment is now true. `vault-transport/src/audit.rs`.
- **R2-5. ✅ Audit shipper detects `_bulk` partial failure**: `bulk_failures()` parses the 200
  response `errors`/`items[].status`; a per-item failure is now an error so the cursor doesn't
  advance past unshipped events. The doc `_id` is the chain hash, so the re-ship is **idempotent**
  (no duplicate docs). `audit_ship.rs` (+ test `bulk_failures_detects_partial_errors`).
- **R2-6. ✅ `push_ops` returns the accepted `StoredOp`s**: built in the write transaction, so the
  push handler fan-out needs no post-commit reader read (no visibility question, one fewer query +
  base64). Supersedes the round-1 `before = latest_seq - accepted` fix. `store.rs`, `http.rs`.
- **R2-7. ✅ `creds.issue` TOCTOU closed**: the `CredHandle` is now inserted **under the same hold
  of the leases lock** as `issue_lease` (both sync; the async revoke-on-session-end happens after
  the guard drops). A sweeper can no longer revoke the lease before its handle exists → no orphaned
  backend user. Lock order leases→cred_handles is deadlock-free vs. the sweeper. `http.rs`.

_Verified: full tree green — root lib 32 tests, services 83 (broker 39, sync 23, transport 21); clippy -D warnings + fmt clean._

## R2-P2 — DX + dedup + polish — (R2-8/9/10/12 ✅ DONE 2026-05-30; R2-11 deliberately skipped)
- **R2-8. ✅ Metrics format deduped**: extracted the shared HTTP-metric core (`requests`/`latency`/
  `inflight` + the `*_http_*` Prometheus render) into a **std-only** `vault_transport::http::HttpMetrics`
  (no axum → firewall intact); broker + vault-sync `Metrics` now embed it and add only their domain
  series (`vault_sealed`/`audit_events` vs `ops_*`/`tail_subscribers`). The format is defined once.
  _Note:_ the hardening **middleware** (concurrency/timeout/record_metrics/request_id/reject) stays
  per-service — deduping it needs a state-access trait whose abstraction cost outweighs ~80 shared
  lines; the High concern (the exposition-format contract) is what's resolved.
- **R2-9. ✅** distinct `unregistered_principal` (403) vs `missing_identity` (401) vs `forbidden`
  codes (typed envelope on the mTLS extractor) + a capability→route table in the broker spec.
- **R2-10. ✅** `X-Request-Id` echo/generate on both; `/healthz` → JSON `{status,version}`;
  `Retry-After` on 408/429/503; spec + bootstrap documented.
- **R2-11. ⏭️ Skipped (deliberate)**: splitting the ~1.1k-line `http.rs` modules is churn for marginal
  benefit (the modules are cohesive; agents rated it "tidy-up, not rescue"). Revisit if a file grows
  materially or a sub-area gains reuse value.
- **R2-12. ✅ Lows**: KMS AEAD now binds the target tuple as AAD; key-file perms warned (both); nonce
  length cap (`bad_nonce`); stale KMS doc comments fixed. _(Replay per-vesta cap + `CredError`
  pre-shaping left as low-value/speculative; single-person scope and no real adapter yet.)_

## Suggested order
R2-1 → R2-2 → R2-3 (P0 security, small + high-value) → R2-4/R2-5 (audit durability) →
R2-6/R2-7 → then the P2 dedup/DX batch. R2-1/R2-2 are the headline: they restore the
short-TTL guarantee that is the whole point of the broker.
