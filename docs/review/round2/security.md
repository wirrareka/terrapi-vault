# terrapi-vault — Round 2 security review

_Round 1 (R1–R18) was thorough; the crypto core, mTLS/SAN→role, lease cascade, KMS XChaCha20
swap, vault-sync at-rest keying, and per-route capability gating hold up. New findings below —
**no Critical, two High** — none re-report R1–R18. The two High and M2 were verified against the
code._

## High

**S2-H1. SSH cert TTL is never capped — short-TTL model defeated.** `http.rs:321-323`
(`ssh_sign`): `let ttl = req.ttl_secs.unwrap_or(SSH_CERT_TTL_INTERACTIVE_SECS); valid_before =
now.saturating_add(ttl)` — **no upper bound** (unlike creds, clamped `.min(self.max_ttl_secs)`).
A daemon holding `SshSign` can request a multi-year cert; the cert stays cryptographically valid
until `valid_before` regardless of lease revoke, and the KRL is best-effort (hosts must pull
`ssh/revoked`). Directly violates the "short-TTL revocable over static" principle in CLAUDE.md.
**Fix:** `SSH_CERT_MAX_TTL_SECS` (e.g. 3600) and `ttl.min(MAX)`; reject `valid_before <=
valid_after` in `ssh_ca::sign` as defense-in-depth.

**S2-H2. Session TTL / idle never capped — compounds H1.** `http.rs:801-802` (`session_open`):
`ttl_secs.unwrap_or(DEFAULT_SESSION_TTL_SECS)` / `idle_timeout_secs.unwrap_or(DEFAULT_…IDLE…)`
with no clamp (the state.rs:150 "8 h hard cap" is only the default). A caller opens a year-long
session; every child lease (SSH/creds) inherits that lifetime. **Fix:** clamp to
`MAX_SESSION_TTL_SECS` / `MAX_SESSION_IDLE_SECS`.

## Med

**S2-M1. `/metrics` loopback guarantee is not enforced — both services.** `vault-broker/main.rs:155`
(`VAULT_METRICS_BIND`), `vault-sync/main.rs:54` (`VAULT_SYNC_METRICS_BIND`). The listener binds
whatever the env gives with **no `is_loopback()` assertion**, yet the code claims "loopback-only,
never expose." A typo (`0.0.0.0:8301`) silently publishes the **unauthenticated** `/metrics` —
exactly the op/device-count metadata the at-rest model protects. **Fix:** refuse to start (or
warn-and-skip) on a non-loopback metrics IP unless `VAULT_*_METRICS_ALLOW_PUBLIC=1`.

**S2-M2. `_bulk` partial failures silently drop audit events.** `audit_ship.rs:240-246` checks
only the HTTP status; OpenSearch `_bulk` returns **200 with `{"errors":true,...}`** on per-item
failure. `ship_backlog` then advances the cursor, so those B3 events are lost from the index
(the durable chain keeps them, but they never reach OpenSearch) — a silent audit-completeness
gap. **Fix:** parse the response `errors` field; on `errors:true` don't advance the cursor (or
re-ship only failed items) and log.

**S2-M3. TOCTOU orphan window in `creds.issue`.** `http.rs:511-548` + `creds.rs:95-104`. The
backend user is created, then the lease bound, then the `CredHandle` inserted. If the sweeper
runs between bind and handle-insert (near-0 TTL or a session expiry landing there), teardown
finds no handle → the OpenSearch user is orphaned (never revoked). Narrow but leaks a privileged
backend user. **Fix:** insert the handle before `issue_lease`, or have teardown reconcile leases
owning no handle, or hold the lease lock across handle insertion.

## Low

**S2-L1. Key-file permissions claimed but not checked — both services.** `vault-sync/config.rs:88`
(`VAULT_SYNC_DB_KEY_FILE`, "mode-600") and `vault-broker/main.rs:61` (`VAULT_UNSEAL_PASSPHRASE_FILE`,
"mode 600"). Neither stats the file; a world-readable key/passphrase loads silently. **Fix:** on
unix, refuse (or warn) if mode `& 0o077 != 0`.

**S2-L2. KMS AEAD uses no AAD.** `kms.rs:184-228` — `(group,tenant_id,key_id,version)` not bound
as AAD. Not exploitable (version prefix selects the per-target KEK; wrong target → auth failure),
but binding the tuple as AAD gives explicit domain separation against any future shared-KEK
refactor. **Fix:** pass the canonical target tuple as `aead::Payload.aad`.

**S2-L3. Replay-guard cap is global, not per-vault.** `auth.rs:129-147` — `MAX_SEEN_NONCES` (100k)
caps the table across all vaults; filling it makes `check_and_record` fail for every vault, and
nonce strings have no length cap. Gated behind signature verification + single-person instance →
low impact, but weakens per-vault isolation. **Fix:** per-`vault_id` cap + cap nonce length (≤128 B).

**S2-L4. Stale KMS doc comments.** `kms.rs:5` ("AES-256-GCM"), `:180`/`:204` ("nonce(12)") describe
the pre-R9 algorithm; code is XChaCha20 / 24-byte nonce. Doc-only. **Fix:** update the comments.

## Regressions from Round 1
None. R1–R18 verified applied. The R1-accepted `enroll-challenge` existence oracle persists by
design (not re-counted).

## Top 5
1. **S2-H1** — cap SSH cert `ttl_secs` (the short-TTL model has no ceiling today).
2. **S2-H2** — cap session `ttl_secs`/idle (compounds H1 via child leases).
3. **S2-M1** — enforce loopback (or explicit opt-in) on both `/metrics` binds.
4. **S2-M2** — detect `_bulk` `errors:true` before advancing the audit cursor.
5. **S2-M3** — close the `creds.issue` handle-insert TOCTOU orphan window.
