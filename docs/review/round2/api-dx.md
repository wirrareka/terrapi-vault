# vault-broker / vault-sync — API & wire-DX review (round 2, 2026-05-30)

Second pass. Round 1 (`docs/review/api-dx.md`) already landed the big wins: typed error
enums in **both** specs (broker `Error.error` and sync `ErrorBody.error`, with per-code
status + meaning), the full ed25519 signing recipe + a pinned test vector, the `/tail`
`TailFrame` `oneOf`, pull pagination + push `op_id` idempotency narrative, and the opaque
`snapshot_id`. The broker spec in particular is now strong — full route set
(ssh ca/sign/revoked, creds, kms wrap/unwrap/rotate, session, leases, snapshot), enum
covers `rate_limited`/`overloaded`/`timeout`, and `docs/broker-bootstrap.md` exists as a
client-implementer doc. So this round is **narrower**: the gaps that remain are real but
mostly polish, concentrated in observability/versioning, broker capability discoverability,
and the two `forbidden`/auth-failure ambiguities. Citations are `file:line`.

---

## High

### H1 — `403 forbidden` conflates two distinct, separately-actionable failures
**Location:** `vault-broker/src/auth.rs:98-115` (unregistered SAN → 403) vs
`vault-broker/src/http.rs:203-213` (`require_cap` → 403); spec enum has a single `forbidden`.
The impl already produces **three** auth outcomes, but the wire only distinguishes two of them:
- mTLS absent / no verified identity → `401` (good, distinct).
- verified cert whose SAN is **not in `VAULT_ROLES_CONFIG`** → `403 forbidden`.
- verified+registered principal whose role **lacks the capability** for this op → `403 forbidden`.

The last two are the same `{error:"forbidden"}` on the wire. For a demon/aether dev these are
opposite remediations: the first means "ask the operator to register my SAN", the second means
"ask the operator to grant my role capability X". They cannot tell which from the response, and
`detail` is explicitly non-contractual. This is the single biggest *new* DX gap.

**Improvement:** split the code (no status change — both stay 403):
```yaml
# Error.error enum — replace `forbidden` with:
  - unregistered_principal  # 403 — cert verified but its SAN is not in VAULT_ROLES_CONFIG
  - forbidden               # 403 — principal is registered but its role lacks this capability
```
and add a `401`/`403` examples block to the `Unauthorized`/`Forbidden` shared responses so a
dev can switch on the three states. `auth.rs:101` already has the branch — just give it its
own code.

### H2 — Per-route capability requirement is not discoverable from the contract
**Location:** every broker handler calls `require_cap(.., Capability::X)` (`http.rs:238,256,280,
395,479,592,799,833,869,887`); the spec states the required cap **only** for `ssh/ca`
(`broker-openapi.yaml:398` prose). A demon dev writing a least-privilege role config has no
machine-readable way to know `creds/{role}` needs `creds`, `kms/*` needs `kms`,
`session` needs `session`, `leases/*` needs `leases`, `snapshot` needs `snapshot`,
`ssh/sign` needs `ssh-sign`, `ssh/ca`+`ssh/revoked` need `ssh-ca`. They must read Rust or
trial-and-error against live 403s.

**Improvement:** add an `x-required-capability` vendor field to each operation (machine-readable,
tooling-visible) **and** a capability→route table in `docs/broker-bootstrap.md`:
```yaml
/v1/{group}/{tenant_id}/creds/{role}:
  post:
    x-required-capability: creds
    ...
```
This is the broker analogue of round 1's "error catalog in code, not contract" — the
capability map is the broker's authz contract and it lives only in source.

---

## Med

### M1 — No `X-Request-Id` correlation header on either service (round-1 M2, still open)
**Location:** neither `vault-broker/src/http.rs` nor `vault-sync/src/http.rs` emits or echoes one;
absent from both specs. Round 1 flagged this (R10 note explicitly **deferred** it). For a secrets
boundary that emits server-side B3 audit (`broker http.rs:4`) but hands the client no handle, a
failed lease/sign call still cannot be tied to a server log line during an incident.

**Improvement:** generate one per request, echo `X-Request-Id` on every response (success + error),
fold it into the B3 audit event and the structured log line, and add optional `request_id` to both
`Error` and `ErrorBody`. Cheapest single change that makes every other error actionable. Document
once in each spec's `info.description`. This is the natural home for the shared helper hinted at in
R13 (`vault-transport`).

### M2 — Version / build-info surface is asymmetric and half-hidden
**Location:** broker exposes its version only as a nullable field inside
`/v1/sys/seal-status` (`http.rs:199`, `broker-openapi.yaml:293`); sync's `/healthz` returns the
bare string `"ok"` (`sync/http.rs:138`) with **no** version surface at all. Both bake
`env!("CARGO_PKG_VERSION")` but only the broker exposes it, and only as a side effect of a
seal-readiness probe. Ops/clients routinely want a cheap unauthenticated build check.

**Improvement:** make both `/healthz` return JSON `{"status":"ok","version":"<crate>","name":"<svc>"}`
(or add `GET /v1/sys/version`). Document it. Lets a client assert compatibility without parsing
seal state, and gives sync the version surface it currently lacks entirely.

### M3 — `info.version` (1.0.0) is decoupled from the crate version (0.1.0) with no policy
**Location:** `spec/broker-openapi.yaml:` `info.version: "1.0.0"`,
`spec/sync-openapi.yaml:` `1.0.0`; crates are `0.1.0` (workspace). The spec version is the
*contract* version and the crate is the *build* — they legitimately differ, but nothing documents
that, nor how a breaking contract change bumps `info.version`. A consumer can't tell whether
`1.0.0` is frozen or aspirational.

**Improvement:** add one line to each `info.description`: "`info.version` is the **contract**
version (semver; bumped on breaking wire changes); the running build version is reported by
`/healthz`/`seal-status` and is independent." State the deprecation/bump policy once.

### M4 — Retry-After semantics for 429/503/408 are undocumented
**Location:** the broker enum names `rate_limited` (429), `overloaded` (503), `timeout` (408)
(`broker-openapi.yaml:126-128`) and the hardening layer produces them, but no response documents a
`Retry-After` header or back-off guidance; sync's `harden.rs` 503/408 are similarly silent.
A client implementing retry/back-off has no contract for *how long* to wait.

**Improvement:** if the limiter/concurrency layer sets `Retry-After`, document it on the 429/503
responses (`retry-after` header schema, seconds); if it doesn't, add it (cheap, and the bucket
already knows the window). Add a one-line "back off and retry on 429/503; do not retry 408 without
fixing the request size" note. Applies to both specs.

---

## Low

### L1 — The two error envelopes are named differently (`Error` vs `ErrorBody`) though shapes match
**Location:** broker `Error` (`broker-openapi.yaml:95`) vs sync `ErrorBody`
(`sync-openapi.yaml`). Both are `{error, detail}` with an enum, and R13 already de-duped the serde
type into `vault_transport::http::ErrorBody`. The **specs** still name them differently, so a dev
writing one client lib for both services sees two schemas. Round 1's L1 asked for a note; this is
the stronger fix.

**Improvement:** rename broker `Error` → `ErrorBody` (or vice-versa) so both specs reference an
identically-named envelope, matching the already-shared Rust type. Add the cross-service note R1/L1
asked for: "the error envelope is identical across all vault services: `{error, detail[, request_id]}`;
`error` is a stable enum, `detail` is human-readable and non-contractual."

### L2 — Broker payload examples are thin vs sync
**Location:** broker request/response bodies (ssh sign, creds lease envelope, kms wrap/unwrap)
have schemas but few worked `examples:`; sync now has rich per-status examples (round 1). A
demon dev integrating `ssh/sign` or a `creds` lease envelope benefits from a concrete
request+response example (a sample principal cert request → signed-cert response; a `creds` call →
`{lease_id, ttl, secret, renewable}` envelope) the way sync got them.

**Improvement:** add one `examples:` per broker mutating endpoint (sign, creds, wrap, unwrap,
session-open, renew). Pure spec edit, no code. Mirrors the sync treatment so DX is symmetric across
the two specs.

### L3 — `/metrics` is implemented but invisible to operators in the contract
**Location:** both services serve Prometheus `/metrics` on a separate loopback listener
(broker `http.rs:184-191` :8201; sync `http.rs:167-174`); the broker spec *mentions* it in prose
(`broker-openapi.yaml:23-24,144`) but neither spec nor an ops doc enumerates the **metric names**
(request counts by route template, op/device counters, seal gauge). An operator wiring PromQL
dashboards must read Rust to learn the series names.

**Improvement:** a short `docs/operations/metrics.md` (or a section in each bootstrap doc) listing
the exported series, their labels (route template, **never** tenant id — already enforced, worth
stating), and the loopback bind. Note it's intentionally off the mTLS surface.

### L4 — Conventions note still absent from the specs
**Location:** both specs. Round 1 L2 recommended a one-line conventions block (snake_case JSON,
`X-Sync-*`/`X-Device-Id` headers on sync, all paths `/v1/...`). Not yet added to either spec.

**Improvement:** add the 2-line conventions note to each `info.description` so future endpoints
don't drift to camelCase and so the header naming scheme is documented once.

---

## Top 5 (do these first)

1. **H1 — Split `forbidden` into `unregistered_principal` (403) vs `forbidden` (403).** The branch
   already exists in `auth.rs`; giving it a distinct code lets a demon/aether dev tell "register my
   SAN" from "grant my role a capability" — the highest-leverage *new* auth-ergonomics fix.
2. **H2 — Publish per-route capability requirements** (`x-required-capability` on each operation +
   a capability→route table in `broker-bootstrap.md`). The broker's authz contract currently lives
   only in `require_cap(..)` calls.
3. **M1 — Add `X-Request-Id`** (echoed header + audit/log + optional `request_id` in the error
   envelope) on both services. Round 1 deferred it; it makes every error actionable in incidents.
4. **M2 / M3 — Fix the version surface**: JSON `/healthz` with `version` on both (sync has none),
   and document `info.version` = contract version vs build version policy.
5. **M4 + L1 — Document Retry-After back-off semantics** for 429/503/408 on both specs, and
   **converge the envelope name** (`Error`→`ErrorBody`) to match the already-shared `vault_transport`
   type, with the cross-service "identical envelope" note.

**Honest bottom line:** round 1 did the heavy lifting and the broker spec is now genuinely good.
What remains is real but bounded — two auth/capability discoverability gaps (H1/H2) are the only
findings that would actually trip a competent client dev; everything else is observability/versioning
hygiene and spec symmetry polish.
