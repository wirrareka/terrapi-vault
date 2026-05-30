# terrapi-vault → service(s): planning doc

> **Status:** DRAFT for owner approval (2026-05-26). Nothing in this doc is yet
> committed to `coordination/`. Once approved, the "Coordination writes" section
> (§8) is executed: inbox answers, `CONTRACTS.md`, `ports-env.md`, demon notify,
> and the `CLAUDE.md` role block.

## 0. Decisions taken (owner, 2026-05-26)

1. **Demon broker = Full Path A** — build a full network secrets broker inside the
   terrapi-vault repo (stack-native, reuse fleet Root CA + WG + residency model).
2. **Two separate services, one shared codebase** — `vault-broker` (fleet creds)
   and `vault-sync` (personal multi-device sync) as distinct binaries from one Rust
   workspace; shared transport/auth/audit/crypto.
3. **Sync model = row-level CRDT/oplog** for memento/probe across devices.
4. **Process** — this planning doc first → owner approval → THEN coordination writes.

## 1. Today's reality (baseline)

`terrapi-vault` is an **embedded SQLCipher at-rest library** (single crate, MIT/Apache):
- `rusqlite (bundled-sqlcipher) + argon2 + secrecy + zeroize` — **no tokio/axum/reqwest, no listener.**
- Argon2id KDF (RFC 9106) from passphrase, key in `SecretBox` + zeroized, in-place
  `PRAGMA rekey`, plaintext `<name>.meta.json` sidecar (salt + KDF params only).
- Public API: `Vault::{create,open,open_with_key,rotate_key,with_connection,…}`,
  `KdfParams`, `VaultMeta`, `export_note/import_note`.
- On-disk format spec'd in `spec/vault-format.md` (doc rev 1.6); has app-level tables
  incl. `audit_log`, `secrets`, `succession_plans` (memento's schema).
- **Consumers:** `memento` and `probe` pin `terrapi-vault = { path = "../terrapi-vault" }`
  and re-use its `rusqlite` re-export. `memento-core` already ships a **sync-provider
  abstraction** — the sync server (§5) implements the remote side of it.

**Hard migration constraint:** memento/probe resolve the lib at path `../terrapi-vault`.
The repo **root must remain the `terrapi-vault` lib package** so that path keeps
resolving to the library, not a workspace shell. (See §3.)

## 2. Two products, deliberately not merged

| | **vault-broker** (demon) | **vault-sync** (memento/probe) |
|---|---|---|
| Purpose | issue/lease short-TTL fleet creds | sync user's encrypted vault across their devices |
| Data | dynamic SSH certs, DB/OpenSearch users, leases | append-only oplog of encrypted row mutations |
| Tenancy | multi-tenant, per residency group, air-gapped | single user, many devices (personal) |
| Auth | mTLS over WireGuard vs fleet Root CA | device keypair enrolment |
| Server sees plaintext? | yes (it mints creds) | **never** (E2E; server is blind) |
| Audit | canonical B3 → group OpenSearch | local only (personal) |

They share: the Rust workspace, the `vault-transport` crate (axum scaffold, WG-only
bind, mTLS, B3 emitter, residency guard), the at-rest crypto, and the lease/oplog
primitives where they overlap. They do **not** share a data model or a listener.

### 2.1 Guiding principle — platform features must not constrain memento/probe

terrapi-vault may grow **whatever the proximi.io platform wants** (broker, dynamic
OpenSearch creds, residency, B3 audit, mTLS-over-WG). **But that growth lives
OUTSIDE the core lib crate and never reaches memento/probe.** OpenSearch,
tenants, residency, WireGuard, the fleet Root CA are **platform (Svet A) concerns
only** — they have nothing to do with memento (notes) or probe (API client), which
merely embed the at-rest library to encrypt a local SQLCipher file (Svet B).

**Dependency firewall (hard rule, CI-enforced):**
- The **root `terrapi-vault` lib crate stays neutral**: only `rusqlite + argon2 +
  secrecy + zeroize + serde` as today. **No tokio/axum/reqwest, no OpenSearch
  client, no residency/tenant/WG logic** ever enters it. memento/probe must keep
  building unchanged with zero new transitive deps.
- All platform machinery (broker, `vault-transport`, dynamic-cred engines, B3 emitter,
  residency guard) lives in **separate workspace members** that memento/probe do **not**
  depend on. If anything platform-flavoured ever needs to touch the lib, it goes behind
  an **off-by-default cargo feature** the apps never enable.
- `vault-sync` (Svet B) carries **none** of Svet A: no OpenSearch, no tenants, no
  residency air-gap, no B3-to-OpenSearch — only E2E oplog + device auth.
- CI gate: `cargo build` + `cargo tree` in memento/probe show no new platform deps.

## 3. Workspace restructure (non-breaking) — REVISED

**Discovered at build time:** the lib has a **deliberate MSRV floor of Rust 1.83**
(`rust-toolchain.toml`, "do not bump"); memento builds the tree on 1.91 with its own
toolchain. The standalone 1.83 build is the proof the MSRV is real.

→ **Do NOT make the repo root a workspace root.** If services were workspace members of
the root, a root `cargo build` would compile them on 1.83 and couple the lib's clean-MSRV
signal to service deps (any service dep raising its MSRV would break the lib's build even
though the lib is fine). That violates the neutrality principle (§2.1).

**Chosen layout — the lib root stays pristine; services are their OWN workspace:**

```
terrapi-vault/                 # ROOT = the existing lib crate — Cargo.toml UNCHANGED
  Cargo.toml                   # [package] terrapi-vault (memento/probe pin path="../terrapi-vault")
  rust-toolchain.toml          # 1.83 — UNCHANGED (MSRV proof)
  src/ …  spec/ …  docs/ …
  services/                    # NEW: a separate cargo workspace (own toolchain if needed)
    Cargo.toml                 # [workspace] members = [vault-transport, vault-broker, vault-sync]
    vault-transport/           # shared scaffold (axum, WG bind, mTLS, B3, residency, HLC)
    vault-broker/              # bin — Full Path A (demon)  [Svet A]
    vault-sync/                # bin — row-level oplog sync (memento/probe)  [Svet B]
```

- Services depend on the lib via `terrapi-vault = { path = ".." }` (a path dep, NOT a
  workspace member) — they get the at-rest crypto without dragging the lib's toolchain.
- Root Cargo.toml is **literally unchanged** → memento/probe carry **zero** regression risk.
- If services need a newer channel than 1.83, add `services/rust-toolchain.toml`
  (overrides that subtree only); the lib keeps proving 1.83.

Verification gate: `cargo build` in **memento** and **probe** still succeed unchanged
(CI), and `cargo +1.83 build` of the lib stays green.

## 4. vault-broker — Full Path A (answers demon's 6 points)

Deployment: **per residency group**, WG-only listener. `residency_group` is a
per-instance constant → a broker instance structurally cannot serve another group
(honours `residency.md`: EU `10.200.0.x` / UAE `10.210.0.x`, only shared thing across
groups is the fleet Root CA). **Proposed port: `8200` (API, WG-only) + `127.0.0.1:8201`
(Prometheus, loopback).**

API is versioned `/v1/...`. JSON. All mutating ops emit a B3 audit event (§4.5).

### 4.1 Daemon-auth (point 1) — mTLS over WireGuard vs fleet Root CA
- **Chosen:** mutual TLS; client cert signed by the **fleet Root CA**; the cert SAN
  (e.g. `demon.<host>.<group>.proximi.internal`) is matched to a registered service
  role. No bearer tokens, no AppRole for daemon auth. Most locked-down, stack-native.
- Connection only reachable on the WG mesh (defence in depth: WG peer + valid cert).
- Cert SAN → role mapping lives in broker config (per group).

### 4.2 Short-TTL issuance (point 2)
**(a) SSH signed-certificate CA**
- `GET  /v1/{group}/ssh/ca` → `{ "ca_public_key": "ssh-ed25519 …" }` (trust anchor; host bootstrap).
- `POST /v1/{group}/ssh/sign`
  - req: `{ "public_key", "cert_type":"user|host", "principals":[…], "ttl":"15m",
    "extensions":{…}, "tenant_id":"<uuidv4|null>" }`
  - resp: `{ "signed_certificate", "serial", "valid_before", "lease_id" }`
  - CA private key lives **in the broker's at-rest encrypted store**, never exported.
  - Host-cert CA = group scope; user-cert principals = tenant-scoped where applicable.
  - Future: `sk-ssh-ed25519` / PIV-backed CA (extension point, not v1).

**(b) Leased service-admin creds (OpenSearch RBAC)**
- `POST /v1/{group}/{tenant_id}/creds/{role}`
  - `{role}` maps to a backend engine + privilege template, defined in broker config.
    **Engine: OpenSearch RBAC (`audit-writer`, write-only).** This is the only brokered
    cred engine — the legacy RethinkDB the stack still runs does **not** use auth, so it is
    never brokered; if a modern datastore later needs brokered creds we add an engine then.
  - resp: `{ "username", "password", "lease_id", "ttl", "renewable", "max_ttl" }`
  - Broker creates an **ephemeral backend user** with TTL; on lease end/revoke it
    **deletes** that user (Vault database-secrets-engine semantics).

> **Demon-confirmed parameters (2026-05-26), lock into v1 OpenAPI:**
> - Host-cert SSH CA = **group scope** (not per-tenant); tenant scoping only for leased
>   service-admin creds under `<group>/<tenant_id>/<role>`.
> - Roles: `audit-writer` (OpenSearch RBAC, write-only on `audit-events-*`; demon writes
>   its own `source:"control-plane"` events — distinct from vault's `source:"vault"`). No
>   `os-metrics-reader` (metrics are Prometheus/PromQL, not OpenSearch); no RethinkDB engine
>   (legacy RethinkDB uses no auth — owner, 2026-05-26).
> - **TTLs:** SSH cert 900 s interactive / 300 s automated + touch-per-op (fresh cert per
>   destructive/secret/CA op). Operator session: **8 h hard cap, 30 min idle**. Every
>   cert/lease is a child of the session lease → cascade-revoke = revoke-on-session-end.
>   Renew only up to `max_ttl` = remaining session lifetime.

### 4.3 Lease model (point 3)
- Every issued cred has `lease_id, ttl, renewable, max_ttl`, and a parent.
- `POST /v1/sys/leases/renew`  `{ "lease_id", "increment" }`
- `POST /v1/sys/leases/revoke` `{ "lease_id" }` → revokes lease + tears down backend
  user / invalidates cert serial (CRL/`KRL` for SSH).
- **Session-bound:** `POST /v1/sys/session` → `{ "session_id", "ttl" }`. Leases issued
  while a session is active are **children** of it. `DELETE /v1/sys/session/{id}`
  (or session-TTL heartbeat timeout) **cascade-revokes** every child lease.
  Implemented as a parent→child lease tree + cascade revoke. Meets demon's
  "creds die when operator session ends".

### 4.4 Namespace / residency (point 4)
- Path convention: **`<group>/<tenant_id UUIDv4>/<role>`**.
  - `group` = per-instance constant (not in client control).
  - `tenant_id` = Vulture `organization_id`, **lowercase UUIDv4** (validated; reject
    non-conforming).
  - A request whose `tenant_id` is not provisioned in this instance's group → `404`
    (structurally cannot resolve another tenant/region; no cross-group route exists).
- Confirm with demon: host-cert CA is group-scoped (fleet hosts), not tenant-scoped.

### 4.5 Audit (point 5) — **vault owns it**
- **Decision:** the broker emits canonical **B3** events itself with **`source:"vault"`**
  (free keyword, not enum-gated → cheap to add) to **group-local** OpenSearch
  `audit-events-{group}-YYYY.MM`. Demon does NOT double-record as `control-plane`.
  Rationale: issuance/revoke is the broker's action → single source of truth.
- Durable local store first (the existing in-vault `audit_log`, hash-chained, evolves
  into the broker's source of truth), then **best-effort** ship — a ship failure never
  blocks issuance.
- **Redact at emitter:** never emit secret values, private keys, passwords, signing
  keys. Emit metadata only: `action` (`ssh.sign`, `creds.issue`, `lease.revoke`,
  `session.end`), `lease_id`, `role`, `tenant`, `ttl`, `serial`, `principals`,
  `outcome`. Matches the audit-event "Hard rules" (default-deny on snapshots).

### 4.6 Bootstrap on FreeBSD without TPM (point 6)
- **Broker's own master key (unseal):** Argon2id-derived from an operator unseal
  passphrase entered at service start (Vault-style manual unseal); key held in
  `SecretBox`, zeroized. For unattended restart, a documented fallback: sealed file
  `mode 600` owned by the broker user on a ZFS-encrypted dataset; or KMS-wrap once a
  per-group KMS exists. Recommend manual unseal for v1; document the trade-off.
- **Demon's FIRST vault-auth secret = its mTLS client key + cert.** Provisioned out
  of band at host bring-up: key generated **on the demon host** (never leaves), cert
  signed by the fleet Root CA by the control-plane operator, stored `mode 600`. No TPM
  required — rely on FreeBSD file perms + ZFS encryption + WG isolation. Residual risk
  (host compromise → that host's cert only) is bounded by per-host certs, short-TTL
  everything-else, and revoke at the Root CA / broker CRL. This is exactly demon's
  "one host-bound long-lived secret" principle.

## 5. vault-sync — row-level oplog (memento/probe)

Implements the remote side of memento-core's existing **sync-provider abstraction**.

- **Op:** `{ op_id (UUIDv7/ULID), device_id, hlc (hybrid logical clock), collection_id,
  encrypted_payload }`. Payload (table, row_id, column values) is **encrypted
  client-side with the vault key** → server is blind. Ordering uses cleartext `hlc`
  + `device_id`; grouping uses an opaque `collection_id` (per vault). Server stores
  ciphertext ops only.
- **Conflict resolution:** start with **per-row LWW keyed by HLC** (pragmatic for the
  notes domain). CRDT text-merge for note bodies is a Phase-4 upgrade, not v1.
- **Endpoints:** `POST /v1/sync/{collection}/push` (batch ops), `GET /v1/sync/{collection}/pull?since=<hlc>`,
  WS channel for live tail. Storage: SQLite/Postgres of opaque encrypted ops.
- **Device auth:** device enrols via the vault passphrase → registers a device
  keypair; server authenticates a device by its pubkey. (Not fleet mTLS — this is
  personal.)
- **Residency:** as scoped today this is the **owner's personal data**, so the EU/UAE
  air-gap does NOT apply. ⚠️ If vault-sync ever serves *tenant* data it must adopt the
  per-group air-gap. Flagged as an explicit scope boundary.
- **Deploy:** small server the owner runs (mac mini or a VPS); clients = memento/probe
  on mac mini + laptop.

## 6. Shared `vault-transport` crate
axum server scaffold · WG-only bind helper · mTLS-against-Root-CA verifier · B3 audit
emitter (best-effort ship + hash-chained local) · residency guard (per-instance group
constant) · lease parent/child tree + cascade revoke · HLC clock. Both services depend
on it; the at-rest lib stays dependency-free of tokio/axum.

## 7. Phasing

- **Phase 0** — workspace restructure (non-breaking; memento/probe `cargo build` green in CI).
- **Phase 1 (unblock demon)** — interim Path C *and* broker skeleton: mTLS-WG listener +
  auth + B3 audit + `ssh/sign` + bootstrap doc. Gives demon points 1, 2a, 5, 6.
- **Phase 2** — leased service-admin creds (OpenSearch/DB engines) + full lease model +
  session-bound cascade + namespace/residency enforcement. Completes demon's needs.
- **Phase 3** — vault-sync MVP (push/pull oplog, LWW, E2E, device enrol) for memento/probe.
- **Phase 4** — hardening: SSH KRL/CRL at scale, CRDT text merge, KMS-wrap unseal, metrics, load.

## 8. Coordination writes (executed ONLY after approval)

1. `inbox/vault/demon-needs-brokering-service.md` → inline answer: **Path A (full),
   phased; Phase 1 doubles as the interim**. Flip `Status: open → answered`.
2. `inbox/vault/demon-brokered-creds-shape.md` → answer all 5 follow-ups (point to §4).
   Flip `Status: partial → answered`.
3. `CONTRACTS.md` "Secrets broker" row: `REQUESTED, NOT BUILT` → `COMMITTED (Path A,
   phased)`, pointing at `terrapi-vault/spec/` (broker OpenAPI to be added) + this doc.
4. `conventions/ports-env.md` vault row: `TBD` → **`8200` API (WG-only) + `8201`
   loopback metrics** (proposed; confirm no collision).
5. New convention file `conventions/secrets-broker.md` (path/namespace + lease +
   session model) — cross-service contract.
6. `inbox/demon/vault-committed-path-a.md` notify note.
7. `terrapi-vault/CLAUDE.md` → add the "Your role in the circle" block (from
   `05-vault-agent-prompt.md`) under the existing coordination block, before `# context-mode`.

## 9. Resolved decisions (owner, 2026-05-26)
- **Broker port:** `8200` API (WG-only) + `127.0.0.1:8201` Prometheus. ✅
- **vault-sync auth:** device keypair enrolled via the vault passphrase; server
  authenticates by device pubkey. No terrapi-identity dependency. ✅
- **vault-sync hosting:** a small **VPS** (reachable from anywhere; no home-network
  dependency). Sync server stays deploy-agnostic; VPS is the target for Phase 3. ✅
- **Unseal:** manual passphrase at boot for v1; KMS-wrap deferred to Phase 4. ✅
- **Repo:** single repo + workspace (this plan); revisit a `vault-broker` repo split
  only after the broker stabilises.

Coordination writes (§8) executed 2026-05-26 after this approval.

## 10. Implementation status (2026-05-26)

**Phase 0 — DONE & verified.** Separate `services/` workspace (own toolchain 1.91.1
via `services/rust-toolchain.toml`); root lib package byte-for-byte unchanged (1.83
MSRV intact). `vault-transport`, `vault-broker`, `vault-sync` build, test, clippy
clean. CI added (`.github/workflows/ci.yml`): lib-msrv (1.83), lib-neutrality
(dependency firewall), services (1.91.1). Verified `memento-core` + `probe-core`
still build against the lib.

**Phase 1 — broker skeleton DONE.** `vault-broker` runs on `8200`:
- Auth boundary (`Principal` from mTLS SAN → role); rustls/WG termination is the next step.
- `/v1/sys/session` (open/end) + `/v1/sys/leases/{renew,revoke}` **implemented** on a
  real session→child-lease engine with cascade-revoke (`vault-transport::lease`, unit-tested).
- B3 audit emitter `source:"vault"` (`vault-transport::audit`, JSONL local sink, tested).
- `/v1/{group}/ssh/{ca,sign}` + `/v1/{group}/{tenant_id}/creds/{role}` are typed **501**
  stubs; shapes fixed. Group-mismatch → 404; bad tenant_id → 400.
- v1 contract published: `spec/broker-openapi.yaml`. Bootstrap: `docs/broker-bootstrap.md`.
- Smoke-tested: healthz, authed session (ttl 28800/1800), 401 unauth, 501 stubs, B3 event.

**Refinement — RESOLVED 2026-05-28.** `group` is now a validated `FromRequestParts`
extractor (`http::Group`) that runs *before* the `Json` body extractor, so a wrong-group
request returns `404` regardless of body validity (was: invalid body `400`'d first). The
residency `404` now also precedes the in-handler capability `403` (a cred for one region
is not even addressable on another's broker — air-gap takes precedence over authz).
Covered by `http::tests::{wrong_group_with_invalid_body_is_404_not_400,
right_group_with_invalid_body_is_400, wrong_group_with_valid_body_is_404}`.

**Phase 1b — DONE:** rustls mTLS-over-WG termination (`tls.rs`: client-cert required +
verified vs the fleet Root CA, peer DNS-SAN → role via `auth::ClientSan`; dev keeps the
header path) · CSPRNG session/lease ids (256-bit, reusing the lib CSPRNG) · boot-time
master-key unseal (`seal.rs`: Argon2id via the lib, zeroizing `SecretBox`, constant-time
passphrase verifier, `mode 600` sidecar) gating all mutating ops behind `503` until
unsealed (`GET /v1/sys/seal-status`). v1 OpenAPI published + demon ack'd.

**Phase 2 — DONE (SSH CA):** the unseal is now **store-backed** (`seal.rs` opens/creates
a `terrapi_vault::Vault` SQLCipher store with the operator passphrase — `WrongPassphrase`
→ sealed). `ssh_ca.rs`: an ed25519 CA per group, generated + persisted in that store on
first run, never exported; signs OpenSSH certs. `GET /v1/{group}/ssh/ca` returns the CA
public key; `POST /v1/{group}/ssh/sign` issues a short-TTL cert as a **session-bound
lease** (keyed by mTLS principal SAN; `409` if no open session; host certs reject a
tenant). Both unstubbed in the spec.

**Phase 3 — framework DONE (dynamic creds):** `creds.rs` — a `CredEngine` trait
(issue/revoke ephemeral backend users), a role→engine registry, and lease→teardown wiring
so a revoke / session-cascade deletes the backend user (`creds.revoke` B3). `POST
/v1/{group}/{tenant_id}/creds/{role}` is unstubbed: validates tenant UUIDv4, requires an
active session (`409`), issues a session-bound lease, emits `creds.issue`. An in-memory
`MockEngine` (registered in dev) makes the path testable; **OpenSearch RBAC `audit-writer`**
is the one real engine. **No RethinkDB engine** — the legacy RethinkDB the stack runs uses
no auth, so it is never brokered (owner, 2026-05-26).

**OpenSearch engine — DONE:** `opensearch.rs` — the modern `audit-writer` adapter behind
`CredEngine` (async): mints an ephemeral OpenSearch internal user via the security REST
API (`PUT …/internalusers/{u}`, admin basic-auth, rustls) mapped to the security role, and
deletes it on revoke/expiry. Registered when `VAULT_OS_*` is configured. Integration-tested
against a live single-node OpenSearch (full create→exists→delete cycle; `docs/dev/opensearch-it.md`).
The `CredEngine` trait is now async (`async_trait`) and `teardown` awaits deletes lock-free.

**Expiry sweeper — DONE:** the lease engine is now time-aware (absolute deadlines, caller
injects `now`; idle deadline advanced by activity). `LeaseEngine::sweep(now)` expires
sessions (hard TTL or idle timeout, cascading children) and individual leases (own TTL).
`sweeper.rs` runs it on a 30 s timer: unbinds expired sessions, deletes the backend users
of expired cred leases, emits B3 `session.expire` / `lease.expire` / `creds.revoke`. This
enforces "short-TTL creds auto-expire" — previously leases only died on explicit revoke /
session end.

**B3 shipping — DONE:** `audit_ship.rs` — a composite sink writes the durable local JSONL
(source of truth) synchronously, then enqueues for a background task that **bulk-indexes**
to group-local OpenSearch `audit-events-{group}-YYYY.MM` (`_bulk` NDJSON). Best-effort +
non-blocking: `emit` only enqueues, a ship failure never blocks issuance (event stays in
JSONL). Enabled by `VAULT_AUDIT_OS_*`. Integration-tested against a live cluster.

**Hash-chained audit store — DONE:** `HashChainSink` (vault-transport) — the durable local
JSONL is now tamper-evident: each record carries `seq` + `prev` + `hash =
SHA256(prev ++ seq ++ event_bytes)` (event bytes recovered byte-exact via `RawValue`).
The chain tip is recovered on restart so appends continue across reboots; `audit::verify`
detects edits, reorders, gaps, and deletions. The broker's `ShippingSink` wraps it (durable
chain first, best-effort OpenSearch fan-out on top).

**Shipping = chain-tailing + replay + drain — DONE:** the shipper no longer uses an
in-memory channel; it **tails the durable hash chain** from a persisted byte cursor
(`<audit>.shipped`), bulk-indexes new events' B3 docs (index from each event's own ts), and
advances the cursor only on a confirmed ship. So a ship failure / crash / shutdown loses
nothing — the next tick or process start **replays** the backlog; shutdown does a best-effort
final flush. Shipping never blocks issuance (reads the durable file out of band).

**Role authz — DONE:** SAN→role mapping is config-driven (`VAULT_ROLES_CONFIG` JSON →
`{role, caps}`) and **per-role least-privilege is enforced**: the matcher reads the cert's
first SAN dNSName; the `Principal` carries its `Capability` set (`ssh-ca|ssh-sign|creds|
session|leases`); each handler calls `require_cap` → `403` if not granted. Prod requires the
config (empty = deny-all `403`); dev keeps the header path + all-caps `dev` principal.
Sample `docs/dev/roles.example.json` (demon-operator, demon-system, aether-backup).

**KMS wrap/unwrap — DONE:** `kms.rs` — per-target KEK (`<group>/<tenant_id>/<key_id>`)
generated + held in the at-rest store, never exported, **stable** (not leased), NOT
session-bound. `POST …/kms/{key_id}/wrap` `{dek}` → `{wrapped,kek_id}` and `…/unwrap`
`{wrapped}` → `{dek}` (XChaCha20-Poly1305 envelope, 24-byte nonce; cap `kms`, aether-backup principal). For
aether fleet-mode backup keys; preserves their zero-knowledge model (KEK never leaves).

**Hardening round — DONE (B gaps):**
- **SSH revocation tracking** — revoking/expiring an ssh-cert lease records its serial in
  the store; `GET /v1/{group}/ssh/revoked` lists serials (build an sshd KRL at deploy).
  (Short-TTL certs mostly self-expire; binary-KRL distribution stays a deploy concern.)
- **KMS KEK rotation** — `POST …/kms/{key_id}/rotate` (versioned KEKs; old blobs carry a
  version prefix and keep unwrapping; new wraps use the latest).
- **Store snapshot** — `POST /v1/sys/store-snapshot` (online `VACUUM INTO`, ciphertext;
  for aether Ask 2), cap `snapshot`.
- **Metrics** — `127.0.0.1:8201/metrics` Prometheus text (per-action audit counters +
  `vault_sealed` gauge), loopback-only.
- **Unattended unseal** — `VAULT_UNSEAL_PASSPHRASE_FILE` (mode-600 fallback). Full
  broker-master-key KMS-wrap stays deferred (needs a per-group KMS that doesn't exist yet).

**FreeBSD deploy module — DONE:** `deploy/` mirrors `identity/deploy/` — `build.sh`,
`jail/{Bastillefile,provision.sh}` (bastille vnet jail per group), `rc.d/vault-broker`
(unprivileged `vault` user, `REQUIRE zfskeys`), `zfs/{zfskeys,check-encryption.sh}`
(encrypted `zroot/terrapi/vault` → `/var/db/terrapi-vault`), `vault-broker.env.sample` +
`roles.json.sample`, `security/{pf,fim,least-privilege,audit_control}`, `alerts/`, and an
`install.sh` runbook. Crown jewels (SSH-CA key + KMS KEKs in `store.sqlcipher`, `unseal.pass`)
on the encrypted dataset. Infra confirmed + ready to run host steps on `medina`.

**Broker hardening — DONE 2026-05-28.** Defensive request middleware in `hardening.rs`,
applied in `http::router` (outer→inner): conservative security headers · per-route request
metrics labelled by the `MatchedPath` *template* (tenant ids never reach `:8201`) +
`vault_http_inflight` gauge · per-principal (per mTLS SAN) token-bucket rate limit (`429`) ·
global concurrency cap (`503`) · request timeout (`408`) · body-size limit (`413`). All five
limits are env-tunable (`VAULT_{MAX_BODY_BYTES,REQUEST_TIMEOUT_SECS,MAX_CONCURRENCY,RATE_PER_SEC,RATE_BURST}`)
with safe defaults — no deploy change required. Zero new crates (axum `DefaultBodyLimit` +
`middleware::from_fn` + std/tokio). Uniform JSON `404` fallback for unrouted paths.

**Next:** additional `CredEngine` adapters for any *modern* datastore that needs brokered
creds (RethinkDB is out); broker-master-key KMS-wrap for unattended unseal once a KMS
exists; `vault-sync` (Svet B).
