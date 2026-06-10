# Changelog

terrapi-vault — the secrets boundary for the quanto / proximi.io stack: a network
secrets **broker** (Path A) plus the embedded at-rest SQLCipher library it grew from.

## 0.1.12 (2026-06-10)

Follow-ups landed after the v0.1.11 cut:

- **security (lib, Sec-L2):** keyed SQLCipher connections set `PRAGMA temp_store = MEMORY`, so
  temp B-trees / spill data from queries on the encrypted store stay in memory and are never
  written to a plaintext temp file on disk.
- **ci:** `actions/setup-node` bumped v4 → v5 (Node 24 runtime; clears the Node 20 deprecation
  warning in the console SPA-build jobs); dropped the redundant `dtolnay/rust-toolchain`
  `toolchain:` input (the SHA-pinned action reads `rust-toolchain.toml`); rustfmt the v0.1.11
  hardening changes.

## 0.1.11 (2026-06-09) — security hardening

Multi-agent security analysis (`docs/security/security-analysis-2026-06-09.md`) → a phased
remediation across the lib + all services. No data-model or wire-breaking changes; the broker
roles config gained one optional field. All Rust + web tests green; `cargo deny check` fully green.

- **Phase 0 — CI / supply chain:** `cargo deny` advisories gate fixed (the `rsa` dev-dep ignore
  re-justified for both `deny.toml` + `audit.toml`); all GitHub Actions SHA-pinned + a Dependabot
  config; web toolchain bumped (vite 6 / vitest 3 / esbuild 0.25.12 — 0 prod & dev vulns) and the
  duplicate npm lockfile removed. Broker: `VAULT_AUDIT_OS_INSECURE_TLS` dev-gated; insecure-dev +
  TLS refused (no prod downgrade); production refuses to default the store/audit paths into a temp
  dir. Console: CSP + nosniff + frame-deny + `no-store` headers, logout → POST, `__Host-` session
  cookie, generic 401 (no IdP-internal leak).
- **Phase 1 — authz correctness:** Console OIDC `state` bound to a `__Host-vc_auth` pre-auth cookie
  (login-CSRF / fixation), bounded pending-auth map, loopback-gated + anti-downgrade insecure-dev.
  Broker: lease renew/revoke + session-end are owner-bound; `kms` cap required even with a JWT;
  per-role `ssh_principals` allowlist; session-rebind ends the prior session; single-SAN client
  certs enforced.
- **Phase 2 — broker resilience:** boot reconciliation sweeps this node's orphaned OpenSearch
  users (node-scoped); issuance audit is fail-closed (no cred without a durable record); mTLS
  handshake timeout + connection cap. CRL vs short-lived certs raised with infra; per-tenant
  OpenSearch role isolation documented as accepted risk.
- **Phase 3 — vault-sync:** rate-limited `/account` + `/enroll`; `deny_unknown_fields` + id length
  caps + per-push op cap; refuses a non-loopback bind without `VAULT_SYNC_DB_KEY`; device list +
  revoke endpoints; key-replacement logged distinctly. Protocol-v2 (AEAD-bound LWW metadata, op
  hash-chain) proposed to memento/probe.
- **Phase 4 — defense-in-depth:** KDF params floored to the RFC 9106 minimum when migrating a v1
  vault (untrusted sidecar can't weaken the new slot); recovery-code intermediates zeroized;
  sidecar/export temp writes use `create_new` (no symlink-follow); `deny.toml` gained
  licenses/bans/sources policy; audit chain readers stream line-by-line (flat memory).
- **Review follow-up (xhigh code review):** extended fail-closed audit to KMS wrap/unwrap/rotate/
  rewrap, object-store presign, and session-open (a shared `require_audit` 503 helper); the audit
  chain now refuses all appends if its tip can't be cleanly recovered (mid-file read error →
  fail-closed, no chain fork). Boot orphan-reconcile moved to a background task with HTTP
  connect/request timeouts so a slow OpenSearch can't stall startup, and it now also reclaims
  legacy users that predate node-tagging. vault-sync: separate rate bucket for account/enroll vs
  enroll-challenge; `revoke_device` won't remove the last device and bounds the device-id length;
  `Op` is now `deny_unknown_fields` (StoredOp un-flattened to keep the response forward-compatible).
  Console pending-auth refuses new logins at the cap instead of evicting in-flight ones, and the
  OIDC error path clears the binding cookie. ssh-sign roles without an allowlist now still refuse
  privileged principals (root/admin/…) unless explicitly listed.

## 0.1.10 (2026-06-08)

vault-console **id_token verification alg fix** — found at the live `acr=mfa` round-trip (the whole
chain — `private_key_jwt` client auth, MFA, the authorization-code callback — passed, then failed on
id_token verification). The id_token verifier **hardcoded RS256**, but identity signs id_tokens with
**ES256** (EC P-256); the RSA cert is only the *client-assertion* signing key. The two algs were
conflated.

- The id_token verifier now **honors the OP's `id_token_signing_alg_values_supported`** from
  discovery instead of pinning one alg, against an asymmetric-only allow-list (`ES256`, `RS256`) so
  alg-confusion (`none` / an HMAC alg verified with the public key) is still rejected before any key
  lookup. The client-assertion alg (RS256, our cert) is unchanged.
- Tests: an **ES256 end-to-end** id_token verification (identity's real alg, the exact regression) +
  alg-acceptance unit tests (advertised-set honored, confusion algs rejected, empty-advertised
  fallback). 23 green, clippy pedantic clean. No env/contract change — binary-swap redeploy only.

## 0.1.9 (2026-06-08)

Release-CI fix for the vault-console artifacts — **supersedes 0.1.8**, which built the broker but
failed to publish the console tarballs (corepack pulled floating-latest pnpm 11, which turns
ignored dependency build scripts into a hard error, so `vite build` had no esbuild/@swc toolchain).
Carries the **same P1b OIDC RP** as 0.1.8 (below); deploy `vault-console-0.1.9-{linux,freebsd}`.

- `web/package.json`: `pnpm.onlyBuiltDependencies = [@swc/core, esbuild]` (fixes the ignored-builds
  error on any pnpm 10/11) + `packageManager` pin `pnpm@10.6.5`.
- `release.yml` (both console jobs): `corepack prepare pnpm@10.6.5 --activate` before install.
- Committed `web/pnpm-lock.yaml` (was never tracked → CI resolved fresh each run).

## 0.1.8 (2026-06-08)

vault-console **P1b — OIDC RP login**. The operator console now authenticates humans against
terrapi-identity; this tag is the trigger for the eu console go-live (infra creates the jail / WG
`.110` / dual-EKU cert + edge, identity creates the staged `vault-console` client, then a live
`acr=mfa` round-trip closes it). The broker binary is **unchanged from 0.1.7** (only the console
and a deploy sample changed); medina's live broker need not move.

- **OIDC Relying Party** (`vault-console/src/oidc.rs`) — `authorization_code` + **PKCE (S256)**,
  **`private_key_jwt`** client auth signed **RS256** with the console cert's RSA key (header `kid`
  = the RFC 7638 thumbprint identity bound — one dual-EKU cert, two uses: broker mTLS + assertion
  signing, no shared secret), and **`acr=mfa` enforced** (we request `acr_values=mfa` AND reject
  any id_token whose `acr` claim is not `mfa`). id_token verified against identity's JWKS
  (discovered from the issuer, kid-miss refetch throttled like the broker's `jwt.rs`), `iss`/`aud`/
  `exp` by jsonwebtoken, `nonce` + `acr` checked in pure unit-tested code. `sub`/`email` → the
  single `operator` role (no per-tenant RBAC).
- **Cookie session** (`vault-console/src/session.rs`) — in-memory operator sessions (stateless
  across restarts, matching the no-DB P1) + a one-shot `state`→PKCE-verifier/nonce store (defeats
  `state` replay). Cookie is `HttpOnly; Secure; SameSite=Lax`.
- `/api/v1/auth/{login,callback,logout}` are now wired (were `501`); the dev stub remains only
  under `VAULT_CONSOLE_ALLOW_INSECURE_DEV`. New env: `VAULT_CONSOLE_OIDC_{ISSUER,REDIRECT_URI,KID}`
  (required to enable login) + optional `CLIENT_ID`/`SCOPES`/`ACR`; the signing key is the existing
  `VAULT_CONSOLE_TLS_KEY`. Unset issuer ⇒ login disabled (dev or all-401).
- **`deploy/roles.json.sample`**: added `vault-console.eu.proximi.internal` → **`observe`** (the
  broker grant the console's mTLS cert needs; absent ⇒ the console reads 403).
- Unit-tested end-to-end against a mock IdP key (PKCE S256 vector, assertion RS256+kid round-trip,
  id_token happy-path + `acr`/nonce/audience rejection). Live `acr=mfa` round-trip runs at deploy.

## 0.1.7 (2026-06-06)

Object-store presign — the DO Spaces tile publish/serve path for proximiio-outer-map (publish)
and proximiio-belt (serve). DO Spaces has no key-management API and only coarse per-bucket key
scoping, so instead of leasing per-tenant keys the broker holds one long-lived per-group Spaces
RWD key (env-held, **never exported**) and signs short-TTL, single-object presigned URLs; the
per-tenant / method / single-object scoping lives in the SigV4 signature.

- **`POST /v1/{group}/object-store/presign` (cap `object-store`)** — presigned **PUT** URL for a
  tile archive or manifest pointer. `{tenant_id,map_id,version,kind:"archive|manifest",ttl_secs?}`
  → `{url,method,key,expires}`. Keys are server-constructed (`t/<tenant>/<map>/<version>.pmtiles`
  and `…/latest.json`); no client-supplied path (tenant_id UUIDv4, map_id/version `[A-Za-z0-9._-]`,
  no traversal).
- **`POST /v1/{group}/object-store/presign-get` (cap `object-store-read`)** — presigned **GET** URL
  for the same keys (the serving side, belt). A distinct cap so a read principal can only sign GETs
  and a writer only PUTs. The `Range` header is unsigned, so range-GETs work unchanged.
- **Stateless — not a lease:** no `lease_id`/renew/revoke (a presigned URL can't be revoked); the
  short TTL is the only bound (default 300 s, max 900 s).
- **SigV4** query-presigning (`object_store.rs`, RustCrypto `hmac`/`sha2`), signing-key chain pinned
  to an independent reference vector.
- Config `VAULT_OBJECT_STORE_{KEY,SECRET,REGION,BUCKET}` (+ optional `HOST`/`TTL_SECS`/`MAX_TTL_SECS`);
  unset ⇒ both ops `503 not_configured`. Audit `object_store.presign{,_get}` = key+tenant+expires
  only (never the URL/signature). Per-group: an `eu` signer only ever signs `eu`-bucket URLs.
- Broker OpenAPI → **1.2.0** (two new ops, `object-store`/`object-store-read` caps). `deploy/`
  env + roles samples updated.

## 0.1.6 (2026-06-04)

- **OpenSearch clients gain a CA-file TLS option (`opensearch.rs`, `audit_ship.rs`).** New
  `VAULT_OS_CA` / `VAULT_AUDIT_OS_CA` (PEM, mirrors `VAULT_TLS_CLIENT_CA`): when set, the cred-engine
  and audit-ship reqwest clients add it as the **sole** trust root (built-in/public roots off), so a
  fleet-CA-signed OpenSearch node cert verifies — the rustls client ignores the FreeBSD system trust,
  so the prior options were only `*_INSECURE_TLS`. Lets eu drop the interim insecure toggle. Shared
  `build_os_client` helper (no duplicate client-build logic across the two modules).

## 0.1.5 (2026-06-03)

KMS hardening from a high-effort code review of the v0.1.4 chain:
- **JWKS refetch is now rate-limited (`jwt.rs`).** A `kid` miss refetches at most once per
  `MIN_JWKS_REFETCH` (30 s); within that window an unknown `kid` returns `UnknownKid` WITHOUT a
  fetch. Previously every token bearing a random/unknown `kid` drove one outbound JWKS call (plus
  an OIDC-discovery GET) against identity — a request-amplification DoS. A down/slow JWKS endpoint
  is rate-limited too (the attempt is stamped even on failure).
- **kms preflight fails fast (`http.rs`).** `require_unsealed` + the tenant/key_id format checks
  now run BEFORE `kms_authorize`, so a sealed broker (or a malformed request) returns `503`/`400`
  without triggering the JWT path's network JWKS round-trip — a sealed broker is no longer an
  amplifier.

## 0.1.4 (2026-06-02)

KMS root-of-trust chain (identity ↔ vault) — vault's side, LOCKED 2026-06-02
(`coordination/conventions/secrets-broker.md §KMS root-of-trust`). Broker API `1.1.0`.
- **kms-cap auth = Option J (JWT-bearer).** New `jwt` module verifies identity-minted
  short-TTL **ES256** workload creds as the per-call `kms` cap proof, on top of the mTLS
  channel: `alg=ES256`+`kid`, JWKS (OIDC-discovered or `VAULT_KMS_JWT_JWKS_URI`, cached +
  refetched on a `kid` miss), `iss`/`aud="vault"`/`exp`, `scope ⊇ kms`, `residency_group ==`
  this instance's group, and the token `tenant_id == path tenant_id`. Opt-in via
  `VAULT_KMS_JWT_ISSUER` (+ `_AUDIENCE`); absent ⇒ kms stays cap-based (cert-SAN `kms`, the
  aether fleet-backup path) — no behaviour change for existing consumers.
- **`kms.rewrap`** (`POST /v1/{group}/{tenant_id}/kms/{key_id}/rewrap`) — server-side re-wrap:
  unwrap under the blob's embedded KEK version, re-wrap under the current version; the
  plaintext DEK never leaves the broker. Drives the ack-gated re-wrap flow (consumer streams
  blobs → emits `kms.rewrap_complete` so identity retires the old root).
- **arm (a) — identity-sealed master key (unseal client).** New `identity_kms` module: at
  boot the broker exchanges an inert `{kek_id, wrapped}` blob for its plaintext unseal master
  key via identity's WG-only KMS listener (`POST /kms/v1/{seal,unseal}`), so a stolen at-rest
  store is useless without a live in-group call to identity. **Auth = native mTLS** (infra
  §2→(A) decision): the broker connects as an mTLS client presenting its own `VAULT_TLS_*`
  cert (the dot-form `vault.<group>.proximi.internal`, clientAuth EKU) and trusts identity's
  server cert via the fleet Root CA — no app-layer secret. Falls back to the manual passphrase
  (break-glass) when identity is unreachable. Opt-in via `VAULT_IDENTITY_KMS_URL`; one-time
  bootstrap with `VAULT_KMS_SEAL_INIT=1`. Ships gated off until the dot-form cert is adopted
  and identity's listener (v0.1.13) + per-group root key are live.
- **Root-rotation handling — arm (a) re-seal + `kms.master_resealed`.** When identity rotates
  its per-group root, the unseal response now carries `current_kek_id`/`reseal_required`; the
  broker re-seals its (value-unchanged) master key under the current root, persists the new blob
  atomically (temp+rename), and emits B3 `kms.master_resealed {old_kek_id→new_kek_id}` so identity
  retires the old root (at-least-once; identity dedups by `{old,new}`). Handled at boot **and** on a
  timer (`VAULT_KMS_RESEAL_CHECK_SECS`, default 6 h) for a broker running across a rotation without
  a restart. NB: this is the *root*-rotation path (master re-seal only); vault's own per-target KEK
  rotation (`kms.rotate`/`kms.rewrap`) is independent and identity-uninvolved.

## 0.1.3

Deploy-only fix (binary unchanged) — the second rc.subr-magic collision found by `sh -x`
in the v0.1.2 medina deploy:
- **`vault_broker_env` collided with rc.subr's magic `${name}_env`** (its "extra
  environment" list), so rc.subr ran `env <envfile-path> daemon …` → `env` tried to **exec
  the file path** → `Permission denied`, `service start` failed. Renamed the var →
  **`vault_broker_envfile`** (the `VB_ENV=` passed to the wrapper was always fine; only the
  rc.d var NAME was hijacked). Added a note enumerating ALL `${name}_*` magic names to avoid
  (`user/group/env/chroot/chdir/nice/limits/flags/fib/oomprotect`).

## 0.1.2

Deploy-only fix (binary unchanged from 0.1.1) — the rc.d `service` start found in the
v0.1.1 medina deploy:
- **rc.d double user-drop** — the rc.d config vars were named `vault_broker_user` /
  `vault_broker_group`, which `rc.subr` treats as **magic** (`${name}_user`) and does its
  OWN su/chroot drop — on top of `daemon -u vault`. That doubled-dropped context couldn't
  read the env file (`env: …/vault-broker.env: Permission denied`), so
  `service vault-broker start` failed (direct `daemon` worked). Renamed to
  `vault_broker_runas` / `vault_broker_rungroup` (plain vars) so the single `daemon -u`
  drop is used — now reboot-safe via `service`.
- **env + roles perms** — `vault-broker.env` and `roles.json` are now `0640 root:vault`
  (the broker reads them as the `vault` user; `0600 root:vault` denied the read).

## 0.1.1

Startup fixes found in the first medina deploy of 0.1.0:
- **rustls CryptoProvider** — install `aws_lc_rs` as the process default at `main` start.
  rustls 0.23 panicked ("Could not automatically determine the process-level
  CryptoProvider") because both `aws-lc-rs` and `ring` are pulled in transitively
  (mTLS server + reqwest); now it's chosen explicitly before any TLS use.
- **rc.d** — `deploy/rc.d/vault-broker` no longer inlines a single-quoted `sh -c` in
  `command_args` (rc.subr word-splits it → "Unterminated quoted string"). It runs a new
  `deploy/libexec/vault-broker-run` wrapper that `set -a`-sources the env drop-in (so
  `VAULT_*` are exported) and execs the broker; the env path is passed via `env(1)`.
- **deploy** — `server.key` is now `0640 root:vault` (the broker reads it as the `vault`
  user); `provision.sh` defaults to `15.0-RELEASE` + notes the `ip4=inherit` + WG /32
  fleet jail pattern; install.sh installs the rc.d wrapper.

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
