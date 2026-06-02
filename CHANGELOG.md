# Changelog

terrapi-vault — the secrets boundary for the quanto / proximi.io stack: a network
secrets **broker** (Path A) plus the embedded at-rest SQLCipher library it grew from.

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
