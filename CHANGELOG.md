# Changelog

terrapi-vault — the secrets boundary for the quanto / proximi.io stack: a network
secrets **broker** (Path A) plus the embedded at-rest SQLCipher library it grew from.

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
