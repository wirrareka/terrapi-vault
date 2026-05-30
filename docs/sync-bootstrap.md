# vault-sync — bootstrap & deploy runbook (Svet B, personal)

vault-sync is the **personal** multi-device oplog server for memento/probe. It is NOT a
platform service: no residency, no tenants, no fleet mTLS. It runs as a single small binary
on a machine you control (mac mini / a small VPS). See `docs/planning/02-vault-sync-oplog.md`
for the design and `spec/sync-openapi.yaml` for the wire contract.

## Trust model (read first)

- **Server-blind.** The server stores only: `vault_id`, an enrolment verifier (Argon2-secret
  hash), device ed25519 public keys, and **opaque encrypted ops**. It never sees the vault
  passphrase, the vault key, or note plaintext.
- **At-rest encryption (recommended).** Content is E2E-encrypted, but the DB *metadata*
  (op/device counts, timing, op sizes, cleartext `collection_id`, device pubkeys) is not — so
  set `VAULT_SYNC_DB_KEY_FILE` (or `VAULT_SYNC_DB_KEY`) and the whole DB + WAL are
  SQLCipher-encrypted, protecting that metadata if the disk/backup is stolen. Set it **before
  first run** and back the key up **separately** from the DB.
- **Device auth is app-layer.** Every `push`/`pull`/`status`/`tail` is signed by the calling
  device's ed25519 key over a canonical string (method + path + vault id + ts + nonce + body
  hash). `account`/`enroll` are self-signed by the key being registered; **both** are gated by
  the passphrase-derived enrolment proof (`account` checks `SHA-256(proof) == verifier.hash`,
  so an account is only created with a genuinely derivable verifier). `vault_id` must be a
  lowercase UUIDv4. `enroll-challenge` is unauthenticated and rate-limited. The exact canonical
  string, base64 variant, skew/nonce rules and a **signing test vector** to validate a client
  implementation are in `spec/sync-openapi.yaml` (`info.description`).
- **TLS is the transport boundary.** The binary speaks plain HTTP. Put a TLS terminator in
  front (so the enrolment proof and ops travel encrypted in transit). Two good options:
  1. **Private overlay (simplest):** run on a WireGuard / Tailscale `/32` and bind there; the
     overlay is the encryption + reachability boundary. No public exposure.
  2. **Public reverse proxy:** Caddy / nginx with a real cert, proxying to `127.0.0.1:8300`
     (and upgrading the `/tail` WebSocket). Never expose the plaintext port directly.

## Configure

Copy `deploy/vault-sync.env.sample` → your service's env file and set `VAULT_SYNC_BIND` +
`VAULT_SYNC_DB`. Defaults: bind `127.0.0.1:8300`, db `vault-sync.db` in the working dir.

## Run

```sh
VAULT_SYNC_BIND=127.0.0.1:8300 VAULT_SYNC_DB=/var/lib/vault-sync/vault-sync.db \
  vault-sync
# → "vault-sync <ver> starting: bind=… db=…"  then  "vault-sync listening on …"
```

### launchd (mac mini) / systemd (VPS)

Run it as an unprivileged user, restart-on-failure, with the env file loaded and the DB
directory writable by that user. `GET /healthz` is a liveness probe (returns
`{"status":"ok","version":"<ver>"}`). Every response carries an `X-Request-Id` (echoed or
generated) for correlation; transient `408`/`429`/`503` carry `Retry-After`.
Prometheus metrics are on a **separate loopback listener** (`VAULT_SYNC_METRICS_BIND`, default
`127.0.0.1:8301`) — `GET /metrics`. Keep it loopback/WG-only (it exposes op/device counts, the
metadata at-rest encryption protects); never route it through the public TLS proxy.

## Endpoints (all under `/v1/sync/{vault_id}`)

| Method | Path                | Auth                          | Purpose |
|--------|---------------------|-------------------------------|---------|
| POST   | `/account`          | self-signed + proof           | first device creates the account (proof must match the verifier) |
| GET    | `/enroll-challenge` | none, rate-limited            | new device fetches enrolment salt/params |
| POST   | `/enroll`           | self-signed + proof           | new device registers its key |
| POST   | `/push`             | device-signed                 | append ops (idempotent on `op_id`) |
| GET    | `/pull?since&limit` | device-signed                 | ops with `seq > since` |
| GET    | `/status`           | device-signed                 | latest_seq / op_count / device_count |
| GET    | `/tail`             | device-signed upgrade         | WebSocket live stream of new ops |

## Backups

`VAULT_SYNC_DB` is the only state. It holds opaque ciphertext, so a backup is safe to store
anywhere — but losing it loses any ops a device hasn't already pulled. Snapshot it
periodically (e.g. `sqlite3 … '.backup'` or a filesystem snapshot). The vault content itself
also lives on each device, so this is a convenience/durability backup, not the sole copy.

## Not yet here (see planning §9 "deferred")

- The **memento-core client** `SyncProvider` (op capture + AEAD payloads + LWW apply) — the
  other half of this; coordinated in the memento repo.
- SQLCipher-at-rest for the server DB (defense-in-depth; payloads are already E2E-encrypted).
- A full `deploy/` module (the broker's FreeBSD bastille pattern) if vault-sync ever needs it.
