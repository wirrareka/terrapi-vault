# vault-broker bootstrap (FreeBSD, no TPM)

How the broker and its first consumer (proximiio.demon) come up securely on FreeBSD
hosts that have no default TPM. Answers demon's bootstrap question (point 6); the
contract summary lives in `coordination/conventions/secrets-broker.md`.

## Trust anchors
- **Fleet Root CA** — the only thing shared across residency groups. Signs every mTLS
  client/server cert and (later) the SSH host CA. Lives offline / on the control plane.
- **WireGuard mesh** — per group (eu `10.200.0.x`, uae `10.210.0.x`). The broker listens
  on `8200` bound to its WG address only; nothing is reachable off-mesh.

## Broker unseal (its own master key)
The broker stores its CA keys + lease state in an at-rest encrypted store (the
`terrapi-vault` SQLCipher library). Its master key is derived at start:

- **v1 — manual unseal (implemented, `seal.rs`):** unsealing = opening the broker's
  at-rest store (`terrapi_vault::Vault`, SQLCipher at `VAULT_STORE_PATH`) with the
  operator passphrase (`VAULT_UNSEAL_PASSPHRASE`). The store's SQLCipher key is derived
  with the lib's Argon2id; a wrong passphrase surfaces as the lib's `WrongPassphrase`.
  Until opened, the broker is **sealed** and every mutating op returns `503` (poll
  `GET /v1/sys/seal-status`). The store holds the SSH CA key (and, later, the lease
  ledger); its plaintext `.meta.json` sidecar holds only the salt + KDF params (no secret).
- **Unattended restart fallback:** the passphrase comes from an `rc.conf`-managed secret
  / env file on a **ZFS-encrypted dataset** (host root can read it — documented
  trade-off; acceptable because the dataset is encrypted and the host is WG-isolated).
- **Phase 4 — KMS-wrap** once a per-group KMS exists. Not required for v1.

No TPM is involved. Security rests on: FreeBSD file perms (`mode 600`, dedicated user),
ZFS dataset encryption, and WG isolation.

## Configuration (env)
- `VAULT_RESIDENCY_GROUP` — `eu` | `uae` (per-instance constant; default `eu`).
- `VAULT_BROKER_BIND` — listen addr (prod: the WG address only; default `127.0.0.1:8200`).
- `VAULT_UNSEAL_PASSPHRASE` — operator unseal passphrase (prod). Absent/invalid → sealed.
- `VAULT_STORE_PATH` — at-rest SQLCipher store (SSH CA key, later the lease ledger);
  created on first unseal, opened with the passphrase thereafter.
- `VAULT_TLS_CERT` / `VAULT_TLS_KEY` — broker server cert chain + key (PEM).
- `VAULT_TLS_CLIENT_CA` — fleet Root CA bundle (PEM); client certs are required + verified
  against it, and the peer DNS-SAN maps to a broker role. All three TLS vars are
  **mandatory in production** — the broker refuses to start without them.
- `VAULT_AUDIT_PATH` — durable local B3 audit store (source of truth): a **tamper-evident
  hash-chained** append-only JSONL (each record SHA-256-chained to the previous; edits,
  reorders, and deletions are detectable).
- `VAULT_AUDIT_OS_URL` / `VAULT_AUDIT_OS_USER` / `VAULT_AUDIT_OS_PASSWORD` — optional
  best-effort shipping of B3 events to group-local OpenSearch (`audit-events-{group}-YYYY.MM`,
  bulk-indexed by a background task; a ship failure never blocks issuance). Set
  `VAULT_AUDIT_OS_URL` to enable. `VAULT_AUDIT_OS_INSECURE_TLS=1` for dev/self-signed.
- `VAULT_OS_URL` / `VAULT_OS_ADMIN_USER` / `VAULT_OS_ADMIN_PASSWORD` — OpenSearch
  dynamic-cred engine: the cluster + the admin credential the broker uses to mint/delete
  ephemeral users. Set `VAULT_OS_URL` to enable the engine. `VAULT_OS_ROLE` (default
  `audit-writer`), `VAULT_OS_MAX_TTL_SECS` (default 28800), `VAULT_OS_INSECURE_TLS=1`
  (dev/self-signed only). See `docs/dev/opensearch-it.md`.
- `VAULT_ALLOW_INSECURE_DEV=1` — **local dev only**: plain HTTP, `X-Client-Cert-SAN`
  header identity, auto-unseal with an ephemeral key. Never in production.

## Demon's FIRST secret (the one host-bound long-lived secret)
Demon's single long-lived secret is its **mTLS client key + cert** for talking to the
broker. Bootstrap at host bring-up:

1. The demon host generates its **client keypair locally** — the private key never
   leaves the host (stored `mode 600`, dedicated user, ZFS-encrypted dataset).
2. The control-plane operator has the **fleet Root CA sign** the client cert (SAN =
   the daemon's service identity, mapped to a broker role).
3. The host joins its group's **WireGuard mesh** (peer config provisioned at bring-up).

From then on demon holds exactly one host-bound secret (this client key) and brokers
everything else as short-TTL leased creds (SSH certs 900/300 s, service creds with
session-bound leases) — its blast-radius story.

## Residual risk
A compromised demon host exposes only **that host's client cert** (per-host, not fleet).
Mitigated by: per-host certs, short-TTL everything-else, cascade-revoke on session end,
and revoke at the Root CA / broker CRL (+ SSH KRL). No shared long-lived material.

## Sequence
```
host bring-up ─┬─ generate demon client keypair (on host, mode 600)
               ├─ Root CA signs client cert (operator, out of band)
               └─ join WG mesh (peer config)
broker start  ─┬─ operator enters unseal passphrase (Argon2id → master key)
               └─ bind 8200 on WG addr, require mTLS (Root CA trust anchor)
demon → broker ── mTLS (client cert) → open session → lease short-TTL creds
```
