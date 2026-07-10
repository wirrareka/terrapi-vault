# vesta-broker bootstrap (FreeBSD, no TPM)

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
`terrapi-vesta` SQLCipher library). Its master key is derived at start:

- **v1 — manual unseal (implemented, `seal.rs`):** unsealing = opening the broker's
  at-rest store (`terrapi_vesta::Vesta`, SQLCipher at `VESTA_STORE_PATH`) with the
  operator passphrase (`VESTA_UNSEAL_PASSPHRASE`). The store's SQLCipher key is derived
  with the lib's Argon2id; a wrong passphrase surfaces as the lib's `WrongPassphrase`.
  Until opened, the broker is **sealed** and every mutating op returns `503` (poll
  `GET /v1/sys/seal-status`). The store holds the SSH CA key (and, later, the lease
  ledger); its plaintext `.meta.json` sidecar holds only the salt + KDF params (no secret).
- **Unattended restart fallback:** the passphrase comes from an `rc.conf`-managed secret
  / env file on a **ZFS-encrypted dataset** (host root can read it — documented
  trade-off; acceptable because the dataset is encrypted and the host is WG-isolated).
- **Arm (a) — identity-sealed master key (implemented, `identity_kms.rs`; opt-in):** when
  `VESTA_IDENTITY_KMS_URL` is set the broker no longer relies on a local passphrase alone —
  at boot it exchanges an inert `{kek_id, wrapped}` blob (stored on the encrypted dataset) for
  the plaintext master key via identity's WG-only **native-mTLS** KMS listener
  (`POST /kms/v1/unseal`). A stolen at-rest store is then useless without a live,
  residency-matched call to identity (the per-group root key never leaves identity). Auth is
  **mTLS**: the broker presents its own `VESTA_TLS_*` client cert (the dot-form
  `vault.<group>.proximi.internal`, clientAuth EKU); there is no application-layer secret. If
  identity is unreachable the broker falls back to the manual passphrase (**break-glass**).
  One-time bootstrap: `VESTA_KMS_SEAL_INIT=1` seals the current passphrase and writes the blob.
  See `coordination/conventions/secrets-broker.md §KMS root-of-trust`.

No TPM is involved. Security rests on: FreeBSD file perms (`mode 600`, dedicated user),
ZFS dataset encryption, and WG isolation.

## Configuration (env)
- `VESTA_RESIDENCY_GROUP` — `eu` | `uae` (per-instance constant; default `eu`).
- `VESTA_BROKER_BIND` — listen addr (prod: the WG address only; default `127.0.0.1:8200`).
- `VESTA_UNSEAL_PASSPHRASE` — operator unseal passphrase (prod). Absent/invalid → sealed.
- `VESTA_UNSEAL_PASSPHRASE_FILE` — unattended-restart fallback: a `mode 600` file (on a
  ZFS-encrypted dataset) holding the passphrase, read if the env var is unset.
- `VESTA_SNAPSHOT_DIR` — where `POST /v1/sys/store-snapshot` writes consistent at-rest
  snapshots (default: temp dir).
- `VESTA_METRICS_BIND` — Prometheus metrics listener (default `127.0.0.1:8201`, loopback).
- `VESTA_STORE_PATH` — at-rest SQLCipher store (SSH CA key, later the lease ledger);
  created on first unseal, opened with the passphrase thereafter.
- `VESTA_TLS_CERT` / `VESTA_TLS_KEY` — broker server cert chain + key (PEM).
- `VESTA_TLS_CLIENT_CA` — fleet Root CA bundle (PEM); client certs are required + verified
  against it, and the peer DNS-SAN maps to a broker role. All three TLS vars are
  **mandatory in production** — the broker refuses to start without them.
- `VESTA_ROLES_CONFIG` — JSON file mapping each cert's first SAN `dNSName` → `{role, caps}`
  (capabilities: `ssh-ca`, `ssh-sign`, `creds`, `session`, `leases`, `kms`, `snapshot`). Drives
  both the SAN→role match and per-role least-privilege authorization. **Required in production**
  — unset/empty means every verified cert is trusted-but-unauthorised (`403`). Sample:
  `docs/dev/roles.example.json`.
- **KMS-cap auth (Option J, optional)** — `VESTA_KMS_JWT_ISSUER` enables an identity-minted
  ES256 bearer JWT as the per-call proof of the `kms` cap, **on top of** mTLS (the JWT carries
  the cap; the channel still authenticates). Verifies the issuer's JWKS (OIDC-discovered, or
  `VESTA_KMS_JWT_JWKS_URI`), `aud` (`VESTA_KMS_JWT_AUDIENCE`, default `vesta`), `exp`,
  `scope ⊇ kms`, `residency_group ==` this instance's group, and `tenant_id ==` the request
  path tenant. **Unset ⇒ kms ops stay cap-based** (cert-SAN `kms` capability — the aether
  fleet-backup path; unchanged).
- **Arm (a) identity-sealed master key (optional, see Broker unseal above)** —
  `VESTA_IDENTITY_KMS_URL` (identity's WG-only native-mTLS KMS listener, e.g.
  `https://10.200.0.100:8202`) enables boot-time unseal via identity; auth reuses the broker's
  `VESTA_TLS_*` client cert (must be the dot-form clientAuth cert). `VESTA_SEALED_MASTER_FILE`
  (default: next to the store) holds the inert `{kek_id, wrapped}` blob. `VESTA_KMS_SEAL_INIT=1`
  is the one-time bootstrap that seals the current passphrase. Unset ⇒ manual passphrase only.
- `VESTA_AUDIT_PATH` — durable local B3 audit store (source of truth): a **tamper-evident
  hash-chained** append-only JSONL (each record SHA-256-chained to the previous; edits,
  reorders, and deletions are detectable).
- `VESTA_AUDIT_OS_URL` / `VESTA_AUDIT_OS_USER` / `VESTA_AUDIT_OS_PASSWORD` — optional
  best-effort shipping of B3 events to group-local OpenSearch (`audit-events-{group}-YYYY.MM`,
  bulk-indexed by a background task; a ship failure never blocks issuance). Set
  `VESTA_AUDIT_OS_URL` to enable. `VESTA_AUDIT_OS_CA` = PEM CA-file to verify the OS node cert
  (e.g. the fleet Root CA; the rustls client does NOT use the FreeBSD system trust). `VESTA_AUDIT_OS_INSECURE_TLS=1`
  for dev/self-signed only — prefer `VESTA_AUDIT_OS_CA`.
- `VESTA_OS_URL` / `VESTA_OS_ADMIN_USER` / `VESTA_OS_ADMIN_PASSWORD` — OpenSearch
  dynamic-cred engine: the cluster + the admin credential the broker uses to mint/delete
  ephemeral users. Set `VESTA_OS_URL` to enable the engine. `VESTA_OS_ROLE` (default
  `audit-writer`), `VESTA_OS_MAX_TTL_SECS` (default 28800), `VESTA_OS_CA` (PEM CA-file to verify
  the OS node cert — the rustls client ignores the system trust), `VESTA_OS_INSECURE_TLS=1`
  (dev/self-signed only; refused outside `VESTA_ALLOW_INSECURE_DEV` — use `VESTA_OS_CA` in prod).
  See `docs/dev/opensearch-it.md`.
- `VESTA_ALLOW_INSECURE_DEV=1` — **local dev only**: plain HTTP, `X-Client-Cert-SAN`
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

## KMS root-of-trust go-live (arm a + b)

Both arms ship **gated off**; turning them on in eu is an operator + cross-service step.
Vesta needs **no code change** — the broker already reads `VESTA_TLS_*` for both its server cert
and the KMS client. Order:

1. **Adopt the dot-form cert (operator, on the broker host).** Infra issued
   `vault.eu.proximi.internal.{pem,key}` (RSA4096, **serverAuth + clientAuth**, SAN +IP, fleet-CA
   signed; staged `~/kms-eu/`). Place it in the vault-eu jail (`vesta:vesta`, key `0600`) and point
   `VESTA_TLS_CERT`/`VESTA_TLS_KEY` at it — this becomes BOTH the broker server cert (retiring the
   dash-form `vault-eu.proximi.internal`) and the arm (a) KMS client cert. `VESTA_TLS_CLIENT_CA`
   stays the fleet Root CA. Demon broker-clients already pin the dot form, so no peer break.
2. **Arm (b) — kms-cred verify (independent of the mTLS listener).** Identity flips
   `kms.mint_enabled` in eu + provisions the Vulture KMS workload client, then sends a sample
   `kms`-scoped token + the JWKS `kid` set. Set `VESTA_KMS_JWT_ISSUER=https://identity.eu.proximi.fi/`
   and run the sample token through the verifier (round-trip). Until then leave it unset (kms stays
   cap-based).
3. **Arm (a) — master-key seal/unseal.** Infra provisions identity's per-group root key
   (`kek_id=eu-2026a`) + identity enables the `:8202` native-mTLS listener (`kms.enabled`). Then on
   the broker: set `VESTA_IDENTITY_KMS_URL=https://10.200.0.100:8202`, run **once** with
   `VESTA_KMS_SEAL_INIT=1` to seal the current passphrase → writes `sealed-master.json`; unset the
   flag. Subsequent boots unseal via identity (manual passphrase stays break-glass). Do a
   seal→unseal round-trip in eu with infra/identity before relying on it.
4. **Rotation (later, joint).** `kms.master_resealed` + the boot/timer re-seal ship in the broker;
   identity's previous-root overlap window + the signal consumer are its fast-follow — land them
   together before the first root rotation.
