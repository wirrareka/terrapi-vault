# worklog — KMS root-of-trust chain, vault side (2026-06-02)

Vault's side of the identity ↔ vault KMS root-of-trust chain (locked with identity per
`coordination/conventions/secrets-broker.md §KMS root-of-trust`). Three pieces, shipped +
tested, all **gated off** until identity/infra enable their side. Broker API `1.0.0 → 1.1.0`.
Does NOT block v0.5.0; Vulture sec-1.9 (SQLCipher per-tenant DBs) is the downstream consumer.

Commits: `6cd068e` (Option J + rewrap), `908f104` (arm (a) client), `419492c` (arm (a) → native mTLS).

## 1. Option J — kms-cap JWT verify (`jwt.rs`, new)

The `kms` capability is now provable **per call** by a short-TTL identity-minted **ES256**
JWT, layered on top of the mTLS-over-WG channel (the JWT carries the cap; mTLS still
authenticates the transport). `JwtVerifier`:
- header `alg` MUST be `ES256` (+ `kid`); reject `none`/alg-confusion;
- signature vs identity's JWKS — OIDC-discovered (`{iss}/.well-known/openid-configuration`
  → `jwks_uri`) or `VAULT_KMS_JWT_JWKS_URI`; cached, refetched on a `kid` miss (key rotation);
- `iss` (pinned, exact) + `aud="vault"` + `exp` (jsonwebtoken); then `scope ⊇ "kms"` +
  `residency_group ==` this instance's group;
- the handler enforces the token `tenant_id ==` the request-path tenant.

Wired in `http::kms_authorize`: when `VAULT_KMS_JWT_ISSUER` is set, kms ops require a valid
bearer; **unset ⇒ kms stays cap-based** (cert-SAN `kms` capability — aether's fleet-backup
path, unchanged). New dep: `jsonwebtoken = "9"`.

## 2. `kms.rewrap` (`kms.rs` + `POST …/kms/{key_id}/rewrap`)

Server-side re-wrap: unwrap under the blob's embedded KEK version, re-wrap under the current
version — the plaintext DEK never leaves the broker. Drives the ack-gated rotation flow (a
consumer streams its ~150 blobs through `rewrap` after a `rotate`, then emits
`kms.rewrap_complete` so identity retires the old root). Audit action `kms.rewrap`.

## 3. Arm (a) — identity-sealed master key (`identity_kms.rs`, new)

At boot the broker exchanges a stored inert `{kek_id, wrapped}` blob for its plaintext unseal
master key via identity's WG-only KMS listener, so a stolen at-rest store is useless without a
live in-group call to identity. `IdentityKmsClient.{seal,unseal}` against
`POST /kms/v1/{seal,unseal}`; `SealedMaster` blob persisted `0600`; `main::obtain_unseal_passphrase`
uses it when configured, else the manual passphrase (**break-glass**). One-time bootstrap
`VAULT_KMS_SEAL_INIT=1` seals the current passphrase.

**Auth — native mTLS (revised mid-effort).** The first cut used identity's proposed WG
terminator + `X-Kms-Auth` boundary secret; infra then chose §2→(A) a native mTLS listener on
identity `:8202` (identity v0.1.13). Reworked (`419492c`): the client now builds its reqwest
client from the broker's own `VAULT_TLS_*` — cert+key as the client identity, the fleet Root
CA as the **sole** trust root (`tls_built_in_root_certs(false)` + `from_pem_bundle`). No
app-layer secret. `IdentityKmsConfig` carries no secret.

## Config (env), all opt-in — see `deploy/vault-broker.env.sample` + `docs/broker-bootstrap.md`

- `VAULT_KMS_JWT_ISSUER` / `_AUDIENCE` / `_JWKS_URI` — Option J kms-cap verify.
- `VAULT_IDENTITY_KMS_URL` — arm (a) unseal (mTLS via `VAULT_TLS_*`); `VAULT_SEALED_MASTER_FILE`;
  `VAULT_KMS_SEAL_INIT=1` (one-time).

## Spec / docs

`spec/broker-openapi.yaml` → `1.1.0`: `kmsBearer` security scheme + per-op security on the kms
ops, `kmsRewrap` path + `KmsRewrapRequest`. `CHANGELOG.md`, `broker-bootstrap.md`,
`planning/01-vault-as-service.md` updated.

## Tests

Broker **51** (7 jwt: `check_claims` matrix + header/kid rejects without network; 2 kms-rewrap;
4 identity_kms: http-mock seal→unseal round-trip via `from_parts`, cert-load failure, blob
round-trip, absent file), sync 23, transport 21, lib 38+5+2. `clippy --all-targets` + `fmt`
clean. The real mTLS handshake + the live JWT round-trip are integration steps (eu), gated on
identity/infra enablement — see the contract.

## Pending (not vault code)

Adopt the infra-issued dot-form cert `vault.eu.proximi.internal` (clientAuth) as `VAULT_TLS_*`
+ eu seal→unseal round-trip; identity enables arm (b) mint (`/kms/v1/workload-cred`, principal-
gated) for the live kms-cred verify; `kms.rewrap_complete` emit lands with KEK rotation.
