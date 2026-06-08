# 02 — vault-console (operator web view) — planning

Status: **BUILT — eu enablement pending** (2026-06-08). P1a (broker `observe` API/cap) +
the `vault-console` crate (SPA + backend fan-out + embed + deploy module) **and P1b (OIDC RP:
authorization_code+PKCE, `private_key_jwt` RS256 with the cert key + bound kid, `acr=mfa`
enforced)** are all shipped in **v0.1.8**. Remaining = the eu host window (infra: jail/WG `.110`/
cert/edge + broker `roles.json` `observe` entry; operator: Route53 + create the staged identity
client + bind JWK) and the closing **live `acr=mfa` round-trip**. Originally APPROVED 2026-06-06.

## Purpose

Today vault has **no human view** — only the mTLS broker API (`:8200`) and Prometheus
metrics (`:8201`). With brokers deployed across many servers we need an operator
**read-mostly observability console** (web + API; native probe/memento later via the same
API). Modelled on the **Kalista web/API standard**.

### Non-goals (hard)
- **Not a secret editor / KV UI.** The console never displays or accepts a *secret value*
  (SSH CA key, KMS master/KEKs, DO Spaces keys, leased passwords). Secret ingest stays
  **CLI / one-time env import** (e.g. `VAULT_KMS_SEAL_INIT`). The console adds **zero**
  "show me the secret" surface — that is the security point of a secrets boundary.
- Not tenant-facing. **Operator-only**, single trust tier. No customer/tenant views.
- Not multi-region aggregating: the eu/uae **residency air-gap is hard** — one console per group.

## Decisions (from the Q&A)

| # | Decision |
|---|---|
| 1 | Brokers run **HA / multiple instances per group**. |
| 2 | **One console per residency group**, aggregating that group's brokers (never cross-group). |
| 3 | **Separate binary** `vault-console` (NOT a listener inside vault-broker). |
| 4 | Reachable **both** WG-only (direct/jump box) **and** behind Kalista edge (OIDC). |
| 5 | Console port: **TBD — coordinate with infra** (`conventions/ports-env.md`). |
| 6 | Auth: **OIDC RP via identity** (PKCE+nonce, issuer allow-list) **+ local break-glass admin**. |
| 7 | **MFA required** (`acr=mfa`) — it is a view into the vault. |
| 8 | **Single `operator` role** (P1). Viewer/operator split deferred to P2 (when mutations land). |
| 9 | **Operator-only**; no tenant-scoped surface. |
| 10 | Read surface as listed below — accepted. |
| 11 | Audit source = **per-broker local hash-chained store** (via the observe API), merged in the console. OpenSearch rich-search later. |
| 12 | **P1 strictly read-only.** Mutations (revoke/rotate/reload) → P2. |
| 13 | **Mirror Kalista stack**; on the Rust side use **rusqlite** (not sqlx) if a DB is needed — consistent with the lib. |
| 14 | `web/` at repo root; the console binary lives in `services/vault-console/`. |
| 15 | **EN-only** (i18n skeleton kept, no translated content). |
| 16 | Shipped in the **same release** as the broker (same tag); separate `vault-console` binary in the artifact. |

## Architecture — the spine

Because the console is **separate (3) + per-group (2) + brokers are HA (1)**, it does **not**
share the broker's in-memory state (leases/sessions live in `LeaseEngine`, not the at-rest
store). So:

```
        operator browser ──OIDC(MFA) / session cookie──▶  vault-console (one per group)
                                                              │  (aggregates the group's brokers)
                                ┌─────────────────────────────┼─────────────────────────────┐
                          mTLS-over-WG (client cert)     mTLS-over-WG                    mTLS-over-WG
              vault-console.<group>.proximi.internal → `observe` cap on each broker
                                │                             │                             │
                          vault-broker #1               vault-broker #2               vault-broker #N
                          (read-only observe API)       (…)                           (…)
```

Two auth planes:
- **Human → console:** OIDC RP via identity (MFA) + local break-glass; session cookie; CSRF;
  rate-limit. (Kalista `kalista-control-plane/src/auth/*` + `middleware/*` pattern.)
- **Console → broker:** the console is just **another broker mTLS client**. It presents a
  fleet-CA client cert SAN `vault-console.<group>.proximi.internal` → a **new read-only
  `observe` capability**. Reuses the existing broker mTLS + `VAULT_ROLES_CONFIG` machinery —
  no new transport security.

### Consequence: the broker gains a read-only `observe` API + cap **(confirm)**
This is the **main new work on the broker side**, and it's required by the per-group/HA shape.
New `observe` capability (cert-SAN→role), gating read-only endpoints that expose what's
currently only in-process:
- `GET /v1/sys/observe/leases` — active leases (id, role, tenant, parent/session, ttl, expiry). No secret values.
- `GET /v1/sys/observe/sessions` — active operator sessions (principal SAN, opened, idle/ttl).
- `GET /v1/{group}/observe/ssh` — issued SSH cert serials + the revocation list.
- `GET /v1/sys/observe/roles` — registered SAN→{role,caps} (the loaded `VAULT_ROLES_CONFIG`).
- `GET /v1/{group}/observe/kms` — KMS key inventory (key_id + current version per target; **never** KEK/DEK bytes).
- `GET /v1/{group}/observe/object-store` — presign activity counters (issued/expired; from metrics/audit).
- `GET /v1/sys/observe/audit?since=<seq>` — tail of the local hash-chained B3 audit (already redacted at emitter).
- (`GET /v1/sys/seal-status` already exists.)
All read-only, `observe`-capped, residency-checked, rate-limited. The broker's audit emitter
**already redacts** secret material, so the audit tail is safe to surface verbatim.

> Open: some of these (`leases`, `sessions`, `roles`, `audit`) are `sys`-scoped (cross-group
> n/a) and some are `{group}`-scoped. Settle the exact route shapes when we write the broker
> `observe` slice. **(confirm on review)**

## Console internals

- **Crate:** `services/vault-console` (workspace member, like vault-broker/sync/transport),
  binary `vault-console`. Its own `[package.version]` tracks the services workspace.
- **Stack (Kalista mirror):** axum + `openidconnect` (RP) + `rust-embed` (embeds `web/dist`)
  + `utoipa` (OpenAPI gen, `print-openapi`). SPA: React + TS + Vite + Tailwind + shadcn/ui
  (Radix) + TanStack Query/Table + react-router + react-hook-form + zod + zustand + recharts
  + lucide; `openapi-typescript` for the typed client. EN-only.
- **State:** P1 is essentially **stateless** — pending-OIDC and sessions in memory (re-login on
  restart is acceptable for an ops console); local break-glass admin from env (hashed). A
  **rusqlite** DB is added only if we want persistent sessions or a console-login audit —
  **(confirm: P1 stateless, no DB)**.
- **Single binary**, SPA embedded → one artifact, matches vault's FreeBSD single-binary deploy.

## Read surface (P1)

seal-status / health · active leases · active sessions · SSH cert serials + revocation list ·
roles→caps · KMS key inventory (ids/versions) · object-store presign activity · B3 audit tail ·
non-secret config (residency group, bind addrs, which engines/features are enabled) · per-broker
up/seal state across the group. **No secret values, ever.**

## P2 (gated mutations — deferred)
Viewer/operator RBAC split; CSRF-guarded actions proxied to the broker (which already audits):
revoke lease/session, rotate a KMS key, reload `VAULT_ROLES_CONFIG` / license trust bundle,
trigger a store snapshot, revoke an SSH serial. Each is an authenticated broker call under a
**write** cap distinct from `observe`.

## P3 — native (probe / memento)
Same OpenAPI; a native client consumes it. No console change needed beyond stable API + CORS/
auth story for a native flow (likely device-token, not browser OIDC) — design later.

## Topology & deploy

- **One `vault-console` per group**, its own bastille jail (or co-located with a broker), WG
  IP allocated by infra. Binds the human listener on the **(infra-assigned) port**, WG-only by
  default; optionally fronted by **Kalista edge** (OIDC) for off-WG operator access (#4).
- Console → brokers: WG mTLS using a fleet-CA client cert `vault-console.<group>.proximi.internal`.
- Discovers its group's brokers via config (list of broker WG addrs) — **(confirm:** static
  config list vs a small registry**)**.
- Release: same tag as the broker; the release tarball ships **both** `vault-broker` and
  `vault-console` (or a sibling `vault-console-*.tar.gz`). `deploy/` gains the console jail +
  env (OIDC client id/secret, issuer, broker list, listener bind). **(confirm packaging)**

## Coordination dependencies (send once this plan is approved)
- **infra:** (a) console **port** allocation in `ports-env.md`; (b) a `vault-console` jail per
  group + WG IP; (c) the console's **server cert** (if edge-exposed) + **client cert**
  `vault-console.<group>.proximi.internal` (fleet-CA, EKU clientAuth) to reach brokers;
  (d) optional **Kalista edge route** to the console (OIDC). 
- **identity:** register **vault-console as an OIDC client** (redirect URI `…/api/v1/auth/callback`,
  PKCE, require `acr=mfa`), issuer `https://identity.<group>.proximi.fi/`.

## Phasing
- **P0 (this doc):** plan + coordination.
- **P1:** broker `observe` API + `observe` cap (broker side) → `vault-console` crate: OIDC+local
  auth, MFA, session, embed, read-only views + aggregation. Single operator role. EN-only.
- **P2:** viewer/operator RBAC split + gated mutations (proxied, audited).
- **P3:** native client (probe/memento) over the same API.

## Resolved (2026-06-06)
1. **`observe` route scoping:** `sys`-scoped (cross-group): `leases`, `sessions`, `roles`,
   `audit`. `{group}`-scoped: `ssh`, `kms`, `object-store`.
2. **P1 is stateless — no DB.** In-memory pending-OIDC + sessions; local break-glass admin from
   env (hashed). rusqlite only if a later phase needs persistent sessions / console-login audit.
3. **Broker discovery = static config list** of the group's broker WG addrs (no registry).
4. **Release packaging = same release tag, separate `vault-console-<ver>-<target>.tar.gz`**
   artifact (its own deploy unit / per-group jail), alongside the `vault-broker` artifact.
5. **Audit = per-broker local hash-chained store, merged in the console. OpenSearch is NOT
   involved** (keep it simple; no OS dependency in the console path).
