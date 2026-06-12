# 03 — Rename `vault` → `Vesta`

**Status:** PLANNED (decision locked 2026-06-12). Not yet executed.
**Why:** `vault` collides with HashiCorp Vault. Product split is **identity = trust layer**
(authN, who-you-are, mints trust/JWT) and **vault = the trezor** (custody of secrets, sealed
sanctum, dispenses short-TTL access). **Vesta** keeps the trezor meaning (the Vestals guarded the
sacred *depositum* — closing wills/treaties in the Temple of Vesta = the original trezor; the
eternal flame = always-on keeper) while dropping the brand collision. Namespace is clean:
`vesta-broker` / `vesta-console` / `vesta-sync` / `terrapi-vesta` are free on crates.io + npm
(bare `vesta` is only trivial unrelated packages; no secrets/PKI product uses it).

## Guiding principle: INTERNAL vs OUTWARD-FACING

The rename splits cleanly into two risk classes. Do all INTERNAL work first (safe, no other team,
no live impact); gate the OUTWARD-FACING items behind coordination + backward-compat shims so the
**live eu broker+console (v0.1.12) never breaks mid-migration**.

| Class | Items | Who | Breaking? |
|---|---|---|---|
| **Internal** | repo dir, crate names, binary names, code identifiers, `VAULT_*`→`VESTA_*` env, metric *names*, docs, CI | vault only | no (with env shim) |
| **Outward-facing** | cert SANs / FQDN, audit `source:"vault"`, KMS JWT `aud`, Prometheus `job` label, coordination repo, sibling SAN→role maps | infra + identity + demon/aether/outer-map/belt | yes — needs window |

## Blast radius (enumerated)

1. **Crates (5):** `terrapi-vault`→`terrapi-vesta` (root lib), `vault-{broker,console,sync,transport}`
   →`vesta-*`. Dirs `services/vault-*` → `services/vesta-*`. **External path-dep:** memento/probe pin
   `../terrapi-vault` — they must repoint (coordinate, or keep a thin `terrapi-vault` re-export
   shim crate for one release).
2. **Env prefix `VAULT_*` → `VESTA_*`** (~60 vars): broker (`VAULT_BROKER_BIND`, `VAULT_TLS_*`,
   `VAULT_ROLES_CONFIG`, `VAULT_STORE_PATH`, `VAULT_AUDIT_PATH`, `VAULT_UNSEAL_*`, hardening, metrics),
   `VAULT_OS_*` + `VAULT_AUDIT_OS_*` (OpenSearch), `VAULT_OBJECT_STORE_*`, `VAULT_KMS_*` +
   `VAULT_IDENTITY_KMS_URL`, console `VAULT_CONSOLE_*` (+ OIDC), sync `VAULT_SYNC_*`. **Shim:** read
   `VESTA_*` then fall back to `VAULT_*` so a unit can flip without a flag day.
3. **Binaries / deploy:** `vault-broker`→`vesta-broker` etc. — `deploy/` rc.d, `install.sh`,
   `deploy/console`, env `.sample`s, `release.yml` artifact names (`vault-broker-<v>-<target>.tar.gz`
   → `vesta-broker-…`), `freebsd-build.yml`.
4. **Cert SANs / FQDN (infra):** `vault.<group>.proximi.internal`,
   `vault-console.<group>.proximi.internal` → `vesta.*`, `vesta-console.*`. Single-dNSName issuance
   (per the single-SAN-strict verifier). Re-mint + update `VAULT_ROLES_CONFIG` SAN→role maps. The
   console→broker mTLS hop + every consumer SAN (demon-*, aether-*, outer-map, belt, kms workload)
   is unaffected (their SANs don't change) **except** the broker/console's own certs.
5. **Audit `source:"vault"` → `"vesta"`** (`AuditEvent::vault()` sets a fixed `source`): this is the
   **dedup key** consumers use to avoid double-recording (identity/aether). Cut over with a window:
   emitter flips last; consumers accept `source ∈ {vault, vesta}` during the window.
6. **KMS JWT `aud` `"vault"` → `"vesta"`:** identity mints the kms-cap bearer with `aud="vault"`;
   vault's verifier expects it (`VAULT_KMS_JWT_AUDIENCE`, default `"vault"`). Coordinate with
   identity; verifier accepts both audiences during cutover, then identity flips, then drop `vault`.
7. **Metrics:** `vault_*` metric names (`vault_sealed`, `vault_audit_events_total`, `vault_http_*`)
   + Prometheus `job=vault` → `vesta_*` / `job=vesta`. Update `deploy/alerts/vault-broker-alerts.yml`
   + group dashboards. (Cosmetic but visible; can lag.)
8. **Ports unchanged:** 8200/8201 (broker+metrics), 8203 (console), 8300/8301 (sync).
9. **Coordination repo** (`proximiio-infra/coordination`, owned by another agent — content only):
   `CONTRACTS.md` "Secrets broker" owner `vault`→`vesta`; `conventions/secrets-broker.md` +
   `ports-env.md`; `inbox/vault/` → `inbox/vesta/`; sibling references in demon/identity/aether/
   outer-map/belt notes.
10. **Repo meta:** README, CHANGELOG header, `CLAUDE.md`, `docs/`, memory files.

## Staged plan

- **Stage 0 — comms (now):** heads-up notes to identity (aud), infra (certs/FQDN/Prometheus/units),
  and audit consumers (aether/identity: `source` dual-accept). State the shim strategy so nobody
  schedules a flag day.
- **Stage 1 — internal rename (one branch, NO deploy):** rename crate dirs + `name=`, binaries,
  `VAULT_*`→`VESTA_*` **with the env-fallback shim**, metric names, code identifiers, docs, CI,
  deploy templates. `cargo fmt --check && cargo clippy --all-targets -D warnings` (root **and**
  services) + full tests green; web build. Keep audit `source`, JWT `aud`, cert SANs on `vault` for
  now. Land on `main`; the next release ships dual-env-compatible binaries.
- **Stage 2 — dual-accept the protocol seams:** verifier accepts `aud ∈ {vault,vesta}`; audit
  consumers accept `source ∈ {vault,vesta}`. Deploy. (No visible change yet; just widened
  acceptance.)
- **Stage 3 — outward cutover (with infra+identity, maintenance window per group):** mint `vesta.*`
  certs (single-SAN); roles config maps old+new SANs; redeploy broker+console units with `VESTA_*`
  env + new certs; identity flips `aud`→`vesta`; emitter flips `source`→`vesta`; flip Prometheus
  `job`/metrics + alerts. Verify observe hop + an issuance round-trip. Retire `vault.*` certs.
- **Stage 4 — cleanup:** drop env-fallback shims, drop `aud`/`source` dual-accepts; rename
  `inbox/vault`→`inbox/vesta` + update CONTRACTS/conventions; update memory + this repo's name.

## Backward-compat helpers (make it non-breaking)

- **env:** one helper `env_any(&["VESTA_FOO","VAULT_FOO"])` (prefer new, fall back to old).
- **JWT aud:** verifier takes a *set* of accepted audiences.
- **roles config:** load + union old and new SAN keys during the window.
- **audit:** consumers match `source` against a set; vault emitter flips last.
- **path-dep:** optional `terrapi-vault` re-export crate (`pub use terrapi_vesta::*;`) for one
  memento/probe release.

## Risks / notes

- The live eu broker+console (v0.1.12) must not break — that's exactly what the shims + dual-accept
  + dual-SAN window buy us. **Do NOT** do a piecemeal rename on the live system without them.
- memento/probe are in separate repos; their `../terrapi-vault` path-dep is the one external code
  edit — coordinate or use the re-export shim.
- This is a wide-but-mechanical change. **Effort:** Stage 1 ≈ one focused session (rename + green
  gates); Stages 2–3 are coordinated with identity + infra over a few days (cert mint + consumer
  cutover); Stage 4 is cleanup.

## Decision log

- 2026-06-12: name = **Vesta** (over Tessera — rejected for the Quorum-Tessera same-space
  collision). Rationale: vault is positioned as the *trezor*; identity owns *trust*; Vesta names
  the keeper-of-the-deposit and keeps the meaning while escaping the HashiCorp brand.
