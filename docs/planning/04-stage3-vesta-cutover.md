# 04 — Stage 3: cut the live `vault` wire/data contracts over to `vesta`

**Status:** IN PROGRESS. Vault-side back-compat prep landed; the rest is sequenced with infra +
identity + memento/probe. Builds on `03-rename-to-vesta.md` (Stages 1/1b done: crates, env shim,
type `Vault`→`Vesta`, `vesta_schema` migration, docs).

**Golden rule:** for every contract, the **consumer dual-accepts FIRST, then vault flips the
emit/value** — never flip vault's output before consumers accept the new value, or live eu breaks.

## Done now (vault-side, non-breaking, on `main`)

- **KMS JWT `aud`:** verifier now accepts a SET — primary `"vesta"` (config default flipped) **plus**
  legacy `"vault"` (`jwt.rs` `JwtVerifier.audiences`). Identity can flip minting `vault`→`vesta`
  anytime; old tokens keep verifying. (Drop `"vault"` in Stage 4.)
- **Cert SAN dual-map:** `deploy/roles.json.sample` maps BOTH `vault-console.<g>` and
  `vesta-console.<g>` → `observe`, so the console works before AND after infra re-mints its cert.

## Per-contract cutover sequence

| Contract | Owner of the flip | Sequence |
|---|---|---|
| **KMS JWT `aud`** | identity mints; vault verifies | vault dual-accepts ✅ → identity flips mint `vault`→`vesta` → Stage 4 vault drops `vault` accept |
| **Cert SANs** `vault.<g>` / `vault-console.<g>` | infra (CA) | roles dual-map ✅ → infra re-mints `vesta.<g>` + `vesta-console.<g>` (single-SAN) → redeploy broker/console with new certs → Stage 4 drop the `vault.*` SAN entries |
| **Audit `source`** `"vault"` | vault emits; identity/aether consume | identity+aether **dual-accept `source ∈ {vault,vesta}`** FIRST → then vault flips emit `"vault"`→`"vesta"` (`audit.rs:87`) → Stage 4 consumers drop `vault` |
| **Prometheus metrics** `vault_*` / `vault_sync_*` / `job` | vault emits; infra scrapes | option A (gap-free): vault **dual-emits** `vault_*`+`vesta_*` → infra migrates dashboards/alerts → vault drops `vault_*`. option B: coordinated window flip. (`state.rs` render + `vesta-sync` metrics) |
| **`vault_id`** (sync URL path `/v1/sync/{vault_id}/`, DB column, DTO) | vault-sync API + memento/probe | **RECOMMEND KEEP** — it's the domain noun "a vault's id", not the product brand; flipping = sync API v2 + a DB column migration + memento/probe client change for ~zero benefit. If renamed: add `{vesta_id}` route alias, `ALTER TABLE ... RENAME COLUMN vault_id TO vesta_id` migration, dual-read, ship clients, then drop. Decide before doing. |
| **`bad_vault_id`** error code | vault-sync emits; clients switch on it | bundle with the `vault_id` decision (same surface) |

## Coordination dropped (this turn)

- `inbox/infra/…` — re-mint `vesta.<g>` + `vesta-console.<g>` certs (single-SAN); add the dual-SAN
  roles entries; plan the metrics-dashboard migration.
- `inbox/identity/…` — flip KMS-cred minting `aud`→`vesta` (vault already dual-accepts); dual-accept
  audit `source ∈ {vault,vesta}` before vault flips its emit.
- `inbox/aether/…` — dual-accept audit `source ∈ {vault,vesta}` (backup/audit consumer).
- `inbox/sync/…` — memento/probe: the `Vault`→`Vesta` API + the `vault_id` keep/rename decision.

## Stage 4 (after all consumers confirm)

Drop the `vault` back-compats: the env `VAULT_*` shim, the KMS `vault` aud accept, the audit-source
`vault` accept (consumers), the `vault.*` SAN/role entries, the metric `vault_*` series; rename
`coordination/inbox/vault`→`inbox/vesta` + CONTRACTS; rename the GitHub repo + on-disk dir
`terrapi-vault`→`terrapi-vesta` (memento/probe repoint the `../` path) — that retires the last
`../terrapi-vault` reference and the `vesta_schema` migration's legacy-name lookup can stay (cheap,
harmless) or be dropped once no pre-rename vault can exist.
