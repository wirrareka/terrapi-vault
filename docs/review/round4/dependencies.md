# terrapi-vault — Dependency / supply-chain audit (2026-05-31)

A different lens from rounds 1–3 (static code review): this is a **runnable** supply-chain audit
— RUSTSEC advisories, the dependency firewall, and duplicate versions — across both workspaces
(the root lib + the `services/` workspace), using `cargo-audit` (lockfile scan) **and**
`cargo-deny` (build-graph scan).

## Outcome: clean, with one real fix + two documented, justified ignores

| Advisory | Crate | Where | Disposition |
|---|---|---|---|
| RUSTSEC-2026-0097 (unsound) | `rand 0.8.5` | root lib | **FIXED** — bumped to `0.8.6` (patch; the advisory is fixed there). |
| RUSTSEC-2023-0071 (MEDIUM) | `rsa 0.9.10` | services (via `ssh-key`) | **Ignored — not reachable.** `rsa` is an *optional* `ssh-key` dep this workspace never enables (SSH-CA is ed25519-only). `cargo tree -i rsa` is empty and `cargo deny` (build-graph) never sees it — it's a Cargo.lock artifact, **never compiled**, so the RSA-timing side-channel can't run. |
| RUSTSEC-2025-0134 (unmaintained) | `rustls-pemfile 2.2.0` | services (broker `tls.rs`) | **Ignored — accepted.** A maintenance warning, not a vulnerability; used only to parse the broker cert/key PEM at boot. Migration to `rustls-pki-types`' PEM API is tracked. |

The one genuine security advisory in the actually-compiled graph was `rand` (lib) — and it was
**fixed**, not muted. `rsa` is a lockfile false positive (confirmed unreachable two ways). The
remaining item is a soft unmaintained warning.

## Dependency firewall — verified INTACT
- **Root lib** pulls only `argon2`, `rand`, `rusqlite` (SQLCipher), `secrecy`, `serde`,
  `serde_json`, `thiserror`, `zeroize` — **no** axum/tokio/hyper/rustls/reqwest/platform crates.
  Confirmed: `cargo tree | grep -iE 'axum|tokio|hyper|rustls|reqwest|opensearch'` → empty.
- **vault-sync** carries **no** platform deps (`cargo tree -p vault-sync | grep -iE
  'opensearch|reqwest|rustls|aes-gcm|ssh-key'` → empty). The R1/R2/R3 firewall holds at the
  dependency level too.

## Duplicate versions (non-security, noted)
Normal transitive duplication from different majors pinned by different deps — **not** a
vulnerability, only a small binary-size cost: `rand 0.8/0.9`, `rand_core 0.6/0.9`,
`rand_chacha 0.3/0.9`, `getrandom 0.2/0.3`, `hashbrown 0.14/0.17`, `thiserror 1.0/2.0`. The vesta
crates pin the 0.8/1.0 lines; the newer copies come from transitive deps (reqwest/aws-lc-rs
stacks). Not worth forcing unification (would constrain transitive deps for no security gain).

## What was added (so the gates stay green)
- **`services/deny.toml`** — `cargo deny check advisories` config; ignores only the genuinely-
  compiled `rustls-pemfile` warning (rsa isn't in cargo-deny's build graph at all), each with a
  rationale comment.
- **`services/.cargo/audit.toml`** — `cargo audit` config; ignores the lockfile-only `rsa` false
  positive **and** `rustls-pemfile`, with rationale. (cargo-audit auto-reads `.cargo/audit.toml`.)
- **root lib** needs no ignore — it is clean after the `rand` bump.

## Verification
- `cargo audit` (lib): clean. `cargo audit` (services): clean (exit 0). `cargo deny check
  advisories` (services): `advisories ok`.
- Lib builds + 38 tests pass on `rand 0.8.6`; services unaffected (they already resolved `rand
  0.8.6`).

## Recommendations
- Wire `cargo audit` + `cargo deny check` into CI so a new advisory fails the build (the ignores
  are documented and will surface a *new* issue rather than hide it — note cargo-deny even warns
  when an ignore is stale).
- When convenient, migrate `tls.rs` off `rustls-pemfile` to `rustls-pki-types`' PEM API and drop
  the `RUSTSEC-2025-0134` ignore.
- Re-check the `rsa` ignore if the SSH-CA ever gains an RSA algorithm (it would then enter the
  build graph and `cargo deny` would flag it).

## Status update (2026-07-10)
Both recommendations above landed: `cargo deny check` now runs in CI for both workspaces
(`.github/workflows/ci.yml` `cargo-deny` job; the root lib gained its own `deny.toml`), and
`tls.rs` was migrated off `rustls-pemfile` to `rustls-pki-types`' PEM API — the dependency and
the `RUSTSEC-2025-0134` ignore (deny.toml + audit.toml) are gone. Note `rsa` has since entered
the build graph as a *dev*-dependency of vesta-console (OIDC test keypairs), so `cargo deny`
now sees it; the RUSTSEC-2023-0071 ignore rationale is updated in `services/deny.toml`.
