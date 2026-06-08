# vault-console — deploy

Operator web/API console, **one per residency group**, in its own bastille vnet jail on the
group's WireGuard mesh. Read-only observability (aggregates the group's brokers' `observe` API
over mTLS); **never surfaces a secret value**. Plan: `../../docs/planning/02-vault-console.md`.

## Layout
- `rc.d/vault-console` → `/usr/local/etc/rc.d/vault-console` (unprivileged `vault-console` user).
- `libexec/vault-console-run` → `/usr/local/libexec/vault-console-run` (sources env, execs the binary).
- `vault-console.env.sample` → `/usr/local/etc/vault-console/vault-console.env` (mode 0600).
- Binary → `/usr/local/sbin/vault-console`.

## Build (single binary with the SPA embedded)
```sh
pnpm --dir web install && pnpm --dir web build      # produces web/dist (Node 24)
cargo build --release -p vault-console --features embed-ui   # embeds web/dist via rust-embed
```
Without `--features embed-ui` the binary still runs the API but serves a "UI not embedded" stub
(that's the default CI build, which needs no built `web/dist`). The release artifact
(`vault-console-<ver>-<target>.tar.gz`) is built with the feature; the FreeBSD (medina) build
needs `web/dist` present on the build step — see the infra coordination note (runner node/pnpm).

## Listener & access
- Binds **`10.200.0.110:8203`** (eu, WG /32) — never `0.0.0.0`. Plain HTTP on the WG hop.
- Browser access: WG-direct, or (recommended) behind the **Kalista edge**
  `vault-console.<region>.proximi.fi` → `:8203` (Kalista TLS + OIDC + downstream-mTLS + IP ACL).
- TLS to the brokers: the console's fleet-CA client cert `vault-console.<group>.proximi.internal`
  (dual-EKU), placed mode-0600 by infra at deploy. No server TLS on the console itself (edge terminates).

## Auth
OIDC RP via identity (`acr=mfa` enforced) — **P1b**, wired once identity mints the client for the
final redirect URI. Until then, only `VAULT_CONSOLE_ALLOW_INSECURE_DEV=1` grants a (dev) session.
No encrypted dataset / unseal needed — the console is stateless.

## State
None at rest beyond config secrets (cert key + OIDC secret, mode 0600). Sessions are in-memory
(re-login on restart is fine for an ops console).
