# vesta-console — deploy

Operator web/API console, **one per residency group**, in its own bastille vnet jail on the
group's WireGuard mesh. Read-only observability (aggregates the group's brokers' `observe` API
over mTLS); **never surfaces a secret value**. Plan: `../../docs/planning/02-vesta-console.md`.

## Layout
- `rc.d/vesta-console` → `/usr/local/etc/rc.d/vesta-console` (unprivileged `vesta-console` user).
- `libexec/vesta-console-run` → `/usr/local/libexec/vesta-console-run` (sources env, execs the binary).
- `vesta-console.env.sample` → `/usr/local/etc/vesta-console/vesta-console.env` (mode 0600).
- Binary → `/usr/local/sbin/vesta-console`.

## Build (single binary with the SPA embedded)
```sh
pnpm --dir web install && pnpm --dir web build      # produces web/dist (Node 24)
cargo build --release -p vesta-console --features embed-ui   # embeds web/dist via rust-embed
```
Without `--features embed-ui` the binary still runs the API but serves a "UI not embedded" stub
(that's the default CI build, which needs no built `web/dist`). The release artifact
(`vesta-console-<ver>-<target>.tar.gz`) is built with the feature; the FreeBSD (medina) build
needs `web/dist` present on the build step — see the infra coordination note (runner node/pnpm).

## Listener & access
- Binds **`10.200.0.110:8203`** (eu, WG /32) — never `0.0.0.0`. Plain HTTP on the WG hop.
- Browser access: WG-direct, or (recommended) behind the **Kalista edge**
  `vesta-console.<region>.proximi.fi` → `:8203` (Kalista TLS + OIDC + downstream-mTLS + IP ACL).
- TLS to the brokers: the console's fleet-CA client cert `vesta-console.<group>.proximi.internal`
  (dual-EKU), placed mode-0600 by infra at deploy. No server TLS on the console itself (edge terminates).

## Auth
OIDC RP via identity (`acr=mfa` enforced) — **P1b**, wired once identity mints the client for the
final redirect URI. Until then, only `VESTA_CONSOLE_ALLOW_INSECURE_DEV=1` grants a (dev) session.
No encrypted dataset / unseal needed — the console is stateless.

**Single-Logout (OIDC Back-Channel Logout, RP side):** `POST /api/v1/auth/backchannel-logout` ends
the console session when identity fans out a revoke / admin force-logout. It is **server-to-server**
(identity → console, signed Logout Token, no operator cookie), so the **Kalista edge IP-ACL must
permit identity's POST** to that path. Register on the console's identity client:
`backchannel_logout_uri` = `https://vesta-console.<region>.proximi.fi/api/v1/auth/backchannel-logout`
(same origin as `redirect_uri`) and `backchannel_logout_session_required=true`. No console env var.

## State
None at rest beyond config secrets (cert key + OIDC secret, mode 0600). Sessions are in-memory
(re-login on restart is fine for an ops console); each session also holds the login id_token `sid`,
plus a small in-memory `jti` replay cache for the back-channel logout endpoint.
