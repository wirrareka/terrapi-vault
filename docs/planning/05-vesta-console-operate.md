# 05 — vesta-console: safe operator actions (`operate` capability)

**Status:** DESIGN (proposed 2026-06-13) — not implemented, not yet coordinated.
**Problem:** vesta-console is strictly read-only (aggregates brokers' `observe` API over
mTLS, never surfaces a secret value). Operators cannot *act* — no revoke, no rotate, no
disable. That is a real UX gap, but "make it editable" the naïve way would turn the
aggregation node into the single most dangerous box in the group. This is the safe design.

Derived from a 3-agent pass (security threat-model + secure architecture + operator UX),
grounded in the current code. Cross-refs: `02-vesta-console.md`, `04-stage3-vesta-cutover.md`,
`conventions/secrets-broker.md`, `conventions/residency.md`.

---

## First principle: the console issues COMMANDS, never credentials

The console must never feel like a CRUD app. It is an **operator command plane**: select a
live object → send a named command → the broker executes → the audit log records it. No
secret value appears anywhere in that flow — not in the request, not in the response, not in
the confirmation. Every mutation reachable from the console is **command-only** (response =
status, never a credential).

This preserves the hard contract invariant: *the console never surfaces a secret value*.

---

## Hard invariants (any implementation MUST preserve)

1. **No secret through the console — ever.** No signed cert, password, plaintext DEK,
   presigned URL, raw key bytes, or static cred in any mutation request/response. Ops that
   return secret material stay **out of console scope, forever** (see "never via console").
2. **Per-operator attribution.** The broker audit must carry the human OIDC `sub`, not just
   the console SAN. The console's mTLS cert authenticates *the box*, not *the human* — so the
   cert alone must never authorize a mutation (else: confused deputy + attribution collapse).
3. **MFA-gated.** Login already enforces `acr=mfa`. Destructive ops additionally step-up.
4. **Dual-control for destructive ops.** Proposer ≠ approver, two distinct operators.
5. **Residency air-gap.** Every mutation is `{group}`-pinned; an eu console can never resolve
   or act on a uae broker.
6. **Fail-closed audit.** The B3 record is durably written *before* success returns; if the
   audit ship fails, the command fails closed (`503 audit_unavailable`).
7. **Least privilege on the console SAN.** Grant the minimum new cap; subtractive before
   additive; never grant `creds`/`ssh-sign`/`kms`/`object-store` to the console cert.

---

## Architecture

### 1. New capability tier: `operate`

Add `Capability::Operate` to `vesta-broker/src/auth.rs` (wire name `"operate"`, beside
`Observe`). `operate` gates **command-only** mutations exposed to the console. It explicitly
does **not** subsume credential-issuing caps (`creds`, `ssh-sign`, `kms`, `object-store`) —
those mint secret material and must stay unreachable from the console path.

A new role `vesta-console-operate` in `VESTA_ROLES_CONFIG` carries `{observe, operate}`.
But the console's mTLS identity alone is **insufficient by design** (invariant #2).

### 2. Per-operator command assertion (operator-bound, NOT confused-deputy)

For a mutation, the console mints a short-TTL (**≤120 s, single-use**) **command assertion** —
a JWT signed with a console-held **command-signing key DISTINCT from the mTLS key** — carrying:
`op_sub`, `op_email`, `acr`, `cmd` (e.g. `lease.revoke`), `scope` (`group/tenant/resource_id`),
`jti`, `iat/exp`, session-binding `cnf`. Forwarded in `X-Vesta-Operator-Assertion` over the
existing mTLS channel.

The broker verifies **both**:
- (a) mTLS SAN→role has `operate` (`require_cap(Operate)`), **and**
- (b) assertion signature vs the registered console command-signing JWKS (config, separate
  trust anchor from the mTLS CA); `acr=mfa`; `exp` fresh; `jti` unseen (replay cache);
  `cmd`+`scope` match the route; `scope.group` == the broker's `residency_group` constant.

Identity audited is the human `op_sub` — attributable, MFA-proven, replay-protected.

> **Decision:** operator-bound assertion, reject console-as-deputy. The console must not be
> able to forge a command "on behalf of" an operator who didn't act.

### 3. Command path

```
UI action (row-level) → POST /api/v1/operate/... (console, session-gated)
  → console mints operator assertion (≤120s, jti, scope)
  → POST broker control endpoint over mTLS + X-Vesta-Operator-Assertion
  → broker: require_cap(operate) + verify assertion + scope/residency check
  → B3 audit (op_sub + cmd + scope + jti) written fail-closed
  → command-only response { status, resource_id }   ← no credential
```

Separate API prefix `/operate/` (vs `/observe/`) so the read/write split is encoded in the
URL and network policy (rate-limit, WAF) can apply per prefix.

### 4. Dual-control (destructive ops)

Reuse the KMS **arm/ack-gated** shape (`secrets-broker.md`): destructive command is *armed*
(pending, records proposer `op_sub`+`jti`), then *acked* by a second operator's assertion
before it executes. Proposer ≠ approver enforced; pending entries TTL-expire (default 15 min;
expiry = no-op, fail-closed).

---

## Phasing — mapped to what the broker actually has TODAY

The broker's existing **command-only** (no-secret-returned) mutating endpoints:

| Endpoint | Class | Returns secret? | Phase |
|---|---|---|---|
| `POST /v1/sys/leases/revoke` | subtractive | no | **1** |
| `DELETE /v1/sys/session/{id}` (cascade-revoke children) | subtractive | no | **1** |
| `POST /v1/sys/leases/renew` (extends TTL) | additive | no | **2** |
| SSH serial revoke (KRL) | subtractive | no | **2** |
| KMS rotate / rewrap | destructive (key lifecycle) | no | **3** (dual-control) |

**Not present today** (would be NEW broker endpoints, design separately, dual-control
mandatory): runtime role enable/disable/create (roles are config-only via env today),
KMS-version *retire* (root retire lives in identity, ack-gated — not in the broker).

**Never via console — forever** (return secret material): `creds` mint, `ssh-sign`,
`kms wrap/unwrap` (unwrap → plaintext DEK), `object-store presign` (URL = bearer), raw
`store-snapshot` download.

Rollout: ship `operate` + assertion verify **flagged off** → enable Phase 1 (subtractive,
reversible) on eu, validate audit attribution → add dual-control engine → Phase 3 last.

---

## UX model

- **Command plane, not CRUD.** Action verbs only: *Revoke, Renew, Disable, Rotate, Kill
  session* — never *View/Copy/Download/Export*.
- **Progressive disclosure / row-action.** Action affordances render only when a row is
  selected **and** `me.caps ∋ operate`. Observe-only operators see **no action column at all**
  (not greyed-out — least disclosure; a disabled+tooltip button is a social-engineering vector).
- **Typed-target confirmation** for subtractive ops: operator types the displayed target ID;
  confirm button disabled until exact match (proves they read the right row). Blast-radius
  warning shown (e.g. session kill: "cascade-revoke N child leases", N from `child_count`).
- **Step-up MFA for destructive ops:** redirect to IdP with `acr_values=mfa max_age=0` (forces
  fresh challenge regardless of SSO age) → short-lived server-side `step_up_token` (5 min) →
  consumed by the typed-target confirm; no token ⇒ endpoint 403.
- **Dual-control UX:** proposer arms (step-up + typed-target) → row shows `PENDING APPROVAL —
  requested by A`; a second operator (cap `operate`, `sub ≠ proposer`) reviews (sees proposer,
  target, effect, audit trail) → their own step-up → executes. Pending visible to all
  `operate` operators in the group; nav count badge (`KMS (1 pending)`); 15-min expiry.
- **Never-show-secrets affordance.** Success shows identity + audit seq, never value:
  "Lease ls-a1 revoked. Recorded in audit log (seq 44)." KMS page header carries a permanent
  trust anchor: "No key material is accessible from this console."
- **Read-first defaults.** Boots read-only regardless of caps; Overview is always pure
  telemetry; no bulk destructive select; no keyboard shortcuts for destructive actions;
  broker-unreachable ⇒ all actions suspended (no split-brain).

### Frontend anchors (`web/`)
- `src/lib/types.ts` — add `caps: ("operate"|"observe"|"audit")[]` to `CurrentUser`; action
  req/resp types.
- `src/hooks/use-auth.ts` — `useOperatorCap(cap)` derived from `useMe()` (single uniform gate).
- `src/hooks/use-observe.ts` — mutation hooks (`useRevokeLease`, `useKillSession`, …) via
  TanStack `useMutation`.
- new `components/`: `ConfirmDialog.tsx` (typed-target), `ActionButton.tsx` (cap-gated),
  `DualControlBadge.tsx`, `StepUpGate.tsx`. `PageHeader` already has a `children` action slot.
- `lib/mock.ts` — add POST handlers so flows develop in isolation.

---

## Coordination (when this is approved — NOT yet sent)

This changes the console↔broker boundary, so before/at implementation:
- `conventions/secrets-broker.md` — add the `operate` cap, the operator-assertion header +
  verification rules, the `/operate/` prefix, dual-control arm/ack semantics.
- `CONTRACTS.md` — console row gains "operator command plane (command-only, operator-bound)".
- **identity** — the command assertion reuses the operator's OIDC+MFA session; confirm
  `acr=mfa max_age=0` step-up is supported, and whether the console command-signing key
  should be registered/trusted anywhere identity-side (likely no — broker-local JWKS config).
- **infra** — new `vesta-console-operate` SAN→role; `/operate/` network policy; the console
  command-signing key provisioning (separate from mTLS key).
- Drop notes in `inbox/{infra,identity}/`.

Per the secrets-broker contract: source of truth is the spec/OpenAPI in this repo — publish
the `/operate/*` endpoints + assertion shape under `spec/` when implemented.
