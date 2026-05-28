# worklog — group validated extractor (2026-05-28)

Backlog item #2 from `docs/planning/01-vault-as-service.md` §10 ("Known refinement").

## Problem

The `:group` residency check (`http::check_group`, returns `404` on mismatch) ran *inside*
each handler body. In axum the `Json` body extractor runs during extraction — i.e. **before**
the handler body — so a request to the *wrong* group with a *malformed* body returned
`400` (JSON deserialize) before the `404` (group). The residency air-gap decision was
therefore order-dependent on body validity.

## Fix (`services/vault-broker/src/http.rs`)

- Added a `Group(String)` extractor implementing `FromRequestParts<AppState>`. It reads the
  `:group` path segment via `RawPathParams` (non-consuming — handlers keep their own
  `Path(...)`), validates it against `cfg.residency_group`, and reuses `check_group` for the
  `404`. Because it is a `FromRequestParts` extractor, it runs **before** the `Json`
  (`FromRequest`) body extractor.
- Replaced the in-body `check_group(&state, &group)?` in `ssh_ca`, `ssh_revoked`, `ssh_sign`,
  `creds`, and `kms_preflight` with the `Group` extractor in each handler signature
  (placed before `Json`). `kms_preflight` lost its now-unused `group` param.
- The kms handlers still bind `group` from their `Path` tuple (used for `kms::{wrap,unwrap,
  rotate}` keying + audit `kek_id`); the `Group` extractor sits alongside as the guard.

## Behaviour change

- Wrong group + invalid body: **`400` → `404`** (the fix).
- Wrong group + valid body: `404` (unchanged).
- Right group + invalid body: `400` (unchanged).
- New precedence: residency `404` now also precedes the in-handler capability `403`. This is
  intended — a cred for one region must not even be *addressable* on another region's broker,
  so the air-gap outranks authz. Legit traffic is unaffected (demon only ever calls its own
  group).

## Tests

Added 3 Router-level `oneshot` tests (`tower::ServiceExt`) in `http::tests`. Full broker
suite: **27 passed**; `clippy -D warnings` clean; `cargo fmt --check` clean.

## Coordination

No boundary change — `404`-on-group-mismatch was already the published contract
(`spec/broker-openapi.yaml`); only the ordering vs body parsing tightened. No inbox note
or `CONTRACTS.md` edit needed.
