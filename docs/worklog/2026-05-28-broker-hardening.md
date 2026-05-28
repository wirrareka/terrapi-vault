# worklog — broker hardening (#3) (2026-05-28)

Backlog item #3 ("rate-limity, metriky/observability"). Done in full, with **zero new
crates** (axum `DefaultBodyLimit` + `middleware::from_fn` + std/tokio primitives).

## New module: `services/vault-broker/src/hardening.rs`

Middleware applied in `http::router`, outer → inner:

1. **Security headers** (`from_fn`, outermost — on every response incl. errors):
   `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
2. **Request metrics** (`route_layer`, so it runs *after* routing and sees `MatchedPath`):
   records `vault_http_requests_total{route,method,status}` + per-route latency
   (`vault_http_request_duration_ms_{count,sum}`). **Labelled by the route *template***
   (`/v1/{group}/{tenant_id}/creds/{role}`), never the concrete path — so tenant UUIDs never
   reach the `:8201` metrics surface and label cardinality stays bounded.
3. **Per-principal rate limit** → `429`: token bucket keyed by mTLS SAN (`ClientSan` ext, or
   the dev header). Refill `rate_per_sec`, depth `rate_burst`; first-seen principal starts full.
4. **Global concurrency cap** → `503`: `tokio::sync::Semaphore::try_acquire_owned`; also drives
   the `vault_http_inflight` gauge.
5. **Request timeout** → `408`: `tokio::time::timeout` around the inner request.
6. **Body-size limit** → `413`: `DefaultBodyLimit::max(...)` (innermost).

Plus a uniform JSON **`404` fallback** (`hardening::not_found`) for any unrouted path.

## Config (`config.rs`)

New `Hardening` struct (defaults: 64 KiB body / 15 s timeout / 256 concurrency / 50 rps /
100 burst), read via `Hardening::from_env` →
`VAULT_{MAX_BODY_BYTES,REQUEST_TIMEOUT_SECS,MAX_CONCURRENCY,RATE_PER_SEC,RATE_BURST}`. All
optional; defaults are safe so **no deploy change is required**. Documented (commented) in
`deploy/vault-broker.env.sample`.

## State / metrics (`state.rs`)

`Metrics` extended with the request counters, per-route latency, and an `inflight` gauge +
`record_request` / `inflight_add`. `AppState` gains `harden: Arc<HardenState>` (semaphore +
buckets), built in `AppState::new` from `cfg.hardening`.

## Sizing rationale

The broker is WG-only + mTLS with a handful of trusted daemon principals, so these are
DoS-resistance guards (bounded bodies / time / concurrency / per-daemon burst), not
public-traffic throttles. `healthz` + `seal-status` share the limits (burst 100 default is
ample for liveness probes).

## Tests

5 new Router-level `oneshot` tests in `http::tests` (413 / 404-fallback / security-headers /
429-after-burst / **metrics use the route template, not the tenant path**) + 2 unit tests for
the token bucket in `hardening::tests`. Full suite: **34 passed**; `clippy -D warnings` clean;
`cargo fmt --check` clean.

## Coordination

No boundary change to the broker contract (`spec/broker-openapi.yaml` request/response shapes
unchanged). New `429/503/408/413` are standard transport-level rejections. The optional env
knobs are operational; if infra wants them surfaced in `conventions/ports-env.md` that's a
doc-only follow-up — flagged, not blocking.
