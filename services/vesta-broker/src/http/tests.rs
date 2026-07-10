use super::*;
use crate::config::BrokerConfig;
use crate::state::now_unix;
use axum::body::Body;
use axum::http::Request;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt as _;
use vesta_transport::audit::{AuditEvent, AuditSink};
use vesta_transport::lock::MutexExt;
use vesta_transport::ResidencyGroup;

#[test]
fn uuid_v4_validation() {
    assert!(is_uuid_v4_lower("11111111-1111-4111-8111-111111111111"));
    assert!(!is_uuid_v4_lower("11111111-1111-1111-8111-111111111111")); // not v4
    assert!(!is_uuid_v4_lower("11111111-1111-4111-c111-111111111111")); // bad variant
    assert!(!is_uuid_v4_lower("11111111-1111-4111-8111-11111111111A")); // uppercase
    assert!(!is_uuid_v4_lower("short"));
}

#[test]
fn session_and_lease_ownership_is_enforced() {
    let state = dev_state(crate::config::Hardening::default());
    // Principal A opens a session (bound to its SAN) and issues a lease under it.
    let sid = {
        let mut e = state.leases.lock_recover();
        e.open_session(now_unix(), 3600, 1800)
    };
    state.bind_session("san-a", &sid);
    let lease = {
        let mut e = state.leases.lock_recover();
        e.issue_lease(now_unix(), &sid, 900, 900, true).unwrap()
    };
    // owns_session: A yes, B no.
    assert!(state.owns_session("san-a", &sid));
    assert!(!state.owns_session("san-b", &sid));

    let principal = |san: &str| Principal {
        san: san.into(),
        role: "dev".into(),
        caps: Capability::all(),
        ssh_principals: None,
    };
    // A may renew/revoke its lease; B is rejected as not-found (no existence leak).
    assert!(require_lease_owner(&state, &principal("san-a"), &lease).is_ok());
    let e = require_lease_owner(&state, &principal("san-b"), &lease).unwrap_err();
    assert_eq!(e.0, StatusCode::NOT_FOUND);
    assert_eq!(e.1 .0.error, "no_such_lease");
    // An unknown lease id is likewise not-found.
    let e = require_lease_owner(&state, &principal("san-a"), "no-such").unwrap_err();
    assert_eq!(e.0, StatusCode::NOT_FOUND);
}

struct NullSink;
impl AuditSink for NullSink {
    fn emit(&self, _event: &AuditEvent) {}
}

/// A sealed dev `AppState` fixed to the `eu` group, with the given hardening limits.
/// Sealed is fine for these tests: the group `404`, body `400`, and the middleware
/// (size/rate/headers/metrics) are all decided before any seal/handler logic runs.
fn dev_state(hardening: crate::config::Hardening) -> AppState {
    let cfg = BrokerConfig {
        bind: "127.0.0.1:8200".parse().expect("addr"),
        residency_group: ResidencyGroup::Eu,
        node: "test".into(),
        hardening,
        audit_path: std::env::temp_dir().join("vault-test-audit.jsonl"),
        store_path: std::env::temp_dir().join("vault-test-store.sqlcipher"),
        snapshot_dir: std::env::temp_dir(),
        roles: HashMap::new(),
        allow_insecure_dev: true,
        tls: None,
        kms_jwt: None,
        identity_kms: None,
    };
    AppState::new(cfg, None, Arc::new(NullSink))
}

fn eu_dev_router() -> Router {
    router(dev_state(crate::config::Hardening::default()))
}

/// A production `AppState` (no insecure-dev) with a fixed roles map, for exercising the
/// mTLS `Principal` extractor's verified-SAN branch.
fn prod_state(roles: HashMap<String, crate::auth::RolePrincipal>) -> AppState {
    let cfg = BrokerConfig {
        bind: "127.0.0.1:8200".parse().expect("addr"),
        residency_group: ResidencyGroup::Eu,
        node: "test".into(),
        hardening: crate::config::Hardening::default(),
        audit_path: std::env::temp_dir().join("vault-test-audit.jsonl"),
        store_path: std::env::temp_dir().join("vault-test-store.sqlcipher"),
        snapshot_dir: std::env::temp_dir(),
        roles,
        allow_insecure_dev: false,
        tls: None,
        kms_jwt: None,
        identity_kms: None,
    };
    AppState::new(cfg, None, Arc::new(NullSink))
}

/// The production auth path: a verified mTLS SAN (injected by the TLS layer as a
/// `ClientSan` extension) maps to its registered role + capabilities; a trusted-but-
/// unregistered SAN is `403`; and with no verified identity and dev off, `401`.
#[tokio::test]
async fn principal_extractor_maps_verified_san_to_role() {
    use crate::auth::{Capability, ClientSan, Principal, RolePrincipal};
    let mut roles = HashMap::new();
    roles.insert(
        "demon-system.eu.proximi.internal".to_string(),
        RolePrincipal {
            role: "demon-system".into(),
            caps: [Capability::SshSign].into_iter().collect(),
            ssh_principals: None,
        },
    );
    let state = prod_state(roles);

    // Registered SAN → its role + only its caps.
    let mut parts = Request::builder()
        .body(Body::empty())
        .unwrap()
        .into_parts()
        .0;
    parts
        .extensions
        .insert(ClientSan("demon-system.eu.proximi.internal".into()));
    let p = Principal::from_request_parts(&mut parts, &state)
        .await
        .expect("registered SAN authorises");
    assert_eq!(p.role, "demon-system");
    assert!(p.allows(Capability::SshSign));
    assert!(!p.allows(Capability::Creds));

    // Trusted (verified) but unregistered SAN → 403.
    let mut parts = Request::builder()
        .body(Body::empty())
        .unwrap()
        .into_parts()
        .0;
    parts
        .extensions
        .insert(ClientSan("stranger.eu.proximi.internal".into()));
    let e = Principal::from_request_parts(&mut parts, &state)
        .await
        .unwrap_err();
    assert_eq!(e.0, StatusCode::FORBIDDEN);
    assert_eq!(e.1 .0.error, "unregistered_principal");

    // No verified identity and insecure-dev off → 401 missing_identity (no header fallback).
    let mut parts = Request::builder()
        .header("x-client-cert-san", "demon-system.eu.proximi.internal")
        .body(Body::empty())
        .unwrap()
        .into_parts()
        .0;
    let e = Principal::from_request_parts(&mut parts, &state)
        .await
        .unwrap_err();
    assert_eq!(e.0, StatusCode::UNAUTHORIZED);
    assert_eq!(e.1 .0.error, "missing_identity");
}

fn sign_request(group: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/{group}/ssh/sign"))
        .header("content-type", "application/json")
        // dev: unmapped SAN → `dev` principal (all caps), so auth/cap never short-circuits.
        .header("x-client-cert-san", "demon-operator.eu.proximi.internal")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

/// The refinement: a wrong-group request must `404` even when its body is malformed —
/// the residency check is order-independent of body parsing. Previously this `400`'d
/// because `Json` (the body extractor) ran before the in-handler `check_group`.
#[tokio::test]
async fn wrong_group_with_invalid_body_is_404_not_400() {
    let resp = eu_dev_router()
        .oneshot(sign_request("uae", "{ not valid json"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Conversely, a *correct*-group request with a malformed body still `400`s — the
/// extractor lets a valid group through, then the body fails to parse.
#[tokio::test]
async fn right_group_with_invalid_body_is_400() {
    let resp = eu_dev_router()
        .oneshot(sign_request("eu", "{ not valid json"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// And a wrong group with a *valid* body is still `404` (unchanged behaviour).
#[tokio::test]
async fn wrong_group_with_valid_body_is_404() {
    let body = r#"{"public_key":"ssh-ed25519 AAAA","cert_type":"user","principals":["x"]}"#;
    let resp = eu_dev_router()
        .oneshot(sign_request("uae", body))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---- hardening (#3) ----

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-client-cert-san", "demon-operator.eu.proximi.internal")
        .body(Body::empty())
        .expect("request")
}

/// An over-limit body is rejected with `413` before the handler runs (DefaultBodyLimit).
#[tokio::test]
async fn oversized_body_is_413() {
    let small = crate::config::Hardening {
        max_body_bytes: 32,
        ..Default::default()
    };
    let big = "x".repeat(1024);
    let resp = router(dev_state(small))
        .oneshot(sign_request("eu", &big))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// An unrouted path gets the uniform JSON `404` fallback.
#[tokio::test]
async fn unrouted_path_is_404_fallback() {
    let resp = eu_dev_router()
        .oneshot(get("/no/such/route"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Security headers are present on every response (outermost layer), including `healthz`.
#[tokio::test]
async fn security_headers_present() {
    let resp = eu_dev_router()
        .oneshot(get("/healthz"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
}

/// A principal that exhausts its token bucket is throttled with `429`; refill is off in
/// this config (rate 0, burst 2) so the third request within the burst window is denied.
#[tokio::test]
async fn rate_limit_throttles_after_burst() {
    let h = crate::config::Hardening {
        rate_per_sec: 0.0,
        rate_burst: 2.0,
        ..Default::default()
    };
    let app = router(dev_state(h));
    assert_eq!(
        app.clone().oneshot(get("/healthz")).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(get("/healthz")).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(get("/healthz")).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// The request metric is labelled by the matched-route *template*, never the concrete
/// tenant-bearing path — so tenant ids never leak into `:8201` metrics.
#[tokio::test]
async fn metrics_label_by_route_template_not_tenant_path() {
    let state = dev_state(crate::config::Hardening::default());
    let app = router(state.clone());
    // A real (tenant-bearing) creds path — sealed so it 503s, but it routes + meters.
    let tenant_uri = "/v1/eu/11111111-1111-4111-8111-111111111111/creds/audit-writer";
    let req = Request::builder()
        .method("POST")
        .uri(tenant_uri)
        .header("content-type", "application/json")
        .header("x-client-cert-san", "demon-operator.eu.proximi.internal")
        .body(Body::from("{}"))
        .expect("request");
    let _ = app.oneshot(req).await.expect("response");

    let dump = state.metrics.render(state.is_sealed());
    assert!(
        dump.contains("route=\"/v1/{group}/{tenant_id}/creds/{role}\""),
        "metrics should use the route template; got:\n{dump}"
    );
    assert!(
        !dump.contains("11111111-1111-4111-8111-111111111111"),
        "the concrete tenant id must NOT appear in metrics; got:\n{dump}"
    );
}

// ---- observe (read-only operator observability) ----

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// `observe/leases` is `observe`-capped (dev principal has it), read-only, NOT seal-gated:
/// a fresh broker returns 200 with `now` + an empty lease list.
#[tokio::test]
async fn observe_leases_ok_and_empty_on_fresh_state() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/sys/observe/leases"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert!(v.get("now").and_then(serde_json::Value::as_u64).is_some());
    assert_eq!(v["leases"].as_array().expect("leases array").len(), 0);
}

#[tokio::test]
async fn observe_sessions_ok_and_empty_on_fresh_state() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/sys/observe/sessions"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["sessions"].as_array().expect("sessions array").len(), 0);
}

/// `observe/roles` returns the loaded role map (empty in dev_state) — never secret material.
#[tokio::test]
async fn observe_roles_ok() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/sys/observe/roles"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert!(v["roles"].is_array());
}

/// `observe/ssh` (group-scoped): 200 with empty issued/revoked on a fresh sealed broker.
#[tokio::test]
async fn observe_ssh_ok() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/eu/observe/ssh"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["issued"].as_array().expect("issued").len(), 0);
    assert!(v["revoked"].is_array());
}

/// `observe/kms` (group-scoped): 200; keys empty when sealed (no store).
#[tokio::test]
async fn observe_kms_ok_empty_when_sealed() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/eu/observe/kms"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["keys"].as_array().expect("keys").len(), 0);
}

/// `observe/object-store` (group-scoped): 200 with a boolean `configured`.
#[tokio::test]
async fn observe_object_store_ok() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/eu/observe/object-store"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert!(v["configured"].is_boolean());
}

/// `observe/audit`: 200 with a `records` array + `next_seq` (the dev sink writes nothing).
#[tokio::test]
async fn observe_audit_ok() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/sys/observe/audit?since=0&limit=10"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert!(v["records"].is_array());
    assert!(v["next_seq"].as_u64().is_some());
}

/// A wrong-group observe path 404s (residency air-gap) like every other `{group}` route.
#[tokio::test]
async fn observe_ssh_wrong_group_is_404() {
    let resp = eu_dev_router()
        .oneshot(get("/v1/uae/observe/ssh"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
