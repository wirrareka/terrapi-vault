use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use terrapi_vesta_replication::{secondary::ReadOnlyApi, *};
use tower::ServiceExt;
fn identity() -> Identity {
    Identity {
        cluster: "test".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}
#[tokio::test]
async fn secondary_cache_excludes_prepared_data_and_never_allows_http_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(
        dir.path().join("p.vesta"),
        Role::Primary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let mut s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let api = ReadOnlyApi::default();
    let app = api.router();
    assert_eq!(
        app.clone()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        503
    );
    api.refresh(&s).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        503
    );
    s.confirm_checkpoint(p.checkpoint().unwrap()).unwrap();
    api.refresh(&s).unwrap();
    let batch = Batch {
        identity: identity(),
        operation_id: "one".into(),
        changes: vec![Change::PutPlace {
            id: "p1".into(),
            name: "Airport".into(),
        }],
    };
    s.stage(p.prepare(batch).unwrap()).unwrap();
    api.refresh(&s).unwrap();
    let response = app
        .clone()
        .oneshot(Request::get("/view").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let view: View =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert!(view.places.is_empty());
    s.apply(p.decide("one").unwrap()).unwrap();
    api.refresh(&s).unwrap();
    drop(p);
    let response = app
        .clone()
        .oneshot(Request::get("/view").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let view: View =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(view.places.len(), 1);
    assert_eq!(
        app.clone()
            .oneshot(Request::post("/transactions").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        503
    );
    let response = app
        .clone()
        .oneshot(Request::get("/capabilities").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let caps: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(caps["readable"], true);
    assert_eq!(caps["writable"], false);
    assert_eq!(caps["reason"], "secondary_read_only");
    api.invalidate();
    assert_eq!(
        app.oneshot(Request::get("/view").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        503
    );
}

#[tokio::test]
async fn snapshot_projection_and_wrong_role_invalidation() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(
        dir.path().join("p.vesta"),
        Role::Primary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let mut s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    commit(
        &mut p,
        &mut s,
        Batch {
            identity: identity(),
            operation_id: "one".into(),
            changes: vec![Change::PutPlace {
                id: "p1".into(),
                name: "Airport".into(),
            }],
        },
    )
    .unwrap();
    let mut replacement = Node::open(
        dir.path().join("replacement.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let api = ReadOnlyApi::default();
    replacement.install(p.snapshot().unwrap()).unwrap();
    assert!(replacement.verified_view().unwrap().is_none());
    replacement
        .confirm_checkpoint(p.checkpoint().unwrap())
        .unwrap();
    api.refresh(&replacement).unwrap();
    let response = api
        .router()
        .oneshot(Request::get("/view").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let view: View =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(view.places.len(), 1);
    assert!(api.refresh(&p).is_err());
    assert_eq!(
        api.router()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        503
    );
}
