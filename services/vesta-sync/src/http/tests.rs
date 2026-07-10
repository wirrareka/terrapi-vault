use super::*;
use crate::auth;
use crate::config::Config;
use crate::dto::{
    CreateAccountRequest, EnrollChallenge, EnrollRequest, PullResponse, PushRequest, PushResponse,
    StatusResponse,
};
use crate::store::now_unix;
use crate::store::Store;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

const VID: &str = "11111111-1111-4111-8111-111111111111";
const SECRET: &[u8] = b"argon2-derived-enrolment-secret";

fn b64e(b: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn state() -> AppState {
    let cfg = Config {
        bind: "127.0.0.1:8300".parse().unwrap(),
        db_path: String::new(),
        db_key: None,
        max_body_bytes: 1 << 20,
        max_pull: 500,
        max_concurrency: 64,
        request_timeout: std::time::Duration::from_secs(30),
        readers: 0,
    };
    AppState::new(cfg, Store::open_memory().unwrap())
}

/// Build a device-signed request (matches what the real client does).
fn signed(
    method: &str,
    uri: &str,
    body: &[u8],
    sk: &SigningKey,
    device_id: &str,
    nonce: &str,
) -> Request<Body> {
    let ts = now_unix();
    let canonical = auth::canonical_string(method, uri, VID, ts, nonce, &auth::sha256_hex(body));
    let sig = sk.sign(canonical.as_bytes()).to_bytes();
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-device-id", device_id)
        .header("x-sync-ts", ts.to_string())
        .header("x-sync-nonce", nonce)
        .header("x-sync-sig", b64e(sig))
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = router(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

fn create_body(sk: &SigningKey, device_id: &str) -> Vec<u8> {
    let enroll = crate::dto::EnrollVerifier {
        salt_b64: b64e(b"enrol-salt-16byte"),
        params: terrapi_vesta::KdfParams::default(),
        hash_b64: b64e(Sha256::digest(SECRET)),
    };
    let req = CreateAccountRequest {
        enroll,
        proof_b64: b64e(SECRET),
        device: crate::dto::DeviceRegistration {
            device_id: device_id.into(),
            pubkey_b64: b64e(sk.verifying_key().to_bytes()),
        },
    };
    serde_json::to_vec(&req).unwrap()
}

fn op(device_id: &str, op_id: &str) -> crate::dto::Op {
    crate::dto::Op {
        op_id: op_id.into(),
        device_id: device_id.into(),
        hlc: vesta_transport::Hlc {
            wall_ms: 1,
            counter: 0,
        },
        collection_id: "notes".into(),
        encrypted_payload: b64e(b"ciphertext"),
    }
}

#[tokio::test]
async fn full_two_device_flow() {
    let st = state();
    let dev_a = SigningKey::generate(&mut OsRng);
    let dev_b = SigningKey::generate(&mut OsRng);
    let acct = format!("/v1/sync/{VID}/account");

    // 1. Device A creates the account (self-signed).
    let body = create_body(&dev_a, "A");
    let (status, _) = send(&st, signed("POST", &acct, &body, &dev_a, "A", "n1")).await;
    assert_eq!(status, StatusCode::CREATED);
    // Re-create → 409.
    let (status, _) = send(&st, signed("POST", &acct, &body, &dev_a, "A", "n2")).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 2. Enroll-challenge is unauthenticated and returns the salt+params.
    let (status, body) = send(
        &st,
        Request::builder()
            .method("GET")
            .uri(format!("/v1/sync/{VID}/enroll-challenge"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ch: EnrollChallenge = serde_json::from_slice(&body).unwrap();
    assert_eq!(ch.salt_b64, b64e(b"enrol-salt-16byte"));

    // 3. Device B enrolls with the correct proof (self-signed by B).
    let enroll_uri = format!("/v1/sync/{VID}/enroll");
    let good = serde_json::to_vec(&EnrollRequest {
        proof_b64: b64e(SECRET),
        device: crate::dto::DeviceRegistration {
            device_id: "B".into(),
            pubkey_b64: b64e(dev_b.verifying_key().to_bytes()),
        },
    })
    .unwrap();
    let (status, _) = send(&st, signed("POST", &enroll_uri, &good, &dev_b, "B", "n3")).await;
    assert_eq!(status, StatusCode::OK);

    // Wrong proof → 401.
    let bad = serde_json::to_vec(&EnrollRequest {
        proof_b64: b64e(b"wrong-secret"),
        device: crate::dto::DeviceRegistration {
            device_id: "C".into(),
            pubkey_b64: b64e(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()),
        },
    })
    .unwrap();
    let dev_c = SigningKey::generate(&mut OsRng);
    let (status, _) = send(&st, signed("POST", &enroll_uri, &bad, &dev_c, "C", "n4")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 4. Device A pushes one op.
    let push_uri = format!("/v1/sync/{VID}/push");
    let push = serde_json::to_vec(&PushRequest {
        ops: vec![op("A", "op-1")],
    })
    .unwrap();
    let (status, body) = send(&st, signed("POST", &push_uri, &push, &dev_a, "A", "n5")).await;
    assert_eq!(status, StatusCode::OK);
    let pr: PushResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!((pr.accepted, pr.duplicates, pr.latest_seq), (1, 0, 1));

    // A cannot author an op under B's device_id.
    let spoof = serde_json::to_vec(&PushRequest {
        ops: vec![op("B", "op-2")],
    })
    .unwrap();
    let (status, _) = send(&st, signed("POST", &push_uri, &spoof, &dev_a, "A", "n6")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 5. Device B pulls and sees A's op.
    let pull_uri = format!("/v1/sync/{VID}/pull?since=0&limit=100");
    let (status, body) = send(&st, signed("GET", &pull_uri, b"", &dev_b, "B", "n7")).await;
    assert_eq!(status, StatusCode::OK);
    let pull: PullResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pull.ops.len(), 1);
    assert_eq!(pull.ops[0].op_id, "op-1");
    assert_eq!(pull.ops[0].seq, 1);

    // 6. Status.
    let status_uri = format!("/v1/sync/{VID}/status");
    let (status, body) = send(&st, signed("GET", &status_uri, b"", &dev_a, "A", "n8")).await;
    assert_eq!(status, StatusCode::OK);
    let s: StatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!((s.latest_seq, s.op_count, s.device_count), (1, 1, 2));
}

#[tokio::test]
async fn unsigned_push_is_401() {
    let st = state();
    // Create the account first so the route exists with an enrolled device.
    let dev_a = SigningKey::generate(&mut OsRng);
    let body = create_body(&dev_a, "A");
    let acct = format!("/v1/sync/{VID}/account");
    let _ = send(&st, signed("POST", &acct, &body, &dev_a, "A", "n1")).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sync/{VID}/push"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"ops":[]}"#))
        .unwrap();
    let (status, _) = send(&st, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replayed_nonce_is_rejected() {
    let st = state();
    let dev_a = SigningKey::generate(&mut OsRng);
    let acct = format!("/v1/sync/{VID}/account");
    let _ = send(
        &st,
        signed("POST", &acct, &create_body(&dev_a, "A"), &dev_a, "A", "n1"),
    )
    .await;

    let status_uri = format!("/v1/sync/{VID}/status");
    let req1 = signed("GET", &status_uri, b"", &dev_a, "A", "dup-nonce");
    let (s1, _) = send(&st, req1).await;
    assert_eq!(s1, StatusCode::OK);
    // Same nonce again → replay rejected.
    let req2 = signed("GET", &status_uri, b"", &dev_a, "A", "dup-nonce");
    let (s2, _) = send(&st, req2).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn push_notifies_tail_subscribers() {
    let st = state();
    let dev_a = SigningKey::generate(&mut OsRng);
    let acct = format!("/v1/sync/{VID}/account");
    let _ = send(
        &st,
        signed("POST", &acct, &create_body(&dev_a, "A"), &dev_a, "A", "n1"),
    )
    .await;

    // Subscribe to the live tail, then push an op.
    let mut rx = st.subscribe(VID);
    let push_uri = format!("/v1/sync/{VID}/push");
    let push = serde_json::to_vec(&PushRequest {
        ops: vec![op("A", "op-1")],
    })
    .unwrap();
    let (status, _) = send(&st, signed("POST", &push_uri, &push, &dev_a, "A", "n2")).await;
    assert_eq!(status, StatusCode::OK);

    // The stored op (with its server seq) was fanned out to the subscriber.
    let json = rx
        .try_recv()
        .expect("subscriber should have received the op");
    let stored: crate::dto::StoredOp = serde_json::from_str(&json).unwrap();
    assert_eq!(stored.op_id, "op-1");
    assert_eq!(stored.seq, 1);
}

#[tokio::test]
async fn tail_fanout_is_exactly_this_push() {
    // Guards the fan-out range (`before = latest_seq - accepted`): a push must publish ONLY
    // its own ops, never ops that already existed before the subscriber joined.
    let st = state();
    let dev_a = SigningKey::generate(&mut OsRng);
    let acct = format!("/v1/sync/{VID}/account");
    let _ = send(
        &st,
        signed("POST", &acct, &create_body(&dev_a, "A"), &dev_a, "A", "n1"),
    )
    .await;
    let push_uri = format!("/v1/sync/{VID}/push");
    // Pre-seed op-1 (seq 1) BEFORE anyone subscribes.
    let p1 = serde_json::to_vec(&PushRequest {
        ops: vec![op("A", "op-1")],
    })
    .unwrap();
    assert_eq!(
        send(&st, signed("POST", &push_uri, &p1, &dev_a, "A", "n2"))
            .await
            .0,
        StatusCode::OK
    );
    // Subscribe, then push op-2 (seq 2).
    let mut rx = st.subscribe(VID);
    let p2 = serde_json::to_vec(&PushRequest {
        ops: vec![op("A", "op-2")],
    })
    .unwrap();
    assert_eq!(
        send(&st, signed("POST", &push_uri, &p2, &dev_a, "A", "n3"))
            .await
            .0,
        StatusCode::OK
    );
    // The subscriber receives exactly op-2 (seq 2) — never the pre-seeded op-1 — and nothing more.
    let stored: crate::dto::StoredOp =
        serde_json::from_str(&rx.try_recv().expect("the new op")).unwrap();
    assert_eq!((stored.op_id.as_str(), stored.seq), ("op-2", 2));
    assert!(
        rx.try_recv().is_err(),
        "only this push's single op should have been published"
    );
}

#[tokio::test]
async fn create_with_mismatched_proof_is_401() {
    let st = state();
    let dev_a = SigningKey::generate(&mut OsRng);
    // Verifier hash is SHA-256(SECRET) but the proof is a different secret → 401, and no
    // account is created (a follow-up correct create then succeeds).
    let enroll = crate::dto::EnrollVerifier {
        salt_b64: b64e(b"enrol-salt-16byte"),
        params: terrapi_vesta::KdfParams::default(),
        hash_b64: b64e(Sha256::digest(SECRET)),
    };
    let bad = serde_json::to_vec(&CreateAccountRequest {
        enroll: enroll.clone(),
        proof_b64: b64e(b"the-wrong-secret"),
        device: crate::dto::DeviceRegistration {
            device_id: "A".into(),
            pubkey_b64: b64e(dev_a.verifying_key().to_bytes()),
        },
    })
    .unwrap();
    let acct = format!("/v1/sync/{VID}/account");
    let (status, _) = send(&st, signed("POST", &acct, &bad, &dev_a, "A", "n1")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A correct create still works (the bad attempt committed nothing).
    let good = create_body(&dev_a, "A");
    let (status, _) = send(&st, signed("POST", &acct, &good, &dev_a, "A", "n2")).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn non_uuid_vesta_id_is_400() {
    let st = state();
    // A bogus (non-UUIDv4) vault id is rejected at the extractor, before any store touch.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/sync/not-a-uuid/enroll-challenge")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&st, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let e: ErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(e.error, "bad_vesta_id");
}

/// End-to-end live tail over a real WebSocket: an enrolled device opens a (device-signed)
/// `/tail` upgrade, then a push fans the new op out and the socket receives it as a text
/// frame. Exercises the WS auth + framing path the oneshot tests can't reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tail_websocket_receives_pushed_op() {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let st = state();
    let dev_a = SigningKey::generate(&mut OsRng);
    // Enrol device A directly in the store (the create/enrol HTTP flow is covered elsewhere).
    let enroll = crate::dto::EnrollVerifier {
        salt_b64: b64e(b"enrol-salt-16byte"),
        params: terrapi_vesta::KdfParams::default(),
        hash_b64: b64e(Sha256::digest(SECRET)),
    };
    st.store
        .create_account(VID, &enroll, "A", &dev_a.verifying_key().to_bytes())
        .unwrap();

    // Start a real server on an ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(st.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Build the device-signed WS upgrade (signed exactly like a GET over an empty body).
    let path = format!("/v1/sync/{VID}/tail");
    let ts = now_unix();
    let canonical = auth::canonical_string("GET", &path, VID, ts, "ws1", &auth::sha256_hex(b""));
    let sig = b64e(dev_a.sign(canonical.as_bytes()).to_bytes());
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    let h = req.headers_mut();
    h.insert("x-device-id", "A".parse().unwrap());
    h.insert("x-sync-ts", ts.to_string().parse().unwrap());
    h.insert("x-sync-nonce", "ws1".parse().unwrap());
    h.insert("x-sync-sig", sig.parse().unwrap());
    let (mut ws, _resp) = tokio_tungstenite::connect_async(req).await.unwrap();

    // The handshake completed → the handler subscribed. Now fan an op out (as push does).
    let stored = crate::dto::StoredOp::from_op(1, op("A", "op-1"));
    st.publish(VID, &[serde_json::to_string(&stored).unwrap()]);

    // The socket receives the op as a JSON text frame.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("frame within timeout")
        .expect("a frame")
        .expect("ok frame");
    let txt = match msg {
        Message::Text(t) => t.to_string(),
        other => panic!("expected text frame, got {other:?}"),
    };
    let got: crate::dto::StoredOp = serde_json::from_str(&txt).unwrap();
    assert_eq!(got.op_id, "op-1");
    assert_eq!(got.seq, 1);
}
