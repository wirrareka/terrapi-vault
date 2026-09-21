use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use terrapi_vesta_replication::{api::Api, coordinator::Coordinator, *};
use tower::ServiceExt;

struct ControlledReplica {
    node: Node,
    offline: Arc<AtomicBool>,
    stall: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
}
impl Replica for ControlledReplica {
    fn summary(&mut self) -> Result<journal::Summary> {
        if self.stall.load(Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(500));
        }
        if self.offline.load(Ordering::SeqCst) {
            return Err("fixture offline".into());
        }
        self.node.summary()
    }
    fn journal_page(
        &mut self,
        head: &journal::JournalHead,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage> {
        self.node.journal_page(head, after, limit)
    }
    fn confirm_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<()> {
        self.node.confirm_checkpoint(checkpoint)
    }
    fn status(&mut self) -> Result<Status> {
        if self.stall.load(Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(500));
        }
        if self.offline.load(Ordering::SeqCst) {
            return Err("fixture offline".into());
        }
        self.node.status()
    }
    fn view(&mut self) -> Result<View> {
        self.node.view()
    }
    fn stage(&mut self, e: Entry) -> Result<()> {
        self.node.stage(e)
    }
    fn apply(&mut self, e: Entry) -> Result<()> {
        self.node.apply(e)
    }
    fn abort(&mut self, id: &str) -> Result<()> {
        self.node.abort(id)
    }
}
fn identity() -> Identity {
    Identity {
        cluster: "test".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}
fn batch(id: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: id.into(),
            name: "Airport".into(),
        }],
    }
}
fn write_request(id: &str) -> Request<Body> {
    Request::post("/transactions")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&batch(id)).unwrap()))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_reads_are_independent_of_blocked_writes_and_ui_sees_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let offline = Arc::new(AtomicBool::new(false));
    let stall = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let p = Node::open(
        dir.path().join("p.vesta"),
        Role::Primary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let api = Api::new(
        Coordinator::new(
            p,
            ControlledReplica {
                node: s,
                offline: offline.clone(),
                stall: stall.clone(),
                entered: entered.clone(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    let app = api.router();
    let response = app.clone().oneshot(write_request("one")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    offline.store(true, Ordering::SeqCst);
    stall.store(true, Ordering::SeqCst);
    let writing = tokio::spawn(app.clone().oneshot(write_request("two")));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let start = Instant::now();
    let response = app
        .clone()
        .oneshot(Request::get("/view").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(start.elapsed() < Duration::from_millis(200));
    assert_eq!(response.status(), StatusCode::OK);
    let value: View =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(value.places.len(), 1);
    let busy = app.clone().oneshot(write_request("three")).await.unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response = writing.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let capabilities = app
        .clone()
        .oneshot(Request::get("/capabilities").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(capabilities.into_body(), 2048).await.unwrap()).unwrap();
    assert_eq!(value["readable"], true);
    assert_eq!(value["writable"], false);
    assert_eq!(
        app.clone()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    offline.store(false, Ordering::SeqCst);
    stall.store(false, Ordering::SeqCst);
    api.reconcile().await.unwrap();
    assert_eq!(
        app.clone()
            .oneshot(write_request("two"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(write_request("two"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let large = app
        .oneshot(
            Request::post("/transactions")
                .header("content-type", "application/json")
                .body(Body::from("x".repeat(network::MAX_FRAME + 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(large.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
