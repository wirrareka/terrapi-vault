//! Test/demo Axum adapter. No user authentication: do not expose publicly.
use crate::{
    coordinator::{Capabilities, Coordinator, Outcome, WriteFailure},
    *,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::{
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

struct Cache {
    view: Option<View>,
    capabilities: Capabilities,
    observed: Instant,
}
struct Inner<R: Replica> {
    gate: Mutex<Coordinator<R>>,
    cache: RwLock<Cache>,
    permit: Arc<Semaphore>,
}
pub struct Api<R: Replica> {
    inner: Arc<Inner<R>>,
}
impl<R: Replica> Clone for Api<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
fn failure(id: String, reason: &str) -> WriteFailure {
    WriteFailure {
        status_code: 503,
        operation_id: id,
        outcome: Outcome::Unknown,
        retry_same_operation_id: true,
        reason: reason.into(),
    }
}
impl IntoResponse for WriteFailure {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(self),
        )
            .into_response()
    }
}
impl<R: Replica + Send + 'static> Api<R> {
    pub fn new(gate: Coordinator<R>) -> Result<Self> {
        let view = gate.view()?;
        let capabilities = gate.capabilities();
        Ok(Self {
            inner: Arc::new(Inner {
                gate: Mutex::new(gate),
                cache: RwLock::new(Cache {
                    view: Some(view),
                    capabilities,
                    observed: Instant::now(),
                }),
                permit: Arc::new(Semaphore::new(1)),
            }),
        })
    }
    pub fn router(&self) -> Router {
        Router::new()
            .route("/view", get(read_view::<R>))
            .route("/capabilities", get(capabilities::<R>))
            .route("/health/ready", get(ready::<R>))
            .route("/transactions", post(write::<R>))
            .layer(DefaultBodyLimit::max(network::MAX_FRAME))
            .layer(axum::middleware::from_fn(
                |request: axum::extract::Request, next: axum::middleware::Next| async move {
                    let mut response = next.run(request).await;
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        header::HeaderValue::from_static("no-store"),
                    );
                    response
                },
            ))
            .with_state(self.clone())
    }
    /// Host may call periodically; GET health/capabilities never initiates recovery writes.
    pub async fn reconcile(&self) -> std::result::Result<usize, WriteFailure> {
        self.run(String::new(), |gate| {
            gate.reconcile()
                .map_err(|_| failure(String::new(), "recovery_required"))
        })
        .await
    }
    async fn run<T: Send + 'static>(
        &self,
        id: String,
        operation: impl FnOnce(&mut Coordinator<R>) -> std::result::Result<T, WriteFailure>
            + Send
            + 'static,
    ) -> std::result::Result<T, WriteFailure> {
        // No unbounded queue of blocking DB jobs. Reads use another lock and stay independent.
        let permit = self
            .inner
            .permit
            .clone()
            .try_acquire_owned()
            .map_err(|_| failure(id.clone(), "writer_busy"))?;
        let inner = self.inner.clone();
        let operation_id = id.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut gate = inner
                .gate
                .lock()
                .map_err(|_| failure(operation_id.clone(), "writer_failed"))?;
            let result = operation(&mut gate);
            let view = gate.view().ok();
            let mut capabilities = gate.capabilities();
            if view.is_none() {
                capabilities.readable = false;
                capabilities.writable = false;
                capabilities.reason = "local_read_failed".into();
            }
            let read_ok = view.is_some();
            *inner
                .cache
                .write()
                .map_err(|_| failure(operation_id.clone(), "cache_failed"))? = Cache {
                view,
                capabilities,
                observed: Instant::now(),
            };
            if !read_ok {
                return Err(failure(operation_id, "local_read_failed"));
            }
            result
        })
        .await;
        match result {
            Ok(value) => value,
            Err(_) => {
                if let Ok(mut cache) = self.inner.cache.write() {
                    cache.capabilities.writable = false;
                    cache.capabilities.reason = "writer_failed".into();
                }
                Err(failure(id, "writer_failed"))
            }
        }
    }
    fn cached_capabilities(&self) -> Capabilities {
        let Ok(cache) = self.inner.cache.read() else {
            return Capabilities {
                readable: false,
                writable: false,
                reason: "cache_failed".into(),
            };
        };
        let mut capabilities = cache.capabilities.clone();
        if capabilities.writable && cache.observed.elapsed() >= Duration::from_secs(1) {
            capabilities.writable = false;
            capabilities.reason = "verification_expired".into();
        }
        capabilities
    }
}
async fn read_view<R: Replica + Send + 'static>(State(api): State<Api<R>>) -> Response {
    let view = api.inner.cache.read().ok().and_then(|c| c.view.clone());
    match view {
        Some(view) => Json(view).into_response(),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
async fn capabilities<R: Replica + Send + 'static>(
    State(api): State<Api<R>>,
) -> Json<Capabilities> {
    Json(api.cached_capabilities())
}
async fn ready<R: Replica + Send + 'static>(State(api): State<Api<R>>) -> StatusCode {
    if api.cached_capabilities().readable {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn write<R: Replica + Send + 'static>(
    State(api): State<Api<R>>,
    Json(batch): Json<Batch>,
) -> Response {
    match api
        .run(batch.operation_id.clone(), move |gate| gate.write(batch))
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(error) => error.into_response(),
    }
}
