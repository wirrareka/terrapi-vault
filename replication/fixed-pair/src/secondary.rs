//! Read-only HTTP projection of a secondary. No writer/coordinator is reachable here.
use crate::{coordinator::Capabilities, *};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct ReadOnlyApi {
    view: Arc<RwLock<Option<View>>>,
}
impl ReadOnlyApi {
    pub fn invalidate(&self) {
        if let Ok(mut view) = self.view.write() {
            *view = None;
        }
    }
    /// Build the view outside the cache lock; reads never wait on TLS or SQLite.
    pub fn refresh(&self, node: &Node) -> Result<()> {
        if node.role != Role::Secondary {
            self.invalidate();
            return Err("secondary projection requires secondary node".into());
        }
        let view = match node.verified_view() {
            Ok(v) => v,
            Err(e) => {
                self.invalidate();
                return Err(e);
            }
        };
        *self.view.write().map_err(|_| "secondary cache poisoned")? = view;
        Ok(())
    }
    fn capabilities(&self) -> Capabilities {
        let readable = self.view.read().is_ok_and(|v| v.is_some());
        Capabilities {
            readable,
            writable: false,
            reason: if readable {
                "secondary_read_only"
            } else {
                "secondary_cache_unavailable"
            }
            .into(),
        }
    }
    pub fn router(&self) -> Router {
        Router::new()
            .route("/view", get(read_view))
            .route("/capabilities", get(capabilities))
            .route("/health/ready", get(ready))
            .route("/transactions", post(reject_write))
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
}
async fn read_view(State(api): State<ReadOnlyApi>) -> Response {
    match api.view.read().ok().and_then(|v| v.clone()) {
        Some(view) => Json(view).into_response(),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
async fn capabilities(State(api): State<ReadOnlyApi>) -> Json<Capabilities> {
    Json(api.capabilities())
}
async fn ready(State(api): State<ReadOnlyApi>) -> StatusCode {
    if api.capabilities().readable {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn reject_write() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"reason":"secondary_read_only","retry_same_operation_id":true})),
    )
        .into_response()
}
