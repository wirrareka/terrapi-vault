//! Live oplog tail over WebSocket.
use super::{auth_registered, paq, VestaId};
use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method};
use axum::response::{IntoResponse, Response};
use tokio::sync::broadcast;

/// `GET /v1/sync/{vesta_id}/tail` — WebSocket live tail. The upgrade request is device-signed
/// exactly like a GET (empty body); after it verifies, the socket streams each newly-pushed
/// `StoredOp` as a JSON text frame. A subscriber that falls behind the buffer is sent
/// `{"resync":true}` and should do a full `pull`.
pub(crate) async fn tail(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(rejection) =
        auth_registered(&state, &method, &paq(&uri), &vesta_id, &headers, b"").await
    {
        return rejection.into_response();
    }
    let rx = state.subscribe(&vesta_id);
    ws.on_upgrade(move |socket| tail_loop(socket, rx))
}

pub(crate) async fn tail_loop(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        tokio::select! {
            // Detect client close / error so the task ends and the receiver is dropped.
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    _ => {}
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = socket.send(Message::Text("{\"resync\":true}".into())).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}
