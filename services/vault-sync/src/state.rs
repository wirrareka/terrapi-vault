//! Shared vault-sync server state: config, the SQLite op store (serialised — the connection
//! is `!Sync`), and the replay guard.

use crate::auth::ReplayGuard;
use crate::config::Config;
use crate::store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Capacity of each per-vault live-tail broadcast buffer. A slow WS subscriber that falls
/// further behind than this is told to resync (full `pull`) rather than the server buffering
/// unboundedly.
const TAIL_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Mutex<Store>>,
    pub replay: Arc<ReplayGuard>,
    /// Per-`vault_id` broadcast of newly-pushed ops (pre-serialised JSON) to live-tail
    /// WebSocket subscribers. Created lazily on first subscribe; the message is a `StoredOp`.
    tails: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
}

impl AppState {
    #[must_use]
    pub fn new(cfg: Config, store: Store) -> Self {
        Self {
            cfg: Arc::new(cfg),
            store: Arc::new(Mutex::new(store)),
            replay: Arc::new(ReplayGuard::default()),
            tails: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Subscribe to the live tail for `vault_id` (creating its channel on first use).
    #[must_use]
    pub fn subscribe(&self, vault_id: &str) -> broadcast::Receiver<String> {
        let mut tails = self.tails.lock().expect("tails lock");
        tails
            .entry(vault_id.to_owned())
            .or_insert_with(|| broadcast::channel(TAIL_CAPACITY).0)
            .subscribe()
    }

    /// Fan out freshly-stored ops to any live-tail subscribers of `vault_id`. No-op if none.
    pub fn publish(&self, vault_id: &str, messages: &[String]) {
        let tails = self.tails.lock().expect("tails lock");
        if let Some(tx) = tails.get(vault_id) {
            for m in messages {
                // `send` errors only when there are no receivers — harmless here.
                let _ = tx.send(m.clone());
            }
        }
    }
}
