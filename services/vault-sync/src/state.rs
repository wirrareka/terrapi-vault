//! Shared vault-sync server state: config, the SQLite op store (serialised — the connection
//! is `!Sync`), and the replay guard.

use crate::auth::ReplayGuard;
use crate::config::Config;
use crate::ratelimit::RateBucket;
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
    /// The op store. `Store` manages its own writer/reader connection mutexes internally, so it
    /// is `Send + Sync` and shared directly (no outer mutex) — handlers drive it via
    /// `spawn_blocking`, off the async runtime.
    pub store: Arc<Store>,
    pub replay: Arc<ReplayGuard>,
    /// Token bucket guarding the unauthenticated `enroll-challenge` endpoint.
    pub challenge_rl: Arc<RateBucket>,
    /// Global concurrency permits — bounds requests executing against the serialised store.
    pub sem: Arc<tokio::sync::Semaphore>,
    /// Per-`vault_id` broadcast of newly-pushed ops (pre-serialised JSON) to live-tail
    /// WebSocket subscribers. Created lazily on first subscribe; the message is a `StoredOp`.
    tails: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
}

impl AppState {
    #[must_use]
    pub fn new(cfg: Config, store: Store) -> Self {
        let sem = Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrency));
        Self {
            cfg: Arc::new(cfg),
            store: Arc::new(store),
            replay: Arc::new(ReplayGuard::default()),
            challenge_rl: Arc::new(RateBucket::default()),
            sem,
            tails: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Subscribe to the live tail for `vault_id` (creating its channel on first use).
    #[must_use]
    pub fn subscribe(&self, vault_id: &str) -> broadcast::Receiver<String> {
        let mut tails = self.tails.lock().expect("tails lock");
        // Drop channels nobody is listening to any more so the map is bounded by the number of
        // vaults with a live subscriber — not by every vault_id ever tailed.
        tails.retain(|_, tx| tx.receiver_count() > 0);
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
