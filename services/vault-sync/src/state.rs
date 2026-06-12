//! Shared vault-sync server state: config, the SQLite op store (serialised — the connection
//! is `!Sync`), and the replay guard.

use crate::auth::ReplayGuard;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::ratelimit::KeyedRateBucket;
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
    /// Per-vault token bucket guarding the unauthenticated `enroll-challenge` (read) endpoint.
    /// Keyed by `vault_id` so probing one vault cannot throttle another.
    pub challenge_rl: Arc<KeyedRateBucket>,
    /// Separate per-vault token bucket for the unauthenticated `account` + `enroll` (write)
    /// endpoints, so a flood of cheap `enroll-challenge` probes cannot starve the owner's actual
    /// account/enrol requests (their availability is decoupled from the challenge surface), and
    /// abuse of one vault cannot starve another.
    pub enroll_rl: Arc<KeyedRateBucket>,
    /// Global concurrency permits — bounds requests executing against the serialised store.
    pub sem: Arc<tokio::sync::Semaphore>,
    /// Prometheus metrics, scraped on the loopback metrics listener.
    pub metrics: Arc<Metrics>,
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
            challenge_rl: Arc::new(KeyedRateBucket::default()),
            enroll_rl: Arc::new(KeyedRateBucket::default()),
            sem,
            metrics: Arc::new(Metrics::default()),
            tails: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Current number of live-tail subscribers across all vaults (for the metrics gauge).
    #[must_use]
    pub fn tail_subscriber_count(&self) -> u64 {
        let tails = self.tails.lock().expect("tails lock");
        tails
            .values()
            .map(|tx| u64::try_from(tx.receiver_count()).unwrap_or(0))
            .sum()
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
