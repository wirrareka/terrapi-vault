//! Shared vault-sync server state: config, the SQLite op store (serialised — the connection
//! is `!Sync`), and the replay guard.

use crate::auth::ReplayGuard;
use crate::config::Config;
use crate::store::Store;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Mutex<Store>>,
    pub replay: Arc<ReplayGuard>,
}

impl AppState {
    #[must_use]
    pub fn new(cfg: Config, store: Store) -> Self {
        Self {
            cfg: Arc::new(cfg),
            store: Arc::new(Mutex::new(store)),
            replay: Arc::new(ReplayGuard::default()),
        }
    }
}
