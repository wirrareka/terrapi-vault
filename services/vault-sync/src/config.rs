//! vault-sync configuration (env, with local-dev defaults). Personal, single-user; no
//! residency, no tenants, no platform knobs.

use std::net::SocketAddr;
use std::time::Duration;

/// Default body cap for a `push` batch. Ops carry ciphertext, so batches can be larger than
/// the broker's tiny JSON; 16 MiB is generous for personal sync.
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Hard cap on how many ops a single `pull` returns (the client pages with `since`).
pub const DEFAULT_MAX_PULL: u32 = 500;
/// Max concurrently-executing requests. The store is one serialised SQLite connection, so this
/// bounds queued work (excess → `503`) rather than letting a misbehaving client pile up.
pub const DEFAULT_MAX_CONCURRENCY: usize = 64;
/// Per-request time budget (excess → `408`). The `/tail` WebSocket upgrade returns immediately,
/// so this does not cap the live socket's lifetime.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db_path: String,
    pub max_body_bytes: usize,
    pub max_pull: u32,
    pub max_concurrency: usize,
    pub request_timeout: Duration,
}

impl Config {
    /// Load from env. `VAULT_SYNC_BIND` (default `127.0.0.1:8300`), `VAULT_SYNC_DB`
    /// (default `vault-sync.db`), `VAULT_SYNC_MAX_BODY_BYTES`, `VAULT_SYNC_MAX_PULL`.
    #[must_use]
    pub fn from_env() -> Self {
        let bind = std::env::var("VAULT_SYNC_BIND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8300".parse().expect("valid default addr"));
        let db_path = std::env::var("VAULT_SYNC_DB").unwrap_or_else(|_| "vault-sync.db".to_owned());
        let max_body_bytes = std::env::var("VAULT_SYNC_MAX_BODY_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);
        let max_pull = std::env::var("VAULT_SYNC_MAX_PULL")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_PULL);
        let max_concurrency = std::env::var("VAULT_SYNC_MAX_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_CONCURRENCY);
        let request_timeout = std::env::var("VAULT_SYNC_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map_or_else(
                || Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
                Duration::from_secs,
            );
        Self {
            bind,
            db_path,
            max_body_bytes,
            max_pull,
            max_concurrency,
            request_timeout,
        }
    }
}
