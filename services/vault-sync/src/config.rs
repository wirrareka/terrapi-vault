//! vault-sync configuration (env, with local-dev defaults). Personal, single-user; no
//! residency, no tenants, no platform knobs.

use std::net::SocketAddr;
use std::time::Duration;
use vault_transport::http::env_parse;

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
/// Read-only SQLite connections beside the writer. WAL allows concurrent readers, so
/// `pull`/`status`/tail-reads fan across these (run in `spawn_blocking`) while writes
/// serialise on the single writer.
pub const DEFAULT_READERS: usize = 4;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db_path: String,
    pub max_body_bytes: usize,
    pub max_pull: u32,
    pub max_concurrency: usize,
    pub request_timeout: Duration,
    pub readers: usize,
}

impl Config {
    /// Load from env. `VAULT_SYNC_BIND` (default `127.0.0.1:8300`), `VAULT_SYNC_DB`
    /// (default `vault-sync.db`), `VAULT_SYNC_MAX_BODY_BYTES`, `VAULT_SYNC_MAX_PULL`.
    #[must_use]
    pub fn from_env() -> Self {
        let bind = env_parse("VAULT_SYNC_BIND")
            .unwrap_or_else(|| "127.0.0.1:8300".parse().expect("valid default addr"));
        let db_path = std::env::var("VAULT_SYNC_DB").unwrap_or_else(|_| "vault-sync.db".to_owned());
        let max_body_bytes =
            env_parse("VAULT_SYNC_MAX_BODY_BYTES").unwrap_or(DEFAULT_MAX_BODY_BYTES);
        let max_pull = env_parse("VAULT_SYNC_MAX_PULL")
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_PULL);
        let max_concurrency = env_parse("VAULT_SYNC_MAX_CONCURRENCY")
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_CONCURRENCY);
        let request_timeout = env_parse("VAULT_SYNC_REQUEST_TIMEOUT_SECS").map_or_else(
            || Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            Duration::from_secs,
        );
        let readers = env_parse("VAULT_SYNC_READERS")
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_READERS);
        Self {
            bind,
            db_path,
            max_body_bytes,
            max_pull,
            max_concurrency,
            request_timeout,
            readers,
        }
    }
}
