//! vesta-sync configuration (env, with local-dev defaults). Personal, single-user; no
//! residency, no tenants, no platform knobs.

use std::net::SocketAddr;
use std::time::Duration;
use vesta_transport::http::env_parse;

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

/// The SQLCipher passphrase for the server DB, kept out of any `Debug` output (`Config`
/// derives `Debug`). When present, every store connection is opened with `PRAGMA key` so the
/// DB — and its WAL — are encrypted at rest, protecting the **metadata** (op/device counts,
/// timing, sizes, cleartext `collection_id`, device pubkeys) a stolen disk would otherwise
/// expose. The content is already E2E-encrypted regardless. See `docs/planning/02-...` §threat.
#[derive(Clone)]
pub struct DbKey(pub String);

impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DbKey(***redacted***)")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db_path: String,
    /// `Some` → SQLCipher-encrypt the DB at rest with this passphrase; `None` → plain SQLite.
    pub db_key: Option<DbKey>,
    pub max_body_bytes: usize,
    pub max_pull: u32,
    pub max_concurrency: usize,
    pub request_timeout: Duration,
    pub readers: usize,
}

impl Config {
    /// Load from env. `VESTA_SYNC_BIND` (default `127.0.0.1:8300`), `VESTA_SYNC_DB`
    /// (default `vesta-sync.db`), `VESTA_SYNC_MAX_BODY_BYTES`, `VESTA_SYNC_MAX_PULL`.
    #[must_use]
    pub fn from_env() -> Self {
        let bind = env_parse("VESTA_SYNC_BIND")
            .unwrap_or_else(|| "127.0.0.1:8300".parse().expect("valid default addr"));
        let db_path = std::env::var("VESTA_SYNC_DB").unwrap_or_else(|_| "vesta-sync.db".to_owned());
        let db_key = load_db_key();
        let max_body_bytes =
            env_parse("VESTA_SYNC_MAX_BODY_BYTES").unwrap_or(DEFAULT_MAX_BODY_BYTES);
        let max_pull = env_parse("VESTA_SYNC_MAX_PULL")
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_PULL);
        let max_concurrency = env_parse("VESTA_SYNC_MAX_CONCURRENCY")
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_CONCURRENCY);
        let request_timeout = env_parse("VESTA_SYNC_REQUEST_TIMEOUT_SECS").map_or_else(
            || Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            Duration::from_secs,
        );
        let readers = env_parse("VESTA_SYNC_READERS")
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_READERS);
        Self {
            bind,
            db_path,
            db_key,
            max_body_bytes,
            max_pull,
            max_concurrency,
            request_timeout,
            readers,
        }
    }
}

/// The SQLCipher passphrase from `VESTA_SYNC_DB_KEY`, or `VESTA_SYNC_DB_KEY_FILE` (a mode-600
/// file — preferred so the secret is not in the process environment). Env wins; trailing
/// newline trimmed. `None` (neither set) → plain SQLite at rest.
fn load_db_key() -> Option<DbKey> {
    if let Ok(k) = std::env::var("VESTA_SYNC_DB_KEY") {
        if !k.is_empty() {
            return Some(DbKey(k));
        }
    }
    let path = std::env::var("VESTA_SYNC_DB_KEY_FILE").ok()?;
    warn_if_group_or_world_readable("VESTA_SYNC_DB_KEY_FILE", &path);
    match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Some(DbKey(s.trim_end_matches(['\n', '\r']).to_owned())),
        _ => None,
    }
}

/// Loudly warn (don't silently accept) if a secret file is readable by group/other — the agent
/// finding was that a world-readable key loaded with no signal. Unix only.
#[cfg(unix)]
pub fn warn_if_group_or_world_readable(label: &str, path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "WARNING: {label} {path} is mode {mode:o} — group/other can read this secret; chmod 600 it."
            );
        }
    }
}
#[cfg(not(unix))]
pub fn warn_if_group_or_world_readable(_label: &str, _path: &str) {}
