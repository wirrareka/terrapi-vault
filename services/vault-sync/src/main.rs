//! vault-sync — personal multi-device vault sync for memento/probe (Svet B).
//!
//! Server-blind row-level **oplog**: stores only opaque encrypted ops (`{op_id, device_id,
//! hlc, collection_id, encrypted_payload}`) partitioned by `vault_id`, plus device public
//! keys and an enrolment verifier. Never holds the vault key or plaintext. Device-keypair
//! (ed25519) request auth; enrolment via a passphrase-derived secret (Argon2 verifier).
//! Per-row LWW / CRDT live client-side. Carries NONE of the platform (no OpenSearch, tenants,
//! residency). See `docs/planning/02-vault-sync-oplog.md`.

mod auth;
mod config;
mod dto;
mod harden;
mod http;
mod metrics;
mod ratelimit;
mod state;
mod store;

use config::Config;
use state::AppState;
use store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::from_env();
    let at_rest = if cfg.db_key.is_some() {
        "encrypted (SQLCipher)"
    } else {
        "PLAINTEXT — set VAULT_SYNC_DB_KEY[_FILE] to encrypt metadata at rest"
    };
    eprintln!(
        "vault-sync {} starting: bind={} db={} at-rest={}",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        cfg.db_path,
        at_rest,
    );

    let key = cfg.db_key.as_ref().map(|k| k.0.as_str());
    let store = Store::open(&cfg.db_path, cfg.readers, key).map_err(|e| {
        let hint = if key.is_some() {
            " — wrong VAULT_SYNC_DB_KEY, or the DB exists and is not SQLCipher-encrypted?"
        } else {
            ""
        };
        format!("vault-sync: cannot open DB at {}: {e}{hint}", cfg.db_path)
    })?;
    let bind = cfg.bind;
    let state = AppState::new(cfg, store);

    // Prometheus metrics on a loopback-only listener (op/device counts are the metadata the
    // at-rest model guards — never expose them on the public API surface). Refuse a non-loopback
    // bind (fail-closed: disable the listener) unless explicitly opted in.
    let metrics_bind =
        std::env::var("VAULT_SYNC_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:8301".to_owned());
    if metrics_bind_allowed(&metrics_bind, "VAULT_SYNC_METRICS_ALLOW_PUBLIC") {
        let metrics_state = state.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&metrics_bind).await {
                Ok(l) => {
                    eprintln!("vault-sync: metrics on http://{metrics_bind}/metrics");
                    let _ = axum::serve(l, http::metrics_router(metrics_state)).await;
                }
                Err(e) => eprintln!("vault-sync: metrics listener disabled ({e})"),
            }
        });
    } else {
        eprintln!(
            "vault-sync: metrics listener DISABLED — {metrics_bind} is not loopback; /metrics \
             exposes op/device counts. Bind 127.0.0.1, or set VAULT_SYNC_METRICS_ALLOW_PUBLIC=1."
        );
    }

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("vault-sync listening on {bind}");
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Whether a metrics listener may bind `bind` without the explicit allow-public override.
/// Safe (allowed): loopback + RFC1918-private / link-local IPv4 (a personal host / WG bind) and
/// IPv6 loopback. Refused unless `allow_env` is `1`: `0.0.0.0`/`::`, any routable-public address,
/// and an unparseable bind (fail-closed).
fn metrics_bind_allowed(bind: &str, allow_env: &str) -> bool {
    let safe = match bind.parse::<std::net::SocketAddr>() {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        },
        Err(_) => false,
    };
    safe || std::env::var(allow_env).as_deref() == Ok("1")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("vault-sync: shutting down");
}
