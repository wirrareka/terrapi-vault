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
    // at-rest model guards — never expose them on the public API surface).
    let metrics_bind =
        std::env::var("VAULT_SYNC_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:8301".to_owned());
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

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("vault-sync listening on {bind}");
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("vault-sync: shutting down");
}
