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
mod http;
mod state;
mod store;

use config::Config;
use state::AppState;
use store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::from_env();
    eprintln!(
        "vault-sync {} starting: bind={} db={}",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        cfg.db_path,
    );

    let store = Store::open(&cfg.db_path)?;
    let bind = cfg.bind;
    let state = AppState::new(cfg, store);

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
