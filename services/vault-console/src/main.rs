//! vault-console — operator web/API console for terrapi-vault, one per residency group.
//! Read-only observability that aggregates the group's brokers' `observe` API over mTLS-over-WG.
//! NEVER surfaces a secret value. See `docs/planning/02-vault-console.md`.
//!
//! P1a: the `/api/v1/*` API (broker fan-out + dev auth stub). The SPA (`web/`) is served by the
//! Vite dev proxy in dev; embedding + OIDC RP land in later slices.

mod broker;
mod config;
mod http;
mod ui;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    let cfg = config::ConsoleConfig::from_env().unwrap_or_else(|e| {
        eprintln!("vault-console: config error: {e}");
        std::process::exit(1);
    });
    let hub = broker::BrokerHub::new(&cfg).unwrap_or_else(|e| {
        eprintln!("vault-console: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "vault-console: group={} brokers={} dev={}",
        cfg.residency_group,
        cfg.brokers.len(),
        cfg.allow_insecure_dev,
    );

    let state = http::AppState {
        hub: Arc::new(hub),
        dev: cfg.allow_insecure_dev,
    };
    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("vault-console: bind {} failed: {e}", cfg.bind);
            std::process::exit(1);
        });
    eprintln!("vault-console: listening on {}", cfg.bind);
    axum::serve(listener, http::router(state))
        .await
        .expect("server error");
}
