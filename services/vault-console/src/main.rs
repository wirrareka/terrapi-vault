//! vault-console — operator web/API console for terrapi-vault, one per residency group.
//! Read-only observability that aggregates the group's brokers' `observe` API over mTLS-over-WG.
//! NEVER surfaces a secret value. See `docs/planning/02-vault-console.md`.
//!
//! P1b: the `/api/v1/*` API (broker fan-out) + OIDC RP login (identity, `private_key_jwt`,
//! `acr=mfa`). The SPA (`web/`) is served by the Vite dev proxy in dev; embedded in release.

mod broker;
mod config;
mod http;
mod oidc;
mod session;
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

    // OIDC RP (P1b): built only when configured. Discovery runs here so a bad issuer fails fast.
    let oidc = build_oidc(&cfg).await;

    eprintln!(
        "vault-console: group={} brokers={} oidc={} dev={}",
        cfg.residency_group,
        cfg.brokers.len(),
        oidc.is_some(),
        cfg.allow_insecure_dev,
    );

    let state = http::AppState {
        hub: Arc::new(hub),
        oidc,
        sessions: Arc::new(session::Sessions::default()),
        pending: Arc::new(session::PendingAuth::default()),
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

/// Build the OIDC RP if configured; exit on an init failure (a bad issuer should not boot a
/// console that can never log anyone in). Returns `None` when OIDC is unconfigured.
async fn build_oidc(cfg: &config::ConsoleConfig) -> Option<Arc<oidc::OidcClient>> {
    let Some(oc) = cfg.oidc.clone() else {
        if !cfg.allow_insecure_dev {
            eprintln!(
                "vault-console: WARNING no VAULT_CONSOLE_OIDC_ISSUER and not dev → all /api/v1 reads will 401"
            );
        }
        return None;
    };
    match oidc::OidcClient::build(oc).await {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            eprintln!("vault-console: OIDC init failed: {e}");
            std::process::exit(1);
        }
    }
}
