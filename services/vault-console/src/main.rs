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
    check_dev_safety(&cfg);
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

/// Refuse the dangerous combinations of `VAULT_CONSOLE_ALLOW_INSECURE_DEV=1`. That single flag
/// both bypasses operator auth (every request becomes the `dev` operator) and disables broker-cert
/// verification, so a mis-set var in production would fully open the console. Fail-closed:
///   * with a non-loopback bind — it must stay on the local host (it has no operator auth); and
///   * together with mTLS material (`VAULT_CONSOLE_TLS_*`) — that pairing is a production downgrade
///     (auth bypassed despite a real prod config).
fn check_dev_safety(cfg: &config::ConsoleConfig) {
    if !cfg.allow_insecure_dev {
        return;
    }
    if !cfg.bind.ip().is_loopback() {
        eprintln!(
            "vault-console: VAULT_CONSOLE_ALLOW_INSECURE_DEV=1 with a non-loopback bind ({}) is \
             refused: insecure dev bypasses operator auth AND broker-cert verification and must \
             stay on the local host. Bind 127.0.0.1 for dev, or unset the flag and provide \
             VAULT_CONSOLE_TLS_* + OIDC for production.",
            cfg.bind
        );
        std::process::exit(1);
    }
    if cfg.tls.is_some() {
        eprintln!(
            "vault-console: VAULT_CONSOLE_ALLOW_INSECURE_DEV=1 together with VAULT_CONSOLE_TLS_* \
             is refused: it bypasses operator auth while mTLS material is configured (a production \
             downgrade). Unset the dev flag for production, or remove the TLS material for dev."
        );
        std::process::exit(1);
    }
    eprintln!(
        "vault-console: WARNING VAULT_CONSOLE_ALLOW_INSECURE_DEV=1 — operator auth bypassed and \
         broker certs unverified on {}. Local development only.",
        cfg.bind
    );
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
