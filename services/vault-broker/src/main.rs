//! vault-broker — proximi.io network secrets broker (Path A). Phase 1 skeleton.
//!
//! Wired now: axum listener on `8200`, the full v1 route surface, an authenticated
//! `Principal` boundary (mTLS-over-WG model; rustls termination is the next step),
//! a real session/lease engine with cascade-revoke, and a B3 audit emitter
//! (`source:"vault"`). SSH-CA signing + dynamic creds (OpenSearch RBAC / RethinkDB)
//! are typed `501` stubs with their contract shapes fixed. See
//! ../../docs/planning/01-vault-as-service.md §4 and ../../spec/broker-openapi.yaml.

mod auth;
mod config;
mod dto;
mod http;
mod seal;
mod state;

use config::BrokerConfig;
use state::AppState;
use terrapi_vault::KdfParams;

/// Attempt a boot-time unseal. Dev mode auto-unseals (ephemeral key); production requires
/// `VAULT_UNSEAL_PASSPHRASE` and verifies it against the seal sidecar. A failed/absent
/// unseal is non-fatal: the broker starts SEALED and mutating ops `503` until it is
/// restarted with a valid passphrase.
fn boot_unseal(cfg: &BrokerConfig) -> Option<seal::Unsealed> {
    if cfg.allow_insecure_dev {
        return Some(seal::unseal_dev());
    }
    match std::env::var("VAULT_UNSEAL_PASSPHRASE") {
        Ok(p) if !p.is_empty() => match seal::unseal(&cfg.seal_path, &p, KdfParams::default()) {
            Ok(u) => {
                eprintln!("vault-broker: unsealed (seal meta {})", cfg.seal_path.display());
                Some(u)
            }
            Err(e) => {
                eprintln!("vault-broker: unseal FAILED ({e}); starting SEALED");
                None
            }
        },
        _ => {
            eprintln!("vault-broker: no VAULT_UNSEAL_PASSPHRASE; starting SEALED");
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = BrokerConfig::from_env();

    if cfg.allow_insecure_dev {
        eprintln!(
            "WARNING: VAULT_ALLOW_INSECURE_DEV=1 — serving plain HTTP with header-only \
             auth. NEVER use this outside local development; production is mTLS-over-WG."
        );
    }
    eprintln!(
        "vault-broker {} starting: bind={} residency_group={} node={} audit={}",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        cfg.residency_group.as_str(),
        cfg.node,
        cfg.audit_path.display(),
    );

    let seal = boot_unseal(&cfg);
    let bind = cfg.bind;
    let app = http::router(AppState::new(cfg, seal));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("vault-broker listening on {bind}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("vault-broker: shutdown signal received");
}
