//! vault-broker — proximi.io network secrets broker (Path A).
//!
//! Wired now: rustls mTLS-over-WG termination (`tls`) — client-cert required + verified
//! vs the fleet Root CA, peer SAN → role; a boot-time master-key unseal (`seal`) that
//! seals mutating ops behind `503` until an operator unseals; the full v1 route surface;
//! a real session/lease engine with cascade-revoke and CSPRNG ids; and a B3 audit emitter
//! (`source:"vault"`). Dev (`VAULT_ALLOW_INSECURE_DEV=1`) serves plain HTTP with
//! header-based identity. SSH-CA signing + dynamic creds (OpenSearch RBAC / RethinkDB)
//! are typed `501` stubs with their contract shapes fixed. See
//! ../../docs/planning/01-vault-as-service.md §4 and ../../spec/broker-openapi.yaml.

mod auth;
mod config;
mod creds;
mod dto;
mod http;
mod opensearch;
mod seal;
mod ssh_ca;
mod state;
mod sweeper;
mod tls;

use config::BrokerConfig;
use ssh_ca::SshCa;
use state::{AppState, Unsealed};
use terrapi_vault::{KdfParams, Vault};

/// How often the expiry sweeper runs. Sub-minute so short automated cert/cred TTLs
/// (300 s) and idle timeouts are enforced promptly.
const SWEEP_INTERVAL_SECS: u64 = 30;

/// Attempt a boot-time unseal: open the at-rest store and load the group's SSH CA. Dev
/// mode auto-unseals (ephemeral store); production requires `VAULT_UNSEAL_PASSPHRASE`. A
/// failed/absent unseal is non-fatal: the broker starts SEALED and mutating ops `503`
/// until it is restarted with a valid passphrase.
fn boot_unseal(cfg: &BrokerConfig) -> Option<Unsealed> {
    let store = if cfg.allow_insecure_dev {
        seal::unseal_dev()
    } else {
        match std::env::var("VAULT_UNSEAL_PASSPHRASE") {
            Ok(p) if !p.is_empty() => seal::unseal(&cfg.store_path, &p, KdfParams::default()),
            _ => {
                eprintln!("vault-broker: no VAULT_UNSEAL_PASSPHRASE; starting SEALED");
                return None;
            }
        }
    };
    let store = match store {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vault-broker: unseal FAILED ({e}); starting SEALED");
            return None;
        }
    };
    load_ca(store, cfg.residency_group.as_str())
}

/// Load (or generate on first run) the SSH CA from the just-opened store.
fn load_ca(store: Vault, group: &str) -> Option<Unsealed> {
    match SshCa::load_or_generate(&store, group) {
        Ok(ssh_ca) => {
            eprintln!("vault-broker: unsealed; SSH CA ready for group {group}");
            Some(Unsealed { store, ssh_ca })
        }
        Err(e) => {
            eprintln!("vault-broker: SSH CA load FAILED ({e}); starting SEALED");
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
    let allow_insecure_dev = cfg.allow_insecure_dev;
    let tls = cfg.tls.clone();
    let state = AppState::new(cfg, seal);

    // Drive lease/session expiry on a timer so short-TTL creds auto-expire.
    tokio::spawn(sweeper::run(
        state.clone(),
        std::time::Duration::from_secs(SWEEP_INTERVAL_SECS),
    ));

    let app = http::router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("vault-broker listening on {bind}");

    if allow_insecure_dev {
        // Dev only: plain HTTP, header-based identity. Never in production.
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    } else {
        // Production: mTLS-over-WG is mandatory. Refuse to start without the material
        // rather than silently serving plain HTTP that auth would reject anyway.
        let Some(tls) = tls else {
            return Err("production requires VAULT_TLS_CERT, VAULT_TLS_KEY and \
                        VAULT_TLS_CLIENT_CA (mTLS-over-WireGuard); refusing to start"
                .into());
        };
        tls::serve(listener, app, &tls).await?;
    }
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("vault-broker: shutdown signal received");
}
