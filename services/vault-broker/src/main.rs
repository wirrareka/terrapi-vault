//! vault-broker — proximi.io network secrets broker (Path A).
//!
//! Wired now: rustls mTLS-over-WG termination (`tls`) — client-cert required + verified
//! vs the fleet Root CA, peer SAN → role; a boot-time master-key unseal (`seal`, the
//! at-rest store) that seals mutating ops behind `503`; the full v1 route surface; a
//! session/lease engine with cascade-revoke, CSPRNG ids and a TTL/idle expiry `sweeper`;
//! the SSH-CA (`ssh_ca`) and the OpenSearch dynamic-cred engine (`creds`/`opensearch`);
//! and a tamper-evident hash-chained B3 audit store (`source:"vault"`) with best-effort
//! OpenSearch shipping (`audit_ship`). Dev (`VAULT_ALLOW_INSECURE_DEV=1`) serves plain
//! HTTP with header-based identity. See ../../docs/planning/01-vault-as-service.md §4 and
//! ../../spec/broker-openapi.yaml.

mod audit_ship;
mod auth;
mod config;
mod creds;
mod dto;
mod hardening;
mod http;
mod kms;
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
        let Some(p) = unseal_passphrase() else {
            eprintln!("vault-broker: no VAULT_UNSEAL_PASSPHRASE[_FILE]; starting SEALED");
            return None;
        };
        seal::unseal(&cfg.store_path, &p, KdfParams::default())
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

/// The operator unseal passphrase, from `VAULT_UNSEAL_PASSPHRASE` or, for unattended
/// restart, a `mode 600` file at `VAULT_UNSEAL_PASSPHRASE_FILE` (on a ZFS-encrypted
/// dataset — see docs/broker-bootstrap.md). Env wins; trailing whitespace is trimmed.
fn unseal_passphrase() -> Option<String> {
    if let Ok(p) = std::env::var("VAULT_UNSEAL_PASSPHRASE") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    let path = std::env::var("VAULT_UNSEAL_PASSPHRASE_FILE").ok()?;
    warn_if_group_or_world_readable("VAULT_UNSEAL_PASSPHRASE_FILE", &path);
    match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Some(s.trim_end_matches(['\n', '\r']).to_owned()),
        Ok(_) => None,
        Err(e) => {
            eprintln!("vault-broker: VAULT_UNSEAL_PASSPHRASE_FILE read error ({e})");
            None
        }
    }
}

/// Loudly warn if a secret file is group/other-readable (it should be mode 600). Unix only.
#[cfg(unix)]
fn warn_if_group_or_world_readable(label: &str, path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "vault-broker: WARNING {label} {path} is mode {mode:o} — group/other can read this secret; chmod 600 it."
            );
        }
    }
}
#[cfg(not(unix))]
fn warn_if_group_or_world_readable(_label: &str, _path: &str) {}

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
    // rustls 0.23 can't auto-pick a crypto provider when both aws-lc-rs and ring are
    // pulled in transitively (rustls server + reqwest) — it panics on first TLS use.
    // Install aws-lc-rs explicitly, before any TLS (mTLS server, reqwest clients).
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("vault-broker: a rustls CryptoProvider was already installed (continuing)");
    }

    let cfg = BrokerConfig::from_env();

    if cfg.allow_insecure_dev {
        // Insecure dev (plain HTTP, header-only identity, all-caps `dev` principal) must never
        // be reachable off the local host. Refuse to start if it would bind a routable address.
        if !cfg.bind.ip().is_loopback() {
            return Err(format!(
                "VAULT_ALLOW_INSECURE_DEV=1 with a non-loopback bind ({}) is refused: insecure \
                 dev has no transport auth and must stay on the local host. Bind 127.0.0.1 for \
                 dev, or unset the flag and provide mTLS material (VAULT_TLS_*) for production.",
                cfg.bind
            )
            .into());
        }
        eprintln!(
            "WARNING: VAULT_ALLOW_INSECURE_DEV=1 — serving plain HTTP with header-only \
             auth on {}. NEVER use this outside local development; production is mTLS-over-WG.",
            cfg.bind
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

    // Durable-local audit + optional best-effort OpenSearch shipping.
    let (audit, ship_task) = audit_ship::build(&cfg);
    let state = AppState::new(cfg, seal, audit);
    if let Some(task) = ship_task {
        tokio::spawn(audit_ship::run(task));
    }

    // Drive lease/session expiry on a timer so short-TTL creds auto-expire.
    tokio::spawn(sweeper::run(
        state.clone(),
        std::time::Duration::from_secs(SWEEP_INTERVAL_SECS),
    ));

    // Prometheus metrics on a loopback-only listener (never on the WG/mTLS surface). `/metrics`
    // is unauthenticated and carries sealed-state + route counters, so refuse a non-loopback bind
    // (fail-closed: disable the listener) unless explicitly opted in.
    let metrics_bind =
        std::env::var("VAULT_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:8201".to_owned());
    if metrics_bind_allowed(&metrics_bind, "VAULT_METRICS_ALLOW_PUBLIC") {
        let metrics_state = state.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&metrics_bind).await {
                Ok(l) => {
                    eprintln!("vault-broker: metrics on http://{metrics_bind}/metrics");
                    let _ = axum::serve(l, http::metrics_router(metrics_state)).await;
                }
                Err(e) => eprintln!("vault-broker: metrics listener disabled ({e})"),
            }
        });
    } else {
        eprintln!(
            "vault-broker: metrics listener DISABLED — {metrics_bind} is not loopback; \
             /metrics exposes sealed-state + route counters. Bind 127.0.0.1, or set \
             VAULT_METRICS_ALLOW_PUBLIC=1 to override."
        );
    }

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

/// Whether a metrics listener may bind `bind` without the explicit allow-public override.
/// **Safe** (not internet-reachable, so allowed): loopback, plus RFC1918-private / link-local
/// IPv4 — this is what the on-box-Prometheus convention uses (the broker binds its per-jail WG
/// `/32`, e.g. `10.200.0.101:8201`; see `coordination/conventions/ports-env.md`). **Refused**
/// unless `allow_env` is `1`: `0.0.0.0`/`::` (all interfaces — could be public), any routable
/// public address, and an unparseable bind (fail-closed).
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
    eprintln!("vault-broker: shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::metrics_bind_allowed;

    #[test]
    fn metrics_bind_loopback_and_private_allowed_public_refused() {
        const UNSET: &str = "VAULT_METRICS_ALLOW_PUBLIC_TEST_UNSET";
        assert!(metrics_bind_allowed("127.0.0.1:8201", UNSET)); // loopback
        assert!(metrics_bind_allowed("[::1]:8201", UNSET)); // v6 loopback
        assert!(metrics_bind_allowed("10.200.0.101:8201", UNSET)); // WG /32 (RFC1918) — the convention
        assert!(metrics_bind_allowed("192.168.1.5:8201", UNSET)); // private
        assert!(!metrics_bind_allowed("0.0.0.0:8201", UNSET)); // all interfaces → refused
        assert!(!metrics_bind_allowed("1.2.3.4:8201", UNSET)); // routable public → refused
        assert!(!metrics_bind_allowed("not-a-socketaddr", UNSET)); // unparseable → fail-closed
    }
}
