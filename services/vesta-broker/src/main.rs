//! vesta-broker — proximi.io network secrets broker (Path A).
//!
//! Wired now: rustls mTLS-over-WG termination (`tls`) — client-cert required + verified
//! vs the fleet Root CA, peer SAN → role; a boot-time master-key unseal (`seal`, the
//! at-rest store) that seals mutating ops behind `503`; the full v1 route surface; a
//! session/lease engine with cascade-revoke, CSPRNG ids and a TTL/idle expiry `sweeper`;
//! the SSH-CA (`ssh_ca`) and the OpenSearch dynamic-cred engine (`creds`/`opensearch`);
//! and a tamper-evident hash-chained B3 audit store (`source:"vesta"`) with best-effort
//! OpenSearch shipping (`audit_ship`). Dev (`VESTA_ALLOW_INSECURE_DEV=1`) serves plain
//! HTTP with header-based identity. See ../../docs/planning/01-vesta-as-service.md §4 and
//! ../../spec/broker-openapi.yaml.

mod audit_ship;
mod auth;
mod config;
mod creds;
mod dto;
mod hardening;
mod http;
mod identity_kms;
mod jwt;
mod kms;
mod object_store;
mod opensearch;
// Enterprise-PKI issuance anchor — Phase 1 (leaf-issuance engine). Not yet wired to a route
// (Phase 2 = sealed-store load + license gate + `/v1/pki/*`, gated on the operator license format),
// so the engine's API is currently exercised only by its tests.
#[allow(dead_code)]
mod pki;
mod seal;
mod ssh_ca;
mod state;
mod sweeper;
mod tls;

use config::BrokerConfig;
use ssh_ca::SshCa;
use state::{AppState, Unsealed};
use terrapi_vesta::{KdfParams, Vesta};

/// How often the expiry sweeper runs. Sub-minute so short automated cert/cred TTLs
/// (300 s) and idle timeouts are enforced promptly.
const SWEEP_INTERVAL_SECS: u64 = 30;

/// Attempt a boot-time unseal: open the at-rest store and load the group's SSH CA. Dev
/// mode auto-unseals (ephemeral store); production obtains the unseal passphrase via
/// [`obtain_unseal_passphrase`] (identity arm (a) if configured, else the manual passphrase).
/// A failed/absent unseal is non-fatal: the broker starts SEALED and mutating ops `503`
/// until it is restarted with a working unseal path.
async fn boot_unseal(cfg: &BrokerConfig) -> (Option<Unsealed>, Option<ResealEvent>) {
    let (store_res, reseal) = if cfg.allow_insecure_dev {
        (seal::unseal_dev(), None)
    } else {
        let Some((p, reseal)) = obtain_unseal_passphrase(cfg).await else {
            eprintln!("vesta-broker: no unseal passphrase (identity arm (a) and manual both unavailable); starting SEALED");
            return (None, None);
        };
        (
            seal::unseal(&cfg.store_path, &p, KdfParams::default()),
            reseal,
        )
    };
    let store = match store_res {
        Ok(v) => v,
        Err(e) => {
            // The re-seal (if any) already persisted, so still surface it for the audit emit.
            eprintln!("vesta-broker: unseal FAILED ({e}); starting SEALED");
            return (None, reseal);
        }
    };
    (load_ca(store, cfg.residency_group.as_str()), reseal)
}

/// A completed root re-seal (arm (a)): the master key was re-sealed from `old_kek_id` under the
/// now-current `new_kek_id`. Surfaced so the broker emits B3 `kms.master_resealed` once the audit
/// sink is built — identity consumes it to retire the old root (idempotent; dedup by `{old,new}`).
struct ResealEvent {
    old_kek_id: String,
    new_kek_id: String,
}

/// Unseal the master key via identity and, when identity signals a root rotation
/// (`reseal_required`), re-seal the (value-unchanged) master under the current root and persist
/// the new blob atomically. Returns the master key bytes + the reseal event (Some on re-seal).
async fn unseal_and_maybe_reseal(
    client: &identity_kms::IdentityKmsClient,
    sealed_file: &std::path::Path,
    blob: &identity_kms::SealedMaster,
) -> Result<(Vec<u8>, Option<ResealEvent>), identity_kms::Error> {
    let outcome = client.unseal(blob).await?;
    if !outcome.reseal_required {
        return Ok((outcome.master_key, None));
    }
    // Root rotated: re-seal the same master under the current root, persist atomically (temp+rename).
    let new = client.seal(&outcome.master_key).await?;
    // Sanity: identity should have sealed under the root it just advertised as current. A mismatch
    // means the root rotated again between unseal and seal — the new blob is still valid under
    // new.kek_id, so we proceed, but log it.
    if let Some(cur) = &outcome.current_kek_id {
        if cur != &new.kek_id {
            eprintln!(
                "vesta-broker: re-seal kek_id {} != identity's advertised current {} (root rotated mid-reseal?); proceeding with {}",
                new.kek_id, cur, new.kek_id
            );
        }
    }
    identity_kms::store_sealed(sealed_file, &new)
        .map_err(|e| identity_kms::Error::Io(e.to_string()))?;
    let reseal = ResealEvent {
        old_kek_id: blob.kek_id.clone(),
        new_kek_id: new.kek_id,
    };
    Ok((outcome.master_key, Some(reseal)))
}

/// Emit B3 `kms.master_resealed` (`source:"vesta"`) so identity retires the old root. At-least-once
/// (identity dedups by `{old,new}`); a lost emit is covered by identity's overlap backstop.
fn emit_master_resealed(state: &AppState, r: &ResealEvent) {
    use vesta_transport::audit::{Actor, ActorKind, AuditEvent, Outcome, Target};
    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        Actor {
            label: state.cfg.node.clone(),
            kind: ActorKind::System,
            id: None,
            tenant: None,
        },
        "kms.master_resealed",
        Target {
            kind: "kms-root".into(),
            id: Some(format!("{}->{}", r.old_kek_id, r.new_kek_id)),
        },
        Outcome::Success,
        None,
    ));
}

/// Periodically re-check identity for a root rotation and re-seal if needed. Boot-time re-seal
/// handles the common case (routine restarts); this covers a broker that runs *across* a rotation
/// without restarting, within identity's overlap window. No-op unless arm (a) is configured.
/// Cadence `VESTA_KMS_RESEAL_CHECK_SECS` (default 6 h) — root rotation is annual + break-glass, so
/// a long interval bounds how often the plaintext master transits (in-group, over mTLS).
async fn reseal_watch(state: AppState, interval: std::time::Duration) {
    let (Some(k), Some(tls)) = (state.cfg.identity_kms.clone(), state.cfg.tls.clone()) else {
        return; // arm (a) not configured (or no mTLS material) → nothing to watch
    };
    let client = match identity_kms::IdentityKmsClient::new(k.url.clone(), &tls) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vesta-broker: reseal-watch disabled — KMS client setup failed ({e})");
            return;
        }
    };
    loop {
        tokio::time::sleep(interval).await;
        let Some(blob) = identity_kms::load_sealed(&k.sealed_master_file) else {
            continue;
        };
        match unseal_and_maybe_reseal(&client, &k.sealed_master_file, &blob).await {
            Ok((_master, Some(r))) => {
                eprintln!(
                    "vesta-broker: reseal-watch — root rotation, re-sealed {} -> {}",
                    r.old_kek_id, r.new_kek_id
                );
                emit_master_resealed(&state, &r);
            }
            Ok((_master, None)) => {} // already under the current root
            Err(e) => eprintln!("vesta-broker: reseal-watch check failed ({e})"),
        }
    }
}

/// The unseal passphrase, via arm (a) (identity-sealed master key) when configured, else the
/// manual passphrase. Arm (a) (secrets-broker.md §KMS root-of-trust): the broker stores an
/// inert `{kek_id, wrapped}` blob and exchanges it for the plaintext master key at identity's
/// KMS listener, so a stolen at-rest store is useless without a live in-group call to identity.
/// If identity is unreachable (or the blob is missing) the broker falls back to the manual
/// passphrase — **break-glass**, as agreed, until arm (a) has run a prod cycle.
///
/// One-time bootstrap: with `VESTA_KMS_SEAL_INIT=1` the broker seals the *current* manual
/// passphrase under identity, persists the returned blob, and boots with it — run once, then
/// unset the flag.
async fn obtain_unseal_passphrase(cfg: &BrokerConfig) -> Option<(String, Option<ResealEvent>)> {
    let manual = || unseal_passphrase().map(|p| (p, None));

    let Some(k) = &cfg.identity_kms else {
        return manual(); // arm (a) not configured → manual passphrase
    };
    // Arm (a) authenticates to identity with the broker's own mTLS material (client cert).
    let Some(tls) = &cfg.tls else {
        eprintln!("vesta-broker: arm (a) configured but no VESTA_TLS_* mTLS material for the KMS client; using manual passphrase");
        return manual();
    };
    let client = match identity_kms::IdentityKmsClient::new(k.url.clone(), tls) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vesta-broker: KMS client mTLS setup FAILED ({e}); falling back to manual passphrase");
            return manual();
        }
    };

    if std::env::var("VESTA_KMS_SEAL_INIT").as_deref() == Ok("1") {
        return seal_init(&client, k).await.map(|p| (p, None));
    }

    let Some(blob) = identity_kms::load_sealed(&k.sealed_master_file) else {
        eprintln!(
            "vesta-broker: arm (a) configured but no sealed-master blob at {} — using manual passphrase (run once with VESTA_KMS_SEAL_INIT=1 to seal it)",
            k.sealed_master_file.display()
        );
        return manual();
    };
    let (master, reseal) = match unseal_and_maybe_reseal(&client, &k.sealed_master_file, &blob)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vesta-broker: identity unseal/re-seal FAILED ({e}); falling back to break-glass passphrase");
            return manual();
        }
    };
    let Ok(p) = String::from_utf8(master) else {
        eprintln!("vesta-broker: identity returned a non-UTF8 master; falling back to break-glass passphrase");
        return manual();
    };
    eprintln!(
        "vesta-broker: unsealed via identity arm (a) (kek_id={})",
        blob.kek_id
    );
    if let Some(r) = &reseal {
        eprintln!(
            "vesta-broker: root rotation detected — re-sealed master {} -> {}",
            r.old_kek_id, r.new_kek_id
        );
    }
    Some((p, reseal))
}

/// One-time arm (a) bootstrap: seal the current manual passphrase under identity's per-group
/// root and persist the inert blob, then return that passphrase so this boot proceeds normally.
async fn seal_init(
    client: &identity_kms::IdentityKmsClient,
    k: &config::IdentityKmsConfig,
) -> Option<String> {
    let Some(p) = unseal_passphrase() else {
        eprintln!(
            "vesta-broker: VESTA_KMS_SEAL_INIT=1 but no manual passphrase to seal; starting SEALED"
        );
        return None;
    };
    match client.seal(p.as_bytes()).await {
        Ok(sealed) => {
            if let Err(e) = identity_kms::store_sealed(&k.sealed_master_file, &sealed) {
                eprintln!(
                    "vesta-broker: SEAL_INIT sealed the master under identity but FAILED to persist {} ({e}); fix perms + retry, NOT booting sealed-by-identity",
                    k.sealed_master_file.display()
                );
                return None;
            }
            eprintln!(
                "vesta-broker: SEAL_INIT ok — master sealed under identity (kek_id={}); wrote {}. Unset VESTA_KMS_SEAL_INIT for subsequent boots.",
                sealed.kek_id,
                k.sealed_master_file.display()
            );
            Some(p)
        }
        Err(e) => {
            eprintln!("vesta-broker: SEAL_INIT seal call FAILED ({e}); starting SEALED");
            None
        }
    }
}

/// The operator unseal passphrase, from `VESTA_UNSEAL_PASSPHRASE` or, for unattended
/// restart, a `mode 600` file at `VESTA_UNSEAL_PASSPHRASE_FILE` (on a ZFS-encrypted
/// dataset — see docs/broker-bootstrap.md). Env wins; trailing whitespace is trimmed.
fn unseal_passphrase() -> Option<String> {
    if let Ok(p) = std::env::var("VESTA_UNSEAL_PASSPHRASE") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    let path = std::env::var("VESTA_UNSEAL_PASSPHRASE_FILE").ok()?;
    warn_if_group_or_world_readable("VESTA_UNSEAL_PASSPHRASE_FILE", &path);
    match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Some(s.trim_end_matches(['\n', '\r']).to_owned()),
        Ok(_) => None,
        Err(e) => {
            eprintln!("vesta-broker: VESTA_UNSEAL_PASSPHRASE_FILE read error ({e})");
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
                "vesta-broker: WARNING {label} {path} is mode {mode:o} — group/other can read this secret; chmod 600 it."
            );
        }
    }
}
#[cfg(not(unix))]
fn warn_if_group_or_world_readable(_label: &str, _path: &str) {}

/// Load (or generate on first run) the SSH CA from the just-opened store.
fn load_ca(store: Vesta, group: &str) -> Option<Unsealed> {
    match SshCa::load_or_generate(&store, group) {
        Ok(ssh_ca) => {
            eprintln!("vesta-broker: unsealed; SSH CA ready for group {group}");
            Some(Unsealed { store, ssh_ca })
        }
        Err(e) => {
            eprintln!("vesta-broker: SSH CA load FAILED ({e}); starting SEALED");
            None
        }
    }
}

/// Fail-closed boot checks for the two insecure footguns: serving insecure-dev where it could be
/// reachable / downgrade production, and silently defaulting the at-rest store + audit chain into
/// a shared temp dir. Returns an error (refusing to start) rather than booting unsafely.
fn check_boot_safety(cfg: &BrokerConfig) -> Result<(), Box<dyn std::error::Error>> {
    if cfg.allow_insecure_dev {
        // Refuse the insecure-dev flag when mTLS material is configured: that pairing is a
        // one-env-var production downgrade (plain HTTP + header-only identity served despite a
        // real server cert + fleet CA being present). Pick one — dev (no TLS) or production
        // (mTLS) — never both.
        if cfg.tls.is_some() {
            return Err(
                "VESTA_ALLOW_INSECURE_DEV=1 together with VESTA_TLS_* material is refused: \
                        it would serve plain HTTP with header-only identity while mTLS material is \
                        configured (a production downgrade). Unset VESTA_ALLOW_INSECURE_DEV for \
                        production, or remove VESTA_TLS_* for local dev."
                    .into(),
            );
        }
        // Insecure dev (plain HTTP, header-only identity, all-caps `dev` principal) must never
        // be reachable off the local host. Refuse to start if it would bind a routable address.
        if !cfg.bind.ip().is_loopback() {
            return Err(format!(
                "VESTA_ALLOW_INSECURE_DEV=1 with a non-loopback bind ({}) is refused: insecure \
                 dev has no transport auth and must stay on the local host. Bind 127.0.0.1 for \
                 dev, or unset the flag and provide mTLS material (VESTA_TLS_*) for production.",
                cfg.bind
            )
            .into());
        }
        eprintln!(
            "WARNING: VESTA_ALLOW_INSECURE_DEV=1 — serving plain HTTP with header-only \
             auth on {}. NEVER use this outside local development; production is mTLS-over-WG.",
            cfg.bind
        );
    } else {
        // Production: refuse to silently place the at-rest store / audit chain in a shared,
        // world-readable temp dir (the `from_env` dev defaults). They must be set explicitly,
        // pointing at an encrypted dataset (see docs/broker-bootstrap.md). Fail-closed at boot.
        for (var, what) in [
            (
                "VESTA_STORE_PATH",
                "the at-rest secrets store (SQLCipher DB)",
            ),
            ("VESTA_AUDIT_PATH", "the tamper-evident audit chain"),
        ] {
            if std::env::var_os(var).is_none() {
                return Err(format!(
                    "production requires {var} to be set explicitly ({what}); refusing to default \
                     to a shared temp dir. Point it at a path on an encrypted dataset, or set \
                     VESTA_ALLOW_INSECURE_DEV=1 for local runs."
                )
                .into());
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Backward-compat for the vault→vesta rename: mirror any VAULT_* env to VESTA_* before reading
    // config, so units still on the old prefix keep working. Remove after the env cutover.
    vesta_transport::http::apply_vault_env_compat();
    // rustls 0.23 can't auto-pick a crypto provider when both aws-lc-rs and ring are
    // pulled in transitively (rustls server + reqwest) — it panics on first TLS use.
    // Install aws-lc-rs explicitly, before any TLS (mTLS server, reqwest clients).
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("vesta-broker: a rustls CryptoProvider was already installed (continuing)");
    }

    let cfg = BrokerConfig::from_env();

    check_boot_safety(&cfg)?;
    eprintln!(
        "vesta-broker {} starting: bind={} residency_group={} node={} audit={}",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        cfg.residency_group.as_str(),
        cfg.node,
        cfg.audit_path.display(),
    );

    let (seal, reseal) = boot_unseal(&cfg).await;
    let bind = cfg.bind;
    let allow_insecure_dev = cfg.allow_insecure_dev;
    let tls = cfg.tls.clone();

    // Durable-local audit + optional best-effort OpenSearch shipping.
    let (audit, ship_task) = audit_ship::build(&cfg);
    let state = AppState::new(cfg, seal, audit);
    if let Some(task) = ship_task {
        tokio::spawn(audit_ship::run(task));
    }

    // Boot reconciliation: the lease ledger is in-memory, so after a crash/restart any backend
    // user a prior incarnation of THIS node created is an orphan (no owning lease) — which would
    // otherwise outlive its short TTL forever. Run it in the BACKGROUND (the HTTP calls are
    // timeout-bounded) so a slow/unreachable OpenSearch can't delay the broker from binding +
    // serving; best-effort, retried on the next restart.
    {
        let recon_state = state.clone();
        tokio::spawn(async move {
            let n = recon_state.engines.reconcile_all().await;
            eprintln!(
                "vesta-broker: boot reconcile complete ({n} orphaned backend user(s) removed)"
            );
        });
    }

    // Arm (a): if boot re-sealed the master under a rotated root, signal it now that the audit
    // sink exists (identity retires the old root on this; at-least-once, deduped by {old,new}).
    if let Some(r) = &reseal {
        emit_master_resealed(&state, r);
    }
    // Watch for a root rotation that happens while the broker runs (no restart) — re-seal within
    // identity's overlap window. No-op unless arm (a) is configured.
    let reseal_check = std::time::Duration::from_secs(
        std::env::var("VESTA_KMS_RESEAL_CHECK_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(6 * 60 * 60),
    );
    tokio::spawn(reseal_watch(state.clone(), reseal_check));

    // Drive lease/session expiry on a timer so short-TTL creds auto-expire.
    tokio::spawn(sweeper::run(
        state.clone(),
        std::time::Duration::from_secs(SWEEP_INTERVAL_SECS),
    ));

    // Prometheus metrics on a loopback-only listener (never on the WG/mTLS surface). `/metrics`
    // is unauthenticated and carries sealed-state + route counters, so refuse a non-loopback bind
    // (fail-closed: disable the listener) unless explicitly opted in.
    let metrics_bind =
        std::env::var("VESTA_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:8201".to_owned());
    if metrics_bind_allowed(&metrics_bind, "VESTA_METRICS_ALLOW_PUBLIC") {
        let metrics_state = state.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&metrics_bind).await {
                Ok(l) => {
                    eprintln!("vesta-broker: metrics on http://{metrics_bind}/metrics");
                    let _ = axum::serve(l, http::metrics_router(metrics_state)).await;
                }
                Err(e) => eprintln!("vesta-broker: metrics listener disabled ({e})"),
            }
        });
    } else {
        eprintln!(
            "vesta-broker: metrics listener DISABLED — {metrics_bind} is not loopback; \
             /metrics exposes sealed-state + route counters. Bind 127.0.0.1, or set \
             VESTA_METRICS_ALLOW_PUBLIC=1 to override."
        );
    }

    let app = http::router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("vesta-broker listening on {bind}");

    if allow_insecure_dev {
        // Dev only: plain HTTP, header-based identity. Never in production.
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    } else {
        // Production: mTLS-over-WG is mandatory. Refuse to start without the material
        // rather than silently serving plain HTTP that auth would reject anyway.
        let Some(tls) = tls else {
            return Err("production requires VESTA_TLS_CERT, VESTA_TLS_KEY and \
                        VESTA_TLS_CLIENT_CA (mTLS-over-WireGuard); refusing to start"
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
    eprintln!("vesta-broker: shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::metrics_bind_allowed;

    #[test]
    fn metrics_bind_loopback_and_private_allowed_public_refused() {
        const UNSET: &str = "VESTA_METRICS_ALLOW_PUBLIC_TEST_UNSET";
        assert!(metrics_bind_allowed("127.0.0.1:8201", UNSET)); // loopback
        assert!(metrics_bind_allowed("[::1]:8201", UNSET)); // v6 loopback
        assert!(metrics_bind_allowed("10.200.0.101:8201", UNSET)); // WG /32 (RFC1918) — the convention
        assert!(metrics_bind_allowed("192.168.1.5:8201", UNSET)); // private
        assert!(!metrics_bind_allowed("0.0.0.0:8201", UNSET)); // all interfaces → refused
        assert!(!metrics_bind_allowed("1.2.3.4:8201", UNSET)); // routable public → refused
        assert!(!metrics_bind_allowed("not-a-socketaddr", UNSET)); // unparseable → fail-closed
    }
}
