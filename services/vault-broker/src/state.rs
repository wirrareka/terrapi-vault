//! Shared broker state: config, the lease/session engine, and the audit sink.

use crate::config::BrokerConfig;
use crate::seal::Unsealed;
use secrecy::SecretBox;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use terrapi_vault::DerivedKey;
use vault_transport::audit::{AuditEvent, AuditSink, JsonlSink};
use vault_transport::lease::LeaseEngine;

/// Demon-confirmed defaults (coordination/conventions/secrets-broker.md):
/// operator session 8 h hard cap, 30 min idle.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 60 * 60;
pub const DEFAULT_SESSION_IDLE_SECS: u64 = 30 * 60;
/// SSH cert defaults: 900 s interactive / 300 s automated. Consumed when `ssh/sign`
/// is implemented (next sub-phase); fixed now so the contract value is committed.
#[allow(dead_code)]
pub const SSH_CERT_TTL_INTERACTIVE_SECS: u64 = 900;
#[allow(dead_code)]
pub const SSH_CERT_TTL_AUTOMATED_SECS: u64 = 300;

type BoxedGen = Box<dyn FnMut() -> String + Send>;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<BrokerConfig>,
    pub leases: Arc<Mutex<LeaseEngine<BoxedGen>>>,
    pub audit: Arc<dyn AuditSink>,
    /// Master-key seal state, reported by `GET /v1/sys/seal-status`. `true` until an
    /// operator unseals; while sealed, mutating ops return `503` (`http::require_unsealed`).
    pub sealed: Arc<AtomicBool>,
    /// The unsealed master key (held in a zeroizing `SecretBox`). `None` while sealed.
    /// The wrapping key the at-rest store (SSH CA key, lease ledger) will use — consumed
    /// once those engines land (Phase 2/3).
    #[allow(dead_code)]
    master_key: Option<Arc<SecretBox<DerivedKey>>>,
}

/// CSPRNG-backed opaque id: 256 bits of OS randomness, hex. Used for session and lease
/// ids so they are unguessable. Reuses the lib's CSPRNG (`random_salt`) rather than
/// pulling a second RNG into the service tree.
#[must_use]
pub fn random_id() -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in terrapi_vault::random_salt().iter().chain(terrapi_vault::random_salt().iter()) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl AppState {
    /// Build state from config and the result of the boot-time unseal attempt. `seal`
    /// is `None` when the broker could not unseal (no/invalid passphrase) — it then runs
    /// sealed and mutating ops `503` until restarted with a valid passphrase.
    #[must_use]
    pub fn new(cfg: BrokerConfig, seal: Option<Unsealed>) -> Self {
        let sink = JsonlSink::new(cfg.audit_path.clone());
        let gen: BoxedGen = Box::new(random_id);
        let sealed = seal.is_none();
        let master_key = seal.map(|u| Arc::new(u.master_key));
        Self {
            cfg: Arc::new(cfg),
            leases: Arc::new(Mutex::new(LeaseEngine::new(gen))),
            audit: Arc::new(sink),
            sealed: Arc::new(AtomicBool::new(sealed)),
            master_key,
        }
    }

    /// Current seal state (`GET /v1/sys/seal-status`).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.sealed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// RFC3339 UTC timestamp for audit events.
    #[must_use]
    pub fn now_ts() -> String {
        use time::format_description::well_known::Rfc3339;
        time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default()
    }

    pub fn emit(&self, event: &AuditEvent) {
        self.audit.emit(event);
    }
}
