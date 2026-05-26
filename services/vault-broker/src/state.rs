//! Shared broker state: config, the lease/session engine, and the audit sink.

use crate::config::BrokerConfig;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
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
    /// Master-key seal state, reported by `GET /v1/sys/seal-status`. This build has no
    /// master-key gating yet (manual unseal lands with broker bootstrap, Phase 1b), so it
    /// boots unsealed; the flag is wired now so the contract endpoint reports truthfully.
    pub sealed: Arc<AtomicBool>,
}

impl AppState {
    #[must_use]
    pub fn new(cfg: BrokerConfig) -> Self {
        let sink = JsonlSink::new(cfg.audit_path.clone());
        // Opaque id generator. NOTE: counter+nanos is fine for the skeleton; the real
        // broker swaps this for a CSPRNG so lease/session ids are unguessable.
        #[allow(clippy::cast_possible_truncation)]
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let mut counter = 0u64;
        let gen: BoxedGen = Box::new(move || {
            counter += 1;
            format!("{seed:016x}{counter:08x}")
        });
        Self {
            cfg: Arc::new(cfg),
            leases: Arc::new(Mutex::new(LeaseEngine::new(gen))),
            audit: Arc::new(sink),
            sealed: Arc::new(AtomicBool::new(false)),
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
