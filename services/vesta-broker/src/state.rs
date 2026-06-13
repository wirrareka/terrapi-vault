//! Shared broker state: config, the lease/session engine, and the audit sink.

use crate::config::BrokerConfig;
use crate::creds::{CredEngines, CredHandle, MockEngine};
use crate::ssh_ca::SshCa;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use terrapi_vesta::Vesta;
use vesta_transport::audit::{AuditEvent, AuditSink};
use vesta_transport::http::HttpMetrics;
use vesta_transport::lease::LeaseEngine;

/// Default TTL for a leased service-admin cred when the request omits `ttl_secs`.
pub const CREDS_DEFAULT_TTL_SECS: u64 = 900;

/// The result of a successful boot-time unseal: the opened at-rest store and the SSH CA
/// loaded from it. `Vesta` owns a rusqlite connection (`!Sync`), hence the `Mutex`.
pub struct Unsealed {
    pub store: Vesta,
    pub ssh_ca: SshCa,
}

/// Minimal in-process metrics, exposed as Prometheus text on the loopback `8201` listener.
/// The `vault_http_*` request series + their format come from the shared [`HttpMetrics`]; the
/// broker adds `vault_sealed` and per-action `vault_audit_events_total` (bumped at the single
/// `AppState::emit` site, so every broker action — `ssh.sign`, `creds.issue`, … — is counted).
#[derive(Default)]
pub struct Metrics {
    http: HttpMetrics,
    events: Mutex<HashMap<String, u64>>,
}

impl Metrics {
    fn incr(&self, action: &str) {
        *self
            .events
            .lock()
            .expect("metrics lock")
            .entry(action.to_owned())
            .or_insert(0) += 1;
    }

    /// Record one served request (delegates to the shared http core; `route` is the matched
    /// template, never the concrete tenant-bearing path).
    pub fn record_request(&self, route: &str, method: &str, status: u16, dur: std::time::Duration) {
        self.http.record_request(route, method, status, dur);
    }

    /// Adjust the in-flight gauge (`+1` on entry, `-1` on exit).
    pub fn inflight_add(&self, delta: i64) {
        self.http.inflight_add(delta);
    }

    /// Render the Prometheus text exposition for `/metrics`. `sealed` is the live gauge.
    #[must_use]
    pub fn render(&self, sealed: bool) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("# HELP vault_sealed 1 if the broker is sealed, 0 if unsealed.\n");
        out.push_str("# TYPE vault_sealed gauge\n");
        let _ = writeln!(out, "vault_sealed {}", u8::from(sealed));
        out.push_str("# HELP vault_audit_events_total B3 audit events emitted, by action.\n");
        out.push_str("# TYPE vault_audit_events_total counter\n");
        let events = self.events.lock().expect("metrics lock");
        let mut actions: Vec<_> = events.iter().collect();
        actions.sort_by(|a, b| a.0.cmp(b.0));
        for (action, n) in actions {
            let _ = writeln!(out, "vault_audit_events_total{{action=\"{action}\"}} {n}");
        }
        out.push_str(&self.http.render("vault"));
        out
    }
}

/// Demon-confirmed defaults (coordination/conventions/secrets-broker.md):
/// operator session 8 h hard cap, 30 min idle.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 60 * 60;
pub const DEFAULT_SESSION_IDLE_SECS: u64 = 30 * 60;
/// Hard ceilings a caller's requested `ttl_secs`/`idle_timeout_secs` are clamped to — the
/// short-TTL guarantee must not be defeatable by a large request value. 8 h is the
/// demon-confirmed operator-session cap; idle is bounded to the (clamped) session TTL.
pub const MAX_SESSION_TTL_SECS: u64 = 8 * 60 * 60;
/// SSH cert defaults (demon-confirmed): 900 s interactive / 300 s automated.
pub const SSH_CERT_TTL_INTERACTIVE_SECS: u64 = 900;
/// Hard ceiling on a signed SSH cert's validity, regardless of the requested `ttl_secs`. The
/// cert stays cryptographically valid until `valid_before` even after lease revoke (the KRL is
/// best-effort), so this bound is what actually keeps issuance short-lived. 1 h is generous.
pub const SSH_CERT_MAX_TTL_SECS: u64 = 60 * 60;
/// Automated/touch-per-op default; selected by the caller via `ttl_secs` for now.
#[allow(dead_code)]
pub const SSH_CERT_TTL_AUTOMATED_SECS: u64 = 300;

type BoxedGen = Box<dyn FnMut() -> String + Send>;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<BrokerConfig>,
    pub leases: Arc<Mutex<LeaseEngine<BoxedGen>>>,
    pub audit: Arc<dyn AuditSink>,
    /// Seal state, reported by `GET /v1/sys/seal-status`. `true` until an operator
    /// unseals; while sealed, mutating ops return `503` (`http::require_unsealed`).
    pub sealed: Arc<AtomicBool>,
    /// The unsealed at-rest store (SQLCipher). `None` while sealed. Holds the SSH CA key
    /// and the per-target KMS KEKs.
    pub store: Option<Arc<Mutex<Vesta>>>,
    /// The SSH CA loaded for this instance's group. `None` while sealed.
    pub ssh_ca: Option<Arc<SshCa>>,
    /// Active operator session per authenticated principal (SAN → session id). Issued
    /// leases (SSH certs, creds) become children of the caller's active session, so they
    /// cascade-revoke when it ends. One active session per principal (a new open replaces).
    sessions: Arc<Mutex<HashMap<String, String>>>,
    /// Dynamic-cred engines (role → backend). Built at boot; empty in prod until adapters
    /// are wired, a `MockEngine` in dev.
    pub engines: Arc<CredEngines>,
    /// Backend handles owned by issued cred leases (lease id → {role, username}), so a
    /// revoke / session-cascade can delete the ephemeral backend user.
    pub cred_handles: Arc<Mutex<HashMap<String, CredHandle>>>,
    /// SSH-cert lease id → cert serial, so a revoke / expiry can record the serial in the
    /// CA's revocation list.
    ssh_serials: Arc<Mutex<HashMap<String, u64>>>,
    /// Process metrics, exposed on the loopback `8201` listener.
    pub metrics: Arc<Metrics>,
    /// Runtime hardening state: concurrency permits + per-principal rate buckets.
    pub harden: Arc<crate::hardening::HardenState>,
    /// KMS-cap JWT verifier (Option J). `Some` when `VESTA_KMS_JWT_ISSUER` is configured →
    /// kms ops require a valid identity-minted ES256 bearer token; `None` → kms is cap-based.
    pub kms_jwt: Option<Arc<crate::jwt::JwtVerifier>>,
    /// Object-store presigner (DO Spaces tile publishing). `Some` when `VESTA_OBJECT_STORE_KEY`
    /// is configured → `object-store/presign` signs URLs; `None` → that op is `503 not_configured`.
    /// Independent of the seal (the Spaces key is env-held, like the OpenSearch admin cred).
    pub object_store: Option<Arc<crate::object_store::ObjectStoreSigner>>,
}

/// Current unix time in seconds — the clock the lease/session engine is driven by.
#[must_use]
pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// CSPRNG-backed opaque id: 256 bits of OS randomness, hex. Used for session and lease
/// ids so they are unguessable. Reuses the lib's CSPRNG (`random_salt`) rather than
/// pulling a second RNG into the service tree.
#[must_use]
pub fn random_id() -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in terrapi_vesta::random_salt()
        .iter()
        .chain(terrapi_vesta::random_salt().iter())
    {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build the dynamic-cred engine registry. If `VESTA_OS_*` is configured, the real
/// OpenSearch RBAC engine is registered under its role; otherwise dev registers an
/// in-memory `MockEngine` so the creds path is exercisable locally. With neither, the
/// registry is empty and an issuance for any role returns `404` (unconfigured role).
fn build_engines(cfg: &BrokerConfig) -> CredEngines {
    let mut engines = CredEngines::new();
    match crate::opensearch::OpenSearchEngine::from_env(&cfg.node) {
        Ok(Some(os)) => {
            let role = os.role().to_owned();
            eprintln!("vesta-broker: OpenSearch cred engine registered for role '{role}'");
            engines.register(role, Box::new(os));
        }
        Ok(None) => {
            if cfg.allow_insecure_dev {
                engines.register(
                    "audit-writer",
                    Box::new(MockEngine::new("audit-writer", 8 * 60 * 60)),
                );
            }
        }
        Err(e) => eprintln!("vesta-broker: OpenSearch cred engine DISABLED ({e})"),
    }
    engines
}

impl AppState {
    /// Build state from config and the result of the boot-time unseal attempt. `seal`
    /// is `None` when the broker could not unseal (no/invalid passphrase) — it then runs
    /// sealed and mutating ops `503` until restarted with a valid passphrase.
    #[must_use]
    pub fn new(cfg: BrokerConfig, seal: Option<Unsealed>, audit: Arc<dyn AuditSink>) -> Self {
        let gen: BoxedGen = Box::new(random_id);
        let harden = Arc::new(crate::hardening::HardenState::new(cfg.hardening));
        // Build the kms-cap JWT verifier when configured. The instance's residency group is
        // the expected `residency_group` claim (cross-region replay defence).
        let kms_jwt = cfg.kms_jwt.as_ref().map(|c| {
            Arc::new(crate::jwt::JwtVerifier::new(
                c.issuer.clone(),
                c.audience.clone(),
                cfg.residency_group.as_str().to_owned(),
                c.jwks_uri.clone(),
            ))
        });
        // Object-store presigner: built from env (VESTA_OBJECT_STORE_*), like the OpenSearch
        // engine. Disabled (op → 503) when unconfigured; a misconfig logs + stays disabled.
        let object_store = match crate::object_store::ObjectStoreSigner::from_env() {
            Ok(Some(s)) => {
                eprintln!("vesta-broker: object-store presigner enabled");
                Some(Arc::new(s))
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("vesta-broker: object-store presigner DISABLED ({e})");
                None
            }
        };
        let sealed = seal.is_none();
        let (store, ssh_ca) = match seal {
            Some(u) => (
                Some(Arc::new(Mutex::new(u.store))),
                Some(Arc::new(u.ssh_ca)),
            ),
            None => (None, None),
        };
        Self {
            leases: Arc::new(Mutex::new(LeaseEngine::new(gen))),
            audit,
            sealed: Arc::new(AtomicBool::new(sealed)),
            store,
            ssh_ca,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            engines: Arc::new(build_engines(&cfg)),
            cred_handles: Arc::new(Mutex::new(HashMap::new())),
            ssh_serials: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()),
            harden,
            kms_jwt,
            object_store,
            cfg: Arc::new(cfg),
        }
    }

    /// Current seal state (`GET /v1/sys/seal-status`).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.sealed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record `session_id` as the active session for `principal_san`.
    pub fn bind_session(&self, principal_san: &str, session_id: &str) {
        self.sessions
            .lock()
            .expect("sessions lock")
            .insert(principal_san.to_owned(), session_id.to_owned());
    }

    /// The active session for `principal_san`, if one is open.
    #[must_use]
    pub fn active_session(&self, principal_san: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("sessions lock")
            .get(principal_san)
            .cloned()
    }

    /// Whether `principal_san` owns `session_id` — i.e. it is that principal's currently-bound
    /// active session. Ownership gate for session-end / lease renew+revoke: one principal must
    /// not be able to end another's session or renew/revoke another's lease by guessing its id.
    #[must_use]
    pub fn owns_session(&self, principal_san: &str, session_id: &str) -> bool {
        self.sessions
            .lock()
            .expect("sessions lock")
            .get(principal_san)
            .is_some_and(|sid| sid == session_id)
    }

    /// Snapshot of the principal→session bindings (SAN, session_id), for the read-only observe
    /// API. The console joins this onto the lease engine's session list to label sessions by SAN.
    #[must_use]
    pub fn list_sessions(&self) -> Vec<(String, String)> {
        self.sessions
            .lock()
            .expect("sessions lock")
            .iter()
            .map(|(san, sid)| (san.clone(), sid.clone()))
            .collect()
    }

    /// Snapshot of the role each active cred lease owns (lease_id → role), for the observe API's
    /// lease view. Username is deliberately excluded (it is the backend secret's handle).
    #[must_use]
    pub fn cred_roles(&self) -> std::collections::HashMap<String, String> {
        self.cred_handles
            .lock()
            .expect("cred handles lock")
            .iter()
            .map(|(lease_id, h)| (lease_id.clone(), h.role.clone()))
            .collect()
    }

    /// Snapshot of issued SSH cert serials by lease (lease_id → serial), for the observe API.
    #[must_use]
    pub fn list_ssh_serials(&self) -> Vec<(String, u64)> {
        self.ssh_serials
            .lock()
            .expect("ssh serials lock")
            .iter()
            .map(|(lease_id, serial)| (lease_id.clone(), *serial))
            .collect()
    }

    /// Drop any principal bindings pointing at `session_id` (called on session end).
    pub fn unbind_session(&self, session_id: &str) {
        self.sessions
            .lock()
            .expect("sessions lock")
            .retain(|_, v| v != session_id);
    }

    /// Remember an issued SSH cert's serial against its lease (for later revocation).
    pub fn record_ssh_serial(&self, lease_id: &str, serial: u64) {
        self.ssh_serials
            .lock()
            .expect("ssh serials lock")
            .insert(lease_id.to_owned(), serial);
    }

    /// Take (and forget) the cert serials owned by `lease_ids` — called when those leases
    /// are revoked/expired, so the serials can be recorded in the CA revocation list.
    #[must_use]
    pub fn take_ssh_serials(&self, lease_ids: &[String]) -> Vec<u64> {
        let mut map = self.ssh_serials.lock().expect("ssh serials lock");
        lease_ids.iter().filter_map(|id| map.remove(id)).collect()
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
        self.metrics.incr(&event.action);
        self.audit.emit(event);
    }

    /// Fail-closed emit for **issuance** ops: returns `Err` if the event could not be durably
    /// recorded, so the caller can tear down the just-issued credential and refuse — no cred is
    /// ever handed out without an audit record.
    ///
    /// # Errors
    /// [`vesta_transport::audit::AuditError`] when the durable append failed.
    pub fn try_emit(&self, event: &AuditEvent) -> Result<(), vesta_transport::audit::AuditError> {
        self.metrics.incr(&event.action);
        self.audit.try_emit(event)
    }
}
