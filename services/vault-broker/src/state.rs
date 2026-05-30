//! Shared broker state: config, the lease/session engine, and the audit sink.

use crate::config::BrokerConfig;
use crate::creds::{CredEngines, CredHandle, MockEngine};
use crate::ssh_ca::SshCa;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use terrapi_vault::Vault;
use vault_transport::audit::{AuditEvent, AuditSink};
use vault_transport::lease::LeaseEngine;

/// Default TTL for a leased service-admin cred when the request omits `ttl_secs`.
pub const CREDS_DEFAULT_TTL_SECS: u64 = 900;

/// The result of a successful boot-time unseal: the opened at-rest store and the SSH CA
/// loaded from it. `Vault` owns a rusqlite connection (`!Sync`), hence the `Mutex`.
pub struct Unsealed {
    pub store: Vault,
    pub ssh_ca: SshCa,
}

/// A served HTTP request, summarised for the `vault_http_*` series. `route` is the matched
/// path *template* (e.g. `/v1/{group}/{tenant_id}/creds/{role}`), never the concrete path —
/// so tenant ids never reach the metrics surface and label cardinality stays bounded.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ReqKey {
    route: String,
    method: String,
    status: u16,
}

/// Minimal in-process metrics, exposed as Prometheus text on the loopback `8201` listener.
/// Per-action audit-event counters are bumped at the single `AppState::emit` site, so every
/// broker action (`ssh.sign`, `creds.issue`, `lease.expire`, …) is counted for free.
#[derive(Default)]
pub struct Metrics {
    events: Mutex<HashMap<String, u64>>,
    /// `vault_http_requests_total{route,method,status}`.
    requests: Mutex<HashMap<ReqKey, u64>>,
    /// Per-route latency: `route -> (count, sum_millis)` → `_count` + `_sum` series.
    latency: Mutex<HashMap<String, (u64, u64)>>,
    /// `vault_http_inflight` — requests currently being served (concurrency middleware).
    inflight: std::sync::atomic::AtomicI64,
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

    /// Record one served request: bump the per-`{route,method,status}` counter and add its
    /// latency to the per-route sum/count.
    pub fn record_request(&self, route: &str, method: &str, status: u16, dur: std::time::Duration) {
        *self
            .requests
            .lock()
            .expect("metrics lock")
            .entry(ReqKey {
                route: route.to_owned(),
                method: method.to_owned(),
                status,
            })
            .or_insert(0) += 1;
        let ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX);
        let mut lat = self.latency.lock().expect("metrics lock");
        let e = lat.entry(route.to_owned()).or_insert((0, 0));
        e.0 += 1;
        e.1 = e.1.saturating_add(ms);
    }

    /// Adjust the in-flight gauge (`+1` on entry, `-1` on exit).
    pub fn inflight_add(&self, delta: i64) {
        self.inflight
            .fetch_add(delta, std::sync::atomic::Ordering::Relaxed);
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

        out.push_str("# HELP vault_http_inflight Requests currently being served.\n");
        out.push_str("# TYPE vault_http_inflight gauge\n");
        let _ = writeln!(
            out,
            "vault_http_inflight {}",
            self.inflight
                .load(std::sync::atomic::Ordering::Relaxed)
                .max(0)
        );

        out.push_str(
            "# HELP vault_http_requests_total Served HTTP requests, by route/method/status.\n",
        );
        out.push_str("# TYPE vault_http_requests_total counter\n");
        let reqs = self.requests.lock().expect("metrics lock");
        let mut rows: Vec<_> = reqs.iter().collect();
        rows.sort_by(|a, b| {
            (&a.0.route, &a.0.method, a.0.status).cmp(&(&b.0.route, &b.0.method, b.0.status))
        });
        for (k, n) in rows {
            let _ = writeln!(
                out,
                "vault_http_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {n}",
                k.route, k.method, k.status
            );
        }

        out.push_str(
            "# HELP vault_http_request_duration_ms Per-route request latency (sum/count).\n",
        );
        out.push_str("# TYPE vault_http_request_duration_ms summary\n");
        let lat = self.latency.lock().expect("metrics lock");
        let mut lrows: Vec<_> = lat.iter().collect();
        lrows.sort_by(|a, b| a.0.cmp(b.0));
        for (route, (count, sum)) in lrows {
            let _ = writeln!(
                out,
                "vault_http_request_duration_ms_count{{route=\"{route}\"}} {count}"
            );
            let _ = writeln!(
                out,
                "vault_http_request_duration_ms_sum{{route=\"{route}\"}} {sum}"
            );
        }
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
    pub store: Option<Arc<Mutex<Vault>>>,
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
    for b in terrapi_vault::random_salt()
        .iter()
        .chain(terrapi_vault::random_salt().iter())
    {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build the dynamic-cred engine registry. If `VAULT_OS_*` is configured, the real
/// OpenSearch RBAC engine is registered under its role; otherwise dev registers an
/// in-memory `MockEngine` so the creds path is exercisable locally. With neither, the
/// registry is empty and an issuance for any role returns `404` (unconfigured role).
fn build_engines(cfg: &BrokerConfig) -> CredEngines {
    let mut engines = CredEngines::new();
    match crate::opensearch::OpenSearchEngine::from_env() {
        Ok(Some(os)) => {
            let role = os.role().to_owned();
            eprintln!("vault-broker: OpenSearch cred engine registered for role '{role}'");
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
        Err(e) => eprintln!("vault-broker: OpenSearch cred engine DISABLED ({e})"),
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
}
