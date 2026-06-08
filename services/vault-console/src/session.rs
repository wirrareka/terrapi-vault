//! In-memory operator sessions + the pending-auth (PKCE) store for the OIDC RP.
//!
//! P1 is stateless across restarts by design (no DB — see `docs/planning/02-vault-console.md`):
//! sessions live in-process, so a restart just forces operators to re-login. Both stores are
//! small `Mutex<HashMap>`s with lazy TTL eviction on access.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::RngCore;

use crate::oidc::Operator;

/// Operator session lifetime. Short enough that a left-open console re-auths; long enough to not
/// nag during an ops session. A logout or restart ends it sooner.
const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
/// How long a started login may sit before the callback must arrive.
const PENDING_TTL: Duration = Duration::from_secs(600);

/// The session cookie name (HttpOnly, Secure, SameSite=Lax — set in `http`).
pub const COOKIE_NAME: &str = "vc_session";

struct SessionEntry {
    op: Operator,
    expires: Instant,
}

struct PendingEntry {
    verifier: String,
    nonce: String,
    expires: Instant,
}

/// Authenticated operator sessions, keyed by an opaque cookie value.
#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, SessionEntry>>,
}

impl Sessions {
    /// Create a session for `op`; returns the opaque cookie value.
    pub fn create(&self, op: Operator) -> String {
        let id = random_id();
        let mut map = self.map.lock().expect("sessions lock");
        map.insert(
            id.clone(),
            SessionEntry {
                op,
                expires: Instant::now() + SESSION_TTL,
            },
        );
        id
    }

    /// Look up a live (non-expired) session by its cookie value.
    pub fn get(&self, id: &str) -> Option<Operator> {
        let mut map = self.map.lock().expect("sessions lock");
        let now = Instant::now();
        map.retain(|_, e| e.expires > now);
        map.get(id).map(|e| e.op.clone())
    }

    /// End a session (logout). Idempotent.
    pub fn remove(&self, id: &str) {
        self.map.lock().expect("sessions lock").remove(id);
    }
}

/// Pending logins: `state` → the PKCE `verifier` + `nonce`, consumed once at the callback.
#[derive(Default)]
pub struct PendingAuth {
    map: Mutex<HashMap<String, PendingEntry>>,
}

impl PendingAuth {
    /// Stash a started login keyed by its `state`.
    pub fn put(&self, state: String, verifier: String, nonce: String) {
        let mut map = self.map.lock().expect("pending lock");
        let now = Instant::now();
        map.retain(|_, e| e.expires > now);
        map.insert(
            state,
            PendingEntry {
                verifier,
                nonce,
                expires: now + PENDING_TTL,
            },
        );
    }

    /// Consume the pending login for `state` (one-shot — also prevents `state` replay). Returns
    /// `(verifier, nonce)` if present and unexpired.
    pub fn take(&self, state: &str) -> Option<(String, String)> {
        let mut map = self.map.lock().expect("pending lock");
        let now = Instant::now();
        let e = map.remove(state)?;
        (e.expires > now).then_some((e.verifier, e.nonce))
    }
}

/// 32 random bytes, base64url — the session cookie value.
fn random_id() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op() -> Operator {
        Operator {
            subject: "op-1".into(),
            email: Some("op@x".into()),
        }
    }

    #[test]
    fn session_roundtrip_and_logout() {
        let s = Sessions::default();
        let id = s.create(op());
        assert_eq!(s.get(&id).unwrap().subject, "op-1");
        s.remove(&id);
        assert!(s.get(&id).is_none());
    }

    #[test]
    fn unknown_session_is_none() {
        assert!(Sessions::default().get("nope").is_none());
    }

    #[test]
    fn pending_is_one_shot() {
        let p = PendingAuth::default();
        p.put("STATE".into(), "verifier".into(), "nonce".into());
        let (v, n) = p.take("STATE").unwrap();
        assert_eq!(v, "verifier");
        assert_eq!(n, "nonce");
        // Second take fails — defeats state replay.
        assert!(p.take("STATE").is_none());
    }
}
