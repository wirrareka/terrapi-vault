//! In-memory operator sessions + the pending-auth (PKCE) store for the OIDC RP.
//!
//! P1 is stateless across restarts by design (no DB — see `docs/planning/02-vesta-console.md`):
//! sessions live in-process, so a restart just forces operators to re-login. Both stores are
//! small `Mutex<HashMap>`s with lazy TTL eviction on access.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vesta_transport::lock::MutexExt;

use base64::Engine as _;
use rand::RngCore;

use crate::oidc::Operator;

/// Operator session lifetime. Short enough that a left-open console re-auths; long enough to not
/// nag during an ops session. A logout or restart ends it sooner.
const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
/// How long a started login may sit before the callback must arrive.
const PENDING_TTL: Duration = Duration::from_secs(600);
/// Hard cap on concurrent pending logins. `/auth/login` is unauthenticated, so without a bound an
/// attacker could insert entries faster than the 600 s TTL evicts them and grow the map without
/// limit. At the cap the oldest pending entry is evicted to make room (a never-completed login is
/// disposable). Sized far above any real concurrent-operator login burst.
const MAX_PENDING: usize = 4096;

/// The session cookie name (HttpOnly, Secure, SameSite=Lax — set in `http`). The `__Host-`
/// prefix host-locks the cookie: browsers only accept it when set with `Secure`, `Path=/`, and
/// no `Domain` (all true here), so a sibling/sub-domain can't plant or override the session.
pub const COOKIE_NAME: &str = "__Host-vc_session";

struct SessionEntry {
    op: Operator,
    /// The id_token `sid` captured at login (OIDC Back-Channel Logout 1.0 §2) — `None` for the dev
    /// stub or a login id_token without `sid`. A Logout Token's `sid` maps back to the session(s)
    /// to end. `sid` is omitted on refresh-minted id_tokens, so it is read from the *login* token.
    sid: Option<String>,
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
    /// Create a session for `op` (carrying the login id_token's `sid`, if any); returns the opaque
    /// cookie value.
    pub fn create(&self, op: Operator, sid: Option<String>) -> String {
        let id = random_id();
        let mut map = self.map.lock_recover();
        map.insert(
            id.clone(),
            SessionEntry {
                op,
                sid,
                expires: Instant::now() + SESSION_TTL,
            },
        );
        id
    }

    /// Look up a live (non-expired) session by its cookie value.
    pub fn get(&self, id: &str) -> Option<Operator> {
        let mut map = self.map.lock_recover();
        let now = Instant::now();
        map.retain(|_, e| e.expires > now);
        map.get(id).map(|e| e.op.clone())
    }

    /// End a session (logout). Idempotent.
    pub fn remove(&self, id: &str) {
        self.map.lock_recover().remove(id);
    }

    /// Back-Channel Logout: end the session(s) the identity Logout Token targets, and return how
    /// many were ended. Per BCL 1.0 §2.4: a token carrying `sid` ends the session bound to that
    /// `sid`; a token with only `sub` (client not registered `..session_required`) ends *all* the
    /// user's sessions. Idempotent — zero matches is fine (the session may already be gone).
    pub fn logout_matching(&self, sid: Option<&str>, sub: Option<&str>) -> usize {
        let mut map = self.map.lock_recover();
        let before = map.len();
        match (sid, sub) {
            (Some(sid), _) => map.retain(|_, e| e.sid.as_deref() != Some(sid)),
            (None, Some(sub)) => map.retain(|_, e| e.op.subject != sub),
            (None, None) => {} // validation guarantees at least one is present
        }
        before - map.len()
    }
}

/// Pending logins: `state` → the PKCE `verifier` + `nonce`, consumed once at the callback.
#[derive(Default)]
pub struct PendingAuth {
    map: Mutex<HashMap<String, PendingEntry>>,
}

impl PendingAuth {
    /// Stash a started login keyed by its `state`. Bounded by [`MAX_PENDING`]: expired entries are
    /// swept first, then — if still at the cap — the single oldest entry is evicted before insert,
    /// so an unauthenticated `/auth/login` flood cannot grow the map without limit.
    pub fn put(&self, state: String, verifier: String, nonce: String) {
        let mut map = self.map.lock_recover();
        let now = Instant::now();
        map.retain(|_, e| e.expires > now);
        // At the cap (after sweeping expired): REFUSE the new login rather than evict an existing
        // one. Under an unauthenticated /auth/login flood this keeps an in-flight legitimate login
        // from being knocked out before its callback returns, and is O(1) (no full-map scan). The
        // dropped attempt simply fails at the callback ("unknown or expired state") and retries.
        if map.len() >= MAX_PENDING {
            return;
        }
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
        let mut map = self.map.lock_recover();
        let now = Instant::now();
        let e = map.remove(state)?;
        (e.expires > now).then_some((e.verifier, e.nonce))
    }
}

/// Replay window for Back-Channel Logout `jti`s — kept ≥ the token's accepted `iat` freshness so a
/// token replayed within its freshness window is caught here, and a staler one is already rejected
/// on `iat`.
const JTI_TTL: Duration = Duration::from_secs(300);
/// Memory bound on the seen-`jti` set. Sized far above any real logout burst; above it we stop
/// recording (see [`SeenJtis::check_and_record`]).
const MAX_JTIS: usize = 8192;

/// Seen Back-Channel Logout `jti`s, for replay rejection (BCL 1.0 §2.4). Bounded + lazily
/// TTL-evicted like [`PendingAuth`].
#[derive(Default)]
pub struct SeenJtis {
    map: Mutex<HashMap<String, Instant>>,
}

impl SeenJtis {
    /// Record `jti`; returns `true` if fresh (accept the logout), `false` if already seen (replay →
    /// reject). At the [`MAX_JTIS`] cap (after sweeping expired) we accept WITHOUT recording: a
    /// replayed logout is idempotent (it re-ends already-dead sessions), so failing open keeps the
    /// map bounded under a flood of distinct tokens without ever dropping a real logout.
    pub fn check_and_record(&self, jti: &str) -> bool {
        let mut map = self.map.lock_recover();
        let now = Instant::now();
        map.retain(|_, exp| *exp > now);
        if map.contains_key(jti) {
            return false;
        }
        if map.len() < MAX_JTIS {
            map.insert(jti.to_string(), now + JTI_TTL);
        }
        true
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
        let id = s.create(op(), None);
        assert_eq!(s.get(&id).unwrap().subject, "op-1");
        s.remove(&id);
        assert!(s.get(&id).is_none());
    }

    #[test]
    fn backchannel_logout_by_sid_ends_only_that_session() {
        let s = Sessions::default();
        let a = s.create(op(), Some("sid-A".into()));
        let b = s.create(op(), Some("sid-B".into()));
        // A token carrying sid-A ends only the sid-A session, even though both are the same `sub`.
        assert_eq!(s.logout_matching(Some("sid-A"), Some("op-1")), 1);
        assert!(s.get(&a).is_none());
        assert!(s.get(&b).is_some());
    }

    #[test]
    fn backchannel_logout_by_sub_ends_all_user_sessions() {
        let s = Sessions::default();
        let a = s.create(op(), Some("sid-A".into()));
        let b = s.create(op(), Some("sid-B".into()));
        // No sid in the token (client not session-bound) → end every session for the `sub`.
        assert_eq!(s.logout_matching(None, Some("op-1")), 2);
        assert!(s.get(&a).is_none());
        assert!(s.get(&b).is_none());
    }

    #[test]
    fn backchannel_logout_is_idempotent_no_match() {
        let s = Sessions::default();
        s.create(op(), Some("sid-A".into()));
        assert_eq!(s.logout_matching(Some("sid-Z"), None), 0);
    }

    #[test]
    fn seen_jtis_accepts_once_then_rejects_replay() {
        let j = SeenJtis::default();
        assert!(j.check_and_record("jti-1"), "first sight accepted");
        assert!(!j.check_and_record("jti-1"), "replay rejected");
        assert!(j.check_and_record("jti-2"), "a different jti is fine");
    }

    #[test]
    fn unknown_session_is_none() {
        assert!(Sessions::default().get("nope").is_none());
    }

    #[test]
    fn pending_is_capped_refusing_new_not_evicting_inflight() {
        let p = PendingAuth::default();
        for i in 0..(MAX_PENDING + 100) {
            p.put(format!("state-{i}"), "v".into(), "n".into());
        }
        let map = p.map.lock_recover();
        assert!(map.len() <= MAX_PENDING, "pending map must stay bounded");
        drop(map);
        // Refuse-new at the cap: an early (in-flight) login is preserved, late ones are refused —
        // a flood cannot knock out a login that was already pending.
        assert!(p.take("state-0").is_some());
        assert!(p.take(&format!("state-{}", MAX_PENDING + 99)).is_none());
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
