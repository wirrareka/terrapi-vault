//! Lease + session engine (pure logic, storage-agnostic).
//!
//! Every issued credential is a **lease**; every lease is a **child of an operator
//! session**. Ending the session cascade-revokes its children — this is demon's
//! "creds die when the operator session ends" (coordination/conventions/secrets-broker.md).
//!
//! Time-aware but clock-free: every time-relevant call takes `now` (unix seconds) from the
//! caller, so the broker injects the real clock while tests stay deterministic. Deadlines
//! are absolute. [`LeaseEngine::sweep`] expires sessions (hard TTL or idle timeout) and
//! individual leases (their own TTL) — this is what actually enforces "short-TTL creds
//! auto-expire"; the broker runs it on a timer and tears down the backend users.
//!
//! This module is in-memory and deliberately free of any backend (SSH CA, OpenSearch,
//! RethinkDB) — the broker layers the real backend teardown on top of `revoke`/`sweep`.

use std::collections::HashMap;

pub type SessionId = String;
pub type LeaseId = String;

/// An operator session. Leases issued during it are its children.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    /// Absolute hard expiry (open time + ttl).
    pub expires_at: u64,
    /// Absolute idle deadline; advanced by activity, never past `expires_at`.
    pub idle_deadline: u64,
    idle_timeout_secs: u64,
    children: Vec<LeaseId>,
    ended: bool,
}

/// A single issued credential lease.
#[derive(Debug, Clone)]
pub struct Lease {
    pub id: LeaseId,
    pub parent_session: SessionId,
    /// Absolute expiry; renew extends it up to `max_deadline` / the session's expiry.
    pub expires_at: u64,
    /// Absolute hard ceiling (issue time + max_ttl).
    pub max_deadline: u64,
    pub renewable: bool,
    pub revoked: bool,
}

/// What a `sweep` expired, so the broker can unbind sessions + tear down backend users.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub ended_sessions: Vec<SessionId>,
    pub revoked_leases: Vec<LeaseId>,
}

impl Swept {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ended_sessions.is_empty() && self.revoked_leases.is_empty()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("no such session")]
    NoSuchSession,
    #[error("no such lease")]
    NoSuchLease,
    #[error("session has ended")]
    SessionEnded,
    #[error("lease is not renewable")]
    NotRenewable,
    #[error("lease already revoked")]
    AlreadyRevoked,
}

/// In-memory lease/session bookkeeping. Ids are issued by an injected generator so the
/// broker controls their format (opaque, unguessable) and tests stay deterministic.
pub struct LeaseEngine<F: FnMut() -> String> {
    sessions: HashMap<SessionId, Session>,
    leases: HashMap<LeaseId, Lease>,
    gen_id: F,
}

impl<F: FnMut() -> String> LeaseEngine<F> {
    pub fn new(gen_id: F) -> Self {
        Self {
            sessions: HashMap::new(),
            leases: HashMap::new(),
            gen_id,
        }
    }

    /// Open an operator session at `now`. Returns its id.
    pub fn open_session(&mut self, now: u64, ttl_secs: u64, idle_timeout_secs: u64) -> SessionId {
        let id = (self.gen_id)();
        self.sessions.insert(
            id.clone(),
            Session {
                id: id.clone(),
                expires_at: now.saturating_add(ttl_secs),
                idle_deadline: now.saturating_add(idle_timeout_secs),
                idle_timeout_secs,
                children: Vec::new(),
                ended: false,
            },
        );
        id
    }

    /// Is the session live at `now` (exists, not ended, within hard + idle deadlines)?
    fn session_live(s: &Session, now: u64) -> bool {
        !s.ended && now < s.expires_at && now < s.idle_deadline
    }

    /// Issue a lease as a child of `session`, valid `ttl_secs` (capped at `max_ttl_secs`
    /// and at the session's hard expiry). Counts as activity → advances the session's idle
    /// deadline.
    ///
    /// # Errors
    /// `NoSuchSession` if unknown; `SessionEnded` if it has ended or timed out.
    pub fn issue_lease(
        &mut self,
        now: u64,
        session: &SessionId,
        ttl_secs: u64,
        max_ttl_secs: u64,
        renewable: bool,
    ) -> Result<LeaseId, LeaseError> {
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(LeaseError::NoSuchSession)?;
        if !Self::session_live(s, now) {
            return Err(LeaseError::SessionEnded);
        }
        Self::touch(s, now);
        let max_deadline = now.saturating_add(max_ttl_secs).min(s.expires_at);
        let expires_at = now.saturating_add(ttl_secs).min(max_deadline);
        let id = (self.gen_id)();
        self.leases.insert(
            id.clone(),
            Lease {
                id: id.clone(),
                parent_session: session.clone(),
                expires_at,
                max_deadline,
                renewable,
                revoked: false,
            },
        );
        s.children.push(id.clone());
        Ok(id)
    }

    /// Renew a lease at `now` by `increment`, never past `max_deadline` or the session's
    /// expiry. Counts as activity. Returns the new remaining ttl (seconds).
    ///
    /// # Errors
    /// `NoSuchLease` if unknown; `AlreadyRevoked`; `NotRenewable`; `SessionEnded` if the
    /// lease or its session has already expired.
    pub fn renew(&mut self, now: u64, lease: &LeaseId, increment: u64) -> Result<u64, LeaseError> {
        let l = self.leases.get_mut(lease).ok_or(LeaseError::NoSuchLease)?;
        if l.revoked {
            return Err(LeaseError::AlreadyRevoked);
        }
        if !l.renewable {
            return Err(LeaseError::NotRenewable);
        }
        if now >= l.expires_at {
            return Err(LeaseError::AlreadyRevoked); // expired, pending sweep
        }
        let session_expiry = self
            .sessions
            .get(&l.parent_session)
            .filter(|s| Self::session_live(s, now))
            .map(|s| s.expires_at)
            .ok_or(LeaseError::SessionEnded)?;
        let ceiling = l.max_deadline.min(session_expiry);
        l.expires_at = now.saturating_add(increment).min(ceiling);
        if let Some(s) = self.sessions.get_mut(&l.parent_session) {
            Self::touch(s, now);
        }
        Ok(l.expires_at.saturating_sub(now))
    }

    /// Advance a session's idle deadline on activity, capped at its hard expiry.
    fn touch(s: &mut Session, now: u64) {
        s.idle_deadline = now.saturating_add(s.idle_timeout_secs).min(s.expires_at);
    }

    /// Revoke a single lease.
    ///
    /// # Errors
    /// `NoSuchLease` if unknown; `AlreadyRevoked` if it was already revoked.
    pub fn revoke(&mut self, lease: &LeaseId) -> Result<(), LeaseError> {
        let l = self.leases.get_mut(lease).ok_or(LeaseError::NoSuchLease)?;
        if l.revoked {
            return Err(LeaseError::AlreadyRevoked);
        }
        l.revoked = true;
        Ok(())
    }

    /// End a session and cascade-revoke every still-live child lease. Returns the ids
    /// that were revoked by this call (already-revoked children are not repeated).
    ///
    /// # Errors
    /// `NoSuchSession` if the session is unknown.
    pub fn end_session(&mut self, session: &SessionId) -> Result<Vec<LeaseId>, LeaseError> {
        let children = {
            let s = self
                .sessions
                .get_mut(session)
                .ok_or(LeaseError::NoSuchSession)?;
            s.ended = true;
            s.children.clone()
        };
        Ok(self.revoke_each(&children))
    }

    /// Expire sessions (hard TTL or idle timeout) and individual leases (own TTL) as of
    /// `now`. Ending a session cascade-revokes its live children. Returns everything newly
    /// ended/revoked so the broker can unbind principals and delete backend users.
    pub fn sweep(&mut self, now: u64) -> Swept {
        let mut swept = Swept::default();

        // 1. Sessions past their hard or idle deadline → end + cascade.
        let expired: Vec<SessionId> = self
            .sessions
            .values()
            .filter(|s| !s.ended && (now >= s.expires_at || now >= s.idle_deadline))
            .map(|s| s.id.clone())
            .collect();
        for sid in expired {
            let Some(s) = self.sessions.get_mut(&sid) else {
                continue;
            };
            s.ended = true;
            let children = s.children.clone();
            swept.revoked_leases.extend(self.revoke_each(&children));
            swept.ended_sessions.push(sid);
        }

        // 2. Individual leases past their own expiry (whose session is still live).
        let expired_leases: Vec<LeaseId> = self
            .leases
            .values()
            .filter(|l| !l.revoked && now >= l.expires_at)
            .map(|l| l.id.clone())
            .collect();
        swept
            .revoked_leases
            .extend(self.revoke_each(&expired_leases));

        swept
    }

    /// Mark each still-live lease revoked; return the ones actually flipped.
    fn revoke_each(&mut self, ids: &[LeaseId]) -> Vec<LeaseId> {
        let mut revoked = Vec::new();
        for id in ids {
            if let Some(l) = self.leases.get_mut(id) {
                if !l.revoked {
                    l.revoked = true;
                    revoked.push(id.clone());
                }
            }
        }
        revoked
    }

    #[must_use]
    pub fn lease(&self, id: &LeaseId) -> Option<&Lease> {
        self.leases.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq_gen() -> impl FnMut() -> String {
        let mut n = 0u64;
        move || {
            n += 1;
            format!("id-{n}")
        }
    }

    #[test]
    fn ending_session_cascade_revokes_children() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 28_800, 1_800);
        let a = e.issue_lease(0, &s, 900, 28_800, true).unwrap();
        let b = e.issue_lease(0, &s, 300, 28_800, false).unwrap();
        assert!(!e.lease(&a).unwrap().revoked);
        let revoked = e.end_session(&s).unwrap();
        assert_eq!(revoked.len(), 2);
        assert!(e.lease(&a).unwrap().revoked);
        assert!(e.lease(&b).unwrap().revoked);
    }

    #[test]
    fn cannot_issue_under_ended_session() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 10, 5);
        e.end_session(&s).unwrap();
        assert_eq!(
            e.issue_lease(0, &s, 1, 1, true),
            Err(LeaseError::SessionEnded)
        );
    }

    #[test]
    fn ttl_capped_to_max_and_session_on_issue() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 10_000, 10_000);
        // request 9999s, max_ttl 900 → expires at 900 (max_ttl is the binding cap here)
        let l = e.issue_lease(0, &s, 9_999, 900, true).unwrap();
        assert_eq!(e.lease(&l).unwrap().expires_at, 900);
        // renew at t=10 by 10_000 → capped at max_deadline (900) → remaining 890
        assert_eq!(e.renew(10, &l, 10_000).unwrap(), 890);
    }

    #[test]
    fn issue_caps_lease_to_session_hard_expiry() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 100, 100);
        // max_ttl 900 but the session only lives to 100 → lease capped at 100
        let l = e.issue_lease(0, &s, 9_999, 900, true).unwrap();
        assert_eq!(e.lease(&l).unwrap().expires_at, 100);
    }

    #[test]
    fn non_renewable_and_double_revoke_rejected() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 100, 100);
        let l = e.issue_lease(0, &s, 50, 50, false).unwrap();
        assert_eq!(e.renew(0, &l, 10), Err(LeaseError::NotRenewable));
        e.revoke(&l).unwrap();
        assert_eq!(e.revoke(&l), Err(LeaseError::AlreadyRevoked));
    }

    #[test]
    fn sweep_expires_lease_past_its_ttl_but_keeps_live_session() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 28_800, 28_800);
        let cert = e.issue_lease(0, &s, 900, 900, false).unwrap();
        // before expiry: nothing swept
        assert!(e.sweep(899).is_empty());
        // at/after the lease ttl: lease revoked, session still live
        let swept = e.sweep(900);
        assert_eq!(swept.revoked_leases, vec![cert.clone()]);
        assert!(swept.ended_sessions.is_empty());
        assert!(e.lease(&cert).unwrap().revoked);
        // a second sweep is a no-op (already revoked)
        assert!(e.sweep(1_000).is_empty());
    }

    #[test]
    fn sweep_expires_session_on_hard_ttl_and_cascades() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 100, 100);
        let l = e.issue_lease(0, &s, 100, 100, true).unwrap();
        let swept = e.sweep(100);
        assert_eq!(swept.ended_sessions, vec![s]);
        assert!(swept.revoked_leases.contains(&l));
        assert!(e.lease(&l).unwrap().revoked);
    }

    #[test]
    fn sweep_expires_idle_session() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 28_800, 1_800); // 8h hard, 30m idle
                                                  // no activity → idle deadline 1800
        assert!(e.sweep(1_799).is_empty());
        let swept = e.sweep(1_800);
        assert_eq!(swept.ended_sessions, vec![s]);
    }

    #[test]
    fn activity_extends_idle_deadline() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(0, 28_800, 1_800);
        // activity at t=1000 pushes idle deadline to 1000+1800=2800 (lease long-lived so it
        // doesn't itself expire and confound the idle check)
        e.issue_lease(1_000, &s, 28_800, 28_800, false).unwrap();
        assert!(e.sweep(1_800).is_empty()); // would have idled out without the touch
        let swept = e.sweep(2_800);
        assert_eq!(swept.ended_sessions, vec![s]);
    }
}
