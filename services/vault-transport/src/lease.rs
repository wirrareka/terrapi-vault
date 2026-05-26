//! Lease + session engine (pure logic, storage-agnostic).
//!
//! Every issued credential is a **lease**; every lease is a **child of an operator
//! session**. Ending the session cascade-revokes its children — this is demon's
//! "creds die when the operator session ends" (coordination/conventions/secrets-broker.md).
//!
//! This module is in-memory and deliberately free of any backend (SSH CA, OpenSearch,
//! RethinkDB) — the broker layers the real backend teardown on top of `revoke`/`end_session`.

use std::collections::HashMap;

pub type SessionId = String;
pub type LeaseId = String;

/// An operator session. Leases issued during it are its children.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub ttl_secs: u64,
    pub idle_timeout_secs: u64,
    children: Vec<LeaseId>,
    ended: bool,
}

/// A single issued credential lease.
#[derive(Debug, Clone)]
pub struct Lease {
    pub id: LeaseId,
    pub parent_session: SessionId,
    pub ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub renewable: bool,
    pub revoked: bool,
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

    /// Open an operator session. Returns its id.
    pub fn open_session(&mut self, ttl_secs: u64, idle_timeout_secs: u64) -> SessionId {
        let id = (self.gen_id)();
        self.sessions.insert(
            id.clone(),
            Session {
                id: id.clone(),
                ttl_secs,
                idle_timeout_secs,
                children: Vec::new(),
                ended: false,
            },
        );
        id
    }

    /// Issue a lease as a child of `session`. `ttl_secs` is clamped to `max_ttl_secs`.
    ///
    /// # Errors
    /// `NoSuchSession` if the session is unknown; `SessionEnded` if it has ended.
    pub fn issue_lease(
        &mut self,
        session: &SessionId,
        ttl_secs: u64,
        max_ttl_secs: u64,
        renewable: bool,
    ) -> Result<LeaseId, LeaseError> {
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(LeaseError::NoSuchSession)?;
        if s.ended {
            return Err(LeaseError::SessionEnded);
        }
        let id = (self.gen_id)();
        self.leases.insert(
            id.clone(),
            Lease {
                id: id.clone(),
                parent_session: session.clone(),
                ttl_secs: ttl_secs.min(max_ttl_secs),
                max_ttl_secs,
                renewable,
                revoked: false,
            },
        );
        s.children.push(id.clone());
        Ok(id)
    }

    /// Renew a lease by `increment`, never beyond `max_ttl_secs`. Returns the new ttl.
    ///
    /// # Errors
    /// `NoSuchLease` if unknown; `AlreadyRevoked` if revoked; `NotRenewable` if the
    /// lease was issued non-renewable.
    pub fn renew(&mut self, lease: &LeaseId, increment: u64) -> Result<u64, LeaseError> {
        let l = self.leases.get_mut(lease).ok_or(LeaseError::NoSuchLease)?;
        if l.revoked {
            return Err(LeaseError::AlreadyRevoked);
        }
        if !l.renewable {
            return Err(LeaseError::NotRenewable);
        }
        l.ttl_secs = (l.ttl_secs + increment).min(l.max_ttl_secs);
        Ok(l.ttl_secs)
    }

    /// Revoke a single lease. Returns Ok once it is revoked.
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
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(LeaseError::NoSuchSession)?;
        s.ended = true;
        let children = s.children.clone();
        let mut revoked = Vec::new();
        for id in children {
            if let Some(l) = self.leases.get_mut(&id) {
                if !l.revoked {
                    l.revoked = true;
                    revoked.push(id);
                }
            }
        }
        Ok(revoked)
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
        let s = e.open_session(28_800, 1_800);
        let a = e.issue_lease(&s, 900, 28_800, true).unwrap();
        let b = e.issue_lease(&s, 300, 28_800, false).unwrap();
        assert!(!e.lease(&a).unwrap().revoked);
        let revoked = e.end_session(&s).unwrap();
        assert_eq!(revoked.len(), 2);
        assert!(e.lease(&a).unwrap().revoked);
        assert!(e.lease(&b).unwrap().revoked);
    }

    #[test]
    fn cannot_issue_under_ended_session() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(10, 5);
        e.end_session(&s).unwrap();
        assert_eq!(e.issue_lease(&s, 1, 1, true), Err(LeaseError::SessionEnded));
    }

    #[test]
    fn ttl_clamped_to_max_on_issue_and_renew() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(100, 50);
        let l = e.issue_lease(&s, 9_999, 900, true).unwrap();
        assert_eq!(e.lease(&l).unwrap().ttl_secs, 900); // clamped on issue
        assert_eq!(e.renew(&l, 10_000).unwrap(), 900); // clamped on renew
    }

    #[test]
    fn non_renewable_and_double_revoke_rejected() {
        let mut e = LeaseEngine::new(seq_gen());
        let s = e.open_session(100, 50);
        let l = e.issue_lease(&s, 300, 300, false).unwrap();
        assert_eq!(e.renew(&l, 10), Err(LeaseError::NotRenewable));
        e.revoke(&l).unwrap();
        assert_eq!(e.revoke(&l), Err(LeaseError::AlreadyRevoked));
    }
}
