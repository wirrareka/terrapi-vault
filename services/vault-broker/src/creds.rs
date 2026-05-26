//! Dynamic service-admin credential engines (Phase 3).
//!
//! A `CredEngine` mints an **ephemeral backend user** on issue and **deletes it** on
//! revoke/expiry (Vault database-secrets-engine semantics). Each issued cred is a
//! session-bound lease; when the lease is revoked — explicitly or by session cascade —
//! the broker calls the owning engine to tear the user down, so no backend user outlives
//! its lease.
//!
//! v1 roles (demon-confirmed, then infra/owner-corrected):
//! - `audit-writer` — OpenSearch RBAC, write-only on `audit-events-*`. The only brokered
//!   cred engine today; the concrete adapter calls the OpenSearch security REST API.
//!
//! (No RethinkDB engine: the legacy RethinkDB the stack runs uses no auth, so it is never
//! brokered — owner, 2026-05-26.)
//!
//! This module owns the engine abstraction, a registry, the teardown wiring, and an
//! in-memory `MockEngine` used for local dev and tests. Concrete network adapters
//! implement the same trait.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    /// The target backend rejected the operation. Constructed by concrete network
    /// adapters (OpenSearch); the in-memory `MockEngine` never fails.
    #[allow(dead_code)]
    #[error("backend error: {0}")]
    Backend(String),
}

/// A freshly issued ephemeral credential. Holds a secret; deliberately no `Debug`.
pub struct Issued {
    pub username: String,
    pub password: String,
    /// Hard ceiling the engine will honour for this user (renew never exceeds it).
    pub max_ttl_secs: u64,
}

/// A backend engine that mints and revokes ephemeral users for one role. Async because
/// concrete adapters talk to a network backend; `async_trait` keeps it `dyn`-compatible.
#[async_trait::async_trait]
pub trait CredEngine: Send + Sync {
    /// Create an ephemeral user for `tenant` valid up to `ttl_secs`.
    ///
    /// # Errors
    /// `Backend` if the target system rejects the create.
    async fn issue(&self, tenant: &str, ttl_secs: u64) -> Result<Issued, CredError>;

    /// Delete the ephemeral `username` (idempotent: a missing user is success).
    ///
    /// # Errors
    /// `Backend` if the target system errors on delete.
    async fn revoke(&self, username: &str) -> Result<(), CredError>;
}

/// role → engine. Built at boot from config (prod) or with a mock (dev).
#[derive(Default)]
pub struct CredEngines {
    map: HashMap<String, Box<dyn CredEngine>>,
}

impl CredEngines {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, role: impl Into<String>, engine: Box<dyn CredEngine>) {
        self.map.insert(role.into(), engine);
    }

    #[must_use]
    pub fn get(&self, role: &str) -> Option<&dyn CredEngine> {
        self.map.get(role).map(AsRef::as_ref)
    }
}

/// What a lease owns in a backend, so the broker can tear it down on revoke/expiry.
#[derive(Debug, Clone)]
pub struct CredHandle {
    pub role: String,
    pub username: String,
}

/// One torn-down handle, for auditing after a revoke/cascade.
pub struct TornDown {
    pub role: String,
    pub outcome_ok: bool,
}

/// Tear down the backend users for `lease_ids` (called after `revoke`/`end_session`):
/// for each lease that owns a cred handle, delete its backend user and drop the handle.
/// Returns one entry per torn-down handle so the caller can emit a `creds.revoke` event.
pub async fn teardown(
    engines: &CredEngines,
    handles: &Mutex<HashMap<String, CredHandle>>,
    lease_ids: &[String],
) -> Vec<TornDown> {
    // Collect + remove the handles under the lock, then await deletes lock-free.
    let owned: Vec<CredHandle> = {
        let mut guard = handles.lock().expect("cred handles lock");
        lease_ids.iter().filter_map(|id| guard.remove(id)).collect()
    };
    let mut torn = Vec::with_capacity(owned.len());
    for handle in owned {
        let outcome_ok = match engines.get(&handle.role) {
            Some(e) => e.revoke(&handle.username).await.is_ok(),
            None => false,
        };
        torn.push(TornDown {
            role: handle.role,
            outcome_ok,
        });
    }
    torn
}

/// In-memory engine for local dev / tests: tracks the set of "live" users. Generates an
/// opaque username + password; honours a fixed max TTL.
pub struct MockEngine {
    role: String,
    users: Mutex<HashSet<String>>,
    max_ttl_secs: u64,
}

impl MockEngine {
    #[must_use]
    pub fn new(role: impl Into<String>, max_ttl_secs: u64) -> Self {
        Self {
            role: role.into(),
            users: Mutex::new(HashSet::new()),
            max_ttl_secs,
        }
    }

    /// Test/inspection helper: is `username` currently live?
    #[cfg(test)]
    #[must_use]
    pub fn has_user(&self, username: &str) -> bool {
        self.users.lock().expect("mock users lock").contains(username)
    }
}

#[async_trait::async_trait]
impl CredEngine for MockEngine {
    async fn issue(&self, tenant: &str, ttl_secs: u64) -> Result<Issued, CredError> {
        let username = format!("v-{}-{tenant}-{}", self.role, crate::state::random_id());
        let password = crate::state::random_id();
        self.users
            .lock()
            .expect("mock users lock")
            .insert(username.clone());
        Ok(Issued {
            username,
            password,
            max_ttl_secs: ttl_secs.min(self.max_ttl_secs),
        })
    }

    async fn revoke(&self, username: &str) -> Result<(), CredError> {
        self.users.lock().expect("mock users lock").remove(username);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issue_then_teardown_deletes_the_backend_user() {
        let mut engines = CredEngines::new();
        engines.register("audit-writer", Box::new(MockEngine::new("audit-writer", 3600)));
        let handles = Mutex::new(HashMap::new());

        let issued = engines
            .get("audit-writer")
            .unwrap()
            .issue("3f1a9c2e-7b44-4d1e-9a2b-1c0d5e6f7a8b", 900)
            .await
            .unwrap();
        handles.lock().unwrap().insert(
            "lease-1".to_string(),
            CredHandle {
                role: "audit-writer".into(),
                username: issued.username.clone(),
            },
        );

        // teardown the lease → user deleted, handle dropped
        let torn = teardown(&engines, &handles, &["lease-1".to_string()]).await;
        assert_eq!(torn.len(), 1);
        assert!(torn[0].outcome_ok);
        assert!(handles.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn teardown_ignores_non_cred_leases() {
        let engines = CredEngines::new();
        let handles = Mutex::new(HashMap::new());
        // an SSH-cert lease id with no cred handle → no-op, no panic
        let torn = teardown(&engines, &handles, &["ssh-lease".to_string()]).await;
        assert!(torn.is_empty());
    }

    #[tokio::test]
    async fn mock_issue_tracks_and_revoke_clears() {
        let m = MockEngine::new("audit-writer", 3600);
        let c = m.issue("tenant", 900).await.unwrap();
        assert!(m.has_user(&c.username));
        assert!(c.max_ttl_secs <= 3600);
        m.revoke(&c.username).await.unwrap();
        assert!(!m.has_user(&c.username));
    }
}
