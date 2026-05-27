//! OpenSearch RBAC dynamic-cred engine (Phase 3, modern primary engine).
//!
//! Mints an ephemeral OpenSearch **internal user** mapped to a security role (default
//! `audit-writer`, write-only on `audit-events-*`) via the security REST API
//! (`PUT /_plugins/_security/api/internalusers/{user}`), and deletes it on revoke/expiry
//! (`DELETE`). The broker authenticates to the security API with a configured admin
//! credential — the one privileged backend secret, used only to broker short-TTL users.
//!
//! Configured from env (`VAULT_OS_*`); absent → engine not registered (creds `404`).
//! TLS is rustls; `VAULT_OS_INSECURE_TLS=1` accepts a self-signed cert for local/dev only.

use crate::creds::{CredEngine, CredError, Issued};
use crate::state::random_id;

/// Engine config + HTTP client. No `Debug` (holds the admin password).
pub struct OpenSearchEngine {
    client: reqwest::Client,
    base_url: String,
    admin_user: String,
    admin_password: String,
    security_role: String,
    max_ttl_secs: u64,
}

impl OpenSearchEngine {
    /// Build from `VAULT_OS_*` env, or `None` if `VAULT_OS_URL` is unset.
    ///
    /// # Errors
    /// `String` if required vars are missing or the HTTP client cannot be built.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(base_url) = std::env::var("VAULT_OS_URL") else {
            return Ok(None);
        };
        let admin_user = std::env::var("VAULT_OS_ADMIN_USER")
            .map_err(|_| "VAULT_OS_URL set but VAULT_OS_ADMIN_USER missing".to_string())?;
        let admin_password = std::env::var("VAULT_OS_ADMIN_PASSWORD")
            .map_err(|_| "VAULT_OS_URL set but VAULT_OS_ADMIN_PASSWORD missing".to_string())?;
        let security_role =
            std::env::var("VAULT_OS_ROLE").unwrap_or_else(|_| "audit-writer".to_string());
        let max_ttl_secs = std::env::var("VAULT_OS_MAX_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(28_800);
        let insecure = std::env::var("VAULT_OS_INSECURE_TLS").as_deref() == Ok("1");

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(|e| format!("opensearch http client: {e}"))?;

        Ok(Some(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            admin_user,
            admin_password,
            security_role,
            max_ttl_secs,
        }))
    }

    /// The security role this engine is registered under (its broker `{role}`).
    #[must_use]
    pub fn role(&self) -> &str {
        &self.security_role
    }

    fn user_url(&self, username: &str) -> String {
        format!(
            "{}/_plugins/_security/api/internalusers/{username}",
            self.base_url
        )
    }
}

#[async_trait::async_trait]
impl CredEngine for OpenSearchEngine {
    async fn issue(&self, tenant: &str, ttl_secs: u64) -> Result<Issued, CredError> {
        let username = format!("v-{}-{}", self.security_role, random_id());
        let password = random_id();
        let body = serde_json::json!({
            "password": password,
            "opendistro_security_roles": [self.security_role],
            "attributes": { "broker": "vault", "tenant": tenant }
        });
        let resp = self
            .client
            .put(self.user_url(&username))
            .basic_auth(&self.admin_user, Some(&self.admin_password))
            .json(&body)
            .send()
            .await
            .map_err(|e| CredError::Backend(format!("create user request: {e}")))?;
        if !resp.status().is_success() {
            let code = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(CredError::Backend(format!("create user {code}: {detail}")));
        }
        Ok(Issued {
            username,
            password,
            max_ttl_secs: ttl_secs.min(self.max_ttl_secs),
        })
    }

    async fn revoke(&self, username: &str) -> Result<(), CredError> {
        let resp = self
            .client
            .delete(self.user_url(username))
            .basic_auth(&self.admin_user, Some(&self.admin_password))
            .send()
            .await
            .map_err(|e| CredError::Backend(format!("delete user request: {e}")))?;
        // 404 = already gone → idempotent success.
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let code = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            Err(CredError::Backend(format!("delete user {code}: {detail}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test against a live OpenSearch. Skipped unless `VAULT_OS_TEST_URL` is
    /// set (see docs/dev/opensearch-it.md for the docker one-liner). Verifies the full
    /// create → exists → delete → gone cycle through the security REST API.
    #[tokio::test]
    async fn issue_creates_and_revoke_deletes_a_real_user() {
        let Ok(url) = std::env::var("VAULT_OS_TEST_URL") else {
            eprintln!("skipping: VAULT_OS_TEST_URL unset");
            return;
        };
        let user = std::env::var("VAULT_OS_TEST_ADMIN_USER").unwrap_or_else(|_| "admin".into());
        let pass =
            std::env::var("VAULT_OS_TEST_ADMIN_PASSWORD").expect("VAULT_OS_TEST_ADMIN_PASSWORD");
        // A built-in role so the security API validates the mapping without extra setup.
        let role = std::env::var("VAULT_OS_TEST_ROLE").unwrap_or_else(|_| "readall".into());

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let engine = OpenSearchEngine {
            client: client.clone(),
            base_url: url.trim_end_matches('/').to_string(),
            admin_user: user.clone(),
            admin_password: pass.clone(),
            security_role: role,
            max_ttl_secs: 3600,
        };

        let issued = engine
            .issue("11111111-1111-4111-8111-111111111111", 900)
            .await
            .unwrap();
        // exists
        let exists = client
            .get(engine.user_url(&issued.username))
            .basic_auth(&user, Some(&pass))
            .send()
            .await
            .unwrap();
        assert!(
            exists.status().is_success(),
            "user should exist after issue"
        );

        engine.revoke(&issued.username).await.unwrap();
        // gone
        let gone = client
            .get(engine.user_url(&issued.username))
            .basic_auth(&user, Some(&pass))
            .send()
            .await
            .unwrap();
        assert_eq!(
            gone.status(),
            reqwest::StatusCode::NOT_FOUND,
            "user should be deleted"
        );
    }
}
