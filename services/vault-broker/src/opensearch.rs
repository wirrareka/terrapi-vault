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
        // Disabling OpenSearch TLS verification exposes the privileged admin credential to a
        // MITM, so it is honoured only in insecure-dev. In production it is refused (the engine
        // then stays disabled → creds `404`, fail-closed) rather than silently trusting any cert.
        if insecure && std::env::var("VAULT_ALLOW_INSECURE_DEV").as_deref() != Ok("1") {
            return Err(
                "VAULT_OS_INSECURE_TLS=1 disables OpenSearch TLS verification and is \
                        refused outside VAULT_ALLOW_INSECURE_DEV=1; use a CA-trusted OpenSearch \
                        endpoint in production"
                    .to_string(),
            );
        }

        let ca_path = std::env::var("VAULT_OS_CA").ok().filter(|s| !s.is_empty());
        let client = build_os_client(insecure, ca_path, "VAULT_OS_CA")?;

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

/// Build a reqwest client for an OpenSearch endpoint. When `ca_pem_path` is set, that PEM (bundle)
/// becomes the **sole** trust root (built-in/public roots disabled) — so a fleet-CA-signed node
/// cert verifies without relying on the OS system trust (the rustls client ignores it). `insecure`
/// disables verification entirely (dev only). `label` names the env source for error messages.
/// Shared by the cred engine and the audit shipper so both gain the CA option uniformly.
///
/// # Errors
/// `String` if the CA file can't be read/parsed or the client can't be built.
pub(crate) fn build_os_client(
    insecure: bool,
    ca_pem_path: Option<String>,
    label: &str,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().danger_accept_invalid_certs(insecure);
    if let Some(path) = ca_pem_path {
        let pem = std::fs::read(&path).map_err(|e| format!("{label} {path}: {e}"))?;
        builder = builder.tls_built_in_root_certs(false);
        for cert in reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| format!("{label} parse: {e}"))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|e| format!("opensearch http client: {e}"))
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

    #[test]
    fn build_os_client_no_ca_builds() {
        // No CA + verifying: builds fine (uses default roots). Insecure also builds.
        assert!(build_os_client(false, None, "VAULT_OS_CA").is_ok());
        assert!(build_os_client(true, None, "VAULT_OS_CA").is_ok());
    }

    #[test]
    fn build_os_client_unreadable_ca_errors() {
        let err = build_os_client(
            false,
            Some("/nonexistent/fleet-ca.pem".into()),
            "VAULT_OS_CA",
        )
        .unwrap_err();
        assert!(
            err.contains("VAULT_OS_CA"),
            "error names the env source: {err}"
        );
    }

    #[test]
    fn build_os_client_accepts_a_valid_ca_pem() {
        // A self-signed cert PEM is a valid trust root to add (verification target is separate).
        let cert = rcgen::generate_simple_self_signed(vec!["ca.test".into()]).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vault-os-ca-test-{}.pem", std::process::id()));
        std::fs::write(&path, cert.cert.pem()).unwrap();
        assert!(build_os_client(
            false,
            Some(path.to_string_lossy().into_owned()),
            "VAULT_OS_CA"
        )
        .is_ok());
        let _ = std::fs::remove_file(&path);
    }

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
