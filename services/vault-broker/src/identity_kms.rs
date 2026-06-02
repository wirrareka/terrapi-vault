//! Arm (a) client: master-key seal/unseal against identity's KMS root-of-trust.
//!
//! At cold start the broker exchanges a stored, inert `{kek_id, wrapped}` blob for its
//! plaintext unseal master key via identity's WG-only KMS listener (`POST /kms/v1/unseal`),
//! so a stolen at-rest store is useless without a live, residency-matched call to identity
//! (`coordination/conventions/secrets-broker.md §KMS root-of-trust`). The per-group ROOT key
//! never leaves identity; only this broker's own master key transits, in-group, behind the WG
//! mTLS terminator. The manual unseal passphrase stays the **break-glass** path when identity
//! is unreachable (augment, not replace).
//!
//! Auth: the WG mTLS terminator verifies the broker's fleet-CA client cert and forwards the
//! verified SAN to identity behind the `X-Kms-Auth` boundary secret (the same pattern as the
//! Vulture a/b control plane); the broker sends that secret on each call. The whole path is
//! **disabled unless `VAULT_IDENTITY_KMS_URL` is configured** — until then the broker unseals
//! with the manual passphrase exactly as before.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("identity kms request failed: {0}")]
    Http(String),
    #[error("identity kms returned status {0}")]
    Status(u16),
    #[error("identity kms response malformed: {0}")]
    Decode(String),
}

/// The inert sealed-master blob persisted at rest (`VAULT_SEALED_MASTER_FILE`). Opaque to the
/// broker: `wrapped` is identity's `base64(0x01‖nonce‖ct+tag)` under the per-group root key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedMaster {
    pub kek_id: String,
    pub wrapped: String,
}

#[derive(Serialize)]
struct SealRequest {
    master_key_b64: String,
}
#[derive(Deserialize)]
struct SealResponse {
    kek_id: String,
    wrapped: String,
}
#[derive(Serialize)]
struct UnsealRequest<'a> {
    kek_id: &'a str,
    wrapped: &'a str,
}
#[derive(Deserialize)]
struct UnsealResponse {
    master_key_b64: String,
}

/// Client for identity's `POST /kms/v1/{seal,unseal}`. One per broker; used only at boot.
pub struct IdentityKmsClient {
    base_url: String,
    auth_secret: String,
    http: reqwest::Client,
}

impl IdentityKmsClient {
    /// `base_url` is identity's KMS listener (WG-only, e.g. via the terminator); `auth_secret`
    /// is the `X-Kms-Auth` boundary secret sent on each call.
    #[must_use]
    pub fn new(mut base_url: String, auth_secret: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Self {
            base_url,
            auth_secret,
            http,
        }
    }

    /// One-time bootstrap: seal `master_key` under identity's per-group root, returning the
    /// inert blob to persist with [`store_sealed`].
    ///
    /// # Errors
    /// [`Error`] on a transport failure, non-2xx status, or a malformed response.
    pub async fn seal(&self, master_key: &[u8]) -> Result<SealedMaster, Error> {
        let body = SealRequest {
            master_key_b64: B64.encode(master_key),
        };
        let resp: SealResponse = self.post("/kms/v1/seal", &body).await?;
        Ok(SealedMaster {
            kek_id: resp.kek_id,
            wrapped: resp.wrapped,
        })
    }

    /// Cold-start: exchange the stored `sealed` blob for the plaintext master key bytes.
    ///
    /// # Errors
    /// [`Error`] on a transport failure, non-2xx status (e.g. a retired `kek_id` → 400), or a
    /// malformed / non-base64 response.
    pub async fn unseal(&self, sealed: &SealedMaster) -> Result<Vec<u8>, Error> {
        let body = UnsealRequest {
            kek_id: &sealed.kek_id,
            wrapped: &sealed.wrapped,
        };
        let resp: UnsealResponse = self.post("/kms/v1/unseal", &body).await?;
        B64.decode(resp.master_key_b64.as_bytes())
            .map_err(|e| Error::Decode(e.to_string()))
    }

    async fn post<B, R>(&self, path: &str, body: &B) -> Result<R, Error>
    where
        B: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{path}", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Kms-Auth", &self.auth_secret)
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Status(resp.status().as_u16()));
        }
        resp.json::<R>()
            .await
            .map_err(|e| Error::Decode(e.to_string()))
    }
}

/// Read the persisted sealed-master blob, if present and parseable. `None` (not an error) when
/// the file is absent — the boot path then falls back to the manual passphrase.
#[must_use]
pub fn load_sealed(path: &Path) -> Option<SealedMaster> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Persist the sealed-master blob as `0600` (it's inert, but it identifies the kek and lives on
/// the encrypted dataset — keep it owner-only).
///
/// # Errors
/// Any filesystem error writing or chmod-ing the file.
pub fn store_sealed(path: &Path, sealed: &SealedMaster) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(sealed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, &json)?;
    set_owner_only(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{json, Value};

    fn check_auth(headers: &HeaderMap) -> Result<(), StatusCode> {
        match headers.get("x-kms-auth").and_then(|v| v.to_str().ok()) {
            Some("boundary-secret") => Ok(()),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    }

    // Mock identity KMS: a trivially-reversible "seal" (wrapped == the b64 master) so the
    // client's request shape, X-Kms-Auth header, and seal→unseal round-trip are exercised.
    async fn mock_seal(
        headers: HeaderMap,
        Json(req): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        check_auth(&headers)?;
        let m = req["master_key_b64"]
            .as_str()
            .ok_or(StatusCode::BAD_REQUEST)?;
        Ok(Json(json!({ "kek_id": "eu-root-1", "wrapped": m })))
    }
    async fn mock_unseal(
        headers: HeaderMap,
        Json(req): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        check_auth(&headers)?;
        let w = req["wrapped"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
        Ok(Json(json!({ "master_key_b64": w })))
    }

    async fn spawn_mock() -> String {
        let app = Router::new()
            .route("/kms/v1/seal", post(mock_seal))
            .route("/kms/v1/unseal", post(mock_unseal));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn seal_then_unseal_round_trips_and_sends_auth() {
        let url = spawn_mock().await;
        let client = IdentityKmsClient::new(url, "boundary-secret".into());
        let sealed = client.seal(b"correct horse battery staple").await.unwrap();
        assert_eq!(sealed.kek_id, "eu-root-1");
        let master = client.unseal(&sealed).await.unwrap();
        assert_eq!(master, b"correct horse battery staple");
    }

    #[tokio::test]
    async fn wrong_boundary_secret_is_rejected() {
        let url = spawn_mock().await;
        let client = IdentityKmsClient::new(url, "WRONG".into());
        let err = client
            .unseal(&SealedMaster {
                kek_id: "eu-root-1".into(),
                wrapped: B64.encode(b"x"),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Status(401)));
    }

    #[test]
    fn sealed_master_file_round_trips() {
        let path =
            std::env::temp_dir().join(format!("vault-sealed-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sealed = SealedMaster {
            kek_id: "eu-root-1".into(),
            wrapped: B64.encode(b"inert-blob"),
        };
        store_sealed(&path, &sealed).unwrap();
        assert_eq!(load_sealed(&path), Some(sealed));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_sealed_absent_file_is_none() {
        let path = std::env::temp_dir().join("vault-sealed-does-not-exist-zzz.json");
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_sealed(&path), None);
    }
}
