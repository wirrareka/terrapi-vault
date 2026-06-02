//! Arm (a) client: master-key seal/unseal against identity's KMS root-of-trust.
//!
//! At cold start the broker exchanges a stored, inert `{kek_id, wrapped}` blob for its
//! plaintext unseal master key via identity's WG-only KMS listener (`POST /kms/v1/unseal`),
//! so a stolen at-rest store is useless without a live, residency-matched call to identity
//! (`coordination/conventions/secrets-broker.md §KMS root-of-trust`). The per-group ROOT key
//! never leaves identity; only this broker's own master key transits, in-group, over mTLS.
//! The manual unseal passphrase stays the **break-glass** path when identity is unreachable
//! (augment, not replace).
//!
//! Auth: identity's `:8202` is a **native mTLS listener** (infra §2→(A) decision, identity
//! v0.1.13). The broker connects as an mTLS **client** presenting its fleet-CA cert
//! (`vault.<group>.proximi.internal`, clientAuth EKU); identity verifies it
//! (`WebPkiClientVerifier`) + authorizes the SAN → `kms-unseal`. There is no application-layer
//! secret — auth is the client certificate itself. The broker reuses its own broker mTLS
//! material (`VAULT_TLS_*`: cert+key as the client identity, the fleet Root CA bundle as the
//! trust root for identity's server cert). The whole path is **disabled unless
//! `VAULT_IDENTITY_KMS_URL` is configured** — until then the broker unseals with the manual
//! passphrase exactly as before.

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
    #[error("kms mTLS material unreadable: {0}")]
    Io(String),
    #[error("kms mTLS client setup failed: {0}")]
    Tls(String),
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
    http: reqwest::Client,
}

/// Build the mTLS reqwest client: the broker's cert+key as the client identity, and ONLY the
/// fleet Root CA as the trust root (so the broker will only talk to a fleet-CA-signed identity).
fn build_mtls_client(tls: &crate::config::TlsPaths) -> Result<reqwest::Client, Error> {
    let read = |p: &Path, what: &str| {
        std::fs::read(p).map_err(|e| Error::Io(format!("{what} {}: {e}", p.display())))
    };
    let cert = read(&tls.cert, "kms client cert")?;
    let key = read(&tls.key, "kms client key")?;
    let ca = read(&tls.client_ca, "kms trust CA")?;

    // reqwest's rustls `Identity` wants the leaf cert chain + private key in one PEM.
    let mut identity_pem = cert;
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(&key);
    let identity =
        reqwest::Identity::from_pem(&identity_pem).map_err(|e| Error::Tls(e.to_string()))?;

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .identity(identity);
    for root in reqwest::Certificate::from_pem_bundle(&ca).map_err(|e| Error::Tls(e.to_string()))? {
        builder = builder.add_root_certificate(root);
    }
    builder.build().map_err(|e| Error::Tls(e.to_string()))
}

impl IdentityKmsClient {
    /// Build a client for identity's KMS listener at `base_url`, authenticating with mTLS from
    /// the broker's own TLS material (`tls`): the cert+key as the client identity, the fleet
    /// Root CA bundle as the sole trust root for identity's server cert.
    ///
    /// # Errors
    /// [`Error::Io`] if the cert/key/CA files can't be read; [`Error::Tls`] if they don't parse
    /// or the TLS client can't be built.
    pub fn new(base_url: String, tls: &crate::config::TlsPaths) -> Result<Self, Error> {
        Ok(Self::from_parts(base_url, build_mtls_client(tls)?))
    }

    fn from_parts(mut base_url: String, http: reqwest::Client) -> Self {
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Self { base_url, http }
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
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{json, Value};

    // Mock identity KMS over plain HTTP — a trivially-reversible "seal" (wrapped == the b64
    // master) so the client's request/response wire shapes + seal→unseal round-trip are
    // exercised. The mTLS handshake is identity's side and is verified in the live eu
    // round-trip; here we inject a plain client via `from_parts` (TLS config is moot for http).
    async fn mock_seal(Json(req): Json<Value>) -> Json<Value> {
        let m = req["master_key_b64"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        Json(json!({ "kek_id": "eu-2026a", "wrapped": m }))
    }
    async fn mock_unseal(Json(req): Json<Value>) -> Json<Value> {
        let w = req["wrapped"].as_str().unwrap_or_default().to_owned();
        Json(json!({ "master_key_b64": w }))
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
    async fn seal_then_unseal_round_trips() {
        let url = spawn_mock().await;
        let client = IdentityKmsClient::from_parts(url, reqwest::Client::new());
        let sealed = client.seal(b"correct horse battery staple").await.unwrap();
        assert_eq!(sealed.kek_id, "eu-2026a");
        let master = client.unseal(&sealed).await.unwrap();
        assert_eq!(master, b"correct horse battery staple");
    }

    #[test]
    fn new_fails_on_unreadable_mtls_material() {
        let tls = crate::config::TlsPaths {
            cert: "/nonexistent/vault.pem".into(),
            key: "/nonexistent/vault.key".into(),
            client_ca: "/nonexistent/fleet-ca.pem".into(),
        };
        assert!(matches!(
            IdentityKmsClient::new("https://identity.eu.proximi.fi".into(), &tls),
            Err(Error::Io(_))
        ));
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
