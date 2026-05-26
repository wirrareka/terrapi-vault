//! Request/response shapes for the v1 broker API. The wire contract is mirrored in
//! `terrapi-vault/spec/broker-openapi.yaml`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub detail: String,
}

// --- SSH signed-cert CA ---------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertType {
    User,
    Host,
}

// Fixed v1 request contract; fields are consumed when ssh/sign signing lands.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct SshSignRequest {
    pub public_key: String,
    pub cert_type: CertType,
    pub principals: Vec<String>,
    /// `None` → server default for the request context (900 interactive / 300 automated);
    /// always clamped to the remaining session. Matches the nullable field in the spec.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SshSignResponse {
    pub signed_certificate: String,
    pub serial: u64,
    pub valid_before: String,
    pub lease_id: String,
}

#[derive(Debug, Serialize)]
pub struct SshCaResponse {
    pub ca_public_key: String,
}

// --- Leased service-admin creds -------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CredsRequest {
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// Carries a generated `password` — intentionally NOT `Debug`, so it can't be logged.
#[derive(Serialize)]
pub struct CredsResponse {
    pub username: String,
    pub password: String,
    pub lease_id: String,
    pub ttl_secs: u64,
    pub renewable: bool,
    pub max_ttl_secs: u64,
}

// --- Sessions + leases ----------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SessionOpenRequest {
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SessionOpenResponse {
    pub session_id: String,
    pub ttl_secs: u64,
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct SessionEndResponse {
    pub session_id: String,
    pub revoked_leases: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LeaseRenewRequest {
    pub lease_id: String,
    pub increment_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct LeaseRenewResponse {
    pub lease_id: String,
    pub ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct LeaseRevokeRequest {
    pub lease_id: String,
}

#[derive(Debug, Serialize)]
pub struct Ack {
    pub ok: bool,
}

// --- KMS DEK wrap/unwrap --------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KmsWrapRequest {
    /// Base64 plaintext data-encryption key to wrap.
    pub dek: String,
}

#[derive(Debug, Serialize)]
pub struct KmsWrapResponse {
    /// Base64 `nonce || ciphertext+tag`.
    pub wrapped: String,
    /// `<group>/<tenant_id>/<key_id>` — which KEK wrapped it (audit/traceability).
    pub kek_id: String,
}

#[derive(Debug, Deserialize)]
pub struct KmsUnwrapRequest {
    /// Base64 wrapped blob from a prior `wrap`.
    pub wrapped: String,
}

/// Carries the plaintext DEK — intentionally NOT `Debug`, so it can't be logged.
#[derive(Serialize)]
pub struct KmsUnwrapResponse {
    /// Base64 plaintext data-encryption key.
    pub dek: String,
}

// --- System: seal state ---------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SealStatus {
    /// `true` until an operator unseals the master key. Mutating ops MAY 503 while sealed.
    /// (The real unseal path lands with broker bootstrap; this build reports its state.)
    pub sealed: bool,
    pub version: Option<String>,
}
