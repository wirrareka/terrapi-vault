//! Request/response shapes for the v1 broker API. The wire contract is mirrored in
//! `terrapi-vault/spec/broker-openapi.yaml`.

use serde::{Deserialize, Serialize};

// Shared wire shapes live in the neutral base crate (single source of truth for both services).
pub use vault_transport::http::{Ack, ErrorBody};

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

#[derive(Debug, Serialize)]
pub struct SshRevokedResponse {
    /// Revoked cert serials (ascending). Build an sshd KRL from these (`ssh-keygen -k`).
    pub revoked_serials: Vec<u64>,
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

// --- Object-store presign -------------------------------------------------------

/// Which object the publisher is presigning a PUT for. Selects a server-constructed key
/// template (the client never supplies a path), so a publish is two calls: `archive` then
/// `manifest`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresignKind {
    /// The tile archive: `t/<tenant>/<map_id>/<version>.pmtiles`.
    Archive,
    /// The mutable pointer readers follow: `t/<tenant>/<map_id>/latest.json`.
    Manifest,
}

#[derive(Debug, Deserialize)]
pub struct PresignRequest {
    /// Tenant (Vulture `organization_id`), lowercase UUIDv4.
    pub tenant_id: String,
    /// Map/dataset id, `[A-Za-z0-9._-]`.
    pub map_id: String,
    /// Version label, `[A-Za-z0-9._-]` (e.g. a date or build id). Ignored for `manifest`.
    pub version: String,
    pub kind: PresignKind,
    /// Requested URL lifetime; clamped to the signer's `[1, max]`. Defaults when absent.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// A short-TTL presigned PUT URL. No secret transits: the URL authorises a single `PUT` to
/// `key` until `expires` and nothing else. NOT a lease — there is no `lease_id` / revoke.
#[derive(Serialize)]
pub struct PresignResponse {
    pub url: String,
    /// Always `PUT` (the only method the URL is signed for).
    pub method: String,
    /// The exact object key the URL is scoped to (non-secret; echoes what the client will hit).
    pub key: String,
    /// Absolute expiry, unix seconds.
    pub expires: u64,
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

#[derive(Debug, Deserialize)]
pub struct KmsRewrapRequest {
    /// Base64 wrapped blob from a prior `wrap` (possibly under an older KEK version).
    pub wrapped: String,
}

#[derive(Debug, Serialize)]
pub struct KmsRotateResponse {
    pub kek_id: String,
    /// New current KEK version; existing wrapped blobs keep unwrapping under their version.
    pub version: u32,
}

// --- System: store snapshot (aether fleet backup) -------------------------------

#[derive(Debug, Serialize)]
pub struct StoreSnapshotResponse {
    /// Opaque snapshot identifier — the filename only, no host directory (review S11). The
    /// broker holds the real path server-side; the caller never resolves a broker-absolute path.
    pub snapshot_id: String,
    pub sha256: String,
    pub bytes: u64,
}

// --- System: seal state ---------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SealStatus {
    /// `true` until an operator unseals the master key. Mutating ops MAY 503 while sealed.
    /// (The real unseal path lands with broker bootstrap; this build reports its state.)
    pub sealed: bool,
    pub version: Option<String>,
}
