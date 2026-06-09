//! Wire types for the vault-sync oplog API (`spec/sync-openapi.yaml`). All payloads are
//! opaque to the server: `encrypted_payload` is client-side AEAD ciphertext and the server
//! never holds the vault key. See `docs/planning/02-vault-sync-oplog.md`.

use serde::{Deserialize, Serialize};
use vault_transport::Hlc;

/// A single row-level operation as it travels on the wire (client → server → client).
/// `seq` is added by the server (see [`StoredOp`]); the client never sends it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // strict: reject unknown fields on a pushed op (request input)
#[allow(clippy::struct_field_names)] // `op_id` is the fixed wire field name (the contract).
pub struct Op {
    /// Globally-unique client id (ULID / UUIDv7). Dedupe + idempotency key.
    pub op_id: String,
    /// Device that authored the op.
    pub device_id: String,
    /// Hybrid logical clock — the client's ordering + per-row LWW key.
    pub hlc: Hlc,
    /// Opaque grouping (per collection/table). The client MAY HMAC this to blind it.
    pub collection_id: String,
    /// Base64 AEAD ciphertext of the change `(table, row_id, columns)`. Server-opaque.
    pub encrypted_payload: String,
}

/// An op as returned by `pull`/`tail`, carrying the server-assigned monotonic `seq` (the pull
/// cursor). `seq` is per-`vault_id`. Fields are explicit (not `#[serde(flatten)] op: Op`) so that
/// `Op` can carry `deny_unknown_fields` for its request use — flatten is incompatible with it. The
/// serialized JSON is identical (flat: `{seq, op_id, …}`). This is a RESPONSE type, so it is
/// deliberately NOT `deny_unknown_fields` (forward-compat for older clients).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOp {
    pub seq: u64,
    pub op_id: String,
    pub device_id: String,
    pub hlc: Hlc,
    pub collection_id: String,
    pub encrypted_payload: String,
}

impl StoredOp {
    /// Build a stored op from a server-assigned `seq` and the wire `Op`.
    #[must_use]
    pub fn from_op(seq: u64, op: Op) -> Self {
        Self {
            seq,
            op_id: op.op_id,
            device_id: op.device_id,
            hlc: op.hlc,
            collection_id: op.collection_id,
            encrypted_payload: op.encrypted_payload,
        }
    }
}

/// A device registering itself: its id and its raw ed25519 public key (base64, 32 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistration {
    pub device_id: String,
    /// Base64 of the 32-byte ed25519 public key.
    pub pubkey_b64: String,
}

/// The enrolment verifier the first device uploads: everything a *new* device needs to
/// re-derive the enrolment secret (`salt` + Argon2 `params`) plus the server's check value
/// (`hash` = SHA-256 of the client-side Argon2 enrolment secret). The server stores this and
/// never learns the secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollVerifier {
    /// Base64 of the enrolment salt (account-level, distinct from the vault's at-rest salt).
    pub salt_b64: String,
    /// Argon2id parameters the client used to derive the enrolment secret.
    pub params: terrapi_vault::KdfParams,
    /// Base64 of SHA-256(enrolment secret) — the server's verifier.
    pub hash_b64: String,
}

/// `POST /v1/sync/{vault_id}/account` — first device creates the sync account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccountRequest {
    pub enroll: EnrollVerifier,
    /// Base64 of the client-side enrolment secret (same value a later device sends as the
    /// enrol `proof_b64`). The server checks `SHA-256(proof) == enroll.hash_b64` so the
    /// account is only created when its verifier is genuinely derivable — this guarantees a
    /// second device with the same passphrase can enrol, and rejects a garbage verifier that
    /// would otherwise brick the vault. The proof is checked then discarded, never stored.
    pub proof_b64: String,
    pub device: DeviceRegistration,
}

/// `GET /v1/sync/{vault_id}/enroll-challenge` — the (non-secret) salt + params a new device
/// needs to derive its enrolment proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollChallenge {
    pub salt_b64: String,
    pub params: terrapi_vault::KdfParams,
}

/// `POST /v1/sync/{vault_id}/enroll` — a new device proves the enrolment secret and registers
/// its key. The request is self-signed by the *new* device key (proves key possession); the
/// `proof` gates the enrolment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    /// Base64 of the enrolment secret (the client-side Argon2 output). The server checks
    /// SHA-256(proof) == stored hash and then discards it — never persisted.
    pub proof_b64: String,
    pub device: DeviceRegistration,
}

/// Upper bounds on op identifier fields (`op_id`, `device_id`, `collection_id`). These are
/// short ids / HMACs in practice; the cap rejects an oversized field cheaply (the big
/// `encrypted_payload` is bounded by the request body limit). Enforced in the push handler.
pub const MAX_OP_ID_LEN: usize = 128;
/// Max ops accepted in one push batch (bounds a single request's work + row insert count; the
/// body byte-limit is the coarser cap).
pub const MAX_OPS_PER_PUSH: usize = 1000;

/// `POST /v1/sync/{vault_id}/push`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRequest {
    pub ops: Vec<Op>,
}

/// Result of a push: how many ops were newly stored vs deduped, and the new high-water `seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    pub accepted: u64,
    pub duplicates: u64,
    pub latest_seq: u64,
}

/// Result of a pull: ops with `seq > since`, ordered, capped by `limit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub ops: Vec<StoredOp>,
    pub latest_seq: u64,
}

/// One enrolled device in the `GET /v1/sync/{vault_id}/devices` listing (no pubkey — the view
/// only needs which devices exist and when they enrolled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    /// Unix seconds the device (re-)enrolled.
    pub enrolled_at: i64,
}

/// `GET /v1/sync/{vault_id}/devices` — the vault's enrolled devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

/// `GET /v1/sync/{vault_id}/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub latest_seq: u64,
    pub op_count: u64,
    pub device_count: u64,
}

// Shared wire shapes live in the neutral base crate (single source of truth for both services).
pub use vault_transport::http::{Ack, ErrorBody};
