//! Broker master-key seal / unseal (bootstrap, FreeBSD without TPM).
//!
//! The broker boots **sealed**: it holds no master key and every mutating op returns
//! `503` (see `http::require_unsealed`). An operator unseals at start by supplying a
//! passphrase; the master key is derived with the lib's Argon2id KDF
//! (`terrapi_vault::derive_key`, never re-implemented) and held in a zeroizing
//! `SecretBox`. The master key is the wrapping key the at-rest store (SSH CA key,
//! lease ledger) will use once those land (Phase 2/3); deriving it now is the real
//! bootstrap, not a placeholder.
//!
//! Unseal is operator-local at boot (passphrase via env / out of band), NOT a network
//! endpoint — there is deliberately no `/v1/sys/unseal` route. Readiness is reported by
//! `GET /v1/sys/seal-status` so a consumer (demon) can poll before issuing.
//!
//! A wrong passphrase is rejected up front via an independent verifier (a second KDF
//! output over a fixed verify-salt), so we never "unseal" with a key that would only
//! fail later against the encrypted store, and the master-key bytes are never compared.

use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::path::Path;
use terrapi_vault::{derive_key, random_salt, DerivedKey, KdfParams, KEY_LEN, SALT_LEN};

/// A successfully unsealed master key. `Debug` is the `SecretBox` redacted form.
#[derive(Debug)]
pub struct Unsealed {
    pub master_key: SecretBox<DerivedKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum UnsealError {
    #[error("wrong unseal passphrase")]
    BadPassphrase,
    #[error("seal metadata is corrupt: {0}")]
    Corrupt(String),
    #[error("seal metadata i/o: {0}")]
    Io(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

/// On-disk seal metadata (sidecar, plaintext like the lib's `<vault>.meta.json`): it holds
/// NO secret — only the two salts, KDF params, and a verifier value used to check the
/// passphrase. Written `mode 600` on first init.
#[derive(Serialize, Deserialize)]
struct SealMeta {
    /// Master-key salt (hex, 16 bytes).
    salt: String,
    /// Independent salt (hex, 16 bytes) for the passphrase verifier.
    verify_salt: String,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    /// `derive_key(passphrase, verify_salt, params)` bytes (hex, 32). Checked, never the key.
    verifier: String,
}

impl SealMeta {
    fn params(&self) -> KdfParams {
        KdfParams {
            m_cost_kib: self.m_cost_kib,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
        }
    }
}

/// Load the seal sidecar (or initialise it on first run) and unseal with `passphrase`.
///
/// First run (no sidecar at `path`): generate salts, compute + persist the verifier,
/// derive the master key. Subsequent runs: verify the passphrase against the stored
/// verifier, then derive the master key.
///
/// # Errors
/// `BadPassphrase` on verifier mismatch; `Io`/`Corrupt` on a bad sidecar; `Kdf` if
/// derivation fails.
pub fn unseal(path: &Path, passphrase: &str, params: KdfParams) -> Result<Unsealed, UnsealError> {
    let meta = if path.exists() {
        let raw = std::fs::read_to_string(path).map_err(|e| UnsealError::Io(e.to_string()))?;
        let meta: SealMeta =
            serde_json::from_str(&raw).map_err(|e| UnsealError::Corrupt(e.to_string()))?;
        let verify_salt = decode_salt(&meta.verify_salt)?;
        let want = decode_key(&meta.verifier)?;
        let got = derive_bytes(passphrase, &verify_salt, meta.params())?;
        if !ct_eq(&got, &want) {
            return Err(UnsealError::BadPassphrase);
        }
        meta
    } else {
        let salt = random_salt();
        let verify_salt = random_salt();
        let verifier = derive_bytes(passphrase, &verify_salt, params)?;
        let meta = SealMeta {
            salt: hex(&salt),
            verify_salt: hex(&verify_salt),
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            verifier: hex(&verifier),
        };
        write_sidecar(path, &meta)?;
        meta
    };

    let salt = decode_salt(&meta.salt)?;
    let master_key = derive_key(passphrase, &salt, meta.params())
        .map_err(|e| UnsealError::Kdf(e.to_string()))?;
    Ok(Unsealed { master_key })
}

/// Ephemeral unseal for local dev: a random in-memory master key, no sidecar, cheap KDF.
/// Only reachable when `VAULT_ALLOW_INSECURE_DEV=1`.
#[must_use]
pub fn unseal_dev() -> Unsealed {
    let salt = random_salt();
    let master_key = derive_key("dev-ephemeral", &salt, dev_params())
        .expect("dev kdf params are valid");
    Unsealed { master_key }
}

/// Deliberately weak params so a dev boot doesn't pay 64 MiB / 2-pass Argon2id.
#[must_use]
pub fn dev_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Derive 32 raw bytes and copy them out of the `SecretBox` (used for the verifier only;
/// the master key itself is never copied out).
fn derive_bytes(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<[u8; KEY_LEN], UnsealError> {
    let secret = derive_key(passphrase, salt, params).map_err(|e| UnsealError::Kdf(e.to_string()))?;
    Ok(*secret.expose_secret().expose_bytes())
}

fn write_sidecar(path: &Path, meta: &SealMeta) -> Result<(), UnsealError> {
    let json = serde_json::to_string_pretty(meta).map_err(|e| UnsealError::Corrupt(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| UnsealError::Io(e.to_string()))?;
    restrict_permissions(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// Constant-time byte compare (avoids a `subtle` dependency for one fixed-length check).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn decode_salt(s: &str) -> Result<[u8; SALT_LEN], UnsealError> {
    let v = decode_hex(s).ok_or_else(|| UnsealError::Corrupt("salt not hex".into()))?;
    v.try_into()
        .map_err(|_| UnsealError::Corrupt("salt wrong length".into()))
}

fn decode_key(s: &str) -> Result<[u8; KEY_LEN], UnsealError> {
    let v = decode_hex(s).ok_or_else(|| UnsealError::Corrupt("verifier not hex".into()))?;
    v.try_into()
        .map_err(|_| UnsealError::Corrupt("verifier wrong length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vault-broker-seal-test-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn init_then_unseal_with_same_passphrase_succeeds() {
        let path = tmp("ok");
        let _ = std::fs::remove_file(&path);
        // first run initialises the sidecar
        let a = unseal(&path, "correct horse battery staple", dev_params()).unwrap();
        // second run loads it and unseals again with the same passphrase
        let b = unseal(&path, "correct horse battery staple", dev_params()).unwrap();
        // same passphrase + same persisted salt => identical master key
        assert_eq!(
            a.master_key.expose_secret().expose_bytes(),
            b.master_key.expose_secret().expose_bytes()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = tmp("bad");
        let _ = std::fs::remove_file(&path);
        unseal(&path, "right-passphrase", dev_params()).unwrap();
        let err = unseal(&path, "WRONG-passphrase", dev_params()).unwrap_err();
        assert!(matches!(err, UnsealError::BadPassphrase));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn hex_roundtrip() {
        let b = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(decode_hex(&hex(&b)).unwrap(), b);
    }
}
