//! KMS DEK wrap/unwrap (envelope encryption) — Phase 4, for aether fleet-backup keys.
//!
//! The broker is the key authority: a per-target **KEK** is generated once and held in the
//! at-rest encrypted store (same SQLCipher store as the SSH CA), **never exported**. The
//! aether agent sends a data-encryption key (DEK) to **wrap** (AES-256-GCM under the KEK)
//! and stores only the wrapped blob; on restore it **unwraps**. This keeps aether's
//! zero-knowledge model (the agent holds the plaintext DEK only in RAM, per run) while the
//! KEK never leaves the broker.
//!
//! KEK identity = `(group, tenant_id, key_id)` — stable (not leased), so old snapshots stay
//! decryptable. Wrapped form = `nonce(12) || ciphertext+tag`, base64. See
//! coordination `inbox/vault/aether-key-custody.md`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use terrapi_vault::{random_salt, rusqlite, Vault};

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("at-rest store error: {0}")]
    Store(String),
    #[error("bad input: {0}")]
    BadInput(String),
    #[error("crypto error")]
    Crypto,
}

/// Load the per-target KEK from the store, generating + persisting one on first use.
///
/// # Errors
/// `Store` on a DB error.
fn load_or_create_kek(
    vault: &Vault,
    group: &str,
    tenant_id: &str,
    key_id: &str,
) -> Result<[u8; 32], KmsError> {
    vault
        .with_connection(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS kms_keks (
                    group_name TEXT NOT NULL,
                    tenant_id  TEXT NOT NULL,
                    key_id     TEXT NOT NULL,
                    kek        BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (group_name, tenant_id, key_id)
                );",
            )
        })
        .map_err(|e| KmsError::Store(e.to_string()))?;

    let existing: Option<Vec<u8>> = vault
        .with_connection(|c| {
            c.query_row(
                "SELECT kek FROM kms_keks WHERE group_name=?1 AND tenant_id=?2 AND key_id=?3",
                rusqlite::params![group, tenant_id, key_id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
        })
        .map_err(|e| KmsError::Store(e.to_string()))?;

    if let Some(bytes) = existing {
        return bytes
            .try_into()
            .map_err(|_| KmsError::Store("stored KEK has wrong length".into()));
    }

    // 32 bytes of OS randomness (two 16-byte CSPRNG draws), persisted once.
    let mut kek = [0u8; 32];
    kek[..16].copy_from_slice(&random_salt());
    kek[16..].copy_from_slice(&random_salt());
    let now = crate::state::AppState::now_ts();
    vault
        .with_connection(|c| {
            c.execute(
                "INSERT INTO kms_keks (group_name, tenant_id, key_id, kek, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![group, tenant_id, key_id, &kek[..], now],
            )
        })
        .map_err(|e| KmsError::Store(e.to_string()))?;
    Ok(kek)
}

/// Wrap `dek` under the target's KEK. Returns `nonce(12) || ct+tag`.
///
/// # Errors
/// `Store` on a DB error; `Crypto` on an AEAD failure.
pub fn wrap(
    vault: &Vault,
    group: &str,
    tenant_id: &str,
    key_id: &str,
    dek: &[u8],
) -> Result<Vec<u8>, KmsError> {
    let kek = load_or_create_kek(vault, group, tenant_id, key_id)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let nonce_bytes = random_salt(); // 16 bytes; take 12
    let nonce = Nonce::from_slice(&nonce_bytes[..NONCE_LEN]);
    let ct = cipher.encrypt(nonce, dek).map_err(|_| KmsError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes[..NONCE_LEN]);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap `wrapped` (`nonce(12) || ct+tag`) under the target's KEK.
///
/// # Errors
/// `BadInput` if too short; `Store` on a DB error; `Crypto` if the KEK/nonce/tag don't
/// authenticate (wrong target or tampered blob).
pub fn unwrap(
    vault: &Vault,
    group: &str,
    tenant_id: &str,
    key_id: &str,
    wrapped: &[u8],
) -> Result<Vec<u8>, KmsError> {
    if wrapped.len() <= NONCE_LEN {
        return Err(KmsError::BadInput("wrapped blob too short".into()));
    }
    let kek = load_or_create_kek(vault, group, tenant_id, key_id)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let (nonce_bytes, ct) = wrapped.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| KmsError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrapi_vault::KdfParams;

    fn dev_vault(name: &str) -> (Vault, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "vault-kms-test-{name}-{}.sqlcipher",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(terrapi_vault::meta_path_for(&path));
        let params = KdfParams { m_cost_kib: 8 * 1024, t_cost: 1, p_cost: 1 };
        let v = Vault::create(&path, "test", params).unwrap();
        (v, path)
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(terrapi_vault::meta_path_for(path));
        // SQLite WAL/SHM sidecars sit next to the DB file.
        for ext in ["-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(ext);
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
    }

    #[test]
    fn wrap_then_unwrap_roundtrips() {
        let (v, path) = dev_vault("rt");
        let dek = b"a-32-byte-data-encryption-key!!!";
        let w = wrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "target-1", dek).unwrap();
        assert_ne!(&w[12..], &dek[..]); // ciphertext != plaintext
        let got = unwrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "target-1", &w).unwrap();
        assert_eq!(got, dek);
        cleanup(&path);
    }

    #[test]
    fn unwrap_under_a_different_key_id_fails() {
        let (v, path) = dev_vault("wrongkey");
        let w = wrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "target-1", b"secret").unwrap();
        // different key_id → different KEK → AEAD auth fails
        let err = unwrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "target-2", &w).unwrap_err();
        assert!(matches!(err, KmsError::Crypto));
        cleanup(&path);
    }

    #[test]
    fn tampered_blob_fails() {
        let (v, path) = dev_vault("tamper");
        let mut w = wrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "t", b"secret").unwrap();
        let last = w.len() - 1;
        w[last] ^= 0xff; // flip a tag byte
        assert!(matches!(
            unwrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "t", &w),
            Err(KmsError::Crypto)
        ));
        cleanup(&path);
    }

    #[test]
    fn kek_is_stable_across_calls() {
        let (v, path) = dev_vault("stable");
        let w1 = wrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "t", b"x").unwrap();
        // a second wrap reuses the persisted KEK (different nonce), and the first blob
        // still unwraps — proving the KEK didn't rotate.
        let _w2 = wrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "t", b"y").unwrap();
        assert_eq!(
            unwrap(&v, "eu", "11111111-1111-4111-8111-111111111111", "t", &w1).unwrap(),
            b"x"
        );
        cleanup(&path);
    }
}
