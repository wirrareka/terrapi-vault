//! Broker seal / unseal (bootstrap, FreeBSD without TPM).
//!
//! The broker boots **sealed**: it holds no open at-rest store and every mutating op
//! returns `503` (see `http::require_unsealed`). Unsealing = opening the broker's at-rest
//! encrypted store (`terrapi_vesta::Vault`, SQLCipher) with the operator passphrase. The
//! store holds the SSH CA key (and, later, the lease ledger / dynamic-cred state); its
//! SQLCipher key is derived from the passphrase with the lib's Argon2id (never
//! re-implemented). A wrong passphrase surfaces as `Vault`'s `WrongPassphrase`.
//!
//! Unseal is operator-local at boot (passphrase via env / out of band), NOT a network
//! endpoint — there is deliberately no `/v1/sys/unseal` route. Readiness is reported by
//! `GET /v1/sys/seal-status`.

use std::path::Path;
use terrapi_vesta::{Error as VaultError, KdfParams, Vault};

#[derive(Debug, thiserror::Error)]
pub enum UnsealError {
    #[error("wrong unseal passphrase")]
    BadPassphrase,
    #[error("at-rest store error: {0}")]
    Store(String),
}

/// Open (or create on first run) the broker's at-rest store with `passphrase`.
///
/// # Errors
/// `BadPassphrase` if an existing store rejects the passphrase; `Store` on any other
/// store error.
pub fn unseal(
    store_path: &Path,
    passphrase: &str,
    params: KdfParams,
) -> Result<Vault, UnsealError> {
    if store_path.exists() {
        match Vault::open(store_path, passphrase) {
            Ok(v) => Ok(v),
            Err(VaultError::WrongPassphrase) => Err(UnsealError::BadPassphrase),
            Err(e) => Err(UnsealError::Store(e.to_string())),
        }
    } else {
        Vault::create(store_path, passphrase, params).map_err(|e| UnsealError::Store(e.to_string()))
    }
}

/// Ephemeral store for local dev: a throwaway SQLCipher file with cheap KDF params. Only
/// reachable when `VESTA_ALLOW_INSECURE_DEV=1`.
///
/// # Errors
/// `Store` if the temp store cannot be created.
pub fn unseal_dev() -> Result<Vault, UnsealError> {
    let path = std::env::temp_dir().join(format!(
        "vesta-broker-dev-store-{}.sqlcipher",
        std::process::id()
    ));
    // A leftover dev store from a previous run would make `create` fail.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(terrapi_vesta::meta_path_for(&path));
    Vault::create(&path, "dev-ephemeral", dev_params())
        .map_err(|e| UnsealError::Store(e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vesta-broker-seal-test-{name}-{}.sqlcipher",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(terrapi_vesta::meta_path_for(path));
    }

    #[test]
    fn create_then_unseal_with_same_passphrase_succeeds() {
        let path = tmp("ok");
        cleanup(&path);
        // first run creates the store
        let v = unseal(&path, "correct horse battery staple", dev_params()).unwrap();
        v.lock();
        // second run opens it with the same passphrase
        let v = unseal(&path, "correct horse battery staple", dev_params()).unwrap();
        v.lock();
        cleanup(&path);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = tmp("bad");
        cleanup(&path);
        unseal(&path, "right-passphrase", dev_params())
            .unwrap()
            .lock();
        let err = unseal(&path, "WRONG-passphrase", dev_params()).unwrap_err();
        assert!(matches!(err, UnsealError::BadPassphrase));
        cleanup(&path);
    }
}
