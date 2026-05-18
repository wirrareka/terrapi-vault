//! Error types for the `memento-vault` crate.

use std::path::PathBuf;

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All failures the vault can surface.
///
/// Libraries use [`thiserror`]; callers can match on the discriminant to
/// distinguish a wrong passphrase from genuine I/O or corruption.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The supplied passphrase did not decrypt the database.
    ///
    /// SQLCipher cannot tell a wrong key from a corrupt file; we map the
    /// "file is not a database" / "not an error" cipher failure that the
    /// first read produces onto this distinct variant so the UI can show a
    /// "wrong password" message instead of a scary corruption error.
    #[error("incorrect passphrase (decryption failed)")]
    WrongPassphrase,

    /// The on-disk sidecar (`<path>.meta.json`) is missing.
    #[error("vault metadata sidecar not found: {0}")]
    MetaMissing(PathBuf),

    /// The sidecar exists but could not be parsed or is structurally invalid.
    #[error("vault metadata is invalid: {0}")]
    MetaInvalid(String),

    /// A vault already exists at the requested path (both DB and sidecar).
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),

    /// The sidecar declares a format version this build cannot read.
    #[error("unsupported vault format version {found} (this build supports {supported})")]
    UnsupportedFormat {
        /// The version found in the sidecar.
        found: u32,
        /// The maximum version this build understands.
        supported: u32,
    },

    /// Argon2id parameter construction or hashing failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// A filesystem operation failed.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization of the sidecar failed.
    #[error("metadata serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// An underlying SQLite/SQLCipher error that is not a key failure.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}
