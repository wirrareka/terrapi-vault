//! Error types for the `terrapi-vault` crate.

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

    /// The linked SQLite is not SQLCipher (or its cipher is unavailable), so the database would
    /// be stored **in the clear**. The vault fails closed rather than write plaintext at rest.
    #[error("at-rest encryption unavailable: the linked SQLite is not SQLCipher")]
    EncryptionUnavailable,

    /// A recovery code was structurally invalid: wrong length, illegal
    /// characters, or a failed checksum. Distinct from [`Error::WrongRecoveryCode`]
    /// (a well-formed code that simply did not decrypt the slot) so the UI can
    /// say "that doesn't look like a recovery code" before spending ~1 s on Argon2id.
    #[error("recovery code is malformed: {0}")]
    RecoveryCodeInvalid(String),

    /// A well-formed recovery code did not unwrap the data key — the analogue
    /// of [`Error::WrongPassphrase`] for the recovery slot.
    #[error("incorrect recovery code (could not unwrap the data key)")]
    WrongRecoveryCode,

    /// The vault has no recovery slot enrolled, so it cannot be opened with a
    /// recovery code (or a recovery slot was asked to be removed when none exists).
    #[error("no recovery code is enrolled for this vault")]
    NoRecoverySlot,

    /// A key-slot wrap/unwrap operation failed for a non-authentication reason
    /// (malformed slot ciphertext, unknown wrap algorithm, bad nonce length).
    /// An authentication failure is reported as the credential-specific
    /// [`Error::WrongPassphrase`] / [`Error::WrongRecoveryCode`] instead.
    #[error("key slot is corrupt: {0}")]
    KeySlotCorrupt(String),
}
