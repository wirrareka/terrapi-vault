//! The [`Vault`] type: lifecycle over an encrypted SQLCipher database.

use crate::error::{Error, Result};
use crate::kdf::{derive_key, random_salt, DerivedKey, KdfParams};
use crate::meta::{meta_path_for, VaultMeta};
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretBox};
use std::path::{Path, PathBuf};

/// An open, unlocked encrypted vault.
///
/// A `Vault` owns a single `rusqlite` [`Connection`] keyed with SQLCipher
/// and the derived key (held in a [`SecretBox`], zeroized on drop). Run SQL
/// — including migrations and FTS5 setup — through [`Vault::with_connection`].
///
/// # Example
///
/// ```no_run
/// use terrapi_vault::{Vault, KdfParams};
///
/// # fn main() -> terrapi_vault::Result<()> {
/// let v = Vault::create("notes.terrapi", "correct horse", KdfParams::default())?;
/// v.with_connection(|c| {
///     c.execute_batch("CREATE TABLE note(id INTEGER PRIMARY KEY, body TEXT);")
/// })?;
/// v.lock();
/// # Ok(())
/// # }
/// ```
pub struct Vault {
    conn: Connection,
    key: SecretBox<DerivedKey>,
    vault_path: PathBuf,
    meta_path: PathBuf,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key or connection internals.
        f.debug_struct("Vault")
            .field("vault_path", &self.vault_path)
            .field("meta_path", &self.meta_path)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a brand-new encrypted vault at `path`.
    ///
    /// Generates a fresh random salt, derives the key with `params`, applies
    /// `PRAGMA key`, writes the `<path>.meta.json` sidecar, and initializes
    /// the `vault_schema` version table. Recovers automatically from a
    /// partial prior state (an orphan DB *or* an orphan sidecar — neither is
    /// recoverable, so the stale file is removed) but refuses if **both**
    /// already exist.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyExists`] if a complete vault is already present,
    /// [`Error::Kdf`] on bad params, [`Error::Db`] / [`Error::Io`] /
    /// [`Error::Json`] on lower-level failures.
    pub fn create<P: AsRef<Path>>(path: P, passphrase: &str, params: KdfParams) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let meta_path = meta_path_for(&vault_path);

        prepare_paths_for_create(&vault_path, &meta_path)?;

        let salt = random_salt();
        let key = derive_key(passphrase, &salt, params)?;

        let conn = open_keyed(&vault_path, &key)?;
        init_schema(&conn)?;

        VaultMeta::new(&salt, params).write(&meta_path)?;

        Ok(Self {
            conn,
            key,
            vault_path,
            meta_path,
        })
    }

    /// Open an existing vault at `path` with `passphrase`.
    ///
    /// Reads the sidecar, re-derives the key with the *stored* salt and
    /// params, opens the DB, and verifies the key with a cheap read.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassphrase`] if the passphrase is incorrect,
    /// [`Error::MetaMissing`] / [`Error::MetaInvalid`] for sidecar problems,
    /// otherwise [`Error::Db`] / [`Error::Io`].
    pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let meta_path = meta_path_for(&vault_path);

        let meta = VaultMeta::read(&meta_path)?;
        let salt = meta.salt()?;
        let key = derive_key(passphrase, &salt, meta.kdf_params)?;

        let conn = open_keyed(&vault_path, &key)?;
        verify_key(&conn)?;

        Ok(Self {
            conn,
            key,
            vault_path,
            meta_path,
        })
    }

    /// Open an existing vault at `path` with a raw 32-byte key.
    ///
    /// Unlike [`Vault::open`], this skips Argon2id derivation and uses
    /// `key` directly as the SQLCipher key. It exists for opt-in
    /// alternative-unlock paths (e.g. a biometric-gated OS keystore that
    /// holds the previously derived key); the sidecar is still read so the
    /// vault remembers its salt/params for a later [`Vault::rotate_key`].
    ///
    /// # Security
    ///
    /// `key` must be the exact key a passphrase would have derived for this
    /// vault. A wrong key is rejected the same way a wrong passphrase is
    /// ([`Error::WrongPassphrase`]). The caller is responsible for keeping
    /// `key` in zeroizing memory; the copy taken here lives in a
    /// [`SecretBox`] and is scrubbed on lock/drop.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassphrase`] if the key is incorrect,
    /// [`Error::MetaMissing`] / [`Error::MetaInvalid`] for sidecar problems,
    /// otherwise [`Error::Db`] / [`Error::Io`].
    pub fn open_with_key<P: AsRef<Path>>(path: P, key: &[u8; crate::KEY_LEN]) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let meta_path = meta_path_for(&vault_path);

        // Read the sidecar so the salt/params are available for a later
        // rotate_key, and to fail early with the same MetaMissing error
        // shape as the passphrase path.
        let _meta = VaultMeta::read(&meta_path)?;
        let key = SecretBox::new(Box::new(DerivedKey::from_bytes(*key)));

        let conn = open_keyed(&vault_path, &key)?;
        verify_key(&conn)?;

        Ok(Self {
            conn,
            key,
            vault_path,
            meta_path,
        })
    }

    /// A clone of the current derived key, in a zeroizing handle.
    ///
    /// Returned so an opt-in alternative-unlock feature can stash the key
    /// in a biometric-gated OS keystore *after* a successful passphrase
    /// unlock, then later reopen via [`Vault::open_with_key`] without the
    /// passphrase. The returned [`SecretBox`] zeroizes on drop; treat the
    /// bytes as sensitive and never log or persist them in the clear.
    #[must_use]
    pub fn derived_key(&self) -> SecretBox<DerivedKey> {
        SecretBox::new(Box::new(self.key.expose_secret().clone()))
    }

    /// Re-key the vault: change the passphrase in place.
    ///
    /// Verifies `old_passphrase` against the current key, runs SQLCipher
    /// `PRAGMA rekey` with a key derived from `new_passphrase` over a
    /// **fresh salt**, then rewrites the sidecar. Existing data is preserved
    /// and remains accessible only with the new passphrase.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassphrase`] if `old_passphrase` is wrong, otherwise
    /// [`Error::Db`] / [`Error::Io`] / [`Error::Json`].
    pub fn rotate_key(&mut self, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        let meta = VaultMeta::read(&self.meta_path)?;
        let salt = meta.salt()?;

        // Confirm the caller actually knows the current passphrase before
        // we touch the cipher key. Compare in constant time so the check does
        // not leak how many leading key bytes matched via timing (no extra
        // crate — a fixed-length XOR-accumulate over the 32-byte keys).
        let old_key = derive_key(old_passphrase, &salt, meta.kdf_params)?;
        if !constant_time_eq(&old_key.expose_secret().0, &self.key.expose_secret().0) {
            return Err(Error::WrongPassphrase);
        }

        let new_salt = random_salt();
        let new_key = derive_key(new_passphrase, &new_salt, meta.kdf_params)?;

        let literal = new_key.expose_secret().pragma_literal();
        self.conn
            .pragma_update(None, "rekey", literal)
            .map_err(map_cipher_err)?;

        VaultMeta::new(&new_salt, meta.kdf_params).write(&self.meta_path)?;
        self.key = new_key;
        Ok(())
    }

    /// Run a closure with the open encrypted [`Connection`].
    ///
    /// This is the sanctioned escape hatch for the downstream crate to run
    /// migrations (`rusqlite_migration`), FTS5 setup, and queries. Errors
    /// returned by the closure are wrapped into [`Error::Db`]; return a
    /// `rusqlite::Result` from it.
    ///
    /// # Errors
    ///
    /// Propagates any [`rusqlite::Error`] the closure returns.
    pub fn with_connection<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T>,
    {
        f(&self.conn).map_err(Error::Db)
    }

    /// Mutable variant of [`Vault::with_connection`] for transactions.
    ///
    /// # Errors
    ///
    /// Propagates any [`rusqlite::Error`] the closure returns.
    pub fn with_connection_mut<T, F>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T>,
    {
        f(&mut self.conn).map_err(Error::Db)
    }

    /// The schema version recorded in the `vault_schema` table.
    ///
    /// `terrapi-vault` owns row 0 (format bookkeeping). Downstream
    /// migrations should use `rusqlite_migration`'s own `user_version`.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] if the table is missing or unreadable.
    pub fn schema_version(&self) -> Result<i64> {
        self.with_connection(|c| {
            c.query_row("SELECT version FROM vault_schema WHERE id = 0", [], |r| {
                r.get(0)
            })
        })
    }

    /// Path of the SQLCipher database file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.vault_path
    }

    /// Path of the metadata sidecar.
    #[must_use]
    pub fn meta_path(&self) -> &Path {
        &self.meta_path
    }

    /// Lock the vault: close the connection and zeroize the key.
    ///
    /// Consumes `self`. The key buffer is scrubbed by [`DerivedKey`]'s
    /// zeroize-on-drop; the connection is closed cleanly.
    pub fn lock(self) {
        // Closing first flushes the WAL; an error here is non-fatal — the
        // key still gets zeroized when `self` (and its `SecretBox`) drops.
        let _ = self.conn.close();
        // `self` drops here -> key zeroized.
    }
}

/// Open a connection and apply the SQLCipher key + hardening pragmas.
///
/// `PRAGMA key` MUST be the first statement on the connection, before any
/// read/write of the file, or SQLCipher will operate on (and corrupt) the
/// file unkeyed. `rusqlite::Connection::open` does not touch the file
/// before our first `pragma_update`, so issuing `key` immediately is safe.
fn open_keyed(path: &Path, key: &SecretBox<DerivedKey>) -> Result<Connection> {
    let conn = Connection::open(path)?;
    let literal = key.expose_secret().pragma_literal();
    // `key` accepts the `x'<hex>'` blob literal -> raw key, no inner KDF.
    conn.pragma_update(None, "key", literal)
        .map_err(map_cipher_err)?;

    // Reasonable SQLCipher / SQLite hardening. Keep cipher defaults
    // (SQLCipher 4: AES-256-CBC, HMAC-SHA512, 256k PBKDF2 — irrelevant to
    // our raw-key path but documented in the format spec).
    conn.pragma_update(None, "cipher_memory_security", "ON")
        .map_err(map_cipher_err)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(map_cipher_err)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(map_cipher_err)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(map_cipher_err)?;
    Ok(conn)
}

/// Cheap read that fails iff the key is wrong (or the file is corrupt).
fn verify_key(conn: &Connection) -> Result<()> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map(|_| ())
    .map_err(map_cipher_err)
}

/// Map a SQLCipher decrypt failure onto [`Error::WrongPassphrase`].
///
/// SQLCipher reports a wrong key as "file is not a database" / "not an
/// error" (`SQLITE_NOTADB`) on the first read. Anything else is a genuine
/// database error.
fn map_cipher_err(e: rusqlite::Error) -> Error {
    if let rusqlite::Error::SqliteFailure(ref f, ref msg) = e {
        let m = msg.as_deref().unwrap_or("");
        if f.code == rusqlite::ErrorCode::NotADatabase || m.contains("file is not a database") {
            return Error::WrongPassphrase;
        }
    }
    Error::Db(e)
}

/// Constant-time equality of two 32-byte keys: always inspects every byte (XOR-accumulate),
/// so comparison time does not reveal how many leading bytes matched. No external crate.
fn constant_time_eq(a: &[u8; crate::KEY_LEN], b: &[u8; crate::KEY_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Create the `vault_schema` bookkeeping table and stamp version 1.
fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_schema (
             id      INTEGER PRIMARY KEY CHECK (id = 0),
             version INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO vault_schema (id, version) VALUES (0, 1);",
    )?;
    Ok(())
}

/// Partial-state recovery, ported from the sibling app's
/// `prepare_vault_paths_for_create`.
///
/// - both exist  -> [`Error::AlreadyExists`] (don't clobber a live vault)
/// - one exists  -> delete the orphan (the salt lives in the sidecar; a DB
///   without it, or a sidecar without a DB, is unrecoverable anyway)
/// - neither     -> clean slate
fn prepare_paths_for_create(vault_path: &Path, meta_path: &Path) -> Result<()> {
    let v = vault_path.exists();
    let m = meta_path.exists();
    match (v, m) {
        (true, true) => Err(Error::AlreadyExists(vault_path.to_path_buf())),
        (true, false) | (false, true) => {
            if v {
                std::fs::remove_file(vault_path)?;
            }
            if m {
                std::fs::remove_file(meta_path)?;
            }
            Ok(())
        }
        (false, false) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn p() -> KdfParams {
        KdfParams::fast_for_tests()
    }

    #[test]
    fn create_close_open_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        {
            let v = Vault::create(&path, "pw", p()).unwrap();
            v.with_connection(|c| c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (42);"))
                .unwrap();
            v.lock();
        }
        let v = Vault::open(&path, "pw").unwrap();
        let x: i64 = v
            .with_connection(|c| c.query_row("SELECT x FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(x, 42);
        assert_eq!(v.schema_version().unwrap(), 1);
    }

    #[test]
    fn wrong_passphrase_is_distinct_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        Vault::create(&path, "right", p()).unwrap().lock();
        let err = Vault::open(&path, "wrong").unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase), "got {err:?}");
    }

    #[test]
    fn rotate_key_changes_passphrase_preserving_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        {
            let mut v = Vault::create(&path, "old", p()).unwrap();
            v.with_connection(|c| c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (7);"))
                .unwrap();
            v.rotate_key("old", "new").unwrap();
            v.lock();
        }
        assert!(matches!(
            Vault::open(&path, "old").unwrap_err(),
            Error::WrongPassphrase
        ));
        let v = Vault::open(&path, "new").unwrap();
        let x: i64 = v
            .with_connection(|c| c.query_row("SELECT x FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(x, 7);
    }

    #[test]
    fn rotate_key_rejects_wrong_old_passphrase() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let mut v = Vault::create(&path, "old", p()).unwrap();
        assert!(matches!(
            v.rotate_key("bogus", "new").unwrap_err(),
            Error::WrongPassphrase
        ));
    }

    #[test]
    fn constant_time_eq_matches_only_identical_keys() {
        let a = [9u8; crate::KEY_LEN];
        let mut b = a;
        assert!(constant_time_eq(&a, &b));
        b[crate::KEY_LEN - 1] ^= 0x01; // flip the last byte
        assert!(!constant_time_eq(&a, &b));
        b = a;
        b[0] ^= 0x80; // flip the first byte
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn create_refuses_when_both_files_exist() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        Vault::create(&path, "pw", p()).unwrap().lock();
        assert!(matches!(
            Vault::create(&path, "pw", p()).unwrap_err(),
            Error::AlreadyExists(_)
        ));
    }

    #[test]
    fn create_recovers_from_orphan_db() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        fs::write(&path, b"stale").unwrap();
        Vault::create(&path, "pw", p()).unwrap().lock();
        assert!(Vault::open(&path, "pw").is_ok());
    }

    #[test]
    fn create_recovers_from_orphan_meta() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        fs::write(meta_path_for(&path), b"{}").unwrap();
        Vault::create(&path, "pw", p()).unwrap().lock();
        assert!(Vault::open(&path, "pw").is_ok());
    }

    #[test]
    fn open_with_key_roundtrips_derived_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let key_bytes;
        {
            let v = Vault::create(&path, "pw", p()).unwrap();
            v.with_connection(|c| c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (99);"))
                .unwrap();
            key_bytes = *v.derived_key().expose_secret().expose_bytes();
            v.lock();
        }
        let v = Vault::open_with_key(&path, &key_bytes).unwrap();
        let x: i64 = v
            .with_connection(|c| c.query_row("SELECT x FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(x, 99);
    }

    #[test]
    fn open_with_wrong_key_is_wrong_passphrase() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        Vault::create(&path, "pw", p()).unwrap().lock();
        let err = Vault::open_with_key(&path, &[0u8; crate::KEY_LEN]).unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase), "got {err:?}");
    }

    #[test]
    fn open_with_key_missing_meta_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.memento");
        assert!(matches!(
            Vault::open_with_key(&path, &[0u8; crate::KEY_LEN]).unwrap_err(),
            Error::MetaMissing(_)
        ));
    }

    #[test]
    fn rotate_key_invalidates_old_derived_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let old_key;
        {
            let mut v = Vault::create(&path, "old", p()).unwrap();
            old_key = *v.derived_key().expose_secret().expose_bytes();
            v.rotate_key("old", "new").unwrap();
            v.lock();
        }
        // The pre-rotation key must no longer open the vault — this is the
        // crypto guarantee the biometric-clear-on-rotate UX relies on.
        assert!(matches!(
            Vault::open_with_key(&path, &old_key).unwrap_err(),
            Error::WrongPassphrase
        ));
    }

    #[test]
    fn open_missing_meta_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.memento");
        assert!(matches!(
            Vault::open(&path, "pw").unwrap_err(),
            Error::MetaMissing(_)
        ));
    }
}
