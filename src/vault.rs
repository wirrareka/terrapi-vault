//! The [`Vault`] type: lifecycle over an encrypted SQLCipher database.

use crate::error::{Error, Result};
use crate::kdf::{
    derive_key, derive_key_from_bytes, random_key, random_salt, DerivedKey, KdfParams,
};
use crate::keyslot;
use crate::meta::{meta_path_for, KeySlot, MetaV2, StoredMeta, VaultMeta};
use crate::recovery::RecoveryCode;
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretBox};
use std::path::{Path, PathBuf};

/// Slot name for the passphrase credential. Bound into the AEAD AAD so a blob
/// can only be opened in the slot it was sealed for (see [`crate::keyslot`]).
const PASSWORD_SLOT: &str = "password";
/// Slot name for the recovery-code credential.
const RECOVERY_SLOT: &str = "recovery";

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

/// Snapshot of the inputs a passphrase change needs, captured cheaply on the
/// thread that owns the [`Vault`] ([`Vault::rotation_inputs`]).
///
/// In the v2 (DEK) format a passphrase change **re-wraps the data key under a
/// new password slot** — it does not re-encrypt the database — so the snapshot
/// carries the current DEK plus the existing password slot (whose salt/params
/// let [`Vault::plan_rotation`] verify the old passphrase off-thread). The DEK
/// it holds zeroizes on drop; treat its bytes as sensitive.
pub struct RotationInputs {
    dek: SecretBox<DerivedKey>,
    password_slot: KeySlot,
}

/// Inputs for setting a passphrase **without** the old one — used after a
/// recovery-code unlock, where authorization already came from the recovery
/// code. Carries the DEK (zeroized on drop) and the cost params to use.
pub struct SetPassphraseInputs {
    dek: SecretBox<DerivedKey>,
    params: KdfParams,
}

/// Inputs for enrolling a recovery code: just the current DEK (zeroized on
/// drop), captured on the vault thread so the expensive Argon2id derivation in
/// [`Vault::plan_enroll_recovery`] can run off-thread.
pub struct RecoveryEnrollInputs {
    dek: SecretBox<DerivedKey>,
}

/// The result of the expensive half of a passphrase change: a freshly built
/// password [`KeySlot`] (a new salt + the DEK re-sealed under the new
/// passphrase's slot key), ready to be committed by [`Vault::apply_rotation`].
///
/// Holds **no** bare key material — the DEK inside `new_password_slot` is
/// authenticated ciphertext — so it is trivially `Send` for the off-thread
/// derivation handoff.
pub struct RotationPlan {
    new_password_slot: KeySlot,
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

        // v2 format: the database is keyed by a random DEK (stable for life);
        // the passphrase only wraps the DEK in its key slot.
        let dek = random_key();
        let salt = random_salt();
        let slot_key = derive_key(passphrase, &salt, params)?;
        let wrap = keyslot::seal(
            slot_key.expose_secret().expose_bytes(),
            dek.expose_secret().expose_bytes(),
            PASSWORD_SLOT,
        );

        let conn = open_keyed(&vault_path, &dek)?;
        init_schema(&conn)?;

        MetaV2::new(KeySlot::new(&salt, params, wrap)).write(&meta_path)?;

        Ok(Self {
            conn,
            key: dek,
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

        match StoredMeta::read(&meta_path)? {
            StoredMeta::V2(meta) => open_v2(vault_path, meta_path, passphrase, &meta),
            // Legacy v1 sidecar: open with the salt-derived key, then transparently
            // migrate to the v2 DEK format on this unlock (the chosen "lazy migration"),
            // recovering crash-safely if a prior migration was interrupted mid-rekey.
            StoredMeta::V1(meta) => {
                let key = derive_key(passphrase, &meta.salt()?, meta.kdf_params)?;
                match open_and_verify(&vault_path, &key) {
                    Ok(conn) => {
                        // v1 key opened the DB → no migration was committed; any staged sidecar is
                        // a pre-rekey orphan. Drop it, then migrate fresh.
                        let _ = std::fs::remove_file(rekey_staging_path(&meta_path));
                        migrate_v1_to_v2(conn, vault_path, meta_path, passphrase, &meta)
                    }
                    // v1 key failed: either a genuine wrong passphrase, or a migration interrupted
                    // after `rekey` but before the sidecar commit (DB now keyed by the DEK) — try
                    // the staged v2 sidecar.
                    Err(Error::WrongPassphrase) => {
                        recover_interrupted_migration(&vault_path, &meta_path, passphrase)?
                            .ok_or(Error::WrongPassphrase)
                    }
                    Err(e) => Err(e),
                }
            }
        }
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

        // Validate the sidecar exists and parses (either format), to fail early
        // with the same MetaMissing/MetaInvalid error shape as the passphrase
        // path. `key` is used directly, so the salt/params aren't needed here.
        let _meta = StoredMeta::read(&meta_path)?;
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

    /// A clone of the current data-encryption key (DEK), in a zeroizing handle.
    ///
    /// In the v2 format this is the random DEK — the actual SQLCipher key —
    /// **not** a passphrase-derived value. An opt-in alternative-unlock feature
    /// can stash it in a biometric-gated OS keystore after a successful unlock
    /// and later reopen via [`Vault::open_with_key`] without the passphrase.
    ///
    /// Because the DEK is stable across passphrase changes (a passphrase change
    /// only re-wraps it), a stashed DEK keeps working after the user changes
    /// their passphrase. A UI that wants biometric re-enrollment gated on
    /// passphrase change must enforce that as a policy; it is no longer implied
    /// by key invalidation. The returned [`SecretBox`] zeroizes on drop; treat
    /// the bytes as sensitive and never log or persist them in the clear.
    #[must_use]
    pub fn derived_key(&self) -> SecretBox<DerivedKey> {
        SecretBox::new(Box::new(self.key.expose_secret().clone()))
    }

    /// The two on-disk files that make up this vault: the SQLCipher database and its
    /// `<path>.meta.json` sidecar.
    ///
    /// **They are a single atomic unit — back them up and sync them together.** The sidecar holds
    /// the salt + KDF params needed to derive the key; copying the database without the matching
    /// sidecar (or snapshotting the pair mid-[`rotate_key`](Self::rotate_key)) loses the salt and
    /// renders the vault unrecoverable. A backup/sync layer MUST treat `(db, meta)` as one item.
    #[must_use]
    pub fn files(&self) -> (&Path, &Path) {
        (&self.vault_path, &self.meta_path)
    }

    /// Change the passphrase in place.
    ///
    /// Verifies `old_passphrase`, then re-wraps the data key (DEK) under a new
    /// password slot derived from `new_passphrase` over a **fresh salt**. The
    /// database itself is **not** re-encrypted (the DEK is unchanged), so this
    /// is fast and — crucially — leaves any enrolled recovery slot intact: a
    /// recovery code keeps working after a passphrase change.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassphrase`] if `old_passphrase` is wrong, otherwise
    /// [`Error::Db`] / [`Error::Io`] / [`Error::Json`].
    ///
    /// Synchronous all-in-one: runs the Argon2id KDF inline (~seconds). A UI
    /// that must stay responsive should drive the three-phase split —
    /// [`rotation_inputs`](Self::rotation_inputs) (cheap) →
    /// [`plan_rotation`](Self::plan_rotation) (expensive, off-thread) →
    /// [`apply_rotation`](Self::apply_rotation) (cheap) — of which this is the
    /// composition.
    pub fn rotate_key(&mut self, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        let inputs = self.rotation_inputs()?;
        let plan = Self::plan_rotation(&inputs, old_passphrase, new_passphrase)?;
        self.apply_rotation(plan)
    }

    /// Cheaply snapshot the inputs a passphrase change needs, so the expensive
    /// [`plan_rotation`](Self::plan_rotation) can run off the vault's thread.
    ///
    /// Clones the current DEK and reads the password slot from the sidecar. The
    /// returned [`RotationInputs`] is `Send`; its DEK bytes are sensitive —
    /// never log or persist them.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Json`] if the sidecar cannot be read, or
    /// [`Error::MetaInvalid`] if the vault has not been migrated to v2.
    pub fn rotation_inputs(&self) -> Result<RotationInputs> {
        let meta = self.read_v2_meta()?;
        Ok(RotationInputs {
            dek: self.derived_key(),
            password_slot: meta.slots.password,
        })
    }

    /// The expensive half of a passphrase change: verify the old passphrase by
    /// unwrapping the DEK from the current password slot, then derive a new
    /// slot key and re-seal the DEK under it.
    ///
    /// Pure compute over owned inputs — touches no files and no connection —
    /// so it is safe to run on a background executor while the `!Send` vault
    /// stays on its own thread.
    ///
    /// # Errors
    ///
    /// [`Error::WrongPassphrase`] if `old_passphrase` is wrong, [`Error::Kdf`]
    /// on invalid params, [`Error::KeySlotCorrupt`] on a malformed slot.
    pub fn plan_rotation(
        inputs: &RotationInputs,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<RotationPlan> {
        // Verify the old passphrase by actually unwrapping the DEK from its slot.
        let old_slot_key = derive_key(
            old_passphrase,
            &inputs.password_slot.salt()?,
            inputs.password_slot.kdf_params,
        )?;
        let Some(unwrapped) = keyslot::open(
            old_slot_key.expose_secret().expose_bytes(),
            &inputs.password_slot.wrap,
            PASSWORD_SLOT,
        )?
        else {
            return Err(Error::WrongPassphrase);
        };
        // Defensive: the slot must unwrap to the very DEK the vault is using.
        if !constant_time_eq(
            &unwrapped.expose_secret().0,
            &inputs.dek.expose_secret().0,
        ) {
            return Err(Error::WrongPassphrase);
        }
        Ok(RotationPlan {
            new_password_slot: reseal_password_slot(
                &inputs.dek,
                new_passphrase,
                inputs.password_slot.kdf_params,
            )?,
        })
    }

    /// The cheap, crash-safe half of a passphrase change / reset: commit a
    /// [`RotationPlan`]'s new password slot. Must run on the vault's thread.
    ///
    /// Replaces only the password slot in the sidecar (preserving any recovery
    /// slot) and writes it atomically (temp + rename). The DEK is unchanged, so
    /// the database is always openable throughout: a crash before the rename
    /// leaves the old passphrase working, after it the new one — never a brick.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] / [`Error::Io`] / [`Error::Json`].
    pub fn apply_rotation(&mut self, plan: RotationPlan) -> Result<()> {
        let mut meta = self.read_v2_meta()?;
        meta.slots.password = plan.new_password_slot;
        meta.write(&self.meta_path)?;
        Ok(())
    }

    /// Cheaply snapshot the inputs for setting a passphrase **without** the old
    /// one (after a recovery unlock). The returned value is `Send`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Json`] / [`Error::MetaInvalid`] reading the sidecar.
    pub fn set_passphrase_inputs(&self) -> Result<SetPassphraseInputs> {
        let meta = self.read_v2_meta()?;
        Ok(SetPassphraseInputs {
            dek: self.derived_key(),
            params: meta.slots.password.kdf_params,
        })
    }

    /// The expensive half of a passphrase reset: derive a new password slot for
    /// `new_passphrase`. No old-passphrase check — authorization came from
    /// whatever unlocked the vault (typically a recovery code). Off-thread safe.
    ///
    /// # Errors
    ///
    /// [`Error::Kdf`] on invalid params.
    pub fn plan_set_passphrase(
        inputs: &SetPassphraseInputs,
        new_passphrase: &str,
    ) -> Result<RotationPlan> {
        Ok(RotationPlan {
            new_password_slot: reseal_password_slot(&inputs.dek, new_passphrase, inputs.params)?,
        })
    }

    /// Set the passphrase without knowing the old one — for use right after a
    /// recovery-code unlock to let the user choose a new passphrase. Re-wraps
    /// the DEK under a fresh password slot; the DEK (and recovery slot) are
    /// untouched. Commit via [`apply_rotation`](Self::apply_rotation).
    ///
    /// # Errors
    ///
    /// [`Error::Kdf`] / [`Error::Db`] / [`Error::Io`] / [`Error::Json`].
    pub fn set_passphrase(&mut self, new_passphrase: &str) -> Result<()> {
        let inputs = self.set_passphrase_inputs()?;
        let plan = Self::plan_set_passphrase(&inputs, new_passphrase)?;
        self.apply_rotation(plan)
    }

    /// Cheaply snapshot the input (the DEK) for enrolling a recovery code.
    #[must_use]
    pub fn recovery_enroll_inputs(&self) -> RecoveryEnrollInputs {
        RecoveryEnrollInputs {
            dek: self.derived_key(),
        }
    }

    /// The expensive half of recovery enrollment: generate a fresh recovery
    /// code and a key slot that wraps the DEK under it. Returns the code (to
    /// show/print to the user) and the slot (to commit with
    /// [`apply_enroll_recovery`](Self::apply_enroll_recovery)). Off-thread safe.
    ///
    /// # Errors
    ///
    /// [`Error::Kdf`] on invalid params.
    pub fn plan_enroll_recovery(
        inputs: &RecoveryEnrollInputs,
        params: KdfParams,
    ) -> Result<(RecoveryCode, KeySlot)> {
        let code = RecoveryCode::generate();
        let salt = random_salt();
        let slot_key = derive_key_from_bytes(code.as_bytes(), &salt, params)?;
        let wrap = keyslot::seal(
            slot_key.expose_secret().expose_bytes(),
            inputs.dek.expose_secret().expose_bytes(),
            RECOVERY_SLOT,
        );
        Ok((code, KeySlot::new(&salt, params, wrap)))
    }

    /// Commit a recovery slot built by
    /// [`plan_enroll_recovery`](Self::plan_enroll_recovery), replacing any
    /// existing recovery slot. Atomic sidecar write.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Json`] / [`Error::MetaInvalid`].
    pub fn apply_enroll_recovery(&mut self, slot: KeySlot) -> Result<()> {
        let mut meta = self.read_v2_meta()?;
        meta.slots.recovery = Some(slot);
        meta.write(&self.meta_path)
    }

    /// Enroll (or replace) a recovery code, returning the freshly generated
    /// code to show the user. Synchronous all-in-one (runs Argon2id inline);
    /// drive the [`recovery_enroll_inputs`](Self::recovery_enroll_inputs) →
    /// [`plan_enroll_recovery`](Self::plan_enroll_recovery) →
    /// [`apply_enroll_recovery`](Self::apply_enroll_recovery) split to keep a UI
    /// responsive.
    ///
    /// # Errors
    ///
    /// [`Error::Kdf`] / [`Error::Io`] / [`Error::Json`].
    pub fn enroll_recovery(&mut self, params: KdfParams) -> Result<RecoveryCode> {
        let inputs = self.recovery_enroll_inputs();
        let (code, slot) = Self::plan_enroll_recovery(&inputs, params)?;
        self.apply_enroll_recovery(slot)?;
        Ok(code)
    }

    /// Whether a recovery code is currently enrolled.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Json`] / [`Error::MetaInvalid`] reading the sidecar.
    pub fn has_recovery(&self) -> Result<bool> {
        Ok(self.read_v2_meta()?.slots.recovery.is_some())
    }

    /// Remove the enrolled recovery slot. The recovery code stops working
    /// immediately; the passphrase is unaffected.
    ///
    /// # Errors
    ///
    /// [`Error::NoRecoverySlot`] if none is enrolled, otherwise
    /// [`Error::Io`] / [`Error::Json`].
    pub fn remove_recovery(&mut self) -> Result<()> {
        let mut meta = self.read_v2_meta()?;
        if meta.slots.recovery.is_none() {
            return Err(Error::NoRecoverySlot);
        }
        meta.slots.recovery = None;
        meta.write(&self.meta_path)
    }

    /// Open a vault using its **recovery code** instead of the passphrase.
    ///
    /// Unwraps the DEK from the recovery slot and opens the database with it.
    /// The caller will typically follow with [`set_passphrase`](Self::set_passphrase)
    /// to let the user choose a new passphrase (they forgot the old one).
    ///
    /// # Errors
    ///
    /// [`Error::NoRecoverySlot`] if the vault has no recovery slot (incl. a
    /// not-yet-migrated v1 vault), [`Error::WrongRecoveryCode`] if the code is
    /// wrong, otherwise [`Error::MetaMissing`] / [`Error::Db`] / [`Error::Io`].
    pub fn open_with_recovery<P: AsRef<Path>>(path: P, code: &RecoveryCode) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let meta_path = meta_path_for(&vault_path);

        let StoredMeta::V2(meta) = StoredMeta::read(&meta_path)? else {
            return Err(Error::NoRecoverySlot);
        };
        let slot = meta.slots.recovery.ok_or(Error::NoRecoverySlot)?;
        let slot_key = derive_key_from_bytes(code.as_bytes(), &slot.salt()?, slot.kdf_params)?;
        let Some(dek) = keyslot::open(
            slot_key.expose_secret().expose_bytes(),
            &slot.wrap,
            RECOVERY_SLOT,
        )?
        else {
            return Err(Error::WrongRecoveryCode);
        };

        let conn = open_keyed(&vault_path, &dek)?;
        verify_key(&conn)?;
        Ok(Self {
            conn,
            key: dek,
            vault_path,
            meta_path,
        })
    }

    /// Read the sidecar and require it to be in v2 (DEK) format. Every
    /// credential-management operation needs the slot model; a `Vault` opened
    /// normally is always v2 (v1 is migrated on `open`), so a v1 here means it
    /// was opened key-only without migrating — a clear, non-destructive error.
    fn read_v2_meta(&self) -> Result<MetaV2> {
        match StoredMeta::read(&self.meta_path)? {
            StoredMeta::V2(m) => Ok(m),
            StoredMeta::V1(_) => Err(Error::MetaInvalid(
                "vault is still in legacy v1 format; reopen with the passphrase to migrate".into(),
            )),
        }
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
    // Fail closed if the linked SQLite isn't SQLCipher: otherwise `PRAGMA key` is a silent no-op
    // and the vault would be written in the clear. `PRAGMA cipher_version` returns the SQLCipher
    // build string; on plain SQLite the pragma yields no row (the query errors).
    let cipher = conn.query_row("PRAGMA cipher_version", [], |r| r.get::<_, String>(0));
    if !matches!(&cipher, Ok(v) if !v.trim().is_empty()) {
        return Err(Error::EncryptionUnavailable);
    }
    let literal = key.expose_secret().pragma_literal();
    // `key` accepts the `x'<hex>'` blob literal -> raw key, no inner KDF.
    conn.pragma_update(None, "key", literal.as_str())
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

/// Where a `rotate_key` stages the new sidecar before committing it: `<meta>.rekeying`.
fn rekey_staging_path(meta_path: &Path) -> PathBuf {
    let mut s = meta_path.as_os_str().to_owned();
    s.push(".rekeying");
    PathBuf::from(s)
}

/// Open a v2 vault with `passphrase`: derive the password slot key, unwrap the
/// DEK, open the database with it. A wrong passphrase fails AEAD authentication
/// → [`Error::WrongPassphrase`].
fn open_v2(
    vault_path: PathBuf,
    meta_path: PathBuf,
    passphrase: &str,
    meta: &MetaV2,
) -> Result<Vault> {
    let slot = &meta.slots.password;
    let slot_key = derive_key(passphrase, &slot.salt()?, slot.kdf_params)?;
    let Some(dek) = keyslot::open(
        slot_key.expose_secret().expose_bytes(),
        &slot.wrap,
        PASSWORD_SLOT,
    )?
    else {
        return Err(Error::WrongPassphrase);
    };
    let conn = open_keyed(&vault_path, &dek)?;
    verify_key(&conn)?;
    // The committed sidecar is already v2, so any staged sidecar is a moot
    // migration orphan — clean it up, best-effort.
    let _ = std::fs::remove_file(rekey_staging_path(&meta_path));
    Ok(Vault {
        conn,
        key: dek,
        vault_path,
        meta_path,
    })
}

/// Build a new **password** [`KeySlot`] that seals `dek` under a key derived
/// from `passphrase` over a fresh salt. Shared by passphrase change and reset.
fn reseal_password_slot(
    dek: &SecretBox<DerivedKey>,
    passphrase: &str,
    params: KdfParams,
) -> Result<KeySlot> {
    let salt = random_salt();
    let slot_key = derive_key(passphrase, &salt, params)?;
    let wrap = keyslot::seal(
        slot_key.expose_secret().expose_bytes(),
        dek.expose_secret().expose_bytes(),
        PASSWORD_SLOT,
    );
    Ok(KeySlot::new(&salt, params, wrap))
}

/// Migrate an open v1 vault to the v2 DEK format, crash-safely.
///
/// `conn` is the database opened with its v1 (salt-derived) key. Generate a
/// random DEK, build a v2 password slot wrapping it, **stage** the v2 sidecar,
/// `PRAGMA rekey` the database to the DEK, then atomically rename the staged
/// sidecar over the v1 one. A crash after rekey but before the rename leaves
/// the DB keyed by the DEK with a v1 committed sidecar + staged v2 sidecar →
/// [`recover_interrupted_migration`] finishes it on the next unlock.
fn migrate_v1_to_v2(
    conn: Connection,
    vault_path: PathBuf,
    meta_path: PathBuf,
    passphrase: &str,
    v1: &VaultMeta,
) -> Result<Vault> {
    // Preserve the vault's chosen Argon2 cost for the new password slot.
    let params = v1.kdf_params;
    let dek = random_key();
    let slot = reseal_password_slot(&dek, passphrase, params)?;
    let staged_meta = MetaV2::new(slot);

    // Stage the v2 sidecar BEFORE rekey (so a post-rekey crash is recoverable).
    let staged = rekey_staging_path(&meta_path);
    staged_meta.write(&staged)?;

    // Re-encrypt the database in place from the v1 key to the DEK.
    let literal = dek.expose_secret().pragma_literal();
    conn.pragma_update(None, "rekey", literal.as_str())
        .map_err(map_cipher_err)?;

    // Commit: atomically replace the v1 sidecar with the staged v2 one.
    std::fs::rename(&staged, &meta_path)?;

    Ok(Vault {
        conn,
        key: dek,
        vault_path,
        meta_path,
    })
}

/// Recover a migration (or a legacy v1 `rotate_key`) interrupted after
/// `PRAGMA rekey` but before the sidecar commit: the database is keyed by the
/// *staged* sidecar's key. If a staged sidecar exists and opens the database
/// with `passphrase`, finalize it (rename into place) and return the open
/// vault; otherwise `None` (a genuine wrong passphrase).
fn recover_interrupted_migration(
    vault_path: &Path,
    meta_path: &Path,
    passphrase: &str,
) -> Result<Option<Vault>> {
    let staged = rekey_staging_path(meta_path);
    if !staged.exists() {
        return Ok(None);
    }
    match StoredMeta::read(&staged)? {
        // Interrupted v1→v2 migration: derive the staged password slot key,
        // unwrap the DEK, confirm it opens the rekeyed DB, then commit.
        StoredMeta::V2(meta) => {
            let slot = &meta.slots.password;
            let slot_key = derive_key(passphrase, &slot.salt()?, slot.kdf_params)?;
            let Some(dek) = keyslot::open(
                slot_key.expose_secret().expose_bytes(),
                &slot.wrap,
                PASSWORD_SLOT,
            )?
            else {
                return Ok(None);
            };
            let Ok(conn) = open_and_verify(vault_path, &dek) else {
                return Ok(None);
            };
            std::fs::rename(&staged, meta_path)?;
            Ok(Some(Vault {
                conn,
                key: dek,
                vault_path: vault_path.to_path_buf(),
                meta_path: meta_path.to_path_buf(),
            }))
        }
        // Legacy: a v1 rotate_key from a pre-upgrade build crashed mid-rekey.
        // Finalize it as v1; the next unlock migrates it to v2.
        StoredMeta::V1(meta) => {
            let key = derive_key(passphrase, &meta.salt()?, meta.kdf_params)?;
            let Ok(conn) = open_and_verify(vault_path, &key) else {
                return Ok(None);
            };
            std::fs::rename(&staged, meta_path)?;
            Ok(Some(Vault {
                conn,
                key,
                vault_path: vault_path.to_path_buf(),
                meta_path: meta_path.to_path_buf(),
            }))
        }
    }
}

/// Open the keyed connection and confirm the key with a cheap read. A wrong key reports
/// `WrongPassphrase` from either step.
fn open_and_verify(path: &Path, key: &SecretBox<DerivedKey>) -> Result<Connection> {
    let conn = open_keyed(path, key)?;
    verify_key(&conn)?;
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
    // A symlink at either path is never a valid vault file. Strip it first (with the
    // non-following `symlink_metadata`) so `create` writes a fresh *regular* file rather than
    // following the link and writing through it — a **dangling** symlink is invisible to
    // `exists()` below, so without this an attacker-planted link could redirect the new DB.
    for p in [vault_path, meta_path] {
        if let Ok(md) = std::fs::symlink_metadata(p) {
            if md.file_type().is_symlink() {
                std::fs::remove_file(p)?;
            }
        }
    }
    let v = vault_path.exists();
    let m = meta_path.exists();
    match (v, m) {
        (true, true) => Err(Error::AlreadyExists(vault_path.to_path_buf())),
        (true, false) | (false, true) => {
            if v {
                std::fs::remove_file(vault_path)?;
                // Drop the orphan DB's WAL/SHM sidecars too, so the fresh DB doesn't inherit a
                // stale write-ahead log (which SQLite would try to replay into the new file).
                for ext in ["-wal", "-shm"] {
                    let mut p = vault_path.as_os_str().to_owned();
                    p.push(ext);
                    let _ = std::fs::remove_file(PathBuf::from(p));
                }
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

    /// Write a genuine **legacy v1** vault (salt directly derives the SQLCipher
    /// key, v1 sidecar) with a `t(x)=7` row, mirroring the pre-DEK `create`.
    /// Used to exercise the lazy v1→v2 migration on `open`.
    fn create_v1_vault(path: &Path, pass: &str, params: KdfParams) {
        let salt = random_salt();
        let key = derive_key(pass, &salt, params).unwrap();
        let conn = open_keyed(path, &key).unwrap();
        init_schema(&conn).unwrap();
        conn.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (7);")
            .unwrap();
        VaultMeta::new(&salt, params)
            .write(&meta_path_for(path))
            .unwrap();
        conn.close().unwrap();
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
    fn three_phase_rotation_matches_rotate_key() {
        // The split path (rotation_inputs → plan_rotation → apply_rotation) the
        // responsive UI uses must be byte-for-byte equivalent to rotate_key:
        // same crash-safe on-disk protocol, same data preserved, old passphrase
        // rejected afterwards.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        {
            let mut v = Vault::create(&path, "old", p()).unwrap();
            v.with_connection(|c| c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (9);"))
                .unwrap();
            let inputs = v.rotation_inputs().unwrap();
            // plan_rotation is the off-thread half; takes only owned inputs.
            let plan = Vault::plan_rotation(&inputs, "old", "new").unwrap();
            v.apply_rotation(plan).unwrap();
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
        assert_eq!(x, 9);
    }

    #[test]
    fn plan_rotation_rejects_wrong_old_passphrase() {
        // The constant-time passphrase check must live in the off-thread half,
        // so a wrong old passphrase never reaches apply_rotation / PRAGMA rekey.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let v = Vault::create(&path, "old", p()).unwrap();
        let inputs = v.rotation_inputs().unwrap();
        // `matches!` (not `unwrap_err`) because the Ok variant `RotationPlan`
        // holds a `SecretBox` and deliberately has no `Debug`.
        assert!(matches!(
            Vault::plan_rotation(&inputs, "bogus", "new"),
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn open_migrates_v1_vault_to_v2_preserving_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        create_v1_vault(&path, "pw", p());
        let meta_path = meta_path_for(&path);
        // Precondition: it really is a v1 sidecar.
        assert!(matches!(
            StoredMeta::read(&meta_path).unwrap(),
            StoredMeta::V1(_)
        ));
        // First open migrates it to v2 and preserves the data.
        {
            let v = Vault::open(&path, "pw").unwrap();
            let x: i64 = v
                .with_connection(|c| c.query_row("SELECT x FROM t", [], |r| r.get(0)))
                .unwrap();
            assert_eq!(x, 7);
            v.lock();
        }
        // It is now v2, the wrong passphrase is still rejected, and — the whole
        // point — it can now enroll a recovery code.
        assert!(matches!(
            StoredMeta::read(&meta_path).unwrap(),
            StoredMeta::V2(_)
        ));
        assert!(matches!(
            Vault::open(&path, "nope").unwrap_err(),
            Error::WrongPassphrase
        ));
        let mut v = Vault::open(&path, "pw").unwrap();
        let code = v.enroll_recovery(p()).unwrap();
        v.lock();
        assert!(Vault::open_with_recovery(&path, &code).is_ok());
    }

    #[test]
    fn open_recovers_from_interrupted_migration_no_brick() {
        use secrecy::ExposeSecret as _;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        create_v1_vault(&path, "pw", p());
        let meta_path = meta_path_for(&path);

        // Simulate migrate_v1_to_v2 crashing AFTER `PRAGMA rekey` but BEFORE the staged-sidecar
        // rename: open with the v1 key, stage a v2 sidecar, rekey the DB to a fresh DEK, then leak
        // the connection (the "crash") so the rekeyed pages persist in the `-wal`.
        {
            let v1 = VaultMeta::read(&meta_path).unwrap();
            let k1 = derive_key("pw", &v1.salt().unwrap(), v1.kdf_params).unwrap();
            let conn = open_keyed(&path, &k1).unwrap();
            let dek = random_key();
            let slot = reseal_password_slot(&dek, "pw", p()).unwrap();
            MetaV2::new(slot)
                .write(&rekey_staging_path(&meta_path))
                .unwrap();
            conn.pragma_update(
                None,
                "rekey",
                dek.expose_secret().pragma_literal().as_str(),
            )
            .unwrap();
            #[allow(clippy::mem_forget)]
            std::mem::forget(conn);
        }
        // The committed (v1) sidecar's key no longer opens the rekeyed DB; open must recover via
        // the staged v2 sidecar, preserve data, and finalize the migration — no brick.
        let v = Vault::open(&path, "pw").unwrap();
        let x: i64 = v
            .with_connection(|c| c.query_row("SELECT x FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(x, 7);
        v.lock();
        assert!(!rekey_staging_path(&meta_path).exists());
        assert!(matches!(
            StoredMeta::read(&meta_path).unwrap(),
            StoredMeta::V2(_)
        ));
    }

    #[test]
    fn recovery_unlock_roundtrip_and_reset_passphrase() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let code;
        {
            let mut v = Vault::create(&path, "orig", p()).unwrap();
            v.with_connection(|c| c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (5);"))
                .unwrap();
            code = v.enroll_recovery(p()).unwrap();
            assert!(v.has_recovery().unwrap());
            v.lock();
        }
        // Forgot the passphrase: unlock with the recovery code, read data, set a new passphrase.
        {
            let mut v = Vault::open_with_recovery(&path, &code).unwrap();
            let x: i64 = v
                .with_connection(|c| c.query_row("SELECT x FROM t", [], |r| r.get(0)))
                .unwrap();
            assert_eq!(x, 5);
            v.set_passphrase("brandnew").unwrap();
            v.lock();
        }
        // Old passphrase dead; new one works; the recovery code STILL works (it survived the reset
        // because the DEK never changed).
        assert!(matches!(
            Vault::open(&path, "orig").unwrap_err(),
            Error::WrongPassphrase
        ));
        assert!(Vault::open(&path, "brandnew").is_ok());
        assert!(Vault::open_with_recovery(&path, &code).is_ok());
    }

    #[test]
    fn recovery_code_round_trips_through_printed_string() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let printed;
        {
            let mut v = Vault::create(&path, "pw", p()).unwrap();
            let code = v.enroll_recovery(p()).unwrap();
            printed = code.format().to_string();
            v.lock();
        }
        // The code as it would appear on the printed kit, re-parsed, unlocks the vault.
        let parsed = RecoveryCode::parse(&printed).unwrap();
        assert!(Vault::open_with_recovery(&path, &parsed).is_ok());
    }

    #[test]
    fn wrong_recovery_code_is_distinct_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let mut v = Vault::create(&path, "pw", p()).unwrap();
        v.enroll_recovery(p()).unwrap();
        v.lock();
        assert!(matches!(
            Vault::open_with_recovery(&path, &RecoveryCode::generate()).unwrap_err(),
            Error::WrongRecoveryCode
        ));
    }

    #[test]
    fn open_with_recovery_without_enrollment_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        Vault::create(&path, "pw", p()).unwrap().lock();
        assert!(matches!(
            Vault::open_with_recovery(&path, &RecoveryCode::generate()).unwrap_err(),
            Error::NoRecoverySlot
        ));
    }

    #[test]
    fn remove_recovery_disables_the_code() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let code;
        {
            let mut v = Vault::create(&path, "pw", p()).unwrap();
            code = v.enroll_recovery(p()).unwrap();
            assert!(v.has_recovery().unwrap());
            v.remove_recovery().unwrap();
            assert!(!v.has_recovery().unwrap());
            // Removing again is a clear error, not a silent success.
            assert!(matches!(v.remove_recovery().unwrap_err(), Error::NoRecoverySlot));
            v.lock();
        }
        assert!(matches!(
            Vault::open_with_recovery(&path, &code).unwrap_err(),
            Error::NoRecoverySlot
        ));
        assert!(Vault::open(&path, "pw").is_ok()); // passphrase unaffected
    }

    #[test]
    fn passphrase_change_preserves_recovery_slot() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let code;
        {
            let mut v = Vault::create(&path, "old", p()).unwrap();
            code = v.enroll_recovery(p()).unwrap();
            v.rotate_key("old", "new").unwrap();
            v.lock();
        }
        // The recovery code is untouched by the passphrase change.
        assert!(Vault::open_with_recovery(&path, &code).is_ok());
        assert!(Vault::open(&path, "new").is_ok());
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
    fn files_returns_db_and_meta_paths() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let v = Vault::create(&path, "pw", p()).unwrap();
        let (db, meta) = v.files();
        assert_eq!(db, path.as_path());
        assert_eq!(meta, meta_path_for(&path).as_path());
        v.lock();
    }

    #[cfg(unix)]
    #[test]
    fn create_strips_a_dangling_symlink_at_the_vault_path() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let victim = dir.path().join("victim-target"); // does not exist → dangling link
        symlink(&victim, &path).unwrap();
        // `create` must strip the link and write a regular file — never follow it and write
        // through to the (attacker-chosen) target.
        Vault::create(&path, "pw", p()).unwrap().lock();
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_file());
        assert!(
            !victim.exists(),
            "create must not write through the symlink"
        );
        assert!(Vault::open(&path, "pw").is_ok());
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
    fn passphrase_change_keeps_dek_stable_but_kills_old_passphrase() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.memento");
        let dek_before;
        let dek_after;
        {
            let mut v = Vault::create(&path, "old", p()).unwrap();
            dek_before = *v.derived_key().expose_secret().expose_bytes();
            v.rotate_key("old", "new").unwrap();
            dek_after = *v.derived_key().expose_secret().expose_bytes();
            v.lock();
        }
        // The DEK is STABLE across a passphrase change (v2 only re-wraps the
        // password slot). This is the property that lets a recovery code — and
        // a biometric-stashed DEK — survive a passphrase change. Biometric
        // re-gating on passphrase change is now a UI policy, not implied by key
        // invalidation (contrast the old v1 rekey behavior).
        assert_eq!(dek_before, dek_after, "DEK must not change on passphrase rotation");
        assert!(
            Vault::open_with_key(&path, &dek_before).is_ok(),
            "the stable DEK still opens the vault"
        );
        // The OLD passphrase no longer derives a working password slot.
        assert!(matches!(
            Vault::open(&path, "old").unwrap_err(),
            Error::WrongPassphrase
        ));
        assert!(Vault::open(&path, "new").is_ok());
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
