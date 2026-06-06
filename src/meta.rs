//! The vault metadata sidecar (`<vault>.meta.json`).
//!
//! SQLCipher stores nothing but ciphertext, so the salt and KDF parameters
//! needed to reproduce the key live in a small JSON file next to the
//! database. The sidecar contains **no secret material** — losing it makes
//! the vault unrecoverable (the salt is gone), but reading it reveals
//! nothing useful to an attacker.

use crate::error::{Error, Result};
use crate::hex;
use crate::kdf::{KdfParams, SALT_LEN};
use crate::keyslot::WrappedKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The legacy (v1) sidecar format: the salt directly derived the SQLCipher
/// key. Still read (and transparently migrated to [`CURRENT_FORMAT_VERSION`]
/// on first unlock), never written by this build.
pub const FORMAT_VERSION: u32 = 1;

/// The current sidecar format version this build writes: the **DEK key-slot**
/// model. The SQLCipher key is a random data-encryption key (DEK); each
/// credential ([`KeySlot`]) wraps the same DEK. See [`MetaV2`].
pub const CURRENT_FORMAT_VERSION: u32 = 2;

/// Filesystem suffix appended to the vault path to locate the sidecar.
///
/// For a vault at `notes.memento` the sidecar is `notes.memento.meta.json`.
pub const META_SUFFIX: &str = ".meta.json";

/// Parsed contents of `<vault>.meta.json`.
///
/// `deny_unknown_fields`: this is a security sidecar, so an unrecognised field must be a hard
/// error — never silently dropped. Otherwise an old build could accept (and `validate()` would
/// pass) a sidecar carrying a future field it doesn't understand.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultMeta {
    /// Sidecar format version. See [`FORMAT_VERSION`].
    pub version: u32,
    /// KDF algorithm identifier. Always `"argon2id"` in v1.
    pub kdf: String,
    /// Argon2id cost parameters used to derive this vault's key.
    pub kdf_params: KdfParams,
    /// Lowercase hex encoding of the 16-byte salt.
    pub salt_hex: String,
    /// RFC 3339 / ISO 8601 creation timestamp (informational only).
    pub created_at: String,
}

impl VaultMeta {
    /// Build a fresh sidecar for a newly-created vault.
    #[must_use]
    pub fn new(salt: &[u8; SALT_LEN], params: KdfParams) -> Self {
        Self {
            version: FORMAT_VERSION,
            kdf: "argon2id".to_string(),
            kdf_params: params,
            salt_hex: hex::encode(salt),
            created_at: now_rfc3339(),
        }
    }

    /// Decode the stored salt back into a fixed 16-byte array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MetaInvalid`] if the hex is malformed or not exactly
    /// 16 bytes long.
    pub fn salt(&self) -> Result<[u8; SALT_LEN]> {
        decode_salt(&self.salt_hex)
    }

    /// Validate semantic invariants after deserialization.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedFormat`] for a future version, or
    /// [`Error::MetaInvalid`] for an unknown KDF or a bad salt.
    pub fn validate(&self) -> Result<()> {
        if self.version > FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                found: self.version,
                supported: FORMAT_VERSION,
            });
        }
        if self.kdf != "argon2id" {
            return Err(Error::MetaInvalid(format!(
                "unsupported kdf {:?}",
                self.kdf
            )));
        }
        // Bound the Argon2 cost: the sidecar is unauthenticated, so a tampered params value must
        // not be able to pin an absurd memory cost (multi-TiB allocation) on the next derive.
        self.kdf_params.validate()?;
        let _ = self.salt()?;
        Ok(())
    }

    /// Read and validate a sidecar from disk.
    ///
    /// # Errors
    ///
    /// [`Error::MetaMissing`] if absent, [`Error::Json`] if unparseable, or
    /// the variants from [`VaultMeta::validate`].
    pub fn read(meta_path: &Path) -> Result<Self> {
        if !meta_path.exists() {
            return Err(Error::MetaMissing(meta_path.to_path_buf()));
        }
        let bytes = std::fs::read(meta_path)?;
        let meta: VaultMeta = serde_json::from_slice(&bytes)?;
        meta.validate()?;
        Ok(meta)
    }

    /// Atomically write the sidecar (write-temp-then-rename).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] on serialization failure or [`Error::Io`] on a
    /// filesystem error.
    pub fn write(&self, meta_path: &Path) -> Result<()> {
        atomic_write_json(self, meta_path)
    }
}

/// Decode a hex salt into the fixed 16-byte array. Shared by [`VaultMeta`]
/// (v1) and [`KeySlot`] (v2).
///
/// # Errors
///
/// [`Error::MetaInvalid`] if the hex is malformed or not exactly [`SALT_LEN`] bytes.
fn decode_salt(salt_hex: &str) -> Result<[u8; SALT_LEN]> {
    let bytes = hex::decode(salt_hex)
        .ok_or_else(|| Error::MetaInvalid("salt_hex is not valid hex".into()))?;
    if bytes.len() != SALT_LEN {
        return Err(Error::MetaInvalid(format!(
            "salt must be {SALT_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes);
    Ok(salt)
}

/// Serialize `value` to pretty JSON and write it atomically (write a sibling
/// `*.tmp`, then rename over the target). Shared by every sidecar writer so the
/// crash-safety property (a reader never sees a half-written sidecar) holds
/// uniformly across v1 and v2.
fn atomic_write_json<T: Serialize>(value: &T, meta_path: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(value)?;
    let tmp = meta_path.with_extension("meta.json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, meta_path)?;
    Ok(())
}

/// Compute the sidecar path for a given vault path.
#[must_use]
pub fn meta_path_for(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_owned();
    s.push(META_SUFFIX);
    PathBuf::from(s)
}

/// One credential's **key slot** in the v2 format.
///
/// Holds the Argon2id parameters and salt used to derive this credential's
/// slot key, plus the DEK sealed under that slot key ([`WrappedKey`]). The
/// slot reveals nothing without the credential: the salt and params are public
/// by design, and the wrap is authenticated ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySlot {
    /// Argon2id cost parameters for deriving this slot's key.
    pub kdf_params: KdfParams,
    /// Lowercase hex of the 16-byte Argon2id salt for this slot.
    pub salt_hex: String,
    /// The DEK sealed under `Argon2id(credential, salt)`.
    pub wrap: WrappedKey,
}

impl KeySlot {
    /// Assemble a slot from its parts (salt + params + wrapped DEK).
    #[must_use]
    pub fn new(salt: &[u8; SALT_LEN], params: KdfParams, wrap: WrappedKey) -> Self {
        Self {
            kdf_params: params,
            salt_hex: hex::encode(salt),
            wrap,
        }
    }

    /// Decode this slot's Argon2id salt.
    ///
    /// # Errors
    ///
    /// [`Error::MetaInvalid`] if the hex is malformed or the wrong length.
    pub fn salt(&self) -> Result<[u8; SALT_LEN]> {
        decode_salt(&self.salt_hex)
    }

    /// Validate the slot's params and salt (the cost bound mirrors v1, so a
    /// tampered sidecar cannot pin an absurd Argon2 memory cost).
    ///
    /// # Errors
    ///
    /// [`Error::MetaInvalid`] / [`Error::Kdf`] on bad params or salt.
    pub fn validate(&self) -> Result<()> {
        self.kdf_params.validate()?;
        let _ = self.salt()?;
        Ok(())
    }
}

/// The credential slots that can unwrap a vault's DEK.
///
/// `password` is always present; `recovery` is present iff a recovery code has
/// been enrolled. The design allows more slots later (e.g. a second recovery)
/// without a format bump — but `deny_unknown_fields` still rejects *unknown*
/// keys so the sidecar stays a strict interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySlots {
    /// The passphrase slot. Always present.
    pub password: KeySlot,
    /// The recovery-code slot, present iff a recovery kit has been enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<KeySlot>,
}

/// Parsed contents of a v2 (`version: 2`) sidecar — the DEK key-slot format.
///
/// Unlike v1, the salt no longer derives the database key directly; the
/// database key is a random DEK wrapped inside each [`KeySlot`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaV2 {
    /// Sidecar format version. Always [`CURRENT_FORMAT_VERSION`] (2).
    pub version: u32,
    /// KDF algorithm identifier. Always `"argon2id"`.
    pub kdf: String,
    /// RFC 3339 creation timestamp (informational only).
    pub created_at: String,
    /// The credential slots wrapping the DEK.
    pub slots: KeySlots,
}

impl MetaV2 {
    /// Build a fresh v2 sidecar carrying only a password slot (no recovery yet).
    #[must_use]
    pub fn new(password: KeySlot) -> Self {
        Self {
            version: CURRENT_FORMAT_VERSION,
            kdf: "argon2id".to_string(),
            created_at: now_rfc3339(),
            slots: KeySlots {
                password,
                recovery: None,
            },
        }
    }

    /// Validate semantic invariants after deserialization.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedFormat`] for a non-2 version, [`Error::MetaInvalid`]
    /// for an unknown KDF, or the per-slot validation errors.
    pub fn validate(&self) -> Result<()> {
        if self.version != CURRENT_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                found: self.version,
                supported: CURRENT_FORMAT_VERSION,
            });
        }
        if self.kdf != "argon2id" {
            return Err(Error::MetaInvalid(format!(
                "unsupported kdf {:?}",
                self.kdf
            )));
        }
        self.slots.password.validate()?;
        if let Some(r) = &self.slots.recovery {
            r.validate()?;
        }
        Ok(())
    }

    /// Read and validate a v2 sidecar from disk.
    ///
    /// # Errors
    ///
    /// [`Error::MetaMissing`] if absent, [`Error::Json`] if unparseable, or the
    /// variants from [`MetaV2::validate`].
    pub fn read(meta_path: &Path) -> Result<Self> {
        if !meta_path.exists() {
            return Err(Error::MetaMissing(meta_path.to_path_buf()));
        }
        let bytes = std::fs::read(meta_path)?;
        let meta: MetaV2 = serde_json::from_slice(&bytes)?;
        meta.validate()?;
        Ok(meta)
    }

    /// Atomically write the sidecar (write-temp-then-rename).
    ///
    /// # Errors
    ///
    /// [`Error::Json`] on serialization failure or [`Error::Io`] on a filesystem error.
    pub fn write(&self, meta_path: &Path) -> Result<()> {
        atomic_write_json(self, meta_path)
    }
}

/// Minimal view used to read just the `version` field before committing to a
/// strict, version-specific schema. Ignores all other fields by design.
#[derive(Deserialize)]
struct VersionPeek {
    version: u32,
}

/// A sidecar read from disk, dispatched by its declared `version`.
///
/// The vault matches on this: a [`StoredMeta::V1`] triggers a transparent
/// migration to the v2 DEK format on unlock; a [`StoredMeta::V2`] is used
/// directly.
#[derive(Debug)]
pub enum StoredMeta {
    /// Legacy salt-derives-key sidecar.
    V1(VaultMeta),
    /// Current DEK key-slot sidecar.
    V2(MetaV2),
}

impl StoredMeta {
    /// Read a sidecar, parsing it as the version it declares.
    ///
    /// Peeks the `version` field first (ignoring all others), then parses with
    /// the strict, `deny_unknown_fields` struct for that exact version — so a
    /// field belonging to the *other* version is a hard error, never silently
    /// accepted.
    ///
    /// # Errors
    ///
    /// [`Error::MetaMissing`] if absent, [`Error::Json`] if unparseable,
    /// [`Error::UnsupportedFormat`] for a version beyond this build, or the
    /// per-version validation errors.
    pub fn read(meta_path: &Path) -> Result<Self> {
        if !meta_path.exists() {
            return Err(Error::MetaMissing(meta_path.to_path_buf()));
        }
        let bytes = std::fs::read(meta_path)?;

        // Peek the version without committing to a strict schema (this tolerates
        // the other version's fields; the real parse below does not).
        let peek: VersionPeek = serde_json::from_slice(&bytes)?;

        match peek.version {
            FORMAT_VERSION => {
                let meta: VaultMeta = serde_json::from_slice(&bytes)?;
                meta.validate()?;
                Ok(StoredMeta::V1(meta))
            }
            CURRENT_FORMAT_VERSION => {
                let meta: MetaV2 = serde_json::from_slice(&bytes)?;
                meta.validate()?;
                Ok(StoredMeta::V2(meta))
            }
            other => Err(Error::UnsupportedFormat {
                found: other,
                supported: CURRENT_FORMAT_VERSION,
            }),
        }
    }
}

fn now_rfc3339() -> String {
    // Avoid a chrono dependency: derive an RFC 3339 UTC timestamp from the
    // Unix epoch with a minimal civil-date computation.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // safe: `as_secs()` is `u64`; the u64->i64 cast only wraps above
    // i64::MAX (~9.2e18 s ≈ year 292_277_026_596). No real system clock
    // reaches that, so `cast_possible_wrap` cannot actually fire here.
    #[allow(clippy::cast_possible_wrap)]
    let secs = dur.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// Howard Hinnant's days-from-civil inverse. Public-domain algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn roundtrip_hex_salt() {
        let salt = [0xABu8; SALT_LEN];
        let m = VaultMeta::new(&salt, KdfParams::default());
        assert_eq!(m.salt().unwrap(), salt);
        assert_eq!(m.salt_hex.len(), SALT_LEN * 2);
    }

    #[test]
    fn meta_path_appends_suffix() {
        let p = meta_path_for(&PathBuf::from("/tmp/notes.memento"));
        assert_eq!(p, PathBuf::from("/tmp/notes.memento.meta.json"));
    }

    #[test]
    fn validate_rejects_out_of_range_kdf_params() {
        // A tampered sidecar pinning an absurd Argon2 memory cost must be refused before any
        // derive attempts a multi-TiB allocation.
        let mut m = VaultMeta::new(&[0u8; SALT_LEN], KdfParams::default());
        m.kdf_params.m_cost_kib = u32::MAX;
        assert!(matches!(m.validate(), Err(Error::MetaInvalid(_))));
    }

    #[test]
    fn deserialize_rejects_unknown_field() {
        // `deny_unknown_fields`: a future/garbage field is a hard error, never silently dropped.
        let json = r#"{"version":1,"kdf":"argon2id","kdf_params":{"m_cost_kib":65536,"t_cost":2,"p_cost":1},"salt_hex":"00112233445566778899aabbccddeeff","created_at":"x","surprise":true}"#;
        assert!(serde_json::from_str::<VaultMeta>(json).is_err());
    }

    #[test]
    fn rejects_future_version() {
        let mut m = VaultMeta::new(&[0u8; SALT_LEN], KdfParams::default());
        m.version = FORMAT_VERSION + 1;
        assert!(matches!(m.validate(), Err(Error::UnsupportedFormat { .. })));
    }

    #[test]
    fn rejects_unknown_kdf() {
        let mut m = VaultMeta::new(&[0u8; SALT_LEN], KdfParams::default());
        m.kdf = "scrypt".into();
        assert!(matches!(m.validate(), Err(Error::MetaInvalid(_))));
    }

    // ---- v2 (DEK key-slot) sidecar -------------------------------------

    fn sample_wrap() -> WrappedKey {
        WrappedKey {
            alg: "xchacha20poly1305".into(),
            nonce_hex: "00".repeat(24),
            ct_hex: "11".repeat(48),
        }
    }

    fn sample_password_slot() -> KeySlot {
        KeySlot::new(&[0xCDu8; SALT_LEN], KdfParams::default(), sample_wrap())
    }

    #[test]
    fn v2_roundtrip_write_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("v.memento.meta.json");
        let mut m = MetaV2::new(sample_password_slot());
        m.slots.recovery = Some(KeySlot::new(
            &[0xABu8; SALT_LEN],
            KdfParams::default(),
            sample_wrap(),
        ));
        m.write(&path).unwrap();
        let back = MetaV2::read(&path).unwrap();
        assert_eq!(back.version, CURRENT_FORMAT_VERSION);
        assert!(back.slots.recovery.is_some());
        assert_eq!(back.slots.password.salt().unwrap(), [0xCDu8; SALT_LEN]);
    }

    #[test]
    fn v2_recovery_slot_omitted_when_absent() {
        // No recovery enrolled → the field must not even appear in the JSON
        // (skip_serializing_if), keeping legacy-shaped vaults clean.
        let json = serde_json::to_string(&MetaV2::new(sample_password_slot())).unwrap();
        assert!(!json.contains("recovery"), "{json}");
        assert!(json.contains("\"version\":2") || json.contains("\"version\": 2"));
    }

    #[test]
    fn stored_meta_dispatches_by_version() {
        let dir = tempfile::TempDir::new().unwrap();

        // v1 file → StoredMeta::V1
        let p1 = dir.path().join("one.meta.json");
        VaultMeta::new(&[1u8; SALT_LEN], KdfParams::default())
            .write(&p1)
            .unwrap();
        assert!(matches!(StoredMeta::read(&p1).unwrap(), StoredMeta::V1(_)));

        // v2 file → StoredMeta::V2
        let p2 = dir.path().join("two.meta.json");
        MetaV2::new(sample_password_slot()).write(&p2).unwrap();
        assert!(matches!(StoredMeta::read(&p2).unwrap(), StoredMeta::V2(_)));
    }

    #[test]
    fn stored_meta_rejects_future_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("future.meta.json");
        std::fs::write(&path, br#"{"version":99,"kdf":"argon2id"}"#).unwrap();
        assert!(matches!(
            StoredMeta::read(&path),
            Err(Error::UnsupportedFormat {
                found: 99,
                supported: 2
            })
        ));
    }

    #[test]
    fn v2_deny_unknown_fields() {
        // A stray top-level field is a hard error — same strictness as v1.
        let json = r#"{"version":2,"kdf":"argon2id","created_at":"x","slots":{"password":{"kdf_params":{"m_cost_kib":65536,"t_cost":2,"p_cost":1},"salt_hex":"00112233445566778899aabbccddeeff","wrap":{"alg":"xchacha20poly1305","nonce_hex":"00","ct_hex":"11"}}},"surprise":true}"#;
        assert!(serde_json::from_str::<MetaV2>(json).is_err());
    }

    #[test]
    fn v2_validate_rejects_bad_salt_and_kdf() {
        let mut m = MetaV2::new(sample_password_slot());
        m.kdf = "scrypt".into();
        assert!(matches!(m.validate(), Err(Error::MetaInvalid(_))));

        let mut m2 = MetaV2::new(KeySlot {
            kdf_params: KdfParams::default(),
            salt_hex: "zz".into(),
            wrap: sample_wrap(),
        });
        m2.kdf = "argon2id".into();
        assert!(matches!(m2.validate(), Err(Error::MetaInvalid(_))));
    }
}
