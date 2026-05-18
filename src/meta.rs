//! The vault metadata sidecar (`<vault>.meta.json`).
//!
//! SQLCipher stores nothing but ciphertext, so the salt and KDF parameters
//! needed to reproduce the key live in a small JSON file next to the
//! database. The sidecar contains **no secret material** — losing it makes
//! the vault unrecoverable (the salt is gone), but reading it reveals
//! nothing useful to an attacker.

use crate::error::{Error, Result};
use crate::kdf::{KdfParams, SALT_LEN};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The only sidecar format version this build understands.
pub const FORMAT_VERSION: u32 = 1;

/// Filesystem suffix appended to the vault path to locate the sidecar.
///
/// For a vault at `notes.memento` the sidecar is `notes.memento.meta.json`.
pub const META_SUFFIX: &str = ".meta.json";

/// Parsed contents of `<vault>.meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            salt_hex: hex_encode(salt),
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
        let bytes = hex_decode(&self.salt_hex)
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
        let json = serde_json::to_vec_pretty(self)?;
        let tmp = meta_path.with_extension("meta.json.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, meta_path)?;
        Ok(())
    }
}

/// Compute the sidecar path for a given vault path.
#[must_use]
pub fn meta_path_for(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_owned();
    s.push(META_SUFFIX);
    PathBuf::from(s)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn now_rfc3339() -> String {
    // Avoid a chrono dependency: derive an RFC 3339 UTC timestamp from the
    // Unix epoch with a minimal civil-date computation.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Seconds since 1970 fit in i64 until year ~292 billion; the wrap the
    // lint warns about cannot occur for any real system clock.
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
}
