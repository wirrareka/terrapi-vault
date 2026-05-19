//! Encrypted single-note export / import: the `.memento-note` container.
//!
//! A `.memento-note` file is a **self-contained, single-file encrypted
//! container that reuses the vault's existing crypto unchanged**. It is
//! deliberately *not* a new cryptographic primitive: the note is stored
//! inside an ordinary [`Vault`] — the same Argon2id KDF, the same raw-key
//! SQLCipher database, the same [`VaultMeta`] sidecar — and that vault's
//! two on-disk artifacts (the SQLCipher DB and its JSON sidecar) are then
//! framed into one portable file with a small plaintext header.
//!
//! Because the crypto path is *literally* [`Vault::create`] /
//! [`Vault::open`], the `.memento-note` format is already covered by the
//! audited vault code and its specification; only the outer framing is new
//! and it carries **no secret material** (it is the same kind of public
//! metadata as the sidecar).
//!
//! ## On-disk layout
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │ magic            8 bytes  ASCII  "MNOTE\0\0\0"  (NOTE_MAGIC) │
//! │ container_ver    1 byte   u8     == CONTAINER_VERSION (1)    │
//! │ meta_len         4 bytes  u32 LE length of the sidecar JSON  │
//! │ db_len           8 bytes  u64 LE length of the SQLCipher DB  │
//! │ meta_json        meta_len bytes  the VaultMeta sidecar JSON  │
//! │ db_bytes         db_len  bytes   the SQLCipher database file │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! The header and `meta_json` are plaintext **by design** (they mirror the
//! always-plaintext vault sidecar: salt + KDF params, no key, no note
//! content). `db_bytes` is a full SQLCipher database — ciphertext only;
//! the note title/body never appear in it in the clear. Authentication of
//! the note content is provided by SQLCipher's per-page HMAC (any flipped
//! byte in `db_bytes` makes the keyed read fail), exactly as for a vault.
//!
//! ## Secrets are intentionally NOT exported
//!
//! [`ExportedNote`] carries only note *content* (title, body, view mode,
//! timestamps). A note's `Secret` rows are vault-scoped; exporting them
//! would widen the blast radius of a leaked `.memento-note` file beyond
//! what the user is likely to expect from "export this note". Sharing
//! credentials is a separate, deliberate action. This decision is recorded
//! in `spec/note-export-format.md`.
//!
//! ## Memory hygiene
//!
//! The passphrase is borrowed, never stored, and handed straight to the
//! vault KDF (which zeroizes its derived key on drop). No plaintext note
//! content is ever written to disk: the only intermediate artifact is the
//! SQLCipher DB itself, which is encrypted. The temporary working
//! directory used while building/reading that DB is created with
//! [`tempfile`]-style semantics and removed (best-effort) before return.

use crate::error::{Error, Result};
use crate::kdf::KdfParams;
use crate::meta::meta_path_for;
use crate::vault::Vault;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

/// Magic prefix identifying a `.memento-note` container (8 bytes).
pub const NOTE_MAGIC: &[u8; 8] = b"MNOTE\0\0\0";

/// The only container framing version this build understands.
pub const CONTAINER_VERSION: u8 = 1;

/// Fixed header size: magic (8) + version (1) + meta_len (4) + db_len (8).
const HEADER_LEN: usize = 8 + 1 + 4 + 8;

/// A note's portable content, decoupled from any application type.
///
/// The vault crate is intentionally domain-free, so this struct mirrors
/// the four content fields a Memento note has *without* depending on
/// `memento-core`. The downstream crate maps between its `Note` and this
/// type. It deliberately excludes ids, folder placement, and secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedNote {
    /// Note title.
    pub title: String,
    /// Markdown body — the canonical content.
    pub body_markdown: String,
    /// Editor presentation hint, persisted verbatim (`"live"` / `"raw"`).
    pub view_mode: String,
    /// Creation timestamp, RFC 3339 string (informational).
    pub created_at: String,
    /// Last-modification timestamp, RFC 3339 string (informational).
    pub updated_at: String,
}

/// Schema applied to the single-note container database.
const NOTE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS exported_note (
        id            INTEGER PRIMARY KEY CHECK (id = 0),
        title         TEXT NOT NULL,
        body_markdown TEXT NOT NULL,
        view_mode     TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    );";

/// Export a single note to an encrypted `.memento-note` file at `path`.
///
/// Builds a fresh one-note [`Vault`] (Argon2id over `params` + a random
/// salt + raw-key SQLCipher) in a temporary directory, writes `note` into
/// it, then frames the encrypted DB and its public sidecar into the
/// single container file. The temporary encrypted DB is removed before
/// return. Any pre-existing file at `path` is overwritten.
///
/// # Errors
///
/// [`Error::Io`] on a filesystem failure, [`Error::Kdf`] on bad
/// `params`, [`Error::Db`] / [`Error::Json`] on lower-level failures.
pub fn export_note(
    path: impl AsRef<Path>,
    passphrase: &str,
    note: &ExportedNote,
    params: KdfParams,
) -> Result<()> {
    let work = TempDir::new()?;
    let db_path = work.path().join("note.memento");
    let meta_path = meta_path_for(&db_path);

    // Reuse the audited vault crypto path verbatim.
    let vault = Vault::create(&db_path, passphrase, params)?;
    vault.with_connection(|c| {
        c.execute_batch(NOTE_SCHEMA)?;
        c.execute(
            "INSERT OR REPLACE INTO exported_note \
             (id, title, body_markdown, view_mode, created_at, updated_at) \
             VALUES (0, ?1, ?2, ?3, ?4, ?5)",
            crate::rusqlite::params![
                note.title,
                note.body_markdown,
                note.view_mode,
                note.created_at,
                note.updated_at,
            ],
        )?;
        Ok(())
    })?;
    // Close cleanly so the WAL is flushed back into the main DB file
    // before we read its bytes; this also zeroizes the derived key.
    vault.lock();

    let meta_json = std::fs::read(&meta_path)?;
    let db_bytes = std::fs::read(&db_path)?;

    write_container(path.as_ref(), &meta_json, &db_bytes)?;
    // `work` (and the encrypted DB inside it) is removed on drop.
    Ok(())
}

/// Import a note from an encrypted `.memento-note` file at `path`.
///
/// Splits the container back into its SQLCipher DB + sidecar in a
/// temporary directory, opens it with the vault crypto path, reads the
/// single note, and returns it. The temporary DB is removed before
/// return.
///
/// # Errors
///
/// [`Error::WrongPassphrase`] if `passphrase` is incorrect **or** the
/// encrypted body has been tampered with (SQLCipher cannot distinguish
/// the two — both fail the keyed read); never panics. [`Error::MetaInvalid`]
/// if the framing is not a valid `.memento-note`; [`Error::Io`] /
/// [`Error::Db`] / [`Error::Json`] on lower-level failures.
pub fn import_note(path: impl AsRef<Path>, passphrase: &str) -> Result<ExportedNote> {
    let (meta_json, db_bytes) = read_container(path.as_ref())?;

    let work = TempDir::new()?;
    let db_path = work.path().join("note.memento");
    let meta_path = meta_path_for(&db_path);
    std::fs::write(&meta_path, &meta_json)?;
    std::fs::write(&db_path, &db_bytes)?;

    let vault = Vault::open(&db_path, passphrase)?;
    let note = vault.with_connection(|c| {
        c.query_row(
            "SELECT title, body_markdown, view_mode, created_at, updated_at \
             FROM exported_note WHERE id = 0",
            [],
            |r| {
                Ok(ExportedNote {
                    title: r.get(0)?,
                    body_markdown: r.get(1)?,
                    view_mode: r.get(2)?,
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            },
        )
    })?;
    vault.lock();
    Ok(note)
}

/// Serialize the framed container to `path` (write-temp-then-rename).
fn write_container(path: &Path, meta_json: &[u8], db_bytes: &[u8]) -> Result<()> {
    let meta_len = u32::try_from(meta_json.len())
        .map_err(|_| Error::MetaInvalid("sidecar too large to frame".into()))?;
    let db_len = db_bytes.len() as u64;

    let mut buf = Vec::with_capacity(HEADER_LEN + meta_json.len() + db_bytes.len());
    buf.extend_from_slice(NOTE_MAGIC);
    buf.push(CONTAINER_VERSION);
    buf.extend_from_slice(&meta_len.to_le_bytes());
    buf.extend_from_slice(&db_len.to_le_bytes());
    buf.extend_from_slice(meta_json);
    buf.extend_from_slice(db_bytes);

    let tmp = path.with_extension("memento-note.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&buf)?;
        f.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Parse the framed container at `path` into `(meta_json, db_bytes)`.
fn read_container(path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut f = std::fs::File::open(path)?;
    let mut header = [0u8; HEADER_LEN];
    f.read_exact(&mut header)
        .map_err(|_| Error::MetaInvalid("file too short to be a .memento-note".into()))?;

    if &header[0..8] != NOTE_MAGIC {
        return Err(Error::MetaInvalid("not a .memento-note file".into()));
    }
    let container_ver = header[8];
    if container_ver != CONTAINER_VERSION {
        return Err(Error::MetaInvalid(format!(
            "unsupported .memento-note container version {container_ver}"
        )));
    }
    let meta_len = u32::from_le_bytes([header[9], header[10], header[11], header[12]]) as usize;
    let db_len = u64::from_le_bytes([
        header[13], header[14], header[15], header[16], header[17], header[18], header[19],
        header[20],
    ]);
    let db_len = usize::try_from(db_len)
        .map_err(|_| Error::MetaInvalid("declared database length too large".into()))?;

    let mut meta_json = vec![0u8; meta_len];
    f.read_exact(&mut meta_json)
        .map_err(|_| Error::MetaInvalid("truncated .memento-note sidecar".into()))?;
    let mut db_bytes = vec![0u8; db_len];
    f.read_exact(&mut db_bytes)
        .map_err(|_| Error::MetaInvalid("truncated .memento-note database".into()))?;

    Ok((meta_json, db_bytes))
}

/// Minimal owned temp directory (no extra dependency in the library).
///
/// Created under [`std::env::temp_dir`] with a process-/nanos-unique
/// name; removed recursively on drop (best-effort — the only thing inside
/// is an already-encrypted SQLCipher DB).
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("memento-note-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self { path: dir })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExportedNote {
        ExportedNote {
            title: "AWS production keys".into(),
            body_markdown: "# Prod\n\nrotate quarterly\n".into(),
            view_mode: "live".into(),
            created_at: "2026-05-19T10:00:00Z".into(),
            updated_at: "2026-05-19T11:30:00Z".into(),
        }
    }

    fn p() -> KdfParams {
        // Mirror the deliberately-weak test params used elsewhere.
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn roundtrip_equals_original() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        let n = sample();
        export_note(&f, "correct horse", &n, p()).unwrap();
        let back = import_note(&f, "correct horse").unwrap();
        assert_eq!(back, n);
    }

    #[test]
    fn wrong_passphrase_is_wrongpassphrase_no_panic() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        export_note(&f, "right", &sample(), p()).unwrap();
        let err = import_note(&f, "wrong").unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase), "got {err:?}");
    }

    #[test]
    fn on_disk_bytes_are_not_plaintext() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        let n = sample();
        export_note(&f, "pw", &n, p()).unwrap();
        let bytes = std::fs::read(&f).unwrap();

        // Note content must not appear anywhere in the container.
        assert!(!contains(&bytes, n.title.as_bytes()));
        assert!(!contains(&bytes, b"rotate quarterly"));
        // The embedded DB must NOT be a plaintext SQLite file: the framed
        // SQLCipher payload starts after the header + sidecar, and a
        // plaintext SQLite file would begin "SQLite format 3\0".
        assert!(!contains(&bytes, b"SQLite format 3\0"));
        // The header itself is the documented magic (public framing).
        assert_eq!(&bytes[0..8], NOTE_MAGIC);
    }

    #[test]
    fn tampering_a_byte_fails_authentication() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        export_note(&f, "pw", &sample(), p()).unwrap();
        let mut bytes = std::fs::read(&f).unwrap();

        // Flip a byte deep inside the encrypted DB payload (well past the
        // header + sidecar) so SQLCipher's page HMAC must reject it.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let mid = bytes.len() - 64;
        bytes[mid] ^= 0xFF;
        let mut fh = std::fs::File::create(&f).unwrap();
        fh.write_all(&bytes).unwrap();
        fh.flush().unwrap();

        let err = import_note(&f, "pw").unwrap_err();
        assert!(
            matches!(err, Error::WrongPassphrase | Error::Db(_)),
            "tampered container must fail to decrypt, got {err:?}"
        );
    }

    #[test]
    fn empty_body_roundtrips() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        let mut n = sample();
        n.body_markdown = String::new();
        n.title = String::new();
        export_note(&f, "pw", &n, p()).unwrap();
        assert_eq!(import_note(&f, "pw").unwrap(), n);
    }

    #[test]
    fn large_body_roundtrips() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        let mut n = sample();
        n.body_markdown = "x".repeat(2_000_000);
        export_note(&f, "pw", &n, p()).unwrap();
        let back = import_note(&f, "pw").unwrap();
        assert_eq!(back.body_markdown.len(), 2_000_000);
        assert_eq!(back, n);
    }

    #[test]
    fn unicode_and_emoji_body_roundtrips() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        let mut n = sample();
        n.title = "日本語 🔐 Ñandú".into();
        n.body_markdown = "Crème brûlée — 漢字 — 😀🚀\nΔεδομένα\n".into();
        export_note(&f, "pw", &n, p()).unwrap();
        assert_eq!(import_note(&f, "pw").unwrap(), n);
    }

    #[test]
    fn not_a_container_is_metainvalid_no_panic() {
        let d = tmp();
        let f = d.path().join("garbage.memento-note");
        std::fs::write(&f, b"not a memento note at all").unwrap();
        assert!(matches!(
            import_note(&f, "pw").unwrap_err(),
            Error::MetaInvalid(_)
        ));
    }

    #[test]
    fn truncated_container_is_metainvalid_no_panic() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        export_note(&f, "pw", &sample(), p()).unwrap();
        let mut bytes = std::fs::read(&f).unwrap();
        bytes.truncate(bytes.len() / 2);
        std::fs::write(&f, &bytes).unwrap();
        assert!(matches!(
            import_note(&f, "pw").unwrap_err(),
            Error::MetaInvalid(_)
        ));
    }

    #[test]
    fn wrong_container_version_rejected() {
        let d = tmp();
        let f = d.path().join("n.memento-note");
        export_note(&f, "pw", &sample(), p()).unwrap();
        let mut bytes = std::fs::read(&f).unwrap();
        bytes[8] = 99; // bogus container version
        std::fs::write(&f, &bytes).unwrap();
        assert!(matches!(
            import_note(&f, "pw").unwrap_err(),
            Error::MetaInvalid(_)
        ));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
