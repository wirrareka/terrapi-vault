//! # terrapi-vault
//!
//! Terrapi shared encrypted-at-rest storage. Adopted by **memento**
//! (notes app) and **probe** (API client); vault files are
//! binary-compatible across apps.
//!
//! `terrapi-vault` wraps a single [SQLCipher](https://www.zetetic.net/sqlcipher/)
//! database behind a small, safe lifecycle API. The database key is derived
//! from a user passphrase with **Argon2id** (RFC 9106) over a random
//! per-vault salt; the derived key never touches disk and lives in a
//! [`secrecy::SecretBox`] that is zeroized on lock/drop. Only the salt and
//! KDF parameters are persisted, in a plaintext JSON sidecar next to the
//! database (`<vault>.meta.json`) — losing it makes the vault
//! unrecoverable but it contains no secret material.
//!
//! This crate is fully self-contained: it has **no** dependency on any UI,
//! GPUI, or application types. The on-disk format is documented in
//! `spec/vault-format.md` precisely enough for an independent compatible
//! implementation.
//!
//! ## Quick start
//!
//! ```no_run
//! use terrapi_vesta::{Vesta, KdfParams};
//!
//! # fn main() -> terrapi_vesta::Result<()> {
//! // First run: create the vault.
//! let vault = Vesta::create("notes.terrapi", "correct horse battery staple",
//!                           KdfParams::default())?;
//! vault.with_connection(|conn| {
//!     conn.execute_batch("CREATE TABLE note(id INTEGER PRIMARY KEY, body TEXT)")
//! })?;
//! vault.lock();
//!
//! // Later run: unlock.
//! let vault = Vesta::open("notes.terrapi", "correct horse battery staple")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Running migrations downstream
//!
//! Downstream crates (e.g. `memento-core`, `probe-core`) run their own
//! migrations through [`Vesta::with_connection`] /
//! [`Vesta::with_connection_mut`]; the encrypted [`rusqlite::Connection`]
//! is never exposed unguarded.
//!
//! ## Licensing
//!
//! Dual-licensed under **MIT OR Apache-2.0**. The on-disk format spec is
//! CC-BY-4.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod hex;
mod kdf;
mod keyslot;
mod meta;
/// The `.memento-note` single-note export format. Behind the default-on `note-export` feature so
/// a neutral consumer (e.g. `probe`) can drop it with `default-features = false`; memento, which
/// uses it, gets it by default.
#[cfg(feature = "note-export")]
mod note_export;
mod recovery;
mod vesta;

pub use error::{Error, Result};
pub use kdf::{
    derive_key, derive_key_from_bytes, random_key, random_salt, DerivedKey, KdfParams, KEY_LEN,
    SALT_LEN,
};
pub use keyslot::WrappedKey;
pub use meta::{
    meta_path_for, KeySlot, KeySlots, MetaV2, StoredMeta, VestaMeta, CURRENT_FORMAT_VERSION,
    FORMAT_VERSION, META_SUFFIX,
};
#[cfg(feature = "note-export")]
pub use note_export::{export_note, import_note, ExportedNote, CONTAINER_VERSION, NOTE_MAGIC};
pub use recovery::{RecoveryCode, RECOVERY_ENTROPY_BYTES};
pub use vesta::{RotationInputs, RotationPlan, Vesta};

/// Re-export of the `rusqlite` version this crate links, so downstream
/// crates can depend on the exact same SQLCipher/rusqlite without a
/// version-mismatch hazard when passing the connection through
/// [`Vesta::with_connection`].
pub use rusqlite;
