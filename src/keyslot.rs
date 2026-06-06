//! Credential **key slots** for the v2 vault format.
//!
//! In v2 the SQLCipher key is a random 32-byte **data-encryption key (DEK)**
//! that never changes for the life of the vault. Each credential (the
//! passphrase, and optionally a recovery code) derives a 32-byte *slot key*
//! via Argon2id over its own salt, and that slot key wraps the *same* DEK
//! with an AEAD. Unlocking = derive slot key → AEAD-open the slot → recover
//! the DEK → `PRAGMA key = DEK`.
//!
//! This is the standard keyslot / envelope design (cf. LUKS, age, 1Password):
//! changing one credential re-wraps only its slot and leaves the DEK — and
//! therefore every *other* slot — untouched. That is what lets a recovery
//! code keep working after a passphrase change.
//!
//! ## AEAD
//!
//! XChaCha20-Poly1305 (the cipher the sync layer already vendors). A fresh
//! random 24-byte nonce per seal. The **AAD binds the slot name**
//! (`terrapi-vault/dek-slot/v2/<slot>`) so a blob lifted from one slot cannot
//! be replayed into another — a wrong-slot ciphertext fails authentication.

use crate::error::{Error, Result};
use crate::hex;
use crate::kdf::DerivedKey;
use crate::KEY_LEN;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore as _;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

/// XChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 24;

/// Wrap-algorithm identifier recorded in each slot. Only value this build writes/accepts.
const WRAP_ALG: &str = "xchacha20poly1305";

/// AEAD-wrapped copy of the vault DEK, as stored inside a [`KeySlot`].
///
/// Holds **no** secret usable without the matching slot key: it is the DEK
/// sealed under `Argon2id(credential, slot.salt)`. Serialized into the meta
/// sidecar; `deny_unknown_fields` keeps it a strict, versioned interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    /// AEAD algorithm. Always `"xchacha20poly1305"` in v2.
    pub alg: String,
    /// Lowercase hex of the 24-byte XChaCha20-Poly1305 nonce.
    pub nonce_hex: String,
    /// Lowercase hex of the AEAD ciphertext (DEK + 16-byte Poly1305 tag).
    pub ct_hex: String,
}

/// Additional authenticated data for a slot: binds the wrap to its slot name
/// so a recovery-slot blob can't be swapped into the password slot (or vice
/// versa) and still authenticate.
fn slot_aad(slot_name: &str) -> Vec<u8> {
    let mut aad = b"terrapi-vault/dek-slot/v2/".to_vec();
    aad.extend_from_slice(slot_name.as_bytes());
    aad
}

/// Seal `dek` under `slot_key` for the slot named `slot_name`.
///
/// Infallible for the fixed-size inputs this crate uses (32-byte key, 32-byte
/// plaintext): XChaCha20-Poly1305 has no failure mode for valid lengths.
#[must_use]
pub(crate) fn seal(slot_key: &[u8; KEY_LEN], dek: &[u8; KEY_LEN], slot_name: &str) -> WrappedKey {
    let cipher = XChaCha20Poly1305::new_from_slice(slot_key)
        .expect("slot key is statically KEY_LEN (32) bytes");
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad: &slot_aad(slot_name),
            },
        )
        .expect("XChaCha20-Poly1305 seal of a 32-byte DEK is infallible");
    WrappedKey {
        alg: WRAP_ALG.to_string(),
        nonce_hex: hex::encode(&nonce),
        ct_hex: hex::encode(&ct),
    }
}

/// Open a [`WrappedKey`] with `slot_key`, recovering the DEK.
///
/// Returns:
/// - `Ok(Some(dek))` — the slot key unwrapped the DEK (correct credential);
/// - `Ok(None)` — AEAD authentication failed (a **wrong** credential): the
///   caller maps this to [`Error::WrongPassphrase`] / [`Error::WrongRecoveryCode`];
/// - `Err(Error::KeySlotCorrupt)` — the slot itself is malformed (unknown
///   algorithm, bad hex, wrong nonce/DEK length), independent of the key.
///
/// # Errors
///
/// [`Error::KeySlotCorrupt`] as described above.
pub(crate) fn open(
    slot_key: &[u8; KEY_LEN],
    wrapped: &WrappedKey,
    slot_name: &str,
) -> Result<Option<SecretBox<DerivedKey>>> {
    if wrapped.alg != WRAP_ALG {
        return Err(Error::KeySlotCorrupt(format!(
            "unknown wrap algorithm {:?}",
            wrapped.alg
        )));
    }
    let nonce = hex::decode(&wrapped.nonce_hex)
        .ok_or_else(|| Error::KeySlotCorrupt("nonce_hex is not valid hex".into()))?;
    if nonce.len() != NONCE_LEN {
        return Err(Error::KeySlotCorrupt(format!(
            "nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        )));
    }
    let ct = hex::decode(&wrapped.ct_hex)
        .ok_or_else(|| Error::KeySlotCorrupt("ct_hex is not valid hex".into()))?;
    let cipher = XChaCha20Poly1305::new_from_slice(slot_key)
        .map_err(|_| Error::KeySlotCorrupt("slot key length".into()))?;

    match cipher.decrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: &ct,
            aad: &slot_aad(slot_name),
        },
    ) {
        Ok(mut pt) => {
            if pt.len() != KEY_LEN {
                pt.zeroize();
                return Err(Error::KeySlotCorrupt(format!(
                    "unwrapped DEK must be {KEY_LEN} bytes, got {}",
                    pt.len()
                )));
            }
            let mut dek = [0u8; KEY_LEN];
            dek.copy_from_slice(&pt);
            pt.zeroize();
            let boxed = SecretBox::new(Box::new(DerivedKey::from_bytes(dek)));
            dek.zeroize();
            Ok(Some(boxed))
        }
        // Poly1305 tag mismatch → wrong slot key (wrong credential). Not a
        // corruption: the caller decides which "wrong credential" error to raise.
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    fn dek() -> [u8; KEY_LEN] {
        let mut d = [0u8; KEY_LEN];
        for (i, b) in d.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0).wrapping_mul(7).wrapping_add(3);
        }
        d
    }

    #[test]
    fn seal_open_roundtrip() {
        let sk = [9u8; KEY_LEN];
        let d = dek();
        let w = seal(&sk, &d, "password");
        let got = open(&sk, &w, "password").unwrap().unwrap();
        assert_eq!(got.expose_secret().expose_bytes(), &d);
    }

    #[test]
    fn wrong_slot_key_fails_auth_not_corrupt() {
        let w = seal(&[1u8; KEY_LEN], &dek(), "password");
        // A different slot key is a wrong *credential* → Ok(None), not an error.
        assert!(open(&[2u8; KEY_LEN], &w, "password").unwrap().is_none());
    }

    #[test]
    fn wrong_slot_name_fails_auth() {
        // AAD binds the slot name: a password-slot blob must not open as recovery.
        let sk = [5u8; KEY_LEN];
        let w = seal(&sk, &dek(), "password");
        assert!(open(&sk, &w, "recovery").unwrap().is_none());
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let sk = [3u8; KEY_LEN];
        let mut w = seal(&sk, &dek(), "password");
        // Flip a byte in the ciphertext hex → tag mismatch.
        let mut bytes = hex::decode(&w.ct_hex).unwrap();
        bytes[0] ^= 0x01;
        w.ct_hex = hex::encode(&bytes);
        assert!(open(&sk, &w, "password").unwrap().is_none());
    }

    #[test]
    fn malformed_slot_is_corrupt_error() {
        let sk = [3u8; KEY_LEN];
        let mut w = seal(&sk, &dek(), "password");
        w.alg = "aes-gcm".into();
        assert!(matches!(
            open(&sk, &w, "password"),
            Err(Error::KeySlotCorrupt(_))
        ));

        let mut w2 = seal(&sk, &dek(), "password");
        w2.nonce_hex = "xx".into();
        assert!(matches!(
            open(&sk, &w2, "password"),
            Err(Error::KeySlotCorrupt(_))
        ));
    }

    #[test]
    fn fresh_nonce_per_seal() {
        let sk = [7u8; KEY_LEN];
        let a = seal(&sk, &dek(), "password");
        let b = seal(&sk, &dek(), "password");
        assert_ne!(a.nonce_hex, b.nonce_hex, "nonce must be random per seal");
        assert_ne!(a.ct_hex, b.ct_hex);
    }
}
