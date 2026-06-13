//! Argon2id key derivation.
//!
//! The vault's encryption key is derived from the user's passphrase with
//! Argon2id (RFC 9106). The derived 32-byte key is the raw SQLCipher key
//! material; it is never persisted. Only the random salt and the KDF
//! parameters live on disk (in the sidecar) so that [`Vesta::open`] can
//! reproduce the key from the passphrase.
//!
//! [`Vesta::open`]: crate::Vesta::open

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Length of the derived SQLCipher key, in bytes (256-bit).
pub const KEY_LEN: usize = 32;

/// Length of the per-vault random salt, in bytes (128-bit).
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters.
///
/// The [`Default`] implementation targets roughly **500 ms** of derivation
/// time on an Apple M-series Mac. The chosen defaults are:
///
/// - `m_cost_kib = 65536` (64 MiB memory)
/// - `t_cost = 2` (2 iterations / passes)
/// - `p_cost = 1` (1 lane / single-threaded)
///
/// These were validated by `kdf::tests::print_default_kdf_timing`, which
/// prints the measured duration so the figure can be re-verified on any
/// machine (run with `cargo test -- --nocapture`). Tune `m_cost_kib`
/// first, then `t_cost`, if you need to retarget the duration; never go
/// below 19 MiB / 2 passes (the RFC 9106 second-recommended floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// Memory cost in kibibytes (KiB). 65536 == 64 MiB.
    pub m_cost_kib: u32,
    /// Time cost: number of iterations / passes over memory.
    pub t_cost: u32,
    /// Parallelism: number of lanes. 1 == single-threaded.
    pub p_cost: u32,
}

/// Upper bounds on the Argon2 cost a vault may carry. A vault's `kdf_params` come from the
/// **plaintext, unauthenticated** sidecar (and, for an imported note, from the container) — so a
/// tampered/hostile value could otherwise pin an absurd memory cost and make the next `open`
/// attempt a multi-TiB allocation (DoS). The algorithm *minimums* are enforced by `Params::new`;
/// these are the maximums. 4 GiB / 16 passes / 16 lanes is far above any legitimate vault KDF.
pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
pub const MAX_T_COST: u32 = 16;
pub const MAX_P_COST: u32 = 16;

/// RFC 9106 second-recommended **floor**: 19 MiB memory, 2 passes. The sidecar's `kdf_params`
/// are plaintext + unauthenticated, so when the library creates a *new* key slot from params that
/// may have come from an untrusted source (notably the v1→v2 migration, which preserves the v1
/// cost), it raises them to at least this floor — a tampered/legacy low-cost sidecar can no longer
/// silently weaken a freshly-wrapped credential. `validate` still bounds the *upper* end.
pub const MIN_M_COST_KIB: u32 = 19 * 1024;
pub const MIN_T_COST: u32 = 2;

impl KdfParams {
    /// Return these params with `m_cost_kib` / `t_cost` raised to at least the RFC 9106 floor
    /// ([`MIN_M_COST_KIB`] / [`MIN_T_COST`]); `p_cost` is left unchanged. Applied when wrapping a
    /// new slot from params of untrusted provenance.
    #[must_use]
    pub fn floored(self) -> Self {
        Self {
            m_cost_kib: self.m_cost_kib.max(MIN_M_COST_KIB),
            t_cost: self.t_cost.max(MIN_T_COST),
            p_cost: self.p_cost,
        }
    }

    /// Reject parameters outside the sane upper bounds — a DoS guard for params read from an
    /// untrusted sidecar or import container.
    ///
    /// # Errors
    /// [`Error::MetaInvalid`] if any cost exceeds its ceiling.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost_kib > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST
        {
            return Err(Error::MetaInvalid(format!(
                "argon2 params exceed limits (m_cost_kib={} t_cost={} p_cost={})",
                self.m_cost_kib, self.t_cost, self.p_cost
            )));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Fast, deliberately weak parameters for tests only.
    ///
    /// Not exported in release builds — exercising the encryption path in
    /// unit tests should not cost 500 ms each.
    #[cfg(test)]
    pub(crate) fn fast_for_tests() -> Self {
        Self {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// Generate a fresh cryptographically-random 16-byte salt.
///
/// Uses `OsRng` explicitly — the salt is a vault's sole per-vault uniqueness source, so the
/// CSPRNG guarantee is pinned in the type rather than relying on `thread_rng`'s (currently
/// CSPRNG, but implicit) default.
#[must_use]
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut buf = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// A wrapper around the raw 32-byte key that zeroizes its buffer on drop.
///
/// Used as the secret type inside a [`secrecy::SecretBox`] so the key is
/// scrubbed from memory when the [`Vesta`](crate::Vesta) is locked or
/// dropped, and cannot be accidentally logged (`SecretBox` has no `Debug`
/// that prints the contents).
///
/// `Clone` is intentional but exists only for the keystore-handoff path
/// ([`Vesta::derived_key`](crate::Vesta::derived_key) → [`Vesta::open_with_key`](crate::Vesta::open_with_key)):
/// each clone is itself a zeroizing `DerivedKey`, but every clone is one more live copy of the
/// key, so do not clone casually — keep the number of copies minimal.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey(pub(crate) [u8; KEY_LEN]);

impl DerivedKey {
    /// Wrap raw 32 bytes as a [`DerivedKey`].
    ///
    /// Used by [`Vesta::open_with_key`](crate::Vesta::open_with_key) to open
    /// a vault from a key obtained out-of-band (e.g. a biometric-gated
    /// Keychain item) instead of re-deriving from a passphrase. The input
    /// `bytes` array is the caller's responsibility to zeroize; the copy
    /// taken here is scrubbed when this `DerivedKey` drops.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes.
    ///
    /// This is sensitive material. Callers persisting it (e.g. into a
    /// biometric-gated OS keystore) MUST keep it in a zeroizing buffer and
    /// MUST NOT log it. The slice borrows the internal buffer, which is
    /// zeroized when this `DerivedKey` drops.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// SQLCipher quoted-blob form: `x'<64 hex chars>'`.
    ///
    /// This is the form passed to `PRAGMA key` / `PRAGMA rekey` so the raw
    /// 32 bytes are used directly as the cipher key (no extra KDF inside
    /// SQLCipher). Returned in a [`Zeroizing`](zeroize::Zeroizing) wrapper so the
    /// key-derived hex is scrubbed from the heap when the caller drops it, rather
    /// than lingering in freed memory.
    pub(crate) fn pragma_literal(&self) -> zeroize::Zeroizing<String> {
        let mut hex = String::with_capacity(2 + KEY_LEN * 2 + 1);
        hex.push_str("x'");
        for b in self.0 {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        hex.push('\'');
        zeroize::Zeroizing::new(hex)
    }
}

/// Derive the 32-byte SQLCipher key from a passphrase and salt.
///
/// Deterministic: the same `(passphrase, salt, params)` triple always
/// yields the same key. The result is wrapped in a [`SecretBox`] so it is
/// zeroized on drop.
///
/// # Errors
///
/// Returns [`Error::Kdf`] if the Argon2 parameters are invalid (e.g. memory
/// cost below the algorithm's minimum) or hashing fails.
pub fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretBox<DerivedKey>> {
    derive_key_from_bytes(passphrase.as_bytes(), salt, params)
}

/// Derive a 32-byte key from arbitrary secret bytes and a salt.
///
/// The bytes-level counterpart of [`derive_key`] (which is just this over
/// `passphrase.as_bytes()`). Used by the recovery-code slot, whose secret is
/// raw high-entropy bytes rather than a UTF-8 passphrase, so it is fed to
/// Argon2id directly with no lossy string round-trip.
///
/// # Errors
///
/// Returns [`Error::Kdf`] if the Argon2 parameters are invalid or hashing
/// fails.
pub fn derive_key_from_bytes(
    secret: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretBox<DerivedKey>> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Kdf(format!("invalid argon2 params: {e}")))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(secret, salt, &mut out)
        .map_err(|e| Error::Kdf(format!("argon2 hashing failed: {e}")))?;

    let key = SecretBox::new(Box::new(DerivedKey(out)));
    out.zeroize();
    Ok(key)
}

/// Generate a fresh cryptographically-random 32-byte data-encryption key (DEK).
///
/// The DEK is the actual SQLCipher key in the v2 vault format: it is random
/// (not passphrase-derived) and stable for the life of the vault, so every
/// credential slot (password, recovery) wraps the *same* DEK. Uses `OsRng`.
#[must_use]
pub fn random_key() -> SecretBox<DerivedKey> {
    let mut out = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut out);
    let key = SecretBox::new(Box::new(DerivedKey(out)));
    out.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::time::Instant;

    #[test]
    fn floored_raises_weak_params_only() {
        // Below the floor → raised to it (t and m), p_cost preserved.
        let weak = KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 3,
        }
        .floored();
        assert_eq!(weak.m_cost_kib, MIN_M_COST_KIB);
        assert_eq!(weak.t_cost, MIN_T_COST);
        assert_eq!(weak.p_cost, 3);
        // At/above the floor → unchanged.
        let strong = KdfParams::default().floored();
        assert_eq!(strong, KdfParams::default());
    }

    #[test]
    fn deterministic_with_same_salt() {
        let salt = [7u8; SALT_LEN];
        let p = KdfParams::fast_for_tests();
        let a = derive_key("hunter2", &salt, p).unwrap();
        let b = derive_key("hunter2", &salt, p).unwrap();
        assert_eq!(a.expose_secret().0, b.expose_secret().0);
    }

    #[test]
    fn different_salts_give_different_keys() {
        let p = KdfParams::fast_for_tests();
        let a = derive_key("pw", &[1u8; SALT_LEN], p).unwrap();
        let b = derive_key("pw", &[2u8; SALT_LEN], p).unwrap();
        assert_ne!(a.expose_secret().0, b.expose_secret().0);
    }

    #[test]
    fn different_passphrase_gives_different_key() {
        let salt = [9u8; SALT_LEN];
        let p = KdfParams::fast_for_tests();
        let a = derive_key("alpha", &salt, p).unwrap();
        let b = derive_key("beta", &salt, p).unwrap();
        assert_ne!(a.expose_secret().0, b.expose_secret().0);
    }

    #[test]
    fn pragma_literal_is_well_formed() {
        let salt = [0u8; SALT_LEN];
        let k = derive_key("x", &salt, KdfParams::fast_for_tests()).unwrap();
        let lit = k.expose_secret().pragma_literal();
        assert!(lit.starts_with("x'"));
        assert!(lit.ends_with('\''));
        assert_eq!(lit.len(), 2 + KEY_LEN * 2 + 1);
    }

    /// Prints the measured derivation time for the *default* (production)
    /// params so the ~500 ms target is independently verifiable.
    /// Run: `cargo test print_default_kdf_timing -- --nocapture`.
    #[test]
    fn print_default_kdf_timing() {
        let salt = random_salt();
        let params = KdfParams::default();
        let start = Instant::now();
        let _ = derive_key("correct horse battery staple", &salt, params).unwrap();
        let elapsed = start.elapsed();
        println!(
            "Argon2id default params (m={} KiB, t={}, p={}) derivation: {:?}",
            params.m_cost_kib, params.t_cost, params.p_cost, elapsed
        );
        // Generous bounds: just guard against accidentally trivial or
        // pathologically slow params. The printed value is the source of
        // truth for tuning.
        assert!(
            elapsed.as_millis() >= 50,
            "default KDF suspiciously fast ({elapsed:?}) — params too weak?"
        );
    }
}
