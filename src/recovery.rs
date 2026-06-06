//! Recovery codes: the high-entropy secret printed on a vault's recovery kit.
//!
//! A [`RecoveryCode`] is 160 bits of CSPRNG entropy. It is independent of the
//! passphrase, derives its own key-slot (Argon2id over its own salt), and that
//! slot wraps the *same* DEK as the passphrase slot — so a recovery code can
//! unlock the vault even when the passphrase is forgotten, and keeps working
//! across passphrase changes (see [`crate::keyslot`]).
//!
//! ## Display format (Crockford Base32, grouped, checksummed)
//!
//! 160 bits encode to exactly 32 Crockford-Base32 characters, shown as eight
//! 4-character groups, plus a final 4-character **checksum** group:
//!
//! ```text
//! XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-CCCC
//! ```
//!
//! Crockford Base32 omits I, L, O, U; on input we fold `O→0`, `I/L→1` and are
//! case-insensitive, so a hand-copied code survives common transcription slips.
//! The checksum (CRC-16 of the payload) is a **typo guard only** — it lets the
//! UI reject a mistyped code before spending ~1 s on Argon2id. The real
//! integrity check is the AEAD tag on the key slot: a wrong code that happens
//! to pass the checksum simply fails to unwrap the DEK.

use crate::error::{Error, Result};
use rand::RngCore as _;
use zeroize::{Zeroize, Zeroizing};

/// Number of random bytes in a recovery code (160 bits).
pub const RECOVERY_ENTROPY_BYTES: usize = 20;

/// Crockford Base32 alphabet (no I, L, O, U).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A vault recovery code: 160 bits of secret entropy.
///
/// Zeroized on drop and deliberately **not** `Debug`/`Display` (printing it
/// would leak the secret). Render it for the user with [`RecoveryCode::format`].
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RecoveryCode([u8; RECOVERY_ENTROPY_BYTES]);

impl RecoveryCode {
    /// Generate a fresh random recovery code from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut buf = [0u8; RECOVERY_ENTROPY_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let code = Self(buf);
        buf.zeroize();
        code
    }

    /// The raw secret bytes, for feeding to the slot KDF
    /// ([`crate::derive_key_from_bytes`]). Sensitive — never log or persist.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Render the code in the grouped, checksummed display format.
    ///
    /// Returned in a [`Zeroizing`] wrapper so the formatted secret is scrubbed
    /// from the heap when dropped.
    #[must_use]
    pub fn format(&self) -> Zeroizing<String> {
        let payload = base32_encode(&self.0); // 32 chars
        let check = base32_encode(&crc16(&self.0).to_be_bytes()); // 4 chars
        let mut out = String::with_capacity(44);
        for (i, ch) in payload.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out.push('-');
        out.push_str(&check);
        Zeroizing::new(out)
    }

    /// Parse a user-entered recovery code (any spacing/case; folds Crockford
    /// look-alikes) and verify its checksum.
    ///
    /// # Errors
    ///
    /// [`Error::RecoveryCodeInvalid`] if the code has the wrong length, an
    /// illegal character, or a failing checksum.
    pub fn parse(input: &str) -> Result<Self> {
        // Normalize: drop separators, uppercase, fold ambiguous glyphs.
        let mut norm = String::with_capacity(40);
        for ch in input.chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            let c = ch.to_ascii_uppercase();
            norm.push(match c {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            });
        }
        // 32 payload chars + 4 checksum chars.
        if norm.len() != 36 {
            return Err(Error::RecoveryCodeInvalid(format!(
                "expected 36 characters, got {}",
                norm.len()
            )));
        }
        let (payload_s, check_s) = norm.split_at(32);
        let payload = base32_decode(payload_s)
            .ok_or_else(|| Error::RecoveryCodeInvalid("illegal character".into()))?;
        let check = base32_decode(check_s)
            .ok_or_else(|| Error::RecoveryCodeInvalid("illegal character".into()))?;
        if payload.len() != RECOVERY_ENTROPY_BYTES || check.len() < 2 {
            return Err(Error::RecoveryCodeInvalid("wrong decoded length".into()));
        }
        let got = u16::from_be_bytes([check[0], check[1]]);
        if got != crc16(&payload) {
            return Err(Error::RecoveryCodeInvalid("checksum mismatch".into()));
        }
        let mut bytes = [0u8; RECOVERY_ENTROPY_BYTES];
        bytes.copy_from_slice(&payload);
        let code = Self(bytes);
        bytes.zeroize();
        Ok(code)
    }
}

/// Crockford Base32 encode (no padding; emits `ceil(8*len/5)` chars).
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Crockford Base32 decode. Input must already be normalized (uppercase,
/// glyphs folded, separators stripped). `None` on an illegal character.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for ch in s.bytes() {
        let v = u32::try_from(ALPHABET.iter().position(|&a| a == ch)?).ok()?;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF). A small typo guard; not a
/// security primitive (the AEAD tag is).
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_then_parse_roundtrips() {
        let code = RecoveryCode::generate();
        let s = code.format();
        let parsed = RecoveryCode::parse(&s).unwrap();
        assert_eq!(parsed.as_bytes(), code.as_bytes());
    }

    #[test]
    fn format_shape_is_grouped() {
        let code = RecoveryCode([0u8; RECOVERY_ENTROPY_BYTES]);
        let s = code.format();
        // 8 payload groups + 1 checksum group, all length 4, dash-separated.
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 9);
        assert!(groups.iter().all(|g| g.len() == 4), "{}", s.as_str());
    }

    #[test]
    fn parse_is_case_and_separator_insensitive() {
        let code = RecoveryCode::generate();
        let canonical = code.format().to_string();
        let mangled = canonical.to_lowercase().replace('-', " ");
        let parsed = RecoveryCode::parse(&mangled).unwrap();
        assert_eq!(parsed.as_bytes(), code.as_bytes());
    }

    #[test]
    fn parse_folds_crockford_lookalikes() {
        // O/o → 0, I/i/L/l → 1: a code transcribed with look-alikes still parses.
        let code = RecoveryCode::generate();
        let canonical = code.format().to_string();
        let folded = canonical
            .replace('0', "O")
            .replace('1', "I")
            .to_lowercase();
        // Re-folding must recover the same bytes (the canonical form has no
        // O/I/L, so injecting them and folding back is lossless).
        let parsed = RecoveryCode::parse(&folded).unwrap();
        assert_eq!(parsed.as_bytes(), code.as_bytes());
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        // Fixed all-zero payload → deterministic. Flipping the first *payload*
        // char changes the payload (and thus its CRC), so the stored checksum
        // no longer matches: exactly the mistyped-code case the checksum guards.
        let code = RecoveryCode([0u8; RECOVERY_ENTROPY_BYTES]);
        let mut chars: Vec<char> = code.format().chars().collect();
        assert_eq!(chars[0], '0', "all-zero payload encodes to leading '0'");
        chars[0] = '1'; // changes the high 5 bits of byte 0
        let mangled: String = chars.into_iter().collect();
        assert!(matches!(
            RecoveryCode::parse(&mangled),
            Err(Error::RecoveryCodeInvalid(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(matches!(
            RecoveryCode::parse("ABCD-EFGH"),
            Err(Error::RecoveryCodeInvalid(_))
        ));
    }

    #[test]
    fn parse_rejects_illegal_character() {
        // 'U' is not in the Crockford alphabet and is not a folded glyph.
        let bad = "UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU";
        assert!(matches!(
            RecoveryCode::parse(bad),
            Err(Error::RecoveryCodeInvalid(_))
        ));
    }

    #[test]
    fn generated_codes_differ() {
        let a = RecoveryCode::generate();
        let b = RecoveryCode::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn base32_roundtrip_exact_160_bits() {
        let data = [0xABu8; RECOVERY_ENTROPY_BYTES];
        let enc = base32_encode(&data);
        assert_eq!(enc.len(), 32, "160 bits → 32 base32 chars");
        assert_eq!(base32_decode(&enc).unwrap(), data);
    }
}
