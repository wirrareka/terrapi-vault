//! Device authentication for vault-sync — all app-layer (the transport is plain TLS,
//! terminated at deploy). Two mechanisms:
//!
//! - **Enrolment proof:** a new device proves it can derive the account's enrolment secret
//!   (client-side Argon2id over the vault passphrase). The server stores only SHA-256 of that
//!   secret and compares in constant time — it never learns the secret or the passphrase.
//! - **Per-request signature:** every `push`/`pull`/`status` carries a detached ed25519
//!   signature by the calling device over a canonical string binding method + path+query +
//!   vault id + timestamp + nonce + body hash. A registered device pubkey verifies it; a
//!   stale timestamp or a replayed nonce is rejected.

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Max accepted clock skew between a device and the server, in seconds. A request whose
/// timestamp is outside `[now - SKEW, now + SKEW]` is rejected (bounds replay windows).
pub const MAX_SKEW_SECS: i64 = 300;

/// Hex SHA-256 of `bytes` (used for the body hash in the canonical string).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The canonical string a device signs (and the server reconstructs). Versioned so the
/// scheme can evolve without ambiguity.
#[must_use]
pub fn canonical_string(
    method: &str,
    path_and_query: &str,
    vault_id: &str,
    ts: i64,
    nonce: &str,
    body_sha256_hex: &str,
) -> String {
    format!("v1\n{method}\n{path_and_query}\n{vault_id}\n{ts}\n{nonce}\n{body_sha256_hex}")
}

/// Decode a base64 ed25519 public key (32 bytes).
#[must_use]
pub fn parse_pubkey_b64(s: &str) -> Option<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

/// Decode a base64 ed25519 signature (64 bytes).
#[must_use]
pub fn parse_sig_b64(s: &str) -> Option<[u8; 64]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .ok()?;
    <[u8; 64]>::try_from(raw.as_slice()).ok()
}

/// Verify a detached ed25519 signature of `message` under `pubkey`.
#[must_use]
pub fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    vk.verify_strict(message, &Signature::from_bytes(sig))
        .is_ok()
}

/// Constant-time check that `proof` hashes to the stored enrolment verifier `stored_hash`.
/// The expensive Argon2 already ran on the client; the server's SHA-256 is just a verifier.
#[must_use]
pub fn verify_enroll_proof(proof: &[u8], stored_hash: &[u8]) -> bool {
    let got = Sha256::digest(proof);
    if stored_hash.len() != got.len() {
        return false;
    }
    // Constant-time compare.
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(stored_hash) {
        diff |= a ^ b;
    }
    diff == 0
}

/// The signature headers a client attaches to a request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub device_id: String,
    pub ts: i64,
    pub nonce: String,
    pub sig: [u8; 64],
}

/// In-memory replay guard: remembers `(device_id, nonce)` it has seen and rejects repeats.
/// Entries older than the skew window are pruned (after the window a stale `ts` is rejected
/// anyway, so the nonce can be forgotten). Adequate for a single personal server.
#[derive(Default)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<String, i64>>,
}

impl ReplayGuard {
    /// Record `(device_id, nonce)` seen at `now`; return `false` if it was already seen
    /// within the window (a replay). Prunes expired entries opportunistically.
    pub fn check_and_record(&self, device_id: &str, nonce: &str, now: i64) -> bool {
        let key = format!("{device_id}\n{nonce}");
        let mut seen = self.seen.lock().expect("replay lock");
        seen.retain(|_, ts| now - *ts <= MAX_SKEW_SECS);
        if seen.contains_key(&key) {
            return false;
        }
        seen.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, pk) = keypair();
        let msg = canonical_string(
            "POST",
            "/v1/sync/v1/push",
            "v1",
            1000,
            "n1",
            &sha256_hex(b"{}"),
        );
        let sig = sk.sign(msg.as_bytes()).to_bytes();
        assert!(verify_ed25519(&pk, msg.as_bytes(), &sig));
        // A tampered message fails.
        let bad = canonical_string(
            "POST",
            "/v1/sync/v1/push",
            "v1",
            1001,
            "n1",
            &sha256_hex(b"{}"),
        );
        assert!(!verify_ed25519(&pk, bad.as_bytes(), &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = keypair();
        let (_, other_pk) = keypair();
        let msg = "v1\nGET\n/x\nv1\n1\nn\nh";
        let sig = sk.sign(msg.as_bytes()).to_bytes();
        assert!(!verify_ed25519(&other_pk, msg.as_bytes(), &sig));
    }

    #[test]
    fn enroll_proof_matches_only_for_correct_secret() {
        let secret = b"argon2-derived-enrolment-secret";
        let stored = Sha256::digest(secret).to_vec();
        assert!(verify_enroll_proof(secret, &stored));
        assert!(!verify_enroll_proof(b"wrong", &stored));
    }

    #[test]
    fn replay_guard_rejects_repeats_inside_window() {
        let g = ReplayGuard::default();
        assert!(g.check_and_record("dev-a", "n1", 1000));
        assert!(!g.check_and_record("dev-a", "n1", 1001)); // replay
        assert!(g.check_and_record("dev-a", "n2", 1001)); // new nonce ok
                                                          // After the window the old nonce is pruned and may be reused (ts itself would be
                                                          // rejected separately by the handler's skew check).
        assert!(g.check_and_record("dev-a", "n1", 1000 + MAX_SKEW_SECS + 1));
    }
}
