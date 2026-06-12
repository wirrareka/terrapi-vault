//! SSH signed-certificate CA (Phase 2).
//!
//! An ed25519 SSH CA whose private key lives in the broker's at-rest encrypted store
//! (`terrapi_vesta::Vault`, SQLCipher) and **never leaves the broker**. On first use the
//! CA key is generated and persisted; thereafter it is loaded. The CA signs short-TTL
//! OpenSSH certificates for daemon/operator keys (`POST /v1/{group}/ssh/sign`); its
//! public key is the trust anchor served by `GET /v1/{group}/ssh/ca`.
//!
//! Host-cert CA is group-scoped (one CA per residency group); per-tenant scoping applies
//! only to leased service-admin creds, not here (coordination/conventions/secrets-broker.md).

use rand::rngs::OsRng;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use terrapi_vesta::{rusqlite, Vault};

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("ssh key error: {0}")]
    Ssh(String),
    #[error("at-rest store error: {0}")]
    Store(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
}

/// A loaded SSH certificate authority for one residency group.
pub struct SshCa {
    key: PrivateKey,
}

/// A freshly signed certificate plus the metadata echoed in the API response.
#[derive(Debug)]
pub struct Signed {
    pub openssh: String,
    pub serial: u64,
    /// Unix seconds; the cert is invalid at/after this.
    pub valid_before: u64,
}

impl SshCa {
    /// Generate a fresh ed25519 CA key (not persisted). Used on first run and in tests.
    ///
    /// # Errors
    /// `Ssh` if key generation fails.
    pub fn generate() -> Result<Self, CaError> {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| CaError::Ssh(e.to_string()))?;
        Ok(Self { key })
    }

    /// Load the CA key for `group` from the store, generating + persisting one on first
    /// use. The private key is stored in OpenSSH PEM form inside the encrypted DB.
    ///
    /// # Errors
    /// `Store` on a DB error; `Ssh` if a stored key cannot be parsed.
    pub fn load_or_generate(vault: &Vault, group: &str) -> Result<Self, CaError> {
        vault
            .with_connection(|c| {
                c.execute_batch(
                    "CREATE TABLE IF NOT EXISTS ssh_ca_keys (
                        group_name TEXT PRIMARY KEY,
                        private_openssh TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );",
                )
            })
            .map_err(|e| CaError::Store(e.to_string()))?;

        let existing: Option<String> = vault
            .with_connection(|c| {
                c.query_row(
                    "SELECT private_openssh FROM ssh_ca_keys WHERE group_name = ?1",
                    [group],
                    |r| r.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(|e| CaError::Store(e.to_string()))?;

        if let Some(pem) = existing {
            let key = PrivateKey::from_openssh(&pem).map_err(|e| CaError::Ssh(e.to_string()))?;
            return Ok(Self { key });
        }

        let ca = Self::generate()?;
        let pem = ca
            .key
            .to_openssh(LineEnding::LF)
            .map_err(|e| CaError::Ssh(e.to_string()))?;
        let now = crate::state::AppState::now_ts();
        vault
            .with_connection(|c| {
                c.execute(
                    "INSERT INTO ssh_ca_keys (group_name, private_openssh, created_at)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![group, pem.as_str(), now],
                )
            })
            .map_err(|e| CaError::Store(e.to_string()))?;
        Ok(ca)
    }

    /// OpenSSH public-key line of the CA — the trust anchor (`TrustedUserCAKeys` /
    /// known host CA). Safe to publish.
    #[must_use]
    pub fn public_openssh(&self) -> String {
        // `to_openssh` on a public key is infallible in practice; fall back to empty.
        self.key.public_key().to_openssh().unwrap_or_default()
    }

    /// Sign `public_key_openssh` into a short-TTL OpenSSH certificate.
    ///
    /// `valid_after` / `valid_before` are unix seconds; `key_id` is recorded in the cert
    /// for audit. A random serial and nonce are drawn from the OS CSPRNG.
    ///
    /// # Errors
    /// `BadRequest` if the public key or principals are invalid; `Ssh` on signing failure.
    pub fn sign(
        &self,
        public_key_openssh: &str,
        cert_type: CertType,
        principals: &[String],
        key_id: &str,
        valid_after: u64,
        valid_before: u64,
    ) -> Result<Signed, CaError> {
        if principals.is_empty() {
            return Err(CaError::BadRequest("principals must be non-empty".into()));
        }
        // Defense in depth: a non-positive validity window (caller bug, or a ttl that underflowed)
        // must never produce a cert. The handler also clamps ttl to SSH_CERT_MAX_TTL_SECS.
        if valid_before <= valid_after {
            return Err(CaError::BadRequest(
                "valid_before must be after valid_after".into(),
            ));
        }
        let subject = PublicKey::from_openssh(public_key_openssh)
            .map_err(|e| CaError::BadRequest(format!("public_key: {e}")))?;

        let serial: u64 = rand::random();
        let mut builder =
            Builder::new_with_random_nonce(&mut OsRng, subject, valid_after, valid_before)
                .map_err(|e| CaError::Ssh(e.to_string()))?;
        builder
            .serial(serial)
            .map_err(|e| CaError::Ssh(e.to_string()))?;
        builder
            .cert_type(cert_type)
            .map_err(|e| CaError::Ssh(e.to_string()))?;
        builder
            .key_id(key_id)
            .map_err(|e| CaError::Ssh(e.to_string()))?;
        for p in principals {
            builder
                .valid_principal(p.clone())
                .map_err(|e| CaError::Ssh(e.to_string()))?;
        }
        let cert = builder
            .sign(&self.key)
            .map_err(|e| CaError::Ssh(e.to_string()))?;
        let openssh = cert.to_openssh().map_err(|e| CaError::Ssh(e.to_string()))?;
        Ok(Signed {
            openssh,
            serial,
            valid_before,
        })
    }
}

/// Record `serials` as revoked (idempotent). Serials are stored bit-exact (u64↔i64).
/// Short-TTL certs mostly self-expire; this list lets a host build an sshd KRL
/// (`ssh-keygen -k`) for belt-and-suspenders revocation. CA-scoped (one CA per group).
///
/// # Errors
/// `Store` on a DB error.
pub fn record_revoked(vault: &Vault, serials: &[u64], now_ts: &str) -> Result<(), CaError> {
    vault
        .with_connection(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS ssh_revoked (serial INTEGER PRIMARY KEY, revoked_at TEXT NOT NULL);",
            )
        })
        .map_err(|e| CaError::Store(e.to_string()))?;
    for s in serials {
        #[allow(clippy::cast_possible_wrap)]
        let signed = *s as i64;
        vault
            .with_connection(|c| {
                c.execute(
                    "INSERT OR IGNORE INTO ssh_revoked (serial, revoked_at) VALUES (?1, ?2)",
                    rusqlite::params![signed, now_ts],
                )
            })
            .map_err(|e| CaError::Store(e.to_string()))?;
    }
    Ok(())
}

/// List revoked cert serials (ascending).
///
/// # Errors
/// `Store` on a DB error.
pub fn list_revoked(vault: &Vault) -> Result<Vec<u64>, CaError> {
    vault
        .with_connection(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS ssh_revoked (serial INTEGER PRIMARY KEY, revoked_at TEXT NOT NULL);",
            )
        })
        .map_err(|e| CaError::Store(e.to_string()))?;
    vault
        .with_connection(|c| {
            let mut stmt = c.prepare("SELECT serial FROM ssh_revoked ORDER BY serial")?;
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
            #[allow(clippy::cast_sign_loss)]
            rows.map(|r| r.map(|v| v as u64))
                .collect::<rusqlite::Result<Vec<u64>>>()
        })
        .map_err(|e| CaError::Store(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_a_user_cert_verifiable_against_the_ca() {
        let ca = SshCa::generate().unwrap();
        // A subject keypair to be certified.
        let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let subject_pub = subject.public_key().to_openssh().unwrap();

        let signed = ca
            .sign(
                &subject_pub,
                CertType::User,
                &["ops".to_string()],
                "demon@host",
                1_000,
                1_900,
            )
            .unwrap();

        let cert = ssh_key::Certificate::from_openssh(&signed.openssh).unwrap();
        assert_eq!(cert.serial(), signed.serial);
        assert_eq!(cert.valid_before(), 1_900);
        assert_eq!(cert.cert_type(), CertType::User);
        assert!(cert.valid_principals().iter().any(|p| p == "ops"));
        // The cert is signed by our CA's public key.
        assert_eq!(cert.signature_key(), ca.key.public_key().key_data());
    }

    #[test]
    fn empty_principals_rejected() {
        let ca = SshCa::generate().unwrap();
        let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pubk = subject.public_key().to_openssh().unwrap();
        let err = ca
            .sign(&pubk, CertType::User, &[], "k", 0, 100)
            .unwrap_err();
        assert!(matches!(err, CaError::BadRequest(_)));
    }

    #[test]
    fn nonpositive_validity_window_rejected() {
        let ca = SshCa::generate().unwrap();
        let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pubk = subject.public_key().to_openssh().unwrap();
        // valid_before == valid_after and valid_before < valid_after both refused (no 0-ttl cert).
        for (after, before) in [(1000, 1000), (1000, 900)] {
            let err = ca
                .sign(&pubk, CertType::User, &["ops".into()], "k", after, before)
                .unwrap_err();
            assert!(matches!(err, CaError::BadRequest(_)));
        }
    }

    #[test]
    fn public_openssh_is_an_ed25519_line() {
        let ca = SshCa::generate().unwrap();
        assert!(ca.public_openssh().starts_with("ssh-ed25519 "));
    }
}
