//! Broker configuration. Per residency group; the group is a per-instance constant
//! (structurally a broker cannot serve another group).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use vault_transport::ResidencyGroup;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub bind: SocketAddr,
    pub residency_group: ResidencyGroup,
    pub node: String,
    pub audit_path: PathBuf,
    /// Plaintext seal-metadata sidecar (salts + KDF params + passphrase verifier; no
    /// secret). Created `mode 600` on first unseal. See `seal`.
    pub seal_path: PathBuf,
    /// mTLS client-cert SAN → role. In production the rustls layer supplies the SAN;
    /// this maps it to a broker role. Empty in dev (any SAN accepted as role "dev").
    pub san_roles: HashMap<String, String>,
    /// When false (production), the listener MUST be mTLS-over-WireGuard; HTTP refused.
    /// True only for local skeleton runs.
    pub allow_insecure_dev: bool,
    /// mTLS material. `Some` in production (server cert/key + the fleet Root CA bundle
    /// used to require + verify client certs). `None` only in `allow_insecure_dev`.
    pub tls: Option<TlsPaths>,
}

/// Filesystem paths to the broker's mTLS material (PEM).
#[derive(Debug, Clone)]
pub struct TlsPaths {
    /// Server certificate chain (leaf first), PEM.
    pub cert: PathBuf,
    /// Server private key, PEM (PKCS#8 / SEC1 / PKCS#1).
    pub key: PathBuf,
    /// Fleet Root CA bundle (PEM) — trust anchor for verifying client certs.
    pub client_ca: PathBuf,
}

impl BrokerConfig {
    /// Load from env with safe local defaults. Real deploy sets these explicitly.
    #[must_use]
    pub fn from_env() -> Self {
        let group = match std::env::var("VAULT_RESIDENCY_GROUP").as_deref() {
            Ok("uae") => ResidencyGroup::Uae,
            _ => ResidencyGroup::Eu,
        };
        let bind = std::env::var("VAULT_BROKER_BIND")
            .ok()
            .and_then(|s| s.parse().ok())
            // Dev default loopback; prod binds the WG address only (see ports-env.md: 8200 WG-only).
            .unwrap_or_else(|| "127.0.0.1:8200".parse().expect("valid default addr"));
        let node = std::env::var("VAULT_NODE")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "vault-broker".into());
        let audit_path = std::env::var("VAULT_AUDIT_PATH").map_or_else(
            |_| std::env::temp_dir().join("vault-broker-audit.jsonl"),
            PathBuf::from,
        );
        let seal_path = std::env::var("VAULT_SEAL_PATH").map_or_else(
            |_| std::env::temp_dir().join("vault-broker-seal.json"),
            PathBuf::from,
        );
        let allow_insecure_dev = std::env::var("VAULT_ALLOW_INSECURE_DEV").as_deref() == Ok("1");
        let tls = match (
            std::env::var("VAULT_TLS_CERT"),
            std::env::var("VAULT_TLS_KEY"),
            std::env::var("VAULT_TLS_CLIENT_CA"),
        ) {
            (Ok(cert), Ok(key), Ok(client_ca)) => Some(TlsPaths {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
                client_ca: PathBuf::from(client_ca),
            }),
            _ => None,
        };
        Self {
            bind,
            residency_group: group,
            node,
            audit_path,
            seal_path,
            san_roles: HashMap::new(),
            allow_insecure_dev,
            tls,
        }
    }
}
