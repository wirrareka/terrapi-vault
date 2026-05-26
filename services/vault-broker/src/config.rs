//! Broker configuration. Per residency group; the group is a per-instance constant
//! (structurally a broker cannot serve another group).

use crate::auth::RolePrincipal;
use serde::Deserialize;
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
    /// At-rest encrypted store (SQLCipher DB) holding the SSH CA key (and, later, the
    /// lease ledger). Created on first unseal; opened with the operator passphrase. See `seal`.
    pub store_path: PathBuf,
    /// Registered principals: cert SAN (dNSName) → {role, capabilities}. Loaded from the
    /// JSON roles config (`VAULT_ROLES_CONFIG`). Empty when unset → in production every
    /// cert is trusted-but-unauthorised (`403`); in dev an unmapped SAN is `dev` (all caps).
    pub roles: HashMap<String, RolePrincipal>,
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
        let store_path = std::env::var("VAULT_STORE_PATH").map_or_else(
            |_| std::env::temp_dir().join("vault-broker-store.sqlcipher"),
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
        let roles = load_roles();
        Self {
            bind,
            residency_group: group,
            node,
            audit_path,
            store_path,
            roles,
            allow_insecure_dev,
            tls,
        }
    }
}

/// Roles config file shape (`VAULT_ROLES_CONFIG`, JSON):
/// `{ "roles": { "<san-dnsname>": { "role": "<name>", "caps": ["ssh-sign", ...] } } }`.
#[derive(Deserialize)]
struct RolesFile {
    roles: HashMap<String, RolePrincipal>,
}

/// Load SAN→{role,caps} from `VAULT_ROLES_CONFIG`. Fail-closed: a missing var or an
/// unreadable/invalid file yields an empty map (every prod cert then `403`s) and logs why.
fn load_roles() -> HashMap<String, RolePrincipal> {
    let Ok(path) = std::env::var("VAULT_ROLES_CONFIG") else {
        return HashMap::new();
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<RolesFile>(&raw) {
            Ok(f) => f.roles,
            Err(e) => {
                eprintln!("vault-broker: VAULT_ROLES_CONFIG parse error ({e}); roles empty (deny-all)");
                HashMap::new()
            }
        },
        Err(e) => {
            eprintln!("vault-broker: VAULT_ROLES_CONFIG read error ({e}); roles empty (deny-all)");
            HashMap::new()
        }
    }
}
