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
    /// mTLS client-cert SAN → role. In production the rustls layer supplies the SAN;
    /// this maps it to a broker role. Empty in dev (any SAN accepted as role "dev").
    pub san_roles: HashMap<String, String>,
    /// When false (production), the listener MUST be mTLS-over-WireGuard; HTTP refused.
    /// True only for local skeleton runs.
    pub allow_insecure_dev: bool,
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
        let allow_insecure_dev = std::env::var("VAULT_ALLOW_INSECURE_DEV").as_deref() == Ok("1");
        Self {
            bind,
            residency_group: group,
            node,
            audit_path,
            san_roles: HashMap::new(),
            allow_insecure_dev,
        }
    }
}
