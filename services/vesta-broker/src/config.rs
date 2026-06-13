//! Broker configuration. Per residency group; the group is a per-instance constant
//! (structurally a broker cannot serve another group).

use crate::auth::RolePrincipal;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vesta_transport::http::env_parse;
use vesta_transport::ResidencyGroup;

/// Hardening defaults. Bodies are small JSON (a public key, a base64 DEK), so 64 KiB is
/// already generous; the timeout/concurrency/rate caps are sized for a handful of trusted
/// daemon principals over WireGuard, not public traffic. All overridable via env so infra
/// can tune per host without a rebuild (none are required at deploy).
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;
pub const DEFAULT_MAX_CONCURRENCY: usize = 256;
pub const DEFAULT_RATE_PER_SEC: f64 = 50.0;
pub const DEFAULT_RATE_BURST: f64 = 100.0;

/// Per-instance hardening limits (body size, request timeout, concurrency, per-principal
/// rate). Applied as middleware in `http::router`.
#[derive(Debug, Clone, Copy)]
pub struct Hardening {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrency: usize,
    /// Sustained per-principal (per mTLS SAN) request rate, tokens/second.
    pub rate_per_sec: f64,
    /// Per-principal burst capacity (token-bucket depth).
    pub rate_burst: f64,
}

impl Default for Hardening {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            rate_per_sec: DEFAULT_RATE_PER_SEC,
            rate_burst: DEFAULT_RATE_BURST,
        }
    }
}

impl Hardening {
    /// Read overrides from `VESTA_MAX_BODY_BYTES` / `VESTA_REQUEST_TIMEOUT_SECS` /
    /// `VESTA_MAX_CONCURRENCY` / `VESTA_RATE_PER_SEC` / `VESTA_RATE_BURST`; each falls back
    /// to its default when unset or unparseable.
    #[must_use]
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            max_body_bytes: env_parse("VESTA_MAX_BODY_BYTES").unwrap_or(d.max_body_bytes),
            request_timeout: env_parse("VESTA_REQUEST_TIMEOUT_SECS")
                .map_or(d.request_timeout, Duration::from_secs),
            max_concurrency: env_parse("VESTA_MAX_CONCURRENCY")
                .filter(|n| *n > 0)
                .unwrap_or(d.max_concurrency),
            rate_per_sec: env_parse("VESTA_RATE_PER_SEC").unwrap_or(d.rate_per_sec),
            rate_burst: env_parse("VESTA_RATE_BURST").unwrap_or(d.rate_burst),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub bind: SocketAddr,
    pub residency_group: ResidencyGroup,
    pub node: String,
    pub hardening: Hardening,
    pub audit_path: PathBuf,
    /// At-rest encrypted store (SQLCipher DB) holding the SSH CA key (and, later, the
    /// lease ledger). Created on first unseal; opened with the operator passphrase. See `seal`.
    pub store_path: PathBuf,
    /// Directory where `store-snapshot` writes consistent at-rest snapshots (for aether
    /// fleet backup). Defaults next to the store.
    pub snapshot_dir: PathBuf,
    /// Registered principals: cert SAN (dNSName) → {role, capabilities}. Loaded from the
    /// JSON roles config (`VESTA_ROLES_CONFIG`). Empty when unset → in production every
    /// cert is trusted-but-unauthorised (`403`); in dev an unmapped SAN is `dev` (all caps).
    pub roles: HashMap<String, RolePrincipal>,
    /// When false (production), the listener MUST be mTLS-over-WireGuard; HTTP refused.
    /// True only for local skeleton runs.
    pub allow_insecure_dev: bool,
    /// mTLS material. `Some` in production (server cert/key + the fleet Root CA bundle
    /// used to require + verify client certs). `None` only in `allow_insecure_dev`.
    pub tls: Option<TlsPaths>,
    /// KMS-cap JWT verification (Option J, secrets-broker.md §KMS root-of-trust). `Some`
    /// when `VESTA_KMS_JWT_ISSUER` is set → kms ops require a valid identity-minted ES256
    /// bearer token. `None` → kms stays cap-based (the aether cert-SAN path). See `jwt`.
    pub kms_jwt: Option<KmsJwtConfig>,
    /// Arm (a) — identity-sealed master key (secrets-broker.md §KMS root-of-trust). `Some`
    /// when `VESTA_IDENTITY_KMS_URL` is set → at boot the broker unseals its master key via
    /// identity instead of (augmenting) the manual passphrase. `None` → manual passphrase only.
    pub identity_kms: Option<IdentityKmsConfig>,
}

/// Config for the arm (a) seal/unseal client (`identity_kms`). Auth is mTLS (the broker's own
/// `VESTA_TLS_*` material — see `identity_kms`), so this carries no secret: just where to reach
/// identity's KMS listener and where the inert sealed-master blob lives.
#[derive(Debug, Clone)]
pub struct IdentityKmsConfig {
    /// Identity's WG-only native-mTLS KMS listener base URL (e.g. `https://10.200.0.100:8202`).
    pub url: String,
    /// Where the inert `{kek_id, wrapped}` sealed-master blob is persisted (encrypted dataset).
    pub sealed_master_file: PathBuf,
}

/// Issuer/audience config for verifying identity-minted kms-cap tokens. The instance's
/// `residency_group` (already on [`BrokerConfig`]) is the expected `residency_group` claim.
#[derive(Debug, Clone)]
pub struct KmsJwtConfig {
    /// Pinned `iss`, matched exactly (incl. trailing slash), e.g. `https://identity.eu.proximi.fi/`.
    pub issuer: String,
    /// Primary expected `aud` — `"vesta"` unless overridden. The verifier ALSO accepts the legacy
    /// `"vault"` during the rename cutover (see [`crate::jwt::JwtVerifier`]).
    pub audience: String,
    /// Explicit JWKS URL (`VESTA_KMS_JWT_JWKS_URI`); `None` → discover via OIDC `/.well-known`.
    pub jwks_uri: Option<String>,
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
        let group = match std::env::var("VESTA_RESIDENCY_GROUP").as_deref() {
            Ok("uae") => ResidencyGroup::Uae,
            _ => ResidencyGroup::Eu,
        };
        let bind = std::env::var("VESTA_BROKER_BIND")
            .ok()
            .and_then(|s| s.parse().ok())
            // Dev default loopback; prod binds the WG address only (see ports-env.md: 8200 WG-only).
            .unwrap_or_else(|| "127.0.0.1:8200".parse().expect("valid default addr"));
        let node = std::env::var("VESTA_NODE")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "vesta-broker".into());
        let audit_path = std::env::var("VESTA_AUDIT_PATH").map_or_else(
            |_| std::env::temp_dir().join("vesta-broker-audit.jsonl"),
            PathBuf::from,
        );
        let store_path = std::env::var("VESTA_STORE_PATH").map_or_else(
            |_| std::env::temp_dir().join("vesta-broker-store.sqlcipher"),
            PathBuf::from,
        );
        let snapshot_dir = std::env::var("VESTA_SNAPSHOT_DIR")
            .map_or_else(|_| std::env::temp_dir(), PathBuf::from);
        let allow_insecure_dev = std::env::var("VESTA_ALLOW_INSECURE_DEV").as_deref() == Ok("1");
        let tls = match (
            std::env::var("VESTA_TLS_CERT"),
            std::env::var("VESTA_TLS_KEY"),
            std::env::var("VESTA_TLS_CLIENT_CA"),
        ) {
            (Ok(cert), Ok(key), Ok(client_ca)) => Some(TlsPaths {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
                client_ca: PathBuf::from(client_ca),
            }),
            _ => None,
        };
        let roles = load_roles();
        // KMS-cap JWT verification is opt-in: enabled only when an issuer is configured.
        let kms_jwt = std::env::var("VESTA_KMS_JWT_ISSUER")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|issuer| KmsJwtConfig {
                issuer,
                audience: std::env::var("VESTA_KMS_JWT_AUDIENCE")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "vesta".to_owned()),
                jwks_uri: std::env::var("VESTA_KMS_JWT_JWKS_URI")
                    .ok()
                    .filter(|s| !s.is_empty()),
            });
        // Arm (a) is opt-in: enabled only when the identity KMS URL + boundary secret are set.
        let identity_kms = load_identity_kms(&store_path);
        Self {
            bind,
            residency_group: group,
            node,
            hardening: Hardening::from_env(),
            audit_path,
            store_path,
            snapshot_dir,
            roles,
            allow_insecure_dev,
            tls,
            kms_jwt,
            identity_kms,
        }
    }
}

/// Build the arm (a) config from env. `None` when `VESTA_IDENTITY_KMS_URL` is unset (arm (a)
/// off). Auth to identity is mTLS via the broker's `VESTA_TLS_*` material (no secret here).
/// The sealed-master blob defaults next to the at-rest store unless `VESTA_SEALED_MASTER_FILE`.
fn load_identity_kms(store_path: &Path) -> Option<IdentityKmsConfig> {
    let url = std::env::var("VESTA_IDENTITY_KMS_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let sealed_master_file = std::env::var("VESTA_SEALED_MASTER_FILE").map_or_else(
        |_| {
            store_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("sealed-master.json")
        },
        PathBuf::from,
    );
    Some(IdentityKmsConfig {
        url,
        sealed_master_file,
    })
}

/// Roles config file shape (`VESTA_ROLES_CONFIG`, JSON):
/// `{ "roles": { "<san-dnsname>": { "role": "<name>", "caps": ["ssh-sign", ...] } } }`.
#[derive(Deserialize)]
struct RolesFile {
    roles: HashMap<String, RolePrincipal>,
}

/// Load SAN→{role,caps} from `VESTA_ROLES_CONFIG`. Fail-closed: a missing var or an
/// unreadable/invalid file yields an empty map (every prod cert then `403`s) and logs why.
fn load_roles() -> HashMap<String, RolePrincipal> {
    let Ok(path) = std::env::var("VESTA_ROLES_CONFIG") else {
        return HashMap::new();
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            match serde_json::from_str::<RolesFile>(&raw) {
                Ok(f) => f.roles,
                Err(e) => {
                    eprintln!("vesta-broker: VESTA_ROLES_CONFIG parse error ({e}); roles empty (deny-all)");
                    HashMap::new()
                }
            }
        }
        Err(e) => {
            eprintln!("vesta-broker: VESTA_ROLES_CONFIG read error ({e}); roles empty (deny-all)");
            HashMap::new()
        }
    }
}
