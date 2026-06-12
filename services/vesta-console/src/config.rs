//! Console config (env). The console is **per residency group** and aggregates that group's
//! broker instances; it is a read-only operator view (no secret values). Browser↔console
//! security is WG + the optional Kalista edge (TLS/OIDC); console↔broker is mTLS-over-WG.

use std::net::SocketAddr;
use std::path::PathBuf;

/// One broker instance the console aggregates: an opaque `id` (for display + result tagging)
/// and its WG `addr` (`host:port`, reached over HTTPS/mTLS).
#[derive(Debug, Clone)]
pub struct BrokerEndpoint {
    pub id: String,
    pub addr: String,
}

/// The console's own fleet-CA client material (cert `vesta-console.<group>.proximi.internal`),
/// presented to the brokers' mTLS-over-WG `observe` API; the fleet Root CA bundle is the sole
/// trust root for the brokers' server certs.
#[derive(Debug, Clone)]
pub struct ConsoleTls {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
}

/// OIDC RP (P1b) parameters: operator login via terrapi-identity, `authorization_code` + PKCE,
/// `private_key_jwt` client auth keyed by the **console cert's key** (so the signing key = the
/// mTLS key — see [`ConsoleTls::key`]), `acr=mfa` enforced. `Some` only when
/// `VESTA_CONSOLE_OIDC_ISSUER` is set; absent → login is unavailable (dev stub or all-401).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// OP issuer, exact incl. trailing slash (e.g. `https://identity.eu.proximi.fi/`).
    pub issuer: String,
    pub client_id: String,
    /// Exact-match redirect URI registered with identity (`…/api/v1/auth/callback`).
    pub redirect_uri: String,
    /// PEM of the RSA private key the client-assertion JWT is signed with — the **same** cert key
    /// presented for broker mTLS ([`ConsoleTls::key`]); RS256, header `kid` = [`Self::kid`].
    pub signing_key: PathBuf,
    /// RFC 7638 thumbprint of the public key identity bound to the client (the assertion `kid`).
    pub kid: String,
    /// Space-delimited scopes (default `openid profile email`).
    pub scopes: String,
    /// Required `acr` value enforced on the id_token (default `mfa`).
    pub acr: String,
}

#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    pub bind: SocketAddr,
    pub residency_group: String,
    pub brokers: Vec<BrokerEndpoint>,
    /// `Some` in production (mTLS to brokers). `None` only in `allow_insecure_dev`.
    pub tls: Option<ConsoleTls>,
    /// `Some` when OIDC is configured (`VESTA_CONSOLE_OIDC_ISSUER` set). The RP (P1b).
    pub oidc: Option<OidcConfig>,
    /// Local dev only: skip broker-cert verification + grant a `dev` operator session (no OIDC).
    pub allow_insecure_dev: bool,
}

impl ConsoleConfig {
    /// Load from env with safe local defaults.
    ///
    /// # Errors
    /// `String` if `VESTA_CONSOLE_BROKERS` is malformed.
    pub fn from_env() -> Result<Self, String> {
        let bind = std::env::var("VESTA_CONSOLE_BIND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8203".parse().expect("valid default addr"));
        let residency_group =
            std::env::var("VESTA_CONSOLE_RESIDENCY_GROUP").unwrap_or_else(|_| "eu".to_string());
        let brokers = parse_brokers(&std::env::var("VESTA_CONSOLE_BROKERS").unwrap_or_default())?;
        let allow_insecure_dev =
            std::env::var("VESTA_CONSOLE_ALLOW_INSECURE_DEV").as_deref() == Ok("1");
        let tls = match (
            std::env::var("VESTA_CONSOLE_TLS_CERT"),
            std::env::var("VESTA_CONSOLE_TLS_KEY"),
            std::env::var("VESTA_CONSOLE_TLS_CLIENT_CA"),
        ) {
            (Ok(cert), Ok(key), Ok(client_ca)) => Some(ConsoleTls {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
                client_ca: PathBuf::from(client_ca),
            }),
            _ => None,
        };
        let oidc = oidc_from_env(tls.as_ref())?;
        Ok(Self {
            bind,
            residency_group,
            brokers,
            tls,
            oidc,
            allow_insecure_dev,
        })
    }
}

/// Build the OIDC RP config from env. Returns `Ok(None)` when `VESTA_CONSOLE_OIDC_ISSUER` is unset
/// (login disabled). The client-assertion signing key is the console cert key ([`ConsoleTls::key`]),
/// so OIDC requires `VESTA_CONSOLE_TLS_*` to be present too.
///
/// # Errors
/// `String` if the issuer is set but a required field (`redirect_uri`, `kid`) or the cert key is missing.
fn oidc_from_env(tls: Option<&ConsoleTls>) -> Result<Option<OidcConfig>, String> {
    let Ok(issuer) = std::env::var("VESTA_CONSOLE_OIDC_ISSUER") else {
        return Ok(None);
    };
    if issuer.is_empty() {
        return Ok(None);
    }
    let redirect_uri = std::env::var("VESTA_CONSOLE_OIDC_REDIRECT_URI")
        .map_err(|_| "VESTA_CONSOLE_OIDC_ISSUER set but VESTA_CONSOLE_OIDC_REDIRECT_URI missing")?;
    let kid = std::env::var("VESTA_CONSOLE_OIDC_KID")
        .map_err(|_| "VESTA_CONSOLE_OIDC_ISSUER set but VESTA_CONSOLE_OIDC_KID missing")?;
    let signing_key = tls
        .map(|t| t.key.clone())
        .ok_or("OIDC needs VESTA_CONSOLE_TLS_KEY (the cert key signs the client assertion)")?;
    let client_id = std::env::var("VESTA_CONSOLE_OIDC_CLIENT_ID")
        .unwrap_or_else(|_| "vesta-console".to_string());
    let scopes = std::env::var("VESTA_CONSOLE_OIDC_SCOPES")
        .unwrap_or_else(|_| "openid profile email".to_string());
    let acr = std::env::var("VESTA_CONSOLE_OIDC_ACR").unwrap_or_else(|_| "mfa".to_string());
    Ok(Some(OidcConfig {
        issuer,
        client_id,
        redirect_uri,
        signing_key,
        kid,
        scopes,
        acr,
    }))
}

/// Parse `VESTA_CONSOLE_BROKERS` = comma-separated `id@host:port` (e.g.
/// `vault-eu-1@10.200.0.101:8200,vault-eu-2@10.200.0.103:8200`). Empty → no brokers.
fn parse_brokers(s: &str) -> Result<Vec<BrokerEndpoint>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|entry| {
            let (id, addr) = entry
                .split_once('@')
                .ok_or_else(|| format!("broker entry '{entry}' must be id@host:port"))?;
            if id.is_empty() || addr.is_empty() {
                return Err(format!("broker entry '{entry}' has empty id or addr"));
            }
            Ok(BrokerEndpoint {
                id: id.to_string(),
                addr: addr.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_broker_list() {
        let b =
            parse_brokers("vault-eu-1@10.200.0.101:8200, vault-eu-2@10.200.0.103:8200").unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].id, "vault-eu-1");
        assert_eq!(b[1].addr, "10.200.0.103:8200");
    }

    #[test]
    fn empty_is_no_brokers() {
        assert!(parse_brokers("").unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_entry() {
        assert!(parse_brokers("no-at-sign").is_err());
    }
}
