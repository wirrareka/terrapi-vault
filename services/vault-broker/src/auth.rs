//! Daemon authentication + authorization = mTLS over WireGuard against the fleet Root CA.
//!
//! The client cert's **SAN `dNSName`** identifies the daemon and maps to a registered
//! broker role + its **capabilities** (coordination/conventions/secrets-broker.md). In
//! production the TLS layer (`tls`) verifies the cert against the Root CA and injects the
//! verified SAN as a [`ClientSan`] request extension; this extractor maps it (via the
//! roles config) to a [`Principal`] carrying the allowed [`Capability`] set. Handlers then
//! call `require_cap` so each principal can invoke only its granted ops (least privilege).
//!
//! DEV ONLY: when `VAULT_ALLOW_INSECURE_DEV=1` the SAN may come from the
//! `X-Client-Cert-SAN` header (plain HTTP, no transport auth) and an unmapped SAN gets a
//! `dev` principal with all capabilities, so local runs need no roles config.

use crate::dto::ErrorBody;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use axum::Json;
use serde::Deserialize;
use std::collections::HashSet;

/// A typed auth rejection (same `{error,detail}` envelope as the rest of the API), so a client
/// can switch on the machine code.
fn deny(status: StatusCode, code: &str, detail: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error: code.to_owned(),
            detail: detail.to_owned(),
        }),
    )
}

/// A broker operation a principal may be granted. Maps to endpoint groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// `GET /v1/{group}/ssh/ca`
    SshCa,
    /// `POST /v1/{group}/ssh/sign`
    SshSign,
    /// `POST /v1/{group}/{tenant_id}/creds/{role}`
    Creds,
    /// `POST /v1/sys/session`, `DELETE /v1/sys/session/{id}`
    Session,
    /// `POST /v1/sys/leases/{renew,revoke}`
    Leases,
    /// `POST /v1/{group}/{tenant_id}/kms/{key_id}/{wrap,unwrap}`
    Kms,
    /// `POST /v1/sys/store-snapshot` (consistent snapshot of vault's own at-rest store)
    Snapshot,
}

impl Capability {
    /// Every capability — granted to the `dev` principal only.
    #[must_use]
    pub fn all() -> HashSet<Capability> {
        [
            Capability::SshCa,
            Capability::SshSign,
            Capability::Creds,
            Capability::Session,
            Capability::Leases,
            Capability::Kms,
            Capability::Snapshot,
        ]
        .into_iter()
        .collect()
    }
}

/// A registered principal: the role name a SAN maps to + its granted capabilities. Loaded
/// from the roles config (`VAULT_ROLES_CONFIG`).
#[derive(Debug, Clone, Deserialize)]
pub struct RolePrincipal {
    pub role: String,
    pub caps: HashSet<Capability>,
}

/// The verified client-cert SAN, injected as a request extension by the TLS accept loop
/// after a successful mTLS handshake. Its presence means the transport authenticated the
/// peer against the Root CA.
#[derive(Debug, Clone)]
pub struct ClientSan(pub String);

/// An authenticated daemon: its cert SAN, the role it maps to, and its capabilities.
#[derive(Debug, Clone)]
pub struct Principal {
    pub san: String,
    pub role: String,
    pub caps: HashSet<Capability>,
}

impl Principal {
    /// Does this principal hold `cap`?
    #[must_use]
    pub fn allows(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = (StatusCode, Json<ErrorBody>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // PRODUCTION: SAN from the verified mTLS peer cert (set by `tls` as an extension).
        if let Some(ClientSan(san)) = parts.extensions.get::<ClientSan>().cloned() {
            // A trusted cert whose SAN is not a registered role is authenticated but not
            // authorised for this broker → 403. A distinct code (`unregistered_principal`) so a
            // client can tell "register my SAN" from a capability `forbidden` on a route.
            let Some(rp) = state.cfg.roles.get(&san).cloned() else {
                return Err(deny(
                    StatusCode::FORBIDDEN,
                    "unregistered_principal",
                    "client cert is trusted but its SAN is not a registered broker role",
                ));
            };
            return Ok(Principal {
                san,
                role: rp.role,
                caps: rp.caps,
            });
        }

        // DEV ONLY: header-based identity, and only when insecure dev is enabled.
        if !state.cfg.allow_insecure_dev {
            return Err(deny(
                StatusCode::UNAUTHORIZED,
                "missing_identity",
                "no verified client identity (mTLS SAN) on the request",
            ));
        }
        let san = parts
            .headers
            .get("x-client-cert-san")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let Some(san) = san else {
            return Err(deny(
                StatusCode::UNAUTHORIZED,
                "missing_identity",
                "missing client identity (mTLS SAN)",
            ));
        };
        // In dev a configured SAN keeps its grants; an unmapped one is `dev` with all caps.
        if let Some(rp) = state.cfg.roles.get(&san).cloned() {
            return Ok(Principal {
                san,
                role: rp.role,
                caps: rp.caps,
            });
        }
        Ok(Principal {
            san,
            role: "dev".to_owned(),
            caps: Capability::all(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_deserialize_from_kebab_case() {
        let rp: RolePrincipal = serde_json::from_str(
            r#"{ "role": "demon-system", "caps": ["ssh-sign", "session", "leases"] }"#,
        )
        .unwrap();
        assert_eq!(rp.role, "demon-system");
        assert!(rp.caps.contains(&Capability::SshSign));
        assert!(rp.caps.contains(&Capability::Session));
        assert!(!rp.caps.contains(&Capability::Creds)); // demon-system has no creds
    }

    #[test]
    fn principal_allows_only_granted_caps() {
        let p = Principal {
            san: "demon-system.eu.proximi.internal".into(),
            role: "demon-system".into(),
            caps: [Capability::SshSign, Capability::Session, Capability::Leases]
                .into_iter()
                .collect(),
        };
        assert!(p.allows(Capability::SshSign));
        assert!(!p.allows(Capability::Creds));
        assert!(!p.allows(Capability::SshCa));
    }

    #[test]
    fn dev_principal_holds_all_caps() {
        let all = Capability::all();
        assert_eq!(all.len(), 7);
        for c in [
            Capability::SshCa,
            Capability::SshSign,
            Capability::Creds,
            Capability::Session,
            Capability::Leases,
            Capability::Kms,
            Capability::Snapshot,
        ] {
            assert!(all.contains(&c));
        }
    }
}
