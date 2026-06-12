//! Daemon authentication + authorization = mTLS over WireGuard against the fleet Root CA.
//!
//! The client cert's **SAN `dNSName`** identifies the daemon and maps to a registered
//! broker role + its **capabilities** (coordination/conventions/secrets-broker.md). In
//! production the TLS layer (`tls`) verifies the cert against the Root CA and injects the
//! verified SAN as a [`ClientSan`] request extension; this extractor maps it (via the
//! roles config) to a [`Principal`] carrying the allowed [`Capability`] set. Handlers then
//! call `require_cap` so each principal can invoke only its granted ops (least privilege).
//!
//! DEV ONLY: when `VESTA_ALLOW_INSECURE_DEV=1` the SAN may come from the
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
    /// `POST /v1/{group}/object-store/presign` (short-TTL presigned PUT URL for tile publishing)
    ObjectStore,
    /// `POST /v1/{group}/object-store/presign-get` (short-TTL presigned GET URL for tile serving)
    ObjectStoreRead,
    /// `GET /v1/sys/observe/*` + `/v1/{group}/observe/*` (read-only operator observability — the
    /// vesta-console plane; state only, never secret values)
    Observe,
    /// `POST /v1/sys/store-snapshot` (consistent snapshot of vault's own at-rest store)
    Snapshot,
}

impl Capability {
    /// The kebab-case wire name (matches the `Deserialize` rename + `VESTA_ROLES_CONFIG`). Used
    /// by the observe API to surface a role's caps as strings without leaking the enum.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::SshCa => "ssh-ca",
            Capability::SshSign => "ssh-sign",
            Capability::Creds => "creds",
            Capability::Session => "session",
            Capability::Leases => "leases",
            Capability::Kms => "kms",
            Capability::ObjectStore => "object-store",
            Capability::ObjectStoreRead => "object-store-read",
            Capability::Observe => "observe",
            Capability::Snapshot => "snapshot",
        }
    }

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
            Capability::ObjectStore,
            Capability::ObjectStoreRead,
            Capability::Observe,
            Capability::Snapshot,
        ]
        .into_iter()
        .collect()
    }
}

/// Privileged SSH principals an ssh-sign role may NEVER mint unless its `ssh_principals` allowlist
/// names them explicitly — so a role left without an allowlist still cannot be coaxed into signing
/// a superuser cert. Lowercase exact match (SSH principals are case-sensitive; these are the
/// conventional privileged accounts).
const DANGEROUS_SSH_PRINCIPALS: &[&str] = &["root", "admin", "administrator", "sudo", "wheel"];

/// A registered principal: the role name a SAN maps to + its granted capabilities. Loaded
/// from the roles config (`VESTA_ROLES_CONFIG`).
#[derive(Debug, Clone, Deserialize)]
pub struct RolePrincipal {
    pub role: String,
    pub caps: HashSet<Capability>,
    /// Optional SSH principal allowlist — the cert subject principals (usernames / hostnames)
    /// this role may request in `POST /v1/{group}/ssh/sign`. When `Some`, every requested
    /// principal must be an exact member, so an `ssh-sign` role cannot mint a cert for an
    /// arbitrary user/host (e.g. `root`). When absent, no constraint (legacy) — production roles
    /// SHOULD set it (see coordination/conventions/secrets-broker.md).
    #[serde(default)]
    pub ssh_principals: Option<Vec<String>>,
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
    /// SSH principal allowlist for this role (see [`RolePrincipal::ssh_principals`]); `None` =
    /// unconstrained (legacy / dev).
    pub ssh_principals: Option<Vec<String>>,
}

impl Principal {
    /// Does this principal hold `cap`?
    #[must_use]
    pub fn allows(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    /// Whether this role may request `requested` SSH principals. With an allowlist, every requested
    /// principal must be an exact member. WITHOUT an allowlist (legacy / unconfigured) the role is
    /// otherwise unconstrained EXCEPT it can never mint a [`DANGEROUS_SSH_PRINCIPALS`] one (e.g.
    /// `root`) — so a role left unconfigured can't be tricked into signing a privileged cert. To
    /// legitimately issue such a principal the role must list it explicitly in `ssh_principals`.
    #[must_use]
    pub fn allows_ssh_principals(&self, requested: &[String]) -> bool {
        match &self.ssh_principals {
            Some(allow) => requested.iter().all(|p| allow.contains(p)),
            None => requested
                .iter()
                .all(|p| !DANGEROUS_SSH_PRINCIPALS.contains(&p.as_str())),
        }
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
                ssh_principals: rp.ssh_principals,
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
                ssh_principals: rp.ssh_principals,
            });
        }
        Ok(Principal {
            san,
            role: "dev".to_owned(),
            caps: Capability::all(),
            ssh_principals: None,
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
            ssh_principals: Some(vec!["ops".into(), "deploy".into()]),
        };
        assert!(p.allows(Capability::SshSign));
        assert!(!p.allows(Capability::Creds));
        assert!(!p.allows(Capability::SshCa));
        // SSH principal allowlist: members allowed, non-members (e.g. root) refused.
        assert!(p.allows_ssh_principals(&["ops".into()]));
        assert!(p.allows_ssh_principals(&["ops".into(), "deploy".into()]));
        assert!(!p.allows_ssh_principals(&["root".into()]));
        assert!(!p.allows_ssh_principals(&["ops".into(), "root".into()]));
    }

    #[test]
    fn no_allowlist_still_refuses_dangerous_principals() {
        let p = Principal {
            san: "demon.eu.proximi.internal".into(),
            role: "dev".into(),
            caps: Capability::all(),
            ssh_principals: None, // unconfigured / legacy
        };
        // Unconstrained for ordinary principals…
        assert!(p.allows_ssh_principals(&["ops".into(), "svc-x".into()]));
        // …but root/admin/etc. are refused unless explicitly allowlisted.
        assert!(!p.allows_ssh_principals(&["root".into()]));
        assert!(!p.allows_ssh_principals(&["ops".into(), "wheel".into()]));
        // An explicit allowlist naming root would permit it (deliberate opt-in).
        let q = Principal {
            ssh_principals: Some(vec!["root".into()]),
            ..p
        };
        assert!(q.allows_ssh_principals(&["root".into()]));
    }

    #[test]
    fn dev_principal_holds_all_caps() {
        let all = Capability::all();
        assert_eq!(all.len(), 10);
        for c in [
            Capability::SshCa,
            Capability::SshSign,
            Capability::Creds,
            Capability::Session,
            Capability::Leases,
            Capability::Kms,
            Capability::ObjectStore,
            Capability::ObjectStoreRead,
            Capability::Observe,
            Capability::Snapshot,
        ] {
            assert!(all.contains(&c));
        }
    }
}
