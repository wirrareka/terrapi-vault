//! Daemon authentication = mTLS over WireGuard against the fleet Root CA.
//!
//! The client cert's SAN identifies the daemon and maps to a broker role
//! (coordination/conventions/secrets-broker.md). In production the TLS layer (`tls`)
//! verifies the client cert against the Root CA and injects the verified SAN as a
//! [`ClientSan`] request extension; this extractor maps it to a role. DEV ONLY: when
//! `VAULT_ALLOW_INSECURE_DEV=1` the SAN may instead come from the `X-Client-Cert-SAN`
//! header (plain HTTP, no transport auth). Handlers depend only on an authenticated
//! `Principal`, never on transport details.

use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};

/// The verified client-cert SAN, injected as a request extension by the TLS accept loop
/// after a successful mTLS handshake. Its presence means the transport authenticated the
/// peer against the Root CA.
#[derive(Debug, Clone)]
pub struct ClientSan(pub String);

/// An authenticated daemon: its cert SAN and the role it maps to.
#[derive(Debug, Clone)]
pub struct Principal {
    pub san: String,
    pub role: String,
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // PRODUCTION: SAN from the verified mTLS peer cert (set by `tls` as an extension).
        if let Some(ClientSan(san)) = parts.extensions.get::<ClientSan>().cloned() {
            // A trusted cert whose SAN is not a registered role is authenticated but not
            // authorised for this broker → 403.
            let Some(role) = state.cfg.san_roles.get(&san).cloned() else {
                return Err((
                    StatusCode::FORBIDDEN,
                    "client cert SAN is not a registered role",
                ));
            };
            return Ok(Principal { san, role });
        }

        // DEV ONLY: header-based identity, and only when insecure dev is enabled.
        if !state.cfg.allow_insecure_dev {
            return Err((
                StatusCode::UNAUTHORIZED,
                "missing verified client identity (mTLS SAN)",
            ));
        }
        let san = parts
            .headers
            .get("x-client-cert-san")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let Some(san) = san else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "missing client identity (mTLS SAN)",
            ));
        };
        // In dev an unmapped SAN falls back to role "dev" so local runs need no config.
        let role = state
            .cfg
            .san_roles
            .get(&san)
            .cloned()
            .unwrap_or_else(|| "dev".to_owned());
        Ok(Principal { san, role })
    }
}
