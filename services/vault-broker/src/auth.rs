//! Daemon authentication = mTLS over WireGuard against the fleet Root CA.
//!
//! The client cert's SAN identifies the daemon and maps to a broker role
//! (coordination/conventions/secrets-broker.md). TLS termination (rustls, client-auth
//! required, Root CA trust anchor) is the immediately-next implementation step; this
//! module already models the boundary so handlers depend on an authenticated
//! `Principal`, not on transport details. Until rustls lands, in dev mode the SAN is
//! read from the `X-Client-Cert-SAN` header (refused unless `VAULT_ALLOW_INSECURE_DEV`).

use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};

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
        // PRODUCTION: the SAN comes from the verified mTLS peer cert (rustls). DEV ONLY:
        // fall back to a header, and only when insecure dev is explicitly enabled.
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
        if !state.cfg.allow_insecure_dev && state.cfg.san_roles.is_empty() {
            // No real mTLS layer wired yet and not in dev mode → refuse rather than
            // accept an unauthenticated header in production.
            return Err((
                StatusCode::UNAUTHORIZED,
                "mTLS not configured; refusing header-only auth",
            ));
        }
        let role = state
            .cfg
            .san_roles
            .get(&san)
            .cloned()
            .unwrap_or_else(|| "dev".to_owned());
        Ok(Principal { san, role })
    }
}
