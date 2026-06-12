//! KMS-cap JWT verification (Option J — identity-minted ES256 workload creds).
//!
//! Per `coordination/conventions/secrets-broker.md §KMS root-of-trust` (LOCKED 2026-06-02):
//! the `kms` capability is proven **per call** by a short-TTL **ES256** JWT minted by
//! terrapi-identity, layered on top of the mTLS-over-WireGuard channel (the JWT is the cap
//! proof, NOT a replacement for the channel — `auth::Principal` still authenticates the
//! transport). This module verifies that token:
//!
//! 1. header `alg` MUST be `ES256` (reject `none`/alg-confusion) and carry a `kid`;
//! 2. signature against identity's JWKS — fetched from the issuer's
//!    `/.well-known/openid-configuration` → `jwks_uri` (or an explicit override), cached and
//!    refetched on a `kid` miss (handles identity key rotation);
//! 3. `iss` (pinned, exact incl. trailing slash) + `aud` (`"vault"`) + `exp` via jsonwebtoken;
//! 4. `scope ⊇ "kms"` (RFC 6749 space-delimited) and `residency_group == this instance's
//!    group` — belt-and-suspenders cross-region replay defence (the caller then enforces
//!    `tenant_id == path tenant_id`).
//!
//! Disabled unless `VESTA_KMS_JWT_ISSUER` is set; when off, kms ops stay cap-based
//! (`Capability::Kms` via the cert-SAN role — the existing aether fleet-backup path).

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimum spacing between JWKS (re)fetches. On a `kid` miss the cache refetches at most this
/// often — so a flood of tokens bearing random/unknown `kid`s cannot amplify 1:1 into outbound
/// fetches against identity's JWKS endpoint. A genuinely rotated signing key is therefore picked
/// up within this bound (identity's kid-rotation overlap must outlast it — see `jwt-claims.md`).
const MIN_JWKS_REFETCH: Duration = Duration::from_secs(30);

/// Cached JWKS + the last (attempted) fetch time, so refetch-on-miss can be rate-limited.
#[derive(Default)]
struct JwksCache {
    set: Option<JwkSet>,
    last_fetch: Option<Instant>,
}

/// Why a kms bearer token was rejected. Mapped to HTTP status by the handler (`http::map_jwt_err`).
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("kms requires a bearer JWT")]
    Missing,
    #[error("token header invalid: {0}")]
    Header(String),
    #[error("unknown signing key (kid)")]
    UnknownKid,
    #[error("jwks unavailable: {0}")]
    Jwks(String),
    #[error("token rejected")]
    Invalid,
    #[error("scope does not include kms")]
    ScopeMissing,
    #[error("residency_group mismatch")]
    ResidencyMismatch,
    #[error("tenant_id missing or not a lowercase UUIDv4")]
    BadTenant,
}

/// The minted access-token claims this broker cares about (`conventions/jwt-claims.md`).
/// `iss`/`aud`/`exp` are validated by jsonwebtoken, not re-read here.
#[derive(Debug, Deserialize)]
struct Claims {
    /// OAuth `scope`, RFC 6749 §3.3 space-delimited (`roles`/array-form are joined upstream).
    #[serde(default)]
    scope: String,
    #[serde(default)]
    residency_group: String,
    #[serde(default)]
    tenant_id: String,
}

/// The verified kms-cap grant the handler authorizes against.
pub struct VerifiedKms {
    /// The token's `tenant_id` — the handler enforces it equals the request path tenant.
    pub tenant_id: String,
}

/// Validate the broker-specific claims once the signature + `iss`/`aud`/`exp` already passed.
/// Pure (no I/O) so the authz policy is unit-tested without minting signed tokens.
fn check_claims(claims: &Claims, expected_group: &str) -> Result<VerifiedKms, JwtError> {
    if !claims.scope.split_whitespace().any(|s| s == "kms") {
        return Err(JwtError::ScopeMissing);
    }
    if claims.residency_group != expected_group {
        return Err(JwtError::ResidencyMismatch);
    }
    if !crate::http::is_uuid_v4_lower(&claims.tenant_id) {
        return Err(JwtError::BadTenant);
    }
    Ok(VerifiedKms {
        tenant_id: claims.tenant_id.clone(),
    })
}

/// Verifies identity-minted ES256 kms-cap tokens. Holds a cached JWKS (by the whole set;
/// `find(kid)` per call); a `kid` miss refetches, but no more often than [`MIN_JWKS_REFETCH`]
/// so unknown-`kid` floods can't amplify into per-request fetches. One per broker (`AppState`).
pub struct JwtVerifier {
    issuer: String,
    audience: String,
    expected_group: String,
    /// Explicit JWKS URL override (`VESTA_KMS_JWT_JWKS_URI`); else discovered from the issuer.
    jwks_uri: Option<String>,
    http: reqwest::Client,
    cache: Mutex<JwksCache>,
}

impl JwtVerifier {
    /// Build a verifier for `issuer`/`audience`, enforcing `expected_group`. `jwks_uri` is an
    /// optional override; otherwise the issuer's OIDC discovery document is used.
    #[must_use]
    pub fn new(
        issuer: String,
        audience: String,
        expected_group: String,
        jwks_uri: Option<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        Self {
            issuer,
            audience,
            expected_group,
            jwks_uri,
            http,
            cache: Mutex::new(JwksCache::default()),
        }
    }

    /// Verify a raw bearer token string. On success returns the token's `tenant_id` for the
    /// handler to match against the request path.
    ///
    /// # Errors
    /// See [`JwtError`] — header/signature/claim failures map to `401`, residency/scope to
    /// `403`, a JWKS-fetch failure (identity unreachable) to `502`.
    pub async fn verify(&self, token: &str) -> Result<VerifiedKms, JwtError> {
        let header = decode_header(token).map_err(|e| JwtError::Header(e.to_string()))?;
        if header.alg != Algorithm::ES256 {
            return Err(JwtError::Header("alg must be ES256".into()));
        }
        let kid = header
            .kid
            .ok_or_else(|| JwtError::Header("missing kid".into()))?;
        let key = self.key_for(&kid).await?;

        let mut v = Validation::new(Algorithm::ES256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.validate_nbf = true;
        let data = decode::<Claims>(token, &key, &v).map_err(|_| JwtError::Invalid)?;
        check_claims(&data.claims, &self.expected_group)
    }

    /// A `DecodingKey` for `kid` from the cached JWKS. A miss refetches (a signing key may have
    /// rotated), but at most once per [`MIN_JWKS_REFETCH`]: within that window an unknown `kid`
    /// returns `UnknownKid` WITHOUT a fetch, so a flood of bogus `kid`s can't drive one outbound
    /// JWKS call per request against identity.
    async fn key_for(&self, kid: &str) -> Result<DecodingKey, JwtError> {
        // Fast path + refetch throttle. Guard dropped before any await.
        {
            let cache = self.cache.lock().expect("jwks cache lock");
            if let Some(set) = cache.set.as_ref() {
                if let Some(jwk) = set.find(kid) {
                    return DecodingKey::from_jwk(jwk).map_err(|e| JwtError::Jwks(e.to_string()));
                }
            }
            // Miss: only refetch if we haven't fetched within the throttle window.
            if let Some(last) = cache.last_fetch {
                if last.elapsed() < MIN_JWKS_REFETCH {
                    return Err(JwtError::UnknownKid);
                }
            }
        }
        // Refetch (identity may have rotated its signing key), then look up once more.
        let fetched = self.fetch_jwks().await;
        let mut cache = self.cache.lock().expect("jwks cache lock");
        // Stamp the attempt even on failure, so a down/slow JWKS endpoint is also rate-limited.
        cache.last_fetch = Some(Instant::now());
        let set = fetched?;
        let key = match set.find(kid) {
            Some(jwk) => DecodingKey::from_jwk(jwk).map_err(|e| JwtError::Jwks(e.to_string())),
            None => Err(JwtError::UnknownKid),
        };
        cache.set = Some(set);
        key
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, JwtError> {
        let uri = self.resolve_jwks_uri().await?;
        self.http
            .get(&uri)
            .send()
            .await
            .map_err(|e| JwtError::Jwks(e.to_string()))?
            .error_for_status()
            .map_err(|e| JwtError::Jwks(e.to_string()))?
            .json::<JwkSet>()
            .await
            .map_err(|e| JwtError::Jwks(e.to_string()))
    }

    /// The JWKS URL: the explicit override, else the issuer's OIDC discovery `jwks_uri`.
    async fn resolve_jwks_uri(&self) -> Result<String, JwtError> {
        if let Some(uri) = &self.jwks_uri {
            return Ok(uri.clone());
        }
        let base = self.issuer.trim_end_matches('/');
        let disc = format!("{base}/.well-known/openid-configuration");
        let doc: serde_json::Value = self
            .http
            .get(&disc)
            .send()
            .await
            .map_err(|e| JwtError::Jwks(e.to_string()))?
            .error_for_status()
            .map_err(|e| JwtError::Jwks(e.to_string()))?
            .json()
            .await
            .map_err(|e| JwtError::Jwks(e.to_string()))?;
        doc.get("jwks_uri")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| JwtError::Jwks("discovery document has no jwks_uri".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const TENANT: &str = "11111111-1111-4111-8111-111111111111";

    fn claims(scope: &str, group: &str, tenant: &str) -> Claims {
        Claims {
            scope: scope.to_owned(),
            residency_group: group.to_owned(),
            tenant_id: tenant.to_owned(),
        }
    }

    #[test]
    fn accepts_kms_scope_matching_group_and_uuid_tenant() {
        let v = check_claims(&claims("openid kms backup", "eu", TENANT), "eu").unwrap();
        assert_eq!(v.tenant_id, TENANT);
    }

    #[test]
    fn rejects_when_scope_lacks_kms() {
        // substring "kmsx" must NOT satisfy "kms" (whitespace-tokenised, exact match).
        assert!(matches!(
            check_claims(&claims("openid kmsx", "eu", TENANT), "eu"),
            Err(JwtError::ScopeMissing)
        ));
    }

    #[test]
    fn rejects_cross_region_token() {
        assert!(matches!(
            check_claims(&claims("kms", "uae", TENANT), "eu"),
            Err(JwtError::ResidencyMismatch)
        ));
    }

    #[test]
    fn rejects_non_uuid_or_uppercase_tenant() {
        assert!(matches!(
            check_claims(&claims("kms", "eu", "not-a-uuid"), "eu"),
            Err(JwtError::BadTenant)
        ));
        assert!(matches!(
            check_claims(
                &claims("kms", "eu", "11111111-1111-4111-8111-11111111111A"),
                "eu"
            ),
            Err(JwtError::BadTenant)
        ));
    }

    /// A non-ES256 token is rejected at the header, before any JWKS/network access.
    #[tokio::test]
    async fn rejects_non_es256_alg_without_network() {
        let v = JwtVerifier::new(
            "https://identity.eu.proximi.fi/".into(),
            "vault".into(),
            "eu".into(),
            // unreachable URL — must never be hit, the alg check short-circuits first.
            Some("http://127.0.0.1:1/jwks".into()),
        );
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","typ":"JWT","kid":"k1"}"#);
        let token = format!("{header}.e30.c2ln"); // header.{}.sig
        assert!(matches!(v.verify(&token).await, Err(JwtError::Header(_))));
    }

    /// An ES256 header with no `kid` is rejected before any JWKS/network access.
    #[tokio::test]
    async fn rejects_missing_kid_without_network() {
        let v = JwtVerifier::new(
            "https://identity.eu.proximi.fi/".into(),
            "vault".into(),
            "eu".into(),
            Some("http://127.0.0.1:1/jwks".into()),
        );
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let token = format!("{header}.e30.c2ln");
        assert!(matches!(v.verify(&token).await, Err(JwtError::Header(_))));
    }

    /// A flood of tokens with unknown `kid`s must NOT trigger one JWKS fetch per request:
    /// after the first refetch, further misses are throttled (DoS hardening).
    #[tokio::test]
    async fn unknown_kid_flood_is_rate_limited() {
        use axum::routing::get;
        use axum::Json;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let hits = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/jwks",
            get({
                let hits = hits.clone();
                move || {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({ "keys": [] }))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let v = JwtVerifier::new(
            "https://identity.eu.proximi.fi/".into(),
            "vault".into(),
            "eu".into(),
            Some(format!("http://{addr}/jwks")), // explicit jwks_uri → no discovery hop
        );
        // Valid ES256 header with an unknown kid; signature/claims are never reached (kid misses).
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES256","typ":"JWT","kid":"nope"}"#);
        let token = format!("{header}.e30.c2ln");
        assert!(matches!(v.verify(&token).await, Err(JwtError::UnknownKid)));
        assert!(matches!(v.verify(&token).await, Err(JwtError::UnknownKid)));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "second unknown-kid must be throttled, not a second JWKS fetch"
        );
    }
}
