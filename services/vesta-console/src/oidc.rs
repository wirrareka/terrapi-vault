//! OIDC Relying Party (P1b) — operator login via terrapi-identity.
//!
//! Per `coordination/inbox/identity/vesta-console-oidc-client.md` (BIND STAGED 2026-06-08) and
//! `docs/planning/02-vesta-console.md`, the console is a confidential RP:
//!
//! 1. **`authorization_code` + PKCE (S256)** — the browser is redirected to identity's
//!    `authorization_endpoint`; we keep the `code_verifier` server-side keyed by `state`.
//! 2. **`private_key_jwt` client auth** — the token request carries a `client_assertion` JWT
//!    signed **RS256** with the **console cert's RSA key**, header `kid` = the RFC 7638 thumbprint
//!    identity bound to the client (`Kqlz8…`). NO shared secret. The signing key is the *same* key
//!    presented for broker mTLS (the dual-EKU cert) — one cert, two uses.
//! 3. **`acr=mfa` enforced** — we request `acr_values=mfa` AND reject any id_token whose `acr`
//!    claim is not `mfa` (a view into the vault is super-admin posture, like vulture).
//! 4. id_token verified against identity's JWKS (discovered from the issuer), `iss`/`aud`/`exp`
//!    by jsonwebtoken, `nonce` + `acr` checked here. `sub`/`email` → the single `operator` role.
//!
//! The token/JWKS/discovery hops go to identity over the *public* edge (system roots), NOT the
//! broker mTLS client — so this module holds its own `reqwest::Client`.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vesta_transport::lock::MutexExt;

use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::OidcConfig;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Client-assertion lifetime — short; it is single-use (identity enforces `jti` replay).
const ASSERTION_TTL_SECS: u64 = 300;
/// Minimum spacing between JWKS (re)fetches on a `kid` miss — mirrors `vesta-broker::jwt`, so a
/// flood of unknown-`kid` id_tokens can't amplify 1:1 into outbound fetches against identity.
const MIN_JWKS_REFETCH: Duration = Duration::from_secs(30);
/// id_token signature algs we will verify — **asymmetric only**. This is the allow-list that keeps
/// us safe from alg-confusion (`none`, or an HMAC alg verified against the public key): a header
/// alg outside this set is rejected before any key lookup. Intersected with the OP's advertised
/// `id_token_signing_alg_values_supported` when discovery provides one.
const SUPPORTED_ID_TOKEN_ALGS: [Algorithm; 2] = [Algorithm::ES256, Algorithm::RS256];
/// JOSE `typ` an identity Back-Channel Logout Token carries (BCL 1.0 §2.4). We require it so an
/// id_token/access-token can't be replayed through the logout endpoint (token-type confusion).
const LOGOUT_TOKEN_TYP: &str = "logout+jwt";
/// The REQUIRED `events` member of a Logout Token (BCL 1.0 §2.4).
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// Max accepted age of a Logout Token by its `iat` (delivery + the replay window the caller's
/// seen-`jti` set must cover). A staler token is rejected here.
const LOGOUT_TOKEN_MAX_AGE_SECS: u64 = 300;
/// Allowance for a Logout Token `iat` slightly in the future (clock skew between identity and us).
const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// JOSE `alg` name for the algs we support (to compare against the OP's advertised string list).
fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::ES256 => "ES256",
        Algorithm::RS256 => "RS256",
        _ => "",
    }
}

/// Validate an id_token header `alg` against our supported set ∩ the OP's advertised set. The alg
/// must be asymmetric & supported (rejects `none`/HMAC alg-confusion) and, when `advertised` is
/// non-empty, listed there. Pure — unit-tested. Returns the alg to verify with.
fn accept_id_token_alg(
    advertised: &[String],
    header_alg: Algorithm,
) -> Result<Algorithm, OidcError> {
    if !SUPPORTED_ID_TOKEN_ALGS.contains(&header_alg) {
        return Err(OidcError::IdToken(format!(
            "unsupported id_token alg {header_alg:?} (we verify {SUPPORTED_ID_TOKEN_ALGS:?})"
        )));
    }
    if !advertised.is_empty() && !advertised.iter().any(|a| a == alg_name(header_alg)) {
        return Err(OidcError::IdToken(format!(
            "id_token alg {header_alg:?} not advertised by the issuer ({advertised:?})"
        )));
    }
    Ok(header_alg)
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("config: {0}")]
    Config(String),
    #[error("discovery: {0}")]
    Discovery(String),
    #[error("token endpoint: {0}")]
    Token(String),
    #[error("id_token rejected: {0}")]
    IdToken(String),
    #[error("acr insufficient (mfa required)")]
    AcrInsufficient,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("jwks: {0}")]
    Jwks(String),
    #[error("unknown signing key (kid)")]
    UnknownKid,
    #[error("logout token rejected: {0}")]
    LogoutToken(String),
}

/// The OP endpoints we use, from OIDC discovery (`/.well-known/openid-configuration`).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// The id_token signing algs the OP advertises. We honor this rather than pinning one alg —
    /// identity signs id_tokens with **ES256** (EC P-256), while our *client assertion* is RS256
    /// (our RSA cert). Empty if the OP omits it (then we fall back to [`SUPPORTED_ID_TOKEN_ALGS`]).
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// A started login: the URL to redirect the browser to, plus the per-attempt secrets we stash
/// server-side keyed by `state` until the callback.
pub struct AuthRequest {
    pub url: String,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

/// The authenticated operator (single role on our side; no per-tenant RBAC).
#[derive(Debug, Clone)]
pub struct Operator {
    pub subject: String,
    pub email: Option<String>,
}

/// id_token claims we read (`iss`/`aud`/`exp` are validated by jsonwebtoken, not re-read here).
#[derive(Debug, Deserialize)]
struct IdClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    acr: Option<String>,
    /// OIDC session id (Back-Channel Logout 1.0 §2) — stored with the session so a future Logout
    /// Token's `sid` maps back to it. Present on the *login* id_token; omitted on refresh.
    #[serde(default)]
    sid: Option<String>,
}

/// A validated Back-Channel Logout Token — which session(s) to end. At least one of `sid`/`sub`
/// is guaranteed present (checked in [`check_logout_claims`]); `jti` is for the caller's replay set.
#[derive(Debug, Clone)]
pub struct LogoutToken {
    pub sid: Option<String>,
    pub sub: Option<String>,
    pub jti: String,
}

/// Back-Channel Logout Token claims (BCL 1.0 §2.4). `iss`/`aud` are validated by jsonwebtoken;
/// `iat` freshness, `events`, the prohibited `nonce`, and sid/sub presence are checked here.
#[derive(Debug, Deserialize)]
struct LogoutClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    iat: u64,
    jti: String,
    #[serde(default)]
    events: std::collections::HashMap<String, serde_json::Value>,
    /// MUST be absent in a Logout Token (BCL 1.0 §2.4) — its presence is a rejection.
    #[serde(default)]
    nonce: Option<String>,
}

/// The client-assertion JWT claims (`private_key_jwt`, RFC 7523 §3 / OIDC core §9).
#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    jti: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Default)]
struct JwksCache {
    set: Option<JwkSet>,
    last_fetch: Option<Instant>,
}

/// The OIDC RP. One per console process (`AppState`).
pub struct OidcClient {
    cfg: OidcConfig,
    endpoints: OidcEndpoints,
    signing_key: EncodingKey,
    http: reqwest::Client,
    jwks: Mutex<JwksCache>,
}

impl OidcClient {
    /// Build the RP: parse the cert key (RS256 signer), run OIDC discovery against the issuer.
    ///
    /// # Errors
    /// [`OidcError::Config`] if the signing key can't be read/parsed; [`OidcError::Discovery`] if
    /// the issuer's discovery document is unreachable or missing endpoints.
    pub async fn build(cfg: OidcConfig) -> Result<Self, OidcError> {
        let key_pem = std::fs::read(&cfg.signing_key).map_err(|e| {
            OidcError::Config(format!(
                "read signing key {}: {e}",
                cfg.signing_key.display()
            ))
        })?;
        let signing_key = EncodingKey::from_rsa_pem(&key_pem)
            .map_err(|e| OidcError::Config(format!("signing key not RSA PEM: {e}")))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| OidcError::Config(e.to_string()))?;
        let endpoints = discover(&http, &cfg.issuer).await?;
        Ok(Self {
            cfg,
            endpoints,
            signing_key,
            http,
            jwks: Mutex::new(JwksCache::default()),
        })
    }

    /// Begin a login: mint `state`/`nonce`/PKCE verifier and the authorize URL.
    #[must_use]
    pub fn auth_request(&self) -> AuthRequest {
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let challenge = s256(&verifier);
        let url = build_auth_url(
            &self.endpoints.authorization_endpoint,
            &self.cfg,
            &state,
            &nonce,
            &challenge,
        );
        AuthRequest {
            url,
            state,
            nonce,
            verifier,
        }
    }

    /// Exchange `code` (+ the stored PKCE `verifier`) for tokens and return the operator.
    /// Enforces `nonce` match and `acr == mfa` on the id_token.
    ///
    /// # Errors
    /// [`OidcError`] on a token-endpoint failure, an id_token that fails signature/claims, a nonce
    /// mismatch, or insufficient `acr`.
    pub async fn complete(
        &self,
        code: &str,
        verifier: &str,
        expected_nonce: &str,
    ) -> Result<(Operator, Option<String>), OidcError> {
        let now = now_unix();
        let jti = random_token();
        let assertion = build_client_assertion(
            &self.signing_key,
            &self.cfg.kid,
            &self.cfg.client_id,
            &self.endpoints.token_endpoint,
            now,
            &jti,
        )?;
        let resp = self
            .http
            .post(&self.endpoints.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.cfg.redirect_uri.as_str()),
                ("client_id", self.cfg.client_id.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|e| OidcError::Token(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| OidcError::Token(e.to_string()))?;
        if !status.is_success() {
            return Err(OidcError::Token(format!("{status}: {body}")));
        }
        let tr: TokenResponse =
            serde_json::from_str(&body).map_err(|e| OidcError::Token(e.to_string()))?;
        let (key, alg) = self.signing_key_for(&tr.id_token).await?;
        let claims = decode_id_token(
            &tr.id_token,
            &key,
            alg,
            &self.cfg.issuer,
            &self.cfg.client_id,
        )?;
        let op = check_id_claims(&claims, expected_nonce, &self.cfg.acr)?;
        // Capture the login id_token's `sid` (if any) for Back-Channel Logout mapping.
        Ok((op, claims.sid.clone()))
    }

    /// Verify an OIDC Back-Channel Logout Token (BCL 1.0 §2.4) identity POSTs to our
    /// `backchannel_logout_uri` and return which session(s) to end. Same ES256 key/JWKS as the
    /// id_token, so it reuses the JWKS resolver. Defends against token-type confusion (`typ`),
    /// alg-confusion (asymmetric allow-list), a present `nonce` (prohibited), a missing logout
    /// event, and a stale/future `iat`. `jti` replay is the caller's (it owns the seen-set).
    ///
    /// # Errors
    /// [`OidcError::LogoutToken`] on any validation failure; [`OidcError::Jwks`]/[`OidcError::UnknownKid`]
    /// if the signing key can't be resolved.
    pub async fn verify_logout_token(&self, token: &str) -> Result<LogoutToken, OidcError> {
        // typ MUST be `logout+jwt` — stops an id_token/access-token being replayed here.
        let header = decode_header(token).map_err(|e| OidcError::LogoutToken(e.to_string()))?;
        if header.typ.as_deref() != Some(LOGOUT_TOKEN_TYP) {
            return Err(OidcError::LogoutToken(format!(
                "unexpected typ {:?} (want {LOGOUT_TOKEN_TYP})",
                header.typ
            )));
        }
        let (key, alg) = self.signing_key_for(token).await?;
        let claims = decode_logout_token(token, &key, alg, &self.cfg.issuer, &self.cfg.client_id)?;
        check_logout_claims(&claims, now_unix())
    }

    /// Resolve a token's signing key from identity's JWKS (cache + refetch-on-miss, throttled like
    /// `vesta-broker::jwt`) and the alg to verify it with. Used for both the id_token and the
    /// Back-Channel Logout Token (identity signs both with the same ES256 key/JWKS). The header alg
    /// must be in [`SUPPORTED_ID_TOKEN_ALGS`] (asymmetric only — rejects `none`/HMAC alg-confusion)
    /// and, when the OP advertises `id_token_signing_alg_values_supported`, must be one of those —
    /// NOT a single pinned alg (identity signs ES256; our RSA cert is only for the client assertion).
    async fn signing_key_for(&self, token: &str) -> Result<(DecodingKey, Algorithm), OidcError> {
        let header = decode_header(token).map_err(|e| OidcError::IdToken(e.to_string()))?;
        let alg = accept_id_token_alg(
            &self.endpoints.id_token_signing_alg_values_supported,
            header.alg,
        )?;
        let kid = header
            .kid
            .ok_or_else(|| OidcError::IdToken("missing kid".into()))?;
        {
            let cache = self.jwks.lock_recover();
            if let Some(set) = cache.set.as_ref() {
                if let Some(jwk) = set.find(&kid) {
                    let key =
                        DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Jwks(e.to_string()))?;
                    return Ok((key, alg));
                }
            }
            if let Some(last) = cache.last_fetch {
                if last.elapsed() < MIN_JWKS_REFETCH {
                    return Err(OidcError::UnknownKid);
                }
            }
        }
        let fetched = self.fetch_jwks().await;
        let mut cache = self.jwks.lock_recover();
        cache.last_fetch = Some(Instant::now());
        let set = fetched?;
        let key = match set.find(&kid) {
            Some(jwk) => DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Jwks(e.to_string())),
            None => Err(OidcError::UnknownKid),
        };
        cache.set = Some(set);
        Ok((key?, alg))
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, OidcError> {
        self.http
            .get(&self.endpoints.jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Jwks(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcError::Jwks(e.to_string()))?
            .json::<JwkSet>()
            .await
            .map_err(|e| OidcError::Jwks(e.to_string()))
    }
}

/// OIDC discovery: `{issuer}/.well-known/openid-configuration` → the three endpoints we use.
async fn discover(http: &reqwest::Client, issuer: &str) -> Result<OidcEndpoints, OidcError> {
    let base = issuer.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    http.get(&url)
        .send()
        .await
        .map_err(|e| OidcError::Discovery(e.to_string()))?
        .error_for_status()
        .map_err(|e| OidcError::Discovery(e.to_string()))?
        .json::<OidcEndpoints>()
        .await
        .map_err(|e| OidcError::Discovery(e.to_string()))
}

/// PKCE S256: `BASE64URL(SHA256(ASCII(verifier)))`.
fn s256(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    B64.encode(h.finalize())
}

/// 32 random bytes, base64url — used for `state`, `nonce`, the PKCE verifier, `jti`, session ids.
fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

/// Build the authorize URL (`response_type=code`, PKCE S256, `acr_values=mfa`, scopes, state,
/// nonce). reqwest's `Url` does the query encoding.
fn build_auth_url(
    authorization_endpoint: &str,
    cfg: &OidcConfig,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> String {
    reqwest::Url::parse_with_params(
        authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", cfg.client_id.as_str()),
            ("redirect_uri", cfg.redirect_uri.as_str()),
            ("scope", cfg.scopes.as_str()),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("acr_values", cfg.acr.as_str()),
        ],
    )
    .map_or_else(|_| authorization_endpoint.to_string(), |u| u.to_string())
}

/// Build + sign the `private_key_jwt` client assertion (RS256, header `kid`). `iss == sub ==
/// client_id`, `aud == token_endpoint` (OIDC core §9), short `exp`, random `jti`.
fn build_client_assertion(
    key: &EncodingKey,
    kid: &str,
    client_id: &str,
    token_endpoint: &str,
    now: u64,
    jti: &str,
) -> Result<String, OidcError> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    header.typ = Some("JWT".to_string());
    let claims = AssertionClaims {
        iss: client_id,
        sub: client_id,
        aud: token_endpoint,
        jti,
        iat: now,
        exp: now + ASSERTION_TTL_SECS,
    };
    encode(&header, &claims, key).map_err(|e| OidcError::IdToken(e.to_string()))
}

/// Verify an id_token's signature (with `alg` — ES256 for identity, RS256 supported too) + `iss`/
/// `aud`/`exp` (jsonwebtoken). Pure (no network) given the decoding `key` + `alg`, so the policy is
/// unit-testable. `nonce`/`acr` are checked by [`check_id_claims`].
fn decode_id_token(
    token: &str,
    key: &DecodingKey,
    alg: Algorithm,
    issuer: &str,
    client_id: &str,
) -> Result<IdClaims, OidcError> {
    let mut v = Validation::new(alg);
    v.set_issuer(&[issuer]);
    v.set_audience(&[client_id]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    decode::<IdClaims>(token, key, &v)
        .map(|d| d.claims)
        .map_err(|e| OidcError::IdToken(e.to_string()))
}

/// Enforce `nonce` match + `acr == required_acr` (mfa), then map to the operator. Pure.
fn check_id_claims(
    claims: &IdClaims,
    expected_nonce: &str,
    required_acr: &str,
) -> Result<Operator, OidcError> {
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(OidcError::NonceMismatch);
    }
    if claims.acr.as_deref() != Some(required_acr) {
        return Err(OidcError::AcrInsufficient);
    }
    Ok(Operator {
        subject: claims.sub.clone(),
        email: claims.email.clone(),
    })
}

/// Verify a Logout Token's signature (`alg`) + `iss`/`aud` (jsonwebtoken). Unlike an id_token, a
/// Logout Token carries **`iat`, not `exp`** (BCL 1.0 §2.4) — so `exp` validation is off and
/// freshness is enforced on `iat` by [`check_logout_claims`]. Pure given the decoding key + alg.
fn decode_logout_token(
    token: &str,
    key: &DecodingKey,
    alg: Algorithm,
    issuer: &str,
    client_id: &str,
) -> Result<LogoutClaims, OidcError> {
    let mut v = Validation::new(alg);
    v.set_issuer(&[issuer]);
    v.set_audience(&[client_id]);
    v.validate_exp = false; // logout tokens have no exp; freshness is on iat
    v.set_required_spec_claims(&["iss", "aud"]);
    decode::<LogoutClaims>(token, key, &v)
        .map(|d| d.claims)
        .map_err(|e| OidcError::LogoutToken(e.to_string()))
}

/// Enforce the Logout Token's non-signature rules (BCL 1.0 §2.4) and reduce it to the session
/// target. Pure: `nonce` prohibited, the backchannel-logout `events` member required, `iat` fresh
/// (not older than [`LOGOUT_TOKEN_MAX_AGE_SECS`], not more than [`CLOCK_SKEW_LEEWAY_SECS`] ahead),
/// and at least one of `sid`/`sub` present.
fn check_logout_claims(claims: &LogoutClaims, now: u64) -> Result<LogoutToken, OidcError> {
    if claims.nonce.is_some() {
        return Err(OidcError::LogoutToken("nonce present (prohibited)".into()));
    }
    if !claims.events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
        return Err(OidcError::LogoutToken(
            "missing backchannel-logout event".into(),
        ));
    }
    if now.saturating_sub(claims.iat) > LOGOUT_TOKEN_MAX_AGE_SECS {
        return Err(OidcError::LogoutToken("iat too old".into()));
    }
    if claims.iat.saturating_sub(now) > CLOCK_SKEW_LEEWAY_SECS {
        return Err(OidcError::LogoutToken("iat in the future".into()));
    }
    if claims.sid.is_none() && claims.sub.is_none() {
        return Err(OidcError::LogoutToken("neither sid nor sub".into()));
    }
    Ok(LogoutToken {
        sid: claims.sid.clone(),
        sub: claims.sub.clone(),
        jti: claims.jti.clone(),
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// A throwaway RSA-2048 keypair, generated once per test process (PKCS#8 priv PEM + SPKI pub
    /// PEM). Generated at runtime so no private key is committed to the repo.
    fn test_keys() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYS.get_or_init(|| {
            use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
            let mut rng = rand::rngs::OsRng;
            let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
            let pub_pem = priv_key
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("spki pem")
                .into_bytes();
            let priv_pem = priv_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("pkcs8 pem")
                .as_bytes()
                .to_vec();
            (priv_pem, pub_pem)
        })
    }

    fn test_priv() -> &'static [u8] {
        &test_keys().0
    }
    fn test_pub() -> &'static [u8] {
        &test_keys().1
    }

    /// Minimal decode target for the client-assertion verification test.
    #[derive(serde::Deserialize)]
    struct AssertionEcho {
        iss: String,
        sub: String,
        aud: String,
        jti: String,
    }

    fn test_cfg() -> OidcConfig {
        OidcConfig {
            issuer: "https://identity.eu.proximi.fi/".into(),
            client_id: "vesta-console".into(),
            redirect_uri: "https://vesta-console.eu.proximi.fi/api/v1/auth/callback".into(),
            signing_key: "unused-in-pure-tests".into(),
            kid: "Kqlz8rNa3Cwz5pUtS1JamQj5f4vd7AmaMeXC1LOyJ88".into(),
            scopes: "openid profile email".into(),
            acr: "mfa".into(),
        }
    }

    fn sign_id_token(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test".into());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(test_priv()).unwrap(),
        )
        .unwrap()
    }

    /// A throwaway EC P-256 keypair (PKCS#8 priv PEM + SPKI pub PEM) — identity's id_token alg.
    fn ec_keys() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYS.get_or_init(|| {
            use base64::Engine as _;
            let kp = rcgen::KeyPair::generate().expect("ec keygen"); // defaults to ECDSA P-256
            let priv_pem = kp.serialize_pem().into_bytes();
            let der = kp.public_key_der();
            let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
            let pub_pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
                .into_bytes();
            (priv_pem, pub_pem)
        })
    }

    /// Sign an id_token with **ES256** (identity's real alg) — the exact path that the RS256
    /// hardcode broke at the live round-trip.
    fn sign_id_token_es256(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("eu-01KSNB0RQ".into());
        encode(
            &header,
            claims,
            &EncodingKey::from_ec_pem(&ec_keys().0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        // Known RFC 7636 Appendix B vector.
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(s256(v), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn auth_url_carries_pkce_acr_and_core_params() {
        let url = build_auth_url(
            "https://identity.eu.proximi.fi/authorize",
            &test_cfg(),
            "STATE1",
            "NONCE1",
            "CHALLENGE1",
        );
        for needle in [
            "response_type=code",
            "client_id=vesta-console",
            "code_challenge=CHALLENGE1",
            "code_challenge_method=S256",
            "acr_values=mfa",
            "state=STATE1",
            "nonce=NONCE1",
            "scope=openid+profile+email",
        ] {
            assert!(url.contains(needle), "auth url missing `{needle}`: {url}");
        }
    }

    #[test]
    fn client_assertion_is_rs256_kid_and_verifies() {
        let key = EncodingKey::from_rsa_pem(test_priv()).unwrap();
        let jwt = build_client_assertion(
            &key,
            "Kqlz8rNa3Cwz5pUtS1JamQj5f4vd7AmaMeXC1LOyJ88",
            "vesta-console",
            "https://identity.eu.proximi.fi/token",
            1_000_000_000,
            "jti-1",
        )
        .unwrap();

        let header = decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(
            header.kid.as_deref(),
            Some("Kqlz8rNa3Cwz5pUtS1JamQj5f4vd7AmaMeXC1LOyJ88")
        );

        // Verifies against the matching public key, with the expected iss/sub/aud.
        let mut v = Validation::new(Algorithm::RS256);
        v.set_audience(&["https://identity.eu.proximi.fi/token"]);
        v.set_issuer(&["vesta-console"]);
        v.validate_exp = false; // fixed iat/exp in the past; we only assert structure here
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        let d = decode::<AssertionEcho>(&jwt, &DecodingKey::from_rsa_pem(test_pub()).unwrap(), &v)
            .unwrap();
        assert_eq!(d.claims.iss, "vesta-console");
        assert_eq!(d.claims.sub, "vesta-console");
        assert_eq!(d.claims.aud, "https://identity.eu.proximi.fi/token");
        assert_eq!(d.claims.jti, "jti-1");
    }

    #[test]
    fn id_token_happy_path_yields_operator() {
        let token = sign_id_token(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "vesta-console",
            "sub": "op-123",
            "email": "op@proximi.io",
            "nonce": "NONCE1",
            "acr": "mfa",
            "exp": now_unix() + 3600,
        }));
        let key = DecodingKey::from_rsa_pem(test_pub()).unwrap();
        let claims = decode_id_token(
            &token,
            &key,
            Algorithm::RS256,
            "https://identity.eu.proximi.fi/",
            "vesta-console",
        )
        .unwrap();
        let op = check_id_claims(&claims, "NONCE1", "mfa").unwrap();
        assert_eq!(op.subject, "op-123");
        assert_eq!(op.email.as_deref(), Some("op@proximi.io"));
    }

    #[test]
    fn id_token_without_mfa_acr_is_rejected() {
        let token = sign_id_token(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "vesta-console",
            "sub": "op-123",
            "nonce": "NONCE1",
            "acr": "pwd",
            "exp": now_unix() + 3600,
        }));
        let key = DecodingKey::from_rsa_pem(test_pub()).unwrap();
        let claims = decode_id_token(
            &token,
            &key,
            Algorithm::RS256,
            "https://identity.eu.proximi.fi/",
            "vesta-console",
        )
        .unwrap();
        assert!(matches!(
            check_id_claims(&claims, "NONCE1", "mfa"),
            Err(OidcError::AcrInsufficient)
        ));
    }

    #[test]
    fn id_token_missing_acr_is_rejected() {
        let token = sign_id_token(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "vesta-console",
            "sub": "op-123",
            "nonce": "NONCE1",
            "exp": now_unix() + 3600,
        }));
        let key = DecodingKey::from_rsa_pem(test_pub()).unwrap();
        let claims = decode_id_token(
            &token,
            &key,
            Algorithm::RS256,
            "https://identity.eu.proximi.fi/",
            "vesta-console",
        )
        .unwrap();
        assert!(matches!(
            check_id_claims(&claims, "NONCE1", "mfa"),
            Err(OidcError::AcrInsufficient)
        ));
    }

    #[test]
    fn id_token_nonce_mismatch_is_rejected() {
        let token = sign_id_token(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "vesta-console",
            "sub": "op-123",
            "nonce": "OTHER",
            "acr": "mfa",
            "exp": now_unix() + 3600,
        }));
        let key = DecodingKey::from_rsa_pem(test_pub()).unwrap();
        let claims = decode_id_token(
            &token,
            &key,
            Algorithm::RS256,
            "https://identity.eu.proximi.fi/",
            "vesta-console",
        )
        .unwrap();
        assert!(matches!(
            check_id_claims(&claims, "NONCE1", "mfa"),
            Err(OidcError::NonceMismatch)
        ));
    }

    #[test]
    fn id_token_wrong_audience_is_rejected() {
        let token = sign_id_token(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "some-other-client",
            "sub": "op-123",
            "nonce": "NONCE1",
            "acr": "mfa",
            "exp": now_unix() + 3600,
        }));
        let key = DecodingKey::from_rsa_pem(test_pub()).unwrap();
        // Wrong aud fails at signature/claims decode (before nonce/acr).
        assert!(matches!(
            decode_id_token(
                &token,
                &key,
                Algorithm::RS256,
                "https://identity.eu.proximi.fi/",
                "vesta-console"
            ),
            Err(OidcError::IdToken(_))
        ));
    }

    /// Regression for the live-login bug: identity signs id_tokens with **ES256**, so the verifier
    /// must accept + verify ES256 (the RS256 hardcode rejected every real login at this step).
    #[test]
    fn id_token_es256_verifies_end_to_end() {
        let token = sign_id_token_es256(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "vesta-console",
            "sub": "op-es",
            "email": "op@proximi.io",
            "nonce": "NONCE1",
            "acr": "mfa",
            "exp": now_unix() + 3600,
        }));
        let alg = accept_id_token_alg(&["ES256".to_string()], decode_header(&token).unwrap().alg)
            .unwrap();
        assert_eq!(alg, Algorithm::ES256);
        let key = DecodingKey::from_ec_pem(&ec_keys().1).unwrap();
        let claims = decode_id_token(
            &token,
            &key,
            Algorithm::ES256,
            "https://identity.eu.proximi.fi/",
            "vesta-console",
        )
        .unwrap();
        let op = check_id_claims(&claims, "NONCE1", "mfa").unwrap();
        assert_eq!(op.subject, "op-es");
    }

    #[test]
    fn accept_alg_honors_advertised_set() {
        // identity advertises only ES256 → ES256 ok, RS256 (our client-assertion alg) NOT for the
        // id_token, since it isn't advertised.
        let adv = vec!["ES256".to_string()];
        assert_eq!(
            accept_id_token_alg(&adv, Algorithm::ES256).unwrap(),
            Algorithm::ES256
        );
        assert!(matches!(
            accept_id_token_alg(&adv, Algorithm::RS256),
            Err(OidcError::IdToken(_))
        ));
    }

    #[test]
    fn accept_alg_rejects_confusion_algs() {
        // none/HMAC are never in SUPPORTED_ID_TOKEN_ALGS → rejected even if (absurdly) advertised.
        for bad in [Algorithm::HS256, Algorithm::HS384] {
            assert!(matches!(
                accept_id_token_alg(&[], bad),
                Err(OidcError::IdToken(_))
            ));
        }
    }

    #[test]
    fn accept_alg_empty_advertised_falls_back_to_supported() {
        // No advertised list (OP omitted it) → accept any supported alg.
        assert_eq!(
            accept_id_token_alg(&[], Algorithm::ES256).unwrap(),
            Algorithm::ES256
        );
        assert_eq!(
            accept_id_token_alg(&[], Algorithm::RS256).unwrap(),
            Algorithm::RS256
        );
    }

    // --- Back-Channel Logout Token ---------------------------------------------------

    /// Sign a Logout Token with **ES256** + header `typ=logout+jwt` (identity's real shape).
    fn sign_logout_token_es256(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("eu-01KSNB0RQ".into());
        header.typ = Some("logout+jwt".into());
        encode(
            &header,
            claims,
            &EncodingKey::from_ec_pem(&ec_keys().0).unwrap(),
        )
        .unwrap()
    }

    fn logout_claims(
        iat: u64,
        sid: Option<&str>,
        sub: Option<&str>,
        nonce: Option<&str>,
        with_event: bool,
    ) -> LogoutClaims {
        let mut events = std::collections::HashMap::new();
        if with_event {
            events.insert(BACKCHANNEL_LOGOUT_EVENT.to_string(), serde_json::json!({}));
        }
        LogoutClaims {
            sub: sub.map(String::from),
            sid: sid.map(String::from),
            iat,
            jti: "jti-1".into(),
            events,
            nonce: nonce.map(String::from),
        }
    }

    #[test]
    fn logout_claims_happy_path() {
        let now = now_unix();
        let lt = check_logout_claims(
            &logout_claims(now, Some("sid-1"), Some("op-1"), None, true),
            now,
        )
        .unwrap();
        assert_eq!(lt.sid.as_deref(), Some("sid-1"));
        assert_eq!(lt.sub.as_deref(), Some("op-1"));
        assert_eq!(lt.jti, "jti-1");
    }

    #[test]
    fn logout_nonce_is_rejected() {
        let now = now_unix();
        assert!(matches!(
            check_logout_claims(&logout_claims(now, Some("s"), None, Some("n"), true), now),
            Err(OidcError::LogoutToken(_))
        ));
    }

    #[test]
    fn logout_missing_event_is_rejected() {
        let now = now_unix();
        assert!(matches!(
            check_logout_claims(&logout_claims(now, Some("s"), None, None, false), now),
            Err(OidcError::LogoutToken(_))
        ));
    }

    #[test]
    fn logout_stale_iat_is_rejected() {
        let now = now_unix();
        let stale = now - (LOGOUT_TOKEN_MAX_AGE_SECS + 10);
        assert!(matches!(
            check_logout_claims(&logout_claims(stale, Some("s"), None, None, true), now),
            Err(OidcError::LogoutToken(_))
        ));
    }

    #[test]
    fn logout_future_iat_is_rejected() {
        let now = now_unix();
        let future = now + CLOCK_SKEW_LEEWAY_SECS + 10;
        assert!(matches!(
            check_logout_claims(&logout_claims(future, Some("s"), None, None, true), now),
            Err(OidcError::LogoutToken(_))
        ));
    }

    #[test]
    fn logout_requires_sid_or_sub() {
        let now = now_unix();
        assert!(matches!(
            check_logout_claims(&logout_claims(now, None, None, None, true), now),
            Err(OidcError::LogoutToken(_))
        ));
    }

    #[test]
    fn logout_token_es256_decodes_end_to_end() {
        let now = now_unix();
        let token = sign_logout_token_es256(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "vesta-console",
            "sub": "op-es",
            "sid": "sid-es",
            "iat": now,
            "jti": "jti-xyz",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }));
        let key = DecodingKey::from_ec_pem(&ec_keys().1).unwrap();
        let claims = decode_logout_token(
            &token,
            &key,
            Algorithm::ES256,
            "https://identity.eu.proximi.fi/",
            "vesta-console",
        )
        .unwrap();
        let lt = check_logout_claims(&claims, now).unwrap();
        assert_eq!(lt.sid.as_deref(), Some("sid-es"));
        assert_eq!(lt.jti, "jti-xyz");
    }

    /// A wrong-audience Logout Token fails at signature/claims decode (before the BCL checks).
    #[test]
    fn logout_token_wrong_audience_is_rejected() {
        let now = now_unix();
        let token = sign_logout_token_es256(&serde_json::json!({
            "iss": "https://identity.eu.proximi.fi/",
            "aud": "some-other-client",
            "sid": "sid-es",
            "iat": now,
            "jti": "jti-xyz",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }));
        let key = DecodingKey::from_ec_pem(&ec_keys().1).unwrap();
        assert!(matches!(
            decode_logout_token(
                &token,
                &key,
                Algorithm::ES256,
                "https://identity.eu.proximi.fi/",
                "vesta-console"
            ),
            Err(OidcError::LogoutToken(_))
        ));
    }
}
