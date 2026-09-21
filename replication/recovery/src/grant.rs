//! Recovery-only ES256 verifier. Verification is not runtime write authority.
//! Context is supplied by a trusted management integration, never by the token.
use super::model::{Event, Id, Model, Plan};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::signature;
use serde::Deserialize;

pub struct Reservation {
    pub plan: Plan,
    pub grant_id: Id,
    pub fencing_ref: Id,
}

/// Explicit application trust domain. Never populate it from an incoming token.
/// No default profile is provided: an integration must choose its issuer/audience/type.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub issuer: String,
    pub audience: String,
    pub token_type: String,
}

impl Profile {
    /// Structural validation only; callers still establish trust in these values.
    pub fn validate(&self) -> Result<(), &'static str> {
        if [&self.issuer, &self.audience, &self.token_type]
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > 512)
        {
            Err("invalid trusted profile")
        } else {
            Ok(())
        }
    }
}

pub struct Context {
    pub profile: Profile,
    /// Already trusted, current recovery-only key set; no URL lookup.
    pub keys: Vec<(String, Vec<u8>)>,
    /// Trusted Unix seconds; the integration must establish clock trust.
    pub now: u64,
    pub max_lifetime: u64,
    pub install_id: String,
    pub region: String,
    /// Fresh trusted external reservation; not an assertion supplied by an API caller.
    pub reservation: Option<Reservation>,
    /// Integration-verified isolation result. The verifier does not perform fencing.
    pub fencing_confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    version: u32,
    iss: String,
    aud: String,
    action: String,
    install_id: String,
    region: String,
    grant_id: Id,
    iat: u64,
    nbf: u64,
    exp: u64,
    plan: Plan,
    fencing_ref: Id,
}

/// A verification result, deliberately not deserializable or a write permit.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedGrant {
    pub plan: Plan,
    pub grant_id: Id,
}

fn decode(segment: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = B64.decode(segment).map_err(|_| "encoding")?;
    if segment.is_empty() || B64.encode(&bytes) != segment {
        return Err("noncanonical encoding");
    }
    Ok(bytes)
}

pub fn verify(token: &str, ctx: &Context) -> Result<VerifiedGrant, &'static str> {
    // Protocol limits precede token parsing and allocations.
    if token.len() > 16 * 1024 {
        return Err("token limit");
    }
    let mut parts = token.split('.');
    let h = parts.next().ok_or("header")?;
    let p = parts.next().ok_or("payload")?;
    let s = parts.next().ok_or("signature")?;
    if parts.next().is_some() || h.len() > 1024 {
        return Err("compact shape");
    }
    let key = trusted_key(h, ctx)?;
    let sig = decode(s)?;
    if sig.len() != 64 {
        return Err("signature shape");
    }
    // ES256 JWS uses fixed-width R||S, not ASN.1 DER. Verify original bytes.
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &sig)
        .map_err(|_| "signature")?;
    let grant = validate_claims(p, ctx)?;
    Ok(VerifiedGrant {
        plan: grant.plan,
        grant_id: grant.grant_id,
    })
}

/// Validate an unsigned draft before reserving it; never returns VerifiedGrant.
pub fn validate_draft(input: &str, ctx: &Context) -> Result<(), &'static str> {
    if input.len() > 16 * 1024 - 87 {
        return Err("draft limit");
    }
    let (h, p) = input.split_once('.').ok_or("draft shape")?;
    if h.len() > 1024 || p.contains('.') {
        return Err("draft shape");
    }
    trusted_key(h, ctx)?;
    validate_claims(p, ctx)?;
    Ok(())
}

fn trusted_key<'a>(h: &str, ctx: &'a Context) -> Result<&'a [u8], &'static str> {
    ctx.profile.validate()?;
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| "header schema")?;
    if header.alg != "ES256" || header.typ != ctx.profile.token_type || header.kid.is_empty() {
        return Err("header purpose");
    }
    let mut matching = ctx.keys.iter().filter(|(kid, _)| kid == &header.kid);
    let (_, key) = matching.next().ok_or("untrusted key")?;
    if matching.next().is_some() {
        return Err("ambiguous key");
    }
    Ok(key)
}

fn validate_claims(p: &str, ctx: &Context) -> Result<Claims, &'static str> {
    let grant: Claims = serde_json::from_slice(&decode(p)?).map_err(|_| "claim schema")?;
    if grant.version != 1
        || grant.iss != ctx.profile.issuer
        || grant.aud != ctx.profile.audience
        || grant.action != "replace_primary"
    {
        return Err("claim purpose");
    }
    if ctx.install_id.is_empty()
        || ctx.region.is_empty()
        || grant.install_id != ctx.install_id
        || grant.region != ctx.region
    {
        return Err("scope");
    }
    let lifetime = grant.exp.checked_sub(grant.iat).ok_or("time order")?;
    if lifetime == 0
        || lifetime > ctx.max_lifetime
        || grant.iat > grant.nbf
        || grant.nbf > ctx.now
        || ctx.now >= grant.exp
    {
        return Err("time window");
    }
    let reserved = ctx.reservation.as_ref().ok_or("authority unavailable")?;
    if !ctx.fencing_confirmed
        || grant.fencing_ref == [0; 32]
        || grant.grant_id == [0; 32]
        || grant.plan != reserved.plan
        || grant.grant_id != reserved.grant_id
        || grant.fencing_ref != reserved.fencing_ref
    {
        return Err("authority binding");
    }
    Model::new(grant.plan.baseline.clone()).step(&grant.plan, Event::Authorize)?;
    Ok(grant)
}
