//! Object-store presigned-PUT-URL signer (the DO Spaces publish path for proximiio-outer-map).
//!
//! DO Spaces has **no key-management API** and only coarse per-bucket key scoping, so we can't
//! mint short-lived per-tenant keys the way the OpenSearch cred engine mints users (see the
//! coordination thread `inbox/vault/proximiio-outer-map-object-storage-creds.md`). Instead the
//! broker holds **one** long-lived per-group Spaces RWD key and, per request, signs a **short-TTL
//! presigned `PUT` URL scoped to exactly one object key** (AWS SigV4 query-param presigning, which
//! the S3-compatible Spaces endpoint accepts). The per-tenant, write-only, single-object scoping
//! that the DO key itself cannot express lives **here, in the signature** — the URL authorises a
//! `PUT` to one key and nothing else, and expires.
//!
//! - The signing key (Spaces secret) **never leaves the broker** — only the signed URL does, and
//!   it can do nothing but `PUT` that one object until `expires`.
//! - A presigned URL **cannot be revoked** (revocation = rotating the underlying key, which voids
//!   all outstanding URLs). So this is a stateless signer: no lease, no `lease_id`, no
//!   renew/revoke. The short TTL is the only bound.
//! - Residency: the bucket/region/key are per-instance config, so an `eu` signer can only ever
//!   sign `eu`-bucket URLs (structural air-gap, same as every other broker op).
//!
//! Configured from env (`VESTA_OBJECT_STORE_*`); absent → the op is unconfigured (`503`). The
//! secret comes from env exactly like the OpenSearch admin credential (`opensearch.rs`).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "s3";
const DEFAULT_TTL_SECS: u64 = 300;
const DEFAULT_MAX_TTL_SECS: u64 = 900;

/// Which object a presign request targets. Selects a server-constructed key template; the
/// client never supplies a path (no traversal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The tile archive: `t/<tenant>/<map_id>/<version>.pmtiles`.
    Archive,
    /// The mutable pointer the readers follow: `t/<tenant>/<map_id>/latest.json`.
    Manifest,
}

/// Signs short-TTL presigned `PUT` URLs for one per-group Spaces bucket. No `Debug` (holds the
/// Spaces secret).
pub struct ObjectStoreSigner {
    access_key: String,
    secret_key: String,
    region: String,
    /// Virtual-hosted bucket host the URL targets and SigV4 signs as the `host` header, e.g.
    /// `proximi-outermap-eu.fra1.digitaloceanspaces.com`. Per-instance config, so an `eu`
    /// signer can only ever sign `eu`-bucket URLs (the residency air-gap; the `:group` path
    /// segment is also checked by the `Group` extractor before this is reached).
    host: String,
    default_ttl_secs: u64,
    max_ttl_secs: u64,
}

impl ObjectStoreSigner {
    /// Build from `VESTA_OBJECT_STORE_*` env, or `None` if `VESTA_OBJECT_STORE_KEY` is unset
    /// (the op then reports `503 not_configured`).
    ///
    /// # Errors
    /// `String` if the key is set but a required var (`SECRET`/`REGION`/`BUCKET`) is missing.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(access_key) = std::env::var("VESTA_OBJECT_STORE_KEY") else {
            return Ok(None);
        };
        let req = |k: &str| {
            std::env::var(k).map_err(|_| format!("VESTA_OBJECT_STORE_KEY set but {k} missing"))
        };
        let secret_key = req("VESTA_OBJECT_STORE_SECRET")?;
        let region = req("VESTA_OBJECT_STORE_REGION")?;
        let bucket = req("VESTA_OBJECT_STORE_BUCKET")?;
        // Virtual-hosted host; overridable for non-DO S3-compatible endpoints / tests.
        let host = std::env::var("VESTA_OBJECT_STORE_HOST")
            .unwrap_or_else(|_| format!("{bucket}.{region}.digitaloceanspaces.com"));
        let default_ttl_secs = env_u64("VESTA_OBJECT_STORE_TTL_SECS", DEFAULT_TTL_SECS);
        let max_ttl_secs = env_u64("VESTA_OBJECT_STORE_MAX_TTL_SECS", DEFAULT_MAX_TTL_SECS);

        Ok(Some(Self {
            access_key,
            secret_key,
            region,
            host,
            default_ttl_secs,
            max_ttl_secs,
        }))
    }

    /// Clamp a requested TTL into `[1, max_ttl_secs]`, defaulting when `None`.
    #[must_use]
    pub fn clamp_ttl(&self, requested: Option<u64>) -> u64 {
        requested
            .unwrap_or(self.default_ttl_secs)
            .clamp(1, self.max_ttl_secs)
    }

    /// The object key for `kind`. Server-constructed from validated components — the caller
    /// supplies no path, so there is no traversal. The in-bucket layout needs no `<group>`
    /// segment: the bucket is already per-group.
    #[must_use]
    pub fn object_key(kind: Kind, tenant_id: &str, map_id: &str, version: &str) -> String {
        match kind {
            Kind::Archive => format!("t/{tenant_id}/{map_id}/{version}.pmtiles"),
            Kind::Manifest => format!("t/{tenant_id}/{map_id}/latest.json"),
        }
    }

    /// Sign a presigned URL for `method` (`"PUT"` to publish, `"GET"` to read) on `key`, valid
    /// `ttl_secs` from `now_unix`. Returns the URL and its absolute expiry (unix seconds).
    /// `now_unix` is injected (not read from the clock) so the signing is deterministic and
    /// unit-testable. The `Range` header is not signed (`SignedHeaders=host`), so a presigned
    /// `GET` URL serves range requests unchanged.
    #[must_use]
    pub fn presign(&self, method: &str, key: &str, now_unix: u64, ttl_secs: u64) -> (String, u64) {
        // SigV4 timestamps. Derive from the injected unix time so tests are deterministic.
        let dt = OffsetDateTime::from_unix_timestamp(i64::try_from(now_unix).unwrap_or(0))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let amz_date = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            dt.year(),
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        let date_stamp = &amz_date[..8]; // YYYYMMDD

        let scope = format!("{date_stamp}/{}/{SERVICE}/aws4_request", self.region);
        let credential = format!("{}/{scope}", self.access_key);

        // Canonical query string: the five SigV4 query params, each side percent-encoded
        // (slashes in `credential` become %2F), keys in ascending order. The five keys below
        // are already alphabetically ordered (Algorithm < Credential < Date < Expires < SignedHeaders).
        let ttl = ttl_secs.to_string();
        let pairs = [
            ("X-Amz-Algorithm", ALGORITHM),
            ("X-Amz-Credential", &credential),
            ("X-Amz-Date", &amz_date),
            ("X-Amz-Expires", &ttl),
            ("X-Amz-SignedHeaders", "host"),
        ];
        let canonical_query = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_uri = canonical_path(key);
        // Canonical request: signed headers = just `host`; payload unsigned (the client streams
        // the body straight to/from Spaces). Layout: METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED\nPAYLOADHASH.
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
            host = self.host,
        );

        let hashed_request = hex(&sha256(canonical_request.as_bytes()));
        let string_to_sign = format!("{ALGORITHM}\n{amz_date}\n{scope}\n{hashed_request}");

        let signing_key = self.signing_key(date_stamp);
        let signature = hex(&hmac(&signing_key, string_to_sign.as_bytes()));

        let url = format!(
            "https://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
            host = self.host,
        );
        (url, now_unix.saturating_add(ttl_secs))
    }

    /// SigV4 signing key: HMAC chain `secret → date → region → service → "aws4_request"`.
    fn signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, SERVICE.as_bytes());
        hmac(&k_service, b"aws4_request")
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// HMAC-SHA256. HMAC accepts any key length, so the `new_from_slice` never errors here.
fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// RFC 3986 percent-encoding as AWS SigV4 requires: leave the unreserved set
/// (`A-Za-z0-9-._~`) as-is, percent-encode everything else (upper-case hex). When
/// `encode_slash` is false, `/` is preserved (used for path segments).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Canonical URI for SigV4: the absolute path with each segment percent-encoded but the `/`
/// separators preserved. Our keys are `[A-Za-z0-9._-/]` only, so this is near-identity, but
/// we encode properly so any future key shape stays correct.
fn canonical_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 1);
    out.push('/');
    out.push_str(&uri_encode(key, false));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> ObjectStoreSigner {
        ObjectStoreSigner {
            access_key: "DO00ACCESSKEYEXAMPLE".into(),
            secret_key: "spaces-secret-key-example-0000000000000000".into(),
            region: "fra1".into(),
            host: "proximi-outermap-eu.fra1.digitaloceanspaces.com".into(),
            default_ttl_secs: 300,
            max_ttl_secs: 900,
        }
    }

    const TENANT: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn object_keys_are_server_constructed_per_kind() {
        assert_eq!(
            ObjectStoreSigner::object_key(Kind::Archive, TENANT, "berlin", "2026-06-06"),
            format!("t/{TENANT}/berlin/2026-06-06.pmtiles")
        );
        assert_eq!(
            ObjectStoreSigner::object_key(Kind::Manifest, TENANT, "berlin", "2026-06-06"),
            format!("t/{TENANT}/berlin/latest.json")
        );
    }

    /// Pins the SigV4 signing-key derivation (HMAC chain `secret→date→region→service→
    /// aws4_request`) against an independently computed reference (Python stdlib
    /// `hmac`/`hashlib`) for the canonical AWS example inputs. If this drifts, the SigV4
    /// signature is wrong and presigned URLs would be rejected by Spaces.
    #[test]
    fn signing_key_matches_independent_reference() {
        // inputs: secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY, date=20120215,
        // region=us-east-1, service=iam.
        let k_date = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", b"20120215");
        let k_region = hmac(&k_date, b"us-east-1");
        let k_service = hmac(&k_region, b"iam");
        let k_signing = hmac(&k_service, b"aws4_request");
        assert_eq!(
            hex(&k_signing),
            "004aa806e13dae88b9032d9261bcb04c67d023afadd221e6b0d206e1760e0b5e"
        );
        // And the signer's own s3/fra1 chain stays stable (regression guard).
        assert_eq!(
            hex(&signer().signing_key("20260606")),
            "bf80f03971021c147ebb55e34a3c4ba2651bedaf323b8932ef71c4d0c257f90d"
        );
    }

    #[test]
    fn presign_is_deterministic_and_well_formed() {
        let s = signer();
        let key = ObjectStoreSigner::object_key(Kind::Archive, TENANT, "berlin", "v1");
        let now = 1_780_000_000; // fixed
        let (url1, exp1) = s.presign("PUT", &key, now, 300);
        let (url2, exp2) = s.presign("PUT", &key, now, 300);
        assert_eq!(url1, url2, "same inputs → identical signed URL");
        assert_eq!(exp1, exp2);
        assert_eq!(exp1, now + 300);
        assert!(url1.starts_with("https://proximi-outermap-eu.fra1.digitaloceanspaces.com/t/"));
        assert!(url1.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url1.contains("X-Amz-Expires=300"));
        assert!(url1.contains("X-Amz-SignedHeaders=host"));
        // credential slashes are percent-encoded in the query
        assert!(url1.contains("X-Amz-Credential=DO00ACCESSKEYEXAMPLE%2F"));
        // signature is 64 lowercase hex chars
        let sig = url1.split("X-Amz-Signature=").nth(1).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn different_tenant_or_kind_changes_url_and_signature() {
        let s = signer();
        let now = 1_780_000_000;
        let a = s.presign(
            "PUT",
            &ObjectStoreSigner::object_key(Kind::Archive, TENANT, "berlin", "v1"),
            now,
            300,
        );
        let other = "22222222-2222-4222-8222-222222222222";
        let b = s.presign(
            "PUT",
            &ObjectStoreSigner::object_key(Kind::Archive, other, "berlin", "v1"),
            now,
            300,
        );
        let m = s.presign(
            "PUT",
            &ObjectStoreSigner::object_key(Kind::Manifest, TENANT, "berlin", "v1"),
            now,
            300,
        );
        assert_ne!(a.0, b.0, "tenant changes the signed path");
        assert_ne!(a.0, m.0, "kind changes the signed path");
    }

    #[test]
    fn get_and_put_presign_differ_by_method() {
        // The HTTP method is part of the SigV4 canonical request, so a GET presign on the
        // same key has a distinct signature — a read URL can't be replayed as a write.
        let s = signer();
        let key = ObjectStoreSigner::object_key(Kind::Archive, TENANT, "berlin", "v1");
        let now = 1_780_000_000;
        let (put, _) = s.presign("PUT", &key, now, 300);
        let (get, _) = s.presign("GET", &key, now, 300);
        assert_ne!(put, get, "method changes the signature");
        // both still target the same object key
        let base = "https://proximi-outermap-eu.fra1.digitaloceanspaces.com/";
        assert!(put.starts_with(&format!("{base}{key}?")));
        assert!(get.starts_with(&format!("{base}{key}?")));
    }

    #[test]
    fn clamp_ttl_defaults_and_bounds() {
        let s = signer();
        assert_eq!(s.clamp_ttl(None), 300);
        assert_eq!(s.clamp_ttl(Some(60)), 60);
        assert_eq!(s.clamp_ttl(Some(100_000)), 900, "clamped to max");
        assert_eq!(s.clamp_ttl(Some(0)), 1, "clamped to min 1");
    }

    #[test]
    fn uri_encode_handles_slash_and_reserved() {
        assert_eq!(uri_encode("a/b c", true), "a%2Fb%20c");
        assert_eq!(uri_encode("a/b c", false), "a/b%20c");
        assert_eq!(uri_encode("Az0-._~", true), "Az0-._~");
    }
}
