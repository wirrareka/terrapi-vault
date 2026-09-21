//! Bounded operation envelopes for an already-authenticated operator transport.
//! No sockets, plaintext listener, authentication defaults, or legacy TLS dispatch.
//! The host must authenticate the peer and authorize the pinned scope/manifest before
//! calling `dispatch`. A successful response proves only local snapshot progress.
use super::*;

pub const MAX_REQUEST_BYTES: usize = MAX_PAGE_BYTES + 128;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    Begin { manifest: Manifest },
    Page { page: Page },
    Finish { manifest_digest: String },
}
impl Request {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Begin { manifest } => {
                manifest.encode()?;
            }
            Self::Page { page } => {
                page.encode()?;
            }
            Self::Finish { manifest_digest } => {
                ensure(
                    manifest_digest.len() == 64
                        && manifest_digest
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                    "invalid finish manifest digest",
                )?;
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure(
            bytes.len() <= MAX_REQUEST_BYTES,
            "SQL snapshot request exceeds wire limit",
        )?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure(
            bytes.len() <= MAX_REQUEST_BYTES,
            "SQL snapshot request exceeds wire limit",
        )?;
        let request: Self = serde_json::from_slice(bytes)?;
        request.validate()?;
        Ok(request)
    }
}
/// Caller-owned connection and authority; this function cannot establish either.
pub fn dispatch<S: Schema>(
    c: &Connection,
    schema: &S,
    scope: &Scope,
    request: &Request,
) -> Result<Progress> {
    request.validate()?;
    match request {
        Request::Begin { manifest } => begin(c, schema, scope, manifest),
        Request::Page { page } => receive(c, schema, scope, page),
        Request::Finish { manifest_digest } => {
            let p = progress(c)?.ok_or("no SQL snapshot transfer")?;
            ensure(
                p.manifest.digest()? == *manifest_digest,
                "stale SQL snapshot finish request",
            )?;
            finish(c, schema, scope)
        }
    }
}
