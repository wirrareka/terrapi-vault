//! Enterprise-PKI issuance anchor — **Phase 1: the leaf-issuance engine** (not yet wired to a
//! route; see the follow-ups below).
//!
//! For enterprise on-prem installs (the client owns the infra and may cut operator access) the
//! trust root must be the operator's, not the client's, and operability is *leased*: an
//! operator-signed **license** gates issuance of short-lived service certs — no license → issuance
//! stops → certs expire ≤48h → controlled degradation (dead-man via PKI expiry). Design:
//! `coordination/decisions/enterprise-trust-operability.md` + `conventions/mtls.md`; vault is the
//! **issuance anchor** (`coordination/inbox/vault/infra-enterprise-pki-sealed-intermediate-and-license-gated-issuance.md`).
//!
//! What this module does (the design-stable core): hold the operator-delivered, **name-constrained
//! per-install Issuing Intermediate** (`*.<install-id>.proximi.internal`) and sign **short-lived
//! (≤48h) leaf certs** under it — server/client profiles, SANs validated against the install
//! namespace server-side (belt-and-suspenders to the cert's own `nameConstraints`). The Operator
//! Root never touches the broker; the intermediate is delivered already signed by it.
//!
//! Phase 2 (gated on the operator license-token format, which demon/operator own — still open):
//! - persist the sealed intermediate as an at-rest row (SSH-CA precedent, `ssh_ca.rs`) + load on unseal;
//! - the **license gate** — verify a current operator-signed license (pinned trust *set*, reloadable)
//!   before each (re)issue, fail-closed when absent/expired-past-grace (the dead-man's teeth);
//! - the install-scoped route `POST /v1/pki/issue {svc,role,san[]}` + `GET /v1/pki/ca` (cap-gated),
//!   DTOs, audit (`pki.issue`), config, OpenAPI.
//!
//! Revocation is **TTL-only** (no CRL/OCSP) by design — rotation + the license gate are the levers.

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use time::OffsetDateTime;

/// The internal mTLS domain (`conventions/mtls.md`). Every install cert lives under
/// `<svc>.<install-id>.proximi.internal`.
const DOMAIN: &str = "proximi.internal";
/// Hard ceiling on a leaf's lifetime (`decisions/enterprise-trust-operability.md`: ≤48h, the
/// dead-man window). A requested TTL above this is clamped, never an error.
pub const MAX_CERT_TTL_SECS: u64 = 48 * 60 * 60;
/// Backdate `not_before` slightly so a freshly issued cert is already valid under modest clock
/// skew between the broker and the consuming service.
const NOT_BEFORE_SKEW_SECS: u64 = 300;

/// What a leaf is allowed to do. mTLS (`conventions/mtls.md`): a server cert carries EKU
/// `serverAuth`; a client cert **must** carry `clientAuth`; a service that is both gets both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Server,
    Client,
    ServerAndClient,
}

impl Profile {
    fn ekus(self) -> Vec<ExtendedKeyUsagePurpose> {
        match self {
            Profile::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
            Profile::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
            Profile::ServerAndClient => vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    /// The intermediate cert/key PEM could not be parsed, or a leaf could not be signed.
    #[error("pki: {0}")]
    Rcgen(String),
    /// A requested DNS SAN is outside this install's namespace — refused before signing so the
    /// broker never even attempts a cert the intermediate's `nameConstraints` would reject.
    #[error("pki: SAN '{0}' is outside install namespace *.{1}.{DOMAIN}")]
    SanOutOfInstall(String, String),
}

impl From<rcgen::Error> for PkiError {
    fn from(e: rcgen::Error) -> Self {
        PkiError::Rcgen(e.to_string())
    }
}

/// The DNS suffix every leaf in `install_id` must sit under (leading dot prevents a
/// `evilacme.proximi.internal` suffix-confusion match against install `acme`).
fn install_suffix(install_id: &str) -> String {
    format!(".{install_id}.{DOMAIN}")
}

/// Reject any DNS SAN not strictly within `*.<install-id>.proximi.internal`. IP SANs (the
/// service's WG /32) are always allowed. This is a server-side guard in addition to the
/// intermediate's own `nameConstraints` — defence in depth, and a clear `400` rather than a
/// silent constraint failure deep in the signer.
pub fn validate_dns_sans(install_id: &str, dns_sans: &[String]) -> Result<(), PkiError> {
    let suffix = install_suffix(install_id);
    for name in dns_sans {
        // must end with the dotted suffix AND carry a non-empty leftmost label
        if !name.ends_with(&suffix) || name.len() <= suffix.len() {
            return Err(PkiError::SanOutOfInstall(
                name.clone(),
                install_id.to_owned(),
            ));
        }
    }
    Ok(())
}

/// A leaf-cert request (the route handler builds this from `{svc, role, san[]}`).
pub struct LeafRequest<'a> {
    /// Subject CN, e.g. `web.acme-corp.proximi.internal`.
    pub common_name: &'a str,
    /// DNS SANs — each validated against the install namespace.
    pub dns_sans: &'a [String],
    /// IP SANs — the service's WG address(es).
    pub ip_sans: &'a [IpAddr],
    pub profile: Profile,
    /// Requested lifetime; clamped to `[1, MAX_CERT_TTL_SECS]`.
    pub ttl_secs: u64,
}

/// A freshly issued leaf + its key and the chain to present. Holds a private key — no `Debug`.
pub struct IssuedCert {
    pub certificate_pem: String,
    pub private_key_pem: String,
    /// The issuing intermediate PEM, so the consumer can present `leaf || intermediate`.
    pub chain_pem: String,
    /// Absolute expiry, unix seconds (= granted, after clamping).
    pub not_after: u64,
}

/// The per-install issuing CA: the operator-delivered, name-constrained intermediate. Signs
/// leaves; cannot name another install. No `Debug` (holds the intermediate private key).
pub struct PkiCa {
    /// The original operator-Root-signed intermediate PEM — served by `GET /v1/pki/ca` and used
    /// as the chain. (NOT the reconstruction below, which is only an rcgen signing handle.)
    intermediate_pem: String,
    /// rcgen signing handle: a reconstruction of the intermediate whose `params` (DN, key id)
    /// drive the leaf's issuer + AKI. The leaf is signed by `issuer_key` (the real intermediate
    /// key) and carries the real intermediate's DN/AKI, so it chains to the real intermediate.
    issuer_cert: Certificate,
    issuer_key: KeyPair,
    install_id: String,
}

impl PkiCa {
    /// Load from the operator-delivered intermediate cert + key PEM. `install_id` is the broker's
    /// per-install constant — it is NOT taken from any request.
    ///
    /// # Errors
    /// `Rcgen` if either PEM fails to parse.
    pub fn from_pem(
        intermediate_cert_pem: &str,
        intermediate_key_pem: &str,
        install_id: &str,
    ) -> Result<Self, PkiError> {
        let issuer_key = KeyPair::from_pem(intermediate_key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(intermediate_cert_pem)?;
        let issuer_cert = params.self_signed(&issuer_key)?;
        Ok(Self {
            intermediate_pem: intermediate_cert_pem.to_owned(),
            issuer_cert,
            issuer_key,
            install_id: install_id.to_owned(),
        })
    }

    /// The intermediate trust anchor PEM (`GET /v1/pki/ca`).
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        &self.intermediate_pem
    }

    /// Sign a short-lived leaf for `req`. The leaf carries a freshly generated P-256 key (returned
    /// alongside), the requested SANs, the profile's EKU, and a clamped ≤48h validity window.
    ///
    /// # Errors
    /// `SanOutOfInstall` if a DNS SAN escapes the install namespace; `Rcgen` on a signing failure.
    pub fn issue(&self, req: &LeafRequest, now_unix: u64) -> Result<IssuedCert, PkiError> {
        validate_dns_sans(&self.install_id, req.dns_sans)?;
        let ttl = req.ttl_secs.clamp(1, MAX_CERT_TTL_SECS);
        let not_before = now_unix.saturating_sub(NOT_BEFORE_SKEW_SECS);
        let not_after = now_unix.saturating_add(ttl);

        // DNS SANs are built by rcgen from strings; append the IP SANs.
        let mut params = CertificateParams::new(req.dns_sans.to_vec())?;
        for ip in req.ip_sans {
            params.subject_alt_names.push(SanType::IpAddress(*ip));
        }
        params.not_before = unix_to_offsetdatetime(not_before)?;
        params.not_after = unix_to_offsetdatetime(not_after)?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = req.profile.ekus();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, req.common_name);
        params.distinguished_name = dn;

        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.issuer_cert, &self.issuer_key)?;

        Ok(IssuedCert {
            certificate_pem: leaf.pem(),
            private_key_pem: leaf_key.serialize_pem(),
            chain_pem: self.intermediate_pem.clone(),
            not_after,
        })
    }
}

fn unix_to_offsetdatetime(secs: u64) -> Result<OffsetDateTime, PkiError> {
    OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(i64::MAX))
        .map_err(|e| PkiError::Rcgen(format!("bad timestamp: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::*;

    const INSTALL: &str = "acme-corp";

    /// Stand-in for the operator-delivered intermediate: a self-signed, name-constrained CA
    /// (the operator Root would sign this offline; for the engine, self-signed is equivalent —
    /// only its DN + key drive leaf issuance).
    fn test_intermediate(install_id: &str) -> (String, String) {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("{install_id} issuing intermediate"),
        );
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        p.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName(format!(
                "{install_id}.{DOMAIN}"
            ))],
            excluded_subtrees: vec![],
        });
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn ca() -> PkiCa {
        let (cert, key) = test_intermediate(INSTALL);
        PkiCa::from_pem(&cert, &key, INSTALL).unwrap()
    }

    #[test]
    fn validate_dns_sans_enforces_install_namespace() {
        assert!(validate_dns_sans(INSTALL, &["web.acme-corp.proximi.internal".into()]).is_ok());
        // wrong install
        assert!(validate_dns_sans(INSTALL, &["x.other.proximi.internal".into()]).is_err());
        // suffix-confusion: no leading-dot boundary
        assert!(validate_dns_sans(INSTALL, &["evilacme-corp.proximi.internal".into()]).is_err());
        // bare apex (no leftmost label)
        assert!(validate_dns_sans(INSTALL, &["acme-corp.proximi.internal".into()]).is_err());
    }

    #[test]
    fn issues_server_leaf_within_install() {
        let now = 1_780_000_000;
        let dns = ["web.acme-corp.proximi.internal".to_string()];
        let ips = ["10.200.0.55".parse::<IpAddr>().unwrap()];
        let issued = ca()
            .issue(
                &LeafRequest {
                    common_name: "web.acme-corp.proximi.internal",
                    dns_sans: &dns,
                    ip_sans: &ips,
                    profile: Profile::Server,
                    ttl_secs: 24 * 3600,
                },
                now,
            )
            .unwrap();
        assert_eq!(issued.not_after, now + 24 * 3600);
        assert!(issued.private_key_pem.contains("PRIVATE KEY"));

        let (_, pem) = parse_x509_pem(issued.certificate_pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        // validity window matches the grant (≈; not_before is backdated by the skew)
        assert_eq!(
            cert.validity().not_after.timestamp(),
            i64::try_from(now + 24 * 3600).unwrap()
        );
        assert!(cert.validity().not_before.timestamp() <= i64::try_from(now).unwrap());

        let mut saw_eku = false;
        let mut saw_san_dns = false;
        let mut saw_san_ip = false;
        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::ExtendedKeyUsage(eku) => {
                    saw_eku = true;
                    assert!(eku.server_auth, "server profile → serverAuth");
                    assert!(!eku.client_auth, "server profile → NOT clientAuth");
                }
                ParsedExtension::SubjectAlternativeName(san) => {
                    for gn in &san.general_names {
                        match gn {
                            GeneralName::DNSName(d) => {
                                if *d == "web.acme-corp.proximi.internal" {
                                    saw_san_dns = true;
                                }
                            }
                            GeneralName::IPAddress(_) => saw_san_ip = true,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        assert!(saw_eku && saw_san_dns && saw_san_ip);
        // chains to the (real) intermediate: issuer DN names the install
        assert!(cert.issuer().to_string().contains(INSTALL));
        // ca_pem is the original intermediate, not the signing reconstruction
        assert!(issued.chain_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn client_profile_sets_clientauth_only() {
        let dns = ["demon.acme-corp.proximi.internal".to_string()];
        let issued = ca()
            .issue(
                &LeafRequest {
                    common_name: "demon.acme-corp.proximi.internal",
                    dns_sans: &dns,
                    ip_sans: &[],
                    profile: Profile::Client,
                    ttl_secs: 3600,
                },
                1_780_000_000,
            )
            .unwrap();
        let (_, pem) = parse_x509_pem(issued.certificate_pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        let eku = cert
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::ExtendedKeyUsage(eku) => Some(eku),
                _ => None,
            })
            .expect("EKU present");
        assert!(eku.client_auth && !eku.server_auth);
    }

    #[test]
    fn ttl_is_clamped_to_48h() {
        let now = 1_780_000_000;
        let dns = ["web.acme-corp.proximi.internal".to_string()];
        let issued = ca()
            .issue(
                &LeafRequest {
                    common_name: "web.acme-corp.proximi.internal",
                    dns_sans: &dns,
                    ip_sans: &[],
                    profile: Profile::Server,
                    ttl_secs: 10 * 24 * 3600, // 10 days requested
                },
                now,
            )
            .unwrap();
        assert_eq!(issued.not_after, now + MAX_CERT_TTL_SECS, "clamped to ≤48h");
    }

    #[test]
    fn refuses_san_outside_install() {
        let dns = ["web.other-install.proximi.internal".to_string()];
        let err = ca().issue(
            &LeafRequest {
                common_name: "web.other-install.proximi.internal",
                dns_sans: &dns,
                ip_sans: &[],
                profile: Profile::Server,
                ttl_secs: 3600,
            },
            1_780_000_000,
        );
        assert!(matches!(err, Err(PkiError::SanOutOfInstall(_, _))));
    }
}
