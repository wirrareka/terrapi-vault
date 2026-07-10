//! mTLS-over-WireGuard termination (production daemon auth).
//!
//! rustls server with **required** client-certificate verification against the fleet
//! Root CA. After each handshake the verified peer cert's SAN is extracted and injected
//! as a [`ClientSan`] request extension, so `auth::Principal` maps it to a role without
//! the handlers ever touching transport details. The connection is only reachable on the
//! WG mesh (defence in depth: WG peer + a valid client cert).
//!
//! axum's `Router` is served over a manual `tokio-rustls` + `hyper-util` accept loop
//! because the verified SAN must be read from the TLS connection per-connection — higher
//! level helpers do not expose it.

use crate::auth::ClientSan;
use crate::config::TlsPaths;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// Bound a TLS handshake: a peer that connects but stalls the handshake must not pin a task
/// forever. Generous for a WG RTT; a real client completes in well under this.
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Ceiling on concurrently-served connections. Bounds task/FD growth from a flood of slow or
/// looping handshakes (defence in depth on top of the WG-only exposure). New connections over
/// the cap are dropped at accept rather than spawned.
const MAX_CONCURRENT_CONNS: usize = 512;

/// Serve `app` over mTLS until a shutdown signal. Each accepted connection must present a
/// client cert signed by the Root CA in `tls.client_ca`; its SAN is injected as a
/// [`ClientSan`] extension.
///
/// # Errors
/// Fails if the TLS material cannot be loaded or the listener errors fatally.
pub async fn serve(listener: TcpListener, app: Router, tls: &TlsPaths) -> io::Result<()> {
    let config = build_server_config(tls).map_err(io::Error::other)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    eprintln!("vesta-broker: mTLS termination active (client-cert required vs Root CA)");

    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("vesta-broker: shutdown signal received");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (tcp, _peer) = accepted?;
                // At the connection cap → drop the new TCP conn rather than spawn unboundedly.
                let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
                    eprintln!("vesta-broker: connection cap ({MAX_CONCURRENT_CONNS}) reached; dropping new connection");
                    drop(tcp);
                    continue;
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit; // released when the connection ends
                    serve_conn(acceptor, app, tcp).await;
                });
            }
        }
    }
}

/// Handle one connection: complete the handshake, lift the verified SAN, serve requests.
async fn serve_conn(acceptor: TlsAcceptor, app: Router, tcp: tokio::net::TcpStream) {
    // Bound the handshake so a peer that stalls mid-handshake can't pin this task forever.
    let accept = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        acceptor.accept(tcp),
    )
    .await;
    let Ok(Ok(stream)) = accept else {
        return; // handshake failed (no/invalid client cert) or timed out — drop the connection
    };
    // Extract the verified peer SAN before the stream is moved into the hyper IO.
    let san = {
        let (_io, conn) = stream.get_ref();
        conn.peer_certificates()
            .and_then(<[_]>::first)
            .and_then(|c| san_from_cert(c.as_ref()))
    };

    let io = TokioIo::new(stream);
    let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        if let Some(san) = san.clone() {
            req.extensions_mut().insert(ClientSan(san));
        }
        let app = app.clone();
        async move { app.oneshot(req.map(axum::body::Body::new)).await }
    });

    let _ = Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await;
}

/// Build the rustls server config: require a client cert verified against the Root CA
/// bundle, present the broker's own server cert/key.
fn build_server_config(tls: &TlsPaths) -> Result<ServerConfig, String> {
    let certs = load_certs(&tls.cert)?;
    let key = load_key(&tls.key)?;

    let mut roots = RootCertStore::empty();
    for ca in load_certs(&tls.client_ca)? {
        roots
            .add(ca)
            .map_err(|e| format!("client CA bundle: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("client verifier: {e}"))?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls protocol versions: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server cert/key: {e}"))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs {}: {e}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    PrivateKeyDer::from_pem_slice(&data).map_err(|e| format!("parse key {}: {e}", path.display()))
}

/// The single DNS SAN of a DER-encoded X.509 cert (the daemon identity → role key). Fleet client
/// certs MUST carry exactly one `dNSName` SAN: with several, which one is "the identity" is
/// ambiguous and the role mapping becomes unpredictable, so this fails closed (returns `None` →
/// no `ClientSan` extension → the principal extractor 401s) rather than silently picking one.
fn san_from_cert(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    let mut dns = san.value.general_names.iter().filter_map(|gn| match gn {
        GeneralName::DNSName(d) => Some((*d).to_owned()),
        _ => None,
    });
    let first = dns.next()?;
    if dns.next().is_some() {
        eprintln!(
            "vesta-broker: client cert presents multiple dNSName SANs — refusing (fleet certs \
             must carry exactly one SAN so the role mapping is unambiguous)"
        );
        return None;
    }
    Some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_dns_san_from_cert() {
        let ck = rcgen::generate_simple_self_signed(vec!["demon.eu.proximi.internal".to_string()])
            .unwrap();
        let san = san_from_cert(ck.cert.der());
        assert_eq!(san.as_deref(), Some("demon.eu.proximi.internal"));
    }

    #[test]
    fn multi_san_cert_is_refused() {
        // A cert with two dNSName SANs is ambiguous for role mapping → no SAN derived.
        let ck = rcgen::generate_simple_self_signed(vec![
            "demon.eu.proximi.internal".to_string(),
            "other.eu.proximi.internal".to_string(),
        ])
        .unwrap();
        assert_eq!(san_from_cert(ck.cert.der()), None);
    }

    #[test]
    fn loads_pem_cert_and_key() {
        let ck = rcgen::generate_simple_self_signed(vec!["broker.eu.proximi.internal".to_string()])
            .unwrap();
        let dir = std::env::temp_dir();
        let cert_p = dir.join(format!("vb-tls-cert-{}.pem", std::process::id()));
        let key_p = dir.join(format!("vb-tls-key-{}.pem", std::process::id()));
        std::fs::write(&cert_p, ck.cert.pem()).unwrap();
        std::fs::write(&key_p, ck.key_pair.serialize_pem()).unwrap();

        assert_eq!(load_certs(&cert_p).unwrap().len(), 1);
        assert!(load_key(&key_p).is_ok());

        let _ = std::fs::remove_file(&cert_p);
        let _ = std::fs::remove_file(&key_p);
    }

    /// A CA-signed leaf; server leaves also carry the 127.0.0.1 IP SAN.
    fn leaf(
        sans: Vec<String>,
        with_ip: bool,
        ca_cert: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
    ) -> (String, String) {
        let mut p = rcgen::CertificateParams::new(sans).expect("leaf params");
        if with_ip {
            p.subject_alt_names
                .push(rcgen::SanType::IpAddress("127.0.0.1".parse().expect("ip")));
        }
        p.is_ca = rcgen::IsCa::NoCa;
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let cert = p.signed_by(&key, ca_cert, ca_key).expect("sign leaf");
        (cert.pem(), key.serialize_pem())
    }

    /// The full production auth path over a real socket: rustls server with required
    /// client-cert verification vs a fleet root CA, SAN lifted from the verified peer cert
    /// and mapped to a role. A registered SAN reaches cap-gated handlers; a trusted-but-
    /// unregistered SAN is 403; a client with no cert fails the handshake outright.
    #[tokio::test(flavor = "multi_thread")]
    async fn mtls_end_to_end_maps_client_san_to_role() {
        use crate::auth::{Capability, RolePrincipal};
        use crate::config::BrokerConfig;
        use crate::state::AppState;
        use std::collections::HashMap;

        // Both ring (reqwest) and aws-lc-rs are linked here, so rustls can't auto-pick a
        // process default; install it like main.rs does at boot.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Fleet root CA.
        let mut ca_p = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "test fleet root");
        ca_p.distinguished_name = dn;
        ca_p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_p.self_signed(&ca_key).expect("ca cert");

        let (server_pem, server_key) = leaf(vec!["localhost".into()], true, &ca_cert, &ca_key);
        let (client_pem, client_key) = leaf(
            vec!["demon-system.eu.proximi.internal".into()],
            false,
            &ca_cert,
            &ca_key,
        );
        let (rogue_pem, rogue_key) = leaf(
            vec!["rogue.eu.proximi.internal".into()],
            false,
            &ca_cert,
            &ca_key,
        );

        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let write = |name: &str, data: &str| {
            let p = dir.join(format!("vb-e2e-{pid}-{name}.pem"));
            std::fs::write(&p, data).expect("write pem");
            p
        };
        let tls = TlsPaths {
            cert: write("srv-cert", &server_pem),
            key: write("srv-key", &server_key),
            client_ca: write("ca", &ca_cert.pem()),
        };

        // Production-shaped state: dev off, one registered SAN with only the ssh-ca cap.
        let mut roles = HashMap::new();
        roles.insert(
            "demon-system.eu.proximi.internal".to_string(),
            RolePrincipal {
                role: "demon-system".into(),
                caps: [Capability::SshCa].into_iter().collect(),
                ssh_principals: None,
            },
        );
        struct NullSink;
        impl vesta_transport::audit::AuditSink for NullSink {
            fn emit(&self, _event: &vesta_transport::audit::AuditEvent) {}
        }
        let cfg = BrokerConfig {
            bind: "127.0.0.1:0".parse().expect("addr"),
            residency_group: vesta_transport::ResidencyGroup::Eu,
            node: "test".into(),
            hardening: crate::config::Hardening::default(),
            audit_path: dir.join(format!("vb-e2e-{pid}-audit.jsonl")),
            store_path: dir.join(format!("vb-e2e-{pid}-store.sqlcipher")),
            snapshot_dir: dir.clone(),
            roles,
            allow_insecure_dev: false,
            tls: None,
            kms_jwt: None,
            identity_kms: None,
        };
        let state = AppState::new(cfg, None, Arc::new(NullSink));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = crate::http::router(state);
        let tls_paths = tls.clone();
        let server = tokio::spawn(async move { serve(listener, app, &tls_paths).await });

        let ca_root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).expect("ca root");
        let client = |identity: Option<(&str, &str)>| {
            let mut b = reqwest::Client::builder()
                .use_rustls_tls()
                .tls_built_in_root_certs(false)
                .add_root_certificate(ca_root.clone())
                // Connect by hostname so the server cert's `localhost` DNS SAN verifies.
                .resolve("localhost", addr)
                .timeout(Duration::from_secs(5));
            if let Some((cert, key)) = identity {
                let mut pem = cert.as_bytes().to_vec();
                pem.push(b'\n');
                pem.extend_from_slice(key.as_bytes());
                b = b.identity(reqwest::Identity::from_pem(&pem).expect("identity"));
            }
            b.build().expect("client")
        };
        let base = format!("https://localhost:{}", addr.port());

        // Registered SAN: unauthenticated route works, and the ssh-ca cap authorises —
        // 503 `sealed` (not 401/403) proves SAN → role → cap all passed.
        let c = client(Some((&client_pem, &client_key)));
        let r = c
            .get(format!("{base}/v1/sys/seal-status"))
            .send()
            .await
            .expect("seal-status");
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.expect("json");
        assert_eq!(body["sealed"], true);
        let r = c
            .get(format!("{base}/v1/eu/ssh/ca"))
            .send()
            .await
            .expect("ssh/ca");
        assert_eq!(
            r.status(),
            503,
            "registered SAN passes authz, hits the seal"
        );

        // Trusted (fleet-CA-signed) but unregistered SAN → 403, never 401.
        let c = client(Some((&rogue_pem, &rogue_key)));
        let r = c
            .get(format!("{base}/v1/eu/ssh/ca"))
            .send()
            .await
            .expect("rogue request");
        assert_eq!(r.status(), 403, "unregistered SAN is forbidden");

        // No client cert at all → the handshake itself is refused.
        let c = client(None);
        assert!(
            c.get(format!("{base}/v1/sys/seal-status"))
                .send()
                .await
                .is_err(),
            "handshake without a client cert must fail"
        );

        server.abort();
        for p in [&tls.cert, &tls.key, &tls.client_ca] {
            let _ = std::fs::remove_file(p);
        }
    }
}
