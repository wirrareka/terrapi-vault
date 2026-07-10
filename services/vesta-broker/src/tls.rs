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
}
