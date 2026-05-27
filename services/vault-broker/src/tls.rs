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
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// Serve `app` over mTLS until a shutdown signal. Each accepted connection must present a
/// client cert signed by the Root CA in `tls.client_ca`; its SAN is injected as a
/// [`ClientSan`] extension.
///
/// # Errors
/// Fails if the TLS material cannot be loaded or the listener errors fatally.
pub async fn serve(listener: TcpListener, app: Router, tls: &TlsPaths) -> io::Result<()> {
    let config = build_server_config(tls).map_err(io::Error::other)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    eprintln!("vault-broker: mTLS termination active (client-cert required vs Root CA)");

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("vault-broker: shutdown signal received");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (tcp, _peer) = accepted?;
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move { serve_conn(acceptor, app, tcp).await });
            }
        }
    }
}

/// Handle one connection: complete the handshake, lift the verified SAN, serve requests.
async fn serve_conn(acceptor: TlsAcceptor, app: Router, tcp: tokio::net::TcpStream) {
    let Ok(stream) = acceptor.accept(tcp).await else {
        return; // handshake failed (no/invalid client cert) — drop the connection
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
    rustls_pemfile::certs(&mut BufReader::new(&data[..]))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs {}: {e}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(&data[..]))
        .map_err(|e| format!("parse key {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key in {}", path.display()))
}

/// First DNS SAN of a DER-encoded X.509 cert (the daemon identity → role key).
fn san_from_cert(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|gn| match gn {
        GeneralName::DNSName(d) => Some((*d).to_owned()),
        _ => None,
    })
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
