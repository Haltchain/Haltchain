//! mTLS support for the HaltChain API server.
//!
//! Set all three env vars to enable mutual TLS:
//!   HALTCHAIN_TLS_CERT      — path to server PEM certificate chain
//!   HALTCHAIN_TLS_KEY       — path to server PEM private key
//!   HALTCHAIN_TLS_CLIENT_CA — path to PEM CA bundle used to verify client certs
//!
//! If the vars are absent the server binds plain HTTP (dev-mode).

use std::{fs, io::BufReader, sync::Arc};

use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::TlsAcceptor;
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS config error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no private key found in key file")]
    NoKey,
    #[error("client CA cert parse error")]
    CaCert,
    #[error("client verifier build error: {0}")]
    Verifier(rustls::server::VerifierBuilderError),
}

/// Reads PEM certs from a file.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let f = fs::File::open(path)?;
    let mut reader = BufReader::new(f);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(TlsError::Io)
}

/// Reads the first private key (PKCS8 or RSA) from a PEM file.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let f = fs::File::open(path)?;
    let reader = BufReader::new(f);
    // Try PKCS8 first, then RSA
    let bytes = fs::read(path)?;
    let mut buf = BufReader::new(bytes.as_slice());
    if let Some(k) = pkcs8_private_keys(&mut buf).flatten().next() {
        return Ok(PrivateKeyDer::Pkcs8(k));
    }
    let mut buf2 = BufReader::new(bytes.as_slice());
    if let Some(k) = rsa_private_keys(&mut buf2).flatten().next() {
        return Ok(PrivateKeyDer::Pkcs1(k));
    }
    drop(reader);
    Err(TlsError::NoKey)
}

/// Build a `TlsAcceptor` from PEM files.
///
/// When `ca_path` is `Some`, client certificate verification is required (mTLS).
/// When it is `None`, only server-side TLS is configured.
pub fn build_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    ca_path: Option<&str>,
) -> Result<TlsAcceptor, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = if let Some(ca) = ca_path {
        // mTLS: require and verify client cert
        let ca_certs = load_certs(ca)?;
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).map_err(|_| TlsError::CaCert)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(TlsError::Verifier)?;
        info!("mTLS enabled: client certificate verification required");
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        info!("TLS enabled (server-only, no client cert required)");
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Returns a `TlsAcceptor` if the TLS env vars are configured, or `None` for plain HTTP.
pub fn tls_acceptor_from_env() -> Option<TlsAcceptor> {
    let cert = std::env::var("HALTCHAIN_TLS_CERT").ok()?;
    let key = std::env::var("HALTCHAIN_TLS_KEY").ok()?;
    let ca = std::env::var("HALTCHAIN_TLS_CLIENT_CA").ok();
    match build_tls_acceptor(&cert, &key, ca.as_deref()) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::error!("Failed to initialise TLS: {e}");
            std::process::exit(1);
        }
    }
}
