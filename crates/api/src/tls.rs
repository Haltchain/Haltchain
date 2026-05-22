//! mTLS support for the HaltChain API server.
//!
//! Set all three env vars to enable mutual TLS:
//!   HALTCHAIN_TLS_CERT      — path to server PEM certificate chain
//!   HALTCHAIN_TLS_KEY       — path to server PEM private key
//!   HALTCHAIN_TLS_CLIENT_CA — path to PEM CA bundle used to verify client certs
//!
//! ## SPIFFE / SPIRE integration
//!
//! When running inside a SPIRE-managed cluster the SVID is refreshed automatically.
//! Point the three env vars above at the SPIRE agent's x.509 SVID output files:
//!
//! ```text
//! HALTCHAIN_TLS_CERT=/run/spire/svids/svid.pem
//! HALTCHAIN_TLS_KEY=/run/spire/svids/svid_key.pem
//! HALTCHAIN_TLS_CLIENT_CA=/run/spire/svids/bundle.pem
//! ```
//!
//! Start `SpiffeReloader::spawn()` after building the initial acceptor to
//! automatically reload certificates when SPIRE rotates the SVID (typically
//! every hour).  The reloader polls every `HALTCHAIN_SVID_POLL_SECS` (default 60).
//!
//! If the vars are absent the server binds plain HTTP (dev-mode).

use std::{fs, io::BufReader, sync::Arc, time::SystemTime};

use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

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
            // TLS env vars are set but config is broken — fail loudly so the
            // operator fixes certs before going live.
            panic!("Failed to initialise TLS (env vars present but invalid): {e}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SPIFFE SVID rotation watcher
// ─────────────────────────────────────────────────────────────────────────────

/// Watches SPIRE-managed SVID PEM files and rebuilds the `TlsAcceptor` when
/// the certificate file changes on disk.
///
/// SPIRE rotates X.509 SVIDs (default TTL: 1 h) by writing new PEM files to the
/// path configured in the SPIRE agent's `SVIDStore "disk"` plugin, or via a
/// Kubernetes projected volume managed by cert-manager + SPIFFE issuer.
///
/// The reloader polls every `poll_secs` (default: 60 s) which is well under
/// the typical SPIRE SVID TTL.
///
/// Usage:
/// ```rust
/// let acceptor = Arc::new(parking_lot::RwLock::new(tls_acceptor_from_env()));
/// SpiffeReloader::spawn(acceptor.clone());
/// ```
pub struct SpiffeReloader {
    cert_path: String,
    key_path: String,
    ca_path: Option<String>,
    poll_secs: u64,
    acceptor: Arc<parking_lot::RwLock<Option<TlsAcceptor>>>,
}

impl SpiffeReloader {
    /// Create a reloader from environment variables and spawn it as a background task.
    ///
    /// Does nothing if the TLS env vars are not set.
    pub fn spawn(acceptor: Arc<parking_lot::RwLock<Option<TlsAcceptor>>>) {
        let cert = match std::env::var("HALTCHAIN_TLS_CERT") {
            Ok(v) => v,
            Err(_) => return, // TLS not configured — nothing to rotate
        };
        let key = match std::env::var("HALTCHAIN_TLS_KEY") {
            Ok(v) => v,
            Err(_) => return,
        };
        let ca = std::env::var("HALTCHAIN_TLS_CLIENT_CA").ok();
        let poll_secs: u64 = std::env::var("HALTCHAIN_SVID_POLL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let reloader = SpiffeReloader {
            cert_path: cert,
            key_path: key,
            ca_path: ca,
            poll_secs,
            acceptor,
        };

        tokio::spawn(async move { reloader.run().await });
    }

    async fn run(self) {
        info!(
            poll_secs = self.poll_secs,
            cert = %self.cert_path,
            "SPIFFE SVID reloader started"
        );

        let mut last_mtime = self.cert_mtime();

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(self.poll_secs)).await;

            let mtime = self.cert_mtime();
            if mtime == last_mtime {
                continue; // cert unchanged — nothing to do
            }
            last_mtime = mtime;

            info!("SVID cert file changed — reloading TLS acceptor");
            match build_tls_acceptor(&self.cert_path, &self.key_path, self.ca_path.as_deref()) {
                Ok(new_acceptor) => {
                    *self.acceptor.write() = Some(new_acceptor);
                    info!("TLS acceptor reloaded with new SVID");
                }
                Err(e) => {
                    warn!("Failed to reload TLS acceptor after SVID rotation: {e}");
                    // Keep the previous acceptor — connections continue until the old SVID expires.
                }
            }
        }
    }

    fn cert_mtime(&self) -> Option<SystemTime> {
        fs::metadata(&self.cert_path)
            .ok()
            .and_then(|m| m.modified().ok())
    }
}
