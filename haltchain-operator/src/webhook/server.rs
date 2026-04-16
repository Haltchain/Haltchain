//! Mutating admission webhook server.
//!
//! Serves on :8443 (TLS) and handles POST /mutate-pods.
//! The TLS certificate/key pair is expected at the paths set by
//! HALTCHAIN_WEBHOOK_TLS_CERT and HALTCHAIN_WEBHOOK_TLS_KEY env vars.

use std::net::SocketAddr;

use axum::{routing::post, Router};
use anyhow::Result;
use tower::Service;
use tracing::info;

use super::sidecar_injector::handle_mutate;

pub async fn run() -> Result<()> {
    let cert_path = std::env::var("HALTCHAIN_WEBHOOK_TLS_CERT")
        .unwrap_or_else(|_| "/etc/haltchain/webhook/tls.crt".to_string());
    let key_path = std::env::var("HALTCHAIN_WEBHOOK_TLS_KEY")
        .unwrap_or_else(|_| "/etc/haltchain/webhook/tls.key".to_string());
    let addr: SocketAddr = "0.0.0.0:8443".parse()?;

    let app = Router::new().route("/mutate-pods", post(handle_mutate));

    // Load TLS credentials
    let cert = std::fs::read(&cert_path)
        .map_err(|e| anyhow::anyhow!("Cannot read TLS cert {}: {}", cert_path, e))?;
    let key = std::fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("Cannot read TLS key {}: {}", key_path, e))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            rustls_pemfile::certs(&mut cert.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Bad TLS cert: {e}"))?,
            rustls_pemfile::private_key(&mut key.as_slice())
                .map_err(|e| anyhow::anyhow!("Bad TLS key: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("No private key found"))?,
        )
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;

    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Admission webhook listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let mut svc = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let hyper_svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let mut app = svc.clone();
                        async move {
                            let req = req.map(axum::body::Body::new);
                            app.call(req).await
                        }
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, hyper_svc)
                        .await
                    {
                        tracing::warn!(addr = %remote_addr, "Webhook connection error: {e}");
                    }
                }
                Err(e) => tracing::warn!(addr = %remote_addr, "TLS handshake failed: {e}"),
            }
        });
    }
}

