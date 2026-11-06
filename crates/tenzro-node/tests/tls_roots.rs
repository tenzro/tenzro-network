//! The node reaches HTTPS origins through the platform's root certificates.
//!
//! `tenzro-node graceful-exit` posts through the node's shared HTTP client.
//! Here it posts to a local TLS server whose certificate a test authority
//! signed, and that authority is trusted only through `SSL_CERT_FILE`, which
//! the platform root store honours. A node built without root certificates
//! fails the first test, and one that skipped verification fails the second.

use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The `tenzro-node` binary `cargo test` built for this test.
fn node_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_tenzro-node")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_tenzro-node").map(PathBuf::from))
        .expect("cargo test names the tenzro-node binary in CARGO_BIN_EXE_tenzro-node")
}

/// A test authority's certificate (PEM) and a certificate for this host
/// and its key, signed by it.
fn test_authority() -> (String, CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "tenzro test authority");
    let authority =
        rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&key, &authority)
            .unwrap();
    (
        authority.pem(),
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}
/// Answer one JSON-RPC request over TLS with a result, then close.
async fn serve_once(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor) {
    let Ok((tcp, _)) = listener.accept().await else {
        return;
    };
    // A client that refuses the certificate ends the handshake here.
    let Ok(mut tls) = acceptor.accept(tcp).await else {
        return;
    };
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let Ok(n) = tls.read(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        seen.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&seen).to_ascii_lowercase();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if seen.len() >= end + 4 + length {
                break;
            }
        }
    }
    let body = r#"{"jsonrpc":"2.0","id":1,"result":"draining"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tls.write_all(response.as_bytes()).await;
    let _ = tls.shutdown().await;
}

/// Run `graceful-exit` against a local TLS server whose certificate a fresh
/// test authority signed. With `trust_authority`, `SSL_CERT_FILE` names that
/// authority; without, the platform store is used as it is.
async fn graceful_exit_over_tls(trust_authority: bool) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let (authority, cert, key) = test_authority();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_once(listener, acceptor));

    let node_config = dir.path().join("node.toml");
    std::fs::write(&node_config, "").unwrap();
    let mut cmd = tokio::process::Command::new(node_binary());
    cmd.arg("-c")
        .arg(&node_config)
        .args(["graceful-exit", "--max-wait-secs", "1", "--rpc-url"])
        .arg(format!("https://127.0.0.1:{port}"))
        .env_remove("SSL_CERT_DIR")
        .env_remove("SSL_CERT_FILE");
    if trust_authority {
        let ca = dir.path().join("authority.pem");
        std::fs::write(&ca, authority).unwrap();
        cmd.env("SSL_CERT_FILE", ca);
    }
    let out = cmd.output().await.unwrap();
    server.abort();
    out
}

#[tokio::test]
async fn the_node_trusts_the_platform_root_store() {
    let out = graceful_exit_over_tls(true).await;
    assert!(
        out.status.success(),
        "graceful-exit over TLS failed with the test authority in the root store:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("draining"));
}

#[tokio::test]
async fn the_node_refuses_a_certificate_no_trusted_root_signed() {
    let out = graceful_exit_over_tls(false).await;
    assert!(
        !out.status.success(),
        "graceful-exit accepted a certificate from an authority nothing trusts"
    );
}
