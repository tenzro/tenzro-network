//! The node reaches HTTPS origins through the platform's root certificates.
//!
//! Every outbound call to an origin the operator configured, `tenzro-node
//! graceful-exit` included, posts through the node's shared HTTP client. Here
//! that client posts to a local TLS server whose certificate a test authority
//! signed, and that authority is trusted only through `SSL_CERT_FILE`, which
//! the platform root store honours. The client reads the root store once per
//! process, so each case runs in a child process of this test with its own
//! environment. A node built without root certificates fails the first test,
//! and one that skipped verification fails the second.
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The child's target: the URL it posts to.
const PROBE_URL: &str = "TENZRO_TLS_PROBE_URL";

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
/// Returns how the TLS handshake ended: `Err` with the server's reading of
/// it when the client broke it off.
async fn serve_once(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Result<(), String> {
    let Ok((tcp, _)) = listener.accept().await else {
        return Err("no connection".into());
    };
    // A client that refuses the certificate ends the handshake here, with
    // the alert that says why.
    let mut tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let Ok(n) = tls.read(&mut buf).await else {
            return Ok(());
        };
        if n == 0 {
            return Ok(());
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
    Ok(())
}

/// Post through the node's shared client, in a child process of this test,
/// to a local TLS server whose certificate a fresh test authority signed.
/// With `trust_authority`, `SSL_CERT_FILE` names that authority; without, the
/// platform store is used as it is. Returns the child's output and how the
/// server saw the TLS handshake end.
async fn post_over_tls(trust_authority: bool) -> (std::process::Output, Result<(), String>) {
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

    let mut cmd = tokio::process::Command::new(std::env::current_exe().unwrap());
    cmd.args(["probe", "--exact", "--ignored", "--nocapture"])
        .env(PROBE_URL, format!("https://127.0.0.1:{port}"))
        .env_remove("SSL_CERT_DIR")
        .env_remove("SSL_CERT_FILE");
    if trust_authority {
        let ca = dir.path().join("authority.pem");
        std::fs::write(&ca, authority).unwrap();
        cmd.env("SSL_CERT_FILE", ca);
    }
    cmd.kill_on_drop(true);
    let out = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output())
        .await
        .expect("the child ends within a minute")
        .unwrap();
    // The child has exited, so its connection is closed and the server is done.
    let handshake = tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .expect("the server ends once the child has gone")
        .expect("the server task");
    (out, handshake)
}

/// The child: one JSON-RPC call through the node's shared client to the URL
/// its parent names; it fails unless the server's answer comes back.
#[tokio::test]
#[ignore = "run by the tests in this file, in a child process with its own root store"]
async fn probe() {
    // Run on its own (`--ignored`), with no parent naming a server, it has
    // nothing to check.
    let Ok(url) = std::env::var(PROBE_URL) else {
        eprintln!("probe: no server named; this is run by the other tests in tls_roots.rs");
        return;
    };
    let reply: serde_json::Value = tenzro_node::http_client::shared()
        .post(&url)
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tenzro_gracefulExit", "params": {}}))
        .send()
        .await
        .expect("the TLS server is reached")
        .json()
        .await
        .expect("a JSON answer");
    assert_eq!(reply["result"], "draining", "{reply}");
}

#[tokio::test]
async fn the_node_trusts_the_platform_root_store() {
    let (out, handshake) = post_over_tls(true).await;
    assert!(
        out.status.success(),
        "the node's client refused a server the root store trusts:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(handshake, Ok(()));
}

#[tokio::test]
async fn the_node_refuses_a_certificate_no_trusted_root_signed() {
    let (out, handshake) = post_over_tls(false).await;
    assert!(
        !out.status.success(),
        "the node's client accepted a certificate from an authority nothing trusts"
    );
    // The server saw the handshake begin and the client break it off for the
    // certificate's issuer, not a connection that failed for another reason.
    let refused = handshake.expect_err("the handshake completed");
    assert!(refused.contains("UnknownCA"), "{refused}");
}
