//! Calls into the running extensions that the gateway did not make: each is
//! refused before it reaches Tenzro.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::Signer as _;
use tenzro_openshell::openshell::credentials::v1::GetCredentialDriverCapabilitiesRequest;
use tenzro_openshell::openshell::credentials::v1::credential_driver_client::CredentialDriverClient;
use tenzro_openshell::openshell::gateway_interceptor::v1::DescribeRequest;
use tenzro_openshell::openshell::gateway_interceptor::v1::gateway_interceptor_client::GatewayInterceptorClient;
use tenzro_openshell::openshell::middleware::v1::MiddlewareDescribeRequest;
use tenzro_openshell::openshell::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

async fn unix(path: &Path) -> Channel {
    let path: PathBuf = path.to_path_buf();
    Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_| {
            let p = path.clone();
            async move {
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::connect(p).await?,
                ))
            }
        }))
        .await
        .unwrap()
}

/// The credential driver answers only the gateway's process: this test's
/// process, the same user, is refused.
pub async fn driver_refuses_another_process(socket: &Path) {
    let mut c = CredentialDriverClient::new(unix(socket).await);
    let e = c
        .get_capabilities(GetCredentialDriverCapabilitiesRequest::default())
        .await
        .expect_err("the credential driver answered a process that is not the gateway");
    assert_eq!(e.code(), tonic::Code::Unauthenticated, "{e}");
    println!("credential driver refused another process: {}", e.message());
}

/// The interceptor answers only the gateway's process with the gateway's
/// token.
pub async fn interceptor_refuses_another_process(socket: &Path) {
    let mut c = GatewayInterceptorClient::new(unix(socket).await);
    let e = c
        .describe(DescribeRequest::default())
        .await
        .expect_err("the interceptor answered a process that is not the gateway");
    assert_eq!(e.code(), tonic::Code::Unauthenticated, "{e}");
    println!("interceptor refused another process: {}", e.message());
}

fn forged_token(audience: &str, gateway_id: &str) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let now = chrono::Utc::now().timestamp();
    let h = B64.encode(br#"{"alg":"EdDSA","typ":"openshell-ext+jwt"}"#);
    let issuer = format!("openshell-gateway:{gateway_id}");
    let c = B64.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": issuer, "aud": audience, "sub": issuer, "iat": now, "exp": now + 300,
            "jti": "forged", "caller_kind": "gateway"
        }))
        .unwrap(),
    );
    let sig = key.sign(format!("{h}.{c}").as_bytes());
    format!("{h}.{c}.{}", B64.encode(sig.to_bytes()))
}

/// The middleware is reached only over TLS, and answers only a token the
/// gateway signed.
pub async fn middleware_refuses_without_the_gateways_token(
    port: u16,
    ca_pem: &[u8],
    audience: &str,
    gateway_id: &str,
) {
    let plain = Endpoint::try_from(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect()
        .await;
    if let Ok(ch) = plain {
        let r = SupervisorMiddlewareClient::new(ch)
            .describe(MiddlewareDescribeRequest::default())
            .await;
        assert!(r.is_err(), "the middleware answered plaintext");
    }
    let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem));
    let ch = Endpoint::try_from(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("TLS to the middleware");
    let mut c = SupervisorMiddlewareClient::new(ch);
    let e = c
        .describe(MiddlewareDescribeRequest::default())
        .await
        .expect_err("the middleware answered without a token");
    assert_eq!(e.code(), tonic::Code::Unauthenticated, "{e}");
    let mut forged = tonic::Request::new(MiddlewareDescribeRequest::default());
    forged.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", forged_token(audience, gateway_id))
            .parse()
            .unwrap(),
    );
    let e = c
        .describe(forged)
        .await
        .expect_err("the middleware answered a forged token");
    assert_eq!(e.code(), tonic::Code::Unauthenticated, "{e}");
    println!(
        "middleware refused plaintext, no token and a forged token: {}",
        e.message()
    );
}
