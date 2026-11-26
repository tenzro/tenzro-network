//! A read moves to the next operator when the first is down, and only the
//! operator that served is sent its voucher.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde_json::json;
use tenzro_sdk::rpc::RpcClient;
use tenzro_sdk::storage::{ReadOperator, StorageClient, retrieve_with_failover};
use tenzro_sdk::wallet::HybridSigner;
use tenzro_sdk::{SdkError, SdkResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct FixedSigner;

#[async_trait::async_trait]
impl HybridSigner for FixedSigner {
    fn p256_public_key(&self) -> [u8; 64] {
        [7; 64]
    }
    fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    async fn sign_composite(&self, _m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
        Ok(([9; 64], None))
    }
    async fn sign_ml_dsa_leg(&self, _m_prime: &[u8]) -> SdkResult<Vec<u8>> {
        unreachable!("this signer holds no ML-DSA-65 key")
    }
    async fn sign_p256(&self, _message: &[u8]) -> SdkResult<[u8; 64]> {
        Ok([9; 64])
    }
}

/// Answers one JSON-RPC request with `reply` (`result` or `error`), and
/// returns the request.
async fn answer_once(
    listener: tokio::net::TcpListener,
    reply: serde_json::Value,
) -> serde_json::Value {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let body_start = loop {
        let n = sock.read(&mut chunk).await.unwrap();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..body_start]).to_lowercase();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    while buf.len() < body_start + len {
        let n = sock.read(&mut chunk).await.unwrap();
        buf.extend_from_slice(&chunk[..n]);
    }
    let request: serde_json::Value = serde_json::from_slice(&buf[body_start..]).unwrap();
    let mut body = json!({ "jsonrpc": "2.0", "id": request["id"] });
    body.as_object_mut()
        .unwrap()
        .extend(reply.as_object().unwrap().clone());
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(response.as_bytes()).await.unwrap();
    request
}

fn operator(name: &str, url: &str, voucher: &str) -> ReadOperator {
    let rpc = RpcClient::new(url, Duration::from_secs(5), None).unwrap();
    ReadOperator {
        name: name.to_string(),
        client: StorageClient::new(Arc::new(rpc)),
        voucher: Some(json!({ "paid_to": voucher })),
    }
}

/// The address of a port nothing listens on.
async fn closed_port() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    url
}

#[tokio::test]
async fn a_read_moves_to_the_next_operator_and_pays_only_that_one() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url_b = format!("http://{}", listener.local_addr().unwrap());
    let data = base64::engine::general_purpose::STANDARD.encode(b"the object");
    let server = tokio::spawn(answer_once(listener, json!({ "result": { "data": data } })));
    let operators = [
        operator("a", &closed_port().await, "a"),
        operator("b", &url_b, "b"),
    ];
    let served = retrieve_with_failover(&operators, "obj", "did:tenzro:human:r", &FixedSigner)
        .await
        .unwrap();
    assert_eq!(served.operator, "b");
    assert_eq!(served.data, b"the object");
    assert_eq!(served.down.len(), 1);
    assert_eq!(served.down[0].0, "a");
    let request = server.await.unwrap();
    assert_eq!(request["method"], "tenzro_storageRetrieveObject");
    let sent = request.to_string();
    assert!(sent.contains(r#""paid_to":"b""#), "{sent}");
    assert!(!sent.contains(r#""paid_to":"a""#), "{sent}");
}

#[tokio::test]
async fn a_refused_reader_ends_the_read_and_every_operator_down_is_an_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(answer_once(
        listener,
        json!({ "error": { "code": -32001, "message": "not permitted" } }),
    ));
    let operators = [
        operator("a", &url, "a"),
        operator("b", &closed_port().await, "b"),
    ];
    let err = retrieve_with_failover(&operators, "obj", "did:tenzro:human:r", &FixedSigner)
        .await
        .unwrap_err();
    assert_eq!(err.node_error().expect("a node error").code, -32001);
    server.await.unwrap();

    let all_down = [
        operator("a", &closed_port().await, "a"),
        operator("b", &closed_port().await, "b"),
    ];
    let err = retrieve_with_failover(&all_down, "obj", "did:tenzro:human:r", &FixedSigner)
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::RpcError(_)), "{err}");
}
