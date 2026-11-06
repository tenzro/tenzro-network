//! A JSON-RPC error the node answers with reaches the caller as
//! `SdkError::Node`, with its code, message and data intact.

use std::time::Duration;

use tenzro_sdk::rpc::RpcClient;
use tenzro_sdk::{NodeError, SdkError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers one JSON-RPC request with `error`, and returns the request.
async fn answer_once(
    listener: tokio::net::TcpListener,
    error: serde_json::Value,
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
    let body =
        serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "error": error }).to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(response.as_bytes()).await.unwrap();
    request
}

async fn call_with_error(error: serde_json::Value) -> SdkError {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(answer_once(listener, error));
    let rpc = RpcClient::new(&url, Duration::from_secs(10), None).unwrap();
    let out = rpc
        .call::<serde_json::Value>("tenzro_chat", serde_json::json!({ "model_id": "m" }))
        .await;
    let request = server.await.unwrap();
    assert_eq!(request["method"], "tenzro_chat");
    out.unwrap_err()
}

#[tokio::test]
async fn the_light_build_refusal_is_recognised() {
    let err = call_with_error(serde_json::json!({
        "code": -32004,
        "message": "tenzro_chat needs a model on this node, and this is the light build of tenzro-node, which runs none",
        "data": { "build": "light" }
    }))
    .await;
    let node = err.node_error().expect("a node error");
    assert_eq!(node.code, -32004);
    assert!(node.is_light_build());
    assert!(err.to_string().contains("[-32004]"));
}

#[tokio::test]
async fn other_node_errors_keep_their_code_and_data() {
    let err = call_with_error(serde_json::json!({
        "code": -32602,
        "message": "missing model_id",
        "data": { "field": "model_id" }
    }))
    .await;
    match err {
        SdkError::Node(NodeError {
            code,
            message,
            data,
        }) => {
            assert_eq!(code, -32602);
            assert_eq!(message, "missing model_id");
            assert_eq!(data.unwrap()["field"], "model_id");
        }
        other => panic!("expected a node error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_not_found_without_build_data_is_not_the_light_build() {
    let err =
        call_with_error(serde_json::json!({ "code": -32004, "message": "no escrow 0x01" })).await;
    let node = err.node_error().expect("a node error");
    assert!(!node.is_light_build());
    assert!(node.data.is_none());
}
