//! A typed transaction dry run: the node encodes the signing payload, the SDK
//! checks it, and nothing is signed or submitted.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tenzro_sdk::rpc::RpcClient;
use tenzro_sdk::{Address, TxKind, TypedTransaction, TypedTxClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serves `count` JSON-RPC requests, answering each as a node would for a
/// dry run; `skew_nonce` makes the signing payload name another nonce.
async fn serve(listener: tokio::net::TcpListener, count: usize, skew_nonce: u64) -> Vec<String> {
    let mut methods = Vec::new();
    for _ in 0..count {
        let Ok((mut sock, _)) = listener.accept().await else {
            break;
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
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
        let method = request["method"].as_str().unwrap().to_string();
        let p = &request["params"];
        let result = match method.as_str() {
            "tenzro_getNonce" => serde_json::json!("0x7"),
            "eth_chainId" => serde_json::json!("0x539"),
            "eth_gasPrice" => serde_json::json!("0x1"),
            "tenzro_getSigningPayload" => {
                let pre = serde_json::json!({
                    "chain_id": p["chain_id"],
                    "from": p["from"].as_str().unwrap().trim_start_matches("0x"),
                    "to": p["to"].as_str().unwrap().trim_start_matches("0x"),
                    "nonce": p["nonce"].as_u64().unwrap() + skew_nonce,
                    "gas_limit": p["gas_limit"],
                    "gas_price": p["gas_price"],
                    "timestamp": p["timestamp"],
                    "valid_until": p["valid_until"],
                    "action": p["tx_type"],
                })
                .to_string();
                let digest = hex::encode(Sha256::digest(pre.as_bytes()));
                serde_json::json!({ "kind": "typed_action", "preimage": pre, "digest": digest })
            }
            other => panic!("unexpected {other}"),
        };
        methods.push(method);
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
            .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(response.as_bytes()).await.unwrap();
    }
    methods
}

async fn prepare_with(
    skew_nonce: u64,
) -> (
    tenzro_sdk::SdkResult<tenzro_sdk::PreparedTransaction>,
    Vec<String>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(serve(listener, 4, skew_nonce));
    let rpc = Arc::new(RpcClient::new(&url, Duration::from_secs(10), None).unwrap());
    let tx = TypedTransaction::new(TxKind::Transfer, serde_json::json!({ "amount": 5 }))
        .unwrap()
        .to(Address::new([0x22; 32]));
    let out = TypedTxClient::new(rpc)
        .prepare(Address::new([0x11; 32]), &tx)
        .await;
    (out, server.await.unwrap())
}

#[tokio::test]
async fn prepare_checks_the_node_encoding_and_sends_nothing() {
    let (out, methods) = prepare_with(0).await;
    let prepared = out.unwrap();
    assert_eq!(prepared.request["from"], format!("0x{}", "11".repeat(32)));
    assert_eq!(prepared.request["nonce"], 7);
    assert_eq!(prepared.request["chain_id"], 1337);
    assert!(prepared.request.get("signature").is_none());
    assert_eq!(
        methods,
        [
            "tenzro_getNonce",
            "eth_chainId",
            "eth_gasPrice",
            "tenzro_getSigningPayload"
        ]
    );
}

#[tokio::test]
async fn prepare_refuses_a_payload_that_is_not_the_transaction() {
    let (out, methods) = prepare_with(1).await;
    assert!(out.unwrap_err().to_string().contains("nonce"));
    assert!(!methods.iter().any(|m| m == "tenzro_sendRawTransaction"));
}
