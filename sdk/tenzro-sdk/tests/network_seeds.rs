//! Discovery reaches the network through any seed that answers.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_sdk::network::{NetworkOptions, discover_endpoints};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHAIN: u64 = 1337;

/// A node answering each method from `replies`.
async fn node(replies: HashMap<&'static str, Value>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let replies = Arc::new(replies);
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let replies = replies.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let body_start = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
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
                let request: Value = serde_json::from_slice(&buf[body_start..]).unwrap();
                let method = request["method"].as_str().unwrap_or("");
                let result = replies.get(method).cloned().unwrap_or(Value::Null);
                let body =
                    json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
            });
        }
    });
    url
}

/// An address nothing listens on.
async fn down() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    url
}

#[tokio::test]
async fn the_first_seed_down_discovery_succeeds_through_the_next() {
    let live = node(HashMap::from([
        (
            "tenzro_listRoleEndpoints",
            json!({ "role": "rpc", "endpoints": [] }),
        ),
        ("eth_chainId", json!(format!("0x{CHAIN:x}"))),
        (
            "tenzro_getCheckpointCertificate",
            json!({ "index": 9, "digest": "0xabc" }),
        ),
    ]))
    .await;
    let dead = down().await;
    let mut options = NetworkOptions::new(vec![dead.clone(), live.clone()], CHAIN);
    options.timeout = std::time::Duration::from_secs(3);
    let found = discover_endpoints(&options).await.unwrap();
    assert_eq!(
        found.iter().map(|e| e.url.as_str()).collect::<Vec<_>>(),
        [live.as_str()]
    );

    // With only the dead seed there is no way in, and discovery says so.
    let only_dead = NetworkOptions::new(vec![dead], CHAIN);
    assert!(discover_endpoints(&only_dead).await.is_err());
}

#[test]
fn the_preview_network_starts_from_every_seed() {
    let options = tenzro_sdk::network::PREVIEW_NETWORK.options();
    assert_eq!(
        options.seeds,
        tenzro_sdk::network::NETWORK_SEEDS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );
}
