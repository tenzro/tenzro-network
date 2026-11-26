//! A rental moves off a down operator: the stream escrow it left is refunded,
//! then the stream with the next operator opens, in that order.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tenzro_sdk::rpc::RpcClient;
use tenzro_sdk::wallet::HybridSigner;
use tenzro_sdk::{Address, ComputeClient, RentRequest, SdkResult};
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

/// Answers the requests a typed transaction makes, as a node would, until the
/// client stops asking; returns each submitted transaction's type.
async fn serve(listener: tokio::net::TcpListener) -> Vec<serde_json::Value> {
    let mut submitted = Vec::new();
    while let Ok(Ok((mut sock, _))) =
        tokio::time::timeout(Duration::from_secs(2), listener.accept()).await
    {
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
        let p = &request["params"];
        let result = match request["method"].as_str().unwrap() {
            "tenzro_getNonce" => serde_json::json!("0x7"),
            "eth_chainId" => serde_json::json!("0x539"),
            "eth_gasPrice" => serde_json::json!("0x1"),
            "tenzro_estimateGas" => serde_json::json!("0x7a120"),
            "tenzro_getSigningPayload" => {
                let pre = serde_json::json!({
                    "chain_id": p["chain_id"],
                    "from": p["from"].as_str().unwrap().trim_start_matches("0x"),
                    "to": p["to"].as_str().unwrap().trim_start_matches("0x"),
                    "nonce": p["nonce"],
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
            "tenzro_sendRawTransaction" => {
                submitted.push(p["tx_type"].clone());
                serde_json::json!({ "tx_hash": format!("0x{:02x}", submitted.len()) })
            }
            other => panic!("unexpected {other}"),
        };
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
            .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(response.as_bytes()).await.unwrap();
    }
    submitted
}

#[tokio::test]
async fn a_rental_refunds_the_down_operator_then_streams_to_the_next() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(serve(listener));
    let rpc = Arc::new(RpcClient::new(&url, Duration::from_secs(10), None).unwrap());
    let next = RentRequest::new(Address::new([4; 32]), 7, 3);
    let answer = ComputeClient::new(rpc)
        .fail_over_rental(&FixedSigner, &hex::encode([5u8; 32]), &next)
        .await
        .unwrap();
    assert_eq!(answer["tx_hash"], "0x02");
    let submitted = server.await.unwrap();
    assert_eq!(submitted.len(), 2);
    assert!(
        submitted[0].to_string().contains("RefundEscrow"),
        "{submitted:?}"
    );
    assert!(
        submitted[1].to_string().contains("CreateEscrow"),
        "{submitted:?}"
    );
}
