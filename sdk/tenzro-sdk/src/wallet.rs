//! Wallet SDK for Tenzro Network
//!
//! This module provides wallet management functionality for the SDK.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::types::Address;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A hardware signer for a Tenzro account. The P-256 key of a TPM, Secure
/// Enclave or other hardware module names the account; where the same
/// hardware holds an ML-DSA-65 key and the account enrolled it in state, that
/// key signs the post-quantum leg. The SDK never holds a private key: this
/// trait is implemented over the hardware, and it is what lets
/// `WalletClient::send_self_custody` and `TypedTxClient::send` build the
/// canonical transaction hash, obtain the composite signature and submit it
/// via `tenzro_sendRawTransaction`.
#[async_trait]
pub trait HybridSigner: Send + Sync {
    /// The hardware P-256 public key, `x || y`. It derives the account
    /// address ([`account_address`]).
    fn p256_public_key(&self) -> [u8; 64];

    /// The hardware ML-DSA-65 verifying key (1952 bytes), when the hardware
    /// holds one: the account's enrolled key, or the key an `AccountKeys`
    /// transaction enrolls ([`crate::account_keys::AccountKeysClient`]).
    fn ml_dsa_public_key(&self) -> Option<Vec<u8>>;

    /// Sign the composite message representative `m_prime` (built by
    /// [`composite_message_representative`]): the P-256 leg as a prehash
    /// signature `r || s` over `SHA-256(m_prime)`, and, when the hardware
    /// holds an ML-DSA-65 key ([`HybridSigner::ml_dsa_public_key`]), the
    /// ML-DSA-65 leg over
    /// `m_prime` with the FIPS 204 context string
    /// [`COMPOSITE_LABEL_MLDSA65_P256`].
    async fn sign_composite(&self, m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)>;

    /// Sign `message` with the P-256 key alone: `r || s` over
    /// `SHA-256(message)`. Statements the node verifies as a plain P-256
    /// signature (a post-quantum rotation's authority leg, a TEE measurement
    /// publication) use this.
    async fn sign_p256(&self, message: &[u8]) -> SdkResult<[u8; 64]>;
}

/// Signature context of a request the account owner signs over RPC.
pub const ACCOUNT_OWNER_SIGNATURE_CONTEXT: &[u8] = b"tenzro/rpc/account-owner";

/// The uncompressed SEC1 form `0x04 || x || y` of a P-256 key `x || y`.
pub fn p256_sec1(p256_xy: &[u8; 64]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..].copy_from_slice(p256_xy);
    out
}

/// Fixed prefix of every composite message representative.
pub const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Composite label for ML-DSA-65 paired with ECDSA P-256, and the FIPS 204
/// context string the ML-DSA-65 component signs under.
pub const COMPOSITE_LABEL_MLDSA65_P256: &[u8] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";

/// Signature context of a ledger transaction.
pub const TRANSACTION_SIGNATURE_CONTEXT: &[u8] = b"tenzro/tx";

/// The 32-byte ledger account slot of a hardware P-256 key, identical to
/// `tenzro_crypto::account_slot`:
/// `SHA-256("tenzro/account" || 0x02 || 0x40 || x || y)[..20]` followed by 12
/// zero bytes. The address commits to the P-256 key only, so enrolling or
/// rotating the ML-DSA-65 key never moves an account.
pub fn account_address(p256_xy: &[u8; 64]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/account");
    h.update([2u8, 64u8]);
    h.update(p256_xy);
    let digest = h.finalize();
    let mut slot = [0u8; 32];
    slot[..20].copy_from_slice(&digest[..20]);
    slot
}

/// The composite message representative both components sign, identical to
/// `tenzro_crypto::composite::message_representative`:
/// `Prefix || Label || len(ctx) || ctx || SHA-512(message)`.
pub fn composite_message_representative(context: &[u8], message: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let ph = Sha512::digest(message);
    let mut out = Vec::with_capacity(
        COMPOSITE_PREFIX.len() + COMPOSITE_LABEL_MLDSA65_P256.len() + 1 + context.len() + 64,
    );
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(COMPOSITE_LABEL_MLDSA65_P256);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out.extend_from_slice(&ph);
    out
}

/// The JSON form of a composite signature with a raw P-256 leg:
/// `{"classical": {"form": "raw", "signature": hex}, "pq": hex}`, `pq`
/// omitted when the signer has no ML-DSA-65 key enrolled.
pub fn composite_signature_json(p256_rs: &[u8; 64], ml_dsa: Option<&[u8]>) -> serde_json::Value {
    let mut sig = serde_json::json!({
        "classical": { "form": "raw", "signature": hex::encode(p256_rs) },
    });
    if let Some(pq) = ml_dsa {
        sig["pq"] = serde_json::Value::String(hex::encode(pq));
    }
    sig
}

/// Builds the canonical `Transaction::hash()` preimage for a native TNZO
/// transfer, byte-identical to `tenzro_types::transaction::Transaction::hash`.
///
/// Preimage order (all integers little-endian):
/// `chain_id ‖ from(32) ‖ to(32) ‖ nonce ‖ gas_limit ‖ gas_price ‖
/// timestamp ‖ valid_until ‖ tx_type_json ‖ (no memo)`.
///
/// The SDK is workspace-isolated (empty `[workspace]`, standalone git
/// mirror) so it cannot depend on `tenzro-types`; the preimage is
/// reproduced here. `tx_type_json` reproduces serde's externally-tagged
/// `{"Transfer":{"amount":<N>}}` with `serde_json`'s exact formatting (no
/// whitespace, bare integer).
#[allow(clippy::too_many_arguments)]
fn transfer_tx_hash(
    chain_id: u64,
    from: &[u8; 32],
    to: &[u8; 32],
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
    timestamp_ms: i64,
    valid_until_ms: i64,
    amount_wei: u128,
) -> [u8; 32] {
    let tx_type_json = format!("{{\"Transfer\":{{\"amount\":{}}}}}", amount_wei);
    let mut hasher = Sha256::new();
    hasher.update(chain_id.to_le_bytes());
    hasher.update(from);
    hasher.update(to);
    hasher.update(nonce.to_le_bytes());
    hasher.update(gas_limit.to_le_bytes());
    hasher.update(gas_price.to_le_bytes());
    hasher.update(timestamp_ms.to_le_bytes());
    hasher.update(valid_until_ms.to_le_bytes());
    hasher.update(tx_type_json.as_bytes());
    // memo is None on native transfers — nothing appended.
    hasher.finalize().into()
}

/// Validity window the SDK signs a transaction with: five minutes, inside
/// the network's validity caps for every transaction class.
const TX_VALIDITY_MS: i64 = 300_000;

/// Current wall-clock time in milliseconds since the Unix epoch, matching
/// `tenzro_types::primitives::Timestamp::now()`.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Reads a hex quantity (a nonce, the chain id) from the node. An RPC
/// failure or an answer that is not a hex quantity is an error naming the
/// endpoint; no default stands in for it.
async fn read_quantity(
    rpc: &RpcClient,
    method: &str,
    params: serde_json::Value,
    what: &str,
) -> SdkResult<u64> {
    let at = rpc.endpoint().unwrap_or("the RPC endpoint");
    let fail =
        |cause: String| SdkError::RpcError(format!("could not read the {what} from {at}: {cause}"));
    let hex: String = rpc
        .call(method, params)
        .await
        .map_err(|e| fail(e.to_string()))?;
    parse_quantity(&hex).map_err(fail)
}

/// Parses a hex quantity, `0x`-prefixed or bare. Anything else is an error.
fn parse_quantity(hex: &str) -> Result<u64, String> {
    let digits = hex.strip_prefix("0x").unwrap_or(hex);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{hex:?} is not a hex quantity"));
    }
    u64::from_str_radix(digits, 16).map_err(|e| format!("{hex:?}: {e}"))
}

/// Wallet client for managing wallets and balances
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let wallet = client.wallet();
///
/// // Read an account's nonce
/// let nonce = wallet.get_nonce(tenzro_sdk::types::Address::zero()).await?;
/// println!("Nonce: {nonce}");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct WalletClient {
    rpc: Arc<RpcClient>,
}

impl WalletClient {
    /// Creates a new wallet client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Gets the TNZO balance of an address (in wei)
    pub async fn get_balance(&self, address: Address) -> SdkResult<u128> {
        let hex: String = self
            .rpc
            .call(
                "tenzro_getBalance",
                serde_json::json!([format!("0x{}", hex::encode(address.as_bytes()))]),
            )
            .await?;
        let stripped = hex.strip_prefix("0x").unwrap_or(&hex);
        u128::from_str_radix(stripped, 16)
            .map_err(|e| crate::error::SdkError::RpcError(format!("Bad hex: {}", e)))
    }

    /// Gets the token balance of an address (decimal string)
    pub async fn get_token_balance(&self, address: Address) -> SdkResult<String> {
        self.rpc
            .call(
                "tenzro_tokenBalance",
                serde_json::json!({
                    "address": format!("0x{}", hex::encode(address.as_bytes()))
                }),
            )
            .await
    }

    /// Gets all asset balances for a wallet address
    pub async fn get_all_balances(&self, address: Address) -> SdkResult<WalletBalance> {
        let balance = self.get_balance(address.clone()).await?;

        Ok(WalletBalance {
            address,
            balances: vec![AssetBalance {
                symbol: "TNZO".to_string(),
                balance,
                decimals: 18,
            }],
        })
    }

    /// Signs a TNZO transfer with a hardware [`HybridSigner`] and submits it
    /// via `tenzro_sendRawTransaction`; the node never holds the key.
    ///
    /// The account of the signer's P-256 key is the `from` account. This
    /// method fetches the nonce and chain id, builds the canonical
    /// `Transaction::hash()` preimage, has the hardware sign its composite
    /// representative, and submits the pre-signed transaction. The node
    /// requires the ML-DSA-65 leg when the account enrolled an ML-DSA-65 key.
    ///
    /// Amount is in wei (smallest TNZO unit). Returns the transaction hash.
    ///
    /// The recipient is checked before the hardware is asked to sign: a
    /// recipient this account has never paid, or one that resembles an
    /// address it trusts, is refused with the findings unless
    /// [`Self::send_self_custody_confirmed`] is used with the full address.
    pub async fn send_self_custody(
        &self,
        signer: &Arc<dyn HybridSigner>,
        to: Address,
        amount_wei: u128,
    ) -> SdkResult<String> {
        self.send_self_custody_confirmed(signer, to, amount_wei, None)
            .await
    }

    /// Checks `to` against this account's history and the governed look-alike
    /// thresholds, as [`Self::send_self_custody`] does before it signs.
    pub async fn assess_recipient(
        &self,
        from_hex: &str,
        to: &Address,
    ) -> SdkResult<crate::recipient_guard::RecipientAssessment> {
        use crate::recipient_guard as rg;
        async fn governed(rpc: &RpcClient, key: &str) -> Option<u64> {
            let v: serde_json::Value = rpc
                .call("tenzro_getNetworkParams", serde_json::json!({ "key": key }))
                .await
                .ok()?;
            v.get("value")?.as_str()?.parse().ok()
        }
        let params = rg::LookalikeParams::from_governed(
            governed(&self.rpc, rg::PREFIX_BYTES_PARAM).await,
            governed(&self.rpc, rg::SUFFIX_BYTES_PARAM).await,
        );
        let history: serde_json::Value = self
            .rpc
            .call(
                "tenzro_getTransactionHistory",
                serde_json::json!({ "address": from_hex, "limit": 500 }),
            )
            .await?;
        let norm = |s: &str| s.trim().trim_start_matches("0x").to_ascii_lowercase();
        let me = norm(from_hex);
        let (mut trusted, mut senders): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        for tx in history
            .get("transactions")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let f = tx.get("from").and_then(|v| v.as_str()).map(norm);
            let t = tx.get("to").and_then(|v| v.as_str()).map(norm);
            match (f, t) {
                (Some(f), Some(t)) if f == me => trusted.push(t),
                (Some(f), Some(t)) if t == me => senders.push(f),
                _ => {}
            }
        }
        senders.retain(|a| !trusted.contains(a));
        let to_hex = hex::encode(to.as_bytes());
        Ok(rg::assess_recipient(&to_hex, &trusted, &senders, &params))
    }

    /// [`Self::send_self_custody`] for a recipient that needs confirming:
    /// `acknowledged_address` is the full recipient address as the user typed
    /// it back; it must match or nothing is signed.
    pub async fn send_self_custody_confirmed(
        &self,
        signer: &Arc<dyn HybridSigner>,
        to: Address,
        amount_wei: u128,
        acknowledged_address: Option<&str>,
    ) -> SdkResult<String> {
        let public_key = signer.p256_public_key();
        let from_arr = account_address(&public_key);
        let from_hex = format!("0x{}", hex::encode(from_arr));
        let assessment = self.assess_recipient(&from_hex, &to).await?;
        if assessment.requires_full_address_confirmation()
            && !acknowledged_address.is_some_and(|a| assessment.confirmation_matches(a))
        {
            return Err(SdkError::WalletError(format!(
                "recipient needs the full address confirmed before signing: {}",
                assessment.describe().join(" ")
            )));
        }
        let to_hex = format!("0x{}", hex::encode(to.as_bytes()));
        let mut to_arr = [0u8; 32];
        to_arr.copy_from_slice(to.as_bytes());

        let nonce = read_quantity(
            &self.rpc,
            "tenzro_getNonce",
            serde_json::json!([from_hex.clone()]),
            "nonce",
        )
        .await?;
        let chain_id =
            read_quantity(&self.rpc, "eth_chainId", serde_json::json!([]), "chain id").await?;

        let gas_limit = 21_000u64;
        let gas_price = 1_000_000_000u64;
        let timestamp_ms = now_ms();
        let valid_until_ms = timestamp_ms + TX_VALIDITY_MS;

        let hash = transfer_tx_hash(
            chain_id,
            &from_arr,
            &to_arr,
            nonce,
            gas_limit,
            gas_price,
            timestamp_ms,
            valid_until_ms,
            amount_wei,
        );
        let m_prime = composite_message_representative(TRANSACTION_SIGNATURE_CONTEXT, &hash);
        let (p256_sig, ml_dsa_sig) = signer.sign_composite(&m_prime).await?;

        self.rpc
            .call(
                "tenzro_sendRawTransaction",
                serde_json::json!({
                    "from": from_hex,
                    "to": to_hex,
                    "value": amount_wei.to_string(),
                    "gas_limit": gas_limit,
                    "gas_price": gas_price,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "timestamp": timestamp_ms,
                    "valid_until": valid_until_ms,
                    "public_key": hex::encode(public_key),
                    "signature": composite_signature_json(&p256_sig, ml_dsa_sig.as_deref()),
                }),
            )
            .await
    }

    /// Gets the nonce for an address
    pub async fn get_nonce(&self, address: Address) -> SdkResult<u64> {
        let hex: String = self
            .rpc
            .call(
                "tenzro_getNonce",
                serde_json::json!([format!("0x{}", hex::encode(address.as_bytes()))]),
            )
            .await?;
        let stripped = hex.strip_prefix("0x").unwrap_or(&hex);
        u64::from_str_radix(stripped, 16)
            .map_err(|e| crate::error::SdkError::RpcError(format!("Bad hex: {}", e)))
    }
}

/// Wallet balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    /// Wallet address
    pub address: Address,
    /// All asset balances
    pub balances: Vec<AssetBalance>,
}

/// Balance information for a specific asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetBalance {
    /// Asset symbol
    pub symbol: String,
    /// Balance in smallest unit (wei)
    pub balance: u128,
    /// Number of decimals
    pub decimals: u8,
}

impl AssetBalance {
    /// Returns the balance as a human-readable decimal value
    pub fn as_decimal(&self) -> f64 {
        self.balance as f64 / 10_f64.powi(self.decimals as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Fixed vector shared with `tenzro_crypto::composite` tests, so the
    /// SDK and the node derive the same account.
    #[test]
    fn account_address_matches_the_node_vector() {
        let slot = account_address(&[7u8; 64]);
        assert_eq!(
            hex::encode(&slot[..20]),
            "625503fe7bf351f5823f2bbdb5e077a0b6548643"
        );
        assert_eq!(&slot[20..], &[0u8; 12]);
    }
    /// A signer that records whether it was asked to sign.
    #[derive(Default)]
    struct RecordingSigner {
        signed: AtomicBool,
    }

    #[async_trait]
    impl HybridSigner for RecordingSigner {
        fn p256_public_key(&self) -> [u8; 64] {
            [7; 64]
        }
        fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
            None
        }
        async fn sign_composite(&self, _m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
            self.signed.store(true, Ordering::SeqCst);
            Ok(([9; 64], None))
        }
        async fn sign_p256(&self, _message: &[u8]) -> SdkResult<[u8; 64]> {
            unreachable!()
        }
    }

    /// Answers one JSON-RPC request per reply, in order, and returns the
    /// requests the client sent. A reply is the JSON-RPC `result`, or an
    /// `{"error": ..}` object sent as the error.
    async fn serve(
        listener: tokio::net::TcpListener,
        replies: Vec<serde_json::Value>,
    ) -> Vec<serde_json::Value> {
        let mut requests = Vec::new();
        for reply in replies {
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
            let mut body = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"] });
            match reply.get("error") {
                Some(error) => body["error"] = error.clone(),
                None => body["result"] = reply,
            }
            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(response.as_bytes()).await.unwrap();
            requests.push(request);
        }
        requests
    }

    /// Runs `send_self_custody` against a node giving `replies`.
    ///
    /// The node first answers the recipient check: the two look-alike
    /// thresholds (unset here, so the defaults apply) and the account's
    /// history, which lists the recipient as one it has paid. `replies` are
    /// the answers after that, and the requests returned are those after it.
    async fn send_with(
        replies: Vec<serde_json::Value>,
    ) -> (SdkResult<String>, Vec<serde_json::Value>, bool, String) {
        let unset = serde_json::json!({ "error": { "code": -32601, "message": "not set" } });
        let paid = serde_json::json!({ "transactions": [{
            "from": format!("0x{}", hex::encode(account_address(&[7u8; 64]))),
            "to": format!("0x{}", hex::encode([3u8; 32])),
        }] });
        let mut all = vec![unset.clone(), unset, paid];
        all.extend(replies);
        let replies = all;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(serve(listener, replies));
        let rpc = RpcClient::new(&url, std::time::Duration::from_secs(10), None).unwrap();
        let wallet = WalletClient::new(Arc::new(rpc));
        let recording = Arc::new(RecordingSigner::default());
        let signer: Arc<dyn HybridSigner> = recording.clone();
        let out = wallet
            .send_self_custody(&signer, Address::new([3; 32]), 5)
            .await;
        if out.is_err() {
            server.abort();
            return (
                out,
                Vec::new(),
                recording.signed.load(Ordering::SeqCst),
                url,
            );
        }
        let mut requests = server.await.unwrap();
        requests.drain(..3);
        (out, requests, recording.signed.load(Ordering::SeqCst), url)
    }

    #[tokio::test]
    async fn self_custody_signs_with_the_nonce_and_chain_id_the_node_reports() {
        let (out, requests, signed, _) = send_with(vec![
            serde_json::json!("0x5"),
            serde_json::json!("0x20aa9"),
            serde_json::json!("0xabc"),
        ])
        .await;
        assert_eq!(out.unwrap(), "0xabc");
        assert!(signed);
        let sent = &requests[2];
        assert_eq!(sent["method"], "tenzro_sendRawTransaction");
        assert_eq!(sent["params"]["nonce"], 5);
        assert_eq!(sent["params"]["chain_id"], 133801);
    }

    #[tokio::test]
    async fn self_custody_fails_when_the_chain_id_cannot_be_read() {
        let (out, _, signed, url) = send_with(vec![
            serde_json::json!("0x5"),
            serde_json::json!({ "error": { "code": -32603, "message": "unavailable" } }),
        ])
        .await;
        let err = out.unwrap_err().to_string();
        assert!(
            err.contains(&format!("could not read the chain id from {url}")),
            "{err}"
        );
        assert!(!signed);
    }

    #[tokio::test]
    async fn self_custody_fails_when_the_nonce_cannot_be_read() {
        let (out, _, signed, url) = send_with(vec![serde_json::json!({
            "error": { "code": -32603, "message": "unavailable" }
        })])
        .await;
        let err = out.unwrap_err().to_string();
        assert!(
            err.contains(&format!("could not read the nonce from {url}")),
            "{err}"
        );
        assert!(!signed);
    }

    #[tokio::test]
    async fn self_custody_fails_on_a_malformed_chain_id() {
        let (out, _, signed, _) =
            send_with(vec![serde_json::json!("0x5"), serde_json::json!("0xzz")]).await;
        let err = out.unwrap_err().to_string();
        assert!(err.contains("could not read the chain id"), "{err}");
        assert!(!signed);
    }

    #[tokio::test]
    async fn self_custody_fails_on_a_malformed_nonce() {
        let (out, _, signed, _) = send_with(vec![serde_json::json!("")]).await;
        let err = out.unwrap_err().to_string();
        assert!(err.contains("could not read the nonce"), "{err}");
        assert!(!signed);
    }

    #[test]
    fn a_quantity_is_hex_or_an_error() {
        assert_eq!(parse_quantity("0x20aa9"), Ok(133801));
        assert_eq!(parse_quantity("ff"), Ok(255));
        for bad in ["", "0x", "0x+1", "0x1g", " 0x1", "0x1_0"] {
            assert!(parse_quantity(bad).is_err(), "{bad:?}");
        }
    }
}
