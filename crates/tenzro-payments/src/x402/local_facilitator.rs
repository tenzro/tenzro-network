//! Self-hosted x402 facilitator.
//!
//! Runs the exact/EVM scheme's verification checks and settles locally,
//! without delegating to a remote facilitator HTTP endpoint. This is the
//! default facilitator: an operator brokers the settlement transaction
//! through its own EVM signer rather than routing the signed authorization
//! to a third party. [`crate::x402::scheme::CdpFacilitatorVerifier`] remains
//! constructible as an alternative route when an operator prefers to defer
//! to the Coinbase CDP facilitator.
//!
//! Reference implementation: the x402-rs self-hosted facilitator. The eight
//! admission checks of the exact/EVM scheme are:
//!
//! 1. the signature recovers to `authorization.from`;
//! 2. `authorization.to == requirement.pay_to`;
//! 3. `authorization.value == requirement.max_amount_required`;
//! 4. `valid_after <= now < valid_before`;
//! 5. the EIP-3009 nonce is unused (`authorizationState(from, nonce)` eth_call);
//! 6. the payload asset + network match the requirement;
//! 7. `balanceOf(from) >= value`;
//! 8. `transferWithAuthorization` succeeds in an eth_call simulation.
//!
//! Settlement broadcasts the `transferWithAuthorization` transaction through
//! [`tenzro_bridge::EvmTransactionSigner`].

use std::sync::Arc;

use async_trait::async_trait;
use sha3::{Digest, Keccak256};
use tenzro_bridge::EvmTransactionSigner;

use crate::error::{PaymentError, Result};
use crate::x402::coinbase::TransferWithAuthorization;
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequirement;
use crate::x402::scheme::FacilitatorVerifier;

/// `authorizationState(address,bytes32)` selector — keccak256 first 4 bytes.
const AUTHORIZATION_STATE_SELECTOR: [u8; 4] = [0xe9, 0x4a, 0x01, 0x02];
/// `balanceOf(address)` selector.
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
/// EIP-712 domain typehash string.
const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Default EIP-712 domain name for the USDC contract family (Circle FiatToken).
const DEFAULT_EIP712_NAME: &str = "USD Coin";
/// Default EIP-712 domain version for the USDC contract family.
const DEFAULT_EIP712_VERSION: &str = "2";

/// A minimal JSON-RPC EVM client used for the read-only admission checks
/// (nonce state, balance, transfer simulation). Settlement uses the signer's
/// own client; this one only needs `eth_call`.
#[derive(Debug, Clone)]
struct EvmReadClient {
    http: reqwest::Client,
    rpc_url: String,
}

impl EvmReadClient {
    fn new(rpc_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url,
        }
    }

    /// `eth_call` against `to` with `data`, from optional `from`. Returns the
    /// 0x-prefixed hex result string. Reverts surface as
    /// `PaymentError::VerificationFailed`.
    async fn eth_call(&self, to: &str, data: &[u8], from: Option<&str>) -> Result<String> {
        let mut call = serde_json::json!({
            "to": to,
            "data": format!("0x{}", hex::encode(data)),
        });
        if let Some(f) = from {
            call["from"] = serde_json::json!(f);
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [call, "latest"],
        });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        if let Some(err) = resp.get("error") {
            return Err(PaymentError::VerificationFailed(format!(
                "x402 self-hosted eth_call reverted: {}",
                err
            )));
        }
        resp.get("result")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                PaymentError::VerificationFailed(
                    "x402 self-hosted eth_call returned no result".to_string(),
                )
            })
    }
}

/// Self-hosted facilitator verifier for the exact/EVM scheme.
///
/// Constructed with the operator's [`EvmTransactionSigner`] (the settlement
/// engine) and the EVM RPC URL used for the read-only admission checks. The
/// chain id is read from the signer.
pub struct LocalFacilitatorVerifier {
    signer: Arc<EvmTransactionSigner>,
    read: EvmReadClient,
}

impl std::fmt::Debug for LocalFacilitatorVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalFacilitatorVerifier")
            .field("relayer", &self.signer.sender_address())
            .field("read", &self.read)
            .finish()
    }
}

impl LocalFacilitatorVerifier {
    /// Build a self-hosted verifier over the given settlement signer and the
    /// EVM RPC URL used for read-only checks.
    pub fn new(signer: Arc<EvmTransactionSigner>, rpc_url: impl Into<String>) -> Self {
        Self {
            signer,
            read: EvmReadClient::new(rpc_url.into()),
        }
    }

    /// The settlement signer's sender address (the operator relayer).
    pub fn relayer_address(&self) -> String {
        self.signer.sender_address()
    }

    /// Decode the base64 payload + requirement JSON pair the facilitator
    /// interface carries.
    fn decode_envelope(
        payload_b64: &str,
        requirements_b64: &str,
    ) -> Result<(X402PaymentPayload, X402PaymentRequirement)> {
        let payload_json = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            payload_b64,
        )
        .map_err(|e| PaymentError::VerificationFailed(format!("payload base64 invalid: {}", e)))?;
        let payload: X402PaymentPayload = serde_json::from_slice(&payload_json)
            .map_err(|e| PaymentError::VerificationFailed(format!("payload JSON invalid: {}", e)))?;

        let req_json = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            requirements_b64,
        )
        .map_err(|e| {
            PaymentError::VerificationFailed(format!("requirements base64 invalid: {}", e))
        })?;
        // Requirements may arrive as a single requirement or the full
        // `X402PaymentRequired` envelope; accept either.
        let requirement = if let Ok(single) =
            serde_json::from_slice::<X402PaymentRequirement>(&req_json)
        {
            single
        } else {
            let required: crate::x402::payment_required::X402PaymentRequired =
                serde_json::from_slice(&req_json).map_err(|e| {
                    PaymentError::VerificationFailed(format!("requirements JSON invalid: {}", e))
                })?;
            required
                .accepts
                .into_iter()
                .next()
                .ok_or_else(|| {
                    PaymentError::VerificationFailed(
                        "requirements envelope carries no accepts entry".to_string(),
                    )
                })?
        };
        Ok((payload, requirement))
    }

    /// Resolve the numeric chain id from a CAIP-2 `eip155:<id>` network string.
    fn chain_id_from_network(network: &str) -> Result<u64> {
        network
            .strip_prefix("eip155:")
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "network '{}' is not an eip155 CAIP-2 identifier",
                    network
                ))
            })
    }

    /// The EIP-712 verifying contract for the authorization — the token
    /// contract. Falls back to the requirement `asset` when `extra` carries no
    /// explicit override.
    fn verifying_contract(requirement: &X402PaymentRequirement) -> Result<String> {
        let addr = requirement
            .extra
            .get("verifyingContract")
            .and_then(|v| v.as_str())
            .unwrap_or(requirement.asset.as_str());
        if !addr.starts_with("0x") || addr.len() != 42 {
            return Err(PaymentError::VerificationFailed(format!(
                "verifying contract '{}' is not a 20-byte EVM address",
                addr
            )));
        }
        Ok(addr.to_string())
    }

    /// Compute the EIP-712 signing digest for the `TransferWithAuthorization`
    /// struct under the token's domain: `keccak256(0x1901 || domainSeparator
    /// || structHash)`.
    fn transfer_digest(
        auth: &TransferWithAuthorization,
        requirement: &X402PaymentRequirement,
        chain_id: u64,
    ) -> Result<[u8; 32]> {
        let name = requirement
            .extra
            .get("eip712Name")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_EIP712_NAME);
        let version = requirement
            .extra
            .get("eip712Version")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_EIP712_VERSION);
        let verifying = Self::verifying_contract(requirement)?;

        // domainSeparator = keccak256(abi.encode(
        //   keccak256(EIP712Domain(...)), keccak256(name), keccak256(version),
        //   chainId, verifyingContract))
        let mut dbuf = Vec::with_capacity(32 * 5);
        dbuf.extend_from_slice(&keccak256(EIP712_DOMAIN_TYPE.as_bytes()));
        dbuf.extend_from_slice(&keccak256(name.as_bytes()));
        dbuf.extend_from_slice(&keccak256(version.as_bytes()));
        dbuf.extend_from_slice(&uint256_word(chain_id as u128));
        dbuf.extend_from_slice(&address_word(&parse_address(&verifying)?));
        let domain_separator = keccak256(&dbuf);

        // structHash = keccak256(abi.encode(
        //   TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter,
        //   validBefore, nonce))
        let mut sbuf = Vec::with_capacity(32 * 7);
        sbuf.extend_from_slice(&keccak256(TransferWithAuthorization::type_hash().as_bytes()));
        sbuf.extend_from_slice(&address_word(&parse_address(&auth.from)?));
        sbuf.extend_from_slice(&address_word(&parse_address(&auth.to)?));
        sbuf.extend_from_slice(&uint256_word(parse_u128(&auth.value)?));
        sbuf.extend_from_slice(&uint256_word(auth.valid_after as u128));
        sbuf.extend_from_slice(&uint256_word(auth.valid_before as u128));
        sbuf.extend_from_slice(&parse_bytes32(&auth.nonce)?);
        let struct_hash = keccak256(&sbuf);

        let mut digest_buf = Vec::with_capacity(2 + 32 + 32);
        digest_buf.extend_from_slice(&[0x19, 0x01]);
        digest_buf.extend_from_slice(&domain_separator);
        digest_buf.extend_from_slice(&struct_hash);
        Ok(keccak256(&digest_buf))
    }

    /// Run the eight admission checks, returning the resolved
    /// `TransferWithAuthorization` + parsed signature parts on success so the
    /// settle path can reuse them.
    async fn admit(
        &self,
        payload: &X402PaymentPayload,
        requirement: &X402PaymentRequirement,
    ) -> Result<AdmittedTransfer> {
        // check 6 — asset + network parity between payload and requirement.
        if payload.network != requirement.network {
            return Err(PaymentError::VerificationFailed(format!(
                "payload network '{}' does not match requirement network '{}'",
                payload.network, requirement.network
            )));
        }
        let chain_id = Self::chain_id_from_network(&requirement.network)?;

        let auth = TransferWithAuthorization {
            from: payload.payload.authorization.from.clone(),
            to: payload.payload.authorization.to.clone(),
            value: payload.payload.authorization.value.clone(),
            valid_after: payload.payload.authorization.valid_after,
            valid_before: payload.payload.authorization.valid_before,
            nonce: payload.payload.authorization.nonce.clone(),
        };

        // check 2 — recipient parity.
        if !addr_eq(&auth.to, &requirement.pay_to) {
            return Err(PaymentError::VerificationFailed(format!(
                "authorization.to '{}' does not match requirement.pay_to '{}'",
                auth.to, requirement.pay_to
            )));
        }

        // check 3 — exact amount parity.
        let value = parse_u128(&auth.value)?;
        let required = parse_u128(&requirement.max_amount_required)?;
        if value != required {
            return Err(PaymentError::VerificationFailed(format!(
                "authorization.value {} does not equal maxAmountRequired {}",
                value, required
            )));
        }

        // check 4 — time window.
        let now = chrono::Utc::now().timestamp() as u64;
        if now < auth.valid_after {
            return Err(PaymentError::VerificationFailed(format!(
                "authorization not yet valid (validAfter {} > now {})",
                auth.valid_after, now
            )));
        }
        if now >= auth.valid_before {
            return Err(PaymentError::VerificationFailed(format!(
                "authorization expired (validBefore {} <= now {})",
                auth.valid_before, now
            )));
        }

        // check 1 — signature recovers to `from`.
        let sig = parse_hex(&payload.payload.signature)?;
        let (v, r, s) = split_signature(&sig)?;
        let digest = Self::transfer_digest(&auth, requirement, chain_id)?;
        let recovered = crate::x402::erc7710::recover_signer(&digest, &sig)?;
        let from = parse_address(&auth.from)?;
        if recovered != from {
            return Err(PaymentError::VerificationFailed(format!(
                "signature recovers to 0x{} but authorization.from is {}",
                hex::encode(recovered),
                auth.from
            )));
        }

        let token = Self::verifying_contract(requirement)?;

        // check 5 — nonce unused: authorizationState(from, nonce) == false.
        let mut nonce_data = Vec::with_capacity(4 + 64);
        nonce_data.extend_from_slice(&AUTHORIZATION_STATE_SELECTOR);
        nonce_data.extend_from_slice(&address_word(&from));
        nonce_data.extend_from_slice(&parse_bytes32(&auth.nonce)?);
        let state = self.read.eth_call(&token, &nonce_data, None).await?;
        if word_is_true(&state) {
            return Err(PaymentError::VerificationFailed(
                "authorization nonce already used".to_string(),
            ));
        }

        // check 7 — balanceOf(from) >= value.
        let mut bal_data = Vec::with_capacity(4 + 32);
        bal_data.extend_from_slice(&BALANCE_OF_SELECTOR);
        bal_data.extend_from_slice(&address_word(&from));
        let bal_hex = self.read.eth_call(&token, &bal_data, None).await?;
        let balance = parse_word_u128(&bal_hex)?;
        if balance < value {
            return Err(PaymentError::InsufficientFunds(format!(
                "balanceOf(from) {} < value {}",
                balance, value
            )));
        }

        // check 8 — simulate transferWithAuthorization from the relayer.
        let calldata = auth.encode_calldata(v, &r, &s);
        let relayer = self.signer.sender_address();
        self.read
            .eth_call(&token, &calldata, Some(&relayer))
            .await?;

        Ok(AdmittedTransfer {
            token,
            calldata,
        })
    }
}

/// The verified transfer ready to settle: the token contract and the
/// pre-encoded `transferWithAuthorization` calldata.
struct AdmittedTransfer {
    token: String,
    calldata: Vec<u8>,
}

#[async_trait]
impl FacilitatorVerifier for LocalFacilitatorVerifier {
    async fn verify_payload(&self, payload_b64: &str, requirements_b64: &str) -> Result<()> {
        let (payload, requirement) = Self::decode_envelope(payload_b64, requirements_b64)?;
        self.admit(&payload, &requirement).await.map(|_| ())
    }

    async fn settle_payload(&self, payload_b64: &str, requirements_b64: &str) -> Result<String> {
        let (payload, requirement) = Self::decode_envelope(payload_b64, requirements_b64)?;
        let admitted = self.admit(&payload, &requirement).await?;
        self.signer
            .send_transaction(&admitted.token, &admitted.calldata, 0)
            .await
            .map_err(|e| PaymentError::SettlementError(e.to_string()))
    }
}

// ─── ABI / hex helpers ─────────────────────────────────────────────────────

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// Left-pad a 20-byte address into a 32-byte ABI word.
fn address_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word
}

/// Encode a u128 as a big-endian uint256 word.
fn uint256_word(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Parse a `0x`-prefixed 20-byte EVM address.
fn parse_address(s: &str) -> Result<[u8; 20]> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean)
        .map_err(|e| PaymentError::VerificationFailed(format!("address hex invalid: {}", e)))?;
    if bytes.len() != 20 {
        return Err(PaymentError::VerificationFailed(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Parse a `0x`-prefixed 32-byte value (nonce).
fn parse_bytes32(s: &str) -> Result<[u8; 32]> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean)
        .map_err(|e| PaymentError::VerificationFailed(format!("bytes32 hex invalid: {}", e)))?;
    if bytes.len() != 32 {
        return Err(PaymentError::VerificationFailed(format!(
            "bytes32 must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse arbitrary `0x`-prefixed hex bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(clean)
        .map_err(|e| PaymentError::VerificationFailed(format!("hex invalid: {}", e)))
}

/// Parse a decimal string into u128.
fn parse_u128(s: &str) -> Result<u128> {
    s.parse::<u128>()
        .map_err(|e| PaymentError::VerificationFailed(format!("uint value '{}' invalid: {}", s, e)))
}

/// Split a 65-byte `r || s || v` signature into `(v, r, s)` with `v` normalized
/// to `{27, 28}` for the EIP-3009 contract call.
fn split_signature(sig: &[u8]) -> Result<(u8, [u8; 32], [u8; 32])> {
    if sig.len() != 65 {
        return Err(PaymentError::VerificationFailed(format!(
            "signature must be 65 bytes, got {}",
            sig.len()
        )));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..64]);
    let v = sig[64];
    let v = if v < 27 { v + 27 } else { v };
    Ok((v, r, s))
}

/// Compare two EVM addresses case-insensitively (allows differing checksums).
fn addr_eq(a: &str, b: &str) -> bool {
    let ca = a.strip_prefix("0x").unwrap_or(a).to_ascii_lowercase();
    let cb = b.strip_prefix("0x").unwrap_or(b).to_ascii_lowercase();
    ca == cb
}

/// Interpret a 32-byte ABI word hex string as a boolean (nonzero == true).
fn word_is_true(hex_word: &str) -> bool {
    let clean = hex_word.strip_prefix("0x").unwrap_or(hex_word);
    clean.chars().any(|c| c != '0')
}

/// Parse a 32-byte ABI word hex string as a u128 (low 128 bits).
fn parse_word_u128(hex_word: &str) -> Result<u128> {
    let clean = hex_word.strip_prefix("0x").unwrap_or(hex_word);
    let bytes = hex::decode(clean)
        .map_err(|e| PaymentError::VerificationFailed(format!("word hex invalid: {}", e)))?;
    if bytes.is_empty() {
        return Ok(0);
    }
    // Take the low 16 bytes; reject if the high bytes are set (would truncate).
    let len = bytes.len();
    if len > 16 {
        let (high, low) = bytes.split_at(len - 16);
        if high.iter().any(|&b| b != 0) {
            return Err(PaymentError::VerificationFailed(
                "balance exceeds u128 range".to_string(),
            ));
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(low);
        Ok(u128::from_be_bytes(buf))
    } else {
        let mut buf = [0u8; 16];
        buf[16 - len..].copy_from_slice(&bytes);
        Ok(u128::from_be_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::erc7710::evm_address_from_verifying_key;
    use chrono::Utc;
    use k256::ecdsa::SigningKey;

    fn test_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        SigningKey::from_slice(&bytes).unwrap()
    }

    fn requirement(pay_to: &str, asset: &str, amount: &str, network: &str) -> X402PaymentRequirement {
        X402PaymentRequirement {
            scheme: "exact-eip3009".to_string(),
            network: network.to_string(),
            max_amount_required: amount.to_string(),
            resource: "https://example/resource".to_string(),
            description: String::new(),
            mime_type: "application/json".to_string(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 300,
            asset: asset.to_string(),
            output_schema: None,
            expires_at: Utc::now(),
            extra: serde_json::json!({}),
        }
    }

    #[test]
    fn chain_id_parses_eip155() {
        assert_eq!(
            LocalFacilitatorVerifier::chain_id_from_network("eip155:8453").unwrap(),
            8453
        );
        assert!(LocalFacilitatorVerifier::chain_id_from_network("solana:mainnet").is_err());
    }

    #[test]
    fn verifying_contract_defaults_to_asset() {
        let req = requirement(
            "0x000000000000000000000000000000000000dEaD",
            "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "1000000",
            "eip155:84532",
        );
        assert_eq!(
            LocalFacilitatorVerifier::verifying_contract(&req).unwrap(),
            "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
        );
    }

    #[test]
    fn word_bool_and_u128_parse() {
        assert!(!word_is_true("0x0000000000000000000000000000000000000000000000000000000000000000"));
        assert!(word_is_true("0x0000000000000000000000000000000000000000000000000000000000000001"));
        assert_eq!(
            parse_word_u128("0x00000000000000000000000000000000000000000000000000000000000f4240")
                .unwrap(),
            1_000_000
        );
    }

    #[test]
    fn split_signature_normalizes_v() {
        let mut sig = [0u8; 65];
        sig[64] = 0; // recid 0 → v 27
        let (v, _, _) = split_signature(&sig).unwrap();
        assert_eq!(v, 27);
        sig[64] = 1;
        let (v, _, _) = split_signature(&sig).unwrap();
        assert_eq!(v, 28);
        sig[64] = 28; // already normalized
        let (v, _, _) = split_signature(&sig).unwrap();
        assert_eq!(v, 28);
    }

    #[test]
    fn digest_recovers_signer() {
        // Sign a TransferWithAuthorization digest and confirm the same digest
        // recovers the signer address — exercising check 1's math offline.
        let sk = test_key(9);
        let from_addr = evm_address_from_verifying_key(sk.verifying_key());
        let from = format!("0x{}", hex::encode(from_addr));
        let pay_to = "0x000000000000000000000000000000000000dEaD";
        let asset = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

        let auth = TransferWithAuthorization {
            from: from.clone(),
            to: pay_to.to_string(),
            value: "1000000".to_string(),
            valid_after: 0,
            valid_before: u64::MAX,
            nonce: format!("0x{}", hex::encode([7u8; 32])),
        };
        let req = requirement(pay_to, asset, "1000000", "eip155:84532");
        let digest = LocalFacilitatorVerifier::transfer_digest(&auth, &req, 84532).unwrap();

        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(recid.to_byte());
        let recovered = crate::x402::erc7710::recover_signer(&digest, &sig65).unwrap();
        assert_eq!(recovered, from_addr);
    }
}
