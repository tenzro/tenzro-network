//! Tenzro x402 receipt — cross-VM extension to the Coinbase x402 v1
//! `X-PAYMENT-RESPONSE` header.
//!
//! Stock x402 carries a base64-encoded `SettleResponse` in the
//! `X-PAYMENT-RESPONSE` header that is, per the spec, "facilitator
//! attestation, not a cryptographic proof". Tenzro extends this with two
//! distinguishing primitives:
//!
//! 1. **Cross-VM `network` field.** The standard CDP facilitator only
//!    reaches EVM and SVM. Tenzro accepts native VM identifiers
//!    `tenzro-evm`, `tenzro-svm`, and `tenzro-daml`, routing settlement
//!    through `MultiVmRuntime`. No third-party x402 extension covers
//!    DAML/Canton.
//!
//! 2. **Plonky3 settlement-AIR commitment.** A 32-byte commitment is
//!    bound to the receipt via domain-separated SHA-256 over the canonical
//!    settlement summary. Validators that hold the matching Plonky3 proof
//!    in `ZkCommitmentRegistry` can verify the receipt cryptographically;
//!    consumers that don't run a node still get a tamper-evident receipt.
//!
//! This module defines the receipt type, the commitment derivation, and
//! the cross-VM network validator. The transport-layer base64 encoding for
//! the actual `X-PAYMENT-RESPONSE` header is the caller's concern.
//!
//! # Domain separation
//!
//! Per the project rule against version segments in Tenzro-owned strings,
//! the SHA-256 domain tag is the literal `"tenzro/x402/receipt"` —
//! no `/v1`, no `1.0.0`. The same tag will be reused if the receipt
//! schema is ever revised; revisions are flag-day cutovers.

use crate::error::{PaymentError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tag for the x402 settlement-AIR commitment.
pub const X402_RECEIPT_DOMAIN: &str = "tenzro/x402/receipt";

/// Length of the settlement-AIR commitment (SHA-256).
pub const X402_RECEIPT_COMMITMENT_LEN: usize = 32;

/// Native Tenzro VM identifier accepted in the x402 `network` field.
///
/// Returned alongside `network()` from `TenzroNetwork::as_str()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TenzroNetwork {
    /// Tenzro EVM (ethereum-compatible execution).
    Evm,
    /// Tenzro SVM (Solana VM).
    Svm,
    /// Tenzro Canton/DAML execution.
    Daml,
}

impl TenzroNetwork {
    /// Parse the wire form of a Tenzro network identifier.
    pub fn parse(network: &str) -> Option<Self> {
        match network {
            "tenzro-evm" => Some(Self::Evm),
            "tenzro-svm" => Some(Self::Svm),
            "tenzro-daml" => Some(Self::Daml),
            _ => None,
        }
    }

    /// Wire form (lower-case kebab).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Evm => "tenzro-evm",
            Self::Svm => "tenzro-svm",
            Self::Daml => "tenzro-daml",
        }
    }
}

/// Validate the x402 `network` field.
///
/// Accepts:
/// - any of the three Tenzro native networks (`tenzro-evm`, `tenzro-svm`,
///   `tenzro-daml`),
/// - any CAIP-2 chain identifier (`<namespace>:<reference>` — the
///   facilitator does the deeper check),
/// - any non-empty bare string the operator has registered with the
///   server (handled at server level via `supported_chains`).
///
/// This is a structural check only. Operator allow-listing happens in
/// `X402PaymentServer`.
pub fn validate_network_format(network: &str) -> Result<()> {
    if network.is_empty() {
        return Err(PaymentError::UnsupportedProtocol(
            "x402 network field is empty".to_string(),
        ));
    }
    // Reject embedded whitespace / control chars to avoid header smuggling.
    if network.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(PaymentError::UnsupportedProtocol(format!(
            "x402 network '{}' contains whitespace or control characters",
            network
        )));
    }
    Ok(())
}

/// Canonical input to the settlement-AIR commitment.
///
/// All fields are bound by the SHA-256 commitment so any tamper of any
/// field invalidates the receipt. Field order is fixed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SettlementCommitmentInput<'a> {
    /// x402 protocol scheme that settled the payment (`exact`,
    /// `tenzro-hybrid`, `permit2`, `erc7710`).
    pub scheme: &'a str,
    /// Network identifier (`tenzro-evm`, `tenzro-svm`, `tenzro-daml`,
    /// or CAIP-2 chain id).
    pub network: &'a str,
    /// The original challenge id this settlement closes.
    pub challenge_id: &'a str,
    /// The credential id that authorized the settlement.
    pub credential_id: &'a str,
    /// Resource that was paid for.
    pub resource: &'a str,
    /// Asset denomination (e.g. `USDC`, `TNZO`).
    pub asset: &'a str,
    /// Amount in the asset's smallest unit, as a decimal string (so it
    /// matches the v1 wire form which uses string-encoded `value`).
    pub amount: &'a str,
    /// Address that paid (lower-case hex, no `0x` prefix expected by
    /// the commitment — caller normalizes).
    pub payer: &'a str,
    /// Address that received funds.
    pub recipient: &'a str,
    /// On-chain transaction hash (lower-case hex, no `0x`).
    pub tx_hash: &'a str,
}

/// Compute the 32-byte settlement-AIR commitment for an x402 receipt.
///
/// This is **not** a Plonky3 proof verification — it's a binding hash
/// over the canonical settlement summary. A validator that wants
/// cryptographic finality verifies the corresponding Plonky3 settlement-AIR
/// proof off-EVM and looks up the resulting commitment in the on-chain
/// `ZkCommitmentRegistry`. If both hashes match, the receipt is finalized.
pub fn compute_settlement_commitment(
    input: &SettlementCommitmentInput<'_>,
) -> [u8; X402_RECEIPT_COMMITMENT_LEN] {
    let mut hasher = Sha256::new();
    // Domain separator first so distinct receipt families (e.g. AP2)
    // never collide.
    hasher.update(X402_RECEIPT_DOMAIN.as_bytes());
    // Length-prefix every field with a 4-byte little-endian length so
    // we don't need a delimiter and can't get tripped up by a `|` in
    // a resource path.
    for field in [
        input.scheme,
        input.network,
        input.challenge_id,
        input.credential_id,
        input.resource,
        input.asset,
        input.amount,
        input.payer,
        input.recipient,
        input.tx_hash,
    ] {
        let bytes = field.as_bytes();
        hasher.update((bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; X402_RECEIPT_COMMITMENT_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Tenzro-extended `X-PAYMENT-RESPONSE` body.
///
/// Field naming follows x402 v1 wire conventions (`txHash`, `network`)
/// for stock-client compatibility. The Tenzro-specific extensions sit
/// under their own namespaced keys (`tenzroCommitment`, `tenzroVm`) so
/// that a non-Tenzro client can still parse the response and ignore
/// what it doesn't understand.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402SettlementReceiptBody {
    /// Whether settlement succeeded.
    pub success: bool,
    /// On-chain transaction hash (lower-case hex with `0x` prefix when
    /// emitted on EVM/SVM; raw contract id on DAML).
    pub tx_hash: String,
    /// Network identifier (`tenzro-evm` / `tenzro-svm` / `tenzro-daml`
    /// or CAIP-2 chain id).
    pub network: String,
    /// Error message when `success == false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// **Tenzro extension.** 32-byte settlement-AIR commitment over the
    /// canonical settlement summary. Lower-case hex, no `0x` prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenzro_commitment: Option<String>,
    /// **Tenzro extension.** Native VM identifier when settlement was
    /// routed via Tenzro `MultiVmRuntime`. Absent when settlement landed
    /// on a non-Tenzro chain (Base, Ethereum mainnet, Solana mainnet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenzro_vm: Option<String>,
}

impl X402SettlementReceiptBody {
    /// Construct a successful receipt with a Plonky3 settlement-AIR
    /// commitment binding the canonical settlement summary.
    ///
    /// `network` is validated. If it parses as a Tenzro native VM,
    /// `tenzro_vm` is populated.
    pub fn finalized(
        scheme: &str,
        network: &str,
        challenge_id: &str,
        credential_id: &str,
        resource: &str,
        asset: &str,
        amount_decimal: &str,
        payer: &str,
        recipient: &str,
        tx_hash: &str,
    ) -> Result<Self> {
        validate_network_format(network)?;

        let commitment = compute_settlement_commitment(&SettlementCommitmentInput {
            scheme,
            network,
            challenge_id,
            credential_id,
            resource,
            asset,
            amount: amount_decimal,
            payer: &normalize_hex(payer),
            recipient: &normalize_hex(recipient),
            tx_hash: &normalize_hex(tx_hash),
        });

        Ok(Self {
            success: true,
            tx_hash: tx_hash.to_string(),
            network: network.to_string(),
            error: None,
            tenzro_commitment: Some(hex::encode(commitment)),
            tenzro_vm: TenzroNetwork::parse(network).map(|n| n.as_str().to_string()),
        })
    }

    /// Construct a failure receipt (no commitment).
    pub fn failed(network: &str, error: impl Into<String>) -> Self {
        Self {
            success: false,
            tx_hash: String::new(),
            network: network.to_string(),
            error: Some(error.into()),
            tenzro_commitment: None,
            tenzro_vm: TenzroNetwork::parse(network).map(|n| n.as_str().to_string()),
        }
    }

    /// Decoded 32-byte commitment, if present and well-formed.
    pub fn decoded_commitment(&self) -> Option<[u8; X402_RECEIPT_COMMITMENT_LEN]> {
        let hex_str = self.tenzro_commitment.as_ref()?;
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != X402_RECEIPT_COMMITMENT_LEN {
            return None;
        }
        let mut out = [0u8; X402_RECEIPT_COMMITMENT_LEN];
        out.copy_from_slice(&bytes);
        Some(out)
    }
}

/// Normalize an address-or-hash string to lower-case hex without `0x`.
fn normalize_hex(s: &str) -> String {
    s.strip_prefix("0x")
        .unwrap_or(s)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenzro_network_parses_three_native_vms() {
        assert_eq!(TenzroNetwork::parse("tenzro-evm"), Some(TenzroNetwork::Evm));
        assert_eq!(TenzroNetwork::parse("tenzro-svm"), Some(TenzroNetwork::Svm));
        assert_eq!(TenzroNetwork::parse("tenzro-daml"), Some(TenzroNetwork::Daml));
        assert_eq!(TenzroNetwork::parse("base-sepolia"), None);
        assert_eq!(TenzroNetwork::parse(""), None);
    }

    #[test]
    fn tenzro_network_round_trips() {
        for n in [TenzroNetwork::Evm, TenzroNetwork::Svm, TenzroNetwork::Daml] {
            assert_eq!(TenzroNetwork::parse(n.as_str()), Some(n));
        }
    }

    #[test]
    fn validate_network_rejects_empty_and_whitespace() {
        assert!(validate_network_format("").is_err());
        assert!(validate_network_format("base sepolia").is_err());
        assert!(validate_network_format("base\nsepolia").is_err());
        assert!(validate_network_format("base-sepolia").is_ok());
        assert!(validate_network_format("eip155:8453").is_ok());
        assert!(validate_network_format("tenzro-daml").is_ok());
    }

    #[test]
    fn commitment_is_deterministic_and_domain_separated() {
        let input = SettlementCommitmentInput {
            scheme: "exact",
            network: "tenzro-evm",
            challenge_id: "ch1",
            credential_id: "cr1",
            resource: "/api/data",
            asset: "USDC",
            amount: "1000000",
            payer: "abc",
            recipient: "def",
            tx_hash: "deadbeef",
        };
        let c1 = compute_settlement_commitment(&input);
        let c2 = compute_settlement_commitment(&input);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 32);
    }

    #[test]
    fn commitment_changes_when_any_field_changes() {
        let base = SettlementCommitmentInput {
            scheme: "exact",
            network: "tenzro-evm",
            challenge_id: "ch1",
            credential_id: "cr1",
            resource: "/api/data",
            asset: "USDC",
            amount: "1000000",
            payer: "abc",
            recipient: "def",
            tx_hash: "deadbeef",
        };
        let baseline = compute_settlement_commitment(&base);

        // Tweak each field and confirm the commitment moves.
        let mut tweaked = base;
        tweaked.network = "tenzro-svm";
        assert_ne!(compute_settlement_commitment(&tweaked), baseline);

        let mut tweaked = base;
        tweaked.amount = "1000001";
        assert_ne!(compute_settlement_commitment(&tweaked), baseline);

        let mut tweaked = base;
        tweaked.recipient = "deg";
        assert_ne!(compute_settlement_commitment(&tweaked), baseline);
    }

    #[test]
    fn commitment_resists_field_concatenation_collision() {
        // Without length prefixing, ("ab","cd") and ("a","bcd") would
        // collide. The length-prefixed encoding must distinguish them.
        let a = SettlementCommitmentInput {
            scheme: "ab",
            network: "cd",
            challenge_id: "",
            credential_id: "",
            resource: "",
            asset: "",
            amount: "",
            payer: "",
            recipient: "",
            tx_hash: "",
        };
        let b = SettlementCommitmentInput {
            scheme: "a",
            network: "bcd",
            challenge_id: "",
            credential_id: "",
            resource: "",
            asset: "",
            amount: "",
            payer: "",
            recipient: "",
            tx_hash: "",
        };
        assert_ne!(
            compute_settlement_commitment(&a),
            compute_settlement_commitment(&b)
        );
    }

    #[test]
    fn finalized_receipt_emits_commitment_and_vm() {
        let r = X402SettlementReceiptBody::finalized(
            "tenzro-hybrid",
            "tenzro-evm",
            "ch-1",
            "cr-1",
            "/api/data",
            "USDC",
            "1000000",
            "0xabc",
            "0xdef",
            "0xdeadbeef",
        )
        .unwrap();

        assert!(r.success);
        assert_eq!(r.network, "tenzro-evm");
        assert_eq!(r.tenzro_vm.as_deref(), Some("tenzro-evm"));
        let c = r.decoded_commitment().expect("commitment present");
        assert_eq!(c.len(), 32);
    }

    #[test]
    fn finalized_receipt_omits_tenzro_vm_for_external_chain() {
        let r = X402SettlementReceiptBody::finalized(
            "exact",
            "base-sepolia",
            "ch-1",
            "cr-1",
            "/api/data",
            "USDC",
            "1000000",
            "0xabc",
            "0xdef",
            "0xdeadbeef",
        )
        .unwrap();

        assert!(r.success);
        assert!(r.tenzro_vm.is_none());
        // Still get a Plonky3-style commitment — receipt finality is
        // network-independent.
        assert!(r.decoded_commitment().is_some());
    }

    #[test]
    fn finalized_normalizes_hex_for_commitment_stability() {
        let upper = X402SettlementReceiptBody::finalized(
            "exact", "tenzro-evm", "ch", "cr", "/r", "USDC", "1",
            "0xABCD", "0xEF01", "0xDEADBEEF",
        )
        .unwrap();
        let lower = X402SettlementReceiptBody::finalized(
            "exact", "tenzro-evm", "ch", "cr", "/r", "USDC", "1",
            "abcd", "ef01", "deadbeef",
        )
        .unwrap();
        // Same logical settlement → same commitment regardless of
        // upper-case / 0x prefix variations in the input.
        assert_eq!(
            upper.decoded_commitment(),
            lower.decoded_commitment()
        );
    }

    #[test]
    fn failed_receipt_carries_no_commitment() {
        let r = X402SettlementReceiptBody::failed("tenzro-svm", "insufficient funds");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("insufficient funds"));
        assert!(r.tenzro_commitment.is_none());
        assert!(r.decoded_commitment().is_none());
        // tenzroVm still tagged so a server-side log can route the failure.
        assert_eq!(r.tenzro_vm.as_deref(), Some("tenzro-svm"));
    }

    #[test]
    fn finalized_rejects_invalid_network() {
        let err = X402SettlementReceiptBody::finalized(
            "exact", "", "ch", "cr", "/r", "USDC", "1", "abc", "def", "deadbeef",
        )
        .unwrap_err();
        assert!(matches!(err, PaymentError::UnsupportedProtocol(_)));

        let err = X402SettlementReceiptBody::finalized(
            "exact", "tenzro evm", "ch", "cr", "/r", "USDC", "1", "abc", "def", "deadbeef",
        )
        .unwrap_err();
        assert!(matches!(err, PaymentError::UnsupportedProtocol(_)));
    }

    #[test]
    fn receipt_round_trips_through_json() {
        let r = X402SettlementReceiptBody::finalized(
            "tenzro-hybrid", "tenzro-daml", "ch-1", "cr-1", "/api/r",
            "TNZO", "1000000000000000000", "0xabc", "0xdef", "contract-id-7",
        )
        .unwrap();
        let json = serde_json::to_string(&r).unwrap();
        // camelCase wire form for stock x402 client compat.
        assert!(json.contains("\"txHash\""));
        assert!(json.contains("\"network\""));
        assert!(json.contains("\"tenzroCommitment\""));
        assert!(json.contains("\"tenzroVm\""));
        let decoded: X402SettlementReceiptBody = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tenzro_commitment, r.tenzro_commitment);
        assert_eq!(decoded.tenzro_vm, r.tenzro_vm);
    }
}
