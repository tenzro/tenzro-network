//! Tenzro Cortex — recurrent-depth reasoning primitives.
//!
//! Cortex is the reasoning-worker tier on Tenzro Network. It treats
//! *loop depth* of recurrent-depth transformers (e.g. OpenMythos-style RDT
//! models) as a schedulable, billable primitive in its own right.
//!
//! These types live in `tenzro-types` so that every crate — RPC, MCP tools,
//! agents, settlement, CLI — can talk about reasoning budgets and signed
//! receipts without circular dependencies.
//!
//! # Lifecycle
//!
//! 1. A caller submits a [`CortexRequest`] with a [`ReasoningBudget`].
//! 2. A Cortex worker node runs the request against a recurrent-depth model
//!    using some number of inner loops within the requested budget.
//! 3. The worker emits a signed [`CortexReceipt`] binding input/output
//!    commitments, loops used, worker identity, and optional TEE/ZK evidence.
//! 4. Settlement is priced per token plus per loop via [`CortexPricing`].
//!
//! These types are transport-agnostic: the HTTP sidecar backend and on-chain
//! settlement both work against the same structs.

use crate::primitives::{Address, Hash, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Tiers + budget
// ---------------------------------------------------------------------------

/// Service tier for a Cortex reasoning request.
///
/// Each tier implies a default loop range, an expected latency profile,
/// and whether hardware attestation / ZK inference proofs are required.
/// Concrete loop ranges per tier are resolved by [`ReasoningBudget::for_tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ReasoningTier {
    /// Shallow reasoning, 2–4 loops, no attestation.
    Fast,
    /// Default tier, 8 loops, no attestation.
    #[default]
    Standard,
    /// Deep reasoning, 16–32 loops, optional TEE attestation.
    Deep,
    /// Institutional tier: deep loops + TEE attestation + on-chain receipt.
    Institutional,
}

impl std::fmt::Display for ReasoningTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fast => write!(f, "fast"),
            Self::Standard => write!(f, "standard"),
            Self::Deep => write!(f, "deep"),
            Self::Institutional => write!(f, "institutional"),
        }
    }
}

impl ReasoningTier {
    /// Parse a tier from a lowercase string label.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "fast" => Self::Fast,
            "deep" => Self::Deep,
            "institutional" | "inst" => Self::Institutional,
            _ => Self::Standard,
        }
    }
}

/// Attestation requirement for a Cortex inference request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttestationRequirement {
    /// No attestation required. Cheapest.
    #[default]
    None,
    /// Require a TEE quote (Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA CC).
    Tee,
    /// Require TEE quote AND a Plonky3 STARK inference-verification proof
    /// (over the KoalaBear field). Expensive; reserved for Institutional tier workloads.
    TeeAndZk,
}

/// Budget envelope for a single Cortex reasoning request.
///
/// The worker MUST use at least `min_loops` and at most `max_loops`
/// of the model's recurrent block, MUST not exceed `max_cost_wei`
/// (TNZO base units, 1 TNZO = 10^18 wei), and MUST satisfy `attestation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasoningBudget {
    /// Minimum number of recurrent loops to execute.
    pub min_loops: u32,
    /// Maximum number of recurrent loops to execute.
    pub max_loops: u32,
    /// Tier hint for routing and pricing.
    pub tier: ReasoningTier,
    /// Maximum total cost in wei (1 TNZO = 10^18 wei).
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_cost_wei: u128,
    /// Attestation requirement.
    pub attestation: AttestationRequirement,
    /// Optional wall-clock deadline in milliseconds.
    pub deadline_ms: Option<u64>,
}

impl Default for ReasoningBudget {
    fn default() -> Self {
        Self::for_tier(ReasoningTier::Standard)
    }
}

impl ReasoningBudget {
    /// Construct a default budget for a given tier.
    ///
    /// Loop ranges per tier are:
    /// - Fast: 2–4
    /// - Standard: 8
    /// - Deep: 16–32
    /// - Institutional: 16–32 with TEE attestation required.
    pub fn for_tier(tier: ReasoningTier) -> Self {
        let (min_loops, max_loops, attestation) = match tier {
            ReasoningTier::Fast => (2, 4, AttestationRequirement::None),
            ReasoningTier::Standard => (8, 8, AttestationRequirement::None),
            ReasoningTier::Deep => (16, 32, AttestationRequirement::None),
            ReasoningTier::Institutional => (16, 32, AttestationRequirement::Tee),
        };
        Self {
            min_loops,
            max_loops,
            tier,
            // 1 TNZO ceiling by default; callers should set this explicitly.
            max_cost_wei: 1_000_000_000_000_000_000,
            attestation,
            deadline_ms: None,
        }
    }

    /// Returns true if `loops_used` falls within this budget's loop bounds.
    pub fn allows_loops(&self, loops_used: u32) -> bool {
        loops_used >= self.min_loops && loops_used <= self.max_loops
    }
}

// ---------------------------------------------------------------------------
// Request + response
// ---------------------------------------------------------------------------

/// A Cortex reasoning request.
///
/// This is the Cortex-native counterpart to [`crate::model::InferenceRequest`]
/// and carries a reasoning budget. Workers may route it to any compatible
/// recurrent-depth model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CortexRequest {
    /// Unique request id.
    pub request_id: String,
    /// Target model id (must be registered as a Cortex model).
    pub model_id: String,
    /// Requester address (also the payer).
    pub requester: Address,
    /// Opaque request payload (e.g. tokenized prompt or JSON).
    pub input: Vec<u8>,
    /// Reasoning budget envelope.
    pub budget: ReasoningBudget,
    /// Optional generation parameters as free-form key/value pairs.
    #[serde(default)]
    pub params: HashMap<String, String>,
    /// Request creation timestamp.
    pub timestamp: Timestamp,
}

/// A Cortex reasoning response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CortexResponse {
    /// Echo of the originating request id.
    pub request_id: String,
    /// Unique response id.
    pub response_id: String,
    /// Model that served the request.
    pub model_id: String,
    /// Worker address that executed the inference.
    pub worker: Address,
    /// Opaque response payload.
    pub output: Vec<u8>,
    /// Reasoning-specific metadata.
    pub metadata: CortexMetadata,
    /// Final price charged in wei (1 TNZO = 10^18 wei).
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_wei: u128,
    /// Receipt binding this response to its inputs, weights, and worker.
    pub receipt: CortexReceipt,
    /// Response creation timestamp.
    pub timestamp: Timestamp,
}

/// Reasoning-specific metadata captured during a Cortex inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CortexMetadata {
    /// Input tokens consumed.
    pub input_tokens: u32,
    /// Output tokens produced.
    pub output_tokens: u32,
    /// Number of recurrent loops actually executed.
    pub loops_used: u32,
    /// Wall-clock inference latency, in milliseconds.
    pub latency_ms: u64,
    /// Model version string reported by the worker, if any.
    pub model_version: Option<String>,
    /// Generation finish reason (e.g. "stop", "length", "converged").
    pub finish_reason: Option<String>,
    /// Count of distinct MoE experts activated during generation, if known.
    pub experts_activated: Option<u32>,
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// Signed execution receipt for a Cortex reasoning call.
///
/// Every Cortex response carries a receipt. Deep / Institutional tier
/// receipts also anchor on Tenzro Ledger and may carry TEE quotes or
/// Plonky3 STARK inference-verification proofs.
///
/// The receipt is designed so that auditors can reconstruct:
/// 1. Which model weights were used (`weights_hash`, `runtime_hash`).
/// 2. What input produced what output (`input_commitment`, `output_commitment`).
/// 3. How much compute was spent (`loops_used`, `tokens_in`, `tokens_out`).
/// 4. Who executed it (`worker_did`, `signature`).
/// 5. Optional hardware / ZK evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CortexReceipt {
    /// Model id that executed the request.
    pub model_id: String,
    /// Cryptographic hash of the model weights.
    pub weights_hash: Hash,
    /// Cryptographic hash of the serving runtime (container / binary).
    pub runtime_hash: Hash,
    /// Number of loops the worker was asked to run at most.
    pub loops_requested: u32,
    /// Number of loops actually run.
    pub loops_used: u32,
    /// Hash of the canonical request payload (not the raw input).
    pub input_commitment: Hash,
    /// Hash of the canonical response payload.
    pub output_commitment: Hash,
    /// DID of the worker that executed the inference.
    pub worker_did: String,
    /// Worker wallet address (for settlement).
    pub worker_address: Address,
    /// Optional TEE attestation quote bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_quote: Option<Vec<u8>>,
    /// Optional Plonky3 STARK inference-verification proof bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zk_proof: Option<Vec<u8>>,
    /// Input tokens charged.
    pub tokens_in: u32,
    /// Output tokens charged.
    pub tokens_out: u32,
    /// Final settled price in wei (1 TNZO = 10^18 wei).
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_wei: u128,
    /// Receipt creation timestamp.
    pub timestamp: Timestamp,
    /// Worker signature over the canonical receipt preimage.
    pub signature: Signature,
}

impl CortexReceipt {
    /// Produce the canonical preimage bytes used for signature
    /// generation and verification.
    ///
    /// The signature is explicitly NOT part of the preimage.
    pub fn signing_preimage(&self) -> Vec<u8> {
        // Deterministic serde_json encoding of every field except the
        // signature is sufficient for a signing preimage because serde
        // serializes struct fields in declaration order.
        let core = CortexReceiptPreimage {
            model_id: &self.model_id,
            weights_hash: &self.weights_hash,
            runtime_hash: &self.runtime_hash,
            loops_requested: self.loops_requested,
            loops_used: self.loops_used,
            input_commitment: &self.input_commitment,
            output_commitment: &self.output_commitment,
            worker_did: &self.worker_did,
            worker_address: &self.worker_address,
            tee_quote: self.tee_quote.as_deref(),
            zk_proof: self.zk_proof.as_deref(),
            tokens_in: self.tokens_in,
            tokens_out: self.tokens_out,
            price_wei: self.price_wei,
            timestamp: self.timestamp,
        };
        serde_json::to_vec(&core).unwrap_or_default()
    }
}

#[derive(Serialize)]
struct CortexReceiptPreimage<'a> {
    model_id: &'a str,
    weights_hash: &'a Hash,
    runtime_hash: &'a Hash,
    loops_requested: u32,
    loops_used: u32,
    input_commitment: &'a Hash,
    output_commitment: &'a Hash,
    worker_did: &'a str,
    worker_address: &'a Address,
    tee_quote: Option<&'a [u8]>,
    zk_proof: Option<&'a [u8]>,
    tokens_in: u32,
    tokens_out: u32,
    price_wei: u128,
    timestamp: Timestamp,
}

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

/// Loop-aware pricing configuration for a Cortex model.
///
/// All amounts are in wei (1 TNZO = 10^18 wei). Total cost formula:
///
/// ```text
/// cost_wei = base_request_fee_wei
///          + tokens_in  * price_per_input_token_wei
///          + tokens_out * price_per_output_token_wei
///          + loops_used * price_per_loop_wei
///          + tee_premium_wei  (if attestation includes Tee)
///          + zk_premium_wei   (if attestation includes Zk)
/// ```
///
/// `price_per_loop_wei` is the key Cortex-specific primitive: reasoning
/// depth is billed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CortexPricing {
    /// Flat fee per request, in wei.
    pub base_request_fee_wei: u64,
    /// Fee per input token, in wei.
    pub price_per_input_token_wei: u64,
    /// Fee per output token, in wei.
    pub price_per_output_token_wei: u64,
    /// Fee per recurrent loop executed, in wei.
    pub price_per_loop_wei: u64,
    /// Premium for TEE-attested execution, in wei.
    pub tee_premium_wei: u64,
    /// Premium for Plonky3 STARK inference-verification proof, in wei.
    pub zk_premium_wei: u64,
}

impl Default for CortexPricing {
    fn default() -> Self {
        // Conservative defaults in wei.
        Self {
            base_request_fee_wei: 100,
            price_per_input_token_wei: 10,
            price_per_output_token_wei: 20,
            price_per_loop_wei: 1_000,
            tee_premium_wei: 10_000,
            zk_premium_wei: 100_000,
        }
    }
}

impl CortexPricing {
    /// Compute total price for a settled inference, in wei.
    pub fn compute(
        &self,
        tokens_in: u32,
        tokens_out: u32,
        loops_used: u32,
        attestation: AttestationRequirement,
    ) -> u128 {
        let mut cost: u128 = self.base_request_fee_wei as u128;
        cost = cost.saturating_add((tokens_in as u128).saturating_mul(self.price_per_input_token_wei as u128));
        cost = cost.saturating_add((tokens_out as u128).saturating_mul(self.price_per_output_token_wei as u128));
        cost = cost.saturating_add((loops_used as u128).saturating_mul(self.price_per_loop_wei as u128));
        match attestation {
            AttestationRequirement::None => {}
            AttestationRequirement::Tee => {
                cost = cost.saturating_add(self.tee_premium_wei as u128);
            }
            AttestationRequirement::TeeAndZk => {
                cost = cost.saturating_add(self.tee_premium_wei as u128);
                cost = cost.saturating_add(self.zk_premium_wei as u128);
            }
        }
        cost
    }
}

// ---------------------------------------------------------------------------
// Model family tagging
// ---------------------------------------------------------------------------

/// Family marker for Cortex-class models.
///
/// This is serialized into [`crate::model::ModelInfo::metadata`] under the
/// key [`CORTEX_FAMILY_KEY`] so existing `ModelInfo` consumers continue to
/// work unchanged. Workers and routers that understand Cortex can parse it
/// out to discover recurrent-depth capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CortexModelFamily {
    /// Architecture identifier, e.g. "rdt-moe", "rdt-dense".
    pub arch: String,
    /// Hard upper bound on recurrent loops this model supports.
    pub max_loops: u32,
    /// Number of MoE experts (0 if dense).
    pub moe_experts: u32,
    /// Number of experts activated per token (0 if dense).
    pub experts_per_token: u32,
    /// Hidden attention type, e.g. "mla", "gqa".
    pub attn_type: String,
    /// Supported reasoning tiers (denormalized for quick filtering).
    #[serde(default)]
    pub supported_tiers: Vec<ReasoningTier>,
}

impl Default for CortexModelFamily {
    fn default() -> Self {
        Self {
            arch: "rdt-moe".to_string(),
            max_loops: 32,
            moe_experts: 0,
            experts_per_token: 0,
            attn_type: "mla".to_string(),
            supported_tiers: vec![
                ReasoningTier::Fast,
                ReasoningTier::Standard,
                ReasoningTier::Deep,
            ],
        }
    }
}

/// Metadata key used on [`crate::model::ModelInfo::metadata`] to mark
/// a model as Cortex-family and carry a serialized [`CortexModelFamily`].
pub const CORTEX_FAMILY_KEY: &str = "tenzro.cortex.family";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_defaults_are_sensible() {
        let fast = ReasoningBudget::for_tier(ReasoningTier::Fast);
        assert_eq!(fast.min_loops, 2);
        assert_eq!(fast.max_loops, 4);
        assert_eq!(fast.attestation, AttestationRequirement::None);

        let inst = ReasoningBudget::for_tier(ReasoningTier::Institutional);
        assert_eq!(inst.attestation, AttestationRequirement::Tee);
        assert!(inst.allows_loops(16));
        assert!(inst.allows_loops(32));
        assert!(!inst.allows_loops(8));
        assert!(!inst.allows_loops(33));
    }

    #[test]
    fn pricing_accounts_for_loops_and_premiums() {
        let p = CortexPricing::default();
        let base = p.compute(10, 20, 8, AttestationRequirement::None);
        let tee = p.compute(10, 20, 8, AttestationRequirement::Tee);
        let full = p.compute(10, 20, 8, AttestationRequirement::TeeAndZk);
        assert!(tee > base);
        assert!(full > tee);
        // loops_used should dominate at 8 loops × 1000 = 8000.
        let no_loops = p.compute(10, 20, 0, AttestationRequirement::None);
        assert_eq!(base - no_loops, 8_000);
    }

    #[test]
    fn tier_parse_is_lossy_but_stable() {
        assert_eq!(ReasoningTier::from_str_lossy("FAST"), ReasoningTier::Fast);
        assert_eq!(
            ReasoningTier::from_str_lossy("institutional"),
            ReasoningTier::Institutional
        );
        assert_eq!(
            ReasoningTier::from_str_lossy("nonsense"),
            ReasoningTier::Standard
        );
    }

    #[test]
    fn receipt_preimage_excludes_signature_and_is_deterministic() {
        let receipt = CortexReceipt {
            model_id: "mythos-3b".to_string(),
            weights_hash: Hash::zero(),
            runtime_hash: Hash::zero(),
            loops_requested: 8,
            loops_used: 8,
            input_commitment: Hash::zero(),
            output_commitment: Hash::zero(),
            worker_did: "did:tenzro:machine:abcd".to_string(),
            worker_address: Address::default(),
            tee_quote: None,
            zk_proof: None,
            tokens_in: 10,
            tokens_out: 20,
            price_wei: 12_345,
            timestamp: Timestamp::default(),
            signature: Signature::default(),
        };
        let a = receipt.signing_preimage();
        let b = receipt.signing_preimage();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }
}
