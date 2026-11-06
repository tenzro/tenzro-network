//! Settlement types for Tenzro Network
//!
//! This module defines types for payment settlement, service billing,
//! and transaction finalization on the network.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of services that can be settled
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ServiceType {
    /// Model inference service
    ModelInference {
        /// Model ID
        model_id: String,
        /// Number of tokens processed
        tokens: u32,
    },
    /// TEE computation service
    TeeComputation {
        /// Computation ID
        computation_id: String,
        /// Compute units used
        compute_units: u64,
    },
    /// Storage service
    Storage {
        /// Data size (bytes)
        data_size: u64,
        /// Duration (seconds)
        duration: u64,
    },
    /// Agent execution service
    AgentExecution {
        /// Agent ID
        agent_id: String,
        /// Task ID
        task_id: String,
    },
    /// Data service
    DataService {
        /// Service ID
        service_id: String,
        /// Data volume
        volume: u64,
    },
    /// Bridge service
    Bridge {
        /// Transfer ID
        transfer_id: String,
        /// Amount bridged
        amount: u64,
    },
    /// HTTP 402 payment protocol service (MPP, x402)
    HttpPayment {
        /// Protocol used (e.g., "mpp", "x402")
        protocol: String,
        /// Resource URL that was paid for
        resource: String,
    },
    /// Custom service
    Custom {
        /// Service name
        name: String,
        /// Service parameters
        parameters: HashMap<String, String>,
    },
}

impl ServiceType {
    /// Returns the service type name
    pub fn type_name(&self) -> &str {
        match self {
            Self::ModelInference { .. } => "ModelInference",
            Self::TeeComputation { .. } => "TeeComputation",
            Self::Storage { .. } => "Storage",
            Self::AgentExecution { .. } => "AgentExecution",
            Self::DataService { .. } => "DataService",
            Self::Bridge { .. } => "Bridge",
            Self::HttpPayment { .. } => "HttpPayment",
            Self::Custom { .. } => "Custom",
        }
    }
}

/// Payment intent for settlement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentIntent {
    /// Immediate payment required
    Immediate,
    /// Payment can be deferred
    Deferred,
    /// Payment on delivery/completion
    OnDelivery,
    /// Escrow-based payment
    Escrow,
    /// Subscription-based payment
    Subscription,
}

/// Proof of service for settlement verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProof {
    /// Proof type
    pub proof_type: ProofType,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Signatures from relevant parties
    pub signatures: Vec<ProofSignature>,
    /// Attestation (if service was performed in TEE)
    pub attestation: Option<Vec<u8>>,
}

impl ServiceProof {
    /// Creates a new service proof
    pub fn new(proof_type: ProofType, proof_data: Vec<u8>) -> Self {
        Self {
            proof_type,
            proof_data,
            signatures: Vec::new(),
            attestation: None,
        }
    }

    /// Adds a signature to the proof
    pub fn add_signature(&mut self, signature: ProofSignature) {
        self.signatures.push(signature);
    }

    /// Adds an attestation
    pub fn with_attestation(mut self, attestation: Vec<u8>) -> Self {
        self.attestation = Some(attestation);
        self
    }
}

/// Types of service proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Cryptographic proof
    Cryptographic,
    /// TEE attestation proof
    TeeAttestation,
    /// Multi-party signature proof
    MultiParty,
    /// Merkle proof
    Merkle,
    /// ZK proof
    ZeroKnowledge,
    /// Oracle verification
    Oracle,
}

/// A signature in a service proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSignature {
    /// Signer address
    pub signer: Address,
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Signer role
    pub role: SignerRole,
}

/// Role of a signer in a proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerRole {
    /// Service provider
    Provider,
    /// Service consumer
    Consumer,
    /// Third-party verifier
    Verifier,
    /// Oracle
    Oracle,
}

/// Escrow configuration for settlements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowConfig {
    /// Escrow address
    pub escrow_address: Address,
    /// Amount held in escrow (in smallest TNZO unit)
    pub amount: u64,
    /// Release conditions
    pub release_conditions: ReleaseConditions,
    /// Timeout (if conditions not met)
    pub timeout: Timestamp,
}

/// Conditions for escrow release
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseConditions {
    /// Released by the provider, the payee, with the release transaction it
    /// signs from its own account before expiry; refundable to the payer after.
    ProviderSignature,
    /// Released by the consumer, the payer, with the release transaction it
    /// signs from its own account before expiry; refundable to it after.
    ConsumerSignature,
    /// Released once the payer and the payee have each sent a release
    /// transaction signed from their own accounts, before expiry; refundable
    /// to the payer after. A third party releases an `Executor` escrow that
    /// names it, or a `QuorumAttestation` escrow that names its committee.
    BothSignatures,
    /// Release on timeout
    Timeout,
    /// Custom condition
    Custom { condition: String },
    /// Paid to the payee by whoever reveals a preimage of `hash` (SHA-256)
    /// before expiry, with a `ClaimEscrowPreimage` transaction; refundable to
    /// the payer after expiry.
    HashLock { hash: [u8; 32] },
    /// A prepaid stream: the payee accrues `rate_per_epoch` for every whole
    /// `epoch_ms` elapsed since funding, up to the amount and the expiry, and
    /// claims it with `ClaimEscrowStream`. The payer may stop the stream at
    /// any time with `RefundEscrow`: the accrued part goes to the payee and
    /// the rest back. Compute rental is one: the provider's bonded address is
    /// the payee, and an epoch the validators froze as unavailable is claimed
    /// back from the insurance pool.
    Stream {
        /// Paid per elapsed epoch.
        #[serde(with = "crate::primitives::u128_serde")]
        rate_per_epoch: u128,
        /// Epoch length in milliseconds.
        epoch_ms: u64,
    },
    /// Release when a threshold of an independent verifier committee attests
    /// that `claim` holds.
    ///
    /// `claim` states, in the parties' agreed encoding, what must have
    /// happened (for a delivery-versus-payment: the asset, amount, receiving
    /// party and deadline of the remote leg). Each member signs
    /// [`quorum_release_digest`] over this escrow's id, the claim and the
    /// evidence it checked. Any account may submit the release once
    /// `verifiers.threshold` distinct members have signed, so the payer
    /// does not have to act; the payer can still refund after expiry.
    ///
    /// The committee is fixed when the escrow is created, obeys the same
    /// size, majority and operator/RPC-diversity rules as a bridge route
    /// committee, and is visible to the payee before it delivers.
    QuorumAttestation {
        /// What the committee must attest.
        claim: String,
        /// Who attests it.
        verifiers: crate::bridge_route::VerifierQuorum,
    },
    /// Released to the payee by a named executor (or the payer) before
    /// expiry; refundable to the payer after expiry. A settlement executor
    /// completing one leg of a multi-leg trade.
    Executor {
        /// The account that may release.
        executor: crate::primitives::Address,
    },
}

/// Domain tag of the digest a committee signs to release a
/// [`ReleaseConditions::QuorumAttestation`] escrow.
pub const QUORUM_RELEASE_DOMAIN: &[u8] = b"tenzro/escrow/quorum-release/v1";

/// Longest claim a [`ReleaseConditions::QuorumAttestation`] escrow may carry.
pub const MAX_RELEASE_CLAIM_LEN: usize = 4096;

/// The digest a committee member signs to release escrow `escrow_id` under
/// `claim`, having checked `evidence`.
///
/// Binding the escrow id means an attestation releases exactly one escrow;
/// binding the claim means it cannot be carried to an escrow with other
/// terms; binding the evidence records what the members checked.
pub fn quorum_release_digest(escrow_id: &[u8; 32], claim: &str, evidence: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(QUORUM_RELEASE_DOMAIN);
    h.update(escrow_id);
    h.update((claim.len() as u64).to_be_bytes());
    h.update(claim.as_bytes());
    h.update((evidence.len() as u64).to_be_bytes());
    h.update(evidence);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Payment records
// ---------------------------------------------------------------------------

use crate::payment_authorization::{DeliveryReceipt, PaymentBinding};

/// How a payment record was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    /// Settled on the Tenzro Ledger.
    Native,
    /// Made on another chain and proven by that chain's light client.
    Proven,
    /// Made on a rail outside any chain (card, bank, payment processor) and
    /// stated by a named attestor. Never counts as proven.
    Attested,
}

/// One payment, as consensus records it at [`payment_record_key`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRecord {
    /// The reference ([`crate::payment_authorization::pay_ref`]), hex.
    pub pay_ref: String,
    /// How it was established.
    pub class: RecordClass,
    /// The payer: a ledger address (hex) for a native payment, the account
    /// on the source chain or rail otherwise.
    pub payer: String,
    /// The payee on Tenzro.
    pub payee: Address,
    /// The asset: `TNZO`, a token id, or for a proven or attested payment
    /// the asset as the source names it (CAIP-19 or an ISO 4217 code).
    pub asset: String,
    /// Amount paid, in the asset's smallest unit.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// The settlement fee, in the smallest unit of `settled.fee_asset`.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fee: u128,
    /// What the fee was collected in and what the payment was worth: the
    /// same fields for every class.
    #[serde(flatten, default)]
    pub settled: SettledReceipt,
    /// The request, quote and USD price the payer signed.
    pub binding: PaymentBinding,
    /// The payer's nonce (the payment id).
    pub nonce: String,
    /// The delegated agent that paid, when one did.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// The chain or rail it was made on, for a proven or attested payment.
    #[serde(default)]
    pub source: Option<String>,
    /// The account that attested it, hex, for an attested payment.
    #[serde(default)]
    pub attestor: Option<String>,
    /// The payee's delivery receipts, by digest, hex.
    #[serde(default)]
    pub receipts: Vec<String>,
    /// What the payee has returned to the payer, in the asset's smallest
    /// unit. The settlement fee is not returned.
    #[serde(default, with = "crate::primitives::u128_serde")]
    pub refunded: u128,
    /// Block time it was recorded at, ms.
    pub recorded_at_ms: i64,
}

/// The unit of account a payment was valued in: a basket and its version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitOfAccount {
    /// The basket's id (`USD` for the dollar alone).
    pub basket: String,
    /// The basket's version.
    pub version: u32,
}

/// The fee and value fields every payment record carries, whatever its
/// class.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SettledReceipt {
    /// The asset the settlement fee was collected in: `TNZO`, or the token
    /// the payment moved. Proven and attested payments pay no fee on Tenzro
    /// and name their own asset.
    pub fee_asset: String,
    /// The fee's worth in TNZO base units at the rates in force.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fee_tnzo_eq: u128,
    /// TNZO base units booked as burned for the fee's burn share when the
    /// fee was collected in another asset; zero when TNZO was burned.
    #[serde(with = "crate::primitives::u128_serde")]
    pub burn_eq: u128,
    /// The epoch whose median set the TNZO rate used; absent while the
    /// governance rate is in force.
    pub rate_epoch: Option<u64>,
    /// The unit of account `value_units` is counted in.
    pub unit: UnitOfAccount,
    /// The payment's value, micro-units of `unit`.
    #[serde(with = "crate::primitives::u128_serde")]
    pub value_units: u128,
    /// The asset the payee was paid in.
    pub payout_asset: String,
    /// Each leg the payment paid: the operator at its price, then each
    /// reseller at its commission and any platform fee, with the settlement
    /// fee each leg paid. A payment with a reseller never has a record
    /// without its legs.
    pub legs: Vec<ReceiptLeg>,
}

/// One leg of a payment, as its record shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptLeg {
    /// `operator`, `reseller` or `platform`.
    pub role: String,
    /// The account paid, hex.
    pub account: String,
    /// What the leg carried, in the payment's asset.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// The settlement fee the leg paid, in the payment's asset.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fee: u128,
    /// A reseller's commission, bps of the operator's price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commission_bps: Option<u32>,
}

impl PaymentRecord {
    /// The record as JSON with every amount a decimal string, for readers
    /// whose JSON numbers are not exact past 2^53.
    pub fn exact_json(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        for (k, n) in [
            ("amount", self.amount),
            ("fee", self.fee),
            ("refunded", self.refunded),
            ("fee_tnzo_eq", self.settled.fee_tnzo_eq),
            ("burn_eq", self.settled.burn_eq),
            ("value_units", self.settled.value_units),
        ] {
            v[k] = serde_json::Value::String(n.to_string());
        }
        for (i, leg) in self.settled.legs.iter().enumerate() {
            v["legs"][i]["amount"] = serde_json::Value::String(leg.amount.to_string());
            v["legs"][i]["fee"] = serde_json::Value::String(leg.fee.to_string());
        }
        v
    }
}

/// Most delivery receipts one record lists.
pub const MAX_RECEIPTS_PER_PAYMENT: usize = 64;

/// System storage key of the record for `pay_ref`.
pub fn payment_record_key(pay_ref: &[u8; 32]) -> String {
    format!("pay:{}", hex::encode(pay_ref))
}

/// State key of a payee's standing split rule.
pub fn payee_split_key(payee: &Address) -> String {
    format!("paysplit:{}", hex::encode(payee.as_bytes()))
}

/// Check a standing split rule a payee sets: a rule the split engine takes,
/// paying fixed accounts or DID-derived ones (a standing rule has no leg
/// submitter to pay).
pub fn validate_standing_split(rule: &crate::split::SplitRule) -> Result<(), String> {
    rule.validate().map_err(|e| e.to_string())?;
    if rule
        .lines
        .iter()
        .any(|l| l.recipient == crate::split::SplitRecipient::LegSubmitter)
    {
        return Err("a standing split pays named accounts, not a leg submitter".to_string());
    }
    Ok(())
}

/// A payment made on a rail outside any chain, as its attestor states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedPayment {
    /// The rail: `card`, `bank`, `processor` or another rail name.
    pub rail: String,
    /// The payer as the rail knows it, or a digest of it.
    pub payer: String,
    /// The payee on Tenzro.
    pub payee: Address,
    /// The asset as the rail names it (an ISO 4217 code or CAIP-19).
    pub asset: String,
    /// Amount, in the asset's smallest unit.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// What it paid for. `usd_e6` must be set: attested payments are capped
    /// in USD.
    pub binding: PaymentBinding,
    /// The payer's nonce on the rail (its transaction reference).
    pub nonce: String,
}

/// An operation on payment records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentOp {
    /// The payee lists what it delivered on its payment's record.
    Receipt {
        /// The receipt; its `pay_ref` names the record.
        receipt: DeliveryReceipt,
    },
    /// Record a payment a delegated agent's account made on another chain:
    /// the account's `Paid` report, proven through that chain's report
    /// route. The account, not the submitter, is the payer.
    Proven {
        /// The paying agent.
        agent_did: String,
        /// The chain its account paid on, CAIP-2.
        chain: String,
        /// The route delivery whose body is the account's report.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        delivery: Vec<u8>,
    },
    /// Record a payment made on a rail outside any chain. The submitting
    /// account is its attestor.
    Attested {
        /// The payment.
        payment: AttestedPayment,
    },
    /// The payee sets the standing split rule the split engine divides
    /// every payment it receives by, after the fee; `None` clears it.
    SetSplit {
        /// The rule.
        rule: Option<crate::split::SplitRule>,
    },
    /// The payee lists the settlement assets it accepts being paid out in,
    /// in its order (`0x` token ids); an empty list keeps what arrives.
    SetPayoutAssets {
        /// The assets.
        assets: Vec<String>,
    },
    /// The payee returns part or all of a native payment to its payer, in
    /// the asset it was paid in. Refunds on one record never exceed what
    /// it paid.
    Refund {
        /// The record.
        #[serde(with = "crate::payment_authorization::hex_array32")]
        pay_ref: [u8; 32],
        /// Amount returned, in the asset's smallest unit.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
}

// ---------------------------------------------------------------------------
// Settlement plans
// ---------------------------------------------------------------------------

/// Most value legs one plan carries.
pub const MAX_PLAN_LEGS: usize = 16;

/// Most legs of one plan that settle on another network.
pub const MAX_EXTERNAL_LEGS: usize = 8;

/// Domain of [`plan_id`].
pub const PLAN_ID_DOMAIN: &[u8] = b"tenzro/plan/v1";

/// Domain of [`leg_id`].
pub const LEG_ID_DOMAIN: &[u8] = b"tenzro/plan/leg/v1";

/// The id of a plan: `SHA-256(domain || chain_id || opened_by || quote_digest
/// || nonce)`, big-endian integers. A single payment's `pay_ref` is its
/// one-leg plan's id, so payments and plans share one id space.
pub fn plan_id(
    chain_id: u64,
    opened_by: &Address,
    quote_digest: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PLAN_ID_DOMAIN);
    h.update(chain_id.to_be_bytes());
    h.update(opened_by.0);
    h.update(quote_digest);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// The id of leg `index` of plan `plan_id`.
pub fn leg_id(plan_id: &[u8; 32], index: u8) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(LEG_ID_DOMAIN);
    h.update(plan_id);
    h.update([index]);
    h.finalize().into()
}

/// Domain tag of the running hash every settlement lock keeps over its
/// entries for reconciliation.
pub const RECON_DOMAIN: &[u8] = b"tenzro/settlement/recon/v1";

/// What a settlement lock entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ReconKind {
    /// A leg's value was locked.
    Locked = 1,
    /// A leg's value was released to its recipient on a commit.
    Released = 2,
    /// A leg's value was refunded to its payer on an abort or escape.
    Refunded = 3,
}

/// Fold one lock entry into a running reconciliation hash:
/// `sha256(RECON_DOMAIN || acc || plan_id || leg_id || kind || amount)`,
/// the amount as a 32-byte big-endian word. Every lock family computes the
/// same hash, from zero, in the order it records entries.
pub fn recon_step(
    acc: &[u8; 32],
    plan_id: &[u8; 32],
    leg_id: &[u8; 32],
    kind: ReconKind,
    amount: u128,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(RECON_DOMAIN);
    h.update(acc);
    h.update(plan_id);
    h.update(leg_id);
    h.update([kind as u8]);
    h.update([0u8; 16]);
    h.update(amount.to_be_bytes());
    h.finalize().into()
}

/// Most entries one reconciliation submits.
pub const MAX_RECON_ENTRIES: usize = 512;

/// One entry a settlement lock recorded, as a reconciliation submits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconEntry {
    /// The plan.
    #[serde(with = "crate::agent_audit::hex32")]
    pub plan_id: [u8; 32],
    /// The leg.
    #[serde(with = "crate::agent_audit::hex32")]
    pub leg_id: [u8; 32],
    /// What the lock recorded.
    pub kind: ReconKind,
    /// The amount, in the leg's units.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
}

impl ReconEntry {
    /// Fold this entry into `acc`.
    pub fn fold(&self, acc: &[u8; 32]) -> [u8; 32] {
        recon_step(acc, &self.plan_id, &self.leg_id, self.kind, self.amount)
    }
}

/// How far a route's settlement lock has been reconciled against Tenzro's
/// books.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconState {
    /// Entries reconciled.
    pub count: u64,
    /// The lock's running hash after them.
    #[serde(with = "crate::agent_audit::hex32")]
    pub acc: [u8; 32],
    /// SHA-256 of the checkpoint evidence that proved them.
    #[serde(with = "crate::agent_audit::hex32")]
    pub checkpoint_digest: [u8; 32],
    /// Block time of the last reconciliation, ms.
    pub at_ms: u64,
    /// Positions (1-based entry counts) of the entries that disagreed.
    pub mismatches: Vec<u64>,
}

/// An entry a lock recorded that disagrees with Tenzro's books. It is
/// provable: folding the entries before it from the stored hash and this
/// entry gives a hash the lock's proven checkpoint committed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconMismatch {
    /// The route's bridge protocol.
    pub adapter: crate::bridge_route::BridgeRouteAdapter,
    /// The route's external chain.
    pub chain: String,
    /// The entry's position in the lock's record, 1-based.
    pub position: u64,
    /// The running hash before the entry.
    #[serde(with = "crate::agent_audit::hex32")]
    pub acc_before: [u8; 32],
    /// The entry.
    pub entry: ReconEntry,
    /// What disagrees.
    pub reason: String,
    /// SHA-256 of the checkpoint evidence the entry was proven under.
    #[serde(with = "crate::agent_audit::hex32")]
    pub checkpoint_digest: [u8; 32],
    /// Who submitted the reconciliation.
    pub submitted_by: crate::primitives::Address,
    /// Block time, ms.
    pub at_ms: u64,
    /// Whether the route admitted the checkpoint on its committee's
    /// attestation alone (it has no light client). Only then is the
    /// committee slashed for the mismatch and its loss claimable from the
    /// insurance pool.
    pub attested: bool,
    /// The account on Tenzro the entry cost the leg's value, when it cost
    /// one: the plan's payer for a release without a commit, the plan's
    /// payee for a refund after one.
    pub harmed: Option<crate::primitives::Address>,
    /// The leg's value in TNZO base units at the rate in force when the
    /// mismatch was found; what a claim against it can be paid.
    #[serde(with = "crate::primitives::u128_serde")]
    pub loss: u128,
}

/// What a leg's evidence is worth, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegClass {
    /// Executed in Tenzro consensus.
    Native,
    /// Proven from another network's own consensus (a light client or a
    /// governed route's quorum over its finalized events).
    Proven,
    /// Asserted by a bonded attestor; never counts as proven.
    Attested,
}

impl LegClass {
    /// Whether evidence of this class satisfies a requirement of `required`.
    pub fn satisfies(self, required: LegClass) -> bool {
        self.rank() <= required.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Self::Native => 0,
            Self::Proven => 1,
            Self::Attested => 2,
        }
    }
}

/// What a leg moves and where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegKind {
    /// TNZO the plan's opener pays into the plan vault when the plan opens,
    /// from its balance or from an escrow it funded; the decision divides it
    /// by the plan's split rule.
    NativeTransfer {
        /// Amount, wei.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// The opener's funded escrow the amount is drawn from, if any.
        #[serde(default, with = "opt_hex32")]
        escrow_id: Option<[u8; 32]>,
    },
    /// Value the opener owes the plan's split recipients in `asset`, settled
    /// net with every other netted obligation of the asset when the epoch's
    /// batch closes, from collateral the opener posted on Tenzro. The plan
    /// commits when it opens: the protocol fee is taken on this gross value
    /// from the collateral at once, and the rest becomes the opener's
    /// obligations to the recipients. A plan with a netted leg holds only
    /// netted legs of one asset.
    Netted {
        /// Token id of the asset (TNZO or a listed stablecoin).
        #[serde(with = "crate::agent_audit::hex32")]
        asset: [u8; 32],
        /// Amount in the asset's smallest unit.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// An ICS-20 packet the payer sent over the governed IBC route to
    /// `chain`: delivered when the Cosmos chain acknowledges it with
    /// success, failed when it acknowledges an error or the packet times out
    /// (the payer is refunded by the route).
    IbcTransfer {
        /// The route's chain.
        chain: String,
        /// The packet's sequence on the route.
        sequence: u64,
    },
    /// Value the payer locked in the route's settlement lock contract on
    /// another chain, released to `recipient` on a proof of the plan's
    /// commit and refunded on a proof of its abort. Proven by the lock's
    /// `Locked` event, which must name this plan and leg.
    RemoteLock {
        /// The transport whose route reaches the chain.
        adapter: crate::bridge_route::BridgeRouteAdapter,
        /// The route's chain.
        chain: String,
        /// The asset locked, as the chain encodes it, left-padded to 32 bytes
        /// (all zero for the chain's native coin).
        #[serde(with = "crate::agent_audit::hex32")]
        asset: [u8; 32],
        /// Amount in the asset's smallest unit.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// Who a commit pays on that chain, left-padded to 32 bytes.
        #[serde(with = "crate::agent_audit::hex32")]
        recipient: [u8; 32],
    },
    /// Bitcoin paid into a hash-locked script (see [`htlc_witness_script`]):
    /// spendable by `recipient_key` with the preimage of `hash`, or by
    /// `refund_key` after `refund_after_secs`. The preimage is revealed on
    /// Tenzro in the transaction that commits the plan, and only there.
    HashLocked {
        /// The Bitcoin route's chain.
        chain: String,
        /// SHA-256 of the secret.
        #[serde(with = "crate::agent_audit::hex32")]
        hash: [u8; 32],
        /// Compressed public key a commit pays.
        #[serde(with = "hex33")]
        recipient_key: [u8; 33],
        /// Compressed public key that may reclaim after the timelock.
        #[serde(with = "hex33")]
        refund_key: [u8; 33],
        /// Unix time (seconds) from which the refund path opens.
        refund_after_secs: u32,
        /// Amount, satoshis.
        amount_sats: u64,
        /// TNZO, wei, the payer escrows in the plan vault when the plan
        /// opens, at least `settlement.griefing_premium_bps` of the plan's
        /// Tenzro value. Paid by the split rule if the plan aborts with this
        /// leg funded and every other leg in but the preimage never revealed;
        /// returned to the payer otherwise.
        #[serde(with = "crate::primitives::u128_serde")]
        premium: u128,
    },
    /// A payment on a rail no chain can lock (a bank credit transfer, a card
    /// capture), instructed once the plan commits. It completes on a
    /// confirmation inside the compensation window that follows the commit:
    /// signed by the payee itself, or, when `attestor` is named, by that
    /// bonded attestor, which the payee may dispute with evidence inside the
    /// same window. Unconfirmed or disputed, the payee is paid `reserve`
    /// from the plan vault and the attestor's bond is slashed.
    RailInstruction {
        /// The rail.
        rail: RailKind,
        /// SHA-256 of the instruction sent on the rail (the pacs.008 or
        /// pacs.009 message, the card capture request).
        #[serde(with = "crate::agent_audit::hex32")]
        instruction_digest: [u8; 32],
        /// ISO 4217 currency code.
        currency: String,
        /// Amount in the currency's minor unit.
        #[serde(with = "crate::primitives::u128_serde")]
        amount_minor: u128,
        /// The Tenzro account of the payee: it confirms, disputes, and is
        /// compensated.
        payee: Address,
        /// The operator that connected the rail and confirms the leg on it,
        /// when the payee does not confirm itself. It holds an attestor bond.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestor: Option<Address>,
        /// TNZO, wei, the payer escrows in the plan vault when the plan
        /// opens; it compensates the payee if the leg is not confirmed or is
        /// disputed, and returns to the payer otherwise.
        #[serde(with = "crate::primitives::u128_serde")]
        reserve: u128,
    },
}

/// A payment rail outside every chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailKind {
    /// An ISO 20022 credit transfer (pacs.008 customer, pacs.009 bank).
    Iso20022,
    /// A card capture through a payment processor.
    Card,
}

/// Witness script of a [`LegKind::HashLocked`] leg, paid to as P2WSH:
/// `OP_IF OP_SHA256 <hash> OP_EQUALVERIFY <recipient_key> OP_ELSE
/// <refund_after_secs> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_key> OP_ENDIF
/// OP_CHECKSIG`.
pub fn htlc_witness_script(
    hash: &[u8; 32],
    recipient_key: &[u8; 33],
    refund_key: &[u8; 33],
    refund_after_secs: u32,
) -> Vec<u8> {
    const OP_IF: u8 = 0x63;
    const OP_ELSE: u8 = 0x67;
    const OP_ENDIF: u8 = 0x68;
    const OP_SHA256: u8 = 0xa8;
    const OP_EQUALVERIFY: u8 = 0x88;
    const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    const OP_DROP: u8 = 0x75;
    const OP_CHECKSIG: u8 = 0xac;
    // Minimal script number: little endian, with a zero byte appended when
    // the top bit is set so it stays positive.
    let mut n = refund_after_secs.to_le_bytes().to_vec();
    while n.len() > 1 && n[n.len() - 1] == 0 && n[n.len() - 2] & 0x80 == 0 {
        n.pop();
    }
    if n[n.len() - 1] & 0x80 != 0 {
        n.push(0);
    }
    let mut s = vec![OP_IF, OP_SHA256, 32];
    s.extend_from_slice(hash);
    s.extend_from_slice(&[OP_EQUALVERIFY, 33]);
    s.extend_from_slice(recipient_key);
    s.push(OP_ELSE);
    s.push(n.len() as u8);
    s.extend_from_slice(&n);
    s.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP, 33]);
    s.extend_from_slice(refund_key);
    s.extend_from_slice(&[OP_ENDIF, OP_CHECKSIG]);
    s
}

/// The P2WSH output script paying to [`htlc_witness_script`].
pub fn htlc_output_script(witness_script: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut out = vec![0x00, 32];
    out.extend_from_slice(&sha2::Sha256::digest(witness_script));
    out
}

mod hex33 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        <[u8; 33]>::try_from(b.as_slice())
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

impl LegKind {
    /// Whether the leg settles on another network.
    pub fn is_external(&self) -> bool {
        !matches!(self, Self::NativeTransfer { .. } | Self::Netted { .. })
    }

    /// The tier a plan holding this leg needs at least.
    pub fn tier(&self) -> AtomicityTier {
        match self {
            Self::NativeTransfer { .. } | Self::Netted { .. } => AtomicityTier::Native,
            Self::IbcTransfer { .. } => AtomicityTier::IbcTransfer,
            Self::RemoteLock { .. } => AtomicityTier::DecisionLocked,
            Self::HashLocked { .. } => AtomicityTier::HashLocked,
            Self::RailInstruction { .. } => AtomicityTier::Compensated,
        }
    }
}

/// One value leg of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leg {
    /// What it moves.
    pub kind: LegKind,
    /// The weakest evidence the plan accepts for it.
    pub class_required: LegClass,
    /// The leg's value, USD micro-units, as the quote priced it. Every leg
    /// that is not a Tenzro transfer states it: a rail leg is held to the
    /// attested cap by it, and an agent's plan counts it against the
    /// agent's terms.
    #[serde(default)]
    pub usd_e6: u64,
    /// The most TNZO, wei, the plan repays the relayer that carries this
    /// leg's proof for the fee it paid on the leg's network. A relayer that
    /// paid more bears the rest. Zero for a Tenzro transfer and a rail leg.
    #[serde(default, with = "crate::primitives::u128_serde")]
    pub max_network_fee: u128,
}

/// The relayer that carried a leg's proof and the network fee it states it
/// paid for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegRelay {
    /// The account whose `ProveLeg` carried the proof.
    pub relayer: Address,
    /// The fee it paid on the leg's network, wei of TNZO.
    #[serde(with = "crate::primitives::u128_serde")]
    pub realised: u128,
}

/// How strongly a plan's legs are bound together, weakest leg first: the
/// tier of a plan is the weakest tier any of its legs needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicityTier {
    /// Every leg is on Tenzro: the plan opens and decides in one transaction.
    Native,
    /// A leg is locked in a settlement lock on another chain that releases
    /// or refunds on a proof of the plan's decision.
    DecisionLocked,
    /// A leg is an IBC transfer: its acknowledgement commits the plan, its
    /// timeout or error acknowledgement aborts it.
    IbcTransfer,
    /// A leg is Bitcoin in a hash-locked script: the commit reveals the
    /// preimage, and the recipient must claim before the refund timelock.
    HashLocked,
    /// A leg is on a rail no chain can lock: it is confirmed after the
    /// commit, inside a bounded window, or its payee is compensated from the
    /// plan's reserve and its attestor slashed.
    Compensated,
}

/// Where a plan stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    /// Waiting for its legs.
    Open,
    /// Every leg reached its class; Tenzro legs were paid.
    Committed,
    /// A leg missed its class by the deadline; Tenzro legs were refunded.
    Aborted,
}

/// Version byte of [`decision_commitment`].
pub const DECISION_COMMITMENT_VERSION: u8 = 1;

/// Length of [`decision_commitment`].
pub const DECISION_COMMITMENT_LEN: usize = 42;

/// The record at `decision:<plan_id>` that a remote lock proves against
/// Tenzro's state root before releasing (commit) or refunding (abort):
/// `version (1) || outcome (1: 1 commit, 2 abort) || decided_at_ms (8, big
/// endian) || plan_id (32)`. Fixed-size so every chain's verifier reads it
/// without a JSON parser.
pub fn decision_commitment(
    plan_id: &[u8; 32],
    commit: bool,
    decided_at_ms: u64,
) -> [u8; DECISION_COMMITMENT_LEN] {
    let mut out = [0u8; DECISION_COMMITMENT_LEN];
    out[0] = DECISION_COMMITMENT_VERSION;
    out[1] = if commit { 1 } else { 2 };
    out[2..10].copy_from_slice(&decided_at_ms.to_be_bytes());
    out[10..].copy_from_slice(plan_id);
    out
}

/// The one decision a plan gets, kept in the plan; its commitment is at
/// `decision:<plan_id>` (see [`decision_commitment`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDecision {
    /// The plan.
    #[serde(with = "crate::agent_audit::hex32")]
    pub plan_id: [u8; 32],
    /// Commit (true) or abort.
    pub commit: bool,
    /// Block time of the decision, ms.
    pub decided_at_ms: u64,
    /// The account whose transaction decided it.
    pub decided_by: Address,
    /// Why it aborted, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The division of the Tenzro value, on commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<crate::split::Allocation>,
    /// The account each split line was paid to, by line index, on commit
    /// or when the abort pays the griefing premium.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<Address>,
    /// The division of a hash-locked leg's premium, when the abort paid it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub premium_paid: Option<crate::split::Allocation>,
}

/// Longest DID one hop of a [`CallAttribution`] names.
pub const MAX_ATTRIBUTION_DID_LEN: usize = 256;

/// Domain tag of [`CallAttribution::signing_bytes`].
pub const CALL_ATTRIBUTION_DOMAIN: &[u8] = b"tenzro/call-attribution";

/// The call chain a payer attributes a settlement to: the app it acted in,
/// the agent that app ran and the tool the agent called, each optional, at
/// most one per hop. Every DID named must be a registered identity. The
/// settlement's activity reward and any creator royalty go to them, never to
/// its payee, and nothing goes to one that shares a root with the payer or
/// the payee.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallAttribution {
    /// The app the payer acted in.
    #[serde(default)]
    pub app_did: Option<String>,
    /// The agent that made the call.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// The tool the agent called.
    #[serde(default)]
    pub tool_did: Option<String>,
}

impl CallAttribution {
    /// The DIDs it names, app first.
    pub fn dids(&self) -> Vec<&str> {
        [&self.app_did, &self.agent_did, &self.tool_did]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    }

    /// Refused when it names no DID, a hop that is not a DID or is longer
    /// than [`MAX_ATTRIBUTION_DID_LEN`], or the same DID twice.
    pub fn check(&self) -> Result<(), String> {
        let dids = self.dids();
        if dids.is_empty() {
            return Err("an attribution names at least one app, agent or tool".into());
        }
        for (i, did) in dids.iter().enumerate() {
            if !did.starts_with("did:") || did.len() > MAX_ATTRIBUTION_DID_LEN {
                return Err(format!(
                    "attributed {did:?} is not a DID of at most {MAX_ATTRIBUTION_DID_LEN} bytes"
                ));
            }
            if dids[..i].contains(did) {
                return Err(format!("attribution names {did} twice"));
            }
        }
        Ok(())
    }

    /// The bytes a payer's signature covers: the domain, then each hop in
    /// order as its length (u32, little endian) and bytes, an absent hop as
    /// length zero.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut m = CALL_ATTRIBUTION_DOMAIN.to_vec();
        for hop in [&self.app_did, &self.agent_did, &self.tool_did] {
            let did = hop.as_deref().unwrap_or("");
            m.extend_from_slice(&(did.len() as u32).to_le_bytes());
            m.extend_from_slice(did.as_bytes());
        }
        m
    }
}

/// A multi-leg settlement with one Commit-or-Abort decision, at
/// `plan:<plan_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPlan {
    /// [`plan_id`].
    #[serde(with = "crate::agent_audit::hex32")]
    pub plan_id: [u8; 32],
    /// The payer: its TNZO funds the Tenzro legs.
    pub opened_by: Address,
    /// The agent that opened it from its wallet, if one did: revoking,
    /// pausing or quarantining that agent aborts the plan while undecided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    /// The quote the plan settles; it binds the split rule's hash.
    #[serde(with = "crate::agent_audit::hex32")]
    pub quote_digest: [u8; 32],
    /// How the Tenzro value divides.
    pub split: crate::split::SplitRule,
    /// The legs, 1 to [`MAX_PLAN_LEGS`].
    pub legs: Vec<Leg>,
    /// The weakest tier among the legs.
    pub tier: AtomicityTier,
    /// TNZO held in the plan vault, wei: the value the decision divides and
    /// the protocol fee is charged on, once.
    #[serde(with = "crate::primitives::u128_serde")]
    pub funded: u128,
    /// Block time it opened, ms.
    pub opened_at_ms: u64,
    /// After this block time an undecided plan aborts, ms.
    pub decide_deadline_ms: u64,
    /// Where it stands.
    pub status: PlanStatus,
    /// The evidence class each leg reached, by leg index.
    pub achieved: Vec<Option<LegClass>>,
    /// The decision, once taken.
    pub decision: Option<PlanDecision>,
    /// Who carried each leg's proof and the fee it paid, by leg index.
    #[serde(default)]
    pub relays: Vec<Option<LegRelay>>,
    /// The call chain the payer attributed the plan to, if it did.
    #[serde(default)]
    pub attribution: Option<CallAttribution>,
}

/// One leg's outcome, at `plr:<leg_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegReceipt {
    /// The plan.
    #[serde(with = "crate::agent_audit::hex32")]
    pub plan_id: [u8; 32],
    /// [`leg_id`].
    #[serde(with = "crate::agent_audit::hex32")]
    pub leg_id: [u8; 32],
    /// Index in the plan.
    pub index: u8,
    /// The plan's decision.
    pub committed: bool,
    /// The class the leg reached, if any.
    pub class_achieved: Option<LegClass>,
    /// Value of the leg, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// Digest of the evidence that proved it, if any.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
    pub proof_digest: Option<[u8; 32]>,
    /// Block time of the decision, ms.
    pub decided_at_ms: u64,
    /// A rail leg's compensation, wei, paid to its payee from the plan's
    /// reserve when the leg went unconfirmed or was disputed.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::primitives::u128_serde_opt"
    )]
    pub compensation: Option<u128>,
    /// The network fee the commit repaid the leg's relayer, wei: what it
    /// stated, capped at the leg's `max_network_fee`.
    #[serde(default, with = "crate::primitives::u128_serde")]
    pub network_fee: u128,
    /// The relayer that carried the leg's proof, if one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayer: Option<Address>,
}

/// Version byte of [`LegReceipt::encode`].
pub const LEG_RECEIPT_VERSION: u8 = 1;

/// Length of [`LegReceipt::encode`].
pub const LEG_RECEIPT_LEN: usize = 189;

impl LegReceipt {
    /// The fixed-size record at `plr:<leg_id>`, what a contract on another
    /// chain proves against Tenzro's state root:
    /// `version (1) || outcome (1: 1 commit, 2 abort) || index (1) ||
    /// class (1: 0 none, 1 native, 2 proven, 3 attested) || flags (1: bit 0
    /// proof digest, bit 1 compensation, bit 2 relayer) || decided_at_ms (8)
    /// || plan_id (32) || leg_id (32) || amount (16) || network_fee (16) ||
    /// compensation (16) || proof_digest (32) || relayer (32)`, integers big
    /// endian, absent fields zero.
    pub fn encode(&self) -> [u8; LEG_RECEIPT_LEN] {
        let mut out = [0u8; LEG_RECEIPT_LEN];
        out[0] = LEG_RECEIPT_VERSION;
        out[1] = if self.committed { 1 } else { 2 };
        out[2] = self.index;
        out[3] = match self.class_achieved {
            None => 0,
            Some(LegClass::Native) => 1,
            Some(LegClass::Proven) => 2,
            Some(LegClass::Attested) => 3,
        };
        out[4] = u8::from(self.proof_digest.is_some())
            | (u8::from(self.compensation.is_some()) << 1)
            | (u8::from(self.relayer.is_some()) << 2);
        out[5..13].copy_from_slice(&self.decided_at_ms.to_be_bytes());
        out[13..45].copy_from_slice(&self.plan_id);
        out[45..77].copy_from_slice(&self.leg_id);
        out[77..93].copy_from_slice(&self.amount.to_be_bytes());
        out[93..109].copy_from_slice(&self.network_fee.to_be_bytes());
        out[109..125].copy_from_slice(&self.compensation.unwrap_or(0).to_be_bytes());
        out[125..157].copy_from_slice(&self.proof_digest.unwrap_or([0; 32]));
        if let Some(r) = &self.relayer {
            out[157..189].copy_from_slice(r.as_bytes());
        }
        out
    }

    /// The receipt `bytes` encodes, if it is one ([`LegReceipt::encode`]).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LEG_RECEIPT_LEN
            || bytes[0] != LEG_RECEIPT_VERSION
            || bytes[4] & !0b111 != 0
        {
            return None;
        }
        let b32 = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().expect("32 bytes") };
        let u128_at =
            |at: usize| u128::from_be_bytes(bytes[at..at + 16].try_into().expect("16 bytes"));
        let flag = |bit: u8| bytes[4] & (1 << bit) != 0;
        Some(Self {
            committed: match bytes[1] {
                1 => true,
                2 => false,
                _ => return None,
            },
            index: bytes[2],
            class_achieved: match bytes[3] {
                0 => None,
                1 => Some(LegClass::Native),
                2 => Some(LegClass::Proven),
                3 => Some(LegClass::Attested),
                _ => return None,
            },
            decided_at_ms: u64::from_be_bytes(bytes[5..13].try_into().expect("8 bytes")),
            plan_id: b32(13),
            leg_id: b32(45),
            amount: u128_at(77),
            network_fee: u128_at(93),
            compensation: flag(1).then(|| u128_at(109)),
            proof_digest: flag(0).then(|| b32(125)),
            relayer: flag(2).then(|| Address::new(b32(157))),
        })
    }
}

/// Serde for an optional 32-byte value as hex.
pub mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| crate::agent_audit::parse_digest(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// An operation on a settlement plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOp {
    /// Open a plan, sent by its payer: the Tenzro legs are paid into the plan
    /// vault, and a plan whose legs are all on Tenzro decides in the same
    /// transaction.
    Open {
        /// Makes the plan id unique per payer and quote.
        nonce: u64,
        /// The quote settled; it signs the split rule's hash.
        #[serde(with = "crate::agent_audit::hex32")]
        quote_digest: [u8; 32],
        /// The split rule's hash as the quote signed it.
        #[serde(with = "crate::agent_audit::hex32")]
        split_hash: [u8; 32],
        /// The split rule.
        split: crate::split::SplitRule,
        /// The legs.
        legs: Vec<Leg>,
        /// After this block time an undecided plan aborts, ms.
        decide_deadline_ms: u64,
        /// The delegated agent that pays, when one does: the plan is opened
        /// from its wallet, and every leg's value counts against its terms.
        #[serde(default)]
        agent: Option<crate::agent_terms::AgentAuthorization>,
        /// The call chain the payer attributes the plan to, if any.
        #[serde(default)]
        attribution: Option<CallAttribution>,
    },
    /// Record that a leg reached its evidence class. Anyone may send it. The
    /// transaction that brings the last leg to its class commits the plan;
    /// one that finds a leg can no longer complete aborts it. Block
    /// execution aborts a plan still open after its deadline.
    ProveLeg {
        /// The plan.
        #[serde(with = "crate::agent_audit::hex32")]
        plan_id: [u8; 32],
        /// The leg's index.
        index: u8,
        /// What proves the leg, for legs Tenzro cannot read from its own
        /// state: a lock leg's proof of its `Locked` event; a hash-locked
        /// leg's proof of its funding transaction, or, once funded, the
        /// preimage. Empty for the other kinds.
        #[serde(default, with = "hex_bytes")]
        evidence: Vec<u8>,
        /// The fee the sender paid on the leg's network to carry this proof,
        /// wei of TNZO. A commit repays it up to the leg's
        /// `max_network_fee`; the sender bears the rest, and all of it when
        /// the plan aborts.
        #[serde(default, with = "crate::primitives::u128_serde")]
        network_fee: u128,
    },
    /// Dispute a rail leg its attestor confirmed, sent by the leg's payee
    /// inside the compensation window with the evidence that the payment
    /// did not arrive: the payee is paid the leg's reserve and the
    /// attestor's bond is slashed into the insurance pool.
    DisputeRail {
        /// The plan.
        #[serde(with = "crate::agent_audit::hex32")]
        plan_id: [u8; 32],
        /// The leg's index.
        index: u8,
        /// The payee's evidence (its account statement or return notice).
        #[serde(with = "hex_bytes")]
        evidence: Vec<u8>,
    },
    /// Post collateral for netted legs: `amount` of `asset` moves from the
    /// sender into its collateral vault. A batch's net debits are paid from
    /// it when the batch closes.
    PostCollateral {
        /// Token id (TNZO or a listed stablecoin).
        #[serde(with = "crate::agent_audit::hex32")]
        asset: [u8; 32],
        /// Amount in the asset's smallest unit.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// The delegated agent that posts, when one does: the collateral
        /// leaves its wallet, and the amount (the most its net debit can
        /// reach) counts against its terms.
        #[serde(default)]
        agent: Option<crate::agent_terms::AgentAuthorization>,
    },
    /// Withdraw collateral the sender posted, down to what its net debit in
    /// the asset's open batch still needs.
    WithdrawCollateral {
        /// Token id.
        #[serde(with = "crate::agent_audit::hex32")]
        asset: [u8; 32],
        /// Amount in the asset's smallest unit.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// The delegated agent whose collateral returns to its wallet, when
        /// one does; its action states no value.
        #[serde(default)]
        agent: Option<crate::agent_terms::AgentAuthorization>,
    },
    /// Reconcile a route's settlement lock against Tenzro's books. Anyone
    /// may send it: `entries` are what the lock recorded after the entries
    /// already reconciled, and `checkpoint` is the route's proof of the
    /// lock's checkpoint. Folded from the stored hash, the entries must give
    /// the proven count and hash; each is then checked against its plan and
    /// decision, and one that disagrees is stored as a mismatch and stops
    /// the route.
    Reconcile {
        /// The route's bridge protocol.
        adapter: crate::bridge_route::BridgeRouteAdapter,
        /// The route's external chain.
        chain: String,
        /// The entries since the last reconciliation, in order.
        entries: Vec<ReconEntry>,
        /// The route's proof of the lock's checkpoint.
        #[serde(with = "hex_bytes")]
        checkpoint: Vec<u8>,
    },
}

/// Most bytes of a [`PlanOp::ProveLeg`] evidence.
pub const MAX_LEG_EVIDENCE: usize = 256 * 1024;

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

impl SettlementPlan {
    /// The hash-locked leg's index and premium, if the plan has one.
    pub fn griefing_premium(&self) -> Option<(usize, u128)> {
        self.legs
            .iter()
            .enumerate()
            .find_map(|(i, l)| match l.kind {
                LegKind::HashLocked { premium, .. } => Some((i, premium)),
                _ => None,
            })
    }
}

impl PlanOp {
    /// Size bounds checked at admission.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::ProveLeg { evidence, .. } | Self::DisputeRail { evidence, .. } = self
            && evidence.len() > MAX_LEG_EVIDENCE
        {
            return Err("leg evidence is larger than 256 KiB");
        }
        if let Self::DisputeRail { evidence, .. } = self
            && evidence.is_empty()
        {
            return Err("a dispute carries its evidence");
        }
        if let Self::Open {
            attribution: Some(a),
            ..
        } = self
            && a.check().is_err()
        {
            return Err("an attribution names one to three distinct DIDs of at most 256 bytes");
        }
        if let Self::Open {
            split,
            split_hash,
            legs,
            ..
        } = self
        {
            if legs.is_empty() || legs.len() > MAX_PLAN_LEGS {
                return Err("a plan has 1 to 16 legs");
            }
            if legs.iter().filter(|l| l.kind.is_external()).count() > MAX_EXTERNAL_LEGS {
                return Err("a plan has at most 8 legs on other networks");
            }
            if legs.iter().any(|l| {
                matches!(
                    l.kind,
                    LegKind::NativeTransfer { amount: 0, .. } | LegKind::Netted { amount: 0, .. }
                )
            }) {
                return Err("a Tenzro leg moves a positive amount");
            }
            let netted: Vec<[u8; 32]> = legs
                .iter()
                .filter_map(|l| match l.kind {
                    LegKind::Netted { asset, .. } => Some(asset),
                    _ => None,
                })
                .collect();
            if !netted.is_empty()
                && (netted.len() != legs.len() || netted.iter().any(|a| *a != netted[0]))
            {
                return Err("a plan with a netted leg holds only netted legs of one asset");
            }
            if legs.iter().any(|l| {
                matches!(l.kind, LegKind::Netted { .. }) && l.class_required != LegClass::Native
            }) {
                return Err("a netted leg is native");
            }
            if legs
                .iter()
                .any(|l| matches!(&l.kind, LegKind::IbcTransfer { chain, .. } if chain.is_empty() || chain.len() > 64))
            {
                return Err("an IBC leg names a chain of 1 to 64 bytes");
            }
            for l in legs {
                if matches!(
                    l.kind,
                    LegKind::NativeTransfer { .. }
                        | LegKind::Netted { .. }
                        | LegKind::RailInstruction { .. }
                ) && l.max_network_fee != 0
                {
                    return Err("only a leg proven from another network repays a network fee");
                }
                if l.kind.is_external() && l.usd_e6 == 0 {
                    return Err("a leg off Tenzro states its USD value");
                }
                match &l.kind {
                    LegKind::RemoteLock { chain, amount, .. } => {
                        if chain.is_empty() || chain.len() > 64 {
                            return Err("a lock leg names a chain of 1 to 64 bytes");
                        }
                        if *amount == 0 {
                            return Err("a lock leg moves a positive amount");
                        }
                        if l.class_required == LegClass::Native {
                            return Err("a lock leg is proven or attested, never native");
                        }
                    }
                    LegKind::HashLocked {
                        chain,
                        amount_sats,
                        recipient_key,
                        refund_key,
                        premium,
                        ..
                    } => {
                        if chain.is_empty() || chain.len() > 64 {
                            return Err("a hash-locked leg names a chain of 1 to 64 bytes");
                        }
                        if *amount_sats == 0 {
                            return Err("a hash-locked leg moves a positive amount");
                        }
                        if *premium == 0 {
                            return Err("a hash-locked leg escrows a positive premium");
                        }
                        if ![recipient_key, refund_key]
                            .iter()
                            .all(|k| matches!(k[0], 2 | 3))
                        {
                            return Err("a hash-locked leg names compressed public keys");
                        }
                        if l.class_required != LegClass::Proven {
                            return Err("a hash-locked leg is proven");
                        }
                    }
                    LegKind::RailInstruction {
                        currency,
                        amount_minor,
                        payee,
                        attestor,
                        reserve,
                        ..
                    } => {
                        if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_uppercase())
                        {
                            return Err("a rail leg names an ISO 4217 currency code");
                        }
                        if *amount_minor == 0 {
                            return Err("a rail leg moves a positive amount");
                        }
                        if *reserve == 0 {
                            return Err("a rail leg escrows a positive reserve");
                        }
                        if attestor.as_ref() == Some(payee) {
                            return Err("a rail leg's attestor is not its payee");
                        }
                        if l.class_required != LegClass::Attested {
                            return Err("a rail leg is attested");
                        }
                    }
                    _ => {}
                }
            }
            if legs
                .iter()
                .filter(|l| matches!(l.kind, LegKind::HashLocked { .. }))
                .count()
                > 1
            {
                // The one preimage reveal is the commit; two would need two.
                return Err("a plan has at most one hash-locked leg");
            }
            split
                .validate()
                .map_err(|_| "the split rule is malformed")?;
            if &split.hash() != split_hash {
                return Err("the split rule does not match the hash the quote signed");
            }
        }
        Ok(())
    }
}

/// The bytes a payee signs, under the account-owner signature context, to set
/// the asset it is paid in (`asset` is `keep_inbound` or `tnzo`): the domain
/// followed by the DID, the asset and the little-endian timestamp, each
/// prefixed by its little-endian `u64` length.
pub fn settlement_preference_preimage(payee_did: &str, asset: &str, timestamp_ms: i64) -> Vec<u8> {
    let mut preimage = b"tenzro/settlement-preference/v1".to_vec();
    for field in [
        payee_did.as_bytes(),
        asset.as_bytes(),
        &timestamp_ms.to_le_bytes()[..],
    ] {
        preimage.extend_from_slice(&(field.len() as u64).to_le_bytes());
        preimage.extend_from_slice(field);
    }
    preimage
}
