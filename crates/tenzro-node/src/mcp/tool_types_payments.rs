//! Typed MCP tool inputs and outputs for payments, settlement, escrow, bridges and delegated agents.

use serde::{Deserialize, Serialize};

// ─── Shared shapes ───

/// A u128 amount as the chain writes it in JSON: a number up to 2^64 - 1, a
/// decimal string above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PayAmount {
    /// The amount as a number.
    Number(u64),
    /// The amount as a decimal string.
    Decimal(String),
}

impl Default for PayAmount {
    fn default() -> Self {
        Self::Number(0)
    }
}

/// A string or a number, one element of a pair the chain writes as a JSON array.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PayTextOrNumber {
    /// A number.
    Number(u64),
    /// A string.
    Text(String),
}

/// Where a record sits in node state, for a state proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayStateProofKey {
    /// The storage column, `state`.
    pub namespace: String,
    /// The storage key, hex.
    pub key: String,
}

/// The classical half of a composite signature.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum PayClassicalProof {
    /// A raw signature, hex.
    Raw {
        /// The signature, hex.
        signature: String,
    },
    /// A WebAuthn assertion.
    WebAuthn {
        /// Authenticator data, hex.
        authenticator_data: String,
        /// Client data JSON, hex.
        client_data_json: String,
        /// The signature, hex.
        signature: String,
    },
}

/// A classical signature and, when the account enrolled one, an ML-DSA-65 signature.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCompositeSignature {
    /// The classical signature.
    pub classical: PayClassicalProof,
    /// The ML-DSA-65 signature, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
}

/// What a client signs for an unsigned transaction.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PaySigningPayload {
    /// A privileged transaction: its typed preimage.
    TypedAction {
        /// The preimage text.
        preimage: String,
        /// The transaction digest, hex.
        digest: String,
    },
    /// A plain transaction: the canonical tx_type encoding its digest covers.
    Plain {
        /// The tx_type JSON the digest covers.
        tx_type_json: String,
        /// The transaction digest, hex.
        digest: String,
    },
}

/// The unsigned transaction request a builder tool completes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayUnsignedTxRequest {
    /// The sending account, hex.
    pub from: String,
    /// The receiving account, hex; the zero address when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The sender's nonce (default 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// Chain id; the node's when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Gas price (default 1 gwei).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<u64>,
    /// Value moved, wei (unused by typed transactions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<PayAmount>,
    /// Unix ms the signer names; the digest covers it.
    pub timestamp: u64,
    /// Last block time, Unix ms, the transaction may execute at.
    pub valid_until: u64,
}

/// A builder tool's request completed with its tx_type and gas limit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayTypedTxRequest<T> {
    /// The caller's request fields.
    #[serde(flatten)]
    pub request: PayUnsignedTxRequest,
    /// The transaction body.
    pub tx_type: T,
    /// The gas the VM charges for it.
    pub gas_limit: u64,
}

/// A completed unsigned transaction and what its signer signs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBuiltTransaction<T> {
    /// The request to sign and send with tenzro_sendRawTransaction.
    pub transaction: PayTypedTxRequest<T>,
    /// What the signer signs.
    pub signing_payload: PaySigningPayload,
}

/// `{"op": ...}`, the body of a typed transaction.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayOpBody<T> {
    /// The operation.
    pub op: T,
}

/// A `SettlementPlan` transaction body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettlementPlanTx<T> {
    /// The plan operation.
    #[serde(rename = "SettlementPlan")]
    pub settlement_plan: PayOpBody<T>,
}

/// A `Payment` transaction body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentTx<T> {
    /// The payment operation.
    #[serde(rename = "Payment")]
    pub payment: PayOpBody<T>,
}

/// A `Bridge` transaction body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeTx<T> {
    /// The bridge operation.
    #[serde(rename = "Bridge")]
    pub bridge: PayOpBody<T>,
}

// ─── Split rules ───

/// What a split line's recipient is paid as.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PaySplitRole {
    Payee,
    Publisher,
    Licensor,
    Referrer,
    Facilitator,
    Relayer,
    Solver,
    Prover,
    Refund,
}

/// Who a split line pays.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PaySplitRecipient {
    /// A Tenzro account, 32-byte hex.
    Address(String),
    /// The account derived from a DID.
    DidDerived(String),
    /// The account that submitted the leg.
    LegSubmitter,
}

/// How much a split line takes of the net.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PaySplitBasis {
    /// Basis points of the net.
    Bps(u16),
    /// A fixed amount, base units.
    Fixed(PayAmount),
    /// What the other lines leave.
    Remainder,
}

/// One line of a split rule.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySplitLine {
    /// The recipient's role.
    pub role: PaySplitRole,
    /// The recipient.
    pub recipient: PaySplitRecipient,
    /// The line's share.
    pub basis: PaySplitBasis,
    /// The most the line takes, base units.
    #[serde(default)]
    pub cap: Option<PayAmount>,
}

/// How a payment's net divides: exactly one line has basis `remainder`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySplitRule {
    /// Rule version, 1.
    pub version: u16,
    /// The lines.
    pub lines: Vec<PaySplitLine>,
}

/// The governed fee parameters a split applies.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayFeeParams {
    /// Protocol fee, basis points of the gross.
    pub fee_bps: u16,
    /// Least protocol fee, wei.
    pub min_fee: PayAmount,
    /// Share of the fee burned, basis points.
    pub burn_bps: u16,
    /// Share of the fee to the insurance pool, basis points.
    pub insurance_bps: u16,
}

/// How the protocol fee divided.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayFeeAllocation {
    /// The whole fee.
    pub fee: PayAmount,
    /// Burned.
    pub burn: PayAmount,
    /// To the treasury.
    pub treasury: PayAmount,
    /// To the insurance pool.
    pub insurance: PayAmount,
}

/// How a gross amount divided under a split rule.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAllocation {
    /// The gross.
    pub gross: PayAmount,
    /// The protocol fee.
    pub fee: PayFeeAllocation,
    /// Payee-borne network fees.
    pub network_fees: PayAmount,
    /// What the split lines divide.
    pub net: PayAmount,
    /// Each line's credit, decimal strings, by line index.
    pub credits: Vec<String>,
}

/// A split preview: the allocation and the rule hash a quote signs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettlePreviewSplitOutput {
    /// The division.
    pub allocation: PayAllocation,
    /// The rule's hash, hex.
    pub split_hash: String,
    /// The live fee parameters applied.
    pub fee_params: PayFeeParams,
}

// ─── Delegated-agent authorizations ───

/// The VM a remote call runs on: `evm` or `svm`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PayCallVm {
    Evm,
    Svm,
}

/// A call into a VM an agent action makes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayVmCall {
    /// The VM.
    pub vm: PayCallVm,
    /// The callee, bytes.
    pub to: Vec<u8>,
    /// Value sent, base units.
    #[serde(default)]
    pub value: u128,
    /// Calldata, bytes.
    pub data: Vec<u8>,
}

/// A payment an agent action pays.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentPayment {
    /// The payment id.
    pub payment_id: String,
    /// Digest of the payment request, hex.
    pub request_digest: String,
    /// Digest of the quote, hex.
    pub quote_digest: String,
}

/// One verifier of a quorum.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(inline)]
pub struct PayVerifierMember {
    /// The verifier's 20-byte address, bytes.
    pub address: Vec<u8>,
    /// Its ML-DSA-65 verifying key, bytes.
    pub pq_public_key: Vec<u8>,
    /// Its operator.
    pub operator: String,
    /// Its RPC provider.
    pub rpc_provider: String,
}

/// A verifier quorum.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(inline)]
pub struct PayVerifierQuorum {
    /// The verifier set's index.
    pub set_index: u32,
    /// Members in the set.
    pub size: u32,
    /// The members.
    pub members: Vec<PayVerifierMember>,
    /// Signatures needed.
    pub threshold: u32,
}

/// When an escrow releases.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PayReleaseConditions {
    ProviderSignature,
    ConsumerSignature,
    BothSignatures,
    Timeout,
    /// A custom condition.
    Custom {
        /// The condition.
        condition: String,
    },
    /// Release on the preimage of a hash.
    HashLock {
        /// The hash, 32 bytes.
        hash: Vec<u8>,
    },
    /// Release at a rate per epoch.
    Stream {
        /// Released per epoch, base units.
        rate_per_epoch: PayAmount,
        /// Epoch length, ms.
        epoch_ms: u64,
    },
    /// Release on a verifier quorum's attestation of a claim.
    QuorumAttestation {
        /// The claim.
        claim: String,
        /// The quorum.
        verifiers: PayVerifierQuorum,
    },
    /// Release by an executor account.
    Executor {
        /// The executor, 32 bytes.
        executor: Vec<u8>,
    },
}

/// The kind of a service proof.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PayProofType {
    Cryptographic,
    TeeAttestation,
    MultiParty,
    Merkle,
    ZeroKnowledge,
    Oracle,
}

/// The role of a service proof's signer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PaySignerRole {
    Provider,
    Consumer,
    Verifier,
    Oracle,
}

/// A signature on a service proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayProofSignature {
    /// The signer, 32 bytes.
    pub signer: Vec<u8>,
    /// The signature, bytes.
    pub signature: Vec<u8>,
    /// The signer's role.
    pub role: PaySignerRole,
}

/// Proof that a service was delivered, releasing an escrow.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayServiceProof {
    /// The proof's kind.
    pub proof_type: PayProofType,
    /// The proof, bytes.
    pub proof_data: Vec<u8>,
    /// Signatures over it.
    pub signatures: Vec<PayProofSignature>,
    /// An attestation, bytes.
    pub attestation: Option<Vec<u8>>,
}

/// An escrow operation an agent action makes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayAgentEscrow {
    /// Fund an escrow.
    Create {
        /// Expiry, Unix ms.
        expires_at_ms: u64,
        /// When it releases.
        release_conditions: PayReleaseConditions,
        /// A reference, 32-byte hex.
        #[serde(default)]
        reference: Option<String>,
    },
    /// Release an escrow.
    Release {
        /// The escrow, 32 bytes.
        escrow_id: Vec<u8>,
        /// The delivery proof.
        proof: PayServiceProof,
    },
    /// Refund an expired escrow.
    Refund {
        /// The escrow, 32 bytes.
        escrow_id: Vec<u8>,
    },
}

/// A target a remote grant lets the account call.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteTarget {
    /// The contract or program, hex.
    pub target: String,
    /// The function selector, hex.
    pub selector: String,
}

/// A grant on another chain: a budget of one asset for a limited time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteGrantRequest {
    /// The asset, CAIP-19.
    pub caip19: String,
    /// The budget, base units, decimal string.
    pub budget: String,
    /// Most per action, base units, decimal string.
    pub per_action_max: String,
    /// Lifetime, ms.
    pub ttl_ms: u64,
    /// Targets the account may call.
    #[serde(default)]
    pub targets: Vec<PayRemoteTarget>,
    /// For an exact grant, the payload's hash, 32-byte hex.
    #[serde(default)]
    pub payload_hash: Option<String>,
    /// Most relay fee, base units, decimal string.
    pub relay_fee_max: String,
}

/// A governance ballot an agent casts.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentBallot {
    /// The proposal.
    pub proposal_id: String,
    /// For or against.
    pub in_favour: bool,
    /// The validator voting.
    pub validator: String,
}

/// The controller's step-up approval of an action.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentTermsApproval {
    /// The controller's account, bytes.
    pub account: Vec<u8>,
    /// The challenge nonce, 16 bytes.
    pub nonce: Vec<u8>,
    /// The root's public key, bytes.
    pub root_public_key: Vec<u8>,
    /// The root's signature.
    pub signature: PayCompositeSignature,
}

/// One action of a delegated agent, as its serving node signs it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentAction {
    /// The agent.
    pub agent_did: String,
    /// The serving node that signs.
    pub machine_did: String,
    /// The operation, e.g. pay, settlement_plan, create_escrow.
    pub operation: String,
    /// The counterparty.
    #[serde(default)]
    pub counterparty: String,
    /// Amount, base units.
    #[serde(default)]
    pub amount: u128,
    /// The asset.
    #[serde(default)]
    pub asset: Option<String>,
    /// Value in USD micro-units.
    #[serde(default)]
    pub usd_e6: u64,
    /// The payment paid.
    #[serde(default)]
    pub payment: Option<PayAgentPayment>,
    /// The chain acted on.
    #[serde(default)]
    pub chain: String,
    /// The payment protocol.
    #[serde(default)]
    pub payment_protocol: Option<String>,
    /// The model used.
    #[serde(default)]
    pub model: Option<String>,
    /// VM calls made.
    #[serde(default)]
    pub calls: Vec<PayVmCall>,
    /// An escrow operation.
    #[serde(default)]
    pub escrow: Option<PayAgentEscrow>,
    /// A remote grant issued.
    #[serde(default)]
    pub remote_grant: Option<PayRemoteGrantRequest>,
    /// A ballot cast.
    #[serde(default)]
    pub ballot: Option<PayAgentBallot>,
    /// A veto signal.
    #[serde(default)]
    pub veto_signal: Option<String>,
    /// The agent's action nonce.
    pub nonce: u64,
    /// Whether the action carries untrusted input.
    #[serde(default)]
    pub tainted: bool,
    /// The controller's step-up approval.
    #[serde(default)]
    pub step_up: Option<PayAgentTermsApproval>,
}

/// An agent action and its serving node's signature.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentAuthorization {
    /// The action.
    pub action: PayAgentAction,
    /// The serving node's signature, hex.
    pub signature: String,
}

// ─── Settlement plans ───

/// What a leg's evidence is worth: `native`, `proven` or `attested`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayLegClass {
    Native,
    Proven,
    Attested,
}

/// How strongly a plan's legs are bound together.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayAtomicityTier {
    Native,
    DecisionLocked,
    IbcTransfer,
    HashLocked,
    Compensated,
}

/// Where a plan stands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayPlanStatus {
    Open,
    Committed,
    Aborted,
}

/// A governed bridge route's protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PayBridgeAdapter {
    Ccip,
    Ibc,
    Deposit,
    Contract,
}

/// A payment rail outside every chain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayRailKind {
    Iso20022,
    Card,
}

/// What a leg moves and where.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayLegKind {
    /// TNZO paid into the plan vault on open.
    NativeTransfer {
        /// Amount, wei.
        amount: PayAmount,
        /// The escrow it is paid from, 32-byte hex.
        #[serde(default)]
        escrow_id: Option<String>,
    },
    /// A netted obligation in a token.
    Netted {
        /// Token id, 32-byte hex.
        asset: String,
        /// Amount, base units.
        amount: PayAmount,
    },
    /// An IBC transfer.
    IbcTransfer {
        /// The counterparty chain.
        chain: String,
        /// The packet sequence.
        sequence: u64,
    },
    /// Value locked in a settlement lock on another chain.
    RemoteLock {
        /// The route's protocol.
        adapter: PayBridgeAdapter,
        /// The route's chain.
        chain: String,
        /// The asset, 32-byte hex.
        asset: String,
        /// Amount, base units.
        amount: PayAmount,
        /// The recipient, 32-byte hex.
        recipient: String,
    },
    /// Bitcoin in a hash-locked script.
    HashLocked {
        /// The Bitcoin route's chain.
        chain: String,
        /// SHA-256 of the secret, hex.
        hash: String,
        /// Compressed key a commit pays, hex.
        recipient_key: String,
        /// Compressed key that may reclaim after the timelock, hex.
        refund_key: String,
        /// Unix seconds the refund path opens.
        refund_after_secs: u32,
        /// Amount, satoshis.
        amount_sats: u64,
        /// TNZO premium escrowed, wei.
        premium: PayAmount,
    },
    /// A payment on a rail no chain can lock.
    RailInstruction {
        /// The rail.
        rail: PayRailKind,
        /// SHA-256 of the rail instruction, hex.
        instruction_digest: String,
        /// ISO 4217 currency.
        currency: String,
        /// Amount, minor units.
        amount_minor: PayAmount,
        /// The payee's account, 32 bytes.
        payee: Vec<u8>,
        /// The attestor's account, 32 bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestor: Option<Vec<u8>>,
        /// TNZO reserve, wei.
        reserve: PayAmount,
    },
}

/// One value leg of a plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLeg {
    /// What it moves.
    pub kind: PayLegKind,
    /// The weakest evidence accepted for it.
    pub class_required: PayLegClass,
    /// Its value, USD micro-units.
    #[serde(default)]
    pub usd_e6: u64,
    /// Most TNZO, wei, repaid to its relayer.
    #[serde(default)]
    pub max_network_fee: PayAmount,
}

/// The call chain a payer attributes a settlement to.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCallAttribution {
    /// The app.
    #[serde(default)]
    pub app_did: Option<String>,
    /// The agent.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// The tool.
    #[serde(default)]
    pub tool_did: Option<String>,
}

/// The open operation of a settlement plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettleOpen {
    /// Makes the plan id unique per payer and quote.
    pub nonce: u64,
    /// The quote settled, 32-byte hex.
    pub quote_digest: String,
    /// The split rule's hash as the quote signed it, 32-byte hex.
    pub split_hash: String,
    /// The split rule.
    pub split: PaySplitRule,
    /// The legs.
    pub legs: Vec<PayLeg>,
    /// Block time after which an undecided plan aborts, ms.
    pub decide_deadline_ms: u64,
    /// The delegated agent that pays, when one does.
    #[serde(default)]
    pub agent: Option<PayAgentAuthorization>,
    /// The call chain the payer attributes the plan to.
    #[serde(default)]
    pub attribution: Option<PayCallAttribution>,
}

/// `{"open": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPlanOpOpen {
    /// The open operation.
    pub open: PaySettleOpen,
}

/// The prove-leg operation of a settlement plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettleProveLeg {
    /// The plan, 32-byte hex.
    pub plan_id: String,
    /// The leg's index.
    pub index: u8,
    /// What proves the leg, hex.
    #[serde(default)]
    pub evidence: String,
    /// Fee paid on the leg's network, wei.
    #[serde(default)]
    pub network_fee: PayAmount,
}

/// `{"prove_leg": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPlanOpProveLeg {
    /// The prove-leg operation.
    pub prove_leg: PaySettleProveLeg,
}

/// The dispute-rail operation of a settlement plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettleDisputeRail {
    /// The plan, 32-byte hex.
    pub plan_id: String,
    /// The leg's index.
    pub index: u8,
    /// The payee's evidence, hex.
    pub evidence: String,
}

/// `{"dispute_rail": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPlanOpDisputeRail {
    /// The dispute-rail operation.
    pub dispute_rail: PaySettleDisputeRail,
}

/// The reconcile operation of a settlement plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettleReconcile {
    /// The route's protocol.
    pub adapter: PayBridgeAdapter,
    /// The route's chain.
    pub chain: String,
    /// The lock's entries since the last reconciliation.
    pub entries: Vec<PayReconEntry>,
    /// The route's proof of the lock checkpoint, hex.
    pub checkpoint: String,
}

/// `{"reconcile": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPlanOpReconcile {
    /// The reconcile operation.
    pub reconcile: PaySettleReconcile,
}

/// The relayer that carried a leg's proof and the fee it paid.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLegRelay {
    /// The relayer, 32 bytes.
    pub relayer: Vec<u8>,
    /// The fee it paid, wei.
    pub realised: PayAmount,
}

/// A plan's one Commit-or-Abort decision.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPlanDecision {
    /// The plan, hex.
    pub plan_id: String,
    /// Commit (true) or abort.
    pub commit: bool,
    /// Block time of the decision, ms.
    pub decided_at_ms: u64,
    /// The account whose transaction decided it, 32 bytes.
    pub decided_by: Vec<u8>,
    /// Why it aborted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The division of the Tenzro value, on commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<PayAllocation>,
    /// The account each split line was paid to, by line index, 32 bytes each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<Vec<u8>>,
    /// The division of a hash-locked leg's premium, when the abort paid it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub premium_paid: Option<PayAllocation>,
}

/// A settlement plan as the chain stores it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettlementPlan {
    /// The plan id, hex.
    pub plan_id: String,
    /// The payer, 32 bytes.
    pub opened_by: Vec<u8>,
    /// The delegated agent that paid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    /// The quote settled, hex.
    pub quote_digest: String,
    /// The split rule.
    pub split: PaySplitRule,
    /// The legs.
    pub legs: Vec<PayLeg>,
    /// The plan's tier.
    pub tier: PayAtomicityTier,
    /// TNZO paid into the vault, wei.
    pub funded: PayAmount,
    /// Block time it opened, ms.
    pub opened_at_ms: u64,
    /// Block time an undecided plan aborts, ms.
    pub decide_deadline_ms: u64,
    /// Its status.
    pub status: PayPlanStatus,
    /// Each leg's achieved class, by index.
    pub achieved: Vec<Option<PayLegClass>>,
    /// The decision, once made.
    pub decision: Option<PayPlanDecision>,
    /// Each leg's relayer, by index.
    #[serde(default)]
    pub relays: Vec<Option<PayLegRelay>>,
    /// The call chain the payer attributed it to.
    #[serde(default)]
    pub attribution: Option<PayCallAttribution>,
}

/// A settlement plan with its derived ids and state-proof key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettlePlanOutput {
    /// The plan.
    pub plan: PaySettlementPlan,
    /// The split rule's hash, hex.
    pub split_hash: String,
    /// Each leg's id, hex.
    pub leg_ids: Vec<String>,
    /// The plan vault, hex.
    pub vault: String,
    /// Where the plan sits in state.
    pub proof: PayStateProofKey,
}

/// Settlement plans.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettlePlanListOutput {
    /// The plans.
    pub plans: Vec<SettlePlanOutput>,
}

/// A plan's decision with its commitment and state-proof key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleDecisionOutput {
    /// The decision.
    pub decision: PayPlanDecision,
    /// The 42-byte record remote locks verify, hex.
    pub commitment: String,
    /// Where the decision sits in state.
    pub proof: PayStateProofKey,
}

/// A leg's receipt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLegReceipt {
    /// The plan, hex.
    pub plan_id: String,
    /// The leg, hex.
    pub leg_id: String,
    /// The leg's index.
    pub index: u8,
    /// Whether the plan committed.
    pub committed: bool,
    /// The class the leg achieved.
    pub class_achieved: Option<PayLegClass>,
    /// The leg's value, base units.
    pub amount: PayAmount,
    /// Digest of the proof, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_digest: Option<String>,
    /// Block time of the decision, ms.
    pub decided_at_ms: u64,
    /// What its payee was compensated, wei.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation: Option<PayAmount>,
    /// Network fee repaid to the relayer, wei.
    #[serde(default)]
    pub network_fee: PayAmount,
    /// The relayer, 32 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayer: Option<Vec<u8>>,
}

/// A leg's recorded evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLegEvidence {
    /// The class it reached.
    pub class: PayLegClass,
    /// Digest of the evidence, hex.
    pub digest: String,
    /// A hash-locked leg's funding txid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_txid: Option<String>,
    /// The preimage the recipient claims with, once the plan commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
}

/// A leg's receipt and evidence, each with its state-proof key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleLegReceiptOutput {
    /// The leg, hex.
    pub leg_id: String,
    /// Its receipt, once decided.
    pub receipt: Option<PayLegReceipt>,
    /// The receipt's commitment, hex.
    pub commitment: Option<String>,
    /// Where the receipt sits in state.
    pub proof: PayStateProofKey,
    /// Its evidence, once recorded.
    pub evidence: Option<PayLegEvidence>,
    /// Where the evidence sits in state.
    pub evidence_proof: PayStateProofKey,
}

// ─── Netting ───

/// What one participant owes another in a netting batch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayObligation {
    /// The debtor, 32 bytes.
    pub debtor: Vec<u8>,
    /// The creditor, 32 bytes.
    pub creditor: Vec<u8>,
    /// The asset.
    pub asset: String,
    /// Amount, base units.
    pub amount: u128,
}

/// A net transfer a settled batch makes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettlementInstruction {
    /// The payer, 32 bytes.
    pub from: Vec<u8>,
    /// The payee, 32 bytes.
    pub to: Vec<u8>,
    /// The asset.
    pub asset: String,
    /// Amount, base units.
    pub amount: u128,
}

/// A participant's shortfall in a settled batch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayNetDefault {
    /// The participant, 32 bytes.
    pub participant: Vec<u8>,
    /// What it owed.
    pub owed: PayAmount,
    /// What it paid.
    pub paid: PayAmount,
}

/// How a netting batch settled.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayNetSettlement {
    /// The batch id.
    pub batch_id: String,
    /// Merkle root of the obligations, hex.
    pub obligations_root: String,
    /// The net instructions.
    pub instructions: Vec<PaySettlementInstruction>,
    /// What each instruction paid, decimal strings.
    pub paid: Vec<String>,
    /// Sum of the obligations.
    pub gross_total: PayAmount,
    /// Sum of the net instructions.
    pub net_total: PayAmount,
    /// Block time it settled, ms.
    pub settled_at_ms: u64,
    /// The defaults.
    pub defaults: Vec<PayNetDefault>,
}

/// An asset's netting batch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayNetBatch {
    /// Token id, hex.
    pub asset: String,
    /// Batch number.
    pub seq: u64,
    /// Close time, ms.
    pub closes_at_ms: u64,
    /// The obligations.
    pub obligations: Vec<PayObligation>,
    /// How it settled, once settled.
    pub settlement: Option<PayNetSettlement>,
}

/// One step of a Merkle path.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayMerklePathStep {
    /// The sibling node, 32 bytes.
    pub sibling: Vec<u8>,
    /// Whether the sibling is on the left.
    pub left: bool,
}

/// An obligation with its Merkle path to the batch root.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayProvenObligation {
    /// Its index among the obligations.
    pub index: u32,
    /// The obligation.
    pub obligation: PayObligation,
    /// Its path.
    pub path: Vec<PayMerklePathStep>,
}

/// A participant's gross-to-net statement.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayNettingStatement {
    /// The participant, 32 bytes.
    pub participant: Vec<u8>,
    /// Its obligations with Merkle paths.
    pub obligations: Vec<PayProvenObligation>,
    /// Its net instructions.
    pub instructions: Vec<PaySettlementInstruction>,
}

/// A netting batch, and with a participant its collateral and statement.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleNettingBatchOutput {
    /// The batch.
    pub batch: PayNetBatch,
    /// Where the batch sits in state.
    pub proof: PayStateProofKey,
    /// The participant's usable collateral, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral: Option<String>,
    /// The participant's collateral vault, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_vault: Option<String>,
    /// The batches the participant defaulted in, as [asset, seq] pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<Vec<Vec<PayTextOrNumber>>>,
    /// The participant's statement, once the batch settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<PayNettingStatement>,
}

// ─── Reconciliation ───

/// What a settlement lock recorded: `locked`, `released` or `refunded`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayReconKind {
    Locked,
    Released,
    Refunded,
}

/// One entry a settlement lock recorded.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayReconEntry {
    /// The plan, 32-byte hex.
    pub plan_id: String,
    /// The leg, 32-byte hex.
    pub leg_id: String,
    /// What happened.
    pub kind: PayReconKind,
    /// Amount, base units.
    pub amount: PayAmount,
}

/// How far a route's settlement lock is reconciled.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayReconState {
    /// Entries reconciled.
    pub count: u64,
    /// Running hash, hex.
    pub acc: String,
    /// Last checkpoint digest, hex.
    pub checkpoint_digest: String,
    /// Block time of the last reconciliation, ms.
    pub at_ms: u64,
    /// Positions of mismatched entries.
    pub mismatches: Vec<u64>,
}

/// What a funded duty is for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayDutyKind {
    /// Reconcile a route.
    Reconciliation {
        /// The route.
        route: String,
        /// The epoch.
        epoch: u64,
    },
    /// Relay an agent's grant.
    GrantRelay {
        /// The agent.
        agent_did: String,
        /// The chain.
        chain: String,
        /// The grant sequence.
        seq: u64,
    },
}

/// Where a duty stands: `open`, `paid` or `expired`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayDutyState {
    Open,
    Paid,
    Expired,
}

/// A funded duty: a reward for whoever does it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayDuty {
    /// The duty id, hex.
    pub id: String,
    /// What it is for.
    pub kind: PayDutyKind,
    /// Its vault, hex.
    pub vault: String,
    /// Who funded it, hex.
    pub funder: String,
    /// The reward, wei.
    pub reward: PayAmount,
    /// When it opened, ms.
    pub opened_at_ms: i64,
    /// When it expires, ms.
    pub expires_at_ms: Option<i64>,
    /// Where it stands.
    pub state: PayDutyState,
    /// Who it paid, hex.
    #[serde(default)]
    pub paid_to: Option<String>,
}

/// A route's reconciliation and its duty.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleReconciliationOutput {
    /// How far it is reconciled.
    pub reconciliation: Option<PayReconState>,
    /// The reconciliation duty.
    pub duty: Option<PayDuty>,
    /// Where the reconciliation sits in state.
    pub proof: PayStateProofKey,
}

/// An entry that disagreed with Tenzro's books.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayReconMismatch {
    /// The route's protocol.
    pub adapter: PayBridgeAdapter,
    /// The route's chain.
    pub chain: String,
    /// The entry's position.
    pub position: u64,
    /// The running hash before it, hex.
    pub acc_before: String,
    /// The entry.
    pub entry: PayReconEntry,
    /// Why it disagreed.
    pub reason: String,
    /// The checkpoint digest, hex.
    pub checkpoint_digest: String,
    /// Who submitted it, 32 bytes.
    pub submitted_by: Vec<u8>,
    /// Block time, ms.
    pub at_ms: u64,
    /// Whether an attestor vouched for it.
    pub attested: bool,
    /// The account it cost, 32 bytes.
    pub harmed: Option<Vec<u8>>,
    /// The loss an insurance claim can pay, base units.
    pub loss: PayAmount,
}

/// A mismatch with its state-proof key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleMismatchEntry {
    /// The mismatch.
    pub mismatch: PayReconMismatch,
    /// Where it sits in state.
    pub proof: PayStateProofKey,
}

/// A route's reconciliation mismatches.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleMismatchesOutput {
    /// The mismatches.
    pub mismatches: Vec<SettleMismatchEntry>,
}

/// The reconcile transaction body and the count and hash its checkpoint must prove.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleSubmitReconciliationOutput {
    /// The SettlementPlan reconcile body to sign and send.
    pub tx_type: PaySettlementPlanTx<PayPlanOpReconcile>,
    /// Entries reconciled before these.
    pub reconciled: u64,
    /// Entries reconciled after these.
    pub count: u64,
    /// The running hash after these, hex.
    pub acc: String,
    /// Where the reconciliation sits in state.
    pub proof: PayStateProofKey,
}

// ─── Bridge and payment operations ───

/// The outbound bridge operation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeOutboundOp {
    /// The external chain.
    pub target_chain: String,
    /// The recipient there, hex.
    pub recipient: String,
    /// Amount, base units.
    pub amount: PayAmount,
    /// The carried asset; TNZO when absent.
    #[serde(default)]
    pub asset: Option<String>,
}

/// `{"outbound": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeOpOutbound {
    /// The outbound operation.
    pub outbound: PayBridgeOutboundOp,
}

/// The refund payment operation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRefundOp {
    /// The payment record, hex.
    pub pay_ref: String,
    /// Amount returned, base units.
    pub amount: PayAmount,
}

/// `{"refund": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentOpRefund {
    /// The refund operation.
    pub refund: PayRefundOp,
}

/// The set-split payment operation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySetSplitOp {
    /// The rule; null clears it.
    pub rule: Option<PaySplitRule>,
}

/// `{"set_split": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentOpSetSplit {
    /// The set-split operation.
    pub set_split: PaySetSplitOp,
}

// ─── Payment challenges, channels and records ───

/// A value in a challenge's protocol extensions: a string, a number or a list
/// of strings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PayChallengeExtra {
    /// A number, e.g. chain_id.
    Number(u64),
    /// A string, e.g. intent, scheme, network, escrow_id.
    Text(String),
    /// A list of strings, e.g. the offered schemes.
    List(Vec<String>),
}

/// A payment challenge for a protected resource.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentChallenge {
    /// The challenge id a credential names.
    pub challenge_id: String,
    /// `mpp`, `x402` or `native`.
    pub protocol: String,
    /// The protected resource.
    pub resource: String,
    /// Amount, the asset's smallest unit.
    pub amount: u128,
    /// The asset.
    pub asset: String,
    /// The payee.
    pub recipient: String,
    /// The chain it settles on.
    pub chain: String,
    /// When it expires, RFC 3339.
    pub expires_at: String,
    /// Protocol extensions: chain_id, intent, escrow_id, scheme, network,
    /// offered schemes, the meter key and a signed offer.
    pub extra: std::collections::BTreeMap<String, PayChallengeExtra>,
}

/// Whether a payment credential verifies against its challenge.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayVerifyPaymentOutput {
    /// The challenge.
    pub challenge_id: String,
    /// Whether it verified.
    pub verified: bool,
    /// Amount verified, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// The payer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_did: Option<String>,
    /// What settles it: `payer`, `voucher` or `foreign`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leg: Option<String>,
    /// The account or escrow it debits, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debits: Option<String>,
    /// Why it did not verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The agent and serving node that signed a voucher.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentVoucherSigner {
    /// The agent.
    pub agent_did: String,
    /// The serving node.
    pub machine_did: String,
    /// When the node checked the agent's terms, ms.
    pub as_of_ms: u64,
}

/// A cumulative voucher on an escrow-backed channel.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayEscrowVoucher {
    /// The channel's escrow, hex.
    pub escrow_id: String,
    /// Total paid on the channel so far, base units.
    pub cumulative_amount: PayAmount,
    /// What the voucher binds, hex.
    #[serde(default)]
    pub binding: String,
    /// The payer's key, hex; empty for an agent voucher.
    pub public_key: String,
    /// The signature.
    pub signature: PayCompositeSignature,
    /// The agent signer, for an agent voucher.
    #[serde(default)]
    pub agent: Option<PayAgentVoucherSigner>,
    /// The call chain the payment is attributed to.
    #[serde(default)]
    pub attribution: Option<PayCallAttribution>,
}

/// An agent voucher and what it pays out now.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentVoucherOutput {
    /// The voucher.
    pub voucher: PayEscrowVoucher,
    /// What the ledger pays on it now, decimal string.
    pub payout: String,
}

/// Where a payment channel stands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PayChannelState {
    Open,
    Closing,
    Closed,
}

/// A payment channel over an escrow.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentChannel {
    /// The channel id, the escrow id hex.
    pub session_id: String,
    /// The payer, 32 bytes.
    pub payer: Vec<u8>,
    /// The payee, 32 bytes.
    pub payee: Vec<u8>,
    /// The escrow's deposit.
    pub deposit: u128,
    /// When the escrow expires, ms.
    pub expires_at_ms: i64,
    /// Highest cumulative amount accepted.
    pub accepted_cumulative: u128,
    /// Charged so far.
    pub spent: u128,
    /// Claimed on chain so far.
    pub claimed_on_chain: u128,
    /// The highest voucher received.
    pub highest_voucher: Option<PayEscrowVoucher>,
    /// Where it stands.
    pub state: PayChannelState,
    /// Opened, RFC 3339.
    pub created_at: String,
    /// Last activity, RFC 3339.
    pub last_activity: String,
}

/// A closed payment channel.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCloseChannelOutput {
    /// The channel.
    pub channel_id: String,
    /// `open`, `closing` or `closed`.
    pub status: String,
    /// The amount claimed on chain, decimal string.
    pub claim_due: Option<String>,
}

/// A payee's standing split rule.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPayeeSplitOutput {
    /// The rule; null when the payee set none.
    pub rule: Option<PaySplitRule>,
}

/// An app's margin on a payment.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAppMargin {
    /// The app's wallet, 32 bytes.
    pub app_wallet: Vec<u8>,
    /// Its margin, basis points.
    pub margin_bps: u32,
}

/// What a payment paid for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentBinding {
    /// Digest of the request, hex.
    pub request_digest: String,
    /// Digest of the quote, hex.
    pub quote_digest: String,
    /// USD price, micro-units.
    pub usd_e6: u64,
    /// The app's margin.
    #[serde(default)]
    pub app_margin: Option<PayAppMargin>,
}

/// How a payment was recorded: `native`, `proven` or `attested`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayRecordClass {
    Native,
    Proven,
    Attested,
}

/// A payment's consensus record.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentRecord {
    /// The record's reference, hex.
    pub pay_ref: String,
    /// How it was recorded.
    pub class: PayRecordClass,
    /// The payer as its rail names it.
    pub payer: String,
    /// The payee, 32 bytes.
    pub payee: Vec<u8>,
    /// The asset.
    pub asset: String,
    /// Amount, base units.
    pub amount: PayAmount,
    /// Settlement fee, base units.
    pub fee: PayAmount,
    /// What it paid for.
    pub binding: PayPaymentBinding,
    /// The payer's nonce.
    pub nonce: String,
    /// The paying agent.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// The chain or rail it came from.
    #[serde(default)]
    pub source: Option<String>,
    /// Its attestor.
    #[serde(default)]
    pub attestor: Option<String>,
    /// The payee's delivery receipts.
    #[serde(default)]
    pub receipts: Vec<String>,
    /// Refunded so far, base units.
    #[serde(default)]
    pub refunded: PayAmount,
    /// When it was recorded, ms.
    pub recorded_at_ms: i64,
}

/// The burn and treasury leg a payment's transaction declared.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettlementLegs {
    /// TNZO burned, wei.
    pub burned: String,
    /// TNZO to the treasury, wei.
    pub treasury_leg: Option<String>,
}

/// The call this node recorded for a payment.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayWorkRecord {
    /// The kind of work.
    pub work_class: String,
    /// The model.
    pub model_id: String,
    /// Billable units by meter.
    pub units: std::collections::BTreeMap<String, PayAmount>,
    /// The serving node.
    pub serving_node: Option<String>,
    /// The capacity key.
    pub cap_key: Option<String>,
    /// The hardware tier.
    pub hardware_tier: Option<String>,
    /// When it was requested, ms.
    pub requested_at_ms: Option<u64>,
    /// Latency, ms.
    pub latency_ms: Option<u64>,
    /// Its cursor in the node's work log.
    pub cursor: String,
    /// `node_local`.
    pub source: String,
}

/// Where an event sits: block height, transaction, event.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayEventCursor {
    /// Block height.
    pub height: u64,
    /// Transaction index.
    pub tx_index: u32,
    /// Event index.
    pub event_index: u32,
}

/// What a chain event records.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayChainEventKind {
    /// A transaction's outcome.
    TxOutcome {
        /// Whether it succeeded.
        success: bool,
        /// Gas used.
        gas_used: u64,
        /// A deployed contract, bytes.
        contract_address: Option<Vec<u8>>,
    },
    /// A log.
    Log {
        /// The emitter, bytes.
        address: Vec<u8>,
        /// Topics, bytes each.
        topics: Vec<Vec<u8>>,
        /// Data, bytes.
        data: Vec<u8>,
    },
}

/// A chain event.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayChainEvent {
    /// Where it sits.
    pub cursor: PayEventCursor,
    /// Its transaction, 32 bytes.
    pub tx_hash: Vec<u8>,
    /// What it records.
    #[serde(flatten)]
    pub kind: PayChainEventKind,
}

/// A block header's execution summary.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBlockMetadata {
    /// Gas used.
    pub gas_used: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Transactions.
    pub tx_count: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Base fee per gas.
    pub base_fee_per_gas: Option<u128>,
}

/// A block header.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBlockHeader {
    /// Height.
    pub height: u64,
    /// Epoch.
    pub epoch: u64,
    /// Consensus round.
    pub round: u64,
    /// Anchor, 32 bytes.
    pub anchor: Vec<u8>,
    /// Previous block, 32 bytes.
    pub prev_hash: Vec<u8>,
    /// Transactions root, 32 bytes.
    pub tx_root: Vec<u8>,
    /// State root, 32 bytes.
    pub state_root: Vec<u8>,
    /// Event root, 32 bytes.
    pub event_root: Vec<u8>,
    /// Receipts root, 32 bytes.
    pub receipts_root: Vec<u8>,
    /// Logs bloom, hex.
    pub logs_bloom: String,
    /// Block time, ms.
    pub timestamp: i64,
    /// Proposer, 32 bytes.
    pub proposer: Vec<u8>,
    /// Execution summary.
    pub metadata: PayBlockMetadata,
}

/// A finality checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayFinalityCheckpoint {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis hash, 32 bytes.
    pub genesis_hash: Vec<u8>,
    /// Epoch.
    pub epoch: u64,
    /// Checkpoint index.
    pub index: u64,
    /// Previous checkpoint's digest, 32 bytes.
    pub prev: Vec<u8>,
    /// First block covered.
    pub first_height: u64,
    /// Last block covered.
    pub last_height: u64,
    /// Root of the covered blocks, 32 bytes.
    pub blocks_root: Vec<u8>,
    /// Height of the state root.
    pub state_height: u64,
    /// State root, 32 bytes.
    pub state_root: Vec<u8>,
    /// Statement root, 32 bytes.
    pub statement_root: Vec<u8>,
    /// The next committee's root, 32 bytes.
    pub next_committee_root: Option<Vec<u8>>,
    /// Anchor round.
    pub anchor_round: u64,
    /// Time, ms.
    pub timestamp_ms: u64,
    /// Ordering root, 32 bytes.
    pub ordering_root: Vec<u8>,
}

/// Proof that an event is in a certified block.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayEventProof {
    /// The event.
    pub event: PayChainEvent,
    /// Its path to the header's event root.
    pub event_path: Vec<PayMerklePathStep>,
    /// The block header.
    pub header: PayBlockHeader,
    /// The header's path to its checkpoint's blocks root.
    pub block_path: Vec<PayMerklePathStep>,
    /// Checkpoints from the covering one to the certified anchor.
    pub checkpoints: Vec<PayFinalityCheckpoint>,
}

/// One payment record with its event cursor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentEntry {
    /// The event cursor.
    pub cursor: String,
    /// The transaction, 32 bytes.
    pub tx_hash: Vec<u8>,
    /// The record.
    pub record: PayPaymentRecord,
    /// The burn and treasury leg its transaction declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<PaySettlementLegs>,
    /// The call this node recorded for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<PayWorkRecord>,
    /// The event's proof, with proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<PayEventProof>,
}

/// A page of payment records.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayListPaymentsOutput {
    /// The records.
    pub payments: Vec<PayPaymentEntry>,
    /// Pass back as from_cursor to continue.
    pub cursor: Option<String>,
}

// ─── Escrows ───

/// An escrow record.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayEscrowView {
    /// The escrow, 0x hex.
    pub escrow_id: String,
    /// The payer, 0x hex.
    pub payer: String,
    /// The payee, 0x hex.
    pub payee: String,
    /// Amount, decimal string.
    pub amount: String,
    /// The asset.
    pub asset_id: String,
    /// `Funded`, `Released`, `Refunded` or `Expired`.
    pub status: String,
    /// Created, ms.
    pub created_at: i64,
    /// Expires, ms.
    pub expires_at: i64,
    /// When it releases.
    pub release_conditions: PayReleaseConditions,
    /// Claimed so far, decimal string.
    pub claimed: String,
    /// Its reference, hex.
    pub reference: Option<String>,
    /// The event cursor, in a listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Escrows a payer funded.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayEscrowsByPayerOutput {
    /// The payer, 0x hex.
    pub payer: String,
    /// The escrows.
    pub escrows: Vec<PayEscrowView>,
    /// Pass back as from_cursor to continue.
    pub cursor: Option<String>,
}

/// Escrows held for a payee.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayEscrowsByPayeeOutput {
    /// The payee, 0x hex.
    pub payee: String,
    /// The escrows.
    pub escrows: Vec<PayEscrowView>,
    /// Pass back as from_cursor to continue.
    pub cursor: Option<String>,
}

/// An action a delegated agent's serving node signed and submitted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentActOutput {
    /// The agent.
    pub agent_did: String,
    /// The serving node that signed.
    pub machine_did: String,
    /// The action's nonce.
    pub nonce: u64,
    /// The escrow the action created, hex.
    pub escrow_id: Option<String>,
    /// The payment record the action made, hex.
    pub pay_ref: Option<String>,
    /// The submitted transaction.
    pub tx_hash: String,
}

// ─── Bridge routes ───

/// A chain family.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayChainFamily {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
    Stellar,
    Sui,
    Aptos,
    Ton,
}

/// The trust anchor of a route's light client.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayLightClientAnchor {
    /// Ethereum's sync committee.
    EthereumSyncCommittee {
        /// Bytes.
        genesis_validators_root: Vec<u8>,
        /// Bytes.
        fork_version: Vec<u8>,
        /// Bytes.
        trusted_block_root: Vec<u8>,
    },
    /// A Tendermint chain.
    Tendermint {
        /// The chain id.
        chain_id: String,
        /// Trusted height.
        trusted_height: u64,
        /// Trusted header hash, bytes.
        trusted_header_hash: Vec<u8>,
        /// Trusting period, s.
        trusting_period_secs: u64,
    },
    /// Bitcoin headers.
    BitcoinHeaders {
        /// Trusted height.
        trusted_height: u64,
        /// Trusted header hash, bytes.
        trusted_header_hash: Vec<u8>,
        /// Confirmations required.
        confirmations: u32,
        /// Signer keys, bytes each.
        signers: Vec<Vec<u8>>,
        /// Signatures required.
        threshold: u32,
        /// Fee rate.
        fee_rate: u64,
    },
    /// Sui's committee.
    SuiCommittee {
        /// Bytes.
        trusted_checkpoint_digest: Vec<u8>,
    },
    /// Aptos validators.
    AptosValidators {
        /// Bytes.
        trusted_ledger_info_hash: Vec<u8>,
    },
    /// Stellar SCP.
    StellarScp {
        /// Bytes.
        network_id: Vec<u8>,
        /// Validator keys, bytes each.
        validators: Vec<Vec<u8>>,
        /// Signatures required.
        threshold: u32,
    },
    /// A TON key block.
    TonKeyBlock {
        /// Trusted seqno.
        trusted_seqno: u32,
        /// Trusted root hash, bytes.
        trusted_root_hash: Vec<u8>,
    },
}

/// A mint rate limit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayMintRateLimit {
    /// Most per mint.
    pub per_mint: PayAmount,
    /// Most per epoch.
    pub per_epoch: PayAmount,
}

/// A token-bucket rate limit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLaneRateLimit {
    /// Bucket capacity.
    pub capacity: PayAmount,
    /// Refill per second.
    pub rate: PayAmount,
}

/// A CCIP lane version.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PayCcipLaneVersion {
    #[serde(rename = "2.0.0")]
    V2_0,
    #[serde(rename = "1.6.0")]
    V1_6,
    #[serde(rename = "1.5.0")]
    V1_5,
}

/// A CCIP lane's settings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCcipLane {
    /// Lane version.
    pub version: PayCcipLaneVersion,
    /// Off-ramp, 20 bytes.
    pub off_ramp: Vec<u8>,
    /// Hash of the CCVs and executor, 32 bytes.
    pub ccv_and_executor_hash: Vec<u8>,
    /// Inbound limit.
    pub inbound: PayLaneRateLimit,
}

/// An IBC version: `classic` or `v2`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayIbcVersion {
    Classic,
    V2,
}

/// An IBC route's settings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayIbcRoute {
    /// IBC version.
    pub version: PayIbcVersion,
    /// The counterparty's client.
    pub counterparty_client_id: String,
    /// The counterparty's connection.
    pub counterparty_connection_id: Option<String>,
    /// The counterparty's channel.
    pub counterparty_channel_id: Option<String>,
    /// Packet timeout, s.
    pub packet_timeout_secs: u64,
}

/// How a carried asset moves.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayAssetTransfer {
    LockAndMint,
    /// Burned on one side, minted on the other.
    BurnAndMint {
        /// The protocol.
        protocol: String,
        /// Its operator.
        operator: String,
    },
}

/// A carried asset's own lane.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAssetLane {
    /// Inbound limit.
    pub inbound: PayLaneRateLimit,
}

/// An asset a route carries.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCarriedAsset {
    /// Symbol.
    pub symbol: String,
    /// Name.
    pub name: String,
    /// Decimals.
    pub decimals: u8,
    /// Pool, 32 bytes.
    pub pool: Vec<u8>,
    /// The token on the other chain, 32 bytes.
    pub remote_token: Vec<u8>,
    /// CAIP-19.
    pub caip19: String,
    /// How it moves.
    pub transfer: PayAssetTransfer,
    /// Mint limit.
    pub mint_limit: PayMintRateLimit,
    /// Outflow limit.
    pub outflow: PayLaneRateLimit,
    /// Its lane.
    pub lane: Option<PayAssetLane>,
    /// Most outstanding.
    pub max_outstanding: PayAmount,
    /// Whether it is carried.
    pub enabled: bool,
}

/// A governed bridge route as stored.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeRoute {
    /// Protocol.
    pub adapter: PayBridgeAdapter,
    /// Chain family.
    pub family: PayChainFamily,
    /// The external chain.
    pub source_chain: String,
    /// Its chain id.
    pub source_chain_id: u64,
    /// Local selector.
    pub local_selector: u64,
    /// Peer, 32 bytes.
    pub peer: Vec<u8>,
    /// Ramp, 32 bytes.
    pub ramp: Vec<u8>,
    /// Local endpoint, 32 bytes.
    pub local_endpoint: Vec<u8>,
    /// The token on the other chain, 32 bytes.
    pub remote_token: Vec<u8>,
    /// The verifier quorum.
    pub verifiers: PayVerifierQuorum,
    /// The blessing quorum.
    pub blessing: Option<PayVerifierQuorum>,
    /// The light client's anchor.
    pub light_client: Option<PayLightClientAnchor>,
    /// Mint limit.
    pub mint_limit: PayMintRateLimit,
    /// Outflow limit.
    pub outflow: PayLaneRateLimit,
    /// The CCIP lane.
    pub lane_limits: Option<PayCcipLane>,
    /// IBC settings.
    pub ibc: Option<PayIbcRoute>,
    /// The settlement lock, 32 bytes.
    pub settlement_lock: Option<Vec<u8>>,
    /// Carried assets.
    #[serde(default)]
    pub assets: Vec<PayCarriedAsset>,
    /// The native asset.
    #[serde(default)]
    pub native_asset: Option<String>,
}

/// A quorum member as a route view shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayQuorumMemberView {
    /// Address, 0x hex.
    pub address: String,
    /// Its operator.
    pub operator: String,
    /// Its RPC provider.
    pub rpc_provider: String,
}

/// A verifier quorum as a route view shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayQuorumView {
    /// The set's index.
    pub set_index: u32,
    /// Signatures needed.
    pub threshold: u32,
    /// Members in the set.
    pub size: u32,
    /// Whether every member is drawn.
    pub drawn: bool,
    /// The members.
    pub members: Vec<PayQuorumMemberView>,
}

/// A committee set and the digest its handover signs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCommitteeSetView {
    /// The set's index.
    pub set_index: u32,
    /// Signatures needed.
    pub threshold: u32,
    /// Member addresses, 0x hex.
    pub members: Vec<String>,
    /// When it expires, Unix s.
    pub expires_at_secs: u64,
    /// The handover digest, 0x hex.
    pub handover_digest: String,
}

/// A carried asset with its supply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRouteAssetView {
    /// Symbol.
    pub symbol: String,
    /// CAIP-19.
    pub caip19: String,
    /// Its representation here, hex.
    pub representation: String,
    /// Whether it is carried.
    pub enabled: bool,
    /// Most outstanding, decimal string.
    pub max_outstanding: String,
    /// Held in the vault, decimal string.
    pub vault_holds: String,
    /// Issued here, decimal string.
    pub issued: String,
}

/// A route's mint limits and this epoch's use.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRouteMintView {
    /// Most per mint, decimal string.
    pub per_mint: String,
    /// Most per epoch, decimal string.
    pub per_epoch: String,
    /// The network's most per mint.
    pub network_per_mint: Option<String>,
    /// The network's most per epoch.
    pub network_per_epoch: Option<String>,
    /// The epoch.
    pub epoch: u64,
    /// Minted this epoch.
    pub minted_this_epoch: Option<String>,
    /// Left this epoch.
    pub remaining_this_epoch: Option<String>,
}

/// A rate-limit bucket's level.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLaneBucket {
    /// Tokens available.
    pub tokens: PayAmount,
    /// Capacity.
    pub capacity: PayAmount,
    /// Refill per second.
    pub rate: PayAmount,
    /// Last refill, s.
    pub last_updated: u64,
}

/// A CCIP lane with its buckets.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRouteLaneView {
    /// Lane version.
    pub version: String,
    /// Off-ramp, 0x hex.
    pub off_ramp: String,
    /// Hash of the CCVs and executor, 0x hex.
    pub ccv_and_executor_hash: String,
    /// Outbound bucket.
    pub outbound: Option<PayLaneBucket>,
    /// Inbound bucket.
    pub inbound: Option<PayLaneBucket>,
}

/// A route's locked and bridged supply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySupplyView {
    /// Locked, decimal string.
    pub locked: String,
    /// Bridged, decimal string.
    pub bridged: String,
}

/// A light client's head.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayLightClientHead {
    /// The client kind.
    pub kind: String,
    /// Finalized height or slot.
    pub finalized: u64,
    /// Current period.
    pub period: u64,
    /// Whether the next period's committee is known.
    pub next_known: bool,
}

/// An IBC route's client, connection and channel.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayIbcStatus {
    /// IBC version.
    pub version: String,
    /// The client.
    pub client_id: String,
    /// The packet id.
    pub packet_id: String,
    /// [connection id, state].
    pub connection: Option<Vec<Option<String>>>,
    /// [channel id, state].
    pub channel: Option<Vec<Option<String>>>,
}

/// What a route may carry: `open`, `disabled` or `paused`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayRouteMode {
    Open,
    Disabled,
    Paused,
}

/// Who stopped a route.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayCircuitAuthority {
    Validators,
    Governance,
    Reconciliation,
}

/// A route's circuit breaker trip.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayCircuitTrip {
    /// Protocol.
    pub adapter: PayBridgeAdapter,
    /// The external chain.
    pub source_chain: String,
    /// The mode set.
    pub mode: PayRouteMode,
    /// Who set it.
    pub by: PayCircuitAuthority,
    /// Why.
    pub reason: String,
    /// Hash of the evidence.
    pub evidence_hash: Option<String>,
    /// Epoch.
    pub epoch: u64,
    /// When, ms.
    pub at_ms: i64,
}

/// A governed bridge route with its live state.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeRouteView {
    /// Storage key.
    pub key: String,
    /// The stored route.
    pub record: PayBridgeRoute,
    /// Protocol.
    pub adapter: String,
    /// Chain family.
    pub family: String,
    /// The external chain.
    pub source_chain: String,
    /// Its chain id.
    pub source_chain_id: u64,
    /// Local selector.
    pub local_selector: u64,
    /// Peer, 0x hex.
    pub peer: String,
    /// Ramp, 0x hex.
    pub ramp: String,
    /// Local endpoint, 0x hex.
    pub local_endpoint: String,
    /// The token on the other chain, 0x hex.
    pub remote_token: String,
    /// The verifier quorum.
    pub verifiers: PayQuorumView,
    /// Recent committee sets.
    pub committee_sets: Vec<PayCommitteeSetView>,
    /// The blessing quorum.
    pub blessing: Option<PayQuorumView>,
    /// Carried assets.
    pub assets: Vec<PayRouteAssetView>,
    /// The native asset.
    pub native_asset: Option<String>,
    /// The light client's anchor.
    pub light_client: Option<PayLightClientAnchor>,
    /// The light client's head.
    pub light_client_head: Option<PayLightClientHead>,
    /// Confirmations awaited.
    pub finality_depth: Option<u64>,
    /// Mint limits and use.
    pub mint_limit: PayRouteMintView,
    /// The CCIP lane.
    pub lane: Option<PayRouteLaneView>,
    /// Supply.
    pub supply: PaySupplyView,
    /// IBC status.
    pub ibc: Option<PayIbcStatus>,
    /// `open`, `disabled` or `paused`.
    pub mode: String,
    /// The breaker trip.
    pub circuit: Option<PayCircuitTrip>,
    /// Settings still placeholders.
    pub placeholders: Vec<String>,
    /// Why the route may not open.
    pub open_refusal: Option<String>,
    /// Whether the route passes its checks.
    pub enforced: bool,
    /// The check it fails.
    pub violation: Option<String>,
}

/// Every governed bridge route.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeRoutesOutput {
    /// How many.
    pub total: u64,
    /// The routes.
    pub routes: Vec<PayBridgeRouteView>,
}

/// An input a Bitcoin withdrawal spends.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBtcInput {
    /// Txid, hex.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Value, satoshis.
    pub value: u64,
}

/// An output a Bitcoin withdrawal pays.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBtcOutput {
    /// Value, satoshis.
    pub value: u64,
    /// Script, hex.
    pub script: String,
}

/// A Bitcoin withdrawal and the digest each input is signed over.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBtcWithdrawal {
    /// Txid, hex.
    pub txid: String,
    /// Inputs.
    pub inputs: Vec<PayBtcInput>,
    /// Outputs.
    pub outputs: Vec<PayBtcOutput>,
    /// Each input's sighash, 0x hex.
    pub sighashes: Vec<String>,
    /// The vault's descriptor.
    pub descriptor: String,
    /// Signer keys, hex.
    pub signers: Vec<String>,
    /// Signatures needed.
    pub threshold: u32,
}

/// An IBC packet and its commitment.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayIbcPacketView {
    /// IBC version.
    pub version: String,
    /// Commitment path, 0x hex.
    pub commitment_path: String,
    /// Commitment, 0x hex.
    pub commitment: String,
    /// State key, 0x hex.
    pub state_key: String,
    /// Timeout, ns.
    pub timeout_timestamp: u64,
    /// Its state.
    pub status: String,
}

/// An outbound record of a governed route.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeOutboundRecord {
    /// The route.
    pub route: String,
    /// Sequence.
    pub sequence: u64,
    /// The message, 0x hex.
    pub message: String,
    /// On a Bitcoin deposit route, the withdrawal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal: Option<PayBtcWithdrawal>,
    /// On an IBC route, the packet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet: Option<PayIbcPacketView>,
}

/// A bridge fee quoted in TNZO.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeFeeQuote {
    /// The quote's id, 0x hex.
    pub quote_id_hex: String,
    /// Protocol.
    pub adapter: PayBridgeAdapter,
    /// Destination chain.
    pub dest_chain: String,
    /// The destination's native symbol.
    pub native_symbol: String,
    /// The fee, native smallest unit.
    pub native_fee_smallest_unit: PayAmount,
    /// The fee in TNZO, wei.
    pub tnzo_amount_wei: PayAmount,
    /// Native price, nano-USD.
    pub native_rate_nano_usd: PayAmount,
    /// TNZO price, nano-USD.
    pub tnzo_rate_nano_usd: PayAmount,
    /// The rate epoch.
    pub rate_epoch: Option<u64>,
    /// Issued, ms.
    pub issued_at_ms: u64,
    /// Valid until, ms.
    pub valid_until_ms: u64,
}

/// A rail a payment can settle on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettlementNetwork {
    /// CAIP-2.
    pub caip2: String,
    /// Name.
    pub name: String,
    /// Family.
    pub family: String,
    /// Native asset.
    pub native_asset: String,
    /// Native stablecoins.
    pub native_stablecoins: Vec<String>,
    /// Whether it speaks x402.
    pub x402: bool,
    /// Least fee, micro-USD.
    pub fee_floor_micro_usd: u64,
    /// Smallest worthwhile payment, micro-USD.
    pub min_payment_micro_usd: u64,
}

/// The settlement rails and the micro-settlement floor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySettlementNetworksOutput {
    /// The rails.
    pub networks: Vec<PaySettlementNetwork>,
    /// Least amount settled alone, wei.
    pub micro_settlement_floor_wei: String,
    /// Payment-to-fee ratio a rail must carry.
    pub fee_ratio: u64,
    /// This network, CAIP-2.
    pub primary: String,
}

// ─── Settlement mirrors ───

/// Who paid.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayPayerKind {
    Human,
    Machine,
    Agent,
}

/// What an interaction was.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayInteractionKind {
    Inference,
    Rental,
    Storage,
    Database,
    Hosting,
    Security,
    Marketplace,
    RpcBrokerage,
    Access,
}

/// What authorized an interaction.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayAuthority {
    /// A delegation.
    Delegation {
        /// Its controller.
        controller_did: String,
    },
    /// An x402 payment.
    X402Payment {
        /// The scheme.
        scheme: String,
    },
    /// A credential.
    Credential {
        /// Its digest.
        digest: String,
    },
    Open,
}

/// How an interaction was charged.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayChargeRef {
    /// A settlement.
    Settlement {
        /// Its id.
        settlement_id: String,
    },
    /// A channel voucher.
    Channel {
        /// The channel.
        channel_id: String,
        /// The voucher's nonce.
        nonce: u64,
    },
    /// Accrued, not yet settled.
    Accrued {
        /// Wei accrued.
        accrued_wei: String,
    },
    Free,
}

/// An access tier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayAccessTier {
    User,
    Subscriber,
    Renter,
}

/// A node's economic mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayNodeEconomicMode {
    Private,
    PublicValidating,
    PublicDelegated,
}

/// The rail a payment came in on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PayInboundRail {
    Tenzro,
    /// x402.
    X402 {
        /// The scheme.
        scheme: String,
        /// The chain.
        chain: String,
    },
    /// Bridged in.
    Bridged {
        /// The chain.
        chain: String,
        /// The asset.
        asset: String,
    },
    /// A mandate.
    Mandate {
        /// The protocol.
        protocol: String,
        /// The mandate's hash.
        mandate_hash: String,
    },
}

/// A payee's role in a settlement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayPayeeRole {
    Operator,
    RpcProvider,
    Treasury,
}

/// One payee of a settlement.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPayeeRecord {
    /// Its role.
    pub role: PayPayeeRole,
    /// Its account, 32 bytes.
    pub address: Vec<u8>,
    /// Amount, wei.
    pub amount: PayAmount,
    /// Share, basis points.
    pub bps: u32,
}

/// A settlement recorded on another layer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySecondarySettlement {
    /// The layer.
    pub layer: String,
    /// The chain.
    pub chain: String,
    /// Its reference there.
    pub reference: String,
}

/// The interaction record of a settlement.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayInteractionProvenance {
    /// Its id.
    pub interaction_id: String,
    /// The payer.
    pub payer_did: String,
    /// The payer's kind.
    pub payer_kind: PayPayerKind,
    /// The payer's wallet, 32 bytes.
    pub payer_wallet: Vec<u8>,
    /// Whom the payer acted for.
    pub on_behalf_of: Option<String>,
    /// What it was.
    pub kind: PayInteractionKind,
    /// The resource.
    pub resource_id: String,
    /// Billable units by meter.
    pub units: std::collections::BTreeMap<String, PayAmount>,
    /// When, ms.
    pub occurred_at: i64,
    /// Who attests it.
    pub attester_did: String,
    /// What authorized it.
    pub authority: PayAuthority,
    /// How it was charged.
    pub charge: PayChargeRef,
    /// The access tier.
    pub tier: PayAccessTier,
    /// The credential's digest.
    pub credential_digest: Option<String>,
    /// The node's economic mode.
    pub mode: PayNodeEconomicMode,
    /// The inbound rail.
    pub inbound_rail: PayInboundRail,
    /// Amount charged, wei.
    pub amount_charged: PayAmount,
    /// The asset settled.
    pub settled_asset: String,
    /// The payees.
    pub payees: Vec<PayPayeeRecord>,
    /// The settlement transaction, 32 bytes.
    pub settlement_tx: Option<Vec<u8>>,
    /// Settlements on other layers.
    #[serde(default)]
    pub secondary_settlements: Vec<PaySecondarySettlement>,
}

/// One mirror target's outcome.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayMirrorOutcome {
    /// The chain, CAIP-2.
    pub chain: String,
    /// `self_contained` or `digest_only`.
    pub durability: String,
    /// Where it stands.
    pub state: String,
    /// Its reference there, once confirmed.
    pub reference: Option<String>,
    /// Why it failed.
    pub reason: Option<String>,
}

/// The send-message bridge operation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeSendMessage {
    /// The external chain.
    pub target_chain: String,
    /// The message, hex.
    pub payload: String,
}

/// `{"send_message": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBridgeOpSendMessage {
    /// The send-message operation.
    pub send_message: PayBridgeSendMessage,
}

/// The Bridge transaction body that writes a settlement to one chain.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayMirrorTransaction {
    /// The route's chain.
    pub chain: String,
    /// The Bridge body to sign and send.
    pub tx_type: PayBridgeTx<PayBridgeOpSendMessage>,
}

/// A settlement mirrored onto other chains.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayMirrorSettlementOutput {
    /// The interaction record, with what was mirrored.
    pub interaction: PayInteractionProvenance,
    /// Its id.
    pub interaction_id: String,
    /// The attestation digest, hex.
    pub attestation_digest: String,
    /// Whether Tenzro committed it.
    pub primary_committed: bool,
    /// Whether every target confirmed.
    pub fully_mirrored: bool,
    /// Whether it survives without Tenzro.
    pub durable_beyond_primary: bool,
    /// Each target's outcome.
    pub outcomes: Vec<PayMirrorOutcome>,
    /// Settlements on other layers.
    pub secondary_settlements: Vec<PaySecondarySettlement>,
    /// One Bridge transaction body per pending target.
    pub transactions: Vec<PayMirrorTransaction>,
}

// ─── Delegated agents ───

/// A per-day limit on a remote chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteLimit {
    /// The asset, CAIP-19.
    pub caip19: String,
    /// Most per day, decimal string.
    pub max_per_day: String,
}

/// Limits on one asset.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAssetLimit {
    /// The asset.
    pub asset: String,
    /// Most per transaction.
    #[serde(default)]
    pub max_per_tx: Option<String>,
    /// Most per day.
    pub max_per_day: String,
    /// Least counterparty KYC tier.
    #[serde(default)]
    pub min_counterparty_kyc_tier: u8,
}

/// What an agent may do in governance.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayGovernanceScope {
    /// Domains.
    #[serde(default)]
    pub domains: Vec<String>,
    /// May vote.
    #[serde(default)]
    pub may_vote: bool,
    /// May signal a veto.
    #[serde(default)]
    pub may_veto_signal: bool,
    /// May originate proposals.
    #[serde(default)]
    pub may_originate: bool,
    /// Most voting weight, basis points.
    #[serde(default)]
    pub max_weight_bps: u16,
    /// Policy hash.
    #[serde(default)]
    pub policy_hash: String,
}

/// A counterparty KYC requirement.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayKycRequirement {
    /// Least tier.
    pub min_tier: u8,
    /// The registry.
    pub registry: String,
}

/// A pinned tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayToolPin {
    /// The server.
    pub server: String,
    /// The tool.
    pub name: String,
    /// Its digest.
    pub digest: String,
}

/// What a delegated agent may do.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayTermsScope {
    #[serde(default)]
    pub max_transaction_value: Option<String>,
    #[serde(default)]
    pub max_daily_spend: Option<String>,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
    #[serde(default)]
    pub allowed_payment_protocols: Vec<String>,
    #[serde(default)]
    pub allowed_chains: Vec<String>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_counterparties: Vec<String>,
    #[serde(default)]
    pub max_hourly_spend: Option<String>,
    #[serde(default)]
    pub max_actions_per_hour: Option<u32>,
    #[serde(default)]
    pub max_actions_per_day: Option<u32>,
    /// [start, end) hours, UTC.
    #[serde(default)]
    pub allowed_hours_utc: Option<Vec<u8>>,
    #[serde(default)]
    pub step_up_above: Option<String>,
    #[serde(default)]
    pub step_up_new_counterparty: bool,
    #[serde(default)]
    pub tainted_value_limit: Option<String>,
    #[serde(default)]
    pub remote_grant_ttl_ms: Option<u64>,
    #[serde(default)]
    pub remote_limits: Vec<PayRemoteLimit>,
    #[serde(default)]
    pub cosign_above: Option<String>,
    #[serde(default)]
    pub asset_limits: Vec<PayAssetLimit>,
    #[serde(default)]
    pub governance: Option<PayGovernanceScope>,
    #[serde(default)]
    pub counterparty_kyc: Option<PayKycRequirement>,
    #[serde(default)]
    pub max_split_fee_bps: Option<u16>,
    #[serde(default)]
    pub tool_pins: Vec<PayToolPin>,
}

/// A serving node of a delegated agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayServingNode {
    /// The machine.
    pub machine_did: String,
    /// Its operator.
    pub operator_did: String,
    /// Its signing key, hex.
    #[serde(default)]
    pub dpop_public_key: String,
    /// Its key's thumbprint.
    #[serde(default)]
    pub dpop_jkt: String,
    /// Its key's certification.
    #[serde(default)]
    pub key_certification: String,
    /// Its sealing key, hex.
    #[serde(default)]
    pub sealing_public_key: String,
}

/// A credential sealed for one serving node.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySealedForNode {
    /// The machine.
    pub machine_did: String,
    /// The sealed envelope.
    pub envelope: String,
}

/// A credential the agent's serving nodes broker.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayBrokeredCredential {
    /// Its name.
    pub name: String,
    /// The host it is for.
    pub host: String,
    /// The header it goes in.
    pub header: String,
    /// Sealed per node.
    pub sealed: Vec<PaySealedForNode>,
}

fn pay_one() -> u32 {
    1
}

/// A delegated agent's terms.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentTerms {
    /// The controller.
    pub controller_did: String,
    /// The agent's name.
    pub agent_name: String,
    /// What it may do.
    #[serde(default)]
    pub delegation_scope: PayTermsScope,
    /// Capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Serving nodes.
    #[serde(default)]
    pub serving_nodes: Vec<PayServingNode>,
    /// Least distinct operators among the serving nodes.
    #[serde(default = "pay_one")]
    pub min_distinct_operators: u32,
    /// Expiry, ms.
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// Whether the trifecta exception applies.
    #[serde(default)]
    pub trifecta_exception: bool,
    /// What it may do without step-up.
    #[serde(default)]
    pub auto_approve: Option<PayTermsScope>,
    /// Brokered credentials.
    #[serde(default)]
    pub credentials: Vec<PayBrokeredCredential>,
}

/// A WebAuthn assertion.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayWebAuthnAssertion {
    /// Authenticator data, bytes.
    pub authenticator_data: Vec<u8>,
    /// Client data JSON, bytes.
    pub client_data_json: Vec<u8>,
    /// Signature, bytes.
    pub signature: Vec<u8>,
    /// User handle, bytes.
    #[serde(default)]
    pub user_handle: Option<Vec<u8>>,
}

/// A keystore's anchor passkey, sent before the account's first change.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayKeystoreAnchor {
    /// The relying party.
    pub rp_id: String,
    /// Credential id, hex.
    pub credential_id: String,
    /// Public key, hex.
    pub public_key: String,
    /// AAGUID, hex.
    pub aaguid: String,
    /// Backup eligible.
    pub backup_eligible: bool,
    /// Backed up.
    pub backup_state: bool,
    /// Salt.
    pub salt: u64,
}

/// A root's approval of a custody challenge.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PayRootApproval {
    /// A human root's passkey assertion.
    Passkey {
        /// The challenge.
        challenge_id: String,
        /// The passkey's credential id, hex.
        credential_id_hex: String,
        /// The assertion.
        assertion: PayWebAuthnAssertion,
        /// ML-DSA-65 signature, hex.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ml_dsa_signature_hex: Option<String>,
        /// The keystore's anchor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        anchor: Option<PayKeystoreAnchor>,
    },
    /// A machine root's hardware signature over challenge_hex.
    Machine {
        /// The challenge.
        challenge_id: String,
        /// The signature.
        signature: PayCompositeSignature,
    },
}

/// A serving node as the network shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPublicServingNode {
    /// The machine.
    pub machine_did: String,
    /// Its operator.
    pub operator_did: String,
    /// Its key's thumbprint.
    pub dpop_jkt: String,
}

/// Whether an access token reached a serving node.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayTokenDelivery {
    /// The machine.
    pub machine_did: String,
    /// Whether it was delivered.
    pub delivered: bool,
    /// Why not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A delegated agent's identity.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentIdentity {
    /// The agent.
    pub did: String,
    /// `machine`.
    pub identity_type: String,
    /// The controller.
    pub controller_did: String,
    /// Capabilities.
    pub capabilities: Vec<String>,
    /// Status.
    pub status: String,
}

/// A delegated agent's watch-only wallet.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentWallet {
    /// Wallet id.
    pub wallet_id: String,
    /// Address, 0x hex.
    pub address: String,
}

/// A delegated agent created.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayDelegateAgentOutput {
    /// Its identity.
    pub identity: PayAgentIdentity,
    /// Its wallet.
    pub wallet: PayAgentWallet,
    /// Its serving nodes.
    pub serving_nodes: Vec<PayPublicServingNode>,
    /// Least distinct operators.
    pub min_distinct_operators: u32,
    /// Expiry, ms.
    pub expires_at_ms: Option<u64>,
    /// The Terms transaction.
    pub terms_tx: String,
    /// Token delivery to each serving node.
    pub token_delivery: Vec<PayTokenDelivery>,
}

/// A delegated agent's terms replaced.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayUpdateAgentTermsOutput {
    /// The agent.
    pub agent_did: String,
    /// The new terms.
    pub delegation: PayAgentTerms,
    /// The Terms transaction.
    pub terms_tx: String,
    /// Token delivery to each serving node.
    pub token_delivery: Vec<PayTokenDelivery>,
    /// Live tokens withdrawn, when rotate_tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_revoked: Option<u64>,
}

/// The revocation and its root's approval.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayIdentityRevocationOp {
    /// The agent revoked.
    pub did: String,
    /// The reason.
    pub reason: String,
    /// The root approving.
    pub approver_did: String,
    /// The root's approval.
    pub approval: PayAgentTermsApproval,
}

/// A `RevokeIdentity` transaction body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRevokeIdentityTx {
    /// The revocation.
    #[serde(rename = "RevokeIdentity")]
    pub revoke_identity: PayOpBody<PayIdentityRevocationOp>,
}

/// A signed RevokeIdentity transaction.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PaySignedRevokeIdentity {
    /// The sending account, hex.
    pub from: String,
    /// The receiving account, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// Chain id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Gas limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    /// Gas price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<u64>,
    /// Unix ms the signer named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    /// Last block time, Unix ms, it may execute at.
    pub valid_until: u64,
    /// The revocation.
    pub tx_type: PayRevokeIdentityTx,
    /// The sender's P-256 key, x || y, hex.
    pub public_key: String,
    /// The sender's signature.
    pub signature: PayCompositeSignature,
}

/// A revocation admitted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRevokeAgentOutput {
    /// The agent revoked.
    pub did: String,
    /// `admitted`.
    pub status: String,
    /// The root that approved.
    pub approver_did: String,
    /// The transaction.
    pub tx_hash: String,
}

/// What a delegated agent's root is: `passkey` or `machine`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayRootKind {
    Passkey,
    Machine,
}

/// An agent's spend in one asset today.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentAssetSpend {
    /// The asset.
    pub asset: String,
    /// Spent today, base units.
    pub spent_today: String,
    /// Left today, base units.
    pub remaining_today: Option<String>,
}

/// An agent's spend so far.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentSpend {
    /// Spent today, wei.
    pub today: String,
    /// Spent this hour, wei.
    pub this_hour: String,
    /// Actions today.
    pub actions_today: u64,
    /// Actions this hour.
    pub actions_this_hour: u64,
    /// Left today, wei.
    pub remaining_today: Option<String>,
    /// Left this hour, wei.
    pub remaining_this_hour: Option<String>,
    /// Per asset.
    pub assets: Vec<PayAgentAssetSpend>,
}

/// A delegated agent's consensus terms and spend.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentTermsView {
    /// The agent.
    pub agent_did: String,
    /// Its root.
    pub root_kind: PayRootKind,
    /// `active`, `quarantined`, `revoked` or `expired`.
    pub status: String,
    /// Terms version.
    pub version: u64,
    /// Digest of the root's approval.
    pub approval_digest: String,
    /// Last change, ms.
    pub updated_at_ms: i64,
    /// The terms.
    pub terms: PayAgentTerms,
    /// Spend so far.
    pub spent: PayAgentSpend,
}

/// An agent's live grant on another chain.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteGrantView {
    /// Grant sequence.
    pub seq: u64,
    /// Whether it is void.
    pub void: bool,
    /// Valid from, ms.
    pub not_before_ms: u64,
    /// Valid until, ms.
    pub not_after_ms: u64,
    /// Budget, decimal string.
    pub budget: String,
    /// Most per action, decimal string.
    pub per_action_max: String,
    /// Cosign above, decimal string.
    pub cosign_above: String,
    /// Most relay fee, decimal string.
    pub relay_fee_max: String,
    /// Whether it is an exact grant.
    pub exact: bool,
    /// The terms version it was issued under.
    pub terms_version: u64,
    /// Root of the serving keys, hex.
    pub keys_root: String,
    /// Root of the targets, hex.
    pub targets_root: String,
}

/// An agent's account on one chain.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentAccount {
    /// The chain, CAIP-2.
    pub chain: String,
    /// `open` or `closed`.
    pub status: String,
    /// What the chain supports.
    pub supports: String,
    /// Whether its reports are proven.
    pub reports_proven: bool,
    /// The address.
    pub address: Option<String>,
    /// CAIP-10.
    pub caip10: Option<String>,
    /// ERC-7930, hex.
    pub erc7930: Option<String>,
    /// Why the address could not be derived.
    pub error: Option<String>,
    /// The live grant.
    pub grant: Option<PayRemoteGrantView>,
}

/// An agent's accounts on other chains.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentAccountsOutput {
    /// The agent.
    pub did: String,
    /// One per configured chain.
    pub accounts: Vec<PayAgentAccount>,
}

/// The end of a state trie proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PayProofTerminal {
    Empty,
    /// Another stem sits where the key would.
    OtherStem {
        /// The stem, bytes.
        stem: Vec<u8>,
        /// Its slots' root, 32 bytes.
        slots_root: Vec<u8>,
    },
    /// The key's stem.
    Stem {
        /// Slot siblings, 32 bytes each.
        slot_siblings: Vec<Vec<u8>>,
    },
}

/// A state trie proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayStateTrieProof {
    /// Siblings, 32 bytes each.
    pub siblings: Vec<Vec<u8>>,
    /// Its end.
    pub terminal: PayProofTerminal,
}

/// An agent's grant and its state proof under a certified checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentGrantProofOutput {
    /// The agent.
    pub did: String,
    /// The chain, CAIP-2.
    pub chain: String,
    /// The checkpoint.
    pub checkpoint: u64,
    /// The state height.
    pub height: u64,
    /// The state root.
    pub state_root: String,
    /// The tree key, hex.
    pub tree_key: String,
    /// The grant bytes, hex.
    pub grant_bytes: Option<String>,
    /// The grant.
    pub grant: Option<PayRemoteGrantView>,
    /// The proof.
    pub proof: PayStateTrieProof,
    /// The proof encoded, hex.
    pub proof_bytes: String,
    /// How a void reaches the chain.
    pub revocation: String,
}

/// One action of an agent's account on another chain.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteAction {
    /// The contract or program, hex.
    pub target: String,
    /// The function selector, hex.
    pub selector: String,
    /// Value sent, base units, decimal string.
    pub amount: String,
    /// Relay refund, base units, decimal string.
    pub relay_refund: String,
    /// Calldata, hex.
    pub data: String,
}

/// The consent that makes an agent's account an ERC-8004 entry's agentWallet.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentWalletConsentOutput {
    /// The agent.
    pub did: String,
    /// The chain, CAIP-2.
    pub chain: String,
    /// The agent's account there.
    pub account: String,
    /// The identity registry, 0x hex.
    pub registry: String,
    /// The ERC-8004 agentId.
    pub agent_id: u64,
    /// The entry's owner, 0x hex.
    pub owner: String,
    /// Consent deadline, Unix s.
    pub deadline: u64,
    /// The AgentWalletSet digest, hex.
    pub digest: String,
    /// The approveHash action to sign with agent_remote_act.
    pub action: PayRemoteAction,
    /// The setAgentWallet calldata, 0x hex.
    pub set_agent_wallet_calldata: String,
}

/// A serving node's signature over a remote action.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteActionSignature {
    /// The agent.
    pub agent_did: String,
    /// The chain, CAIP-2.
    pub chain: String,
    /// Grant sequence.
    pub seq: u64,
    /// Action nonce.
    pub nonce: u64,
    /// The digest signed, hex.
    pub digest: String,
    /// The signature, hex.
    pub signature: String,
    /// The node's key, uncompressed hex.
    pub public_key: String,
    /// Its operator.
    pub operator_did: String,
    /// The node.
    pub machine_did: String,
    /// Whether another operator's node must cosign.
    pub needs_cosign: bool,
}

/// A serving key and its Merkle proof under the grant's keys root.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayServingKeyProof {
    /// The node.
    pub machine_did: String,
    /// Its operator.
    pub operator_did: String,
    /// Its key, uncompressed hex.
    pub public_key: String,
    /// Its proof, hex each.
    pub proof: Vec<String>,
}

/// What the agent's account checks for one action.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayRemoteActionProofs {
    /// The agent.
    pub did: String,
    /// The chain, CAIP-2.
    pub chain: String,
    /// The account.
    pub account: String,
    /// Grant sequence.
    pub seq: u64,
    /// Action nonce.
    pub nonce: u64,
    /// The action encoded, hex.
    pub action: String,
    /// The digest, hex.
    pub digest: String,
    /// The payload hash, hex.
    pub payload_hash: String,
    /// Whether another operator's node must cosign.
    pub needs_cosign: bool,
    /// Serving keys with proofs.
    pub keys: Vec<PayServingKeyProof>,
    /// The target's proof under the grant's targets root, hex each.
    pub target_proof: Option<Vec<String>>,
}

/// A signed remote action and its proofs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAgentRemoteActOutput {
    /// The serving node's signature.
    pub signature: PayRemoteActionSignature,
    /// The proofs the account checks.
    pub proofs: PayRemoteActionProofs,
}

/// A payer's signed authorization of a payment.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPaymentAuthorization {
    /// The payer's hardware key, hex.
    pub public_key: String,
    /// The payer's signature.
    pub signature: PayCompositeSignature,
    /// The most it pays, base units.
    pub max_amount: PayAmount,
    /// The asset.
    pub asset: String,
    /// What it pays for.
    pub binding: PayPaymentBinding,
}

/// The payer's signed authorization a settlement carries.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayPayerPayment {
    /// The payer, hex.
    pub payer: String,
    /// The payment id, 1 to 128 bytes.
    pub payment_id: String,
    /// The authorization, naming this payee and a ceiling of at least the amount.
    pub authorization: PayPaymentAuthorization,
}

/// An unsigned transaction of any kind, as tenzro_sendRawTransaction takes it
/// without signatures.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayAnyUnsignedTx {
    /// The caller's request fields.
    #[serde(flatten)]
    pub request: PayUnsignedTxRequest,
    /// Gas limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    /// The transaction body: any transaction kind, in its JSON form
    /// (`"Transfer"`-style unit kinds as a string, others as `{"Kind": {...}}`).
    /// A plain transfer when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<super::server::JsonValue>,
}
