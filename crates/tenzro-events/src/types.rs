//! Core event types for the Tenzro event streaming system
//!
//! Provides a unified event model across all VMs and subsystems with
//! monotonic sequencing, cursor-based replay, and rich filtering.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Serde helper to serialize/deserialize u128 as a decimal string.
/// Required because serde_json does not support u128 natively.
mod u128_str {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

/// VM execution environment that produced an event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmType {
    /// Native Tenzro chain events (staking, identity, governance)
    Native,
    /// Ethereum Virtual Machine
    Evm,
    /// Solana Virtual Machine
    Svm,
    /// Canton/DAML runtime
    Daml,
}

impl fmt::Display for VmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmType::Native => write!(f, "native"),
            VmType::Evm => write!(f, "evm"),
            VmType::Svm => write!(f, "svm"),
            VmType::Daml => write!(f, "daml"),
        }
    }
}

/// Discriminant enum that mirrors [`TenzroEvent`] variant names for filtering
/// without carrying payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    NewBlock,
    BlockFinalized,
    BlockReorged,
    NewPendingTransaction,
    TransactionIncluded,
    TransactionFinalized,
    Log,
    Transfer,
    NftTransfer,
    CrosschainMint,
    CrosschainBurn,
    IdentityRegistered,
    CredentialIssued,
    ComplianceViolation,
    ModelRegistered,
    InferenceCompleted,
    InferenceStreamStarted,
    InferenceStreamFirstToken,
    InferenceStreamDropped,
    InferenceStreamCompleted,
    AgentMessage,
    SettlementCompleted,
    PaymentChannelUpdate,
    StakeDeposited,
    StakeWithdrawn,
    ValidatorSlashed,
    ProposalCreated,
    VoteCast,
    BridgeTransferInitiated,
    BridgeTransferCompleted,
    SyncProgress,
    WorkflowCreated,
    WorkflowLifecycleTransitioned,
    WorkflowReceiptEmitted,
    ApprovalRequested,
    ApprovalFinalized,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", event_type_static_name(*self))
    }
}

/// Returns the human-readable variant name for an [`EventType`].
pub fn event_type_static_name(et: EventType) -> &'static str {
    match et {
        EventType::NewBlock => "NewBlock",
        EventType::BlockFinalized => "BlockFinalized",
        EventType::BlockReorged => "BlockReorged",
        EventType::NewPendingTransaction => "NewPendingTransaction",
        EventType::TransactionIncluded => "TransactionIncluded",
        EventType::TransactionFinalized => "TransactionFinalized",
        EventType::Log => "Log",
        EventType::Transfer => "Transfer",
        EventType::NftTransfer => "NftTransfer",
        EventType::CrosschainMint => "CrosschainMint",
        EventType::CrosschainBurn => "CrosschainBurn",
        EventType::IdentityRegistered => "IdentityRegistered",
        EventType::CredentialIssued => "CredentialIssued",
        EventType::ComplianceViolation => "ComplianceViolation",
        EventType::ModelRegistered => "ModelRegistered",
        EventType::InferenceCompleted => "InferenceCompleted",
        EventType::InferenceStreamStarted => "InferenceStreamStarted",
        EventType::InferenceStreamFirstToken => "InferenceStreamFirstToken",
        EventType::InferenceStreamDropped => "InferenceStreamDropped",
        EventType::InferenceStreamCompleted => "InferenceStreamCompleted",
        EventType::AgentMessage => "AgentMessage",
        EventType::SettlementCompleted => "SettlementCompleted",
        EventType::PaymentChannelUpdate => "PaymentChannelUpdate",
        EventType::StakeDeposited => "StakeDeposited",
        EventType::StakeWithdrawn => "StakeWithdrawn",
        EventType::ValidatorSlashed => "ValidatorSlashed",
        EventType::ProposalCreated => "ProposalCreated",
        EventType::VoteCast => "VoteCast",
        EventType::BridgeTransferInitiated => "BridgeTransferInitiated",
        EventType::BridgeTransferCompleted => "BridgeTransferCompleted",
        EventType::SyncProgress => "SyncProgress",
        EventType::WorkflowCreated => "WorkflowCreated",
        EventType::WorkflowLifecycleTransitioned => "WorkflowLifecycleTransitioned",
        EventType::WorkflowReceiptEmitted => "WorkflowReceiptEmitted",
        EventType::ApprovalRequested => "ApprovalRequested",
        EventType::ApprovalFinalized => "ApprovalFinalized",
    }
}

/// Returns the human-readable variant name for a [`TenzroEvent`].
pub fn event_type_name(event: &TenzroEvent) -> &'static str {
    event_type_static_name(event.event_type())
}

// ---------------------------------------------------------------------------
// TenzroEvent
// ---------------------------------------------------------------------------

/// Unified event enum covering all Tenzro subsystems.
///
/// Every variant uses concrete, self-contained types so events can be
/// serialized, persisted, and replayed without resolving external references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TenzroEvent {
    // -- Block lifecycle -----------------------------------------------------

    /// A new block has been produced but not yet finalized.
    NewBlock {
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        height: u64,
        tx_count: u32,
        proposer: [u8; 20],
    },

    /// A block has reached finality.
    BlockFinalized {
        block_hash: [u8; 32],
        height: u64,
    },

    /// A previously-included block was removed during a chain reorganization.
    BlockReorged {
        block_hash: [u8; 32],
        height: u64,
        /// New canonical block hash that replaced the reorged block.
        new_block_hash: [u8; 32],
    },

    // -- Transaction lifecycle -----------------------------------------------

    /// A transaction entered the mempool.
    NewPendingTransaction {
        tx_hash: [u8; 32],
        from: [u8; 20],
        to: Option<[u8; 20]>,
        #[serde(with = "u128_str")]
        value: u128,
        nonce: u64,
    },

    /// A transaction was included in a block.
    TransactionIncluded {
        tx_hash: [u8; 32],
        block_hash: [u8; 32],
        block_height: u64,
        index: u32,
        gas_used: u64,
        success: bool,
    },

    /// A transaction's block reached finality.
    TransactionFinalized {
        tx_hash: [u8; 32],
        block_hash: [u8; 32],
        block_height: u64,
    },

    // -- EVM Logs (EIP-7708 compliant) ---------------------------------------

    /// An EVM log entry emitted by a smart contract.
    Log {
        address: [u8; 20],
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
        block_height: u64,
        tx_hash: [u8; 32],
        log_index: u32,
        /// `true` when this log was removed during a reorg.
        removed: bool,
    },

    // -- Token events --------------------------------------------------------

    /// A fungible token transfer (native TNZO or ERC-20 / SPL / CIP-56).
    Transfer {
        from: [u8; 20],
        to: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        token_id: String,
        tx_hash: [u8; 32],
    },

    /// An NFT (non-fungible) token transfer.
    NftTransfer {
        from: [u8; 20],
        to: [u8; 20],
        token_id: String,
        #[serde(with = "u128_str")]
        nft_id: u128,
        tx_hash: [u8; 32],
    },

    /// Tokens minted on Tenzro as the destination side of a cross-chain bridge.
    CrosschainMint {
        to: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        source_chain: String,
        source_tx_hash: [u8; 32],
        token_id: String,
    },

    /// Tokens burned on Tenzro as the source side of a cross-chain bridge.
    CrosschainBurn {
        from: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        destination_chain: String,
        token_id: String,
        tx_hash: [u8; 32],
    },

    // -- Identity ------------------------------------------------------------

    /// A new identity (human or machine) was registered via TDIP.
    IdentityRegistered {
        did: String,
        identity_type: String,
        controller: Option<String>,
    },

    /// A verifiable credential was issued to an identity.
    CredentialIssued {
        issuer_did: String,
        subject_did: String,
        credential_type: String,
        credential_id: String,
    },

    /// A compliance violation was detected (e.g., delegation scope breach).
    ComplianceViolation {
        did: String,
        violation_type: String,
        details: String,
    },

    // -- AI ------------------------------------------------------------------

    /// A new AI model was registered in the model registry.
    ModelRegistered {
        model_id: String,
        name: String,
        provider: [u8; 20],
        /// Modality of the registered model — lets subscribers filter per modality
        /// (e.g. only react to Audio model registrations) without re-querying the
        /// registry. Default-deserialized to Text for backward compatibility with
        /// rows persisted before this field existed.
        #[serde(default)]
        modality: tenzro_types::model::ModelModality,
    },

    /// An inference request completed.
    InferenceCompleted {
        request_id: String,
        model_id: String,
        provider: [u8; 20],
        latency_ms: u64,
        tokens_used: u64,
        #[serde(with = "u128_str")]
        cost: u128,
    },

    /// A streaming inference request opened an SSE stream.
    ///
    /// `provider_label` mirrors the SLO-metrics label space so audit logs
    /// and Prometheus rows join on the same key — `"local"` for
    /// self-served streams, hex-encoded provider address for network-proxy
    /// streams. Native Tenzro addresses (32 bytes) don't fit the EVM-style
    /// `[u8; 20]` address-filter pathway used by `Log` / `Transfer`, so
    /// string labels are the right shape here.
    InferenceStreamStarted {
        request_id: String,
        model_id: String,
        provider_label: String,
    },

    /// First token emitted on an SSE stream — fires at most once per stream.
    /// `ttft_ms` is time-to-first-token measured from `InferenceStreamStarted`.
    InferenceStreamFirstToken {
        request_id: String,
        model_id: String,
        provider_label: String,
        ttft_ms: u64,
    },

    /// SSE stream dropped before the upstream signalled completion.
    /// `reason` is one of `"stall"`, `"upstream_error"`, `"transport_error"`.
    /// `silent_for_ms` is populated when `reason == "stall"` (heartbeat
    /// watchdog tripped) and reflects the silent window in milliseconds.
    InferenceStreamDropped {
        request_id: String,
        model_id: String,
        provider_label: String,
        reason: String,
        silent_for_ms: Option<u64>,
    },

    /// SSE stream completed cleanly. `latency_ms` is wall-clock from
    /// `InferenceStreamStarted` to terminate. `success` distinguishes a
    /// stream that produced at least one token from one that closed empty.
    InferenceStreamCompleted {
        request_id: String,
        model_id: String,
        provider_label: String,
        latency_ms: u64,
        success: bool,
    },

    /// An agent-to-agent message was delivered.
    AgentMessage {
        from_agent: String,
        to_agent: String,
        message_type: String,
        message_id: String,
    },

    // -- Settlement ----------------------------------------------------------

    /// A settlement was completed on-chain.
    SettlementCompleted {
        settlement_id: String,
        payer: [u8; 20],
        payee: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        tx_hash: [u8; 32],
    },

    /// A micropayment channel state changed (opened, updated, closed, disputed).
    PaymentChannelUpdate {
        channel_id: String,
        sender: [u8; 20],
        receiver: [u8; 20],
        #[serde(with = "u128_str")]
        balance: u128,
        status: String,
    },

    // -- Staking -------------------------------------------------------------

    /// TNZO tokens were staked by a validator or provider.
    StakeDeposited {
        staker: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        role: String,
        tx_hash: [u8; 32],
    },

    /// TNZO tokens were unstaked (unbonding initiated).
    StakeWithdrawn {
        staker: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        tx_hash: [u8; 32],
    },

    /// A validator was slashed for equivocation or misbehaviour.
    ValidatorSlashed {
        validator: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        reason: String,
        evidence_hash: [u8; 32],
    },

    // -- Governance ----------------------------------------------------------

    /// A governance proposal was created.
    ProposalCreated {
        proposal_id: String,
        proposer: [u8; 20],
        title: String,
    },

    /// A vote was cast on a governance proposal.
    VoteCast {
        proposal_id: String,
        voter: [u8; 20],
        /// true = for, false = against
        support: bool,
        #[serde(with = "u128_str")]
        weight: u128,
    },

    // -- Bridge --------------------------------------------------------------

    /// A cross-chain bridge transfer was initiated from Tenzro.
    BridgeTransferInitiated {
        bridge_adapter: String,
        source_tx_hash: [u8; 32],
        destination_chain: String,
        sender: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        token_id: String,
    },

    /// A cross-chain bridge transfer was completed on Tenzro.
    BridgeTransferCompleted {
        bridge_adapter: String,
        source_chain: String,
        source_tx_hash: [u8; 32],
        receiver: [u8; 20],
        #[serde(with = "u128_str")]
        amount: u128,
        token_id: String,
    },

    // -- Sync ----------------------------------------------------------------

    /// Periodic progress report during node synchronization.
    SyncProgress {
        current_block: u64,
        highest_block: u64,
        /// Progress percentage 0..100
        percent: u8,
    },

    // -- Workflow ------------------------------------------------------------
    //
    // Workflow events carry an optional `privacy_domain` reference. When set,
    // subscribers are expected to authorize delivery via
    // `tenzro_workflow::acl_check` before forwarding the event off-node:
    // `Allow` → deliver, `Deny` → drop silently (no existence leak), `Plaintext`
    // → deliver as-is. The event itself never carries the encrypted body —
    // that lives in the corresponding `EncryptedReceipt` in `CF_SETTLEMENTS`.

    /// A new workflow was created (Draft).
    WorkflowCreated {
        workflow_id: [u8; 32],
        creator_did: String,
        title: String,
        /// Optional privacy domain — when present, this event is ACL-gated.
        privacy_domain: Option<[u8; 32]>,
    },

    /// A workflow underwent a lifecycle transition.
    WorkflowLifecycleTransitioned {
        workflow_id: [u8; 32],
        from_status: String,
        to_status: String,
        trigger: String,
        privacy_domain: Option<[u8; 32]>,
    },

    /// A workflow receipt was emitted (every receipt-bearing event projects
    /// here for indexing). `payload_commitment` is the SHA-256 of the receipt
    /// payload — set when the receipt is privacy-domain-encrypted; for inline
    /// receipts it equals the canonical commitment from `WorkflowReceipt`.
    WorkflowReceiptEmitted {
        workflow_id: [u8; 32],
        receipt_id: [u8; 32],
        event_kind: String,
        privacy_domain: Option<[u8; 32]>,
        payload_commitment: Option<[u8; 32]>,
    },

    /// An approval request was opened against an approval gate.
    ApprovalRequested {
        workflow_id: [u8; 32],
        gate_id: [u8; 32],
        request_id: [u8; 32],
        privacy_domain: Option<[u8; 32]>,
    },

    /// An approval request was finalized (approved / rejected / timed out).
    ApprovalFinalized {
        workflow_id: [u8; 32],
        gate_id: [u8; 32],
        request_id: [u8; 32],
        outcome: String,
        privacy_domain: Option<[u8; 32]>,
    },
}

impl TenzroEvent {
    /// Returns the discriminant [`EventType`] for this event.
    pub fn event_type(&self) -> EventType {
        match self {
            TenzroEvent::NewBlock { .. } => EventType::NewBlock,
            TenzroEvent::BlockFinalized { .. } => EventType::BlockFinalized,
            TenzroEvent::BlockReorged { .. } => EventType::BlockReorged,
            TenzroEvent::NewPendingTransaction { .. } => EventType::NewPendingTransaction,
            TenzroEvent::TransactionIncluded { .. } => EventType::TransactionIncluded,
            TenzroEvent::TransactionFinalized { .. } => EventType::TransactionFinalized,
            TenzroEvent::Log { .. } => EventType::Log,
            TenzroEvent::Transfer { .. } => EventType::Transfer,
            TenzroEvent::NftTransfer { .. } => EventType::NftTransfer,
            TenzroEvent::CrosschainMint { .. } => EventType::CrosschainMint,
            TenzroEvent::CrosschainBurn { .. } => EventType::CrosschainBurn,
            TenzroEvent::IdentityRegistered { .. } => EventType::IdentityRegistered,
            TenzroEvent::CredentialIssued { .. } => EventType::CredentialIssued,
            TenzroEvent::ComplianceViolation { .. } => EventType::ComplianceViolation,
            TenzroEvent::ModelRegistered { .. } => EventType::ModelRegistered,
            TenzroEvent::InferenceCompleted { .. } => EventType::InferenceCompleted,
            TenzroEvent::InferenceStreamStarted { .. } => EventType::InferenceStreamStarted,
            TenzroEvent::InferenceStreamFirstToken { .. } => EventType::InferenceStreamFirstToken,
            TenzroEvent::InferenceStreamDropped { .. } => EventType::InferenceStreamDropped,
            TenzroEvent::InferenceStreamCompleted { .. } => EventType::InferenceStreamCompleted,
            TenzroEvent::AgentMessage { .. } => EventType::AgentMessage,
            TenzroEvent::SettlementCompleted { .. } => EventType::SettlementCompleted,
            TenzroEvent::PaymentChannelUpdate { .. } => EventType::PaymentChannelUpdate,
            TenzroEvent::StakeDeposited { .. } => EventType::StakeDeposited,
            TenzroEvent::StakeWithdrawn { .. } => EventType::StakeWithdrawn,
            TenzroEvent::ValidatorSlashed { .. } => EventType::ValidatorSlashed,
            TenzroEvent::ProposalCreated { .. } => EventType::ProposalCreated,
            TenzroEvent::VoteCast { .. } => EventType::VoteCast,
            TenzroEvent::BridgeTransferInitiated { .. } => EventType::BridgeTransferInitiated,
            TenzroEvent::BridgeTransferCompleted { .. } => EventType::BridgeTransferCompleted,
            TenzroEvent::SyncProgress { .. } => EventType::SyncProgress,
            TenzroEvent::WorkflowCreated { .. } => EventType::WorkflowCreated,
            TenzroEvent::WorkflowLifecycleTransitioned { .. } => EventType::WorkflowLifecycleTransitioned,
            TenzroEvent::WorkflowReceiptEmitted { .. } => EventType::WorkflowReceiptEmitted,
            TenzroEvent::ApprovalRequested { .. } => EventType::ApprovalRequested,
            TenzroEvent::ApprovalFinalized { .. } => EventType::ApprovalFinalized,
        }
    }

    /// Returns the privacy domain id this event is bound to, if any.
    /// Subscribers should pass this to `tenzro_workflow::acl_check` to decide
    /// whether to deliver the event.
    pub fn privacy_domain(&self) -> Option<[u8; 32]> {
        match self {
            TenzroEvent::WorkflowCreated { privacy_domain, .. }
            | TenzroEvent::WorkflowLifecycleTransitioned { privacy_domain, .. }
            | TenzroEvent::WorkflowReceiptEmitted { privacy_domain, .. }
            | TenzroEvent::ApprovalRequested { privacy_domain, .. }
            | TenzroEvent::ApprovalFinalized { privacy_domain, .. } => *privacy_domain,
            _ => None,
        }
    }
}

impl fmt::Display for TenzroEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenzroEvent::NewBlock { height, tx_count, .. } => {
                write!(f, "NewBlock height={} txs={}", height, tx_count)
            }
            TenzroEvent::BlockFinalized { height, .. } => {
                write!(f, "BlockFinalized height={}", height)
            }
            TenzroEvent::BlockReorged { height, .. } => {
                write!(f, "BlockReorged height={}", height)
            }
            TenzroEvent::NewPendingTransaction { nonce, value, .. } => {
                write!(f, "NewPendingTx nonce={} value={}", nonce, value)
            }
            TenzroEvent::TransactionIncluded { block_height, index, success, .. } => {
                write!(
                    f,
                    "TxIncluded block={} idx={} ok={}",
                    block_height, index, success
                )
            }
            TenzroEvent::TransactionFinalized { block_height, .. } => {
                write!(f, "TxFinalized block={}", block_height)
            }
            TenzroEvent::Log { address, log_index, removed, .. } => {
                write!(
                    f,
                    "Log addr=0x{} idx={} removed={}",
                    hex::encode(address),
                    log_index,
                    removed
                )
            }
            TenzroEvent::Transfer { amount, token_id, .. } => {
                write!(f, "Transfer amount={} token={}", amount, token_id)
            }
            TenzroEvent::NftTransfer { token_id, nft_id, .. } => {
                write!(f, "NftTransfer token={} nft={}", token_id, nft_id)
            }
            TenzroEvent::CrosschainMint { amount, source_chain, .. } => {
                write!(f, "CrosschainMint amount={} from={}", amount, source_chain)
            }
            TenzroEvent::CrosschainBurn { amount, destination_chain, .. } => {
                write!(f, "CrosschainBurn amount={} to={}", amount, destination_chain)
            }
            TenzroEvent::IdentityRegistered { did, identity_type, .. } => {
                write!(f, "IdentityRegistered did={} type={}", did, identity_type)
            }
            TenzroEvent::CredentialIssued { credential_type, subject_did, .. } => {
                write!(f, "CredentialIssued type={} subject={}", credential_type, subject_did)
            }
            TenzroEvent::ComplianceViolation { did, violation_type, .. } => {
                write!(f, "ComplianceViolation did={} type={}", did, violation_type)
            }
            TenzroEvent::ModelRegistered { model_id, name, .. } => {
                write!(f, "ModelRegistered id={} name={}", model_id, name)
            }
            TenzroEvent::InferenceCompleted { model_id, latency_ms, tokens_used, .. } => {
                write!(
                    f,
                    "InferenceCompleted model={} latency={}ms tokens={}",
                    model_id, latency_ms, tokens_used
                )
            }
            TenzroEvent::InferenceStreamStarted { request_id, model_id, provider_label } => {
                write!(
                    f,
                    "InferenceStreamStarted req={} model={} provider={}",
                    request_id, model_id, provider_label
                )
            }
            TenzroEvent::InferenceStreamFirstToken { request_id, model_id, ttft_ms, .. } => {
                write!(
                    f,
                    "InferenceStreamFirstToken req={} model={} ttft={}ms",
                    request_id, model_id, ttft_ms
                )
            }
            TenzroEvent::InferenceStreamDropped { request_id, model_id, reason, silent_for_ms, .. } => {
                match silent_for_ms {
                    Some(ms) => write!(
                        f,
                        "InferenceStreamDropped req={} model={} reason={} silent={}ms",
                        request_id, model_id, reason, ms
                    ),
                    None => write!(
                        f,
                        "InferenceStreamDropped req={} model={} reason={}",
                        request_id, model_id, reason
                    ),
                }
            }
            TenzroEvent::InferenceStreamCompleted { request_id, model_id, latency_ms, success, .. } => {
                write!(
                    f,
                    "InferenceStreamCompleted req={} model={} latency={}ms success={}",
                    request_id, model_id, latency_ms, success
                )
            }
            TenzroEvent::AgentMessage { from_agent, to_agent, message_type, .. } => {
                write!(
                    f,
                    "AgentMessage from={} to={} type={}",
                    from_agent, to_agent, message_type
                )
            }
            TenzroEvent::SettlementCompleted { settlement_id, amount, .. } => {
                write!(f, "SettlementCompleted id={} amount={}", settlement_id, amount)
            }
            TenzroEvent::PaymentChannelUpdate { channel_id, status, .. } => {
                write!(f, "PaymentChannelUpdate id={} status={}", channel_id, status)
            }
            TenzroEvent::StakeDeposited { amount, role, .. } => {
                write!(f, "StakeDeposited amount={} role={}", amount, role)
            }
            TenzroEvent::StakeWithdrawn { amount, .. } => {
                write!(f, "StakeWithdrawn amount={}", amount)
            }
            TenzroEvent::ValidatorSlashed { amount, reason, .. } => {
                write!(f, "ValidatorSlashed amount={} reason={}", amount, reason)
            }
            TenzroEvent::ProposalCreated { proposal_id, title, .. } => {
                write!(f, "ProposalCreated id={} title={}", proposal_id, title)
            }
            TenzroEvent::VoteCast { proposal_id, support, weight, .. } => {
                write!(
                    f,
                    "VoteCast proposal={} support={} weight={}",
                    proposal_id, support, weight
                )
            }
            TenzroEvent::BridgeTransferInitiated { bridge_adapter, destination_chain, amount, .. } => {
                write!(
                    f,
                    "BridgeTransferInitiated adapter={} dest={} amount={}",
                    bridge_adapter, destination_chain, amount
                )
            }
            TenzroEvent::BridgeTransferCompleted { bridge_adapter, source_chain, amount, .. } => {
                write!(
                    f,
                    "BridgeTransferCompleted adapter={} src={} amount={}",
                    bridge_adapter, source_chain, amount
                )
            }
            TenzroEvent::SyncProgress { current_block, highest_block, percent } => {
                write!(
                    f,
                    "SyncProgress {}/{} ({}%)",
                    current_block, highest_block, percent
                )
            }
            TenzroEvent::WorkflowCreated { workflow_id, title, .. } => {
                write!(f, "WorkflowCreated id={} title={}", hex::encode(workflow_id), title)
            }
            TenzroEvent::WorkflowLifecycleTransitioned {
                workflow_id, from_status, to_status, ..
            } => {
                write!(
                    f,
                    "WorkflowLifecycle id={} {}→{}",
                    hex::encode(workflow_id),
                    from_status,
                    to_status
                )
            }
            TenzroEvent::WorkflowReceiptEmitted { workflow_id, event_kind, .. } => {
                write!(
                    f,
                    "WorkflowReceipt wf={} kind={}",
                    hex::encode(workflow_id),
                    event_kind
                )
            }
            TenzroEvent::ApprovalRequested { workflow_id, gate_id, .. } => {
                write!(
                    f,
                    "ApprovalRequested wf={} gate={}",
                    hex::encode(workflow_id),
                    hex::encode(gate_id)
                )
            }
            TenzroEvent::ApprovalFinalized { workflow_id, outcome, .. } => {
                write!(f, "ApprovalFinalized wf={} outcome={}", hex::encode(workflow_id), outcome)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EventEnvelope
// ---------------------------------------------------------------------------

/// Wraps a [`TenzroEvent`] with monotonic sequencing and metadata.
///
/// Sequences are gap-free and strictly increasing. Consumers can use
/// `from_sequence` in [`EventFilter`] for cursor-based replay (Sui model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Monotonically increasing, gap-free sequence number.
    pub sequence: u64,
    /// Unix timestamp in milliseconds when the event was published.
    pub timestamp: i64,
    /// Block height associated with this event, if applicable.
    pub block_height: Option<u64>,
    /// VM that produced this event, if applicable.
    pub vm_type: Option<VmType>,
    /// The event payload.
    pub event: TenzroEvent,
}

impl EventEnvelope {
    /// Returns the discriminant [`EventType`] for the wrapped event.
    pub fn event_type(&self) -> EventType {
        self.event.event_type()
    }
}

impl fmt::Display for EventEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[seq={} t={}] {}", self.sequence, self.timestamp, self.event)
    }
}

// ---------------------------------------------------------------------------
// SubscriptionId
// ---------------------------------------------------------------------------

/// Opaque subscription handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(pub u64);

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// EventFilter
// ---------------------------------------------------------------------------

/// Describes which events a subscriber or query is interested in.
///
/// All filter fields are conjunctive (AND): an event must match every
/// non-empty field. Within a single field the values are disjunctive (OR).
///
/// The `topics` field follows the `eth_getLogs` convention: up to 4 positional
/// slots. `None` in a slot means "any value at this position". Within a slot,
/// multiple hashes mean "match any of these".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Only include events at or after this block height.
    pub from_block: Option<u64>,
    /// Only include events at or before this block height.
    pub to_block: Option<u64>,
    /// Cursor-based: only include events with sequence >= this value.
    pub from_sequence: Option<u64>,
    /// Addresses to match (e.g., contract addresses in Log events, sender/receiver in Transfer).
    pub addresses: Vec<[u8; 20]>,
    /// Topic filters following `eth_getLogs` semantics (up to 4 positional slots).
    pub topics: Vec<Option<Vec<[u8; 32]>>>,
    /// Only include events of these types.
    pub event_types: Vec<EventType>,
    /// Only include events from these VM types.
    pub vm_types: Vec<VmType>,
    /// Whether to include events that were removed during a reorg.
    pub include_removed: bool,
}

impl EventFilter {
    /// Create a new empty filter that matches everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set event types to filter on.
    pub fn with_event_types(mut self, types: Vec<EventType>) -> Self {
        self.event_types = types;
        self
    }

    /// Builder: set addresses to filter on.
    pub fn with_addresses(mut self, addrs: Vec<[u8; 20]>) -> Self {
        self.addresses = addrs;
        self
    }

    /// Returns `true` if the given envelope passes all filter predicates.
    pub fn matches(&self, envelope: &EventEnvelope) -> bool {
        // Block range
        if let Some(from) = self.from_block
            && let Some(bh) = envelope.block_height
            && bh < from
        {
            return false;
        }
        if let Some(to) = self.to_block
            && let Some(bh) = envelope.block_height
            && bh > to
        {
            return false;
        }

        // Sequence cursor
        if let Some(from_seq) = self.from_sequence
            && envelope.sequence < from_seq
        {
            return false;
        }

        // Event type filter
        if !self.event_types.is_empty()
            && !self.event_types.contains(&envelope.event_type())
        {
            return false;
        }

        // VM type filter
        if !self.vm_types.is_empty() {
            match &envelope.vm_type {
                Some(vm) if self.vm_types.contains(vm) => {}
                Some(_) => return false,
                // If no vm_type on envelope and filter requires one, skip
                None => return false,
            }
        }

        // Address filter — check relevant address fields on the event
        if !self.addresses.is_empty() && !self.matches_address(&envelope.event) {
            return false;
        }

        // Topic filter (only applies to Log events)
        if !self.topics.is_empty() {
            if let TenzroEvent::Log { topics, removed, .. } = &envelope.event {
                // Exclude removed logs unless include_removed is set
                if *removed && !self.include_removed {
                    return false;
                }
                if !self.matches_topics(topics) {
                    return false;
                }
            }
            // Non-Log events cannot match a topic filter
            else {
                return false;
            }
        }

        // Removed-log exclusion (even when no topic filter is set)
        if !self.include_removed
            && let TenzroEvent::Log { removed: true, .. } = &envelope.event
        {
            return false;
        }

        true
    }

    /// Check whether any address field on the event matches the filter addresses.
    fn matches_address(&self, event: &TenzroEvent) -> bool {
        let addrs = self.event_addresses(event);
        addrs.iter().any(|a| self.addresses.contains(a))
    }

    /// Extract all address fields from an event for address filtering.
    fn event_addresses(&self, event: &TenzroEvent) -> Vec<[u8; 20]> {
        match event {
            TenzroEvent::NewBlock { proposer, .. } => vec![*proposer],
            TenzroEvent::NewPendingTransaction { from, to, .. } => {
                let mut v = vec![*from];
                if let Some(t) = to {
                    v.push(*t);
                }
                v
            }
            TenzroEvent::Log { address, .. } => vec![*address],
            TenzroEvent::Transfer { from, to, .. } => vec![*from, *to],
            TenzroEvent::NftTransfer { from, to, .. } => vec![*from, *to],
            TenzroEvent::CrosschainMint { to, .. } => vec![*to],
            TenzroEvent::CrosschainBurn { from, .. } => vec![*from],
            TenzroEvent::ModelRegistered { provider, .. } => vec![*provider],
            TenzroEvent::InferenceCompleted { provider, .. } => vec![*provider],
            TenzroEvent::SettlementCompleted { payer, payee, .. } => vec![*payer, *payee],
            TenzroEvent::PaymentChannelUpdate { sender, receiver, .. } => {
                vec![*sender, *receiver]
            }
            TenzroEvent::StakeDeposited { staker, .. } => vec![*staker],
            TenzroEvent::StakeWithdrawn { staker, .. } => vec![*staker],
            TenzroEvent::ValidatorSlashed { validator, .. } => vec![*validator],
            TenzroEvent::ProposalCreated { proposer, .. } => vec![*proposer],
            TenzroEvent::VoteCast { voter, .. } => vec![*voter],
            TenzroEvent::BridgeTransferInitiated { sender, .. } => vec![*sender],
            TenzroEvent::BridgeTransferCompleted { receiver, .. } => vec![*receiver],
            _ => vec![],
        }
    }

    /// Check eth_getLogs-style positional topic matching.
    fn matches_topics(&self, event_topics: &[[u8; 32]]) -> bool {
        for (i, slot) in self.topics.iter().enumerate() {
            if let Some(wanted) = slot {
                match event_topics.get(i) {
                    Some(actual) if wanted.contains(actual) => {}
                    _ => return false,
                }
            }
            // None means "any value at this position" — always matches
        }
        true
    }
}

// ---------------------------------------------------------------------------
// SubscriptionConfig
// ---------------------------------------------------------------------------

/// Configuration for a live event subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    /// Unique subscription handle.
    pub id: SubscriptionId,
    /// Filter applied to incoming events.
    pub filter: EventFilter,
    /// Optional rate limit (events per second).
    pub max_events_per_second: Option<u32>,
    /// Whether to send full [`EventEnvelope`] or just the inner [`TenzroEvent`].
    pub include_envelope: bool,
}

impl SubscriptionConfig {
    /// Create a new subscription config with the given id and filter.
    pub fn new(id: SubscriptionId, filter: EventFilter) -> Self {
        Self {
            id,
            filter,
            max_events_per_second: None,
            include_envelope: true,
        }
    }

    /// Builder: set the maximum events per second.
    pub fn with_max_events_per_second(mut self, rate: u32) -> Self {
        self.max_events_per_second = Some(rate);
        self
    }

    /// Builder: set whether to include the full envelope.
    pub fn with_include_envelope(mut self, include: bool) -> Self {
        self.include_envelope = include;
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addr() -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = 0x42;
        a
    }

    fn sample_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        h
    }

    fn make_transfer() -> TenzroEvent {
        TenzroEvent::Transfer {
            from: sample_addr(),
            to: [1u8; 20],
            amount: 1_000_000,
            token_id: "TNZO".into(),
            tx_hash: sample_hash(),
        }
    }

    fn wrap(seq: u64, event: TenzroEvent) -> EventEnvelope {
        EventEnvelope {
            sequence: seq,
            timestamp: 1700000000000,
            block_height: Some(100),
            vm_type: Some(VmType::Native),
            event,
        }
    }

    #[test]
    fn test_event_creation_and_type() {
        let e = make_transfer();
        assert_eq!(e.event_type(), EventType::Transfer);
        assert_eq!(event_type_name(&e), "Transfer");
    }

    #[test]
    fn test_all_event_types_mapped() {
        let all = vec![
            EventType::NewBlock,
            EventType::BlockFinalized,
            EventType::BlockReorged,
            EventType::NewPendingTransaction,
            EventType::TransactionIncluded,
            EventType::TransactionFinalized,
            EventType::Log,
            EventType::Transfer,
            EventType::NftTransfer,
            EventType::CrosschainMint,
            EventType::CrosschainBurn,
            EventType::IdentityRegistered,
            EventType::CredentialIssued,
            EventType::ComplianceViolation,
            EventType::ModelRegistered,
            EventType::InferenceCompleted,
            EventType::InferenceStreamStarted,
            EventType::InferenceStreamFirstToken,
            EventType::InferenceStreamDropped,
            EventType::InferenceStreamCompleted,
            EventType::AgentMessage,
            EventType::SettlementCompleted,
            EventType::PaymentChannelUpdate,
            EventType::StakeDeposited,
            EventType::StakeWithdrawn,
            EventType::ValidatorSlashed,
            EventType::ProposalCreated,
            EventType::VoteCast,
            EventType::BridgeTransferInitiated,
            EventType::BridgeTransferCompleted,
            EventType::SyncProgress,
            EventType::WorkflowCreated,
            EventType::WorkflowLifecycleTransitioned,
            EventType::WorkflowReceiptEmitted,
            EventType::ApprovalRequested,
            EventType::ApprovalFinalized,
        ];
        for et in &all {
            let name = event_type_static_name(*et);
            assert!(!name.is_empty(), "Empty name for {:?}", et);
        }
        assert_eq!(all.len(), 36);
    }

    #[test]
    fn workflow_event_carries_privacy_domain() {
        let wf_id = [9u8; 32];
        let pd = [7u8; 32];
        let e = TenzroEvent::WorkflowCreated {
            workflow_id: wf_id,
            creator_did: "did:tenzro:human:alice".into(),
            title: "Trade settlement".into(),
            privacy_domain: Some(pd),
        };
        assert_eq!(e.event_type(), EventType::WorkflowCreated);
        assert_eq!(e.privacy_domain(), Some(pd));

        let public = TenzroEvent::WorkflowLifecycleTransitioned {
            workflow_id: wf_id,
            from_status: "Draft".into(),
            to_status: "AwaitingSignatures".into(),
            trigger: "Participant".into(),
            privacy_domain: None,
        };
        assert_eq!(public.privacy_domain(), None);
    }

    #[test]
    fn workflow_event_serde_roundtrip() {
        let e = TenzroEvent::ApprovalFinalized {
            workflow_id: [1u8; 32],
            gate_id: [2u8; 32],
            request_id: [3u8; 32],
            outcome: "Approved".into(),
            privacy_domain: Some([4u8; 32]),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn inference_stream_started_roundtrip() {
        let e = TenzroEvent::InferenceStreamStarted {
            request_id: "req-abc-123".into(),
            model_id: "qwen3-0.6b".into(),
            provider_label: "local".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(e.event_type(), EventType::InferenceStreamStarted);
    }

    #[test]
    fn inference_stream_first_token_roundtrip() {
        let e = TenzroEvent::InferenceStreamFirstToken {
            request_id: "req-abc-123".into(),
            model_id: "qwen3-0.6b".into(),
            provider_label: "0xdeadbeef".into(),
            ttft_ms: 250,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(e.event_type(), EventType::InferenceStreamFirstToken);
        if let TenzroEvent::InferenceStreamFirstToken { ttft_ms, .. } = back {
            assert_eq!(ttft_ms, 250);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn inference_stream_dropped_with_stall() {
        let e = TenzroEvent::InferenceStreamDropped {
            request_id: "req-abc-123".into(),
            model_id: "qwen3-0.6b".into(),
            provider_label: "0xdeadbeef".into(),
            reason: "stall".into(),
            silent_for_ms: Some(10_500),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(e.event_type(), EventType::InferenceStreamDropped);
        if let TenzroEvent::InferenceStreamDropped {
            reason,
            silent_for_ms,
            ..
        } = back
        {
            assert_eq!(reason, "stall");
            assert_eq!(silent_for_ms, Some(10_500));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn inference_stream_completed_success() {
        let e = TenzroEvent::InferenceStreamCompleted {
            request_id: "req-abc-123".into(),
            model_id: "qwen3-0.6b".into(),
            provider_label: "local".into(),
            latency_ms: 4_200,
            success: true,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(e.event_type(), EventType::InferenceStreamCompleted);
        if let TenzroEvent::InferenceStreamCompleted {
            latency_ms,
            success,
            ..
        } = back
        {
            assert_eq!(latency_ms, 4_200);
            assert!(success);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serialization_roundtrip_transfer() {
        let event = make_transfer();
        let json = serde_json::to_string(&event).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serialization_roundtrip_envelope() {
        let env = wrap(42, make_transfer());
        let json = serde_json::to_string(&env).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.event_type(), EventType::Transfer);
    }

    #[test]
    fn test_serialization_roundtrip_log_event() {
        let event = TenzroEvent::Log {
            address: sample_addr(),
            topics: vec![sample_hash(), [0xCDu8; 32]],
            data: vec![1, 2, 3, 4],
            block_height: 500,
            tx_hash: sample_hash(),
            log_index: 7,
            removed: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: TenzroEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_filter_matches_event_type() {
        let env = wrap(1, make_transfer());
        let filter = EventFilter {
            event_types: vec![EventType::Transfer],
            ..Default::default()
        };
        assert!(filter.matches(&env));

        let filter_miss = EventFilter {
            event_types: vec![EventType::NewBlock],
            ..Default::default()
        };
        assert!(!filter_miss.matches(&env));
    }

    #[test]
    fn test_filter_matches_block_range() {
        let env = wrap(1, make_transfer()); // block_height = Some(100)

        let within = EventFilter {
            from_block: Some(50),
            to_block: Some(150),
            ..Default::default()
        };
        assert!(within.matches(&env));

        let below = EventFilter {
            from_block: Some(101),
            ..Default::default()
        };
        assert!(!below.matches(&env));

        let above = EventFilter {
            to_block: Some(99),
            ..Default::default()
        };
        assert!(!above.matches(&env));
    }

    #[test]
    fn test_filter_matches_sequence_cursor() {
        let env = wrap(10, make_transfer());

        let before = EventFilter {
            from_sequence: Some(5),
            ..Default::default()
        };
        assert!(before.matches(&env));

        let exact = EventFilter {
            from_sequence: Some(10),
            ..Default::default()
        };
        assert!(exact.matches(&env));

        let after = EventFilter {
            from_sequence: Some(11),
            ..Default::default()
        };
        assert!(!after.matches(&env));
    }

    #[test]
    fn test_filter_matches_address() {
        let env = wrap(1, make_transfer());

        let hit = EventFilter {
            addresses: vec![sample_addr()],
            ..Default::default()
        };
        assert!(hit.matches(&env));

        let miss = EventFilter {
            addresses: vec![[0xFFu8; 20]],
            ..Default::default()
        };
        assert!(!miss.matches(&env));
    }

    #[test]
    fn test_filter_matches_topics() {
        let topic0 = sample_hash();
        let topic1 = [0xCDu8; 32];
        let log_event = TenzroEvent::Log {
            address: sample_addr(),
            topics: vec![topic0, topic1],
            data: vec![],
            block_height: 100,
            tx_hash: sample_hash(),
            log_index: 0,
            removed: false,
        };
        let env = wrap(1, log_event);

        let filter = EventFilter {
            topics: vec![Some(vec![topic0])],
            ..Default::default()
        };
        assert!(filter.matches(&env));

        let filter2 = EventFilter {
            topics: vec![None, Some(vec![topic1])],
            ..Default::default()
        };
        assert!(filter2.matches(&env));

        let filter_miss = EventFilter {
            topics: vec![Some(vec![[0xFFu8; 32]])],
            ..Default::default()
        };
        assert!(!filter_miss.matches(&env));
    }

    #[test]
    fn test_filter_removed_log_excluded_by_default() {
        let removed_log = TenzroEvent::Log {
            address: sample_addr(),
            topics: vec![],
            data: vec![],
            block_height: 100,
            tx_hash: sample_hash(),
            log_index: 0,
            removed: true,
        };
        let env = wrap(1, removed_log);

        let default_filter = EventFilter::default();
        assert!(!default_filter.matches(&env));

        let include_removed = EventFilter {
            include_removed: true,
            ..Default::default()
        };
        assert!(include_removed.matches(&env));
    }

    #[test]
    fn test_filter_vm_type() {
        let env = wrap(1, make_transfer()); // vm_type = Some(Native)

        let native_filter = EventFilter {
            vm_types: vec![VmType::Native],
            ..Default::default()
        };
        assert!(native_filter.matches(&env));

        let evm_filter = EventFilter {
            vm_types: vec![VmType::Evm],
            ..Default::default()
        };
        assert!(!evm_filter.matches(&env));
    }

    #[test]
    fn test_display_formatting() {
        let e = make_transfer();
        let s = format!("{}", e);
        assert!(s.contains("Transfer"));
        assert!(s.contains("1000000"));
        assert!(s.contains("TNZO"));

        let env = wrap(42, e);
        let s2 = format!("{}", env);
        assert!(s2.contains("seq=42"));
    }

    #[test]
    fn test_subscription_config_builder() {
        let cfg = SubscriptionConfig::new(SubscriptionId(1), EventFilter::default())
            .with_max_events_per_second(100)
            .with_include_envelope(false);
        assert_eq!(cfg.id, SubscriptionId(1));
        assert_eq!(cfg.max_events_per_second, Some(100));
        assert!(!cfg.include_envelope);
    }

    #[test]
    fn test_envelope_event_type() {
        let env = wrap(
            1,
            TenzroEvent::BlockFinalized {
                block_hash: sample_hash(),
                height: 50,
            },
        );
        assert_eq!(env.event_type(), EventType::BlockFinalized);
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::NewBlock), "NewBlock");
        assert_eq!(format!("{}", EventType::SyncProgress), "SyncProgress");
    }
}
