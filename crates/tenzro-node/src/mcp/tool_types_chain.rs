//! Typed MCP tool inputs and outputs for chain reads, node status and identity, access tokens, passkeys, governance, treasury, TEE, ZK and events.

use serde::{Deserialize, Serialize};

/// An amount in wei: a JSON number up to 2^64 - 1, a decimal string above it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChainWei {
    /// At most 2^64 - 1.
    Number(u64),
    /// Above 2^64 - 1, decimal.
    Decimal(String),
}

// ─── Node status and profile ───

/// The data volume's fill state.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeDiskStatus {
    /// normal, pruning or refusing.
    pub pressure: String,
    /// Percent of the data volume in use at the last check.
    pub used_pct: u8,
    /// Whether non-essential data is being refused.
    pub refusing_non_essential: bool,
}

/// This node's status.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeStatusOutput {
    pub state: String,
    /// The roles the node serves, e.g. Validator, FullNode, ModelProvider.
    pub roles: Vec<String>,
    /// Healthy, Degraded, Unhealthy or Unknown.
    pub health_status: String,
    pub uptime_secs: u64,
    pub block_height: u64,
    pub peer_count: u64,
    pub data_dir: String,
    pub tee_capable: bool,
    /// The TEE vendor, e.g. IntelTdx or AmdSevSnp; null on commodity hardware.
    pub tee_vendor: Option<String>,
    pub iroh_enabled: bool,
    /// The iroh EndpointId, z-base-32; null when iroh is off.
    pub iroh_endpoint_id: Option<String>,
    pub iroh_alpns: Vec<String>,
    /// GPUs present but hidden from the node by an empty visibility variable.
    pub hidden_gpus: Vec<String>,
    pub disk: NodeDiskStatus,
    /// The machine's hardware DID, when it has one.
    pub machine_did: Option<String>,
    /// The operator's DID, when one is bound.
    pub operator_did: Option<String>,
    /// The wallet this node is paid at, `0x` hex.
    pub payee: Option<String>,
}

/// A compute device this node detected.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeProfileDevice {
    /// Cpu, Cuda, Metal, Vulkan, Hip or Sycl.
    pub backend: String,
    /// Gpu, IntegratedGpu, Cpu, Accelerator or Unknown.
    pub dev_type: String,
    pub description: String,
    pub cap_key: String,
    /// Bytes.
    pub mem_free: u64,
    /// Bytes.
    pub mem_total: u64,
}

/// This node's hardware self-profile.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeProfileOutput {
    /// The linked runtime build commit.
    pub llama_commit: String,
    pub cpu_arch: String,
    pub os: String,
    pub devices: Vec<NodeProfileDevice>,
    /// Serving capacity in GB.
    pub serving_vram_gb: f64,
    /// The backend of the strongest GPU-class device, else Cpu.
    pub serving_backend: String,
    pub serving_cap_key: String,
}

// ─── Fee markets ───

/// eth_feeHistory's result.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeeHistoryOutput {
    /// `0x` hex height.
    #[serde(rename = "oldestBlock")]
    pub oldest_block: String,
    /// Base fee per block, `0x` hex, with one trailing entry for the next block.
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Vec<String>,
    #[serde(rename = "gasUsedRatio")]
    pub gas_used_ratio: Vec<f64>,
    /// Priority fee per block and percentile, `0x` hex, when percentiles were asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reward: Option<Vec<Vec<String>>>,
}

/// One resource market's base fee.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeeResourceMarket {
    /// Atto-USD per unit, decimal string.
    pub base_fee_usd: String,
    /// TNZO base units per unit at the rate in force, decimal string.
    pub base_fee: String,
    pub target_per_block: u64,
}

/// The fee markets.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeeMarketOutput {
    /// eth_gasPrice, `0x` hex.
    pub gas_price_wei: String,
    /// eth_maxPriorityFeePerGas, `0x` hex.
    pub max_priority_fee_per_gas_wei: String,
    pub fee_history: FeeHistoryOutput,
    /// Each resource market by name: compute, state_growth, bandwidth, proof.
    pub resource_markets: std::collections::BTreeMap<String, FeeResourceMarket>,
}

// ─── Role stakes and relays ───

/// The capacity a role bond backs.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoleStakeCapacity {
    /// No capacity dimension; the role's flat bond applies.
    #[serde(rename = "none")]
    Flat,
    /// Accelerator classes pledged: integrated, consumer, workstation or datacentre.
    Accelerators(Vec<String>),
    /// Whole terabytes of disk pledged.
    Terabytes(u32),
    /// A wallet provider's relying-party domain.
    Domain(String),
    /// An attestor's bridge signing key.
    BridgeSigner {
        /// The 20-byte signing address, as bytes.
        address: Vec<u8>,
        /// The RPC provider it reads source chains from.
        rpc_provider: String,
        /// Recoverable secp256k1 signature, hex.
        proof: String,
        /// The ML-DSA-65 verifying key, hex.
        pq_public_key: String,
        /// ML-DSA-65 signature over the bridge signer digest, hex.
        pq_proof: String,
    },
}

/// An account's stake for one role.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleStakeEntry {
    pub role: String,
    /// Wei, decimal string.
    pub bonded: String,
    /// Wei required for the declared capacity, decimal string.
    pub required: String,
    /// Wei required at entry, decimal string.
    pub entry_required: String,
    pub capacity: RoleStakeCapacity,
    /// Wei, decimal string.
    pub unbonding: String,
    /// When the unbonding stake can be withdrawn, Unix ms.
    pub release_at_ms: i64,
    /// The public URL the role is served at, when published.
    pub endpoint: Option<String>,
    /// The SLA subject, for a role that owes an SLA.
    pub sla_subject: Option<String>,
}

/// A role's network total.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleStakeTotal {
    pub role: String,
    /// Wei, decimal string.
    pub bonded: String,
    pub stakers: u64,
}

/// An account's stake per role and every role's network total.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleStakesOutput {
    /// `0x` hex.
    pub address: String,
    pub stakes: Vec<RoleStakeEntry>,
    pub totals: Vec<RoleStakeTotal>,
}

/// This node's latest check of a relay.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RelayCheckOutput {
    pub url: String,
    /// The operator's machine identity, from its record.
    pub operator: Option<String>,
    /// Whether the relay answered with a valid record.
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    /// Unix ms.
    pub checked_ms: u64,
    /// Why the check failed.
    pub error: Option<String>,
}

/// The SLA verdict validators froze for a relay.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RelaySlaVerdict {
    pub epoch: u64,
    pub available: bool,
    pub attesters: u64,
}

/// A staked edge operator's relay.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RelayEntry {
    /// `0x` hex.
    pub account: String,
    pub url: String,
    /// Wei, decimal string.
    pub bonded: String,
    /// Whether this node uses it.
    pub used: bool,
    pub check: Option<RelayCheckOutput>,
    /// The verdict for the last closed epoch, when frozen.
    pub sla: Option<RelaySlaVerdict>,
}

/// The staked relays, most bonded first.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RelaysOutput {
    pub relays: Vec<RelayEntry>,
}

// ─── Duties and evidence ───

/// The work a duty pays for.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DutyKindOutput {
    /// Reconcile a route's settlement lock for one epoch.
    Reconciliation { route: String, epoch: u64 },
    /// Install a voided agent grant on another chain (CAIP-2).
    GrantRelay {
        agent_did: String,
        chain: String,
        seq: u64,
    },
}

/// A network duty.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DutyOutput {
    /// Hex.
    pub id: String,
    pub kind: DutyKindOutput,
    /// The vault holding the reward, hex.
    pub vault: String,
    /// The account an unpaid reward returns to, hex.
    pub funder: String,
    pub reward: ChainWei,
    /// Unix ms.
    pub opened_at_ms: i64,
    /// When it closes unpaid, Unix ms; null while its funder keeps it open.
    pub expires_at_ms: Option<i64>,
    /// open, paid or expired.
    pub state: String,
    /// Who it paid, hex, once paid.
    #[serde(default)]
    pub paid_to: Option<String>,
}

/// The open duties, oldest first.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DutiesOutput {
    pub count: u64,
    pub duties: Vec<DutyOutput>,
}

/// An audit entry as signed: its bytes and the session signature over them.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuditSignedEntry {
    /// The entry's JSON, hex.
    pub body: String,
    /// The session signature over `body`, hex.
    pub signature: String,
}

/// Inclusion of one leaf in an MMR.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuditMmrProof {
    pub index: u64,
    pub size: u64,
    /// 32-byte hex each.
    pub siblings: Vec<String>,
    /// 32-byte hex each.
    pub peaks: Vec<String>,
}

/// One session's line in an epoch commitment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuditSessionLeaf {
    /// Hex.
    pub session_id: String,
    /// Hex.
    pub mmr_root: String,
    pub count: u64,
}

/// Inclusion of one session in an epoch tree.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuditEpochProof {
    pub leaf: AuditSessionLeaf,
    pub index: u64,
    pub count: u64,
    /// 32-byte hex each.
    pub siblings: Vec<String>,
}

/// An audit entry with its proof to the epoch root its node committed.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceAuditProof {
    pub entry: AuditSignedEntry,
    pub mmr: AuditMmrProof,
    pub epoch_proof: AuditEpochProof,
    pub epoch: u64,
    /// The ledger account that committed it, `0x` hex.
    pub committer: String,
}

/// The P-256 leg of a signature.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum EvidenceClassicalProof {
    /// `r || s` or DER from a TPM or Secure Enclave, hex.
    Raw { signature: String },
    /// A passkey assertion, each field hex.
    WebAuthn {
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
}

/// A hardware composite signature.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceSignature {
    pub classical: EvidenceClassicalProof,
    /// The ML-DSA-65 leg, hex, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
}

/// What an off-chain document is.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDocumentKind {
    Mandate,
    Receipt,
    EvidencePack,
    Delivery,
}

/// One evidence item.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceItemParam {
    /// An audit or attested-telemetry entry with its proof.
    Audit(Box<EvidenceAuditProof>),
    /// The terms an agent holds on chain.
    Terms { agent_did: String },
    /// An HTTP-402 settlement the chain recorded.
    Settlement { payment_id: String },
    /// A reading signed by the device that measured it.
    SensorData {
        device_did: String,
        /// SHA-256 of the reading's payload, hex.
        payload_digest: String,
        /// Unix ms.
        measured_at_ms: u64,
        signature: EvidenceSignature,
    },
    /// A finality program journal and its proof, hex each. Give `stark`, the
    /// quantum-safe canonical form; `seal`, the Groth16 wrap over BN254, is a
    /// compact form for EVM verifiers and rests on a classical assumption.
    /// Exactly one of the two.
    FinalityProof {
        journal: String,
        #[serde(default)]
        stark: Option<String>,
        #[serde(default)]
        seal: Option<String>,
    },
    /// A document held off chain, bound by its SHA-256 (hex).
    Document {
        kind: EvidenceDocumentKind,
        digest: String,
    },
}

/// The result of checking one evidence item.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceCheckedOutput {
    /// audit, terms, settlement, sensor_data, finality_proof, or the document kind.
    pub kind: String,
    /// What the item checks to, hex.
    pub digest: String,
    /// Whether the chain checked it against its own records.
    pub verified_on_chain: bool,
}

/// Each evidence item checked.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceVerifiedOutput {
    pub items: Vec<EvidenceCheckedOutput>,
}

// ─── Treasury and guardians ───

/// The last remote grant an enacted proposal wrote for a treasury account.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryRemoteGrantOutput {
    pub seq: u64,
    /// Hex.
    pub payload_hash: String,
    /// Decimal string.
    pub amount: String,
    /// Unix ms.
    pub not_after_ms: u64,
    pub void: bool,
}

/// The treasury's account on one chain, or why it has none.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryAccountEntry {
    /// CAIP-2.
    pub caip2: String,
    /// The address as the chain writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caip10: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<TreasuryRemoteGrantOutput>,
    /// Why there is no account on this chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The treasury's keyless accounts.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryAccountsOutput {
    /// The treasury identity.
    pub did: String,
    /// The treasury's Tenzro address, hex.
    pub tenzro: String,
    pub accounts: Vec<TreasuryAccountEntry>,
    /// How Bitcoin moves.
    pub bitcoin: String,
}

/// A pause: until when it holds, and until when a new one is refused.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuardianPauseOutput {
    /// Unix ms.
    pub paused_until_ms: i64,
    /// Unix ms.
    pub cooloff_until_ms: i64,
}

/// What a seat's signing key is rooted in.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuardianSeatKeyRoot {
    /// A synced passkey; its provider's AAGUID, hex.
    SyncProvider { aaguid: String },
    /// A device-bound credential; its id, hex.
    Device { credential_id: String },
}

/// A guardian or steward seat.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuardianSeatOutput {
    /// The holder's human DID.
    pub did: String,
    /// protocol, governance or steward.
    pub role: String,
    /// Unix ms.
    pub term_ends_ms: i64,
    pub key_root: GuardianSeatKeyRoot,
}

/// A seat and whether it is live.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuardianSeatEntry {
    pub address: String,
    pub seat: GuardianSeatOutput,
    pub active: bool,
}

/// Guardian seats, the enactment pause and the steward treasury hold.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuardianStateOutput {
    pub pause: GuardianPauseOutput,
    pub paused: bool,
    pub treasury_hold: GuardianPauseOutput,
    pub treasury_held: bool,
    pub threshold: u64,
    /// Unix ms.
    pub steward_sunset_ms: i64,
    pub steward_max_seats: u64,
    pub seats: Vec<GuardianSeatEntry>,
    /// With an address: whether its seat is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// With an address: the seat it holds, null for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat: Option<GuardianSeatOutput>,
}

// ─── Economic policy ───

/// Division when the serving node validates for itself.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EconomicValidatingSchedule {
    pub operator_bps: u32,
    pub treasury_bps: u32,
}

/// Division when an RPC provider validates on the serving node's behalf.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EconomicDelegatedSchedule {
    pub operator_bps: u32,
    pub rpc_provider_bps: u32,
    pub treasury_bps: u32,
}

/// Every rate the network charges.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EconomicPolicyRates {
    pub validating: EconomicValidatingSchedule,
    pub delegated: EconomicDelegatedSchedule,
    /// convert_to_tnzo or keep_inbound.
    pub default_conversion: String,
    /// The smallest charge settled on its own, wei.
    pub micro_settlement_floor: ChainWei,
}

/// One payee's share in this node's mode.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EconomicShare {
    pub role: String,
    pub bps: u32,
}

/// The operator's share in each economic mode.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OperatorShareByMode {
    pub private: u32,
    pub public_validating: u32,
    pub public_delegated: u32,
}

/// This node's economic policy and the mode it settles under.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EconomicPolicyOutput {
    pub policy: EconomicPolicyRates,
    pub validating: bool,
    /// `0x` hex.
    pub rpc_provider_payee: Option<String>,
    pub visibility: String,
    pub mode: String,
    pub shares: Vec<EconomicShare>,
    pub operator_share_bps_by_mode: OperatorShareByMode,
}

// ─── Data availability ───

/// One member's availability score, or every scored member's.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum DaAvailabilityResult {
    /// Every scored member, lowest first.
    All {
        count: u64,
        scores: Vec<crate::mcp::server::DaAvailabilityOutput>,
    },
    /// The member asked for.
    One(crate::mcp::server::DaAvailabilityOutput),
}

// ─── Zero-knowledge proofs ───

/// One proof leg of a statement.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkProofLegInput {
    /// koala-bear-sha256-fri, goldilocks-blake3-fri or halo2-ipa-pasta.
    pub system: String,
    /// The proof bytes, hex (`0x` optional).
    pub proof: String,
}

/// The witness of a settlement statement.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkSettlementWitness {
    /// The 32-byte service result, hex.
    pub witness: String,
    /// The 32-byte request binding, hex.
    pub binding: String,
}

/// The transaction that attests one leg: its hash, or why it was not submitted.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ZkAttestTx {
    /// The transaction hash.
    Submitted(String),
    /// The submission failed.
    Failed { error: String },
}

/// One leg of a verified statement submitted for attestation.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkLegAttestationOutput {
    pub system: String,
    /// The leg's commitment, `0x` hex.
    pub commitment_hex: String,
    pub attest_tx: ZkAttestTx,
}

/// The verdict on a statement and its proof legs.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkVerifyOutput {
    /// Whether every leg verified.
    pub valid: bool,
    pub circuit_id: String,
    /// Commitment to the circuit and its public inputs, `0x` hex.
    pub statement_commitment: String,
    /// Number of proof legs given.
    pub legs: u64,
    /// The proof systems the legs verified in.
    pub verified_systems: Vec<String>,
    /// Distinct proof systems a statement needs to be attested.
    pub diverse_threshold: u64,
    pub meets_diverse_threshold: bool,
    /// One entry per leg once the statement is submitted for attestation.
    pub attestations: Vec<ZkLegAttestationOutput>,
    /// Why verification failed.
    pub error: Option<String>,
    pub note: String,
}

/// One proof system a circuit is proven in, with its security.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkProofSystemOutput {
    pub system: String,
    /// plonky3 or halo2.
    pub implementation: String,
    /// FRI systems: log2 of the base-field order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_field_bits: Option<f64>,
    /// FRI systems: degree of the challenge extension field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_degree: Option<u64>,
    /// FRI systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fri_log_blowup: Option<u64>,
    /// FRI systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fri_queries: Option<u64>,
    /// FRI systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_pow_bits: Option<u64>,
    /// FRI systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proven_security_bits: Option<f64>,
    /// FRI systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conjectured_security_bits: Option<f64>,
    /// Halo2: the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Halo2: the commitment scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// Halo2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<String>,
    /// Halo2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_rows_log2: Option<u64>,
    /// Halo2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computational_security_bits: Option<u64>,
}

/// A circuit this node verifies.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkCircuitOutput {
    /// identity or settlement.
    #[serde(rename = "type")]
    pub circuit_type: String,
    pub name: String,
    /// What a proof shows.
    pub statement: String,
    pub public_inputs: Vec<String>,
    pub in_circuit_hash: String,
    /// Whether a node may produce this circuit's proofs.
    pub node_provable: bool,
    pub proof_systems: Vec<ZkProofSystemOutput>,
    pub diverse_threshold: u64,
}

/// The circuit catalogue.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkCircuitsOutput {
    pub circuits: Vec<ZkCircuitOutput>,
    pub total: u64,
}

// ─── Chain events and their proofs ───

/// One topic position of an event filter: a topic, or any of several.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum EventTopicSlot {
    /// One 32-byte topic, hex.
    One(String),
    /// Any of these 32-byte topics, hex.
    Any(Vec<String>),
}

/// Which chain events a read selects.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventFilterInput {
    /// Event type names, snake_case, e.g. log or transaction_included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<String>>,
    /// Emitting addresses, 20-byte hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
    /// Up to 4 topic positions; null matches any topic there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<EventTopicSlot>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_block: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_block: Option<u64>,
}

/// Where an event sits in the chain.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventCursorOutput {
    pub height: u64,
    pub tx_index: u32,
    pub event_index: u32,
}

/// One event a block's execution emitted. Byte fields are arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainEventOutput {
    /// A transaction executed; always its first event.
    TxOutcome {
        cursor: EventCursorOutput,
        /// 32 bytes.
        tx_hash: Vec<u8>,
        success: bool,
        gas_used: u64,
        /// The contract it deployed, if any.
        contract_address: Option<Vec<u8>>,
    },
    /// A log the transaction emitted.
    Log {
        cursor: EventCursorOutput,
        /// 32 bytes.
        tx_hash: Vec<u8>,
        address: Vec<u8>,
        topics: Vec<Vec<u8>>,
        data: Vec<u8>,
    },
}

/// One step up a Merkle inclusion path.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MerklePathStep {
    /// The 32-byte sibling node.
    pub sibling: Vec<u8>,
    /// Whether the sibling is the left child.
    pub left: bool,
}

/// Execution metadata of a block header.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventBlockMetadata {
    pub gas_used: u64,
    pub gas_limit: u64,
    pub tx_count: u64,
    pub protocol_version: u32,
    pub base_fee_per_gas: Option<u128>,
}

/// A block header. Hash and address fields are arrays of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventBlockHeader {
    pub height: u64,
    pub epoch: u64,
    pub round: u64,
    pub anchor: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub tx_root: Vec<u8>,
    pub state_root: Vec<u8>,
    pub event_root: Vec<u8>,
    pub receipts_root: Vec<u8>,
    /// 256-byte bloom, hex.
    pub logs_bloom: String,
    /// Unix ms.
    pub timestamp: i64,
    pub proposer: Vec<u8>,
    pub metadata: EventBlockMetadata,
}

/// A finality checkpoint body. Digest fields are arrays of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointBody {
    pub chain_id: u64,
    pub genesis_hash: Vec<u8>,
    pub epoch: u64,
    pub index: u64,
    pub prev: Vec<u8>,
    pub first_height: u64,
    pub last_height: u64,
    pub blocks_root: Vec<u8>,
    pub state_height: u64,
    pub state_root: Vec<u8>,
    pub statement_root: Vec<u8>,
    pub next_committee_root: Option<Vec<u8>>,
    pub anchor_round: u64,
    pub timestamp_ms: u64,
    pub ordering_root: Vec<u8>,
}

/// An event, the header that commits it, and the checkpoints that carry the
/// header to a certified one.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventProofBody {
    pub event: ChainEventOutput,
    /// Path from the event's leaf to the header's event root.
    pub event_path: Vec<MerklePathStep>,
    pub header: EventBlockHeader,
    /// Path from the header hash to the covering checkpoint's blocks root.
    pub block_path: Vec<MerklePathStep>,
    /// From the checkpoint covering the block up to the certified anchor.
    pub checkpoints: Vec<CheckpointBody>,
}

/// One entry of a block's event index.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventIndexEntry {
    /// The key, hex.
    pub key: String,
    /// The next key, hex, or null for the last entry.
    pub next: Option<String>,
    pub cursors: Vec<EventCursorOutput>,
}

/// An index entry and its path to the block's event root.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventIndexEntryProof {
    pub entry: EventIndexEntry,
    pub path: Vec<MerklePathStep>,
}

/// One block's index entries for the keys a read asked for.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventBlockIndexProof {
    pub header: EventBlockHeader,
    pub block_path: Vec<MerklePathStep>,
    pub entries: Vec<EventIndexEntryProof>,
}

/// Proof that a page left out nothing its filter selects.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventCompletenessProof {
    /// The index keys covered, hex.
    pub keys: Vec<String>,
    pub first_height: u64,
    /// Events at or before this cursor are not part of the read.
    pub after: Option<EventCursorOutput>,
    /// The last cursor the read covers.
    pub through: EventCursorOutput,
    pub blocks: Vec<EventBlockIndexProof>,
    pub checkpoints: Vec<CheckpointBody>,
    /// Proofs of the candidate events the filter rejects.
    pub excluded: Vec<EventProofBody>,
}

/// One event of a page, with its proof when proofs were asked for.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventsPageEntry {
    pub event: ChainEventOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<EventProofBody>,
}

/// A page of chain events.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventsPageOutput {
    pub events: Vec<EventsPageEntry>,
    /// Pass back as from_cursor to resume (height:tx_index:event_index).
    pub cursor: Option<String>,
    /// The highest height the event log holds.
    pub tip: Option<u64>,
    /// When completeness was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<EventCompletenessProof>,
}

/// Whether an event proof checks against a certified checkpoint.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventProofVerdictOutput {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── State snapshots ───

/// How a bucket's subtree combines into the state root: `"Empty"`, or
/// `{"Single": [32 bytes]}` / `{"Multi": [32 bytes]}`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum SnapshotSubtree {
    Empty,
    Single(Vec<u8>),
    Multi(Vec<u8>),
}

/// A bucket's index and summary.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotBucketSummary {
    pub index: u32,
    pub subtree: SnapshotSubtree,
}

/// One bucket of a snapshot.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotBucketOutput {
    pub summary: SnapshotBucketSummary,
    /// BLAKE3 hash of the blob holding the bucket's entries, 32 byte values.
    pub blob: Vec<u8>,
    pub entries: u64,
}

/// A snapshot manifest.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotManifestOutput {
    pub height: u64,
    /// The state root at height, 32 byte values.
    pub state_root: Vec<u8>,
    /// BLAKE3 hash of the blob holding the blocks that commit the root, 32 byte values.
    pub anchor_chain: Vec<u8>,
    /// Every non-empty bucket, in index order.
    pub buckets: Vec<SnapshotBucketOutput>,
}

// ─── TEE attestation ───

/// One measurement register of an attestation.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeMeasurementOutput {
    pub register: String,
    pub algorithm: String,
    /// `0x` hex.
    pub value_hex: String,
}

/// An attestation report from this node's enclave.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeAttestationOutput {
    pub vendor: String,
    /// `0x` hex.
    pub user_data_hex: String,
    /// `0x` hex.
    pub measurement_hex: String,
    pub measurements: Vec<TeeMeasurementOutput>,
    /// The JSON report, `0x` hex, as verify_tee_attestation takes it.
    pub report_hex: String,
    /// Unix ms.
    pub timestamp: i64,
}

/// A facility's claim of where a chip sits.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeFacilityClaim {
    pub facility_id: String,
    pub region: String,
    /// P-256 public key, byte values.
    pub facility_key: Vec<u8>,
}

/// A facility claim and its signature.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeSignedFacilityClaim {
    pub claim: TeeFacilityClaim,
    pub signature: Vec<u8>,
}

/// What an attestation transparency log entry records.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum TeeLogEntryBody {
    /// A published measurement.
    Measurement {
        vendor: String,
        measurement: Vec<u8>,
        publisher_did: String,
    },
    /// A chip's first placement in a facility.
    Placement {
        vendor: String,
        platform_id: Vec<u8>,
        facility: TeeSignedFacilityClaim,
    },
}

/// An attestation transparency log entry.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeLogEntry {
    pub body: TeeLogEntryBody,
    pub prev: Vec<u8>,
    pub hash: Vec<u8>,
}

/// The recorded and the presented placement of a chip.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeFacilityEvidence {
    pub recorded: TeeLogEntry,
    pub presented: TeeSignedFacilityClaim,
}

/// An attestation that verified and is admitted.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeAttestationVerified {
    /// true.
    pub valid: bool,
    pub vendor: String,
    /// `0x` hex.
    pub measurement_hex: String,
    pub measurements: Vec<TeeMeasurementOutput>,
    /// `0x` hex.
    pub platform_id_hex: String,
    pub tcb_status: String,
    /// The facility the chip is placed in, when a claim was presented.
    pub facility: Option<String>,
}

/// An attestation that was refused.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeAttestationRefused {
    /// false.
    pub valid: bool,
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// When the measurement is not in the transparency log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurements: Option<Vec<TeeMeasurementOutput>>,
    /// When the chip was first placed in a different facility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<TeeFacilityEvidence>,
}

/// The verdict on a TEE attestation report.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum TeeAttestationVerdictOutput {
    Verified(TeeAttestationVerified),
    Refused(TeeAttestationRefused),
}

// ─── Checkpoint certificates ───

/// One signer of a checkpoint certificate, read against the epoch's committee.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointSignerOutput {
    pub index: u64,
    /// `0x` hex; null when the committee is not known.
    pub address: Option<String>,
    pub seats: Option<u64>,
    /// Decimal string.
    pub stake: Option<String>,
    /// `0x` hex.
    pub key_fingerprint: Option<String>,
    /// `0x` hex.
    pub session_digest: String,
}

/// A certificate's signer set decoded against its committee.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointSignersOutput {
    pub signers: Vec<CheckpointSignerOutput>,
    pub signed_seats: Option<u64>,
    pub total_seats: Option<u64>,
    pub quorum: Option<u64>,
    pub committee_known: bool,
}

/// A checkpoint certificate and the session certificates it names.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointCertificateOutput {
    pub epoch: u64,
    pub index: u64,
    pub last_height: u64,
    /// The checkpoint digest, `0x` hex.
    pub digest: String,
    /// The certificate, `0x` hex bincode.
    pub certificate: String,
    /// The session certificates, `0x` hex bincode.
    pub sessions: String,
    /// With decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded: Option<CheckpointSignersOutput>,
}

// ─── Content provenance ───

/// A signed provenance manifest for generated content. Byte fields are arrays
/// of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContentProvenanceOutput {
    /// 32 bytes.
    pub content_hash: Vec<u8>,
    pub model_id: String,
    /// 32 bytes.
    pub provider: Vec<u8>,
    /// Unix ms.
    pub signed_at: i64,
    pub assertion: String,
    pub signer_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub algorithm: String,
}

// ─── Keys, proofs and signatures ───

/// A P-256 public key as a JWK.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EcP256Jwk {
    /// `EC`.
    pub kty: String,
    /// `P-256`.
    pub crv: String,
    /// Base64url.
    pub x: String,
    /// Base64url.
    pub y: String,
}

/// The ES256 key access tokens verify under, as a JWK.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessTokenJwk {
    /// `EC`.
    pub kty: String,
    /// `P-256`.
    pub crv: String,
    /// Base64url.
    pub x: String,
    /// Base64url.
    pub y: String,
    pub kid: String,
    /// `ES256`.
    pub alg: String,
    /// `sig`.
    #[serde(rename = "use")]
    pub key_use: String,
}

/// A W3C Data Integrity proof (`ecdsa-jcs-2019`) made by a hardware key.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DataIntegrityProof {
    /// `DataIntegrityProof`.
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    /// RFC 3339.
    pub created: String,
    /// Multibase base58btc signature.
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// The P-256 leg of a hardware signature, hex bytes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum HardwareClassicalProof {
    /// `r || s` or DER from a TPM or Secure Enclave.
    Raw { signature: String },
    /// A passkey assertion.
    WebAuthn {
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
}

/// A composite signature: the P-256 leg and, when the signer holds one, the
/// hardware ML-DSA-65 leg.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HardwareCompositeSignature {
    pub classical: HardwareClassicalProof,
    /// ML-DSA-65 signature, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
}

// ─── Node DID document and DID envelopes ───

/// A verification method in a node DID Document.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeDidVerificationMethod {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub method_type: String,
    #[serde(
        rename = "publicKeyMultibase",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_multibase: Option<String>,
    #[serde(
        rename = "publicKeyJwk",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_jwk: Option<EcP256Jwk>,
}

/// A service entry in a DID Document.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeDidService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// This node's DID Document, signed by its hardware identity key when the DID
/// derives from that key.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeDidDocumentOutput {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    #[serde(
        rename = "verificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_method: Vec<NodeDidVerificationMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    #[serde(
        rename = "assertionMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<String>,
    #[serde(
        rename = "keyAgreement",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<NodeDidService>,
    /// Absent when the node holds no hardware key its DID derives from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
}

/// What a did:web envelope check found.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DidWebEnvelopeDetails {
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// `did:web` when the document was fetched and the envelope verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The verdict on a DID envelope.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum DidEnvelopeVerdictOutput {
    /// A did:web envelope, checked against the fetched did.json.
    DidWeb {
        valid: bool,
        details: DidWebEnvelopeDetails,
        /// RFC 3339.
        verified_at: String,
    },
    /// A did:tenzro, did:key or did:ethr envelope, checked against the registry.
    Registry {
        valid: bool,
        did: String,
        /// The envelope's signature method, when valid.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
        /// Why it failed, when invalid.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

// ─── Proof of reserve ───

/// Where a reserve figure came from.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSourceKind {
    Issuer,
    Tee,
    ChainlinkPor,
    Oracle,
}

/// A signed statement of the reserves backing a tokenized asset.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReserveAttestationRecord {
    /// Tokenized-asset id (hex token id).
    pub asset_id: String,
    /// Smallest units.
    pub reserves: ChainWei,
    pub source: ReserveSourceKind,
    pub attestor_did: String,
    /// Unix seconds.
    pub attested_at: i64,
    /// The attestor's composite signature (context ReserveAttestation) over the
    /// attestation; required for a submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HardwareCompositeSignature>,
}

// ─── OAuth: RAR and AAP claims ───

/// One RFC 9396 authorization detail. Amounts are decimal strings; addresses
/// and escrow ids are 32-byte arrays.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RarAuthorizationDetail {
    Transfer {
        asset: String,
        max_amount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_daily_amount: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_counterparties: Option<Vec<Vec<u8>>>,
    },
    CreateEscrow {
        asset: String,
        max_amount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_payees: Option<Vec<Vec<u8>>>,
    },
    DischargeEscrow {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_escrow_ids: Option<Vec<Vec<u8>>>,
    },
    Inference {
        max_amount_per_call: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_daily_amount: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_model_ids: Option<Vec<String>>,
    },
    Stake {
        max_amount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_validators: Option<Vec<Vec<u8>>>,
    },
    Vote {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_proposals: Option<Vec<String>>,
    },
    Contract {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_contracts: Option<Vec<Vec<u8>>>,
        #[serde(default)]
        allow_deploy: bool,
    },
    RegisterIdentity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_children: Option<u32>,
    },
    ResourceInvocation {
        max_amount_per_call: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        class: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_resource_ids: Option<Vec<String>>,
    },
}

/// A token's RFC 9396 authorization details.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RarAuthorizationDetails {
    pub details: Vec<RarAuthorizationDetail>,
}

/// The constraint keys an AAP capability recognises.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapConstraintsWire {
    /// Decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_assets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_chains: Option<Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_counterparties: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_resources: Option<Vec<String>>,
}

/// One AAP capability: an action and its constraints.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapCapabilityWire {
    pub action: String,
    /// Absent for an unconstrained action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<AapConstraintsWire>,
}

/// The AAP agent claim.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapAgentWire {
    pub id: String,
    #[serde(rename = "type")]
    pub agent_type: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

/// The AAP task claim.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapTaskWire {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// An AAP time window, Unix seconds.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapTimeWindowWire {
    pub nbf: u64,
    pub exp: u64,
}

/// The AAP context claim.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapContextWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<AapTimeWindowWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_restriction: Option<Vec<String>>,
}

/// The AAP audit claim.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AapAuditWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// The key a token is bound to.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenConfirmation {
    /// RFC 7638 thumbprint of the DPoP key.
    pub jkt: String,
}

/// RFC 7662 introspection: `{active: false}` alone for an inactive token, the
/// claim set for an active one.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenIntrospectionOutput {
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<TokenConfirmation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<RarAuthorizationDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_agent: Option<AapAgentWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_task: Option<AapTaskWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_capabilities: Option<Vec<AapCapabilityWire>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_delegation: Option<crate::mcp::server::DelegationClaimOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_context: Option<AapContextWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_audit: Option<AapAuditWire>,
}

// ─── Node access tokens ───

/// The answer to a sign-in challenge.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessSignInProof {
    /// A passkey assertion over the challenge, base64url fields.
    Passkey {
        account_address: String,
        credential_id: String,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    /// A hardware-key signature over the sign-in digest, hex fields.
    Device {
        public_key: String,
        signature: String,
    },
}

/// The hardware key a KYA credential was issued under.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KyaIssuer {
    /// The issuer's machine DID, derived from its key.
    pub id: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: EcP256Jwk,
}

/// A TPM's endorsement, attestation key and quote. Byte fields are arrays of
/// byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KyaTpmEvidence {
    pub ek_public: Vec<u8>,
    pub ek_certificate: Vec<u8>,
    pub ek_intermediates: Vec<Vec<u8>>,
    pub ak_public: Vec<u8>,
    pub quote: Vec<u8>,
    pub quote_signature: Vec<u8>,
}

/// A machine's recorded TPM attestation.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KyaTpmAttestation {
    pub evidence: KyaTpmEvidence,
    pub nonce: Vec<u8>,
    pub activated: bool,
}

/// How a KYA credential's subject is bound to its controller key.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type")]
pub enum KyaEvidence {
    /// The subject DID derives from the controller key.
    KeyDerivation,
    /// A TPM-admitted machine: its attestation binds the DID to the key.
    TpmAttestation { attestation: KyaTpmAttestation },
}

/// The agent a KYA credential is about.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KyaSubject {
    pub id: String,
    /// Hex.
    #[serde(rename = "controllerKey")]
    pub controller_key: String,
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub capabilities: Vec<String>,
    pub evidence: KyaEvidence,
}

/// A Know-Your-Agent credential (W3C VC 2.0, type
/// TenzroKnowYourAgentCredential) as a node issues it. Every member is covered
/// by its proof.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KyaCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: KyaIssuer,
    /// RFC 3339.
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    /// RFC 3339.
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: KyaSubject,
    pub proof: DataIntegrityProof,
}

/// A node access token issued for a sign-in.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessTokenIssuedOutput {
    pub access_token: String,
    /// `DPoP`.
    pub token_type: String,
    /// Seconds.
    pub expires_in: u64,
    pub did: String,
    /// The method classes the policy admits the DID to on some surface.
    pub classes: Vec<String>,
    pub jwk: AccessTokenJwk,
}

/// A live access token this node issued.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveAccessToken {
    pub jti: String,
    pub bearer_did: String,
    /// Unix ms.
    pub issued_at_ms: u64,
    /// Unix seconds.
    pub expires_at: u64,
}

/// The live access tokens this node issued.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveAccessTokensOutput {
    pub tokens: Vec<LiveAccessToken>,
}

// ─── Passkey accounts and keystores ───

/// How many passkeys approve a keystore change.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreSecondFactorPolicy {
    SingleCredential,
    TwoCredentials,
}

/// The role of a recovery signer.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreRecoveryRole {
    RecoveryKey,
    EmailVerifier,
    Device,
}

/// A passkey linked to an account. Byte fields are hex.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeystoreCredentialWire {
    pub rp_id: String,
    pub credential_id: String,
    /// P-256 `x || y`.
    pub public_key: String,
    pub aaguid: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// Block time (ms) from which it counts as an independent root.
    pub counts_as_root_from_ms: u64,
    pub label: String,
    #[serde(default)]
    pub added_at_ms: u64,
}

/// A key that may approve an account recovery. Byte fields are hex.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeystoreRecoverySigner {
    pub rp_id: String,
    pub public_key: String,
    pub aaguid: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub role: KeystoreRecoveryRole,
    pub label: String,
}

/// A recovery in progress.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeystorePendingRecovery {
    pub credential: KeystoreCredentialWire,
    /// Indices of the recovery signers that approved.
    pub approvers: Vec<u32>,
    pub started_at_ms: u64,
    pub ready_at_ms: u64,
}

/// An account's one-time recovery code commitment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeystoreRecoveryCode {
    /// Hex.
    pub commitment: String,
}

/// An account's keystore as consensus state holds it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeystoreRecordWire {
    /// The 20-byte account address, hex.
    pub account: String,
    pub owner_did: String,
    pub salt: u64,
    pub version: u64,
    pub credentials: Vec<KeystoreCredentialWire>,
    pub policy: KeystoreSecondFactorPolicy,
    pub recovery_signers: Vec<KeystoreRecoverySigner>,
    pub recovery_threshold: u32,
    pub pending_recovery: Option<KeystorePendingRecovery>,
    pub recovery_code: Option<KeystoreRecoveryCode>,
}

/// An account's first passkey, which derives the account. Byte fields are hex.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeystoreAnchorWire {
    pub rp_id: String,
    pub credential_id: String,
    /// P-256 `x || y`.
    pub public_key: String,
    pub aaguid: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub salt: u64,
}

/// A passkey-bound account after enrolment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PasskeyEnrolledOutput {
    pub did: String,
    /// `0x` hex.
    pub smart_account_address: String,
    /// `0x` hex.
    pub credential_id_hex: String,
    pub keystore: KeystoreRecordWire,
    /// The commitment the account's next KeystoreUpdate names, hex.
    pub keystore_commitment: String,
    /// The anchor the account's first KeystoreUpdate carries; null once the
    /// account has a keystore on chain.
    pub anchor: Option<KeystoreAnchorWire>,
}

/// A WebAuthn assertion. Byte fields are arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebAuthnAssertionWire {
    pub authenticator_data: Vec<u8>,
    /// `clientDataJSON` exactly as the client produced it.
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Vec<u8>>,
}

/// The approval of a custody challenge by a passkey enrolled on the account.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CustodyAuthorizationWire {
    pub challenge_id: String,
    pub credential_id_hex: String,
    /// The assertion over the challenge's webauthn_challenge.
    pub assertion: WebAuthnAssertionWire,
    /// The hardware ML-DSA-65 leg over the same digest, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_signature_hex: Option<String>,
    /// For an account with no keystore on chain yet: its first passkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<KeystoreAnchorWire>,
}

/// The state of a browser passkey ceremony.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasskeySessionStatus {
    Pending,
    InFlight,
    Completed,
    Failed,
    Expired,
}

/// The kind of a browser passkey ceremony.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasskeySessionKind {
    Enroll,
}

/// A browser passkey ceremony, created.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PasskeySessionCreatedOutput {
    pub session_id: String,
    /// The node-served page to open, `/auth/passkey?session=...`.
    pub verification_path: String,
    pub status: PasskeySessionStatus,
    /// Base64url.
    pub challenge_b64: String,
    pub expires_at_ms: u64,
}

/// A browser passkey ceremony and, once terminal, its outcome.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PasskeySessionOutput {
    pub session_id: String,
    pub kind: PasskeySessionKind,
    pub status: PasskeySessionStatus,
    /// The enrolment, once completed.
    pub result: Option<PasskeyEnrolledOutput>,
    /// Why it failed, once failed.
    pub error: Option<String>,
    pub expires_at_ms: u64,
}

// ─── Machine access ───

/// A resource a machine-access grant opens.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineResourceWire {
    /// A network range, optionally one port.
    Network {
        cidr: String,
        #[serde(default)]
        port: Option<u16>,
    },
    /// A folder.
    Folder { path: String },
    /// A device node.
    Device { path: String },
}

/// Limits on each use of one named operation.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineOperationBound {
    pub operation: String,
    /// The values a use may carry; empty places no limit.
    pub allowed_values: Vec<String>,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub max_per_hour: Option<u32>,
}

/// The terms of a machine-access grant, as the owner signs them.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineGrantTerms {
    pub grantee_did: String,
    pub resources: Vec<MachineResourceWire>,
    /// connect for networks; read and/or write for folders.
    pub operations: Vec<String>,
    /// Unix ms.
    pub expires_at_ms: i64,
    #[serde(default)]
    pub max_uses_per_minute: Option<u32>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Machine grants take none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_bounds: Vec<MachineOperationBound>,
}

/// The machine-access change a custody challenge is for.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum MachineAccessChangeWire {
    /// Add a grant with these terms.
    Add(MachineGrantTerms),
    /// List the grants.
    List,
    /// Revoke a grant.
    Revoke { grant_id: String },
}

/// A machine-access grant with its meters.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineGrantSummary {
    pub grant_id: String,
    pub owner_did: String,
    pub grantee_did: String,
    pub resources: Vec<MachineResourceWire>,
    pub operations: Vec<String>,
    pub max_uses_per_minute: Option<u32>,
    pub max_bytes: Option<u64>,
    pub operation_bounds: Vec<MachineOperationBound>,
    /// RFC 3339.
    pub not_after: Option<String>,
    /// RFC 3339.
    pub created_at: String,
    pub revoked: bool,
    /// RFC 3339.
    pub revoked_at: Option<String>,
    pub uses: u64,
    pub refusals: u64,
    pub bytes: u64,
}

/// The machine-access grants on this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineGrantsOutput {
    pub grants: Vec<MachineGrantSummary>,
}

// ─── Delegated agent terms ───

/// A per-chain daily limit on remote grants.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRemoteLimit {
    pub caip19: String,
    /// Decimal string.
    pub max_per_day: String,
}

/// A per-asset limit.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentAssetLimit {
    pub asset: String,
    /// Decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_tx: Option<String>,
    /// Decimal string.
    pub max_per_day: String,
    #[serde(default)]
    pub min_counterparty_kyc_tier: u8,
}

/// What an agent may do in governance.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentGovernanceScope {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub may_vote: bool,
    #[serde(default)]
    pub may_veto_signal: bool,
    #[serde(default)]
    pub may_originate: bool,
    #[serde(default)]
    pub max_weight_bps: u16,
    #[serde(default)]
    pub policy_hash: String,
}

/// The KYC tier a counterparty must hold.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentKycRequirement {
    pub min_tier: u8,
    pub registry: String,
}

/// A tool the agent may call only at this digest.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentToolPin {
    pub server: String,
    pub name: String,
    pub digest: String,
}

/// The limits an agent acts within. Amounts are decimal strings; every field
/// may be omitted.
#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTermsScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transaction_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hourly_spend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_actions_per_hour: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_actions_per_day: Option<u32>,
    /// `[start, end]` hours, UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_hours_utc: Option<[u8; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_above: Option<String>,
    #[serde(default)]
    pub step_up_new_counterparty: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tainted_value_limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_grant_ttl_ms: Option<u64>,
    #[serde(default)]
    pub remote_limits: Vec<AgentRemoteLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosign_above: Option<String>,
    #[serde(default)]
    pub asset_limits: Vec<AgentAssetLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<AgentGovernanceScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_kyc: Option<AgentKycRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_split_fee_bps: Option<u16>,
    #[serde(default)]
    pub tool_pins: Vec<AgentToolPin>,
}

/// A machine that serves an agent. The node completes the key fields.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentServingNode {
    pub machine_did: String,
    pub operator_did: String,
    #[serde(default)]
    pub dpop_public_key: String,
    #[serde(default)]
    pub dpop_jkt: String,
    #[serde(default)]
    pub key_certification: String,
    #[serde(default)]
    pub sealing_public_key: String,
}

/// A credential sealed to one serving node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentSealedForNode {
    pub machine_did: String,
    pub envelope: String,
}

/// A credential the serving nodes attach to requests to one host.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentBrokeredCredential {
    pub name: String,
    pub host: String,
    pub header: String,
    pub sealed: Vec<AgentSealedForNode>,
}

/// A delegated agent's terms.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTermsWire {
    pub controller_did: String,
    pub agent_name: String,
    #[serde(default)]
    pub delegation_scope: AgentTermsScope,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub serving_nodes: Vec<AgentServingNode>,
    /// One when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_distinct_operators: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub trifecta_exception: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_approve: Option<AgentTermsScope>,
    #[serde(default)]
    pub credentials: Vec<AgentBrokeredCredential>,
}

// ─── Governance proposals and records ───

/// The rules a proposal was opened under.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovRules {
    pub voting_period_ms: i64,
    pub expedited_voting_period_ms: i64,
    pub timelock_ms: i64,
    pub expedited_timelock_ms: i64,
    pub ratify_timelock_ms: i64,
    pub quorum_bps: u64,
    pub threshold_bps: u64,
    pub expedited_threshold_bps: u64,
    pub ratify_threshold_bps: u64,
    pub min_bond_age_ms: i64,
    pub large_spend_tnzo: u64,
    pub large_spend_approval_bps: u64,
    pub large_spend_timelock_ms: i64,
}

/// A proposal's track.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovProposalTrack {
    Standard,
    Expedited,
    Ratify,
    SecurityFix,
}

/// A proposal's status.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovProposalStatus {
    Voting,
    Passed,
    Queued,
    Vetoed,
    Rejected,
    Executed,
    Contested,
}

/// How a treasury grant vests.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovGrantVesting {
    Liquid,
    Grant,
    Contributor,
}

/// What a security fix rests on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GovSecurityBasis {
    Fault { fault_id: String },
    Vulnerability { commitment: String },
}

/// The track a policy update is enacted on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GovPolicyTrack {
    Standard,
    Expedited,
    SecurityFix { basis: GovSecurityBasis },
}

/// A guardian seat's role.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovGuardianRole {
    Protocol,
    Governance,
    Steward,
}

/// A bridge adapter.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GovBridgeAdapter {
    Ccip,
    Ibc,
    Deposit,
    Contract,
}

/// Whether a bridge route admits transfers.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovBridgeRouteMode {
    Open,
    Disabled,
    Paused,
}

/// A source chain's family.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovChainFamily {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
    Stellar,
    Sui,
    Aptos,
    Ton,
}

/// The light-client anchor a route verifies against. Hashes and keys are
/// arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovLightClientAnchor {
    EthereumSyncCommittee {
        genesis_validators_root: Vec<u8>,
        fork_version: Vec<u8>,
        trusted_block_root: Vec<u8>,
    },
    Tendermint {
        chain_id: String,
        trusted_height: u64,
        trusted_header_hash: Vec<u8>,
        trusting_period_secs: u64,
    },
    BitcoinHeaders {
        trusted_height: u64,
        trusted_header_hash: Vec<u8>,
        confirmations: u32,
        signers: Vec<Vec<u8>>,
        threshold: u32,
        fee_rate: u64,
    },
    SuiCommittee {
        trusted_checkpoint_digest: Vec<u8>,
    },
    AptosValidators {
        trusted_ledger_info_hash: Vec<u8>,
    },
    StellarScp {
        network_id: Vec<u8>,
        validators: Vec<Vec<u8>>,
        threshold: u32,
    },
    TonKeyBlock {
        trusted_seqno: u32,
        trusted_root_hash: Vec<u8>,
    },
}

/// A route verifier. `address` is an array of 20 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovVerifierMember {
    pub address: Vec<u8>,
    pub operator: String,
    pub rpc_provider: String,
}

/// A route's verifier quorum.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovVerifierQuorum {
    pub set_index: u32,
    pub size: u32,
    pub members: Vec<GovVerifierMember>,
    pub threshold: u32,
}

/// Mint limits, smallest units.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovMintRateLimit {
    pub per_mint: ChainWei,
    pub per_epoch: ChainWei,
}

/// A token-bucket limit, smallest units.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovLaneRateLimit {
    pub capacity: ChainWei,
    pub rate: ChainWei,
}

/// A CCIP lane version.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GovCcipLaneVersion {
    #[serde(rename = "2.0.0")]
    V2_0,
    #[serde(rename = "1.6.0")]
    V1_6,
    #[serde(rename = "1.5.0")]
    V1_5,
}

/// A CCIP lane. Addresses and hashes are arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovCcipLane {
    pub version: GovCcipLaneVersion,
    pub off_ramp: Vec<u8>,
    pub ccv_and_executor_hash: Vec<u8>,
    pub inbound: GovLaneRateLimit,
}

/// An IBC version.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovIbcVersion {
    Classic,
    V2,
}

/// An IBC route.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovIbcRoute {
    pub version: GovIbcVersion,
    pub counterparty_client_id: String,
    pub counterparty_connection_id: Option<String>,
    pub counterparty_channel_id: Option<String>,
    pub packet_timeout_secs: u64,
}

/// How a carried asset moves.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovAssetTransfer {
    LockAndMint,
    BurnAndMint { protocol: String, operator: String },
}

/// A per-asset lane limit.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovAssetLane {
    pub inbound: GovLaneRateLimit,
}

/// An asset a route carries. `pool` and `remote_token` are arrays of byte
/// values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovCarriedAsset {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub pool: Vec<u8>,
    pub remote_token: Vec<u8>,
    pub caip19: String,
    pub transfer: GovAssetTransfer,
    pub mint_limit: GovMintRateLimit,
    pub outflow: GovLaneRateLimit,
    pub lane: Option<GovAssetLane>,
    pub max_outstanding: ChainWei,
    pub enabled: bool,
}

/// A bridge route. 32-byte fields are arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovBridgeRoute {
    pub adapter: GovBridgeAdapter,
    pub family: GovChainFamily,
    pub source_chain: String,
    pub source_chain_id: u64,
    pub local_selector: u64,
    pub peer: Vec<u8>,
    pub ramp: Vec<u8>,
    pub local_endpoint: Vec<u8>,
    pub remote_token: Vec<u8>,
    pub verifiers: GovVerifierQuorum,
    pub blessing: Option<GovVerifierQuorum>,
    pub light_client: Option<GovLightClientAnchor>,
    pub mint_limit: GovMintRateLimit,
    pub outflow: GovLaneRateLimit,
    pub lane_limits: Option<GovCcipLane>,
    pub ibc: Option<GovIbcRoute>,
    pub settlement_lock: Option<Vec<u8>>,
    #[serde(default)]
    pub assets: Vec<GovCarriedAsset>,
    #[serde(default)]
    pub native_asset: Option<String>,
}

/// Mint limits for proven and attested routes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovNetworkMintLimits {
    pub proven: GovMintRateLimit,
    pub attested: GovMintRateLimit,
    /// Ceiling on every route whose destination verifies only classical
    /// signatures.
    pub classical: GovMintRateLimit,
}

/// An outflow cap per epoch for one unit.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovOutflowCap {
    pub unit: String,
    pub per_epoch: ChainWei,
}

/// Network outflow limits.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovNetworkOutflowLimits {
    pub caps: Vec<GovOutflowCap>,
}

/// A network policy change. Externally tagged by the variant name.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GovPolicyUpdate {
    /// `code_hash` is an array of 32 byte values.
    ProtocolUpgrade {
        version: String,
        code_hash: Vec<u8>,
    },
    EconomicPolicyUpdate {
        policy: EconomicPolicyRates,
    },
    AdaptiveBurnConfigUpdate {
        base_fee_burn_bps: u16,
        local_fee_burn_bps: u16,
    },
    SupplyTargetsUpdate {
        epoch_neutral_band_bps: u16,
        rolling_window_epochs: u32,
        inflation_alarm_bps: u16,
        deflation_alarm_bps: u16,
        target_annual_supply_bps: i32,
        gain_bps_per_pct: u16,
        magnitude_cap_normal_bps: u16,
        magnitude_cap_alarm_bps: u16,
        auto_proposal_min_magnitude_bps: u16,
        alarm_fast_track_enabled: bool,
    },
    TpmEndorsementRootsSet {
        roots_pem: Vec<String>,
    },
    BridgeCircuitSet {
        adapter: GovBridgeAdapter,
        source_chain: String,
        mode: GovBridgeRouteMode,
        reason: String,
    },
    BridgeMintLimitsSet {
        limits: GovNetworkMintLimits,
    },
    BridgeOutflowLimitsSet {
        limits: GovNetworkOutflowLimits,
    },
    /// `image_id` is hex.
    FinalityProgramSet {
        image_id: String,
    },
}

/// Where an agent account is deployed on a chain family. Byte fields are
/// arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum GovAccountDeployment {
    Eip155 {
        factory: Vec<u8>,
        init_code_hash: Vec<u8>,
    },
    Solana {
        program_id: Vec<u8>,
    },
    Sui {
        registry: Vec<u8>,
    },
    Aptos {
        creator: Vec<u8>,
    },
    Stellar {
        network_passphrase: String,
        factory: Vec<u8>,
    },
    Cosmos {
        hrp: String,
        factory: Vec<u8>,
        code_checksum: Vec<u8>,
    },
    Tvm {
        workchain: i8,
        code_hash: Vec<u8>,
        code_depth: u16,
    },
}

/// The route an agent account reports through.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovReportRoute {
    pub adapter: GovBridgeAdapter,
    pub source_chain: String,
}

/// A chain agent accounts are opened on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovAgentAccountChain {
    pub caip2: String,
    pub deployment: GovAccountDeployment,
    pub open: bool,
    #[serde(default)]
    pub report_route: Option<GovReportRoute>,
}

/// A call the treasury makes on another chain.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovRemoteAction {
    /// Hex.
    pub target: String,
    /// Hex.
    pub selector: String,
    /// Decimal string.
    pub amount: String,
    /// Decimal string.
    pub relay_refund: String,
    /// Hex.
    pub data: String,
}

/// The signers of a rate stream.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovRateStreamSigners {
    /// Hex.
    pub feed_id: String,
    pub symbol: String,
    /// 20-byte addresses, hex.
    pub signers: Vec<String>,
    pub threshold: u8,
}

/// A Proof-of-Reserve feed.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovReserveFeed {
    pub asset_id: String,
    pub aggregator_address: String,
    pub chain_caip2: String,
    pub decimals: u8,
    pub max_staleness_secs: u64,
}

/// What a proposal does. Addresses are arrays of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum GovProposalAction {
    RecoverUnownedFunds {
        from: Vec<u8>,
        to: Vec<u8>,
        amount: ChainWei,
        memo: String,
    },
    ParameterChange {
        key: String,
        value: u64,
        memo: String,
    },
    TreasuryGrant {
        recipient: Vec<u8>,
        amount: ChainWei,
        memo: String,
        category: String,
        link: String,
        /// Decimal strings.
        tranches: Vec<String>,
        /// The milestone each payment is for, one per tranche (one when
        /// there are none).
        milestones: Vec<String>,
        vesting: GovGrantVesting,
        /// Settlement asset token id the grant pays in; absent pays TNZO.
        #[serde(default)]
        asset: Option<String>,
        /// How later tranches are released; absent means one release
        /// proposal per tranche.
        #[serde(default)]
        release: GovGrantRelease,
    },
    ReleaseGrantTranche {
        grant_id: String,
        index: u32,
        memo: String,
    },
    PolicyUpdate {
        update: GovPolicyUpdate,
        memo: String,
        track: GovPolicyTrack,
    },
    RevokeIdentity {
        did: String,
        reason: String,
    },
    SetNetworkPayout {
        rail: String,
        destination: String,
        memo: String,
    },
    SetBridgeRoute {
        route: GovBridgeRoute,
        memo: String,
    },
    SetAgentAccountChain {
        chain: GovAgentAccountChain,
        memo: String,
    },
    TreasuryRemoteAction {
        caip2: String,
        caip19: String,
        remote: GovRemoteAction,
        ttl_ms: u64,
        /// Required when the action moves value: the approved operator paid.
        #[serde(default)]
        payout: Option<GovRemotePayout>,
        memo: String,
    },
    SetGuardian {
        address: Vec<u8>,
        did: String,
        role: GovGuardianRole,
        term_ends_ms: i64,
        key_root: GuardianSeatKeyRoot,
        memo: String,
    },
    RemoveGuardian {
        address: Vec<u8>,
        memo: String,
    },
    RemoveBridgeRoute {
        adapter: GovBridgeAdapter,
        source_chain: String,
        memo: String,
    },
    SetRateStream {
        stream: GovRateStreamSigners,
        memo: String,
    },
    RetireRegistryEntry {
        id: String,
        memo: String,
    },
    RemoveRateStream {
        /// Hex.
        feed_id: String,
        memo: String,
    },
    SetReserveFeed {
        feed: GovReserveFeed,
        memo: String,
    },
    RemoveReserveFeed {
        asset_id: String,
        memo: String,
    },
    RunningCostPayment {
        recipient: Vec<u8>,
        from_epoch: u64,
        to_epoch: u64,
        amount: ChainWei,
        memo: String,
        link: String,
    },
    ApproveValidators {
        accounts: Vec<Vec<u8>>,
        approve: bool,
        memo: String,
    },
    SponsorValidatorBond {
        validator: Vec<u8>,
        amount: ChainWei,
        memo: String,
    },
    RecallSponsoredBond {
        validator: Vec<u8>,
        amount: ChainWei,
        memo: String,
    },
    ApproveOperator {
        operator: Vec<u8>,
        class: GovOperatorClass,
        criteria: GovOperatorCriteria,
        memo: String,
    },
    RevokeOperator {
        operator: Vec<u8>,
        memo: String,
    },
    ReinstateValidator {
        /// The jailed validator, an array of 32 byte values.
        validator: Vec<u8>,
        memo: String,
    },
    ApproveGrantee {
        grantee: Vec<u8>,
        class: GovGranteeClass,
        criteria: GovGranteeCriteria,
        memo: String,
    },
    RevokeGrantee {
        grantee: Vec<u8>,
        memo: String,
    },
    SponsorOperatorRunningCost {
        operator: Vec<u8>,
        from_epoch: u64,
        to_epoch: u64,
        amount: ChainWei,
        memo: String,
    },
    SponsorOperatorStable {
        operator: Vec<u8>,
        from_epoch: u64,
        to_epoch: u64,
        /// The settlement asset token id (0x and 64 hex digits).
        token_id: String,
        /// In the asset's smallest unit.
        amount: ChainWei,
        /// Ask for the governed per-proposal headroom above the period
        /// limit.
        #[serde(default)]
        period_exception: bool,
        memo: String,
    },
}

/// How a tranched grant's later payments are released.
#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GovGrantRelease {
    /// One release proposal per tranche.
    #[default]
    Governed,
    /// Tranches are released against milestones the named verifiers record.
    Scheduled {
        verifiers: Vec<Vec<u8>>,
        threshold: u32,
    },
}

/// What a treasury remote action pays.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovRemotePayout {
    pub payee: Vec<u8>,
    pub from_epoch: u64,
    pub to_epoch: u64,
    /// The settlement asset token id that prices the remote asset.
    pub priced_by: String,
}

/// What an approved operator is.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovOperatorClass {
    Validator,
    Provider,
}

/// The published criteria an operator approval rests on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovOperatorCriteria {
    pub provider_did: String,
    pub region: String,
    pub history_from_epoch: u64,
    pub history_to_epoch: u64,
    pub independence: String,
    pub link: String,
}

/// What an approved grantee does.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovGranteeClass {
    Developer,
    Contributor,
    Community,
}

/// The published basis of a grantee approval.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovGranteeCriteria {
    pub summary: String,
    pub link: String,
}

/// A governance proposal as stored. `proposer` is an array of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovProposal {
    pub id: String,
    pub proposer: Vec<u8>,
    pub track: GovProposalTrack,
    pub eta_ms: Option<i64>,
    pub action: GovProposalAction,
    pub created_ms: i64,
    pub voting_ends_ms: i64,
    pub status: GovProposalStatus,
    pub queued_ms: Option<i64>,
    pub veto_extension_ms: i64,
    pub concerns: u32,
    pub concern_doubled: bool,
    pub rules: GovRules,
}

/// A proposal's running tally, decimal strings.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovTally {
    pub yes: String,
    pub no: String,
    pub total_eligible: String,
}

/// A proposal with its tally and the stake locked behind vetoes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovProposalView {
    pub proposal: GovProposal,
    /// The action's kind, e.g. policy_update or treasury_grant.
    pub kind: String,
    pub tally: GovTally,
    /// Decimal string.
    pub veto_locked: String,
}

/// A page of proposals, newest first.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovProposalsOutput {
    pub proposals: Vec<GovProposalView>,
    pub total: u64,
    /// The `before` that reads the next page; null on the last.
    pub next: Option<u64>,
}

/// The last enacted change of a network policy.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovPolicyEnacted {
    pub proposal_id: String,
    pub update: GovPolicyUpdate,
}

/// A tranched treasury grant. `recipient` is an array of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovGrantRecord {
    pub recipient: Vec<u8>,
    /// Decimal strings.
    pub tranches: Vec<String>,
    /// The milestone each tranche is paid against.
    pub milestones: Vec<String>,
    /// Tranches paid so far.
    pub paid: u32,
    pub vesting: GovGrantVesting,
}

/// One validator machine's readiness for a binary.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovReadySignal {
    /// Hex.
    pub validator: String,
    pub machine_did: String,
    /// Hex.
    pub pcr_digest: String,
    pub height: u64,
}

/// A scheduled protocol upgrade.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovUpgradeActivation {
    pub proposal_id: String,
    pub version: String,
    pub code_hash: String,
    pub readiness_met_height: u64,
    pub activation_height: u64,
}

/// How much bonded stake runs a binary.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovUpgradeReadiness {
    /// Hex.
    pub code_hash: String,
    /// Decimal string.
    pub ready_stake: String,
    /// Decimal string.
    pub total_bonded: String,
    pub ready_bps: u64,
    pub required_bps: u64,
    pub met: bool,
    pub signals: Vec<GovReadySignal>,
    /// The latest scheduled activation, of any binary.
    pub scheduled: Option<GovUpgradeActivation>,
    pub this_node_runs_it: bool,
}

/// The end of a state proof path.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GovProofTerminal {
    /// No entry on the path.
    Empty,
    /// Another stem sits on the path. Byte arrays of values.
    OtherStem { stem: Vec<u8>, slots_root: Vec<u8> },
    /// The entry's stem: the eight sibling hashes of its slot.
    Stem { slot_siblings: Vec<Vec<u8>> },
}

/// A state proof under a state root. Hashes are arrays of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovStateProof {
    pub siblings: Vec<Vec<u8>>,
    pub terminal: GovProofTerminal,
}

/// A record proven under the certified state.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovProvenRecord {
    /// proposal, decision, ...
    pub kind: String,
    pub subject: String,
    pub slot: String,
    /// The stored value, hex; null when absent.
    pub value: Option<String>,
    pub proof: GovStateProof,
}

/// A validator's composite key: ML-DSA-65 and P-256, arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovValidatorKey {
    pub ml_dsa: Vec<u8>,
    pub p256: Vec<u8>,
}

/// A composite signature: ML-DSA-65 and P-256 legs, arrays of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovValidatorSignature {
    pub ml_dsa: Vec<u8>,
    pub p256: Vec<u8>,
}

/// A committee member. `address` is an array of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovCommitteeMember {
    pub address: Vec<u8>,
    pub public_key: GovValidatorKey,
    /// Wei; serialized only when it fits in 64 bits.
    pub stake: u64,
    pub seats: u64,
}

/// A validator's session key for one epoch, signed by its hardware key.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovSessionCertificate {
    pub chain_id: u64,
    pub genesis_hash: Vec<u8>,
    pub epoch: u64,
    pub validator: Vec<u8>,
    pub session_key: GovValidatorKey,
    pub signature: GovValidatorSignature,
}

/// A checkpoint and the seat signatures certifying it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovCheckpointCertificate {
    pub checkpoint: CheckpointBody,
    pub signers: Vec<u16>,
    /// Session certificate digests, arrays of 32 byte values.
    pub sessions: Vec<Vec<u8>>,
    pub signatures: Vec<GovValidatorSignature>,
}

/// One epoch's handover to the next committee.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovEpochHandover {
    pub certificate: GovCheckpointCertificate,
    pub sessions: Vec<GovSessionCertificate>,
    pub next_members: Vec<GovCommitteeMember>,
}

/// The proof from genesis that a checkpoint is certified.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovCheckpointProof {
    pub genesis_members: Vec<GovCommitteeMember>,
    pub handovers: Vec<GovEpochHandover>,
    pub certificate: GovCheckpointCertificate,
    pub sessions: Vec<GovSessionCertificate>,
}

/// A proposal's records, proven under the latest certified state, with that
/// checkpoint's proof from genesis.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GovReceipt {
    pub proposal_id: String,
    pub state_height: u64,
    /// Hex.
    pub state_root: String,
    pub checkpoint: GovCheckpointProof,
    pub records: Vec<GovProvenRecord>,
}

/// What governance_get read, by kind.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum GovRecordOutput {
    /// kind receipt.
    Receipt(GovReceipt),
    /// kind proposal.
    Proposal(GovProposalView),
    /// kind readiness.
    Readiness(GovUpgradeReadiness),
    /// kind grant.
    Grant(GovGrantRecord),
    /// kind policy.
    Policy(GovPolicyEnacted),
}

// ─── Transactions and TEE providers ───

/// A transaction this node holds, finalized or in its mempool.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChainTransactionOutput {
    /// As the caller gave it.
    pub hash: String,
    pub from: String,
    pub to: String,
    /// Amount a transfer moves, decimal string; "0" for other kinds.
    pub value: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub chain_id: u64,
    /// The transaction kind, e.g. Transfer.
    #[serde(rename = "type")]
    pub tx_type: String,
    /// The kind's fields; integers above 2^53 as decimal strings and byte
    /// strings of 16 bytes or more as hex, so each field's JSON type follows
    /// its value. Null for a kind without fields.
    pub payload: super::server::JsonValue,
    /// finalized or pending.
    pub status: String,
    /// Hex.
    pub public_key: String,
    pub signature: HardwareCompositeSignature,
}

/// A TEE provider record stored under a `tee:` key.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeProviderEntry {
    pub id: String,
    /// The stored record, as its writer stored it.
    pub info: super::server::JsonValue,
}

/// TEE providers and this machine's own TEE.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeeProvidersOutput {
    pub providers: Vec<TeeProviderEntry>,
    pub total: u64,
    pub local_tee_available: bool,
    /// The local TEE vendor, when there is one.
    pub local_vendor: Option<String>,
}

// ─── Resolved identities ───

/// One public key of an identity.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityPublicKey {
    pub key_id: String,
    pub key_type: String,
    /// Hex.
    pub public_key: String,
}

/// What a trust credential's claim is about.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TrustClaimKind {
    Certification,
    Rating,
    Evaluation,
    SafetyScan,
    PolicyConformance,
}

/// A verifiable reference to the report behind a claim.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustClaimEvidence {
    pub uri: String,
    /// Hex SHA-256 of the report bytes.
    pub sha256: String,
}

/// The statement a trust credential makes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustClaim {
    pub kind: TrustClaimKind,
    /// The issuer's scheme identifier (a standard, benchmark or programme).
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    /// 0 to 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<TrustClaimEvidence>,
}

/// Where a trust credential stands now.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TrustCredentialState {
    Valid,
    NotYetValid,
    Expired,
    Revoked,
    IssuerRevoked,
}

/// A trust credential issued about an identity.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityCredentialSummary {
    pub digest: String,
    pub issuer: String,
    pub claim: TrustClaim,
    /// RFC 3339.
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    pub state: TrustCredentialState,
}

/// A service an identity publishes in its DID document.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityService {
    /// `<did>#<service id>`.
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
}

/// An identity resolved from the registry or the ledger.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResolvedIdentityOutput {
    pub did: String,
    pub status: String,
    pub is_human: bool,
    pub is_machine: bool,
    pub display_name: String,
    pub key_count: u64,
    pub service_count: u64,
    pub public_keys: Vec<IdentityPublicKey>,
    pub credentials: Vec<IdentityCredentialSummary>,
    pub services: Vec<IdentityService>,
    pub metadata: std::collections::BTreeMap<String, String>,
}
