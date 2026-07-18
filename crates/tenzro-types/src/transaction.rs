//! Transaction types for Tenzro Network
//!
//! This module defines the transaction structure and related types used
//! to represent state transitions on the Tenzro Network blockchain.

use crate::asset::AssetId;
use crate::primitives::{Address, Hash, Nonce, Signature, Timestamp, ChainId};
use crate::settlement::{ReleaseConditions, ServiceProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum transaction data size in bytes (128 KB)
pub const MAX_TX_DATA_SIZE: usize = 131_072;

/// A transaction on Tenzro Network
///
/// Transactions represent actions taken by accounts, including transfers,
/// smart contract calls, agent operations, and model inference requests.
///
/// # Note
/// The `Default` implementation creates a transaction with zero values
/// and is intended for testing purposes only. Production transactions
/// should be created with `Transaction::new()` and properly signed.
///
/// # Post-quantum migration
///
/// The `pq_public_key` field carries the ML-DSA-65 verifying key bytes
/// (FIPS 204, exactly 1952 bytes) and is **mandatory**. Tenzro Network does
/// not support classical-only transactions — the field has no `Option`
/// wrapper and no `serde(default)`. Decoders reject any payload that omits
/// or mis-sizes this field. There is no legacy fallback: a classical-only
/// transaction cannot be constructed in this codebase and cannot be parsed
/// from any external source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// The chain ID this transaction is valid for
    pub chain_id: ChainId,
    /// The sender's address
    pub from: Address,
    /// The recipient's address (or contract address)
    pub to: Address,
    /// The nonce for replay protection
    pub nonce: Nonce,
    /// The transaction type and payload
    pub tx_type: TransactionType,
    /// Maximum gas to spend
    pub gas_limit: u64,
    /// Gas price in the smallest unit of TNZO
    pub gas_price: u64,
    /// Transaction timestamp
    pub timestamp: Timestamp,
    /// Optional memo or metadata
    pub memo: Option<String>,
    /// ML-DSA-65 verifying key bytes (FIPS 204, exactly 1952 bytes).
    /// Bound into the `hash()` preimage so a hybrid signer commits to the PQ
    /// key before signing and any key-substitution attempt invalidates the
    /// transaction.
    #[serde(deserialize_with = "crate::validation::bounded_pq_public_key_bytes")]
    pub pq_public_key: Vec<u8>,
}

impl Transaction {
    /// Creates a new transaction. The `pq_public_key` is the ML-DSA-65
    /// verifying key bytes (FIPS 204, exactly 1952 bytes) and is mandatory —
    /// classical-only transactions are not constructible.
    pub fn new(
        chain_id: ChainId,
        from: Address,
        to: Address,
        nonce: Nonce,
        tx_type: TransactionType,
        gas_limit: u64,
        gas_price: u64,
        pq_public_key: Vec<u8>,
    ) -> Self {
        Self {
            chain_id,
            from,
            to,
            nonce,
            tx_type,
            gas_limit,
            gas_price,
            timestamp: Timestamp::now(),
            memo: None,
            pq_public_key,
        }
    }

    /// Adds a memo to the transaction
    pub fn with_memo(mut self, memo: String) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Computes the SHA-256 hash of the transaction.
    ///
    /// The preimage layout is the canonical signing surface for the network.
    /// The mandatory ML-DSA-65 verifying key (`pq_public_key`) is included
    /// with an explicit `u32` little-endian length prefix so the preimage
    /// is unambiguous and a key-substitution attempt invalidates the hash.
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(self.chain_id.0.to_le_bytes());
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(self.nonce.0.to_le_bytes());
        hasher.update(self.gas_limit.to_le_bytes());
        hasher.update(self.gas_price.to_le_bytes());
        hasher.update(self.timestamp.0.to_le_bytes());
        // Include tx_type via JSON serialization for deterministic encoding
        if let Ok(tx_type_json) = serde_json::to_vec(&self.tx_type) {
            hasher.update(&tx_type_json);
        }
        if let Some(ref memo) = self.memo {
            hasher.update(memo.as_bytes());
        }
        // PQ-binding: explicit length prefix is canonical even though the
        // field is fixed-size — keeps the preimage shape stable if FIPS 204
        // ever moves to a variant with a different key length.
        hasher.update((self.pq_public_key.len() as u32).to_le_bytes());
        hasher.update(&self.pq_public_key);
        let result = hasher.finalize();
        Hash::new(result.into())
    }
}

/// The type and payload of a transaction.
///
/// Different transaction types enable different operations on Tenzro Network.
///
/// Uses serde's default externally-tagged enum representation
/// (`{"Transfer": {...}}` in JSON, `u32` discriminant + payload in bincode).
/// Adjacently-tagged form (`#[serde(tag = "type", content = "data")]`) is
/// incompatible with bincode 1.x — see `tenzro_network::message::MessagePayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Transfer TNZO tokens
    Transfer {
        /// Amount to transfer in the smallest unit
        amount: u128,
    },
    /// Deploy a smart contract
    ContractDeploy {
        /// Contract bytecode
        code: Vec<u8>,
        /// Constructor arguments
        args: Vec<u8>,
    },
    /// Call a smart contract
    ContractCall {
        /// Function signature
        function: String,
        /// Function arguments
        args: Vec<u8>,
    },
    /// Register an AI agent
    AgentRegister {
        /// Agent configuration
        config: Vec<u8>,
    },
    /// Execute an agent task
    AgentExecute {
        /// Task specification
        task: Vec<u8>,
    },
    /// Request model inference
    ModelInference {
        /// Model identifier
        model_id: String,
        /// Inference input
        input: Vec<u8>,
    },
    /// Register as a TEE provider
    TeeProviderRegister {
        /// Attestation data
        attestation: Vec<u8>,
        /// Provider info
        info: Vec<u8>,
    },
    /// Stake tokens for provider operations
    ProviderStake {
        /// Amount to stake
        amount: u128,
        /// Provider type
        provider_type: String,
    },
    /// Unstake tokens
    ProviderUnstake {
        /// Amount to unstake
        amount: u128,
    },
    /// Submit a governance proposal
    GovernancePropose {
        /// Proposal data
        proposal: Vec<u8>,
    },
    /// Vote on a governance proposal
    GovernanceVote {
        /// Proposal ID
        proposal_id: String,
        /// Vote value
        vote: bool,
    },
    /// Initiate a bridge transfer
    BridgeTransfer {
        /// Target chain
        target_chain: String,
        /// Target address
        target_address: String,
        /// Amount to bridge
        amount: u128,
    },
    /// Create a new escrow account, locking funds from the payer
    ///
    /// The escrow_id is derived deterministically by the VM as
    /// `SHA-256("tenzro/escrow/id" || payer || nonce_le)` and the funds are
    /// transferred to a vault address derived as
    /// `Address(SHA-256("tenzro/escrow/vault" || escrow_id)[..20])`.
    ///
    /// Authorization: `tx.from` must equal the payer (enforced by signature verification).
    CreateEscrow {
        /// Recipient of funds upon successful release
        payee: Address,
        /// Amount to lock in escrow
        amount: u128,
        /// Asset being escrowed
        asset_id: AssetId,
        /// Unix timestamp (millis) at which the escrow expires
        expires_at: u64,
        /// Conditions for releasing funds to the payee
        release_conditions: ReleaseConditions,
    },
    /// Release escrowed funds to the payee with a proof of service
    ///
    /// Authorization: `tx.from` must equal the original payer.
    ReleaseEscrow {
        /// 32-byte deterministic escrow identifier
        escrow_id: [u8; 32],
        /// Proof satisfying the escrow's release conditions
        proof: ServiceProof,
    },
    /// Refund escrowed funds to the payer
    ///
    /// Authorization: `tx.from` must equal the original payer AND the escrow must
    /// either be expired or use Timeout/Custom release conditions.
    RefundEscrow {
        /// 32-byte deterministic escrow identifier
        escrow_id: [u8; 32],
    },
    /// Pause an agent (Agent-Swarm Spec 1, tier 1).
    ///
    /// Reversible state. Agent stops accepting new tasks; existing
    /// obligations are honored under the pause-bypass allow-list. Stake
    /// untouched. Inbound payments still permitted; outbound payments
    /// blocked.
    ///
    /// Authorization: `tx.from` MUST equal the agent's controller DID
    /// (or hold a `DelegationScope.allowed_operations` entry of
    /// `pause_agent`). Network-initiated pauses are not allowed — escalate
    /// to Quarantine instead.
    PauseAgent {
        /// DID of the agent to pause (`did:tenzro:machine:...`)
        agent_did: String,
        /// DID of the authorising controller. Must match the identity
        /// bound to `tx.from`; echoed on the wire so the receipt is
        /// self-describing and the VM does not need an identity lookup.
        controller_did: String,
        /// Canonical reason code (see kill-switch spec §"Reason codes")
        reason_code: u16,
        /// Optional human reason text, capped at 256 bytes
        reason_text: Option<String>,
        /// Optional pause expiry; `None` means indefinite (capped by
        /// governance `pause_max_duration`).
        until: Option<Timestamp>,
    },
    /// Quarantine an agent (Agent-Swarm Spec 1, tier 2).
    ///
    /// Reversible only after evidence review. Inbound + outbound payments
    /// blocked. Stake frozen — cannot withdraw, cannot earn rewards.
    /// Existing tasks halt.
    ///
    /// Authorization: controller (as PauseAgent), OR slashing-committee
    /// quorum via `StakingSlashingCallback`, OR governance proposal.
    QuarantineAgent {
        /// DID of the agent to quarantine
        agent_did: String,
        /// DID of the authorising controller. Must match the identity
        /// bound to `tx.from`.
        controller_did: String,
        /// Canonical reason code
        reason_code: u16,
        /// Optional human reason text, capped at 256 bytes
        reason_text: Option<String>,
        /// Optional commitment hash to off-chain evidence (32-byte SHA-256)
        evidence_hash: Option<[u8; 32]>,
    },
    /// Terminate an agent (Agent-Swarm Spec 1, tier 3).
    ///
    /// **Irreversible.** Identity revoked via the underlying
    /// `revoke_did` primitive. Stake/bond slashed by `slash_bps` capped
    /// at the governance `slash_bps_cap`. With `cascade=true`, all
    /// descendants under the agent's `children:` index are terminated
    /// recursively (depth-bounded by `cascade_max_depth`, default 32).
    ///
    /// Authorization: controller, OR governance proposal with timelock,
    /// OR cascade=true descended from a parent's TerminateAgent.
    TerminateAgent {
        /// DID of the agent to terminate
        agent_did: String,
        /// DID of the authorising controller. Must match the identity
        /// bound to `tx.from`.
        controller_did: String,
        /// Canonical reason code
        reason_code: u16,
        /// Basis points of stake/bond to slash (0..=10000), capped per
        /// governance `slash_bps_cap`.
        slash_bps: u16,
        /// If true, recursively terminate descendants under `children:`.
        cascade: bool,
    },
    /// Post a fresh AgentBond for `agent_did` (Agent-Swarm Spec 9).
    ///
    /// Locks `amount` TNZO from `tx.from` (the controller wallet) into
    /// the bond vault derived as
    /// `Address(SHA-256("tenzro/agent-bond/vault" || agent_did))`. The
    /// bond enters `BondLifecycle::Active` and promotes the agent to the
    /// Delegated admission lane while ≥ `bond_min_for_promotion`.
    ///
    /// Authorization: `tx.from` is the controller; the VM enforces that
    /// the agent_did either has no prior bond or its prior bond is in a
    /// terminal state (`Returned` / `Slashed`).
    PostAgentBond {
        /// DID of the agent being bonded (`did:tenzro:machine:...`)
        agent_did: String,
        /// DID of the controller posting the bond. Echoed on the wire so
        /// the receipt is self-describing without an identity lookup.
        controller_did: String,
        /// Amount of TNZO to lock in the bond vault
        amount: u128,
    },
    /// Top up an existing Active AgentBond by `amount`.
    ///
    /// Authorization: `tx.from` MUST equal the original poster (the
    /// bond's `controller` field).
    IncreaseAgentBond {
        /// DID of the agent whose bond is being increased
        agent_did: String,
        /// Additional TNZO to lock
        amount: u128,
    },
    /// Initiate the cooldown timer on an Active AgentBond. Funds are
    /// **not** released by the VM — finalisation happens off-VM via the
    /// node-side `BondManager` once `cooldown_ms` has elapsed.
    ///
    /// Authorization: `tx.from` MUST equal the bond's controller.
    WithdrawAgentBond {
        /// DID of the agent whose bond is being withdrawn
        agent_did: String,
    },
    /// Pay out an `Approved` insurance claim from the insurance pool
    /// vault to the claimant. The off-chain `BondManager` has already
    /// validated the claim and reserved funds; this transaction performs
    /// the on-chain transfer and persists a `paid_claim:<claim_id>`
    /// marker so the same claim cannot be paid twice.
    ///
    /// Authorization: governance committee (or `tx.from` matching the
    /// configured insurance-pool admin DID).
    PayInsuranceClaim {
        /// 32-byte deterministic claim identifier (lowercase hex)
        claim_id_hex: String,
        /// Recipient of the payout
        claimant: Address,
        /// Amount to pay from the pool vault, in TNZO base units
        amount: u128,
    },
    /// Settle an x402 payment on-chain, moving `amount` from `payer` to
    /// `payee`. Dispatched by the node's `TnzoSettlementCallback` after the
    /// x402 credential has been verified off-chain; the node's system key
    /// signs the transaction, so this is a privileged consensus-mediated
    /// settlement rather than a payer-signed transfer. The VM records a
    /// `x402_settle:<payment_id>` marker so a replayed dispatch cannot
    /// double-debit the payer.
    ///
    /// Authorization: `tx.from` is the node's system key; the settlement's
    /// legitimacy derives from the verified x402 credential the callback holds,
    /// not from a payer signature (the callback never holds the payer's key).
    X402Settle {
        /// Address funds move from.
        payer: Address,
        /// Address funds move to.
        payee: Address,
        /// Amount to settle, in TNZO base units. When `margin_bps > 0` this
        /// is the margin-inclusive total the payer authorized; the VM carves
        /// `amount * margin_bps / (10_000 + margin_bps)` out of it to
        /// `app_wallet` and credits the remainder to `payee`.
        amount: u128,
        /// x402 payment identifier — the idempotency key.
        payment_id: String,
        /// Registered app's wallet receiving the developer-margin carve.
        /// Snapshot taken from the on-chain `AppRegistry` at challenge
        /// creation so the VM needs no registry access. `None` disables the
        /// carve (requires `margin_bps == 0`).
        app_wallet: Option<Address>,
        /// Developer margin, in basis points, already included in `amount`.
        /// Bounded by `MAX_DEVELOPER_MARGIN_BPS`.
        margin_bps: u32,
    },
    /// Register the signing wallet as a Candidate validator (Dynamic Validator
    /// Set, modern permissionless join).
    ///
    /// On execution the VM emits a `ValidatorRegister` typed log carrying
    /// `from || stake_le || consensus_pubkey || pq_pubkey || withdrawal_address ||
    /// metadata_uri`. The node-side `ValidatorRegistry` consumes the log and
    /// inserts a `Candidate` entry that becomes `PendingActive` at the next
    /// epoch boundary if `self_stake >= min_self_stake` and the activation
    /// churn budget admits it; the `EpochManager` then promotes it to `Active`
    /// `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` after the boundary block.
    ///
    /// Authorization: `tx.from` is the validator's stake-owning wallet. The
    /// classical Ed25519 signature in `SignedTransaction::signature` proves
    /// control of `consensus_pubkey`, the ML-DSA-65 leg proves control of
    /// `pq_pubkey`, and the BLS leg proves control of `bls_pubkey`.
    RegisterValidator {
        /// 32-byte Ed25519 BFT signing key.
        consensus_pubkey: Vec<u8>,
        /// 1952-byte ML-DSA-65 verifying key (FIPS 204). Mandatory hybrid PQ.
        pq_pubkey: Vec<u8>,
        /// 48-byte BLS12-381 G1-compressed verifying key (`min_pk` scheme).
        /// Mandatory third leg, used by HotStuff-2 to aggregate per-vote
        /// signatures into a single QC-level aggregate.
        bls_pubkey: Vec<u8>,
        /// Address rewards / unbonded principal settle to.
        withdrawal_address: Address,
        /// Self-stake committed to the candidate. Must be ≥ the registry's
        /// `min_self_stake` (default 10,000 TNZO).
        self_stake: u128,
        /// Optional ≤256-byte off-chain pointer (moniker / website / contact).
        metadata_uri: String,
    },
    /// Voluntarily exit the active set (Dynamic Validator Set).
    ///
    /// The VM emits a `ValidatorExit` log; the registry transitions the entry
    /// to `PendingExit` and the next epoch boundary stages it for removal —
    /// effective `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` after that boundary
    /// block. Re-registration is blocked for `reentry_cooldown_epochs` (default
    /// 4) following voluntary exit.
    ///
    /// Authorization: `tx.from` MUST equal the validator's registry address.
    ExitValidator,
    /// Update validator metadata (moniker / TEE attestation commitment).
    ///
    /// At least one of `metadata_uri` or `tee_attestation_hash` should be
    /// `Some`; the registry treats `None` as "no change". `tee_attestation_hash`
    /// is the 32-byte SHA-256 commitment to a fresh attestation document — the
    /// active-set boundary applies the TEE multiplier from this commitment.
    ///
    /// Authorization: `tx.from` MUST equal the validator's registry address.
    UpdateValidatorMetadata {
        /// New off-chain pointer; `None` = no change. ≤256 bytes when present.
        metadata_uri: Option<String>,
        /// New 32-byte SHA-256 commitment to the attestation document.
        tee_attestation_hash: Option<[u8; 32]>,
    },
}

/// A signed transaction ready for submission
///
/// Contains the transaction and the **composite** signature (classical +
/// post-quantum) proving authorization. Both legs are mandatory — there is
/// no classical-only path. Verifiers reject a `SignedTransaction` whose
/// `pq_signature` is absent or wrong-sized.
///
/// # Wire layout
///
/// - `signature` — classical Ed25519 / Secp256k1 leg (existing field, raw bytes
///   in `signature.bytes` and the classical pubkey in `signature.public_key`).
/// - `pq_signature` — ML-DSA-65 signature (FIPS 204, exactly 3309 bytes).
/// - The ML-DSA-65 verifying key lives in `transaction.pq_public_key` so that
///   the hash preimage commits to the PQ identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The underlying transaction
    pub transaction: Transaction,
    /// The classical signature authorizing the transaction
    pub signature: Signature,
    /// ML-DSA-65 signature over `transaction.hash()` (FIPS 204, exactly 3309
    /// bytes). Mandatory; mis-sized payloads are rejected at deserialization.
    #[serde(deserialize_with = "crate::validation::bounded_pq_signature_bytes")]
    pub pq_signature: Vec<u8>,
    /// Cached transaction hash
    #[serde(skip)]
    hash: Option<Hash>,
}

impl SignedTransaction {
    /// Creates a new signed transaction. Both the classical signature and the
    /// ML-DSA-65 signature are mandatory.
    pub fn new(transaction: Transaction, signature: Signature, pq_signature: Vec<u8>) -> Self {
        Self {
            transaction,
            signature,
            pq_signature,
            hash: None,
        }
    }

    /// Returns the hash of the transaction
    pub fn hash(&mut self) -> Hash {
        if let Some(hash) = self.hash {
            hash
        } else {
            let hash = self.transaction.hash();
            self.hash = Some(hash);
            hash
        }
    }

    /// Validates the signed transaction
    ///
    /// Performs basic validation checks:
    /// - Classical signature bytes are non-empty
    /// - Classical public key is non-empty
    /// - PQ signature is exactly ML_DSA_65_SIG_LEN bytes (3309)
    /// - PQ public key (carried in `transaction.pq_public_key`) is exactly
    ///   ML_DSA_65_VK_LEN bytes (1952)
    /// - Gas limit is non-zero
    /// - Addresses are non-zero
    /// - Transaction data size is within limits
    ///
    /// Note: This does NOT verify the cryptographic signature.
    /// Signature verification requires the crypto crate.
    pub fn validate(&self) -> Result<(), &'static str> {
        // Check classical signature is non-empty
        if self.signature.bytes.is_empty() {
            return Err("Transaction signature is empty");
        }

        // Check classical public key is non-empty
        if self.signature.public_key.is_empty() {
            return Err("Transaction public key is empty");
        }

        // PQ leg is mandatory — defense-in-depth in case in-memory construction
        // bypassed the deserializer-level length checks.
        if self.pq_signature.len() != 3309 {
            return Err("PQ signature has wrong length (expected ML-DSA-65, 3309 bytes)");
        }
        if self.transaction.pq_public_key.len() != 1952 {
            return Err("PQ public key has wrong length (expected ML-DSA-65 vk, 1952 bytes)");
        }

        // Check gas limit is non-zero
        if self.transaction.gas_limit == 0 {
            return Err("Gas limit cannot be zero");
        }

        // Check sender is not zero address
        if self.transaction.from == Address::zero() {
            return Err("Sender address cannot be zero");
        }

        // Validate transaction data size based on type
        match &self.transaction.tx_type {
            TransactionType::ContractDeploy { code, args } => {
                if code.len() > MAX_TX_DATA_SIZE {
                    return Err("Contract code exceeds maximum size");
                }
                if args.len() > MAX_TX_DATA_SIZE {
                    return Err("Contract args exceed maximum size");
                }
            }
            TransactionType::ContractCall { args, .. } => {
                if args.len() > MAX_TX_DATA_SIZE {
                    return Err("Contract call args exceed maximum size");
                }
            }
            TransactionType::AgentRegister { config } => {
                if config.len() > MAX_TX_DATA_SIZE {
                    return Err("Agent config exceeds maximum size");
                }
            }
            TransactionType::AgentExecute { task } => {
                if task.len() > MAX_TX_DATA_SIZE {
                    return Err("Agent task exceeds maximum size");
                }
            }
            TransactionType::ModelInference { input, .. } => {
                if input.len() > MAX_TX_DATA_SIZE {
                    return Err("Inference input exceeds maximum size");
                }
            }
            TransactionType::TeeProviderRegister { attestation, info } => {
                if attestation.len() > MAX_TX_DATA_SIZE {
                    return Err("TEE attestation exceeds maximum size");
                }
                if info.len() > MAX_TX_DATA_SIZE {
                    return Err("Provider info exceeds maximum size");
                }
            }
            TransactionType::GovernancePropose { proposal } => {
                if proposal.len() > MAX_TX_DATA_SIZE {
                    return Err("Proposal data exceeds maximum size");
                }
            }
            TransactionType::ReleaseEscrow { proof, .. } => {
                if proof.proof_data.len() > MAX_TX_DATA_SIZE {
                    return Err("Escrow proof data exceeds maximum size");
                }
                // Bound number of signatures to prevent DoS at verification time
                if proof.signatures.len() > 16 {
                    return Err("Too many signatures in escrow release proof");
                }
            }
            TransactionType::PauseAgent { agent_did, reason_text, .. }
            | TransactionType::QuarantineAgent { agent_did, reason_text, .. } => {
                if agent_did.len() > 256 {
                    return Err("agent_did exceeds maximum length");
                }
                if let Some(t) = reason_text
                    && t.len() > 256
                {
                    return Err("reason_text exceeds 256 bytes");
                }
            }
            TransactionType::TerminateAgent { agent_did, slash_bps, .. } => {
                if agent_did.len() > 256 {
                    return Err("agent_did exceeds maximum length");
                }
                if *slash_bps > 10_000 {
                    return Err("slash_bps exceeds 100%");
                }
            }
            TransactionType::RegisterValidator {
                consensus_pubkey,
                pq_pubkey,
                bls_pubkey,
                metadata_uri,
                ..
            } => {
                if consensus_pubkey.len() != 32 {
                    return Err("consensus_pubkey must be 32 bytes (Ed25519)");
                }
                if pq_pubkey.len() != 1952 {
                    return Err("pq_pubkey must be 1952 bytes (ML-DSA-65 vk)");
                }
                if bls_pubkey.len() != 48 {
                    return Err("bls_pubkey must be 48 bytes (BLS12-381 G1-compressed, min_pk)");
                }
                if metadata_uri.len() > 256 {
                    return Err("metadata_uri exceeds 256 bytes");
                }
            }
            TransactionType::UpdateValidatorMetadata { metadata_uri, .. } => {
                if let Some(uri) = metadata_uri
                    && uri.len() > 256
                {
                    return Err("metadata_uri exceeds 256 bytes");
                }
            }
            // Other transaction types have bounded data (strings, primitives)
            _ => {}
        }

        // Recipient can be zero for contract creation

        Ok(())
    }

    /// Returns the sender address
    pub fn sender(&self) -> Address {
        self.transaction.from
    }

    /// Returns the recipient address
    pub fn recipient(&self) -> Address {
        self.transaction.to
    }

    /// Returns the nonce
    pub fn nonce(&self) -> Nonce {
        self.transaction.nonce
    }

    /// Checks if the transaction has both classical and PQ signatures
    /// populated (non-empty classical legs and exact-size PQ legs).
    /// This does NOT verify cryptographic validity.
    pub fn is_signed(&self) -> bool {
        !self.signature.bytes.is_empty()
            && !self.signature.public_key.is_empty()
            && self.pq_signature.len() == 3309
            && self.transaction.pq_public_key.len() == 1952
    }
}
