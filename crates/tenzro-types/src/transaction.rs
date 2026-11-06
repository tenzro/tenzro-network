//! Transaction types for Tenzro Network
//!
//! This module defines the transaction structure and related types used
//! to represent state transitions on the Tenzro Network blockchain.

use crate::asset::AssetId;
use crate::primitives::{Address, ChainId, Hash, Nonce, Timestamp};
use crate::settlement::{ReleaseConditions, ServiceProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum transaction data size in bytes (128 KB)
pub const MAX_TX_DATA_SIZE: usize = 131_072;

/// Largest proof envelope an `AttestZkProof` transaction may carry. STARK
/// proofs run to about 1.5 MB, so this transaction type has its own bound;
/// every validator re-verifies the proof, so its bytes must be in the block.
pub const MAX_ZK_PROOF_SIZE: usize = 4 * 1024 * 1024;

/// Validity window [`Transaction::new`] gives a transaction: five minutes,
/// inside both governed caps (`tx.max_validity_ms` and
/// `tx.privileged_max_validity_ms`).
pub const DEFAULT_TX_VALIDITY_MS: i64 = 300_000;

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
/// # Keys
///
/// A transaction names no key: the signature in [`SignedTransaction`] carries
/// the sender's P-256 key, and an ML-DSA-65 key the account has enrolled
/// lives in account state, not in the transaction.
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
    /// Last block time (Unix milliseconds) at which the transaction may
    /// execute. Bound into [`Transaction::hash`]. Execution refuses a
    /// transaction whose block time is past this instant, or whose window
    /// reaches further ahead than the governed validity cap for its class.
    pub valid_until: Timestamp,
    /// Optional memo or metadata
    pub memo: Option<String>,
}

impl Transaction {
    /// Creates a new transaction valid for [`DEFAULT_TX_VALIDITY_MS`].
    pub fn new(
        chain_id: ChainId,
        from: Address,
        to: Address,
        nonce: Nonce,
        tx_type: TransactionType,
        gas_limit: u64,
        gas_price: u64,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            chain_id,
            from,
            to,
            nonce,
            tx_type,
            gas_limit,
            gas_price,
            timestamp: now,
            valid_until: Timestamp::new(now.0.saturating_add(DEFAULT_TX_VALIDITY_MS)),
            memo: None,
        }
    }

    /// Sets the last block time at which the transaction may execute.
    pub fn with_valid_until(mut self, valid_until: Timestamp) -> Self {
        self.valid_until = valid_until;
        self
    }

    /// Adds a memo to the transaction
    pub fn with_memo(mut self, memo: String) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Computes the SHA-256 hash of the transaction.
    ///
    /// The preimage layout is the canonical signing surface for the network.
    ///
    /// A privileged transaction's hash is its typed action digest
    /// ([`crate::typed_action::typed_action_digest`]), over a preimage a
    /// wallet decodes and shows before signing.
    pub fn hash(&self) -> Hash {
        match &self.tx_type {
            TransactionType::ExternalEvm { raw } => {
                use sha3::{Digest as _, Keccak256};
                return Hash::new(Keccak256::digest(raw).into());
            }
            TransactionType::ExternalSvm { raw } => return external_svm_hash(raw),
            _ => {}
        }
        if let Some(digest) = crate::typed_action::typed_action_digest(self) {
            return Hash::new(digest);
        }
        self.native_hash_under(crate::hash_scheme::TX_HASH_SCHEMES)
    }

    /// [`Self::hash`] of a native transaction under the `valid_until` to
    /// scheme table `schemes`.
    pub fn native_hash_under(&self, schemes: &[(u64, crate::hash_scheme::HashScheme)]) -> Hash {
        let scheme = crate::hash_scheme::scheme_from(
            self.valid_until.0.max(0) as u64,
            schemes.iter().copied(),
        );
        Hash::new(scheme.digest(&self.native_hash_bytes()))
    }

    fn native_hash_bytes(&self) -> Vec<u8> {
        trait Update {
            fn update(&mut self, bytes: impl AsRef<[u8]>);
        }
        impl Update for Vec<u8> {
            fn update(&mut self, bytes: impl AsRef<[u8]>) {
                self.extend_from_slice(bytes.as_ref());
            }
        }
        let mut hasher: Vec<u8> = Vec::with_capacity(256);
        hasher.update(self.chain_id.0.to_le_bytes());
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(self.nonce.0.to_le_bytes());
        hasher.update(self.gas_limit.to_le_bytes());
        hasher.update(self.gas_price.to_le_bytes());
        hasher.update(self.timestamp.0.to_le_bytes());
        hasher.update(self.valid_until.0.to_le_bytes());
        // Include tx_type via JSON serialization for deterministic encoding
        if let Ok(tx_type_json) = serde_json::to_vec(&self.tx_type) {
            hasher.update(&tx_type_json);
        }
        if let Some(ref memo) = self.memo {
            hasher.update(memo.as_bytes());
        }
        hasher
    }
}

#[cfg(test)]
mod hash_scheme_tests {
    use super::*;
    use crate::hash_scheme::HashScheme;

    fn transfer(valid_until: i64, memo: Option<&str>) -> Transaction {
        let mut t = Transaction::new(
            ChainId::from(9u64),
            Address::new([1; 32]),
            Address::new([2; 32]),
            Nonce::from(4),
            TransactionType::Transfer { amount: 5 },
            21_000,
            7,
        );
        t.timestamp = Timestamp::new(1_700_000_000_000);
        t.valid_until = Timestamp::new(valid_until);
        t.memo = memo.map(str::to_string);
        t
    }

    /// The hash as it was computed before schemes were named.
    fn sha256_as_before(t: &Transaction) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(t.chain_id.0.to_le_bytes());
        hasher.update(t.from.as_bytes());
        hasher.update(t.to.as_bytes());
        hasher.update(t.nonce.0.to_le_bytes());
        hasher.update(t.gas_limit.to_le_bytes());
        hasher.update(t.gas_price.to_le_bytes());
        hasher.update(t.timestamp.0.to_le_bytes());
        hasher.update(t.valid_until.0.to_le_bytes());
        hasher.update(serde_json::to_vec(&t.tx_type).unwrap());
        if let Some(ref memo) = t.memo {
            hasher.update(memo.as_bytes());
        }
        Hash::new(hasher.finalize().into())
    }

    #[test]
    fn existing_transactions_keep_their_hashes() {
        for memo in [None, Some("x")] {
            let t = transfer(1_800_000_000_000, memo);
            assert_eq!(t.hash(), sha256_as_before(&t));
        }
    }

    /// From the time an upgrade names, a transaction hashes with SHA3-256;
    /// one expiring before it keeps its SHA-256 hash.
    #[test]
    fn the_hash_changes_for_transactions_valid_past_the_switch() {
        let schemes = [
            (0u64, HashScheme::Sha256),
            (2_000_000_000_000, HashScheme::Sha3_256),
        ];
        let before = transfer(1_999_999_999_999, None);
        let after = transfer(2_000_000_000_000, None);
        assert_eq!(
            before.native_hash_under(&schemes),
            sha256_as_before(&before)
        );
        assert_ne!(after.native_hash_under(&schemes), sha256_as_before(&after));
        assert_eq!(
            after.native_hash_under(&schemes),
            Hash::new(HashScheme::Sha3_256.digest(&after.native_hash_bytes()))
        );
    }
}

impl TransactionType {
    /// A transaction signed by an external EVM or Solana wallet.
    pub fn is_external(&self) -> bool {
        matches!(self, Self::ExternalEvm { .. } | Self::ExternalSvm { .. })
    }

    /// A record the protocol asks a bonded validator to make, which pays no
    /// fee: the signers of a certified checkpoint. Chain progress never
    /// depends on these records, and a validator records them whatever its
    /// spendable balance, so a validator with nothing to spend keeps the
    /// vote work of the checkpoints it signs. The mempool admits one only
    /// from a bonded validator and orders it ahead of fee-paying
    /// transactions; the VM charges it nothing and refuses it from an
    /// account with no bond.
    pub fn pays_no_fee(&self) -> bool {
        matches!(self, Self::RecordCheckpointSigners { .. })
    }
}

/// The hash an external Solana transaction is recorded under: SHA-256 of
/// its first signature, the id a Solana wallet looks the transaction up by.
/// `raw` is the wire transaction (a one-byte signature count, then the
/// signatures).
pub fn external_svm_hash(raw: &[u8]) -> Hash {
    svm_signature_hash(raw.get(1..65).unwrap_or(raw))
}

/// The hash of the external Solana transaction whose first signature is
/// `signature`.
pub fn svm_signature_hash(signature: &[u8]) -> Hash {
    Hash::new(Sha256::digest(signature).into())
}

/// The VM a [`VmCall`] executes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallVm {
    /// The EVM.
    Evm,
    /// The SVM.
    Svm,
}

impl CallVm {
    /// The name a delegated agent's terms use for this VM's chain.
    pub fn name(self) -> &'static str {
        match self {
            CallVm::Evm => "evm",
            CallVm::Svm => "svm",
        }
    }

    fn tag(self) -> u8 {
        match self {
            CallVm::Evm => 0,
            CallVm::Svm => 1,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(CallVm::Evm),
            1 => Some(CallVm::Svm),
            _ => None,
        }
    }
}

/// Most calls one transaction may carry.
pub const MAX_VM_CALLS: usize = 16;

/// One call of a [`TransactionType::ContractCall`] or of a delegated
/// agent's [`crate::agent_terms::AgentAction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmCall {
    /// The VM the call executes in.
    pub vm: CallVm,
    /// The code called: an EVM contract (20 bytes) or an SVM program
    /// (32 bytes).
    pub to: Vec<u8>,
    /// Native TNZO the call carries, wei. Only EVM calls carry value.
    #[serde(default)]
    pub value: u128,
    /// Calldata in the VM's own format: EVM ABI calldata or SVM instruction
    /// data (`[n_accounts] [accounts: 32 * n] [instruction]`).
    pub data: Vec<u8>,
}

impl VmCall {
    /// Check a call list's shape: at least one call and at most
    /// [`MAX_VM_CALLS`], each with a 20- or 32-byte target, value only on
    /// EVM calls, and calldata within the transaction data limit in total.
    pub fn validate_list(calls: &[VmCall]) -> Result<(), &'static str> {
        if calls.is_empty() {
            return Err("a contract call needs at least one call");
        }
        if calls.len() > MAX_VM_CALLS {
            return Err("a contract call carries at most 16 calls");
        }
        let mut total = 0usize;
        for call in calls {
            if call.to.len() != 20 && call.to.len() != 32 {
                return Err("a call target is 20 or 32 bytes");
            }
            if call.value != 0 && call.vm != CallVm::Evm {
                return Err("only EVM calls carry value");
            }
            total = total.saturating_add(call.data.len());
        }
        if total > MAX_TX_DATA_SIZE {
            return Err("the calls' calldata exceeds the maximum size");
        }
        Ok(())
    }

    /// Binary encoding of a call list, as the VM receives it:
    /// `count: u8`, then per call `vm: u8 | to_len: u8 | to | value: u128 BE |
    /// data_len: u32 BE | data`.
    pub fn encode_list(calls: &[VmCall]) -> Vec<u8> {
        let mut out = vec![calls.len() as u8];
        for call in calls {
            out.push(call.vm.tag());
            out.push(call.to.len() as u8);
            out.extend_from_slice(&call.to);
            out.extend_from_slice(&call.value.to_be_bytes());
            out.extend_from_slice(&(call.data.len() as u32).to_be_bytes());
            out.extend_from_slice(&call.data);
        }
        out
    }

    /// Decode [`Self::encode_list`]. Refuses trailing bytes and any list
    /// [`Self::validate_list`] refuses.
    pub fn decode_list(bytes: &[u8]) -> Result<Vec<VmCall>, &'static str> {
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], &'static str> {
            if bytes.len() < n {
                return Err("truncated call list");
            }
            let (head, rest) = bytes.split_at(n);
            *bytes = rest;
            Ok(head)
        }
        let mut rest = bytes;
        let count = take(&mut rest, 1)?[0] as usize;
        let mut calls = Vec::with_capacity(count.min(MAX_VM_CALLS));
        for _ in 0..count {
            let vm = CallVm::from_tag(take(&mut rest, 1)?[0]).ok_or("unknown call VM")?;
            let to_len = take(&mut rest, 1)?[0] as usize;
            let to = take(&mut rest, to_len)?.to_vec();
            let value = u128::from_be_bytes(
                take(&mut rest, 16)?
                    .try_into()
                    .map_err(|_| "truncated call list")?,
            );
            let data_len = u32::from_be_bytes(
                take(&mut rest, 4)?
                    .try_into()
                    .map_err(|_| "truncated call list")?,
            ) as usize;
            let data = take(&mut rest, data_len)?.to_vec();
            calls.push(VmCall {
                vm,
                to,
                value,
                data,
            });
        }
        if !rest.is_empty() {
            return Err("trailing bytes after the call list");
        }
        Self::validate_list(&calls)?;
        Ok(calls)
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
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Deploy a smart contract
    ContractDeploy {
        /// Contract bytecode
        code: Vec<u8>,
        /// Constructor arguments
        args: Vec<u8>,
    },
    /// Call contracts and programs in the EVM and the SVM, in order, as one
    /// transaction.
    ///
    /// The calls are all-or-nothing: they run against the one native ledger
    /// under a single undo log, so if any call fails every call's writes in
    /// every VM are undone and the sender pays only the gas used. Gas and
    /// fees are summed over the calls, and every call's events belong to
    /// this transaction.
    ///
    /// Authorization: `tx.from` is the caller of every call.
    ContractCall {
        /// The calls, executed in order.
        calls: Vec<VmCall>,
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
    /// Submit a governance proposal
    GovernancePropose {
        /// Proposal data
        proposal: Vec<u8>,
    },
    /// Vote on a governance proposal with a validator's bond, cast by the
    /// validator's root. A validator whose identity is rooted in a person
    /// votes by its operator signing the transaction with that person's
    /// passkey identity, and `root_approval` is `None`. A validator whose
    /// identity is an autonomous machine votes by `root_approval`: the
    /// hardware key its machine DID derives from approving exactly this
    /// ballot, which anyone may then submit. One ballot per validator.
    GovernanceVote {
        /// Proposal ID
        proposal_id: String,
        /// Vote value
        vote: bool,
        /// The validator account whose bond the ballot carries.
        validator: Address,
        /// The machine root's approval of the ballot
        /// ([`crate::agent_terms::governance_vote_target`] under
        /// [`crate::agent_terms::OP_ROOT_BALLOT`]); `None` for a
        /// passkey-signed ballot.
        #[serde(default)]
        root_approval: Option<crate::agent_terms::AgentTermsApproval>,
    },
    /// Enact a governance proposal whose voting window has closed and which
    /// passed.
    ///
    /// Carries no authority of its own — the VM re-checks the window, the
    /// quorum, the threshold and the not-already-executed guard against
    /// consensus state, so anyone may submit it and pay its gas. Making it
    /// permissionless is deliberate: a passed proposal only its proposer could
    /// enact is one a departed proposer can strand forever.
    /// A governance guardian vetoing a queued proposal during its timelock.
    ///
    /// Terminal for that proposal. Only reachable while it is queued: before
    /// it carries there is nothing to stop, and once it executes there is
    /// nothing left to stop.
    GovernanceVeto {
        /// Which proposal to stop, by id.
        proposal_id: String,
    },
    /// A protocol guardian pausing or resuming governance enactment.
    ///
    /// Stops enactment only. Voting, proposing and vetoing continue, so the
    /// power that imposed a pause is not the only route out of it.
    GovernancePause {
        /// True to pause, false to resume.
        paused: bool,
    },
    GovernanceExecute {
        /// Hex-encoded 32-byte proposal ID.
        proposal_id: String,
    },
    /// A funding operation: a request filed for the governance vote, a
    /// report of settled work, a claim of earned network rewards, or the
    /// release of vested funds. The treasury pays its gas, so an identity
    /// with a zero balance can submit it.
    Funding {
        /// JSON-encoded funding operation.
        op: Vec<u8>,
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
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// Asset being escrowed: `TNZO` or a token id, `0x`-prefixed hex
        asset_id: AssetId,
        /// USD price of the amount, micro-units. Required for an asset other
        /// than TNZO; claims pay the settlement fee in TNZO on it.
        #[serde(default)]
        usd_e6: u64,
        /// Unix timestamp (millis) at which the escrow expires
        expires_at: u64,
        /// Conditions for releasing funds to the payee
        release_conditions: ReleaseConditions,
        /// An opaque reference the escrow carries, so the application that
        /// opens it can find it again (a task milestone, a session), hex.
        #[serde(default, with = "crate::settlement::opt_hex32")]
        reference: Option<[u8; 32]>,
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
    /// Pause an agent (tier 1).
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
    /// Quarantine an agent (tier 2).
    ///
    /// Reversible only after evidence review. Inbound + outbound payments
    /// blocked. Stake frozen — cannot withdraw, cannot earn rewards.
    /// Existing tasks halt.
    ///
    /// Authorization: controller (as PauseAgent), OR slashing-committee
    /// quorum, OR governance proposal.
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
    /// Terminate an agent (tier 3).
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
    /// Post a fresh AgentBond for `agent_did`.
    ///
    /// Locks `amount` TNZO from `tx.from` (the controller wallet) into
    /// the bond vault derived as
    /// `Address(SHA-256("tenzro/agent-bond/vault" || agent_did))`. The
    /// bond is Active and promotes the agent to the
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
        #[serde(with = "crate::primitives::u128_serde")]
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
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Withdraw an AgentBond: the first call starts the cooldown, a call
    /// after it ends returns the bond to its owner.
    ///
    /// Authorization: `tx.from` MUST equal the bond's controller.
    WithdrawAgentBond {
        /// DID of the agent whose bond is being withdrawn
        agent_did: String,
    },
    /// Post a fresh compute bond for `provider_did`.
    ///
    /// Locks `amount` TNZO from `tx.from` (the provider wallet) into the
    /// bond vault derived as
    /// `Address(SHA-256("tenzro/compute-bond/vault" || provider_did))`.
    /// The bond inference faults, SLA verdicts and proven policy violations
    /// are slashed from; a role's admission bond is its `Stake` bond.
    ///
    /// Authorization: `tx.from` is the provider wallet and becomes the
    /// bond's payout address. The VM enforces that `provider_did` either
    /// has no prior bond or its prior bond is in a terminal state.
    PostComputeBond {
        /// DID of the provider being bonded
        provider_did: String,
        /// Amount of TNZO to lock in the bond vault
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Top up an existing Active compute bond by `amount`.
    ///
    /// Authorization: `tx.from` MUST equal the bond's provider address.
    IncreaseComputeBond {
        /// DID of the provider whose bond is being increased
        provider_did: String,
        /// Additional TNZO to lock
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Initiate the cooldown timer on an Active compute bond. The vault stays
    /// funded — and stays slashable — for the whole cooldown; the transfer back
    /// to the provider wallet happens in a separate
    /// `FinalizeComputeBondWithdrawal` transaction once the deadline passes.
    ///
    /// Authorization: `tx.from` MUST equal the bond's provider address.
    WithdrawComputeBond {
        /// DID of the provider whose bond is being withdrawn
        provider_did: String,
    },
    /// Release a withdrawing compute bond's vault balance back to the provider
    /// once the cooldown deadline recorded by `WithdrawComputeBond` has passed.
    /// The deadline is compared against the block timestamp, so every replica
    /// reaches the same decision.
    ///
    /// Authorization: `tx.from` MUST equal the bond's provider address.
    FinalizeComputeBondWithdrawal {
        /// DID of the provider whose bond is being released
        provider_did: String,
    },
    /// Claim from the insurance pool on evidence chain state holds of a loss
    /// a bonded party caused (see [`crate::insurance`]). The sender must be
    /// the party the evidence names; each evidence pays once, capped by
    /// governance.
    PayInsuranceClaim {
        /// The evidence of the loss.
        evidence: crate::insurance::InsuranceEvidence,
    },
    /// Settle a payer-authorized payment
    /// on-chain, moving `amount` from `payer` to `payee`.
    ///
    /// Authorization is the payer's own signature: `authorization` carries
    /// the payer's Ed25519 key and its signature over
    /// [`crate::payment_authorization::payment_authorization_preimage`]
    /// (chain, `payment_id`, payer, payee, ceiling, asset, and the binding
    /// with any application margin). The VM checks
    /// that the key controls `payer`, that the signature verifies, and that
    /// `amount` does not exceed the signed ceiling, so any account may submit
    /// the transaction and pay its gas without being able to move anyone
    /// else's funds. The VM records a `payer_settle:<payment_id>` marker so
    /// the same authorization cannot settle twice.
    ///
    /// Every settlement carries the network share: after the developer
    /// margin, the governed `fees.http402_network_share_bps` of the remainder
    /// goes to the network treasury and the rest to `payee`.
    PayerSettle {
        /// Address funds move from.
        payer: Address,
        /// Address funds move to.
        payee: Address,
        /// Amount to settle, in TNZO base units. When the payer's signed
        /// binding names an application margin this is the margin-inclusive
        /// total; the VM carves `amount * margin_bps / (10_000 + margin_bps)`
        /// out of it to the signed `app_wallet` and credits the remainder to
        /// `payee`.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// Payment identifier, the idempotency key.
        payment_id: String,
        /// The payer's signed authorization of this payment.
        authorization: crate::payment_authorization::PaymentAuthorization,
    },
    /// Claim from one or more on-chain escrows with payer-signed cumulative
    /// vouchers ([`crate::payment_authorization::EscrowVoucher`]).
    ///
    /// Each claim pays its escrow's recorded payee the difference between the
    /// cumulative amount claimed, which its voucher must cover, and what was
    /// already claimed. The VM
    /// checks every voucher's signature against the escrow's payer before
    /// moving anything, and applies all claims or none, so a batch can settle
    /// the legs of a delivery-versus-payment atomically. Any account may
    /// submit it: the vouchers are the authority and the money can only go
    /// to each escrow's payee.
    ClaimEscrow {
        /// Claims to honour, at most one per escrow.
        claims: Vec<crate::payment_authorization::EscrowClaim>,
    },
    /// Pay a hash-locked escrow's remainder to its payee by revealing a
    /// preimage of its lock.
    ///
    /// The preimage is published in the transaction and its log, so the
    /// payment and the revelation are one event: a seller that locks the key
    /// of an encrypted delivery gets paid exactly when the buyer can read the
    /// key. Any account may submit it; the money can only go to the escrow's
    /// payee.
    ClaimEscrowPreimage {
        /// 32-byte escrow identifier.
        escrow_id: [u8; 32],
        /// A preimage of the escrow's lock.
        preimage: Vec<u8>,
    },
    /// Pay a streaming escrow's accrued, unpaid part to its payee. Any
    /// account may submit it.
    ClaimEscrowStream {
        /// 32-byte escrow identifier.
        escrow_id: [u8; 32],
    },
    /// Lock `amount` from the sender behind a usage meter. The meter is
    /// named by the account slot of its hardware P-256 key, and that key
    /// signs its consent to the sender as the bond's owner
    /// ([`crate::metering::meter_bond_consent`]).
    PostMeterBond {
        /// The meter's P-256 public key (`x || y`, 64 bytes).
        meter_public_key: Vec<u8>,
        /// Value to lock.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// The meter's signature over its consent; the ML-DSA-65 leg is
        /// checked against the key enrolled for the meter's account slot.
        consent: crate::account_signature::CompositeSignature,
    },
    /// Ask to withdraw a meter bond, or, a full dispute window after asking,
    /// withdraw it.
    WithdrawMeterBond {
        /// The meter id: the account slot of its P-256 key.
        meter_id: [u8; 32],
    },
    /// Prove a meter lied about a metered charge; a proven dispute pays the
    /// payer from the meter's bond.
    DisputeMeteredCharge {
        /// The evidence.
        dispute: crate::metering::MeterDispute,
    },
    /// Move funds into the governance treasury.
    ///
    /// The treasury could pay out — `TreasuryGrant` debits it — but nothing
    /// could ever credit it: no genesis allocation, no fee routing, no deposit.
    /// A vault that can only be spent from starts empty and stays empty, so
    /// every grant proposal would pass its vote and then fail enactment on an
    /// insufficient balance.
    ///
    /// Permissionless on purpose. Giving away your own money needs no
    /// authorization beyond holding it, and requiring some privileged role to
    /// fund the commons would be a strange gate to build.
    TreasuryDeposit {
        /// Amount to move, in base units.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Add to an already-registered validator's self-stake.
    ///
    /// The registry could create a stake and end one, and nothing in between —
    /// `RegisterValidator` refuses an address that has not exited, and exiting
    /// to re-register costs the re-entry cooldown and the validator's place in
    /// the set. A validator set therefore had no way to rebalance, which is
    /// most consequential where it is least visible: a network bootstrapped
    /// from one funded genesis validator cannot dilute it, and stays dependent
    /// on that single node for every block however many others join.
    ///
    /// Authorization: `tx.from` MUST equal the validator's registry address.
    IncreaseValidatorStake {
        /// Additional self-stake, in base units. Must be greater than zero;
        /// this only ever adds. Reducing a stake is unbonding, which has its
        /// own path, delay and slashing exposure.
        #[serde(with = "crate::primitives::u128_serde")]
        additional: u128,
    },
    /// Register the signing wallet as a Candidate validator (Dynamic Validator
    /// Set, permissionless join).
    ///
    /// On execution the VM emits a `ValidatorRegister` typed log carrying
    /// `from || stake_le || node_key || p256_pubkey || ml_dsa_pubkey ||
    /// withdrawal_address || metadata_uri`. The node-side `ValidatorRegistry`
    /// consumes the log and inserts a `Candidate` entry that becomes
    /// `PendingActive` at the next epoch boundary if
    /// `self_stake >= min_self_stake` and the activation churn budget admits
    /// it; the `EpochManager` then promotes it to `Active`
    /// `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` after the boundary block.
    ///
    /// Authorization: `tx.from` is the validator's stake-owning wallet, whose
    /// signature authorizes the transaction; `proof_of_possession` proves
    /// control of the consensus key it registers, `node_key_proof`
    /// control of the node key and `vrf_key_proof` control of the VRF key. Where to reach the
    /// validator is not registered: each boot announces its network endpoint
    /// signed by the consensus key.
    RegisterValidator {
        /// 1952-byte ML-DSA-65 verifying key (FIPS 204) of the validator's
        /// hardware-held consensus key.
        ml_dsa_pubkey: Vec<u8>,
        /// 65-byte uncompressed SEC1 P-256 key: the classical leg of the
        /// same composite key.
        p256_pubkey: Vec<u8>,
        /// The node's Ed25519 key, derived from its hardware: the key its
        /// peer bindings and availability attestations are signed with.
        node_key: [u8; 32],
        /// Ed25519 signature by `node_key` over the registration: proof that
        /// the registrant holds it.
        node_key_proof: Vec<u8>,
        /// The validator's VRF key, derived from its hardware apart from the
        /// node key: the key its beacon contributions verify under.
        vrf_key: [u8; 32],
        /// 80-byte VRF proof by `vrf_key` over the registration: proof that
        /// the registrant holds it.
        vrf_key_proof: Vec<u8>,
        /// Composite signature (ML-DSA-65 and P-256) by the key being
        /// registered over the registration: proof that the registrant holds
        /// it. The registration is refused without a valid one.
        proof_of_possession: Vec<u8>,
        /// Address rewards / unbonded principal settle to.
        withdrawal_address: Address,
        /// Self-stake committed to the candidate. Must be ≥ the registry's
        /// `min_self_stake` (default 10,000 TNZO).
        #[serde(with = "crate::primitives::u128_serde")]
        self_stake: u128,
        /// Optional ≤256-byte off-chain pointer (moniker / website / contact).
        metadata_uri: String,
    },
    /// Proof that one validator signed two different checkpoints with the
    /// same index: the encoded `CheckpointEquivocation` of the consensus
    /// crate. Anyone may submit it. The VM verifies both signatures and
    /// records the offence once; every node slashes the signer when it
    /// replays the resulting log.
    ReportCheckpointEquivocation {
        /// bincode-encoded evidence.
        evidence: Vec<u8>,
    },
    /// Voluntarily exit the active set (Dynamic Validator Set).
    ///
    /// Two steps under this one type. The first moves the bond into
    /// unbonding: it stops counting as stake immediately but stays in the
    /// staking vault, still slashable, for seven days. Sending it again after
    /// that period pays the bond out.
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
    /// Register an identity (DID) into replicated consensus state.
    ///
    /// Identities were historically written **local-only** by each RPC
    /// registration handler, so a DID created on node A never resolved on
    /// node B. This native tx fixes that: the record is
    /// ordered by consensus, DID uniqueness is enforced against
    /// `SYSTEM_ADDRESS` storage in the VM, and every node re-executes and
    /// converges. On execution the VM emits an `IdentityRegister` typed log
    /// carrying the JSON [`crate::identity::RegisterIdentityPayload`]; the
    /// node-side `IdentityRegistry` consumes the log and upserts the record
    /// so it becomes replicated read-model state.
    ///
    /// Key MATERIAL (TEE-sealed / hardware-held signing keys) is NOT carried
    /// here and stays node-local by design — only the public identity record
    /// (DID, controller pubkey, wallet bindings, verifying keys, metadata)
    /// replicates.
    ///
    /// Authorization: `tx.from` is the payer (the node's system key when the
    /// registration is dispatched by the node on the identity's behalf), so it
    /// authorizes nothing about the identity. `proof` is what does: a
    /// signature by `controller_pubkey` over every other field. DID
    /// uniqueness is enforced against consensus state, and a DID already held
    /// by a different controller is refused.
    RegisterIdentity {
        /// The DID being registered. Uniqueness is consensus-enforced.
        did: String,
        /// Identity class: `"human"` | `"machine"` | `"institution"`.
        identity_type: String,
        /// Human-readable display / legal name.
        display_name: String,
        /// Classical controller public key (Ed25519 / Secp256k1).
        controller_pubkey: Vec<u8>,
        /// Key type string for `controller_pubkey`.
        key_type: String,
        /// Wallet ID bound to the identity's primary wallet.
        wallet_id: String,
        /// On-chain address of the identity's primary wallet.
        wallet_address: Address,
        /// ML-DSA-65 (FIPS 204) verifying key. Empty when unset.
        pq_verifying_key: Vec<u8>,
        /// Additional public metadata. `BTreeMap` for deterministic ordering
        /// so the bincode tx-hash preimage is identical on every node.
        metadata: std::collections::BTreeMap<String, String>,
        /// Proof the submitter holds `controller_pubkey`.
        proof: crate::identity::RegistrationProof,
    },
    /// Record a zero-knowledge proof as verified on chain.
    ///
    /// Every validator runs the verifier on `proof` while executing the
    /// block; on success the proof's commitment is stored where the ZK_VERIFY
    /// precompile reads it. A proof that does not verify fails the
    /// transaction. Anyone may submit one and pays its gas.
    AttestZkProof {
        /// bincode-encoded proof envelope (`tenzro_zk::Proof`), at most
        /// [`MAX_ZK_PROOF_SIZE`] bytes.
        proof: Vec<u8>,
    },
    /// A bonded validator's view of which bonded compute providers answered
    /// its SLA probes during one closed epoch. The VM freezes a provider's
    /// verdict once two thirds of bonded stake has attested it; rental
    /// billing pays or makes the renter whole on that verdict.
    SlaAttest {
        /// Epoch (hours since the Unix epoch) the probes were issued in
        epoch: u64,
        /// One outcome per provider the validator probed
        outcomes: Vec<SlaOutcome>,
    },
    /// One operation on a standardized compute claim held in consensus state.
    ComputeClaim {
        /// What to do
        op: ComputeClaimOp,
    },
    /// A checkpoint certificate, recorded so its signers earn the epoch's
    /// vote reward: the encoded `PublishedCertificate` of the consensus
    /// crate, carrying the session certificate of every signer. Every node
    /// verifies it against the committee of its epoch before the block
    /// executes, and leaves it out of the block when it does not verify.
    RecordCheckpointSigners {
        /// bincode-encoded certificate with its signers' session certificates.
        certificate: Vec<u8>,
    },
    /// A node's commitment to the audit trail of every agent session it
    /// supervised in one epoch: the Merkle root over each session's
    /// `(session_id, MMR root, entry count)`. One per node per epoch.
    AgentAuditCommit {
        /// Reward epoch the sessions were active in
        epoch: u64,
        /// 32-byte root over the sessions' lines
        root: Vec<u8>,
        /// Sessions the root covers
        sessions: u64,
        /// Where the epoch's entries are held in the network's DA layer
        /// (encrypted to each session's owner or controller on a private
        /// node); empty when the node discloses them only on request
        entries_ref: String,
        /// The machine's hardware attestation over `(epoch, root)`: a TPM
        /// quote binding the commitment to the measured boot state and the
        /// machine identity, JSON-encoded. Empty on a machine with no TPM.
        attestation: Vec<u8>,
    },
    /// Lift an agent's quarantine. Only the owner or controller the
    /// quarantine names may send it, from the wallet its identity is
    /// registered with (a passkey or hardware key).
    LiftAgentQuarantine {
        /// DID of the quarantined agent
        agent_did: String,
        /// Optional human reason text, capped at 256 bytes
        reason_text: Option<String>,
    },
    /// A bonded validator's findings from checking its peers' committed
    /// audit and telemetry roots in one epoch. A finding takes effect once
    /// validators holding two thirds of bonded stake have made it.
    AgentAuditFlag {
        /// Epoch the findings were made in
        epoch: u64,
        /// One entry per finding
        findings: Vec<crate::agent_audit::AuditFinding>,
    },
    /// Revoke a delegated agent. Permanent: every node refuses the agent's
    /// actions from then on, and no quarantine lift restores it.
    ///
    /// Authorization: the controller's registered wallet, or a bonded
    /// account relaying the controller's verified passkey approval, whose
    /// challenge digest it records.
    RevokeDelegatedAgent {
        /// DID of the agent to revoke
        agent_did: String,
        /// DID of the controller who approved the revocation
        controller_did: String,
        /// Digest of the custody challenge the controller's passkey signed
        approval_digest: [u8; 32],
    },
    /// Record a delegated agent's terms in chain state, creating the agent
    /// or replacing its terms. Carries the controller's passkey approval,
    /// which every validator re-checks: the passkey the controller's DID
    /// derives from signed the custody challenge over exactly these terms.
    SetAgentTerms {
        /// The approved terms
        terms: crate::agent_terms::AgentTerms,
        /// `None` when creating the agent; the approved API-key rotation
        /// flag when replacing its terms
        rotate: Option<bool>,
        /// The controller's passkey approval
        approval: crate::agent_terms::AgentTermsApproval,
    },
    /// One action by a delegated agent, signed by the serving node that
    /// computed it with its hardware key for the agent. Executes only
    /// within the agent's terms as chain state records them.
    AgentAct {
        /// The action
        action: crate::agent_terms::AgentAction,
        /// The serving node's P-256 signature over the action digest
        signature: Vec<u8>,
    },
    /// A bonded validator's sealed USD rates for one closed epoch, and the
    /// opening of its sealed rates for the epoch before. Rates are sealed in
    /// the hour after their epoch closes and opened in the hour after that,
    /// so no validator sees another's rates before its own are fixed. Once
    /// the opening hour ends, each symbol's stake-weighted median of the
    /// opened rates moves the rate in force, smoothed and bounded per epoch
    /// by governed parameters. The TNZO rate prices fees (in validator
    /// mode); the others convert amounts named in other assets, such as a
    /// destination chain's native fee.
    FeeRateSubmit {
        /// Epoch (hours since the Unix epoch) the commitment seals
        epoch: u64,
        /// [`fee_rate_commitment`] of this epoch's quotes
        #[serde(with = "hex::serde")]
        commitment: [u8; 32],
        /// The opening of the commitment sent for `epoch - 1`, if any
        reveal: Option<FeeRateReveal>,
    },
    /// Filing or attesting an inference fault: a bonded provider's receipted
    /// answer that re-execution on other providers does not reproduce. Once
    /// two thirds of bonded stake upholds it the provider's bond refunds the
    /// requester and pays a penalty.
    InferenceFault {
        /// What to do
        op: crate::inference_verification::InferenceFaultOp,
    },
    /// An operation on a governed bridge route: an inbound credit, an
    /// outbound lock, a light-client update, or a data message (see
    /// [`crate::bridge_transfer::BridgeOp`]). The sender is the actor; an
    /// outbound transfer locks the sender's own TNZO.
    Bridge {
        /// The operation.
        op: crate::bridge_transfer::BridgeOp,
    },
    /// An operation on a token-factory token: create, mint, burn, transfer,
    /// or an issuer's compliance control (see
    /// [`crate::token_op::TokenOp`]). The sender is the issuer or the holder.
    Token {
        /// The operation.
        op: crate::token_op::TokenOp,
    },
    /// Bond, unbond or withdraw the sender's stake for one role (see
    /// [`crate::token::StakeOp`]). One stake per account per role; unbonded
    /// stake returns after the governed unbonding period.
    Stake {
        /// The operation.
        op: crate::token::StakeOp,
    },
    /// One report of an agent's account on another chain (a grant closed,
    /// an action taken, a void installed), delivered through that chain's
    /// route. Anyone may submit it.
    RemoteGrantSettle {
        /// The agent
        agent_did: String,
        /// The chain, CAIP-2
        chain: String,
        /// The route delivery carrying the report
        #[serde(with = "crate::remote_grant::hex_bytes")]
        delivery: Vec<u8>,
    },
    /// An operation on payment records (see
    /// [`crate::settlement::PaymentOp`]): the payee lists a delivery
    /// receipt, or a payment made on another chain or rail is recorded as
    /// proven or attested.
    Payment {
        /// The operation.
        op: crate::settlement::PaymentOp,
    },
    /// Lock TNZO against a treasury, sanction or protocol upgrade proposal
    /// in its veto escrow. Past the signal share of supply the timelock
    /// stretches; at the blocking share the proposal is voted again on the
    /// Ratify track.
    GovernanceVetoSignal {
        /// Hex-encoded 32-byte proposal id.
        proposal_id: String,
        /// TNZO to lock, in base units.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Return a holder's veto lock to it once its proposal is decided.
    /// Anyone may submit it; the lock only goes back to its holder.
    GovernanceVetoWithdraw {
        /// Hex-encoded 32-byte proposal id.
        proposal_id: String,
        /// The account that locked it.
        holder: Address,
    },
    /// An aged human root's concern on a queued proposal: a count that
    /// doubles the timelock once past the quorum, never weight.
    GovernanceConcern {
        /// Hex-encoded 32-byte proposal id.
        proposal_id: String,
    },
    /// A validator's machine signalling it runs the binary a protocol
    /// upgrade names, sent from the validator account. A protocol upgrade
    /// enacts only once validators holding the readiness share of bonded
    /// stake have sent one.
    UpgradeReady {
        /// Hex SHA-256 of the binary.
        code_hash: String,
        /// JSON TPM quote by the attestation key the validator's machine
        /// identity was admitted with, over
        /// `upgrade_ready_digest(code_hash, validator)`.
        quote: Vec<u8>,
    },
    /// Settle a security fix's vulnerability commitment: the disclosure
    /// that hashes to it, or, past the reveal deadline, nothing, which
    /// slashes the proposer.
    GovernanceSecurityDisclosure {
        /// Hex-encoded 32-byte proposal id.
        proposal_id: String,
        /// The disclosure, or empty to claim the lapse.
        disclosure: Vec<u8>,
    },
    /// An operation on a settlement plan: open it, or record a leg's
    /// evidence (see [`crate::settlement::PlanOp`]). Opening is sent by the
    /// payer; proving by anyone.
    SettlementPlan {
        /// The operation.
        op: crate::settlement::PlanOp,
    },
    /// A bonded validator's contribution to the randomness beacon: its VRF
    /// proof, under its registered node key, over the beacon's round and
    /// current mix.
    BeaconContribute {
        /// The round it is for.
        round: u64,
        /// The VRF proof.
        proof: Vec<u8>,
    },
    /// An operation on the registry of data-availability objects (see
    /// [`crate::da_retention::DaRetentionOp`]).
    DaRetention {
        /// The operation.
        op: crate::da_retention::DaRetentionOp,
    },
    /// An operation on the sender's own keys (see
    /// [`crate::account_signature::AccountKeysOp`]): enroll or replace its
    /// hardware ML-DSA-65 key.
    AccountKeys {
        /// The operation.
        op: crate::account_signature::AccountKeysOp,
    },
    /// A change to a passkey account's keystore (see
    /// [`crate::keystore::KeystoreUpdate`]): link or unlink a passkey, set its
    /// recovery signers, or start, cancel or complete a recovery. Approved by
    /// the account's passkeys or recovery signers; any account may send it.
    KeystoreUpdate {
        /// The change and its approvals.
        update: crate::keystore::KeystoreUpdate,
    },
    /// A change to a DID document's service entries (see
    /// [`crate::did_services::IdentityServiceOp`]), approved by the DID's
    /// root; any account may send it.
    IdentityServices {
        /// The change and its approval.
        op: crate::did_services::IdentityServiceOp,
    },
    /// An Ethereum transaction signed by an external secp256k1 wallet: the
    /// standard RLP envelope (EIP-155 legacy, EIP-2930, EIP-1559 or
    /// EIP-7702) exactly as the wallet signed it. Every validator decodes it
    /// and recovers the sender; the envelope's `from`, `to`, `nonce`,
    /// `gas_limit` and `chain_id` must equal the decoded values. The sender
    /// holds no agent authority.
    ExternalEvm {
        /// The signed RLP envelope.
        raw: Vec<u8>,
    },
    /// A Solana wire-format transaction signed by an external Ed25519
    /// wallet. Every validator verifies each required signature over the
    /// message; `from` must be the fee payer. The signers hold no agent
    /// authority.
    ExternalSvm {
        /// The signed wire transaction.
        raw: Vec<u8>,
    },
    /// Revoke an identity on its root's authority (see
    /// [`crate::identity::IdentityRevocationOp`]): the identity itself when
    /// it is a root, or the controller chain state names for a delegated
    /// agent. Every validator verifies the approval against keys in chain
    /// state; any account may send it.
    RevokeIdentity {
        /// The revocation and its approval.
        op: crate::identity::IdentityRevocationOp,
    },
    /// Put or retire an entry in the generic registry.
    Registry {
        /// What to do
        op: RegistryOp,
    },
    /// Let a delegated agent's wallet be refilled from its controller's
    /// wallet within an allowance; `None` cancels. Sent by the controller
    /// from the wallet its identity is registered with.
    SetAgentTopUp {
        /// DID of the agent refilled
        agent_did: String,
        /// DID of the agent's controller
        controller_did: String,
        /// Most moved per period (wei), period length (ms), the balance a
        /// refill brings the wallet up to (wei), and when the allowance ends
        /// (ms); `None` cancels it
        allowance: Option<(u128, u64, u128, i64)>,
    },
    /// Refill a delegated agent's wallet within its controller's allowance.
    /// Anyone may send it.
    TopUpAgent {
        /// DID of the agent refilled
        agent_did: String,
    },
    /// Move TNZO out of a delegated agent's wallet back to its controller:
    /// all of it, or `amount` wei. Sent by the controller from the wallet its
    /// identity is registered with; works whatever the agent's state.
    ReclaimAgentFunds {
        /// DID of the agent whose wallet is drawn from
        agent_did: String,
        /// DID of the agent's controller
        controller_did: String,
        /// Wei to move; `None` moves the whole balance
        amount: Option<u128>,
    },
    /// Replace the sender's consensus key, effective at the next epoch
    /// boundary, keeping its registration, bond and seat. The new key may
    /// be of any scheme governance admits.
    ///
    /// Authorization: `tx.from` MUST be a registered validator with a bond.
    RotateValidatorKey {
        /// The new key's ML-DSA leg (tagged with its scheme unless it is
        /// the default one).
        ml_dsa_pubkey: Vec<u8>,
        /// The new key's uncompressed SEC1 ECDSA leg.
        p256_pubkey: Vec<u8>,
        /// Composite signature by the new key over the registration message
        /// for the sender's address, the new key and the registered node
        /// key: proof that the validator holds it.
        proof_of_possession: Vec<u8>,
    },
    /// A proof about the hardware of the identity whose wallet sends it:
    /// that its machine still holds its TPM this reward epoch, or a further
    /// hardware attestation its level rests on.
    HardwareProof {
        /// The proof.
        op: crate::hardware_level::HardwareProofOp,
    },
    /// Name the machine identity of the sender's validator, for a validator
    /// whose consensus key does not name it (ML-DSA-87 / P-384), so peers
    /// hold that machine's endpoint records to its ML-DSA key from the
    /// first. Refused until governance enables it.
    ///
    /// Authorization: `tx.from` MUST be a registered validator with a bond,
    /// and both machine keys sign the registration message for it.
    RegisterValidatorMachine {
        /// The machine's hardware P-256 key, uncompressed SEC1.
        machine_p256: Vec<u8>,
        /// The ML-DSA-65 key the machine binds its endpoint records with.
        machine_ml_dsa: Vec<u8>,
        /// The P-256 key's signature over the SHA-256 of the registration
        /// message, `r || s`.
        p256_signature: Vec<u8>,
        /// The ML-DSA-65 key's signature over the registration message.
        ml_dsa_signature: Vec<u8>,
    },
    /// A key-release operation: register or revoke a model's release policy,
    /// or record one release of its content key to an attested environment
    /// (see [`crate::key_release`]).
    KeyRelease {
        /// The operation.
        op: crate::key_release::KeyReleaseOp,
    },
    /// A training proof operation ([`crate::training_verification`]): commit
    /// a round's signed receipt against its milestone escrow, challenge it,
    /// attest a replay, or settle it once its window has closed.
    TrainingProof {
        /// The operation.
        op: crate::training_verification::TrainingProofOp,
    },
    /// A TPM attestation attached to a machine root registered without one:
    /// signed by the root's identity key, sent by its wallet, refused once
    /// the root carries an attestation.
    AttachMachineAttestation {
        /// The attach.
        op: crate::identity::AttachMachineAttestationOp,
    },
    /// An operation on governance-sponsored validator bonds: returning a
    /// validator's matured unbonding sponsored stake to the treasury. Anyone
    /// may send it.
    SponsoredBond {
        /// The operation.
        op: SponsoredBondOp,
    },
    /// An operation on the sender's own opt-in outflow policy (set, remove,
    /// cancel a queued change, queue, cancel or claim a release). `op` is the
    /// JSON the VM's `account_outflow::Op` reads; the rules are in
    /// `tenzro-vm`. A guardian sends it from the guardian's own account for
    /// the account it guards.
    AccountOutflow {
        /// The operation, JSON.
        op: Vec<u8>,
    },
}

/// An operation on governance-sponsored validator bonds.
///
/// Sponsoring and recalling are governance actions; what a transaction does
/// is finish a recall or an exit once its unbonding period has passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsoredBondOp {
    /// Return `validator`'s matured unbonding sponsored stake to the
    /// treasury.
    Release {
        /// The validator whose sponsored stake returns.
        validator: Address,
    },
}

impl SponsoredBondOp {
    /// Reject a malformed operation before it is gossiped.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            SponsoredBondOp::Release { validator } => {
                if validator.as_bytes().iter().all(|b| *b == 0) {
                    return Err("a sponsored-bond release names its validator");
                }
                Ok(())
            }
        }
    }
}

/// An operation on the generic registry ([`crate::registry`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOp {
    /// Put a new version of entry `id`. The first put of an id takes the
    /// governed bond from the sender, who owns it from then on; later puts
    /// are its owner's.
    Put {
        id: String,
        kind: String,
        /// SHA-256 of the harness module that interprets the entry, hex.
        anchor: String,
        /// The entry's data, hex.
        data: String,
    },
    /// Retire entry `id`; its owner gets the bond back.
    Retire { id: String },
}

/// The opening of a sealed rate report: its quotes and the salt it was
/// sealed with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRateReveal {
    /// One quote per source
    pub quotes: Vec<FeeRateQuote>,
    /// The 32-byte salt the commitment was made with
    #[serde(with = "hex::serde")]
    pub salt: [u8; 32],
}

/// The commitment a validator seals its rates for `epoch` with: SHA-256 over
/// a domain tag, the validator's address, the epoch, the salt and each
/// quote's symbol, source and rate in order. Binding the address stops one
/// validator from copying another's sealed report.
pub fn fee_rate_commitment<'a>(
    validator: &[u8],
    epoch: u64,
    salt: &[u8; 32],
    quotes: impl IntoIterator<Item = (&'a str, &'a str, u128)>,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/fee-rate-commitment/v1");
    h.update((validator.len() as u32).to_le_bytes());
    h.update(validator);
    h.update(epoch.to_le_bytes());
    h.update(salt);
    for (symbol, source, rate) in quotes {
        for part in [symbol.as_bytes(), source.as_bytes()] {
            h.update((part.len() as u32).to_le_bytes());
            h.update(part);
        }
        h.update(rate.to_le_bytes());
    }
    h.finalize().into()
}

/// One source's quote in a [`TransactionType::FeeRateSubmit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRateQuote {
    /// The priced asset's symbol (`TNZO`, `ETH`, ...)
    pub symbol: String,
    /// Source name, as the validator's configuration names it
    pub source: String,
    /// Nano-USD per whole unit of the symbol
    #[serde(with = "crate::primitives::u128_serde")]
    pub rate_nano_usd: u128,
}

/// The signer set a signed rate stream's reports must carry, as governance
/// installs it. A validator reading the stream accepts a report only with
/// `threshold` distinct signatures from `signers`, so no operator's
/// configuration decides whose reports count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateStreamSigners {
    /// The stream's feed id.
    #[serde(with = "hex::serde")]
    pub feed_id: [u8; 32],
    /// The symbol the stream prices (`TNZO`, `ETH`, ...).
    pub symbol: String,
    /// The reporting oracles' secp256k1 addresses.
    pub signers: Vec<RateStreamSigner>,
    /// Distinct signatures a report needs.
    pub threshold: u8,
}

/// One oracle address in a [`RateStreamSigners`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RateStreamSigner(#[serde(with = "hex::serde")] pub [u8; 20]);

/// Most oracles one stream's signer set may name.
pub const MAX_RATE_STREAM_SIGNERS: usize = 31;

impl RateStreamSigners {
    /// Storage key of the set for `feed_id`.
    pub fn storage_key(feed_id: &[u8; 32]) -> String {
        format!("rate_stream:{}", hex::encode(feed_id))
    }

    /// Whether the set is usable: 1 to 31 distinct signers, a threshold
    /// above a third of them and at most all of them.
    pub fn validate(&self) -> Result<(), String> {
        let n = self.signers.len();
        if n == 0 || n > MAX_RATE_STREAM_SIGNERS {
            return Err(format!(
                "a rate stream names 1 to {MAX_RATE_STREAM_SIGNERS} signers"
            ));
        }
        let mut sorted = self.signers.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != n {
            return Err("a rate stream's signers are distinct".into());
        }
        let t = usize::from(self.threshold);
        if t == 0 || t > n || t * 3 <= n {
            return Err(format!(
                "threshold {t} must exceed a third of {n} signers and not exceed them"
            ));
        }
        let s = self.symbol.trim();
        if s.len() < 2 || s.len() > 12 || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!(
                "rate symbol {s:?} is not 2 to 12 letters or digits"
            ));
        }
        Ok(())
    }
}

/// A Proof-of-Reserve feed as governance installs it: the aggregator whose
/// latest round reports the reserve behind `asset_id`. Validators read a
/// reserve only through an installed feed, so no operator's configuration
/// decides which aggregator speaks for an asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveFeed {
    /// The asset the feed reports on (`tnzo:<route key>` for a bridge route).
    pub asset_id: String,
    /// The aggregator proxy contract, `0x` and 40 hex digits.
    pub aggregator_address: String,
    /// CAIP-2 id of the EVM chain the aggregator lives on (`eip155:<id>`).
    pub chain_caip2: String,
    /// Decimals of the feed's answer.
    pub decimals: u8,
    /// Oldest round, in seconds, a reading may come from.
    pub max_staleness_secs: u64,
}

/// Longest staleness bound a reserve feed may declare: one week.
pub const MAX_RESERVE_FEED_STALENESS_SECS: u64 = 7 * 24 * 60 * 60;

impl ReserveFeed {
    /// Storage key of the feed for `asset_id`.
    pub fn storage_key(asset_id: &str) -> String {
        format!("reserve_feed:{asset_id}")
    }

    /// Whether the feed is usable: a 1 to 128 character asset id without
    /// whitespace, a 20-byte hex aggregator address on an `eip155` chain, at
    /// most 36 decimals and a staleness bound of one minute to one week.
    pub fn validate(&self) -> Result<(), String> {
        let a = &self.asset_id;
        if a.is_empty() || a.len() > 128 || a.chars().any(char::is_whitespace) {
            return Err(format!(
                "reserve asset id {a:?} is not 1 to 128 characters without spaces"
            ));
        }
        let addr = self.aggregator_address.strip_prefix("0x").unwrap_or("");
        if addr.len() != 40 || !addr.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "aggregator address {:?} is not 0x and 40 hex digits",
                self.aggregator_address
            ));
        }
        let chain = self.chain_caip2.strip_prefix("eip155:").unwrap_or("");
        if chain.is_empty() || chain.len() > 32 || !chain.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "chain {:?} is not an eip155 CAIP-2 id",
                self.chain_caip2
            ));
        }
        if self.decimals > 36 {
            return Err(format!("{} decimals is above 36", self.decimals));
        }
        if self.max_staleness_secs < 60 || self.max_staleness_secs > MAX_RESERVE_FEED_STALENESS_SECS
        {
            return Err(format!(
                "staleness bound {}s is outside 60..={MAX_RESERVE_FEED_STALENESS_SECS}",
                self.max_staleness_secs
            ));
        }
        Ok(())
    }
}

/// An operation on a compute claim. Claims are written against hour-aligned
/// terms, hold their money in a per-claim vault, and settle on the SLA
/// verdicts and compute index validators commit, so no single node decides
/// their outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeClaimOp {
    /// Write a claim, posting `collateral` from the sender.
    Offer {
        /// `HardwareClass` as its `u8` discriminant
        hardware_class: u8,
        /// Upper-case country code, or empty for any region
        region: String,
        /// First hour of delivery (unix ms, on an hour boundary)
        delivery_start_ms: i64,
        /// Hours delivered
        epochs: u64,
        /// Price per hour, in wei
        #[serde(with = "crate::primitives::u128_serde")]
        strike_per_epoch: u128,
        /// Writer collateral, in wei: makes the holder whole for missed hours
        #[serde(with = "crate::primitives::u128_serde")]
        collateral: u128,
        /// The compute bond (or storage stake) the sender owns that delivers
        /// the claim
        provider_did: String,
        /// For a storage claim: SHA-256 of the bincode object descriptor the
        /// bond keeps retrievable. Each hour's verdict for the bond then
        /// includes a possession proof of that object.
        #[serde(default)]
        storage_descriptor: Option<String>,
        /// For a claim on metered capacity rather than a whole machine: the
        /// unit (a registry unit id, or one at a tier) the capacity is stated in,
        /// such as `output_tokens@model_class_x` or `accel_ms@class3`.
        #[serde(default)]
        unit: Option<String>,
        /// How many of `unit` each hour of the claim reserves. Zero exactly
        /// when `unit` is absent.
        #[serde(default, with = "crate::primitives::u128_serde")]
        units_per_epoch: u128,
    },
    /// Withdraw an unbought claim; the collateral returns.
    Cancel {
        /// Claim id
        claim_id: String,
    },
    /// Buy a claim, paying its total strike. Refused when that exceeds
    /// `max_total`, so a buyer's consent names an amount.
    Accept {
        /// Claim id
        claim_id: String,
        /// Most the buyer agrees to pay, in wei
        #[serde(with = "crate::primitives::u128_serde")]
        max_total: u128,
    },
    /// Settle whatever is due. Anyone may send it.
    Settle {
        /// Claim id
        claim_id: String,
    },
    /// Hand a held claim, with every hour still to settle, to another
    /// account. Only its holder may. Markets, pledges and loans over claims
    /// are built on this.
    Transfer {
        /// Claim id
        claim_id: String,
        /// Hex of the new holder's address
        to: String,
    },
}

/// One provider's outcome in a [`TransactionType::SlaAttest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaOutcome {
    /// DID the provider's compute bond is posted under
    pub provider_did: String,
    /// Whether it answered most of this validator's probes in time
    pub available: bool,
    /// Capacity the validator measured, when its probes measure one
    pub capacity: Option<u64>,
}

/// A signed transaction ready for submission.
///
/// `public_key` is the sender's P-256 key (`x || y`, 64 bytes); the account
/// address commits to it. `signature` is its P-256 leg (raw from a TPM or the
/// Secure Enclave, or a passkey assertion) and, when the account has enrolled
/// a hardware ML-DSA-65 key, the ML-DSA-65 leg. That key is read from account
/// state, and once enrolled its leg is mandatory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The transaction.
    pub transaction: Transaction,
    /// The sender's P-256 public key, `x || y`.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// The signature over the transaction hash.
    pub signature: crate::account_signature::CompositeSignature,
    #[serde(skip)]
    hash: Option<Hash>,
}

impl SignedTransaction {
    /// Wraps a transaction signed by an external wallet ([`TransactionType::ExternalEvm`]
    /// or [`TransactionType::ExternalSvm`]): the signature travels inside the
    /// raw bytes, so the envelope carries no key and no composite signature.
    pub fn external(transaction: Transaction) -> Self {
        Self {
            transaction,
            public_key: Vec::new(),
            signature: crate::account_signature::CompositeSignature::classical(
                crate::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
            hash: None,
        }
    }

    /// Creates a new signed transaction. Both the classical signature and the
    /// ML-DSA-65 signature are mandatory.
    pub fn new(
        transaction: Transaction,
        public_key: Vec<u8>,
        signature: crate::account_signature::CompositeSignature,
    ) -> Self {
        Self {
            transaction,
            public_key,
            signature,
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
    /// - The P-256 leg carries signature bytes
    /// - The public key is a 64-byte P-256 point
    /// - An ML-DSA-65 leg, when present, is 3309 bytes
    /// - Gas limit is non-zero
    /// - Addresses are non-zero
    /// - Transaction data size is within limits
    ///
    /// Note: This does NOT verify the cryptographic signature.
    /// Signature verification requires the crypto crate.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::typed_action::action_encodes(&self.transaction.tx_type) {
            return Err("a privileged transaction's amounts must each fit a JSON number");
        }
        if self.transaction.tx_type.is_external() {
            if self.signature.has_classical_leg() || !self.public_key.is_empty() {
                return Err(
                    "An external wallet transaction carries its signature in its raw bytes",
                );
            }
        } else if !self.signature.has_classical_leg() && self.signature.pq.is_none() {
            return Err("Transaction signature is empty");
        }
        if !self.transaction.tx_type.is_external() && self.public_key.len() != 64 {
            return Err("Transaction public key is not a 64-byte P-256 point");
        }
        if self.signature.pq.as_ref().is_some_and(|pq| {
            crate::signature_scheme::SignatureScheme::split_signature(pq).is_none()
        }) {
            return Err("ML-DSA leg names no known scheme or has the wrong length");
        }

        // Check gas limit is non-zero
        if self.transaction.gas_limit == 0 {
            return Err("Gas limit cannot be zero");
        }

        // Check sender is not zero address
        if self.transaction.from == Address::zero() {
            return Err("Sender address cannot be zero");
        }

        // Nothing but the typed action is signed for a privileged power.
        if self.transaction.memo.is_some()
            && crate::typed_action::action_class(&self.transaction.tx_type).is_some()
        {
            return Err("A privileged transaction carries no memo");
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
            TransactionType::ContractCall { calls } => VmCall::validate_list(calls)?,
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
            TransactionType::Funding { op } => {
                if op.is_empty() || op.len() > MAX_TX_DATA_SIZE {
                    return Err("Funding operation must be 1 byte to the maximum data size");
                }
            }
            TransactionType::GovernanceVetoSignal { proposal_id, .. }
            | TransactionType::GovernanceVetoWithdraw { proposal_id, .. }
            | TransactionType::GovernanceConcern { proposal_id } => {
                if proposal_id.len() != 64 || hex::decode(proposal_id).is_err() {
                    return Err("Proposal ID must be 64 hex characters (32 bytes)");
                }
            }
            TransactionType::GovernanceSecurityDisclosure {
                proposal_id,
                disclosure,
            } => {
                if proposal_id.len() != 64 || hex::decode(proposal_id).is_err() {
                    return Err("Proposal ID must be 64 hex characters (32 bytes)");
                }
                if disclosure.len() > 4096 {
                    return Err("A disclosure is at most 4096 bytes");
                }
            }
            TransactionType::UpgradeReady { code_hash, quote } => {
                if code_hash.len() != 64 || hex::decode(code_hash).is_err() {
                    return Err("Code hash must be 64 hex characters (32 bytes)");
                }
                if quote.is_empty() || quote.len() > MAX_TX_DATA_SIZE {
                    return Err("UpgradeReady carries a TPM quote within the maximum data size");
                }
            }
            TransactionType::GovernanceExecute { proposal_id } => {
                // A proposal id is a 32-byte hash rendered as hex. Checking the
                // shape here means a malformed id is refused at admission
                // rather than decoded into a silently different proposal.
                if proposal_id.len() != 64 || hex::decode(proposal_id).is_err() {
                    return Err("Proposal ID must be 64 hex characters (32 bytes)");
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
            TransactionType::PauseAgent {
                agent_did,
                reason_text,
                ..
            }
            | TransactionType::QuarantineAgent {
                agent_did,
                reason_text,
                ..
            } => {
                if agent_did.len() > 256 {
                    return Err("agent_did exceeds maximum length");
                }
                if let Some(t) = reason_text
                    && t.len() > 256
                {
                    return Err("reason_text exceeds 256 bytes");
                }
            }
            TransactionType::TerminateAgent {
                agent_did,
                slash_bps,
                ..
            } => {
                if agent_did.len() > 256 {
                    return Err("agent_did exceeds maximum length");
                }
                if *slash_bps > 10_000 {
                    return Err("slash_bps exceeds 100%");
                }
            }
            TransactionType::RegisterValidator {
                ml_dsa_pubkey,
                p256_pubkey,
                proof_of_possession,
                node_key_proof,
                vrf_key_proof,
                metadata_uri,
                ..
            } => {
                if node_key_proof.len() != 64 {
                    return Err("node_key_proof must be a 64-byte Ed25519 signature");
                }
                if vrf_key_proof.len() != 80 {
                    return Err("vrf_key_proof must be an 80-byte VRF proof");
                }
                if ml_dsa_pubkey.len() != 1952 {
                    return Err("ml_dsa_pubkey must be 1952 bytes (ML-DSA-65 vk)");
                }
                if p256_pubkey.len() != 65 {
                    return Err("p256_pubkey must be 65 bytes (uncompressed SEC1)");
                }
                if proof_of_possession.is_empty() || proof_of_possession.len() > 8_192 {
                    return Err("proof_of_possession must be a composite signature");
                }
                if metadata_uri.len() > 256 {
                    return Err("metadata_uri exceeds 256 bytes");
                }
            }
            TransactionType::ReportCheckpointEquivocation { evidence } => {
                if evidence.is_empty() || evidence.len() > 32 * 1024 {
                    return Err("evidence must be 1 to 32768 bytes");
                }
            }
            TransactionType::RecordCheckpointSigners { certificate } => {
                if certificate.is_empty() || certificate.len() > 1024 * 1024 {
                    return Err("certificate must be 1 to 1048576 bytes");
                }
            }
            TransactionType::AgentAuditCommit {
                root,
                entries_ref,
                attestation,
                ..
            } => {
                if root.len() != 32 {
                    return Err("an audit root is 32 bytes");
                }
                if entries_ref.len() > 1024 {
                    return Err("entries_ref exceeds 1024 bytes");
                }
                if attestation.len() > 8192 {
                    return Err("attestation exceeds 8192 bytes");
                }
            }
            TransactionType::LiftAgentQuarantine {
                agent_did,
                reason_text,
            } => {
                if agent_did.is_empty() || agent_did.len() > 256 {
                    return Err("agent_did must be 1 to 256 bytes");
                }
                if reason_text.as_ref().is_some_and(|t| t.len() > 256) {
                    return Err("reason_text exceeds 256 bytes");
                }
            }
            TransactionType::Bridge { op } => op.validate()?,
            TransactionType::SettlementPlan { op } => op.validate()?,
            TransactionType::Token { op } => op.validate()?,
            TransactionType::AccountKeys { op } => op.validate()?,
            TransactionType::KeystoreUpdate { update } => update.validate()?,
            TransactionType::IdentityServices { op } => op.validate()?,
            TransactionType::RevokeIdentity { op } => op.validate()?,
            TransactionType::BeaconContribute { proof, .. } => {
                if proof.len() != 80 {
                    return Err("a beacon contribution carries an 80-byte VRF proof");
                }
            }
            TransactionType::HardwareProof { op } => op.validate()?,
            TransactionType::KeyRelease { op } => {
                if op.validate().is_err() {
                    return Err("a key-release operation is malformed");
                }
            }
            TransactionType::AttachMachineAttestation { op } => op.validate()?,
            TransactionType::SponsoredBond { op } => op.validate()?,
            TransactionType::DaRetention { op } => op.validate()?,
            TransactionType::AgentAuditFlag { findings, .. } => {
                if findings.is_empty() || findings.len() > crate::agent_audit::MAX_FINDINGS {
                    return Err("a flag carries 1 to 256 findings");
                }
            }
            TransactionType::SetAgentTerms {
                terms, approval, ..
            } => {
                if terms.serving_nodes.len() > 16 {
                    return Err("an agent has at most 16 serving nodes");
                }
                if terms.credentials.len() > 16 {
                    return Err("an agent has at most 16 brokered credentials");
                }
                for c in &terms.credentials {
                    c.validate(&terms.serving_nodes)?;
                }
                if terms.delegation_scope.tool_pins.len() > crate::agent_terms::MAX_TOOL_PINS {
                    return Err("an agent pins at most 256 tools");
                }
                for p in &terms.delegation_scope.tool_pins {
                    p.validate()?;
                }
                if terms
                    .credentials
                    .iter()
                    .enumerate()
                    .any(|(i, c)| terms.credentials[..i].iter().any(|d| d.name == c.name))
                {
                    return Err("brokered credential names are unique");
                }
                approval.check_bounds()?;
            }
            TransactionType::RemoteGrantSettle {
                agent_did,
                chain,
                delivery,
            } => {
                if agent_did.is_empty()
                    || agent_did.len() > 256
                    || chain.is_empty()
                    || chain.len() > 128
                {
                    return Err("agent_did is 1 to 256 bytes and chain 1 to 128");
                }
                if delivery.len() > 65_536 {
                    return Err("a report delivery is at most 64 KiB");
                }
            }
            TransactionType::Payment { op } => match op {
                crate::settlement::PaymentOp::Receipt { .. } => {}
                crate::settlement::PaymentOp::SetSplit { rule } => {
                    if rule
                        .as_ref()
                        .is_some_and(|r| crate::settlement::validate_standing_split(r).is_err())
                    {
                        return Err("a standing split is a valid rule paying named accounts");
                    }
                }
                crate::settlement::PaymentOp::SetPayoutAssets { assets } => {
                    if assets.len() > 8 || assets.iter().any(|a| a.len() != 66) {
                        return Err(
                            "a payee lists at most 8 payout assets, each 0x and 64 hex digits",
                        );
                    }
                }
                crate::settlement::PaymentOp::Refund { amount, .. } => {
                    if *amount == 0 {
                        return Err("a refund returns a positive amount");
                    }
                }
                crate::settlement::PaymentOp::Proven {
                    agent_did,
                    chain,
                    delivery,
                } => {
                    if agent_did.is_empty()
                        || agent_did.len() > 256
                        || chain.is_empty()
                        || chain.len() > 128
                        || delivery.len() > 65_536
                    {
                        return Err(
                            "agent_did is 1 to 256 bytes, chain 1 to 128 and a delivery at most 64 KiB",
                        );
                    }
                }
                crate::settlement::PaymentOp::Attested { payment } => {
                    let fields = [
                        &payment.rail,
                        &payment.payer,
                        &payment.asset,
                        &payment.nonce,
                    ];
                    if fields.iter().any(|f| f.is_empty() || f.len() > 256) {
                        return Err(
                            "an attested payment's rail, payer, asset and nonce are 1 to 256 bytes",
                        );
                    }
                }
            },
            TransactionType::AgentAct { action, signature } => {
                if action.agent_did.is_empty() || action.agent_did.len() > 256 {
                    return Err("agent_did must be 1 to 256 bytes");
                }
                if signature.len() > 128 {
                    return Err("signature exceeds 128 bytes");
                }
                if !action.calls.is_empty() {
                    VmCall::validate_list(&action.calls)?;
                }
            }
            TransactionType::RevokeDelegatedAgent {
                agent_did,
                controller_did,
                ..
            } => {
                if agent_did.is_empty() || agent_did.len() > 256 {
                    return Err("agent_did must be 1 to 256 bytes");
                }
                if controller_did.is_empty() || controller_did.len() > 256 {
                    return Err("controller_did must be 1 to 256 bytes");
                }
            }
            TransactionType::UpdateValidatorMetadata { metadata_uri, .. } => {
                if let Some(uri) = metadata_uri
                    && uri.len() > 256
                {
                    return Err("metadata_uri exceeds 256 bytes");
                }
            }
            TransactionType::RegisterIdentity {
                did,
                identity_type,
                display_name,
                controller_pubkey,
                ..
            } => {
                if did.trim().is_empty() {
                    return Err("RegisterIdentity requires a non-empty did");
                }
                if did.len() > 256 {
                    return Err("did exceeds 256 bytes");
                }
                if !matches!(identity_type.as_str(), "human" | "machine" | "institution") {
                    return Err("identity_type must be human|machine|institution");
                }
                if display_name.len() > MAX_TX_DATA_SIZE {
                    return Err("display_name exceeds maximum size");
                }
                if controller_pubkey.len() > 128 {
                    return Err("controller_pubkey exceeds 128 bytes");
                }
            }
            TransactionType::AttestZkProof { proof } => {
                if proof.is_empty() {
                    return Err("AttestZkProof requires a proof envelope");
                }
                if proof.len() > MAX_ZK_PROOF_SIZE {
                    return Err("proof envelope exceeds maximum size");
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
        self.signature.has_classical_leg() && self.public_key.len() == 64
    }
}

#[cfg(test)]
mod valid_until_tests {
    use super::*;

    fn tx() -> Transaction {
        Transaction::new(
            ChainId::from(1337u64),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce::from(0u64),
            TransactionType::Transfer { amount: 1 },
            21_000,
            1,
        )
    }

    #[test]
    fn new_transaction_expires() {
        let t = tx();
        assert_eq!(t.valid_until.0 - t.timestamp.0, DEFAULT_TX_VALIDITY_MS);
    }

    #[test]
    fn valid_until_is_bound_into_the_hash() {
        let t = tx();
        let later = t
            .clone()
            .with_valid_until(Timestamp::new(t.valid_until.0 + 1));
        assert_ne!(t.hash(), later.hash());
    }

    #[test]
    fn a_transaction_without_valid_until_does_not_decode() {
        let mut v = serde_json::to_value(tx()).unwrap();
        v.as_object_mut().unwrap().remove("valid_until");
        assert!(serde_json::from_value::<Transaction>(v).is_err());
    }
}
