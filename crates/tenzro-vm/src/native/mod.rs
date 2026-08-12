//! Native transaction executor for Tenzro-specific operations
//!
//! This module implements a NativeExecutor for handling Tenzro-specific native transactions
//! including transfers, staking, unstaking, governance proposals, and voting.
//!
//! # Transaction Types
//!
//! The NativeExecutor handles the following transaction types:
//!
//! - **Transfer**: Simple value transfers (tx.data is empty)
//! - **ProviderStake**: Stake tokens to become a provider (selector: 0x01000001)
//! - **ProviderUnstake**: Unstake provider tokens (selector: 0x01000002)
//! - **GovernancePropose**: Create a governance proposal (selector: 0x02000001)
//! - **GovernanceVote**: Vote on a proposal (selector: 0x02000002)
//! - **CreateEscrow**: Lock funds in a derived vault (selector: 0x01000010)
//! - **ReleaseEscrow**: Drain vault → payee on proof (selector: 0x01000011)
//! - **RefundEscrow**: Drain vault → payer after expiry (selector: 0x01000012)
//! - **PauseAgent**: Reversibly pause an agent (selector: 0x1000001d)
//! - **QuarantineAgent**: Reversibly freeze an agent (selector: 0x1000001e)
//! - **TerminateAgent**: Irreversibly terminate + slash (selector: 0x1000001f)
//! - **Workflow* (12)**: Canton-native workflow ops (selectors 0x01000040..=0x0100004B)
//!
//! # Function Selectors
//!
//! Native transactions use 4-byte function selectors to identify the operation:
//!
//! ```text
//! 0x01000001 - ProviderStake(amount: u64)
//! 0x01000002 - ProviderUnstake(amount: u64)
//! 0x02000001 - GovernancePropose(proposal: bytes)
//! 0x02000002 - GovernanceVote(proposal_id: bytes32, vote: bool)
//! 0x01000010 - CreateEscrow(payee, amount, asset_id, expires_at, release_conditions)
//! 0x01000011 - ReleaseEscrow(escrow_id: bytes32, proof: ServiceProof)
//! 0x01000012 - RefundEscrow(escrow_id: bytes32)
//! 0x1000001d - PauseAgent(agent_did, reason_code, reason_text?, until?)
//! 0x1000001e - QuarantineAgent(agent_did, reason_code, reason_text?, evidence_hash?)
//! 0x1000001f - TerminateAgent(agent_did, reason_code, slash_bps, cascade)
//! 0x01000040 - WorkflowCreate(creator_did, title, participants, obligations, gates, policy)
//! 0x01000041 - WorkflowSign(workflow_id, signature, signed_by_pubkey)
//! 0x01000042 - WorkflowTransition(workflow_id, next_status, trigger)
//! 0x01000043 - WorkflowRegisterObligation(workflow_id, obligation)
//! 0x01000044 - WorkflowDischargeObligation(obligation_id, proof)
//! 0x01000045 - WorkflowDefaultObligation(obligation_id, reason)
//! 0x01000046 - WorkflowRegisterGate(workflow_id, gate)
//! 0x01000047 - WorkflowOpenApproval(gate_id, request)
//! 0x01000048 - WorkflowSubmitDecision(request_id, decision)
//! 0x01000049 - WorkflowKillSwitch(workflow_id, scope, reason)
//! 0x0100004A - WorkflowRegisterPrivacyDomain(domain)
//! 0x0100004B - WorkflowFreezePrivacyDomain(domain_id)
//! ```
//!
//! # Escrow Vault Semantics
//!
//! `CreateEscrow` derives a deterministic 32-byte `escrow_id` as
//! `SHA-256("tenzro/escrow/id" || payer || nonce_le)` and a vault `Address`
//! as `SHA-256("tenzro/escrow/vault" || escrow_id)`. The vault address has
//! no private key — only the `ReleaseEscrow` and `RefundEscrow` handlers may
//! debit/credit it via privileged `state.set_balance` writes. The total TNZO
//! supply invariant `Σ user balances + Σ funded vault balances = total supply`
//! must hold across all three handlers.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use tenzro_settlement::escrow::{EscrowAccount, EscrowStatus, verify_release_conditions};
use tenzro_types::asset::AssetId;
use tenzro_types::kill_switch::{KillSwitchAction, KillSwitchReceipt};
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};
use tenzro_types::settlement::{ReleaseConditions, ServiceProof};

use crate::{
    config::VmConfig,
    error::{Result, VmError},
    gas::GasMeter,
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log,
        StateChange, VmTransaction,
    },
};

// Function selectors (4 bytes)
const SELECTOR_PROVIDER_STAKE: [u8; 4] = [0x01, 0x00, 0x00, 0x01];
const SELECTOR_PROVIDER_UNSTAKE: [u8; 4] = [0x01, 0x00, 0x00, 0x02];
const SELECTOR_GOVERNANCE_PROPOSE: [u8; 4] = [0x02, 0x00, 0x00, 0x01];
const SELECTOR_GOVERNANCE_VOTE: [u8; 4] = [0x02, 0x00, 0x00, 0x02];
pub const SELECTOR_ESCROW_CREATE: [u8; 4] = [0x01, 0x00, 0x00, 0x10];
pub const SELECTOR_ESCROW_RELEASE: [u8; 4] = [0x01, 0x00, 0x00, 0x11];
pub const SELECTOR_ESCROW_REFUND: [u8; 4] = [0x01, 0x00, 0x00, 0x12];
// Kill-switch selectors (Agent-Swarm Spec 1) — exposed `pub` so the
// transaction encoder in `tenzro-node::event_loop::convert_transaction`
// can synthesise the VM dispatch payload from a `SignedTransaction`.
pub const SELECTOR_KILLSWITCH_PAUSE: [u8; 4] = [0x10, 0x00, 0x00, 0x1d];
pub const SELECTOR_KILLSWITCH_QUARANTINE: [u8; 4] = [0x10, 0x00, 0x00, 0x1e];
pub const SELECTOR_KILLSWITCH_TERMINATE: [u8; 4] = [0x10, 0x00, 0x00, 0x1f];
// AgentBond surety selectors (Agent-Swarm Spec 9). Exposed `pub` so the
// node-side encoder in `convert_transaction` can synthesise dispatch
// payloads from `SignedTransaction::{PostAgentBond,IncreaseAgentBond,
// WithdrawAgentBond}`.
pub const SELECTOR_POST_AGENT_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x20];
pub const SELECTOR_INCREASE_AGENT_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x21];
pub const SELECTOR_WITHDRAW_AGENT_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x22];
pub const SELECTOR_PAY_INSURANCE_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x23];
// x402 consensus-mediated settlement selector. Authorized by on-chain state,
// not by a payer signature: the node's system key signs the dispatching tx
// (like insurance-claim payout), the VM moves payer→payee balance, and a
// per-payment_id marker under `SYSTEM_ADDRESS` makes the settlement
// idempotent so a replayed dispatch cannot double-debit the payer. Exposed
// `pub` so the node-side encoder in `convert_transaction` can synthesise the
// dispatch payload from `SignedTransaction::X402Settle`.
pub const SELECTOR_X402_SETTLE: [u8; 4] = [0x01, 0x00, 0x00, 0x24];
// Compute-bond selectors. Every non-validator provider rung — model, compute,
// TEE, storage, RPC — admits registration only against an Active bond whose
// amount meets `ProviderType::required_stake` for the declared capacity. The
// bond is real locked TNZO in a derived vault, on the same consensus path as
// AgentBond. Exposed `pub` so the node-side encoder in `convert_transaction`
// can synthesise dispatch payloads from
// `SignedTransaction::{PostComputeBond,IncreaseComputeBond,WithdrawComputeBond,
// FinalizeComputeBondWithdrawal}`.
pub const SELECTOR_POST_COMPUTE_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x25];
pub const SELECTOR_INCREASE_COMPUTE_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x26];
pub const SELECTOR_WITHDRAW_COMPUTE_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x27];
pub const SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL: [u8; 4] = [0x01, 0x00, 0x00, 0x28];
// Dynamic validator-set selectors. Permissionless join / voluntary exit /
// metadata update. Authorization, churn caps, and state-machine transitions
// live in `tenzro_token::ValidatorRegistry` (the on-chain source of truth);
// the VM dispatcher emits a typed Log that the node-side post-execute scan
// translates into a registry mutation. Stake escrow / slashing piggyback on
// the existing `StakingManager` flow.
pub const SELECTOR_VALIDATOR_REGISTER: [u8; 4] = [0x01, 0x00, 0x00, 0x30];
pub const SELECTOR_VALIDATOR_EXIT: [u8; 4] = [0x01, 0x00, 0x00, 0x31];
pub const SELECTOR_VALIDATOR_UPDATE_METADATA: [u8; 4] = [0x01, 0x00, 0x00, 0x32];

// Workflow selectors (Canton-native multi-party workflow primitive).
//
// VM-side handlers are deliberately thin: they validate the payload, charge
// gas, persist a replay marker under `SYSTEM_ADDRESS`, and emit a typed Log.
// The structural mutation (against the in-memory `WorkflowManager` indices,
// privacy-domain registry, approval state machine, lifecycle clocks) is
// performed by the node-side `WorkflowRuntime` post-execute scan —
// same pattern used by `SELECTOR_VALIDATOR_*` for the dynamic validator set.
//
// Selectors `0x01000040..=0x0100004B` are reserved for workflow operations.
// Exposed `pub` so the node-side encoder in `convert_transaction` can build
// dispatch payloads from typed `SignedTransaction::Workflow*` variants.
pub const SELECTOR_WORKFLOW_CREATE: [u8; 4] = [0x01, 0x00, 0x00, 0x40];
pub const SELECTOR_WORKFLOW_SIGN: [u8; 4] = [0x01, 0x00, 0x00, 0x41];
pub const SELECTOR_WORKFLOW_TRANSITION: [u8; 4] = [0x01, 0x00, 0x00, 0x42];
pub const SELECTOR_WORKFLOW_REGISTER_OBLIGATION: [u8; 4] = [0x01, 0x00, 0x00, 0x43];
pub const SELECTOR_WORKFLOW_DISCHARGE_OBLIGATION: [u8; 4] = [0x01, 0x00, 0x00, 0x44];
pub const SELECTOR_WORKFLOW_DEFAULT_OBLIGATION: [u8; 4] = [0x01, 0x00, 0x00, 0x45];
pub const SELECTOR_WORKFLOW_REGISTER_GATE: [u8; 4] = [0x01, 0x00, 0x00, 0x46];
pub const SELECTOR_WORKFLOW_OPEN_APPROVAL: [u8; 4] = [0x01, 0x00, 0x00, 0x47];
pub const SELECTOR_WORKFLOW_SUBMIT_DECISION: [u8; 4] = [0x01, 0x00, 0x00, 0x48];
pub const SELECTOR_WORKFLOW_KILL_SWITCH: [u8; 4] = [0x01, 0x00, 0x00, 0x49];
pub const SELECTOR_WORKFLOW_REGISTER_PRIVACY_DOMAIN: [u8; 4] = [0x01, 0x00, 0x00, 0x4A];
pub const SELECTOR_WORKFLOW_FREEZE_PRIVACY_DOMAIN: [u8; 4] = [0x01, 0x00, 0x00, 0x4B];

// Node aliases — the readable name a node is addressed by. These are typed
// transactions rather than RPC writes because the network is permissionless:
// a registry held in one node's memory would mean whoever you asked decides
// who owns `alice`. Ordered by consensus, every node applies the same
// transition and first-claim-wins falls out of block order.
pub const SELECTOR_NODE_ALIAS_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x50];
pub const SELECTOR_NODE_ALIAS_BIND: [u8; 4] = [0x01, 0x00, 0x00, 0x51];
pub const SELECTOR_NODE_ALIAS_RELEASE: [u8; 4] = [0x01, 0x00, 0x00, 0x52];

// Identity registration (TDIP D5) — replicate a DID + its public record into
// consensus state so an identity created on one node resolves on every node.
// Same rationale as node aliases: a registry held in one node's memory would
// mean whoever you asked decides who owns a DID. Ordered by consensus, every
// node applies the same transition and DID uniqueness falls out of block order.
// Next free block after node-alias 0x50-0x52.
pub const SELECTOR_IDENTITY_REGISTER: [u8; 4] = [0x01, 0x00, 0x00, 0x60];

// Gas costs for native operations
const GAS_TRANSFER: u64 = 21_000;
const GAS_STAKE: u64 = 50_000;
const GAS_UNSTAKE: u64 = 50_000;
const GAS_PROPOSE: u64 = 100_000;
const GAS_VOTE: u64 = 30_000;
const GAS_ESCROW_CREATE: u64 = 75_000;
const GAS_ESCROW_RELEASE: u64 = 60_000;
const GAS_ESCROW_REFUND: u64 = 50_000;
// Kill-switch gas costs (controller-tier intervention is intentionally
// pricier than ordinary writes — discourages spam without making genuine
// pauses prohibitive).
const GAS_KILLSWITCH_PAUSE: u64 = 60_000;
const GAS_KILLSWITCH_QUARANTINE: u64 = 90_000;
const GAS_KILLSWITCH_TERMINATE: u64 = 120_000;
// AgentBond gas costs — bond writes are infrequent but each updates
// state-of-record + emits a log; price between escrow and kill-switch tiers.
const GAS_BOND_POST: u64 = 80_000;
const GAS_BOND_INCREASE: u64 = 50_000;
const GAS_BOND_WITHDRAW: u64 = 60_000;
// Compute-bond gas costs — same shape and same state footprint as the
// AgentBond writes, so the same prices apply.
const GAS_COMPUTE_BOND_POST: u64 = 80_000;
const GAS_COMPUTE_BOND_INCREASE: u64 = 50_000;
const GAS_COMPUTE_BOND_WITHDRAW: u64 = 60_000;
// Finalizing a withdrawal moves the vault balance back to the provider and
// clears the marker — one extra balance write over the withdraw path.
const GAS_COMPUTE_BOND_FINALIZE: u64 = 70_000;
// Cooldown between initiating a compute-bond withdrawal and being able to
// finalize it. Must match `tenzro_token::compute_bond::DEFAULT_COMPUTE_BOND_COOLDOWN_MS`.
const COMPUTE_BOND_COOLDOWN_MS: i64 = 7 * 24 * 60 * 60 * 1000;
// InsurancePool payouts: governance-approved, settled on-chain. Heavier than
// bond ops because they cross from singleton pool vault into a user wallet
// and persist a per-claim marker to make double-pay impossible.
const GAS_PAY_INSURANCE_CLAIM: u64 = 90_000;
// x402 settlement: one payer→payee balance move + per-payment_id replay
// marker. Priced at the transfer-plus-marker tier — heavier than a bare
// Transfer (writes a storage marker + emits an audit Log) but lighter than
// escrow release (no vault indirection, no proof verification).
const GAS_X402_SETTLE: u64 = 40_000;
// Dynamic validator-set gas costs. Register is the most expensive (writes
// 2 KiB+ of PQ key material to the registry index); update is cheap; exit
// is mid-tier (state-machine transition + index update).
const GAS_VALIDATOR_REGISTER: u64 = 150_000;
const GAS_VALIDATOR_EXIT: u64 = 80_000;
const GAS_VALIDATOR_UPDATE_METADATA: u64 = 50_000;

// Workflow gas costs. Workflow-create and gate-registration write the
// largest payloads (full participant + obligation + policy snapshot);
// signatures, decisions, and lifecycle transitions are cheap state writes;
// privacy-domain registration is mid-tier (X25519 recipient set + ACL
// metadata); kill-switch is dearer to discourage spam.
const GAS_WORKFLOW_CREATE: u64 = 80_000;
const GAS_WORKFLOW_SIGN: u64 = 40_000;
const GAS_WORKFLOW_TRANSITION: u64 = 50_000;
const GAS_WORKFLOW_REGISTER_OBLIGATION: u64 = 60_000;
const GAS_WORKFLOW_DISCHARGE_OBLIGATION: u64 = 70_000;
const GAS_WORKFLOW_DEFAULT_OBLIGATION: u64 = 60_000;
const GAS_WORKFLOW_REGISTER_GATE: u64 = 80_000;
const GAS_WORKFLOW_OPEN_APPROVAL: u64 = 50_000;
const GAS_WORKFLOW_SUBMIT_DECISION: u64 = 50_000;
const GAS_WORKFLOW_KILL_SWITCH: u64 = 100_000;
const GAS_WORKFLOW_REGISTER_PRIVACY_DOMAIN: u64 = 90_000;
const GAS_WORKFLOW_FREEZE_PRIVACY_DOMAIN: u64 = 40_000;

// Claiming is priced well above binding/releasing: it consumes a globally
// unique name out of a finite namespace, and a trivially cheap claim is a
// squatting subsidy.
const GAS_NODE_ALIAS_CLAIM: u64 = 100_000;
const GAS_NODE_ALIAS_BIND: u64 = 40_000;
const GAS_NODE_ALIAS_RELEASE: u64 = 25_000;

// Registering a DID consumes a globally unique name out of the DID namespace
// and writes a record every node must carry, so it is priced with the
// claim-class ops rather than the cheaper binds (TDIP D5).
const GAS_IDENTITY_REGISTER: u64 = 100_000;

// Maximum size of an inline workflow JSON payload. Workflows with payloads
// larger than this must be referenced by a DA pointer and submitted with the
// ReceiptEnvelope OffloadedDA mode by the caller; the VM rejects oversize
// dispatches outright to bound block-witness cost.
const WORKFLOW_PAYLOAD_MAX_BYTES: usize = 64 * 1024;

// Domain-separated hash prefixes for escrow id and vault address derivation
const ESCROW_ID_DOMAIN: &[u8] = b"tenzro/escrow/id";
const ESCROW_VAULT_DOMAIN: &[u8] = b"tenzro/escrow/vault";

// Domain-separated hash prefix for kill-switch receipt id derivation
const KILLSWITCH_RECEIPT_DOMAIN: &[u8] = b"tenzro/killswitch/receipt";

// Domain-separated hash prefix for AgentBond vault address derivation.
// Must match `tenzro_token::bond::derive_bond_vault_address`.
const AGENT_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/agent-bond/vault";

// Domain-separated hash prefix for compute-bond vault address derivation.
// Must match `tenzro_token::compute_bond::derive_compute_bond_vault_address`.
const COMPUTE_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/compute-bond/vault";

// Domain-separated hash prefix for the singleton InsurancePool vault address.
// Must match `tenzro_token::bond::derive_insurance_pool_address`.
const INSURANCE_POOL_VAULT_DOMAIN: &[u8] = b"tenzro/insurance-pool/vault";

// Bond slashing residual floor — must match `tenzro_token::bond::DEFAULT_MIN_RESIDUAL`.
// 10 TNZO (10 × 10^18). If the post-slash bond amount drops below this floor,
// the bond is fully drained and marked Slashed.
const BOND_MIN_RESIDUAL: u128 = 10 * 1_000_000_000_000_000_000u128;

// System address for native operations (all 0xFF)
const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];

// Staking vault: the reserved account that holds bonded validator stake.
// Bonded stake lives in replicated VM balance state (CF_ACCOUNTS → state root)
// so every node agrees on who bonded what — no side-structure drift. Distinct
// from SYSTEM_ADDRESS (0xFF..) so it can never alias a real or system account.
const STAKING_VAULT_ADDRESS: [u8; 20] = [0xFE; 20];

/// Native transaction executor for Tenzro-specific operations
pub struct NativeExecutor {
    _config: VmConfig,
}

impl NativeExecutor {
    /// Create a new native executor
    pub fn new(config: VmConfig) -> Result<Self> {
        Ok(Self { _config: config })
    }

    /// Handle a simple transfer transaction
    async fn execute_transfer(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        tracing::debug!(
            "Executing native transfer: from={}, to={:?}, value={}",
            hex::encode(&tx.from),
            tx.to.as_ref().map(hex::encode),
            tx.value
        );

        // Consume gas for transfer
        gas_meter.consume(GAS_TRANSFER)?;

        let to = tx.to.as_ref().ok_or_else(|| {
            VmError::InvalidTransaction("Transfer requires recipient address".to_string())
        })?;

        // Calculate total cost (value + gas cost)
        let gas_cost = tx.gas_price.saturating_mul(GAS_TRANSFER as u128);
        let total_cost = tx
            .value
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("Transfer amount overflow".to_string()))?;

        // Check sender balance
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: sender_balance,
            });
        }

        // Record old values for state changes
        let old_sender_balance = sender_balance;
        let old_receiver_balance = state.get_balance(to);
        let old_sender_nonce = state.get_nonce(&tx.from);

        // Debit sender (value + gas cost)
        let new_sender_balance = sender_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_sender_balance);

        // Credit receiver (value only)
        let new_receiver_balance = old_receiver_balance
            .checked_add(tx.value)
            .ok_or_else(|| VmError::Internal("Receiver balance overflow".to_string()))?;
        state.set_balance(to, new_receiver_balance);

        // Increment sender nonce
        state.set_nonce(&tx.from, old_sender_nonce + 1);

        // Create state changes
        let state_changes = vec![
            // Sender balance change
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(old_sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ),
            // Receiver balance change
            StateChange::new(
                to.clone(),
                b"balance".to_vec(),
                Some(old_receiver_balance.to_le_bytes().to_vec()),
                Some(new_receiver_balance.to_le_bytes().to_vec()),
            ),
            // Sender nonce change
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_sender_nonce.to_le_bytes().to_vec()),
                Some((old_sender_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            Vec::new(),
            state_changes,
        ))
    }

    /// Handle a provider stake transaction
    async fn execute_stake(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        tracing::debug!("Executing native stake: from={}", hex::encode(&tx.from));

        // Consume gas for staking
        gas_meter.consume(GAS_STAKE)?;

        // Decode amount from tx.data (skip 4-byte selector, read next 8 bytes as u64 LE)
        if tx.data.len() < 12 {
            return Err(VmError::InvalidTransaction(
                "Stake transaction requires selector + amount (12 bytes minimum)".to_string(),
            ));
        }

        let amount_bytes: [u8; 8] = tx.data[4..12].try_into().map_err(|_| {
            VmError::InvalidTransaction("Invalid stake amount encoding".to_string())
        })?;
        let stake_amount = u64::from_le_bytes(amount_bytes) as u128;

        // Calculate total cost (stake amount + gas cost)
        let gas_cost = tx.gas_price.saturating_mul(GAS_STAKE as u128);
        let total_cost = stake_amount
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("Stake cost overflow".to_string()))?;

        // Check sender balance
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: sender_balance,
            });
        }

        // Debit sender balance
        let new_balance = sender_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_balance);

        // Load existing stake
        let stake_key = format!("stake:{}", hex::encode(&tx.from));
        let existing_stake = state
            .get_storage(&SYSTEM_ADDRESS, stake_key.as_bytes())
            .and_then(|bytes| {
                if bytes.len() >= 8 {
                    let stake_bytes: [u8; 8] = bytes[..8].try_into().ok()?;
                    Some(u64::from_le_bytes(stake_bytes) as u128)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Update stake
        let new_stake = existing_stake
            .checked_add(stake_amount)
            .ok_or_else(|| VmError::Internal("Stake amount overflow".to_string()))?;

        // Store new stake (as u64 for compatibility with token amounts)
        let new_stake_u64 = new_stake.min(u64::MAX as u128) as u64;
        state.set_storage(
            &SYSTEM_ADDRESS,
            stake_key.as_bytes(),
            new_stake_u64.to_le_bytes().to_vec(),
        );

        // Increment sender nonce
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Create state changes
        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                stake_key.as_bytes().to_vec(),
                Some(existing_stake.to_le_bytes().to_vec()),
                Some(new_stake.to_le_bytes().to_vec()),
            ),
        ];

        // Emit log
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"Staked".to_vec()],
            [tx.from.as_slice(), &new_stake_u64.to_le_bytes()].concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a provider unstake transaction
    async fn execute_unstake(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        tracing::debug!("Executing native unstake: from={}", hex::encode(&tx.from));

        // Consume gas for unstaking
        gas_meter.consume(GAS_UNSTAKE)?;

        // Decode amount from tx.data
        if tx.data.len() < 12 {
            return Err(VmError::InvalidTransaction(
                "Unstake transaction requires selector + amount (12 bytes minimum)".to_string(),
            ));
        }

        let amount_bytes: [u8; 8] = tx.data[4..12].try_into().map_err(|_| {
            VmError::InvalidTransaction("Invalid unstake amount encoding".to_string())
        })?;
        let unstake_amount = u64::from_le_bytes(amount_bytes) as u128;

        // Load existing stake
        let stake_key = format!("stake:{}", hex::encode(&tx.from));
        let existing_stake = state
            .get_storage(&SYSTEM_ADDRESS, stake_key.as_bytes())
            .and_then(|bytes| {
                if bytes.len() >= 8 {
                    let stake_bytes: [u8; 8] = bytes[..8].try_into().ok()?;
                    Some(u64::from_le_bytes(stake_bytes) as u128)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Validate unstake amount
        if unstake_amount > existing_stake {
            return Err(VmError::InvalidTransaction(format!(
                "Insufficient stake: requested {}, available {}",
                unstake_amount, existing_stake
            )));
        }

        // Calculate gas cost
        let gas_cost = tx.gas_price.saturating_mul(GAS_UNSTAKE as u128);

        // Check sender has enough balance for gas
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }

        // Update stake
        let new_stake = existing_stake.saturating_sub(unstake_amount);
        let new_stake_u64 = new_stake.min(u64::MAX as u128) as u64;
        state.set_storage(
            &SYSTEM_ADDRESS,
            stake_key.as_bytes(),
            new_stake_u64.to_le_bytes().to_vec(),
        );

        // Credit sender balance (unstake amount - gas cost)
        let new_balance = sender_balance
            .saturating_add(unstake_amount)
            .saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_balance);

        // Increment sender nonce
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Create state changes
        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                stake_key.as_bytes().to_vec(),
                Some(existing_stake.to_le_bytes().to_vec()),
                Some(new_stake.to_le_bytes().to_vec()),
            ),
        ];

        // Emit log
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"Unstaked".to_vec()],
            [tx.from.as_slice(), &(unstake_amount as u64).to_le_bytes()].concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a governance proposal transaction
    async fn execute_propose(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        tracing::debug!(
            "Executing governance proposal: from={}",
            hex::encode(&tx.from)
        );

        // Consume gas for proposal
        gas_meter.consume(GAS_PROPOSE)?;

        // Extract proposal data (everything after 4-byte selector)
        if tx.data.len() < 5 {
            return Err(VmError::InvalidTransaction(
                "Proposal transaction requires selector + proposal data".to_string(),
            ));
        }

        let proposal_data = &tx.data[4..];

        // Calculate gas cost
        let gas_cost = tx.gas_price.saturating_mul(GAS_PROPOSE as u128);

        // Check sender balance for gas
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }

        // Debit gas cost
        let new_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_balance);

        // Hash proposal to generate ID
        let mut hasher = Sha256::new();
        hasher.update(&tx.from);
        hasher.update(proposal_data);
        hasher.update(state.get_nonce(&tx.from).to_le_bytes());
        let proposal_hash = hasher.finalize();
        let proposal_id = hex::encode(&proposal_hash[..]);

        // Store proposal
        let proposal_key = format!("proposal:{}", proposal_id);
        state.set_storage(
            &SYSTEM_ADDRESS,
            proposal_key.as_bytes(),
            proposal_data.to_vec(),
        );

        // Increment proposal counter
        let counter_key = b"proposal_counter";
        let current_count = state
            .get_storage(&SYSTEM_ADDRESS, counter_key)
            .and_then(|bytes| {
                if bytes.len() >= 8 {
                    let count_bytes: [u8; 8] = bytes[..8].try_into().ok()?;
                    Some(u64::from_le_bytes(count_bytes))
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let new_count = current_count + 1;
        state.set_storage(
            &SYSTEM_ADDRESS,
            counter_key,
            new_count.to_le_bytes().to_vec(),
        );

        // Increment sender nonce
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Create state changes
        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                proposal_key.as_bytes().to_vec(),
                None,
                Some(proposal_data.to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                counter_key.to_vec(),
                Some(current_count.to_le_bytes().to_vec()),
                Some(new_count.to_le_bytes().to_vec()),
            ),
        ];

        // Emit log with proposal ID
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ProposalCreated".to_vec()],
            [proposal_hash.as_slice(), tx.from.as_slice()].concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            proposal_hash.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a governance vote transaction
    async fn execute_vote(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        tracing::debug!("Executing governance vote: from={}", hex::encode(&tx.from));

        // Consume gas for voting
        gas_meter.consume(GAS_VOTE)?;

        // Extract proposal ID (32 bytes) and vote (1 byte)
        if tx.data.len() < 37 {
            return Err(VmError::InvalidTransaction(
                "Vote transaction requires selector + proposal_id (32 bytes) + vote (1 byte)"
                    .to_string(),
            ));
        }

        let proposal_id_bytes = &tx.data[4..36];
        let proposal_id = hex::encode(proposal_id_bytes);
        let vote_byte = tx.data[36];
        let _vote = vote_byte != 0; // Vote value (true/false), used in logs

        // Check if proposal exists
        let proposal_key = format!("proposal:{}", proposal_id);
        let proposal_exists = state
            .get_storage(&SYSTEM_ADDRESS, proposal_key.as_bytes())
            .is_some();

        if !proposal_exists {
            return Err(VmError::InvalidTransaction(format!(
                "Proposal {} does not exist",
                proposal_id
            )));
        }

        // Calculate gas cost
        let gas_cost = tx.gas_price.saturating_mul(GAS_VOTE as u128);

        // Check sender balance for gas
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }

        // Debit gas cost
        let new_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_balance);

        // Store vote
        let vote_key = format!("vote:{}:{}", proposal_id, hex::encode(&tx.from));
        let old_vote = state.get_storage(&SYSTEM_ADDRESS, vote_key.as_bytes());
        state.set_storage(&SYSTEM_ADDRESS, vote_key.as_bytes(), vec![vote_byte]);

        // Increment sender nonce
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Create state changes
        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                vote_key.as_bytes().to_vec(),
                old_vote,
                Some(vec![vote_byte]),
            ),
        ];

        // Emit log
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"VoteCast".to_vec()],
            [proposal_id_bytes, tx.from.as_slice(), &[vote_byte]].concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![log],
            state_changes,
        ))
    }

    // ---- Escrow handlers ----------------------------------------------------

    /// Handle a `CreateEscrow` native transaction.
    ///
    /// Decodes a JSON-encoded `CreateEscrowPayload` from `tx.data[4..]`, derives
    /// a deterministic 32-byte `escrow_id` and a vault `Address`, debits the
    /// payer (gas + amount), credits the vault, and persists a serialized
    /// `EscrowAccount{Funded}` under `SYSTEM_ADDRESS` at storage key
    /// `escrow:<hex(escrow_id)>`. Emits an `EscrowCreated` log carrying
    /// `(escrow_id || payer_addr)`. The `escrow_id` is also returned as the
    /// transaction output so callers can observe it without scanning logs.
    ///
    /// Authorization: `tx.from` is the payer. The block builder is responsible
    /// for verifying the signature before reaching this handler.
    async fn execute_escrow_create(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_ESCROW_CREATE)?;

        let payload_bytes = &tx.data[4..];
        let payload: CreateEscrowPayload = serde_json::from_slice(payload_bytes).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid CreateEscrow payload: {}", e))
        })?;

        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "Escrow amount must be greater than zero".to_string(),
            ));
        }

        // Derive escrow_id and vault address.
        let payer_addr = address_from_tx_from(&tx.from)?;
        let escrow_id = derive_escrow_id(&payer_addr, tx.nonce);
        let vault_addr = derive_vault_address(&escrow_id);
        let escrow_id_hex = hex::encode(escrow_id);

        // Reject collisions on the (vanishingly unlikely) chance an escrow with
        // the same id already exists. This makes the handler idempotent under
        // replay attempts.
        let storage_key = escrow_storage_key(&escrow_id_hex);
        if state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .is_some()
        {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {} already exists",
                escrow_id_hex
            )));
        }

        // Total cost = gas + escrowed amount. Must come from payer balance.
        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_CREATE as u128);
        let total_cost = payload
            .amount
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("Escrow create cost overflow".to_string()))?;

        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: payer_balance,
            });
        }

        let new_payer_balance = payer_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Privileged credit to the vault address. Vault has no key — only this
        // VM helper, `vault_payout`, may move funds in or out of vaults.
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        let new_vault_balance = old_vault_balance
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("Vault balance overflow".to_string()))?;
        state.set_balance(&vault_bytes, new_vault_balance);

        // Build and persist the escrow record.
        let payee_bytes = payload.payee.as_bytes();
        let payee_addr_padded = pad_address_32(payee_bytes)?;

        let now_millis = deterministic_now_ms(tx);
        let escrow = EscrowAccount {
            escrow_id: escrow_id_hex.clone(),
            payer: payer_addr,
            payee: Address::new(payee_addr_padded),
            amount: payload.amount,
            asset_id: payload.asset_id.clone(),
            created_at: Timestamp::new(now_millis),
            expires_at: Timestamp::new(payload.expires_at as i64),
            status: EscrowStatus::Funded,
            release_conditions: payload.release_conditions.clone(),
        };
        let escrow_blob = serde_json::to_vec(&escrow)
            .map_err(|e| VmError::Internal(format!("Failed to serialize escrow record: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), escrow_blob.clone());

        // Increment payer nonce.
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes.clone(),
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                None,
                Some(escrow_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"EscrowCreated".to_vec()],
            [escrow_id.as_slice(), tx.from.as_slice(), &vault_bytes].concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            escrow_id.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `ReleaseEscrow` native transaction.
    ///
    /// Decodes a JSON-encoded `ReleaseEscrowPayload`. Asserts that
    /// `tx.from == escrow.payer`, the escrow is `Funded`, not expired, and that
    /// the proof satisfies the release conditions. Then drains the vault into
    /// the payee balance and marks the escrow `Released`.
    async fn execute_escrow_release(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_ESCROW_RELEASE)?;

        let payload: ReleaseEscrowPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid ReleaseEscrow payload: {}", e))
        })?;

        let escrow_id_hex = hex::encode(payload.escrow_id);
        let storage_key = escrow_storage_key(&escrow_id_hex);
        let escrow_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {} not found", escrow_id_hex))
            })?;
        let mut escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
            VmError::Internal(format!(
                "Failed to decode escrow record {}: {}",
                escrow_id_hex, e
            ))
        })?;

        // Authorization: only the original payer may release.
        let payer_addr = address_from_tx_from(&tx.from)?;
        if escrow.payer != payer_addr {
            return Err(VmError::InvalidTransaction(
                "EscrowUnauthorized: only payer can release".to_string(),
            ));
        }
        if escrow.status != EscrowStatus::Funded {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {} is not in Funded state ({:?})",
                escrow_id_hex, escrow.status
            )));
        }
        let now_millis = deterministic_now_ms(tx);
        if now_millis > escrow.expires_at.0 {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {} has expired",
                escrow_id_hex
            )));
        }

        // Verify the proof against the encoded release conditions.
        verify_release_conditions(&escrow.release_conditions, &payload.proof).map_err(|e| {
            VmError::InvalidTransaction(format!("Proof verification failed: {}", e))
        })?;

        // Charge payer for gas.
        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_RELEASE as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Drain vault → payee.
        let vault_addr = derive_vault_address(&payload.escrow_id);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        if old_vault_balance < escrow.amount {
            return Err(VmError::Internal(format!(
                "Vault for escrow {} underfunded: held {}, expected {}",
                escrow_id_hex, old_vault_balance, escrow.amount
            )));
        }
        let new_vault_balance = old_vault_balance.saturating_sub(escrow.amount);
        state.set_balance(&vault_bytes, new_vault_balance);

        let payee_bytes = escrow.payee.as_bytes().to_vec();
        let old_payee_balance = state.get_balance(&payee_bytes);
        let new_payee_balance = old_payee_balance
            .checked_add(escrow.amount)
            .ok_or_else(|| VmError::Internal("Payee balance overflow".to_string()))?;
        state.set_balance(&payee_bytes, new_payee_balance);

        // Update escrow record.
        escrow.status = EscrowStatus::Released;
        let new_blob = serde_json::to_vec(&escrow)
            .map_err(|e| VmError::Internal(format!("Failed to serialize escrow record: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), new_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes.clone(),
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                payee_bytes.clone(),
                b"balance".to_vec(),
                Some(old_payee_balance.to_le_bytes().to_vec()),
                Some(new_payee_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(escrow_blob),
                Some(new_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"EscrowReleased".to_vec()],
            [
                payload.escrow_id.as_slice(),
                payee_bytes.as_slice(),
                &escrow.amount.to_le_bytes(),
            ]
            .concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.escrow_id.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `RefundEscrow` native transaction.
    ///
    /// Authorization: `tx.from == escrow.payer` AND (escrow expired OR
    /// release conditions ∈ {Timeout, Custom}). Drains the vault back to the
    /// payer and marks the escrow `Refunded`.
    async fn execute_escrow_refund(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_ESCROW_REFUND)?;

        let payload: RefundEscrowPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid RefundEscrow payload: {}", e))
        })?;

        let escrow_id_hex = hex::encode(payload.escrow_id);
        let storage_key = escrow_storage_key(&escrow_id_hex);
        let escrow_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {} not found", escrow_id_hex))
            })?;
        let mut escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
            VmError::Internal(format!(
                "Failed to decode escrow record {}: {}",
                escrow_id_hex, e
            ))
        })?;

        // Authorization: only the original payer may refund.
        let payer_addr = address_from_tx_from(&tx.from)?;
        if escrow.payer != payer_addr {
            return Err(VmError::InvalidTransaction(
                "EscrowUnauthorized: only payer can refund".to_string(),
            ));
        }
        if escrow.status != EscrowStatus::Funded {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {} is not in Funded state ({:?})",
                escrow_id_hex, escrow.status
            )));
        }

        // Refund is permitted if expired OR if release conditions don't require
        // a counterparty (Timeout / Custom).
        let now_millis = deterministic_now_ms(tx);
        let is_expired = now_millis > escrow.expires_at.0;
        let conditions_allow_refund = matches!(
            escrow.release_conditions,
            ReleaseConditions::Timeout | ReleaseConditions::Custom { .. }
        );
        if !is_expired && !conditions_allow_refund {
            return Err(VmError::InvalidTransaction(
                "EscrowNotExpired: refund disallowed before expiry under these conditions"
                    .to_string(),
            ));
        }

        // Charge payer for gas.
        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_REFUND as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance_after_gas = payer_balance.saturating_sub(gas_cost);

        // Drain vault → payer (refund).
        let vault_addr = derive_vault_address(&payload.escrow_id);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        if old_vault_balance < escrow.amount {
            return Err(VmError::Internal(format!(
                "Vault for escrow {} underfunded: held {}, expected {}",
                escrow_id_hex, old_vault_balance, escrow.amount
            )));
        }
        let new_vault_balance = old_vault_balance.saturating_sub(escrow.amount);
        state.set_balance(&vault_bytes, new_vault_balance);

        // Credit refund into payer (after the gas debit).
        let new_payer_balance = new_payer_balance_after_gas
            .checked_add(escrow.amount)
            .ok_or_else(|| VmError::Internal("Payer balance overflow".to_string()))?;
        state.set_balance(&tx.from, new_payer_balance);

        // Update escrow record.
        escrow.status = EscrowStatus::Refunded;
        let new_blob = serde_json::to_vec(&escrow)
            .map_err(|e| VmError::Internal(format!("Failed to serialize escrow record: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), new_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes.clone(),
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(escrow_blob),
                Some(new_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"EscrowRefunded".to_vec()],
            [
                payload.escrow_id.as_slice(),
                tx.from.as_slice(),
                &escrow.amount.to_le_bytes(),
            ]
            .concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.escrow_id.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    // ---- Kill-switch handlers (Agent-Swarm Spec 1) --------------------------
    //
    // All three handlers share the same shape:
    //   1. consume gas
    //   2. decode JSON payload from `tx.data[4..]`
    //   3. validate fields (bps cap, non-empty DIDs, reason_text length)
    //   4. charge sender for gas
    //   5. derive a deterministic 32-byte receipt id
    //   6. build a `KillSwitchReceipt` and persist it under
    //      `killswitch:<hex_id>` at `SYSTEM_ADDRESS`
    //   7. emit a `Log` whose topic identifies the action and whose data is
    //      `agent_did_len_le(4) || agent_did || controller_did_len_le(4) ||
    //      controller_did || receipt_id(32)`. This is what the node-side
    //      post-execute scan parses to dispatch lifecycle FSM transitions
    //      (`AgentRuntime::pause_agent`/etc.) and to write the canonical
    //      `KillSwitchReceipt` (with the real `frozen_at_block`) to
    //      `KillSwitchStore` in `CF_SETTLEMENTS`.
    //
    // The receipt persisted here uses `tx.nonce` as a placeholder for
    // `frozen_at_block`; the node rewrites that field when it observes the
    // log so the on-chain artifact has the correct block height.

    async fn execute_killswitch_pause(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_KILLSWITCH_PAUSE)?;

        let payload: PauseAgentPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid PauseAgent payload: {}", e))
        })?;

        validate_killswitch_dids(&payload.agent_did, &payload.controller_did)?;
        validate_reason_text_len(payload.reason_text.as_deref())?;

        // Charge sender for gas.
        let gas_cost = tx.gas_price.saturating_mul(GAS_KILLSWITCH_PAUSE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let new_sender_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_sender_balance);

        let receipt_id = derive_killswitch_receipt_id(
            KillSwitchAction::Pause.as_str(),
            &payload.agent_did,
            &payload.controller_did,
            tx.nonce,
        );
        let receipt_id_hex = hex::encode(receipt_id);

        let receipt = KillSwitchReceipt {
            receipt_id: receipt_id_hex.clone(),
            action: KillSwitchAction::Pause,
            agent_did: payload.agent_did.clone(),
            controller_did: payload.controller_did.clone(),
            reason_code: payload.reason_code,
            reason_text: payload.reason_text.clone(),
            evidence_hash: None,
            slash_bps: None,
            cascade: None,
            pause_until: payload.until,
            // Stand-in: node-side scan rewrites this to the real block height
            // before persisting to KillSwitchStore.
            frozen_at_block: BlockHeight::new(tx.nonce),
            timestamp: Timestamp::new(deterministic_now_ms(tx)),
        };
        let blob = serde_json::to_vec(&receipt).map_err(|e| {
            VmError::Internal(format!("Failed to serialize KillSwitchReceipt: {}", e))
        })?;
        let storage_key = killswitch_storage_key(&receipt_id_hex);
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                None,
                Some(blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"KillSwitchPause".to_vec()],
            encode_killswitch_log_data(&payload.agent_did, &payload.controller_did, &receipt_id),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            receipt_id.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    async fn execute_killswitch_quarantine(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_KILLSWITCH_QUARANTINE)?;

        let payload: QuarantineAgentPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid QuarantineAgent payload: {}", e))
            })?;

        validate_killswitch_dids(&payload.agent_did, &payload.controller_did)?;
        validate_reason_text_len(payload.reason_text.as_deref())?;
        if let Some(ref hash) = payload.evidence_hash {
            validate_evidence_hash(hash)?;
        }

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_KILLSWITCH_QUARANTINE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let new_sender_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_sender_balance);

        let receipt_id = derive_killswitch_receipt_id(
            KillSwitchAction::Quarantine.as_str(),
            &payload.agent_did,
            &payload.controller_did,
            tx.nonce,
        );
        let receipt_id_hex = hex::encode(receipt_id);

        let receipt = KillSwitchReceipt {
            receipt_id: receipt_id_hex.clone(),
            action: KillSwitchAction::Quarantine,
            agent_did: payload.agent_did.clone(),
            controller_did: payload.controller_did.clone(),
            reason_code: payload.reason_code,
            reason_text: payload.reason_text.clone(),
            evidence_hash: payload.evidence_hash.clone(),
            slash_bps: None,
            cascade: None,
            pause_until: None,
            frozen_at_block: BlockHeight::new(tx.nonce),
            timestamp: Timestamp::new(deterministic_now_ms(tx)),
        };
        let blob = serde_json::to_vec(&receipt).map_err(|e| {
            VmError::Internal(format!("Failed to serialize KillSwitchReceipt: {}", e))
        })?;
        let storage_key = killswitch_storage_key(&receipt_id_hex);
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                None,
                Some(blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"KillSwitchQuarantine".to_vec()],
            encode_killswitch_log_data(&payload.agent_did, &payload.controller_did, &receipt_id),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            receipt_id.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    async fn execute_killswitch_terminate(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_KILLSWITCH_TERMINATE)?;

        let payload: TerminateAgentPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid TerminateAgent payload: {}", e))
            })?;

        validate_killswitch_dids(&payload.agent_did, &payload.controller_did)?;
        if payload.slash_bps > 10_000 {
            return Err(VmError::InvalidTransaction(format!(
                "TerminateAgent slash_bps {} exceeds 10000 (100%)",
                payload.slash_bps
            )));
        }

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_KILLSWITCH_TERMINATE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let new_sender_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_sender_balance);

        let receipt_id = derive_killswitch_receipt_id(
            KillSwitchAction::Terminate.as_str(),
            &payload.agent_did,
            &payload.controller_did,
            tx.nonce,
        );
        let receipt_id_hex = hex::encode(receipt_id);

        let receipt = KillSwitchReceipt {
            receipt_id: receipt_id_hex.clone(),
            action: KillSwitchAction::Terminate,
            agent_did: payload.agent_did.clone(),
            controller_did: payload.controller_did.clone(),
            reason_code: payload.reason_code,
            reason_text: None,
            evidence_hash: None,
            slash_bps: Some(payload.slash_bps),
            cascade: Some(payload.cascade),
            pause_until: None,
            frozen_at_block: BlockHeight::new(tx.nonce),
            timestamp: Timestamp::new(deterministic_now_ms(tx)),
        };
        let blob = serde_json::to_vec(&receipt).map_err(|e| {
            VmError::Internal(format!("Failed to serialize KillSwitchReceipt: {}", e))
        })?;
        let storage_key = killswitch_storage_key(&receipt_id_hex);
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                None,
                Some(blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let mut logs = vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"KillSwitchTerminate".to_vec()],
            encode_killswitch_log_data(&payload.agent_did, &payload.controller_did, &receipt_id),
        )];

        // AgentBond slashing (Spec 9): if Terminate carries a non-zero
        // slash_bps AND the agent has a posted bond, drain the slashed
        // portion from the bond vault into the InsurancePool vault. Use
        // exactly the same math as `tenzro_token::bond::BondManager::slash`
        // so the off-chain manager and the on-chain balances stay in lockstep
        // when the post-block scan flips lifecycle state.
        if payload.slash_bps > 0 {
            let bond_storage_key_str = bond_storage_key(&payload.agent_did);
            if let Some(prior_blob) =
                state.get_storage(&SYSTEM_ADDRESS, bond_storage_key_str.as_bytes())
            {
                let mut marker: serde_json::Value = serde_json::from_slice(&prior_blob)
                    .map_err(|e| VmError::Internal(format!("decode bond marker: {}", e)))?;
                let prior_op = marker
                    .get("op")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // Already-terminal bonds are skipped silently — Terminate
                // is idempotent w.r.t. the bond.
                if !matches!(prior_op.as_str(), "Slashed" | "Returned") {
                    let prior_amount: u128 = marker
                        .get("amount")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u128>().ok())
                        .ok_or_else(|| {
                            VmError::Internal("bond marker missing amount".to_string())
                        })?;
                    let slashed =
                        compute_slash_amount(prior_amount, payload.slash_bps, BOND_MIN_RESIDUAL);
                    if slashed > 0 {
                        let bond_vault_addr = derive_bond_vault_address(&payload.agent_did);
                        let bond_vault_bytes = bond_vault_addr.as_bytes().to_vec();
                        let pool_addr = derive_insurance_pool_address();
                        let pool_bytes = pool_addr.as_bytes().to_vec();

                        let old_bond_vault_balance = state.get_balance(&bond_vault_bytes);
                        // Defensive — the vault should never hold less than
                        // the marker says, but use saturating math anyway so
                        // a state divergence doesn't underflow.
                        let new_bond_vault_balance = old_bond_vault_balance.saturating_sub(slashed);
                        state.set_balance(&bond_vault_bytes, new_bond_vault_balance);

                        let old_pool_balance = state.get_balance(&pool_bytes);
                        let new_pool_balance =
                            old_pool_balance.checked_add(slashed).ok_or_else(|| {
                                VmError::Internal("InsurancePool balance overflow".to_string())
                            })?;
                        state.set_balance(&pool_bytes, new_pool_balance);

                        let new_amount = prior_amount.saturating_sub(slashed);
                        let terminal = new_amount < BOND_MIN_RESIDUAL;
                        marker["amount"] = serde_json::Value::String(
                            (if terminal { 0u128 } else { new_amount }).to_string(),
                        );
                        marker["op"] = serde_json::Value::String(if terminal {
                            "Slashed".to_string()
                        } else {
                            "PartiallySlashed".to_string()
                        });
                        let new_marker_blob = serde_json::to_vec(&marker)
                            .map_err(|e| VmError::Internal(format!("encode bond marker: {}", e)))?;
                        state.set_storage(
                            &SYSTEM_ADDRESS,
                            bond_storage_key_str.as_bytes(),
                            new_marker_blob.clone(),
                        );

                        state_changes.push(StateChange::new(
                            bond_vault_bytes,
                            b"balance".to_vec(),
                            Some(old_bond_vault_balance.to_le_bytes().to_vec()),
                            Some(new_bond_vault_balance.to_le_bytes().to_vec()),
                        ));
                        state_changes.push(StateChange::new(
                            pool_bytes,
                            b"balance".to_vec(),
                            Some(old_pool_balance.to_le_bytes().to_vec()),
                            Some(new_pool_balance.to_le_bytes().to_vec()),
                        ));
                        state_changes.push(StateChange::new(
                            SYSTEM_ADDRESS.to_vec(),
                            bond_storage_key_str.as_bytes().to_vec(),
                            Some(prior_blob),
                            Some(new_marker_blob),
                        ));

                        // Emit a `BondSlashed` log so the post-block scan can
                        // mirror this into `BondManager::slash`. Layout:
                        //   agent_did_len_le(4) || agent_did
                        //   controller_did_len_le(4) || controller_did
                        //   slashed_amount_le(16)
                        //   bps_le(2)
                        //   terminal(1)
                        //
                        // controller_did is read back out of the marker so
                        // we emit the same DID the bond was posted under,
                        // not whoever invoked Terminate.
                        let controller_for_log = marker
                            .get("controller_did")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let mut bond_log_data = Vec::with_capacity(
                            4 + payload.agent_did.len() + 4 + controller_for_log.len() + 16 + 2 + 1,
                        );
                        bond_log_data
                            .extend_from_slice(&(payload.agent_did.len() as u32).to_le_bytes());
                        bond_log_data.extend_from_slice(payload.agent_did.as_bytes());
                        bond_log_data
                            .extend_from_slice(&(controller_for_log.len() as u32).to_le_bytes());
                        bond_log_data.extend_from_slice(controller_for_log.as_bytes());
                        bond_log_data.extend_from_slice(&slashed.to_le_bytes());
                        bond_log_data.extend_from_slice(&payload.slash_bps.to_le_bytes());
                        bond_log_data.push(if terminal { 1 } else { 0 });

                        logs.push(Log::new(
                            SYSTEM_ADDRESS.to_vec(),
                            vec![b"BondSlashed".to_vec()],
                            bond_log_data,
                        ));
                    }
                }
            }
        }

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            receipt_id.to_vec(),
            logs,
            state_changes,
        ))
    }

    // ---- AgentBond handlers (Agent-Swarm Spec 9) ---------------------------

    /// Handle a `PostAgentBond` native transaction.
    ///
    /// Decodes a JSON-encoded `PostAgentBondPayload`. Verifies that the
    /// payer (`tx.from` = `controller_did` owner) holds enough TNZO,
    /// debits gas + bond amount, credits the deterministic per-agent
    /// vault, persists a marker record at
    /// `SYSTEM_ADDRESS/bond:<agent_did>` carrying the controller and
    /// amount, and emits a `BondPosted` log so the node-side
    /// post-execute scan can update its `BondManager`.
    ///
    /// Rejects:
    /// - Empty agent_did or > 256 bytes.
    /// - Zero amount.
    /// - An existing bond marker for the same agent (re-posting requires
    ///   the prior bond to be terminal — Returned or Slashed — and the
    ///   marker is rewritten by the node side after that lifecycle event).
    async fn execute_post_agent_bond(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_BOND_POST)?;

        let payload: PostAgentBondPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid PostAgentBond payload: {}", e))
        })?;

        validate_bond_agent_did(&payload.agent_did)?;
        if payload.controller_did.is_empty() || payload.controller_did.len() > 256 {
            return Err(VmError::InvalidTransaction(
                "agent bond controller_did must be 1..=256 bytes".to_string(),
            ));
        }
        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "agent bond amount must be > 0".to_string(),
            ));
        }

        // Reject if a non-terminal bond marker already exists.
        let storage_key = bond_storage_key(&payload.agent_did);
        if state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .is_some()
        {
            return Err(VmError::InvalidTransaction(format!(
                "agent {} already has a bond — use IncreaseAgentBond",
                payload.agent_did
            )));
        }

        // Cost = gas + bond amount, debited from the controller's wallet
        // (tx.from is the signer, which is the controller's address).
        let gas_cost = tx.gas_price.saturating_mul(GAS_BOND_POST as u128);
        let total_cost = payload
            .amount
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("AgentBond post cost overflow".to_string()))?;

        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Privileged credit to the bond vault.
        let vault_addr = derive_bond_vault_address(&payload.agent_did);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        let new_vault_balance = old_vault_balance
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("AgentBond vault overflow".to_string()))?;
        state.set_balance(&vault_bytes, new_vault_balance);

        // Persist a JSON marker record. The node-side post-execute scan
        // promotes this into a typed `BondManager` entry — the VM only
        // needs determinism on (controller_did, amount, vault), not the
        // full lifecycle envelope.
        let marker = serde_json::json!({
            "agent_did": payload.agent_did,
            "controller_did": payload.controller_did,
            "amount": payload.amount.to_string(),
            "vault": hex::encode(vault_addr.as_bytes()),
            "op": "Posted",
        });
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        // Bump payer nonce.
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes.clone(),
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"BondPosted".to_vec()],
            encode_bond_log_data(
                &payload.agent_did,
                &payload.controller_did,
                payload.amount,
                /*op_tag=Posted=*/ 0,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            vault_addr.as_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle an `IncreaseAgentBond` native transaction. Top up an
    /// existing Active bond. The marker record stays at the same key;
    /// only the `amount` field is rewritten (and the vault credited).
    async fn execute_increase_agent_bond(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_BOND_INCREASE)?;

        let payload: IncreaseAgentBondPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid IncreaseAgentBond payload: {}", e))
            })?;

        validate_bond_agent_did(&payload.agent_did)?;
        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "agent bond increase amount must be > 0".to_string(),
            ));
        }

        let storage_key = bond_storage_key(&payload.agent_did);
        let prior_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no bond exists for agent {}",
                    payload.agent_did
                ))
            })?;
        let mut marker: serde_json::Value = serde_json::from_slice(&prior_blob)
            .map_err(|e| VmError::Internal(format!("decode bond marker: {}", e)))?;

        // Authorization: tx.from must equal the payer that posted the
        // bond. We don't have the controller wallet address in the
        // marker, so we trust the node-side encoder to refuse encoding
        // an Increase from anyone other than the controller. The VM
        // re-checks the persisted controller_did string against
        // `tx.from` only loosely — the controller_did is the typed
        // identity, and address-derivation from a DID is upstream.
        let prior_amount: u128 = marker
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .ok_or_else(|| VmError::Internal("bond marker missing amount".to_string()))?;
        let new_amount = prior_amount
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("AgentBond amount overflow".to_string()))?;

        // Cost = gas + delta. Debit from controller wallet.
        let gas_cost = tx.gas_price.saturating_mul(GAS_BOND_INCREASE as u128);
        let total_cost = payload
            .amount
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("AgentBond increase cost overflow".to_string()))?;
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Vault credit.
        let vault_addr = derive_bond_vault_address(&payload.agent_did);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        let new_vault_balance = old_vault_balance
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("AgentBond vault overflow".to_string()))?;
        state.set_balance(&vault_bytes, new_vault_balance);

        // Update marker.
        marker["amount"] = serde_json::Value::String(new_amount.to_string());
        marker["op"] = serde_json::Value::String("Increased".to_string());
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        // Bump nonce.
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let controller_did_str = marker
            .get("controller_did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes,
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(prior_blob),
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"BondIncreased".to_vec()],
            encode_bond_log_data(
                &payload.agent_did,
                &controller_did_str,
                payload.amount,
                /*op_tag=Increased=*/ 1,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            new_amount.to_le_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `WithdrawAgentBond` native transaction. Initiates the
    /// cooldown timer. The vault stays funded (slashable during
    /// cooldown); the actual transfer back to the controller's wallet
    /// happens via `BondManager::finalize_withdrawal` once the cooldown
    /// elapses (driven by an off-VM tick on the node-side, not on the
    /// chain). The marker is updated to record the cooldown initiation.
    async fn execute_withdraw_agent_bond(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_BOND_WITHDRAW)?;

        let payload: WithdrawAgentBondPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid WithdrawAgentBond payload: {}", e))
            })?;

        validate_bond_agent_did(&payload.agent_did)?;

        let storage_key = bond_storage_key(&payload.agent_did);
        let prior_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no bond exists for agent {}",
                    payload.agent_did
                ))
            })?;
        let mut marker: serde_json::Value = serde_json::from_slice(&prior_blob)
            .map_err(|e| VmError::Internal(format!("decode bond marker: {}", e)))?;

        // Bond must be in `Posted` or `Increased` (i.e. lifecycle == Active)
        // to initiate withdrawal. Cooldown / Frozen / Slashed reject.
        let prior_op = marker.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(prior_op, "Posted" | "Increased") {
            return Err(VmError::InvalidTransaction(format!(
                "cannot withdraw bond in {} state",
                prior_op
            )));
        }

        // Pay gas only — the bond stays in the vault until the cooldown
        // elapses and is then released by the node-side BondManager.
        let gas_cost = tx.gas_price.saturating_mul(GAS_BOND_WITHDRAW as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Mark op as WithdrawInitiated. Node-side flips lifecycle to
        // Cooldown and arms the timer.
        marker["op"] = serde_json::Value::String("WithdrawInitiated".to_string());
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let amount_str = marker
            .get("amount")
            .and_then(|v| v.as_str())
            .unwrap_or("0")
            .to_string();
        let amount: u128 = amount_str.parse().unwrap_or(0);
        let controller_did_str = marker
            .get("controller_did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(prior_blob),
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"BondWithdrawInitiated".to_vec()],
            encode_bond_log_data(
                &payload.agent_did,
                &controller_did_str,
                amount,
                /*op_tag=WithdrawInitiated=*/ 2,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.agent_did.as_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    // ---- Compute-bond handlers ---------------------------------------------

    /// Handle a `PostComputeBond` native transaction.
    ///
    /// Decodes a JSON-encoded `PostComputeBondPayload`. Verifies the
    /// provider wallet (`tx.from`) holds enough TNZO, debits gas + bond
    /// amount, credits the deterministic per-provider vault, persists a
    /// marker at `SYSTEM_ADDRESS/compute_bond:<provider_did>`, and emits a
    /// `ComputeBondPosted` log so the node-side post-execute scan can
    /// update its `ComputeBondManager`.
    ///
    /// `tx.from` becomes the bond's payout address — the wallet that
    /// receives the funds back when a withdrawal finalises.
    async fn execute_post_compute_bond(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_COMPUTE_BOND_POST)?;

        let payload: PostComputeBondPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid PostComputeBond payload: {}", e))
            })?;

        validate_compute_bond_provider_did(&payload.provider_did)?;
        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "compute bond amount must be > 0".to_string(),
            ));
        }

        // Reject if a non-terminal bond marker already exists.
        let storage_key = compute_bond_storage_key(&payload.provider_did);
        if state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .is_some()
        {
            return Err(VmError::InvalidTransaction(format!(
                "provider {} already has a compute bond — use IncreaseComputeBond",
                payload.provider_did
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_COMPUTE_BOND_POST as u128);
        let total_cost = payload
            .amount
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("compute bond post cost overflow".to_string()))?;

        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Privileged credit to the bond vault.
        let vault_addr = derive_compute_bond_vault_address(&payload.provider_did);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        let new_vault_balance = old_vault_balance
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("compute bond vault overflow".to_string()))?;
        state.set_balance(&vault_bytes, new_vault_balance);

        let marker = serde_json::json!({
            "provider_did": payload.provider_did,
            "provider_address": hex::encode(&tx.from),
            "amount": payload.amount.to_string(),
            "vault": hex::encode(vault_addr.as_bytes()),
            "op": "Posted",
        });
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode compute bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes,
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ComputeBondPosted".to_vec()],
            encode_compute_bond_log_data(
                &payload.provider_did,
                &tx.from,
                payload.amount,
                /*op_tag=Posted=*/ 0,
                /*cooldown_until_ms=*/ 0,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            vault_addr.as_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle an `IncreaseComputeBond` native transaction. Top up an
    /// existing Active bond. The marker stays at the same key; only the
    /// `amount` field is rewritten (and the vault credited).
    ///
    /// Authorization: `tx.from` MUST equal the `provider_address` recorded
    /// when the bond was posted — a third party cannot mutate the bond.
    async fn execute_increase_compute_bond(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_COMPUTE_BOND_INCREASE)?;

        let payload: IncreaseComputeBondPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid IncreaseComputeBond payload: {}", e))
            })?;

        validate_compute_bond_provider_did(&payload.provider_did)?;
        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "compute bond increase amount must be > 0".to_string(),
            ));
        }

        let storage_key = compute_bond_storage_key(&payload.provider_did);
        let prior_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no compute bond exists for provider {}",
                    payload.provider_did
                ))
            })?;
        let mut marker: serde_json::Value = serde_json::from_slice(&prior_blob)
            .map_err(|e| VmError::Internal(format!("decode compute bond marker: {}", e)))?;

        require_compute_bond_owner(&marker, &tx.from)?;

        let prior_amount: u128 = marker
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .ok_or_else(|| VmError::Internal("compute bond marker missing amount".to_string()))?;
        let new_amount = prior_amount
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("compute bond amount overflow".to_string()))?;

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_COMPUTE_BOND_INCREASE as u128);
        let total_cost = payload
            .amount
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("compute bond increase cost overflow".to_string()))?;
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < total_cost {
            return Err(VmError::InsufficientBalance {
                required: total_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_payer_balance);

        let vault_addr = derive_compute_bond_vault_address(&payload.provider_did);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let old_vault_balance = state.get_balance(&vault_bytes);
        let new_vault_balance = old_vault_balance
            .checked_add(payload.amount)
            .ok_or_else(|| VmError::Internal("compute bond vault overflow".to_string()))?;
        state.set_balance(&vault_bytes, new_vault_balance);

        marker["amount"] = serde_json::Value::String(new_amount.to_string());
        marker["op"] = serde_json::Value::String("Increased".to_string());
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode compute bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes,
                b"balance".to_vec(),
                Some(old_vault_balance.to_le_bytes().to_vec()),
                Some(new_vault_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(prior_blob),
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ComputeBondIncreased".to_vec()],
            encode_compute_bond_log_data(
                &payload.provider_did,
                &tx.from,
                payload.amount,
                /*op_tag=Increased=*/ 1,
                /*cooldown_until_ms=*/ 0,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            new_amount.to_le_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `WithdrawComputeBond` native transaction. Initiates the
    /// cooldown timer and records the deadline on the marker. The vault
    /// stays funded (and slashable) for the whole cooldown; the transfer
    /// back to the provider wallet happens in a separate
    /// `FinalizeComputeBondWithdrawal` transaction once the deadline passes.
    ///
    /// Authorization: `tx.from` MUST equal the recorded `provider_address`.
    async fn execute_withdraw_compute_bond(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_COMPUTE_BOND_WITHDRAW)?;

        let payload: WithdrawComputeBondPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid WithdrawComputeBond payload: {}", e))
            })?;

        validate_compute_bond_provider_did(&payload.provider_did)?;

        let storage_key = compute_bond_storage_key(&payload.provider_did);
        let prior_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no compute bond exists for provider {}",
                    payload.provider_did
                ))
            })?;
        let mut marker: serde_json::Value = serde_json::from_slice(&prior_blob)
            .map_err(|e| VmError::Internal(format!("decode compute bond marker: {}", e)))?;

        require_compute_bond_owner(&marker, &tx.from)?;

        let prior_op = marker.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(prior_op, "Posted" | "Increased") {
            return Err(VmError::InvalidTransaction(format!(
                "cannot withdraw compute bond in {} state",
                prior_op
            )));
        }

        // Pay gas only — the bond stays in the vault until the cooldown
        // elapses and the node-side ComputeBondManager releases it.
        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_COMPUTE_BOND_WITHDRAW as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // The deadline is derived from the block timestamp so every
        // replica computes the same value; `FinalizeComputeBondWithdrawal`
        // reads it back rather than consulting a local clock.
        let cooldown_until_ms = deterministic_now_ms(tx).saturating_add(COMPUTE_BOND_COOLDOWN_MS);
        marker["op"] = serde_json::Value::String("WithdrawInitiated".to_string());
        marker["cooldown_until_ms"] = serde_json::Value::String(cooldown_until_ms.to_string());
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode compute bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let amount: u128 = marker
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(prior_blob),
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ComputeBondWithdrawInitiated".to_vec()],
            encode_compute_bond_log_data(
                &payload.provider_did,
                &tx.from,
                amount,
                /*op_tag=WithdrawInitiated=*/ 2,
                cooldown_until_ms,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.provider_did.as_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `FinalizeComputeBondWithdrawal` native transaction. Pays
    /// the vault balance back to the provider once the cooldown deadline
    /// recorded by `WithdrawComputeBond` has passed.
    ///
    /// Authorization: `tx.from` MUST equal the recorded `provider_address`.
    async fn execute_finalize_compute_bond_withdrawal(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_COMPUTE_BOND_FINALIZE)?;

        let payload: FinalizeComputeBondWithdrawalPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| {
            VmError::InvalidTransaction(format!(
                "Invalid FinalizeComputeBondWithdrawal payload: {}",
                e
            ))
        })?;

        validate_compute_bond_provider_did(&payload.provider_did)?;

        let storage_key = compute_bond_storage_key(&payload.provider_did);
        let prior_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no compute bond exists for provider {}",
                    payload.provider_did
                ))
            })?;
        let mut marker: serde_json::Value = serde_json::from_slice(&prior_blob)
            .map_err(|e| VmError::Internal(format!("decode compute bond marker: {}", e)))?;

        require_compute_bond_owner(&marker, &tx.from)?;

        let prior_op = marker.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if prior_op != "WithdrawInitiated" {
            return Err(VmError::InvalidTransaction(format!(
                "cannot finalize compute bond withdrawal in {} state",
                prior_op
            )));
        }

        let cooldown_until_ms: i64 = marker
            .get("cooldown_until_ms")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| {
                VmError::Internal("compute bond marker is missing cooldown_until_ms".to_string())
            })?;
        let now_ms = deterministic_now_ms(tx);
        if now_ms < cooldown_until_ms {
            return Err(VmError::InvalidTransaction(format!(
                "compute bond cooldown has not elapsed ({} ms remaining)",
                cooldown_until_ms.saturating_sub(now_ms)
            )));
        }

        let vault_addr = derive_compute_bond_vault_address(&payload.provider_did);
        let vault_bytes = vault_addr.as_bytes().to_vec();
        let vault_balance = state.get_balance(&vault_bytes);

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_COMPUTE_BOND_FINALIZE as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }

        // Gas out, vault balance in — both land on the provider address.
        let new_payer_balance = payer_balance
            .saturating_sub(gas_cost)
            .saturating_add(vault_balance);
        state.set_balance(&tx.from, new_payer_balance);
        state.set_balance(&vault_bytes, 0);

        marker["op"] = serde_json::Value::String("Returned".to_string());
        marker["amount"] = serde_json::Value::String("0".to_string());
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode compute bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                vault_bytes,
                b"balance".to_vec(),
                Some(vault_balance.to_le_bytes().to_vec()),
                Some(0u128.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(prior_blob),
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ComputeBondReturned".to_vec()],
            encode_compute_bond_log_data(
                &payload.provider_did,
                &tx.from,
                vault_balance,
                /*op_tag=Returned=*/ 3,
                cooldown_until_ms,
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            vault_balance.to_le_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `PayInsuranceClaim` native transaction. Debits the
    /// singleton InsurancePool vault and credits the claimant address.
    ///
    /// Authorization:
    /// - Off-chain BondManager has marked the claim Approved with a
    ///   specific `paid_amount`. The transaction encoder is responsible
    ///   for forwarding only well-formed, governance-approved payouts.
    /// - The VM does not re-derive the claim record (it lives in
    ///   `CF_AGENTS`, not VM state). It does enforce the per-claim
    ///   "already paid" marker so the same `claim_id_hex` cannot drain
    ///   the pool twice on-chain even if the BondManager state is
    ///   misconfigured.
    ///
    /// On success emits an `InsuranceClaimPaid` log so the node-side
    /// post-execute scan can flip `BondManager::pay_claim` and update
    /// the `CF_AGENTS` claim record.
    async fn execute_pay_insurance_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_PAY_INSURANCE_CLAIM)?;

        let payload: PayInsuranceClaimPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid PayInsuranceClaim payload: {}", e))
            })?;

        if payload.claim_id_hex.is_empty() || payload.claim_id_hex.len() > 128 {
            return Err(VmError::InvalidTransaction(
                "claim_id_hex must be 1..=128 chars".to_string(),
            ));
        }
        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "PayInsuranceClaim amount must be > 0".to_string(),
            ));
        }

        // Reject double-pay: marker exists → claim already drained the pool.
        let marker_key = paid_claim_storage_key(&payload.claim_id_hex);
        if state
            .get_storage(&SYSTEM_ADDRESS, marker_key.as_bytes())
            .is_some()
        {
            return Err(VmError::InvalidTransaction(format!(
                "claim {} already paid",
                payload.claim_id_hex
            )));
        }

        // Caller pays gas — typically a governance-authorized address
        // (treasury operator / proposal-execution caller).
        let gas_cost = tx.gas_price.saturating_mul(GAS_PAY_INSURANCE_CLAIM as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }
        let new_payer_balance = payer_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_payer_balance);

        // Debit pool vault.
        let pool_addr = derive_insurance_pool_address();
        let pool_bytes = pool_addr.as_bytes().to_vec();
        let old_pool_balance = state.get_balance(&pool_bytes);
        if old_pool_balance < payload.amount {
            return Err(VmError::InsufficientBalance {
                required: payload.amount,
                available: old_pool_balance,
            });
        }
        let new_pool_balance = old_pool_balance.saturating_sub(payload.amount);
        state.set_balance(&pool_bytes, new_pool_balance);

        // Credit claimant.
        let claimant_bytes = payload.claimant.as_bytes().to_vec();
        let old_claimant_balance = state.get_balance(&claimant_bytes);
        let new_claimant_balance = old_claimant_balance
            .checked_add(payload.amount)
            .ok_or_else(|| {
                VmError::Internal("InsurancePool claimant balance overflow".to_string())
            })?;
        state.set_balance(&claimant_bytes, new_claimant_balance);

        // Persist the per-claim "paid" marker so a replayed dispatch
        // cannot drain the pool twice. Body is the LE-encoded amount —
        // not strictly necessary, but useful for audit.
        let marker_blob = payload.amount.to_le_bytes().to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                pool_bytes,
                b"balance".to_vec(),
                Some(old_pool_balance.to_le_bytes().to_vec()),
                Some(new_pool_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                claimant_bytes,
                b"balance".to_vec(),
                Some(old_claimant_balance.to_le_bytes().to_vec()),
                Some(new_claimant_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                marker_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        // Log layout (parseable by node-side scan): `claim_id_len_le(4) ||
        //  claim_id_bytes || claimant(32) || amount_le(16)`.
        let mut log_data = Vec::with_capacity(4 + payload.claim_id_hex.len() + 32 + 16);
        log_data.extend_from_slice(&(payload.claim_id_hex.len() as u32).to_le_bytes());
        log_data.extend_from_slice(payload.claim_id_hex.as_bytes());
        log_data.extend_from_slice(payload.claimant.as_bytes());
        log_data.extend_from_slice(&payload.amount.to_le_bytes());

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"InsuranceClaimPaid".to_vec()],
            log_data,
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.claim_id_hex.as_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle an `X402Settle` native transaction.
    ///
    /// Moves `amount` from `payer` to `payee` on-chain, gated by a
    /// per-`payment_id` replay marker under `SYSTEM_ADDRESS`. The dispatching
    /// tx is signed by the node's system key (not the payer), so authorization
    /// derives from the settlement having been consensus-ordered by the node's
    /// `TnzoSettlementCallback` — the same privileged-dispatch model used by
    /// insurance-claim payouts. The system key pays gas.
    async fn execute_x402_settle(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_X402_SETTLE)?;

        let payload: X402SettlePayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid X402Settle payload: {}", e))
        })?;

        if payload.payment_id.is_empty() || payload.payment_id.len() > 128 {
            return Err(VmError::InvalidTransaction(
                "payment_id must be 1..=128 chars".to_string(),
            ));
        }
        if payload.amount == 0 {
            return Err(VmError::InvalidTransaction(
                "X402Settle amount must be > 0".to_string(),
            ));
        }
        if payload.payer == payload.payee {
            return Err(VmError::InvalidTransaction(
                "X402Settle payer and payee must differ".to_string(),
            ));
        }
        if payload.margin_bps > tenzro_types::fees::MAX_DEVELOPER_MARGIN_BPS {
            return Err(VmError::InvalidTransaction(format!(
                "X402Settle margin_bps {} exceeds cap {}",
                payload.margin_bps,
                tenzro_types::fees::MAX_DEVELOPER_MARGIN_BPS
            )));
        }
        if payload.margin_bps > 0 && payload.app_wallet.is_none() {
            return Err(VmError::InvalidTransaction(
                "X402Settle margin_bps > 0 requires app_wallet".to_string(),
            ));
        }

        // Developer-margin carve out of the payer-authorized total:
        // `amount` already includes the margin, so the app's share is
        // `amount * margin_bps / (10_000 + margin_bps)` and the payee
        // receives the remainder (the network cost).
        let margin = if payload.margin_bps > 0 {
            payload
                .amount
                .checked_mul(payload.margin_bps as u128)
                .ok_or_else(|| VmError::Internal("x402 margin overflow".to_string()))?
                / (10_000u128 + payload.margin_bps as u128)
        } else {
            0
        };

        // Reject replay: marker exists → this payment_id already settled.
        let marker_key = x402_settle_storage_key(&payload.payment_id);
        if state
            .get_storage(&SYSTEM_ADDRESS, marker_key.as_bytes())
            .is_some()
        {
            return Err(VmError::InvalidTransaction(format!(
                "x402 payment {} already settled",
                payload.payment_id
            )));
        }

        // System key pays gas.
        let gas_cost = tx.gas_price.saturating_mul(GAS_X402_SETTLE as u128);
        let caller_balance = state.get_balance(&tx.from);
        if caller_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: caller_balance,
            });
        }
        let new_caller_balance = caller_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_caller_balance);

        // Debit payer.
        let payer_bytes = payload.payer.as_bytes().to_vec();
        let old_payer_balance = state.get_balance(&payer_bytes);
        if old_payer_balance < payload.amount {
            return Err(VmError::InsufficientBalance {
                required: payload.amount,
                available: old_payer_balance,
            });
        }
        let new_payer_balance = old_payer_balance.saturating_sub(payload.amount);
        state.set_balance(&payer_bytes, new_payer_balance);

        // Credit payee with the network cost (total minus the margin carve).
        let payee_credit = payload.amount - margin;
        let payee_bytes = payload.payee.as_bytes().to_vec();
        let old_payee_balance = state.get_balance(&payee_bytes);
        let new_payee_balance = old_payee_balance
            .checked_add(payee_credit)
            .ok_or_else(|| VmError::Internal("x402 payee balance overflow".to_string()))?;
        state.set_balance(&payee_bytes, new_payee_balance);

        // Credit the app wallet with the developer margin. Balance is read
        // after the payee credit so an app_wallet == payee snapshot composes
        // correctly.
        let app_wallet_credit = match (&payload.app_wallet, margin) {
            (Some(app_wallet), m) if m > 0 => {
                let app_bytes = app_wallet.as_bytes().to_vec();
                let old_app_balance = state.get_balance(&app_bytes);
                let new_app_balance = old_app_balance.checked_add(m).ok_or_else(|| {
                    VmError::Internal("x402 app wallet balance overflow".to_string())
                })?;
                state.set_balance(&app_bytes, new_app_balance);
                Some((app_bytes, old_app_balance, new_app_balance))
            }
            _ => None,
        };

        // Persist the per-payment_id "settled" marker (body: LE amount, for audit).
        let marker_blob = payload.amount.to_le_bytes().to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(caller_balance.to_le_bytes().to_vec()),
                Some(new_caller_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                payer_bytes.clone(),
                b"balance".to_vec(),
                Some(old_payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                payee_bytes.clone(),
                b"balance".to_vec(),
                Some(old_payee_balance.to_le_bytes().to_vec()),
                Some(new_payee_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                marker_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];
        if let Some((app_bytes, old_app_balance, new_app_balance)) = &app_wallet_credit {
            state_changes.push(StateChange::new(
                app_bytes.clone(),
                b"balance".to_vec(),
                Some(old_app_balance.to_le_bytes().to_vec()),
                Some(new_app_balance.to_le_bytes().to_vec()),
            ));
        }

        // Log layout (parseable by node-side scan): `payment_id_len_le(4) ||
        //  payment_id_bytes || payer(32) || payee(32) || amount_le(16) ||
        //  margin_le(16) || app_wallet(32, zeroed when no attribution)`.
        let mut log_data =
            Vec::with_capacity(4 + payload.payment_id.len() + 32 + 32 + 16 + 16 + 32);
        log_data.extend_from_slice(&(payload.payment_id.len() as u32).to_le_bytes());
        log_data.extend_from_slice(payload.payment_id.as_bytes());
        log_data.extend_from_slice(payload.payer.as_bytes());
        log_data.extend_from_slice(payload.payee.as_bytes());
        log_data.extend_from_slice(&payload.amount.to_le_bytes());
        log_data.extend_from_slice(&margin.to_le_bytes());
        match &payload.app_wallet {
            Some(app_wallet) => log_data.extend_from_slice(app_wallet.as_bytes()),
            None => log_data.extend_from_slice(&[0u8; 32]),
        }

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"X402Settled".to_vec()],
            log_data,
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.payment_id.as_bytes().to_vec(),
            vec![log],
            state_changes,
        ))
    }

    // ---- Dynamic validator-set handlers ----------------------------------
    //
    // These three handlers form the on-chain control surface for the
    // permissionless validator set. They DO NOT mutate the consensus
    // ValidatorSet directly — that's the EpochManager's job, driven by
    // `tenzro_token::ValidatorRegistry::compute_epoch_transition()` at every
    // epoch boundary. The VM handlers:
    //
    //   1. validate the payload + charge gas
    //   2. emit a typed Log that the node-side post-execute scan
    //      (`event_loop.rs::handle_block_finalized` → registry mutator)
    //      consumes to drive the registry state machine
    //   3. write a marker to SYSTEM_ADDRESS storage for off-line
    //      reconstructibility (audit / forensics / re-org replay)
    //
    // The `from` address is the validator's operator key — the same
    // address used as the staking address.

    async fn execute_validator_register(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VALIDATOR_REGISTER)?;

        let payload: ValidatorRegisterPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid ValidatorRegister payload: {}", e))
            })?;

        if payload.consensus_pubkey.len() != 32 {
            return Err(VmError::InvalidTransaction(format!(
                "consensus_pubkey must be 32 bytes, got {}",
                payload.consensus_pubkey.len()
            )));
        }
        // ML-DSA-65 verifying key length per FIPS 204.
        if payload.pq_pubkey.len() != 1952 {
            return Err(VmError::InvalidTransaction(format!(
                "pq_pubkey must be 1952 bytes (ML-DSA-65), got {}",
                payload.pq_pubkey.len()
            )));
        }
        // BLS12-381 G1-compressed (`min_pk` scheme) — mandatory third leg.
        if payload.bls_pubkey.len() != 48 {
            return Err(VmError::InvalidTransaction(format!(
                "bls_pubkey must be 48 bytes (BLS12-381 G1-compressed, min_pk), got {}",
                payload.bls_pubkey.len()
            )));
        }
        if payload.metadata_uri.len() > 256 {
            return Err(VmError::InvalidTransaction(format!(
                "metadata_uri exceeds 256 bytes (got {})",
                payload.metadata_uri.len()
            )));
        }

        // A validator must bond real balance. Reject a zero-stake
        // registration outright. The *policy* floor (minimum self-stake for
        // admission) is enforced deterministically at the epoch gate against
        // the registry's configurable `min_self_stake`, so it is NOT hardcoded
        // here — that would drift from governance. The VM enforces only the
        // correctness invariant: you hold and escrow what you declare.
        let stake = payload.self_stake;
        if stake == 0 {
            return Err(VmError::InvalidTransaction(
                "RegisterValidator requires a non-zero self_stake".to_string(),
            ));
        }

        // Charge gas + escrow the declared stake in one balance check, so an
        // account cannot register a validator with stake it does not hold.
        let gas_cost = tx.gas_price.saturating_mul(GAS_VALIDATOR_REGISTER as u128);
        let total_debit = stake
            .checked_add(gas_cost)
            .ok_or_else(|| VmError::Internal("stake + gas overflow".to_string()))?;
        let bal = state.get_balance(&tx.from);
        if bal < total_debit {
            return Err(VmError::InsufficientBalance {
                required: total_debit,
                available: bal,
            });
        }
        let new_bal = bal.saturating_sub(total_debit);
        state.set_balance(&tx.from, new_bal);

        // Move the bonded stake into the staking vault (replicated VM balance
        // state) and record the per-validator bond so ValidatorExit can refund
        // the exact amount. Both are part of the state root, so all nodes agree.
        let old_vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        let new_vault = old_vault
            .checked_add(stake)
            .ok_or_else(|| VmError::Internal("staking vault overflow".to_string()))?;
        state.set_balance(&STAKING_VAULT_ADDRESS, new_vault);
        let bond_key = format!("staking_bond:{}", hex::encode(&tx.from));
        state.set_storage(
            &SYSTEM_ADDRESS,
            bond_key.as_bytes(),
            stake.to_le_bytes().to_vec(),
        );

        // Persist a marker for re-org replay & audit. Body is the JSON
        // payload — the registry hydrates from this if it ever needs to.
        let marker_key = format!("validator_register:{}", hex::encode(&tx.from));
        let marker_blob = tx.data[4..].to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Log layout: `from(32) || stake_le(16) || consensus_pubkey(32) ||
        //              bls_pubkey(48) || pq_pubkey_len_le(4) || pq_pubkey ||
        //              withdrawal(32) || metadata_uri_len_le(4) || metadata_uri`
        let mut log_data = Vec::with_capacity(
            32 + 16 + 32 + 48 + 4 + payload.pq_pubkey.len() + 32 + 4 + payload.metadata_uri.len(),
        );
        log_data.extend_from_slice(&tx.from);
        log_data.extend_from_slice(&payload.self_stake.to_le_bytes());
        log_data.extend_from_slice(&payload.consensus_pubkey);
        log_data.extend_from_slice(&payload.bls_pubkey);
        log_data.extend_from_slice(&(payload.pq_pubkey.len() as u32).to_le_bytes());
        log_data.extend_from_slice(&payload.pq_pubkey);
        log_data.extend_from_slice(payload.withdrawal_address.as_bytes());
        log_data.extend_from_slice(&(payload.metadata_uri.len() as u32).to_le_bytes());
        log_data.extend_from_slice(payload.metadata_uri.as_bytes());

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ValidatorRegister".to_vec()],
            log_data,
        );

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(bal.to_le_bytes().to_vec()),
                Some(new_bal.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                STAKING_VAULT_ADDRESS.to_vec(),
                b"balance".to_vec(),
                Some(old_vault.to_le_bytes().to_vec()),
                Some(new_vault.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                bond_key.as_bytes().to_vec(),
                None,
                Some(stake.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                marker_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Debit the flat gas cost of a fixed-price native op from `tx.from`.
    ///
    /// Returns `(old_balance, new_balance)` for the caller's `StateChange`
    /// record. Refuses rather than saturating when the payer cannot cover the
    /// cost, so an unfunded account cannot claim a name for free.
    fn charge_gas(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas: u64,
    ) -> Result<(u128, u128)> {
        let gas_cost = tx.gas_price.saturating_mul(gas as u128);
        let bal = state.get_balance(&tx.from);
        if bal < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            });
        }
        let new_bal = bal.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_bal);
        Ok((bal, new_bal))
    }

    /// `ClaimNodeAlias` — take a readable name for a node, permissionlessly.
    ///
    /// Uniqueness is enforced here, against consensus state, which is what
    /// makes the whole scheme node-operator-independent: every validator
    /// executes this same handler over the same ordered transactions, so they
    /// all agree on who claimed `alice` first. Nothing about the outcome
    /// depends on which RPC endpoint the claimant used.
    ///
    /// A re-claim by the existing owner is accepted and refreshes the record
    /// (it is how `exposed_prefixes` is changed); a claim over someone else's
    /// name is refused.
    async fn execute_node_alias_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_NODE_ALIAS_CLAIM)?;

        let payload: ClaimNodeAliasPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid ClaimNodeAlias payload: {}", e))
            })?;

        tenzro_types::node_alias::validate_alias(&payload.name)
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid node alias: {e}")))?;
        if payload.owner_did.trim().is_empty() {
            return Err(VmError::InvalidTransaction(
                "ClaimNodeAlias requires a non-empty owner_did".to_string(),
            ));
        }

        let now_ms = deterministic_now_ms(tx).max(0) as u64;
        let sender_hex = hex::encode(&tx.from);
        let key = node_alias_storage_key(&payload.name);
        let existing = state.get_storage(&SYSTEM_ADDRESS, &key);

        // Preserve the bind across an owner's re-claim: re-declaring the
        // exposed paths must not silently unbind a running node.
        let (claimed_at, machine_did, endpoint_id) = match &existing {
            Some(blob) if !blob.is_empty() => {
                let prior: tenzro_types::node_alias::NodeAlias = serde_json::from_slice(blob)
                    .map_err(|e| {
                        VmError::InvalidTransaction(format!("Corrupt node-alias record: {e}"))
                    })?;
                // This is the whole uniqueness rule, and it is enforced
                // against consensus state so every node reaches the same
                // verdict on the same ordered transactions.
                if prior.owner_address != sender_hex {
                    return Err(VmError::InvalidTransaction(format!(
                        "node alias '{}' is already claimed",
                        payload.name
                    )));
                }
                (prior.claimed_at, prior.machine_did, prior.endpoint_id)
            }
            _ => (now_ms, None, None),
        };

        let record = tenzro_types::node_alias::NodeAlias {
            name: payload.name.clone(),
            owner_address: sender_hex,
            owner_did: payload.owner_did.clone(),
            machine_did,
            endpoint_id,
            exposed_prefixes: payload
                .exposed_prefixes
                .unwrap_or_else(tenzro_types::node_alias::default_exposed_prefixes),
            claimed_at,
            updated_at: now_ms,
        };
        let blob = serde_json::to_vec(&record).map_err(|e| {
            VmError::InvalidTransaction(format!("Unserializable node-alias record: {e}"))
        })?;

        let (bal, new_bal) = self.charge_gas(tx, state, GAS_NODE_ALIAS_CLAIM)?;
        state.set_storage(&SYSTEM_ADDRESS, &key, blob.clone());
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"NodeAliasClaim".to_vec()],
            blob.clone(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            vec![
                StateChange::new(
                    tx.from.clone(),
                    b"balance".to_vec(),
                    Some(bal.to_le_bytes().to_vec()),
                    Some(new_bal.to_le_bytes().to_vec()),
                ),
                StateChange::new(SYSTEM_ADDRESS.to_vec(), key, existing, Some(blob)),
                StateChange::new(
                    tx.from.clone(),
                    b"nonce".to_vec(),
                    Some(old_nonce.to_le_bytes().to_vec()),
                    Some((old_nonce + 1).to_le_bytes().to_vec()),
                ),
            ],
        ))
    }

    /// `RegisterIdentity` — land a DID + its public record into consensus
    /// state (TDIP D5). Mirrors [`Self::execute_node_alias_claim`]: the
    /// record lives under `SYSTEM_ADDRESS` at `identity:<did>`, DID
    /// uniqueness is enforced against that consensus state so every node
    /// reaches the same verdict on the same ordered transactions, and the
    /// emitted `IdentityRegister` log drives the node-side registry mirror.
    ///
    /// Uniqueness rule: a DID already held by a *different* controller pubkey
    /// is refused (fail-closed); a re-registration by the same controller
    /// refreshes the record (idempotent replay across re-orgs / restarts).
    async fn execute_identity_register(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_IDENTITY_REGISTER)?;

        let payload: tenzro_types::identity::RegisterIdentityPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid RegisterIdentity payload: {}", e))
            })?;

        if payload.did.trim().is_empty() {
            return Err(VmError::InvalidTransaction(
                "RegisterIdentity requires a non-empty did".to_string(),
            ));
        }
        if payload.did.len() > 256 {
            return Err(VmError::InvalidTransaction(format!(
                "did exceeds 256 bytes (got {})",
                payload.did.len()
            )));
        }
        if !matches!(
            payload.identity_type.as_str(),
            "human" | "machine" | "institution"
        ) {
            return Err(VmError::InvalidTransaction(format!(
                "identity_type must be human|machine|institution, got '{}'",
                payload.identity_type
            )));
        }

        let key = identity_storage_key(&payload.did);
        let existing = state.get_storage(&SYSTEM_ADDRESS, &key);

        // DID uniqueness is the whole invariant, enforced against consensus
        // state so every node agrees on the same ordered transactions. A DID
        // already claimed by a different controller is refused fail-closed.
        if let Some(blob) = existing.as_ref().filter(|b| !b.is_empty()) {
            let prior: tenzro_types::identity::RegisterIdentityPayload =
                serde_json::from_slice(blob).map_err(|e| {
                    VmError::InvalidTransaction(format!("Corrupt identity record: {e}"))
                })?;
            if prior.controller_pubkey != payload.controller_pubkey {
                return Err(VmError::InvalidTransaction(format!(
                    "identity DID '{}' is already registered",
                    payload.did
                )));
            }
        }

        // Canonical blob = the exact JSON body the submitter signed over, so
        // the stored record and the emitted log are byte-identical on every
        // node (no re-serialization drift).
        let blob = tx.data[4..].to_vec();

        let (bal, new_bal) = self.charge_gas(tx, state, GAS_IDENTITY_REGISTER)?;
        state.set_storage(&SYSTEM_ADDRESS, &key, blob.clone());
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"IdentityRegister".to_vec()],
            blob.clone(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            vec![
                StateChange::new(
                    tx.from.clone(),
                    b"balance".to_vec(),
                    Some(bal.to_le_bytes().to_vec()),
                    Some(new_bal.to_le_bytes().to_vec()),
                ),
                StateChange::new(SYSTEM_ADDRESS.to_vec(), key, existing, Some(blob)),
                StateChange::new(
                    tx.from.clone(),
                    b"nonce".to_vec(),
                    Some(old_nonce.to_le_bytes().to_vec()),
                    Some((old_nonce + 1).to_le_bytes().to_vec()),
                ),
            ],
        ))
    }

    /// `BindNodeAlias` — point a claimed name at a specific node.
    ///
    /// Only the claim's owner may bind it, so possession of a name cannot be
    /// separated from the right to direct where it resolves.
    async fn execute_node_alias_bind(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_NODE_ALIAS_BIND)?;

        let payload: BindNodeAliasPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid BindNodeAlias payload: {}", e))
        })?;
        if payload.machine_did.trim().is_empty() || payload.endpoint_id.trim().is_empty() {
            return Err(VmError::InvalidTransaction(
                "BindNodeAlias requires machine_did and endpoint_id".to_string(),
            ));
        }

        let key = node_alias_storage_key(&payload.name);
        let existing = state.get_storage(&SYSTEM_ADDRESS, &key);
        let Some(blob) = existing.clone().filter(|b| !b.is_empty()) else {
            return Err(VmError::InvalidTransaction(format!(
                "node alias '{}' is not claimed",
                payload.name
            )));
        };
        let mut record: tenzro_types::node_alias::NodeAlias = serde_json::from_slice(&blob)
            .map_err(|e| VmError::InvalidTransaction(format!("Corrupt node-alias record: {e}")))?;

        // Two independent checks, because binding needs consent from both
        // sides and either one alone is forgeable by the other.
        //
        // (1) Only the address that claimed the name may repoint it —
        //     otherwise a third party redirects a name they do not hold.
        if record.owner_address != hex::encode(&tx.from) {
            return Err(VmError::InvalidTransaction(format!(
                "node alias '{}' is owned by another account",
                payload.name
            )));
        }

        // (2) The machine must have consented to being bound. `machine_did`
        //     and `endpoint_id` arrive as caller-supplied strings; without a
        //     signature over them, the name's owner could point it at any
        //     node on the network and have that node serve traffic under a
        //     name its operator never agreed to. On a registrable domain
        //     shared by every node — the one every passkey is scoped to —
        //     that is a phishing primitive, so this is fail-closed.
        //
        //     The signature is checked against `endpoint_id`, which is the
        //     node's Ed25519 public key, keeping the verdict identical on
        //     every validator with no registry lookup.
        // `EndpointId` renders as hex; accept an explicit `0x` either way.
        let endpoint_key = hex::decode(payload.endpoint_id.trim_start_matches("0x"))
            .ok()
            .filter(|k| k.len() == 32)
            .ok_or_else(|| {
                VmError::InvalidTransaction(
                    "endpoint_id is not a 32-byte hex Ed25519 key".to_string(),
                )
            })?;
        let consent = tenzro_types::node_alias::bind_consent_preimage(
            &payload.name,
            &record.owner_address,
            &payload.machine_did,
            &payload.endpoint_id,
        );
        let machine_key =
            tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, endpoint_key.clone());
        let signature = tenzro_crypto::signatures::Signature::new(
            tenzro_crypto::KeyType::Ed25519,
            payload.machine_consent.clone(),
        );
        tenzro_crypto::signatures::verify(&machine_key, &consent, &signature).map_err(|e| {
            VmError::InvalidTransaction(format!(
                "machine did not consent to binding '{}': {e}",
                payload.name
            ))
        })?;

        record.machine_did = Some(payload.machine_did.clone());
        record.endpoint_id = Some(payload.endpoint_id.clone());
        if let Some(prefixes) = payload.exposed_prefixes {
            record.exposed_prefixes = prefixes;
        }
        record.updated_at = deterministic_now_ms(tx).max(0) as u64;

        let new_blob = serde_json::to_vec(&record).map_err(|e| {
            VmError::InvalidTransaction(format!("Unserializable node-alias record: {e}"))
        })?;

        let (bal, new_bal) = self.charge_gas(tx, state, GAS_NODE_ALIAS_BIND)?;
        state.set_storage(&SYSTEM_ADDRESS, &key, new_blob.clone());
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"NodeAliasBind".to_vec()],
            new_blob.clone(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            vec![
                StateChange::new(
                    tx.from.clone(),
                    b"balance".to_vec(),
                    Some(bal.to_le_bytes().to_vec()),
                    Some(new_bal.to_le_bytes().to_vec()),
                ),
                StateChange::new(SYSTEM_ADDRESS.to_vec(), key, existing, Some(new_blob)),
                StateChange::new(
                    tx.from.clone(),
                    b"nonce".to_vec(),
                    Some(old_nonce.to_le_bytes().to_vec()),
                    Some((old_nonce + 1).to_le_bytes().to_vec()),
                ),
            ],
        ))
    }

    /// `ReleaseNodeAlias` — return a name to the unclaimed pool.
    async fn execute_node_alias_release(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_NODE_ALIAS_RELEASE)?;

        let payload: ReleaseNodeAliasPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid ReleaseNodeAlias payload: {}", e))
            })?;

        let key = node_alias_storage_key(&payload.name);
        let existing = state.get_storage(&SYSTEM_ADDRESS, &key);
        let Some(blob) = existing.clone().filter(|b| !b.is_empty()) else {
            return Err(VmError::InvalidTransaction(format!(
                "node alias '{}' is not claimed",
                payload.name
            )));
        };
        let record: tenzro_types::node_alias::NodeAlias = serde_json::from_slice(&blob)
            .map_err(|e| VmError::InvalidTransaction(format!("Corrupt node-alias record: {e}")))?;
        if record.owner_address != hex::encode(&tx.from) {
            return Err(VmError::InvalidTransaction(format!(
                "node alias '{}' is owned by another account",
                payload.name
            )));
        }

        let (bal, new_bal) = self.charge_gas(tx, state, GAS_NODE_ALIAS_RELEASE)?;
        // Empty value is the tombstone; `resolve` treats it as unclaimed.
        state.set_storage(&SYSTEM_ADDRESS, &key, Vec::new());
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"NodeAliasRelease".to_vec()],
            record.name.as_bytes().to_vec(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            vec![
                StateChange::new(
                    tx.from.clone(),
                    b"balance".to_vec(),
                    Some(bal.to_le_bytes().to_vec()),
                    Some(new_bal.to_le_bytes().to_vec()),
                ),
                StateChange::new(SYSTEM_ADDRESS.to_vec(), key, existing, Some(Vec::new())),
                StateChange::new(
                    tx.from.clone(),
                    b"nonce".to_vec(),
                    Some(old_nonce.to_le_bytes().to_vec()),
                    Some((old_nonce + 1).to_le_bytes().to_vec()),
                ),
            ],
        ))
    }

    async fn execute_validator_exit(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VALIDATOR_EXIT)?;

        // Exit takes no payload beyond the selector; from-address is the
        // validator. Reject if any extra bytes were supplied.
        if tx.data.len() != 4 {
            return Err(VmError::InvalidTransaction(format!(
                "ValidatorExit expects no payload, got {} extra bytes",
                tx.data.len() - 4
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_VALIDATOR_EXIT as u128);
        let bal = state.get_balance(&tx.from);
        if bal < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            });
        }
        let after_gas = bal.saturating_sub(gas_cost);

        // Refund the bonded stake from the staking vault. Immediate refund on
        // exit keeps escrow non-trapping; the unbonding delay + slashing
        // seizure are deterministic follow-ons layered on this base.
        let bond_key = format!("staking_bond:{}", hex::encode(&tx.from));
        let bonded = state
            .get_storage(&SYSTEM_ADDRESS, bond_key.as_bytes())
            .filter(|b| b.len() == 16)
            .map(|b| {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                u128::from_le_bytes(a)
            })
            .unwrap_or(0);
        let new_bal = after_gas
            .checked_add(bonded)
            .ok_or_else(|| VmError::Internal("stake refund overflow".to_string()))?;
        state.set_balance(&tx.from, new_bal);

        let old_vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        let new_vault = old_vault.saturating_sub(bonded);
        if bonded > 0 {
            state.set_balance(&STAKING_VAULT_ADDRESS, new_vault);
            // Clear the bond record so a repeated exit cannot double-refund.
            state.set_storage(&SYSTEM_ADDRESS, bond_key.as_bytes(), Vec::new());
        }

        let marker_key = format!("validator_exit:{}", hex::encode(&tx.from));
        let marker_blob = b"requested".to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ValidatorExit".to_vec()],
            tx.from.to_vec(),
        );

        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(bal.to_le_bytes().to_vec()),
                Some(new_bal.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                marker_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];
        if bonded > 0 {
            state_changes.push(StateChange::new(
                STAKING_VAULT_ADDRESS.to_vec(),
                b"balance".to_vec(),
                Some(old_vault.to_le_bytes().to_vec()),
                Some(new_vault.to_le_bytes().to_vec()),
            ));
            state_changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                bond_key.as_bytes().to_vec(),
                Some(bonded.to_le_bytes().to_vec()),
                Some(Vec::new()),
            ));
        }

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    async fn execute_validator_update_metadata(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VALIDATOR_UPDATE_METADATA)?;

        let payload: ValidatorUpdateMetadataPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| {
                VmError::InvalidTransaction(format!(
                    "Invalid ValidatorUpdateMetadata payload: {}",
                    e
                ))
            })?;

        if let Some(uri) = &payload.metadata_uri
            && uri.len() > 256
        {
            return Err(VmError::InvalidTransaction(format!(
                "metadata_uri exceeds 256 bytes (got {})",
                uri.len()
            )));
        }
        if let Some(h) = &payload.tee_attestation_hash
            && h.len() != 32
        {
            return Err(VmError::InvalidTransaction(format!(
                "tee_attestation_hash must be 32 bytes (got {})",
                h.len()
            )));
        }

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_VALIDATOR_UPDATE_METADATA as u128);
        let bal = state.get_balance(&tx.from);
        if bal < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            });
        }
        let new_bal = bal.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_bal);

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Log layout: `from(32) || metadata_uri_len_le(4) || metadata_uri ||
        //              tee_hash_present(1) || [tee_hash(32)]`
        let uri_str = payload.metadata_uri.unwrap_or_default();
        let mut log_data = Vec::with_capacity(32 + 4 + uri_str.len() + 1 + 32);
        log_data.extend_from_slice(&tx.from);
        log_data.extend_from_slice(&(uri_str.len() as u32).to_le_bytes());
        log_data.extend_from_slice(uri_str.as_bytes());
        match payload.tee_attestation_hash {
            Some(h) => {
                log_data.push(1);
                log_data.extend_from_slice(&h);
            }
            None => log_data.push(0),
        }

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ValidatorMetadataUpdate".to_vec()],
            log_data,
        );

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(bal.to_le_bytes().to_vec()),
                Some(new_bal.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    // ---- Workflow handlers (Canton-native multi-party workflow primitive) ----
    //
    // Each handler is intentionally thin: validate the JSON payload bounds,
    // charge gas, persist a replay marker under SYSTEM_ADDRESS keyed by
    // (op-prefix, op-id), and emit a typed Log carrying the JSON payload
    // verbatim. The node-side WorkflowRuntime decodes the log and
    // drives the in-memory WorkflowManager + privacy-domain registry +
    // approval state machine. This same split is what SELECTOR_VALIDATOR_*
    // uses for the dynamic validator set.
    //
    // Handlers do NOT couple tenzro-vm to tenzro-workflow at the type level —
    // payloads are opaque JSON blobs to the VM. The marker keyspace under
    // SYSTEM_ADDRESS is `wf:<op>:<id>` so the registry can hydrate by
    // iterating the prefix on startup.

    async fn execute_workflow_op(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
        gas_cost_units: u64,
        op_topic: &[u8],
        op_marker_prefix: &str,
        op_marker_id: &str,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(gas_cost_units)?;

        // Bound the JSON payload size (post-selector) to keep block-witness
        // cost finite. Larger payloads must be DA-offloaded by the caller.
        if tx.data.len() < 4 {
            return Err(VmError::InvalidTransaction(
                "Workflow op missing selector".to_string(),
            ));
        }
        let payload = &tx.data[4..];
        if payload.len() > WORKFLOW_PAYLOAD_MAX_BYTES {
            return Err(VmError::InvalidTransaction(format!(
                "Workflow payload exceeds {} bytes (got {})",
                WORKFLOW_PAYLOAD_MAX_BYTES,
                payload.len()
            )));
        }
        // Reject empty payloads except for ops where empty is meaningful.
        // All current workflow ops require at least an id field, so reject.
        if payload.is_empty() {
            return Err(VmError::InvalidTransaction(
                "Workflow op requires JSON payload".to_string(),
            ));
        }
        // Lightweight JSON well-formedness check — full structural decode
        // happens in the node-side WorkflowRuntime which has the typed
        // schemas. Catching malformed JSON here keeps bad txs out of blocks.
        if let Err(e) = serde_json::from_slice::<serde_json::Value>(payload) {
            return Err(VmError::InvalidTransaction(format!(
                "Workflow payload is not valid JSON: {}",
                e
            )));
        }

        // Charge fee.
        let gas_cost = tx.gas_price.saturating_mul(gas_cost_units as u128);
        let bal = state.get_balance(&tx.from);
        if bal < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            });
        }
        let new_bal = bal.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_bal);

        // Persist marker so the WorkflowRuntime can replay / hydrate.
        // Key: `wf:<op>:<id>`. Value: the raw JSON payload.
        let marker_key = format!("wf:{}:{}", op_marker_prefix, op_marker_id);
        let marker_blob = payload.to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Log layout: `from(32) || marker_key_len_le(4) || marker_key ||
        //              payload_len_le(4) || payload`. The node-side scan
        // matches on `topic == op_topic` and decodes the typed payload.
        let mut log_data = Vec::with_capacity(32 + 4 + marker_key.len() + 4 + payload.len());
        log_data.extend_from_slice(&tx.from);
        log_data.extend_from_slice(&(marker_key.len() as u32).to_le_bytes());
        log_data.extend_from_slice(marker_key.as_bytes());
        log_data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        log_data.extend_from_slice(payload);

        let log = Log::new(SYSTEM_ADDRESS.to_vec(), vec![op_topic.to_vec()], log_data);

        let state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(bal.to_le_bytes().to_vec()),
                Some(new_bal.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                marker_key.as_bytes().to_vec(),
                None,
                Some(marker_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            marker_key.into_bytes(),
            vec![log],
            state_changes,
        ))
    }

    async fn execute_workflow_create(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "workflow_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_CREATE,
            b"WorkflowCreate",
            "create",
            &id,
        )
        .await
    }

    async fn execute_workflow_sign(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "workflow_id")?;
        let did = workflow_extract_field(&tx.data[4..], "signer_did")?;
        let key = format!("{}:{}", id, did);
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_SIGN,
            b"WorkflowSign",
            "sign",
            &key,
        )
        .await
    }

    async fn execute_workflow_transition(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "workflow_id")?;
        let to = workflow_extract_field(&tx.data[4..], "to_status")?;
        let key = format!("{}:{}", id, to);
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_TRANSITION,
            b"WorkflowTransition",
            "tx",
            &key,
        )
        .await
    }

    async fn execute_workflow_register_obligation(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "obligation_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_REGISTER_OBLIGATION,
            b"WorkflowObligationRegister",
            "obl",
            &id,
        )
        .await
    }

    async fn execute_workflow_discharge_obligation(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "obligation_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_DISCHARGE_OBLIGATION,
            b"WorkflowObligationDischarge",
            "obl_dis",
            &id,
        )
        .await
    }

    async fn execute_workflow_default_obligation(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "obligation_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_DEFAULT_OBLIGATION,
            b"WorkflowObligationDefault",
            "obl_def",
            &id,
        )
        .await
    }

    async fn execute_workflow_register_gate(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "gate_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_REGISTER_GATE,
            b"WorkflowGateRegister",
            "gate",
            &id,
        )
        .await
    }

    async fn execute_workflow_open_approval(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "request_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_OPEN_APPROVAL,
            b"WorkflowApprovalOpen",
            "appr_open",
            &id,
        )
        .await
    }

    async fn execute_workflow_submit_decision(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let req = workflow_extract_field(&tx.data[4..], "request_id")?;
        let did = workflow_extract_field(&tx.data[4..], "approver_did")?;
        let key = format!("{}:{}", req, did);
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_SUBMIT_DECISION,
            b"WorkflowApprovalDecision",
            "appr_dec",
            &key,
        )
        .await
    }

    async fn execute_workflow_kill_switch(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "workflow_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_KILL_SWITCH,
            b"WorkflowKillSwitch",
            "kill",
            &id,
        )
        .await
    }

    async fn execute_workflow_register_privacy_domain(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "domain_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_REGISTER_PRIVACY_DOMAIN,
            b"WorkflowPrivacyDomainRegister",
            "pd",
            &id,
        )
        .await
    }

    async fn execute_workflow_freeze_privacy_domain(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let id = workflow_extract_field(&tx.data[4..], "domain_id")?;
        self.execute_workflow_op(
            tx,
            state,
            gas_meter,
            GAS_WORKFLOW_FREEZE_PRIVACY_DOMAIN,
            b"WorkflowPrivacyDomainFreeze",
            "pd_freeze",
            &id,
        )
        .await
    }
}

/// Extract a top-level string field from a JSON workflow payload. The VM
/// uses this only to derive the marker storage key — full structural
/// validation is the node-side WorkflowRuntime's job. Returns
/// `InvalidTransaction` if the field is missing or not a string.
fn workflow_extract_field(payload: &[u8], field: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid workflow JSON: {}", e)))?;
    let s = v.get(field).and_then(|x| x.as_str()).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "Workflow payload missing required string field `{}`",
            field
        ))
    })?;
    if s.is_empty() {
        return Err(VmError::InvalidTransaction(format!(
            "Workflow payload field `{}` must not be empty",
            field
        )));
    }
    if s.len() > 256 {
        return Err(VmError::InvalidTransaction(format!(
            "Workflow payload field `{}` exceeds 256 bytes (got {})",
            field,
            s.len()
        )));
    }
    Ok(s.to_string())
}

// ---- Free helpers for escrow handlers ---------------------------------------

/// JSON payload decoded from `tx.data[4..]` for `CreateEscrow`.
#[derive(Debug, Clone, serde::Deserialize)]
struct CreateEscrowPayload {
    payee: Address,
    amount: u128,
    asset_id: AssetId,
    expires_at: u64,
    release_conditions: ReleaseConditions,
}

/// JSON payload decoded from `tx.data[4..]` for `ReleaseEscrow`.
#[derive(Debug, Clone, serde::Deserialize)]
struct ReleaseEscrowPayload {
    escrow_id: [u8; 32],
    proof: ServiceProof,
}

/// JSON payload decoded from `tx.data[4..]` for `RefundEscrow`.
#[derive(Debug, Clone, serde::Deserialize)]
struct RefundEscrowPayload {
    escrow_id: [u8; 32],
}

// ---- Validator-registry payloads (Dynamic Validator Set) -------------------

/// JSON payload decoded from `tx.data[4..]` for `RegisterValidator`.
///
/// `consensus_pubkey` is the 32-byte Ed25519 BFT signing key. `pq_pubkey` is
/// the 1952-byte ML-DSA-65 verifying key (FIPS 204) — mandatory hybrid PQ.
/// `bls_pubkey` is the 48-byte BLS12-381 G1-compressed verifying key
/// (`min_pk` scheme) — mandatory third leg, used by HotStuff-2 to aggregate
/// per-vote signatures into a single QC-level aggregate.
/// `withdrawal_address` is the `Address` rewards/return-of-stake settle to.
/// `metadata_uri` is an optional ≤256-byte off-chain pointer (e.g. moniker,
/// website, contact).
#[derive(Debug, Clone, serde::Deserialize)]
struct ValidatorRegisterPayload {
    consensus_pubkey: Vec<u8>,
    pq_pubkey: Vec<u8>,
    bls_pubkey: Vec<u8>,
    withdrawal_address: Address,
    self_stake: u128,
    #[serde(default)]
    metadata_uri: String,
}

/// JSON payload decoded from `tx.data[4..]` for `UpdateValidatorMetadata`.
///
/// At least one of `metadata_uri` / `tee_attestation_hash` should be set —
/// the registry treats `None` as "no change" for that field. `tee_attestation_hash`
/// is a 32-byte SHA-256 commitment to a fresh attestation document; the active-set
/// boundary applies the TEE multiplier from this commitment.
#[derive(Debug, Clone, serde::Deserialize)]
struct ValidatorUpdateMetadataPayload {
    #[serde(default)]
    metadata_uri: Option<String>,
    #[serde(default)]
    tee_attestation_hash: Option<Vec<u8>>,
}

// ---- Node-alias payloads ----------------------------------------------------

/// JSON payload decoded from `tx.data[4..]` for `ClaimNodeAlias`.
///
/// `name` is a bare DNS label — never a hostname. The public suffix is a
/// node-configuration presentation detail (and a temporary one, present only
/// because WebAuthn demands a registrable domain), so recording it here would
/// tie every claim to a domain the network expects to outlive.
#[derive(Debug, Clone, serde::Deserialize)]
struct ClaimNodeAliasPayload {
    name: String,
    owner_did: String,
    #[serde(default)]
    exposed_prefixes: Option<Vec<String>>,
}

/// JSON payload decoded from `tx.data[4..]` for `BindNodeAlias`.
///
/// Binding is separate from claiming because the wizard claims a name before
/// the node has ever run, and neither `machine_did` nor `endpoint_id` exists
/// until first boot.
#[derive(Debug, Clone, serde::Deserialize)]
struct BindNodeAliasPayload {
    name: String,
    machine_did: String,
    endpoint_id: String,
    /// The machine's own Ed25519 signature over
    /// [`tenzro_types::node_alias::bind_consent_preimage`].
    ///
    /// Without this, `machine_did` / `endpoint_id` would be unverified
    /// caller-supplied strings and any claimant could point their name at
    /// somebody else's node. Verified against `endpoint_id`, which is the
    /// node's Ed25519 public key — so the check is deterministic in-VM with
    /// no DID resolution, and possession of the machine key (TPM-sealed for
    /// an autonomous node, node key of a passkey-controlled account
    /// otherwise) is what actually authorises the bind.
    machine_consent: Vec<u8>,
    #[serde(default)]
    exposed_prefixes: Option<Vec<String>>,
}

/// JSON payload decoded from `tx.data[4..]` for `ReleaseNodeAlias`.
#[derive(Debug, Clone, serde::Deserialize)]
struct ReleaseNodeAliasPayload {
    name: String,
}

/// Consensus-state key a claimed alias lives under, within `SYSTEM_ADDRESS`
/// storage. The `node_alias:` prefix keeps the namespace distinct from human
/// `@usernames` and agent names by construction.
fn node_alias_storage_key(name: &str) -> Vec<u8> {
    format!("node_alias:{name}").into_bytes()
}

/// Consensus-state key a registered identity record lives under, within
/// `SYSTEM_ADDRESS` storage. The `identity:` prefix keeps the DID namespace
/// distinct from node aliases and human `@usernames` by construction, and the
/// DID is globally unique so the key doubles as the uniqueness guard (TDIP D5).
fn identity_storage_key(did: &str) -> Vec<u8> {
    format!("identity:{did}").into_bytes()
}

// ---- Kill-switch payloads (Agent-Swarm Spec 1) ------------------------------

/// JSON payload decoded from `tx.data[4..]` for `PauseAgent`.
///
/// `controller_did` is intentionally explicit on the wire — it is recovered
/// at the `tenzro-node` layer when synthesising the VM transaction from a
/// `SignedTransaction::PauseAgent`, sourced from `tx.from`'s identity.
/// Echoing it into the payload keeps the receipt self-describing without
/// requiring readers to re-resolve the payer DID.
#[derive(Debug, Clone, serde::Deserialize)]
struct PauseAgentPayload {
    agent_did: String,
    controller_did: String,
    reason_code: u16,
    #[serde(default)]
    reason_text: Option<String>,
    #[serde(default)]
    until: Option<u64>,
}

/// JSON payload decoded from `tx.data[4..]` for `QuarantineAgent`.
#[derive(Debug, Clone, serde::Deserialize)]
struct QuarantineAgentPayload {
    agent_did: String,
    controller_did: String,
    reason_code: u16,
    #[serde(default)]
    reason_text: Option<String>,
    /// Hex-encoded SHA-256 commitment to off-chain evidence (optional).
    #[serde(default)]
    evidence_hash: Option<String>,
}

/// JSON payload decoded from `tx.data[4..]` for `TerminateAgent`.
#[derive(Debug, Clone, serde::Deserialize)]
struct TerminateAgentPayload {
    agent_did: String,
    controller_did: String,
    reason_code: u16,
    slash_bps: u16,
    #[serde(default)]
    cascade: bool,
}

// ---- AgentBond payloads (Agent-Swarm Spec 9) --------------------------------

/// JSON payload decoded from `tx.data[4..]` for `PostAgentBond`.
///
/// `controller_did` is recovered from `tx.from` at the node-side encoder
/// before the VM sees it; the agent_did is the bonded subject.
#[derive(Debug, Clone, serde::Deserialize)]
struct PostAgentBondPayload {
    agent_did: String,
    controller_did: String,
    amount: u128,
}

/// JSON payload decoded from `tx.data[4..]` for `IncreaseAgentBond`.
#[derive(Debug, Clone, serde::Deserialize)]
struct IncreaseAgentBondPayload {
    agent_did: String,
    amount: u128,
}

/// JSON payload decoded from `tx.data[4..]` for `WithdrawAgentBond`.
/// Initiates the cooldown timer; finalisation happens off-VM via the
/// node-side BondManager once the cooldown period elapses.
#[derive(Debug, Clone, serde::Deserialize)]
struct WithdrawAgentBondPayload {
    agent_did: String,
}

// ---- Compute-bond payloads --------------------------------------------------

/// JSON payload decoded from `tx.data[4..]` for `PostComputeBond`.
///
/// `tx.from` is the payer and becomes the bond's payout address, so the
/// wire payload carries no provider address to disagree with it.
#[derive(Debug, Clone, serde::Deserialize)]
struct PostComputeBondPayload {
    provider_did: String,
    amount: u128,
}

/// JSON payload decoded from `tx.data[4..]` for `IncreaseComputeBond`.
#[derive(Debug, Clone, serde::Deserialize)]
struct IncreaseComputeBondPayload {
    provider_did: String,
    amount: u128,
}

/// JSON payload decoded from `tx.data[4..]` for `WithdrawComputeBond`.
/// Starts the cooldown timer; the funds stay in the vault (and stay
/// slashable) until `ComputeBondManager::finalize_withdrawal` releases them.
#[derive(Debug, Clone, serde::Deserialize)]
struct WithdrawComputeBondPayload {
    provider_did: String,
}

/// JSON payload decoded from `tx.data[4..]` for
/// `FinalizeComputeBondWithdrawal`. Releases the vault balance back to the
/// provider once the cooldown deadline recorded by `WithdrawComputeBond`
/// has passed.
#[derive(Debug, Clone, serde::Deserialize)]
struct FinalizeComputeBondWithdrawalPayload {
    provider_did: String,
}

/// JSON payload decoded from `tx.data[4..]` for `PayInsuranceClaim`.
///
/// Settles an `Approved` insurance claim on-chain. The off-chain
/// BondManager has already validated:
/// - `claim_id_hex` exists, status == Approved.
/// - `paid_amount` matches the governance-approved figure.
/// - The pool has sufficient balance (in the BondManager-tracked aggregate).
///
/// The VM enforces the lower-level on-chain invariants:
/// - The InsurancePool vault holds at least `amount` TNZO at execution time.
/// - The same `claim_id_hex` cannot be paid twice (per-claim marker under
///   `SYSTEM_ADDRESS`).
#[derive(Debug, Clone, serde::Deserialize)]
struct PayInsuranceClaimPayload {
    claim_id_hex: String,
    claimant: Address,
    amount: u128,
}

/// JSON payload decoded from `tx.data[4..]` for `X402Settle`.
///
/// `payer` / `payee` are the settling parties' native addresses.
/// `payment_id` is the x402 payment identifier — the idempotency key. The VM
/// records a per-`payment_id` marker under `SYSTEM_ADDRESS` on first success
/// so a replayed dispatch is rejected before it can debit the payer twice.
///
/// The `from` of the dispatching tx is the node's system key, NOT the payer —
/// authorization derives from the on-chain settlement being consensus-ordered
/// via the node's `TnzoSettlementCallback`, exactly as insurance-claim payouts
/// are authorized by governance rather than the claimant's signature.
#[derive(Debug, Clone, serde::Deserialize)]
struct X402SettlePayload {
    payer: Address,
    payee: Address,
    amount: u128,
    payment_id: String,
    /// App wallet receiving the developer-margin carve; `None` disables it.
    app_wallet: Option<Address>,
    /// Developer margin, in basis points, already included in `amount`.
    margin_bps: u32,
}

/// Storage key for an escrow record under `SYSTEM_ADDRESS`: `escrow:<hex_id>`.
fn escrow_storage_key(escrow_id_hex: &str) -> String {
    format!("escrow:{}", escrow_id_hex)
}

/// Returns the deterministic wall-clock timestamp (Unix milliseconds)
/// for native-VM handlers that need to make time-based decisions.
///
/// CRITICAL: native-VM handlers MUST NOT call `chrono::Utc::now()`
/// directly. Each validator's host clock drifts independently, so a
/// transaction that compares `now > expires_at` could produce
/// different results on different validators, splitting the
/// finalized state and breaking consensus.
///
/// This helper:
/// 1. Prefers `tx.block_timestamp_ms` when the consensus event loop
///    has supplied it (the canonical case under finalized execution).
/// 2. Falls back to `Utc::now()` ONLY when no block timestamp is set,
///    which is the test / read-only-call path that doesn't go through
///    consensus and therefore can't break replay determinism.
fn deterministic_now_ms(tx: &VmTransaction) -> i64 {
    tx.block_timestamp_ms
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis())
}

/// Storage key for a kill-switch receipt under `SYSTEM_ADDRESS`:
/// `killswitch:<hex_id>`. The node-side `KillSwitchStore` mirrors this key
/// shape into `CF_SETTLEMENTS` so RPC readers can look up by receipt id
/// directly.
fn killswitch_storage_key(receipt_id_hex: &str) -> String {
    format!("killswitch:{}", receipt_id_hex)
}

/// Storage key for a bond marker under `SYSTEM_ADDRESS`:
/// `bond:<agent_did>`. The node-side `BondManager` reads these markers
/// post-block to update its in-memory cache + RocksDB write-through.
fn bond_storage_key(agent_did: &str) -> String {
    format!("bond:{}", agent_did)
}

/// Encode the data field of a bond `Log`:
/// `agent_did_len_le(4) || agent_did_bytes || controller_did_len_le(4) ||
///  controller_did_bytes || amount_le(16) || op_tag(1)` where
/// `op_tag ∈ {0=Posted, 1=Increased, 2=WithdrawInitiated}`.
///
/// The node-side post-execute scan reads this layout to dispatch the
/// matching `BondManager` operation.
fn encode_bond_log_data(
    agent_did: &str,
    controller_did: &str,
    amount: u128,
    op_tag: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + agent_did.len() + 4 + controller_did.len() + 16 + 1);
    out.extend_from_slice(&(agent_did.len() as u32).to_le_bytes());
    out.extend_from_slice(agent_did.as_bytes());
    out.extend_from_slice(&(controller_did.len() as u32).to_le_bytes());
    out.extend_from_slice(controller_did.as_bytes());
    out.extend_from_slice(&amount.to_le_bytes());
    out.push(op_tag);
    out
}

/// Validate an `agent_did` for bond ops. Same rules as kill-switch.
fn validate_bond_agent_did(agent_did: &str) -> Result<()> {
    if agent_did.is_empty() {
        return Err(VmError::InvalidTransaction(
            "agent bond agent_did must not be empty".to_string(),
        ));
    }
    if agent_did.len() > 256 {
        return Err(VmError::InvalidTransaction(format!(
            "agent bond agent_did too long: {} bytes (max 256)",
            agent_did.len()
        )));
    }
    Ok(())
}

/// Derive the deterministic vault address for an agent bond:
/// `Address(SHA-256("tenzro/agent-bond/vault" || agent_did))`.
///
/// MUST match `tenzro_token::bond::derive_bond_vault_address` byte-for-byte
/// — the BondManager and the VM handlers cooperate on the same vault.
fn derive_bond_vault_address(agent_did: &str) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(AGENT_BOND_VAULT_DOMAIN);
    hasher.update(agent_did.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// Storage key for a compute-bond marker under `SYSTEM_ADDRESS`:
/// `compute_bond:<provider_did>`. The node-side `ComputeBondManager` reads
/// these markers post-block to update its cache + RocksDB write-through.
fn compute_bond_storage_key(provider_did: &str) -> String {
    format!("compute_bond:{}", provider_did)
}

/// Encode the data field of a compute-bond `Log`:
/// `provider_did_len_le(4) || provider_did_bytes || addr_len_le(4) ||
///  provider_address_bytes || amount_le(16) || op_tag(1) ||
///  cooldown_until_ms_le(8)` where
/// `op_tag ∈ {0=Posted, 1=Increased, 2=WithdrawInitiated, 3=Returned}`.
///
/// The second field is the raw payout address (`tx.from`), not a DID.
///
/// `cooldown_until_ms` is the block-timestamp-derived deadline written on the
/// marker by `WithdrawComputeBond`, and is 0 for every other op. The node-side
/// read model adopts this value verbatim rather than deriving one from a local
/// clock, so a replica with clock skew still reports the deadline the chain
/// will enforce.
fn encode_compute_bond_log_data(
    provider_did: &str,
    provider_address: &[u8],
    amount: u128,
    op_tag: u8,
    cooldown_until_ms: i64,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(4 + provider_did.len() + 4 + provider_address.len() + 16 + 1 + 8);
    out.extend_from_slice(&(provider_did.len() as u32).to_le_bytes());
    out.extend_from_slice(provider_did.as_bytes());
    out.extend_from_slice(&(provider_address.len() as u32).to_le_bytes());
    out.extend_from_slice(provider_address);
    out.extend_from_slice(&amount.to_le_bytes());
    out.push(op_tag);
    out.extend_from_slice(&cooldown_until_ms.to_le_bytes());
    out
}

/// Validate a `provider_did` for compute-bond ops.
fn validate_compute_bond_provider_did(provider_did: &str) -> Result<()> {
    if provider_did.is_empty() {
        return Err(VmError::InvalidTransaction(
            "compute bond provider_did must not be empty".to_string(),
        ));
    }
    if provider_did.len() > 256 {
        return Err(VmError::InvalidTransaction(format!(
            "compute bond provider_did too long: {} bytes (max 256)",
            provider_did.len()
        )));
    }
    Ok(())
}

/// Derive the deterministic vault address for a compute bond:
/// `Address(SHA-256("tenzro/compute-bond/vault" || provider_did))`.
///
/// MUST match `tenzro_token::compute_bond::derive_compute_bond_vault_address`
/// byte-for-byte — the ComputeBondManager and the VM handlers cooperate on
/// the same vault.
fn derive_compute_bond_vault_address(provider_did: &str) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(COMPUTE_BOND_VAULT_DOMAIN);
    hasher.update(provider_did.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// Enforce that `from` is the payout address recorded on the bond marker.
///
/// Increase and withdraw are authorized on-chain rather than deferred to the
/// node-side encoder: the marker records the payer that funded the vault, and
/// only that address may add to it or start its cooldown.
fn require_compute_bond_owner(marker: &serde_json::Value, from: &[u8]) -> Result<()> {
    let owner = marker
        .get("provider_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VmError::InvalidTransaction(
                "compute bond marker is missing provider_address".to_string(),
            )
        })?;
    let caller = hex::encode(from);
    if !owner.eq_ignore_ascii_case(&caller) {
        return Err(VmError::InvalidTransaction(format!(
            "compute bond is owned by 0x{} — 0x{} may not modify it",
            owner, caller
        )));
    }
    Ok(())
}

/// Derive the deterministic singleton InsurancePool vault address:
/// `Address(SHA-256("tenzro/insurance-pool/vault"))`.
///
/// MUST match `tenzro_token::bond::derive_insurance_pool_address`.
fn derive_insurance_pool_address() -> Address {
    let mut hasher = Sha256::new();
    hasher.update(INSURANCE_POOL_VAULT_DOMAIN);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// Storage key for the per-claim "already paid" guard. Set the first time
/// `PayInsuranceClaim` succeeds for a given claim_id; subsequent attempts
/// are rejected even if the off-chain BondManager state allowed them.
fn paid_claim_storage_key(claim_id_hex: &str) -> String {
    format!("paid_claim:{}", claim_id_hex)
}

/// Storage key for the per-payment_id "already settled" guard. Set the first
/// time `X402Settle` succeeds for a given payment_id; subsequent dispatches
/// are rejected so a replayed settlement cannot debit the payer twice.
fn x402_settle_storage_key(payment_id: &str) -> String {
    format!("x402_settle:{}", payment_id)
}

/// Slash math — must match `tenzro_token::bond::BondManager::slash`
/// byte-for-byte so the VM and the off-chain manager arrive at the same
/// post-slash residual. Returns the amount drained from the bond vault
/// into the insurance pool.
///
/// `(amount / 10000) * bps + (amount % 10000) * bps / 10000`
fn compute_slash_amount(amount: u128, bps: u16, min_residual: u128) -> u128 {
    if bps == 0 || amount == 0 {
        return 0;
    }
    let slashed = (amount / 10_000)
        .saturating_mul(bps as u128)
        .saturating_add(((amount % 10_000) * bps as u128) / 10_000);
    let remainder = amount.saturating_sub(slashed);
    if remainder < min_residual {
        amount
    } else {
        slashed
    }
}

/// Encode the data field of a kill-switch `Log`:
/// `agent_did_len_le(4) || agent_did_bytes || controller_did_len_le(4) ||
///  controller_did_bytes || receipt_id(32)`.
///
/// The node-side post-execute scan reads this layout to dispatch the matching
/// `AgentRuntime` lifecycle method and to record the canonical
/// `KillSwitchReceipt` (with the real `frozen_at_block`) in
/// `KillSwitchStore`.
fn encode_killswitch_log_data(
    agent_did: &str,
    controller_did: &str,
    receipt_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + agent_did.len() + 4 + controller_did.len() + 32);
    out.extend_from_slice(&(agent_did.len() as u32).to_le_bytes());
    out.extend_from_slice(agent_did.as_bytes());
    out.extend_from_slice(&(controller_did.len() as u32).to_le_bytes());
    out.extend_from_slice(controller_did.as_bytes());
    out.extend_from_slice(receipt_id);
    out
}

/// Validate that both DIDs are non-empty and within a sane length bound.
fn validate_killswitch_dids(agent_did: &str, controller_did: &str) -> Result<()> {
    if agent_did.is_empty() {
        return Err(VmError::InvalidTransaction(
            "kill-switch agent_did must not be empty".to_string(),
        ));
    }
    if controller_did.is_empty() {
        return Err(VmError::InvalidTransaction(
            "kill-switch controller_did must not be empty".to_string(),
        ));
    }
    if agent_did.len() > 256 {
        return Err(VmError::InvalidTransaction(format!(
            "kill-switch agent_did too long: {} bytes (max 256)",
            agent_did.len()
        )));
    }
    if controller_did.len() > 256 {
        return Err(VmError::InvalidTransaction(format!(
            "kill-switch controller_did too long: {} bytes (max 256)",
            controller_did.len()
        )));
    }
    Ok(())
}

/// Validate optional `reason_text` is within the 256-byte cap from
/// `KillSwitchReceipt`.
fn validate_reason_text_len(reason_text: Option<&str>) -> Result<()> {
    if let Some(text) = reason_text
        && text.len() > 256
    {
        return Err(VmError::InvalidTransaction(format!(
            "kill-switch reason_text too long: {} bytes (max 256)",
            text.len()
        )));
    }
    Ok(())
}

/// Validate that `evidence_hash` is a 64-character lowercase hex string
/// (32-byte SHA-256 digest).
fn validate_evidence_hash(hash: &str) -> Result<()> {
    if hash.len() != 64 {
        return Err(VmError::InvalidTransaction(format!(
            "kill-switch evidence_hash must be 64 hex chars (32-byte SHA-256), got {}",
            hash.len()
        )));
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VmError::InvalidTransaction(
            "kill-switch evidence_hash must be hex".to_string(),
        ));
    }
    Ok(())
}

/// Derive the deterministic 32-byte kill-switch receipt id:
/// `SHA-256("tenzro/killswitch/receipt" || action || agent_did ||
///  controller_did || block_height_le)`.
///
/// Block height is stand-in'd via `tx.nonce` here because the VM does not
/// observe block height directly — the node-side post-execute scan
/// substitutes the real `frozen_at_block` value into the persisted receipt
/// (see `KillSwitchStore::record`). The id we emit here is good enough for
/// log indexing within the block and the node rewrites the
/// `frozen_at_block` field before persisting.
fn derive_killswitch_receipt_id(
    action: &str,
    agent_did: &str,
    controller_did: &str,
    nonce_le: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KILLSWITCH_RECEIPT_DOMAIN);
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(agent_did.as_bytes());
    hasher.update(b"|");
    hasher.update(controller_did.as_bytes());
    hasher.update(b"|");
    hasher.update(nonce_le.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive a deterministic 32-byte escrow id:
/// `SHA-256("tenzro/escrow/id" || payer || nonce_le)`.
fn derive_escrow_id(payer: &Address, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ESCROW_ID_DOMAIN);
    hasher.update(payer.as_bytes());
    hasher.update(nonce.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive the vault address for an escrow:
/// `Address(SHA-256("tenzro/escrow/vault" || escrow_id))`.
///
/// The full 32-byte digest is used as the address, since `Address` itself is a
/// 32-byte value in `tenzro-types`. The vault has no private key — only the
/// `execute_escrow_release` and `execute_escrow_refund` handlers may move funds
/// in or out of it via `state.set_balance`.
fn derive_vault_address(escrow_id: &[u8; 32]) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(ESCROW_VAULT_DOMAIN);
    hasher.update(escrow_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// Convert a raw `tx.from` byte slice to a typed 32-byte `Address`.
///
/// `VmTransaction::from` is `Vec<u8>`; for native escrow handlers we require
/// the exact 32-byte canonical address shape.
fn address_from_tx_from(from: &[u8]) -> Result<Address> {
    pad_address_32(from).map(Address::new)
}

/// Pad / validate a byte slice into a `[u8; 32]` for use as a Tenzro address.
fn pad_address_32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() > 32 {
        return Err(VmError::InvalidTransaction(format!(
            "Address too long: {} bytes (max 32)",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

#[async_trait]
impl VmExecutor for NativeExecutor {
    fn vm_type(&self) -> VmType {
        VmType::Tenzro
    }

    async fn execute_transaction(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        // Create gas meter
        let mut gas_meter = GasMeter::new(tx.gas_limit);

        // Dispatch based on transaction data
        if tx.data.is_empty() {
            // Simple transfer
            if tx.value > 0 {
                return self.execute_transfer(tx, state, &mut gas_meter).await;
            } else {
                return Err(VmError::InvalidTransaction(
                    "Empty transaction with zero value".to_string(),
                ));
            }
        }

        // Check for function selector
        if tx.data.len() < 4 {
            return Err(VmError::InvalidTransaction(
                "Transaction data too short for function selector".to_string(),
            ));
        }

        let selector: [u8; 4] = tx.data[..4].try_into().unwrap();

        match selector {
            SELECTOR_PROVIDER_STAKE => self.execute_stake(tx, state, &mut gas_meter).await,
            SELECTOR_PROVIDER_UNSTAKE => self.execute_unstake(tx, state, &mut gas_meter).await,
            SELECTOR_GOVERNANCE_PROPOSE => self.execute_propose(tx, state, &mut gas_meter).await,
            SELECTOR_GOVERNANCE_VOTE => self.execute_vote(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_CREATE => self.execute_escrow_create(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_RELEASE => self.execute_escrow_release(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_REFUND => self.execute_escrow_refund(tx, state, &mut gas_meter).await,
            SELECTOR_KILLSWITCH_PAUSE => {
                self.execute_killswitch_pause(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_KILLSWITCH_QUARANTINE => {
                self.execute_killswitch_quarantine(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_KILLSWITCH_TERMINATE => {
                self.execute_killswitch_terminate(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_POST_AGENT_BOND => {
                self.execute_post_agent_bond(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_INCREASE_AGENT_BOND => {
                self.execute_increase_agent_bond(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WITHDRAW_AGENT_BOND => {
                self.execute_withdraw_agent_bond(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_POST_COMPUTE_BOND => {
                self.execute_post_compute_bond(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_INCREASE_COMPUTE_BOND => {
                self.execute_increase_compute_bond(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WITHDRAW_COMPUTE_BOND => {
                self.execute_withdraw_compute_bond(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL => {
                self.execute_finalize_compute_bond_withdrawal(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_PAY_INSURANCE_CLAIM => {
                self.execute_pay_insurance_claim(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_X402_SETTLE => self.execute_x402_settle(tx, state, &mut gas_meter).await,
            SELECTOR_VALIDATOR_REGISTER => {
                self.execute_validator_register(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_VALIDATOR_EXIT => self.execute_validator_exit(tx, state, &mut gas_meter).await,
            SELECTOR_VALIDATOR_UPDATE_METADATA => {
                self.execute_validator_update_metadata(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_CREATE => {
                self.execute_workflow_create(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_SIGN => self.execute_workflow_sign(tx, state, &mut gas_meter).await,
            SELECTOR_WORKFLOW_TRANSITION => {
                self.execute_workflow_transition(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_REGISTER_OBLIGATION => {
                self.execute_workflow_register_obligation(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_DISCHARGE_OBLIGATION => {
                self.execute_workflow_discharge_obligation(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_DEFAULT_OBLIGATION => {
                self.execute_workflow_default_obligation(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_REGISTER_GATE => {
                self.execute_workflow_register_gate(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_OPEN_APPROVAL => {
                self.execute_workflow_open_approval(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_SUBMIT_DECISION => {
                self.execute_workflow_submit_decision(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_KILL_SWITCH => {
                self.execute_workflow_kill_switch(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_REGISTER_PRIVACY_DOMAIN => {
                self.execute_workflow_register_privacy_domain(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_NODE_ALIAS_CLAIM => {
                self.execute_node_alias_claim(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_NODE_ALIAS_BIND => {
                self.execute_node_alias_bind(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_NODE_ALIAS_RELEASE => {
                self.execute_node_alias_release(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_IDENTITY_REGISTER => {
                self.execute_identity_register(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_WORKFLOW_FREEZE_PRIVACY_DOMAIN => {
                self.execute_workflow_freeze_privacy_domain(tx, state, &mut gas_meter)
                    .await
            }
            _ => Err(VmError::InvalidTransaction(format!(
                "Unknown native function selector: {:?}",
                selector
            ))),
        }
    }

    async fn call(&self, _call: &ContractCall, _state: &dyn VmState) -> Result<CallResult> {
        // Native executor doesn't support read-only calls (no state to query directly)
        Err(VmError::ExecutionFailed(
            "Native executor does not support read-only calls".to_string(),
        ))
    }

    async fn deploy_contract(
        &self,
        _deployment: &ContractDeployment,
        _state: &mut dyn VmState,
    ) -> Result<DeployResult> {
        // Native executor doesn't deploy contracts
        Err(VmError::ExecutionFailed(
            "Native executor does not support contract deployment".to_string(),
        ))
    }

    async fn estimate_gas(&self, tx: &VmTransaction, _state: &dyn VmState) -> Result<u64> {
        // Estimate gas based on transaction type
        if tx.data.is_empty() {
            return Ok(GAS_TRANSFER);
        }

        if tx.data.len() < 4 {
            return Err(VmError::InvalidTransaction(
                "Transaction data too short for function selector".to_string(),
            ));
        }

        let selector: [u8; 4] = tx.data[..4].try_into().unwrap();

        Ok(match selector {
            SELECTOR_PROVIDER_STAKE => GAS_STAKE,
            SELECTOR_PROVIDER_UNSTAKE => GAS_UNSTAKE,
            SELECTOR_GOVERNANCE_PROPOSE => GAS_PROPOSE,
            SELECTOR_GOVERNANCE_VOTE => GAS_VOTE,
            SELECTOR_ESCROW_CREATE => GAS_ESCROW_CREATE,
            SELECTOR_ESCROW_RELEASE => GAS_ESCROW_RELEASE,
            SELECTOR_ESCROW_REFUND => GAS_ESCROW_REFUND,
            SELECTOR_KILLSWITCH_PAUSE => GAS_KILLSWITCH_PAUSE,
            SELECTOR_KILLSWITCH_QUARANTINE => GAS_KILLSWITCH_QUARANTINE,
            SELECTOR_KILLSWITCH_TERMINATE => GAS_KILLSWITCH_TERMINATE,
            SELECTOR_POST_AGENT_BOND => GAS_BOND_POST,
            SELECTOR_INCREASE_AGENT_BOND => GAS_BOND_INCREASE,
            SELECTOR_WITHDRAW_AGENT_BOND => GAS_BOND_WITHDRAW,
            SELECTOR_POST_COMPUTE_BOND => GAS_COMPUTE_BOND_POST,
            SELECTOR_INCREASE_COMPUTE_BOND => GAS_COMPUTE_BOND_INCREASE,
            SELECTOR_WITHDRAW_COMPUTE_BOND => GAS_COMPUTE_BOND_WITHDRAW,
            SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL => GAS_COMPUTE_BOND_FINALIZE,
            SELECTOR_PAY_INSURANCE_CLAIM => GAS_PAY_INSURANCE_CLAIM,
            SELECTOR_X402_SETTLE => GAS_X402_SETTLE,
            SELECTOR_VALIDATOR_REGISTER => GAS_VALIDATOR_REGISTER,
            SELECTOR_VALIDATOR_EXIT => GAS_VALIDATOR_EXIT,
            SELECTOR_VALIDATOR_UPDATE_METADATA => GAS_VALIDATOR_UPDATE_METADATA,
            SELECTOR_WORKFLOW_CREATE => GAS_WORKFLOW_CREATE,
            SELECTOR_WORKFLOW_SIGN => GAS_WORKFLOW_SIGN,
            SELECTOR_WORKFLOW_TRANSITION => GAS_WORKFLOW_TRANSITION,
            SELECTOR_WORKFLOW_REGISTER_OBLIGATION => GAS_WORKFLOW_REGISTER_OBLIGATION,
            SELECTOR_WORKFLOW_DISCHARGE_OBLIGATION => GAS_WORKFLOW_DISCHARGE_OBLIGATION,
            SELECTOR_WORKFLOW_DEFAULT_OBLIGATION => GAS_WORKFLOW_DEFAULT_OBLIGATION,
            SELECTOR_WORKFLOW_REGISTER_GATE => GAS_WORKFLOW_REGISTER_GATE,
            SELECTOR_WORKFLOW_OPEN_APPROVAL => GAS_WORKFLOW_OPEN_APPROVAL,
            SELECTOR_WORKFLOW_SUBMIT_DECISION => GAS_WORKFLOW_SUBMIT_DECISION,
            SELECTOR_WORKFLOW_KILL_SWITCH => GAS_WORKFLOW_KILL_SWITCH,
            SELECTOR_WORKFLOW_REGISTER_PRIVACY_DOMAIN => GAS_WORKFLOW_REGISTER_PRIVACY_DOMAIN,
            SELECTOR_NODE_ALIAS_CLAIM => GAS_NODE_ALIAS_CLAIM,
            SELECTOR_NODE_ALIAS_BIND => GAS_NODE_ALIAS_BIND,
            SELECTOR_NODE_ALIAS_RELEASE => GAS_NODE_ALIAS_RELEASE,
            SELECTOR_IDENTITY_REGISTER => GAS_IDENTITY_REGISTER,
            SELECTOR_WORKFLOW_FREEZE_PRIVACY_DOMAIN => GAS_WORKFLOW_FREEZE_PRIVACY_DOMAIN,
            _ => GAS_TRANSFER, // Default to transfer cost
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    #[tokio::test]
    async fn test_native_transfer() {
        let config = VmConfig::default();
        let executor = NativeExecutor::new(config).unwrap();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        // Set initial balance
        state.set_balance(&from, 1_000_000_000_000_000_000); // 1 ETH equivalent

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            100_000_000_000_000_000, // 0.1 ETH
            vec![],
            21_000,
            1_000_000_000, // 1 Gwei
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 21_000);
        assert_eq!(state.get_balance(&to), 100_000_000_000_000_000);
        assert_eq!(state.get_nonce(&from), 1);
    }

    #[tokio::test]
    async fn test_native_transfer_insufficient_balance() {
        let config = VmConfig::default();
        let executor = NativeExecutor::new(config).unwrap();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        // Set insufficient balance
        state.set_balance(&from, 1000);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            100_000_000_000_000_000,
            vec![],
            21_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await;

        assert!(result.is_err());
        match result {
            Err(VmError::InsufficientBalance { .. }) => {}
            _ => panic!("Expected InsufficientBalance error"),
        }
    }

    #[tokio::test]
    async fn test_native_stake() {
        let config = VmConfig::default();
        let executor = NativeExecutor::new(config).unwrap();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];

        // Set initial balance
        state.set_balance(&from, 10_000_000_000_000_000_000); // 10 ETH

        // Build stake transaction data
        let mut data = SELECTOR_PROVIDER_STAKE.to_vec();
        data.extend_from_slice(&1_000_000_000u64.to_le_bytes()); // Stake 1 TNZO (in smallest units)

        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            50_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 50_000);
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0].topics[0], b"Staked".to_vec());

        // Verify stake was recorded
        let stake_key = format!("stake:{}", hex::encode(&from));
        let stake = state
            .get_storage(&SYSTEM_ADDRESS, stake_key.as_bytes())
            .unwrap();
        let stake_amount = u64::from_le_bytes(stake[..8].try_into().unwrap());
        assert_eq!(stake_amount, 1_000_000_000);
    }

    #[tokio::test]
    async fn test_native_unstake() {
        let config = VmConfig::default();
        let executor = NativeExecutor::new(config).unwrap();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];

        // Set initial balance and stake
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let stake_key = format!("stake:{}", hex::encode(&from));
        state.set_storage(
            &SYSTEM_ADDRESS,
            stake_key.as_bytes(),
            2_000_000_000u64.to_le_bytes().to_vec(),
        );

        // Build unstake transaction data
        let mut data = SELECTOR_PROVIDER_UNSTAKE.to_vec();
        data.extend_from_slice(&1_000_000_000u64.to_le_bytes()); // Unstake 1 TNZO

        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            50_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 50_000);
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0].topics[0], b"Unstaked".to_vec());

        // Verify stake was reduced
        let stake = state
            .get_storage(&SYSTEM_ADDRESS, stake_key.as_bytes())
            .unwrap();
        let stake_amount = u64::from_le_bytes(stake[..8].try_into().unwrap());
        assert_eq!(stake_amount, 1_000_000_000);
    }

    #[tokio::test]
    async fn test_native_governance_propose() {
        let config = VmConfig::default();
        let executor = NativeExecutor::new(config).unwrap();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];

        // Set initial balance
        state.set_balance(&from, 10_000_000_000_000_000_000);

        // Build proposal transaction data
        let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
        data.extend_from_slice(b"Increase block gas limit to 50M");

        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            100_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 100_000);
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0].topics[0], b"ProposalCreated".to_vec());
        assert!(!result.output.is_empty()); // Contains proposal hash

        // Verify proposal counter was incremented
        let counter = state
            .get_storage(&SYSTEM_ADDRESS, b"proposal_counter")
            .unwrap();
        let count = u64::from_le_bytes(counter[..8].try_into().unwrap());
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_native_governance_vote() {
        let config = VmConfig::default();
        let executor = NativeExecutor::new(config).unwrap();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];

        // Set initial balance
        state.set_balance(&from, 10_000_000_000_000_000_000);

        // Create a proposal first
        let proposal_id = [0xAAu8; 32];
        let proposal_key = format!("proposal:{}", hex::encode(proposal_id));
        state.set_storage(
            &SYSTEM_ADDRESS,
            proposal_key.as_bytes(),
            b"Some proposal data".to_vec(),
        );

        // Build vote transaction data
        let mut data = SELECTOR_GOVERNANCE_VOTE.to_vec();
        data.extend_from_slice(&proposal_id); // proposal ID
        data.push(1); // vote = true

        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            30_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 30_000);
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0].topics[0], b"VoteCast".to_vec());

        // Verify vote was recorded
        let vote_key = format!("vote:{}:{}", hex::encode(proposal_id), hex::encode(&from));
        let vote = state
            .get_storage(&SYSTEM_ADDRESS, vote_key.as_bytes())
            .unwrap();
        assert_eq!(vote[0], 1);
    }

    // ---- Validator staking (register escrow / exit refund) tests -------------

    fn make_register_validator_data(self_stake: u128) -> Vec<u8> {
        let payload = serde_json::json!({
            "consensus_pubkey": vec![1u8; 32],
            "pq_pubkey": vec![2u8; 1952],
            "bls_pubkey": vec![3u8; 48],
            "withdrawal_address": Address::new([9u8; 32]),
            "self_stake": self_stake,
            "metadata_uri": "",
        });
        let mut data = SELECTOR_VALIDATOR_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    fn register_tx(from: Vec<u8>, self_stake: u128, nonce: u64) -> VmTransaction {
        VmTransaction::new(
            from,
            None,
            0,
            make_register_validator_data(self_stake),
            300_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            1337,
        )
    }

    const REG_GAS_COST: u128 = 1_000_000_000u128 * GAS_VALIDATOR_REGISTER as u128;
    const EXIT_GAS_COST: u128 = 1_000_000_000u128 * GAS_VALIDATOR_EXIT as u128;

    #[tokio::test]
    async fn test_validator_register_escrows_stake() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        let stake: u128 = 1_000_000_000_000_000; // 1e15 wei
        let start: u128 = 10_000_000_000_000_000_000; // 10 TNZO
        state.set_balance(&from, start);

        let tx = register_tx(from.clone(), stake, 0);
        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(result.success);

        // Balance debited by stake + gas; stake moved into the vault.
        assert_eq!(state.get_balance(&from), start - stake - REG_GAS_COST);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), stake);
        // Bond recorded for exact refund on exit.
        let bond = state
            .get_storage(
                &SYSTEM_ADDRESS,
                format!("staking_bond:{}", hex::encode(&from)).as_bytes(),
            )
            .unwrap();
        assert_eq!(u128::from_le_bytes(bond.try_into().unwrap()), stake);
    }

    #[tokio::test]
    async fn test_validator_register_insufficient_balance_rejected() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![2u8; 20];
        let stake: u128 = 1_000_000_000_000_000_000; // 1 TNZO
        let start: u128 = 500_000_000_000_000_000; // 0.5 TNZO — gas ok, stake not
        state.set_balance(&from, start);

        let tx = register_tx(from.clone(), stake, 0);
        let result = executor.execute_transaction(&tx, &mut state).await;
        assert!(result.is_err(), "registration must fail without the stake");
        // No partial escrow: balance untouched, vault empty.
        assert_eq!(state.get_balance(&from), start);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), 0);
    }

    #[tokio::test]
    async fn test_validator_register_zero_stake_rejected() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![3u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);

        let tx = register_tx(from.clone(), 0, 0);
        assert!(
            executor.execute_transaction(&tx, &mut state).await.is_err(),
            "zero-stake registration must be rejected"
        );
    }

    // ---- RegisterIdentity (TDIP D5) ----------------------------------------

    fn make_identity_register_data(did: &str, controller: &[u8]) -> Vec<u8> {
        let payload = tenzro_types::identity::RegisterIdentityPayload {
            did: did.to_string(),
            identity_type: "human".to_string(),
            display_name: "Alice".to_string(),
            controller_pubkey: controller.to_vec(),
            key_type: "Ed25519".to_string(),
            wallet_id: "wallet-1".to_string(),
            wallet_address: Address::new([7u8; 32]),
            pq_verifying_key: vec![1u8; 1952],
            bls_verifying_key: vec![2u8; 48],
            metadata: Default::default(),
        };
        let mut data = SELECTOR_IDENTITY_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    fn identity_register_tx(from: Vec<u8>, did: &str, controller: &[u8], nonce: u64) -> VmTransaction {
        VmTransaction::new(
            from,
            None,
            0,
            make_identity_register_data(did, controller),
            300_000,
            1_000_000_000,
            nonce,
            VmType::Tenzro,
            1337,
        )
    }

    #[tokio::test]
    async fn test_identity_register_stores_record_and_emits_log() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);

        let did = "did:tenzro:human:abc";
        let tx = identity_register_tx(from.clone(), did, &[9u8; 32], 0);
        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(result.success);

        // Record landed under SYSTEM_ADDRESS at identity:<did>.
        let stored = state
            .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(did))
            .expect("identity record must be stored");
        let decoded: tenzro_types::identity::RegisterIdentityPayload =
            serde_json::from_slice(&stored).unwrap();
        assert_eq!(decoded.did, did);

        // IdentityRegister log emitted with the canonical blob.
        assert!(
            result
                .logs
                .iter()
                .any(|l| l.topics.first().map(|t| t.as_slice()) == Some(b"IdentityRegister".as_ref())),
            "IdentityRegister log must be emitted"
        );
    }

    #[tokio::test]
    async fn test_identity_register_duplicate_did_rejected() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let did = "did:tenzro:human:dup";

        // First registration by controller A succeeds.
        let tx1 = identity_register_tx(from.clone(), did, &[9u8; 32], 0);
        assert!(executor.execute_transaction(&tx1, &mut state).await.unwrap().success);

        // Second registration of the SAME did by a DIFFERENT controller is
        // refused fail-closed (consensus-enforced DID uniqueness).
        let tx2 = identity_register_tx(from.clone(), did, &[8u8; 32], 1);
        assert!(
            executor.execute_transaction(&tx2, &mut state).await.is_err(),
            "duplicate DID from a different controller must be rejected"
        );
    }

    #[tokio::test]
    async fn test_identity_register_same_controller_refresh_ok() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let did = "did:tenzro:human:refresh";

        let tx1 = identity_register_tx(from.clone(), did, &[9u8; 32], 0);
        assert!(executor.execute_transaction(&tx1, &mut state).await.unwrap().success);
        // Same controller re-registers — idempotent refresh, not a rejection.
        let tx2 = identity_register_tx(from.clone(), did, &[9u8; 32], 1);
        assert!(
            executor.execute_transaction(&tx2, &mut state).await.unwrap().success,
            "same-controller re-registration must be allowed as a refresh"
        );
    }

    #[tokio::test]
    async fn test_validator_exit_refunds_stake() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![4u8; 20];
        let stake: u128 = 1_000_000_000_000_000; // 1e15
        let start: u128 = 10_000_000_000_000_000_000;
        state.set_balance(&from, start);

        // Register (bonds the stake).
        let reg = register_tx(from.clone(), stake, 0);
        assert!(executor.execute_transaction(&reg, &mut state).await.unwrap().success);
        let after_register = state.get_balance(&from);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), stake);

        // Exit (refunds the stake, drains the vault, clears the bond).
        let exit = VmTransaction::new(
            from.clone(),
            None,
            0,
            SELECTOR_VALIDATOR_EXIT.to_vec(),
            200_000,
            1_000_000_000,
            1,
            VmType::Evm,
            1337,
        );
        assert!(executor.execute_transaction(&exit, &mut state).await.unwrap().success);

        assert_eq!(state.get_balance(&from), after_register - EXIT_GAS_COST + stake);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), 0);
        let bond = state.get_storage(
            &SYSTEM_ADDRESS,
            format!("staking_bond:{}", hex::encode(&from)).as_bytes(),
        );
        assert!(bond.map(|b| b.is_empty()).unwrap_or(true), "bond record cleared");
    }

    // ---- Escrow handler tests ------------------------------------------------

    fn make_create_escrow_data(
        payee: &Address,
        amount: u128,
        expires_at: u64,
        release_conditions: ReleaseConditions,
    ) -> Vec<u8> {
        let payload = serde_json::json!({
            "payee": payee,
            "amount": amount,
            "asset_id": AssetId::tnzo(),
            "expires_at": expires_at,
            "release_conditions": release_conditions,
        });
        let mut data = SELECTOR_ESCROW_CREATE.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    fn make_release_escrow_data(escrow_id: [u8; 32], proof: ServiceProof) -> Vec<u8> {
        let payload = serde_json::json!({
            "escrow_id": escrow_id,
            "proof": proof,
        });
        let mut data = SELECTOR_ESCROW_RELEASE.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    fn make_refund_escrow_data(escrow_id: [u8; 32]) -> Vec<u8> {
        let payload = serde_json::json!({ "escrow_id": escrow_id });
        let mut data = SELECTOR_ESCROW_REFUND.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    /// Happy path: create + release with `Timeout` conditions (no signature required).
    #[tokio::test]
    async fn test_native_escrow_create_and_release_timeout() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();

        // Use a 32-byte payer address (canonical Tenzro shape).
        let payer_bytes = vec![1u8; 32];
        let payer_addr = Address::new([1u8; 32]);
        let payee_addr = Address::new([2u8; 32]);

        // Fund payer.
        state.set_balance(&payer_bytes, 10_000_000_000_000_000_000u128);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        // Use Timeout so release is permitted without a proof signature.
        // (Release additionally requires `now <= expires_at`, so set expiry far out.)
        let expires_at = now + 24 * 60 * 60 * 1000;

        let create_data =
            make_create_escrow_data(&payee_addr, 5_000, expires_at, ReleaseConditions::Timeout);
        let create_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            create_data,
            GAS_ESCROW_CREATE,
            1_000_000_000,
            7,
            VmType::Tenzro,
            1337,
        );

        let create_res = executor
            .execute_transaction(&create_tx, &mut state)
            .await
            .unwrap();
        assert!(create_res.success);
        assert_eq!(create_res.gas_used, GAS_ESCROW_CREATE);
        assert_eq!(create_res.output.len(), 32);

        let escrow_id: [u8; 32] = create_res.output.as_slice().try_into().unwrap();
        // Vault should hold the escrowed funds.
        let vault_addr = derive_vault_address(&escrow_id);
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 5_000);

        // Release. With Timeout conditions, no signatures are needed.
        let proof = ServiceProof::new(
            tenzro_types::settlement::ProofType::Cryptographic,
            b"timeout-noop".to_vec(),
        );
        let release_data = make_release_escrow_data(escrow_id, proof);
        let release_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            release_data,
            GAS_ESCROW_RELEASE,
            1_000_000_000,
            8,
            VmType::Tenzro,
            1337,
        );

        let release_res = executor
            .execute_transaction(&release_tx, &mut state)
            .await
            .unwrap();
        assert!(release_res.success);

        // Vault drained, payee credited.
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 0);
        assert_eq!(state.get_balance(payee_addr.as_bytes()), 5_000);

        // Escrow record updated to Released.
        let key = escrow_storage_key(&hex::encode(escrow_id));
        let blob = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()).unwrap();
        let stored: EscrowAccount = serde_json::from_slice(&blob).unwrap();
        assert_eq!(stored.status, EscrowStatus::Released);
        assert_eq!(stored.payer, payer_addr);
        assert_eq!(stored.payee, payee_addr);
    }

    /// Unauthorized release: only the payer may release. A non-payer caller
    /// must be rejected before any vault movement.
    #[tokio::test]
    async fn test_native_escrow_unauthorized_release() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();

        let payer_bytes = vec![1u8; 32];
        let payee_addr = Address::new([2u8; 32]);
        let attacker_bytes = vec![9u8; 32];
        state.set_balance(&payer_bytes, 10_000_000_000_000_000_000u128);
        state.set_balance(&attacker_bytes, 10_000_000_000_000_000_000u128);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let expires_at = now + 24 * 60 * 60 * 1000;
        let create_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            make_create_escrow_data(&payee_addr, 5_000, expires_at, ReleaseConditions::Timeout),
            GAS_ESCROW_CREATE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let create_res = executor
            .execute_transaction(&create_tx, &mut state)
            .await
            .unwrap();
        let escrow_id: [u8; 32] = create_res.output.as_slice().try_into().unwrap();
        let vault_addr = derive_vault_address(&escrow_id);
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 5_000);

        // Attacker (≠ payer) attempts to release.
        let proof = ServiceProof::new(
            tenzro_types::settlement::ProofType::Cryptographic,
            b"x".to_vec(),
        );
        let release_tx = VmTransaction::new(
            attacker_bytes.clone(),
            None,
            0,
            make_release_escrow_data(escrow_id, proof),
            GAS_ESCROW_RELEASE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let res = executor.execute_transaction(&release_tx, &mut state).await;
        assert!(res.is_err(), "attacker release must fail");
        let err_msg = format!("{}", res.unwrap_err());
        assert!(
            err_msg.contains("EscrowUnauthorized"),
            "expected EscrowUnauthorized, got: {}",
            err_msg
        );

        // Vault still funded; escrow still in Funded state.
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 5_000);
        assert_eq!(state.get_balance(payee_addr.as_bytes()), 0);
    }

    /// Refund before expiry is rejected for `ProviderSignature` conditions
    /// (counterparty-required); refund AFTER expiry must succeed.
    #[tokio::test]
    async fn test_native_escrow_refund_only_after_expiry() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();

        let payer_bytes = vec![1u8; 32];
        let payee_addr = Address::new([2u8; 32]);
        state.set_balance(&payer_bytes, 10_000_000_000_000_000_000u128);
        let payer_balance_before_create = state.get_balance(&payer_bytes);

        // ProviderSignature conditions: refund forbidden until expiry.
        // Set expires_at well in the past to make the escrow already expired.
        let past = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(60_000);
        let create_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            make_create_escrow_data(
                &payee_addr,
                5_000,
                past,
                ReleaseConditions::ProviderSignature,
            ),
            GAS_ESCROW_CREATE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let create_res = executor
            .execute_transaction(&create_tx, &mut state)
            .await
            .unwrap();
        let escrow_id: [u8; 32] = create_res.output.as_slice().try_into().unwrap();
        let vault_addr = derive_vault_address(&escrow_id);
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 5_000);

        // Escrow is already expired AND the conditions are ProviderSignature, so
        // refund is permitted via the expired branch. Drive the refund.
        let refund_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            make_refund_escrow_data(escrow_id),
            GAS_ESCROW_REFUND,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let refund_res = executor
            .execute_transaction(&refund_tx, &mut state)
            .await
            .unwrap();
        assert!(refund_res.success);

        // Vault drained.
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 0);

        // Escrow status updated.
        let key = escrow_storage_key(&hex::encode(escrow_id));
        let blob = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()).unwrap();
        let stored: EscrowAccount = serde_json::from_slice(&blob).unwrap();
        assert_eq!(stored.status, EscrowStatus::Refunded);

        // Payee never received funds.
        assert_eq!(state.get_balance(payee_addr.as_bytes()), 0);

        // Payer's net change = 0 minus 2x gas (create + refund).
        let final_payer = state.get_balance(&payer_bytes);
        let total_gas_paid =
            (GAS_ESCROW_CREATE as u128 + GAS_ESCROW_REFUND as u128).saturating_mul(1_000_000_000);
        assert_eq!(
            final_payer,
            payer_balance_before_create - total_gas_paid,
            "payer should be whole except for gas"
        );
    }

    /// Refund before expiry must fail when conditions require a counterparty.
    #[tokio::test]
    async fn test_native_escrow_refund_before_expiry_rejected() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();

        let payer_bytes = vec![1u8; 32];
        let payee_addr = Address::new([2u8; 32]);
        state.set_balance(&payer_bytes, 10_000_000_000_000_000_000u128);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let future = now + 60 * 60 * 1000;
        let create_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            make_create_escrow_data(
                &payee_addr,
                5_000,
                future,
                ReleaseConditions::ProviderSignature,
            ),
            GAS_ESCROW_CREATE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let create_res = executor
            .execute_transaction(&create_tx, &mut state)
            .await
            .unwrap();
        let escrow_id: [u8; 32] = create_res.output.as_slice().try_into().unwrap();

        // Refund attempt before expiry on ProviderSignature must fail.
        let refund_tx = VmTransaction::new(
            payer_bytes.clone(),
            None,
            0,
            make_refund_escrow_data(escrow_id),
            GAS_ESCROW_REFUND,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let res = executor.execute_transaction(&refund_tx, &mut state).await;
        assert!(res.is_err(), "premature refund must fail");
        let err_msg = format!("{}", res.unwrap_err());
        assert!(
            err_msg.contains("EscrowNotExpired"),
            "expected EscrowNotExpired, got: {}",
            err_msg
        );

        // Vault must still be funded.
        let vault_addr = derive_vault_address(&escrow_id);
        assert_eq!(state.get_balance(vault_addr.as_bytes()), 5_000);
    }

    // ---- Workflow handler smoke tests ---------------------------------------

    fn make_workflow_tx(selector: [u8; 4], from: Vec<u8>, json: &str) -> VmTransaction {
        let mut data = Vec::with_capacity(4 + json.len());
        data.extend_from_slice(&selector);
        data.extend_from_slice(json.as_bytes());
        VmTransaction::new(
            from,
            None,
            0,
            data,
            200_000,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        )
    }

    #[tokio::test]
    async fn test_workflow_create_emits_log_and_marker() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![7u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        let payload =
            r#"{"workflow_id":"wf123","creator":"did:tenzro:human:alice:1","title":"swap"}"#;
        let tx = make_workflow_tx(SELECTOR_WORKFLOW_CREATE, from.clone(), payload);

        let res = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(res.success);
        assert_eq!(res.gas_used, GAS_WORKFLOW_CREATE);
        assert_eq!(res.logs.len(), 1);
        assert_eq!(res.logs[0].topics[0], b"WorkflowCreate");

        // Marker is persisted under SYSTEM_ADDRESS.
        let marker = state.get_storage(&SYSTEM_ADDRESS, b"wf:create:wf123");
        assert_eq!(marker.as_deref(), Some(payload.as_bytes()));

        // Nonce incremented.
        assert_eq!(state.get_nonce(&from), 1);
    }

    #[tokio::test]
    async fn test_workflow_sign_uses_composite_marker_key() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![8u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        let payload =
            r#"{"workflow_id":"wf42","signer_did":"did:tenzro:human:bob:1","signature":"0x00"}"#;
        let tx = make_workflow_tx(SELECTOR_WORKFLOW_SIGN, from.clone(), payload);

        let res = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(res.success);
        assert_eq!(res.logs[0].topics[0], b"WorkflowSign");

        let marker = state.get_storage(&SYSTEM_ADDRESS, b"wf:sign:wf42:did:tenzro:human:bob:1");
        assert!(marker.is_some(), "composite-key marker must be persisted");
    }

    #[tokio::test]
    async fn test_workflow_rejects_oversized_payload() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![9u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        // Build a > 64KiB payload that's still well-formed JSON.
        let huge_value = "x".repeat(WORKFLOW_PAYLOAD_MAX_BYTES + 1);
        let payload = format!(
            r#"{{"workflow_id":"wf","creator":"did:tenzro:human:a:1","blob":"{}"}}"#,
            huge_value
        );
        let tx = make_workflow_tx(SELECTOR_WORKFLOW_CREATE, from, &payload);

        let err = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("exceeds"),
            "expected size-limit rejection, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn test_workflow_rejects_malformed_json() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![10u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        let tx = make_workflow_tx(SELECTOR_WORKFLOW_TRANSITION, from, "{not json");
        let err = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("not valid JSON") || msg.contains("Invalid workflow JSON"),
            "expected JSON parse error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn test_workflow_rejects_missing_id_field() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![11u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        // Valid JSON, but missing the `obligation_id` field.
        let payload = r#"{"some_other_field":"x"}"#;
        let tx = make_workflow_tx(SELECTOR_WORKFLOW_REGISTER_OBLIGATION, from, payload);
        let err = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("obligation_id"),
            "expected missing-field error mentioning `obligation_id`, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn test_workflow_estimate_gas_table() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let state = StateAdapter::new();

        // Each workflow selector should map to its dedicated gas table entry.
        let cases: Vec<([u8; 4], u64)> = vec![
            (SELECTOR_WORKFLOW_CREATE, GAS_WORKFLOW_CREATE),
            (SELECTOR_WORKFLOW_SIGN, GAS_WORKFLOW_SIGN),
            (SELECTOR_WORKFLOW_TRANSITION, GAS_WORKFLOW_TRANSITION),
            (
                SELECTOR_WORKFLOW_REGISTER_OBLIGATION,
                GAS_WORKFLOW_REGISTER_OBLIGATION,
            ),
            (
                SELECTOR_WORKFLOW_DISCHARGE_OBLIGATION,
                GAS_WORKFLOW_DISCHARGE_OBLIGATION,
            ),
            (
                SELECTOR_WORKFLOW_DEFAULT_OBLIGATION,
                GAS_WORKFLOW_DEFAULT_OBLIGATION,
            ),
            (SELECTOR_WORKFLOW_REGISTER_GATE, GAS_WORKFLOW_REGISTER_GATE),
            (SELECTOR_WORKFLOW_OPEN_APPROVAL, GAS_WORKFLOW_OPEN_APPROVAL),
            (
                SELECTOR_WORKFLOW_SUBMIT_DECISION,
                GAS_WORKFLOW_SUBMIT_DECISION,
            ),
            (SELECTOR_WORKFLOW_KILL_SWITCH, GAS_WORKFLOW_KILL_SWITCH),
            (
                SELECTOR_WORKFLOW_REGISTER_PRIVACY_DOMAIN,
                GAS_WORKFLOW_REGISTER_PRIVACY_DOMAIN,
            ),
            (
                SELECTOR_WORKFLOW_FREEZE_PRIVACY_DOMAIN,
                GAS_WORKFLOW_FREEZE_PRIVACY_DOMAIN,
            ),
        ];
        for (sel, want) in cases {
            let mut data = sel.to_vec();
            data.extend_from_slice(b"{}");
            let tx = VmTransaction::new(
                vec![0u8; 20],
                None,
                0,
                data,
                200_000,
                1_000_000_000,
                0,
                VmType::Tenzro,
                1337,
            );
            let got = executor.estimate_gas(&tx, &state).await.unwrap();
            assert_eq!(got, want, "selector {:?} estimated wrong gas", sel);
        }
    }

    #[tokio::test]
    async fn test_workflow_kill_switch_charges_higher_gas() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![12u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        let payload = r#"{"workflow_id":"emerg","scope":"workflow","reason":"oncall"}"#;
        let tx = make_workflow_tx(SELECTOR_WORKFLOW_KILL_SWITCH, from, payload);

        let res = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert_eq!(res.gas_used, GAS_WORKFLOW_KILL_SWITCH);
        const { assert!(GAS_WORKFLOW_KILL_SWITCH > GAS_WORKFLOW_TRANSITION) };
        assert_eq!(res.logs[0].topics[0], b"WorkflowKillSwitch");
    }
}
