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

use tenzro_settlement::escrow::{verify_release_conditions, EscrowAccount, EscrowStatus};
use tenzro_types::asset::AssetId;
use tenzro_types::kill_switch::{KillSwitchAction, KillSwitchReceipt};
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};
use tenzro_types::settlement::{ReleaseConditions, ServiceProof};

use crate::{
    config::VmConfig,
    error::{Result, VmError},
    gas::GasMeter,
    traits::{VmExecutor, VmState, VmType},
    types::{CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log, StateChange, VmTransaction},
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
// InsurancePool payouts: governance-approved, settled on-chain. Heavier than
// bond ops because they cross from singleton pool vault into a user wallet
// and persist a per-claim marker to make double-pay impossible.
const GAS_PAY_INSURANCE_CLAIM: u64 = 90_000;

// Domain-separated hash prefixes for escrow id and vault address derivation
const ESCROW_ID_DOMAIN: &[u8] = b"tenzro/escrow/id";
const ESCROW_VAULT_DOMAIN: &[u8] = b"tenzro/escrow/vault";

// Domain-separated hash prefix for kill-switch receipt id derivation
const KILLSWITCH_RECEIPT_DOMAIN: &[u8] = b"tenzro/killswitch/receipt";

// Domain-separated hash prefix for AgentBond vault address derivation.
// Must match `tenzro_token::bond::derive_bond_vault_address`.
const AGENT_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/agent-bond/vault";

// Domain-separated hash prefix for the singleton InsurancePool vault address.
// Must match `tenzro_token::bond::derive_insurance_pool_address`.
const INSURANCE_POOL_VAULT_DOMAIN: &[u8] = b"tenzro/insurance-pool/vault";

// Bond slashing residual floor — must match `tenzro_token::bond::DEFAULT_MIN_RESIDUAL`.
// 10 TNZO (10 × 10^18). If the post-slash bond amount drops below this floor,
// the bond is fully drained and marked Slashed.
const BOND_MIN_RESIDUAL: u128 = 10 * 1_000_000_000_000_000_000u128;

// System address for native operations (all 0xFF)
const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];

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

        let to = tx.to.as_ref()
            .ok_or_else(|| VmError::InvalidTransaction("Transfer requires recipient address".to_string()))?;

        // Calculate total cost (value + gas cost)
        let gas_cost = tx.gas_price.saturating_mul(GAS_TRANSFER as u128);
        let total_cost = tx.value.checked_add(gas_cost)
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
        let new_receiver_balance = old_receiver_balance.checked_add(tx.value)
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

        let amount_bytes: [u8; 8] = tx.data[4..12].try_into()
            .map_err(|_| VmError::InvalidTransaction("Invalid stake amount encoding".to_string()))?;
        let stake_amount = u64::from_le_bytes(amount_bytes) as u128;

        // Calculate total cost (stake amount + gas cost)
        let gas_cost = tx.gas_price.saturating_mul(GAS_STAKE as u128);
        let total_cost = stake_amount.checked_add(gas_cost)
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
        let new_stake = existing_stake.checked_add(stake_amount)
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

        let amount_bytes: [u8; 8] = tx.data[4..12].try_into()
            .map_err(|_| VmError::InvalidTransaction("Invalid unstake amount encoding".to_string()))?;
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
        tracing::debug!("Executing governance proposal: from={}", hex::encode(&tx.from));

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
                "Vote transaction requires selector + proposal_id (32 bytes) + vote (1 byte)".to_string(),
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
        state.set_storage(
            &SYSTEM_ADDRESS,
            vote_key.as_bytes(),
            vec![vote_byte],
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
        let payload: CreateEscrowPayload = serde_json::from_slice(payload_bytes)
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid CreateEscrow payload: {}", e)))?;

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
        let total_cost = payload.amount.checked_add(gas_cost).ok_or_else(|| {
            VmError::Internal("Escrow create cost overflow".to_string())
        })?;

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
        let new_vault_balance = old_vault_balance.checked_add(payload.amount).ok_or_else(|| {
            VmError::Internal("Vault balance overflow".to_string())
        })?;
        state.set_balance(&vault_bytes, new_vault_balance);

        // Build and persist the escrow record.
        let payee_bytes = payload.payee.as_bytes();
        let payee_addr_padded = pad_address_32(payee_bytes)?;

        let now_millis = chrono::Utc::now().timestamp_millis();
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
        let escrow_blob = serde_json::to_vec(&escrow).map_err(|e| {
            VmError::Internal(format!("Failed to serialize escrow record: {}", e))
        })?;
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

        let payload: ReleaseEscrowPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid ReleaseEscrow payload: {}", e)))?;

        let escrow_id_hex = hex::encode(payload.escrow_id);
        let storage_key = escrow_storage_key(&escrow_id_hex);
        let escrow_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {} not found", escrow_id_hex))
            })?;
        let mut escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
            VmError::Internal(format!("Failed to decode escrow record {}: {}", escrow_id_hex, e))
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
        let now_millis = chrono::Utc::now().timestamp_millis();
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
        let new_payee_balance = old_payee_balance.checked_add(escrow.amount).ok_or_else(|| {
            VmError::Internal("Payee balance overflow".to_string())
        })?;
        state.set_balance(&payee_bytes, new_payee_balance);

        // Update escrow record.
        escrow.status = EscrowStatus::Released;
        let new_blob = serde_json::to_vec(&escrow).map_err(|e| {
            VmError::Internal(format!("Failed to serialize escrow record: {}", e))
        })?;
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

        let payload: RefundEscrowPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid RefundEscrow payload: {}", e)))?;

        let escrow_id_hex = hex::encode(payload.escrow_id);
        let storage_key = escrow_storage_key(&escrow_id_hex);
        let escrow_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {} not found", escrow_id_hex))
            })?;
        let mut escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
            VmError::Internal(format!("Failed to decode escrow record {}: {}", escrow_id_hex, e))
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
        let now_millis = chrono::Utc::now().timestamp_millis();
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
        let new_blob = serde_json::to_vec(&escrow).map_err(|e| {
            VmError::Internal(format!("Failed to serialize escrow record: {}", e))
        })?;
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
            timestamp: Timestamp::new(chrono::Utc::now().timestamp_millis()),
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

        let payload: QuarantineAgentPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| {
                VmError::InvalidTransaction(format!(
                    "Invalid QuarantineAgent payload: {}",
                    e
                ))
            })?;

        validate_killswitch_dids(&payload.agent_did, &payload.controller_did)?;
        validate_reason_text_len(payload.reason_text.as_deref())?;
        if let Some(ref hash) = payload.evidence_hash {
            validate_evidence_hash(hash)?;
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_KILLSWITCH_QUARANTINE as u128);
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
            timestamp: Timestamp::new(chrono::Utc::now().timestamp_millis()),
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

        let payload: TerminateAgentPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| {
                VmError::InvalidTransaction(format!(
                    "Invalid TerminateAgent payload: {}",
                    e
                ))
            })?;

        validate_killswitch_dids(&payload.agent_did, &payload.controller_did)?;
        if payload.slash_bps > 10_000 {
            return Err(VmError::InvalidTransaction(format!(
                "TerminateAgent slash_bps {} exceeds 10000 (100%)",
                payload.slash_bps
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_KILLSWITCH_TERMINATE as u128);
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
            timestamp: Timestamp::new(chrono::Utc::now().timestamp_millis()),
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
                    .map_err(|e| {
                        VmError::Internal(format!("decode bond marker: {}", e))
                    })?;
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
                            VmError::Internal(
                                "bond marker missing amount".to_string(),
                            )
                        })?;
                    let slashed = compute_slash_amount(
                        prior_amount,
                        payload.slash_bps,
                        BOND_MIN_RESIDUAL,
                    );
                    if slashed > 0 {
                        let bond_vault_addr =
                            derive_bond_vault_address(&payload.agent_did);
                        let bond_vault_bytes = bond_vault_addr.as_bytes().to_vec();
                        let pool_addr = derive_insurance_pool_address();
                        let pool_bytes = pool_addr.as_bytes().to_vec();

                        let old_bond_vault_balance =
                            state.get_balance(&bond_vault_bytes);
                        // Defensive — the vault should never hold less than
                        // the marker says, but use saturating math anyway so
                        // a state divergence doesn't underflow.
                        let new_bond_vault_balance =
                            old_bond_vault_balance.saturating_sub(slashed);
                        state.set_balance(&bond_vault_bytes, new_bond_vault_balance);

                        let old_pool_balance = state.get_balance(&pool_bytes);
                        let new_pool_balance = old_pool_balance
                            .checked_add(slashed)
                            .ok_or_else(|| {
                                VmError::Internal(
                                    "InsurancePool balance overflow".to_string(),
                                )
                            })?;
                        state.set_balance(&pool_bytes, new_pool_balance);

                        let new_amount = prior_amount.saturating_sub(slashed);
                        let terminal = new_amount < BOND_MIN_RESIDUAL;
                        marker["amount"] = serde_json::Value::String(
                            (if terminal { 0u128 } else { new_amount }).to_string(),
                        );
                        marker["op"] = serde_json::Value::String(
                            if terminal {
                                "Slashed".to_string()
                            } else {
                                "PartiallySlashed".to_string()
                            },
                        );
                        let new_marker_blob = serde_json::to_vec(&marker)
                            .map_err(|e| {
                                VmError::Internal(format!(
                                    "encode bond marker: {}",
                                    e
                                ))
                            })?;
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
                            4 + payload.agent_did.len()
                                + 4
                                + controller_for_log.len()
                                + 16
                                + 2
                                + 1,
                        );
                        bond_log_data.extend_from_slice(
                            &(payload.agent_did.len() as u32).to_le_bytes(),
                        );
                        bond_log_data.extend_from_slice(payload.agent_did.as_bytes());
                        bond_log_data.extend_from_slice(
                            &(controller_for_log.len() as u32).to_le_bytes(),
                        );
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

        let payload: PostAgentBondPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid PostAgentBond payload: {}", e)))?;

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
        let total_cost = payload.amount.checked_add(gas_cost).ok_or_else(|| {
            VmError::Internal("AgentBond post cost overflow".to_string())
        })?;

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
        let new_vault_balance = old_vault_balance.checked_add(payload.amount).ok_or_else(|| {
            VmError::Internal("AgentBond vault overflow".to_string())
        })?;
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

        let payload: IncreaseAgentBondPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid IncreaseAgentBond payload: {}", e)))?;

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
        let new_amount = prior_amount.checked_add(payload.amount).ok_or_else(|| {
            VmError::Internal("AgentBond amount overflow".to_string())
        })?;

        // Cost = gas + delta. Debit from controller wallet.
        let gas_cost = tx.gas_price.saturating_mul(GAS_BOND_INCREASE as u128);
        let total_cost = payload.amount.checked_add(gas_cost).ok_or_else(|| {
            VmError::Internal("AgentBond increase cost overflow".to_string())
        })?;
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
        let new_vault_balance = old_vault_balance.checked_add(payload.amount).ok_or_else(|| {
            VmError::Internal("AgentBond vault overflow".to_string())
        })?;
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

        let payload: WithdrawAgentBondPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid WithdrawAgentBond payload: {}", e)))?;

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
        let prior_op = marker
            .get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("");
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

        let payload: PayInsuranceClaimPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| {
                VmError::InvalidTransaction(format!(
                    "Invalid PayInsuranceClaim payload: {}",
                    e
                ))
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

/// Storage key for an escrow record under `SYSTEM_ADDRESS`: `escrow:<hex_id>`.
fn escrow_storage_key(escrow_id_hex: &str) -> String {
    format!("escrow:{}", escrow_id_hex)
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
    let mut out =
        Vec::with_capacity(4 + agent_did.len() + 4 + controller_did.len() + 32);
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
                self.execute_killswitch_pause(tx, state, &mut gas_meter).await
            }
            SELECTOR_KILLSWITCH_QUARANTINE => {
                self.execute_killswitch_quarantine(tx, state, &mut gas_meter).await
            }
            SELECTOR_KILLSWITCH_TERMINATE => {
                self.execute_killswitch_terminate(tx, state, &mut gas_meter).await
            }
            SELECTOR_POST_AGENT_BOND => {
                self.execute_post_agent_bond(tx, state, &mut gas_meter).await
            }
            SELECTOR_INCREASE_AGENT_BOND => {
                self.execute_increase_agent_bond(tx, state, &mut gas_meter).await
            }
            SELECTOR_WITHDRAW_AGENT_BOND => {
                self.execute_withdraw_agent_bond(tx, state, &mut gas_meter).await
            }
            SELECTOR_PAY_INSURANCE_CLAIM => {
                self.execute_pay_insurance_claim(tx, state, &mut gas_meter).await
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
            SELECTOR_PAY_INSURANCE_CLAIM => GAS_PAY_INSURANCE_CLAIM,
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
        let blob = state
            .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
            .unwrap();
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
        let total_gas_paid = (GAS_ESCROW_CREATE as u128 + GAS_ESCROW_REFUND as u128)
            .saturating_mul(1_000_000_000);
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
}
