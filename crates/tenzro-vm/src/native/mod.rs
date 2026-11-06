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
//! - **Stake**: bond, unbond or withdraw an account's stake for one role (selector: 0x01000001)
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
//! 0x01000001 - Stake(StakeOp)
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

pub mod feature_pause;
pub(crate) mod staking;
pub use participation::{
    Participation, begin_block as begin_block_participation, read_missed_epochs, read_participation,
};
pub use staking::{
    ACTIVE_FLOOR_PARAM, EXIT_CHURN_PARAM, INACTIVITY_ACTIVATION_PARAM, INACTIVITY_LIMIT_PARAM,
    JAIL_TERM_PARAM, genesis_validator_bonds, reinstated_at_epoch, staking_vault_address,
    vrf_key_of,
};
pub use staking::{SIGNATURE_SCHEMES_PARAM, scheme_admitted};
pub use staking::{
    governance_total_bonded, own_bonded_stake_of, sponsored_bond_of, sponsored_unbonding_of,
    total_sponsored_outstanding,
};
// Staking arithmetic, public for the fuzz targets that drive it directly.
pub use staking::{
    add_bond, begin_unbonding, correlated_slash_bps, slash_for_equivocation, vault_liabilities,
    withdraw_unbonded,
};
mod zk_registry;
pub use zk_registry::{SELECTOR_ZK_ATTEST, zk_attest_gas};

use tenzro_settlement::escrow::{EscrowAccount, EscrowStatus, verify_release_conditions};
use tenzro_types::asset::AssetId;
use tenzro_types::kill_switch::{KillSwitchAction, KillSwitchReceipt};
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};
use tenzro_types::settlement::{
    MAX_RELEASE_CLAIM_LEN, ReleaseConditions, ServiceProof, quorum_release_digest,
};

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

pub mod meter_bond;
pub(crate) mod payment_settlement;
pub use meter_bond::{meter_bond_storage_key, meter_bond_vault, read_meter_bond};
pub use payment_settlement::netting as settlement_netting;
pub use payment_settlement::plan::{
    GAS_SETTLEMENT_PLAN, LegEvidence, SELECTOR_SETTLEMENT_PLAN, SETTLEMENT_PLAN_TOPIC,
    begin_block as begin_block_plans, plan_vault_address, read_decision, read_decision_commitment,
    read_leg_evidence, read_leg_receipt, read_leg_receipt_commitment, read_plan,
    settlement_plan_gas,
};
pub use payment_settlement::recon::{
    RECON_MISMATCH_TOPIC, RECON_REWARD_PARAM, RECON_ROUTES_KEY, ReconJobs, list_mismatches,
    read_mismatch, read_recon_duty, read_recon_jobs, read_reconciliation, recon_routes,
};
pub use payment_settlement::{
    ATTESTED_CAP_PARAM, ATTESTED_ENABLED_PARAM, GAS_PAYMENT_OP, PAYMENT_RECORDED_TOPIC,
    VOUCHER_FRESHNESS_PARAM, check_escrow_voucher, read_escrow, read_payment, read_payment_by_id,
    read_split, usd_e6_to_wei, verify_payment_authorization,
};
pub use payment_settlement::{amount_with_leg, declared_leg};
pub mod compute_claim;
pub use compute_claim::{GAS_COMPUTE_CLAIM, SELECTOR_COMPUTE_CLAIM};
#[cfg(test)]
mod agent_control_tests;
pub mod registry;
pub use registry::{GAS_REGISTRY, SELECTOR_REGISTRY};
#[cfg(test)]
mod breaker_latency_tests;
#[cfg(test)]
mod bridge_watcher_tests;
#[cfg(test)]
mod charter_tests;
#[cfg(test)]
mod feature_pause_tests;
pub mod inference_fault;
#[cfg(test)]
mod metered_payment_tests;
#[cfg(test)]
mod outflow_caps_tests;
#[cfg(test)]
mod slash_paths_tests;
pub use inference_fault::{
    GAS_INFERENCE_FAULT, GAS_INFERENCE_FAULT_BYTE, SELECTOR_INFERENCE_FAULT,
};
pub mod training_proof;
pub use training_proof::{GAS_TRAINING_PROOF, GAS_TRAINING_PROOF_BYTE, SELECTOR_TRAINING_PROOF};
pub mod duty;
pub mod evidence;
pub mod insurance;
pub mod treasury_reserve;
pub mod validator_cover;
pub use evidence::{
    FINALITY_PROGRAM_KEY, HANDOVER_PROGRAM_KEY, check_evidence, read_finality_program,
    read_handover_program,
};
pub use treasury_reserve::{begin_block as begin_block_treasury, reserve_address};
pub mod bridge;
pub use bridge::{SELECTOR_BRIDGE, bridge_gas};
pub mod guardian;
pub mod token;
pub mod veto_escrow;
pub use veto_escrow::{
    SELECTOR_GOVERNANCE_CONCERN, SELECTOR_GOVERNANCE_VETO_SIGNAL, SELECTOR_GOVERNANCE_VETO_WITHDRAW,
};
pub mod upgrade;
pub use upgrade::{
    Readiness, ReadySignal, SELECTOR_SECURITY_DISCLOSURE, SELECTOR_UPGRADE_READY,
    SecurityCommitment, UPGRADE_SCHEDULED_TOPIC, read_security_commitment, read_upgrade_activation,
    readiness,
};
#[cfg(test)]
mod confidential_job_tests;
#[cfg(test)]
mod hardware_level_tests;
#[cfg(test)]
mod key_release_tests;
#[cfg(test)]
mod machine_attestation_tests;
#[cfg(test)]
mod passkey_identity_tests;
#[cfg(test)]
mod payout_gates_tests;
#[cfg(test)]
mod sponsored_bond_tests;
#[cfg(test)]
mod upgrade_tests;
#[cfg(test)]
mod vote_integrity_tests;
pub use crate::account_keys::SELECTOR_ACCOUNT_KEYS;
pub use crate::keystore::SELECTOR_KEYSTORE_UPDATE;
pub use token::SELECTOR_TOKEN;
pub mod role_stake;
pub use role_stake::{
    GenesisRoleBond, ROLE_STAKE_SUBJECT_PREFIX, RoleEndpoint, RoleStakeTotal, SELECTOR_STAKE,
    SlaSubject, SlaSubjectKind, WALLET_PROVIDER_DOCUMENT_PATH, WalletProviderStatus,
    entry_stake_ladder, genesis_role_bonds, read_role_stake, role_bonded, role_endpoints,
    role_owes_sla, role_stake_subject, role_stake_totals, role_stake_vault, role_stakes_of,
    sla_subject, stake_ladder, wallet_providers_for_domain,
};
pub mod availability_reward;
pub mod burn_netting;
pub mod economy;
pub mod participation;
pub mod payout_swap;
pub mod rewards;
pub mod settlement_asset;
pub use economy::{
    AgentBond, ComputeBond, EpochActivity, FeeRate, SELECTOR_FEE_RATE_SUBMIT, agent_bond,
    agent_bond_amount, agent_bonds_of_controller, amount_in_tnzo, compute_bond, compute_bonds,
    read_committed_rate, read_epoch_activity, read_fee_rate, read_symbol_rate, required_agent_bond,
    safety_rate, settlement_fee, slash_agent_bond, usd_to_wei,
};
pub mod agent_audit;
pub mod agent_terms;
pub mod bridge_watcher;
pub mod remote_grant;
pub mod treasury_remote;
pub use agent_audit::{
    AGENT_AUDIT_COMMIT_WINDOW, AGENT_AUDIT_FINDING_TOPIC, AGENT_AUDIT_TOPIC,
    AGENT_QUARANTINE_LIFTED_TOPIC, AGENT_REVOKED_TOPIC, AgentAuditRecord, AgentAuditVerdict,
    AgentQuarantine, GAS_AGENT_AUDIT_COMMIT, GAS_AGENT_AUDIT_FINDING, GAS_AGENT_AUDIT_FLAG,
    GAS_LIFT_AGENT_QUARANTINE, GAS_REVOKE_DELEGATED_AGENT, agent_audit_committers,
    last_agent_audit_epoch, read_agent_audit, read_agent_audit_verdict, read_agent_quarantine,
};
pub use agent_terms::{
    AGENT_ACT_TOPIC, AGENT_TERMS_TOPIC, GAS_AGENT_ACT, GAS_SET_AGENT_TERMS, PaymentProposal,
    StoredAgentTerms, check_agent_act, check_agent_payment, check_agent_status, machine_root_key,
    read_agent_act_nonce, read_agent_asset_spent, read_agent_history, read_agent_spent,
    read_agent_terms, verify_root_approval,
};
pub mod bridge_circuit;
pub mod bridge_committee;
pub mod bridge_exit;
pub mod security;
pub use bridge_circuit::{
    BRIDGE_CIRCUIT_LIFTED_TOPIC, BRIDGE_CIRCUIT_TOPIC, BRIDGE_MINT_LIMITS_KEY,
    BRIDGE_OUTFLOW_LIMITS_KEY, BridgeCircuitAuthority, BridgeCircuitTrip, bridge_route_stop,
    circuit_key as bridge_circuit_key, open_refusal as bridge_route_open_refusal,
    placeholders_key as bridge_placeholders_key, read_bridge_circuit, read_bridge_mint_limits,
    read_bridge_outflow_limits, read_bridge_route_mode, read_route_placeholders,
};
pub mod beacon;
pub mod da_retention;
pub mod did_services;
pub mod identity_revocation;
pub mod sla_energy_budget;
pub mod validator_machine;
pub use crate::account_outflow::SELECTOR_ACCOUNT_OUTFLOW;
pub use bridge_watcher::SELECTOR_BRIDGE_WATCHER;
pub use da_retention::begin_block as begin_block_da_retention;
pub use did_services::{SELECTOR_IDENTITY_SERVICES, read_did_services};
pub use identity_revocation::{SELECTOR_IDENTITY_REVOKE, read_delegated_agents};
pub use rewards::{
    CALENDAR_KEY, CheckpointSigners, EpochVotes, REWARD_SCHEDULE_KEY, VESTING_RELEASED_TOPIC,
    begin_block as begin_block_rewards, block_ms_at, calendar_ms, genesis_calendar,
    genesis_reward_schedule, read_coupons, read_epoch_summary, read_epoch_votes,
    read_reward_schedule, read_reward_state, read_vesting,
};
pub use sla_energy_budget::{
    MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS, SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM,
    SLA_CHALLENGE_JOULES_PER_PROBE, SLA_FLEET_JOULES_PER_UNIT_PER_DAY,
    challenge_energy_within_budget, fleet_unit_count, total_challenge_energy_joules_per_day,
    total_fleet_energy_joules_per_day,
};
pub mod funding;
pub mod hardware_level;
pub mod key_release;
pub mod machine_attestation;
pub mod payout_gates;
pub mod sponsored_bond;
pub mod stable_payout;
pub use funding::{
    ENDORSEMENT_ROOTS_KEY, GAS_FUNDING, SELECTOR_FUNDING, machine_endorsed, read_endorsement_roots,
    read_grant, read_proposal,
};
pub use key_release::SELECTOR_KEY_RELEASE;

// Function selectors (4 bytes)
pub const SELECTOR_GOVERNANCE_PROPOSE: [u8; 4] = [0x02, 0x00, 0x00, 0x01];
pub const SELECTOR_GOVERNANCE_VOTE: [u8; 4] = [0x02, 0x00, 0x00, 0x02];
/// Enact a proposal whose voting window has closed and which passed.
pub const SELECTOR_GOVERNANCE_EXECUTE: [u8; 4] = [0x02, 0x00, 0x00, 0x03];

/// A protocol guardian pausing or resuming governance enactment.
///
/// Payload is a single byte: 1 to pause, 0 to resume.
pub const SELECTOR_GOVERNANCE_PAUSE: [u8; 4] = [0x02, 0x00, 0x00, 0x05];

/// A protocol guardian signalling a pause of one feature for a bounded number
/// of epochs.
///
/// Payload: the epochs (u32, big endian), then the status lever's key as
/// UTF-8.
pub const SELECTOR_GOVERNANCE_FEATURE_PAUSE: [u8; 4] = [0x02, 0x00, 0x00, 0x0c];

/// A governance guardian vetoing a queued proposal during its timelock.
pub const SELECTOR_GOVERNANCE_VETO: [u8; 4] = [0x02, 0x00, 0x00, 0x04];
/// Add to an already-registered validator's self-stake.
///
/// `0x61`, not `0x30`: that was already `SELECTOR_VALIDATOR_REGISTER`, and a
/// duplicate is not a compile error — it is an unreachable match arm. The
/// second one silently never runs, so the transaction would have been accepted,
/// routed, and executed as a *registration* instead.
pub const SELECTOR_INCREASE_VALIDATOR_STAKE: [u8; 4] = [0x01, 0x00, 0x00, 0x61];
/// Move funds into the governance treasury.
pub const SELECTOR_TREASURY_DEPOSIT: [u8; 4] = [0x01, 0x00, 0x00, 0x62];
pub const SELECTOR_ESCROW_CREATE: [u8; 4] = [0x01, 0x00, 0x00, 0x10];
pub const SELECTOR_ESCROW_RELEASE: [u8; 4] = [0x01, 0x00, 0x00, 0x11];
pub const SELECTOR_ESCROW_REFUND: [u8; 4] = [0x01, 0x00, 0x00, 0x12];
/// Claim from escrows with payer-signed cumulative vouchers. Exposed `pub` so
/// the node-side encoder in `convert_transaction` can build the dispatch.
pub const SELECTOR_ESCROW_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x13];
/// Pay a hash-locked escrow to its payee against the lock's preimage.
pub const SELECTOR_ESCROW_PREIMAGE_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x14];
/// Pay a streaming escrow's accrued part to its payee.
pub const SELECTOR_ESCROW_STREAM_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x15];
/// Lock a bond behind a usage meter's key.
pub const SELECTOR_METER_BOND_POST: [u8; 4] = [0x01, 0x00, 0x00, 0x16];
/// Ask to withdraw, or withdraw, a meter bond.
pub const SELECTOR_METER_BOND_WITHDRAW: [u8; 4] = [0x01, 0x00, 0x00, 0x17];
/// Prove a meter lied about a metered charge and take from its bond.
pub const SELECTOR_METER_DISPUTE: [u8; 4] = [0x01, 0x00, 0x00, 0x18];
// Kill-switch selectors — exposed `pub` so the
// transaction encoder in `tenzro-node::event_loop::convert_transaction`
// can synthesise the VM dispatch payload from a `SignedTransaction`.
pub const SELECTOR_KILLSWITCH_PAUSE: [u8; 4] = [0x10, 0x00, 0x00, 0x1d];
pub const SELECTOR_KILLSWITCH_QUARANTINE: [u8; 4] = [0x10, 0x00, 0x00, 0x1e];
pub const SELECTOR_KILLSWITCH_TERMINATE: [u8; 4] = [0x10, 0x00, 0x00, 0x1f];
// AgentBond surety selectors. Exposed `pub` so the
// node-side encoder in `convert_transaction` can synthesise dispatch
// payloads from `SignedTransaction::{PostAgentBond,IncreaseAgentBond,
// WithdrawAgentBond}`.
pub const SELECTOR_POST_AGENT_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x20];
pub const SELECTOR_INCREASE_AGENT_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x21];
pub const SELECTOR_WITHDRAW_AGENT_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x22];
pub const SELECTOR_PAY_INSURANCE_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x23];
// HTTP-402 settlement selector. Authorized by the payer's own signature over
// the canonical payment authorization, verified in the handler; a
// per-payment_id marker under `SYSTEM_ADDRESS` makes the settlement
// idempotent so a replayed dispatch cannot double-debit the payer. Exposed
// `pub` so the node-side encoder in `convert_transaction` can synthesise the
// dispatch payload from `SignedTransaction::PayerSettle`.
pub const SELECTOR_PAYER_SETTLE: [u8; 4] = [0x01, 0x00, 0x00, 0x24];
// Compute-bond selectors. A compute bond is the per-DID service bond inference
// faults, frozen SLA verdicts and proven policy violations slash from; a
// role's admission bond is its `Stake` bond. The bond is real locked TNZO in a
// derived vault, on the same consensus path as AgentBond. Exposed `pub` so the node-side encoder in `convert_transaction`
// can synthesise dispatch payloads from
// `SignedTransaction::{PostComputeBond,IncreaseComputeBond,WithdrawComputeBond,
// FinalizeComputeBondWithdrawal}`.
pub const SELECTOR_POST_COMPUTE_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x25];
pub const SELECTOR_INCREASE_COMPUTE_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x26];
pub const SELECTOR_WITHDRAW_COMPUTE_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0x27];
pub const SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL: [u8; 4] = [0x01, 0x00, 0x00, 0x28];
/// A bonded validator's SLA probe outcomes for one closed epoch, one per
/// bonded compute provider. Once attesters hold two thirds of bonded stake the
/// provider's verdict for that epoch is frozen, and rental billing settles on
/// it instead of on the provider's own word.
pub const SELECTOR_SLA_ATTEST: [u8; 4] = [0x01, 0x00, 0x00, 0x2b];
// Dynamic validator-set selectors. Permissionless join / voluntary exit /
// metadata update. Authorization, churn caps, and state-machine transitions
// live in `tenzro_token::ValidatorRegistry` (the on-chain source of truth);
// the VM dispatcher emits a typed Log that the node-side post-execute scan
// translates into a registry mutation. The self-stake is bonded and slashed
// in `native/staking.rs`.
pub const SELECTOR_VALIDATOR_REGISTER: [u8; 4] = [0x01, 0x00, 0x00, 0x30];
pub const SELECTOR_VALIDATOR_EXIT: [u8; 4] = [0x01, 0x00, 0x00, 0x31];
/// Selector of a validator's consensus key rotation.
pub const SELECTOR_VALIDATOR_ROTATE_KEY: [u8; 4] = [0x01, 0x00, 0x00, 0x35];
/// Topic of the log a consensus key rotation emits.
pub const VALIDATOR_KEY_ROTATION_TOPIC: &[u8] = b"ValidatorKeyRotation";
/// Selector of a validator naming its machine identity
/// ([`validator_machine`]).
pub const SELECTOR_VALIDATOR_MACHINE: [u8; 4] = [0x01, 0x00, 0x00, 0xD9];
pub const SELECTOR_VALIDATOR_UPDATE_METADATA: [u8; 4] = [0x01, 0x00, 0x00, 0x32];
/// Evidence that a validator signed two checkpoints with one index. Anyone
/// may submit it; the signer's bond is slashed into the insurance pool when it executes,
/// and every node jails the signer when it replays the log.
pub const SELECTOR_CHECKPOINT_EQUIVOCATION: [u8; 4] = [0x01, 0x00, 0x00, 0x33];
/// The signers of a certified checkpoint, recorded so they earn the epoch's
/// vote reward. The node verifies the certificate against the committee of
/// its epoch before the block executes and hands the VM the signers'
/// accounts ([`rewards::CheckpointSigners`], JSON); a certificate that does
/// not verify never reaches the VM.
pub const SELECTOR_CHECKPOINT_SIGNERS: [u8; 4] = [0x01, 0x00, 0x00, 0x34];

/// A record the protocol asks a bonded validator to make, which pays no fee
/// whatever gas price it names: the signers of a certified checkpoint (see
/// `TransactionType::pays_no_fee`). Block execution holds it to no base fee
/// and charges it neither gas nor resource fees; its handler refuses it
/// from an account with no bond.
pub fn pays_no_fee(tx: &VmTransaction) -> bool {
    tx.vm_type == VmType::Tenzro && tx.data.starts_with(&SELECTOR_CHECKPOINT_SIGNERS)
}
/// A bonded validator's VRF contribution to the randomness beacon
/// ([`beacon`]).
pub const SELECTOR_BEACON_CONTRIBUTE: [u8; 4] = [0x01, 0x00, 0x00, 0xD0];
/// An operation on the registry of data-availability objects
/// ([`da_retention`]).
pub const SELECTOR_DA_RETENTION: [u8; 4] = [0x01, 0x00, 0x00, 0xD1];
/// A proof about the sending identity's hardware ([`hardware_level`]).
pub const SELECTOR_HARDWARE_PROOF: [u8; 4] = [0x01, 0x00, 0x00, 0xD7];
/// A TPM attestation attached to a machine root registered without one
/// ([`machine_attestation`]).
pub const SELECTOR_ATTACH_MACHINE_ATTESTATION: [u8; 4] = [0x01, 0x00, 0x00, 0xDA];
/// An operation on governance-sponsored validator bonds
/// ([`sponsored_bond`]).
pub const SELECTOR_SPONSORED_BOND: [u8; 4] = [0x01, 0x00, 0x00, 0xDB];
/// A node's per-epoch commitment to the audit trail of the agents it
/// supervised ([`agent_audit`]).
pub const SELECTOR_AGENT_AUDIT_COMMIT: [u8; 4] = [0x01, 0x00, 0x00, 0x36];
/// An agent's controller lifting its quarantine ([`agent_audit`]).
pub const SELECTOR_LIFT_AGENT_QUARANTINE: [u8; 4] = [0x01, 0x00, 0x00, 0x37];
/// A bonded validator's findings on its peers' committed audit roots
/// ([`agent_audit`]).
pub const SELECTOR_AGENT_AUDIT_FLAG: [u8; 4] = [0x01, 0x00, 0x00, 0x38];
/// A controller revoking a delegated agent ([`agent_audit`]).
pub const SELECTOR_REVOKE_DELEGATED_AGENT: [u8; 4] = [0x01, 0x00, 0x00, 0x39];
/// A controller's approved terms for a delegated agent ([`agent_terms`]).
pub const SELECTOR_SET_AGENT_TERMS: [u8; 4] = [0x01, 0x00, 0x00, 0x3a];
/// Open, deliver or close a handover proof duty ([`duty::handover_op`]).
pub const SELECTOR_HANDOVER_DUTY: [u8; 4] = [0x01, 0x00, 0x00, 0x3e];

/// `ReclaimAgentFunds { agent_did, controller_did, amount? }`: the
/// controller moves TNZO out of its agent's wallet back to its own.
pub const SELECTOR_RECLAIM_AGENT_FUNDS: [u8; 4] = [0x01, 0x00, 0x00, 0x92];

/// Gas for a reclaim: an authority check and two balance moves.
const GAS_RECLAIM_AGENT_FUNDS: u64 = 40_000;

/// `SetAgentTopUp { agent_did, controller_did, allowance? }`: the controller
/// lets its agent's wallet be refilled from its own, within an allowance;
/// no allowance cancels it.
pub const SELECTOR_SET_AGENT_TOPUP: [u8; 4] = [0x01, 0x00, 0x00, 0x93];

/// `TopUpAgent { agent_did }`: anyone refills an agent's wallet within its
/// controller's allowance.
pub const SELECTOR_TOPUP_AGENT: [u8; 4] = [0x01, 0x00, 0x00, 0x94];

/// Gas for setting a top-up allowance: an authority check and one record.
const GAS_SET_AGENT_TOPUP: u64 = 40_000;

/// Gas for a top-up: two records and two balance moves.
const GAS_TOPUP_AGENT: u64 = 40_000;

/// A controller's standing approval to refill its agent's wallet from its
/// own: whoever triggers a refill, the chain moves no more than this allows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentTopUp {
    /// The wallet refills come from (hex): the controller's, which set it.
    pub from: String,
    /// Most moved in one period, wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub per_period: u128,
    /// Period length, ms.
    pub period_ms: u64,
    /// A refill brings the agent's wallet up to this, wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub target: u128,
    /// No refill after this, ms.
    pub expires_at_ms: i64,
}

fn agent_topup_key(agent_did: &str) -> String {
    format!("agent_topup:{agent_did}")
}

fn agent_topup_used_key(agent_did: &str) -> String {
    format!("agent_topup_used:{agent_did}")
}

/// The top-up allowance a controller set for `agent_did`, if any.
pub fn read_agent_topup(state: &dyn VmState, agent_did: &str) -> Option<AgentTopUp> {
    funding::read_json(state, &agent_topup_key(agent_did))
}
/// One action by a delegated agent ([`agent_terms`]). Its calls, if any,
/// run in the runtime after the action ([`crate::calls`]).
pub const SELECTOR_AGENT_ACT: [u8; 4] = [0x01, 0x00, 0x00, 0x3b];
/// `RemoteGrantSettle`: an agent account's report, proven through its
/// chain's route.
pub const SELECTOR_REMOTE_GRANT_SETTLE: [u8; 4] = [0x01, 0x00, 0x00, 0x90];
/// Gas for settling one account report, before the route's own checks.
pub const GAS_REMOTE_GRANT_SETTLE: u64 = 150_000;
/// Ordered calls across the EVM and the SVM as one
/// transaction. The runtime executes it, since it reaches every VM
/// ([`crate::calls`]); the native executor never sees it.
pub const SELECTOR_CONTRACT_CALL: [u8; 4] = [0x01, 0x00, 0x00, 0x3c];

// Identity registration — replicate a DID + its public record into
// consensus state so an identity created on one node resolves on every node.
// A registry held in one node's memory would
// mean whoever you asked decides who owns a DID. Ordered by consensus, every
// node applies the same transition and DID uniqueness falls out of block order.
pub const SELECTOR_IDENTITY_REGISTER: [u8; 4] = [0x01, 0x00, 0x00, 0x60];

/// Selector of a payment record operation (`TransactionType::Payment`).
pub const SELECTOR_PAYMENT: [u8; 4] = [0x01, 0x00, 0x00, 0xA0];

// Gas costs for native operations
const GAS_TRANSFER: u64 = 21_000;
/// Gas limit of a `GovernancePropose` transaction.
pub const GAS_PROPOSE: u64 = 100_000;
/// Gas limit of a `GovernanceVote` transaction.
pub const GAS_VOTE: u64 = 30_000;
/// Enacting a passed proposal. Priced above a vote because it reads the
/// proposal, both tally legs and the electorate size, then moves balances.
pub const GAS_GOVERNANCE_EXECUTE: u64 = 120_000;
/// Increasing a self-stake: one storage read, a balance move, one write.
const GAS_INCREASE_VALIDATOR_STAKE: u64 = 60_000;
/// Depositing to the treasury: two balance reads, two writes.
const GAS_TREASURY_DEPOSIT: u64 = 40_000;
pub const GAS_ESCROW_CREATE: u64 = 75_000;
pub const GAS_ESCROW_RELEASE: u64 = 60_000;
pub const GAS_ESCROW_REFUND: u64 = 50_000;
// Kill-switch gas costs (controller-tier intervention is intentionally
// pricier than ordinary writes — discourages spam without making genuine
// pauses prohibitive).
const GAS_KILLSWITCH_PAUSE: u64 = 60_000;
const GAS_KILLSWITCH_QUARANTINE: u64 = 90_000;
const GAS_KILLSWITCH_TERMINATE: u64 = 120_000;
// Bond gas costs are shared with the CLI, which sends them as gas limits.
use tenzro_types::constants::bond_gas::{
    AGENT_BOND_INCREASE as GAS_BOND_INCREASE, AGENT_BOND_POST as GAS_BOND_POST,
    AGENT_BOND_WITHDRAW as GAS_BOND_WITHDRAW, COMPUTE_BOND_FINALIZE as GAS_COMPUTE_BOND_FINALIZE,
    COMPUTE_BOND_INCREASE as GAS_COMPUTE_BOND_INCREASE, COMPUTE_BOND_POST as GAS_COMPUTE_BOND_POST,
    COMPUTE_BOND_WITHDRAW as GAS_COMPUTE_BOND_WITHDRAW,
};
/// Length of one compute-index epoch. Matches the provider billing epoch, so
/// an index epoch and a billing epoch are the same hour.
pub const MARKET_EPOCH_MS: i64 = 3_600_000;
/// How many closed epochs back a submission may still refer to.
pub const MARKET_SUBMIT_WINDOW: u64 = 24;
// Base cost; each outcome adds GAS_SLA_OUTCOME.
pub const GAS_SLA_ATTEST: u64 = 40_000;
/// Log topic when a provider's SLA verdict for an epoch is frozen.
pub const SLA_VERDICT_TOPIC: &[u8] = b"SlaVerdict";
/// Log topic when a governance policy change enacts; the payload is a
/// [`crate::governance::PolicyEnactedLog`].
pub const POLICY_ENACTED_TOPIC: &[u8] = b"PolicyEnacted";
/// Governed key: cooldown between initiating a compute-bond withdrawal and
/// being able to finalize it, ms.
pub const COMPUTE_BOND_COOLDOWN_PARAM: &str = "compute_bond.withdraw_cooldown_ms";
/// Genesis value of [`COMPUTE_BOND_COOLDOWN_PARAM`]: seven days.
pub const DEFAULT_COMPUTE_BOND_COOLDOWN_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Governed key: cooldown between initiating an agent-bond withdrawal and
/// being able to finalize it, ms.
pub const AGENT_BOND_COOLDOWN_PARAM: &str = "agent_bond.withdraw_cooldown_ms";
/// Genesis value of [`AGENT_BOND_COOLDOWN_PARAM`]: fourteen days.
pub const DEFAULT_AGENT_BOND_COOLDOWN_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Governed key: a bond a slash leaves below this many whole TNZO is drained
/// entirely and marked slashed.
pub const BOND_MIN_RESIDUAL_PARAM: &str = "slashing.bond_min_residual_tnzo";
/// Genesis value of [`BOND_MIN_RESIDUAL_PARAM`]: 10 TNZO.
pub const DEFAULT_BOND_MIN_RESIDUAL_TNZO: u64 = 10;

/// The governed bond residual floor in base units.
pub(crate) fn bond_min_residual(state: &dyn VmState) -> u128 {
    u128::from(network_param(state, BOND_MIN_RESIDUAL_PARAM))
        .saturating_mul(1_000_000_000_000_000_000)
}
/// Governed key: the least compute bond a provider posts to be probed and
/// routed to, whole TNZO. A raised value waits out the tightening grace, so a
/// bond posted under the old value keeps backing its provider until then.
pub const COMPUTE_BOND_MIN_PARAM: &str = "compute_bond.min_tnzo";
/// Genesis value of [`COMPUTE_BOND_MIN_PARAM`]: 100 TNZO.
pub const DEFAULT_COMPUTE_BOND_MIN_TNZO: u64 = 100;

/// The governed compute bond minimum in base units.
pub fn compute_bond_min(state: &dyn VmState) -> u128 {
    u128::from(network_param(state, COMPUTE_BOND_MIN_PARAM))
        .saturating_mul(tenzro_types::constants::ONE_TNZO)
}
// InsurancePool payouts: governance-approved, settled on-chain. Heavier than
// bond ops because they cross from singleton pool vault into a user wallet
// and persist a per-claim marker to make double-pay impossible.
const GAS_PAY_INSURANCE_CLAIM: u64 = 90_000;
// Payer-authorized settlement: one payer→payee balance move + per-payment_id replay
// marker. Priced at the transfer-plus-marker tier — heavier than a bare
// Transfer (writes a storage marker + emits an audit Log) but lighter than
// escrow release (no vault indirection, no proof verification).
const GAS_PAYER_SETTLE: u64 = 40_000;
// Dynamic validator-set gas costs. Register is the most expensive (writes
// 2 KiB+ of PQ key material to the registry index); update is cheap; exit
// is mid-tier (state-machine transition + index update).
const GAS_VALIDATOR_REGISTER: u64 = 150_000;
const GAS_VALIDATOR_ROTATE_KEY: u64 = 150_000;
const GAS_VALIDATOR_EXIT: u64 = 80_000;
const GAS_VALIDATOR_UPDATE_METADATA: u64 = 50_000;
// Two composite signature verifications over checkpoint bodies, plus the
// bond, vault and replay-marker writes.
const GAS_CHECKPOINT_EQUIVOCATION: u64 = 150_000;
// The epoch's vote tally and the pending-payment queue, both rewritten.
const GAS_CHECKPOINT_SIGNERS: u64 = 60_000;

// Registering a DID consumes a globally unique name out of the DID namespace
// and writes a record every node must carry, so it is priced with the
// claim-class ops rather than the cheaper binds.
pub const GAS_IDENTITY_REGISTER: u64 = 100_000;

// Domain-separated hash prefixes for escrow id and vault address derivation
const ESCROW_ID_DOMAIN: &[u8] = b"tenzro/escrow/id";
const ESCROW_VAULT_DOMAIN: &[u8] = b"tenzro/escrow/vault";

// Domain-separated hash prefix for kill-switch receipt id derivation
const KILLSWITCH_RECEIPT_DOMAIN: &[u8] = b"tenzro/killswitch/receipt";

// Domain-separated hash prefix for AgentBond vault address derivation.
// Must match `tenzro_token::bond::derive_bond_vault_address`.
const AGENT_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/agent-bond/vault";

// Domain-separated hash prefix for compute-bond vault address derivation.
const COMPUTE_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/compute-bond/vault";

// Domain-separated hash prefix for the singleton InsurancePool vault address.
// Must match `tenzro_token::bond::derive_insurance_pool_address`.
const INSURANCE_POOL_VAULT_DOMAIN: &[u8] = b"tenzro/insurance-pool/vault";

// System address for native operations (all 0xFF)
pub const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];

/// Storage key, under `SYSTEM_ADDRESS`, of the network's chain id (u64
/// little-endian). Genesis writes it; custody approvals are checked against it.
pub const NETWORK_CHAIN_ID_KEY: &str = "network:chain_id";

/// The chain id genesis recorded for this network, or 0 when none is recorded.
pub fn network_chain_id(state: &dyn VmState) -> u64 {
    state
        .get_storage(&SYSTEM_ADDRESS, NETWORK_CHAIN_ID_KEY.as_bytes())
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

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
        let old_sender_nonce = state.get_nonce(&tx.from);

        // Debit sender (value + gas cost)
        let new_sender_balance = sender_balance.saturating_sub(total_cost);
        state.set_balance(&tx.from, new_sender_balance);

        // Credit receiver (value only). The receiver is read after the debit
        // is written: when `to == from` this sees the debited balance, so a
        // transfer to oneself nets out to paying the gas fee and nothing else.
        let old_receiver_balance = state.get_balance(to);
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

    /// Handle a governance proposal transaction
    /// Handle a `GovernancePropose` native transaction.
    ///
    /// Decodes a typed [`ProposalAction`](crate::governance::ProposalAction)
    /// from `tx.data[4..]`, validates it, and opens it for voting.
    ///
    /// This used to store the payload as opaque bytes and return. Nothing
    /// decoded it, so a proposal could say anything at all — including nothing
    /// — and only be discovered as meaningless at the point somebody tried to
    /// act on it, which nothing ever did. Validating at submission means a
    /// proposal that reaches the electorate is one that can actually be
    /// enacted.
    ///
    /// Authorization: only an address with bonded stake may propose. Without
    /// that, anyone with gas money can fill consensus state with proposals
    /// nobody will ever vote on, and each one is a permanent record every node
    /// stores forever.
    async fn execute_propose(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        use crate::governance::ProposalAction;

        gas_meter.consume(GAS_PROPOSE)?;

        if tx.data.len() < 5 {
            return Err(VmError::InvalidTransaction(
                "Proposal transaction requires selector + proposal data".to_string(),
            ));
        }
        let proposal_data = &tx.data[4..];

        // Only bonded validators propose, with stake they put up themselves:
        // a sponsored bond never votes and never proposes.
        let proposer_stake = staking::own_bonded_stake_of(state, &tx.from);
        if proposer_stake == 0 {
            return Err(VmError::InvalidTransaction(format!(
                "{} has no bonded stake, so it cannot submit a governance proposal",
                hex::encode(&tx.from)
            )));
        }
        // And enough of it: the governed share of all bonded stake, so the
        // network's attention is not spent on proposals with no real backing.
        let threshold_bps = network_param(state, crate::governance::PROPOSAL_THRESHOLD_PARAM);
        if !crate::governance::meets_proposal_threshold(
            proposer_stake,
            staking::governance_total_bonded(state),
            threshold_bps,
        ) {
            return Err(VmError::InvalidTransaction(format!(
                "{} holds {proposer_stake} of {} bonded stake, below the {threshold_bps} bps needed to open a proposal",
                hex::encode(&tx.from),
                staking::governance_total_bonded(state)
            )));
        }

        let action: ProposalAction = serde_json::from_slice(proposal_data).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid governance proposal payload: {e}"))
        })?;
        action
            .validate()
            .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;

        // A proposal signed by an agent is held to the agent phase. The
        // phase is governed, defaults to `None`, and widening it is itself a
        // timelocked, vetoable decision — so autonomy is something the network
        // grants deliberately rather than something that arrives with a
        // deployment.
        if is_agent_identity(state, &tx.from) {
            let phase = current_agent_phase(state);
            let domain = action.domain();
            if !phase.permits(domain) {
                return Err(VmError::InvalidTransaction(format!(
                    "an agent may not originate a {:?} action at agent phase '{}'; \
                     advancing the phase is itself a governance decision",
                    domain,
                    phase.as_str()
                )));
            }
        }

        // Per-action admission checks. Both exist to keep a governance power
        // from becoming a broader one than it is meant to be.
        match &action {
            // Bounds are already checked by `validate()` above, which runs
            // before this and refuses an out-of-range value at submission.
            // There is no further admission rule: changing a parameter is a
            // network decision, reversible by another vote, and it moves no
            // value.
            ProposalAction::RecoverUnownedFunds {
                from, to, amount, ..
            } => {
                // Source must be a system-held sink, never a user account.
                if !is_recoverable_source(from.as_bytes()) {
                    return Err(VmError::InvalidTransaction(format!(
                        "{} is not a system-held address; recovery may only draw from \
                         protocol sinks, because a power that reaches a user balance is \
                         confiscation rather than recovery",
                        hex::encode(from.as_bytes())
                    )));
                }
                // Unowned funds belong to the network: they return to the
                // treasury, which pays out only through the gated payout
                // actions. A recovery that paid a person would be a payout
                // with no approved recipient and no verified work.
                if to.as_bytes() != derive_treasury_address().as_bytes() {
                    return Err(VmError::InvalidTransaction(
                        "unowned funds return to the treasury; paying a person is a gated payout"
                            .to_string(),
                    ));
                }
                // The claim is checked against the books now as well as at
                // enactment, so a proposal for an imbalance the chain does
                // not show never reaches a vote.
                let recoverable = recoverable_amount(state, &recovery_key(from.as_bytes()));
                if recoverable < *amount {
                    return Err(VmError::InsufficientBalance {
                        required: *amount,
                        available: recoverable,
                    });
                }
            }
            ProposalAction::ParameterChange { key, value, .. } => {
                let in_force = network_param(state, key);
                let scheduled = pending_param(state, key).map_or(in_force, |p| p.value);
                crate::feature_gate::check_change(state, key, *value)?;
                crate::governance::steward_change_allowed(key, scheduled, *value)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                crate::governance::lever_change_allowed(key, network_param(state, key), *value)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                security::param_change_allowed(state, key, scheduled, *value)?;
                crate::governance::cap_change_allowed(
                    key,
                    crate::governance::guard_step_base(key, in_force, scheduled),
                    *value,
                    bridge_circuit::max_cap_raise_bps(state),
                )
                .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                let scheduled_of = |k: &str| {
                    pending_param(&*state, k).map_or_else(|| network_param(&*state, k), |p| p.value)
                };
                crate::governance::joint_change_allowed(key, *value, &scheduled_of)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                sla_energy_budget::param_change_allowed(state, key, *value, &scheduled_of)?;
            }
            ProposalAction::SetBridgeRoute { route, .. } => {
                bridge_circuit::check_route_raise(state, route)?;
            }
            ProposalAction::SetAgentAccountChain { .. } => {}
            ProposalAction::TreasuryRemoteAction {
                caip2,
                remote,
                payout,
                ..
            } => {
                treasury_remote::check_chain(state, caip2).map_err(|e| {
                    VmError::InvalidTransaction(format!("treasury remote action refused: {e}"))
                })?;
                stable_payout::check_remote(state, remote, payout.as_ref())?;
            }
            ProposalAction::SponsorOperatorStable {
                operator,
                from_epoch,
                to_epoch,
                token_id,
                amount,
                ..
            } => {
                stable_payout::check_sponsorship(
                    state,
                    operator.as_bytes(),
                    *from_epoch,
                    *to_epoch,
                    token_id,
                    *amount,
                )?;
            }
            ProposalAction::SetRateStream { .. }
            | ProposalAction::SetReserveFeed { .. }
            | ProposalAction::SetDelegateCode { .. } => {}
            ProposalAction::SetSettlementAsset { asset, .. } => {
                settlement_asset::check_against_ledger(state, asset)?;
            }
            ProposalAction::RemoveReserveFeed { asset_id, .. } => {
                if economy::read_reserve_feed(state, asset_id).is_none() {
                    return Err(VmError::InvalidTransaction(format!(
                        "no reserve feed is installed for {asset_id}"
                    )));
                }
            }
            ProposalAction::RetireRegistryEntry { id, .. } => {
                if registry::read_entry(state, id).is_none_or(|e| e.retired_at_ms.is_some()) {
                    return Err(VmError::InvalidTransaction(format!(
                        "no standing registry entry '{id}'"
                    )));
                }
            }
            ProposalAction::RemoveRateStream { feed_id, .. } => {
                if economy::read_rate_stream(state, feed_id).is_none() {
                    return Err(VmError::InvalidTransaction(format!(
                        "no rate stream {} is installed",
                        hex::encode(feed_id)
                    )));
                }
            }
            ProposalAction::RemoveBridgeRoute {
                adapter,
                source_chain,
                ..
            } => {
                // Removing a route that is not installed spends a vote on
                // nothing.
                let key =
                    tenzro_types::bridge_route::bridge_route_storage_key(*adapter, source_chain);
                let installed = state
                    .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
                    .is_some_and(|b| !b.is_empty());
                if !installed {
                    return Err(VmError::InvalidTransaction(format!(
                        "no bridge route is installed at {key}"
                    )));
                }
            }
            ProposalAction::SetGuardian {
                address,
                did,
                role,
                term_ends_ms,
                key_root,
                ..
            } => {
                guardian::check_seat(
                    state,
                    address.as_bytes(),
                    did,
                    *role,
                    *term_ends_ms,
                    key_root,
                    deterministic_now_ms(tx),
                )
                .map_err(|e| VmError::InvalidTransaction(format!("guardian seat refused: {e}")))?;
            }
            ProposalAction::LiftModuleFreeze { module, .. } => {
                if crate::invariant_monitor::frozen(state, *module).is_none() {
                    return Err(VmError::InvalidTransaction(format!(
                        "{} is not frozen",
                        module.name()
                    )));
                }
            }
            ProposalAction::RemoveGuardian { address, .. } => {
                if guardian::load_seat(state, address.as_bytes()).is_none() {
                    return Err(VmError::InvalidTransaction(format!(
                        "no guardian is seated at {}",
                        hex::encode(address.as_bytes())
                    )));
                }
            }
            ProposalAction::RevokeIdentity { did, .. } => {
                // The subject must exist. Voting on a DID that was never
                // registered spends a voting period and a timelock on nothing
                // and leaves a passed proposal that cannot enact — which reads
                // afterwards as the network having failed to act, rather than
                // as the proposal having been malformed.
                let did = did.trim();
                let known = state
                    .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(did))
                    .is_some_and(|b| !b.is_empty());
                if !known {
                    return Err(VmError::InvalidTransaction(format!(
                        "no identity '{did}' is registered on this chain, so there is nothing \
                         to revoke"
                    )));
                }
                // Already revoked is refused for the same reason: the vote
                // would decide something already decided.
                let revoked = state
                    .get_storage(&SYSTEM_ADDRESS, &identity_revocation_key(did))
                    .is_some_and(|b| !b.is_empty());
                if revoked {
                    return Err(VmError::InvalidTransaction(format!(
                        "identity '{did}' is already revoked"
                    )));
                }
            }
            ProposalAction::SetNetworkPayout { .. } | ProposalAction::ApproveValidators { .. } => {}
            ProposalAction::ReinstateValidator { validator, .. } => {
                if staking::bonded_stake_of(state, validator.as_bytes()) == 0 {
                    return Err(VmError::InvalidTransaction(format!(
                        "{} holds no validator bond to reinstate",
                        hex::encode(validator.as_bytes())
                    )));
                }
            }
            ProposalAction::SponsorValidatorBond {
                validator, amount, ..
            } => {
                sponsored_bond::check_sponsor(state, validator.as_bytes(), *amount)?;
            }
            ProposalAction::ApproveOperator {
                operator, criteria, ..
            } => {
                payout_gates::check_approve_operator(
                    state,
                    operator.as_bytes(),
                    criteria,
                    deterministic_now_ms(tx),
                )?;
            }
            ProposalAction::RevokeOperator { operator, .. } => {
                payout_gates::check_revoke_operator(state, operator.as_bytes())?;
            }
            ProposalAction::ApproveGrantee { grantee, .. } => {
                funding::require_registered_recipient(state, grantee.as_bytes())?;
            }
            ProposalAction::RevokeGrantee { grantee, .. } => {
                payout_gates::check_revoke_grantee(state, grantee.as_bytes())?;
            }
            ProposalAction::SponsorOperatorRunningCost {
                operator,
                from_epoch,
                to_epoch,
                amount,
                ..
            } => {
                payout_gates::check_running_cost(
                    state,
                    operator.as_bytes(),
                    *from_epoch,
                    *to_epoch,
                    *amount,
                )?;
            }
            ProposalAction::RecallSponsoredBond {
                validator, amount, ..
            } => {
                sponsored_bond::check_recall(state, validator.as_bytes(), *amount)?;
            }
            ProposalAction::TreasuryGrant {
                recipient,
                asset,
                release,
                ..
            } => {
                // The recipient must already have an identity. Paying an
                // address with nobody behind it would mint exactly what the
                // network forbids: a funded wallet answerable to no one.
                funding::require_registered_recipient(state, recipient.as_bytes())?;
                // A grant goes only to a grantee governance has approved.
                payout_gates::require_approved_grantee(state, recipient.as_bytes())?;
                if let Some(token_id) = asset {
                    stable_payout::check_grant_asset(state, token_id)?;
                }
                if let crate::governance::GrantRelease::Scheduled { verifiers, .. } = release {
                    for v in verifiers {
                        funding::require_registered_recipient(state, v.as_bytes())?;
                    }
                }
            }
            ProposalAction::RunningCostPayment {
                recipient,
                from_epoch,
                to_epoch,
                amount,
                ..
            } => {
                funding::require_registered_recipient(state, recipient.as_bytes())?;
                // The reserve pays an approved operator only for hours the
                // network judged it available, each hour once.
                payout_gates::check_running_cost(
                    state,
                    recipient.as_bytes(),
                    *from_epoch,
                    *to_epoch,
                    *amount,
                )?;
            }
            ProposalAction::ReleaseGrantTranche {
                grant_id, index, ..
            } => {
                funding::check_release_admissible(state, grant_id, *index)?;
            }
            ProposalAction::PolicyUpdate { .. } => {
                if let Some(basis) = action.security_basis() {
                    upgrade::admit_security_fix(state, &tx.from, basis)?;
                }
            }
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_PROPOSE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let new_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_balance);

        let mut opened = open_proposal(state, tx, &action, proposal_data)?;
        let proposal_hash = opened.hash;
        if let Some(basis) = action.security_basis() {
            upgrade::record_commitment(
                state,
                &hex::encode(proposal_hash),
                &tx.from,
                basis,
                &mut opened.state_changes,
            )?;
        }

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut state_changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(sender_balance.to_le_bytes().to_vec()),
            Some(new_balance.to_le_bytes().to_vec()),
        )];
        state_changes.extend(opened.state_changes);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ProposalCreated".to_vec()],
            [
                proposal_hash.as_slice(),
                tx.from.as_slice(),
                action.kind().as_bytes(),
            ]
            .concat(),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            proposal_hash.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `GovernanceVote` native transaction.
    ///
    /// Records a stake-weighted ballot and folds it into the proposal's running
    /// totals.
    ///
    /// Two things were missing before, and either alone was fatal. Eligibility
    /// was never checked, so *any* address could vote — an attacker needed only
    /// gas to manufacture a result. And votes were never weighted or totalled,
    /// so there was no result to manufacture in the first place; the bytes just
    /// accumulated. Voting is now restricted to bonded validators, weighted by
    /// what they had bonded when they cast it, and accumulated into a tally the
    /// enactment path can actually read.
    async fn execute_vote(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VOTE)?;

        // selector || proposal_id(32) || vote(1) || validator_len(1) || validator
        //   || machine root approval (JSON, absent for a passkey-signed ballot)
        let (validator, root_approval) = match tx.data.get(37).map(|l| *l as usize) {
            Some(len @ (20 | 32)) if tx.data.len() >= 38 + len => {
                let rest = &tx.data[38 + len..];
                let approval = if rest.is_empty() {
                    None
                } else {
                    let approval: tenzro_types::agent_terms::AgentTermsApproval =
                        serde_json::from_slice(rest).map_err(|e| {
                            VmError::InvalidTransaction(format!("the ballot's root approval: {e}"))
                        })?;
                    approval.check_bounds().map_err(|e| {
                        VmError::InvalidTransaction(format!("the ballot's root approval: {e}"))
                    })?;
                    Some(approval)
                };
                (tx.data[38..38 + len].to_vec(), approval)
            }
            _ => {
                return Err(VmError::InvalidTransaction(
                    "Vote transaction requires selector + proposal_id (32 bytes) + vote (1 byte) \
                     + validator account (length-prefixed, 20 or 32 bytes)"
                        .to_string(),
                ));
            }
        };

        let proposal_id_bytes: [u8; 32] = tx.data[4..36].try_into().expect("length checked above");
        let proposal_id = hex::encode(proposal_id_bytes);
        let in_favour = tx.data[36] != 0;

        let mut proposal = load_proposal(state, &proposal_id).ok_or_else(|| {
            VmError::InvalidTransaction(format!("Proposal {proposal_id} does not exist"))
        })?;

        // The window has to be shut by the same clock every validator sees, or
        // two nodes disagree about whether a late ballot counted and fork.
        let now_ms = deterministic_now_ms(tx);
        if !proposal.is_open_at(now_ms) {
            return Err(VmError::InvalidTransaction(format!(
                "voting on {proposal_id} closed at {} (now {now_ms})",
                proposal.voting_ends_ms
            )));
        }

        let ballot_id = proposal.ballot_id();

        // The ballot is cast by the validator's root: its operator's passkey
        // identity signing the transaction, or, for a validator that is an
        // autonomous machine, that machine's root approving this ballot.
        // A validator has one root, so it has one ballot.
        let spent_approval = match &root_approval {
            None => {
                operator_may_vote(state, &tx.from, &validator)?;
                None
            }
            Some(approval) => Some(machine_root_may_vote(
                state,
                &proposal_id_bytes,
                in_favour,
                &validator,
                approval,
                deterministic_now_ms(tx).max(0) as u64,
            )?),
        };

        // Weight is the validator's bond that had aged the minimum bond age
        // when the proposal opened, or less if it has since fallen: bonding
        // shortly before or during the vote adds nothing.
        let weight = staking::vote_weight(state, &validator, &proposal);
        if weight == 0 {
            return Err(VmError::InvalidTransaction(format!(
                "{} had no bonded stake when the proposal opened, so it cannot vote",
                hex::encode(&validator)
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_VOTE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let new_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_balance);

        let voter_hex = hex::encode(&validator);
        let previous = load_vote(state, &ballot_id, &voter_hex);

        let mut tally = load_tally(state, &ballot_id);
        tally.apply_vote(weight, in_favour, previous);
        let (tally_blob, prior_tally) = store_tally(state, &ballot_id, &tally)?;
        let (vote_blob, prior_vote) = store_vote(
            state,
            &ballot_id,
            &voter_hex,
            weight,
            in_favour,
            CastBy::Principal,
        );

        // Keep the stored proposal's status in step once the window shuts, so a
        // reader does not have to recompute the outcome to know it.
        let mut proposal_change = None;
        if !proposal.is_open_at(now_ms) {
            proposal.status = proposal.outcome(&tally);
            let (blob, prior) = store_proposal(state, &proposal)?;
            proposal_change = Some(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                governance_proposal_key(&proposal_id).into_bytes(),
                prior,
                Some(blob),
            ));
        }

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // An approval counts once: replaying it cannot restore a vote the
        // machine root has since changed.
        let spent_change = spent_approval.map(|key| {
            state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), vec![1]);
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                key.into_bytes(),
                None,
                Some(vec![1]),
            )
        });

        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_balance.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                governance_vote_key(&ballot_id, &voter_hex).into_bytes(),
                prior_vote,
                Some(vote_blob),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                governance_tally_key(&ballot_id).into_bytes(),
                prior_tally,
                Some(tally_blob),
            ),
        ];
        state_changes.extend(proposal_change);
        state_changes.extend(spent_change);

        let mut log_data = Vec::with_capacity(32 + 32 + 16 + 1);
        log_data.extend_from_slice(&proposal_id_bytes);
        log_data.extend_from_slice(&validator);
        log_data.extend_from_slice(&weight.to_le_bytes());
        log_data.push(u8::from(in_favour));
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"VoteCast".to_vec()],
            log_data,
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![log],
            state_changes,
        ))
    }

    /// Handle a `GovernanceExecute` native transaction: enact a passed proposal.
    ///
    /// Permissionless on purpose. Anyone may submit the enactment and pay its
    /// gas, because the transaction carries no authority of its own — every
    /// condition is re-checked here against consensus state. If the window is
    /// still open, or quorum or threshold was not met, or the proposal already
    /// ran, this refuses regardless of who asked. Restricting *who* may submit
    /// it would add a liveness dependency without adding any safety: a passed
    /// proposal that only its proposer can enact is one a departed proposer can
    /// strand.
    /// Pause or resume governance enactment. Protocol guardians only.
    ///
    /// Stops enactment and nothing else. Voting, proposing and vetoing carry
    /// on, because freezing deliberation during an emergency would leave the
    /// power that imposed the pause as the only way out of it. Ordinary
    /// transactions are untouched: halting the chain is a different power from
    /// delaying a governance action, and only the second is granted here.
    async fn execute_governance_pause(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        use crate::governance::may_set_pause;

        gas_meter.consume(GAS_GOVERNANCE_EXECUTE)?;

        let want_paused = match tx.data.get(4) {
            Some(0) => false,
            Some(1) => true,
            _ => {
                return Err(VmError::InvalidTransaction(
                    "pause payload must be a single byte: 1 to pause, 0 to resume".into(),
                ));
            }
        };

        let now = tx.block_timestamp_ms.ok_or_else(|| {
            VmError::InvalidTransaction("a guardian pause executes only inside a block".into())
        })?;
        let role = guardian::active_role(state, &tx.from, now);
        // A steward's pause holds treasury and expedited enactment only; a
        // protocol guardian's holds all enactment.
        let scope = guardian::PauseScope::of(role);
        let record = guardian::pause_record(state, scope);
        let currently = now < record.paused_until_ms;
        may_set_pause(role, currently, want_paused)
            .map_err(|e| VmError::InvalidTransaction(format!("pause refused: {e}")))?;
        if want_paused && now < record.cooloff_until_ms {
            return Err(VmError::InvalidTransaction(format!(
                "pause refused: the last pause's cool-off runs until {}",
                record.cooloff_until_ms
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_GOVERNANCE_EXECUTE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let mut changes = Vec::new();
        let tallied =
            guardian::signal_pause(state, scope, want_paused, &tx.from, now, &mut changes)
                .map_err(|e| VmError::InvalidTransaction(format!("pause refused: {e}")))?;
        state.set_balance(&tx.from, sender_balance.saturating_sub(gas_cost));
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let topic: &[u8] = match (scope, tallied.carried(), want_paused) {
            (guardian::PauseScope::Enactment, true, true) => b"GovernancePaused",
            (guardian::PauseScope::Enactment, true, false) => b"GovernanceResumed",
            (guardian::PauseScope::Treasury, true, true) => b"TreasuryHeld",
            (guardian::PauseScope::Treasury, true, false) => b"TreasuryReleased",
            (_, false, true) => b"GuardianPauseSignalled",
            (_, false, false) => b"GuardianResumeSignalled",
        };
        if tallied.carried() {
            guardian::apply_pause(state, scope, want_paused, now, &mut changes);
        }

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![topic.to_vec()],
                tx.from.clone(),
            )],
            changes,
        ))
    }

    /// Veto a queued proposal. Governance guardians, or Foundation stewards
    /// on a treasury or expedited proposal; timelock only.
    ///
    /// The whole power is negative: it stops one decision and originates
    /// nothing. There is no path from here to moving funds or changing a
    /// parameter, which is what keeps an emergency brake from being a back
    /// door — a captured guardian can refuse to let the network act, visibly,
    /// but cannot act in its name.
    async fn execute_governance_veto(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        use crate::governance::may_veto;

        gas_meter.consume(GAS_GOVERNANCE_EXECUTE)?;

        let proposal_id = String::from_utf8(tx.data[4..].to_vec())
            .map_err(|_| VmError::InvalidTransaction("proposal id is not utf-8".into()))?;

        let mut proposal = load_proposal(state, &proposal_id).ok_or_else(|| {
            VmError::InvalidTransaction(format!("Proposal {proposal_id} does not exist"))
        })?;

        let now = tx.block_timestamp_ms.ok_or_else(|| {
            VmError::InvalidTransaction("a guardian veto executes only inside a block".into())
        })?;
        let role = guardian::active_role(state, &tx.from, now);
        may_veto(role, &proposal)
            .map_err(|e| VmError::InvalidTransaction(format!("veto refused: {e}")))?;

        let gas_cost = tx.gas_price.saturating_mul(GAS_GOVERNANCE_EXECUTE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let mut changes = Vec::new();
        let role = role.expect("may_veto refuses a caller without a seat");
        let tallied = guardian::signal_veto(state, role, &proposal_id, &tx.from, now, &mut changes)
            .map_err(|e| VmError::InvalidTransaction(format!("veto refused: {e}")))?;
        state.set_balance(&tx.from, sender_balance.saturating_sub(gas_cost));
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let topic: &[u8] = if tallied.carried() {
            if !proposal.veto() {
                return Err(VmError::Internal(format!(
                    "proposal {proposal_id} could not be vetoed"
                )));
            }
            store_proposal(state, &proposal).map_err(|e| {
                VmError::Internal(format!(
                    "failed to persist vetoed proposal {proposal_id}: {e}"
                ))
            })?;
            b"ProposalVetoed"
        } else {
            b"ProposalVetoSignalled"
        };

        let mut log_data = Vec::new();
        log_data.extend_from_slice(proposal_id.as_bytes());
        log_data.extend_from_slice(&tx.from);

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![topic.to_vec()],
                log_data,
            )],
            changes,
        ))
    }

    async fn execute_governance_execute(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        use crate::governance::{ProposalAction, ProposalStatus};

        gas_meter.consume(GAS_GOVERNANCE_EXECUTE)?;

        if tx.data.len() < 36 {
            return Err(VmError::InvalidTransaction(
                "Execute transaction requires selector + proposal_id (32 bytes)".to_string(),
            ));
        }
        let proposal_id = hex::encode(&tx.data[4..36]);

        let mut proposal = load_proposal(state, &proposal_id).ok_or_else(|| {
            VmError::InvalidTransaction(format!("Proposal {proposal_id} does not exist"))
        })?;

        let tally = load_tally(state, &proposal.ballot_id());
        let now_ms = deterministic_now_ms(tx);

        // A pause stops enactment, which is the blast radius that matters:
        // an attack that has already carried a vote is exactly what the brake
        // is for. Checked before the vote is read, so a paused chain gives the
        // same answer regardless of how the tally happens to stand.
        if guardian::is_paused(state, guardian::PauseScope::Enactment, now_ms) {
            return Err(VmError::InvalidTransaction(
                "governance enactment is paused by a protocol guardian; voting, proposing \
                 and vetoing continue"
                    .into(),
            ));
        }
        if crate::governance::steward_scope(&proposal.action)
            && guardian::is_paused(state, guardian::PauseScope::Treasury, now_ms)
        {
            return Err(VmError::InvalidTransaction(
                "treasury and expedited enactment is held by Foundation stewards; the hold \
                 lifts by itself"
                    .into(),
            ));
        }

        // Terminal states are refused before anything else looks at the vote.
        // A vetoed proposal must never become executable by re-deciding it, and
        // an executed one must not enact twice.
        match proposal.status {
            ProposalStatus::Vetoed => {
                return Err(VmError::InvalidTransaction(format!(
                    "proposal {proposal_id} was vetoed during its timelock"
                )));
            }
            ProposalStatus::Executed => {
                return Err(VmError::InvalidTransaction(format!(
                    "proposal {proposal_id} has already been executed"
                )));
            }
            _ => {}
        }

        // Not yet queued: decide it, and if it carried, start the timelock.
        // This call does not also enact — that is the point. Queuing and
        // enacting in one call would set the deadline and pass it in the same
        // instant, leaving the delay real in the type system and nowhere else.
        if !matches!(proposal.status, ProposalStatus::Queued) {
            let loosens = loosens_capture_guard(state, &proposal.action);
            let outcome = crate::governance::decide_guarded(&proposal, &tally, now_ms, loosens)
                .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
            if outcome != ProposalStatus::Passed {
                let reason = if loosens && proposal.outcome(&tally) == ProposalStatus::Passed {
                    format!(
                        "it loosens an economic safety bound, which needs yes votes of {} bps \
                         of all eligible stake",
                        proposal.rules.large_spend_approval_bps
                    )
                } else {
                    tally.failure_reason(proposal.track, &proposal.rules)
                };
                return Err(VmError::InvalidTransaction(format!(
                    "proposal {proposal_id} did not pass: {reason}"
                )));
            }

            proposal.status = ProposalStatus::Passed;
            if !proposal.queue(now_ms) {
                return Err(VmError::Internal(format!(
                    "proposal {proposal_id} could not be queued"
                )));
            }

            let gas_cost = tx.gas_price.saturating_mul(GAS_GOVERNANCE_EXECUTE as u128);
            let sender_balance = state.get_balance(&tx.from);
            if sender_balance < gas_cost {
                return Err(VmError::InsufficientBalance {
                    required: gas_cost,
                    available: sender_balance,
                });
            }
            state.set_balance(&tx.from, sender_balance.saturating_sub(gas_cost));
            let old_nonce = state.get_nonce(&tx.from);
            state.set_nonce(&tx.from, old_nonce + 1);
            // A queue that is not persisted is a timelock that does not exist:
            // the next call would find the proposal un-queued, decide it afresh
            // and start the delay again, or worse, report success while nothing
            // was written.
            store_proposal(state, &proposal).map_err(|e| {
                VmError::Internal(format!(
                    "failed to persist queued proposal {proposal_id}: {e}"
                ))
            })?;

            let eta = proposal.eta_ms.unwrap_or_default();
            let mut log_data = Vec::new();
            log_data.extend_from_slice(proposal_id.as_bytes());
            log_data.extend_from_slice(&eta.to_le_bytes());

            return Ok(ExecutionResult::success(
                gas_meter.final_used(),
                eta.to_le_bytes().to_vec(),
                vec![Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"GovernanceQueued".to_vec()],
                    log_data,
                )],
                vec![],
            ));
        }

        // Queued: enact only once the delay has actually elapsed.
        if !proposal.is_executable_at(now_ms) {
            let eta = proposal.eta_ms.unwrap_or_default();
            return Err(VmError::InvalidTransaction(format!(
                "proposal {proposal_id} is in timelock until {eta} (now {now_ms}); \
                 it can still be vetoed until then"
            )));
        }
        // A protocol upgrade waits for the validators' machines as well as
        // the clock.
        upgrade::require_readiness(state, &proposal.action)?;

        let gas_cost = tx.gas_price.saturating_mul(GAS_GOVERNANCE_EXECUTE as u128);
        let sender_balance = state.get_balance(&tx.from);
        if sender_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: sender_balance,
            });
        }
        let new_balance = sender_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_balance);

        let mut state_changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(sender_balance.to_le_bytes().to_vec()),
            Some(new_balance.to_le_bytes().to_vec()),
        )];
        // Actions whose effect is a record rather than a balance movement put
        // it here. `ProposalExecuted` is appended after these, so a consumer
        // reading in order sees what the proposal did before it sees that it
        // is done.
        let mut action_logs: Vec<Log> = Vec::new();

        let (moved, counterparty) = match &proposal.action {
            ProposalAction::RecoverUnownedFunds {
                from, to, amount, ..
            } => {
                let from_bytes = recovery_key(from.as_bytes());

                // Re-check eligibility at enactment. A voting period and a
                // timelock separate submission from here, and the set of
                // system addresses could move underneath in an upgrade.
                if !is_recoverable_source(&from_bytes) {
                    return Err(VmError::InvalidTransaction(format!(
                        "{} is no longer a system-held address",
                        hex::encode(&from_bytes)
                    )));
                }

                // Governance supplies the claim; state settles it. A proposal
                // asserting more than the source holds, or reaching into
                // validators' stake in the vault, is refused however it voted.
                let recoverable = recoverable_amount(state, &from_bytes);
                if recoverable < *amount {
                    return Err(VmError::InsufficientBalance {
                        required: *amount,
                        available: recoverable,
                    });
                }

                let available = state.get_balance(&from_bytes);
                let new_from = available.saturating_sub(*amount);
                state.set_balance(&from_bytes, new_from);

                let to_bytes = to.as_bytes().to_vec();
                let old_to = state.get_balance(&to_bytes);
                let new_to = old_to.checked_add(*amount).ok_or_else(|| {
                    VmError::Internal("recovery would overflow the destination".to_string())
                })?;
                state.set_balance(&to_bytes, new_to);

                state_changes.push(StateChange::new(
                    from_bytes.clone(),
                    b"balance".to_vec(),
                    Some(available.to_le_bytes().to_vec()),
                    Some(new_from.to_le_bytes().to_vec()),
                ));
                state_changes.push(StateChange::new(
                    to_bytes.clone(),
                    b"balance".to_vec(),
                    Some(old_to.to_le_bytes().to_vec()),
                    Some(new_to.to_le_bytes().to_vec()),
                ));

                (*amount, to_bytes)
            }
            ProposalAction::ParameterChange { key, value, .. } => {
                // Re-check the bounds at enactment as well as at submission.
                // The two are separated by a voting period and a timelock, and
                // the table could have changed underneath in an upgrade; a
                // value that is no longer permitted must not be written just
                // because it was permitted when it was proposed.
                let param = crate::governance::governed_param(key).ok_or_else(|| {
                    VmError::InvalidTransaction(format!("'{key}' is not a governed parameter"))
                })?;
                if *value < param.min || *value > param.max {
                    return Err(VmError::InvalidTransaction(format!(
                        "{key} = {value} is outside the permitted range {}..={}",
                        param.min, param.max
                    )));
                }
                let in_force = network_param(state, key);
                let scheduled = pending_param(state, key).map_or(in_force, |p| p.value);
                crate::feature_gate::check_change(state, key, *value)?;
                crate::governance::steward_change_allowed(key, scheduled, *value)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                crate::governance::lever_change_allowed(key, network_param(state, key), *value)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                security::param_change_allowed(state, key, scheduled, *value)?;
                crate::governance::cap_change_allowed(
                    key,
                    crate::governance::guard_step_base(key, in_force, scheduled),
                    *value,
                    bridge_circuit::max_cap_raise_bps(state),
                )
                .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                let scheduled_of = |k: &str| {
                    pending_param(&*state, k).map_or_else(|| network_param(&*state, k), |p| p.value)
                };
                crate::governance::joint_change_allowed(key, *value, &scheduled_of)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                sla_energy_budget::param_change_allowed(state, key, *value, &scheduled_of)?;
                schedule_param_change(state, param, *value, &proposal.id, &mut state_changes)?;
                // Setting validator mode again is how governance re-arms the
                // rate after the dispersion breaker fell back to its own rate.
                if key == economy::RATE_MODE_PARAM && *value == 1 {
                    economy::rearm_rate_breaker(state, &mut state_changes);
                }

                // No value moved and there is no counterparty: this is the
                // whole point of separating network decisions from treasury
                // ones.
                (0u128, Vec::new())
            }
            ProposalAction::SetAgentAccountChain { chain, .. } => {
                chain.validate().map_err(|e| {
                    VmError::InvalidTransaction(format!("agent account chain no longer valid: {e}"))
                })?;
                let key = tenzro_types::omni_account::AgentAccountChain::storage_key(&chain.caip2);
                funding::write_json(state, &key, chain, &mut state_changes)?;
                treasury_remote::index_chain(state, &chain.caip2, &mut state_changes)?;
                (0u128, Vec::new())
            }
            ProposalAction::SponsorOperatorStable {
                operator,
                from_epoch,
                to_epoch,
                token_id,
                amount,
                period_exception,
                ..
            } => {
                stable_payout::sponsor_stable(
                    state,
                    &proposal_id,
                    operator,
                    *from_epoch,
                    *to_epoch,
                    token_id,
                    *amount,
                    *period_exception,
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (0u128, operator.as_bytes().to_vec())
            }
            ProposalAction::TreasuryRemoteAction {
                caip2,
                caip19,
                remote,
                ttl_ms,
                payout,
                ..
            } => {
                stable_payout::pay_remote(
                    state,
                    &proposal_id,
                    remote,
                    payout.as_ref(),
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                treasury_remote::enact(
                    state,
                    caip2,
                    caip19,
                    remote,
                    *ttl_ms,
                    now_ms.max(0) as u64,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::SetBridgeRoute { route, .. } => {
                // Re-checked at enactment: the route rules can tighten in an
                // upgrade between submission and here, and a route that no
                // longer passes must not be written because it once did.
                route.validate_proposal().map_err(|e| {
                    VmError::InvalidTransaction(format!("bridge route no longer valid: {e}"))
                })?;
                // Checked against the route installed now, which may have
                // changed since submission.
                bridge_circuit::check_route_raise(state, route)?;
                // An issuer relationship is held by a bonded attestor.
                for asset in &route.assets {
                    if let tenzro_types::bridge_route::AssetTransfer::BurnAndMint {
                        operator, ..
                    } = &asset.transfer
                    {
                        let account = hex::decode(operator).unwrap_or_default();
                        if !role_bonded(
                            state,
                            &account,
                            tenzro_types::network::NetworkRole::Attestor,
                        ) {
                            return Err(VmError::InvalidTransaction(format!(
                                "the issuer relationship of {} is held by {operator}, which holds no attestor bond",
                                asset.symbol
                            )));
                        }
                    }
                }
                // The committees continue the set indexes bridge contracts hold.
                let mut installed = route.clone();
                bridge_committee::carry_set_indexes(state, &mut installed);
                let route = &installed;
                let storage_key = route.storage_key();
                let blob = serde_json::to_vec(route).map_err(|e| {
                    VmError::Internal(format!("bridge route serialization failed: {e}"))
                })?;
                let previous = state.get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes());
                state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    storage_key.into_bytes(),
                    previous,
                    Some(blob),
                ));
                // The route is now whole: nothing of it is a placeholder. Its
                // committees are drawn from bonded attestors next.
                bridge_circuit::clear_placeholders(
                    state,
                    route.adapter,
                    &route.source_chain,
                    &mut state_changes,
                );
                bridge_committee::on_route_installed(
                    state,
                    route,
                    deterministic_now_ms(tx),
                    &mut state_changes,
                )?;
                payment_settlement::recon::note_route(
                    state,
                    route.adapter,
                    &route.source_chain,
                    route.settlement_lock.is_some(),
                    &mut state_changes,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::RemoveBridgeRoute {
                adapter,
                source_chain,
                ..
            } => {
                let storage_key =
                    tenzro_types::bridge_route::bridge_route_storage_key(*adapter, source_chain);
                let previous = state.get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes());
                // An empty value reads as absent everywhere routes are read.
                state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), Vec::new());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    storage_key.into_bytes(),
                    previous,
                    Some(Vec::new()),
                ));
                payment_settlement::recon::note_route(
                    state,
                    *adapter,
                    source_chain,
                    false,
                    &mut state_changes,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::SetGuardian {
                address,
                did,
                role,
                term_ends_ms,
                key_root,
                ..
            } => {
                // Re-checked at enactment: the identity or the clock may have
                // moved during the vote and the timelock.
                guardian::check_seat(
                    state,
                    address.as_bytes(),
                    did,
                    *role,
                    *term_ends_ms,
                    key_root,
                    now_ms,
                )
                .map_err(|e| VmError::InvalidTransaction(format!("guardian seat refused: {e}")))?;
                let seat = crate::governance::GuardianSeat {
                    did: did.clone(),
                    role: *role,
                    term_ends_ms: *term_ends_ms,
                    key_root: key_root.clone(),
                };
                guardian::write_seat(state, address.as_bytes(), Some(&seat), &mut state_changes);
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"GuardianSeated".to_vec()],
                    serde_json::to_vec(&seat).unwrap_or_default(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::LiftModuleFreeze { module, .. } => {
                let (key, prior) = crate::invariant_monitor::lift(state, *module)?;
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key,
                    Some(prior),
                    Some(Vec::new()),
                ));
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"ModuleFreezeLifted".to_vec()],
                    module.name().as_bytes().to_vec(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::SetDelegateCode {
                code_hash, allowed, ..
            } => {
                let key = crate::delegation_guard::delegate_code_key(code_hash);
                let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                let value = allowed.then(|| vec![1u8]);
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    key.as_bytes(),
                    value.clone().unwrap_or_default(),
                );
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    previous,
                    value,
                ));
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"DelegateCodeListed".to_vec()],
                    code_hash.as_bytes().to_vec(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::RemoveGuardian { address, .. } => {
                guardian::write_seat(state, address.as_bytes(), None, &mut state_changes);
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"GuardianUnseated".to_vec()],
                    address.as_bytes().to_vec(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::SetRateStream { stream, .. } => {
                stream.validate().map_err(|e| {
                    VmError::InvalidTransaction(format!("rate stream no longer valid: {e}"))
                })?;
                let mut stream = stream.clone();
                stream.symbol = stream.symbol.trim().to_ascii_uppercase();
                let key = tenzro_types::RateStreamSigners::storage_key(&stream.feed_id);
                let blob = serde_json::to_vec(&stream).map_err(|e| {
                    VmError::Internal(format!("rate stream serialization failed: {e}"))
                })?;
                let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    previous,
                    Some(blob),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::RetireRegistryEntry { id, .. } => {
                registry::governance_retire(state, id, now_ms, &mut state_changes)?;
                (0u128, Vec::new())
            }
            ProposalAction::ApproveValidators {
                accounts, approve, ..
            } => {
                for account in accounts {
                    set_validator_approval(state, account.as_bytes(), *approve, &mut state_changes);
                }
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![if *approve {
                        b"ValidatorsApproved".to_vec()
                    } else {
                        b"ValidatorApprovalsWithdrawn".to_vec()
                    }],
                    serde_json::to_vec(accounts).unwrap_or_default(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::ReinstateValidator { validator, .. } => {
                if staking::bonded_stake_of(state, validator.as_bytes()) == 0 {
                    return Err(VmError::InvalidTransaction(format!(
                        "{} holds no validator bond to reinstate",
                        hex::encode(validator.as_bytes())
                    )));
                }
                let key = staking::reinstatement_key(validator.as_bytes());
                let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                let epoch = params_epoch(state).to_le_bytes().to_vec();
                state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), epoch.clone());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    previous,
                    Some(epoch),
                ));
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"ValidatorReinstated".to_vec()],
                    validator.as_bytes().to_vec(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::SponsorValidatorBond {
                validator, amount, ..
            } => {
                sponsored_bond::sponsor_bond(
                    state,
                    &proposal_id,
                    validator.as_bytes(),
                    *amount,
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (*amount, validator.as_bytes().to_vec())
            }
            ProposalAction::ApproveOperator {
                operator,
                class,
                criteria,
                ..
            } => {
                payout_gates::approve_operator(
                    state,
                    &proposal_id,
                    operator,
                    *class,
                    criteria,
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::RevokeOperator { operator, .. } => {
                payout_gates::revoke_operator(
                    state,
                    operator,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::ApproveGrantee {
                grantee,
                class,
                criteria,
                ..
            } => {
                payout_gates::approve_grantee(
                    state,
                    &proposal_id,
                    grantee,
                    *class,
                    criteria,
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::RevokeGrantee { grantee, .. } => {
                payout_gates::revoke_grantee(state, grantee, &mut state_changes, &mut action_logs)?;
                (0u128, Vec::new())
            }
            ProposalAction::SponsorOperatorRunningCost {
                operator,
                from_epoch,
                to_epoch,
                amount,
                ..
            } => {
                payout_gates::sponsor_running_cost(
                    state,
                    &proposal_id,
                    operator,
                    *from_epoch,
                    *to_epoch,
                    *amount,
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (*amount, operator.as_bytes().to_vec())
            }
            ProposalAction::RecallSponsoredBond {
                validator, amount, ..
            } => {
                sponsored_bond::recall_bond(
                    state,
                    validator.as_bytes(),
                    *amount,
                    now_ms,
                    &mut action_logs,
                )?;
                (0u128, Vec::new())
            }
            ProposalAction::RemoveRateStream { feed_id, .. } => {
                let key = tenzro_types::RateStreamSigners::storage_key(feed_id);
                let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    previous,
                    Some(Vec::new()),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::SetReserveFeed { feed, .. } => {
                feed.validate().map_err(|e| {
                    VmError::InvalidTransaction(format!("reserve feed no longer valid: {e}"))
                })?;
                let mut feed = feed.clone();
                feed.aggregator_address = feed.aggregator_address.to_ascii_lowercase();
                let key = tenzro_types::ReserveFeed::storage_key(&feed.asset_id);
                let blob = serde_json::to_vec(&feed).map_err(|e| {
                    VmError::Internal(format!("reserve feed serialization failed: {e}"))
                })?;
                let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    previous,
                    Some(blob),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::SetSettlementAsset { asset, .. } => {
                asset.validate().map_err(|e| {
                    VmError::InvalidTransaction(format!("settlement asset no longer valid: {e}"))
                })?;
                settlement_asset::check_against_ledger(state, asset)?;
                settlement_asset::write_settlement_asset(state, asset, &mut state_changes)?;
                (0u128, Vec::new())
            }
            ProposalAction::RemoveReserveFeed { asset_id, .. } => {
                let key = tenzro_types::ReserveFeed::storage_key(asset_id);
                let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    previous,
                    Some(Vec::new()),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::RevokeIdentity { did, reason } => {
                let did = did.trim();

                // Re-checked here, not only at submission. A voting period and
                // a timelock separate the two, and the identity may have been
                // revoked by its own holder in between — in which case the
                // sanction has already happened, and writing it again would
                // restate it with a new timestamp and a different author.
                let known = state
                    .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(did))
                    .is_some_and(|b| !b.is_empty());
                if !known {
                    return Err(VmError::InvalidTransaction(format!(
                        "identity '{did}' is no longer registered on this chain"
                    )));
                }
                let revocation_key = identity_revocation_key(did);
                if state
                    .get_storage(&SYSTEM_ADDRESS, &revocation_key)
                    .is_some_and(|b| !b.is_empty())
                {
                    return Err(VmError::InvalidTransaction(format!(
                        "identity '{did}' was already revoked before this proposal enacted"
                    )));
                }

                // The record is the whole effect. Nothing here touches a
                // balance: this power withdraws standing, and one that could
                // also reach the subject's funds would be confiscation wearing
                // a procedural name.
                let record = tenzro_types::identity::IdentityRevokedLog {
                    did: did.to_string(),
                    reason: reason.clone(),
                    revoked_by: format!("did:tenzro:governance:proposal:{proposal_id}"),
                    proposal_id: Some(proposal_id.clone()),
                };
                let blob = serde_json::to_vec(&record).map_err(|e| {
                    VmError::Internal(format!("cannot serialise the revocation record: {e}"))
                })?;
                state.set_storage(&SYSTEM_ADDRESS, &revocation_key, blob.clone());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    revocation_key,
                    None,
                    Some(blob.clone()),
                ));
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"IdentityRevoked".to_vec()],
                    blob,
                ));

                // No value moved and no counterparty, as for a parameter
                // change.
                (0u128, Vec::new())
            }
            ProposalAction::SetNetworkPayout {
                rail, destination, ..
            } => {
                let key = network_payout_storage_key(rail);
                let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    key.as_bytes(),
                    destination.as_bytes().to_vec(),
                );
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    prior,
                    Some(destination.as_bytes().to_vec()),
                ));
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"NetworkPayoutSet".to_vec()],
                    [rail.as_bytes(), b":", destination.as_bytes()].concat(),
                ));
                (0u128, Vec::new())
            }
            ProposalAction::TreasuryGrant {
                recipient,
                amount,
                tranches,
                milestones,
                vesting,
                asset,
                release,
                ..
            } => {
                let paid = funding::enact_grant(
                    state,
                    &proposal_id,
                    recipient,
                    *amount,
                    tranches,
                    milestones,
                    *vesting,
                    asset.as_deref(),
                    release,
                    deterministic_now_ms(tx),
                    &mut state_changes,
                    &mut action_logs,
                )?;
                (paid, recipient.as_bytes().to_vec())
            }
            ProposalAction::RunningCostPayment {
                recipient,
                from_epoch,
                to_epoch,
                amount,
                ..
            } => {
                funding::require_registered_recipient(state, recipient.as_bytes())?;
                // Gated like the treasury sponsorship: an approved operator,
                // unused verified hours, the yearly caps and the per-proposal
                // limit, a logged payout. The queue then pays within the
                // reserve's caps and the period limit.
                payout_gates::commit_reserve_payment(
                    state,
                    &proposal_id,
                    recipient,
                    *from_epoch,
                    *to_epoch,
                    *amount,
                    now_ms,
                    &mut state_changes,
                    &mut action_logs,
                )?;
                treasury_reserve::queue_payment(
                    state,
                    &proposal_id,
                    recipient,
                    *amount,
                    &mut state_changes,
                )?;
                (0u128, recipient.as_bytes().to_vec())
            }
            ProposalAction::ReleaseGrantTranche {
                grant_id, index, ..
            } => funding::enact_tranche_release(
                state,
                grant_id,
                *index,
                deterministic_now_ms(tx),
                &mut state_changes,
                &mut action_logs,
            )?,
            ProposalAction::PolicyUpdate { update, .. } => {
                // Checked again against the rules in force now: a vote does
                // not make an inapplicable change applicable.
                crate::governance::validate_policy_update(update)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                bridge_circuit::apply_policy(
                    state,
                    update,
                    deterministic_now_ms(tx),
                    &mut state_changes,
                    &mut action_logs,
                )?;
                if let tenzro_types::token::PolicyUpdate::TpmEndorsementRootsSet { roots_pem } =
                    update
                {
                    funding::set_endorsement_roots(state, roots_pem, &mut state_changes)?;
                }
                if let tenzro_types::token::PolicyUpdate::GpuDeviceRootsSet { roots_pem } = update {
                    hardware_level::set_gpu_roots(state, roots_pem, &mut state_changes)?;
                }
                if let tenzro_types::token::PolicyUpdate::GpuReferenceValuesSet { references } =
                    update
                {
                    hardware_level::set_gpu_references(state, references, &mut state_changes)?;
                }
                if let tenzro_types::token::PolicyUpdate::FinalityProgramSet { image_id } = update {
                    evidence::set_finality_program(state, image_id, &mut state_changes)?;
                }
                if let tenzro_types::token::PolicyUpdate::HandoverProgramSet { image_id } = update {
                    evidence::set_handover_program(state, image_id, &mut state_changes)?;
                }
                if let tenzro_types::token::PolicyUpdate::ProtocolUpgrade { version, code_hash } =
                    update
                {
                    upgrade::schedule(
                        state,
                        &proposal_id,
                        version,
                        code_hash,
                        tx.block_height.unwrap_or_default(),
                        &mut state_changes,
                        &mut action_logs,
                    )?;
                }
                let record = crate::governance::PolicyEnactedLog {
                    proposal_id: proposal_id.clone(),
                    update: update.clone(),
                };
                let blob = serde_json::to_vec(&record).map_err(|e| {
                    VmError::Internal(format!("cannot serialise the policy record: {e}"))
                })?;
                let key = policy_storage_key(crate::governance::policy_kind(update));
                let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
                state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
                state_changes.push(StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    key.into_bytes(),
                    prior,
                    Some(blob.clone()),
                ));
                action_logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![POLICY_ENACTED_TOPIC.to_vec()],
                    blob,
                ));
                (0u128, Vec::new())
            }
        };

        // Terminal, and written before returning: this is what stops the action
        // being applied twice by two enactment transactions in the same block.
        proposal.status = ProposalStatus::Executed;
        if proposal.action.security_basis().is_some() {
            upgrade::start_reveal_window(state, &proposal_id, now_ms, &mut state_changes)?;
        }
        let (proposal_blob, prior_proposal) = store_proposal(state, &proposal)?;
        let mut decision = Sha256::digest(&proposal_blob).to_vec();
        decision.extend_from_slice(&tx.block_height.unwrap_or_default().to_be_bytes());
        let decision_slot = governance_decision_slot(&proposal_id);
        state.set_storage(&SYSTEM_ADDRESS, decision_slot.as_bytes(), decision.clone());
        state_changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            decision_slot.into_bytes(),
            None,
            Some(decision),
        ));
        state_changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            governance_proposal_key(&proposal_id).into_bytes(),
            prior_proposal,
            Some(proposal_blob),
        ));

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut log_data = Vec::with_capacity(32 + 32 + 16);
        log_data.extend_from_slice(&tx.data[4..36]);
        log_data.extend_from_slice(&counterparty);
        log_data.extend_from_slice(&moved.to_le_bytes());
        action_logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ProposalExecuted".to_vec()],
            log_data,
        ));

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            moved.to_le_bytes().to_vec(),
            action_logs,
            state_changes,
        ))
    }

    // ---- Escrow handlers ----------------------------------------------------

    /// Handle a `CreateEscrow` native transaction: `tx.from` is the payer
    /// and pays the gas; [`lock_escrow`] does the rest. The `escrow_id` is
    /// the transaction output.
    async fn execute_escrow_create(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_ESCROW_CREATE)?;
        let payload: CreateEscrowPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid CreateEscrow payload: {}", e))
        })?;
        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_CREATE as u128);
        let (escrow_id, mut state_changes, log) = lock_escrow(
            state,
            &tx.from,
            tx.nonce,
            &payload,
            gas_cost,
            deterministic_now_ms(tx),
        )?;
        economy::check_provider_exposure(
            state,
            &payload.payee,
            &payload.asset_id,
            payload.amount,
            &escrow_id,
            deterministic_now_ms(tx),
            &mut state_changes,
        )?;
        // Each new escrow pays for looking at old records, so they are
        // deleted at least as fast as new ones come.
        let mut logs = vec![log];
        logs.extend(sweep_escrow_records(
            state,
            deterministic_now_ms(tx),
            &mut state_changes,
        )?);
        state_changes.extend(charge_and_advance(tx, state, gas_cost));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            escrow_id.to_vec(),
            logs,
            state_changes,
        ))
    }

    /// Handle a `ReleaseEscrow` native transaction: [`release_escrow`] with
    /// `tx.from` as the caller, who pays the gas.
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
        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_RELEASE as u128);
        require_balance(state, &tx.from, gas_cost)?;
        let (mut state_changes, log, burned) = release_escrow(
            state,
            &payload.escrow_id,
            &payload.proof,
            &tx.from,
            deterministic_now_ms(tx),
        )?;
        state_changes.extend(charge_and_advance(tx, state, gas_cost));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.escrow_id.to_vec(),
            vec![log],
            state_changes,
        )
        .with_burn(burned))
    }

    /// Handle a `RefundEscrow` native transaction: [`refund_escrow`] with
    /// `tx.from` as the caller, who pays the gas.
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
        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_REFUND as u128);
        require_balance(state, &tx.from, gas_cost)?;
        let (mut state_changes, log, burned) = refund_escrow(
            state,
            &payload.escrow_id,
            &tx.from,
            deterministic_now_ms(tx),
        )?;
        state_changes.extend(charge_and_advance(tx, state, gas_cost));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.escrow_id.to_vec(),
            vec![log],
            state_changes,
        )
        .with_burn(burned))
    }

    // ---- Kill-switch handlers --------------------------
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
    //      controller_did || receipt_id(32)`. Readers list receipts from
    //      these logs and load each from state (`read_kill_switch_receipt`).
    //
    // `frozen_at_block` is the height of the executing block (0 outside
    // block execution, as the EVM sees it).

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
        require_agent_controller(state, &tx.from, &payload.agent_did, &payload.controller_did)?;

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
            frozen_at_block: BlockHeight::new(tx.block_height.unwrap_or(0)),
            timestamp: Timestamp::new(deterministic_now_ms(tx)),
        };
        let blob = serde_json::to_vec(&receipt).map_err(|e| {
            VmError::Internal(format!("Failed to serialize KillSwitchReceipt: {}", e))
        })?;
        let storage_key = killswitch_storage_key(&receipt_id_hex);
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());

        // The pause freezes the agent's bond until it ends; a later pause
        // replaces the end.
        let paused_until = payload
            .until
            .map_or(i64::MAX, |u| i64::try_from(u).unwrap_or(i64::MAX));
        let pause_key = agent_pause_key(&payload.agent_did);
        let prior_pause = state.get_storage(&SYSTEM_ADDRESS, pause_key.as_bytes());
        let pause_blob = paused_until.to_le_bytes().to_vec();
        state.set_storage(&SYSTEM_ADDRESS, pause_key.as_bytes(), pause_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut state_changes = vec![
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                pause_key.as_bytes().to_vec(),
                prior_pause,
                Some(pause_blob),
            ),
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
            vec![KILL_SWITCH_TOPICS[0].to_vec()],
            encode_killswitch_log_data(&payload.agent_did, &payload.controller_did, &receipt_id),
        )];
        agent_audit::withdraw_authority(
            state,
            &payload.agent_did,
            deterministic_now_ms(tx).max(0) as u64,
            &mut state_changes,
            &mut logs,
        )?;

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            receipt_id.to_vec(),
            logs,
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
        // Only the agent's own controller quarantines it directly; anyone
        // else reaches a quarantine through an audit finding the validator
        // quorum stands behind.
        require_agent_controller(state, &tx.from, &payload.agent_did, &payload.controller_did)?;

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
            frozen_at_block: BlockHeight::new(tx.block_height.unwrap_or(0)),
            timestamp: Timestamp::new(deterministic_now_ms(tx)),
        };
        let blob = serde_json::to_vec(&receipt).map_err(|e| {
            VmError::Internal(format!("Failed to serialize KillSwitchReceipt: {}", e))
        })?;
        let storage_key = killswitch_storage_key(&receipt_id_hex);
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());

        // The status every node enforces the quarantine from, until the
        // controller lifts it.
        let mut state_changes = Vec::new();
        let mut logs = Vec::new();
        agent_audit::impose(
            state,
            &payload.agent_did,
            &AgentQuarantine {
                controller_did: payload.controller_did.clone(),
                by: hex::encode(&tx.from),
                reason_code: payload.reason_code,
                evidence_hash: payload.evidence_hash.clone(),
                at_ms: deterministic_now_ms(tx),
                revoked: false,
            },
            &mut state_changes,
            &mut logs,
        )?;

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        state_changes.extend([
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
        ]);

        logs.insert(
            0,
            Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![KILL_SWITCH_TOPICS[1].to_vec()],
                encode_killswitch_log_data(
                    &payload.agent_did,
                    &payload.controller_did,
                    &receipt_id,
                ),
            ),
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            receipt_id.to_vec(),
            logs,
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
        require_agent_controller(state, &tx.from, &payload.agent_did, &payload.controller_did)?;
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
            frozen_at_block: BlockHeight::new(tx.block_height.unwrap_or(0)),
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
            vec![KILL_SWITCH_TOPICS[2].to_vec()],
            encode_killswitch_log_data(&payload.agent_did, &payload.controller_did, &receipt_id),
        )];

        agent_audit::withdraw_authority(
            state,
            &payload.agent_did,
            deterministic_now_ms(tx).max(0) as u64,
            &mut state_changes,
            &mut logs,
        )?;

        // A Terminate carrying a slash takes that share of the agent's bond
        // into the insurance pool.
        economy::slash_agent_bond(
            state,
            &payload.agent_did,
            payload.slash_bps,
            &mut state_changes,
            &mut logs,
        )?;

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            receipt_id.to_vec(),
            logs,
            state_changes,
        ))
    }

    // ---- AgentBond handlers ---------------------------

    /// Handle a `PostAgentBond` native transaction.
    ///
    /// Decodes a JSON-encoded `PostAgentBondPayload`. Verifies that the
    /// payer (`tx.from` = `controller_did` owner) holds enough TNZO,
    /// debits gas + bond amount, credits the deterministic per-agent
    /// vault, persists a marker record at
    /// `SYSTEM_ADDRESS/bond:<agent_did>` carrying the controller and
    /// amount, indexes it under the controller, and emits a `BondPosted`
    /// log.
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

        // The bond's poster becomes the controller of an agent without
        // terms, so only whoever answers for the agent may post it.
        require_bond_poster(state, tx, &payload.agent_did, &payload.controller_did)?;

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

        // The bond's record; `economy::agent_bond` reads it.
        let marker = serde_json::json!({
            "agent_did": payload.agent_did,
            "controller_did": payload.controller_did,
            "amount": payload.amount.to_string(),
            "vault": hex::encode(vault_addr.as_bytes()),
            "owner": hex::encode(&tx.from),
            "op": "Posted",
        });
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());
        let mut index_changes = Vec::new();
        economy::index_bond_controller(
            state,
            &payload.controller_did,
            &payload.agent_did,
            &mut index_changes,
        )?;

        // Bump payer nonce.
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut state_changes = vec![
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
        state_changes.extend(index_changes);

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

        // Only the account that posted the bond tops it up, and only while
        // it is active: the vault pays back to that account, and a top-up
        // must not land in a bond that is being withdrawn.
        if marker.get("owner").and_then(|v| v.as_str()) != Some(hex::encode(&tx.from).as_str()) {
            return Err(VmError::InvalidTransaction(
                "only the account that posted the bond may top it up".to_string(),
            ));
        }
        if !matches!(
            marker.get("op").and_then(|v| v.as_str()),
            Some("Posted" | "Increased" | "PartiallySlashed")
        ) {
            return Err(VmError::InvalidTransaction(format!(
                "the bond of {} is not active",
                payload.agent_did
            )));
        }
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

    /// Handle a `WithdrawAgentBond` native transaction, sent by the account
    /// that posted the bond. The first starts the cooldown (the vault stays
    /// funded and slashable); one sent after the cooldown pays the vault back
    /// to that account and ends the bond. Both refuse while the agent is
    /// paused or quarantined: a frozen bond stays put.
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

        if marker.get("owner").and_then(|v| v.as_str()) != Some(hex::encode(&tx.from).as_str()) {
            return Err(VmError::InvalidTransaction(
                "only the account that posted the bond may withdraw it".to_string(),
            ));
        }
        let now_ms = deterministic_now_ms(tx);
        if agent_bond_frozen(state, &payload.agent_did, now_ms) {
            return Err(VmError::InvalidTransaction(format!(
                "the bond of {} is frozen while the agent is paused or quarantined",
                payload.agent_did
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_BOND_WITHDRAW as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }
        let mut new_payer_balance = payer_balance.saturating_sub(gas_cost);

        let prior_op = marker
            .get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let controller_did_str = marker
            .get("controller_did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut state_changes = Vec::new();
        let (topic, op_tag, amount): (&[u8], u8, u128) = match prior_op.as_str() {
            "Posted" | "Increased" | "PartiallySlashed" => {
                let cooldown_until =
                    now_ms.saturating_add(network_param(state, AGENT_BOND_COOLDOWN_PARAM) as i64);
                marker["op"] = serde_json::Value::String("WithdrawInitiated".to_string());
                marker["cooldown_until_ms"] = serde_json::Value::from(cooldown_until);
                let amount: u128 = marker
                    .get("amount")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                (b"BondWithdrawInitiated", 2, amount)
            }
            "WithdrawInitiated" => {
                let cooldown_until = marker
                    .get("cooldown_until_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::MAX);
                if now_ms < cooldown_until {
                    return Err(VmError::InvalidTransaction(format!(
                        "the bond's cooldown runs until {cooldown_until} ms"
                    )));
                }
                let vault = derive_bond_vault_address(&payload.agent_did)
                    .as_bytes()
                    .to_vec();
                let held = state.get_balance(&vault);
                state.set_balance(&vault, 0);
                state_changes.push(StateChange::new(
                    vault,
                    b"balance".to_vec(),
                    Some(held.to_le_bytes().to_vec()),
                    Some(0u128.to_le_bytes().to_vec()),
                ));
                new_payer_balance = new_payer_balance
                    .checked_add(held)
                    .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
                marker["op"] = serde_json::Value::String("Returned".to_string());
                marker["amount"] = serde_json::Value::String("0".to_string());
                (b"BondReturned", 3, held)
            }
            other => {
                return Err(VmError::InvalidTransaction(format!(
                    "cannot withdraw bond in {} state",
                    other
                )));
            }
        };
        state.set_balance(&tx.from, new_payer_balance);
        let marker_blob = serde_json::to_vec(&marker)
            .map_err(|e| VmError::Internal(format!("encode bond marker: {}", e)))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), marker_blob.clone());

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        state_changes.extend([
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
        ]);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![topic.to_vec()],
            encode_bond_log_data(&payload.agent_did, &controller_did_str, amount, op_tag),
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
    /// marker at `SYSTEM_ADDRESS/compute_bond:<provider_did>`, indexes the
    /// provider in the compute-bond index, and emits a `ComputeBondPosted`
    /// log.
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
        let min = compute_bond_min(state);
        if payload.amount < min {
            return Err(VmError::InvalidTransaction(format!(
                "a compute bond must hold at least {min} wei (compute_bond.min_tnzo)"
            )));
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
        let mut state_changes = state_changes;
        economy::index_compute_bond(state, &payload.provider_did, &mut state_changes)?;

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

    /// Handle an `SlaAttest` native transaction: one bonded validator's
    /// probe outcomes for a closed epoch, at most one per provider. Once the
    /// attesters for a provider hold two thirds of bonded stake its verdict is
    /// frozen: available when the stake saying so outweighs the stake saying
    /// not. Frozen providers, and providers this validator already attested,
    /// are skipped rather than refused.
    async fn execute_sla_attest(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let payload: SlaAttestPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid SlaAttest payload: {}", e))
        })?;
        if payload.outcomes.is_empty() || payload.outcomes.len() > MAX_SLA_OUTCOMES {
            return Err(VmError::InvalidTransaction(format!(
                "an attestation carries 1 to {} outcomes",
                MAX_SLA_OUTCOMES
            )));
        }
        let gas = GAS_SLA_ATTEST + GAS_SLA_OUTCOME * payload.outcomes.len() as u64;
        gas_meter.consume(gas)?;

        let now_epoch = (deterministic_now_ms(tx).max(0) / MARKET_EPOCH_MS) as u64;
        if payload.epoch >= now_epoch || payload.epoch + MARKET_SUBMIT_WINDOW < now_epoch {
            return Err(VmError::InvalidTransaction(format!(
                "epoch {} is not a closed epoch within the last {} (current {})",
                payload.epoch, MARKET_SUBMIT_WINDOW, now_epoch
            )));
        }
        let stake = bonded_stake_of(state, &tx.from);
        if stake == 0 {
            return Err(VmError::InvalidTransaction(
                "only accounts with bonded stake may attest SLA outcomes".to_string(),
            ));
        }
        for o in &payload.outcomes {
            if o.provider_did.is_empty() || o.provider_did.len() > 256 {
                return Err(VmError::InvalidTransaction(
                    "provider_did must be 1 to 256 bytes".to_string(),
                ));
            }
        }

        let gas_cost = tx.gas_price.saturating_mul(gas as u128);
        let payer_balance = state.get_balance(&tx.from);
        if payer_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer_balance,
            });
        }

        let me = hex::encode(&tx.from);
        let total = total_bonded_stake(state);
        let mut state_changes = Vec::new();
        let mut logs = Vec::new();
        let mut recorded = 0usize;
        sweep_open_sla(state, now_epoch, &mut state_changes)?;
        for outcome in payload.outcomes {
            // Only a compute bond or a bonded storage stake can owe an SLA.
            let Some(subject) = sla_subject(state, &outcome.provider_did) else {
                continue;
            };
            let bucket = sla_bucket(&outcome.provider_did, payload.epoch);
            let final_key = format!("sla:{}", bucket);
            if state
                .get_storage(&SYSTEM_ADDRESS, final_key.as_bytes())
                .is_some()
            {
                continue;
            }
            let subs_key = format!("sla_sub:{}", bucket);
            let prior = state.get_storage(&SYSTEM_ADDRESS, subs_key.as_bytes());
            let mut subs: Vec<SlaAttestation> = match &prior {
                Some(b) => serde_json::from_slice(b)
                    .map_err(|e| VmError::Internal(format!("decode SLA attestations: {}", e)))?,
                None => Vec::new(),
            };
            if subs.iter().any(|s| s.validator == me) {
                continue;
            }
            // No validator attests its own availability.
            if matches!(subject.kind, SlaSubjectKind::RoleStake(r) if r.is_validator())
                && subject.owner == tx.from
            {
                continue;
            }
            if prior.is_none() {
                // Listed by epoch, so one that never reaches a verdict can be found and deleted.
                let n: u64 =
                    funding::read_json(state, &sla_open_count_key(payload.epoch)).unwrap_or(0);
                funding::write_json(
                    state,
                    &sla_open_key(payload.epoch, n),
                    &outcome.provider_did,
                    &mut state_changes,
                )?;
                funding::write_json(
                    state,
                    &sla_open_count_key(payload.epoch),
                    &(n + 1),
                    &mut state_changes,
                )?;
            }
            subs.push(SlaAttestation {
                validator: me.clone(),
                available: outcome.available,
                stake: stake.to_string(),
                capacity: outcome.capacity,
            });
            let subs_blob = serde_json::to_vec(&subs)
                .map_err(|e| VmError::Internal(format!("encode SLA attestations: {}", e)))?;
            state.set_storage(&SYSTEM_ADDRESS, subs_key.as_bytes(), subs_blob.clone());
            state_changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                subs_key.as_bytes().to_vec(),
                prior,
                Some(subs_blob),
            ));
            recorded += 1;

            let (up, down) = subs.iter().fold((0u128, 0u128), |(up, down), s| {
                let w: u128 = s.stake.parse().unwrap_or(0);
                if s.available {
                    (up.saturating_add(w), down)
                } else {
                    (up, down.saturating_add(w))
                }
            });
            let submitted = up.saturating_add(down);
            if total == 0 || submitted.saturating_mul(3) < total.saturating_mul(2) {
                continue;
            }
            let verdict = SlaVerdict {
                available: up > down,
                up_stake: up,
                down_stake: down,
                attesters: subs.len(),
                measured_capacity: crate::funding::median_capacity(
                    subs.iter()
                        .filter_map(|s| Some((s.capacity?, s.stake.parse().unwrap_or(0))))
                        .collect(),
                ),
            };
            let blob = serde_json::to_vec(&verdict)
                .map_err(|e| VmError::Internal(format!("encode SLA verdict: {}", e)))?;
            state.set_storage(&SYSTEM_ADDRESS, final_key.as_bytes(), blob.clone());
            state_changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                final_key.as_bytes().to_vec(),
                None,
                Some(blob),
            ));
            // The verdict keeps what is read later; the attestations are not read again.
            funding::delete_record(state, &subs_key, &mut state_changes);
            if !verdict.available {
                // Outlives the verdict: streams and claims settle the hour by it.
                funding::write_json(
                    state,
                    &format!("sla_down:{bucket}"),
                    &true,
                    &mut state_changes,
                )?;
                let n: u64 =
                    funding::read_json(state, &sla_down_count_key(payload.epoch)).unwrap_or(0);
                funding::write_json(
                    state,
                    &sla_down_key(payload.epoch, n),
                    &outcome.provider_did,
                    &mut state_changes,
                )?;
                funding::write_json(
                    state,
                    &sla_down_count_key(payload.epoch),
                    &(n + 1),
                    &mut state_changes,
                )?;
            }
            let log_data = serde_json::to_vec(&serde_json::json!({
                "provider_did": outcome.provider_did,
                "epoch": payload.epoch,
                "available": verdict.available,
            }))
            .map_err(|e| VmError::Internal(format!("encode SLA verdict log: {}", e)))?;
            logs.push(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![SLA_VERDICT_TOPIC.to_vec()],
                log_data,
            ));
            // A provider judged unavailable pays the governed penalty out of
            // its compute bond or role stake into the insurance pool.
            if !verdict.available {
                let penalty = network_param(state, SLA_UNAVAILABLE_PENALTY_GWEI_PARAM) as u128
                    * 1_000_000_000;
                match subject.kind {
                    SlaSubjectKind::ComputeBond => {
                        let (_, _, bond_log) = inference_fault::slash_compute_bond(
                            state,
                            &outcome.provider_did,
                            None,
                            penalty,
                            &mut state_changes,
                        )?;
                        logs.extend(bond_log);
                    }
                    SlaSubjectKind::RoleStake(role) if role.is_validator() => {
                        // The penalty, as a share of the validator's bond,
                        // rounded up, through the one slashing route.
                        let bond = bonded_stake_of(state, &subject.owner);
                        let bps = if bond == 0 {
                            0
                        } else {
                            penalty.saturating_mul(10_000).div_ceil(bond).min(10_000) as u16
                        };
                        staking::slash_to_insurance(
                            state,
                            &subject.owner,
                            staking::SlashedStake::Validator,
                            bps,
                            &mut state_changes,
                        )?;
                    }
                    SlaSubjectKind::RoleStake(role) => {
                        let taken = role_stake::take_role_stake_amount(
                            state,
                            &subject.owner,
                            role,
                            penalty,
                            &mut state_changes,
                        )?;
                        let pool = derive_insurance_pool_address().as_bytes().to_vec();
                        let before = state.get_balance(&pool);
                        let after = before.saturating_add(taken);
                        state.set_balance(&pool, after);
                        state_changes.push(StateChange::new(
                            pool,
                            b"balance".to_vec(),
                            Some(before.to_le_bytes().to_vec()),
                            Some(after.to_le_bytes().to_vec()),
                        ));
                        insurance::note_credit(
                            state,
                            taken,
                            insurance::PoolSource::Slash,
                            &mut state_changes,
                        )?;
                    }
                }
            } else {
                // A validator's verdict pays against its registered machine
                // identity, which the hardware binding checks.
                let paid_did = match subject.kind {
                    SlaSubjectKind::RoleStake(r) if r.is_validator() => {
                        identity_did_of(state, &subject.owner)
                            .unwrap_or_else(|| outcome.provider_did.clone())
                    }
                    _ => outcome.provider_did.clone(),
                };
                availability_reward::pay_if_available(
                    state,
                    &paid_did,
                    &subject.owner,
                    payload.epoch,
                    deterministic_now_ms(tx),
                    &mut state_changes,
                    &mut logs,
                )?;
            }
        }
        if recorded == 0 {
            return Err(VmError::InvalidTransaction(
                "nothing to record: every provider is unbonded, frozen, or already attested by \
                 this validator"
                    .to_string(),
            ));
        }

        let new_payer_balance = payer_balance - gas_cost;
        state.set_balance(&tx.from, new_payer_balance);
        state_changes.insert(
            0,
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer_balance.to_le_bytes().to_vec()),
                Some(new_payer_balance.to_le_bytes().to_vec()),
            ),
        );
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            logs,
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
        // elapses and `FinalizeComputeBondWithdrawal` releases it.
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
        let cooldown_until_ms = deterministic_now_ms(tx)
            .saturating_add(network_param(state, COMPUTE_BOND_COOLDOWN_PARAM) as i64);
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

    /// Handle a `PayerSettle` native transaction.
    ///
    /// Moves `amount` from `payer` on-chain, gated by the payer's signed
    /// authorization and a per-`payment_id` replay marker under
    /// `SYSTEM_ADDRESS`. The amount splits three ways: the developer margin the
    /// payer signed to the app wallet it signed, then the network share of the
    /// remainder to the treasury, then the rest to `payee`. The submitting
    /// account pays gas and names no part of the split.
    async fn execute_payer_settle(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_PAYER_SETTLE)?;

        let payload: PayerSettlePayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid PayerSettle payload: {}", e))
        })?;

        payment_settlement::verify_payment_authorization(
            state,
            tx.chain_id,
            &payload.payment_id,
            &payload.payer,
            &payload.payee,
            payload.amount,
            &payload.authorization,
            deterministic_now_ms(tx).max(0) as u64,
        )?;

        // When the payer's own account is an agent's, this settlement is
        // held to the agent's standing and spend caps exactly as an
        // `AgentAct` is, whatever RPC surface produced the signed payment: a
        // generic settlement names no operation for `check_agent_payment`'s
        // fuller terms gate to check, but a revoked, quarantined or
        // over-cap agent is refused here regardless.
        let settle_at_ms = deterministic_now_ms(tx).max(0) as u64;
        let agent_did = identity_did_of(state, payload.payer.as_bytes())
            .filter(|did| did.starts_with("did:tenzro:agent:"));
        let mut agent_spend_changes = Vec::new();
        if let Some(did) = &agent_did {
            agent_spend_changes = agent_terms::check_and_record_agent_spend(
                state,
                did,
                &hex::encode(payload.payee.as_bytes()),
                Some(payload.authorization.asset.as_str()),
                payload.amount,
                payload.authorization.binding.usd_e6,
                settle_at_ms,
            )
            .map_err(VmError::InvalidTransaction)?;
        }

        // The submitting account pays gas.
        let gas_cost = tx.gas_price.saturating_mul(GAS_PAYER_SETTLE as u128);
        let caller_balance = state.get_balance(&tx.from);
        if caller_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: caller_balance,
            });
        }
        let new_caller_balance = caller_balance.saturating_sub(gas_cost);
        state.set_balance(&tx.from, new_caller_balance);
        let mut state_changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(caller_balance.to_le_bytes().to_vec()),
            Some(new_caller_balance.to_le_bytes().to_vec()),
        )];
        state_changes.append(&mut agent_spend_changes);

        // The signed developer margin is carved out of the payer-authorized
        // total (`amount * margin_bps / (10_000 + margin_bps)`), the settlement
        // fee out of the rest, and the payment's record is written.
        let outcome = payment_settlement::settle_native(
            state,
            tx.chain_id,
            deterministic_now_ms(tx),
            &payment_settlement::NativePayment {
                payer: &payload.payer,
                payee: &payload.payee,
                asset: &payload.authorization.asset,
                amount: payload.amount,
                binding: payload.authorization.binding,
                nonce: &payload.payment_id,
                agent_did: agent_did.as_deref(),
                relayer: Some(payment_settlement::Relayer {
                    account: &tx.from,
                    gas_wei: gas_cost,
                }),
                resellers: &payload.authorization.resellers,
            },
            &mut state_changes,
        )?;

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));

        // Log layout (parseable by node-side scan): `payment_id_len_le(4) ||
        //  payment_id_bytes || payer(32) || payee(32) || amount_le(16) ||
        //  margin_le(16) || app_wallet(32, zeroed when no attribution) ||
        //  settlement_fee_le(16) || pay_ref(32)`.
        let mut log_data =
            Vec::with_capacity(4 + payload.payment_id.len() + 32 + 32 + 16 + 16 + 32 + 16 + 32);
        log_data.extend_from_slice(&(payload.payment_id.len() as u32).to_le_bytes());
        log_data.extend_from_slice(payload.payment_id.as_bytes());
        log_data.extend_from_slice(payload.payer.as_bytes());
        log_data.extend_from_slice(payload.payee.as_bytes());
        log_data.extend_from_slice(&payload.amount.to_le_bytes());
        log_data.extend_from_slice(&outcome.margin.to_le_bytes());
        match &payload.authorization.binding.app_margin {
            Some(m) => log_data.extend_from_slice(m.app_wallet.as_bytes()),
            None => log_data.extend_from_slice(&[0u8; 32]),
        }
        log_data.extend_from_slice(&outcome.record.fee.to_le_bytes());
        log_data.extend_from_slice(&hex::decode(&outcome.record.pay_ref).unwrap_or_default());

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"PayerSettled".to_vec()],
            log_data,
        );

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            payload.payment_id.as_bytes().to_vec(),
            vec![log, outcome.log],
            state_changes,
        )
        .with_burn(outcome.burned)
        .with_treasury_leg(outcome.treasury_leg))
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

    /// Handle an `IncreaseValidatorStake` native transaction.
    ///
    /// Debits `tx.from` and moves the amount into the staking vault, exactly as
    /// registration does, then raises the recorded bond. The registry entry is
    /// updated by the node layer from the emitted log, the same way
    /// registration is mirrored.
    ///
    /// Authorization is structural: the stake is debited from `tx.from` and
    /// credited to `tx.from`'s own bond, so a caller can only ever increase
    /// their own — there is no address parameter to point elsewhere.
    /// Handle a `TreasuryDeposit` native transaction.
    ///
    /// Debits `tx.from` and credits the treasury vault. The mirror image of
    /// `TreasuryGrant`, which was previously the only side that existed — so the
    /// treasury could pay out but never take in, and every grant proposal would
    /// have passed its vote and then failed enactment on an empty balance.
    async fn execute_treasury_deposit(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_TREASURY_DEPOSIT)?;

        if tx.data.len() < 20 {
            return Err(VmError::InvalidTransaction(
                "TreasuryDeposit requires selector + amount (16 bytes)".to_string(),
            ));
        }
        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&tx.data[4..20]);
        let amount = u128::from_le_bytes(amount_bytes);

        if amount == 0 {
            return Err(VmError::InvalidTransaction(
                "treasury deposit must be greater than zero".to_string(),
            ));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_TREASURY_DEPOSIT as u128);
        let total_debit = gas_cost.saturating_add(amount);
        let balance = state.get_balance(&tx.from);
        if balance < total_debit {
            return Err(VmError::InsufficientBalance {
                required: total_debit,
                available: balance,
            });
        }
        let new_balance = balance.saturating_sub(total_debit);
        state.set_balance(&tx.from, new_balance);

        let treasury = derive_treasury_address();
        let treasury_bytes = treasury.as_bytes().to_vec();
        let old_treasury = state.get_balance(&treasury_bytes);
        let new_treasury = old_treasury
            .checked_add(amount)
            .ok_or_else(|| VmError::Internal("treasury overflow".to_string()))?;
        state.set_balance(&treasury_bytes, new_treasury);

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut log_data = Vec::with_capacity(32 + 16 + 16);
        log_data.extend_from_slice(&tx.from);
        log_data.extend_from_slice(&amount.to_le_bytes());
        log_data.extend_from_slice(&new_treasury.to_le_bytes());

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            new_treasury.to_le_bytes().to_vec(),
            vec![Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![b"TreasuryDeposit".to_vec()],
                log_data,
            )],
            vec![
                StateChange::new(
                    tx.from.clone(),
                    b"balance".to_vec(),
                    Some(balance.to_le_bytes().to_vec()),
                    Some(new_balance.to_le_bytes().to_vec()),
                ),
                StateChange::new(
                    treasury_bytes,
                    b"balance".to_vec(),
                    Some(old_treasury.to_le_bytes().to_vec()),
                    Some(new_treasury.to_le_bytes().to_vec()),
                ),
            ],
        ))
    }

    async fn execute_increase_validator_stake(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_INCREASE_VALIDATOR_STAKE)?;

        if tx.data.len() < 20 {
            return Err(VmError::InvalidTransaction(
                "IncreaseValidatorStake requires selector + amount (16 bytes)".to_string(),
            ));
        }
        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&tx.data[4..20]);
        let additional = u128::from_le_bytes(amount_bytes);

        if additional == 0 {
            return Err(VmError::InvalidTransaction(
                "stake increase must be greater than zero".to_string(),
            ));
        }

        // Must already be a validator. Registering is a different transaction
        // with different requirements — consensus keys, a withdrawal address —
        // and silently creating an entry here would bypass all of them.
        let marker_key = format!("validator_register:{}", hex::encode(&tx.from));
        if state
            .get_storage(&SYSTEM_ADDRESS, marker_key.as_bytes())
            .filter(|b| !b.is_empty())
            .is_none()
        {
            return Err(VmError::InvalidTransaction(format!(
                "{} is not a registered validator; use RegisterValidator",
                hex::encode(&tx.from)
            )));
        }

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_INCREASE_VALIDATOR_STAKE as u128);
        let total_debit = gas_cost.saturating_add(additional);
        let balance = state.get_balance(&tx.from);
        if balance < total_debit {
            return Err(VmError::InsufficientBalance {
                required: total_debit,
                available: balance,
            });
        }
        let new_balance = balance.saturating_sub(total_debit);
        state.set_balance(&tx.from, new_balance);

        // Into the staking vault, so the replicated vault balance stays the sum
        // of every live bond — the same invariant governance quorum divides by.
        let old_vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        let new_vault = old_vault
            .checked_add(additional)
            .ok_or_else(|| VmError::Internal("staking vault overflow".to_string()))?;
        state.set_balance(&STAKING_VAULT_ADDRESS, new_vault);

        let bond_key = format!("staking_bond:{}", hex::encode(&tx.from));
        let prior_bond = staking::bonded_stake_of(state, &tx.from);
        staking::add_bond(state, &tx.from, additional, deterministic_now_ms(tx))?;
        let new_bond = staking::bonded_stake_of(state, &tx.from);

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut log_data = Vec::with_capacity(32 + 16 + 16);
        log_data.extend_from_slice(&tx.from);
        log_data.extend_from_slice(&additional.to_le_bytes());
        log_data.extend_from_slice(&new_bond.to_le_bytes());

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            new_bond.to_le_bytes().to_vec(),
            vec![Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![b"ValidatorStakeIncreased".to_vec()],
                log_data,
            )],
            vec![
                StateChange::new(
                    tx.from.clone(),
                    b"balance".to_vec(),
                    Some(balance.to_le_bytes().to_vec()),
                    Some(new_balance.to_le_bytes().to_vec()),
                ),
                StateChange::new(
                    STAKING_VAULT_ADDRESS.to_vec(),
                    b"balance".to_vec(),
                    Some(old_vault.to_le_bytes().to_vec()),
                    Some(new_vault.to_le_bytes().to_vec()),
                ),
                StateChange::new(
                    SYSTEM_ADDRESS.to_vec(),
                    bond_key.into_bytes(),
                    Some(prior_bond.to_le_bytes().to_vec()),
                    Some(new_bond.to_le_bytes().to_vec()),
                ),
            ],
        ))
    }

    async fn execute_validator_register(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VALIDATOR_REGISTER)?;

        // While admission needs approval, only an account an enacted
        // ApproveValidators proposal named may register; one already
        // registered (a genesis validator, or one re-registering) is not held
        // back.
        if network_param(state, VALIDATOR_ADMISSION_APPROVAL_PARAM) != 0
            && !validator_approved(state, &tx.from)
            && state
                .get_storage(
                    &SYSTEM_ADDRESS,
                    format!("validator_register:{}", hex::encode(&tx.from)).as_bytes(),
                )
                .filter(|b| !b.is_empty())
                .is_none()
        {
            return Err(VmError::InvalidTransaction(format!(
                "{} is not approved to register as a validator; admission needs an enacted ApproveValidators proposal",
                hex::encode(&tx.from)
            )));
        }

        let payload: ValidatorRegisterPayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid ValidatorRegister payload: {}", e))
            })?;

        // The consensus key is admitted only with proof that the registrant
        // holds it: a composite signature by that key over this validator's
        // address, both key legs and its node key, and the node key's own
        // signature over the same. Without them anyone could register
        // someone else's key and have its signatures counted for them.
        let key = tenzro_consensus::ValidatorPublicKey::new(
            payload.ml_dsa_pubkey.clone(),
            payload.p256_pubkey.clone(),
        )
        .map_err(|e| VmError::InvalidTransaction(format!("consensus key: {e}")))?;
        if !staking::scheme_admitted(state, key.scheme()) {
            return Err(VmError::InvalidTransaction(format!(
                "consensus key: governance does not admit keys of scheme {:?}",
                key.scheme()
            )));
        }
        tenzro_consensus::validator_key::verify_registration(
            &tx.from,
            &key,
            &payload.node_key,
            &payload.proof_of_possession,
        )
        .map_err(|e| {
            VmError::InvalidTransaction(format!("consensus key proof of possession: {e}"))
        })?;
        tenzro_consensus::validator_key::verify_node_key_registration(
            &tx.from,
            &key,
            &payload.node_key,
            &payload.node_key_proof,
        )
        .map_err(|e| VmError::InvalidTransaction(format!("node key proof of possession: {e}")))?;
        tenzro_consensus::validator_key::verify_vrf_key_registration(
            &tx.from,
            &key,
            &payload.node_key,
            &payload.vrf_key,
            &payload.vrf_key_proof,
        )
        .map_err(|e| VmError::InvalidTransaction(format!("VRF key proof of possession: {e}")))?;
        // One consensus key answers with one bond. A key already registered
        // by another account stays with that account: registering it again
        // elsewhere would point equivocation evidence against the key at the
        // new account's bond, and seat two validators on one key.
        if staking::account_of_consensus_key(state, &key.fingerprint())
            .is_some_and(|owner| owner != tx.from)
        {
            return Err(VmError::InvalidTransaction(
                "consensus key is already registered by another account".to_string(),
            ));
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
        staking::add_bond(state, &tx.from, stake, deterministic_now_ms(tx))?;

        // Persist a marker for re-org replay & audit. Body is the JSON
        // payload — the registry hydrates from this if it ever needs to.
        let marker_key = format!("validator_register:{}", hex::encode(&tx.from));
        let marker_blob = tx.data[4..].to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), marker_blob.clone());
        staking::index_consensus_key(state, &key.fingerprint(), &tx.from);
        staking::index_vrf_key(state, &tx.from, &payload.vrf_key);

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        // Log layout: `from(32) || stake_le(16) || node_key(32) ||
        //              p256_pubkey(65) || ml_dsa_pubkey_len_le(4) || ml_dsa_pubkey ||
        //              withdrawal(32) || metadata_uri_len_le(4) || metadata_uri`
        let mut log_data = Vec::with_capacity(
            32 + 16
                + 32
                + 65
                + 4
                + payload.ml_dsa_pubkey.len()
                + 32
                + 4
                + payload.metadata_uri.len(),
        );
        log_data.extend_from_slice(&tx.from);
        log_data.extend_from_slice(&payload.self_stake.to_le_bytes());
        log_data.extend_from_slice(&payload.node_key);
        log_data.extend_from_slice(&payload.p256_pubkey);
        log_data.extend_from_slice(&(payload.ml_dsa_pubkey.len() as u32).to_le_bytes());
        log_data.extend_from_slice(&payload.ml_dsa_pubkey);
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
                format!("staking_bond:{}", hex::encode(&tx.from)).into_bytes(),
                None,
                Some(
                    staking::bonded_stake_of(state, &tx.from)
                        .to_le_bytes()
                        .to_vec(),
                ),
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

    /// Records proof that one consensus key signed two different checkpoints
    /// with the same index on this chain.
    ///
    /// Payload: the bincode-encoded `tenzro_consensus::CheckpointEquivocation`.
    /// Both signatures are verified here, so the log every node replays is
    /// proof, not an accusation. One offence is recorded once: the marker is
    /// keyed by the key's fingerprint, the epoch and the index.
    ///
    /// Log layout: `epoch_be(8) || index_be(8) || p256_pubkey(65) ||
    /// ml_dsa_pubkey`.
    fn execute_checkpoint_equivocation(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_CHECKPOINT_EQUIVOCATION)?;
        let evidence: tenzro_consensus::CheckpointEquivocation =
            bincode::deserialize(&tx.data[4..])
                .map_err(|e| VmError::InvalidTransaction(format!("equivocation evidence: {e}")))?;
        if !evidence.is_valid(tx.chain_id) {
            return Err(VmError::InvalidTransaction(
                "equivocation evidence does not prove two signed checkpoints".to_string(),
            ));
        }
        let (epoch, index) = (evidence.first.epoch, evidence.first.index);
        let marker_key = format!(
            "checkpoint_equivocation:{}:{epoch}:{index}",
            hex::encode(evidence.public_key.fingerprint())
        );
        if state
            .get_storage(&SYSTEM_ADDRESS, marker_key.as_bytes())
            .is_some_and(|m| !m.is_empty())
        {
            return Err(VmError::InvalidTransaction(
                "this equivocation is already recorded".to_string(),
            ));
        }
        let (bal, new_bal) = self.charge_gas(tx, state, GAS_CHECKPOINT_EQUIVOCATION)?;
        state.set_storage(&SYSTEM_ADDRESS, marker_key.as_bytes(), b"recorded".to_vec());
        // Every validator key, genesis or registered, indexes the bond it
        // answers with; the slash goes to the insurance pool.
        let mut slash_changes = Vec::new();
        if let Some(account) =
            staking::account_of_consensus_key(state, &evidence.public_key.fingerprint())
        {
            staking::slash_for_equivocation(state, &account, index, &mut slash_changes)?;
        }
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut log_data = Vec::with_capacity(16 + 65 + evidence.public_key.ml_dsa.len());
        log_data.extend_from_slice(&epoch.to_be_bytes());
        log_data.extend_from_slice(&index.to_be_bytes());
        log_data.extend_from_slice(&evidence.public_key.p256);
        log_data.extend_from_slice(&evidence.public_key.ml_dsa);
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"CheckpointEquivocation".to_vec()],
            log_data,
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
                Some(b"recorded".to_vec()),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];
        state_changes.extend(slash_changes);
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            state_changes,
        ))
    }

    /// Records the signers of a certified checkpoint: the epoch's vote tally
    /// and the vote work the next block pays (see
    /// [`rewards::record_checkpoint_signers`]).
    ///
    /// Payload: the JSON [`rewards::CheckpointSigners`] the node derived from
    /// a certificate it verified against the epoch's committee.
    ///
    /// Log layout: `epoch_be(8) || index_be(8) || signer_count_be(4)`.
    fn execute_checkpoint_signers(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_CHECKPOINT_SIGNERS)?;
        // Certificates are recorded by validators. The node verifies each
        // against the committee of its epoch before the block executes; the
        // VM also refuses a record from an account with no bond, so no other
        // account can present a signers list as recorded.
        if staking::bonded_stake_of(state, &tx.from) == 0 {
            return Err(VmError::InvalidTransaction(
                "checkpoint signers are recorded only by a bonded validator".to_string(),
            ));
        }
        let record: rewards::CheckpointSigners = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("checkpoint signers: {e}")))?;
        // The record pays no fee (see [`pays_no_fee`]): what the validator
        // can spend never decides whether its vote work is recorded.
        let mut state_changes = rewards::record_checkpoint_signers(state, &record)?;
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut log_data = Vec::with_capacity(20);
        log_data.extend_from_slice(&record.epoch.to_be_bytes());
        log_data.extend_from_slice(&record.index.to_be_bytes());
        log_data.extend_from_slice(&(record.signers.len() as u32).to_be_bytes());
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"CheckpointSigners".to_vec()],
            log_data,
        );
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
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
    /// Apply `(changes, logs)` a native module computed: charge `gas` and
    /// bump the sender's nonce.
    fn settle_native(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
        gas: u64,
        mut state_changes: Vec<StateChange>,
        logs: Vec<Log>,
    ) -> Result<ExecutionResult> {
        let (bal, new_bal) = self.charge_gas(tx, state, gas)?;
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(bal.to_le_bytes().to_vec()),
            Some(new_bal.to_le_bytes().to_vec()),
        ));
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            logs,
            state_changes,
        ))
    }

    /// Handle a `LiftAgentQuarantine`: the controller lifting a quarantine.
    fn execute_lift_agent_quarantine(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_LIFT_AGENT_QUARANTINE)?;
        let (changes, logs) = agent_audit::lift(state, &tx.from, &tx.data[4..])?;
        self.settle_native(
            tx,
            state,
            gas_meter,
            GAS_LIFT_AGENT_QUARANTINE,
            changes,
            logs,
        )
    }

    /// Handle a `RevokeDelegatedAgent`: the controller revoking an agent.
    fn execute_revoke_delegated_agent(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_REVOKE_DELEGATED_AGENT)?;
        let (changes, logs) =
            agent_audit::revoke(state, &tx.from, &tx.data[4..], deterministic_now_ms(tx))?;
        self.settle_native(
            tx,
            state,
            gas_meter,
            GAS_REVOKE_DELEGATED_AGENT,
            changes,
            logs,
        )
    }

    /// Handle a `ReclaimAgentFunds`: the agent's controller, from the wallet
    /// its identity is registered with, moves TNZO out of the agent's wallet
    /// to that wallet: all of it, or `amount`. The wallet has no key, so this
    /// is the only way back for what an agent was funded with and did not
    /// spend; it works whatever the agent's state (paused, quarantined,
    /// revoked), since the controller answers for the agent throughout.
    fn execute_reclaim_agent_funds(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        #[derive(serde::Deserialize)]
        struct Payload {
            agent_did: String,
            controller_did: String,
            #[serde(default)]
            amount: Option<String>,
        }
        gas_meter.consume(GAS_RECLAIM_AGENT_FUNDS)?;
        let p: Payload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid ReclaimAgentFunds payload: {e}"))
        })?;
        require_agent_controller(state, &tx.from, &p.agent_did, &p.controller_did)?;
        let wallet = tenzro_types::agent_terms::agent_wallet(&p.agent_did);
        let held = state.get_balance(&wallet);
        let amount = match p.amount.as_deref() {
            None => held,
            Some(a) => a.parse::<u128>().map_err(|_| {
                VmError::InvalidTransaction("amount must be a whole number of wei".to_string())
            })?,
        };
        if amount == 0 || amount > held {
            return Err(VmError::InvalidTransaction(format!(
                "{} holds {held} wei; cannot reclaim {amount}",
                p.agent_did
            )));
        }
        let to_before = state.get_balance(&tx.from);
        state.set_balance(&wallet, held - amount);
        state.set_balance(&tx.from, to_before.saturating_add(amount));
        let changes = vec![
            StateChange::new(
                wallet.to_vec(),
                b"balance".to_vec(),
                Some(held.to_le_bytes().to_vec()),
                Some((held - amount).to_le_bytes().to_vec()),
            ),
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(to_before.to_le_bytes().to_vec()),
                Some(to_before.saturating_add(amount).to_le_bytes().to_vec()),
            ),
        ];
        let log_data = serde_json::to_vec(&serde_json::json!({
            "agent_did": p.agent_did,
            "controller_did": p.controller_did,
            "to": hex::encode(&tx.from),
            "amount": amount.to_string(),
        }))
        .map_err(|e| VmError::Internal(format!("encode reclaim log: {e}")))?;
        let logs = vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"AgentFundsReclaimed".to_vec()],
            log_data,
        )];
        self.settle_native(tx, state, gas_meter, GAS_RECLAIM_AGENT_FUNDS, changes, logs)
    }

    /// Handle a `SetAgentTopUp`: the agent's controller, from the wallet its
    /// identity is registered with, approves refills of the agent's wallet
    /// from that wallet within an allowance, or cancels them.
    fn execute_set_agent_topup(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        #[derive(serde::Deserialize)]
        struct Allowance {
            #[serde(with = "tenzro_types::primitives::u128_serde")]
            per_period: u128,
            period_ms: u64,
            #[serde(with = "tenzro_types::primitives::u128_serde")]
            target: u128,
            expires_at_ms: i64,
        }
        #[derive(serde::Deserialize)]
        struct Payload {
            agent_did: String,
            controller_did: String,
            #[serde(default)]
            allowance: Option<Allowance>,
        }
        gas_meter.consume(GAS_SET_AGENT_TOPUP)?;
        let p: Payload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid SetAgentTopUp payload: {e}"))
        })?;
        require_agent_controller(state, &tx.from, &p.agent_did, &p.controller_did)?;
        let mut changes = Vec::new();
        let key = agent_topup_key(&p.agent_did);
        let record = match p.allowance {
            None => {
                funding::delete_record(state, &key, &mut changes);
                None
            }
            Some(a) => {
                if a.per_period == 0 || a.period_ms == 0 || a.target == 0 {
                    return Err(VmError::InvalidTransaction(
                        "a top-up allowance needs a period, an amount per period and a target"
                            .to_string(),
                    ));
                }
                let now = deterministic_now_ms(tx);
                let latest = now.saturating_add(
                    (network_param(state, AGENT_TOPUP_MAX_DAYS_PARAM) as i64)
                        .saturating_mul(86_400_000),
                );
                if a.expires_at_ms <= now || a.expires_at_ms > latest {
                    return Err(VmError::InvalidTransaction(format!(
                        "a top-up allowance must expire after now and by {latest} ms"
                    )));
                }
                let record = AgentTopUp {
                    from: hex::encode(&tx.from),
                    per_period: a.per_period,
                    period_ms: a.period_ms,
                    target: a.target,
                    expires_at_ms: a.expires_at_ms,
                };
                funding::write_json(state, &key, &record, &mut changes)?;
                Some(record)
            }
        };
        let log_data = serde_json::to_vec(&serde_json::json!({
            "agent_did": p.agent_did,
            "controller_did": p.controller_did,
            "allowance": record,
        }))
        .map_err(|e| VmError::Internal(format!("encode top-up log: {e}")))?;
        let logs = vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"AgentTopUpSet".to_vec()],
            log_data,
        )];
        self.settle_native(tx, state, gas_meter, GAS_SET_AGENT_TOPUP, changes, logs)
    }

    /// Handle a `TopUpAgent`: anyone (a harness, an app, a relayer) refills
    /// an agent's wallet from its controller's, up to the allowance's target
    /// and within what this period has left. A paused, quarantined or
    /// revoked agent is not refilled.
    fn execute_topup_agent(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        #[derive(serde::Deserialize)]
        struct Payload {
            agent_did: String,
        }
        gas_meter.consume(GAS_TOPUP_AGENT)?;
        let p: Payload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid TopUpAgent payload: {e}")))?;
        let now = deterministic_now_ms(tx);
        let allowance = read_agent_topup(state, &p.agent_did).ok_or_else(|| {
            VmError::InvalidTransaction(format!("{} has no top-up allowance", p.agent_did))
        })?;
        if now > allowance.expires_at_ms {
            return Err(VmError::InvalidTransaction(format!(
                "{}'s top-up allowance has expired",
                p.agent_did
            )));
        }
        agent_terms::check_agent_status(state, &p.agent_did, now.max(0) as u64)
            .map_err(VmError::InvalidTransaction)?;
        let from = hex::decode(&allowance.from)
            .map_err(|_| VmError::Internal("top-up source is not hex".to_string()))?;
        let wallet = tenzro_types::agent_terms::agent_wallet(&p.agent_did);
        let period = (now.max(0) as u64) / allowance.period_ms;
        let used_key = agent_topup_used_key(&p.agent_did);
        let used: u128 = match funding::read_json::<(u64, String)>(state, &used_key) {
            Some((at, u)) if at == period => u.parse().unwrap_or(0),
            _ => 0,
        };
        let held = state.get_balance(&wallet);
        let source = state.get_balance(&from);
        let amount = allowance
            .target
            .saturating_sub(held)
            .min(allowance.per_period.saturating_sub(used))
            .min(source);
        if amount == 0 {
            return Err(VmError::InvalidTransaction(format!(
                "{} needs no refill or its allowance for this period is used",
                p.agent_did
            )));
        }
        state.set_balance(&from, source - amount);
        state.set_balance(&wallet, held + amount);
        let mut changes = vec![
            StateChange::new(
                from.clone(),
                b"balance".to_vec(),
                Some(source.to_le_bytes().to_vec()),
                Some((source - amount).to_le_bytes().to_vec()),
            ),
            StateChange::new(
                wallet.to_vec(),
                b"balance".to_vec(),
                Some(held.to_le_bytes().to_vec()),
                Some((held + amount).to_le_bytes().to_vec()),
            ),
        ];
        funding::write_json(
            state,
            &used_key,
            &(period, (used + amount).to_string()),
            &mut changes,
        )?;
        let log_data = serde_json::to_vec(&serde_json::json!({
            "agent_did": p.agent_did,
            "from": allowance.from,
            "amount": amount.to_string(),
        }))
        .map_err(|e| VmError::Internal(format!("encode top-up log: {e}")))?;
        let logs = vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"AgentToppedUp".to_vec()],
            log_data,
        )];
        self.settle_native(tx, state, gas_meter, GAS_TOPUP_AGENT, changes, logs)
    }

    /// Handle a `SetAgentTerms`: a controller's approved terms.
    fn execute_set_agent_terms(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        #[derive(serde::Deserialize)]
        struct Payload {
            terms: tenzro_types::agent_terms::AgentTerms,
            rotate: Option<bool>,
            approval: tenzro_types::agent_terms::AgentTermsApproval,
        }
        gas_meter.consume(GAS_SET_AGENT_TERMS)?;
        let p: Payload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid SetAgentTerms payload: {e}"))
        })?;
        let (changes, logs) = agent_terms::set_terms(
            state,
            &p.terms,
            p.rotate,
            &p.approval,
            deterministic_now_ms(tx),
        )?;
        self.settle_native(tx, state, gas_meter, GAS_SET_AGENT_TERMS, changes, logs)
    }

    /// Handle an `AgentAct`: one action by a delegated agent.
    fn execute_agent_act(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_AGENT_ACT)?;
        let (action, signature) = agent_terms::decode_act(&tx.data[4..])?;
        let (changes, logs, burned) = agent_terms::act(
            state,
            tx.chain_id,
            &action,
            &signature,
            deterministic_now_ms(tx),
        )?;
        // What the action's settlements burned leaves supply; declared here,
        // or the block's value check reverts the action.
        self.settle_native(tx, state, gas_meter, GAS_AGENT_ACT, changes, logs)
            .map(|r| r.with_burn(burned))
    }

    /// Handle a `Payment` operation: a delivery receipt on a payment's
    /// record, or a payment proven on another chain or attested on another
    /// rail.
    fn execute_payment_op(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(payment_settlement::GAS_PAYMENT_OP)?;
        let op: tenzro_types::settlement::PaymentOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| VmError::InvalidTransaction(format!("Invalid Payment payload: {e}")))?;
        let mut changes = Vec::new();
        let now = deterministic_now_ms(tx);
        let log = payment_settlement::apply_payment_op(
            state,
            tx.chain_id,
            now,
            &tx.from,
            &op,
            &mut changes,
        )?;
        self.settle_native(
            tx,
            state,
            gas_meter,
            payment_settlement::GAS_PAYMENT_OP,
            changes,
            vec![log],
        )
    }

    /// Handle a `RemoteGrantSettle`: one agent account report a relayer
    /// delivers through the chain's route.
    fn execute_remote_grant_settle(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_REMOTE_GRANT_SETTLE)?;
        let payload: remote_grant::SettlePayload =
            serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                VmError::InvalidTransaction(format!("Invalid RemoteGrantSettle payload: {e}"))
            })?;
        let (changes, logs) =
            remote_grant::settle(state, tx.chain_id, deterministic_now_ms(tx), &payload)?;
        self.settle_native(tx, state, gas_meter, GAS_REMOTE_GRANT_SETTLE, changes, logs)
    }

    /// Handle an `AgentAuditFlag`: one validator's findings for an epoch.
    fn execute_agent_audit_flag(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let payload = &tx.data[4..];
        let gas = agent_audit::flag_gas(payload)?;
        gas_meter.consume(gas)?;
        let (changes, logs) =
            agent_audit::flag(state, &tx.from, deterministic_now_ms(tx), payload)?;
        self.settle_native(tx, state, gas_meter, gas, changes, logs)
    }

    /// Handle a `FeeRateSubmit`: one validator's per-symbol USD rate
    /// report for a closed epoch.
    fn execute_fee_rate_submit(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(economy::GAS_FEE_RATE_SUBMIT)?;
        let (changes, logs) =
            economy::submit_rate(state, &tx.from, &tx.data[4..], deterministic_now_ms(tx))?;
        self.settle_native(
            tx,
            state,
            gas_meter,
            economy::GAS_FEE_RATE_SUBMIT,
            changes,
            logs,
        )
    }

    /// Handle an `AgentAuditCommit`: one node's audit root for an epoch.
    fn execute_agent_audit_commit(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_AGENT_AUDIT_COMMIT)?;
        let (mut state_changes, logs) =
            agent_audit::commit(state, &tx.from, deterministic_now_ms(tx), &tx.data[4..])?;
        let (bal, new_bal) = self.charge_gas(tx, state, GAS_AGENT_AUDIT_COMMIT)?;
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(bal.to_le_bytes().to_vec()),
            Some(new_bal.to_le_bytes().to_vec()),
        ));
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            logs,
            state_changes,
        ))
    }

    /// Run an operation that writes system state: consume `gas`, apply it at
    /// the block time, charge the sender and advance its nonce.
    fn execute_system_op(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
        gas: u64,
        op: impl FnOnce(&mut dyn VmState, &VmTransaction, i64) -> Result<(Vec<StateChange>, Vec<Log>)>,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(gas)?;
        let (mut state_changes, logs) = op(state, tx, deterministic_now_ms(tx))?;
        let (bal, new_bal) = self.charge_gas(tx, state, gas)?;
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(bal.to_le_bytes().to_vec()),
            Some(new_bal.to_le_bytes().to_vec()),
        ));
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            logs,
            state_changes,
        ))
    }

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

    /// `RegisterIdentity` — land a DID + its public record into consensus
    /// state. The
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

        // The DID must provably belong to the controller key it binds, the
        // class must be the one the DID names, and the submitter must hold
        // that key. Derivation alone would let anyone who has read a public
        // key register its owner's DID first and choose the wallet the record
        // pays to.
        let controller_xy = match payload.controller_pubkey.as_slice() {
            [0x04, xy @ ..] if xy.len() == 64 => xy,
            other => other,
        };
        let enrolled_pq = crate::account_keys::enrolled_pq_key(&*state, controller_xy);
        if !tenzro_tee::identity_evidence::registration_is_authorized(
            &payload,
            enrolled_pq.as_deref(),
        ) {
            return Err(VmError::InvalidTransaction(format!(
                "identity DID '{}' is not authorized by its controller key",
                payload.did
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
            // A re-registration by the same controller refreshes the record:
            // the proof verified above is that controller's own signature over
            // every field being written, so the overwrite is authorized.
        }

        // Canonical blob = the exact JSON body the submitter signed over, so
        // the stored record and the emitted log are byte-identical on every
        // node (no re-serialization drift).
        let blob = tx.data[4..].to_vec();

        let (bal, new_bal) = self.charge_gas(tx, state, GAS_IDENTITY_REGISTER)?;
        state.set_storage(&SYSTEM_ADDRESS, &key, blob.clone());

        // Index the identity by its wallet address as well as by its DID.
        //
        // The DID-keyed record answers "who is this DID?". Nothing could ask
        // the reverse — "does this address belong to anyone?" — because
        // `VmState` has point lookups only and no way to scan for a record
        // whose `wallet_address` matches. That question is the one a treasury
        // grant has to ask before paying an address, since paying one with no
        // identity behind it creates precisely what the network forbids: a
        // funded wallet nobody answers for. Writing the reverse edge here is
        // what makes it answerable in a single lookup.
        let wallet_index_key = identity_wallet_index_key(payload.wallet_address.as_bytes());
        let prior_wallet_index = state.get_storage(&SYSTEM_ADDRESS, wallet_index_key.as_bytes());
        // An address already indexed to another identity is not reassigned:
        // otherwise a registration could claim someone else's wallet.
        if prior_wallet_index
            .as_ref()
            .is_some_and(|p| !p.is_empty() && p.as_slice() != payload.did.as_bytes())
        {
            return Err(VmError::InvalidTransaction(format!(
                "wallet address is already bound to another identity (registering '{}')",
                payload.did
            )));
        }
        let wallet_index_value = payload.did.as_bytes().to_vec();
        state.set_storage(
            &SYSTEM_ADDRESS,
            wallet_index_key.as_bytes(),
            wallet_index_value.clone(),
        );

        // The ML-DSA-65 key the proof's leg verified against becomes the key
        // enrolled for the controller, so every later approval by it must
        // carry both legs.
        let mut enrolment_changes = Vec::new();
        let mut enrolment_log = None;
        if let Some(pq) = tenzro_tee::identity_evidence::registration_enrolled_pq_key(
            &payload,
            enrolled_pq.as_deref(),
        ) {
            crate::account_keys::set_enrolled_pq_key(
                state,
                controller_xy,
                pq.to_vec(),
                &mut enrolment_changes,
            );
            enrolment_log = Some(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![
                    crate::account_keys::PQ_KEY_ENROLLED_TOPIC.to_vec(),
                    tenzro_crypto::composite::account_slot(controller_xy).to_vec(),
                ],
                pq.to_vec(),
            ));
        }

        // The account's genesis in consensus time: written once, at first
        // registration, and never moved by a re-registration. It is what an
        // identity's age is measured from.
        let registered_at_key = identity_registered_at_key(&payload.did);
        let registered_at = if existing.as_ref().is_some_and(|b| !b.is_empty()) {
            None
        } else {
            let at = deterministic_now_ms(tx).to_le_bytes().to_vec();
            state.set_storage(&SYSTEM_ADDRESS, registered_at_key.as_bytes(), at.clone());
            Some(at)
        };

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"IdentityRegister".to_vec()],
            blob.clone(),
        );
        let mut changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(bal.to_le_bytes().to_vec()),
                Some(new_bal.to_le_bytes().to_vec()),
            ),
            StateChange::new(SYSTEM_ADDRESS.to_vec(), key, existing, Some(blob)),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                wallet_index_key.into_bytes(),
                prior_wallet_index,
                Some(wallet_index_value),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];
        machine_attestation::note_registered_tpm(state, &payload, &mut changes)?;
        if let Some(at) = registered_at {
            changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                registered_at_key.into_bytes(),
                None,
                Some(at),
            ));
        }
        changes.extend(enrolment_changes);
        let logs = std::iter::once(log).chain(enrolment_log).collect();
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            logs,
            changes,
        ))
    }

    async fn execute_validator_exit(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VALIDATOR_EXIT)?;
        // Without a payload the sender is the validator. With a 32-byte
        // payload the sender is the withdrawal address the named validator
        // registered, exiting for it when its hardware can no longer sign;
        // the bond is then paid to that address.
        let (validator, payee) = match tx.data.len() {
            4 => (tx.from.to_vec(), tx.from.to_vec()),
            36 => {
                let validator = tx.data[4..36].to_vec();
                let withdrawal =
                    registered_withdrawal_address(state, &validator).ok_or_else(|| {
                        VmError::InvalidTransaction(format!(
                            "{} is not a registered validator",
                            hex::encode(&validator)
                        ))
                    })?;
                if withdrawal != tx.from {
                    return Err(VmError::InvalidTransaction(
                        "only the validator or its registered withdrawal address may exit it"
                            .to_string(),
                    ));
                }
                (validator, withdrawal)
            }
            n => {
                return Err(VmError::InvalidTransaction(format!(
                    "ValidatorExit takes no payload or a 32-byte validator account, got {} bytes",
                    n - 4
                )));
            }
        };

        let gas_cost = tx.gas_price.saturating_mul(GAS_VALIDATOR_EXIT as u128);
        let bal = state.get_balance(&tx.from);
        if bal < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            });
        }
        let now_ms = deterministic_now_ms(tx);

        // Exit is two steps under the one transaction type. The first moves
        // the bond into unbonding: it stops counting as stake at once, but
        // stays in the vault, where a slash can still reach it, for
        // the governed unbonding period. The second, after that period, pays it
        // out of the vault.
        // A sponsored part of the bond is never paid to the validator: it
        // returns to the treasury with the withdrawal.
        let mut sponsored_returned = 0u128;
        let (step, amount) = match staking::begin_unbonding(state, &validator, now_ms)? {
            Some(unbonding) => ("unbonding", unbonding.amount),
            None => {
                let (paid, returned) =
                    staking::withdraw_unbonded_split(state, &validator, &payee, now_ms)?;
                sponsored_returned = returned;
                ("withdrawn", paid)
            }
        };

        // Gas, read after any refund so a payout and the fee net correctly.
        let bal = state.get_balance(&tx.from);
        let new_bal = bal
            .checked_sub(gas_cost)
            .ok_or(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            })?;
        state.set_balance(&tx.from, new_bal);

        let marker_key = format!("validator_exit:{}", hex::encode(&validator));
        state.set_storage(
            &SYSTEM_ADDRESS,
            marker_key.as_bytes(),
            step.as_bytes().to_vec(),
        );

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);

        let mut data = validator.clone();
        data.extend_from_slice(&amount.to_le_bytes());
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"ValidatorExit".to_vec(), step.as_bytes().to_vec()],
            data,
        );
        let mut logs = vec![log];
        if sponsored_returned > 0 {
            logs.push(sponsored_bond::returned_log(
                state,
                &validator,
                sponsored_returned,
            ));
        }

        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            logs,
            Vec::new(),
        ))
    }

    /// Replaces the sender's consensus key from the next epoch boundary:
    /// the new key must prove possession over the registration message for
    /// the sender and its registered node key, be of a scheme governance
    /// admits, and be registered to no one. The old key stays indexed to the
    /// sender, so evidence against it still reaches the bond.
    async fn execute_validator_rotate_key(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_VALIDATOR_ROTATE_KEY)?;
        #[derive(serde::Deserialize)]
        struct Rotation {
            ml_dsa_pubkey: Vec<u8>,
            p256_pubkey: Vec<u8>,
            proof_of_possession: Vec<u8>,
        }
        let refuse = |m: String| VmError::InvalidTransaction(format!("ValidatorRotateKey: {m}"));
        let rotation: Rotation = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("invalid payload: {e}")))?;
        let marker_key = format!("validator_register:{}", hex::encode(&tx.from));
        let marker = state
            .get_storage(&SYSTEM_ADDRESS, marker_key.as_bytes())
            .filter(|b| !b.is_empty())
            .ok_or_else(|| refuse("the sender is not a registered validator".into()))?;
        let registered: ValidatorRegisterPayload = serde_json::from_slice(&marker)
            .map_err(|e| refuse(format!("registration record: {e}")))?;
        if staking::bonded_stake_of(state, &tx.from) == 0 {
            return Err(refuse("the sender has no bond".into()));
        }
        let key = tenzro_consensus::ValidatorPublicKey::new(
            rotation.ml_dsa_pubkey.clone(),
            rotation.p256_pubkey.clone(),
        )
        .map_err(|e| refuse(format!("consensus key: {e}")))?;
        if !staking::scheme_admitted(state, key.scheme()) {
            return Err(refuse(format!(
                "governance does not admit keys of scheme {:?}",
                key.scheme()
            )));
        }
        if staking::account_of_consensus_key(state, &key.fingerprint()).is_some() {
            return Err(refuse("the key is already registered".into()));
        }
        tenzro_consensus::validator_key::verify_registration(
            &tx.from,
            &key,
            &registered.node_key,
            &rotation.proof_of_possession,
        )
        .map_err(|e| refuse(format!("proof of possession: {e}")))?;

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_VALIDATOR_ROTATE_KEY as u128);
        let bal = state.get_balance(&tx.from);
        let new_bal = bal
            .checked_sub(gas_cost)
            .ok_or(VmError::InsufficientBalance {
                required: gas_cost,
                available: bal,
            })?;
        state.set_balance(&tx.from, new_bal);
        staking::index_consensus_key(state, &key.fingerprint(), &tx.from);
        // The registration record names the key in force, so a registry
        // rebuilt from it seats the new one.
        let mut record: serde_json::Value = serde_json::from_slice(&marker)
            .map_err(|e| refuse(format!("registration record: {e}")))?;
        record["ml_dsa_pubkey"] = serde_json::json!(rotation.ml_dsa_pubkey);
        record["p256_pubkey"] = serde_json::json!(rotation.p256_pubkey);
        state.set_storage(
            &SYSTEM_ADDRESS,
            marker_key.as_bytes(),
            serde_json::to_vec(&record).map_err(|e| refuse(format!("record: {e}")))?,
        );
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![VALIDATOR_KEY_ROTATION_TOPIC.to_vec()],
            validator_key_rotation_log(&tx.from, &rotation.ml_dsa_pubkey, &rotation.p256_pubkey),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            tx.from.to_vec(),
            vec![log],
            Vec::new(),
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
}

// ---- Free helpers for escrow handlers ---------------------------------------

/// JSON payload decoded from `tx.data[4..]` for `CreateEscrow`.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct CreateEscrowPayload {
    pub(crate) payee: Address,
    pub(crate) amount: u128,
    pub(crate) asset_id: AssetId,
    #[serde(default)]
    pub(crate) usd_e6: u64,
    pub(crate) expires_at: u64,
    pub(crate) release_conditions: ReleaseConditions,
    #[serde(default, with = "tenzro_types::settlement::opt_hex32")]
    pub(crate) reference: Option<[u8; 32]>,
}

/// JSON payload decoded from `tx.data[4..]` for `ReleaseEscrow`.
#[derive(Debug, Clone, serde::Deserialize)]
struct ReleaseEscrowPayload {
    escrow_id: [u8; 32],
    proof: ServiceProof,
}

/// Check a committee attestation releasing `escrow_id` under `claim`.
///
/// `proof.proof_data` is the evidence the members checked. Each entry of
/// `proof.signatures` names a member by its 20-byte address in the first 20
/// bytes of `signer` (the rest zero) and carries a 65-byte `r || s || v`
/// secp256k1 signature over [`quorum_release_digest`]. A signature counts
/// only if it recovers to the member it names; each member counts once.
fn verify_quorum_release(
    escrow_id: &[u8; 32],
    claim: &str,
    verifiers: &tenzro_types::bridge_route::VerifierQuorum,
    proof: &ServiceProof,
) -> Result<()> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::Keccak256;

    verifiers.validate("release verifiers").map_err(|e| {
        VmError::InvalidTransaction(format!("quorum release committee refused: {e}"))
    })?;
    let digest = quorum_release_digest(escrow_id, claim, &proof.proof_data);
    let members: std::collections::HashSet<[u8; 20]> =
        verifiers.members.iter().map(|m| m.address).collect();
    let mut counted = std::collections::HashSet::new();
    for entry in &proof.signatures {
        let signer = entry.signer.as_bytes();
        if signer[20..].iter().any(|b| *b != 0) || entry.signature.len() != 65 {
            continue;
        }
        let mut named = [0u8; 20];
        named.copy_from_slice(&signer[..20]);
        if !members.contains(&named) || counted.contains(&named) {
            continue;
        }
        let Ok(sig) = Signature::from_slice(&entry.signature[..64]) else {
            continue;
        };
        let v = entry.signature[64];
        let Some(rec) = RecoveryId::from_byte(if v >= 27 { v - 27 } else { v }) else {
            continue;
        };
        let Ok(key) = VerifyingKey::recover_from_prehash(&digest, &sig, rec) else {
            continue;
        };
        let point = key.to_sec1_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        if hash[12..] == named {
            counted.insert(named);
        }
    }
    if counted.len() < verifiers.threshold as usize {
        return Err(VmError::InvalidTransaction(format!(
            "quorum release needs {} member signatures over this escrow, got {}",
            verifiers.threshold,
            counted.len()
        )));
    }
    Ok(())
}

/// JSON payload decoded from `tx.data[4..]` for `RefundEscrow`.
#[derive(Debug, Clone, serde::Deserialize)]
struct RefundEscrowPayload {
    escrow_id: [u8; 32],
}

// ---- Validator-registry payloads (Dynamic Validator Set) -------------------

/// JSON payload decoded from `tx.data[4..]` for `RegisterValidator`.
///
/// `ml_dsa_pubkey` (1952 bytes, FIPS 204) and `p256_pubkey` (65-byte
/// uncompressed SEC1) are the two legs of the validator's hardware-held
/// composite consensus key; `node_key` is the node's Ed25519 key;
/// `proof_of_possession` is the consensus key's composite signature over the
/// registration and `node_key_proof` the node key's Ed25519 signature over
/// it. `vrf_key` is the separate key the validator's VRF proofs verify
/// under, and `vrf_key_proof` its VRF proof over the registration.
/// `withdrawal_address` is the `Address` rewards/return-of-stake settle to.
/// `metadata_uri` is an optional ≤256-byte off-chain pointer (e.g. moniker,
/// website, contact).
#[derive(Debug, Clone, serde::Deserialize)]
struct ValidatorRegisterPayload {
    ml_dsa_pubkey: Vec<u8>,
    p256_pubkey: Vec<u8>,
    node_key: [u8; 32],
    proof_of_possession: Vec<u8>,
    node_key_proof: Vec<u8>,
    vrf_key: [u8; 32],
    vrf_key_proof: Vec<u8>,
    withdrawal_address: Address,
    self_stake: u128,
    #[serde(default)]
    metadata_uri: String,
}

/// The validator account a `ValidatorExit` log names: its data is the
/// account followed by the 16-byte amount.
pub fn validator_exit_log_account(data: &[u8]) -> Option<&[u8]> {
    data.len()
        .checked_sub(16)
        .filter(|n| *n == 20 || *n == 32)
        .map(|n| &data[..n])
}

/// The data of a `ValidatorKeyRotation` log: the account's length and the
/// account, the ML-DSA leg's length (u32 LE) and the leg, then the ECDSA leg.
pub fn validator_key_rotation_log(account: &[u8], ml_dsa: &[u8], ecdsa: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(1 + account.len() + 4 + ml_dsa.len() + ecdsa.len());
    d.push(account.len() as u8);
    d.extend_from_slice(account);
    d.extend_from_slice(&(ml_dsa.len() as u32).to_le_bytes());
    d.extend_from_slice(ml_dsa);
    d.extend_from_slice(ecdsa);
    d
}

/// The account, ML-DSA leg and ECDSA leg a `ValidatorKeyRotation` log names.
pub fn decode_validator_key_rotation_log(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (&n, rest) = data.split_first()?;
    let account = rest.get(..n as usize)?;
    let rest = &rest[n as usize..];
    let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    let ml_dsa = rest.get(4..4 + len)?;
    Some((account, ml_dsa, &rest[4 + len..]))
}

/// The withdrawal address `validator` named when it registered.
fn registered_withdrawal_address(state: &dyn VmState, validator: &[u8]) -> Option<Vec<u8>> {
    let marker = format!("validator_register:{}", hex::encode(validator));
    let blob = state.get_storage(&SYSTEM_ADDRESS, marker.as_bytes())?;
    let payload: ValidatorRegisterPayload = serde_json::from_slice(&blob).ok()?;
    Some(payload.withdrawal_address.as_bytes().to_vec())
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

/// Consensus-state key a registered identity record lives under, within
/// `SYSTEM_ADDRESS` storage. The `identity:` prefix keeps the DID namespace
/// distinct from other system keys by construction, and the
/// DID is globally unique so the key doubles as the uniqueness guard.
fn identity_storage_key(did: &str) -> Vec<u8> {
    tenzro_types::identity::identity_slot(did).into_bytes()
}

/// The hardware identity key `did` registered on chain: its P-256 point, with
/// its ML-DSA-65 key when it enrolled one. Refused when the DID has no
/// identity or its key is not a hardware P-256 key.
pub(crate) fn registered_identity_key(
    state: &dyn VmState,
    did: &str,
) -> Result<tenzro_crypto::CompositePublicKey> {
    let refuse = |m: String| VmError::InvalidTransaction(m);
    let record: tenzro_types::identity::RegisterIdentityPayload = state
        .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(did))
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| refuse(format!("{did} has no identity on chain")))?;
    tenzro_consensus::eu_ai_act::registered_key(
        did,
        &record.controller_pubkey,
        &record.key_type,
        &record.pq_verifying_key,
    )
    .map_err(refuse)
}

/// Consensus-state marker that an identity has been revoked by governance.
///
/// A key beside the identity record rather than a field inside it. The record
/// is the exact JSON its submitter signed over, byte-for-byte on every node
/// (see `execute_identity_register`), so editing it here would break that
/// property for the sake of one boolean. A separate marker keeps both facts
/// intact and makes "is this revoked?" a single point lookup, which is all the
/// admission checks need.
fn identity_revocation_key(did: &str) -> Vec<u8> {
    format!("identity_revoked:{did}").into_bytes()
}

// ---- Kill-switch payloads ------------------------------

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

// ---- AgentBond payloads --------------------------------

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
/// The first call starts the cooldown; a call after it ends returns the
/// bond to its owner.
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

/// JSON payload decoded from `tx.data[4..]` for `SlaAttest`.
#[derive(Debug, Clone, serde::Deserialize)]
struct SlaAttestPayload {
    epoch: u64,
    outcomes: Vec<SlaOutcomePayload>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SlaOutcomePayload {
    provider_did: String,
    available: bool,
    /// Capacity the validator measured, when its probe measures one.
    capacity: Option<u64>,
}

/// Most providers one attestation may carry.
pub const MAX_SLA_OUTCOMES: usize = 256;
/// Governed penalty, in gwei, a frozen unavailable SLA verdict takes from the
/// provider's compute bond into the insurance pool.
pub const SLA_UNAVAILABLE_PENALTY_GWEI_PARAM: &str = "sla.unavailable.penalty_gwei";

/// Governed key: how often validators probe each bonded provider, ms.
pub const SLA_PROBE_INTERVAL_PARAM: &str = "sla.probe_interval_ms";
/// Governed key: how long a provider has to answer a scheduled probe, ms.
pub const SLA_PROBE_WINDOW_PARAM: &str = "sla.probe_window_ms";

/// Governed key: seconds an inference challenge's committee has to commit
/// its votes after filing.
pub const CHALLENGE_COMMIT_WINDOW_PARAM: &str = "inference.challenge_commit_window_secs";
/// Governed key: seconds the committee has to reveal after the commit window.
pub const CHALLENGE_REVEAL_WINDOW_PARAM: &str = "inference.challenge_reveal_window_secs";
/// Ten TNZO.
pub const DEFAULT_SLA_UNAVAILABLE_PENALTY_GWEI: u64 = 10_000_000_000;
// Per outcome, on top of the base cost.
pub const GAS_SLA_OUTCOME: u64 = 10_000;

/// One validator's attestation, as stored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SlaAttestation {
    validator: String,
    available: bool,
    stake: String,
    capacity: Option<u64>,
}

/// A frozen SLA verdict for one provider and epoch, as stored and as read by
/// nodes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SlaVerdict {
    /// Whether the stake attesting availability outweighed the stake that did not.
    pub available: bool,
    /// Stake that attested the provider available.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub up_stake: u128,
    /// Stake that attested it unavailable.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub down_stake: u128,
    /// Validators whose attestations it was computed from.
    pub attesters: usize,
    /// Stake-weighted median of the capacity validators measured, when any
    /// of them measured one.
    pub measured_capacity: Option<u64>,
}

fn sla_bucket(provider_did: &str, epoch: u64) -> String {
    format!("{}:{}", epoch, provider_did)
}

fn sla_open_count_key(epoch: u64) -> String {
    format!("sla_open_n:{epoch}")
}

fn sla_open_key(epoch: u64, i: u64) -> String {
    format!("sla_open:{epoch}:{i}")
}

/// The first epoch whose unfinished SLA attestations are still kept.
const SLA_SWEPT_BELOW_KEY: &str = "sla_open_swept_below";

/// Most epochs one attestation sweeps.
const MAX_SLA_SWEPT_EPOCHS: u64 = 64;

fn sla_down_count_key(epoch: u64) -> String {
    format!("sla_down_n:{epoch}")
}

fn sla_down_key(epoch: u64, i: u64) -> String {
    format!("sla_down_i:{epoch}:{i}")
}

/// Governed key: epochs a frozen SLA verdict is kept.
pub const SLA_VERDICT_RETENTION_PARAM: &str = "sla.verdict_retention_epochs";

/// Governed key: epochs the mark of an hour judged unavailable is kept
/// after its verdict is gone; 0 keeps it.
pub const SLA_DOWN_RETENTION_PARAM: &str = "sla.down_retention_epochs";

/// The first epoch whose unavailable-hour marks are still kept.
const SLA_DOWN_SWEPT_BELOW_KEY: &str = "sla_down_swept_below";

/// Deletes, for every epoch more than the governed verdict retention behind
/// `now_epoch` (never less than the attest window), the epoch's verdicts and
/// any attestations that never reached one, with the epoch's list of them;
/// and, when a mark retention is set, the marks of hours judged unavailable
/// that are older still. At most [`MAX_SLA_SWEPT_EPOCHS`] epochs of each a
/// call, from cursors recorded on the first attestation, so each call goes
/// on from where the last stopped.
fn sweep_open_sla(
    state: &mut dyn VmState,
    now_epoch: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let keep = network_param(state, SLA_VERDICT_RETENTION_PARAM).max(MARKET_SUBMIT_WINDOW + 1);
    let end = now_epoch.saturating_sub(keep);
    let kept: Option<u64> = funding::read_json(state, SLA_SWEPT_BELOW_KEY);
    let from = kept.unwrap_or(end);
    let to = end.min(from.saturating_add(MAX_SLA_SWEPT_EPOCHS)).max(from);
    for e in from..to {
        let n: u64 = funding::read_json(state, &sla_open_count_key(e)).unwrap_or(0);
        for i in 0..n {
            let k = sla_open_key(e, i);
            if let Some(did) = funding::read_json::<String>(state, &k) {
                let bucket = sla_bucket(&did, e);
                funding::delete_record(state, &format!("sla_sub:{bucket}"), changes);
                funding::delete_record(state, &format!("sla:{bucket}"), changes);
            }
            funding::delete_record(state, &k, changes);
        }
        funding::delete_record(state, &sla_open_count_key(e), changes);
    }
    if kept != Some(to) {
        funding::write_json(state, SLA_SWEPT_BELOW_KEY, &to, changes)?;
    }
    let marks = network_param(state, SLA_DOWN_RETENTION_PARAM);
    if marks == 0 {
        return Ok(());
    }
    let end = now_epoch.saturating_sub(keep.saturating_add(marks));
    let kept: Option<u64> = funding::read_json(state, SLA_DOWN_SWEPT_BELOW_KEY);
    let from = kept.unwrap_or(end);
    let to = end.min(from.saturating_add(MAX_SLA_SWEPT_EPOCHS)).max(from);
    for e in from..to {
        let n: u64 = funding::read_json(state, &sla_down_count_key(e)).unwrap_or(0);
        for i in 0..n {
            let k = sla_down_key(e, i);
            if let Some(did) = funding::read_json::<String>(state, &k) {
                funding::delete_record(
                    state,
                    &format!("sla_down:{}", sla_bucket(&did, e)),
                    changes,
                );
            }
            funding::delete_record(state, &k, changes);
        }
        funding::delete_record(state, &sla_down_count_key(e), changes);
    }
    if kept != Some(to) {
        funding::write_json(state, SLA_DOWN_SWEPT_BELOW_KEY, &to, changes)?;
    }
    Ok(())
}

/// Read the frozen SLA verdict for a provider and epoch from VM state.
///
/// A verdict is kept for the governed retention; after it, an hour judged
/// unavailable still reads as unavailable (with no stake or capacity
/// figures) and one judged available reads as no verdict, which every
/// reader pays once the attest window has closed.
pub fn read_sla_verdict(state: &dyn VmState, provider_did: &str, epoch: u64) -> Option<SlaVerdict> {
    read_sla_verdict_kept(state, provider_did, epoch).or_else(|| {
        funding::read_json::<bool>(
            state,
            &format!("sla_down:{}", sla_bucket(provider_did, epoch)),
        )
        .map(|_| SlaVerdict {
            available: false,
            up_stake: 0,
            down_stake: 0,
            attesters: 0,
            measured_capacity: None,
        })
    })
}

fn read_sla_verdict_kept(
    state: &dyn VmState,
    provider_did: &str,
    epoch: u64,
) -> Option<SlaVerdict> {
    let key = format!("sla:{}", sla_bucket(provider_did, epoch));
    serde_json::from_slice(&state.get_storage(&SYSTEM_ADDRESS, key.as_bytes())?).ok()
}

/// JSON payload decoded from `tx.data[4..]` for `IncreaseComputeBond`.
#[derive(Debug, Clone, serde::Deserialize)]
struct IncreaseComputeBondPayload {
    provider_did: String,
    amount: u128,
}

/// JSON payload decoded from `tx.data[4..]` for `WithdrawComputeBond`.
/// Starts the cooldown timer; the funds stay in the vault (and stay
/// slashable) until `FinalizeComputeBondWithdrawal` releases them.
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

/// JSON payload decoded from `tx.data[4..]` for `PayerSettle`.
///
/// `payer` / `payee` are the settling parties' native addresses.
/// `payment_id` is the challenge id the payer signed — the idempotency key.
/// The VM records a per-`payment_id` marker under `SYSTEM_ADDRESS` on first
/// success so a replayed dispatch is rejected before it can debit the payer
/// twice. `authorization` is the payer's signature over the canonical payment
/// authorization; the `from` of the dispatching tx only pays gas.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PayerSettlePayload {
    payer: Address,
    payee: Address,
    amount: u128,
    payment_id: String,
    /// The payer's signed authorization, with any application margin.
    authorization: tenzro_types::payment_authorization::PaymentAuthorization,
}

/// Storage key for an escrow record under `SYSTEM_ADDRESS`: `escrow:<hex_id>`.
/// Governed key: hours an escrow's record is kept once it can no longer
/// move, counted from its expiry (or from its creation, when that is
/// sooner by the same span).
pub const ESCROW_RETENTION_PARAM: &str = "escrow.retention_hours";

/// One review bucket of escrow records.
const ESCROW_DAY_MS: i64 = 86_400_000;

/// Most escrow records one sweep looks at, empty days included.
const MAX_ESCROWS_SWEPT: u32 = 64;

/// The first (day, entry) of escrow records not yet looked at.
const ESCROW_SWEPT_KEY: &str = "escrow_swept";

fn escrow_due_key(day: i64, i: u64) -> String {
    format!("escrow_due:{day}:{i}")
}

fn escrow_due_count_key(day: i64) -> String {
    format!("escrow_due_n:{day}")
}

fn escrow_retention_ms(state: &dyn VmState) -> i64 {
    (network_param(state, ESCROW_RETENTION_PARAM) as i64).saturating_mul(3_600_000)
}

/// When a new escrow's record is first looked at: a retention after it
/// expires, or after a retention from its creation when that comes sooner,
/// so an escrow set to expire far ahead is still looked at.
fn escrow_review_ms(state: &dyn VmState, escrow: &EscrowAccount) -> i64 {
    let keep = escrow_retention_ms(state);
    escrow
        .expires_at
        .0
        .min(escrow.created_at.0.saturating_add(keep))
        .saturating_add(keep)
}

/// List `escrow_id` to be looked at on the day `at_ms` falls in.
fn schedule_escrow_record(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    at_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let day = at_ms.max(0) / ESCROW_DAY_MS;
    let n: u64 = funding::read_json(state, &escrow_due_count_key(day)).unwrap_or(0);
    funding::write_json(
        state,
        &escrow_due_key(day, n),
        &hex::encode(escrow_id),
        changes,
    )?;
    funding::write_json(state, &escrow_due_count_key(day), &(n + 1), changes)?;
    Ok(())
}

/// Deletes the records of escrows that can no longer move and whose review
/// day has passed, each with an `EscrowArchived` log carrying the whole
/// record; one still funded is looked at again a retention later. At most
/// [`MAX_ESCROWS_SWEPT`] entries and days a call, from a cursor recorded on
/// the first call, so each call goes on from where the last stopped.
pub(crate) fn sweep_escrow_records(
    state: &mut dyn VmState,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<Vec<Log>> {
    let today = now_ms.max(0) / ESCROW_DAY_MS;
    let kept: Option<(i64, u64)> = funding::read_json(state, ESCROW_SWEPT_KEY);
    let (mut day, mut i) = kept.unwrap_or((today, 0));
    let mut logs = Vec::new();
    let mut budget = MAX_ESCROWS_SWEPT;
    while day < today && budget > 0 {
        let n: u64 = funding::read_json(state, &escrow_due_count_key(day)).unwrap_or(0);
        while i < n && budget > 0 {
            budget -= 1;
            let k = escrow_due_key(day, i);
            let id = funding::read_json::<String>(state, &k)
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            funding::delete_record(state, &k, changes);
            i += 1;
            let Some(id) = id else { continue };
            let Ok((key, blob, escrow)) = read_escrow_record(state, &id) else {
                continue;
            };
            if escrow.status == EscrowStatus::Funded {
                let again = now_ms.saturating_add(escrow_retention_ms(state));
                schedule_escrow_record(state, &id, again, changes)?;
                continue;
            }
            funding::delete_record(state, &key, changes);
            funding::delete_record(state, &payment_settlement::stream_cursor_key(&id), changes);
            logs.push(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![b"EscrowArchived".to_vec()],
                blob,
            ));
        }
        if i >= n {
            funding::delete_record(state, &escrow_due_count_key(day), changes);
            day += 1;
            i = 0;
            budget = budget.saturating_sub(1);
        }
    }
    if kept != Some((day, i)) {
        funding::write_json(state, ESCROW_SWEPT_KEY, &(day, i), changes)?;
    }
    Ok(logs)
}

/// Governed key: hours past its expiry after which anyone may close an
/// escrow.
pub const ESCROW_CLOSE_GRACE_PARAM: &str = "escrow.close_grace_hours";
/// Governed: 1 while a new validator needs an enacted approval to register.
pub const VALIDATOR_ADMISSION_APPROVAL_PARAM: &str = "validator.admission_approval";

fn validator_approval_key(account: &[u8]) -> String {
    format!("validator_approved:{}", hex::encode(account))
}

/// Whether an enacted ApproveValidators proposal approved `account`.
pub fn validator_approved(state: &dyn VmState, account: &[u8]) -> bool {
    state
        .get_storage(&SYSTEM_ADDRESS, validator_approval_key(account).as_bytes())
        .is_some_and(|b| !b.is_empty())
}

fn set_validator_approval(
    state: &mut dyn VmState,
    account: &[u8],
    approve: bool,
    changes: &mut Vec<StateChange>,
) {
    let key = validator_approval_key(account);
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let next = if approve { vec![1u8] } else { Vec::new() };
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), next.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        previous,
        Some(next),
    ));
}

/// Governed: how many days ahead a top-up allowance may expire.
pub const AGENT_TOPUP_MAX_DAYS_PARAM: &str = "agent.topup_max_days";

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
pub(crate) fn deterministic_now_ms(tx: &VmTransaction) -> i64 {
    tx.block_timestamp_ms
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis())
}

/// Log topics of a pause, a quarantine and a termination, in that order.
pub const KILL_SWITCH_TOPICS: [&[u8]; 3] = [
    b"KillSwitchPause",
    b"KillSwitchQuarantine",
    b"KillSwitchTerminate",
];

/// Storage key for a kill-switch receipt under `SYSTEM_ADDRESS`:
/// `killswitch:<hex_id>`.
fn killswitch_storage_key(receipt_id_hex: &str) -> String {
    format!("killswitch:{}", receipt_id_hex)
}

/// Storage key for a bond marker under `SYSTEM_ADDRESS`:
/// `bond:<agent_did>`, read through `economy::agent_bond`.
fn bond_storage_key(agent_did: &str) -> String {
    format!("bond:{}", agent_did)
}

/// Encode the data field of a bond `Log`:
/// `agent_did_len_le(4) || agent_did_bytes || controller_did_len_le(4) ||
///  controller_did_bytes || amount_le(16) || op_tag(1)` where
/// `op_tag ∈ {0=Posted, 1=Increased, 2=WithdrawInitiated, 3=Returned}`.
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
/// MUST match `tenzro_token::bond::derive_bond_vault_address` byte-for-byte.
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
/// `compute_bond:<provider_did>`. Every reader reads this marker through
/// [`economy::compute_bond`].
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
/// marker by `WithdrawComputeBond`, and is 0 for every other op.
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

// ---- Governance storage ----------------------------------------------------

/// The treasury vault address: the one network treasury account that fee
/// settlement, commissions and governance treasury grants all use.
///
/// The treasury is an address with no key: nothing can sign for it, and in
/// the VM the only thing that moves its balance out is a proposal that
/// cleared quorum and threshold. Deriving it from a fixed domain rather than
/// nominating an existing account is what makes that true: there is no
/// private key in existence that corresponds to it.
pub fn derive_treasury_address() -> Address {
    tenzro_types::network_treasury_address()
}

/// A proposal just written to consensus state.
pub(crate) struct OpenedProposal {
    /// 32-byte proposal hash; its hex is the proposal id.
    pub hash: [u8; 32],
    pub id: String,
    pub state_changes: Vec<StateChange>,
}

/// Opens a proposal for `action`: stores it, opens its tally against the
/// bonded stake as of now, and bumps the proposal counter. The id derives
/// from proposer, payload and nonce, so two identical proposals from the same
/// account are still distinct records.
pub(crate) fn open_proposal(
    state: &mut dyn VmState,
    tx: &VmTransaction,
    action: &crate::governance::ProposalAction,
    proposal_data: &[u8],
) -> Result<OpenedProposal> {
    use crate::governance::{Proposal, Tally};

    let mut hasher = Sha256::new();
    hasher.update(&tx.from);
    hasher.update(proposal_data);
    hasher.update(state.get_nonce(&tx.from).to_le_bytes());
    let proposal_hash: [u8; 32] = hasher.finalize().into();
    let proposal_id = hex::encode(proposal_hash);

    let now_ms = deterministic_now_ms(tx);
    let mut proposer = [0u8; 32];
    let len = tx.from.len().min(32);
    proposer[..len].copy_from_slice(&tx.from[..len]);
    let proposal = Proposal::open(
        proposal_id.clone(),
        Address::new(proposer),
        action.clone(),
        now_ms,
        governance_rules(state),
    );
    let (proposal_blob, prior_proposal) = store_proposal(state, &proposal)?;

    let tally = Tally {
        yes: 0,
        no: 0,
        total_eligible: staking::governance_total_bonded(state),
    };
    let (tally_blob, prior_tally) = store_tally(state, &proposal_id, &tally)?;

    let counter_key = b"proposal_counter";
    let current_count = state
        .get_storage(&SYSTEM_ADDRESS, counter_key)
        .and_then(|bytes| {
            let count_bytes: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
            Some(u64::from_le_bytes(count_bytes))
        })
        .unwrap_or(0);
    let new_count = current_count + 1;
    state.set_storage(
        &SYSTEM_ADDRESS,
        counter_key,
        new_count.to_le_bytes().to_vec(),
    );
    // Numbered index, so proposals can be listed without prefix iteration.
    let index_key = proposal_index_key(new_count);
    state.set_storage(
        &SYSTEM_ADDRESS,
        index_key.as_bytes(),
        proposal_id.as_bytes().to_vec(),
    );

    Ok(OpenedProposal {
        hash: proposal_hash,
        id: proposal_id.clone(),
        state_changes: vec![
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                governance_proposal_key(&proposal_id).into_bytes(),
                prior_proposal,
                Some(proposal_blob),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                governance_tally_key(&proposal_id).into_bytes(),
                prior_tally,
                Some(tally_blob),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                counter_key.to_vec(),
                Some(current_count.to_le_bytes().to_vec()),
                Some(new_count.to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                index_key.into_bytes(),
                None,
                Some(proposal_id.into_bytes()),
            ),
        ],
    })
}

/// Storage key of the `n`th proposal's id (1-based, in the order opened).
fn proposal_index_key(n: u64) -> String {
    format!("proposal_index:{n}")
}

/// How many proposals have been opened.
pub fn proposal_count(state: &dyn VmState) -> u64 {
    state
        .get_storage(&SYSTEM_ADDRESS, b"proposal_counter")
        .and_then(|bytes| Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)))
        .unwrap_or(0)
}

/// Id of the `n`th proposal opened (1-based).
pub fn proposal_id_at(state: &dyn VmState, n: u64) -> Option<String> {
    let raw = state.get_storage(&SYSTEM_ADDRESS, proposal_index_key(n).as_bytes())?;
    String::from_utf8(raw).ok()
}

/// Storage key for a stored [`Proposal`](crate::governance::Proposal).
fn governance_proposal_key(id: &str) -> String {
    format!("proposal:{id}")
}

/// Storage key for a proposal's running vote totals.
fn governance_tally_key(id: &str) -> String {
    format!("proposal_tally:{id}")
}

/// Storage slot of an enacted proposal's decision record:
/// `sha256(executed proposal record)(32) || executed_height (u64
/// big-endian)`. Fixed-width, so a contract on another chain checks it with a
/// state proof alone and binds it to the proposal by the record's hash.
pub fn governance_decision_slot(id: &str) -> String {
    format!("governance_decision:{id}")
}

/// The system storage slots a governance receipt proves for `proposal_id`,
/// by kind: the proposal, its tally, its veto escrow total, its decision
/// record, and for a protocol upgrade the readiness signals and the
/// scheduled activation.
pub fn governance_receipt_slots(
    state: &dyn VmState,
    proposal_id: &str,
) -> Vec<(&'static str, String)> {
    let mut slots = vec![("proposal", governance_proposal_key(proposal_id))];
    if let Some(p) = load_proposal(state, proposal_id) {
        slots.push(("tally", governance_tally_key(&p.ballot_id())));
        if let crate::governance::ProposalAction::PolicyUpdate {
            update: tenzro_types::token::PolicyUpdate::ProtocolUpgrade { code_hash, .. },
            ..
        } = &p.action
        {
            slots.push((
                "readiness",
                format!("upgrade_ready:{}", hex::encode(code_hash)),
            ));
            slots.push(("activation", "upgrade_activation".to_string()));
        }
    }
    slots.push(("veto_total", format!("veto_total:{proposal_id}")));
    slots.push(("decision", governance_decision_slot(proposal_id)));
    slots
}

/// Storage key for one voter's ballot on one proposal.
/// Cast `ballot` for `action`'s agent under `terms`: the agent must hold a
/// governance scope that lets it vote in the proposal's domain, the
/// validator must be its principal's, a treasury or sanction ballot needs the
/// principal's step-up, and a ballot the principal cast itself stands. The
/// weight counted is the validator's bond at open, capped at the smaller of
/// the scope's and governance's per-ballot share of the eligible stake; the
/// rest abstains.
pub(crate) fn cast_agent_ballot(
    state: &mut dyn VmState,
    terms: &tenzro_types::agent_terms::AgentTerms,
    action: &tenzro_types::agent_terms::AgentAction,
    ballot: &tenzro_types::agent_terms::AgentBallot,
    at_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    use crate::governance::{AGENT_WEIGHT_MAX_PARAM, ActionDomain};
    let refuse = |m: String| VmError::InvalidTransaction(format!("agent ballot refused: {m}"));
    let scope = terms
        .delegation_scope
        .governance
        .as_ref()
        .filter(|g| g.may_vote)
        .ok_or_else(|| refuse("the agent's terms give it no vote".into()))?;
    let proposal_id = ballot
        .proposal_id
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    let mut proposal = load_proposal(state, &proposal_id)
        .ok_or_else(|| refuse(format!("no proposal {proposal_id}")))?;
    if !proposal.is_open_at(at_ms) {
        return Err(refuse("voting has closed".into()));
    }
    let ballot_id = proposal.ballot_id();
    let domain = proposal.action.domain();
    let name = match domain {
        ActionDomain::Network => "network",
        ActionDomain::Treasury => "treasury",
        ActionDomain::Sanction => "sanction",
    };
    if !scope.domains.iter().any(|d| d.eq_ignore_ascii_case(name)) {
        return Err(refuse(format!(
            "the agent may not vote in the {name} domain"
        )));
    }
    if matches!(domain, ActionDomain::Treasury | ActionDomain::Sanction) && action.step_up.is_none()
    {
        return Err(refuse(format!(
            "a {name} ballot needs the principal's step-up"
        )));
    }
    let validator = hex::decode(ballot.validator.trim_start_matches("0x"))
        .ok()
        .filter(|v| v.len() == 20 || v.len() == 32)
        .ok_or_else(|| refuse("the validator is a 20 or 32 byte account".into()))?;
    let validator_did = identity_of_wallet(state, &validator)
        .ok_or_else(|| refuse("the validator has no identity".into()))?;
    if crate::funding::root_did(&validator_did) != terms.controller_did {
        return Err(refuse(
            "the validator is not the agent's principal's".into(),
        ));
    }
    let voter_hex = hex::encode(&validator);
    let previous = load_ballot(state, &ballot_id, &voter_hex);
    if matches!(previous, Some((_, _, CastBy::Principal))) {
        return Err(refuse("the principal's own ballot stands".into()));
    }
    let weight = staking::vote_weight(state, &validator, &proposal);
    if weight == 0 {
        return Err(refuse(
            "the validator had no bond when the proposal opened".into(),
        ));
    }
    let mut tally = load_tally(state, &ballot_id);
    let cap_bps = u128::from(scope.max_weight_bps)
        .min(u128::from(network_param(state, AGENT_WEIGHT_MAX_PARAM)));
    let cap = tally.total_eligible.saturating_mul(cap_bps) / 10_000;
    let counted = weight.min(cap);
    if counted == 0 {
        return Err(refuse("the agent's ballot cap counts nothing".into()));
    }
    tally.apply_vote(counted, ballot.in_favour, previous.map(|(w, f, _)| (w, f)));
    let (tally_blob, prior_tally) = store_tally(state, &ballot_id, &tally)?;
    let (vote_blob, prior_vote) = store_vote(
        state,
        &ballot_id,
        &voter_hex,
        counted,
        ballot.in_favour,
        CastBy::Agent,
    );
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        governance_vote_key(&ballot_id, &voter_hex).into_bytes(),
        prior_vote,
        Some(vote_blob),
    ));
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        governance_tally_key(&ballot_id).into_bytes(),
        prior_tally,
        Some(tally_blob),
    ));
    if !proposal.is_open_at(at_ms) {
        proposal.status = proposal.outcome(&tally);
        store_proposal(state, &proposal)?;
    }
    let mut data = hex::decode(&proposal_id).unwrap_or_default();
    data.extend_from_slice(&validator);
    data.extend_from_slice(&counted.to_le_bytes());
    data.push(u8::from(ballot.in_favour));
    data.extend_from_slice(action.agent_did.as_bytes());
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![b"AgentVoteCast".to_vec()],
        data,
    ));
    Ok(())
}

fn governance_vote_key(id: &str, voter_hex: &str) -> String {
    format!("vote:{id}:{voter_hex}")
}

/// Storage key for the wallet-address -> DID reverse index.
///
/// Identity records are keyed by DID, which answers "who is this DID?" but not
/// "does this address belong to anyone?". A treasury grant has to ask the
/// second question — paying an address with no identity behind it would create
/// exactly the thing the network forbids, a wallet nobody answers for — and
/// with no prefix iteration in `VmState` the only way to ask it is an index
/// written when the identity is registered.
fn identity_wallet_index_key(address: &[u8]) -> String {
    format!("identity_wallet:{}", hex::encode(address))
}

/// The DID registered to wallet `address`, if any.
pub fn identity_of_wallet(state: &dyn VmState, address: &[u8]) -> Option<String> {
    let raw = state.get_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(address).as_bytes(),
    )?;
    String::from_utf8(raw).ok().filter(|d| !d.is_empty())
}

/// Refuses a governance ballot for `validator` unless `signer` is the
/// validator's operator: a registered, unrevoked human identity that is the
/// root of the validator account's identity (or that identity itself).
fn operator_may_vote(state: &dyn VmState, signer: &[u8], validator: &[u8]) -> Result<()> {
    if let Some(did) = identity_of_wallet(state, validator)
        && tenzro_types::agent_terms::RootKind::of(&did)
            == Some(tenzro_types::agent_terms::RootKind::Machine)
    {
        return Err(VmError::InvalidTransaction(format!(
            "validator {} is the autonomous machine {did}; its ballot carries that machine root's approval",
            hex::encode(validator)
        )));
    }
    let signer_did = identity_of_wallet(state, signer).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "{} has no registered identity; a ballot is signed by the validator operator's passkey identity",
            hex::encode(signer)
        ))
    })?;
    if !signer_did.starts_with(crate::governance::HUMAN_DID_PREFIX)
        || is_identity_revoked(state, &signer_did)
    {
        return Err(VmError::InvalidTransaction(format!(
            "{signer_did} is not a live human identity; a ballot is signed by the validator operator's \
             passkey, not a machine key"
        )));
    }
    let validator_did = identity_of_wallet(state, validator).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "validator {} has no registered identity",
            hex::encode(validator)
        ))
    })?;
    if crate::funding::root_did(&validator_did) != signer_did {
        return Err(VmError::InvalidTransaction(format!(
            "{signer_did} does not operate validator {}",
            hex::encode(validator)
        )));
    }
    Ok(())
}

/// Storage key marking a machine root's ballot approval as counted.
fn root_ballot_spent_key(digest: &[u8; 32]) -> String {
    format!("governance_root_ballot:{}", hex::encode(digest))
}

/// Refuses a ballot for `validator` carried by `approval` unless the
/// validator's identity is an autonomous machine whose root, the hardware
/// key its DID derives from, approved exactly this ballot and the approval
/// has not been counted before. Returns the key that marks it counted.
fn machine_root_may_vote(
    state: &dyn VmState,
    proposal_id: &[u8; 32],
    in_favour: bool,
    validator: &[u8],
    approval: &tenzro_types::agent_terms::AgentTermsApproval,
    now_ms: u64,
) -> Result<String> {
    use tenzro_types::agent_terms::{OP_ROOT_BALLOT, RootKind, governance_vote_target};
    let refuse =
        |m: String| VmError::InvalidTransaction(format!("machine root ballot refused: {m}"));
    let validator_did = identity_of_wallet(state, validator).ok_or_else(|| {
        refuse(format!(
            "validator {} has no registered identity",
            hex::encode(validator)
        ))
    })?;
    if RootKind::of(&validator_did) != Some(RootKind::Machine) {
        return Err(refuse(format!(
            "validator {} is not an autonomous machine; its operator signs the ballot with their passkey identity",
            hex::encode(validator)
        )));
    }
    if approval.account != validator {
        return Err(refuse("the approval names another account".to_string()));
    }
    let target = governance_vote_target(proposal_id, in_favour, validator);
    let digest = verify_root_approval(
        state,
        &validator_did,
        OP_ROOT_BALLOT,
        &target,
        approval,
        now_ms,
    )
    .map_err(refuse)?;
    let key = root_ballot_spent_key(&digest);
    if state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .is_some_and(|b| !b.is_empty())
    {
        return Err(refuse("this approval has already been counted".to_string()));
    }
    Ok(key)
}

/// Ballot body for `validator`: proposal id, vote, length-prefixed account.
#[cfg(test)]
pub(crate) fn test_vote_data(proposal_id: &[u8], in_favour: bool, validator: &[u8]) -> Vec<u8> {
    let mut data = SELECTOR_GOVERNANCE_VOTE.to_vec();
    data.extend_from_slice(proposal_id);
    data.push(u8::from(in_favour));
    data.push(validator.len() as u8);
    data.extend_from_slice(validator);
    data
}

/// Bind `validator` to a human identity of its own, so the account signs its
/// ballots as its own operator.
#[cfg(test)]
pub(crate) fn test_operate_own_validator(state: &mut dyn VmState, validator: &[u8]) {
    let key = identity_wallet_index_key(validator);
    if state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()).is_none() {
        let did = format!(
            "{}{}",
            crate::governance::HUMAN_DID_PREFIX,
            hex::encode(validator)
        );
        state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), did.into_bytes());
    }
}

/// Whether chain state records `did` as revoked, by its root or by
/// governance.
pub fn is_identity_revoked(state: &dyn VmState, did: &str) -> bool {
    state
        .get_storage(&SYSTEM_ADDRESS, &identity_revocation_key(did))
        .is_some_and(|b| !b.is_empty())
}

/// Stake `addr` currently has bonded, in the smallest unit.
///
/// This is the voter's weight. Zero means not a validator, which is also what
/// makes someone ineligible to vote at all. A validator that has begun exiting
/// has zero here: its bond is unbonding and no longer votes.
pub fn bonded_stake_of(state: &dyn VmState, addr: &[u8]) -> u128 {
    staking::bonded_stake_of(state, addr)
}

/// Total stake bonded network-wide, the denominator for quorum.
///
/// A counter kept by the bond operations, not the staking vault's balance:
/// anyone can send TNZO to the vault, and a donation there must not move the
/// quorum.
pub fn total_bonded_stake(state: &dyn VmState) -> u128 {
    staking::total_bonded(state)
}

/// How much of `addr`'s balance a governance recovery may take. For the
/// staking vault that is only what it holds beyond what it owes validators;
/// bonded and unbonding stake are never recoverable.
fn recoverable_amount(state: &dyn VmState, addr: &[u8]) -> u128 {
    let balance = state.get_balance(addr);
    if is_vault_form(addr) {
        return balance.saturating_sub(staking::vault_liabilities(state));
    }
    balance
}

/// Addresses a recovery may draw from.
///
/// System-held sinks only. Everything on this list is an address the protocol
/// itself credits, so a balance sitting there that the books cannot attribute
/// is genuinely nobody's. A user account can never appear here: a recovery
/// power that reaches a user balance is a confiscation power with a friendly
/// name, and the difference has to be structural rather than a matter of who
/// is proposing.
fn is_recoverable_source(addr: &[u8]) -> bool {
    // The treasury is not on the list: its balance is owned by the network
    // and leaves only through a gated payout.
    is_vault_form(addr)
}

/// Whether `addr` names the staking vault: its 20 bytes, or the 32-byte form
/// of them padded with zeros, which is how a proposal's `Address` carries it.
fn is_vault_form(addr: &[u8]) -> bool {
    addr.len() >= 20 && addr[..20] == STAKING_VAULT_ADDRESS && addr[20..].iter().all(|b| *b == 0)
}

/// The account whose balance a recovery from `addr` reads and moves.
fn recovery_key(addr: &[u8]) -> Vec<u8> {
    if is_vault_form(addr) {
        STAKING_VAULT_ADDRESS.to_vec()
    } else {
        addr.to_vec()
    }
}

/// The staking vault as a proposal's `Address`: the one source a recovery
/// may draw on.
pub fn vault_recovery_address() -> Address {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(&STAKING_VAULT_ADDRESS);
    Address::new(bytes)
}

/// The DID bound to `addr`, if any.
pub fn identity_did_of(state: &dyn VmState, addr: &[u8]) -> Option<String> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, identity_wallet_index_key(addr).as_bytes())?;
    if blob.is_empty() {
        return None;
    }
    String::from_utf8(blob).ok()
}

/// Whether `addr` proposes as an autonomous agent.
///
/// `did:tenzro:agent:` specifically, **not** `did:tenzro:machine:`. The two
/// are different things and conflating them locks governance shut: every
/// validator holds a machine identity, machine identities are what hold stake,
/// and gating them would leave nobody able to propose anything at the default
/// phase. A validator operated by a person is hardware with an operator, not
/// an autonomous process.
///
/// The distinction is the whole question. A machine identity says what the
/// keys are bound to; an agent identity says what kind of thing decided.
fn is_agent_identity(state: &dyn VmState, addr: &[u8]) -> bool {
    identity_did_of(state, addr).is_some_and(|did| did.starts_with("did:tenzro:agent:"))
}

/// The agent phase currently in force, defaulting to the compiled-in value.
///
/// A network that has never voted on this sits at `None`, so agents originate
/// nothing until somebody decides they should.
fn current_agent_phase(state: &dyn VmState) -> crate::governance::AgentPhase {
    use crate::governance::AgentPhase;
    match network_param(state, "governance.agent_phase") {
        1 => AgentPhase::Network,
        2 => AgentPhase::All,
        _ => AgentPhase::None,
    }
}

/// The governed bridge route for `(adapter, source_chain)`, if one is
/// installed. An empty or unreadable record reads as absent, so traffic on
/// it is refused.
pub fn read_bridge_route(
    state: &dyn VmState,
    adapter: tenzro_types::bridge_route::BridgeRouteAdapter,
    source_chain: &str,
) -> Option<tenzro_types::bridge_route::BridgeRoute> {
    let key = tenzro_types::bridge_route::bridge_route_storage_key(adapter, source_chain);
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The address governed records live under, as the node's state readers need
/// it to enumerate them.
pub const GOVERNED_STATE_ADDRESS: [u8; 20] = SYSTEM_ADDRESS;

/// Storage key for a governed parameter's current value.
pub fn governed_param_key(key: &str) -> String {
    format!("governance_param:{key}")
}

/// Storage key for a governed parameter's enacted change that waits for
/// its epoch.
pub fn pending_param_key(key: &str) -> String {
    format!("governance_param_pending:{key}")
}

/// Storage key of the list of governed keys with a change waiting.
pub const PENDING_PARAMS_INDEX_KEY: &str = "governance_param_pending_index";

/// Storage key of the epoch the latest executed block began in, as the
/// parameter schedule last saw it.
pub const PARAMS_EPOCH_KEY: &str = "governance_params_epoch";

/// An enacted parameter change waiting for the epoch it applies in.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingParam {
    /// The value it becomes.
    pub value: u64,
    /// First epoch whose blocks run with it.
    pub activates_epoch: u64,
    /// The enacted proposal that decided it.
    pub proposal_id: String,
}

/// A governed parameter's value: what governance last set, or its genesis
/// value from the registry.
///
/// Every network policy value is read here and nowhere else. A key outside
/// the registry is a programming error; it reads as zero and fails the
/// registry tests.
/// Writes a governed parameter's starting value into a genesis state, as
/// genesis does. Only genesis and enactment write governed parameters.
pub fn set_genesis_param(state: &mut dyn VmState, key: &str, value: u64) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(key).as_bytes(),
        value.to_le_bytes().to_vec(),
    );
}

/// Test seam: sets a governed parameter the way enactment would store it.
#[cfg(test)]
pub(crate) fn set_governed_param_for_test(state: &mut dyn VmState, key: &str, value: u64) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(key).as_bytes(),
        value.to_le_bytes().to_vec(),
    );
}

/// The value governance or genesis stored for `key` in `state`, or `None`
/// when none has been stored. Readers that need a default of their own (the
/// feature gates) read through here; nothing outside this module touches the
/// parameter storage.
pub fn stored_param(state: &dyn VmState, key: &str) -> Option<u64> {
    state
        .get_storage(&SYSTEM_ADDRESS, governed_param_key(key).as_bytes())
        .filter(|b| b.len() == 8)
        .map(|b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b);
            u64::from_le_bytes(a)
        })
}

pub fn network_param(state: &dyn VmState, key: &str) -> u64 {
    stored_param(state, key)
        .unwrap_or_else(|| {
            debug_assert!(
                crate::governance::governed_param(key).is_some(),
                "{key} is not in the governed parameter registry"
            );
            crate::governance::governed_param(key).map_or(0, |p| p.genesis)
        })
}

/// The status a status lever (`<feature>.status`) holds in `state`: what
/// governance set, or paused while a guardian pause of the feature runs
/// ([`feature_pause`]). A guardian pause never reports a paused or retired
/// lever as anything else.
pub fn lever_status(state: &dyn VmState, key: &str) -> crate::governance::LeverStatus {
    use crate::governance::LeverStatus;
    match LeverStatus::from_value(network_param(state, key)) {
        LeverStatus::Enabled if feature_pause::active(state, key) => LeverStatus::Paused,
        status => status,
    }
}

/// Refuse what `feature` would start unless its status lever is enabled.
pub fn require_lever_enabled(state: &dyn VmState, key: &str, feature: &str) -> Result<()> {
    match lever_status(state, key) {
        crate::governance::LeverStatus::Enabled => Ok(()),
        status => Err(VmError::InvalidTransaction(format!(
            "{feature} is {} by governance ({key})",
            status.as_str()
        ))),
    }
}

/// The voting rules in force, from the governed parameters. A proposal
/// keeps the rules it opened under.
pub fn governance_rules(state: &dyn VmState) -> crate::governance::GovernanceRules {
    use crate::governance as g;
    let ms = |key| network_param(state, key) as i64;
    g::GovernanceRules {
        voting_period_ms: ms(g::VOTING_PERIOD_PARAM),
        expedited_voting_period_ms: ms(g::EXPEDITED_VOTING_PERIOD_PARAM),
        timelock_ms: ms(g::TIMELOCK_PARAM),
        expedited_timelock_ms: ms(g::EXPEDITED_TIMELOCK_PARAM),
        ratify_timelock_ms: ms(g::RATIFY_TIMELOCK_PARAM),
        quorum_bps: network_param(state, g::QUORUM_PARAM),
        threshold_bps: network_param(state, g::THRESHOLD_PARAM),
        expedited_threshold_bps: network_param(state, g::EXPEDITED_THRESHOLD_PARAM),
        ratify_threshold_bps: network_param(state, g::RATIFY_THRESHOLD_PARAM),
        min_bond_age_ms: ms(g::MIN_BOND_AGE_PARAM),
        large_spend_tnzo: network_param(state, g::LARGE_SPEND_PARAM),
        large_spend_approval_bps: network_param(state, g::LARGE_SPEND_APPROVAL_PARAM),
        large_spend_timelock_ms: ms(g::LARGE_SPEND_TIMELOCK_PARAM),
    }
}

/// The change waiting for `key`, if one was enacted and has not applied yet.
pub fn pending_param(state: &dyn VmState, key: &str) -> Option<PendingParam> {
    state
        .get_storage(&SYSTEM_ADDRESS, pending_param_key(key).as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Keys with a change waiting, in the order they were enacted.
pub fn pending_param_keys(state: &dyn VmState) -> Vec<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, PENDING_PARAMS_INDEX_KEY.as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// The epoch of the latest executed block.
pub fn params_epoch(state: &dyn VmState) -> u64 {
    state
        .get_storage(&SYSTEM_ADDRESS, PARAMS_EPOCH_KEY.as_bytes())
        .filter(|b| b.len() == 8)
        .map(|b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b);
            u64::from_le_bytes(a)
        })
        .unwrap_or(0)
}

/// Whether `action` loosens a capture guard: a parameter change that moves a
/// guard looser than the value its step is measured from (the tighter of the
/// value in force and the one already scheduled).
pub(crate) fn loosens_capture_guard(
    state: &dyn VmState,
    action: &crate::governance::ProposalAction,
) -> bool {
    use crate::governance::ProposalAction;
    match action {
        ProposalAction::ParameterChange { key, value, .. } => {
            let in_force = network_param(state, key);
            let scheduled = pending_param(state, key).map_or(in_force, |p| p.value);
            crate::governance::loosens_guard(
                key,
                crate::governance::guard_step_base(key, in_force, scheduled),
                *value,
            )
        }
        _ => false,
    }
}

/// Schedule an enacted change of `key` to `value`: it applies from the next
/// epoch, or after the tightening grace window when it asks more of those
/// the rule binds. A later enacted change of the same key replaces it.
fn schedule_param_change(
    state: &mut dyn VmState,
    param: &crate::governance::GovernedParam,
    value: u64,
    proposal_id: &str,
    changes: &mut Vec<StateChange>,
) -> Result<u64> {
    let current = network_param(state, param.key);
    let grace = if param.tighten.tightens(current, value) {
        network_param(state, crate::governance::TIGHTENING_GRACE_PARAM)
    } else if crate::governance::loosens_guard(param.key, current, value) {
        network_param(state, crate::governance::GUARD_LOOSENING_GRACE_PARAM)
    } else {
        0
    };
    let activates_epoch = params_epoch(state).saturating_add(1).saturating_add(grace);
    let pending = PendingParam {
        value,
        activates_epoch,
        proposal_id: proposal_id.to_string(),
    };
    let key = pending_param_key(param.key);
    let blob = serde_json::to_vec(&pending)
        .map_err(|e| VmError::Internal(format!("encoding pending parameter: {e}")))?;
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        previous,
        Some(blob),
    ));

    let mut index = pending_param_keys(state);
    if !index.iter().any(|k| k == param.key) {
        index.push(param.key.to_string());
        let blob = serde_json::to_vec(&index)
            .map_err(|e| VmError::Internal(format!("encoding pending index: {e}")))?;
        let previous = state.get_storage(&SYSTEM_ADDRESS, PENDING_PARAMS_INDEX_KEY.as_bytes());
        state.set_storage(
            &SYSTEM_ADDRESS,
            PENDING_PARAMS_INDEX_KEY.as_bytes(),
            blob.clone(),
        );
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            PENDING_PARAMS_INDEX_KEY.as_bytes().to_vec(),
            previous,
            Some(blob),
        ));
    }
    Ok(activates_epoch)
}

/// Parameter schedule for one block, run before its transactions: when the
/// block opens a new epoch, every waiting change due by that epoch applies.
/// Returns the keys and values applied. Every node executing the block
/// applies the same changes at the same height.
pub fn begin_block_params(state: &mut dyn VmState, epoch: u64) -> Result<Vec<(String, u64)>> {
    let stored = state
        .get_storage(&SYSTEM_ADDRESS, PARAMS_EPOCH_KEY.as_bytes())
        .filter(|b| b.len() == 8)
        .map(|_| params_epoch(state));
    if stored.is_some_and(|e| e >= epoch) {
        return Ok(Vec::new());
    }
    state.set_storage(
        &SYSTEM_ADDRESS,
        PARAMS_EPOCH_KEY.as_bytes(),
        epoch.to_le_bytes().to_vec(),
    );

    let index = pending_param_keys(state);
    if index.is_empty() {
        return Ok(Vec::new());
    }
    let mut applied = Vec::new();
    let mut waiting = Vec::new();
    // A due change that breaks a rule binding it to another parameter's
    // value in force waits for that one; each pass applies what now fits.
    let mut due = Vec::new();
    for key in index {
        match pending_param(state, &key) {
            Some(p) if p.activates_epoch > epoch => waiting.push(key),
            Some(_) => due.push(key),
            None => {}
        }
    }
    loop {
        let mut held = Vec::new();
        let before = due.len();
        for key in std::mem::take(&mut due) {
            let Some(pending) = pending_param(state, &key) else {
                continue;
            };
            // The registry may have changed in an upgrade since the vote; a
            // value it no longer permits is dropped rather than applied.
            let Some(param) = crate::governance::governed_param(&key) else {
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    pending_param_key(&key).as_bytes(),
                    Vec::new(),
                );
                continue;
            };
            if pending.value < param.min || pending.value > param.max {
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    pending_param_key(&key).as_bytes(),
                    Vec::new(),
                );
                continue;
            }
            let in_force = |k: &str| network_param(&*state, k);
            if crate::governance::joint_change_allowed(&key, pending.value, &in_force).is_err() {
                held.push(key);
                continue;
            }
            state.set_storage(
                &SYSTEM_ADDRESS,
                pending_param_key(&key).as_bytes(),
                Vec::new(),
            );
            state.set_storage(
                &SYSTEM_ADDRESS,
                governed_param_key(&key).as_bytes(),
                pending.value.to_le_bytes().to_vec(),
            );
            applied.push((key, pending.value));
        }
        due = held;
        if due.is_empty() || due.len() == before {
            break;
        }
    }
    waiting.extend(due);
    let blob = if waiting.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(&waiting)
            .map_err(|e| VmError::Internal(format!("encoding pending index: {e}")))?
    };
    state.set_storage(&SYSTEM_ADDRESS, PENDING_PARAMS_INDEX_KEY.as_bytes(), blob);
    Ok(applied)
}

fn load_proposal(state: &dyn VmState, id: &str) -> Option<crate::governance::Proposal> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, governance_proposal_key(id).as_bytes())?;
    if blob.is_empty() {
        return None;
    }
    serde_json::from_slice(&blob).ok()
}

/// Persist a proposal, returning the previous blob for the state-change record.
fn store_proposal(
    state: &mut dyn VmState,
    proposal: &crate::governance::Proposal,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let key = governance_proposal_key(&proposal.id);
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = serde_json::to_vec(proposal)
        .map_err(|e| VmError::Internal(format!("encoding proposal: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    Ok((blob, previous))
}

/// Load a proposal's running totals, defaulting to an empty tally.
fn load_tally(state: &dyn VmState, id: &str) -> crate::governance::Tally {
    state
        .get_storage(&SYSTEM_ADDRESS, governance_tally_key(id).as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Persist a proposal's running totals.
fn store_tally(
    state: &mut dyn VmState,
    id: &str,
    tally: &crate::governance::Tally,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let key = governance_tally_key(id);
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob =
        serde_json::to_vec(tally).map_err(|e| VmError::Internal(format!("encoding tally: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    Ok((blob, previous))
}

/// A voter's existing ballot as `(weight, in_favour)`, if they have one.
///
/// The weight is stored alongside the direction rather than re-read from the
/// voter's bond at tally time. A validator who bonds more after voting must not
/// have their already-cast ballot grow underneath them.
fn load_vote(state: &dyn VmState, id: &str, voter_hex: &str) -> Option<(u128, bool)> {
    load_ballot(state, id, voter_hex).map(|(w, f, _)| (w, f))
}

/// Who cast a stored ballot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastBy {
    /// The validator's operator, with its own passkey.
    Principal,
    /// A delegated agent under the operator's Terms.
    Agent,
}

/// A stored ballot: weight, direction and who cast it.
fn load_ballot(state: &dyn VmState, id: &str, voter_hex: &str) -> Option<(u128, bool, CastBy)> {
    let blob = state.get_storage(
        &SYSTEM_ADDRESS,
        governance_vote_key(id, voter_hex).as_bytes(),
    )?;
    if blob.len() != 18 {
        return None;
    }
    let by = if blob[17] == 1 {
        CastBy::Agent
    } else {
        CastBy::Principal
    };
    let mut w = [0u8; 16];
    w.copy_from_slice(&blob[..16]);
    Some((u128::from_le_bytes(w), blob[16] != 0, by))
}

/// Record a voter's ballot as `weight_le(16) || direction(1) || cast_by(1)`.
fn store_vote(
    state: &mut dyn VmState,
    id: &str,
    voter_hex: &str,
    weight: u128,
    in_favour: bool,
    by: CastBy,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let key = governance_vote_key(id, voter_hex);
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let mut blob = Vec::with_capacity(18);
    blob.extend_from_slice(&weight.to_le_bytes());
    blob.push(u8::from(in_favour));
    blob.push(u8::from(by == CastBy::Agent));
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    (blob, previous)
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

/// Storage key of the network payout destination governance set for `rail`.
pub fn network_payout_storage_key(rail: &str) -> String {
    format!("network_payout:{rail}")
}

/// Consensus-state key of the time an identity was first registered.
pub fn identity_registered_at_key(did: &str) -> String {
    format!("identity_registered_at:{did}")
}

/// When `did` was first registered, in consensus time (ms), if it was.
pub fn identity_registered_at(state: &dyn VmState, did: &str) -> Option<i64> {
    let raw = state.get_storage(&SYSTEM_ADDRESS, identity_registered_at_key(did).as_bytes())?;
    Some(i64::from_le_bytes(raw.get(..8)?.try_into().ok()?))
}

/// Whether governance has revoked `did` in consensus state.
pub fn identity_is_revoked(state: &dyn VmState, did: &str) -> bool {
    state
        .get_storage(&SYSTEM_ADDRESS, &identity_revocation_key(did))
        .is_some()
}

/// Consensus-state key of the last enacted policy change of `kind`
/// (see [`crate::governance::policy_kind`]).
pub fn policy_storage_key(kind: &str) -> String {
    format!("policy:{kind}")
}

/// The last enacted policy change of `kind`, with the proposal that decided
/// it.
pub fn read_policy(state: &dyn VmState, kind: &str) -> Option<crate::governance::PolicyEnactedLog> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, policy_storage_key(kind).as_bytes())?;
    serde_json::from_slice(&blob).ok()
}

/// The network payout destination governance set for `rail`, if any.
pub fn network_payout(state: &dyn VmState, rail: &str) -> Option<String> {
    let bytes = state.get_storage(&SYSTEM_ADDRESS, network_payout_storage_key(rail).as_bytes())?;
    String::from_utf8(bytes).ok().filter(|d| !d.is_empty())
}

/// Slash math. Returns the amount drained from the bond vault
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
/// Readers decode it with [`decode_kill_switch_log`].
/// The kill-switch receipt `receipt_id_hex`, as the VM holds it.
pub fn read_kill_switch_receipt(
    state: &dyn VmState,
    receipt_id_hex: &str,
) -> Option<KillSwitchReceipt> {
    let blob = state.get_storage(
        &SYSTEM_ADDRESS,
        killswitch_storage_key(receipt_id_hex).as_bytes(),
    )?;
    serde_json::from_slice(&blob).ok()
}

/// `(agent_did, controller_did, receipt_id_hex)` of a kill-switch log's data,
/// the inverse of the layout written at execution.
pub fn decode_kill_switch_log(data: &[u8]) -> Option<(String, String, String)> {
    let take = |d: &[u8], at: usize| -> Option<(String, usize)> {
        let len = u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?) as usize;
        let s = std::str::from_utf8(d.get(at + 4..at + 4 + len)?)
            .ok()?
            .to_owned();
        Some((s, at + 4 + len))
    };
    let (agent, at) = take(data, 0)?;
    let (controller, at) = take(data, at)?;
    let id: &[u8] = data.get(at..)?;
    (id.len() == 32).then(|| (agent, controller, hex::encode(id)))
}

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
/// Storage key of the end (ms, i64 LE) of an agent's latest pause.
fn agent_pause_key(agent_did: &str) -> String {
    format!("agent_paused:{}", agent_did)
}

/// Whether `agent_did`'s bond is frozen at `now_ms`: a pause has not ended, or
/// the agent is quarantined.
pub fn agent_bond_frozen(state: &dyn VmState, agent_did: &str, now_ms: i64) -> bool {
    agent_paused(state, agent_did, now_ms)
        || agent_audit::read_agent_quarantine(state, agent_did).is_some()
}

/// Whether `agent_did`'s controller paused it until after `now_ms`. A paused
/// agent neither acts nor pays, and its bond stays.
pub fn agent_paused(state: &dyn VmState, agent_did: &str, now_ms: i64) -> bool {
    state
        .get_storage(&SYSTEM_ADDRESS, agent_pause_key(agent_did).as_bytes())
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .is_some_and(|b| i64::from_le_bytes(b) > now_ms)
}

/// The controller `agent_did` answers to on chain: the one its terms name,
/// or, for an agent without terms, the one its bond names.
pub(super) fn agent_controller_on_chain(
    state: &dyn VmState,
    agent_did: &str,
) -> Result<Option<String>> {
    if let Some(stored) = agent_terms::read_agent_terms(state, agent_did) {
        return Ok(Some(stored.terms.controller_did));
    }
    Ok(read_bond_marker(state, agent_did)?.and_then(|m| {
        m.get("controller_did")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }))
}

fn read_bond_marker(state: &dyn VmState, agent_did: &str) -> Result<Option<serde_json::Value>> {
    match state.get_storage(&SYSTEM_ADDRESS, bond_storage_key(agent_did).as_bytes()) {
        Some(blob) if !blob.is_empty() => serde_json::from_slice(&blob)
            .map(Some)
            .map_err(|e| VmError::Internal(format!("decode bond marker: {}", e))),
        _ => Ok(None),
    }
}

/// Refuse a control action on `agent_did` (pause, quarantine, terminate,
/// lift, revoke) unless `from` is its controller, and return the controller.
/// An agent with terms answers to the wallet its terms' controller's identity
/// is registered with, whoever posted its bond. An agent without terms
/// answers to the account that posted its bond. An agent with neither has no
/// controller on chain and nobody controls it directly.
pub(crate) fn authorize_agent_controller(
    state: &dyn VmState,
    from: &[u8],
    agent_did: &str,
) -> Result<String> {
    let refused = || {
        VmError::InvalidTransaction(format!(
            "only {}'s controller may pause, quarantine, terminate, lift or revoke it",
            agent_did
        ))
    };
    if let Some(stored) = agent_terms::read_agent_terms(state, agent_did) {
        let controller = stored.terms.controller_did;
        return if identity_did_of(state, from).as_deref() == Some(controller.as_str()) {
            Ok(controller)
        } else {
            Err(refused())
        };
    }
    let Some(marker) = read_bond_marker(state, agent_did)? else {
        return Err(VmError::InvalidTransaction(format!(
            "{} has no controller on chain: it has neither terms nor a bond",
            agent_did
        )));
    };
    if marker.get("owner").and_then(|v| v.as_str()) != Some(hex::encode(from).as_str()) {
        return Err(refused());
    }
    marker
        .get("controller_did")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| VmError::Internal("bond marker missing controller_did".to_string()))
}

/// [`authorize_agent_controller`], also refusing a transaction that names a
/// controller other than the one on chain.
fn require_agent_controller(
    state: &dyn VmState,
    from: &[u8],
    agent_did: &str,
    controller_did: &str,
) -> Result<()> {
    let controller = authorize_agent_controller(state, from, agent_did)?;
    if controller != controller_did {
        return Err(VmError::InvalidTransaction(format!(
            "{} is controlled by {}, not {}",
            agent_did, controller, controller_did
        )));
    }
    Ok(())
}

/// Refuse a bond post unless `tx` comes from whoever answers for the agent.
/// An agent with terms is bonded by the controller its terms name, from the
/// wallet that controller's identity is registered with. An agent without
/// terms is bonded by the root its DID is derived under, from that root's
/// wallet. An autonomous agent (its own controller) posts before it is
/// registered, so it signs with the device key its DID derives from.
fn require_bond_poster(
    state: &dyn VmState,
    tx: &VmTransaction,
    agent_did: &str,
    controller_did: &str,
) -> Result<()> {
    if let Some(stored) = agent_terms::read_agent_terms(state, agent_did) {
        let controller = stored.terms.controller_did;
        if controller_did != controller
            || identity_did_of(state, &tx.from).as_deref() != Some(controller.as_str())
        {
            return Err(VmError::InvalidTransaction(format!(
                "{} is bonded by its controller {}, from the wallet its identity is registered with",
                agent_did, controller
            )));
        }
        return Ok(());
    }
    if agent_did == controller_did {
        let derives = tx.public_key.as_deref().is_some_and(|key| {
            let sec1 = [&[0x04u8][..], key].concat();
            tenzro_crypto::composite::controls_account(key, &tx.from)
                && (tenzro_types::did_derivation::machine_did(key) == agent_did
                    || tenzro_types::did_derivation::machine_did(&sec1) == agent_did)
        });
        if !derives {
            return Err(VmError::InvalidTransaction(format!(
                "{agent_did} posts its own bond, signed with the device key its DID derives from"
            )));
        }
        return Ok(());
    }
    if !tenzro_types::identity::is_delegated_under(agent_did, controller_did)
        || identity_did_of(state, &tx.from).as_deref() != Some(controller_did)
    {
        return Err(VmError::InvalidTransaction(format!(
            "{agent_did} is bonded by the root it is derived under, from the wallet that root is registered with"
        )));
    }
    Ok(())
}

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
/// The sender's nonce stands in for the height, so the id is fixed by the
/// transaction alone.
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

// ---- Escrow lifecycle --------------------------------------------------------
//
// One implementation for every payer: an account submitting its own signed
// `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow`, and a delegated agent
// whose wallet pays through an `AgentAct` within its terms. Gas is the
// caller's concern; these move only the escrowed value.

fn require_balance(state: &dyn VmState, account: &[u8], required: u128) -> Result<()> {
    let available = state.get_balance(account);
    if available < required {
        return Err(VmError::InsufficientBalance {
            required,
            available,
        });
    }
    Ok(())
}

/// Charge `tx.from` the gas and advance its nonce.
fn charge_and_advance(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_cost: u128,
) -> Vec<StateChange> {
    let balance = state.get_balance(&tx.from);
    let new_balance = balance.saturating_sub(gas_cost);
    state.set_balance(&tx.from, new_balance);
    let old_nonce = state.get_nonce(&tx.from);
    state.set_nonce(&tx.from, old_nonce + 1);
    vec![
        StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some(new_balance.to_le_bytes().to_vec()),
        ),
        StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ),
    ]
}

pub(crate) fn read_escrow_record(
    state: &dyn VmState,
    escrow_id: &[u8; 32],
) -> Result<(String, Vec<u8>, EscrowAccount)> {
    let escrow_id_hex = hex::encode(escrow_id);
    let storage_key = escrow_storage_key(&escrow_id_hex);
    let blob = state
        .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
        .ok_or_else(|| {
            VmError::InvalidTransaction(format!("Escrow {} not found", escrow_id_hex))
        })?;
    let escrow: EscrowAccount = serde_json::from_slice(&blob).map_err(|e| {
        VmError::Internal(format!(
            "Failed to decode escrow record {}: {}",
            escrow_id_hex, e
        ))
    })?;
    Ok((storage_key, blob, escrow))
}

/// Move `amount` of an escrow's asset from its vault to `to`, with no fee.
fn release_from_vault(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    escrow: &EscrowAccount,
    to: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let token = payment_settlement::asset_token(state, escrow.asset_id.as_str())?;
    let vault = derive_vault_address(escrow_id).as_bytes().to_vec();
    payment_settlement::move_asset(state, &token, &vault, to, amount, now_ms, changes)
}

/// Records what `escrow`'s vault still owes by its record (the amount less
/// what was claimed while it is funded, nothing once it is settled), for the
/// end-of-block vault check of `module`.
pub(crate) fn record_escrow_owed(
    state: &mut dyn VmState,
    module: crate::invariant_monitor::GuardedModule,
    escrow: &EscrowAccount,
) -> Result<()> {
    let id: [u8; 32] = hex::decode(&escrow.escrow_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| VmError::Internal("an escrow id is 32 bytes".to_string()))?;
    let token = payment_settlement::asset_token(state, escrow.asset_id.as_str())?;
    let owed = if escrow.status == EscrowStatus::Funded {
        escrow.amount.saturating_sub(escrow.claimed)
    } else {
        0
    };
    crate::invariant_monitor::record_owed(
        state,
        module,
        derive_vault_address(&id).as_bytes(),
        &token,
        owed,
    );
    Ok(())
}

fn write_escrow_record(
    state: &mut dyn VmState,
    storage_key: &str,
    old_blob: Option<Vec<u8>>,
    escrow: &EscrowAccount,
) -> Result<StateChange> {
    let blob = serde_json::to_vec(escrow)
        .map_err(|e| VmError::Internal(format!("Failed to serialize escrow record: {}", e)))?;
    state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());
    record_escrow_owed(
        state,
        crate::invariant_monitor::GuardedModule::Escrow,
        escrow,
    )?;
    Ok(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        storage_key.as_bytes().to_vec(),
        old_blob,
        Some(blob),
    ))
}

/// Lock `payload.amount` from `payer` in a new escrow whose id derives from
/// `(payer, nonce)`: the vault is credited and an `EscrowAccount{Funded}`
/// is stored at `escrow:<hex(escrow_id)>` under `SYSTEM_ADDRESS`. `payer`
/// must hold the amount plus `reserve` (the gas its caller still owes).
/// Emits `EscrowCreated` carrying `(escrow_id || payer || vault || reference)`,
/// the reference only when the payer set one.
pub(crate) fn lock_escrow(
    state: &mut dyn VmState,
    payer: &[u8],
    nonce: u64,
    payload: &CreateEscrowPayload,
    reserve: u128,
    now_ms: i64,
) -> Result<([u8; 32], Vec<StateChange>, Log)> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Escrow,
    )?;
    if payload.amount == 0 {
        return Err(VmError::InvalidTransaction(
            "Escrow amount must be greater than zero".to_string(),
        ));
    }
    if let ReleaseConditions::Stream {
        rate_per_epoch,
        epoch_ms,
    } = payload.release_conditions
        && (rate_per_epoch == 0 || epoch_ms == 0 || rate_per_epoch > payload.amount)
    {
        return Err(VmError::InvalidTransaction(
            "a stream pays a positive rate, at most its amount, over a positive epoch".to_string(),
        ));
    }
    if let ReleaseConditions::QuorumAttestation { claim, verifiers } = &payload.release_conditions {
        if claim.is_empty() || claim.len() > MAX_RELEASE_CLAIM_LEN {
            return Err(VmError::InvalidTransaction(format!(
                "quorum release claim must be 1..={MAX_RELEASE_CLAIM_LEN} bytes"
            )));
        }
        verifiers.validate("release verifiers").map_err(|e| {
            VmError::InvalidTransaction(format!("quorum release committee refused: {e}"))
        })?;
    }
    let payer_addr = address_from_tx_from(payer)?;
    let escrow_id = derive_escrow_id(&payer_addr, nonce);
    let escrow_id_hex = hex::encode(escrow_id);
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
    // An escrow holds TNZO or any token, the payer keeping `reserve` TNZO
    // for the gas its caller still owes; a token escrow carries its USD
    // price so its claims pay the settlement fee in TNZO. An escrow only a
    // named executor releases is never claimed, so it needs no price.
    let token = payment_settlement::asset_token(state, payload.asset_id.as_str())?;
    let tnzo = token == crate::token_ledger::tnzo_id();
    let claimable = !matches!(
        payload.release_conditions,
        ReleaseConditions::Executor { .. }
    );
    if !tnzo && claimable && payload.usd_e6 == 0 {
        return Err(VmError::InvalidTransaction(
            "an escrow of a token other than TNZO carries its USD price".to_string(),
        ));
    }
    let required = if tnzo {
        payload
            .amount
            .checked_add(reserve)
            .ok_or_else(|| VmError::Internal("Escrow create cost overflow".to_string()))?
    } else {
        reserve
    };
    require_balance(state, payer, required)?;

    let vault_bytes = derive_vault_address(&escrow_id).as_bytes().to_vec();
    let mut changes = Vec::new();
    payment_settlement::move_asset(
        state,
        &token,
        payer,
        &vault_bytes,
        payload.amount,
        now_ms,
        &mut changes,
    )?;
    let escrow = EscrowAccount {
        escrow_id: escrow_id_hex,
        payer: payer_addr,
        payee: Address::new(pad_address_32(payload.payee.as_bytes())?),
        amount: payload.amount,
        asset_id: payload.asset_id.clone(),
        usd_e6: payload.usd_e6,
        created_at: Timestamp::new(now_ms),
        expires_at: Timestamp::new(payload.expires_at as i64),
        status: EscrowStatus::Funded,
        release_conditions: payload.release_conditions.clone(),
        claimed: 0,
        approved_by: None,
        reference: payload.reference,
    };
    changes.push(write_escrow_record(state, &storage_key, None, &escrow)?);
    payment_settlement::note_network_share_lock(state, &escrow_id, &escrow, &mut changes);
    let review = escrow_review_ms(state, &escrow);
    schedule_escrow_record(state, &escrow_id, review, &mut changes)?;
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![b"EscrowCreated".to_vec()],
        [
            escrow_id.as_slice(),
            payer,
            &vault_bytes,
            payload.reference.as_ref().map_or(&[][..], |r| &r[..]),
        ]
        .concat(),
    );
    Ok((escrow_id, changes, log))
}

/// Release a funded, unexpired escrow: what remains in the vault (the
/// amount less voucher claims already paid) goes to the payee. Who may
/// release is the escrow's kind: its payer (consumer, timeout, hash-lock,
/// stream and custom escrows), its payee (a provider escrow), its payer or
/// named executor, or anyone presenting a threshold of its committee's
/// signatures. An escrow both parties approve takes one release transaction
/// from each: the first is recorded as an approval (`EscrowApproved`), the
/// second releases. Every party authorises with its own signed transaction;
/// no key carried in `proof` stands for a party. The release is a settlement
/// like any claim: the payee is paid less the settlement fee, and the TNZO
/// the fee burned is returned for the transaction to declare. Emits
/// `EscrowReleased`.
pub(crate) fn release_escrow(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    proof: &ServiceProof,
    caller: &[u8],
    now_ms: i64,
) -> Result<(Vec<StateChange>, Log, u128)> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Escrow,
    )?;
    let (storage_key, blob, mut escrow) = read_escrow_record(state, escrow_id)?;
    let escrow_id_hex = &escrow.escrow_id.clone();
    let quorum = match &escrow.release_conditions {
        ReleaseConditions::QuorumAttestation { claim, verifiers } => {
            Some((claim.clone(), verifiers.clone()))
        }
        _ => None,
    };
    let caller_addr = address_from_tx_from(caller)?;
    let executor = match &escrow.release_conditions {
        ReleaseConditions::Executor { executor } => {
            Some(Address::new(pad_address_32(executor.as_bytes())?))
        }
        _ => None,
    };
    let may_release = match &escrow.release_conditions {
        ReleaseConditions::QuorumAttestation { .. } => true,
        ReleaseConditions::Executor { .. } => {
            caller_addr == escrow.payer || executor == Some(caller_addr)
        }
        ReleaseConditions::ProviderSignature => caller_addr == escrow.payee,
        ReleaseConditions::BothSignatures => {
            caller_addr == escrow.payer || caller_addr == escrow.payee
        }
        _ => caller_addr == escrow.payer,
    };
    if !may_release {
        return Err(VmError::InvalidTransaction(format!(
            "EscrowUnauthorized: a {:?} escrow is released by {}",
            escrow.release_conditions,
            match &escrow.release_conditions {
                ReleaseConditions::Executor { .. } => "its payer or its named executor",
                ReleaseConditions::ProviderSignature => "its payee",
                ReleaseConditions::BothSignatures => "its payer and its payee together",
                _ => "its payer",
            }
        )));
    }
    if escrow.status != EscrowStatus::Funded {
        return Err(VmError::InvalidTransaction(format!(
            "Escrow {} is not in Funded state ({:?})",
            escrow_id_hex, escrow.status
        )));
    }
    if now_ms > escrow.expires_at.0 {
        return Err(VmError::InvalidTransaction(format!(
            "Escrow {} has expired",
            escrow_id_hex
        )));
    }
    match quorum {
        Some((claim, verifiers)) => verify_quorum_release(escrow_id, &claim, &verifiers, proof)?,
        None => verify_release_conditions(&escrow.release_conditions, proof).map_err(|e| {
            VmError::InvalidTransaction(format!("Proof verification failed: {}", e))
        })?,
    }
    // Both parties approve: the first party's transaction is recorded, the
    // other party's releases.
    if escrow.release_conditions == ReleaseConditions::BothSignatures {
        match escrow.approved_by {
            None => {
                escrow.approved_by = Some(caller_addr);
                let change = write_escrow_record(state, &storage_key, Some(blob), &escrow)?;
                let log = Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"EscrowApproved".to_vec()],
                    [escrow_id.as_slice(), caller_addr.as_bytes()].concat(),
                );
                return Ok((vec![change], log, 0));
            }
            Some(first) if first == caller_addr => {
                return Err(VmError::InvalidTransaction(format!(
                    "Escrow {escrow_id_hex} already has this party's approval; the other party releases it"
                )));
            }
            Some(_) => {}
        }
    }

    let remaining = escrow.amount - escrow.claimed;
    let payee_bytes = escrow.payee.as_bytes().to_vec();
    let mut changes = Vec::new();
    let earning = payment_settlement::escrow_earning(&*state, &payee_bytes, false, None);
    let settled = payment_settlement::pay_from_vault(
        state,
        escrow_id,
        &escrow,
        &payee_bytes,
        remaining,
        now_ms,
        &earning,
        &mut changes,
    )?;
    economy::count_settlement(state, 1, &mut changes)?;
    escrow.claimed = escrow.amount;
    escrow.status = EscrowStatus::Released;
    changes.push(write_escrow_record(
        state,
        &storage_key,
        Some(blob),
        &escrow,
    )?);
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![b"EscrowReleased".to_vec()],
        [
            escrow_id.as_slice(),
            payee_bytes.as_slice(),
            &remaining.to_le_bytes(),
        ]
        .concat(),
    );
    Ok((changes, log, settled.burned))
}

/// Refund an escrow. The payer may refund; a stream's payee may also close
/// it, which only waives what has not yet accrued. A stream may be stopped
/// at any time (what has accrued goes to the payee); any other escrow
/// refunds only after it expires, so a payee holding vouchers can claim
/// first. Once an escrow is past its expiry by the governed grace, anyone
/// may close it, so none stays open because both parties walked away. The
/// remainder returns to the payer, whoever closed it. Emits
/// `EscrowRefunded`.
pub(crate) fn refund_escrow(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    caller: &[u8],
    now_ms: i64,
) -> Result<(Vec<StateChange>, Log, u128)> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Escrow,
    )?;
    let (storage_key, blob, mut escrow) = read_escrow_record(state, escrow_id)?;
    let caller_addr = address_from_tx_from(caller)?;
    let is_stream = matches!(escrow.release_conditions, ReleaseConditions::Stream { .. });
    let grace_ms =
        (network_param(state, ESCROW_CLOSE_GRACE_PARAM) as i64).saturating_mul(3_600_000);
    let abandoned = now_ms > escrow.expires_at.0.saturating_add(grace_ms);
    if escrow.payer != caller_addr && !(is_stream && escrow.payee == caller_addr) && !abandoned {
        return Err(VmError::InvalidTransaction(
            "EscrowUnauthorized: only payer can refund".to_string(),
        ));
    }
    if escrow.status != EscrowStatus::Funded {
        return Err(VmError::InvalidTransaction(format!(
            "Escrow {} is not in Funded state ({:?})",
            escrow.escrow_id, escrow.status
        )));
    }
    let streamed = payment_settlement::stream_due(&*state, &escrow, now_ms, true);
    if streamed.is_none() && now_ms <= escrow.expires_at.0 {
        return Err(VmError::InvalidTransaction(
            "EscrowNotExpired: refund disallowed before expiry".to_string(),
        ));
    }
    let accrued = streamed.unwrap_or(0);
    let remaining = escrow.amount - escrow.claimed - accrued;
    let mut changes = Vec::new();
    let mut burned = 0u128;
    if accrued > 0 {
        // What a stream paid out is settled like a claim: it pays the
        // settlement fee, so closing a stream is no way around it.
        let payee_bytes = escrow.payee.as_bytes().to_vec();
        let earning = payment_settlement::escrow_earning(&*state, &payee_bytes, true, None);
        let settled = payment_settlement::pay_from_vault(
            state,
            escrow_id,
            &escrow,
            &payee_bytes,
            accrued,
            now_ms,
            &earning,
            &mut changes,
        )?;
        economy::count_settlement(state, 1, &mut changes)?;
        burned = settled.burned;
        escrow.claimed += accrued;
    }
    let payer_bytes = escrow.payer.as_bytes().to_vec();
    release_from_vault(
        state,
        escrow_id,
        &escrow,
        &payer_bytes,
        remaining,
        now_ms,
        &mut changes,
    )?;
    escrow.status = EscrowStatus::Refunded;
    changes.push(write_escrow_record(
        state,
        &storage_key,
        Some(blob),
        &escrow,
    )?);
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![b"EscrowRefunded".to_vec()],
        [
            escrow_id.as_slice(),
            payer_bytes.as_slice(),
            &remaining.to_le_bytes(),
        ]
        .concat(),
    );
    Ok((changes, log, burned))
}

/// Derive a deterministic 32-byte escrow id:
/// `SHA-256("tenzro/escrow/id" || payer || nonce_le)`.
pub fn derive_escrow_id(payer: &Address, nonce: u64) -> [u8; 32] {
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
        // A call with a posted USD price is refused up front when its sender
        // cannot pay it, and pays it (burned) only when it succeeds.
        let posted = economy::posted_fee(state, selector);
        if posted > 0 && state.get_balance(&tx.from) < posted {
            return Err(VmError::InvalidTransaction(format!(
                "this call's posted fee of {posted} wei is more than the sender holds"
            )));
        }

        let out = match selector {
            SELECTOR_STAKE => self.execute_stake(tx, state, &mut gas_meter),
            SELECTOR_GOVERNANCE_PROPOSE => self.execute_propose(tx, state, &mut gas_meter).await,
            SELECTOR_GOVERNANCE_VOTE => self.execute_vote(tx, state, &mut gas_meter).await,
            SELECTOR_GOVERNANCE_PAUSE => {
                self.execute_governance_pause(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_GOVERNANCE_FEATURE_PAUSE => {
                feature_pause::execute_feature_pause(tx, state, &mut gas_meter)
            }
            SELECTOR_GOVERNANCE_VETO => {
                self.execute_governance_veto(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_GOVERNANCE_EXECUTE => {
                self.execute_governance_execute(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_GOVERNANCE_VETO_SIGNAL => {
                veto_escrow::execute_veto_signal(tx, state, &mut gas_meter)
            }
            SELECTOR_GOVERNANCE_VETO_WITHDRAW => {
                veto_escrow::execute_veto_withdraw(tx, state, &mut gas_meter)
            }
            SELECTOR_GOVERNANCE_CONCERN => veto_escrow::execute_concern(tx, state, &mut gas_meter),
            SELECTOR_UPGRADE_READY => upgrade::execute_upgrade_ready(tx, state, &mut gas_meter),
            SELECTOR_SECURITY_DISCLOSURE => {
                upgrade::execute_security_disclosure(tx, state, &mut gas_meter)
            }
            SELECTOR_ESCROW_CREATE => self.execute_escrow_create(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_RELEASE => self.execute_escrow_release(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_REFUND => self.execute_escrow_refund(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_CLAIM => self.execute_escrow_claim(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_PREIMAGE_CLAIM => {
                self.execute_escrow_preimage_claim(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_METER_BOND_POST => {
                self.execute_meter_bond_post(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_METER_BOND_WITHDRAW => {
                self.execute_meter_bond_withdraw(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_METER_DISPUTE => self.execute_meter_dispute(tx, state, &mut gas_meter).await,
            SELECTOR_ESCROW_STREAM_CLAIM => {
                self.execute_escrow_stream_claim(tx, state, &mut gas_meter)
                    .await
            }
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
            SELECTOR_SLA_ATTEST => self.execute_sla_attest(tx, state, &mut gas_meter).await,
            availability_reward::SELECTOR_DECLARE_READINESS_TIER => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                availability_reward::GAS_DECLARE_READINESS_TIER,
                |state, tx, now| {
                    availability_reward::declare_readiness_tier(state, &tx.from, now, &tx.data[4..])
                },
            ),
            economy::SELECTOR_FEE_RATE_SUBMIT => {
                self.execute_fee_rate_submit(tx, state, &mut gas_meter)
            }
            SELECTOR_COMPUTE_CLAIM => self.execute_compute_claim(tx, state, &mut gas_meter).await,
            SELECTOR_REGISTRY => self.execute_registry(tx, state, &mut gas_meter).await,
            SELECTOR_INFERENCE_FAULT => {
                self.execute_inference_fault(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_TRAINING_PROOF => self.execute_training_proof(tx, state, &mut gas_meter).await,
            SELECTOR_BRIDGE => self.execute_bridge(tx, state, &mut gas_meter),
            SELECTOR_SETTLEMENT_PLAN => self.execute_settlement_plan(tx, state, &mut gas_meter),
            SELECTOR_TOKEN => self.execute_token(tx, state, &mut gas_meter),
            SELECTOR_FUNDING => self.execute_funding(tx, state, &mut gas_meter).await,
            SELECTOR_PAY_INSURANCE_CLAIM => {
                self.execute_pay_insurance_claim(tx, state, &mut gas_meter)
            }
            SELECTOR_PAYER_SETTLE => self.execute_payer_settle(tx, state, &mut gas_meter).await,
            SELECTOR_ZK_ATTEST => zk_registry::execute_zk_attest(tx, state, &mut gas_meter),
            SELECTOR_VALIDATOR_REGISTER => {
                self.execute_validator_register(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_INCREASE_VALIDATOR_STAKE => {
                self.execute_increase_validator_stake(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_TREASURY_DEPOSIT => {
                self.execute_treasury_deposit(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_VALIDATOR_EXIT => self.execute_validator_exit(tx, state, &mut gas_meter).await,
            SELECTOR_VALIDATOR_ROTATE_KEY => {
                self.execute_validator_rotate_key(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_CHECKPOINT_EQUIVOCATION => {
                self.execute_checkpoint_equivocation(tx, state, &mut gas_meter)
            }
            SELECTOR_CHECKPOINT_SIGNERS => {
                self.execute_checkpoint_signers(tx, state, &mut gas_meter)
            }
            SELECTOR_BEACON_CONTRIBUTE => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                beacon::GAS_BEACON_CONTRIBUTE,
                |state, tx, now| beacon::contribute(state, &tx.from, now, &tx.data[4..]),
            ),
            SELECTOR_HARDWARE_PROOF => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                hardware_level::proof_gas(&tx.data[4..]),
                |state, tx, now| hardware_level::prove(state, &tx.from, now, &tx.data[4..]),
            ),
            SELECTOR_VALIDATOR_MACHINE => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                validator_machine::GAS_VALIDATOR_MACHINE,
                |state, tx, _| validator_machine::register(state, &tx.from, &tx.data[4..]),
            ),
            SELECTOR_KEY_RELEASE => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                key_release::GAS_KEY_RELEASE,
                |state, tx, now| key_release::apply(state, &tx.from, now, &tx.data[4..]),
            ),
            SELECTOR_ATTACH_MACHINE_ATTESTATION => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                machine_attestation::GAS_ATTACH_MACHINE_ATTESTATION,
                |state, tx, _| machine_attestation::attach(state, &tx.from, &tx.data[4..]),
            ),
            SELECTOR_SPONSORED_BOND => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                sponsored_bond::GAS_SPONSORED_BOND,
                |state, tx, now| sponsored_bond::execute(state, &tx.from, &tx.data[4..], now),
            ),
            SELECTOR_DA_RETENTION => {
                let op: tenzro_types::da_retention::DaRetentionOp =
                    serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid DaRetention payload: {e}"))
                    })?;
                self.execute_system_op(
                    tx,
                    state,
                    &mut gas_meter,
                    da_retention::GAS_DA_RECORD,
                    |state, tx, now| da_retention::apply(state, &tx.from, now, &op),
                )
            }
            SELECTOR_ACCOUNT_KEYS => {
                let op: tenzro_types::account_signature::AccountKeysOp =
                    serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid AccountKeys payload: {e}"))
                    })?;
                self.execute_system_op(
                    tx,
                    state,
                    &mut gas_meter,
                    crate::account_keys::GAS_ACCOUNT_KEYS,
                    |state, tx, _now| crate::account_keys::apply(state, tx, &op),
                )
            }
            SELECTOR_IDENTITY_REVOKE => {
                let op: tenzro_types::identity::IdentityRevocationOp =
                    serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid RevokeIdentity payload: {e}"))
                    })?;
                let gas = identity_revocation::gas(state, &op);
                self.execute_system_op(tx, state, &mut gas_meter, gas, |state, _tx, now| {
                    identity_revocation::apply(state, &op, now)
                })
            }
            SELECTOR_BRIDGE_WATCHER => {
                let op: bridge_watcher::Op =
                    serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid BridgeWatcher payload: {e}"))
                    })?;
                self.execute_system_op(
                    tx,
                    state,
                    &mut gas_meter,
                    bridge_watcher::GAS_BRIDGE_WATCHER,
                    |state, tx, now| bridge_watcher::apply(state, tx, &op, now),
                )
            }
            SELECTOR_ACCOUNT_OUTFLOW => {
                let op: crate::account_outflow::Op = serde_json::from_slice(&tx.data[4..])
                    .map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid AccountOutflow payload: {e}"))
                    })?;
                self.execute_system_op(
                    tx,
                    state,
                    &mut gas_meter,
                    crate::account_outflow::GAS_ACCOUNT_OUTFLOW,
                    |state, tx, now| crate::account_outflow::apply(state, tx, &op, now),
                )
            }
            SELECTOR_IDENTITY_SERVICES => {
                let op: tenzro_types::did_services::IdentityServiceOp =
                    serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                        VmError::InvalidTransaction(format!(
                            "Invalid IdentityServices payload: {e}"
                        ))
                    })?;
                self.execute_system_op(
                    tx,
                    state,
                    &mut gas_meter,
                    did_services::GAS_IDENTITY_SERVICES,
                    |state, _tx, now| did_services::apply(state, &op, now),
                )
            }
            SELECTOR_KEYSTORE_UPDATE => {
                let update: tenzro_types::keystore::KeystoreUpdate =
                    serde_json::from_slice(&tx.data[4..]).map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid KeystoreUpdate payload: {e}"))
                    })?;
                self.execute_system_op(
                    tx,
                    state,
                    &mut gas_meter,
                    crate::keystore::GAS_KEYSTORE_UPDATE,
                    |state, tx, now| crate::keystore::apply(state, tx, &update, now.max(0) as u64),
                )
            }
            SELECTOR_AGENT_AUDIT_COMMIT => {
                self.execute_agent_audit_commit(tx, state, &mut gas_meter)
            }
            SELECTOR_LIFT_AGENT_QUARANTINE => {
                self.execute_lift_agent_quarantine(tx, state, &mut gas_meter)
            }
            SELECTOR_REVOKE_DELEGATED_AGENT => {
                self.execute_revoke_delegated_agent(tx, state, &mut gas_meter)
            }
            SELECTOR_SET_AGENT_TERMS => self.execute_set_agent_terms(tx, state, &mut gas_meter),
            SELECTOR_RECLAIM_AGENT_FUNDS => {
                self.execute_reclaim_agent_funds(tx, state, &mut gas_meter)
            }
            SELECTOR_SET_AGENT_TOPUP => self.execute_set_agent_topup(tx, state, &mut gas_meter),
            SELECTOR_TOPUP_AGENT => self.execute_topup_agent(tx, state, &mut gas_meter),
            SELECTOR_AGENT_ACT => self.execute_agent_act(tx, state, &mut gas_meter),
            SELECTOR_PAYMENT => self.execute_payment_op(tx, state, &mut gas_meter),
            SELECTOR_REMOTE_GRANT_SETTLE => {
                self.execute_remote_grant_settle(tx, state, &mut gas_meter)
            }
            SELECTOR_AGENT_AUDIT_FLAG => self.execute_agent_audit_flag(tx, state, &mut gas_meter),
            SELECTOR_HANDOVER_DUTY => self.execute_system_op(
                tx,
                state,
                &mut gas_meter,
                duty::GAS_HANDOVER_DUTY,
                |state, tx, now| duty::handover_op(state, &tx.from, now, &tx.data[4..]),
            ),
            SELECTOR_VALIDATOR_UPDATE_METADATA => {
                self.execute_validator_update_metadata(tx, state, &mut gas_meter)
                    .await
            }
            SELECTOR_IDENTITY_REGISTER => {
                self.execute_identity_register(tx, state, &mut gas_meter)
                    .await
            }
            _ => Err(VmError::InvalidTransaction(format!(
                "Unknown native function selector: {:?}",
                selector
            ))),
        };
        match out {
            Ok(r) if r.success && posted > 0 => {
                economy::charge_posted_fee(state, &tx.from, posted, r)
            }
            other => other,
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
            SELECTOR_STAKE => role_stake::GAS_STAKE,
            SELECTOR_GOVERNANCE_PROPOSE => GAS_PROPOSE,
            SELECTOR_GOVERNANCE_VOTE => GAS_VOTE,
            SELECTOR_GOVERNANCE_EXECUTE => GAS_GOVERNANCE_EXECUTE,
            SELECTOR_GOVERNANCE_VETO => GAS_GOVERNANCE_EXECUTE,
            SELECTOR_GOVERNANCE_PAUSE => GAS_GOVERNANCE_EXECUTE,
            SELECTOR_GOVERNANCE_VETO_SIGNAL
            | SELECTOR_GOVERNANCE_VETO_WITHDRAW
            | SELECTOR_GOVERNANCE_CONCERN => veto_escrow::GAS_HOLDER_GOVERNANCE,
            SELECTOR_UPGRADE_READY => upgrade::GAS_UPGRADE_READY,
            SELECTOR_SECURITY_DISCLOSURE => upgrade::GAS_SECURITY_DISCLOSURE,
            SELECTOR_INCREASE_VALIDATOR_STAKE => GAS_INCREASE_VALIDATOR_STAKE,
            SELECTOR_TREASURY_DEPOSIT => GAS_TREASURY_DEPOSIT,
            SELECTOR_ESCROW_CREATE => GAS_ESCROW_CREATE,
            SELECTOR_ESCROW_RELEASE => GAS_ESCROW_RELEASE,
            SELECTOR_ESCROW_REFUND => GAS_ESCROW_REFUND,
            SELECTOR_ESCROW_PREIMAGE_CLAIM => payment_settlement::GAS_ESCROW_PREIMAGE_CLAIM,
            SELECTOR_ESCROW_STREAM_CLAIM => payment_settlement::GAS_ESCROW_STREAM_CLAIM,
            SELECTOR_METER_BOND_POST => meter_bond::GAS_METER_BOND_POST,
            SELECTOR_METER_BOND_WITHDRAW => meter_bond::GAS_METER_BOND_WITHDRAW,
            SELECTOR_METER_DISPUTE => meter_bond::GAS_METER_DISPUTE,
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
            SELECTOR_SLA_ATTEST => GAS_SLA_ATTEST + GAS_SLA_OUTCOME * MAX_SLA_OUTCOMES as u64,
            availability_reward::SELECTOR_DECLARE_READINESS_TIER => {
                availability_reward::GAS_DECLARE_READINESS_TIER
            }
            economy::SELECTOR_FEE_RATE_SUBMIT => economy::GAS_FEE_RATE_SUBMIT,
            SELECTOR_COMPUTE_CLAIM => GAS_COMPUTE_CLAIM,
            SELECTOR_REGISTRY => GAS_REGISTRY,
            SELECTOR_INFERENCE_FAULT => {
                GAS_INFERENCE_FAULT + GAS_INFERENCE_FAULT_BYTE * tx.data.len() as u64
            }
            SELECTOR_TRAINING_PROOF => {
                GAS_TRAINING_PROOF + GAS_TRAINING_PROOF_BYTE * tx.data.len() as u64
            }
            SELECTOR_BRIDGE => serde_json::from_slice(&tx.data[4..])
                .map(|op| bridge_gas(&op))
                .unwrap_or(bridge::GAS_BRIDGE),
            SELECTOR_SETTLEMENT_PLAN => serde_json::from_slice(&tx.data[4..])
                .map(|op| settlement_plan_gas(&op))
                .unwrap_or(GAS_SETTLEMENT_PLAN),
            SELECTOR_TOKEN => token::GAS_TOKEN,
            SELECTOR_FUNDING => GAS_FUNDING,
            SELECTOR_PAY_INSURANCE_CLAIM => GAS_PAY_INSURANCE_CLAIM,
            SELECTOR_PAYER_SETTLE => GAS_PAYER_SETTLE,
            SELECTOR_ZK_ATTEST => zk_registry::zk_attest_gas(tx.data.len().saturating_sub(4)),
            SELECTOR_VALIDATOR_REGISTER => GAS_VALIDATOR_REGISTER,
            SELECTOR_VALIDATOR_EXIT => GAS_VALIDATOR_EXIT,
            SELECTOR_VALIDATOR_ROTATE_KEY => GAS_VALIDATOR_ROTATE_KEY,
            SELECTOR_CHECKPOINT_EQUIVOCATION => GAS_CHECKPOINT_EQUIVOCATION,
            SELECTOR_CHECKPOINT_SIGNERS => GAS_CHECKPOINT_SIGNERS,
            SELECTOR_BEACON_CONTRIBUTE => beacon::GAS_BEACON_CONTRIBUTE,
            SELECTOR_HARDWARE_PROOF => hardware_level::proof_gas(&tx.data[4..]),
            SELECTOR_VALIDATOR_MACHINE => validator_machine::GAS_VALIDATOR_MACHINE,
            SELECTOR_KEY_RELEASE => key_release::GAS_KEY_RELEASE,
            SELECTOR_ATTACH_MACHINE_ATTESTATION => {
                machine_attestation::GAS_ATTACH_MACHINE_ATTESTATION
            }
            SELECTOR_SPONSORED_BOND => sponsored_bond::GAS_SPONSORED_BOND,
            SELECTOR_DA_RETENTION => da_retention::GAS_DA_RECORD,
            SELECTOR_ACCOUNT_KEYS => crate::account_keys::GAS_ACCOUNT_KEYS,
            SELECTOR_KEYSTORE_UPDATE => crate::keystore::GAS_KEYSTORE_UPDATE,
            SELECTOR_IDENTITY_SERVICES => did_services::GAS_IDENTITY_SERVICES,
            SELECTOR_ACCOUNT_OUTFLOW => crate::account_outflow::GAS_ACCOUNT_OUTFLOW,
            SELECTOR_BRIDGE_WATCHER => bridge_watcher::GAS_BRIDGE_WATCHER,
            SELECTOR_IDENTITY_REVOKE => identity_revocation::GAS_IDENTITY_REVOKE,
            SELECTOR_AGENT_AUDIT_COMMIT => GAS_AGENT_AUDIT_COMMIT,
            SELECTOR_LIFT_AGENT_QUARANTINE => GAS_LIFT_AGENT_QUARANTINE,
            SELECTOR_REVOKE_DELEGATED_AGENT => GAS_REVOKE_DELEGATED_AGENT,
            SELECTOR_SET_AGENT_TERMS => GAS_SET_AGENT_TERMS,
            SELECTOR_RECLAIM_AGENT_FUNDS => GAS_RECLAIM_AGENT_FUNDS,
            SELECTOR_SET_AGENT_TOPUP => GAS_SET_AGENT_TOPUP,
            SELECTOR_TOPUP_AGENT => GAS_TOPUP_AGENT,
            SELECTOR_AGENT_ACT => GAS_AGENT_ACT,
            SELECTOR_PAYMENT => payment_settlement::GAS_PAYMENT_OP,
            SELECTOR_REMOTE_GRANT_SETTLE => GAS_REMOTE_GRANT_SETTLE,
            SELECTOR_HANDOVER_DUTY => duty::GAS_HANDOVER_DUTY,
            SELECTOR_AGENT_AUDIT_FLAG => {
                GAS_AGENT_AUDIT_FLAG
                    + GAS_AGENT_AUDIT_FINDING * tenzro_types::agent_audit::MAX_FINDINGS as u64
            }
            SELECTOR_VALIDATOR_UPDATE_METADATA => GAS_VALIDATOR_UPDATE_METADATA,
            SELECTOR_IDENTITY_REGISTER => GAS_IDENTITY_REGISTER,
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

    // ---- Governance ---------------------------------------------------------

    /// No two native transactions may share a selector.
    ///
    /// A duplicate is not a compile error — it is an unreachable match arm, so
    /// the second handler silently never runs and the transaction executes as
    /// whichever one was declared first. `SELECTOR_INCREASE_VALIDATOR_STAKE`
    /// was briefly `0x01000030`, already taken by `SELECTOR_VALIDATOR_REGISTER`,
    /// which would have routed a stake increase into registration. Only a
    /// warning caught it.
    #[test]
    fn every_native_selector_is_unique() {
        let selectors: Vec<([u8; 4], &str)> = vec![
            (SELECTOR_STAKE, "stake"),
            (SELECTOR_GOVERNANCE_PROPOSE, "governance_propose"),
            (SELECTOR_GOVERNANCE_VOTE, "governance_vote"),
            (SELECTOR_GOVERNANCE_EXECUTE, "governance_execute"),
            (
                SELECTOR_INCREASE_VALIDATOR_STAKE,
                "increase_validator_stake",
            ),
            (SELECTOR_ESCROW_CREATE, "escrow_create"),
            (SELECTOR_ESCROW_RELEASE, "escrow_release"),
            (SELECTOR_ESCROW_REFUND, "escrow_refund"),
            (SELECTOR_ESCROW_CLAIM, "escrow_claim"),
            (SELECTOR_ESCROW_PREIMAGE_CLAIM, "escrow_preimage_claim"),
            (SELECTOR_ESCROW_STREAM_CLAIM, "escrow_stream_claim"),
            (SELECTOR_METER_BOND_POST, "meter_bond_post"),
            (SELECTOR_METER_BOND_WITHDRAW, "meter_bond_withdraw"),
            (SELECTOR_METER_DISPUTE, "meter_dispute"),
            (SELECTOR_KILLSWITCH_PAUSE, "killswitch_pause"),
            (SELECTOR_KILLSWITCH_QUARANTINE, "killswitch_quarantine"),
            (SELECTOR_KILLSWITCH_TERMINATE, "killswitch_terminate"),
            (SELECTOR_POST_AGENT_BOND, "post_agent_bond"),
            (SELECTOR_INCREASE_AGENT_BOND, "increase_agent_bond"),
            (SELECTOR_WITHDRAW_AGENT_BOND, "withdraw_agent_bond"),
            (SELECTOR_PAY_INSURANCE_CLAIM, "pay_insurance_claim"),
            (SELECTOR_PAYER_SETTLE, "payer_settle"),
            (SELECTOR_POST_COMPUTE_BOND, "post_compute_bond"),
            (SELECTOR_INCREASE_COMPUTE_BOND, "increase_compute_bond"),
            (SELECTOR_WITHDRAW_COMPUTE_BOND, "withdraw_compute_bond"),
            (
                SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL,
                "finalize_compute_bond_withdrawal",
            ),
            (SELECTOR_SLA_ATTEST, "sla_attest"),
            (
                availability_reward::SELECTOR_DECLARE_READINESS_TIER,
                "declare_readiness_tier",
            ),
            (economy::SELECTOR_FEE_RATE_SUBMIT, "fee_rate_submit"),
            (SELECTOR_COMPUTE_CLAIM, "compute_claim"),
            (SELECTOR_REGISTRY, "registry"),
            (SELECTOR_INFERENCE_FAULT, "inference_fault"),
            (SELECTOR_TRAINING_PROOF, "training_proof"),
            (SELECTOR_BRIDGE, "bridge"),
            (SELECTOR_SETTLEMENT_PLAN, "settlement_plan"),
            (SELECTOR_TOKEN, "token"),
            (SELECTOR_GOVERNANCE_VETO_SIGNAL, "governance_veto_signal"),
            (
                SELECTOR_GOVERNANCE_VETO_WITHDRAW,
                "governance_veto_withdraw",
            ),
            (SELECTOR_GOVERNANCE_CONCERN, "governance_concern"),
            (SELECTOR_UPGRADE_READY, "upgrade_ready"),
            (SELECTOR_SECURITY_DISCLOSURE, "security_disclosure"),
            (SELECTOR_VALIDATOR_REGISTER, "validator_register"),
            (SELECTOR_VALIDATOR_EXIT, "validator_exit"),
            (SELECTOR_VALIDATOR_ROTATE_KEY, "validator_rotate_key"),
            (SELECTOR_CHECKPOINT_EQUIVOCATION, "checkpoint_equivocation"),
            (SELECTOR_CHECKPOINT_SIGNERS, "checkpoint_signers"),
            (SELECTOR_BEACON_CONTRIBUTE, "beacon_contribute"),
            (SELECTOR_HARDWARE_PROOF, "hardware_proof"),
            (SELECTOR_VALIDATOR_MACHINE, "validator_machine"),
            (SELECTOR_KEY_RELEASE, "key_release"),
            (
                SELECTOR_ATTACH_MACHINE_ATTESTATION,
                "attach_machine_attestation",
            ),
            (SELECTOR_SPONSORED_BOND, "sponsored_bond"),
            (SELECTOR_DA_RETENTION, "da_retention"),
            (SELECTOR_ACCOUNT_KEYS, "account_keys"),
            (SELECTOR_KEYSTORE_UPDATE, "keystore_update"),
            (SELECTOR_IDENTITY_SERVICES, "identity_services"),
            (SELECTOR_ACCOUNT_OUTFLOW, "account_outflow"),
            (SELECTOR_BRIDGE_WATCHER, "bridge_watcher"),
            (SELECTOR_IDENTITY_REVOKE, "identity_revoke"),
            (SELECTOR_AGENT_AUDIT_COMMIT, "agent_audit_commit"),
            (SELECTOR_LIFT_AGENT_QUARANTINE, "lift_agent_quarantine"),
            (SELECTOR_REVOKE_DELEGATED_AGENT, "revoke_delegated_agent"),
            (SELECTOR_SET_AGENT_TERMS, "set_agent_terms"),
            (SELECTOR_RECLAIM_AGENT_FUNDS, "reclaim_agent_funds"),
            (SELECTOR_SET_AGENT_TOPUP, "set_agent_topup"),
            (SELECTOR_TOPUP_AGENT, "topup_agent"),
            (SELECTOR_AGENT_ACT, "agent_act"),
            (SELECTOR_PAYMENT, "payment"),
            (SELECTOR_REMOTE_GRANT_SETTLE, "remote_grant_settle"),
            (SELECTOR_CONTRACT_CALL, "contract_call"),
            (SELECTOR_AGENT_AUDIT_FLAG, "agent_audit_flag"),
            (SELECTOR_HANDOVER_DUTY, "handover_duty"),
            (SELECTOR_IDENTITY_REGISTER, "identity_register"),
        ];

        let mut seen = std::collections::HashMap::new();
        for (sel, name) in selectors {
            if let Some(prev) = seen.insert(sel, name) {
                panic!("selector {sel:02x?} is used by both {prev} and {name}");
            }
        }
    }

    const GOV_STAKE: u128 = 1_000_000;
    const GOV_GAS_BALANCE: u128 = 10_000_000_000_000_000_000;

    /// Give `who` a bonded stake, and credit the staking vault to match.
    ///
    /// Quorum divides by the bonded-stake total the bond operations keep, so
    /// the bond goes through `staking::add_bond` rather than a raw write.
    fn gov_bond(state: &mut StateAdapter, who: &[u8], stake: u128) {
        staking::add_bond(state, who, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
        state.set_balance(who, GOV_GAS_BALANCE);
        test_operate_own_validator(state, who);
    }

    /// Record that `address` belongs to some identity, as `RegisterIdentity` does.
    fn gov_give_identity(state: &mut StateAdapter, address: &[u8], did: &str) {
        payout_gates::approve_grantee_for_test(
            state,
            address,
            crate::governance::GranteeClass::Developer,
        );
        let key = identity_wallet_index_key(address);
        state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), did.as_bytes().to_vec());
    }

    fn gov_tx(from: &[u8], data: Vec<u8>, gas: u64, at_ms: i64) -> VmTransaction {
        let mut tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            gas,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        tx.block_timestamp_ms = Some(at_ms);
        tx
    }

    fn gov_propose_data(action: &crate::governance::ProposalAction) -> Vec<u8> {
        let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
        data.extend_from_slice(&serde_json::to_vec(action).unwrap());
        data
    }

    fn gov_vote_data(proposal_id: &[u8], in_favour: bool, validator: &[u8]) -> Vec<u8> {
        test_vote_data(proposal_id, in_favour, validator)
    }

    fn gov_execute_data(proposal_id: &[u8]) -> Vec<u8> {
        let mut data = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
        data.extend_from_slice(proposal_id);
        data
    }

    /// A canonical derived address: 20 significant bytes, zero tail.
    fn gov_canonical(byte: u8) -> tenzro_types::primitives::Address {
        let mut a = [0u8; 32];
        a[..20].fill(byte);
        tenzro_types::primitives::Address::new(a)
    }

    #[tokio::test]
    async fn a_proposal_opens_for_voting_and_records_the_electorate() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let proposer = vec![1u8; 20];
        gov_bond(&mut state, &proposer, GOV_STAKE);

        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 500,
            memo: "founding validator allocation".into(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let tx = gov_tx(&proposer, gov_propose_data(&action), 100_000, 1_000);
        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();

        assert!(result.success);
        assert_eq!(result.logs[0].topics[0], b"ProposalCreated".to_vec());

        let id = hex::encode(&result.output);
        let stored = load_proposal(&state, &id).expect("proposal stored");
        assert_eq!(stored.status, crate::governance::ProposalStatus::Voting);
        assert_eq!(stored.action, action);

        // The tally opens knowing how much stake exists to be convinced.
        let tally = load_tally(&state, &id);
        assert_eq!(tally.total_eligible, GOV_STAKE);
        assert_eq!((tally.yes, tally.no), (0, 0));
    }

    /// Proposing costs a bond, not just gas.
    ///
    /// Every proposal is a record every node keeps forever. Without this, an
    /// address with pocket change can fill consensus state indefinitely.
    #[tokio::test]
    async fn an_unbonded_address_cannot_propose() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let stranger = vec![9u8; 20];
        state.set_balance(&stranger, GOV_GAS_BALANCE);

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient: gov_canonical(0x22),
            amount: 1,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let tx = gov_tx(&stranger, gov_propose_data(&action), 100_000, 1_000);
        let err = executor.execute_transaction(&tx, &mut state).await;
        assert!(
            err.is_err(),
            "an unbonded address must not be able to propose"
        );
    }

    /// The hole this closes: voting used to be open to any address at all, and
    /// unweighted. A stranger with gas money could manufacture a result.
    #[tokio::test]
    async fn an_unbonded_address_cannot_vote() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let proposer = vec![1u8; 20];
        gov_bond(&mut state, &proposer, GOV_STAKE);
        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 500,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&proposer, gov_propose_data(&action), 100_000, 1_000),
                &mut state,
            )
            .await
            .unwrap();
        let id_bytes = created.output.clone();

        let stranger = vec![9u8; 20];
        state.set_balance(&stranger, GOV_GAS_BALANCE);
        let err = executor
            .execute_transaction(
                &gov_tx(
                    &stranger,
                    gov_vote_data(&id_bytes, true, &stranger),
                    30_000,
                    2_000,
                ),
                &mut state,
            )
            .await;
        assert!(err.is_err(), "an unbonded address must not be able to vote");
    }

    fn gov_deposit_data(amount: u128) -> Vec<u8> {
        let mut data = SELECTOR_TREASURY_DEPOSIT.to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    /// The treasury had no way to be funded.
    ///
    /// `TreasuryGrant` debits it, but nothing credited it: no genesis
    /// allocation, no fee routing, no deposit. A vault that can only be spent
    /// from starts empty and stays empty, so every grant proposal would pass
    /// its vote and then fail enactment on an insufficient balance — the
    /// governance path was complete except for the half that makes it useful.
    #[tokio::test]
    async fn the_treasury_can_be_funded() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let donor = vec![1u8; 20];
        state.set_balance(&donor, GOV_GAS_BALANCE);

        let treasury = derive_treasury_address().as_bytes().to_vec();
        assert_eq!(state.get_balance(&treasury), 0, "starts empty");

        let result = executor
            .execute_transaction(
                &gov_tx(&donor, gov_deposit_data(5_000), 40_000, 0),
                &mut state,
            )
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.logs[0].topics[0], b"TreasuryDeposit".to_vec());
        assert_eq!(state.get_balance(&treasury), 5_000);
    }

    /// Deposit then grant: the full round trip the governance path needs.
    #[tokio::test]
    async fn a_funded_treasury_can_pay_a_grant() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        // Fund it through the deposit path rather than by writing state, so
        // this exercises the seam rather than assuming it.
        executor
            .execute_transaction(
                &gov_tx(&a, gov_deposit_data(200_000), 40_000, 0),
                &mut state,
            )
            .await
            .unwrap();

        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 4_000,
            memo: "funded by deposit".into(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        let id = created.output.clone();
        executor
            .execute_transaction(
                &gov_tx(&a, gov_vote_data(&id, true, &a), 30_000, 10),
                &mut state,
            )
            .await
            .unwrap();

        // Two calls now: the first queues into the timelock, the second enacts
        // once it has elapsed. A single call cannot do both, or the delay would
        // be set and passed in the same instant.
        let after = crate::governance::VOTING_PERIOD_MS + 1;
        executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, after),
                &mut state,
            )
            .await
            .expect("queueing a passed proposal");
        let past_timelock = after + crate::governance::TIMELOCK_DELAY_MS + 1;
        executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, past_timelock),
                &mut state,
            )
            .await
            .expect("a funded treasury must be able to pay");

        assert_eq!(state.get_balance(recipient.as_bytes()), 4_000);
        assert_eq!(
            state.get_balance(derive_treasury_address().as_bytes()),
            196_000
        );
    }

    /// A deposit of nothing moves nothing and should not consume a nonce.
    #[tokio::test]
    async fn a_zero_treasury_deposit_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let donor = vec![1u8; 20];
        state.set_balance(&donor, GOV_GAS_BALANCE);
        assert!(
            executor
                .execute_transaction(&gov_tx(&donor, gov_deposit_data(0), 40_000, 0), &mut state)
                .await
                .is_err()
        );
    }

    /// A grant to an address with no identity is refused at submission.
    ///
    /// This is the network's standing invariant — no wallet without an identity
    /// — and a treasury grant is the one operation that could otherwise create
    /// a funded address answerable to nobody.
    #[tokio::test]
    async fn a_grant_to_an_address_with_no_identity_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let proposer = vec![1u8; 20];
        gov_bond(&mut state, &proposer, GOV_STAKE);

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient: gov_canonical(0x77), // never indexed
            amount: 1,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let err = executor
            .execute_transaction(
                &gov_tx(&proposer, gov_propose_data(&action), 100_000, 1_000),
                &mut state,
            )
            .await;
        assert!(
            err.is_err(),
            "paying an address with no identity behind it must be refused"
        );
    }

    /// The whole path: propose, vote, wait, enact, money moves.
    #[tokio::test]
    async fn a_passed_grant_pays_the_recipient_from_the_treasury() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();

        let a = vec![1u8; 20];
        let b = vec![2u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        gov_bond(&mut state, &b, GOV_STAKE);

        let treasury = derive_treasury_address().as_bytes().to_vec();
        state.set_balance(&treasury, 200_000);

        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 4_000,
            memo: "founding validator allocation".into(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        let id = created.output.clone();

        // Both validators vote yes: 100% of the electorate, well past 2/3.
        for voter in [&a, &b] {
            executor
                .execute_transaction(
                    &gov_tx(voter, gov_vote_data(&id, true, voter), 30_000, 10),
                    &mut state,
                )
                .await
                .unwrap();
        }

        let after = crate::governance::VOTING_PERIOD_MS + 1;
        executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, after),
                &mut state,
            )
            .await
            .expect("queueing a passed proposal");
        let past_timelock = after + crate::governance::TIMELOCK_DELAY_MS + 1;
        let executed = executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, past_timelock),
                &mut state,
            )
            .await
            .unwrap();
        assert!(executed.success);
        assert!(
            executed
                .logs
                .iter()
                .any(|l| l.topics[0] == b"ProposalExecuted".to_vec())
        );

        assert_eq!(
            state.get_balance(recipient.as_bytes()),
            4_000,
            "the recipient must actually be paid"
        );
        assert_eq!(state.get_balance(&treasury), 196_000);
        assert_eq!(
            load_proposal(&state, &hex::encode(&id)).unwrap().status,
            crate::governance::ProposalStatus::Executed
        );
    }

    /// Land an identity record in consensus state, as `RegisterIdentity` does.
    fn gov_register_identity(state: &mut StateAdapter, did: &str) {
        // Only presence matters to the revocation path; the byte-exact record
        // is the registration handler's business.
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(did),
            br#"{"did":"placeholder"}"#.to_vec(),
        );
    }

    #[tokio::test]
    async fn governance_sets_the_bridge_network_payout_destination() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        assert_eq!(network_payout(&state, "bridge"), None);

        let action = crate::governance::ProposalAction::SetNetworkPayout {
            rail: "bridge".into(),
            destination: "base:0x00000000000000000000000000000000000fee01".into(),
            memo: "network share on Bridge-settled payments".into(),
        };
        let r = gov_carry(&executor, &mut state, &a, &action).await.unwrap();
        assert!(r.success);
        assert_eq!(
            network_payout(&state, "bridge").as_deref(),
            Some("base:0x00000000000000000000000000000000000fee01")
        );

        // A malformed destination or an unknown rail is refused at submission.
        for bad in [
            crate::governance::ProposalAction::SetNetworkPayout {
                rail: "bridge".into(),
                destination: "no-rail-separator".into(),
                memo: String::new(),
            },
            crate::governance::ProposalAction::SetNetworkPayout {
                rail: "elsewhere".into(),
                destination: "base:0x1".into(),
                memo: String::new(),
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }

    /// Drive a proposal from submission to enactment.
    async fn gov_carry(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        who: &[u8],
        action: &crate::governance::ProposalAction,
    ) -> Result<ExecutionResult> {
        let created = executor
            .execute_transaction(&gov_tx(who, gov_propose_data(action), 100_000, 0), state)
            .await?;
        let id = created.output.clone();
        executor
            .execute_transaction(
                &gov_tx(who, gov_vote_data(&id, true, who), 30_000, 10),
                state,
            )
            .await?;
        let track = action.track();
        let after = track.voting_period_ms(&crate::governance::GovernanceRules::GENESIS) + 1;
        executor
            .execute_transaction(&gov_tx(who, gov_execute_data(&id), 120_000, after), state)
            .await?;
        let past = after + track.timelock_ms(&crate::governance::GovernanceRules::GENESIS) + 1;
        executor
            .execute_transaction(&gov_tx(who, gov_execute_data(&id), 120_000, past), state)
            .await
    }

    fn param_change(key: &str, value: u64) -> crate::governance::ProposalAction {
        crate::governance::ProposalAction::ParameterChange {
            key: key.into(),
            value,
            memo: "m".into(),
        }
    }

    /// Pausing a feature is a pause-only change on the expedited track, and
    /// applies at the next epoch with no grace window; resuming it takes the
    /// standard track.
    #[tokio::test]
    async fn a_pause_only_change_is_decided_on_the_expedited_track() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let key = "bridge.ibc.status";
        let pause = param_change(key, 1);
        assert_eq!(pause.track(), crate::governance::ProposalTrack::Expedited);
        let r = gov_carry(&executor, &mut state, &a, &pause).await.unwrap();
        assert!(r.success);
        assert_eq!(
            pending_param(&state, key).map(|p| (p.value, p.activates_epoch)),
            Some((1, 6))
        );
        begin_block_params(&mut state, 6).unwrap();
        assert_eq!(
            lever_status(&state, key),
            crate::governance::LeverStatus::Paused
        );

        // Putting it back is not an emergency: standard track.
        let resume = param_change(key, 0);
        assert_eq!(resume.track(), crate::governance::ProposalTrack::Standard);
        let r = gov_carry(&executor, &mut state, &a, &resume).await.unwrap();
        assert!(r.success);
    }

    fn reinstate(validator: [u8; 32]) -> crate::governance::ProposalAction {
        crate::governance::ProposalAction::ReinstateValidator {
            validator: tenzro_types::primitives::Address::new(validator),
            memo: "jailed in error".into(),
        }
    }

    /// An enacted reinstatement records the epoch it was enacted in, which is
    /// what releases the jailed validator; a validator that holds no bond is
    /// refused when the proposal is submitted.
    #[tokio::test]
    async fn an_enacted_reinstatement_records_its_epoch_for_the_node() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        let v = [2u8; 32];
        gov_bond(&mut state, &v, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        assert_eq!(reinstated_at_epoch(&state, &v), None);

        let none = gov_carry(&executor, &mut state, &a, &reinstate([3u8; 32])).await;
        assert!(none.map_or(true, |r| !r.success));
        assert_eq!(reinstated_at_epoch(&state, &[3u8; 32]), None);

        let r = gov_carry(&executor, &mut state, &a, &reinstate(v))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(reinstated_at_epoch(&state, &v), Some(5));
        assert_eq!(reinstated_at_epoch(&state, &a), None);
    }

    /// A longer jail asks more of a validator, so it waits out the
    /// tightening grace window; a shorter one applies at the next epoch.
    #[tokio::test]
    async fn the_jail_term_follows_the_tightening_rules() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let genesis = crate::governance::genesis_param(JAIL_TERM_PARAM);
        assert_eq!(network_param(&state, JAIL_TERM_PARAM), genesis);

        let r = gov_carry(
            &executor,
            &mut state,
            &a,
            &param_change(JAIL_TERM_PARAM, genesis + 1),
        )
        .await
        .unwrap();
        assert!(r.success);
        let grace = crate::governance::genesis_param(crate::governance::TIGHTENING_GRACE_PARAM);
        assert_eq!(
            pending_param(&state, JAIL_TERM_PARAM).map(|p| p.activates_epoch),
            Some(6 + grace)
        );

        let r = gov_carry(
            &executor,
            &mut state,
            &a,
            &param_change(JAIL_TERM_PARAM, genesis - 1),
        )
        .await
        .unwrap();
        assert!(r.success);
        assert_eq!(
            pending_param(&state, JAIL_TERM_PARAM).map(|p| (p.value, p.activates_epoch)),
            Some((genesis - 1, 6))
        );
    }

    /// An enacted change waits for the next epoch boundary, then every block
    /// of that epoch runs on it.
    #[tokio::test]
    async fn an_enacted_parameter_change_applies_from_the_next_epoch() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let key = "agent.remote_grant_budget_divisor";
        let genesis = crate::governance::genesis_param(key);

        let r = gov_carry(&executor, &mut state, &a, &param_change(key, genesis + 1))
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            network_param(&state, key),
            genesis,
            "nothing changes mid-epoch"
        );
        assert_eq!(
            pending_param(&state, key).map(|p| (p.value, p.activates_epoch)),
            Some((genesis + 1, 6))
        );

        assert!(begin_block_params(&mut state, 5).unwrap().is_empty());
        assert_eq!(network_param(&state, key), genesis);
        assert_eq!(
            begin_block_params(&mut state, 6).unwrap(),
            vec![(key.to_string(), genesis + 1)]
        );
        assert_eq!(network_param(&state, key), genesis + 1);
        assert!(pending_param(&state, key).is_none());
        assert!(pending_param_keys(&state).is_empty());
    }

    /// Parameters bound together by a rule move only to values that keep it:
    /// the provider and activity rewards of one settlement stay below its
    /// fee, and the inference penalty times the sampling share covers the
    /// payment. A change whose partner is still waiting is held at the epoch
    /// boundary until the partner applies.
    #[tokio::test]
    async fn parameters_bound_together_never_break_their_rule() {
        use crate::native::economy::ACTIVITY_REWARD_FEE_PARAM;
        use crate::native::inference_fault::{PENALTY_PAYMENT_PARAM, SAMPLE_BPS_PARAM};
        use crate::native::rewards::PROVIDER_REWARD_COST_PARAM;
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let carried = |r: Result<ExecutionResult>| matches!(r, Ok(ref x) if x.success);

        // 4000 + 5000 is the ceiling: one more point is refused.
        assert!(!carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(PROVIDER_REWARD_COST_PARAM, 4_001)
            )
            .await
        ));
        assert!(pending_param(&state, PROVIDER_REWARD_COST_PARAM).is_none());
        // Lower the activity reward first, then the provider reward may rise.
        assert!(carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(ACTIVITY_REWARD_FEE_PARAM, 3_000)
            )
            .await
        ));
        assert!(carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(PROVIDER_REWARD_COST_PARAM, 6_000)
            )
            .await
        ));
        begin_block_params(&mut state, 6).unwrap();
        assert_eq!(
            crate::native::rewards::settlement_reward_bps(&state),
            (6_000, 3_000)
        );
        // Raising the activity reward back is refused while the provider
        // reward holds the room.
        assert!(!carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(ACTIVITY_REWARD_FEE_PARAM, 5_000)
            )
            .await
        ));

        // A lower sampling share needs a higher penalty multiple, which as a
        // tightening waits out the grace window; the lower share, enacted
        // against the scheduled multiple, is held until the multiple applies.
        let grace = crate::governance::DEFAULT_TIGHTENING_GRACE_EPOCHS;
        assert!(!carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(SAMPLE_BPS_PARAM, 250)
            )
            .await
        ));
        assert!(carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(PENALTY_PAYMENT_PARAM, 400_000)
            )
            .await
        ));
        assert!(carried(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(SAMPLE_BPS_PARAM, 251)
            )
            .await
        ));
        begin_block_params(&mut state, 7).unwrap();
        assert_eq!(
            network_param(&state, SAMPLE_BPS_PARAM),
            500,
            "held for its partner"
        );
        assert_eq!(network_param(&state, PENALTY_PAYMENT_PARAM), 200_000);
        begin_block_params(&mut state, 7 + grace).unwrap();
        assert_eq!(network_param(&state, PENALTY_PAYMENT_PARAM), 400_000);
        assert_eq!(network_param(&state, SAMPLE_BPS_PARAM), 251);
        assert!(pending_param_keys(&state).is_empty());
    }

    /// A change that asks more of those a rule binds (here a longer cooldown)
    /// waits out the tightening grace window as well.
    #[tokio::test]
    async fn a_tightening_change_waits_out_the_grace_window() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let key = crate::native::AGENT_BOND_COOLDOWN_PARAM;
        let genesis = crate::governance::genesis_param(key);
        let grace = crate::governance::DEFAULT_TIGHTENING_GRACE_EPOCHS;

        assert!(
            gov_carry(
                &executor,
                &mut state,
                &a,
                &param_change(key, genesis + 1_000)
            )
            .await
            .unwrap()
            .success
        );
        assert_eq!(
            pending_param(&state, key).map(|p| p.activates_epoch),
            Some(6 + grace)
        );
        begin_block_params(&mut state, 6).unwrap();
        assert_eq!(
            network_param(&state, key),
            genesis,
            "inside the grace window"
        );
        begin_block_params(&mut state, 6 + grace).unwrap();
        assert_eq!(network_param(&state, key), genesis + 1_000);

        // Loosening it back applies at the next boundary.
        assert!(
            gov_carry(&executor, &mut state, &a, &param_change(key, genesis))
                .await
                .unwrap()
                .success
        );
        assert_eq!(
            pending_param(&state, key).map(|p| p.activates_epoch),
            Some(7 + grace)
        );
    }

    /// Every status lever: a vote pauses it from the next epoch boundary and
    /// not before, another resumes it at the boundary after, a third retires
    /// it only once the tightening grace window has passed, and a retired
    /// lever cannot be voted back.
    #[tokio::test]
    async fn every_status_lever_moves_exactly_at_its_epoch_boundary() {
        use crate::governance::{GOVERNED_PARAMS, LeverStatus, Tighten};
        let grace = crate::governance::DEFAULT_TIGHTENING_GRACE_EPOCHS;
        let levers: Vec<_> = GOVERNED_PARAMS
            .iter()
            .filter(|p| p.tighten == Tighten::Retire)
            .map(|p| p.key)
            .collect();
        assert!(levers.len() >= 23, "{levers:?}");
        for key in levers {
            assert!(key.ends_with(".status"), "{key}");
            let executor = NativeExecutor::new(VmConfig::default()).unwrap();
            let mut state = StateAdapter::new();
            let a = vec![1u8; 20];
            gov_bond(&mut state, &a, GOV_STAKE);
            begin_block_params(&mut state, 5).unwrap();
            assert_eq!(lever_status(&state, key), LeverStatus::Enabled, "{key}");

            let paused = gov_carry(&executor, &mut state, &a, &param_change(key, 1))
                .await
                .unwrap();
            assert!(paused.success, "{key}");
            assert_eq!(
                lever_status(&state, key),
                LeverStatus::Enabled,
                "{key} mid-epoch"
            );
            assert_eq!(
                pending_param(&state, key).map(|p| (p.value, p.activates_epoch)),
                Some((1, 6)),
                "{key}"
            );
            assert!(begin_block_params(&mut state, 5).unwrap().is_empty());
            assert_eq!(
                begin_block_params(&mut state, 6).unwrap(),
                vec![(key.to_string(), 1)]
            );
            assert_eq!(lever_status(&state, key), LeverStatus::Paused, "{key}");

            assert!(
                gov_carry(&executor, &mut state, &a, &param_change(key, 0))
                    .await
                    .unwrap()
                    .success
            );
            assert_eq!(
                lever_status(&state, key),
                LeverStatus::Paused,
                "{key} mid-epoch"
            );
            begin_block_params(&mut state, 7).unwrap();
            assert_eq!(lever_status(&state, key), LeverStatus::Enabled, "{key}");

            assert!(
                gov_carry(&executor, &mut state, &a, &param_change(key, 2))
                    .await
                    .unwrap()
                    .success
            );
            assert_eq!(
                pending_param(&state, key).map(|p| p.activates_epoch),
                Some(8 + grace),
                "{key}: retiring waits out the grace window"
            );
            begin_block_params(&mut state, 7 + grace).unwrap();
            assert_eq!(lever_status(&state, key), LeverStatus::Enabled, "{key}");
            begin_block_params(&mut state, 8 + grace).unwrap();
            assert_eq!(lever_status(&state, key), LeverStatus::Retired, "{key}");

            let back = gov_carry(&executor, &mut state, &a, &param_change(key, 0)).await;
            assert!(
                back.as_ref().map_or(true, |r| !r.success),
                "{key}: a retired lever was voted back"
            );
            assert_eq!(lever_status(&state, key), LeverStatus::Retired, "{key}");
        }
    }

    /// Every governed parameter: an enacted proposal that moves it one step
    /// in the stricter direction (the looser one where it already sits at
    /// that end of its bounds) leaves the value in force untouched in every
    /// block before its activation epoch, and the first block of that epoch
    /// applies it exactly. A change the rules refuse at submission is
    /// reported, and nearly every parameter must accept one.
    #[tokio::test]
    async fn every_governed_parameter_flips_exactly_at_its_activation_epoch() {
        use crate::governance::{GOVERNED_PARAMS, Tighten};
        let (mut flipped, mut refused) = (0usize, Vec::new());
        let movable: Vec<_> = GOVERNED_PARAMS.iter().filter(|p| p.min < p.max).collect();
        for p in &movable {
            let up = p.genesis < p.max;
            let down = p.genesis > p.min;
            let value = match p.tighten {
                Tighten::Retire => 1,
                Tighten::Up if up => p.genesis + 1,
                Tighten::Down if down => p.genesis - 1,
                _ if up => p.genesis + 1,
                _ => p.genesis - 1,
            };
            let executor = NativeExecutor::new(VmConfig::default()).unwrap();
            let mut state = StateAdapter::new();
            let a = vec![1u8; 20];
            gov_bond(&mut state, &a, GOV_STAKE);
            begin_block_params(&mut state, 5).unwrap();
            let before = network_param(&state, p.key);
            let carried = gov_carry(&executor, &mut state, &a, &param_change(p.key, value)).await;
            let Some(activates) = carried
                .ok()
                .filter(|r| r.success)
                .and_then(|_| pending_param(&state, p.key))
                .map(|c| c.activates_epoch)
            else {
                refused.push(p.key);
                continue;
            };
            assert!(activates > 5, "{}: activates in the current epoch", p.key);
            for epoch in 5..activates {
                begin_block_params(&mut state, epoch).unwrap();
                assert_eq!(
                    network_param(&state, p.key),
                    before,
                    "{} at epoch {epoch}",
                    p.key
                );
            }
            begin_block_params(&mut state, activates).unwrap();
            assert_eq!(
                network_param(&state, p.key),
                value,
                "{} at its epoch",
                p.key
            );
            assert!(pending_param(&state, p.key).is_none(), "{}", p.key);
            flipped += 1;
        }
        eprintln!("refused at submission: {refused:?}");
        assert!(
            flipped * 10 >= movable.len() * 9,
            "{flipped} of {} parameters flipped; refused {refused:?}",
            movable.len()
        );
    }

    /// The governed bounds on a validator's round timing change at the next
    /// epoch boundary, not before.
    #[tokio::test]
    async fn consensus_timing_bounds_move_at_the_epoch_boundary() {
        use crate::governance as g;
        for key in [
            g::CONSENSUS_LEADER_TIMEOUT_MIN_PARAM,
            g::CONSENSUS_LEADER_TIMEOUT_MAX_PARAM,
            g::CONSENSUS_ROUND_INTERVAL_MIN_PARAM,
            g::CONSENSUS_ROUND_INTERVAL_MAX_PARAM,
        ] {
            let executor = NativeExecutor::new(VmConfig::default()).unwrap();
            let mut state = StateAdapter::new();
            let a = vec![1u8; 20];
            gov_bond(&mut state, &a, GOV_STAKE);
            begin_block_params(&mut state, 5).unwrap();
            let genesis = g::genesis_param(key);
            let value = genesis + 10;
            assert!(
                gov_carry(&executor, &mut state, &a, &param_change(key, value))
                    .await
                    .unwrap()
                    .success
            );
            assert_eq!(network_param(&state, key), genesis, "{key} mid-epoch");
            begin_block_params(&mut state, 6).unwrap();
            assert_eq!(network_param(&state, key), value, "{key}");
        }
        assert_eq!(g::within_bounds(5, 100, 30_000), 100);
        assert_eq!(g::within_bounds(50_000, 100, 30_000), 30_000);
        assert_eq!(g::within_bounds(700, 100, 30_000), 700);
        assert_eq!(g::within_bounds(700, 900, 800), 900, "the floor wins");
    }

    /// A paused bridge transport stops every route on it; retired, its routes
    /// wind down as a disabled route does; a route's own stricter record
    /// still holds.
    #[test]
    fn a_bridge_transport_lever_stops_its_routes() {
        use tenzro_types::bridge_route::{BridgeRouteAdapter as A, BridgeRouteMode as M};
        let mut state = StateAdapter::new();
        assert!(bridge_route_stop(&state, A::Ccip, "ethereum").is_none());
        set_genesis_param(&mut state, "bridge.ccip.status", 1);
        assert_eq!(
            bridge_route_stop(&state, A::Ccip, "ethereum").map(|s| s.0),
            Some(M::Paused)
        );
        assert!(bridge_route_stop(&state, A::Ibc, "osmosis-1").is_none());
        set_genesis_param(&mut state, "bridge.ccip.status", 2);
        assert_eq!(
            bridge_route_stop(&state, A::Ccip, "ethereum").map(|s| s.0),
            Some(M::Disabled)
        );
    }

    /// A role's bond amount is a governed parameter: a vote raises it, a bond
    /// that met the old amount keeps serving through the tightening grace
    /// window and stops serving once the raise applies, and no transaction
    /// other than an enacted proposal moves it.
    #[tokio::test]
    async fn a_raised_bond_minimum_applies_after_the_grace_window() {
        use tenzro_types::network::NetworkRole;
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let key = "stake.wallet_tnzo";
        let genesis = crate::governance::genesis_param(key);
        assert_eq!(
            role_stake::stake_ladder(&state).wallet,
            u128::from(genesis) * tenzro_types::constants::ONE_TNZO
        );
        let operator = [0x33u8; 32];
        role_stake::bond_role_for_test(
            &mut state,
            &operator,
            NetworkRole::Attestor,
            tenzro_types::constants::MIN_ATTESTOR_STAKE,
        );
        assert!(role_bonded(&state, &operator, NetworkRole::Attestor));

        let attestor_key = "stake.attestor_tnzo";
        let attestor_genesis = crate::governance::genesis_param(attestor_key);
        let grace = crate::governance::DEFAULT_TIGHTENING_GRACE_EPOCHS;
        let raise = param_change(attestor_key, attestor_genesis * 2);
        assert!(
            gov_carry(&executor, &mut state, &a, &raise)
                .await
                .unwrap()
                .success
        );
        assert_eq!(
            pending_param(&state, attestor_key).map(|p| p.activates_epoch),
            Some(6 + grace)
        );
        begin_block_params(&mut state, 6).unwrap();
        assert!(
            role_bonded(&state, &operator, NetworkRole::Attestor),
            "the old bond serves through the grace window"
        );
        begin_block_params(&mut state, 6 + grace).unwrap();
        assert!(
            !role_bonded(&state, &operator, NetworkRole::Attestor),
            "below the raised minimum, the role stops"
        );
        assert_eq!(
            role_stake::stake_ladder(&state).attestor,
            u128::from(attestor_genesis * 2) * tenzro_types::constants::ONE_TNZO
        );

        // A Stake transaction cannot move an amount; only the vote did.
        let op = tenzro_types::token::StakeOp::Bond {
            role: NetworkRole::Attestor,
            amount: tenzro_types::constants::MIN_ATTESTOR_STAKE,
            capacity: tenzro_types::token::StakeCapacity::None,
        };
        let mut data = role_stake::SELECTOR_STAKE.to_vec();
        data.extend(serde_json::to_vec(&op).unwrap());
        state.set_balance(
            &[0x44u8; 32],
            10 * tenzro_types::constants::MIN_ATTESTOR_STAKE,
        );
        let mut tx = VmTransaction::new(
            vec![0x44u8; 32],
            None,
            0,
            data,
            1_000_000,
            0,
            0,
            crate::VmType::Tenzro,
            1337,
        );
        tx.block_timestamp_ms = Some(1);
        assert!(
            executor.execute_transaction(&tx, &mut state).await.is_err(),
            "the old amount no longer bonds"
        );
        assert_eq!(network_param(&state, attestor_key), attestor_genesis * 2);
    }

    /// The compute bond minimum is governed: a post below it is refused, and a
    /// raised minimum leaves an existing bond eligible through the grace window.
    #[tokio::test]
    async fn a_raised_compute_bond_minimum_applies_after_the_grace_window() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        begin_block_params(&mut state, 5).unwrap();
        let genesis = crate::governance::genesis_param(COMPUTE_BOND_MIN_PARAM);
        let min = compute_bond_min(&state);
        assert_eq!(min, u128::from(genesis) * tenzro_types::constants::ONE_TNZO);

        let payer = vec![0x55u8; 20];
        state.set_balance(&payer, 10 * min);
        let did = "did:tenzro:machine:bonded";
        let post = |amount: u128, nonce: u64| {
            let mut data = SELECTOR_POST_COMPUTE_BOND.to_vec();
            data.extend(format!(r#"{{"provider_did":"{did}","amount":{amount}}}"#).into_bytes());
            VmTransaction::new(
                payer.clone(),
                None,
                0,
                data,
                300_000,
                1_000_000_000,
                nonce,
                VmType::Tenzro,
                1337,
            )
        };
        let below = executor
            .execute_transaction(&post(min - 1, 0), &mut state)
            .await;
        assert!(
            below.map(|r| !r.success).unwrap_or(true),
            "a bond below the minimum is refused"
        );
        assert!(compute_bond(&state, did).is_none());
        assert!(
            executor
                .execute_transaction(&post(min, 0), &mut state)
                .await
                .unwrap()
                .success
        );
        assert!(compute_bond(&state, did).unwrap().is_eligible());

        let grace = crate::governance::DEFAULT_TIGHTENING_GRACE_EPOCHS;
        let raise = param_change(COMPUTE_BOND_MIN_PARAM, genesis * 2);
        assert!(
            gov_carry(&executor, &mut state, &a, &raise)
                .await
                .unwrap()
                .success
        );
        assert_eq!(
            pending_param(&state, COMPUTE_BOND_MIN_PARAM).map(|p| p.activates_epoch),
            Some(6 + grace)
        );
        begin_block_params(&mut state, 6).unwrap();
        assert!(
            compute_bond(&state, did).unwrap().is_eligible(),
            "the old bond backs its provider through the grace"
        );
        begin_block_params(&mut state, 6 + grace).unwrap();
        let bond = compute_bond(&state, did).unwrap();
        assert!(
            !bond.is_eligible(),
            "below the raised minimum, the bond no longer backs its provider"
        );
        assert_eq!(bond.effective_amount(), 0);
        assert_eq!(compute_bond_min(&state), 2 * min);
    }

    /// A value outside a parameter's bounds is refused when proposed, and an
    /// unknown key cannot be proposed at all.
    #[tokio::test]
    async fn an_out_of_bounds_parameter_change_is_refused_at_submission() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        let key = "agent.remote_grant_budget_divisor";
        let max = crate::governance::governed_param(key).unwrap().max;
        for action in [
            param_change(key, max + 1),
            param_change("fees.not_a_parameter", 1),
        ] {
            let r = executor
                .execute_transaction(
                    &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                    &mut state,
                )
                .await;
            assert!(
                r.map(|r| !r.success).unwrap_or(true),
                "{action:?} must be refused"
            );
        }
        assert!(pending_param_keys(&state).is_empty());
    }

    /// A cheap fleet-scale fixture: `n` eligible compute bonds, written
    /// directly and indexed in one call, the same shape `compute_bond`
    /// posts but without the posting transaction this test has no interest
    /// in running `n` times.
    fn gov_fleet_of(state: &mut StateAdapter, n: u64) {
        let min = compute_bond_min(&*state);
        let amount = (min + 1).to_string();
        let mut index = Vec::with_capacity(n as usize);
        for i in 0..n {
            let did = format!("did:tenzro:machine:gov-fleet-{i}");
            let marker = serde_json::json!({
                "provider_did": did,
                "provider_address": hex::encode([0u8; 20]),
                "amount": amount,
                "op": "Posted",
            });
            state.set_storage(
                &SYSTEM_ADDRESS,
                compute_bond_storage_key(&did).as_bytes(),
                serde_json::to_vec(&marker).unwrap(),
            );
            index.push(did);
        }
        state.set_storage(
            &SYSTEM_ADDRESS,
            b"compute_bond_index",
            serde_json::to_vec(&index).unwrap(),
        );
    }

    /// The energy-budget cap, driven through the real propose/vote/enact
    /// pipeline rather than called as a bare function: turning the budget on
    /// at the research doc's own validated 0.1% figure is refused against
    /// the genesis probe interval (the real tension the module's doc comment
    /// names), the same figure holds at the module's generous 10% ceiling,
    /// and once on, a further change that would blow even that ceiling is
    /// also refused.
    #[tokio::test]
    async fn the_sla_energy_budget_refuses_an_over_budget_change_through_governance() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        gov_fleet_of(&mut state, 500);

        let strict = param_change(sla_energy_budget::SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM, 10);
        let refused = gov_carry(&executor, &mut state, &a, &strict).await;
        assert!(
            refused.map(|r| !r.success).unwrap_or(true),
            "the genesis probe interval spends far more than 0.1% of fleet energy; \
             turning the budget on at that figure must be refused"
        );
        assert_eq!(
            network_param(
                &state,
                sla_energy_budget::SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM
            ),
            0
        );

        let lenient = param_change(
            sla_energy_budget::SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM,
            sla_energy_budget::MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS,
        );
        assert!(
            gov_carry(&executor, &mut state, &a, &lenient)
                .await
                .unwrap()
                .success,
            "the genesis probe interval holds within the module's generous 10% ceiling"
        );
        assert_eq!(
            pending_param(
                &state,
                sla_energy_budget::SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM
            )
            .map(|p| p.value),
            Some(sla_energy_budget::MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS),
            "the change is scheduled, waiting for the next epoch to apply"
        );

        let too_frequent = param_change(
            SLA_PROBE_INTERVAL_PARAM,
            crate::governance::governed_param(SLA_PROBE_INTERVAL_PARAM)
                .unwrap()
                .min,
        );
        let refused = gov_carry(&executor, &mut state, &a, &too_frequent).await;
        assert!(
            refused.map(|r| !r.success).unwrap_or(true),
            "the shortest allowed probe interval spends far more than 10% of fleet \
             energy once the budget is live; it must be refused"
        );
        assert_eq!(
            network_param(&state, SLA_PROBE_INTERVAL_PARAM),
            crate::governance::genesis_param(SLA_PROBE_INTERVAL_PARAM)
        );
    }

    /// A proposer needs the governed share of bonded stake; governance can
    /// lower or raise that share.
    #[tokio::test]
    async fn a_proposer_below_the_threshold_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (big, small) = (vec![1u8; 20], vec![2u8; 20]);
        gov_bond(&mut state, &big, GOV_STAKE);
        gov_bond(&mut state, &small, GOV_STAKE / 1_000);
        let action = param_change("agent.remote_grant_budget_divisor", 4);
        let refused = executor
            .execute_transaction(
                &gov_tx(&small, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await;
        assert!(
            refused.map(|r| !r.success).unwrap_or(true),
            "0.1% of stake is below the 1% threshold"
        );

        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(crate::governance::PROPOSAL_THRESHOLD_PARAM).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
        let opened = executor
            .execute_transaction(
                &gov_tx(&small, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        assert!(
            opened.success,
            "with no threshold any bonded validator proposes"
        );
    }

    /// Voting rules are taken when a proposal opens: a rule change enacted
    /// later never moves an open proposal's window.
    #[tokio::test]
    async fn a_proposal_keeps_the_voting_rules_it_opened_under() {
        let mut state = StateAdapter::new();
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(crate::governance::VOTING_PERIOD_PARAM).as_bytes(),
            (5 * 24 * 60 * 60 * 1000u64).to_le_bytes().to_vec(),
        );
        let rules = governance_rules(&state);
        assert_eq!(rules.voting_period_ms, 5 * 24 * 60 * 60 * 1000);
        let p = crate::governance::Proposal::open(
            "p".into(),
            Address::default(),
            param_change("agent.remote_grant_budget_divisor", 4),
            0,
            rules,
        );
        assert_eq!(p.voting_ends_ms, 5 * 24 * 60 * 60 * 1000);
    }

    /// **The gap this closes.** The registry could always revoke on its
    /// holder's own authority, and a holder acting in bad faith does not
    /// revoke themselves — so nothing the network said about identities was
    /// enforceable. A carried proposal now writes the revocation into
    /// consensus state and emits the log every node's read model follows.
    #[tokio::test]
    async fn governance_can_revoke_a_registered_identity() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let did = "did:tenzro:human:a828941c-fe91-8250-af8b-a16527305188";
        gov_register_identity(&mut state, did);

        let action = crate::governance::ProposalAction::RevokeIdentity {
            did: did.to_string(),
            reason: "forged enrolment evidence".into(),
        };
        let enacted = gov_carry(&executor, &mut state, &a, &action)
            .await
            .expect("a passed revocation must enact");

        assert!(enacted.success);
        assert!(
            enacted.logs.iter().any(
                |l| l.topics.first().map(|t| t.as_slice()) == Some(b"IdentityRevoked".as_ref())
            ),
            "the node-side mirror follows this log; without it consensus revokes \
             an identity every node still answers questions about"
        );

        let stored = state
            .get_storage(&SYSTEM_ADDRESS, &identity_revocation_key(did))
            .expect("revocation written to consensus state");
        let record: tenzro_types::identity::IdentityRevokedLog =
            serde_json::from_slice(&stored).unwrap();
        assert_eq!(record.did, did);
        assert_eq!(record.reason, "forged enrolment evidence");
        assert!(
            record.revoked_by.contains("proposal"),
            "the revocation must name the vote that produced it: {}",
            record.revoked_by
        );
    }

    fn gov_bridge_route() -> tenzro_types::bridge_route::BridgeRoute {
        use tenzro_types::bridge_route::*;
        BridgeRoute {
            adapter: BridgeRouteAdapter::Ccip,
            family: ChainFamily::Evm,
            source_chain: "ethereum".into(),
            source_chain_id: 42,
            local_selector: 7_777,
            peer: [7u8; 32],
            ramp: [8u8; 32],
            local_endpoint: [9u8; 32],
            remote_token: [6u8; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 3,
                members: Vec::new(),
                threshold: 2,
            },
            blessing: Some(VerifierQuorum {
                set_index: 0,
                size: 3,
                members: Vec::new(),
                threshold: 2,
            }),
            light_client: None,
            mint_limit: MintRateLimit {
                per_mint: 100,
                per_epoch: 1_000,
            },
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: u128::MAX,
                rate: u128::MAX / 2,
            },
            lane_limits: Some(CcipLane {
                version: CcipLaneVersion::V1_6,
                off_ramp: [0u8; 20],
                ccv_and_executor_hash: [0u8; 32],
                inbound: tenzro_types::bridge_route::LaneRateLimit {
                    capacity: 1_000,
                    rate: 10,
                },
            }),
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
        }
    }

    /// A carried route proposal writes the route into consensus state, where
    /// every node's inbound verifier reads it, and a carried removal clears it.
    #[tokio::test]
    async fn governance_installs_and_removes_a_bridge_route() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let route = gov_bridge_route();
        let key = route.storage_key();
        let install = crate::governance::ProposalAction::SetBridgeRoute {
            route: route.clone(),
            memo: "ethereum peer".into(),
        };
        let enacted = gov_carry(&executor, &mut state, &a, &install)
            .await
            .expect("a passed route proposal must enact");
        assert!(enacted.success);
        let stored = state
            .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
            .expect("route written to consensus state");
        let back: tenzro_types::bridge_route::BridgeRoute =
            serde_json::from_slice(&stored).unwrap();
        assert_eq!(back, route);

        let remove = crate::governance::ProposalAction::RemoveBridgeRoute {
            adapter: route.adapter,
            source_chain: route.source_chain.clone(),
            memo: "retired".into(),
        };
        gov_carry(&executor, &mut state, &a, &remove)
            .await
            .expect("a passed removal must enact");
        assert!(
            state
                .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
                .is_none_or(|b| b.is_empty()),
            "a removed route must read as absent"
        );
    }

    /// A route proposal that names committee members is refused at
    /// submission: members are drawn from bonded attestors, never voted in.
    #[tokio::test]
    async fn a_bridge_route_naming_committee_members_never_reaches_a_vote() {
        use tenzro_types::bridge_route::VerifierMember;
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let mut route = gov_bridge_route();
        route.verifiers.members = (1..=3u8)
            .map(|i| VerifierMember {
                address: [i; 20],
                pq_public_key: vec![0u8; 1952],
                operator: hex::encode([i; 32]),
                rpc_provider: format!("rpc{i}"),
            })
            .collect();
        let action = crate::governance::ProposalAction::SetBridgeRoute {
            route,
            memo: String::new(),
        };
        let err = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .expect_err("a proposal naming members must be refused at submission");
        assert!(err.to_string().contains("drawn"), "{err}");
    }

    /// A route genesis left as a placeholder opens only after a vote has
    /// installed it whole and its light client has been bootstrapped from the
    /// anchor; a vote on the expedited track disables it again, and opening
    /// never takes that track.
    #[tokio::test]
    async fn a_placeholder_route_opens_only_once_filled_and_its_anchor_verified() {
        use tenzro_types::bridge_route::{
            BridgeRouteAdapter, BridgeRouteMode, ChainFamily, LightClientAnchor,
        };
        use tenzro_types::token::PolicyUpdate;
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let mut route = gov_bridge_route();
        route.adapter = BridgeRouteAdapter::Contract;
        route.family = ChainFamily::Sui;
        route.source_chain = "sui".into();
        route.blessing = None;
        route.lane_limits = None;
        route.light_client = Some(LightClientAnchor::SuiCommittee {
            trusted_checkpoint_digest: [5u8; 32],
        });
        route.validate_proposal().unwrap();
        let (adapter, chain) = (route.adapter, route.source_chain.clone());

        // As genesis writes a placeholder route: zeroed, its placeholder
        // fields recorded, disabled by governance.
        let mut placeholder = route.clone();
        placeholder.verifiers.members.clear();
        placeholder.light_client = None;
        let put = |state: &mut StateAdapter, key: String, v: Vec<u8>| {
            state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), v)
        };
        put(
            &mut state,
            placeholder.storage_key(),
            serde_json::to_vec(&placeholder).unwrap(),
        );
        put(
            &mut state,
            bridge_placeholders_key(adapter, &chain),
            serde_json::to_vec(&["verifiers", "light_client"]).unwrap(),
        );
        let held = BridgeCircuitTrip {
            adapter,
            source_chain: chain.clone(),
            mode: BridgeRouteMode::Disabled,
            by: BridgeCircuitAuthority::Governance,
            reason: "closed at genesis".into(),
            evidence_hash: None,
            epoch: 0,
            at_ms: 0,
        };
        put(
            &mut state,
            bridge_circuit_key(adapter, &chain),
            serde_json::to_vec(&held).unwrap(),
        );

        let set_mode = |mode: BridgeRouteMode, expedited: bool| {
            crate::governance::ProposalAction::PolicyUpdate {
                update: PolicyUpdate::BridgeCircuitSet {
                    adapter,
                    source_chain: chain.clone(),
                    mode,
                    reason: "route governance".into(),
                },
                memo: "route governance".into(),
                track: if expedited {
                    crate::governance::PolicyTrack::Expedited
                } else {
                    crate::governance::PolicyTrack::Standard
                },
            }
        };

        let err = gov_carry(
            &executor,
            &mut state,
            &a,
            &set_mode(BridgeRouteMode::Open, false),
        )
        .await
        .expect_err("a placeholder route must not open");
        let msg = err.to_string();
        assert!(
            msg.contains("contract:sui") && msg.contains("verifiers, light_client"),
            "{msg}"
        );
        assert_eq!(
            read_bridge_route_mode(&state, adapter, &chain),
            BridgeRouteMode::Disabled
        );

        // A vote installs the route whole; its placeholders are gone, but its
        // light client has not been bootstrapped from the anchor yet.
        let install = crate::governance::ProposalAction::SetBridgeRoute {
            route: route.clone(),
            memo: "filled".into(),
        };
        gov_carry(&executor, &mut state, &a, &install)
            .await
            .unwrap();
        assert!(read_route_placeholders(&state, adapter, &chain).is_empty());
        let err = gov_carry(
            &executor,
            &mut state,
            &a,
            &set_mode(BridgeRouteMode::Open, false),
        )
        .await
        .expect_err("a route whose committee is not drawn must not open");
        assert!(err.to_string().contains("has not been drawn"), "{err}");

        // As a committee draw writes it: the members seated.
        let mut drawn = route.clone();
        drawn.verifiers.members = (1..=3u8)
            .map(|i| tenzro_types::bridge_route::VerifierMember {
                address: [i; 20],
                pq_public_key: vec![0u8; 1952],
                operator: hex::encode([i; 32]),
                rpc_provider: format!("rpc{i}"),
            })
            .collect();
        drawn.validate().unwrap();
        put(
            &mut state,
            drawn.storage_key(),
            serde_json::to_vec(&drawn).unwrap(),
        );
        let err = gov_carry(
            &executor,
            &mut state,
            &a,
            &set_mode(BridgeRouteMode::Open, false),
        )
        .await
        .expect_err("an unverified anchor must not open");
        assert!(
            err.to_string()
                .contains("light_client has not been bootstrapped"),
            "{err}"
        );

        // Once the light client holds state started from the anchor, it opens.
        let anchor = route.light_client.clone().unwrap();
        put(&mut state, anchor.store_key(&route), vec![1]);
        gov_carry(
            &executor,
            &mut state,
            &a,
            &set_mode(BridgeRouteMode::Open, false),
        )
        .await
        .unwrap();
        assert_eq!(
            read_bridge_route_mode(&state, adapter, &chain),
            BridgeRouteMode::Open
        );
        assert!(bridge_route_open_refusal(&state, adapter, &chain).is_none());

        // Disabling may take the expedited track; opening may not.
        gov_carry(
            &executor,
            &mut state,
            &a,
            &set_mode(BridgeRouteMode::Disabled, true),
        )
        .await
        .unwrap();
        assert_eq!(
            read_bridge_route_mode(&state, adapter, &chain),
            BridgeRouteMode::Disabled
        );
        let err = executor
            .execute_transaction(
                &gov_tx(
                    &a,
                    gov_propose_data(&set_mode(BridgeRouteMode::Open, true)),
                    100_000,
                    0,
                ),
                &mut state,
            )
            .await
            .expect_err("opening must not take the expedited track");
        assert!(err.to_string().contains("expedited"), "{err}");
    }

    /// Removing a route that was never installed is refused at submission.
    #[tokio::test]
    async fn removing_an_absent_bridge_route_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        let action = crate::governance::ProposalAction::RemoveBridgeRoute {
            adapter: tenzro_types::bridge_route::BridgeRouteAdapter::Ccip,
            source_chain: "solana".into(),
            memo: String::new(),
        };
        assert!(
            executor
                .execute_transaction(
                    &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                    &mut state
                )
                .await
                .is_err()
        );
    }

    /// **Standing, never property.** The sanction withdraws an identity and
    /// touches no balance. A power that could also reach the subject's funds
    /// would be confiscation wearing a procedural name.
    #[tokio::test]
    async fn revoking_an_identity_moves_no_value() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let subject = gov_canonical(0x33);
        state.set_balance(subject.as_bytes(), 7_777);
        let treasury = derive_treasury_address().as_bytes().to_vec();
        state.set_balance(&treasury, 10_000);

        let did = "did:tenzro:machine:subject";
        gov_register_identity(&mut state, did);
        gov_give_identity(&mut state, subject.as_bytes(), did);

        let action = crate::governance::ProposalAction::RevokeIdentity {
            did: did.to_string(),
            reason: "evidence".into(),
        };
        let enacted = gov_carry(&executor, &mut state, &a, &action).await.unwrap();

        assert_eq!(
            enacted.output,
            0u128.to_le_bytes().to_vec(),
            "a sanction reports no value moved"
        );
        assert_eq!(
            state.get_balance(subject.as_bytes()),
            7_777,
            "revocation must not reach the subject's balance"
        );
        assert_eq!(state.get_balance(&treasury), 10_000);
    }

    /// Voting on a DID that was never registered spends a voting period and a
    /// timelock on nothing and leaves a passed proposal that cannot enact —
    /// which reads afterwards as the network having failed to act.
    #[tokio::test]
    async fn a_revocation_of_an_unregistered_identity_is_refused_at_submission() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let action = crate::governance::ProposalAction::RevokeIdentity {
            did: "did:tenzro:machine:never-existed".into(),
            reason: "evidence".into(),
        };
        let err = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await;
        assert!(err.is_err(), "there is nothing to revoke");
    }

    /// A second sanction against an already-revoked identity would have the
    /// vote decide something already decided.
    #[tokio::test]
    async fn an_identity_cannot_be_revoked_twice() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let did = "did:tenzro:machine:subject";
        gov_register_identity(&mut state, did);

        let action = crate::governance::ProposalAction::RevokeIdentity {
            did: did.to_string(),
            reason: "evidence".into(),
        };
        gov_carry(&executor, &mut state, &a, &action).await.unwrap();

        let second = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await;
        assert!(second.is_err(), "already revoked");
    }

    /// An action applies once. Two enactments in the same window must not pay twice.
    #[tokio::test]
    async fn a_grant_cannot_be_enacted_twice() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        let treasury = derive_treasury_address().as_bytes().to_vec();
        state.set_balance(&treasury, 200_000);
        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 4_000,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        let id = created.output.clone();
        executor
            .execute_transaction(
                &gov_tx(&a, gov_vote_data(&id, true, &a), 30_000, 10),
                &mut state,
            )
            .await
            .unwrap();

        let after = crate::governance::VOTING_PERIOD_MS + 1;
        executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, after),
                &mut state,
            )
            .await
            .expect("queueing a passed proposal");

        // Inside the timelock the proposal is not yet enactable, and saying so
        // is the whole point of the window.
        let too_early = executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, after + 1),
                &mut state,
            )
            .await;
        assert!(
            too_early.is_err(),
            "a queued proposal must wait out its timelock"
        );

        let past_timelock = after + crate::governance::TIMELOCK_DELAY_MS + 1;
        executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, past_timelock),
                &mut state,
            )
            .await
            .expect("enacting after the timelock");

        let second = executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, past_timelock + 1),
                &mut state,
            )
            .await;

        assert!(second.is_err(), "a proposal must enact exactly once");
        assert_eq!(
            state.get_balance(recipient.as_bytes()),
            4_000,
            "the recipient must not be paid a second time"
        );
    }

    /// The tally cannot be snapshotted at a convenient moment.
    #[tokio::test]
    async fn a_proposal_cannot_be_enacted_while_voting_is_open() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        let treasury = derive_treasury_address().as_bytes().to_vec();
        state.set_balance(&treasury, 200_000);
        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 1_000,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        let id = created.output.clone();
        executor
            .execute_transaction(
                &gov_tx(&a, gov_vote_data(&id, true, &a), 30_000, 10),
                &mut state,
            )
            .await
            .unwrap();

        let err = executor
            .execute_transaction(&gov_tx(&a, gov_execute_data(&id), 120_000, 20), &mut state)
            .await;
        assert!(
            err.is_err(),
            "enactment before the window closes must be refused"
        );
        assert_eq!(state.get_balance(recipient.as_bytes()), 0);
    }

    /// A proposal the electorate voted down does not pay out.
    #[tokio::test]
    async fn a_rejected_grant_pays_nothing() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        let b = vec![2u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        gov_bond(&mut state, &b, GOV_STAKE);
        let treasury = derive_treasury_address().as_bytes().to_vec();
        state.set_balance(&treasury, 10_000);
        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 4_000,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        let id = created.output.clone();

        // 50/50 clears quorum but not the two-thirds threshold.
        executor
            .execute_transaction(
                &gov_tx(&a, gov_vote_data(&id, true, &a), 30_000, 10),
                &mut state,
            )
            .await
            .unwrap();
        executor
            .execute_transaction(
                &gov_tx(&b, gov_vote_data(&id, false, &b), 30_000, 10),
                &mut state,
            )
            .await
            .unwrap();

        let after = crate::governance::VOTING_PERIOD_MS + 1;
        let err = executor
            .execute_transaction(
                &gov_tx(&a, gov_execute_data(&id), 120_000, after),
                &mut state,
            )
            .await;
        assert!(err.is_err(), "a split vote must not move the treasury");
        assert_eq!(state.get_balance(recipient.as_bytes()), 0);
        assert_eq!(state.get_balance(&treasury), 10_000);
    }

    /// Changing a vote moves the weight instead of counting twice.
    #[tokio::test]
    async fn revoting_replaces_the_earlier_ballot() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);
        let recipient = gov_canonical(0x22);
        gov_give_identity(&mut state, recipient.as_bytes(), "did:tenzro:machine:test");

        let action = crate::governance::ProposalAction::TreasuryGrant {
            recipient,
            amount: 1,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        let created = executor
            .execute_transaction(
                &gov_tx(&a, gov_propose_data(&action), 100_000, 0),
                &mut state,
            )
            .await
            .unwrap();
        let id = created.output.clone();

        executor
            .execute_transaction(
                &gov_tx(&a, gov_vote_data(&id, true, &a), 30_000, 10),
                &mut state,
            )
            .await
            .unwrap();
        executor
            .execute_transaction(
                &gov_tx(&a, gov_vote_data(&id, false, &a), 30_000, 20),
                &mut state,
            )
            .await
            .unwrap();

        let tally = load_tally(&state, &hex::encode(&id));
        assert_eq!(
            (tally.yes, tally.no),
            (0, GOV_STAKE),
            "the earlier yes must be withdrawn, not kept alongside the no"
        );
        assert_eq!(
            tally.participation(),
            GOV_STAKE,
            "one voter is one voter's worth"
        );
    }

    /// A payload that is not a valid action is refused rather than stored.
    #[tokio::test]
    async fn an_untyped_proposal_payload_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        gov_bond(&mut state, &a, GOV_STAKE);

        let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
        data.extend_from_slice(b"Increase block gas limit to 50M");
        let err = executor
            .execute_transaction(&gov_tx(&a, data, 100_000, 0), &mut state)
            .await;
        assert!(
            err.is_err(),
            "a proposal that decodes to no action must not be stored"
        );
    }

    // ---- Validator staking (register escrow / exit refund) tests -------------

    /// A software composite key standing in for a validator's hardware key.
    struct TestConsensusKey {
        ml_dsa: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
        p256: p256::ecdsa::SigningKey,
        public: tenzro_consensus::ValidatorPublicKey,
    }

    impl TestConsensusKey {
        fn new(seed: u8) -> Self {
            let ml_dsa =
                ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&[seed; 32].into());
            let mut s = [seed; 32];
            s[0] = 1;
            let p256 = p256::ecdsa::SigningKey::from_slice(&s).unwrap();
            let public = tenzro_consensus::ValidatorPublicKey::new(
                ml_dsa.verifying_key().encode().to_vec(),
                p256.verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
            Self {
                ml_dsa,
                p256,
                public,
            }
        }
    }

    impl tenzro_consensus::ValidatorSigner for TestConsensusKey {
        fn public_key(&self) -> &tenzro_consensus::ValidatorPublicKey {
            &self.public
        }
        fn sign(
            &self,
            domain: &[u8],
            message: &[u8],
        ) -> tenzro_consensus::Result<tenzro_consensus::CompositeSignature> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            use sha2::Digest;
            let rep =
                tenzro_consensus::validator_key::message_representative(domain, message).unwrap();
            let ml = self
                .ml_dsa
                .sign_deterministic(&rep, tenzro_consensus::validator_key::ml_dsa_context())
                .unwrap();
            let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
            let ec: p256::ecdsa::Signature = self.p256.sign_prehash(&digest).unwrap();
            Ok(tenzro_consensus::CompositeSignature {
                ml_dsa: ml.encode().to_vec(),
                p256: ec.to_bytes().to_vec(),
            })
        }
    }

    /// The 20-byte account of the test node key `[seed; 32]`.
    fn account(seed: u8) -> Vec<u8> {
        vec![seed; 20]
    }

    /// A registration from `account(seed)`, every proof made by the key it
    /// names.
    fn make_register_validator_data(seed: u8, self_stake: u128) -> Vec<u8> {
        let key = TestConsensusKey::new(seed);
        let node = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        register_validator_data_with(&account(seed), self_stake, &key, &key, &node, &node)
    }

    /// The test VRF key of a node: a key of its own, not the node key.
    fn test_vrf_key(node_key: &[u8; 32]) -> tenzro_crypto::vrf::VrfSecretKey {
        use sha2::Digest;
        tenzro_crypto::vrf::VrfSecretKey(
            sha2::Sha256::new()
                .chain_update(b"test vrf key")
                .chain_update(node_key)
                .finalize()
                .into(),
        )
    }

    /// Registers `key` and `node`'s key from `from`, with the consensus
    /// key's proof made by `prover` and the node key's by `node_prover`.
    fn register_validator_data_with(
        from: &[u8],
        self_stake: u128,
        key: &dyn tenzro_consensus::ValidatorSigner,
        prover: &dyn tenzro_consensus::ValidatorSigner,
        node: &tenzro_crypto::signatures::Ed25519SignerImpl,
        node_prover: &tenzro_crypto::signatures::Ed25519SignerImpl,
    ) -> Vec<u8> {
        use tenzro_crypto::Signer;
        let node_key: [u8; 32] = node.public_key().as_bytes().try_into().unwrap();
        let proof =
            tenzro_consensus::validator_key::prove_registration(prover, from, &node_key).unwrap();
        let node_key_proof = node_prover
            .sign(
                &tenzro_consensus::validator_key::node_key_registration_message(
                    from,
                    key.public_key(),
                    &node_key,
                ),
            )
            .unwrap()
            .to_bytes();
        let vrf = test_vrf_key(&node_key);
        let vrf_key = tenzro_crypto::vrf::VrfProver::public_key(&vrf).0;
        let vrf_key_proof = tenzro_crypto::vrf::VrfProver::prove(
            &vrf,
            &tenzro_consensus::validator_key::vrf_key_registration_alpha(
                from,
                key.public_key(),
                &node_key,
                &vrf_key,
            ),
        )
        .unwrap();
        let payload = serde_json::json!({
            "ml_dsa_pubkey": key.public_key().ml_dsa,
            "p256_pubkey": key.public_key().p256,
            "node_key": node_key,
            "proof_of_possession": proof,
            "node_key_proof": node_key_proof,
            "vrf_key": vrf_key,
            "vrf_key_proof": vrf_key_proof.as_bytes().to_vec(),
            "withdrawal_address": Address::new([9u8; 32]),
            "self_stake": self_stake,
            "metadata_uri": "",
        });
        let mut data = SELECTOR_VALIDATOR_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    /// A consensus key registers only under a scheme governance admits: an
    /// ML-DSA-87 key is refused at genesis and registers once governance
    /// admits its scheme; once governance admits ML-DSA-87 alone, a new
    /// ML-DSA-65 key is refused while the key registered before stays.
    #[tokio::test]
    async fn a_consensus_key_registers_only_under_a_scheme_governance_admits() {
        use tenzro_consensus::ValidatorSigner as _;
        use tenzro_consensus::validator_key::SignatureScheme;
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        let set = |state: &mut StateAdapter, value: u64| {
            state.set_storage(
                &SYSTEM_ADDRESS,
                governed_param_key(staking::SIGNATURE_SCHEMES_PARAM).as_bytes(),
                value.to_le_bytes().to_vec(),
            )
        };
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        set(&mut state, staking::DEFAULT_SIGNATURE_SCHEMES);
        let stake: u128 = 1_000_000_000_000_000;
        let register = |seed: u8, key: &SoftwareTestSigner, nonce: u64| {
            let node = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
            VmTransaction::new(
                account(seed),
                None,
                0,
                register_validator_data_with(&account(seed), stake, key, key, &node, &node),
                300_000,
                1_000_000_000,
                nonce,
                VmType::Evm,
                1337,
            )
        };
        let ok = |r: &Result<ExecutionResult>| matches!(r, Ok(x) if x.success);
        for seed in [41u8, 42] {
            state.set_balance(&account(seed), 10_000_000_000_000_000_000);
        }
        let new_key = SoftwareTestSigner::from_seed_with_scheme(41, SignatureScheme::MlDsa87P384);
        assert_eq!(new_key.public_key().scheme(), SignatureScheme::MlDsa87P384);
        let r = executor
            .execute_transaction(&register(41, &new_key, 0), &mut state)
            .await;
        assert!(
            !ok(&r),
            "an ML-DSA-87 key registered before governance admitted it"
        );

        set(&mut state, 0b11);
        let n = state.get_nonce(&account(41));
        let r = executor
            .execute_transaction(&register(41, &new_key, n), &mut state)
            .await;
        assert!(ok(&r), "{r:?}");
        assert_eq!(
            staking::account_of_consensus_key(&state, &new_key.public_key().fingerprint()),
            Some(account(41))
        );

        set(&mut state, 0b10);
        let old_key = SoftwareTestSigner::from_seed(42);
        let r = executor
            .execute_transaction(&register(42, &old_key, 0), &mut state)
            .await;
        assert!(
            !ok(&r),
            "an ML-DSA-65 key registered after governance retired the scheme"
        );
        assert_eq!(
            staking::account_of_consensus_key(&state, &new_key.public_key().fingerprint()),
            Some(account(41))
        );
    }

    /// A seated validator replaces its consensus key with one of another
    /// scheme without exiting: the new key proves possession, its scheme
    /// must be admitted, it must be registered to no one, and the old key
    /// stays indexed to the validator so evidence against it still reaches
    /// the bond. Someone who is not a validator cannot rotate.
    #[tokio::test]
    async fn a_validator_rotates_its_consensus_key_to_another_scheme_without_exiting() {
        use tenzro_consensus::ValidatorSigner as _;
        use tenzro_consensus::validator_key::SignatureScheme;
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let set = |state: &mut StateAdapter, value: u64| {
            state.set_storage(
                &SYSTEM_ADDRESS,
                governed_param_key(staking::SIGNATURE_SCHEMES_PARAM).as_bytes(),
                value.to_le_bytes().to_vec(),
            )
        };
        set(&mut state, staking::DEFAULT_SIGNATURE_SCHEMES);
        let ok = |r: &Result<ExecutionResult>| matches!(r, Ok(x) if x.success);
        let call = |from: &[u8], data: Vec<u8>, nonce: u64| {
            VmTransaction::new(
                from.to_vec(),
                None,
                0,
                data,
                300_000,
                1_000_000_000,
                nonce,
                VmType::Evm,
                1337,
            )
        };
        let (seed, stranger) = (51u8, 52u8);
        let from = account(seed);
        for a in [from.clone(), account(stranger)] {
            state.set_balance(&a, 10_000_000_000_000_000_000);
        }
        let old = SoftwareTestSigner::from_seed(51);
        let node = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let reg =
            register_validator_data_with(&from, 1_000_000_000_000_000, &old, &old, &node, &node);
        assert!(ok(&executor
            .execute_transaction(&call(&from, reg, 0), &mut state)
            .await));
        let node_key: [u8; 32] = {
            use tenzro_crypto::Signer;
            node.public_key().as_bytes().try_into().unwrap()
        };

        let new = SoftwareTestSigner::from_seed_with_scheme(53, SignatureScheme::MlDsa87P384);
        let rotate = |who: &[u8], key: &SoftwareTestSigner, prover: &SoftwareTestSigner| {
            let proof = tenzro_consensus::validator_key::prove_registration(prover, who, &node_key)
                .unwrap();
            let mut d = SELECTOR_VALIDATOR_ROTATE_KEY.to_vec();
            d.extend(
                serde_json::to_vec(&serde_json::json!({
                    "ml_dsa_pubkey": key.public_key().ml_dsa,
                    "p256_pubkey": key.public_key().p256,
                    "proof_of_possession": proof,
                }))
                .unwrap(),
            );
            d
        };
        let n = |s: &StateAdapter, a: &[u8]| s.get_nonce(a);

        let r = executor
            .execute_transaction(
                &call(&from, rotate(&from, &new, &new), n(&state, &from)),
                &mut state,
            )
            .await;
        assert!(!ok(&r), "a scheme governance does not admit");
        set(&mut state, 0b11);
        let r = executor
            .execute_transaction(
                &call(&from, rotate(&from, &new, &old), n(&state, &from)),
                &mut state,
            )
            .await;
        assert!(!ok(&r), "a proof made by another key");
        let r = executor
            .execute_transaction(
                &call(
                    &account(stranger),
                    rotate(&account(stranger), &new, &new),
                    0,
                ),
                &mut state,
            )
            .await;
        assert!(!ok(&r), "a sender that is not a validator");

        let r = executor
            .execute_transaction(
                &call(&from, rotate(&from, &new, &new), n(&state, &from)),
                &mut state,
            )
            .await
            .unwrap();
        assert!(r.success);
        let log = r
            .logs
            .iter()
            .find(|l| {
                l.topics
                    .first()
                    .is_some_and(|t| t == VALIDATOR_KEY_ROTATION_TOPIC)
            })
            .expect("a rotation log");
        let (who, ml, ec) = decode_validator_key_rotation_log(&log.data).unwrap();
        assert_eq!(
            (who, ml, ec),
            (
                from.as_slice(),
                new.public_key().ml_dsa.as_slice(),
                new.public_key().p256.as_slice()
            )
        );
        for key in [&old, &new] {
            assert_eq!(
                staking::account_of_consensus_key(&state, &key.public_key().fingerprint()),
                Some(from.clone())
            );
        }
        let record: serde_json::Value = serde_json::from_slice(
            &state
                .get_storage(
                    &SYSTEM_ADDRESS,
                    format!("validator_register:{}", hex::encode(&from)).as_bytes(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            record["ml_dsa_pubkey"],
            serde_json::json!(new.public_key().ml_dsa)
        );
        assert!(
            staking::bonded_stake_of(&state, &from) > 0,
            "the bond stays"
        );

        let again = executor
            .execute_transaction(
                &call(&from, rotate(&from, &new, &new), n(&state, &from)),
                &mut state,
            )
            .await;
        assert!(!ok(&again), "a key already registered");
    }

    #[tokio::test]
    async fn a_validator_registration_without_a_valid_proof_of_possession_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let from = account(0x42);
        let key = TestConsensusKey::new(3);
        let other = TestConsensusKey::new(4);
        let node = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let squatter = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let stake = 1_000_000_000_000_000_000;
        // A proof made by a different key, a proof made for a different
        // sender, and a node key signed for by someone else: none admits
        // the key.
        for data in [
            register_validator_data_with(&from, stake, &key, &other, &node, &node),
            register_validator_data_with(&account(0x43), stake, &key, &key, &node, &node),
            register_validator_data_with(&from, stake, &key, &key, &node, &squatter),
        ] {
            let mut state = StateAdapter::new();
            state.set_balance(&from, 10_000_000_000_000_000_000_000u128);
            let tx = VmTransaction::new(
                from.clone(),
                None,
                0,
                data,
                300_000,
                1_000_000_000,
                0,
                VmType::Evm,
                1337,
            );
            let result = executor.execute_transaction(&tx, &mut state).await;
            let refused = match result {
                Err(_) => true,
                Ok(r) => !r.success,
            };
            assert!(refused, "a registration without a valid proof must fail");
            assert!(
                state
                    .get_storage(
                        &SYSTEM_ADDRESS,
                        format!("validator_register:{}", hex::encode(&from)).as_bytes()
                    )
                    .is_none(),
                "no registration marker is written"
            );
        }
    }

    /// A registration indexes its VRF key, not its node key, for the beacon;
    /// one whose VRF key is its node key, or whose VRF proof is missing, is
    /// refused.
    #[tokio::test]
    async fn a_validator_registers_a_vrf_key_of_its_own() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let from = account(0x44);
        let key = TestConsensusKey::new(5);
        let node = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let stake = 1_000_000_000_000_000_000;
        let good = register_validator_data_with(&from, stake, &key, &key, &node, &node);
        let payload: serde_json::Value = serde_json::from_slice(&good[4..]).unwrap();
        let mut same = payload.clone();
        same["vrf_key"] = payload["node_key"].clone();
        let mut unproven = payload.clone();
        unproven["vrf_key_proof"] = serde_json::json!(vec![0u8; 80]);
        let encode = |v: &serde_json::Value| {
            let mut d = SELECTOR_VALIDATOR_REGISTER.to_vec();
            d.extend(serde_json::to_vec(v).unwrap());
            d
        };
        let run = |data: Vec<u8>| {
            let from = from.clone();
            let executor = &executor;
            async move {
                let mut state = StateAdapter::new();
                state.set_balance(&from, 10_000_000_000_000_000_000_000u128);
                let tx = VmTransaction::new(
                    from,
                    None,
                    0,
                    data,
                    300_000,
                    1_000_000_000,
                    0,
                    VmType::Evm,
                    1337,
                );
                let ok = matches!(executor.execute_transaction(&tx, &mut state).await, Ok(r) if r.success);
                (ok, state)
            }
        };
        for bad in [encode(&same), encode(&unproven)] {
            let (ok, state) = run(bad).await;
            assert!(
                !ok,
                "a registration without its own proven VRF key must fail"
            );
            assert!(staking::vrf_key_of(&state, &from).is_none());
        }
        let (ok, state) = run(good).await;
        assert!(ok);
        let vrf_key: [u8; 32] = serde_json::from_value(payload["vrf_key"].clone()).unwrap();
        let node_key: [u8; 32] = serde_json::from_value(payload["node_key"].clone()).unwrap();
        assert_eq!(staking::vrf_key_of(&state, &from), Some(vrf_key));
        assert_ne!(vrf_key, node_key);
    }

    fn register_tx(seed: u8, self_stake: u128, nonce: u64) -> VmTransaction {
        let data = make_register_validator_data(seed, self_stake);
        VmTransaction::new(
            account(seed),
            None,
            0,
            data,
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
        let from = account(1);
        let stake: u128 = 1_000_000_000_000_000; // 1e15 wei
        let start: u128 = 10_000_000_000_000_000_000; // 10 TNZO
        state.set_balance(&from, start);

        let tx = register_tx(1, stake, 0);
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
        let from = account(2);
        let stake: u128 = 1_000_000_000_000_000_000; // 1 TNZO
        let start: u128 = 500_000_000_000_000_000; // 0.5 TNZO — gas ok, stake not
        state.set_balance(&from, start);

        let tx = register_tx(2, stake, 0);
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
        let from = account(3);
        state.set_balance(&from, 10_000_000_000_000_000_000);

        let tx = register_tx(3, 0, 0);
        assert!(
            executor.execute_transaction(&tx, &mut state).await.is_err(),
            "zero-stake registration must be rejected"
        );
    }

    // ---- RegisterIdentity ----------------------------------------

    /// A controller key with its secret, so a registration can be signed the
    /// way a real one is.
    fn controller(tag: u8) -> tenzro_crypto::composite::testing::TestHybridSigner {
        tenzro_crypto::composite::testing::TestHybridSigner::hybrid(tag)
    }

    fn controller_pk(tag: u8) -> Vec<u8> {
        use tenzro_crypto::composite::HybridSigner as _;
        controller(tag).public_key().p256.clone()
    }

    fn sign_registration(
        signer: &tenzro_crypto::composite::testing::TestHybridSigner,
        statement: &[u8; 32],
    ) -> tenzro_types::identity::RegistrationProof {
        use tenzro_crypto::composite::HybridSigner as _;
        tenzro_types::identity::RegistrationProof::Hardware {
            signature: signer
                .sign(
                    tenzro_crypto::composite::SignatureContext::IdentityRegistration,
                    statement,
                )
                .unwrap(),
        }
    }

    /// Build a registration and sign it with `signer`. Passing a signer that
    /// is not the controller is how the tests forge one.
    fn make_identity_register_data(
        did: &str,
        controller_pubkey: &[u8],
        signer: &tenzro_crypto::composite::testing::TestHybridSigner,
        wallet_tag: u8,
    ) -> Vec<u8> {
        let mut payload = tenzro_types::identity::RegisterIdentityPayload {
            did: did.to_string(),
            identity_type: "human".to_string(),
            display_name: "Alice".to_string(),
            controller_pubkey: controller_pubkey.to_vec(),
            key_type: "P256".to_string(),
            wallet_id: "wallet-1".to_string(),
            wallet_address: Address::new([wallet_tag; 32]),
            pq_verifying_key: {
                use tenzro_crypto::composite::HybridSigner as _;
                signer
                    .public_key()
                    .pq
                    .clone()
                    .unwrap_or_else(|| vec![1u8; 1952])
            },
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let statement = tenzro_types::identity::registration_statement(&payload);
        payload.proof = sign_registration(signer, &statement);
        let mut data = SELECTOR_IDENTITY_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        data
    }

    fn human_did(passkey: &[u8]) -> String {
        format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(passkey)
        )
    }

    /// The DID a controller key owns.
    fn did_of(tag: u8) -> String {
        human_did(&controller_pk(tag))
    }

    fn identity_register_tx(from: Vec<u8>, tag: u8, nonce: u64) -> VmTransaction {
        identity_register_tx_with(
            from,
            &did_of(tag),
            &controller_pk(tag),
            &controller(tag),
            nonce,
            7,
        )
    }

    fn identity_register_tx_with(
        from: Vec<u8>,
        did: &str,
        controller_pubkey: &[u8],
        signer: &tenzro_crypto::composite::testing::TestHybridSigner,
        nonce: u64,
        wallet_tag: u8,
    ) -> VmTransaction {
        VmTransaction::new(
            from,
            None,
            0,
            make_identity_register_data(did, controller_pubkey, signer, wallet_tag),
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

        let did_owned = did_of(9);
        let did = did_owned.as_str();
        let tx = identity_register_tx(from.clone(), 9, 0);
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
                .any(|l| l.topics.first().map(|t| t.as_slice())
                    == Some(b"IdentityRegister".as_ref())),
            "IdentityRegister log must be emitted"
        );
    }

    #[tokio::test]
    async fn test_identity_register_duplicate_did_rejected() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let did_owned = did_of(9);
        let did = did_owned.as_str();

        // First registration by controller A succeeds.
        let tx1 = identity_register_tx(from.clone(), 9, 0);
        assert!(
            executor
                .execute_transaction(&tx1, &mut state)
                .await
                .unwrap()
                .success
        );

        // Second registration of the SAME did by a DIFFERENT controller is
        // refused fail-closed (consensus-enforced DID uniqueness).
        let tx2 =
            identity_register_tx_with(from.clone(), did, &controller_pk(8), &controller(8), 1, 7);
        assert!(
            executor
                .execute_transaction(&tx2, &mut state)
                .await
                .is_err(),
            "duplicate DID from a different controller must be rejected"
        );
    }

    /// Nobody can pre-register the DID a victim's passkey derives, and no DID
    /// that derives from nothing is accepted.
    #[tokio::test]
    async fn test_identity_register_squatting_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let victim_did = did_of(9);
        let tx = identity_register_tx_with(
            from.clone(),
            &victim_did,
            &controller_pk(8),
            &controller(8),
            0,
            7,
        );
        assert!(executor.execute_transaction(&tx, &mut state).await.is_err());
        let tx = identity_register_tx_with(
            from.clone(),
            "did:tenzro:human:chosen-by-me",
            &controller_pk(8),
            &controller(8),
            0,
            7,
        );
        assert!(executor.execute_transaction(&tx, &mut state).await.is_err());
        assert!(
            state
                .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(&victim_did))
                .is_none()
        );
    }

    /// The victim's own public key is not enough: registering their DID takes
    /// their secret. Without this, reading a passkey's public half is all it
    /// costs to claim someone's identity and point its wallet at your address.
    #[tokio::test]
    async fn a_registration_needs_the_controllers_signature() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);

        // The attacker has the victim's public key and their own secret.
        let forged = identity_register_tx_with(
            from.clone(),
            &did_of(9),
            &controller_pk(9),
            &controller(8),
            0,
            /* the attacker's wallet */ 3,
        );
        assert!(
            executor
                .execute_transaction(&forged, &mut state)
                .await
                .is_err(),
            "a registration signed by anyone but the controller must be refused"
        );

        // The same statement signed by the controller is accepted.
        let real = identity_register_tx(from.clone(), 9, 0);
        assert!(
            executor
                .execute_transaction(&real, &mut state)
                .await
                .unwrap()
                .success
        );
    }

    /// Once the controller has an ML-DSA-65 key enrolled in state, a
    /// registration signed with the P-256 leg alone is refused: the hybrid is
    /// checked against the stored key, never one the registration names.
    #[tokio::test]
    async fn a_registration_by_an_enrolled_controller_needs_the_hybrid() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let pq =
            tenzro_crypto::composite::testing::TestHybridSigner::hybrid_pq_key(&controller_pk(9))
                .expect("seed 9 hybrid key");
        crate::account_keys::set_enrolled_pq_key(
            &mut state,
            &controller_pk(9),
            pq,
            &mut Vec::new(),
        );

        let p256_only = identity_register_tx_with(
            from.clone(),
            &did_of(9),
            &controller_pk(9),
            &tenzro_crypto::composite::testing::TestHybridSigner::p256_only(9),
            0,
            7,
        );
        assert!(
            executor
                .execute_transaction(&p256_only, &mut state)
                .await
                .is_err()
        );

        let hybrid = identity_register_tx_with(
            from.clone(),
            &did_of(9),
            &controller_pk(9),
            &tenzro_crypto::composite::testing::TestHybridSigner::hybrid(9),
            0,
            7,
        );
        assert!(
            executor
                .execute_transaction(&hybrid, &mut state)
                .await
                .unwrap()
                .success
        );
    }

    /// Hardware with no ML-DSA-65 key registers nothing: a registration that
    /// names none, signed with P-256 alone, is refused.
    #[tokio::test]
    async fn a_registration_without_an_ml_dsa_key_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(9);

        let mut payload: tenzro_types::identity::RegisterIdentityPayload = serde_json::from_slice(
            &identity_register_tx_with(from.clone(), &did_of(9), &controller_pk(9), &signer, 0, 7)
                .data[4..],
        )
        .unwrap();
        payload.pq_verifying_key = Vec::new();
        let statement = tenzro_types::identity::registration_statement(&payload);
        payload.proof = sign_registration(&signer, &statement);
        let mut data = SELECTOR_IDENTITY_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            300_000,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        assert!(executor.execute_transaction(&tx, &mut state).await.is_err());
        assert!(
            executor
                .execute_transaction(&identity_register_tx(from, 9, 0), &mut state)
                .await
                .unwrap()
                .success,
            "the same identity registers once its hardware names an ML-DSA-65 key"
        );
    }

    /// The signature covers the wallet address, so it cannot be lifted off one
    /// registration and replayed onto a record that pays somewhere else.
    #[tokio::test]
    async fn a_registration_signature_does_not_transfer_to_another_wallet() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);

        let mut payload = tenzro_types::identity::RegisterIdentityPayload {
            did: did_of(9),
            identity_type: "human".to_string(),
            display_name: "Alice".to_string(),
            controller_pubkey: controller_pk(9),
            key_type: "P256".to_string(),
            wallet_id: "wallet-1".to_string(),
            wallet_address: Address::new([7u8; 32]),
            pq_verifying_key: {
                use tenzro_crypto::composite::HybridSigner as _;
                controller(9).public_key().pq.clone().unwrap()
            },
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let statement = tenzro_types::identity::registration_statement(&payload);
        payload.proof = sign_registration(&controller(9), &statement);
        // Redirect the wallet after signing.
        payload.wallet_address = Address::new([3u8; 32]);
        let mut data = SELECTOR_IDENTITY_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            300_000,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        assert!(executor.execute_transaction(&tx, &mut state).await.is_err());
    }

    /// The class must be the one the DID names, so a machine record cannot be
    /// filed under a human DID and read back under the other class's rules.
    #[tokio::test]
    async fn a_registration_class_must_match_its_did() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);

        let mut payload = tenzro_types::identity::RegisterIdentityPayload {
            did: did_of(9),
            identity_type: "machine".to_string(),
            display_name: "Alice".to_string(),
            controller_pubkey: controller_pk(9),
            key_type: "P256".to_string(),
            wallet_id: "wallet-1".to_string(),
            wallet_address: Address::new([7u8; 32]),
            pq_verifying_key: {
                use tenzro_crypto::composite::HybridSigner as _;
                controller(9).public_key().pq.clone().unwrap()
            },
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let statement = tenzro_types::identity::registration_statement(&payload);
        payload.proof = sign_registration(&controller(9), &statement);
        let mut data = SELECTOR_IDENTITY_REGISTER.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        let tx = VmTransaction::new(
            from.clone(),
            None,
            0,
            data,
            300_000,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        assert!(executor.execute_transaction(&tx, &mut state).await.is_err());
    }

    /// A second identity cannot take over an address already indexed to
    /// another identity.
    #[tokio::test]
    async fn test_identity_register_cannot_claim_another_identitys_wallet() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let first = identity_register_tx(from.clone(), 9, 0);
        assert!(
            executor
                .execute_transaction(&first, &mut state)
                .await
                .unwrap()
                .success
        );
        // A different identity, signed by its own controller, claiming the
        // same wallet address.
        let second = identity_register_tx_with(
            from.clone(),
            &did_of(6),
            &controller_pk(6),
            &controller(6),
            1,
            7,
        );
        assert!(
            executor
                .execute_transaction(&second, &mut state)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_identity_register_same_controller_refresh_ok() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let tx1 = identity_register_tx(from.clone(), 9, 0);
        assert!(
            executor
                .execute_transaction(&tx1, &mut state)
                .await
                .unwrap()
                .success
        );
        // Same controller re-registers — idempotent refresh, not a rejection.
        let tx2 = identity_register_tx(from.clone(), 9, 1);
        assert!(
            executor
                .execute_transaction(&tx2, &mut state)
                .await
                .unwrap()
                .success,
            "same-controller re-registration must be allowed as a refresh"
        );
    }

    #[tokio::test]
    async fn test_validator_exit_refunds_stake() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = account(4);
        let stake: u128 = 1_000_000_000_000_000; // 1e15
        let start: u128 = 10_000_000_000_000_000_000;
        state.set_balance(&from, start);

        // Register (bonds the stake).
        let reg = register_tx(4, stake, 0);
        assert!(
            executor
                .execute_transaction(&reg, &mut state)
                .await
                .unwrap()
                .success
        );
        let after_register = state.get_balance(&from);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), stake);

        let exit_at = |nonce: u64, at_ms: i64| {
            let mut tx = VmTransaction::new(
                from.clone(),
                None,
                0,
                SELECTOR_VALIDATOR_EXIT.to_vec(),
                200_000,
                1_000_000_000,
                nonce,
                VmType::Evm,
                1337,
            );
            tx.block_timestamp_ms = Some(at_ms);
            tx
        };
        let start_ms: i64 = 1_700_000_000_000;

        // First exit: the bond starts unbonding and stays in the vault.
        let first = executor
            .execute_transaction(&exit_at(1, start_ms), &mut state)
            .await
            .unwrap();
        assert!(first.success);
        assert_eq!(state.get_balance(&from), after_register - EXIT_GAS_COST);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), stake);

        // Withdrawing before the unbonding period ends is refused.
        let early = executor
            .execute_transaction(
                &exit_at(
                    2,
                    start_ms + (staking::DEFAULT_VALIDATOR_UNBONDING_MS as i64) - 1,
                ),
                &mut state,
            )
            .await;
        assert!(early.is_err() || !early.unwrap().success);
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), stake);

        // After it ends, the second exit pays the stake out.
        let second = executor
            .execute_transaction(
                &exit_at(
                    2,
                    start_ms + (staking::DEFAULT_VALIDATOR_UNBONDING_MS as i64),
                ),
                &mut state,
            )
            .await
            .unwrap();
        assert!(second.success);
        assert_eq!(
            state.get_balance(&from),
            after_register - 2 * EXIT_GAS_COST + stake
        );
        assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), 0);
        let bond = state.get_storage(
            &SYSTEM_ADDRESS,
            format!("staking_bond:{}", hex::encode(&from)).as_bytes(),
        );
        assert!(
            bond.map(|b| b.is_empty()).unwrap_or(true),
            "bond record cleared"
        );
    }

    /// The account a `ValidatorExit` log names is read back from the log the
    /// handler emits, for both exit steps.
    #[tokio::test]
    async fn the_exit_log_names_the_validator_that_exited() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let from = account(7);
        state.set_balance(&from, 10_000_000_000_000_000_000);
        let stake: u128 = 1_000_000_000_000_000;
        assert!(
            executor
                .execute_transaction(&register_tx(7, stake, 0), &mut state)
                .await
                .unwrap()
                .success
        );
        let start_ms: i64 = 1_700_000_000_000;
        for (nonce, at) in [
            (1u64, start_ms),
            (2, start_ms + staking::DEFAULT_VALIDATOR_UNBONDING_MS as i64),
        ] {
            let mut tx = VmTransaction::new(
                from.clone(),
                None,
                0,
                SELECTOR_VALIDATOR_EXIT.to_vec(),
                200_000,
                1_000_000_000,
                nonce,
                VmType::Evm,
                1337,
            );
            tx.block_timestamp_ms = Some(at);
            let r = executor.execute_transaction(&tx, &mut state).await.unwrap();
            assert!(r.success);
            let log = r
                .logs
                .iter()
                .find(|l| l.topics.first().is_some_and(|t| t == b"ValidatorExit"))
                .expect("an exit log");
            assert_eq!(validator_exit_log_account(&log.data), Some(from.as_slice()));
        }
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

    fn native_tx(from: Vec<u8>, data: Vec<u8>, nonce: u64) -> VmTransaction {
        VmTransaction::new(
            from,
            None,
            0,
            data,
            2_000_000,
            1_000_000_000,
            nonce,
            VmType::Tenzro,
            1337,
        )
    }

    fn preimage_claim_data(escrow_id: [u8; 32], preimage: &[u8]) -> Vec<u8> {
        let mut data = SELECTOR_ESCROW_PREIMAGE_CLAIM.to_vec();
        data.extend(
            serde_json::to_vec(&serde_json::json!({
                "escrow_id": escrow_id,
                "preimage": preimage,
            }))
            .unwrap(),
        );
        data
    }

    /// A native transaction at `at_ms` with free gas, so balances show
    /// exactly the value moved.
    fn timed(from: Vec<u8>, data: Vec<u8>, nonce: u64, at_ms: i64) -> VmTransaction {
        let mut tx = native_tx(from, data, nonce);
        tx.block_timestamp_ms = Some(at_ms);
        tx.gas_price = 0;
        tx
    }

    #[tokio::test]
    async fn a_stream_escrow_opens_with_create_escrow_at_a_bounded_rate() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let payer = vec![1u8; 32];
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let t0 = 1_800_000_000_000i64;
        let create = timed(
            payer,
            make_create_escrow_data(
                &Address::new([2u8; 32]),
                1_000,
                (t0 + 100_000) as u64,
                ReleaseConditions::Stream {
                    rate_per_epoch: 100,
                    epoch_ms: 1_000,
                },
            ),
            0,
            t0,
        );
        let r = executor
            .execute_transaction(&create, &mut state)
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.revert_reason);
        let escrow_id: [u8; 32] = r.output.clone().try_into().unwrap();
        let escrow = payment_settlement::read_escrow(&state, &escrow_id).unwrap();
        assert!(matches!(
            escrow.release_conditions,
            ReleaseConditions::Stream {
                rate_per_epoch: 100,
                ..
            }
        ));
        for bad in [
            ReleaseConditions::Stream {
                rate_per_epoch: 0,
                epoch_ms: 1_000,
            },
            ReleaseConditions::Stream {
                rate_per_epoch: 1_001,
                epoch_ms: 1_000,
            },
            ReleaseConditions::Stream {
                rate_per_epoch: 100,
                epoch_ms: 0,
            },
        ] {
            let tx = timed(
                vec![1u8; 32],
                make_create_escrow_data(
                    &Address::new([2u8; 32]),
                    1_000,
                    (t0 + 100_000) as u64,
                    bad,
                ),
                1,
                t0,
            );
            let reason = match executor.execute_transaction(&tx, &mut state).await {
                Ok(r) => r.revert_reason.unwrap_or_default(),
                Err(e) => e.to_string(),
            };
            assert!(reason.contains("positive rate"), "{reason}");
        }
    }

    #[tokio::test]
    async fn a_hash_locked_escrow_pays_its_payee_only_against_the_preimage() {
        use sha2::{Digest, Sha256};
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        // Wei-sized amounts: the least-fee floor would take them whole.
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(economy::MIN_SETTLEMENT_FEE_PARAM).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
        let payer = vec![1u8; 32];
        let payee = Address::new([2u8; 32]);
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let key = [5u8; 32];
        let hash: [u8; 32] = Sha256::digest(key).into();
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 3_600_000;
        let create = native_tx(
            payer.clone(),
            make_create_escrow_data(
                &payee,
                5_000,
                expires_at,
                ReleaseConditions::HashLock { hash },
            ),
            0,
        );
        let created = executor
            .execute_transaction(&create, &mut state)
            .await
            .unwrap();
        assert!(created.success);
        let escrow_id: [u8; 32] = created.output[..32].try_into().unwrap();

        let claimer = vec![3u8; 32];
        state.set_balance(&claimer, 10_000_000_000_000_000_000u128);
        let wrong = native_tx(
            claimer.clone(),
            preimage_claim_data(escrow_id, &[6u8; 32]),
            0,
        );
        let r = executor.execute_transaction(&wrong, &mut state).await;
        assert!(r.is_err() || !r.unwrap().success);
        assert_eq!(state.get_balance(payee.as_bytes()), 0);

        // The payee receives the escrow less the settlement fee.
        let paid = 5_000 - 5_000 * u128::from(economy::DEFAULT_SETTLEMENT_FEE_BPS) / 10_000;
        let right = native_tx(claimer.clone(), preimage_claim_data(escrow_id, &key), 0);
        let r = executor
            .execute_transaction(&right, &mut state)
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(state.get_balance(payee.as_bytes()), paid);
        assert!(r.logs[0].data.ends_with(&key));

        // Spent: a second opening pays nothing more.
        let again = native_tx(claimer, preimage_claim_data(escrow_id, &key), 1);
        let r = executor.execute_transaction(&again, &mut state).await;
        assert!(r.is_err() || !r.unwrap().success);
        assert_eq!(state.get_balance(payee.as_bytes()), paid);
    }

    #[tokio::test]
    async fn a_sealed_delivery_pays_the_network_its_share_and_no_settlement_fee_once() {
        use sha2::{Digest, Sha256};
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(economy::MIN_SETTLEMENT_FEE_PARAM).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
        let payer = vec![1u8; 32];
        let seller = Address::new([2u8; 32]);
        let treasury = tenzro_types::network_treasury_address();
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let key = [5u8; 32];
        let hash: [u8; 32] = Sha256::digest(key).into();
        let lock = ReleaseConditions::HashLock { hash };
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 3_600_000;
        let bps = u128::from(network_param(&state, economy::HTTP402_NETWORK_SHARE_PARAM));
        let price = 1_000_000u128;
        let share = price * bps / 10_000;
        let create = |payee: &Address, amount: u128, nonce: u64| {
            native_tx(
                payer.clone(),
                make_create_escrow_data(payee, amount, expires_at, lock.clone()),
                nonce,
            )
        };
        let mut ids = Vec::new();
        for (nonce, (payee, amount)) in [
            (&seller, price - share),
            (&treasury, share),
            (&seller, price - share),
        ]
        .into_iter()
        .enumerate()
        {
            let r = executor
                .execute_transaction(&create(payee, amount, nonce as u64), &mut state)
                .await
                .unwrap();
            assert!(r.success);
            ids.push(<[u8; 32]>::try_from(&r.output[..32]).unwrap());
        }
        let claimer = vec![3u8; 32];
        state.set_balance(&claimer, 10_000_000_000_000_000_000u128);
        let claim = |id: [u8; 32], nonce: u64| {
            native_tx(claimer.clone(), preimage_claim_data(id, &key), nonce)
        };

        // The seller is paid its amount whole: the network was paid its
        // share in its own escrow.
        let r = executor
            .execute_transaction(&claim(ids[0], 0), &mut state)
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(state.get_balance(seller.as_bytes()), price - share);

        // The network escrow is the share itself: the treasury is paid it
        // whole.
        let treasury_before = state.get_balance(treasury.as_bytes());
        let r = executor
            .execute_transaction(&claim(ids[1], 1), &mut state)
            .await
            .unwrap();
        assert!(r.success);
        assert_eq!(
            state.get_balance(treasury.as_bytes()),
            treasury_before + share
        );

        // One network escrow exempts one payout: a second seller escrow under
        // the same lock pays the settlement fee.
        let r = executor
            .execute_transaction(&claim(ids[2], 2), &mut state)
            .await
            .unwrap();
        assert!(r.success);
        let second = price - share;
        let fee = second * u128::from(economy::DEFAULT_SETTLEMENT_FEE_BPS) / 10_000;
        assert_eq!(
            state.get_balance(seller.as_bytes()),
            price - share + second - fee
        );
    }

    /// A transaction refused, for `why` when the refusal is an error.
    fn refused(r: Result<ExecutionResult>, why: &str) {
        match r {
            Err(e) => assert!(e.to_string().contains(why), "{e}"),
            Ok(res) => assert!(!res.success, "applied while {why}"),
        }
    }

    /// An escrow vault holding less than its record still owes freezes the
    /// escrow module at the end of the block: escrows can be neither made,
    /// released nor refunded, payment-channel claims go on, and the freeze
    /// holds until governance lifts it with the vault restored.
    #[tokio::test]
    async fn an_escrow_vault_short_of_its_record_freezes_escrow_only() {
        use crate::invariant_monitor::{self as monitor, GuardedModule};
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) = create_consumer_escrow(&executor, &mut state).await;
        // The block that made the escrow ends with every vault covered.
        assert!(monitor::check_block(&mut state).is_empty());

        // A planted bug in an escrow path pays 2 000 out of the vault to a
        // stranger without touching the escrow record. Supply is conserved;
        // the path still records what the vault owes, as every escrow path
        // does.
        let thief = [9u8; 32];
        state.set_balance(vault.as_bytes(), 3_000);
        state.set_balance(&thief, 2_000);
        let escrow = payment_settlement::read_escrow(&state, &escrow_id).unwrap();
        record_escrow_owed(&mut state, GuardedModule::Escrow, &escrow).unwrap();

        let frozen_now = monitor::check_block(&mut state);
        assert_eq!(frozen_now.len(), 1, "{frozen_now:?}");
        assert_eq!(frozen_now[0].0, GuardedModule::Escrow);
        assert_eq!((frozen_now[0].1.held, frozen_now[0].1.owed), (3_000, 5_000));

        // Escrow refuses: no new escrow, no release of the short one.
        state.set_balance(&[2u8; 32], 1_000_000_000_000_000_000u128);
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 3_600_000;
        let create = native_tx(
            vec![1u8; 32],
            make_create_escrow_data(
                &Address::new([2u8; 32]),
                5_000,
                expires_at,
                ReleaseConditions::Timeout,
            ),
            1,
        );
        refused(
            executor.execute_transaction(&create, &mut state).await,
            "escrow is frozen",
        );
        assert!(monitor::require_unfrozen(&state, GuardedModule::PaymentChannel).is_ok());
        assert!(monitor::require_unfrozen(&state, GuardedModule::Staking).is_ok());
        assert_eq!(state.get_balance(vault.as_bytes()), 3_000);

        // Lifted while still short: frozen again at the end of the next block.
        monitor::lift(&mut state, GuardedModule::Escrow).unwrap();
        assert_eq!(monitor::check_block(&mut state).len(), 1);
        // Restored, then lifted: stays lifted.
        state.set_balance(vault.as_bytes(), 5_000);
        state.set_balance(&thief, 0);
        monitor::lift(&mut state, GuardedModule::Escrow).unwrap();
        assert!(monitor::check_block(&mut state).is_empty());
        assert!(monitor::require_unfrozen(&state, GuardedModule::Escrow).is_ok());
    }

    /// Payment-channel claims record what the escrow vault still owes, and a
    /// channel vault short of it freezes payment channels only: a claim is
    /// refused, escrows keep working.
    #[tokio::test]
    async fn a_short_channel_vault_freezes_payment_channels_only() {
        use crate::invariant_monitor::{self as monitor, GuardedModule};
        use sha2::{Digest, Sha256};
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(economy::MIN_SETTLEMENT_FEE_PARAM).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
        let payer = vec![1u8; 32];
        let payee = Address::new([2u8; 32]);
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let key = [5u8; 32];
        let hash: [u8; 32] = Sha256::digest(key).into();
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 3_600_000;
        let mut ids = Vec::new();
        for nonce in 0..2 {
            let create = native_tx(
                payer.clone(),
                make_create_escrow_data(
                    &payee,
                    5_000,
                    expires_at,
                    ReleaseConditions::HashLock { hash },
                ),
                nonce,
            );
            let created = executor
                .execute_transaction(&create, &mut state)
                .await
                .unwrap();
            assert!(created.success);
            ids.push(<[u8; 32]>::try_from(&created.output[..32]).unwrap());
        }
        assert!(monitor::check_block(&mut state).is_empty());

        // A claim on the first channel records that its vault owes nothing.
        let claimer = vec![3u8; 32];
        state.set_balance(&claimer, 10_000_000_000_000_000_000u128);
        let claim = native_tx(claimer.clone(), preimage_claim_data(ids[0], &key), 0);
        assert!(
            executor
                .execute_transaction(&claim, &mut state)
                .await
                .unwrap()
                .success
        );
        assert!(monitor::check_block(&mut state).is_empty());

        // A planted bug in a claim path leaves the second channel's vault
        // 1 000 short of what its escrow record owes.
        let vault = derive_vault_address(&ids[1]);
        state.set_balance(vault.as_bytes(), 4_000);
        state.set_balance(&[9u8; 32], 1_000);
        let escrow = payment_settlement::read_escrow(&state, &ids[1]).unwrap();
        record_escrow_owed(&mut state, GuardedModule::PaymentChannel, &escrow).unwrap();
        let frozen_now = monitor::check_block(&mut state);
        assert_eq!(frozen_now.len(), 1, "{frozen_now:?}");
        assert_eq!(frozen_now[0].0, GuardedModule::PaymentChannel);

        let claim = native_tx(claimer, preimage_claim_data(ids[1], &key), 1);
        refused(
            executor.execute_transaction(&claim, &mut state).await,
            "payment_channel is frozen",
        );
        assert_eq!(state.get_balance(vault.as_bytes()), 4_000);
        assert!(monitor::require_unfrozen(&state, GuardedModule::Escrow).is_ok());
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
        // A release is a settlement: the payee gets it less the settlement fee.
        assert_eq!(
            state.get_balance(payee_addr.as_bytes()),
            5_000 - crate::native::economy::settlement_fee(&state, 5_000).min(5_000)
        );

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

    /// A funded `ConsumerSignature` escrow from payer `[1; 32]` to payee
    /// `[2; 32]`, and its vault.
    async fn create_consumer_escrow(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
    ) -> ([u8; 32], Address) {
        create_escrow_with(executor, state, ReleaseConditions::ConsumerSignature).await
    }

    /// A funded escrow under `conditions` from payer `[1; 32]` to payee
    /// `[2; 32]` (both funded for gas), and its vault.
    async fn create_escrow_with(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        conditions: ReleaseConditions,
    ) -> ([u8; 32], Address) {
        state.set_balance(&[2u8; 32], 1_000_000_000_000_000_000u128);
        let payer = vec![1u8; 32];
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 24 * 60 * 60 * 1000;
        let tx = VmTransaction::new(
            payer,
            None,
            0,
            make_create_escrow_data(&Address::new([2u8; 32]), 5_000, expires_at, conditions),
            GAS_ESCROW_CREATE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let res = executor.execute_transaction(&tx, state).await.unwrap();
        assert!(res.success);
        let escrow_id: [u8; 32] = res.output.as_slice().try_into().unwrap();
        (escrow_id, derive_vault_address(&escrow_id))
    }

    /// A release proof carrying an Ed25519 signature by `key` over `data`,
    /// claiming the consumer role.
    fn proof_signed_by(
        key: &tenzro_crypto::signatures::Ed25519SignerImpl,
        data: &[u8],
    ) -> ServiceProof {
        use tenzro_crypto::Signer;
        let mut proof = ServiceProof::new(
            tenzro_types::settlement::ProofType::Cryptographic,
            data.to_vec(),
        );
        proof
            .signatures
            .push(tenzro_types::settlement::ProofSignature {
                signer: Address::new(key.public_key().as_bytes().try_into().unwrap()),
                signature: key.sign(data).unwrap().to_bytes(),
                role: tenzro_types::settlement::SignerRole::Consumer,
            });
        proof
    }

    /// A stranger holding an Ed25519 key of its own cannot release someone
    /// else's consumer escrow by signing the release proof with it.
    #[tokio::test]
    async fn a_strangers_own_key_does_not_release_a_consumer_escrow() {
        use tenzro_crypto::Signer;
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) = create_consumer_escrow(&executor, &mut state).await;
        let stranger_key = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let stranger = stranger_key.public_key().as_bytes().to_vec();
        state.set_balance(&stranger, 10_000_000_000_000_000_000u128);

        let res = executor
            .execute_transaction(
                &release_tx(
                    &stranger,
                    escrow_id,
                    proof_signed_by(&stranger_key, b"release"),
                ),
                &mut state,
            )
            .await;

        assert!(
            res.is_err() || !res.unwrap().success,
            "a stranger released the escrow"
        );
        assert_eq!(state.get_balance(vault.as_bytes()), 5_000);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Funded);
    }

    /// The payee cannot release a consumer escrow to itself with a key it
    /// made up, whatever role the proof claims.
    #[tokio::test]
    async fn the_payee_does_not_release_a_consumer_escrow_with_a_key_of_its_own() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) = create_consumer_escrow(&executor, &mut state).await;
        let payee = vec![2u8; 32];
        state.set_balance(&payee, 1_000_000_000_000_000_000u128);
        let made_up = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();

        let res = executor
            .execute_transaction(
                &release_tx(&payee, escrow_id, proof_signed_by(&made_up, b"release")),
                &mut state,
            )
            .await;

        assert!(
            res.is_err() || !res.unwrap().success,
            "the payee released the escrow"
        );
        assert_eq!(state.get_balance(vault.as_bytes()), 5_000);
    }

    /// The consumer releases its escrow by signing the release transaction
    /// with its own account key; no separate key or proof signature is asked.
    #[tokio::test]
    async fn the_payer_releases_a_consumer_escrow_with_its_own_transaction() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) = create_consumer_escrow(&executor, &mut state).await;
        let proof = ServiceProof::new(tenzro_types::settlement::ProofType::Cryptographic, vec![]);

        let res = executor
            .execute_transaction(&release_tx(&[1u8; 32], escrow_id, proof), &mut state)
            .await
            .expect("the payer's release is accepted");

        assert!(res.success);
        assert_eq!(state.get_balance(vault.as_bytes()), 0);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Released);
    }

    /// A release proof carrying one Ed25519 signature over `data` from each
    /// of `keys`, every one claiming `role`.
    fn proof_signed_by_all(
        keys: &[tenzro_crypto::signatures::Ed25519SignerImpl],
        data: &[u8],
        role: tenzro_types::settlement::SignerRole,
    ) -> ServiceProof {
        use tenzro_crypto::Signer;
        let mut proof = ServiceProof::new(
            tenzro_types::settlement::ProofType::Cryptographic,
            data.to_vec(),
        );
        for key in keys {
            proof
                .signatures
                .push(tenzro_types::settlement::ProofSignature {
                    signer: Address::new(key.public_key().as_bytes().try_into().unwrap()),
                    signature: key.sign(data).unwrap().to_bytes(),
                    role,
                });
        }
        proof
    }

    fn escrow_status(state: &StateAdapter, escrow_id: &[u8; 32]) -> EscrowStatus {
        let key = escrow_storage_key(&hex::encode(escrow_id));
        let blob = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()).unwrap();
        serde_json::from_slice::<EscrowAccount>(&blob)
            .unwrap()
            .status
    }

    fn made_up_keys(n: usize) -> Vec<tenzro_crypto::signatures::Ed25519SignerImpl> {
        (0..n)
            .map(|_| tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap())
            .collect()
    }

    /// A provider escrow is released by the provider. The payer cannot stand
    /// in for it with a key of its own in the proof.
    #[tokio::test]
    async fn the_payer_does_not_release_a_provider_escrow_with_a_key_in_its_proof() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) =
            create_escrow_with(&executor, &mut state, ReleaseConditions::ProviderSignature).await;
        let proof = proof_signed_by_all(
            &made_up_keys(1),
            b"delivered",
            tenzro_types::settlement::SignerRole::Provider,
        );

        let res = executor
            .execute_transaction(&release_tx(&[1u8; 32], escrow_id, proof), &mut state)
            .await;

        assert!(
            res.is_err() || !res.unwrap().success,
            "a made-up key released the escrow"
        );
        assert_eq!(state.get_balance(vault.as_bytes()), 5_000);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Funded);
    }

    /// The provider releases a provider escrow with its own signed
    /// transaction once it has delivered.
    #[tokio::test]
    async fn the_provider_releases_a_provider_escrow_with_its_own_transaction() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) =
            create_escrow_with(&executor, &mut state, ReleaseConditions::ProviderSignature).await;
        let proof = ServiceProof::new(tenzro_types::settlement::ProofType::Cryptographic, vec![]);

        let res = executor
            .execute_transaction(&release_tx(&[2u8; 32], escrow_id, proof), &mut state)
            .await
            .expect("the provider's release is accepted");

        assert!(res.success);
        assert_eq!(state.get_balance(vault.as_bytes()), 0);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Released);
    }

    /// An escrow both parties must approve is not released by one of them,
    /// whatever keys its proof carries.
    #[tokio::test]
    async fn one_party_does_not_release_an_escrow_both_must_approve() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) =
            create_escrow_with(&executor, &mut state, ReleaseConditions::BothSignatures).await;
        let proof = proof_signed_by_all(
            &made_up_keys(2),
            b"both agree",
            tenzro_types::settlement::SignerRole::Consumer,
        );

        let _ = executor
            .execute_transaction(&release_tx(&[1u8; 32], escrow_id, proof), &mut state)
            .await;

        assert_eq!(state.get_balance(vault.as_bytes()), 5_000);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Funded);
    }

    /// Each party approves with its own signed transaction; the second
    /// approval releases the escrow.
    #[tokio::test]
    async fn an_escrow_both_must_approve_is_released_by_the_second_approval() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (escrow_id, vault) =
            create_escrow_with(&executor, &mut state, ReleaseConditions::BothSignatures).await;
        let empty =
            || ServiceProof::new(tenzro_types::settlement::ProofType::Cryptographic, vec![]);

        let first = executor
            .execute_transaction(&release_tx(&[1u8; 32], escrow_id, empty()), &mut state)
            .await
            .expect("the payer's approval is accepted");
        assert!(first.success);
        assert_eq!(state.get_balance(vault.as_bytes()), 5_000);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Funded);

        let second = executor
            .execute_transaction(&release_tx(&[2u8; 32], escrow_id, empty()), &mut state)
            .await
            .expect("the payee's approval is accepted");
        assert!(second.success);
        assert_eq!(state.get_balance(vault.as_bytes()), 0);
        assert_eq!(escrow_status(&state, &escrow_id), EscrowStatus::Released);
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

    // ---- Quorum-attested escrow release ------------------------------------

    fn quorum_member_key(seed: u8) -> k256::ecdsa::SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x21;
        bytes[31] = seed;
        k256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap()
    }

    fn quorum_member_address(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
        use sha3::Keccak256;
        let point = sk.verifying_key().to_sec1_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    fn quorum_committee() -> (
        Vec<k256::ecdsa::SigningKey>,
        tenzro_types::bridge_route::VerifierQuorum,
    ) {
        use tenzro_types::bridge_route::{VerifierMember, VerifierQuorum};
        let keys: Vec<_> = (1..=3).map(quorum_member_key).collect();
        let members: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| VerifierMember {
                address: quorum_member_address(k),
                pq_public_key: tenzro_bridge::route::attestation::testing::pq_key(&k.to_bytes()).verifying_key_bytes().to_vec(),
                operator: format!("operator-{i}"),
                rpc_provider: format!("participant-{i}"),
            })
            .collect();
        (
            keys,
            VerifierQuorum {
                set_index: 0,
                size: members.len() as u32,
                members,
                threshold: 2,
            },
        )
    }

    fn quorum_signature(
        sk: &k256::ecdsa::SigningKey,
        digest: &[u8; 32],
    ) -> tenzro_types::settlement::ProofSignature {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (sig, rec): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            sk.sign_prehash(digest).unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(rec.to_byte());
        let mut signer = [0u8; 32];
        signer[..20].copy_from_slice(&quorum_member_address(sk));
        tenzro_types::settlement::ProofSignature {
            signer: Address::new(signer),
            signature: bytes,
            role: tenzro_types::settlement::SignerRole::Verifier,
        }
    }

    const QUORUM_CLAIM: &str = r#"{"kind":"external_delivery"}"#;

    async fn create_quorum_escrow(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        payer: &[u8],
        payee: &Address,
        nonce: u64,
    ) -> [u8; 32] {
        let (_, verifiers) = quorum_committee();
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 24 * 60 * 60 * 1000;
        let tx = VmTransaction::new(
            payer.to_vec(),
            None,
            0,
            make_create_escrow_data(
                payee,
                5_000,
                expires_at,
                ReleaseConditions::QuorumAttestation {
                    claim: QUORUM_CLAIM.to_string(),
                    verifiers,
                },
            ),
            GAS_ESCROW_CREATE,
            1_000_000_000,
            nonce,
            VmType::Tenzro,
            1337,
        );
        let res = executor.execute_transaction(&tx, state).await.unwrap();
        assert!(res.success);
        res.output.as_slice().try_into().unwrap()
    }

    fn release_tx(from: &[u8], escrow_id: [u8; 32], proof: ServiceProof) -> VmTransaction {
        VmTransaction::new(
            from.to_vec(),
            None,
            0,
            make_release_escrow_data(escrow_id, proof),
            GAS_ESCROW_RELEASE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        )
    }

    /// Any account may release a quorum-attested escrow with a threshold of
    /// member signatures over this escrow; the payer takes no part.
    #[tokio::test]
    async fn quorum_escrow_releases_for_any_submitter_with_threshold_signatures() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let payer = vec![1u8; 32];
        let payee = Address::new([2u8; 32]);
        let relayer = vec![7u8; 32];
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        state.set_balance(&relayer, 10_000_000_000_000_000_000u128);
        let escrow_id = create_quorum_escrow(&executor, &mut state, &payer, &payee, 0).await;

        let (keys, _) = quorum_committee();
        let evidence = b"update-1|holding-1".to_vec();
        let digest = quorum_release_digest(&escrow_id, QUORUM_CLAIM, &evidence);
        let mut proof =
            ServiceProof::new(tenzro_types::settlement::ProofType::Cryptographic, evidence);
        proof.add_signature(quorum_signature(&keys[0], &digest));
        proof.add_signature(quorum_signature(&keys[2], &digest));

        let res = executor
            .execute_transaction(&release_tx(&relayer, escrow_id, proof), &mut state)
            .await
            .unwrap();
        assert!(res.success);
        assert_eq!(
            state.get_balance(payee.as_bytes()),
            5_000 - crate::native::economy::settlement_fee(&state, 5_000).min(5_000)
        );
        assert_eq!(
            state.get_balance(derive_vault_address(&escrow_id).as_bytes()),
            0
        );
    }

    /// Below threshold, a repeated member, a non-member, or signatures over
    /// another escrow's digest all leave the vault untouched.
    #[tokio::test]
    async fn quorum_escrow_refuses_insufficient_or_misbound_attestations() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let payer = vec![1u8; 32];
        let payee = Address::new([2u8; 32]);
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let escrow_id = create_quorum_escrow(&executor, &mut state, &payer, &payee, 0).await;
        let other_id = create_quorum_escrow(&executor, &mut state, &payer, &payee, 1).await;

        let (keys, _) = quorum_committee();
        let evidence = b"update-1|holding-1".to_vec();
        let digest = quorum_release_digest(&escrow_id, QUORUM_CLAIM, &evidence);
        let other_digest = quorum_release_digest(&other_id, QUORUM_CLAIM, &evidence);
        let outsider = quorum_member_key(9);
        let cases = [
            vec![quorum_signature(&keys[0], &digest)],
            vec![
                quorum_signature(&keys[0], &digest),
                quorum_signature(&keys[0], &digest),
            ],
            vec![
                quorum_signature(&keys[0], &digest),
                quorum_signature(&outsider, &digest),
            ],
            vec![
                quorum_signature(&keys[0], &other_digest),
                quorum_signature(&keys[1], &other_digest),
            ],
        ];
        for signatures in cases {
            let mut proof = ServiceProof::new(
                tenzro_types::settlement::ProofType::Cryptographic,
                evidence.clone(),
            );
            proof.signatures = signatures;
            let res = executor
                .execute_transaction(&release_tx(&payer, escrow_id, proof), &mut state)
                .await;
            assert!(res.is_err() || !res.unwrap().success);
            assert_eq!(
                state.get_balance(derive_vault_address(&escrow_id).as_bytes()),
                5_000
            );
        }
        assert_eq!(state.get_balance(payee.as_bytes()), 0);
    }

    /// A committee one operator can satisfy alone is refused at creation.
    #[tokio::test]
    async fn quorum_escrow_refuses_a_single_operator_committee() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let payer = vec![1u8; 32];
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let (_, mut verifiers) = quorum_committee();
        for m in &mut verifiers.members {
            m.operator = "one-operator".to_string();
        }
        let expires_at = chrono::Utc::now().timestamp_millis() as u64 + 60_000;
        let tx = VmTransaction::new(
            payer.clone(),
            None,
            0,
            make_create_escrow_data(
                &Address::new([2u8; 32]),
                5_000,
                expires_at,
                ReleaseConditions::QuorumAttestation {
                    claim: QUORUM_CLAIM.to_string(),
                    verifiers,
                },
            ),
            GAS_ESCROW_CREATE,
            1_000_000_000,
            0,
            VmType::Tenzro,
            1337,
        );
        let res = executor.execute_transaction(&tx, &mut state).await;
        assert!(res.is_err() || !res.unwrap().success);
        assert_eq!(state.get_balance(&payer), 10_000_000_000_000_000_000u128);
    }

    /// The payer cannot pull a quorum-attested escrow back before expiry.
    #[tokio::test]
    async fn quorum_escrow_refund_waits_for_expiry() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let payer = vec![1u8; 32];
        let payee = Address::new([2u8; 32]);
        state.set_balance(&payer, 10_000_000_000_000_000_000u128);
        let escrow_id = create_quorum_escrow(&executor, &mut state, &payer, &payee, 0).await;
        let tx = VmTransaction::new(
            payer.clone(),
            None,
            0,
            make_refund_escrow_data(escrow_id),
            GAS_ESCROW_REFUND,
            1_000_000_000,
            1,
            VmType::Tenzro,
            1337,
        );
        let res = executor.execute_transaction(&tx, &mut state).await;
        assert!(res.is_err() || !res.unwrap().success);
        assert_eq!(
            state.get_balance(derive_vault_address(&escrow_id).as_bytes()),
            5_000
        );
    }

    fn selector_tx(
        from: Vec<u8>,
        selector: [u8; 4],
        body: serde_json::Value,
        nonce: u64,
    ) -> VmTransaction {
        let mut data = selector.to_vec();
        data.extend_from_slice(&serde_json::to_vec(&body).unwrap());
        VmTransaction::new(
            from,
            None,
            0,
            data,
            300_000,
            1_000_000_000,
            nonce,
            VmType::Tenzro,
            1337,
        )
    }

    fn bond_validator(state: &mut StateAdapter, addr: &[u8], stake: u128) {
        gov_bond(state, addr, stake);
    }

    fn sla_tx(from: &[u8], epoch: u64, outcomes: &[(&str, bool)], now_ms: i64) -> VmTransaction {
        let outcomes: Vec<_> = outcomes
            .iter()
            .map(|(did, up)| serde_json::json!({"provider_did": did, "available": up}))
            .collect();
        let mut tx = selector_tx(
            from.to_vec(),
            SELECTOR_SLA_ATTEST,
            serde_json::json!({"epoch": epoch, "outcomes": outcomes}),
            0,
        );
        tx.block_timestamp_ms = Some(now_ms);
        tx
    }

    #[tokio::test]
    async fn an_sla_verdict_freezes_at_two_thirds_of_stake_and_follows_the_stake() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (a, b, c, d) = (vec![1u8; 20], vec![2u8; 20], vec![3u8; 20], vec![4u8; 20]);
        bond_validator(&mut state, &a, 100);
        bond_validator(&mut state, &b, 100);
        bond_validator(&mut state, &c, 300);
        bond_validator(&mut state, &d, 100);
        let did = "did:tenzro:machine:gpu";
        let vault = derive_compute_bond_vault_address(did);
        let bond: u128 = 1_000_000_000_000_000_000_000;
        let marker = serde_json::json!({
            "provider_did": did,
            "provider_address": hex::encode([7u8; 20]),
            "amount": bond.to_string(),
            "vault": hex::encode(vault.as_bytes()),
            "op": "Posted",
        });
        state.set_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(did).as_bytes(),
            serde_json::to_vec(&marker).unwrap(),
        );
        state.set_balance(vault.as_bytes(), bond);
        let now = 10 * MARKET_EPOCH_MS + 5;

        // An open epoch, an unbonded attester, and an unbonded provider are refused.
        assert!(
            executor
                .execute_transaction(&sla_tx(&a, 10, &[(did, true)], now), &mut state)
                .await
                .is_err()
        );
        let outsider = vec![9u8; 20];
        state.set_balance(&outsider, 10_000_000_000_000_000_000);
        assert!(
            executor
                .execute_transaction(&sla_tx(&outsider, 9, &[(did, true)], now), &mut state)
                .await
                .is_err()
        );
        assert!(
            executor
                .execute_transaction(
                    &sla_tx(&a, 9, &[("did:tenzro:machine:nobond", true)], now),
                    &mut state
                )
                .await
                .is_err()
        );

        assert!(
            executor
                .execute_transaction(&sla_tx(&a, 9, &[(did, true)], now), &mut state)
                .await
                .unwrap()
                .success
        );
        assert!(
            executor
                .execute_transaction(&sla_tx(&a, 9, &[(did, false)], now), &mut state)
                .await
                .is_err(),
            "one per validator"
        );
        executor
            .execute_transaction(&sla_tx(&b, 9, &[(did, true)], now), &mut state)
            .await
            .unwrap();
        assert_eq!(
            read_sla_verdict(&state, did, 9),
            None,
            "a third of the stake is not enough"
        );

        // c alone outweighs a and b together.
        let r = executor
            .execute_transaction(&sla_tx(&c, 9, &[(did, false)], now), &mut state)
            .await
            .unwrap();
        assert_eq!(r.logs[0].topics[0], SLA_VERDICT_TOPIC.to_vec());
        let v = read_sla_verdict(&state, did, 9).unwrap();
        assert!(!v.available);
        assert_eq!((v.up_stake, v.down_stake, v.attesters), (200, 300, 3));
        assert!(
            state.get_balance(vault.as_bytes()) < bond,
            "an unavailable verdict pays from the bond"
        );

        // Frozen: a late attestation cannot move it.
        assert!(
            executor
                .execute_transaction(&sla_tx(&d, 9, &[(did, true)], now), &mut state)
                .await
                .is_err()
        );
    }

    /// A fresh available verdict pays the availability reward from the
    /// treasury only once the governed per-unit-hour cap is nonzero and
    /// hardware binding is on and passed: nothing at the genesis cap, and
    /// nothing with a cap while binding is off.
    #[tokio::test]
    async fn an_available_sla_verdict_pays_the_governed_availability_reward() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let a = vec![1u8; 20];
        bond_validator(&mut state, &a, 100); // alone, outweighs two thirds of 100.
        let did = "did:tenzro:machine:gpu";
        let vault = derive_compute_bond_vault_address(did);
        let bond: u128 = 1_000_000_000_000_000_000_000;
        let marker = serde_json::json!({
            "provider_did": did,
            "provider_address": hex::encode([7u8; 20]),
            "amount": bond.to_string(),
            "vault": hex::encode(vault.as_bytes()),
            "op": "Posted",
        });
        state.set_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(did).as_bytes(),
            serde_json::to_vec(&marker).unwrap(),
        );
        state.set_balance(vault.as_bytes(), bond);
        let now = 10 * MARKET_EPOCH_MS + 5; // epoch 10 is current; epoch 9 is closed.
        let treasury: [u8; 32] = derive_treasury_address().as_bytes().try_into().unwrap();

        // Genesis default: the cap is zero, so an available verdict pays
        // nothing even though the treasury could cover it.
        state.set_balance(&treasury, 1_000_000);
        let r = executor
            .execute_transaction(&sla_tx(&a, 9, &[(did, true)], now), &mut state)
            .await
            .unwrap();
        assert!(
            !r.logs
                .iter()
                .any(|l| l.topics[0] == availability_reward::AVAILABILITY_REWARD_TOPIC.to_vec()),
            "the genesis-disabled reward must not pay"
        );
        assert_eq!(state.get_balance(&treasury), 1_000_000);

        // A second provider, so the cap set below applies to a fresh verdict.
        let did2 = "did:tenzro:machine:gpu2";
        let vault2 = derive_compute_bond_vault_address(did2);
        let marker2 = serde_json::json!({
            "provider_did": did2,
            "provider_address": hex::encode([8u8; 20]),
            "amount": bond.to_string(),
            "vault": hex::encode(vault2.as_bytes()),
            "op": "Posted",
        });
        state.set_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(did2).as_bytes(),
            serde_json::to_vec(&marker2).unwrap(),
        );
        state.set_balance(vault2.as_bytes(), bond);
        set_governed_param_for_test(
            &mut state,
            availability_reward::AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
            1_000,
        );
        let subject_owner = [8u8; 20]; // the provider_address marker2 names.
        let before = state.get_balance(subject_owner.as_slice());
        let r = executor
            .execute_transaction(&sla_tx(&a, 9, &[(did2, true)], now), &mut state)
            .await
            .unwrap();
        assert!(
            !r.logs
                .iter()
                .any(|l| l.topics[0] == availability_reward::AVAILABILITY_REWARD_TOPIC.to_vec()),
            "with hardware binding off a nonzero cap still pays nothing"
        );
        assert_eq!(state.get_balance(&treasury), 1_000_000);
        assert_eq!(state.get_balance(subject_owner.as_slice()), before);

        // Binding on, and a TPM-endorsed machine bonded as the provider.
        let did3 = availability_reward::tests::register_endorsed_machine(&mut state, 21);
        let vault3 = derive_compute_bond_vault_address(&did3);
        let marker3 = serde_json::json!({
            "provider_did": did3,
            "provider_address": hex::encode([9u8; 20]),
            "amount": bond.to_string(),
            "vault": hex::encode(vault3.as_bytes()),
            "op": "Posted",
        });
        state.set_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(&did3).as_bytes(),
            serde_json::to_vec(&marker3).unwrap(),
        );
        state.set_balance(vault3.as_bytes(), bond);
        set_governed_param_for_test(
            &mut state,
            availability_reward::AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM,
            1,
        );
        let bound_now = availability_reward::tests::BOUND_NOW_MS;
        let bound_epoch = (bound_now / MARKET_EPOCH_MS) as u64 - 1;
        let subject_owner = [9u8; 20];
        let r = executor
            .execute_transaction(
                &sla_tx(&a, bound_epoch, &[(&did3, true)], bound_now),
                &mut state,
            )
            .await
            .unwrap();
        assert_eq!(
            r.logs
                .iter()
                .filter(|l| l.topics[0] == availability_reward::AVAILABILITY_REWARD_TOPIC.to_vec())
                .count(),
            1,
            "a nonzero cap pays a bound machine exactly once for this fresh verdict"
        );
        assert_eq!(state.get_balance(&treasury), 1_000_000 - 1_000);
        assert_eq!(state.get_balance(subject_owner.as_slice()), 1_000);
    }

    /// A checkpoint-signers record from a bonded validator with nothing to
    /// spend, naming no gas price in a block whose base fee is above zero.
    fn checkpoint_record(from: &[u8], index: u64, anchor_round: u64) -> VmTransaction {
        let record = rewards::CheckpointSigners {
            epoch: 0,
            index,
            anchor_round,
            signers: vec![Address::new([0x51; 32]), Address::new([0x52; 32])],
        };
        let mut data = SELECTOR_CHECKPOINT_SIGNERS.to_vec();
        data.extend_from_slice(&serde_json::to_vec(&record).unwrap());
        VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            100_000,
            0,
            index,
            VmType::Tenzro,
            1337,
        )
    }

    #[tokio::test]
    async fn a_validator_with_nothing_to_spend_records_checkpoint_signers() {
        let runtime = crate::MultiVmRuntime::new(VmConfig::default())
            .await
            .unwrap();
        let mut state = StateAdapter::new();
        let validator = vec![0x50u8; 32];
        gov_bond(&mut state, &validator, 1_000);
        state.set_balance(&validator, 0);
        let base_fee = 40_000_000_000u128;

        let mut fees = crate::ledger::BlockFees::default();
        for (index, round) in [(0, 3), (1, 7)] {
            let tx = checkpoint_record(&validator, index, round);
            match crate::ledger::execute_in_block(&runtime, &mut state, &tx, base_fee, &mut fees)
                .await
            {
                crate::ledger::TxOutcome::Applied { fee, .. } => assert_eq!(fee, 0),
                other => panic!("record {index} not applied: {other:?}"),
            }
        }
        assert_eq!(state.get_balance(&validator), 0);
        assert_eq!(state.get_nonce(&validator), 2);
        assert_eq!(fees.collected, 0);
        let votes = rewards::read_epoch_votes(&state, 0).unwrap();
        assert_eq!(votes.last_index, Some(1));
        assert_eq!(votes.certified_rounds, 8);
    }

    #[tokio::test]
    async fn a_refused_checkpoint_record_charges_nothing_and_spends_its_nonce() {
        let runtime = crate::MultiVmRuntime::new(VmConfig::default())
            .await
            .unwrap();
        let mut state = StateAdapter::new();
        // No bond: the record is refused, and still costs the account
        // nothing, so no account's balance decides what a block holds.
        let account = vec![0x53u8; 32];
        let mut fees = crate::ledger::BlockFees::default();
        let tx = checkpoint_record(&account, 0, 3);
        match crate::ledger::execute_in_block(&runtime, &mut state, &tx, 1, &mut fees).await {
            crate::ledger::TxOutcome::Reverted { fee, .. } => assert_eq!(fee, 0),
            other => panic!("record from an unbonded account not refused: {other:?}"),
        }
        assert_eq!(state.get_nonce(&account), 1);
        assert_eq!(
            rewards::read_epoch_votes(&state, 0).unwrap().last_index,
            None
        );

        // Only the protocol's records go free: any other transaction naming
        // no gas price is still held to the block's base fee.
        let mut transfer = checkpoint_record(&account, 1, 3);
        transfer.data = SELECTOR_TREASURY_DEPOSIT.to_vec();
        assert!(matches!(
            crate::ledger::execute_in_block(&runtime, &mut state, &transfer, 1, &mut fees).await,
            crate::ledger::TxOutcome::Rejected(_)
        ));
    }
}
