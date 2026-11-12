//! On-chain governance: typed proposals, stake-weighted tally, enactment.
//!
//! # What this replaces
//!
//! Governance used to be two handlers that recorded and forgot. `execute_propose`
//! stored an opaque `Vec<u8>` under `proposal:<id>` and `execute_vote` wrote a
//! single byte under `vote:<id>:<voter>`. Nothing read either back. There was no
//! tally, no quorum, no voting period, no proposal *meaning* — the payload was
//! untyped bytes — and nothing that enacted a passed proposal. Worse, any
//! address at all could vote: eligibility was never checked and votes were never
//! weighted, so a proposal's "result" was a pile of bytes an attacker could
//! stuff for the price of gas.
//!
//! This module is the decision logic that was missing. It is deliberately pure:
//! no `VmState`, no clock, no storage. Everything here is a function of values
//! the caller supplies, so the rules can be tested exhaustively and the handlers
//! in [`crate::native`] are left to do nothing but read state, call in here, and
//! write state back.
//!
//! # The rules
//!
//! - **Only bonded validators vote**, and a vote weighs exactly what the voter
//!   had bonded *at the moment they cast it*. Recording the weight at vote time
//!   rather than reading it at tally time is what stops a validator bonding more
//!   after voting to retroactively inflate a ballot already cast.
//! - **Quorum** — at least the governed quorum share ([`QUORUM_BPS`] at
//!   genesis) of all bonded stake must participate. Without it, a proposal nobody noticed passes
//!   on one vote.
//! - **Threshold** — at least the governed threshold ([`THRESHOLD_BPS`] at
//!   genesis) of the stake that *did* vote must be in favour. A supermajority rather than
//!   a simple majority, because what these proposals move is the treasury.
//! - **The voting period closes.** A proposal is decided when
//!   its voting period has elapsed, and not before — so a tally cannot be
//!   snapshotted early at a moment that happens to favour the proposer.
//!
//! # Safeguards, and why each one is shaped this way
//!
//! Governance began as a treasury grant voted by three validators and enacted
//! the instant it carried. That is survivable at that scale and stops being
//! survivable the moment governance can change consensus parameters, correct
//! the books, or delegate to something that acts on its own. What follows is
//! the set of powers added to make those things safe, each with the reason it
//! exists — because a safeguard whose purpose is forgotten is a safeguard
//! someone eventually removes as overhead.
//!
//! ## The timelock is the foundation
//!
//! A passed proposal enters [`ProposalStatus::Queued`] with an `eta_ms` and
//! enacts only once that instant passes. Queuing and enacting are two calls,
//! deliberately: doing both in one transaction would set the deadline and
//! clear it in the same instant, leaving the delay real in the type system and
//! nowhere else.
//!
//! Everything else depends on this. The delay lets holders exit the system
//! if they disagree with a decision before it is executed; it also means a proposal carrying a bug has a bounded window in which it can
//! still be stopped. It is also the only place a guardian can act, the only
//! place the community sees a decision before it lands, and the natural
//! dispute period for a verifiable-inference receipt.
//!
//! **If you shorten or remove this, everything below stops working.**
//!
//! ## Guardians hold negative powers only
//!
//! Two roles, separate: Protocol Guardians pause, Governance Guardians veto.
//! They differ in blast radius: a pause halts enactment briefly, a veto kills
//! one decision permanently. A role holding both can quietly become the
//! government.
//!
//! Guardians are seated only by an enacted `SetGuardian` proposal (or at
//! genesis), each for a fixed term, and must be human identities. No single
//! guardian acts alone: a veto or pause takes effect once
//! `governance.guardian_threshold` distinct seated guardians of the role have
//! signed it, and a pause lifts by itself after `governance.max_pause_ms`.
//!
//! Every guardian power *stops* things and originates nothing. There is no
//! guardian action that moves funds, sets a parameter or enacts a proposal.
//! That asymmetry is what keeps an emergency brake from being a back door: the
//! worst a captured guardian achieves is refusing to let the network act,
//! which is visible immediately, rather than acting in its name, which may not
//! be. **Preserve this property in anything added here.**
//!
//! The pause stops enactment and not deliberation. Voting, proposing and
//! vetoing continue while paused, because freezing debate during an emergency
//! would leave the power that imposed the pause as the only way out of it.
//!
//! ## Actions are classified by how they fail
//!
//! [`ActionDomain`] splits by failure mode, not subject matter. `Network`
//! decisions are reversible — a parameter set wrongly is corrected by setting
//! it again, and the cost is degraded operation for a timelock. `Treasury`
//! decisions move value, and a payment to the wrong address is not corrected
//! by a later vote.
//!
//! [`ProposalAction::domain`] is an exhaustive match, so a new action cannot
//! be added without someone deciding which side it falls on. "Nobody thought
//! about whether an agent should be allowed to do this" fails the build
//! instead of shipping.
//!
//! ## Agent autonomy is granted, never assumed
//!
//! [`AgentPhase`] scopes what agents may originate and defaults to
//! [`AgentPhase::None`]. Whether agents should originate anything is a
//! question the network answers by voting, and a permissive default would
//! answer it by omission. Advancing the phase is itself a governed decision:
//! timelocked, visible, vetoable.
//!
//! The enforcement keys on `did:tenzro:agent:` and **not**
//! `did:tenzro:machine:`. This distinction is load-bearing and was nearly got
//! wrong: every validator holds a machine identity, machine identities are
//! what hold stake, and gating them would leave nobody able to propose
//! anything at the default phase — governance locked shut. A machine identity
//! says what the keys are bound to; an agent identity says what kind of thing
//! decided. A validator operated by a person is hardware with an operator.
//!
//! ## Tracks trade speed against a higher bar
//!
//! [`ProposalTrack::Expedited`] is faster *and* harder — a shorter window at
//! the same threshold would simply be a way to pass something while fewer
//! people are watching. An emergency worth the speed is one obviously right
//! enough to clear 4/5 in six hours. The shortened timelock is still a real
//! window, because a guardian needs somewhere to act.
//!
//! A proposal stores its track rather than looking it up per step, so timing
//! cannot change underneath a vote already in progress.
//!
//! ## Recovery is narrow by construction
//!
//! [`ProposalAction::RecoverUnownedFunds`] exists because its absence made an
//! accounting error permanent: value left two accounts into the staking vault,
//! the registry recorded no stake, and there was no legitimate way to say the
//! funds were nobody's. The dangerous version of this power is "governance may
//! move any balance", which is confiscation with a polite name. The difference
//! must stay structural:
//!
//! - the source must be a system-held sink that can hold funds nobody owns,
//!   never a user account and never the treasury: the treasury's balance is
//!   owned by the network and leaves only through a gated payout;
//! - the destination is the treasury: unowned funds belong to the network,
//!   and paying a person is a payout, which needs an approved recipient and
//!   verified work, not a recovery;
//! - the claimed amount is settled against actual state at submission and at
//!   enactment, and for the staking vault only what it holds beyond what it
//!   owes validators counts;
//! - the memo carries the evidence, and an empty one is refused.
//!
//! ## Revocation is standing, never property
//!
//! [`ProposalAction::RevokeIdentity`] exists because without it every rule
//! about identities was advisory. The registry could always revoke on its
//! holder's own authority, and a holder acting in bad faith does not revoke
//! themselves — so the network had no way to withdraw standing it had granted,
//! and "we enforce this on bad actors" was not true of anything.
//!
//! The dangerous version is the one that also reaches the party's balance.
//! That is confiscation, it is a different power, and it must not arrive
//! bundled behind a word that sounds procedural. So the boundary is
//! structural:
//!
//! - it withdraws standing, and touches no balance;
//! - it cascades to controlled machines, because a sanction that left them
//!   running would not be one;
//! - the subject must exist in consensus state, checked at submission and
//!   again at enactment;
//! - the reason is recorded on-chain, and an empty one is refused;
//! - re-registration stays open. A permanent ban is a further power and should
//!   be argued for on its own terms.
//!
//! It is [`ActionDomain::Sanction`], which is neither of the other two on
//! purpose — see that variant.
//!
//! # Deliberately not built
//!
//! **Spend periods and burn-unspent.** Polkadot's treasury burns what it does
//! not allocate, creating pressure to spend. That pressure is noise until the
//! treasury has real claims on it, and the mechanism needs a period and a burn
//! destination decided first. A policy choice, not a missing safeguard.
//!
//! **Quadratic or conviction voting.** Stake-weighted is what the validator
//! set already is. Changing the weighting is a governance-design decision that
//! should be made deliberately rather than inherited from whoever wrote the
//! tally.
//!
//! # If you are adding an action
//!
//! 1. Classify it in [`ProposalAction::domain`]. The match is exhaustive; this
//!    is the point at which someone decides whether an agent may originate it.
//! 2. Validate it in [`ProposalAction::validate`], and reject impossible
//!    values *at submission*. Discovering a bad value at enactment means the
//!    failure lands after a vote has carried, where nobody is watching.
//! 3. Re-check anything that could have moved between submission and
//!    enactment. A voting period and a timelock separate them, and tables can
//!    change in an upgrade.
//! 4. If it moves value, it is `Treasury`. If it takes something away from a
//!    named party, it is `Sanction`. Either way it inherits the timelock, the
//!    veto and the agent boundary automatically.
//!
//! # If you are adding a governed parameter
//!
//! Add it to [`GOVERNED_PARAMS`] with bounds that still leave a working
//! network. Bounds are not decoration: a sync tolerance of zero makes every
//! node sync continuously, an epoch of zero divides by zero. Governance may
//! change these values and may not change them into a network that does not
//! run. A constant *not* in that table still needs a rebuild to change, which
//! is the honest signal that nobody decided it should be adjustable at
//! runtime.
//!
//! # The failure mode this module is built against
//!
//! Repeatedly, on this codebase: **something declared and never read.** A
//! guardian role with no consumer, a parameter with no reader, a rollback with
//! one caller in a test. Each looked like protection in review and provided
//! none. When adding a safeguard here, the question that matters is not "is it
//! defined" but "what refuses when it is violated, and is there a test that
//! proves the refusal".
//!
//! # Note on serde
//!
//! Nothing in this module uses `skip_serializing_if`. These types travel in
//! transaction payloads and are persisted into consensus state, and bincode is
//! not self-describing: an omitted field shifts every byte after it and
//! desynchronises the whole record. `#[serde(default)]` does not rescue that —
//! it only helps a self-describing format like JSON. This is the same footgun
//! that took provider discovery down network-wide, and it is cheap to avoid by
//! simply always writing the field.

use serde::{Deserialize, Serialize};
use tenzro_types::primitives::Address;
use tenzro_types::token::PolicyUpdate;

/// How long a proposal accepts votes, in milliseconds.
///
/// Measured against the block timestamp the transaction executes under, never
/// against wall-clock time: `Utc::now()` in a handler is a non-deterministic
/// syscall and two validators a few milliseconds apart would compute different
/// outcomes and fork.
pub const VOTING_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;

/// Quorum: the share of all bonded stake that must participate, bps; just
/// over one third at genesis.
pub const QUORUM_BPS: u64 = 3_334;

/// Threshold: the share of *participating* stake that must vote yes, bps;
/// just over two thirds at genesis.
pub const THRESHOLD_BPS: u64 = 6_667;

/// Longest permitted free-text field on a proposal.
///
/// Memos and reasons are written into consensus state on every node forever, so
/// they are bounded. Long enough to say why, short enough not to be storage.
pub const MAX_TEXT_LEN: usize = 512;

/// Most accounts one `ApproveValidators` proposal names.
pub const MAX_APPROVED_VALIDATORS: usize = 64;

/// Longest region label an operator approval carries.
pub const MAX_REGION_LEN: usize = 64;

/// Most hourly epochs the availability history of an operator approval spans.
pub const MAX_OPERATOR_HISTORY_EPOCHS: u64 = 8_760;

/// Most hourly epochs one running-cost sponsorship claims.
pub const MAX_RUNNING_COST_EPOCHS: u64 = 31 * 24;

/// What an approved operator is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorClass {
    /// Runs a consensus validator.
    Validator,
    /// Provides inference, confidential compute or storage.
    Provider,
}

impl OperatorClass {
    /// The label events and queries carry.
    pub fn label(self) -> &'static str {
        match self {
            OperatorClass::Validator => "validator",
            OperatorClass::Provider => "provider",
        }
    }
}

/// What an approved grantee does for the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GranteeClass {
    /// Builds software or applications on the network.
    Developer,
    /// Protocol or infrastructure work, audits, documentation, security
    /// research, data or content.
    Contributor,
    /// Community work.
    Community,
}

impl GranteeClass {
    /// The label events and queries carry.
    pub fn label(self) -> &'static str {
        match self {
            GranteeClass::Developer => "developer",
            GranteeClass::Contributor => "contributor",
            GranteeClass::Community => "community",
        }
    }
}

/// The published criteria an operator approval rests on. The chain checks
/// the hardware attestation and counts the verified availability itself; the
/// region and the independence declaration are recorded as stated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCriteria {
    /// The machine identity whose TPM endorsement and verified availability
    /// verdicts the approval rests on.
    pub provider_did: String,
    /// Where the operator runs, as published.
    pub region: String,
    /// First hourly epoch of the availability history counted.
    pub history_from_epoch: u64,
    /// Last hourly epoch of the availability history counted.
    pub history_to_epoch: u64,
    /// The operator's declaration that it is independent of the other
    /// approved operators, or a link to it.
    pub independence: String,
    /// Link to the public statement of the criteria and how they were met.
    pub link: String,
}

/// The published basis of a grantee approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranteeCriteria {
    /// What the grantee builds or does, as published.
    pub summary: String,
    /// Link to the public statement of the criteria and how they were met.
    pub link: String,
}

/// Voting window on the expedited track.
///
/// Six hours: long enough that a decision is not made by whoever is awake,
/// short enough to matter in an incident.
pub const EXPEDITED_VOTING_PERIOD_MS: i64 = 6 * 60 * 60 * 1000;

/// Timelock on the expedited track.
///
/// Four hours. Still a real window — a guardian can veto inside it — but not
/// two days, which is the point of the track.
pub const EXPEDITED_TIMELOCK_DELAY_MS: i64 = 4 * 60 * 60 * 1000;

/// Share of participating stake that must be in favour on the expedited
/// track. Higher than standard: this is what pays for the shorter window.
pub const EXPEDITED_THRESHOLD_BPS: u64 = 8_000;

/// Share of bonded stake a proposer must hold to open a proposal.
///
/// Every proposal costs the network a voting period of attention, so creating
/// one has to be non-trivial or the surface is unusable through volume alone.
/// One percent: enough that a proposal represents a real position, low enough
/// that it is not a validators-only power.
pub const PROPOSAL_THRESHOLD_BPS: u64 = 100;

/// How long a passed proposal waits before it may be executed.
///
/// The delay is the only interval in which anyone can respond to a decision
/// that has already carried. OpenZeppelin's rationale is that it lets holders
/// "exit the system if they disagree with a decision before it is executed";
/// the operational one is that a proposal carrying a bug or an attack has a
/// bounded window in which it can still be stopped.
///
/// It is also what makes delegated autonomy reviewable. An agent acting
/// instantly cannot be checked; an agent acting into a challenge window can.
/// Every guardian power built on top of governance needs somewhere to
/// intervene, and this is it.
///
/// Two days: long enough for a human to notice and act across timezones,
/// short enough that routine operations are not paralysed. Large DAOs use
/// 2-7 days for the same trade-off.
pub const TIMELOCK_DELAY_MS: i64 = 2 * 24 * 60 * 60 * 1000;

/// Share of the stake that voted which must be in favour on the Ratify track,
/// bps: three quarters.
pub const RATIFY_THRESHOLD_BPS: u64 = 7_500;
/// Timelock of a proposal re-passed on the Ratify track: thirty days, so the
/// holders who contested it can leave before it takes effect.
pub const RATIFY_TIMELOCK_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Governed key: standard and Ratify voting window, ms.
pub const VOTING_PERIOD_PARAM: &str = "governance.voting_period_ms";
/// Governed key: expedited and security-fix voting window, ms.
pub const EXPEDITED_VOTING_PERIOD_PARAM: &str = "governance.expedited_voting_period_ms";
/// Governed key: standard timelock, ms.
pub const TIMELOCK_PARAM: &str = "governance.timelock_ms";
/// Governed key: expedited and security-fix timelock, ms.
pub const EXPEDITED_TIMELOCK_PARAM: &str = "governance.expedited_timelock_ms";
/// Governed key: Ratify timelock, ms.
pub const RATIFY_TIMELOCK_PARAM: &str = "governance.ratify_timelock_ms";
/// Governed key: quorum, bps of bonded stake.
pub const QUORUM_PARAM: &str = "governance.quorum_bps";
/// Governed key: standard threshold, bps of participating stake.
pub const THRESHOLD_PARAM: &str = "governance.threshold_bps";
/// Governed key: expedited and security-fix threshold, bps.
pub const EXPEDITED_THRESHOLD_PARAM: &str = "governance.expedited_threshold_bps";
/// Governed key: Ratify threshold, bps.
pub const RATIFY_THRESHOLD_PARAM: &str = "governance.ratify_threshold_bps";
/// Governed key: stake a proposer must hold to open a proposal, bps of
/// bonded stake.
pub const PROPOSAL_THRESHOLD_PARAM: &str = "governance.proposal_threshold_bps";
/// Governed key: how long stake must have been bonded before a proposal
/// opened to weigh in its vote, ms.
pub const MIN_BOND_AGE_PARAM: &str = "governance.min_bond_age_ms";
/// Genesis value of [`MIN_BOND_AGE_PARAM`]: seven days, so stake bonded
/// after a proposal is announced off chain cannot be rushed into its vote.
pub const MIN_BOND_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Upper bound of [`MIN_BOND_AGE_PARAM`]; bond history is kept this much
/// longer than the longest voting window.
pub const MAX_MIN_BOND_AGE_MS: i64 = 90 * 24 * 60 * 60 * 1000;
/// Governed key: a payment of at least this many whole TNZO out of the
/// treasury or its running-cost reserve is a large spend, which waits the
/// large-spend timelock.
pub const LARGE_SPEND_PARAM: &str = "governance.large_spend_tnzo";
/// Genesis value of [`LARGE_SPEND_PARAM`].
pub const LARGE_SPEND_TNZO: u64 = 100_000;
/// Governed key: yes votes any treasury or reserve payment needs, bps of all
/// stake eligible
/// when it opened (not of the stake that voted), so a low turnout cannot
/// carry it.
pub const LARGE_SPEND_APPROVAL_PARAM: &str = "governance.large_spend_approval_bps";
/// Genesis value of [`LARGE_SPEND_APPROVAL_PARAM`]: three quarters, above
/// the two thirds of stake that orders blocks, so stake able to control
/// consensus still cannot carry a large spend by itself.
pub const LARGE_SPEND_APPROVAL_BPS: u64 = 7_500;
/// Governed key: the least timelock of a large spend, ms.
pub const LARGE_SPEND_TIMELOCK_PARAM: &str = "governance.large_spend_timelock_ms";
/// Genesis value of [`LARGE_SPEND_TIMELOCK_PARAM`]: fourteen days.
pub const LARGE_SPEND_TIMELOCK_MS: i64 = 14 * 24 * 60 * 60 * 1000;
/// Governed key: most one proposal may pay out of the treasury, bps of the
/// treasury balance when it enacts.
pub const MAX_PROPOSAL_OUTFLOW_PARAM: &str = "treasury.max_proposal_outflow_bps";
/// Genesis value of [`MAX_PROPOSAL_OUTFLOW_PARAM`].
pub const MAX_PROPOSAL_OUTFLOW_BPS: u64 = 200;
/// Governed key: most the treasury may pay out within one outflow period,
/// bps of its balance when the period began.
pub const MAX_PERIOD_OUTFLOW_PARAM: &str = "treasury.max_period_outflow_bps";
/// Genesis value of [`MAX_PERIOD_OUTFLOW_PARAM`]: 3% a period, above the
/// grants and buffer refills the treasury policy plans for a month.
pub const MAX_PERIOD_OUTFLOW_BPS: u64 = 300;
/// Governed key: length of a treasury outflow period, ms.
pub const OUTFLOW_PERIOD_PARAM: &str = "treasury.outflow_period_ms";
/// Genesis value of [`OUTFLOW_PERIOD_PARAM`]: thirty days.
pub const OUTFLOW_PERIOD_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Governed key: epochs a change that loosens a capture guard waits after
/// the next epoch boundary before it applies.
///
/// The guards bound what a captured vote can take or weaken. Loosening one
/// takes this long, so stake that captured a vote takes out at most what the
/// guards in force allow for this long, while every other holder sees the
/// change coming.
pub const GUARD_LOOSENING_GRACE_PARAM: &str = "governance.guard_loosening_grace_epochs";
/// Genesis value of [`GUARD_LOOSENING_GRACE_PARAM`]: 2,160 one-hour epochs,
/// ninety days.
pub const DEFAULT_GUARD_LOOSENING_GRACE_EPOCHS: u64 = 2_160;

/// The direction that tightens `key` when it is a capture guard: a
/// parameter that bounds what a captured vote can take or weaken. That is
/// what governance can pay out of the treasury, its running-cost reserve or
/// the insurance pool; how fast stake can come to vote and how much of it a
/// vote needs; and the pool release, validator pay, slashing, unbonding and
/// fee-rate rules a buyer of cheap stake after a crash would loosen first.
/// `None` for any other key.
pub fn capture_guard(key: &str) -> Option<Tighten> {
    use crate::native::{bridge_committee, economy, rewards, role_stake, staking};
    match key {
        rewards::MINT_BASE_PARAM
        | rewards::MINT_FLOOR_PARAM
        | rewards::MINT_MAX_MULT_PARAM
        | rewards::MINT_MIN_MULT_PARAM
        | rewards::VALIDATOR_BASE_CAP_PARAM
        | rewards::VALIDATOR_BASE_COST_PARAM
        | rewards::VALIDATOR_BURN_SHARE_PARAM
        | economy::RATE_MAX_CHANGE_PARAM
        | economy::RATE_QUANTILE_HIGH_PARAM
        | economy::RATE_BREAKER_SPREAD_PARAM
        | economy::RATE_BREAKER_GAP_PARAM
        | economy::RATE_BREAKER_EPOCHS_PARAM
        | staking::EXIT_CHURN_PARAM
        | crate::native::security::ATTACK_STAKE_PARAM => Some(Tighten::Down),
        rewards::MINT_DECAY_PARAM
        | economy::RATE_QUORUM_PARAM
        | economy::RATE_MAX_FALL_PARAM
        | economy::SAFETY_RATE_WINDOW_PARAM
        | economy::RATE_QUANTILE_LOW_PARAM
        | economy::RATE_STALE_QUORUM_PARAM
        | economy::RATE_MIN_SOURCES_PARAM
        | economy::RATE_UNOPENED_SLASH_PARAM
        | role_stake::BOND_FLOOR_RATE_PARAM
        | crate::native::security::MIN_RATIO_PARAM
        | crate::native::security::ATTACK_WINDOW_PARAM
        | crate::native::security::GAMMA_PARAM
        | staking::UNBONDING_PARAM
        | role_stake::UNBONDING_MS_PARAM
        | staking::EQUIVOCATION_MIN_SLASH_PARAM
        | staking::CORRELATION_MULTIPLIER_PARAM
        | staking::CORRELATION_WINDOW_PARAM
        | bridge_committee::EQUIVOCATION_SLASH_PARAM
        | crate::native::inference_fault::CATALOG_FAULT_SLASH_BPS_PARAM
        | crate::native::payment_settlement::plan::ATTESTOR_SLASH_PARAM
        | QUORUM_PARAM
        | THRESHOLD_PARAM
        | EXPEDITED_THRESHOLD_PARAM
        | RATIFY_THRESHOLD_PARAM => Some(Tighten::Up),
        MAX_PROPOSAL_OUTFLOW_PARAM
        | MAX_PERIOD_OUTFLOW_PARAM
        | LARGE_SPEND_PARAM
        | MAX_CAP_RAISE_PARAM
        | crate::native::insurance::MAX_CLAIM_BPS_PARAM
        | crate::native::insurance::MAX_CLAIM_TNZO_PARAM
        | crate::native::insurance::MAX_PAID_EPOCH_PARAM
        | crate::native::treasury_reserve::FILL_SHARE_PARAM
        | crate::native::treasury_reserve::TARGET_MONTHS_PARAM
        | crate::native::treasury_reserve::REVENUE_SHARE_PARAM
        | crate::native::treasury_reserve::DRAWDOWN_PARAM
        | crate::native::treasury_reserve::MAX_SALE_PARAM => Some(Tighten::Down),
        crate::native::treasury_reserve::MONTH_EPOCHS_PARAM
        | crate::native::treasury_reserve::GRANT_FLOOR_PARAM
        | OUTFLOW_PERIOD_PARAM
        | LARGE_SPEND_APPROVAL_PARAM
        | LARGE_SPEND_TIMELOCK_PARAM
        | MIN_BOND_AGE_PARAM
        | GUARD_LOOSENING_GRACE_PARAM => Some(Tighten::Up),
        _ => None,
    }
}

/// Whether moving `key` from `current` to `value` loosens a capture guard.
///
/// A change that does needs, besides its track's bars, yes votes of the
/// large-spend approval share of all eligible stake (see
/// [`decide_guarded`]): stake that captured a vote at standard turnout can
/// no more weaken an economic safety bound than pay itself from the
/// treasury.
pub fn loosens_guard(key: &str, current: u64, value: u64) -> bool {
    capture_guard(key).is_some_and(|t| guard_step_loosens(t, current, value))
}

/// The value one step of a change to `key` is measured from, given the value
/// in force and the value already scheduled to replace it. For a capture
/// guard that is the tighter of the two, so a loosening still waiting its
/// grace is not a base for a further step: proposals queued back to back
/// move a guard one step per grace, not one step each.
pub fn guard_step_base(key: &str, in_force: u64, scheduled: u64) -> u64 {
    match capture_guard(key) {
        Some(Tighten::Down) => in_force.min(scheduled),
        Some(Tighten::Up) => in_force.max(scheduled),
        _ => scheduled,
    }
}

/// Whether moving a guard that `tightens` in that direction from `current`
/// to `value` loosens it.
pub fn guard_step_loosens(tightens: Tighten, current: u64, value: u64) -> bool {
    match tightens {
        Tighten::Up => value < current,
        Tighten::Down => value > current,
        Tighten::Neither => false,
        // Resuming a paused feature applies at the next epoch, and a retired
        // one never returns (see [`lever_change_allowed`]), so no status step
        // is a loosening that waits out the grace window.
        Tighten::Retire => false,
    }
}

/// The voting rules a proposal is decided by. A proposal takes the rules in
/// force when it opens and keeps them, so a rule change enacted while it is
/// being voted on never moves its window, timelock or bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceRules {
    /// Standard and Ratify voting window, ms.
    pub voting_period_ms: i64,
    /// Expedited and security-fix voting window, ms.
    pub expedited_voting_period_ms: i64,
    /// Standard timelock, ms.
    pub timelock_ms: i64,
    /// Expedited and security-fix timelock, ms.
    pub expedited_timelock_ms: i64,
    /// Ratify timelock, ms.
    pub ratify_timelock_ms: i64,
    /// Share of bonded stake that must take part, bps.
    pub quorum_bps: u64,
    /// Share of participating stake in favour on the standard track, bps.
    pub threshold_bps: u64,
    /// The same on the expedited and security-fix tracks, bps.
    pub expedited_threshold_bps: u64,
    /// The same on the Ratify track, bps.
    pub ratify_threshold_bps: u64,
    /// Stake counts only if it was bonded this long before the proposal
    /// opened, ms.
    pub min_bond_age_ms: i64,
    /// A treasury grant of at least this many whole TNZO is a large spend.
    pub large_spend_tnzo: u64,
    /// Yes votes a large spend needs, bps of all eligible stake.
    pub large_spend_approval_bps: u64,
    /// The least timelock of a large spend, ms.
    pub large_spend_timelock_ms: i64,
}

impl GovernanceRules {
    /// The rules the network starts with.
    pub const GENESIS: Self = Self {
        voting_period_ms: VOTING_PERIOD_MS,
        expedited_voting_period_ms: EXPEDITED_VOTING_PERIOD_MS,
        timelock_ms: TIMELOCK_DELAY_MS,
        expedited_timelock_ms: EXPEDITED_TIMELOCK_DELAY_MS,
        ratify_timelock_ms: RATIFY_TIMELOCK_MS,
        quorum_bps: QUORUM_BPS,
        threshold_bps: THRESHOLD_BPS,
        expedited_threshold_bps: EXPEDITED_THRESHOLD_BPS,
        ratify_threshold_bps: RATIFY_THRESHOLD_BPS,
        min_bond_age_ms: MIN_BOND_AGE_MS,
        large_spend_tnzo: LARGE_SPEND_TNZO,
        large_spend_approval_bps: LARGE_SPEND_APPROVAL_BPS,
        large_spend_timelock_ms: LARGE_SPEND_TIMELOCK_MS,
    };
}

impl Default for GovernanceRules {
    fn default() -> Self {
        Self::GENESIS
    }
}

/// Errors a proposal can be rejected with before it ever reaches a vote.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceError {
    /// Only a human identity may hold a guardian seat.
    #[error("guardian {did} is not a human identity (did:tenzro:human:...)")]
    GuardianNotHuman {
        /// The DID named.
        did: String,
    },
    /// A guardian term must end in the future and within the governed
    /// maximum term.
    #[error("guardian term ending at {term_ends_ms} is not within the next {max_term_ms} ms")]
    GuardianTermOutOfRange {
        /// The term end named.
        term_ends_ms: i64,
        /// The governed maximum term.
        max_term_ms: u64,
    },
    /// A recovery that moves funds to the address they came from does
    /// nothing, and a proposal that does nothing should not occupy a vote.
    #[error("recovery source and destination are the same address")]
    RecoveryToSelf,
    /// A recovery with no explanation is a transfer wearing the word
    /// recovery. The memo is the evidence and is required.
    #[error("a recovery must carry evidence explaining why these funds are unowned")]
    RecoveryNeedsEvidence,
    /// The key names no parameter governance knows how to set. Refused at
    /// submission so the proposer learns immediately, rather than at
    /// enactment where the only outcome is a failed transaction.
    #[error("'{key}' is not a governed parameter")]
    UnknownParameter { key: String },
    /// The value is outside the range that leaves a working network.
    #[error("{key} = {value} is outside the permitted range {min}..={max}")]
    ParameterOutOfRange {
        key: String,
        value: u64,
        min: u64,
        max: u64,
    },
    /// A grant or recovery of zero moves nothing and would still consume state.
    #[error("proposal amount must be greater than zero")]
    ZeroAmount,

    /// Free-text field over [`MAX_TEXT_LEN`].
    #[error("{field} is {len} bytes, over the {MAX_TEXT_LEN}-byte limit")]
    TextTooLong {
        /// Which field overflowed.
        field: &'static str,
        /// Its actual length.
        len: usize,
    },

    /// The recipient or source address is all zeroes.
    #[error("{field} must not be the zero address")]
    ZeroAddress {
        /// Which field was zero.
        field: &'static str,
    },

    /// A grant recipient with no identity would be a wallet nobody answers for.
    #[error("grant recipient {0} has no registered identity")]
    RecipientHasNoIdentity(String),

    /// Voting is still open, so there is no outcome to act on yet.
    #[error("voting is open until {ends_ms}; now is {now_ms}")]
    VotingStillOpen {
        /// When voting closes.
        ends_ms: i64,
        /// The block timestamp the caller executed under.
        now_ms: i64,
    },

    /// The proposal did not pass, so there is nothing to enact.
    #[error("proposal did not pass: {0}")]
    DidNotPass(String),

    /// A proposal enacts once.
    #[error("proposal has already been executed")]
    AlreadyExecuted,

    /// Only bonded validators may propose or vote.
    #[error("{0} has no bonded stake, so it cannot take part in governance")]
    NotABondedValidator(String),

    /// A revocation naming nobody.
    #[error("a revocation must name the identity it revokes")]
    RevocationNeedsSubject,

    /// A revocation with no stated reason.
    #[error(
        "a revocation must carry its reason; a sanction nobody explained cannot later be \
         told apart from an attack by whoever held the votes"
    )]
    RevocationNeedsEvidence,

    /// A bridge route that breaks the route rules (committee size, majority
    /// threshold, operator and RPC diversity, peer, signer keys, mint limit).
    #[error("invalid bridge route: {0}")]
    InvalidBridgeRoute(String),

    /// An agent account chain that breaks the account rules.
    #[error("invalid agent account chain: {0}")]
    InvalidAgentAccountChain(String),
    /// A rate stream signer set that breaks the stream rules.
    #[error("invalid rate stream: {0}")]
    InvalidRateStream(String),
    /// A reserve feed that breaks the feed rules.
    #[error("invalid reserve feed: {0}")]
    InvalidReserveFeed(String),
    /// A settlement asset entry outside its bounds.
    #[error("invalid settlement asset: {0}")]
    InvalidSettlementAsset(String),

    /// A DID that is not this network's to revoke.
    #[error("'{did}' is not a did:tenzro identity")]
    NotATenzroDid {
        /// The subject as proposed.
        did: String,
    },
    /// A funding action whose terms cannot be enacted.
    #[error("invalid funding terms: {0}")]
    InvalidFunding(String),
    /// A policy change whose values cannot be applied.
    #[error("invalid validator approval: {0}")]
    InvalidValidatorApproval(String),
    #[error("invalid policy update: {0}")]
    InvalidPolicy(String),
}

/// Longest DID a proposal may name.
///
/// The same ceiling `execute_identity_register` enforces, so no proposal can
/// name a subject that could never have been registered.
pub const MAX_DID_LEN: usize = 256;

/// How a tranched grant's later payments are released.
///
/// `Governed` is the default and the genesis-conservative choice: every
/// tranche after the first needs its own [`ProposalAction::ReleaseGrantTranche`]
/// proposal. `Scheduled` lets the one approved grant proposal carry the
/// schedule: governance names, in the grant itself, the verifiers who record
/// each milestone and how many must agree, and a tranche is then released
/// against that milestone record with no further proposal. Approval of the
/// grantee, the yearly caps, the reserve floor and the treasury outflow limit
/// are checked on every tranche either way.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GrantRelease {
    /// Each later tranche needs a release proposal.
    #[default]
    Governed,
    /// Later tranches are released against verified milestones.
    Scheduled {
        /// Accounts that record a milestone as met. Named by the approved
        /// grant, never the grantee.
        verifiers: Vec<Address>,
        /// How many distinct verifiers must record a milestone.
        threshold: u32,
    },
}

/// A settlement token id: `0x` and 64 hex digits.
pub fn parse_token_id(id: &str) -> Result<[u8; 32], GovernanceError> {
    id.strip_prefix("0x")
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            GovernanceError::InvalidFunding(format!("{id} is not a token id: 0x and 64 hex digits"))
        })
}

/// Most verifiers one scheduled grant names.
pub const MAX_MILESTONE_VERIFIERS: usize = 9;

/// How a treasury grant's payments vest. Every tranche vests on its own
/// schedule, starting when it is paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantVesting {
    /// Paid to the recipient's balance.
    Liquid,
    /// A development grant: linear over six months.
    Grant,
    /// A core contributor's allocation: a twelve-month cliff, then linear
    /// over thirty-six months.
    Contributor,
}

impl GrantVesting {
    /// The vesting kind, cliff and duration in milliseconds, or `None` when
    /// the payment is liquid.
    pub fn schedule(self) -> Option<(tenzro_token::vesting::VestingKind, i64, i64)> {
        use tenzro_token::vesting::{
            CONTRIBUTOR_CLIFF_MS, CONTRIBUTOR_VESTING_MS, GRANT_VESTING_MS, VestingKind,
        };
        match self {
            Self::Liquid => None,
            Self::Grant => Some((VestingKind::Grant, 0, GRANT_VESTING_MS)),
            Self::Contributor => Some((
                VestingKind::Contributor,
                CONTRIBUTOR_CLIFF_MS,
                CONTRIBUTOR_VESTING_MS,
            )),
        }
    }
}

/// What a proposal does if it passes.
///
/// Typed rather than opaque bytes, so the VM can validate a proposal when it is
/// *submitted* instead of discovering at enactment that it decodes to nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ProposalAction {
    /// Reassign funds from a system-held address that the accounting shows
    /// belong to nobody.
    ///
    /// Deliberately narrow. `from` must be a system address — a vault, the
    /// treasury, a fee sink — never a user account, because a recovery power
    /// that can reach a user's balance is a confiscation power. The amount is
    /// re-derived at enactment against actual state, so a proposal claiming an
    /// imbalance the chain does not show is refused however it voted.
    RecoverUnownedFunds {
        /// The system-held address holding the unattributed balance.
        from: Address,
        /// Where the funds go. Must hold a registered identity, like any
        /// other recipient of value on this network.
        to: Address,
        /// The imbalance being claimed, checked against state at enactment.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// The evidence, recorded on-chain with the proposal: what went wrong,
        /// and why these funds are nobody's.
        memo: String,
    },
    /// Set a governed parameter to a new value.
    ///
    /// Reversible by another vote, which is why this is a `Network` action and
    /// treasury movements are not: setting a parameter wrongly costs degraded
    /// operation until it is set again, while paying the wrong address costs
    /// the money.
    ParameterChange {
        /// Which parameter, by its stable key.
        key: String,
        /// The value to set, bounds-checked at submission.
        value: u64,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Pay `amount` from the treasury to `recipient`.
    ///
    /// The recipient must be an approved grantee ([`ProposalAction::ApproveGrantee`])
    /// and every payment must stay within the governed yearly caps, which are
    /// zero at genesis. The recipient must already hold a registered identity. That is the
    /// network's standing invariant — no entity holds a wallet without an
    /// identity behind it — and a treasury grant is exactly the moment it would
    /// otherwise be broken, by creating a funded address answerable to nobody.
    ///
    /// A grant may be split into `tranches` that sum to `amount`. The first
    /// tranche is paid when the grant enacts; each later one only when its own
    /// [`ProposalAction::ReleaseGrantTranche`] passes. No tranches pays
    /// `amount` at once. Each payment goes to the recipient as `vesting`
    /// says: liquid, or into a vesting schedule the recipient releases from.
    TreasuryGrant {
        /// Who is paid.
        recipient: Address,
        /// How much, in the smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// Why, recorded on-chain with the proposal.
        memo: String,
        /// What the grant is for: a free label (development, research,
        /// audit, infrastructure, community, events, operators, ...).
        category: String,
        /// Link to the public write-up.
        link: String,
        /// Tranche amounts, in order. Empty pays `amount` at once.
        #[serde(with = "crate::funding::tranche_amounts")]
        tranches: Vec<u128>,
        /// The milestone each payment is for, one per tranche (one when
        /// `tranches` is empty): what was delivered or what must be
        /// delivered. Public, recorded with the grant and in the payout
        /// event. The first is the one this vote records as met; each later
        /// one only when its own release proposal passes.
        milestones: Vec<String>,
        /// How each payment vests.
        vesting: GrantVesting,
        /// The settlement asset the grant is paid in, a token id (`0x` and 64
        /// hex digits) the governed settlement registry lists as a USD
        /// stable asset. `None` pays TNZO. Amounts are then in the asset's
        /// smallest unit, valued in USD at the validator rate when paid and
        /// counted against the USD caps. A stable grant vests liquid.
        #[serde(default)]
        asset: Option<String>,
        /// How later tranches are released.
        #[serde(default)]
        release: GrantRelease,
    },
    /// Pay the next tranche of an enacted grant.
    ReleaseGrantTranche {
        /// Id of the enacted grant proposal.
        grant_id: String,
        /// Which tranche; must be the next unpaid one.
        index: u32,
        /// Why now: the milestone evidence, recorded on-chain.
        memo: String,
    },
    /// Change network policy: the economic policy, the burn dial and its
    /// supply targets, the TPM endorsement roots, a bridge route's limits or
    /// circuit, the finality program, or a protocol upgrade. Enactment
    /// records the change in consensus state and logs it; every node applies
    /// it to the subsystem it names.
    PolicyUpdate {
        /// The change.
        update: PolicyUpdate,
        /// Why, recorded on-chain with the proposal.
        memo: String,
        /// Which track it runs on. Only a burn-rate change (which answers a
        /// supply alarm) and disabling or pausing a bridge route (which
        /// answers a route under attack) may be expedited; only a protocol
        /// upgrade with a fault record or a vulnerability commitment may be a
        /// security fix.
        track: PolicyTrack,
    },
    /// Revoke a registered identity, and everything it controls.
    ///
    /// The network's answer to a party that turns out to be acting in bad
    /// faith. Without it every other rule about identities is advisory: the
    /// registry can revoke on its holder's own authority, and a holder acting
    /// in bad faith does not revoke themselves, so there was no path by which
    /// the network could withdraw standing it had granted.
    ///
    /// It is deliberately the heaviest thing governance can do to a party, and
    /// it is scoped to match:
    ///
    /// - It takes away standing. It does **not** reach the party's balance —
    ///   confiscation is not on the menu, and bundling it here would smuggle it
    ///   in behind a word that sounds procedural.
    /// - It cascades exactly as an ordinary revocation does, to the machines a
    ///   human or institution controls. A sanction that left the controlled
    ///   machines running would not be a sanction.
    /// - The DID must already exist in consensus state, checked at submission
    ///   and again at enactment, so the network never votes on a party that is
    ///   not there.
    /// - The reason is the record. An empty one is refused, for the same
    ///   reason `RecoverUnownedFunds` refuses an empty memo: a sanction nobody
    ///   explained is indistinguishable from an attack by whoever holds the
    ///   votes, and the on-chain text is the only thing that later
    ///   distinguishes them.
    ///
    /// Re-registration is not blocked. The revocation is a statement about the
    /// identity that existed, not a permanent exclusion of a person or a
    /// machine, and a permanent ban is a different power that should be argued
    /// for on its own terms rather than arriving as a side effect of this one.
    RevokeIdentity {
        /// The DID to revoke.
        did: String,
        /// Why, recorded on-chain with the proposal. The evidence.
        reason: String,
    },
    /// Set where the network's share of payments settled on an off-ledger
    /// rail is paid. `rail` names the rail (`bridge`); `destination` is the
    /// rail's own address form (for Bridge, `"<payment rail>:<address>"`).
    /// A rail with no destination set refuses payments rather than skip the
    /// share.
    SetNetworkPayout {
        /// The rail.
        rail: String,
        /// Where the share is paid on it.
        destination: String,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Install or replace the inbound route for one bridge protocol and one
    /// source chain.
    ///
    /// A route decides which remote contract may cause TNZO to be minted here
    /// and which committee vouches for each delivery, so it is a `Treasury`
    /// action: installing a bad route costs the money minted through it, and a
    /// later vote does not get that back.
    SetBridgeRoute {
        /// The route, checked against the route rules at submission and again
        /// at enactment.
        route: tenzro_types::bridge_route::BridgeRoute,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Install or replace the record of a chain agents hold accounts on: the
    /// account code's deployment there, whether grants may be issued, and
    /// the route that proves the accounts' reports. The deployment decides
    /// which contract holds every agent's authority on that chain, so it is a
    /// `Treasury` action.
    SetAgentAccountChain {
        /// The chain's record, checked at submission and at enactment.
        chain: tenzro_types::omni_account::AgentAccountChain,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Move treasury funds on another chain: write the exact remote grant
    /// the treasury's keyless account there runs once it proves the grant
    /// under a final checkpoint. Not for Bitcoin, which moves through the
    /// deposit route. A `Treasury` action.
    TreasuryRemoteAction {
        /// The chain, CAIP-2.
        caip2: String,
        /// The asset the action moves, CAIP-19.
        caip19: String,
        /// The one action the grant allows.
        remote: tenzro_types::remote_grant::RemoteAction,
        /// How long the grant may wait to be installed and run, ms.
        ttl_ms: u64,
        /// What a value-moving action pays and to whom. Required whenever
        /// the action moves any of the asset or refunds a relayer; an action
        /// that moves nothing needs none.
        #[serde(default)]
        payout: Option<RemotePayout>,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Seat a guardian at `address` for a fixed term, or replace that seat.
    /// The address's registered identity must be `did`, a human identity.
    /// A `Sanction` action: it hands a person a brake on the network.
    SetGuardian {
        /// The account the guardian signs from.
        address: Address,
        /// The guardian's human DID, registered to `address`.
        did: String,
        /// The power the seat holds.
        role: GuardianRole,
        /// Block time (Unix ms) the seat lapses at, within
        /// `governance.guardian_max_term_ms` of enactment.
        term_ends_ms: i64,
        /// What the seat's signing key is rooted in; distinct from every
        /// other live seat of the role.
        key_root: SeatKeyRoot,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// List or delist the code hash of an EIP-7702 delegate. While
    /// `evm.delegate_allowlist_enforced` is set, an authorization may only
    /// name a delegate whose code hash is listed.
    SetDelegateCode {
        /// Keccak-256 of the delegate's code, 64 hex characters.
        code_hash: String,
        /// List (true) or delist (false).
        allowed: bool,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Unseat the guardian at `address` before its term ends.
    RemoveGuardian {
        /// The seated account.
        address: Address,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Lift the freeze the value-invariant monitor put on `module` (see
    /// `crate::invariant_monitor`). If the module's vault is still short
    /// at the end of the next block, the monitor freezes it again.
    LiftModuleFreeze {
        /// The frozen module.
        module: crate::invariant_monitor::GuardedModule,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Remove an inbound route. Deliveries on it are refused from enactment
    /// on. Reversible by installing it again, so a `Network` action.
    RemoveBridgeRoute {
        /// The bridge protocol.
        adapter: tenzro_types::bridge_route::BridgeRouteAdapter,
        /// The adapter's name for the source chain.
        source_chain: String,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Install or replace the signer set of a signed rate stream that
    /// validators quote from. Reversible by another vote, so a `Network`
    /// action.
    SetRateStream {
        /// The set, checked at submission and again at enactment.
        stream: tenzro_types::RateStreamSigners,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Retire an abusive registry entry; its bond goes to the insurance pool.
    /// Takes something from a named owner, so a `Sanction`.
    RetireRegistryEntry {
        /// The entry's id.
        id: String,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Remove a rate stream's signer set; validators stop quoting it.
    RemoveRateStream {
        /// The stream's feed id.
        #[serde(with = "hex::serde")]
        feed_id: [u8; 32],
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Install or replace the Proof-of-Reserve feed validators read for an
    /// asset. Reversible by another vote, so a `Network` action.
    SetReserveFeed {
        /// The feed, checked at submission and again at enactment.
        feed: tenzro_types::ReserveFeed,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Install or replace the entry that permits payments to settle in a
    /// token other than TNZO. Disabling is an entry with `enabled` false.
    /// Reversible by another vote, so a `Network` action.
    SetSettlementAsset {
        /// The entry, checked at submission and again at enactment.
        asset: tenzro_types::settlement_asset::SettlementAsset,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Remove an asset's reserve feed; validators stop reading it.
    RemoveReserveFeed {
        /// The asset whose feed is removed.
        asset_id: String,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Pay `amount` of the network's running costs to `recipient` from the
    /// running-cost reserve.
    ///
    /// Enactment queues the payment; it is paid at epoch boundaries, in
    /// order, within the reserve's governed caps: the trailing month's share
    /// of realised fee revenue plus its drawdown of the reserve, the epoch's
    /// share of traded volume, and the reserve balance. A payment the caps
    /// do not cover yet waits; nothing is paid that the reserve does not
    /// hold. The recipient must hold a registered identity.
    RunningCostPayment {
        /// Who is paid: an approved operator.
        recipient: Address,
        /// First hourly epoch claimed.
        from_epoch: u64,
        /// Last hourly epoch claimed.
        to_epoch: u64,
        /// How much, in the smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// What it pays for, recorded on-chain with the proposal.
        memo: String,
        /// Link to the public statement of the costs.
        link: String,
    },
    /// Approve accounts to register as validators while admission needs
    /// approval (`validator.admission_approval`), or withdraw an approval.
    /// The approved accounts are the admitted set, which starts as the
    /// genesis validators. An approval admits a registration and a committee
    /// seat; while admission is closed, a withdrawal takes a seated validator
    /// off the committee at the next epoch boundary. While it is open
    /// approvals change nothing.
    ApproveValidators {
        /// The accounts the validators register from.
        accounts: Vec<Address>,
        /// True approves, false withdraws.
        approve: bool,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Bond `amount` of existing treasury TNZO on `validator`'s behalf
    /// ([`crate::native::sponsored_bond`]). It counts toward the validator's
    /// bond and is slashable with it, never votes, earns nothing, is never
    /// paid to the validator, and returns to the treasury on recall or exit.
    /// It covers the bond only. Refused while the governed caps
    /// (`validator.sponsored_bond_max_tnzo`,
    /// `validator.sponsored_bond_total_max_tnzo`) are zero, their genesis
    /// value. Moves treasury funds, so a `Treasury` action.
    SponsorValidatorBond {
        /// The registered validator.
        validator: Address,
        /// How much, in the smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Recall `amount` of `validator`'s sponsored bond: it unbonds for the
    /// governed period, still slashable, then returns to the treasury.
    /// Returns value to the treasury and can be undone by sponsoring again,
    /// so a `Network` action.
    RecallSponsoredBond {
        /// The validator.
        validator: Address,
        /// How much, in the smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Approve `operator` for sponsorship, or renew its approval
    /// ([`crate::native::payout_gates`]). Sponsorship, a sponsored bond or
    /// running-cost payment, goes only to an approved operator. The
    /// operator's machine identity must hold a TPM endorsement a recognised
    /// root signs and a verified-available verdict in the history named; both
    /// are checked at enactment and recorded with the criteria. Approval
    /// confers no vote, no reward and no class. Allows nothing to be paid
    /// by itself, so a `Treasury` action only because it opens the gate.
    ApproveOperator {
        /// The account sponsorship is paid to or bonded for.
        operator: Address,
        /// Validator or provider.
        class: OperatorClass,
        /// The published criteria.
        criteria: OperatorCriteria,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Revoke an operator's approval. Takes effect for every later payment
    /// at once; a sponsored bond already held is recalled by its own
    /// proposal.
    RevokeOperator {
        /// The operator.
        operator: Address,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Approve `grantee` to receive grants, or renew its approval. Approval
    /// confers no vote, no reward and no class.
    ApproveGrantee {
        /// The account grants are paid to; it must hold a registered identity.
        grantee: Address,
        /// Developer, contributor or community.
        class: GranteeClass,
        /// The published criteria.
        criteria: GranteeCriteria,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Revoke a grantee's approval. Takes effect for every later tranche at
    /// once.
    RevokeGrantee {
        /// The grantee.
        grantee: Address,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Pay an approved operator part of its running cost out of the
    /// treasury, against the verified-available hours in `from_epoch` to
    /// `to_epoch` ([`crate::native::payout_gates`]). Each verified hour backs
    /// one payment only, one hour is worth at most the governed
    /// `sponsorship.running_cost_per_verified_epoch_wei`, an operator receives
    /// at most one third of the governed yearly sponsorship, and the payment
    /// counts against the treasury outflow caps and the combined yearly cap.
    /// An operator with no verified hour receives nothing.
    SponsorOperatorRunningCost {
        /// The approved operator.
        operator: Address,
        /// First hourly epoch claimed.
        from_epoch: u64,
        /// Last hourly epoch claimed.
        to_epoch: u64,
        /// How much, in the smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// The same sponsorship paid in an approved USD stable asset the
    /// treasury holds, sized in USD rather than TNZO, so a falling TNZO
    /// price does not shrink what a verified hour is worth. Each verified
    /// hour backs one payment only, across both forms; one hour is worth at
    /// most the governed `sponsorship.running_cost_per_verified_epoch_usd_e6`;
    /// the payment counts against the USD yearly caps and the stable
    /// outflow limit. `period_exception` asks for the governed
    /// `treasury.proposal_outflow_exception_bps` of headroom above the
    /// period limit for this one payment, which is zero at genesis. Nothing
    /// is minted: the asset moves from the treasury's balance.
    SponsorOperatorStable {
        /// The approved operator.
        operator: Address,
        /// First hourly epoch claimed.
        from_epoch: u64,
        /// Last hourly epoch claimed.
        to_epoch: u64,
        /// The settlement asset, a token id (`0x` and 64 hex digits).
        token_id: String,
        /// How much, in the asset's smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// Use the governed per-proposal headroom above the period limit.
        #[serde(default)]
        period_exception: bool,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
    /// Reinstate a validator the jail holds: it returns to candidacy at the
    /// next epoch boundary, ahead of the end of its governed jail term
    /// (`slashing.jail_term_epochs`). It is admitted again like any
    /// candidate, by the activation churn cap and the self-stake floor.
    /// Slashing is not undone. A reinstatement of a validator that is not
    /// jailed does nothing. A `Sanction` action: agents originate it only at
    /// the highest agent phase.
    ReinstateValidator {
        /// The jailed validator.
        validator: Address,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
}

/// What a treasury remote action pays: an approved operator's running cost
/// on another chain, against verified hours, in a USD stable asset the
/// settlement registry prices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePayout {
    /// The approved operator paid.
    pub payee: Address,
    /// First hourly epoch claimed.
    pub from_epoch: u64,
    /// Last hourly epoch claimed.
    pub to_epoch: u64,
    /// The local settlement-registry entry that prices the remote asset: a
    /// token id (`0x` and 64 hex digits) of a USD stable asset.
    pub priced_by: String,
}

impl ProposalAction {
    /// Reject a malformed proposal at submission rather than at enactment.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        match self {
            ProposalAction::RecoverUnownedFunds {
                from,
                to,
                amount,
                memo,
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if from.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "from" });
                }
                if to.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "to" });
                }
                if from == to {
                    return Err(GovernanceError::RecoveryToSelf);
                }
                // Funds the books cannot attribute belong to the network, so
                // they return to the treasury, which pays out only through
                // the gated payout actions. The treasury itself is never a
                // source: its balance is owned, and drawing on it is a payout.
                if *from == tenzro_types::network_treasury_address() {
                    return Err(GovernanceError::InvalidFunding(
                        "the treasury's balance is owned; it leaves only through a gated payout"
                            .into(),
                    ));
                }
                if *to != tenzro_types::network_treasury_address() {
                    return Err(GovernanceError::InvalidFunding(
                        "unowned funds return to the treasury; paying a person is a gated payout"
                            .into(),
                    ));
                }
                // The evidence is the point of this action, so an empty memo
                // is refused. A recovery nobody explained is a transfer.
                if memo.trim().is_empty() {
                    return Err(GovernanceError::RecoveryNeedsEvidence);
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::ParameterChange { key, value, memo } => {
                let Some(param) = governed_param(key) else {
                    return Err(GovernanceError::UnknownParameter { key: key.clone() });
                };
                if *value < param.min || *value > param.max {
                    return Err(GovernanceError::ParameterOutOfRange {
                        key: key.clone(),
                        value: *value,
                        min: param.min,
                        max: param.max,
                    });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::TreasuryGrant {
                recipient,
                amount,
                memo,
                category,
                link,
                tranches,
                milestones,
                vesting,
                asset,
                release,
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if let Some(id) = asset {
                    parse_token_id(id)?;
                    if *vesting != GrantVesting::Liquid {
                        return Err(GovernanceError::InvalidFunding(
                            "a grant paid in a stable asset vests liquid".into(),
                        ));
                    }
                }
                if let GrantRelease::Scheduled {
                    verifiers,
                    threshold,
                } = release
                {
                    if tranches.len() < 2 {
                        return Err(GovernanceError::InvalidFunding(
                            "a scheduled release needs a grant of at least two tranches".into(),
                        ));
                    }
                    if verifiers.is_empty()
                        || verifiers.len() > MAX_MILESTONE_VERIFIERS
                        || *threshold == 0
                        || *threshold as usize > verifiers.len()
                        || verifiers.contains(recipient)
                        || verifiers
                            .iter()
                            .enumerate()
                            .any(|(i, v)| verifiers[..i].contains(v))
                    {
                        return Err(GovernanceError::InvalidFunding(format!(
                            "a scheduled release names 1 to {MAX_MILESTONE_VERIFIERS} distinct \
                             verifiers other than the grantee and a threshold within them"
                        )));
                    }
                }
                if milestones.len() != tranches.len().max(1)
                    || milestones
                        .iter()
                        .any(|m| m.trim().is_empty() || m.len() > MAX_TEXT_LEN)
                {
                    return Err(GovernanceError::InvalidFunding(format!(
                        "a grant names one milestone for each of its {} payments, each stated \
                         and at most {MAX_TEXT_LEN} bytes",
                        tranches.len().max(1)
                    )));
                }
                if recipient.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "recipient" });
                }
                for (field, text) in [("memo", memo), ("category", category), ("link", link)] {
                    if text.len() > MAX_TEXT_LEN {
                        return Err(GovernanceError::TextTooLong {
                            field,
                            len: text.len(),
                        });
                    }
                }
                if !tranches.is_empty() {
                    if tranches.len() > crate::funding::MAX_GRANT_TRANCHES {
                        return Err(GovernanceError::InvalidFunding(format!(
                            "at most {} tranches",
                            crate::funding::MAX_GRANT_TRANCHES
                        )));
                    }
                    if tranches.contains(&0) {
                        return Err(GovernanceError::ZeroAmount);
                    }
                    let sum = tranches
                        .iter()
                        .try_fold(0u128, |acc, t| acc.checked_add(*t))
                        .ok_or_else(|| {
                            GovernanceError::InvalidFunding("tranches overflow".into())
                        })?;
                    if sum != *amount {
                        return Err(GovernanceError::InvalidFunding(format!(
                            "tranches sum to {sum}, not the grant amount {amount}"
                        )));
                    }
                }
                Ok(())
            }
            ProposalAction::ReleaseGrantTranche {
                grant_id,
                index,
                memo,
            } => {
                if grant_id.len() != 64 || hex::decode(grant_id).is_err() {
                    return Err(GovernanceError::InvalidFunding(
                        "grant_id must be a 64-hex proposal id".into(),
                    ));
                }
                if *index == 0 || *index as usize >= crate::funding::MAX_GRANT_TRANCHES {
                    return Err(GovernanceError::InvalidFunding(
                        "the first tranche is paid at enactment; release indexes start at 1".into(),
                    ));
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::PolicyUpdate {
                update,
                memo,
                track,
            } => {
                if memo.trim().is_empty() {
                    return Err(GovernanceError::InvalidPolicy(
                        "a policy change must say why, in its memo".into(),
                    ));
                }
                match track {
                    PolicyTrack::Standard => {}
                    PolicyTrack::Expedited => {
                        if !may_expedite(update) {
                            return Err(GovernanceError::InvalidPolicy(
                                "only a burn-rate change, or disabling or pausing a bridge route, \
                                 may take the expedited track"
                                    .into(),
                            ));
                        }
                    }
                    PolicyTrack::SecurityFix { basis } => {
                        if !matches!(update, PolicyUpdate::ProtocolUpgrade { .. }) {
                            return Err(GovernanceError::InvalidPolicy(
                                "only a protocol upgrade may take the security-fix track".into(),
                            ));
                        }
                        basis.validate()?;
                    }
                }
                validate_policy_update(update)
            }
            ProposalAction::SetNetworkPayout {
                rail,
                destination,
                memo,
            } => {
                if !matches!(rail.as_str(), "bridge") {
                    return Err(GovernanceError::UnknownParameter { key: rail.clone() });
                }
                let well_formed = destination
                    .split_once(':')
                    .is_some_and(|(r, a)| !r.is_empty() && !a.is_empty());
                if !well_formed || destination.len() > 256 {
                    return Err(GovernanceError::TextTooLong {
                        field: "destination",
                        len: destination.len(),
                    });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::RevokeIdentity { did, reason } => {
                let did = did.trim();
                if did.is_empty() {
                    return Err(GovernanceError::RevocationNeedsSubject);
                }
                // Same shape and ceiling the registration path enforces, so a
                // proposal cannot name a DID that could never have been
                // registered and sit in the queue looking legitimate.
                if !did.starts_with("did:tenzro:") {
                    return Err(GovernanceError::NotATenzroDid {
                        did: did.to_string(),
                    });
                }
                if did.len() > MAX_DID_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "did",
                        len: did.len(),
                    });
                }
                // The evidence is the point, exactly as it is for recovery.
                if reason.trim().is_empty() {
                    return Err(GovernanceError::RevocationNeedsEvidence);
                }
                if reason.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "reason",
                        len: reason.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetAgentAccountChain { chain, memo } => {
                chain
                    .validate()
                    .map_err(|e| GovernanceError::InvalidAgentAccountChain(e.to_string()))?;
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::TreasuryRemoteAction {
                caip2,
                caip19,
                remote,
                ttl_ms,
                payout,
                memo,
            } => {
                if let Some(p) = payout {
                    parse_token_id(&p.priced_by)?;
                    if p.payee.as_bytes().iter().all(|b| *b == 0) {
                        return Err(GovernanceError::ZeroAddress { field: "payee" });
                    }
                    if p.to_epoch < p.from_epoch
                        || p.to_epoch - p.from_epoch >= MAX_RUNNING_COST_EPOCHS
                    {
                        return Err(GovernanceError::InvalidFunding(format!(
                            "a remote payout claims between 1 and {MAX_RUNNING_COST_EPOCHS} \
                             hourly epochs"
                        )));
                    }
                }
                if caip2.starts_with("bip122:") {
                    return Err(GovernanceError::InvalidPolicy(
                        "treasury BTC moves through the deposit route, not an account".into(),
                    ));
                }
                if tenzro_types::omni_account::Family::of(caip2).is_none() {
                    return Err(GovernanceError::InvalidPolicy(format!(
                        "{caip2} has no treasury account"
                    )));
                }
                if caip19.is_empty() || !caip19.starts_with(caip2.as_str()) {
                    return Err(GovernanceError::InvalidPolicy(
                        "the asset is a CAIP-19 id on the chain".into(),
                    ));
                }
                if *ttl_ms == 0
                    || *ttl_ms > crate::native::treasury_remote::MAX_TREASURY_GRANT_TTL_MS
                {
                    return Err(GovernanceError::InvalidPolicy(
                        "the grant lifetime is 1 ms to 30 days".into(),
                    ));
                }
                if remote.target.is_empty() {
                    return Err(GovernanceError::InvalidPolicy(
                        "the action names a target".into(),
                    ));
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetBridgeRoute { route, memo } => {
                route
                    .validate_proposal()
                    .map_err(|e| GovernanceError::InvalidBridgeRoute(e.to_string()))?;
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetGuardian {
                did,
                term_ends_ms,
                key_root,
                memo,
                ..
            } => {
                if !did.starts_with(HUMAN_DID_PREFIX) || did.len() > MAX_DID_LEN {
                    return Err(GovernanceError::GuardianNotHuman { did: did.clone() });
                }
                key_root.validate()?;
                if *term_ends_ms <= 0 {
                    return Err(GovernanceError::GuardianTermOutOfRange {
                        term_ends_ms: *term_ends_ms,
                        max_term_ms: 0,
                    });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetDelegateCode {
                code_hash, memo, ..
            } => {
                if code_hash.len() != 64 || !code_hash.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(GovernanceError::TextTooLong {
                        field: "code_hash",
                        len: code_hash.len(),
                    });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::ReinstateValidator { validator, memo } => {
                if validator.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "validator" });
                }
                if memo.trim().is_empty() {
                    return Err(GovernanceError::InvalidPolicy(
                        "a reinstatement states why the validator is returned".into(),
                    ));
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::RemoveGuardian { memo, .. }
            | ProposalAction::LiftModuleFreeze { memo, .. } => {
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetRateStream { stream, memo } => {
                stream
                    .validate()
                    .map_err(GovernanceError::InvalidRateStream)?;
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetSettlementAsset { asset, memo } => {
                asset
                    .validate()
                    .map_err(GovernanceError::InvalidSettlementAsset)?;
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SetReserveFeed { feed, memo } => {
                feed.validate()
                    .map_err(GovernanceError::InvalidReserveFeed)?;
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::RunningCostPayment {
                recipient,
                from_epoch,
                to_epoch,
                amount,
                memo,
                link,
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if to_epoch < from_epoch || to_epoch - from_epoch >= MAX_RUNNING_COST_EPOCHS {
                    return Err(GovernanceError::InvalidFunding(format!(
                        "a running-cost payment claims between 1 and {MAX_RUNNING_COST_EPOCHS} \
                         hourly epochs"
                    )));
                }
                if recipient.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "recipient" });
                }
                for (field, text) in [("memo", memo), ("link", link)] {
                    if text.len() > MAX_TEXT_LEN {
                        return Err(GovernanceError::TextTooLong {
                            field,
                            len: text.len(),
                        });
                    }
                }
                Ok(())
            }
            ProposalAction::ApproveValidators { accounts, memo, .. } => {
                if accounts.is_empty() || accounts.len() > MAX_APPROVED_VALIDATORS {
                    return Err(GovernanceError::InvalidValidatorApproval(format!(
                        "name between 1 and {MAX_APPROVED_VALIDATORS} accounts"
                    )));
                }
                if accounts
                    .iter()
                    .any(|a| a.as_bytes().iter().all(|b| *b == 0))
                {
                    return Err(GovernanceError::ZeroAddress { field: "accounts" });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SponsorValidatorBond {
                validator,
                amount,
                memo,
            }
            | ProposalAction::RecallSponsoredBond {
                validator,
                amount,
                memo,
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if validator.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "validator" });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::ApproveOperator {
                operator,
                criteria,
                memo,
                ..
            } => {
                if operator.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "operator" });
                }
                if criteria.provider_did.len() > MAX_DID_LEN
                    || !criteria.provider_did.starts_with("did:tenzro:")
                {
                    return Err(GovernanceError::InvalidFunding(
                        "the criteria name the operator's did:tenzro machine identity".into(),
                    ));
                }
                if criteria.region.trim().is_empty() || criteria.region.len() > MAX_REGION_LEN {
                    return Err(GovernanceError::InvalidFunding(format!(
                        "the criteria state the operator's region, at most {MAX_REGION_LEN} bytes"
                    )));
                }
                if criteria.history_to_epoch < criteria.history_from_epoch
                    || criteria.history_to_epoch - criteria.history_from_epoch
                        >= MAX_OPERATOR_HISTORY_EPOCHS
                {
                    return Err(GovernanceError::InvalidFunding(format!(
                        "the availability history is between 1 and {MAX_OPERATOR_HISTORY_EPOCHS} \
                         epochs"
                    )));
                }
                if criteria.independence.trim().is_empty() {
                    return Err(GovernanceError::InvalidFunding(
                        "the criteria carry the operator's independence declaration".into(),
                    ));
                }
                for (field, text) in [
                    ("independence", &criteria.independence),
                    ("link", &criteria.link),
                    ("memo", memo),
                ] {
                    if text.len() > MAX_TEXT_LEN {
                        return Err(GovernanceError::TextTooLong {
                            field,
                            len: text.len(),
                        });
                    }
                }
                Ok(())
            }
            ProposalAction::ApproveGrantee {
                grantee,
                criteria,
                memo,
                ..
            } => {
                if grantee.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "grantee" });
                }
                if criteria.summary.trim().is_empty() {
                    return Err(GovernanceError::InvalidFunding(
                        "the criteria state what the grantee builds or does".into(),
                    ));
                }
                for (field, text) in [
                    ("summary", &criteria.summary),
                    ("link", &criteria.link),
                    ("memo", memo),
                ] {
                    if text.len() > MAX_TEXT_LEN {
                        return Err(GovernanceError::TextTooLong {
                            field,
                            len: text.len(),
                        });
                    }
                }
                Ok(())
            }
            ProposalAction::RevokeOperator {
                operator: who,
                memo,
            }
            | ProposalAction::RevokeGrantee { grantee: who, memo } => {
                if who.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "account" });
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SponsorOperatorRunningCost {
                operator,
                from_epoch,
                to_epoch,
                amount,
                memo,
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if operator.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "operator" });
                }
                if to_epoch < from_epoch || to_epoch - from_epoch >= MAX_RUNNING_COST_EPOCHS {
                    return Err(GovernanceError::InvalidFunding(format!(
                        "a running-cost sponsorship claims between 1 and {MAX_RUNNING_COST_EPOCHS} \
                         hourly epochs"
                    )));
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::SponsorOperatorStable {
                operator,
                from_epoch,
                to_epoch,
                token_id,
                amount,
                memo,
                ..
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if operator.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "operator" });
                }
                parse_token_id(token_id)?;
                if to_epoch < from_epoch || to_epoch - from_epoch >= MAX_RUNNING_COST_EPOCHS {
                    return Err(GovernanceError::InvalidFunding(format!(
                        "a running-cost sponsorship claims between 1 and {MAX_RUNNING_COST_EPOCHS} \
                         hourly epochs"
                    )));
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::RemoveReserveFeed { memo, .. }
            | ProposalAction::RemoveRateStream { memo, .. }
            | ProposalAction::RetireRegistryEntry { memo, .. } => {
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
            ProposalAction::RemoveBridgeRoute {
                source_chain, memo, ..
            } => {
                if source_chain.trim().is_empty() {
                    return Err(GovernanceError::InvalidBridgeRoute(
                        "a route removal must name the source chain".to_string(),
                    ));
                }
                if memo.len() > MAX_TEXT_LEN {
                    return Err(GovernanceError::TextTooLong {
                        field: "memo",
                        len: memo.len(),
                    });
                }
                Ok(())
            }
        }
    }

    /// Which domain this action decides in, and therefore who may originate
    /// it.
    ///
    /// Exhaustive by construction: a new action cannot be added without
    /// classifying it, so "we forgot to think about whether an agent should
    /// be allowed to do this" fails the build rather than shipping.
    pub fn domain(&self) -> ActionDomain {
        match self {
            ProposalAction::RecoverUnownedFunds { .. } => ActionDomain::Treasury,
            ProposalAction::ParameterChange { .. } => ActionDomain::Network,
            ProposalAction::TreasuryGrant { .. } => ActionDomain::Treasury,
            ProposalAction::ReleaseGrantTranche { .. } => ActionDomain::Treasury,
            // A policy change is a setting another vote can put back.
            ProposalAction::PolicyUpdate { .. } => ActionDomain::Network,
            ProposalAction::RevokeIdentity { .. } => ActionDomain::Sanction,
            ProposalAction::SetNetworkPayout { .. } => ActionDomain::Treasury,
            ProposalAction::SetBridgeRoute { .. } => ActionDomain::Treasury,
            ProposalAction::SetAgentAccountChain { .. } => ActionDomain::Treasury,
            ProposalAction::TreasuryRemoteAction { .. } => ActionDomain::Treasury,
            ProposalAction::RemoveBridgeRoute { .. } => ActionDomain::Network,
            ProposalAction::SetGuardian { .. } | ProposalAction::RemoveGuardian { .. } => {
                ActionDomain::Sanction
            }
            ProposalAction::SetDelegateCode { .. } => ActionDomain::Network,
            ProposalAction::SetRateStream { .. } => ActionDomain::Network,
            ProposalAction::RemoveRateStream { .. } => ActionDomain::Network,
            ProposalAction::RetireRegistryEntry { .. } => ActionDomain::Sanction,
            // Moves nothing itself, and the monitor puts the freeze back
            // while the vault is short.
            ProposalAction::LiftModuleFreeze { .. } => ActionDomain::Network,
            ProposalAction::SetReserveFeed { .. } => ActionDomain::Network,
            ProposalAction::SetSettlementAsset { .. } => ActionDomain::Network,
            ProposalAction::RemoveReserveFeed { .. } => ActionDomain::Network,
            ProposalAction::RunningCostPayment { .. } => ActionDomain::Treasury,
            ProposalAction::ApproveValidators { .. } => ActionDomain::Network,
            ProposalAction::SponsorValidatorBond { .. } => ActionDomain::Treasury,
            // Returns value to the treasury; sponsoring again undoes it.
            ProposalAction::RecallSponsoredBond { .. } => ActionDomain::Network,
            // Approving opens the gate sponsorship and grants pay through.
            ProposalAction::ApproveOperator { .. } => ActionDomain::Treasury,
            ProposalAction::ApproveGrantee { .. } => ActionDomain::Treasury,
            // Revoking only stops later payments; approving again undoes it.
            ProposalAction::RevokeOperator { .. } => ActionDomain::Network,
            ProposalAction::RevokeGrantee { .. } => ActionDomain::Network,
            ProposalAction::SponsorOperatorRunningCost { .. } => ActionDomain::Treasury,
            ProposalAction::SponsorOperatorStable { .. } => ActionDomain::Treasury,
            // Returns a slashed party to the set a vote already put out.
            ProposalAction::ReinstateValidator { .. } => ActionDomain::Sanction,
        }
    }

    /// A short label for logs and RPC, stable across releases.
    pub fn kind(&self) -> &'static str {
        match self {
            ProposalAction::RecoverUnownedFunds { .. } => "recover_unowned_funds",
            ProposalAction::ParameterChange { .. } => "parameter_change",
            ProposalAction::TreasuryGrant { .. } => "treasury_grant",
            ProposalAction::ReleaseGrantTranche { .. } => "release_grant_tranche",
            ProposalAction::PolicyUpdate { .. } => "policy_update",
            ProposalAction::RevokeIdentity { .. } => "revoke_identity",
            ProposalAction::SetNetworkPayout { .. } => "set_network_payout",
            ProposalAction::SetBridgeRoute { .. } => "set_bridge_route",
            ProposalAction::SetAgentAccountChain { .. } => "set_agent_account_chain",
            ProposalAction::TreasuryRemoteAction { .. } => "treasury_remote_action",
            ProposalAction::RemoveBridgeRoute { .. } => "remove_bridge_route",
            ProposalAction::SetGuardian { .. } => "set_guardian",
            ProposalAction::RemoveGuardian { .. } => "remove_guardian",
            ProposalAction::SetDelegateCode { .. } => "set_delegate_code",
            ProposalAction::LiftModuleFreeze { .. } => "lift_module_freeze",
            ProposalAction::SetRateStream { .. } => "set_rate_stream",
            ProposalAction::RemoveRateStream { .. } => "remove_rate_stream",
            ProposalAction::RetireRegistryEntry { .. } => "retire_registry_entry",
            ProposalAction::SetReserveFeed { .. } => "set_reserve_feed",
            ProposalAction::SetSettlementAsset { .. } => "set_settlement_asset",
            ProposalAction::RemoveReserveFeed { .. } => "remove_reserve_feed",
            ProposalAction::RunningCostPayment { .. } => "running_cost_payment",
            ProposalAction::ApproveValidators { .. } => "approve_validators",
            ProposalAction::SponsorValidatorBond { .. } => "sponsor_validator_bond",
            ProposalAction::RecallSponsoredBond { .. } => "recall_sponsored_bond",
            ProposalAction::ApproveOperator { .. } => "approve_operator",
            ProposalAction::RevokeOperator { .. } => "revoke_operator",
            ProposalAction::ApproveGrantee { .. } => "approve_grantee",
            ProposalAction::RevokeGrantee { .. } => "revoke_grantee",
            ProposalAction::SponsorOperatorRunningCost { .. } => "sponsor_operator_running_cost",
            ProposalAction::SponsorOperatorStable { .. } => "sponsor_operator_stable",
            ProposalAction::ReinstateValidator { .. } => "reinstate_validator",
        }
    }

    /// The track this action runs on. Everything is standard except a policy
    /// change submitted on another track, which `validate` limits.
    pub fn track(&self) -> ProposalTrack {
        match self {
            ProposalAction::ParameterChange { key, value, .. } if is_pause_only(key, *value) => {
                ProposalTrack::Expedited
            }
            ProposalAction::PolicyUpdate {
                track: PolicyTrack::Expedited,
                ..
            } => ProposalTrack::Expedited,
            ProposalAction::PolicyUpdate {
                track: PolicyTrack::SecurityFix { .. },
                ..
            } => ProposalTrack::SecurityFix,
            _ => ProposalTrack::Standard,
        }
    }

    /// What a security-fix proposal rests on, if this is one.
    pub fn security_basis(&self) -> Option<&SecurityBasis> {
        match self {
            ProposalAction::PolicyUpdate {
                track: PolicyTrack::SecurityFix { basis },
                ..
            } => Some(basis),
            _ => None,
        }
    }
}

/// The track a policy change asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyTrack {
    /// Full window, full timelock.
    Standard,
    /// Short window at a higher threshold.
    Expedited,
    /// A protocol upgrade that fixes a fault: the expedited window and
    /// threshold, and the readiness gate still applies.
    SecurityFix {
        /// The fault record or vulnerability commitment it rests on.
        basis: SecurityBasis,
    },
}

/// What a security fix rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecurityBasis {
    /// An inference fault the validators upheld.
    Fault {
        /// The fault's id.
        fault_id: String,
    },
    /// A commitment to an undisclosed vulnerability: hex SHA-256 of the
    /// disclosure. The proposer reveals the disclosure after enactment, or
    /// forfeits part of its bond.
    Vulnerability {
        /// Hex SHA-256 of the disclosure.
        commitment: String,
    },
}

impl SecurityBasis {
    /// Shape checks; whether the fault exists is checked against state when
    /// the proposal opens.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        let bad = |m: &str| Err(GovernanceError::InvalidPolicy(m.into()));
        match self {
            SecurityBasis::Fault { fault_id } => {
                if fault_id.trim().is_empty() || fault_id.len() > 128 {
                    return bad("a security fix names its fault in 1..=128 characters");
                }
            }
            SecurityBasis::Vulnerability { commitment } => {
                if commitment.len() != 64 || hex::decode(commitment).is_err() {
                    return bad("a vulnerability commitment is 32 bytes of hex");
                }
            }
        }
        Ok(())
    }
}

/// The digest a validator's machine quotes to signal it runs the binary
/// whose SHA-256 is `code_hash`, on behalf of validator account `validator`.
pub fn upgrade_ready_digest(code_hash: &[u8; 32], validator: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/governance/upgrade-ready");
    h.update(code_hash);
    h.update((validator.len() as u32).to_be_bytes());
    h.update(validator);
    h.finalize().into()
}

/// A protocol upgrade enacted with its readiness met: the height from which
/// every node runs `code_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeActivation {
    /// The proposal that decided it.
    pub proposal_id: String,
    /// The version it names.
    pub version: String,
    /// Hex SHA-256 of the binary.
    pub code_hash: String,
    /// The height readiness was confirmed at, by the enacting transaction.
    pub readiness_met_height: u64,
    /// `readiness_met_height` plus the governed activation delay.
    pub activation_height: u64,
}

impl UpgradeActivation {
    /// The major protocol version `version` names ("3.1.0" names 3), if it
    /// parses. The header version and the chain's recorded version both
    /// follow this number.
    pub fn named_protocol_version(&self) -> Option<u32> {
        self.version.split('.').next()?.trim().parse::<u32>().ok()
    }
}

/// Whether `update` may take the expedited track: a burn-rate change, which
/// answers a supply alarm, or stopping a bridge route, which answers a route
/// under attack. Opening a route never may: it waits out the full window.
fn may_expedite(update: &PolicyUpdate) -> bool {
    match update {
        PolicyUpdate::AdaptiveBurnConfigUpdate { .. } => true,
        PolicyUpdate::BridgeCircuitSet { mode, .. } => {
            *mode != tenzro_types::bridge_route::BridgeRouteMode::Open
        }
        _ => false,
    }
}

/// A stable label for a policy change, used as its consensus-state key.
pub fn policy_kind(update: &PolicyUpdate) -> &'static str {
    match update {
        PolicyUpdate::ProtocolUpgrade { .. } => "protocol_upgrade",
        PolicyUpdate::EconomicPolicyUpdate { .. } => "economic_policy",
        PolicyUpdate::AdaptiveBurnConfigUpdate { .. } => "adaptive_burn_config",
        PolicyUpdate::SupplyTargetsUpdate { .. } => "supply_targets",
        PolicyUpdate::TpmEndorsementRootsSet { .. } => "tpm_endorsement_roots",
        PolicyUpdate::GpuDeviceRootsSet { .. } => "gpu_device_roots",
        PolicyUpdate::GpuReferenceValuesSet { .. } => "gpu_reference_values",
        PolicyUpdate::BridgeCircuitSet { .. } => "bridge_circuit",
        PolicyUpdate::BridgeMintLimitsSet { .. } => "bridge_mint_limits",
        PolicyUpdate::BridgeOutflowLimitsSet { .. } => "bridge_outflow_limits",
        PolicyUpdate::FinalityProgramSet { .. } => "finality_program",
        PolicyUpdate::HandoverProgramSet { .. } => "handover_program",
    }
}

/// Logged when a policy change enacts: the proposal that decided it and the
/// change itself, for every node to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEnactedLog {
    /// Id of the enacted proposal.
    pub proposal_id: String,
    /// The change.
    pub update: PolicyUpdate,
}

/// Checks a policy change can be applied, so the network never votes on one
/// that every node would then refuse.
pub fn validate_policy_update(update: &PolicyUpdate) -> Result<(), GovernanceError> {
    let bad = |m: String| Err(GovernanceError::InvalidPolicy(m));
    match update {
        PolicyUpdate::ProtocolUpgrade { version, code_hash } => {
            if version.trim().is_empty() || version.len() > 64 {
                return bad("a protocol upgrade names its version in 1..=64 characters".into());
            }
            if code_hash.len() != 32 {
                return bad(format!(
                    "a protocol upgrade carries the 32-byte SHA-256 of its code, not {} bytes",
                    code_hash.len()
                ));
            }
            Ok(())
        }
        PolicyUpdate::EconomicPolicyUpdate { policy } => policy
            .validate()
            .map_err(|e| GovernanceError::InvalidPolicy(e.to_string())),
        PolicyUpdate::AdaptiveBurnConfigUpdate {
            base_fee_burn_bps,
            local_fee_burn_bps,
        } => tenzro_token::adaptive_burn::BurnRateConfig {
            base_fee_burn_bps: *base_fee_burn_bps,
            local_fee_burn_bps: *local_fee_burn_bps,
        }
        .validate()
        .map_err(|e| GovernanceError::InvalidPolicy(e.to_string())),
        PolicyUpdate::SupplyTargetsUpdate {
            epoch_neutral_band_bps,
            rolling_window_epochs,
            inflation_alarm_bps,
            deflation_alarm_bps,
            gain_bps_per_pct,
            magnitude_cap_normal_bps,
            magnitude_cap_alarm_bps,
            auto_proposal_min_magnitude_bps,
            target_annual_supply_bps,
            ..
        } => {
            // TNZO supply is fixed: the dial may aim at a flat or falling
            // supply, never a rising one.
            if *target_annual_supply_bps > 0 {
                return bad(format!(
                    "target_annual_supply_bps is {target_annual_supply_bps}; TNZO supply is fixed, \
                     so the target is at most 0"
                ));
            }
            let bps = [
                ("epoch_neutral_band_bps", *epoch_neutral_band_bps),
                ("inflation_alarm_bps", *inflation_alarm_bps),
                ("deflation_alarm_bps", *deflation_alarm_bps),
                ("gain_bps_per_pct", *gain_bps_per_pct),
                ("magnitude_cap_normal_bps", *magnitude_cap_normal_bps),
                ("magnitude_cap_alarm_bps", *magnitude_cap_alarm_bps),
                (
                    "auto_proposal_min_magnitude_bps",
                    *auto_proposal_min_magnitude_bps,
                ),
            ];
            if let Some((name, v)) = bps.iter().find(|(_, v)| *v > 10_000) {
                return bad(format!("{name} is {v}, above 10000"));
            }
            if *rolling_window_epochs == 0 {
                return bad("rolling_window_epochs must be at least 1".into());
            }
            Ok(())
        }
        PolicyUpdate::TpmEndorsementRootsSet { roots_pem } => {
            for pem in roots_pem {
                tenzro_tee::x509::parse_pem_chain(pem).map_err(|e| {
                    GovernanceError::InvalidPolicy(format!("endorsement root: {e}"))
                })?;
            }
            Ok(())
        }
        PolicyUpdate::GpuDeviceRootsSet { roots_pem } => {
            for pem in roots_pem {
                tenzro_tee::x509::parse_pem_chain(pem)
                    .map_err(|e| GovernanceError::InvalidPolicy(format!("GPU device root: {e}")))?;
            }
            Ok(())
        }
        PolicyUpdate::GpuReferenceValuesSet { references } => {
            tenzro_types::hardware_level::decode_gpu_references(references)
                .map(|_| ())
                .map_err(|e| GovernanceError::InvalidPolicy(format!("GPU reference values: {e}")))
        }
        PolicyUpdate::BridgeCircuitSet {
            source_chain,
            mode,
            reason,
            ..
        } => {
            if source_chain.trim().is_empty() || source_chain.len() > 64 {
                return bad("a bridge route names its chain in 1..=64 characters".into());
            }
            if *mode != tenzro_types::bridge_route::BridgeRouteMode::Open
                && reason.trim().is_empty()
            {
                return bad("disabling or pausing a bridge route must say why".into());
            }
            Ok(())
        }
        PolicyUpdate::BridgeMintLimitsSet { limits } => limits
            .validate()
            .map_err(|e| GovernanceError::InvalidPolicy(format!("bridge mint limits: {e}"))),
        PolicyUpdate::BridgeOutflowLimitsSet { limits } => limits
            .validate()
            .map_err(|e| GovernanceError::InvalidPolicy(format!("bridge outflow limits: {e}"))),
        PolicyUpdate::FinalityProgramSet { image_id } => {
            if *image_id == [0u8; 32] {
                return Err(GovernanceError::InvalidPolicy(
                    "the finality program image id is zero".into(),
                ));
            }
            Ok(())
        }
        PolicyUpdate::HandoverProgramSet { image_id } => {
            if *image_id == [0u8; 32] {
                return Err(GovernanceError::InvalidPolicy(
                    "the handover program image id is zero".into(),
                ));
            }
            Ok(())
        }
    }
}

/// What a guardian is permitted to stop.
///
/// Two powers, held separately: Protocol Guardians handle emergency responses
/// and can pause enactment, Governance Guardians can veto a malicious queued
/// proposal. They differ in blast radius —
/// a pause halts everything for a while, a veto kills one decision forever —
/// and a role holding both is a role that can quietly become the government.
///
/// Every guardian power is negative. A guardian stops things and originates
/// nothing: none of these can move funds, change a parameter or enact a
/// proposal. The worst a captured guardian achieves is refusing to let the
/// network act, which is visible at once, rather than acting in its name,
/// which may not be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianRole {
    /// May pause execution in an emergency. Cannot veto a specific proposal.
    Protocol,
    /// May veto a queued proposal during its timelock. Cannot pause.
    Governance,
    /// Foundation stewardship: may veto a queued treasury or expedited
    /// proposal during its timelock, and may hold treasury and expedited
    /// enactment for a bounded time. Cannot spend, propose or pause anything
    /// else, and holds no power after `governance.steward_sunset_ms`.
    Steward,
}

impl GuardianRole {
    /// Whether this role may veto a queued proposal.
    pub fn may_veto(&self) -> bool {
        matches!(self, GuardianRole::Governance | GuardianRole::Steward)
    }

    /// Whether this role may pause execution (a steward's pause holds only
    /// treasury and expedited enactment).
    pub fn may_pause(&self) -> bool {
        matches!(self, GuardianRole::Protocol | GuardianRole::Steward)
    }

    /// Stable label for logs and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardianRole::Protocol => "protocol",
            GuardianRole::Governance => "governance",
            GuardianRole::Steward => "steward",
        }
    }
}

/// What a seat's signing key shares its loss or compromise with: a passkey
/// sync provider (named by its AAGUID) or one device-bound credential. Two
/// live seats of one role never share a root, so the m-of-n threshold counts
/// independent keys rather than copies of one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SeatKeyRoot {
    /// A synced passkey, rooted in its provider's sync account.
    SyncProvider {
        /// The provider's AAGUID, hex.
        aaguid: String,
    },
    /// A device-bound credential (security key, TPM or secure enclave).
    Device {
        /// The credential id, hex.
        credential_id: String,
    },
}

impl SeatKeyRoot {
    /// Refuse an empty or non-hex root.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        let (field, value, len) = match self {
            SeatKeyRoot::SyncProvider { aaguid } => ("aaguid", aaguid, Some(32)),
            SeatKeyRoot::Device { credential_id } => ("credential_id", credential_id, None),
        };
        let ok = !value.is_empty()
            && value.len() <= 2 * 1024
            && value.len() % 2 == 0
            && value.bytes().all(|b| b.is_ascii_hexdigit())
            && len.is_none_or(|l| value.len() == l);
        if ok {
            Ok(())
        } else {
            Err(GovernanceError::InvalidPolicy(format!(
                "seat key root {field} is not valid hex"
            )))
        }
    }
}

/// A seated guardian: the human identity behind the seat, its role, and when
/// its term ends. Written to consensus state by an enacted
/// [`ProposalAction::SetGuardian`] or by the genesis seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSeat {
    /// The guardian's human DID.
    pub did: String,
    /// Which negative power the seat holds.
    pub role: GuardianRole,
    /// Block time (Unix ms) at which the seat lapses.
    pub term_ends_ms: i64,
    /// What the seat's signing key is rooted in.
    pub key_root: SeatKeyRoot,
}

impl GuardianSeat {
    /// Whether the seat still holds its power at block time `now_ms`.
    pub fn is_active(&self, now_ms: i64) -> bool {
        now_ms < self.term_ends_ms
    }
}

/// DID prefix of a human identity, the only kind that may hold a guardian
/// seat: an agent or machine answers to a root, and a guardian must be one.
pub const HUMAN_DID_PREFIX: &str = "did:tenzro:human:";

/// Check a guardian seat's identity and term at block time `now_ms` against
/// the longest term governance allows.
pub fn check_guardian_term(
    did: &str,
    term_ends_ms: i64,
    now_ms: i64,
    max_term_ms: u64,
) -> Result<(), GovernanceError> {
    if !did.starts_with(HUMAN_DID_PREFIX) || did.len() > MAX_DID_LEN {
        return Err(GovernanceError::GuardianNotHuman {
            did: did.to_string(),
        });
    }
    if term_ends_ms <= now_ms || (term_ends_ms - now_ms) as u64 > max_term_ms {
        return Err(GovernanceError::GuardianTermOutOfRange {
            term_ends_ms,
            max_term_ms,
        });
    }
    Ok(())
}

/// Why a veto was refused, so the caller learns which rule stopped it rather
/// than a bare failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VetoRefusal {
    /// The caller holds no guardian role at all.
    NotAGuardian,
    /// The caller is a guardian, but not one that may veto.
    WrongRole(GuardianRole),
    /// The proposal is not in the timelock: not yet queued, or already
    /// terminal.
    NotQueued(ProposalStatus),
    /// A steward may veto only a treasury or expedited proposal.
    OutsideStewardScope,
}

impl std::fmt::Display for VetoRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VetoRefusal::NotAGuardian => write!(f, "caller holds no guardian role"),
            VetoRefusal::WrongRole(r) => write!(
                f,
                "guardian role '{}' may not veto; that is the governance guardian's power",
                r.as_str()
            ),
            VetoRefusal::NotQueued(s) => write!(
                f,
                "only a queued proposal can be vetoed (this one is {s:?}); before it carries \
                 there is nothing to stop, and after it executes there is nothing left to stop"
            ),
            VetoRefusal::OutsideStewardScope => write!(
                f,
                "a steward may veto only a treasury or expedited proposal"
            ),
        }
    }
}

/// Why a pause or unpause was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseRefusal {
    /// The caller holds no guardian role.
    NotAGuardian,
    /// The caller is a guardian, but not one that may pause.
    WrongRole(GuardianRole),
    /// Already in the requested state; a no-op should not consume a slot or
    /// look like it did something.
    AlreadyInState(bool),
}

impl std::fmt::Display for PauseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PauseRefusal::NotAGuardian => write!(f, "caller holds no guardian role"),
            PauseRefusal::WrongRole(r) => write!(
                f,
                "guardian role '{}' may not pause; that is the protocol guardian's power",
                r.as_str()
            ),
            PauseRefusal::AlreadyInState(p) => write!(
                f,
                "governance execution is already {}",
                if *p { "paused" } else { "running" }
            ),
        }
    }
}

/// Decide whether `role` may set the pause flag to `want_paused`.
///
/// Pure over its inputs, so the rule is testable without a VM and the same
/// rule answers both the handler and anything showing a caller in advance
/// whether the button will work.
pub fn may_set_pause(
    role: Option<GuardianRole>,
    currently_paused: bool,
    want_paused: bool,
) -> Result<(), PauseRefusal> {
    let Some(role) = role else {
        return Err(PauseRefusal::NotAGuardian);
    };
    if !role.may_pause() {
        return Err(PauseRefusal::WrongRole(role));
    }
    if currently_paused == want_paused {
        return Err(PauseRefusal::AlreadyInState(currently_paused));
    }
    Ok(())
}

/// Decide whether `role` may veto `proposal`, and why not when it may not.
///
/// Pure over its inputs so the rule can be tested without a VM, and so the
/// same rule is used by the handler and by anything that wants to show a
/// caller in advance whether the button will work.
pub fn may_veto(role: Option<GuardianRole>, proposal: &Proposal) -> Result<(), VetoRefusal> {
    let Some(role) = role else {
        return Err(VetoRefusal::NotAGuardian);
    };
    if !role.may_veto() {
        return Err(VetoRefusal::WrongRole(role));
    }
    if !matches!(proposal.status, ProposalStatus::Queued) {
        return Err(VetoRefusal::NotQueued(proposal.status));
    }
    if role == GuardianRole::Steward && !steward_scope(&proposal.action) {
        return Err(VetoRefusal::OutsideStewardScope);
    }
    Ok(())
}

/// Whether `action` is one a Foundation steward may veto or hold: it moves
/// treasury value or runs on the expedited track. A change to the steward
/// seats or the sunset is never in scope, so stewardship cannot block its
/// own reduction.
pub fn steward_scope(action: &ProposalAction) -> bool {
    action.domain() == ActionDomain::Treasury || action.track() == ProposalTrack::Expedited
}

/// What kind of thing an action decides, and therefore who may originate it.
///
/// The split is by failure mode rather than by subject. Network decisions are
/// reversible: a parameter set wrongly is corrected by setting it again, and
/// the cost is degraded operation for the length of a timelock. Treasury
/// decisions move value, and a payment to the wrong address is not corrected
/// by a later vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDomain {
    /// Consensus and operational parameters, validator lifecycle. Reversible.
    Network,
    /// Anything that moves value. Not reversible by a later vote.
    Treasury,
    /// Anything that takes something away from a named party.
    ///
    /// Its own domain because it fits neither of the others and putting it in
    /// either would be wrong in a way that matters. It moves no value, so
    /// calling it `Treasury` would be a lie about what it does. It is not
    /// reversible the way a parameter is — re-registering an identity does not
    /// undo the period in which everything it controlled stopped being trusted
    /// — so calling it `Network` would import a reversibility it does not have,
    /// and would hand agents the power to strip identities at the middle agent
    /// phase, which is not what voting for that phase meant.
    Sanction,
}

/// How far autonomous agents are trusted to originate proposals.
///
/// A governed value, not a constant: widening it is a decision the community
/// makes through the ordinary process — timelocked, visible, vetoable —
/// rather than a code change nobody voted on.
///
/// Starts at `None`. Whether agents should originate anything at all is not
/// yet settled, and a permissive default would settle it by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentPhase {
    /// Agents propose nothing. Humans and the community originate everything.
    #[default]
    None,
    /// Agents may originate network decisions. Treasury remains human-only.
    Network,
    /// Agents may originate any action. Not reachable without a vote that
    /// says so explicitly.
    All,
}

impl AgentPhase {
    /// Whether an agent may originate an action in `domain` at this phase.
    pub fn permits(&self, domain: ActionDomain) -> bool {
        match (self, domain) {
            (AgentPhase::None, _) => false,
            (AgentPhase::Network, ActionDomain::Network) => true,
            // Neither at the middle phase. A vote for `Network` said agents may
            // tune the network, not that they may spend its money or strip a
            // party's standing. Both of those need the phase that says so.
            (AgentPhase::Network, ActionDomain::Treasury | ActionDomain::Sanction) => false,
            (AgentPhase::All, _) => true,
        }
    }

    /// Stable label for logs and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentPhase::None => "none",
            AgentPhase::Network => "network",
            AgentPhase::All => "all",
        }
    }
}

/// A parameter governance may change, with the range it may change it to.
///
/// Bounds are checked when a proposal is *submitted*, not when it is enacted.
/// A value that cannot work should be refused in front of the proposer, while
/// there is someone to tell — not after it has carried a vote, when the only
/// place left to fail is enactment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernedParam {
    /// Stable key, used on the wire and in storage.
    pub key: &'static str,
    /// Smallest value that still leaves a working network.
    pub min: u64,
    /// Largest value that still leaves a working network.
    pub max: u64,
    /// Value the network starts with. Genesis writes it into state unless
    /// the genesis file's `[network_params]` names another value in bounds.
    pub genesis: u64,
    /// Which direction makes the rule stricter for the people it binds.
    /// A change in that direction waits out the tightening grace window.
    pub tighten: Tighten,
    /// What it does, surfaced to whoever is being asked to vote on it.
    pub description: &'static str,
}

/// Which direction of change makes a governed rule stricter for those it
/// binds: a higher bond or slash, or a shorter window to respond in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tighten {
    /// Raising the value tightens the rule.
    Up,
    /// Lowering the value tightens the rule.
    Down,
    /// Neither direction asks anything more of an existing participant.
    Neither,
    /// A status lever ([`LeverStatus`]): pausing and resuming apply at the
    /// next epoch, so a pause answers a fault within one epoch; retiring asks
    /// more of everyone who relies on the feature, so it waits out the grace
    /// window, and it is final.
    Retire,
}

impl Tighten {
    /// Whether moving from `current` to `value` tightens the rule.
    pub fn tightens(self, current: u64, value: u64) -> bool {
        match self {
            Tighten::Up => value > current,
            Tighten::Down => value < current,
            Tighten::Neither => false,
            Tighten::Retire => value == LeverStatus::Retired as u64 && current != value,
        }
    }
}

/// Whether a parameter change only pauses a feature: it sets a status lever
/// to paused, or the identity rule's mode to audit. A pause answers a fault
/// and can be put back by another vote, so it takes the expedited track;
/// enabling, retiring and every other change take the standard one.
pub fn is_pause_only(key: &str, value: u64) -> bool {
    if key == crate::identity_required::MODE_KEY {
        // Auditing the identity rule is its pause: nothing is refused while
        // what enforce would refuse is still logged.
        return value == crate::identity_required::Mode::Audit as u64;
    }
    value == LeverStatus::Paused as u64
        && governed_param(key).is_some_and(|p| p.tighten == Tighten::Retire)
}

/// The state of a feature a status lever governs. The lever is a governed
/// parameter whose key ends in `.status`, read with
/// [`crate::native::lever_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u64)]
pub enum LeverStatus {
    /// The feature works, open to anyone who meets its rules.
    Enabled = 0,
    /// Nothing new may start on the feature; what already started finishes
    /// or winds down under its own rules. Reversible by another vote.
    Paused = 1,
    /// The feature is gone for good: nothing new starts and no vote brings
    /// it back. A replacement ships under a new lever.
    Retired = 2,
}

impl LeverStatus {
    /// The status a lever's stored value names. A value outside the three is
    /// unreachable through the registry bounds and reads as paused.
    pub fn from_value(value: u64) -> Self {
        match value {
            0 => Self::Enabled,
            2 => Self::Retired,
            _ => Self::Paused,
        }
    }

    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

/// Refuse a change of a status lever that is already retired: retirement is
/// final, and a feature that returns ships under a new lever with its own
/// vote.
pub fn lever_change_allowed(key: &str, current: u64, value: u64) -> Result<(), GovernanceError> {
    let is_status = governed_param(key).is_some_and(|p| p.tighten == Tighten::Retire);
    if is_status && current == LeverStatus::Retired as u64 && value != current {
        return Err(GovernanceError::InvalidPolicy(format!(
            "{key} is retired; a retired feature does not return"
        )));
    }
    Ok(())
}

/// A status lever's registry entry: enabled at genesis, any of the three
/// statuses in bounds.
macro_rules! status_lever {
    ($key:expr, $description:expr) => {
        GovernedParam {
            key: $key,
            min: LeverStatus::Enabled as u64,
            max: LeverStatus::Retired as u64,
            genesis: LeverStatus::Enabled as u64,
            tighten: Tighten::Retire,
            description: $description,
        }
    };
}

/// Governed key: the moment from which stored records must carry hybrid
/// session signatures, ms since the Unix epoch (see
/// `tenzro_crypto::session::SessionSignature::verify_record`).
pub const HYBRID_RECORDS_FROM_PARAM: &str = "session.hybrid_records_from_ms";

/// Governed key: the moment from which a machine identity key must carry a
/// native ML-DSA-65 leg: a node without one then refuses to start, and a batch
/// root signed at or after it needs both legs to verify. Before it a node
/// signs with the classical leg its hardware holds (and the ML-DSA leg when the
/// hardware provides one, never a software key), and a root with only the
/// classical leg verifies. The highest value means never.
pub const PQ_LEG_REQUIRED_FROM_PARAM: &str = "records.pq_leg_required_from_ms";

/// Governed key: how long before the block that carries it a signed record (a
/// training receipt, inference evidence) and the batch root that signs it may
/// be dated. The signer's clock supplies those dates, so a verifier bounds
/// them against block time.
pub const MAX_RECORD_AGE_PARAM: &str = "records.max_record_age_ms";

/// Status lever of each inference verification level.
pub const VERIFICATION_RECEIPT_STATUS: &str = "inference.verification.receipt.status";
/// See [`VERIFICATION_RECEIPT_STATUS`].
pub const VERIFICATION_OPTIMISTIC_STATUS: &str = "inference.verification.optimistic.status";
/// See [`VERIFICATION_RECEIPT_STATUS`].
pub const VERIFICATION_TEE_STATUS: &str = "inference.verification.tee.status";

/// The status lever of an inference verification level; none for `none`,
/// which asks nothing of the network.
pub fn verification_status_key(
    level: tenzro_types::inference_verification::VerificationLevel,
) -> Option<&'static str> {
    use tenzro_types::inference_verification::VerificationLevel as L;
    match level {
        L::None => None,
        L::Receipt => Some(VERIFICATION_RECEIPT_STATUS),
        L::Optimistic => Some(VERIFICATION_OPTIMISTIC_STATUS),
        L::Tee => Some(VERIFICATION_TEE_STATUS),
    }
}

/// The status lever of a proof system the chain verifies.
pub fn proof_system_status_key(system: tenzro_zk::ProofSystem) -> &'static str {
    use tenzro_zk::ProofSystem as S;
    match system {
        S::KoalaBearSha256Fri => "zk.koala_bear_sha256_fri.status",
        S::GoldilocksBlake3Fri => "zk.goldilocks_blake3_fri.status",
        S::Halo2IpaPasta => "zk.halo2_ipa_pasta.status",
    }
}

/// Status lever of account recovery by a one-time recovery code.
pub const RECOVERY_CODE_STATUS: &str = "keystore.recovery.code.status";

/// The status lever of a kind of recovery signer.
pub fn recovery_factor_status_key(role: tenzro_types::keystore::RecoveryRole) -> &'static str {
    use tenzro_types::keystore::RecoveryRole as R;
    match role {
        R::RecoveryKey => "keystore.recovery.recovery_key.status",
        R::EmailVerifier => "keystore.recovery.email_verifier.status",
        R::Device => "keystore.recovery.device.status",
    }
}

/// The status lever of a bonded operator role other than validator: whether
/// new bonds for it are taken. Validator entry has no lever, so the
/// committee stays open to anyone who bonds.
pub fn role_status_key(role: tenzro_types::network::NetworkRole) -> Option<&'static str> {
    use tenzro_types::network::NetworkRole as R;
    Some(match role {
        R::TeeProvider => "roles.tee.status",
        R::ModelProvider => "roles.ai.status",
        R::ComputeProvider => "roles.compute.status",
        R::StorageProvider => "roles.storage.status",
        R::Rpc => "roles.rpc.status",
        R::Attestor => "roles.attestor.status",
        R::WalletProvider => "roles.wallet.status",
        R::CatalogPublisher => "roles.catalog.status",
        R::Edge => "roles.edge.status",
        _ => return None,
    })
}

/// The status lever of a bridge transport, over every route it carries.
pub fn bridge_adapter_status_key(
    adapter: tenzro_types::bridge_route::BridgeRouteAdapter,
) -> Option<&'static str> {
    use tenzro_types::bridge_route::BridgeRouteAdapter as A;
    Some(match adapter {
        A::Ccip => "bridge.ccip.status",
        A::Ibc => "bridge.ibc.status",
        A::Deposit => "bridge.deposit.status",
        A::Contract => "bridge.contract.status",
    })
}

/// Governed lower bound on the leader timeout a validator runs with, ms.
pub const CONSENSUS_LEADER_TIMEOUT_MIN_PARAM: &str = "consensus.leader_timeout_min_ms";
/// Governed upper bound on the leader timeout a validator runs with, ms.
pub const CONSENSUS_LEADER_TIMEOUT_MAX_PARAM: &str = "consensus.leader_timeout_max_ms";
/// Governed lower bound on the least time between a validator's rounds, ms.
pub const CONSENSUS_ROUND_INTERVAL_MIN_PARAM: &str = "consensus.round_interval_min_ms";
/// Governed upper bound on the least time between a validator's rounds, ms.
pub const CONSENSUS_ROUND_INTERVAL_MAX_PARAM: &str = "consensus.round_interval_max_ms";

/// `value` held inside `[min, max]`; when governance set the bounds the
/// wrong way round the lower bound wins, so a validator never runs faster
/// than the floor.
pub fn within_bounds(value: u64, min: u64, max: u64) -> u64 {
    value.min(max).max(min)
}

/// Governed key: epochs a tightening parameter change waits after the next
/// epoch boundary before it applies, so those it binds can adjust first.
pub const TIGHTENING_GRACE_PARAM: &str = "governance.tightening_grace_epochs";

/// Genesis value of [`TIGHTENING_GRACE_PARAM`]: 168 one-hour epochs, a week.
pub const DEFAULT_TIGHTENING_GRACE_EPOCHS: u64 = 168;

/// Governed key: recent blocks a validator or RPC node keeps locally.
pub const HISTORY_RETENTION_PARAM: &str = "storage.history_retention_blocks";

/// Genesis value of [`HISTORY_RETENTION_PARAM`]: about two weeks of blocks at
/// one a second. REVIEW before genesis: size it against the expected block
/// rate and the disk a validator is asked to provide.
pub const DEFAULT_HISTORY_RETENTION_BLOCKS: u64 = 1_209_600;

/// Governed key: the window, in milliseconds, over which each gossip
/// neighbour's message budgets are counted.
pub const GOSSIP_WINDOW_MS_PARAM: &str = "gossip.rate_window_ms";

/// Governed key: messages one gossip neighbour may deliver per window on the
/// topics consensus and sync depend on (certificates, blocks, validator
/// endpoints, peer status).
pub const GOSSIP_CONSENSUS_MESSAGES_PARAM: &str = "gossip.consensus_messages_per_window";

/// Governed key: messages one gossip neighbour may deliver per window on
/// every other topic, transactions included.
pub const GOSSIP_GENERAL_MESSAGES_PARAM: &str = "gossip.general_messages_per_window";

/// Governed key: seconds a gossip neighbour stays banned after its invalid
/// messages brought its score to the ban threshold.
pub const GOSSIP_BAN_SECONDS_PARAM: &str = "gossip.ban_seconds";

/// Governed key: seconds an agent's recorder keeps its audit entries after
/// their session closed, whatever the block-history window.
pub const AUDIT_RETENTION_PARAM: &str = "storage.audit_retention_seconds";

/// Shortest audit retention governance may set, and its genesis value: 183
/// days, six months rounded up.
pub const AUDIT_RETENTION_FLOOR_SECS: u64 = 183 * 24 * 60 * 60;

/// Every parameter governance may set.
///
/// Adding one here is what makes it governable; a constant not in this table
/// still requires a rebuild, which is the honest signal that nobody decided it
/// should be adjustable at runtime.
pub const GOVERNED_PARAMS: &[GovernedParam] = &[
    crate::feature_gate::registry_entry(
        crate::identity_required::KEY,
        crate::feature_gate::NEVER,
        "First epoch whose blocks refuse a transaction from an account with no registered identity (RegisterIdentity, key enrolment and protocol records stay open; a bonded validator is exempt). Dormant until a vote sets it.",
    ),
    GovernedParam {
        key: crate::identity_required::MODE_KEY,
        min: crate::identity_required::Mode::Enforce as u64,
        max: crate::identity_required::Mode::Off as u64,
        genesis: crate::identity_required::Mode::Enforce as u64,
        tighten: Tighten::Down,
        description: "What the identity rule does once live, at execution and at every node's peer, mempool and edge admission: 0 enforce (refuse an account or peer with no registered identity), 1 audit (refuse nothing, log what enforce would refuse), 2 off. Relaxing applies at the next epoch, and a change to audit runs on the expedited track; returning to enforce waits out the tightening grace window.",
    },
    GovernedParam {
        key: "stake.validator_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_VALIDATOR_STAKE / tenzro_types::constants::ONE_TNZO)
            as u64,
        tighten: Tighten::Up,
        description: "Validator self-stake admitted to the active set, whole TNZO. Seated validators are not ejected by a raise.",
    },
    GovernedParam {
        key: "stake.rpc_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_RPC_OPERATOR_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "RPC operator bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.attestor_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_ATTESTOR_STAKE / tenzro_types::constants::ONE_TNZO)
            as u64,
        tighten: Tighten::Up,
        description: "Attestor bond, whole TNZO. It also admits an attestor to bridge committee draws and reserve attestation.",
    },
    GovernedParam {
        key: "stake.wallet_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_WALLET_PROVIDER_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Wallet provider bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.catalog_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_CATALOG_PUBLISHER_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Catalog publisher bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.tee_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_TEE_PROVIDER_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "TEE provider bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.ai_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_MODEL_PROVIDER_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Model provider bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.compute_floor_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_COMPUTE_PROVIDER_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Smallest compute provider bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.compute_per_accelerator_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::COMPUTE_STAKE_PER_ACCELERATOR
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Compute bond per pledged accelerator at consumer class, before its class multiplier, whole TNZO.",
    },
    GovernedParam {
        key: "stake.storage_floor_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_STORAGE_PROVIDER_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Smallest storage provider bond, whole TNZO.",
    },
    GovernedParam {
        key: "stake.storage_per_tb_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::STORAGE_STAKE_PER_TB / tenzro_types::constants::ONE_TNZO)
            as u64,
        tighten: Tighten::Up,
        description: "Storage bond per pledged terabyte, whole TNZO.",
    },
    GovernedParam {
        key: "stake.edge_tnzo",
        min: 1,
        max: 10_000_000,
        genesis: (tenzro_types::constants::MIN_EDGE_OPERATOR_STAKE
            / tenzro_types::constants::ONE_TNZO) as u64,
        tighten: Tighten::Up,
        description: "Edge operator bond, whole TNZO. An edge operator serves the relay nodes find on chain at the URL its bond publishes.",
    },
    GovernedParam {
        key: crate::native::role_stake::BOND_FLOOR_RATE_PARAM,
        min: 0,
        max: 1_000_000_000_000,
        genesis: crate::native::role_stake::DEFAULT_BOND_FLOOR_RATE_NANO_USD,
        tighten: Tighten::Up,
        description: "TNZO/USD rate, nano-USD per TNZO, at which the bond amounts \
                      keep their USD value for a new or raised bond and a validator \
                      joining the set: below it, at the safety rate, each amount \
                      rises in proportion. Bonds already in place keep serving at \
                      the TNZO amounts. 0 turns the floor off.",
    },
    GovernedParam {
        key: "catalog.fault_slash_bps",
        min: 1,
        max: 10_000,
        genesis: crate::native::inference_fault::DEFAULT_CATALOG_FAULT_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Share of a catalog publisher's bond an upheld catalog fault takes into the insurance pool, bps.",
    },
    GovernedParam {
        key: "token.reserve_attestation_max_age_secs",
        min: 60,
        max: 30 * 24 * 60 * 60,
        genesis: crate::native::token::DEFAULT_RESERVE_ATTESTATION_MAX_AGE_SECS,
        tighten: Tighten::Down,
        description: "Oldest a reserve attestation behind a reserve-backed mint may be, seconds.",
    },
    GovernedParam {
        key: "bridge.committee_term_ms",
        min: 24 * 60 * 60 * 1000,
        max: 365 * 24 * 60 * 60 * 1000,
        genesis: crate::native::bridge_committee::DEFAULT_COMMITTEE_TERM_MS,
        tighten: Tighten::Neither,
        description: "How long a drawn bridge committee serves before a new draw falls due, ms.",
    },
    GovernedParam {
        key: "bridge.equivocation_slash_bps",
        min: 1,
        max: 10_000,
        genesis: crate::native::bridge_committee::DEFAULT_EQUIVOCATION_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Share of a bridge committee member's attestor bond taken when it signed two deliveries with one \
                      nonce or a handover to a committee the chain did not draw, bps.",
    },
    GovernedParam {
        key: crate::native::bridge_committee::HANDOVER_WINDOW_PARAM,
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::bridge_committee::DEFAULT_HANDOVER_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "How long after its term a bridge committee may still hand bridge contracts over to the next one, \
                      ms. Its members stay bonded until then, and the contracts stop trusting it after.",
    },
    GovernedParam {
        key: "fees.usd_rate_mode",
        min: 0,
        max: 1,
        genesis: crate::native::economy::DEFAULT_RATE_MODE,
        tighten: Tighten::Neither,
        description: "Where the TNZO/USD rate that prices fees comes from: 0 the \
                      governance-set rate, 1 the stake-weighted median of the \
                      rates bonded validators report each epoch.",
    },
    GovernedParam {
        key: "fees.tnzo_usd_nano",
        min: 1,
        max: 1_000_000_000_000_000,
        genesis: crate::native::economy::DEFAULT_TNZO_USD_NANO,
        tighten: Tighten::Neither,
        description: "The TNZO/USD rate in governance mode, in nano-USD per \
                      TNZO. Validator mode starts from it.",
    },
    GovernedParam {
        key: "fees.usd_rate_max_change_bps",
        min: 1,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_RATE_MAX_CHANGE_BPS,
        tighten: Tighten::Neither,
        description: "Most the validator-reported rate may rise in one hourly \
                      epoch, in basis points of the rate in force.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_MAX_FALL_PARAM,
        min: 100,
        max: 2_000,
        genesis: crate::native::economy::DEFAULT_RATE_MAX_FALL_BPS,
        tighten: Tighten::Neither,
        description: "Most the validator-reported rate may fall in one hourly \
                      epoch, in basis points of the rate in force. Above the rise \
                      cap, so a crash is followed within days, not weeks.",
    },
    GovernedParam {
        key: crate::native::economy::SAFETY_RATE_WINDOW_PARAM,
        min: 1,
        max: crate::native::economy::MAX_SAFETY_RATE_WINDOW_EPOCHS,
        genesis: crate::native::economy::DEFAULT_SAFETY_RATE_WINDOW_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs of frozen medians the safety rate looks back over. \
                      Safety checks (the security ratio, the stake-backed bridge \
                      caps, the USD floor on bonds) value TNZO at the lower of the \
                      rate in force and the lowest median in this window; \
                      payments keep the rate in force.",
    },
    GovernedParam {
        key: "fees.usd_rate_quorum_bps",
        min: 5_001,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_RATE_QUORUM_BPS,
        tighten: Tighten::Neither,
        description: "Share of bonded stake, in basis points, that must open its sealed rates for an epoch before that epoch's median moves the rate.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_STALE_EPOCHS_PARAM,
        min: 1,
        max: 720,
        genesis: crate::native::economy::DEFAULT_RATE_STALE_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs in a row short of the quorum, with at least the staleness quorum still reporting, that the rate in force may sit further than the staleness gap from their median before it moves toward that median at the per-epoch bound.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_STALE_GAP_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_RATE_STALE_GAP_BPS,
        tighten: Tighten::Neither,
        description: "Gap between the rate in force and an epoch's median, in basis points of the median, that counts the epoch as stale.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_STALE_QUORUM_PARAM,
        min: 5_001,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_RATE_STALE_QUORUM_BPS,
        tighten: Tighten::Neither,
        description: "Share of bonded stake, in basis points, that must open its rates for an epoch short of the quorum to count toward staleness and to move a stale rate toward its median; never less than a majority.",
    },
    GovernedParam {
        key: "fees.usd_rate_quantile_low_bps",
        min: 0,
        max: 5_000,
        genesis: crate::native::economy::DEFAULT_RATE_QUANTILE_LOW_BPS,
        tighten: Tighten::Neither,
        description: "Low stake-weighted quantile of an epoch's opened rate reports, in basis points: the rate moves only into the band between it and the high quantile, so reporters below this share of stake can hold the rate but not move it.",
    },
    GovernedParam {
        key: "fees.usd_rate_quantile_high_bps",
        min: 5_000,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_RATE_QUANTILE_HIGH_BPS,
        tighten: Tighten::Neither,
        description: "High stake-weighted quantile of an epoch's opened rate reports, in basis points; the top of the band the rate may move into.",
    },
    GovernedParam {
        key: "fees.usd_rate_frozen",
        min: 0,
        max: 1,
        genesis: 0,
        tighten: Tighten::Neither,
        description: "1 holds the validator-reported rate where it is while a challenge or a lost quorum is decided; medians are still recorded. Fees go on at the held rate.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_MIN_SOURCES_PARAM,
        min: crate::native::economy::MIN_RATE_SOURCES as u64,
        max: crate::native::economy::MAX_RATE_MIN_SOURCES,
        genesis: crate::native::economy::MIN_RATE_SOURCES as u64,
        tighten: Tighten::Up,
        description: "Fewest independent sources a validator's rate report must quote for each symbol. A report quoting fewer is refused when opened, and an opened report below the value in force at the tally is not counted, so no single venue sets a report.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_BREAKER_SPREAD_PARAM,
        min: 50,
        max: 5_000,
        genesis: crate::native::economy::DEFAULT_RATE_BREAKER_SPREAD_BPS,
        tighten: Tighten::Down,
        description: "Widest spread between the low and high stake-weighted quantiles of an epoch's rate reports, in basis points of the low quantile, before that epoch holds the rate instead of moving it and counts toward the dispersion breaker.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_BREAKER_GAP_PARAM,
        min: 500,
        max: 50_000,
        genesis: crate::native::economy::DEFAULT_RATE_BREAKER_GAP_BPS,
        tighten: Tighten::Down,
        description: "Widest gap between an epoch's TNZO median and the governance rate, in basis points of the governance rate, before that epoch holds the rate and counts toward the dispersion breaker.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_BREAKER_EPOCHS_PARAM,
        min: 1,
        max: 24,
        genesis: crate::native::economy::DEFAULT_RATE_BREAKER_EPOCHS,
        tighten: Tighten::Down,
        description: "Tallied epochs in a row whose reports breach the dispersion spread or the governance-rate gap before the TNZO rate falls back to the governance rate. It stays there until governance sets fees.usd_rate_mode to 1 again.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_UNOPENED_SLASH_PARAM,
        min: 1,
        max: 500,
        genesis: crate::native::economy::DEFAULT_RATE_UNOPENED_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Share of its validator bond, in basis points, a validator forfeits to the insurance pool for each epoch it sealed rates for and never opened, so sealing a report and withholding it when it turns out unwelcome costs stake.",
    },
    GovernedParam {
        key: crate::native::economy::RATE_MAX_AGE_PARAM,
        min: 1,
        max: 8_760,
        genesis: crate::native::economy::DEFAULT_RATE_MAX_AGE_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs the validator-reported rate may go without a newer frozen median before it is reported as held. Fees go on at the last good rate while it is held; it never moves on its own.",
    },
    GovernedParam {
        key: "fees.identity_register_micro_usd",
        min: 0,
        max: 100_000_000,
        genesis: crate::native::economy::DEFAULT_IDENTITY_FEE_MICRO_USD,
        tighten: Tighten::Neither,
        description: "USD price of registering an identity, in micro-USD, paid in TNZO at the rate in force and burned.",
    },
    GovernedParam {
        key: "fees.verify_micro_usd",
        min: 0,
        max: 100_000_000,
        genesis: crate::native::economy::DEFAULT_VERIFY_FEE_MICRO_USD,
        tighten: Tighten::Neither,
        description: "USD price of one verification (a proof attestation), in micro-USD, paid in TNZO at the rate in force and burned.",
    },
    GovernedParam {
        key: "fees.inference_settle_micro_usd",
        min: 0,
        max: 100_000_000,
        genesis: crate::native::economy::DEFAULT_INFERENCE_FEE_MICRO_USD,
        tighten: Tighten::Neither,
        description: "USD price of one inference or compute stream settlement, in micro-USD, paid by the claiming provider in TNZO at the rate in force and burned.",
    },
    GovernedParam {
        key: "compute_bond.var_ratio_bps",
        min: 0,
        max: 1_000_000,
        genesis: crate::native::economy::DEFAULT_VAR_RATIO_BPS,
        tighten: Tighten::Up,
        description: "Least ratio, in basis points, of a bonded provider's compute bond to the TNZO it holds in open escrows; an escrow that would breach it is refused. 0 turns the check off.",
    },
    GovernedParam {
        key: "compute_bond.min_escrow_gwei",
        min: 0,
        max: 1_000_000_000_000,
        genesis: crate::native::economy::DEFAULT_MIN_ESCROW_GWEI,
        tighten: Tighten::Up,
        description: "Least TNZO, in gwei, one escrow toward a bonded provider may lock, so the open escrows a provider's bond carries stay few enough to check on every new one.",
    },
    GovernedParam {
        key: "sla.verdict_retention_epochs",
        min: 48,
        max: 24 * 3_660,
        genesis: 168,
        tighten: Tighten::Neither,
        description: "Market epochs a frozen SLA verdict is kept. After it an hour judged unavailable still reads as unavailable from a small mark, and one judged available reads as paid.",
    },
    GovernedParam {
        key: "sla.down_retention_epochs",
        min: 0,
        max: 24 * 36_600,
        genesis: 0,
        tighten: Tighten::Neither,
        description: "Market epochs the mark of an hour judged unavailable is kept after its verdict is gone; 0 keeps it. A stream or claim settled after the mark is gone pays that hour.",
    },
    GovernedParam {
        key: "escrow.retention_hours",
        min: 24,
        max: 24 * 3_660,
        genesis: 720,
        tighten: Tighten::Neither,
        description: "Hours an escrow's record stays in state once it can no longer move, counted from its expiry; it is then deleted and its whole record emitted in an EscrowArchived log for indexers.",
    },
    GovernedParam {
        key: "validator.admission_approval",
        min: 0,
        max: 1,
        genesis: 0,
        tighten: Tighten::Up,
        description: "1: closed: a validator registers and sits on a committee only if it is on the admitted set (the genesis validators and the accounts an enacted ApproveValidators proposal approved); 0: open: any account that meets the bond rules may.",
    },
    GovernedParam {
        key: "validator.sponsored_bond_max_tnzo",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most sponsored stake one validator may hold, bonded and unbonding, whole TNZO: existing treasury TNZO an enacted SponsorValidatorBond bonded on its behalf. It counts toward the bond and is slashable, never votes, earns nothing and returns to the treasury on recall or exit. 0 disables sponsorship.",
    },
    GovernedParam {
        key: "validator.sponsored_bond_total_max_tnzo",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most sponsored stake out of the treasury network-wide, bonded and unbonding, whole TNZO. 0 disables sponsorship.",
    },
    GovernedParam {
        key: "sponsorship.yearly_max_tnzo",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most treasury TNZO sponsorship may commit in a 365-day period, whole TNZO: sponsored bonds and running-cost payments to approved operators. One operator receives at most one third of it. 0 disables sponsorship.",
    },
    GovernedParam {
        key: "sponsorship.running_cost_per_verified_epoch_wei",
        min: 0,
        max: 1_000_000_000_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most TNZO, in wei, one verified-available hour of an approved operator backs in a running-cost sponsorship. 0 disables running-cost sponsorship.",
    },
    GovernedParam {
        key: "grants.per_grantee_yearly_max_tnzo",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most treasury TNZO one approved grantee may be paid in a 365-day period, whole TNZO, whoever the grantee is. 0 disables grants.",
    },
    GovernedParam {
        key: "treasury.sponsorship_grants_yearly_max_tnzo",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most treasury TNZO sponsorship and grants may pay out together in a 365-day period, whole TNZO. 0 disables both.",
    },
    GovernedParam {
        key: "sponsorship.yearly_max_usd",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most treasury sponsorship paid in an approved USD stable asset may commit in a 365-day period, whole US dollars. One operator receives at most one third of it. 0 disables stable sponsorship.",
    },
    GovernedParam {
        key: "sponsorship.running_cost_per_verified_epoch_usd_e6",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most one verified-available hour of an approved operator backs in a stable-asset running-cost payment, micro-dollars. 0 disables stable running-cost payments.",
    },
    GovernedParam {
        key: "grants.per_grantee_yearly_max_usd",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most one approved grantee may be paid in a stable asset in a 365-day period, whole US dollars. 0 disables stable grants.",
    },
    GovernedParam {
        key: "treasury.sponsorship_grants_yearly_max_usd",
        min: 0,
        max: 1_000_000_000,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Most sponsorship and grants may pay together in stable assets in a 365-day period, whole US dollars. 0 disables both.",
    },
    GovernedParam {
        key: "treasury.proposal_outflow_exception_bps",
        min: 0,
        max: 500,
        genesis: 0,
        tighten: Tighten::Down,
        description: "Basis points of the period's opening stable holdings one stable sponsorship payment may use above the period outflow limit when its proposal asks for the exception. The yearly USD caps and the per-proposal limit still bind. 0 disables the exception.",
    },
    GovernedParam {
        key: "agent.topup_max_days",
        min: 1,
        max: 366,
        genesis: 90,
        tighten: Tighten::Down,
        description: "Days ahead the expiry of an agent top-up allowance may be set; an allowance runs out within this and the controller renews it to keep refills going.",
    },
    GovernedParam {
        key: "escrow.close_grace_hours",
        min: 0,
        max: 24 * 366,
        genesis: 168,
        tighten: Tighten::Neither,
        description: "Hours past its expiry after which anyone may close an escrow; what accrued goes to the payee and the rest to the payer, as when they close it.",
    },
    GovernedParam {
        key: "fees.validator_burn_share_bps",
        min: 0,
        max: 10_000,
        genesis: 2_500,
        tighten: Tighten::Neither,
        description: "Share of each epoch's burned fees, in basis points, that funds validators' base rewards, drawn from the rewards pool on top of the validator share.",
    },
    GovernedParam {
        key: "validator.base_cost_usd_month",
        min: 0,
        max: 100_000,
        genesis: 1_500,
        tighten: Tighten::Neither,
        description: "Running cost one active validator's base reward covers, in USD a month at the rate in force; one base per validator with recorded consensus work.",
    },
    GovernedParam {
        key: crate::native::validator_cover::FEE_SHARE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::validator_cover::DEFAULT_FEE_SHARE_BPS,
        tighten: Tighten::Neither,
        description: "Share of the stable settlement fees the treasury keeps that fills the validator cover reserve, bps; the reserve pays each active validator's running cost in stable assets before any base reward.",
    },
    GovernedParam {
        key: crate::native::validator_cover::TARGET_MONTHS_PARAM,
        min: 0,
        max: 60,
        genesis: crate::native::validator_cover::DEFAULT_TARGET_MONTHS,
        tighten: Tighten::Neither,
        description: "Months of the active validators' running cost the validator cover reserve fills up to from stable settlement fees; fees beyond it stay with the treasury.",
    },
    GovernedParam {
        key: "validator.base_cap_tnzo_month",
        min: 0,
        max: 10_000_000,
        genesis: 20_000,
        tighten: Tighten::Neither,
        description: "Most base reward one validator earns, in whole TNZO a month, so a falling rate cannot raise it without bound.",
    },
    GovernedParam {
        key: "mint.base_tnzo_per_year",
        min: 0,
        max: 400_000_000,
        genesis: 60_000_000,
        tighten: Tighten::Neither,
        description: "TNZO released from the genesis-funded network-rewards pool in schedule year 0, in whole TNZO. Never priced in fiat. The `mint.` keys name pool releases: no TNZO is minted, and releases stop when the pool is empty.",
    },
    GovernedParam {
        key: "mint.decay_bps_per_year",
        min: 0,
        max: 10_000,
        genesis: 1_500,
        tighten: Tighten::Neither,
        description: "Share of a year's pool release dropped the following year, in basis points.",
    },
    GovernedParam {
        key: "mint.floor_tnzo_per_year",
        min: 0,
        max: 400_000_000,
        genesis: 10_000_000,
        tighten: Tighten::Neither,
        description: "Least yearly pool release, in whole TNZO, while the pool lasts.",
    },
    GovernedParam {
        key: crate::native::security::MIN_RATIO_PARAM,
        min: 10_000,
        max: 100_000,
        genesis: crate::native::security::DEFAULT_MIN_RATIO_BPS,
        tighten: Tighten::Up,
        description: "Least security ratio, bps: slashable stake over what one attack \
                      can take out over the bridges. A raise of any bridge outflow cap, \
                      and the switch of the fee rate to validator mode, are refused \
                      below it; the pool release rises below it and falls above it.",
    },
    GovernedParam {
        key: crate::native::security::ATTACK_STAKE_PARAM,
        min: 100,
        max: 3_334,
        genesis: crate::native::security::DEFAULT_ATTACK_STAKE_BPS,
        tighten: Tighten::Down,
        description: "Share of bonded stake, bps, a safety fault must put at risk: the \
                      slashable side of the security ratio.",
    },
    GovernedParam {
        key: crate::native::security::ATTACK_WINDOW_PARAM,
        min: 1,
        max: 8_760,
        genesis: crate::native::security::DEFAULT_ATTACK_WINDOW_EPOCHS,
        tighten: Tighten::Up,
        description: "Epochs an attack drains the bridge outflow caps before it is \
                      stopped: the extractable side of the security ratio is this many \
                      epochs of every cap.",
    },
    GovernedParam {
        key: "mint.adj_bps_per_year",
        min: 0,
        max: 10_000,
        genesis: 2_500,
        tighten: Tighten::Neither,
        description: "Most the pool release controller moves its multiplier in a year, in basis points of 1x.",
    },
    GovernedParam {
        key: "mint.min_mult_bps",
        min: 0,
        max: 100_000,
        genesis: 5_000,
        tighten: Tighten::Neither,
        description: "Least pool release controller multiplier, in basis points of 1x.",
    },
    GovernedParam {
        key: "mint.max_mult_bps",
        min: 0,
        max: 100_000,
        genesis: 10_000,
        tighten: Tighten::Neither,
        description: "Greatest pool release controller multiplier, in basis points of 1x.",
    },
    GovernedParam {
        key: "mint.validator_share_bps",
        min: 0,
        max: 10_000,
        genesis: 4_500,
        tighten: Tighten::Neither,
        description: "Validators' share of each epoch's pool release, in basis points of the three shares' sum.",
    },
    GovernedParam {
        key: "mint.provider_share_bps",
        min: 0,
        max: 10_000,
        genesis: 4_000,
        tighten: Tighten::Neither,
        description: "Providers' share of each epoch's pool release, paid by verified served revenue, in basis points of the three shares' sum.",
    },
    GovernedParam {
        key: "mint.ecosystem_share_bps",
        min: 0,
        max: 10_000,
        genesis: 1_500,
        tighten: Tighten::Neither,
        description: "Apps' share of each epoch's pool release, paid by the fees their users paid, in basis points of the three shares' sum.",
    },
    GovernedParam {
        key: "mint.revenue_peg_bps",
        min: 0,
        max: 10_000,
        genesis: tenzro_token::rewards::DEFAULT_REVENUE_PEG_BPS,
        tighten: Tighten::Neither,
        description: "Cap on what the provider and app shares pay in an epoch, in basis points of the work weight their settlements recorded (each settlement's own reward ceiling); the rest stays in the pool.",
    },
    GovernedParam {
        key: crate::native::rewards::PROVIDER_REWARD_COST_PARAM,
        min: 0,
        max: tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS,
        genesis: crate::native::rewards::DEFAULT_PROVIDER_REWARD_COST_BPS,
        tighten: Tighten::Neither,
        description: "Most provider reward weight one settlement earns, in basis points of the protocol fee it paid outside the trade. With fees.activity_reward_fee_bps and fees.creator_royalty_fee_bps it may add up to at most 9000, so a buyer, provider and app acting together never earn back what a settlement cost them.",
    },
    GovernedParam {
        key: crate::native::hardware_level::LEVEL1_BONUS_PARAM,
        min: 0,
        max: crate::native::hardware_level::MAX_LEVEL_BONUS_BPS,
        genesis: crate::native::hardware_level::DEFAULT_LEVEL1_BONUS_BPS,
        tighten: Tighten::Neither,
        description: "Bonus on a provider's base reward share for hardware level 1 (a manufacturer-certified TPM the chain verified), in basis points, at most hardware.level_bonus_cap_bps. Paid on top of base shares, never out of them; at most hardware.level2_bonus_bps.",
    },
    GovernedParam {
        key: crate::native::hardware_level::LEVEL2_BONUS_PARAM,
        min: 0,
        max: crate::native::hardware_level::MAX_LEVEL_BONUS_BPS,
        genesis: crate::native::hardware_level::DEFAULT_LEVEL2_BONUS_BPS,
        tighten: Tighten::Neither,
        description: "Bonus for hardware level 2 (level 1 plus a hardware-held ML-DSA key proven on chain), in basis points, at most hardware.level_bonus_cap_bps; between hardware.level1_bonus_bps and hardware.level3_bonus_bps.",
    },
    GovernedParam {
        key: crate::native::hardware_level::LEVEL3_BONUS_PARAM,
        min: 0,
        max: crate::native::hardware_level::MAX_LEVEL_BONUS_BPS,
        genesis: crate::native::hardware_level::DEFAULT_LEVEL3_BONUS_BPS,
        tighten: Tighten::Neither,
        description: "Bonus for hardware level 3 (a hardware post-quantum attestation key, or a second hardware scheme, proven on chain), in basis points, at most hardware.level_bonus_cap_bps; at least hardware.level2_bonus_bps.",
    },
    GovernedParam {
        key: crate::native::hardware_level::LEVEL_BONUS_CAP_PARAM,
        min: 0,
        max: crate::native::hardware_level::MAX_LEVEL_BONUS_BPS,
        genesis: crate::native::hardware_level::DEFAULT_LEVEL_BONUS_CAP_BPS,
        tighten: Tighten::Neither,
        description: "Most hardware-level bonus any provider earns, in basis points of its base reward share; 0 turns the bonus off. A level never admits or excludes anyone. With mint.provider_reward_cost_bps raised by it, fees.activity_reward_fee_bps and fees.creator_royalty_fee_bps may add up to at most 9500, so the bonus never makes trading with oneself pay.",
    },
    GovernedParam {
        key: "fees.settlement_fee_bps",
        min: 0,
        max: 1_000,
        genesis: crate::native::economy::DEFAULT_SETTLEMENT_FEE_BPS,
        tighten: Tighten::Up,
        description: "Settlement fee, in basis points of the value each \
                      on-chain settlement pays out, divided between burn and \
                      treasury by fees.settlement_fee_burn_bps.",
    },
    GovernedParam {
        key: "fees.activity_reward_fee_bps",
        min: 0,
        max: 9_000,
        genesis: crate::native::economy::DEFAULT_ACTIVITY_REWARD_FEE_BPS,
        tighten: Tighten::Neither,
        description: "Most one settlement earns in ecosystem activity \
                      rewards, in basis points of the settlement fee it paid, \
                      shared by the apps, agents and tools its payer \
                      attributed it to. With mint.provider_reward_cost_bps \
                      and fees.creator_royalty_fee_bps it may add up to at \
                      most 9000, below the whole fee, so trading with oneself \
                      never pays.",
    },
    GovernedParam {
        key: crate::native::economy::TREASURY_LEG_INFERENCE_PARAM,
        min: 0,
        max: crate::native::economy::MAX_TREASURY_LEG_BPS,
        genesis: crate::native::economy::DEFAULT_TREASURY_LEG_BPS,
        tighten: Tighten::Up,
        description: "Treasury leg of an inference payment settled on chain to a provider \
                      whose bond or stake makes it that class of work, in \
                      basis points of what the provider is credited after the \
                      settlement fee. It is paid outside the trade, so it \
                      counts with the fee toward what the settlement may earn.",
    },
    GovernedParam {
        key: crate::native::economy::TREASURY_LEG_TEE_PARAM,
        min: 0,
        max: crate::native::economy::MAX_TREASURY_LEG_BPS,
        genesis: crate::native::economy::DEFAULT_TREASURY_LEG_BPS,
        tighten: Tighten::Up,
        description: "Treasury leg of a TEE session payment settled on chain to a provider \
                      whose bond or stake makes it that class of work, in \
                      basis points of what the provider is credited after the \
                      settlement fee. It is paid outside the trade, so it \
                      counts with the fee toward what the settlement may earn.",
    },
    GovernedParam {
        key: crate::native::economy::TREASURY_LEG_RPC_PARAM,
        min: 0,
        max: crate::native::economy::MAX_TREASURY_LEG_BPS,
        genesis: crate::native::economy::DEFAULT_TREASURY_LEG_BPS,
        tighten: Tighten::Up,
        description: "Treasury leg of an RPC traffic payment settled on chain to a provider \
                      whose bond or stake makes it that class of work, in \
                      basis points of what the provider is credited after the \
                      settlement fee. It is paid outside the trade, so it \
                      counts with the fee toward what the settlement may earn.",
    },
    GovernedParam {
        key: crate::native::economy::TREASURY_LEG_COMPUTE_PARAM,
        min: 0,
        max: crate::native::economy::MAX_TREASURY_LEG_BPS,
        genesis: crate::native::economy::DEFAULT_TREASURY_LEG_BPS,
        tighten: Tighten::Up,
        description: "Treasury leg of a compute lease payment settled on chain to a provider \
                      whose bond or stake makes it that class of work, in \
                      basis points of what the provider is credited after the \
                      settlement fee. It is paid outside the trade, so it \
                      counts with the fee toward what the settlement may earn.",
    },
    GovernedParam {
        key: crate::native::economy::TREASURY_LEG_STORAGE_PARAM,
        min: 0,
        max: crate::native::economy::MAX_TREASURY_LEG_BPS,
        genesis: crate::native::economy::DEFAULT_TREASURY_LEG_BPS,
        tighten: Tighten::Up,
        description: "Treasury leg of a storage payment settled on chain to a provider \
                      whose bond or stake makes it that class of work, in \
                      basis points of what the provider is credited after the \
                      settlement fee. It is paid outside the trade, so it \
                      counts with the fee toward what the settlement may earn.",
    },
    GovernedParam {
        key: crate::native::economy::CREATOR_ROYALTY_FEE_PARAM,
        min: 0,
        max: tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS,
        genesis: crate::native::economy::DEFAULT_CREATOR_ROYALTY_FEE_BPS,
        tighten: Tighten::Neither,
        description: "Royalty one settlement pays the apps, agents and tools \
                      its payer attributed it to, in basis points of its \
                      settlement fee, out of the fee's treasury part, so the \
                      payer pays no more. With mint.provider_reward_cost_bps \
                      and fees.activity_reward_fee_bps it may add up to at \
                      most 9000.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_REWARD_PER_UNIT_HOUR,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_REWARD_PER_UNIT_HOUR,
        tighten: Tighten::Neither,
        description: "TNZO per hour the availability reward pays, before \
                      decay, for one verified-available SLA verdict (every \
                      serving role an SLA probe owes: TEE, model, compute, \
                      storage and RPC providers, plus wallet and edge \
                      stakes). Zero disables the reward entirely, which is \
                      genesis. Paid out of the treasury; an epoch the \
                      treasury cannot cover forfeits that epoch's reward.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_REWARD_DECAY_START_EPOCH,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_REWARD_DECAY_START_EPOCH,
        tighten: Tighten::Down,
        description: "The one-hour epoch the availability reward's decay \
                      clock starts counting from. Zero means decay has not \
                      been scheduled: the reward pays its full per-unit-hour \
                      cap undecayed for as long as the cap stays nonzero. \
                      Lowering it starts decay sooner, which is why it \
                      tightens downward.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS,
        tighten: Tighten::Down,
        description: "Half-life, in whole days, of the availability \
                      reward's decay once its start epoch is reached. Decay \
                      is a deterministic integer half-life, not floating- \
                      point exponential (this VM has no floating-point \
                      arithmetic, for cross-validator determinism): exact at \
                      every whole half-life (a bit shift) and linearly \
                      interpolated in between, so it keeps halving rather \
                      than clamping to zero at some fixed multiple of the \
                      half-life. Zero disables decay.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_REWARD_REQUIRE_HARDWARE,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_REWARD_REQUIRE_HARDWARE,
        tighten: Tighten::Up,
        description: "Whether the availability reward is paid at all: while \
                      zero (genesis) it pays nothing, whatever its cap, decay, \
                      demand offset or readiness tiers, because nothing ties a \
                      verdict to a real machine. Set, a verified-available \
                      verdict pays only when the subject's provider_did is a \
                      machine identity with a TPM endorsement chaining to a \
                      recognised root (the check validator admission uses).",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY,
        tighten: Tighten::Up,
        description: "Verified-paid-demand target, atto-USD per day, at \
                      which the availability reward's demand offset has \
                      phased the reward all the way to zero. Converted to \
                      wei at the validator-signed rate in force. Zero \
                      (genesis) disables the offset: the reward ignores \
                      settled demand until governance sets a real target.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS_PARAM,
        min: 1,
        max: crate::native::availability_reward::MAX_AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS,
        tighten: Tighten::Neither,
        description: "One-hour epochs the availability reward's demand \
                      offset trails behind the attested epoch when summing \
                      verified-paid demand. Genesis one day.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_READINESS_COLD_BPS_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_READINESS_BPS,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_READINESS_BPS,
        tighten: Tighten::Down,
        description: "Availability reward multiplier, bps, for a subject \
                      that declared ReadinessTier::Cold (a \
                      DeclareReadinessTier transaction signed by the \
                      account that owns its bond or stake). Genesis 100%: \
                      the tier changes no payout until governance sets it \
                      apart from Warm.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_READINESS_COOL_BPS_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_READINESS_BPS,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_READINESS_BPS,
        tighten: Tighten::Down,
        description: "Availability reward multiplier, bps, for a subject \
                      that declared ReadinessTier::Cool. Genesis 100%.",
    },
    GovernedParam {
        key: crate::native::availability_reward::AVAILABILITY_READINESS_WARM_BPS_PARAM,
        min: 0,
        max: crate::native::availability_reward::MAX_AVAILABILITY_READINESS_BPS,
        genesis: crate::native::availability_reward::DEFAULT_AVAILABILITY_READINESS_BPS,
        tighten: Tighten::Down,
        description: "Availability reward multiplier, bps, for \
                      ReadinessTier::Warm -- the default tier for any \
                      subject that has never declared one. Genesis 100%.",
    },
    GovernedParam {
        key: "fees.settlement_fee_burn_bps",
        min: 0,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_SETTLEMENT_FEE_BURN_BPS,
        tighten: Tighten::Neither,
        description: "Share of the settlement fee burned, in basis points; \
                      the rest goes to the treasury.",
    },
    GovernedParam {
        key: crate::native::payment_settlement::MAX_RESELLER_LEGS_PARAM,
        min: 0,
        max: crate::native::payment_settlement::MAX_MAX_RESELLER_LEGS,
        genesis: crate::native::payment_settlement::DEFAULT_MAX_RESELLER_LEGS,
        tighten: Tighten::Down,
        description: "Most reseller legs one payment carries, each a commission the payer signed on top of the operator's price; zero refuses resold payments.",
    },
    GovernedParam {
        key: crate::native::payment_settlement::RELAY_REIMBURSE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::payment_settlement::DEFAULT_RELAY_REIMBURSE_BPS,
        tighten: Tighten::Neither,
        description: "Most of the treasury's share of a fee collected in kind a \
                      relayer is reimbursed for the gas it fronted, bps; never more \
                      than the gas at the rates in force.",
    },
    GovernedParam {
        key: crate::native::payout_swap::SPREAD_PARAM,
        min: 0,
        max: crate::native::payout_swap::MAX_SPREAD_BPS,
        genesis: crate::native::payout_swap::DEFAULT_SPREAD_BPS,
        tighten: Tighten::Up,
        description: "Spread the treasury keeps on a payout swap, bps, taken from \
                      the lower of the par amount and the amount at the two \
                      validator rates.",
    },
    GovernedParam {
        key: crate::native::payout_swap::EPOCH_CAP_PARAM,
        min: 0,
        max: crate::native::payout_swap::MAX_EPOCH_CAP_UNITS,
        genesis: crate::native::payout_swap::DEFAULT_EPOCH_CAP_UNITS,
        tighten: Tighten::Down,
        description: "Most value swapped from the treasury's stable holdings for \
                      payouts in one epoch, whole units of account. Requests are \
                      collected through the epoch and the cap is shared pro-rata \
                      by value when it closes, so a request's place in the epoch \
                      changes nothing.",
    },
    GovernedParam {
        key: crate::native::payout_swap::CARRY_PARAM,
        min: 1,
        max: crate::native::payout_swap::MAX_CARRY_EPOCHS,
        genesis: crate::native::payout_swap::DEFAULT_CARRY_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs the unfilled part of a payout swap request is carried \
                      into later epochs' pro-rata fills before it is paid to the \
                      payee in the asset it arrived in.",
    },
    GovernedParam {
        key: crate::native::settlement_asset::BREAKER_SUSPEND_PARAM,
        min: 1,
        max: crate::native::settlement_asset::MAX_BREAKER_SUSPEND_EPOCHS,
        genesis: crate::native::settlement_asset::DEFAULT_BREAKER_SUSPEND_EPOCHS,
        tighten: Tighten::Down,
        description: "Consecutive epochs a settlement asset's frozen rate may sit \
                      outside its par band before its peg breaker suspends it. A \
                      suspended asset settles nothing and pays nothing out; what \
                      the treasury holds of it is kept, never sold.",
    },
    GovernedParam {
        key: crate::native::settlement_asset::BREAKER_RESUME_PARAM,
        min: 1,
        max: crate::native::settlement_asset::MAX_BREAKER_RESUME_EPOCHS,
        genesis: crate::native::settlement_asset::DEFAULT_BREAKER_RESUME_EPOCHS,
        tighten: Tighten::Up,
        description: "Consecutive epochs a suspended settlement asset's frozen rate \
                      must hold inside the resume band before it settles again, so \
                      a rate at the band edge cannot switch it on and off.",
    },
    GovernedParam {
        key: crate::native::settlement_asset::BREAKER_RESUME_BAND_PARAM,
        min: crate::native::settlement_asset::MIN_BREAKER_RESUME_BAND_BPS,
        max: tenzro_types::settlement_asset::MAX_PAR_BAND_BPS,
        genesis: crate::native::settlement_asset::DEFAULT_BREAKER_RESUME_BAND_BPS,
        tighten: Tighten::Down,
        description: "Band around par, bps, a suspended settlement asset's rate must \
                      hold inside to count toward settling again; never wider than \
                      the asset's own par band.",
    },
    GovernedParam {
        key: crate::native::insurance::MAX_PAID_EPOCH_PARAM,
        min: 0,
        max: crate::native::insurance::MAX_PAID_TNZO_EPOCH,
        genesis: crate::native::insurance::DEFAULT_MAX_PAID_TNZO_EPOCH,
        tighten: Tighten::Down,
        description: "Most all insurance claims pay in one epoch, whole TNZO, \
                      whatever the rate their USD losses were priced at.",
    },
    GovernedParam {
        key: crate::native::insurance::COVER_TARGET_PARAM,
        min: 0,
        max: crate::native::insurance::MAX_COVER_TARGET_UNITS,
        genesis: crate::native::insurance::DEFAULT_COVER_TARGET_UNITS,
        tighten: Tighten::Neither,
        description: "Value the insurance pool is meant to cover, whole units of \
                      account. Each epoch boundary publishes the pool's value, \
                      its TNZO at the safety rate, against it as the coverage \
                      ratio; 0 publishes no ratio.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::GRANT_FLOOR_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::treasury_reserve::DEFAULT_GRANT_FLOOR_BPS,
        tighten: Tighten::Up,
        description: "Reserve balance, bps of the running-cost reserve's target, \
                      under which treasury grants and grant tranche releases are \
                      refused; running costs are still paid. A reserve with no \
                      target yet has no floor.",
    },
    GovernedParam {
        key: crate::native::burn_netting::BURN_DEBT_CAP_PARAM,
        min: 0,
        max: crate::native::burn_netting::MAX_BURN_DEBT_CAP_EPOCHS,
        genesis: crate::native::burn_netting::DEFAULT_BURN_DEBT_CAP_EPOCHS,
        tighten: Tighten::Neither,
        description: "Most burn debt carried from epoch to epoch, in epochs of \
                      scheduled pool release. Fees collected in other assets burn by \
                      withholding pool release; what the release cannot cover is \
                      carried up to this cap, and past it the treasury burns TNZO.",
    },
    GovernedParam {
        key: crate::native::burn_netting::TREASURY_BURN_MAX_PARAM,
        min: 0,
        max: 10_000_000,
        genesis: crate::native::burn_netting::DEFAULT_TREASURY_BURN_MAX_TNZO_EPOCH,
        tighten: Tighten::Neither,
        description: "Most TNZO the treasury burns in one epoch for burn debt past \
                      its cap, whole TNZO; never more than \
                      treasury.max_sale_tnzo_epoch. Debt past both caps is written \
                      off and recorded on the epoch's netting record.",
    },
    GovernedParam {
        key: "fees.min_settlement_fee_micro_usd",
        min: 0,
        max: 1_000_000,
        genesis: crate::native::economy::DEFAULT_MIN_SETTLEMENT_FEE_MICRO_USD,
        tighten: Tighten::Up,
        description: "The least fee one settlement pays, in micro-USD at the \
                      live rate, charged once per settlement and never above \
                      the value settled.",
    },
    GovernedParam {
        key: "settlement.escape_horizon_ms",
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::payment_settlement::plan::DEFAULT_ESCAPE_HORIZON_MS,
        tighten: Tighten::Neither,
        description: "Longest a settlement plan may stay undecided, and the \
                      least time a remote lock holds before its holder may \
                      reclaim it without a proven decision.",
    },
    GovernedParam {
        key: "settlement.griefing_premium_bps",
        min: 0,
        max: 10_000,
        genesis: crate::native::payment_settlement::plan::DEFAULT_GRIEFING_PREMIUM_BPS,
        tighten: Tighten::Up,
        description: "Least TNZO premium a settlement plan's Bitcoin leg \
                      escrows, in basis points of the plan's Tenzro value; \
                      paid by the split rule when the plan aborts with that \
                      leg funded and every other leg in but its preimage \
                      withheld.",
    },
    GovernedParam {
        key: "settlement.release_margin_ms",
        min: 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::native::payment_settlement::plan::DEFAULT_RELEASE_MARGIN_MS,
        tighten: Tighten::Neither,
        description: "How long past a settlement plan's deadline a remote \
                      lock or Bitcoin script must still hold its leg, so a \
                      proven decision can be relayed before the payer may \
                      reclaim. 24 hours at genesis.",
    },
    GovernedParam {
        key: "settlement.compensation_window_ms",
        min: 60 * 60 * 1000,
        // Below the role unbonding period, so an attestor's bond is still
        // there to slash when a window closes.
        max: 6 * 24 * 60 * 60 * 1000,
        genesis: crate::native::payment_settlement::plan::DEFAULT_COMPENSATION_WINDOW_MS,
        tighten: Tighten::Down,
        description: "How long after a settlement plan commits its bank, \
                      card or ISO 20022 legs may be confirmed or disputed \
                      before an unconfirmed leg's payee is compensated from \
                      the plan's reserve. 72 hours at genesis.",
    },
    GovernedParam {
        key: "settlement.attestor_slash_bps",
        min: 0,
        max: 10_000,
        genesis: crate::native::payment_settlement::plan::DEFAULT_ATTESTOR_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Share of a rail attestor's bond, in basis points, \
                      slashed into the insurance pool when a leg it \
                      attests is compensated. 10% at genesis.",
    },
    GovernedParam {
        key: "settlement.reconciliation_reward",
        min: 0,
        max: 10_000_000_000_000_000_000,
        genesis: crate::native::payment_settlement::recon::DEFAULT_RECON_REWARD,
        tighten: Tighten::Neither,
        description: "Reward, in wei, of the reconciliation task the chain \
                      opens each epoch for every route with a settlement \
                      lock, paid from the treasury to the first verified \
                      reconciliation of the route in the epoch. 0 opens no \
                      tasks. 1 TNZO at genesis.",
    },
    GovernedParam {
        key: "agent_bond.spend_bps",
        min: 0,
        max: 10_000,
        genesis: crate::native::economy::DEFAULT_AGENT_BOND_BPS,
        tighten: Tighten::Up,
        description: "A delegated agent's bond, in basis points of its spend \
                      ceiling.",
    },
    GovernedParam {
        key: "governance.agent_phase",
        min: 0,
        max: 2,
        genesis: 0,
        tighten: Tighten::Neither,
        description: "How far agents are trusted to originate proposals: \
                      0 none, 1 network only, 2 all. Advancing this is itself \
                      a governed decision.",
    },
    GovernedParam {
        key: "funding.requests_per_window",
        min: 1,
        max: 100_000,
        genesis: crate::funding::DEFAULT_REQUESTS_PER_WINDOW,
        tighten: Tighten::Down,
        description: "Most funding requests the network accepts per request \
                      window, network-wide. Requests are filed without a \
                      balance, so this bounds what they cost the treasury.",
    },
    GovernedParam {
        key: "funding.request_window_ms",
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::funding::DEFAULT_REQUEST_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "Length of the funding-request cap window, in milliseconds.",
    },
    GovernedParam {
        key: GOSSIP_WINDOW_MS_PARAM,
        min: 1_000,
        max: 600_000,
        genesis: 10_000,
        tighten: Tighten::Neither,
        description: "Window, in milliseconds, over which each gossip neighbour's \
                      message budgets are counted.",
    },
    GovernedParam {
        key: GOSSIP_CONSENSUS_MESSAGES_PARAM,
        min: 1_000,
        max: 10_000_000,
        genesis: 20_000,
        tighten: Tighten::Down,
        description: "Messages one gossip neighbour may deliver per window on the \
                      topics consensus and sync depend on: certificates, blocks, \
                      validator endpoints and peer status. Kept apart from \
                      transactions so user load never delays them. Messages over \
                      it are dropped without penalty.",
    },
    GovernedParam {
        key: GOSSIP_GENERAL_MESSAGES_PARAM,
        min: 100,
        max: 10_000_000,
        genesis: 50_000,
        tighten: Tighten::Down,
        description: "Messages one gossip neighbour may deliver per window on every \
                      other topic, transactions included. Messages over it are \
                      dropped without penalty; only invalid messages cost a \
                      neighbour its standing.",
    },
    GovernedParam {
        key: GOSSIP_BAN_SECONDS_PARAM,
        min: 10,
        max: 86_400,
        genesis: 300,
        tighten: Tighten::Up,
        description: "Seconds a gossip neighbour is refused after its invalid \
                      messages brought its score to the ban threshold.",
    },
    GovernedParam {
        key: HISTORY_RETENTION_PARAM,
        min: 10_000,
        max: u64::MAX,
        genesis: crate::governance::DEFAULT_HISTORY_RETENTION_BLOCKS,
        tighten: Tighten::Neither,
        description: "Recent blocks validators and RPC nodes keep locally. \
                      Older blocks are held by the committee's data-availability \
                      layer and fetched from it, verified against checkpoint \
                      certificates. The floor keeps every node able to serve \
                      the blocks peers catching up still import.",
    },
    GovernedParam {
        key: AUDIT_RETENTION_PARAM,
        min: AUDIT_RETENTION_FLOOR_SECS,
        max: u64::MAX,
        genesis: crate::governance::AUDIT_RETENTION_FLOOR_SECS,
        tighten: Tighten::Neither,
        description: "Seconds an agent's recorder keeps its audit entries, \
                      with their proofs, after the session closed. \
                      Independent of block-history retention; the floor is six \
                      months.",
    },
    GovernedParam {
        key: "fees.state_growth_target_per_block",
        min: 1,
        max: u64::MAX,
        genesis: crate::ledger::DEFAULT_RESOURCE_TARGET_PER_BLOCK,
        tighten: Tighten::Neither,
        description: "Gas worth of new state entries a block targets. Above it the \
                      state-growth base fee rises, below it falls, independently of \
                      compute.",
    },
    GovernedParam {
        key: "fees.bandwidth_target_per_block",
        min: 1,
        max: u64::MAX,
        genesis: crate::ledger::DEFAULT_RESOURCE_TARGET_PER_BLOCK,
        tighten: Tighten::Neither,
        description: "Gas worth of transaction bytes a block targets; the \
                      bandwidth base fee follows its own use against it.",
    },
    GovernedParam {
        key: "fees.proof_target_per_block",
        min: 1,
        max: u64::MAX,
        genesis: crate::ledger::DEFAULT_RESOURCE_TARGET_PER_BLOCK,
        tighten: Tighten::Neither,
        description: "Gas of proof verification a block targets; the proof base \
                      fee follows its own use against it.",
    },
    GovernedParam {
        key: crate::native::da_retention::DA_HISTORY_RETENTION_PARAM,
        min: AUDIT_RETENTION_FLOOR_SECS,
        max: u64::MAX,
        genesis: crate::native::da_retention::DEFAULT_DA_HISTORY_RETENTION_SECS,
        tighten: Tighten::Neither,
        description: "Seconds a history segment stays in the data-availability \
                      layer after it was recorded. Block execution expires it \
                      after that and committee members drop its slivers. Audit \
                      objects follow storage.audit_retention_seconds.",
    },
    GovernedParam {
        key: crate::native::inference_fault::SAMPLE_BPS_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::native::inference_fault::DEFAULT_SAMPLE_BPS,
        tighten: Tighten::Up,
        description: "Least share (bps) of optimistic-level answers a requester's \
                      node re-executes on another provider serving the same model; \
                      never zero.",
    },
    GovernedParam {
        key: crate::native::inference_fault::SAMPLE_ESCROW_STEP_GWEI_PARAM,
        min: 1,
        max: u64::MAX,
        genesis: crate::native::inference_fault::DEFAULT_SAMPLE_ESCROW_STEP_GWEI,
        tighten: Tighten::Down,
        description: "Payment, gwei, for each multiple of which an optimistic \
                      answer's re-execution share rises by the sample step.",
    },
    GovernedParam {
        key: crate::native::inference_fault::SAMPLE_STEP_BPS_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::inference_fault::DEFAULT_SAMPLE_STEP_BPS,
        tighten: Tighten::Up,
        description: "Bps added to an optimistic answer's re-execution share for \
                      each sample escrow step its payment holds.",
    },
    GovernedParam {
        key: crate::native::training_proof::WINDOW_MS_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::native::training_proof::DEFAULT_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "Challenge window (ms) of a committed training round: anyone may \
                      challenge it this long after its receipt was committed.",
    },
    GovernedParam {
        key: crate::native::training_proof::TEE_WINDOW_MS_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::native::training_proof::DEFAULT_TEE_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "Challenge window (ms) of a training round whose receipt carries an \
                      accepted TEE attestation.",
    },
    GovernedParam {
        key: crate::native::training_proof::DECIDE_WINDOW_MS_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::native::training_proof::DEFAULT_DECIDE_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "How long (ms) validators have to decide a training challenge after \
                      it was filed; undecided, it expires.",
    },
    GovernedParam {
        key: crate::native::training_proof::CHALLENGE_BOND_GWEI_PARAM,
        min: 1,
        max: u64::MAX,
        genesis: crate::native::training_proof::DEFAULT_CHALLENGE_BOND_GWEI,
        tighten: Tighten::Up,
        description: "Bond (gwei of TNZO) a challenger posts against a training round.",
    },
    GovernedParam {
        key: crate::native::training_proof::CHALLENGE_FEE_BPS_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::training_proof::DEFAULT_CHALLENGE_FEE_BPS,
        tighten: Tighten::Up,
        description: "Share (bps) of a training challenge bond kept as the fee, paid to the \
                      insurance pool whatever the outcome.",
    },
    GovernedParam {
        key: crate::native::training_proof::CHALLENGER_REWARD_GWEI_PARAM,
        min: 0,
        max: u64::MAX,
        genesis: crate::native::training_proof::DEFAULT_CHALLENGER_REWARD_GWEI,
        tighten: Tighten::Neither,
        description: "Reward (gwei of TNZO) an upheld training challenge pays its \
                      challenger out of the trainer's compute bond.",
    },
    GovernedParam {
        key: crate::native::training_proof::PENALTY_GWEI_PARAM,
        min: 0,
        max: u64::MAX,
        genesis: crate::native::training_proof::DEFAULT_PENALTY_GWEI,
        tighten: Tighten::Up,
        description: "Penalty (gwei of TNZO) a trainer's compute bond pays to the \
                      insurance pool for an upheld training challenge.",
    },
    GovernedParam {
        key: crate::native::training_proof::SAMPLE_STEPS_PARAM,
        min: 2,
        max: 4_096,
        genesis: crate::native::training_proof::DEFAULT_SAMPLE_STEPS,
        tighten: Tighten::Neither,
        description: "Steps a verifier replays for one training challenge; the first and \
                      the last step are always among them.",
    },
    GovernedParam {
        key: crate::native::training_proof::TOLERANCE_PPM_PARAM,
        min: 0,
        max: 1_000_000,
        genesis: crate::native::training_proof::DEFAULT_TOLERANCE_PPM,
        tighten: Tighten::Neither,
        description: "Largest distance (ppm) between a replayed and a claimed training \
                      state that still counts as reproduced; 0 for bit-exact kernels.",
    },
    GovernedParam {
        key: crate::native::training_proof::MAX_CHALLENGES_PARAM,
        min: 1,
        max: 64,
        genesis: crate::native::training_proof::DEFAULT_MAX_CHALLENGES,
        tighten: Tighten::Neither,
        description: "Most challenges one training round may carry.",
    },
    GovernedParam {
        key: crate::native::inference_fault::WINDOW_MS_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::native::inference_fault::DEFAULT_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "Challenge window (ms): a fault must be filed this soon \
                      after the receipt was signed, and decided this soon after \
                      it was filed.",
    },
    GovernedParam {
        key: crate::native::inference_fault::PENALTY_FLOOR_PARAM,
        min: 0,
        max: 1_000_000_000_000,
        genesis: crate::native::inference_fault::DEFAULT_PENALTY_FLOOR_MICRO_USD,
        tighten: Tighten::Up,
        description: "Least penalty (micro-USD, paid in TNZO at the rate in \
                      force) a provider's bond pays to the insurance pool for \
                      an upheld inference fault, on top of the refund.",
    },
    GovernedParam {
        key: crate::native::inference_fault::PENALTY_PAYMENT_PARAM,
        min: 10_000,
        max: 100_000_000,
        genesis: crate::native::inference_fault::DEFAULT_PENALTY_PAYMENT_BPS,
        tighten: Tighten::Up,
        description: "Penalty a provider's bond pays to the insurance pool for \
                      an upheld inference fault, in basis points of what the \
                      requester paid, when above the floor. Held at or above \
                      10^8 / inference.optimistic.sample_bps, so the expected \
                      penalty of a substituted answer is at least what it was \
                      paid.",
    },
    GovernedParam {
        key: crate::native::inference_fault::MAX_REFUND_GWEI_PARAM,
        min: 0,
        max: u64::MAX,
        genesis: crate::native::inference_fault::DEFAULT_MAX_REFUND_GWEI,
        tighten: Tighten::Neither,
        description: "Largest refund (gwei of TNZO) one inference fault may \
                      claim.",
    },
    GovernedParam {
        key: crate::native::inference_fault::RECEIPT_SURCHARGE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::inference_fault::DEFAULT_RECEIPT_SURCHARGE_BPS,
        tighten: Tighten::Up,
        description: "Surcharge (bps of the base price) for an answer at the \
                      receipt verification level.",
    },
    GovernedParam {
        key: crate::native::inference_fault::OPTIMISTIC_SURCHARGE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::inference_fault::DEFAULT_OPTIMISTIC_SURCHARGE_BPS,
        tighten: Tighten::Up,
        description: "Surcharge (bps of the base price) for an answer at the \
                      optimistic verification level, which pays for sampled \
                      re-execution.",
    },
    GovernedParam {
        key: crate::native::inference_fault::TEE_SURCHARGE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::inference_fault::DEFAULT_TEE_SURCHARGE_BPS,
        tighten: Tighten::Up,
        description: "Surcharge (bps of the base price) for an answer at the \
                      TEE verification level.",
    },
    GovernedParam {
        key: "fees.insurance_pool_bps",
        min: 0,
        max: 10_000,
        genesis: crate::native::insurance::DEFAULT_POOL_FEE_SHARE_BPS,
        tighten: Tighten::Up,
        description: "Share of the fee revenue bound for the treasury (block fees \
                      and settlement fees) credited to the insurance pool instead.",
    },
    GovernedParam {
        key: "insurance.max_claim_bps",
        min: 1,
        max: 10_000,
        genesis: crate::native::insurance::DEFAULT_MAX_CLAIM_BPS,
        tighten: Tighten::Neither,
        description: "Most of the insurance pool one claim may take.",
    },
    GovernedParam {
        key: "insurance.max_claim_tnzo",
        min: 1,
        max: 1_000_000_000,
        genesis: crate::native::insurance::DEFAULT_MAX_CLAIM_TNZO,
        tighten: Tighten::Neither,
        description: "Most one insurance claim may take, in whole TNZO.",
    },
    GovernedParam {
        key: "agent.remote_grant_ttl_ms",
        min: 10_000,
        max: 86_400_000,
        genesis: tenzro_types::agent_terms::DEFAULT_REMOTE_GRANT_TTL_MS,
        tighten: Tighten::Neither,
        description: "Lifetime of an agent's grant on another chain when its \
                      terms set none. It bounds how long a revoked agent can \
                      still act there.",
    },
    GovernedParam {
        key: crate::native::agent_terms::PARAM_MAX_UNRENEWED_MS,
        min: 86_400_000,
        max: 34_560_000_000,
        genesis: crate::native::agent_terms::DEFAULT_MAX_UNRENEWED_MS,
        tighten: Tighten::Down,
        description: "How long (ms) a delegated agent may act after its root \
                      last approved its terms in full. A scope change within \
                      pre-approved bounds does not renew; a lapsed agent acts \
                      again once its root re-approves its terms.",
    },
    GovernedParam {
        key: "agent.remote_grant_budget_divisor",
        min: 1,
        max: 1_440,
        genesis: crate::native::remote_grant::DEFAULT_BUDGET_DIVISOR,
        tighten: Tighten::Neither,
        description: "A grant on another chain holds at most the asset's daily \
                      limit over this.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.eip155",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on an EVM chain holds, micro-TNZO.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.solana",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on Solana holds, micro-TNZO.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.sui",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on Sui holds, micro-TNZO.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.aptos",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on Aptos holds, micro-TNZO.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.stellar",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on Stellar holds, micro-TNZO.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.cosmos",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on a Cosmos chain holds, micro-TNZO.",
    },
    GovernedParam {
        key: "agent.relay_deposit_utnzo.tvm",
        min: 0,
        max: 1_000_000_000,
        genesis: crate::native::remote_grant::DEFAULT_RELAY_DEPOSIT_UTNZO,
        tighten: Tighten::Up,
        description: "Relay deposit a grant on TON holds, micro-TNZO.",
    },
    GovernedParam {
        key: crate::native::token::POLICY_TIMELOCK_FLOOR_PARAM,
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::token::DEFAULT_POLICY_TIMELOCK_FLOOR_MS,
        tighten: Tighten::Neither,
        description: "Shortest timelock a token's issuer may set on its eligibility \
                      policy and attestor-set changes; holders move under the policy \
                      in force until a queued change executes.",
    },
    GovernedParam {
        key: GUARDIAN_THRESHOLD_PARAM,
        min: 1,
        max: 15,
        genesis: crate::governance::DEFAULT_GUARDIAN_THRESHOLD,
        tighten: Tighten::Neither,
        description: "Distinct seated guardians of a role whose signals it takes to \
                      veto a proposal or to pause or resume enactment.",
    },
    GovernedParam {
        key: MAX_PAUSE_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_MAX_PAUSE_MS,
        tighten: Tighten::Neither,
        description: "Longest a guardian pause holds enactment before it lifts by itself.",
    },
    GovernedParam {
        key: PAUSE_COOLOFF_PARAM,
        min: 0,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_PAUSE_COOLOFF_MS,
        tighten: Tighten::Neither,
        description: "Time after a pause ends before guardians may pause again.",
    },
    GovernedParam {
        key: FEATURE_PAUSE_MAX_PARAM,
        min: 1,
        max: 720,
        genesis: DEFAULT_FEATURE_PAUSE_MAX_EPOCHS,
        tighten: Tighten::Neither,
        description: "Longest a guardian pause of one feature (a status lever) holds before \
                      it lifts by itself. Guardians stop a running feature and nothing else.",
    },
    GovernedParam {
        key: FEATURE_PAUSE_COOLOFF_PARAM,
        min: 0,
        max: 4_380,
        genesis: DEFAULT_FEATURE_PAUSE_COOLOFF_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs after a guardian pause of one feature lifts before guardians \
                      may pause the same feature again.",
    },
    GovernedParam {
        key: GUARDIAN_MAX_TERM_PARAM,
        min: 24 * 60 * 60 * 1000,
        max: 2 * 365 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_GUARDIAN_MAX_TERM_MS,
        tighten: Tighten::Neither,
        description: "Longest term a guardian seat may be granted for.",
    },
    GovernedParam {
        key: AGENT_WEIGHT_MAX_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::governance::DEFAULT_AGENT_WEIGHT_MAX_BPS,
        tighten: Tighten::Neither,
        description: "Most of the eligible stake one agent-cast ballot may weigh; the rest \
                      of the validator's weight abstains.",
    },
    GovernedParam {
        key: STEWARD_SUNSET_PARAM,
        min: 0,
        max: 4_102_444_800_000,
        genesis: crate::governance::DEFAULT_STEWARD_SUNSET_MS,
        tighten: Tighten::Neither,
        description: "Block time after which Foundation steward seats hold no power; \
                      governance may only move it earlier.",
    },
    GovernedParam {
        key: STEWARD_MAX_SEATS_PARAM,
        min: 0,
        max: 15,
        genesis: crate::governance::DEFAULT_STEWARD_MAX_SEATS,
        tighten: Tighten::Neither,
        description: "Most live Foundation steward seats; governance may only lower it.",
    },
    GovernedParam {
        key: GUARDIAN_SIGNAL_WINDOW_PARAM,
        min: 60_000,
        max: 7 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_GUARDIAN_SIGNAL_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "How long a guardian's pause or resume signal counts toward the threshold.",
    },
    GovernedParam {
        key: crate::tx_validity::MAX_VALIDITY_PARAM,
        min: 1_000,
        max: 7 * 24 * 60 * 60 * 1000,
        genesis: crate::tx_validity::DEFAULT_MAX_VALIDITY_MS,
        tighten: Tighten::Down,
        description: "Longest window a signed transaction's valid_until may reach \
                      past the block time it executes at.",
    },
    GovernedParam {
        key: crate::tx_validity::PRIVILEGED_MAX_VALIDITY_PARAM,
        min: 1_000,
        max: 24 * 60 * 60 * 1000,
        genesis: crate::tx_validity::DEFAULT_PRIVILEGED_MAX_VALIDITY_MS,
        tighten: Tighten::Down,
        description: "Longest validity window for a privileged transaction (governance, \
                      guardian, issuer, agent Terms and kill-switch actions).",
    },
    GovernedParam {
        key: crate::delegation_guard::MAX_AUTHORIZATIONS_PARAM,
        min: 1,
        max: 256,
        genesis: crate::delegation_guard::DEFAULT_MAX_AUTHORIZATIONS,
        tighten: Tighten::Down,
        description: "Most EIP-7702 authorizations one set-code transaction may carry. \
                      A run of them over consecutive nonces is how a stolen key sweeps \
                      accounts.",
    },
    GovernedParam {
        key: crate::delegation_guard::UNIVERSAL_ALLOWED_PARAM,
        min: 0,
        max: 1,
        genesis: crate::delegation_guard::DEFAULT_UNIVERSAL_ALLOWED,
        tighten: Tighten::Down,
        description: "Whether an EIP-7702 authorization signed for every chain (chain id \
                      zero) is admitted. One signature then holds on each chain that \
                      admits it.",
    },
    GovernedParam {
        key: crate::delegation_guard::MULTI_SIGNER_ENTRIES_PARAM,
        min: 0,
        max: 1,
        genesis: crate::delegation_guard::DEFAULT_MULTI_SIGNER_ENTRIES,
        tighten: Tighten::Down,
        description: "Whether one signer may appear more than once in an EIP-7702 \
                      authorization list. Entries over consecutive nonces for one \
                      account are how a stolen key sweeps it.",
    },
    GovernedParam {
        key: crate::delegation_guard::FOREIGN_CHAIN_PARAM,
        min: 0,
        max: 1,
        genesis: crate::delegation_guard::DEFAULT_FOREIGN_CHAIN,
        tighten: Tighten::Down,
        description: "Whether an EIP-7702 authorization signed for another chain id is \
                      admitted in a transaction here (the EVM then skips it).",
    },
    GovernedParam {
        key: crate::delegation_guard::CHANGES_PER_WINDOW_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::delegation_guard::DEFAULT_CHANGES_PER_WINDOW,
        tighten: Tighten::Down,
        description: "Most delegation changes (EIP-7702) one account may make in the \
                      rolling window, across transactions. Slows a thief who lands one \
                      authorization per transaction.",
    },
    GovernedParam {
        key: crate::delegation_guard::WINDOW_MS_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::delegation_guard::DEFAULT_WINDOW_MS,
        tighten: Tighten::Up,
        description: "Rolling window, ms, over which delegation changes per account are \
                      counted against the ceiling.",
    },
    GovernedParam {
        key: crate::delegation_guard::ALLOWLIST_ENFORCED_PARAM,
        min: 0,
        max: 1,
        genesis: crate::delegation_guard::DEFAULT_ALLOWLIST_ENFORCED,
        tighten: Tighten::Up,
        description: "Whether an EIP-7702 authorization may only name a delegate whose \
                      code hash governance listed (SetDelegateCode). The zero address, \
                      which clears a delegation, is always admitted.",
    },
    GovernedParam {
        key: crate::account_outflow::MIN_HOLD_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::account_outflow::DEFAULT_MIN_HOLD_MS,
        tighten: Tighten::Up,
        description: "Shortest hold, ms, an account may set on its own outflow policy: \
                      the time its owner or guardian has to cancel a queued release or a \
                      queued loosening.",
    },
    GovernedParam {
        key: crate::account_outflow::MIN_WINDOW_PARAM,
        min: 60_000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::account_outflow::DEFAULT_MIN_WINDOW_MS,
        tighten: Tighten::Up,
        description: "Shortest window, ms, an account may count its outflow cap over.",
    },
    GovernedParam {
        key: crate::account_outflow::MAX_RELEASES_PARAM,
        min: 1,
        max: 1024,
        genesis: crate::account_outflow::DEFAULT_MAX_RELEASES,
        tighten: Tighten::Down,
        description: "Most queued releases one account may have open at once.",
    },
    GovernedParam {
        key: crate::native::bridge_watcher::PAUSE_MS_PARAM,
        min: 600000,
        max: 259200000,
        genesis: crate::native::bridge_watcher::DEFAULT_PAUSE_MS,
        tighten: Tighten::Up,
        description: "How long, ms, the pause a bonded watcher puts on a bridge route holds before it lifts by itself.",
    },
    GovernedParam {
        key: crate::native::bridge_watcher::COOLOFF_MS_PARAM,
        min: 3600000,
        max: 2592000000,
        genesis: crate::native::bridge_watcher::DEFAULT_COOLOFF_MS,
        tighten: Tighten::Up,
        description: "How long, ms, after a watcher pause ended before a watcher may pause the same route again.",
    },
    GovernedParam {
        key: crate::native::bridge_watcher::REVIEW_MS_PARAM,
        min: 3600000,
        max: 1209600000,
        genesis: crate::native::bridge_watcher::DEFAULT_REVIEW_MS,
        tighten: Tighten::Up,
        description: "How long, ms, after a watcher pause ended validators and governance have to confirm it before it is judged.",
    },
    GovernedParam {
        key: crate::native::bridge_watcher::SLASH_BPS_PARAM,
        min: 1,
        max: 10000,
        genesis: crate::native::bridge_watcher::DEFAULT_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Share, basis points, of everything a watcher has at stake that an unconfirmed pause costs it.",
    },
    GovernedParam {
        key: crate::native::bridge_watcher::MIN_STAKE_PARAM,
        min: 1,
        max: 10000000000,
        genesis: crate::native::bridge_watcher::DEFAULT_MIN_STAKE_TNZO,
        tighten: Tighten::Up,
        description: "Least bonded stake, whole TNZO, an account holds to pause a bridge route as a watcher.",
    },
    GovernedParam {
        key: crate::native::bridge_watcher::MIN_BOND_AGE_PARAM,
        min: 3600000,
        max: 2592000000,
        genesis: crate::native::bridge_watcher::DEFAULT_MIN_BOND_AGE_MS,
        tighten: Tighten::Up,
        description: "How long, ms, a bond must have been held to count for a watcher.",
    },
    GovernedParam {
        key: "payments.attested_enabled",
        min: 0,
        max: 1,
        genesis: crate::native::payment_settlement::DEFAULT_ATTESTED_ENABLED,
        tighten: Tighten::Neither,
        description: "Whether payments attested on rails outside any chain are \
                      recorded. They are labelled attested and never count as proven.",
    },
    GovernedParam {
        key: "payments.attested_cap_usd_e6",
        min: 1_000_000,
        max: 1_000_000_000_000,
        genesis: crate::native::payment_settlement::DEFAULT_ATTESTED_CAP_USD_E6,
        tighten: Tighten::Neither,
        description: "Most one attested payment may be worth, USD micro-units.",
    },
    GovernedParam {
        key: "payments.voucher_freshness_ms",
        min: 1_000,
        max: 600_000,
        genesis: crate::native::payment_settlement::DEFAULT_VOUCHER_FRESHNESS_MS,
        tighten: Tighten::Down,
        description: "How far ahead of block time a serving node may date an \
                      agent's voucher. Zero would refuse every voucher signed \
                      on a clock slightly ahead of the chain.",
    },
    GovernedParam {
        key: VETO_SIGNAL_BPS_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::governance::DEFAULT_VETO_SIGNAL_BPS,
        tighten: Tighten::Neither,
        description: "Share of TNZO supply, in basis points, locked in a proposal's veto \
                      escrow before its timelock starts to stretch.",
    },
    GovernedParam {
        key: VETO_BLOCK_BPS_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::governance::DEFAULT_VETO_BLOCK_BPS,
        tighten: Tighten::Neither,
        description: "Share of TNZO supply, in basis points, locked in a proposal's veto \
                      escrow that contests it: it is voted again on the Ratify track.",
    },
    GovernedParam {
        key: VETO_MAX_EXTENSION_PARAM,
        min: 0,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_VETO_MAX_EXTENSION_MS,
        tighten: Tighten::Neither,
        description: "Most the holders' veto escrow may stretch a timelock, reached at \
                      the blocking share.",
    },
    GovernedParam {
        key: CONCERN_QUORUM_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: crate::governance::DEFAULT_CONCERN_QUORUM,
        tighten: Tighten::Neither,
        description: "Distinct aged human roots whose concerns, once exceeded, double a \
                      queued proposal's timelock (once only).",
    },
    GovernedParam {
        key: ROOT_MIN_AGE_PARAM,
        min: 0,
        max: 365 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_ROOT_MIN_AGE_MS,
        tighten: Tighten::Neither,
        description: "How long before a proposal opened a human root must have been \
                      registered for its concern to count.",
    },
    GovernedParam {
        key: UPGRADE_READINESS_BPS_PARAM,
        min: 5_001,
        max: 10_000,
        genesis: crate::governance::DEFAULT_UPGRADE_READINESS_BPS,
        tighten: Tighten::Neither,
        description: "Share of bonded validator stake, in basis points, whose machines must \
                      have quoted the new binary before a protocol upgrade enacts.",
    },
    GovernedParam {
        key: UPGRADE_ACTIVATION_DELAY_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: crate::governance::DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS,
        tighten: Tighten::Neither,
        description: "Blocks between an upgrade's enactment and the height from which every \
                      node runs the new binary.",
    },
    GovernedParam {
        key: SECURITY_REVEAL_WINDOW_PARAM,
        min: 24 * 60 * 60 * 1000,
        max: 180 * 24 * 60 * 60 * 1000,
        genesis: crate::governance::DEFAULT_SECURITY_REVEAL_WINDOW_MS,
        tighten: Tighten::Neither,
        description: "How long after a security fix enacts its proposer has to reveal the \
                      vulnerability it committed to.",
    },
    GovernedParam {
        key: SECURITY_REVEAL_SLASH_BPS_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::governance::DEFAULT_SECURITY_REVEAL_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Share of a proposer's stake, in basis points, slashed when a security \
                      fix's vulnerability is not revealed in time.",
    },
    GovernedParam {
        key: GUARD_LOOSENING_GRACE_PARAM,
        min: 24,
        max: 8_760,
        genesis: DEFAULT_GUARD_LOOSENING_GRACE_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs a change that loosens a capture guard waits after \
                      the next epoch boundary before it applies: a treasury guard \
                      (an outflow cap or period, the large-spend size, approval \
                      or timelock, a running-cost reserve limit, an insurance \
                      claim cap, the bond age, the raise bound or this grace), \
                      the vote's quorum and thresholds, pool release and validator \
                      pay, slashing and unbonding, and the fee rate's move cap \
                      and quorum.",
    },
    GovernedParam {
        key: TIGHTENING_GRACE_PARAM,
        min: 0,
        max: 2_160,
        genesis: DEFAULT_TIGHTENING_GRACE_EPOCHS,
        tighten: Tighten::Down,
        description: "Epochs a tightening parameter change (a higher bond, \
                      slash or fee, or a shorter window) waits after the next \
                      epoch boundary before it applies. At most 90 days.",
    },
    GovernedParam {
        key: crate::native::role_stake::UNBONDING_MS_PARAM,
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::role_stake::DEFAULT_UNBONDING_MS,
        tighten: Tighten::Up,
        description: "Milliseconds a role stake stays slashable after its \
                      operator asks to withdraw it.",
    },
    GovernedParam {
        key: crate::native::SLA_UNAVAILABLE_PENALTY_GWEI_PARAM,
        min: 0,
        max: u64::MAX,
        genesis: crate::native::DEFAULT_SLA_UNAVAILABLE_PENALTY_GWEI,
        tighten: Tighten::Up,
        description: "Gwei slashed from a serving role's stake for one frozen \
                      unavailable SLA verdict.",
    },
    GovernedParam {
        key: crate::native::payment_settlement::netting::NETTING_EPOCH_PARAM,
        min: 60 * 1000,
        max: 7 * 24 * 60 * 60 * 1000,
        genesis: crate::native::payment_settlement::netting::DEFAULT_NETTING_EPOCH_MS,
        tighten: Tighten::Neither,
        description: "Milliseconds between payment netting rounds.",
    },
    GovernedParam {
        key: crate::ledger::COMPUTE_TARGET_PARAM,
        min: 1_000_000,
        max: 1_000_000_000,
        genesis: 15_000_000,
        tighten: Tighten::Neither,
        description: "Compute gas a block targets. The base fee rises when \
                      blocks use more and falls when they use less.",
    },
    GovernedParam {
        key: crate::ledger::BASE_FEE_CHANGE_DENOMINATOR_PARAM,
        min: 2,
        max: 1_024,
        genesis: 8,
        tighten: Tighten::Neither,
        description: "The base fee moves at most 1/this per block (8: 12.5%).",
    },
    GovernedParam {
        key: crate::ledger::MIN_BASE_FEE_PARAM,
        min: 1,
        max: 1_000_000_000_000,
        genesis: 100_000_000,
        tighten: Tighten::Up,
        description: "Lowest base fee, atto-USD per unit of gas or resource.",
    },
    GovernedParam {
        key: crate::ledger::MAX_BASE_FEE_PARAM,
        min: 1_000_000_000,
        max: u64::MAX,
        genesis: 1_000_000_000_000,
        tighten: Tighten::Neither,
        description: "Highest base fee, atto-USD per unit of gas or resource. \
                      Read as the floor if set below it.",
    },
    GovernedParam {
        key: crate::native::staking::SIGNATURE_SCHEMES_PARAM,
        min: 1,
        max: (1 << tenzro_types::signature_scheme::SignatureScheme::ALL.len()) - 1,
        genesis: crate::native::staking::DEFAULT_SIGNATURE_SCHEMES,
        tighten: Tighten::Neither,
        description: "Signature schemes a validator may register its consensus key \
                      under, one bit per scheme id: 1 is ML-DSA-65 with P-256, 2 is \
                      ML-DSA-87 with P-256. Keys already registered are unaffected.",
    },
    GovernedParam {
        key: crate::native::validator_machine::MACHINE_IDENTITY_STATUS,
        min: LeverStatus::Enabled as u64,
        max: LeverStatus::Retired as u64,
        genesis: LeverStatus::Paused as u64,
        tighten: Tighten::Neither,
        description: "Whether a validator may name its machine identity on chain, so \
                      peers hold its endpoint records to the machine's ML-DSA key: 0 \
                      enabled, 1 paused, 2 retired. Paused until the network runs a \
                      build that reads the registration.",
    },
    GovernedParam {
        key: crate::native::beacon::COMMIT_REVEAL_STATUS,
        min: LeverStatus::Enabled as u64,
        max: LeverStatus::Retired as u64,
        genesis: LeverStatus::Paused as u64,
        tighten: Tighten::Neither,
        description: "Whether beacon contributions commit to a secret and reveal the \
                      last one, which the mix takes beside the VRF output: 0 enabled, 1 \
                      paused, 2 retired. Paused until the network runs a build that \
                      reads them.",
    },
    GovernedParam {
        key: HYBRID_RECORDS_FROM_PARAM,
        min: 0,
        max: u64::MAX,
        genesis: u64::MAX,
        tighten: Tighten::Neither,
        description: "Milliseconds since the Unix epoch from which stored records \
                      (receipts, billing, SLA answers, availability attestations) must \
                      carry hybrid Ed25519 / ML-DSA-65 session signatures. The highest \
                      value means never.",
    },
    GovernedParam {
        key: PQ_LEG_REQUIRED_FROM_PARAM,
        min: 0,
        max: u64::MAX,
        genesis: u64::MAX,
        tighten: Tighten::Neither,
        description: "Milliseconds since the Unix epoch from which a machine identity \
                      key must carry a native ML-DSA-65 leg: a node without one then \
                      refuses to start and a batch root signed from then on needs both \
                      legs. Before it, classical-only roots are accepted. The highest \
                      value means never; a network whose validators hold ML-DSA-capable \
                      hardware sets it to zero in its genesis.",
    },
    GovernedParam {
        key: MAX_RECORD_AGE_PARAM,
        min: 60_000,
        max: 30 * 24 * 3_600_000,
        genesis: 3_600_000,
        tighten: Tighten::Neither,
        description: "Milliseconds before a block within which the date of a signed \
                      record and the date of the batch root that signs it must fall. \
                      The signing node supplies those dates, so consensus bounds them \
                      against block time; together with the ML-DSA requirement being \
                      judged at block time, a classical-only signer cannot backdate a \
                      record to before the moment the requirement starts.",
    },
    GovernedParam {
        key: crate::account_keys::PQ_LEG_ON_ENROLMENT_STATUS,
        min: LeverStatus::Enabled as u64,
        max: LeverStatus::Retired as u64,
        genesis: LeverStatus::Paused as u64,
        tighten: Tighten::Neither,
        description: "Whether an account that enrolls an ML-DSA-65 key requires from \
                      then on the ML-DSA-65 leg of every key acting for it (its own \
                      key, linked passkeys, recovery signers), as if it sent the \
                      require-leg operation: 0 enabled, 1 paused, 2 retired. Paused \
                      until the network runs a build that reads it.",
    },
    GovernedParam {
        key: crate::native::staking::UNBONDING_PARAM,
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::staking::DEFAULT_VALIDATOR_UNBONDING_MS,
        tighten: Tighten::Up,
        description: "Milliseconds an exiting validator's bond stays slashable in \
                      the staking vault before it can be withdrawn.",
    },
    GovernedParam {
        key: crate::native::staking::EXIT_CHURN_PARAM,
        min: 100,
        max: 2_000,
        genesis: tenzro_token::validator_registry::DEFAULT_EXIT_CHURN_BPS as u64,
        tighten: Tighten::Neither,
        description: "Share of the active validator set's self-stake that may finish \
                      exiting in one epoch, bps. Exits complete in address order while \
                      their stake fits; at least one completes every epoch.",
    },
    GovernedParam {
        key: crate::native::staking::INACTIVITY_LIMIT_PARAM,
        min: 0,
        max: 10_000_000,
        genesis: tenzro_token::validator_registry::DEFAULT_INACTIVITY_LIMIT_EPOCHS,
        tighten: Tighten::Neither,
        description: "Consecutive epochs in which a validator signs nothing the \
                      chain certifies before it is moved to exit, so a validator that \
                      is gone cannot hold the quorum above what the live set reaches. \
                      0 turns ejection off.",
    },
    GovernedParam {
        key: crate::native::staking::JAIL_TERM_PARAM,
        min: 24,
        max: 8_766,
        genesis: tenzro_token::validator_registry::DEFAULT_JAIL_TERM_EPOCHS,
        tighten: Tighten::Up,
        description: "Epochs a validator slashed for misbehaviour stays jailed before it \
                      returns as a candidate. Jail is never permanent: it ends at the term, \
                      or sooner when a reinstatement proposal passes. A longer term waits \
                      out the tightening grace window.",
    },
    GovernedParam {
        key: crate::native::staking::INACTIVITY_ACTIVATION_PARAM,
        min: 0,
        max: 1 << 62,
        genesis: 0,
        tighten: Tighten::Neither,
        description: "First epoch whose validators' participation counts toward \
                      inactivity ejection. A running chain sets it to an epoch every \
                      node has reached the build that keeps the count; a new chain \
                      starts at 0.",
    },
    GovernedParam {
        key: crate::native::staking::ACTIVE_FLOOR_PARAM,
        min: tenzro_types::launch_rule::MIN_LAUNCH_VALIDATORS as u64,
        max: 10_000,
        genesis: tenzro_token::validator_registry::DEFAULT_ACTIVE_SET_FLOOR,
        tighten: Tighten::Neither,
        description: "Fewest validators the active set keeps: an ejection for \
                      inactivity never takes it below this.",
    },
    GovernedParam {
        key: crate::native::staking::CORRELATION_WINDOW_PARAM,
        min: 1,
        max: 100_000,
        genesis: crate::native::staking::DEFAULT_CORRELATION_WINDOW_CHECKPOINTS,
        tighten: Tighten::Up,
        description: "Equivocations within this many checkpoints of each other are \
                      correlated: each offender's penalty scales with the stake of \
                      all offenders in the window.",
    },
    GovernedParam {
        key: crate::native::staking::EQUIVOCATION_MIN_SLASH_PARAM,
        min: 1,
        max: 10_000,
        genesis: crate::native::staking::DEFAULT_EQUIVOCATION_MIN_SLASH_BPS,
        tighten: Tighten::Up,
        description: "Least an equivocation costs, bps of the offender's stake.",
    },
    GovernedParam {
        key: crate::native::staking::CORRELATION_MULTIPLIER_PARAM,
        min: 1,
        max: 100,
        genesis: crate::native::staking::DEFAULT_CORRELATION_MULTIPLIER,
        tighten: Tighten::Up,
        description: "How steeply an equivocation's penalty grows with the share of \
                      stake that equivocated together, and the multiple of the floor \
                      a repeat offender pays.",
    },
    GovernedParam {
        key: crate::native::COMPUTE_BOND_MIN_PARAM,
        min: 1,
        max: 10_000_000,
        genesis: crate::native::DEFAULT_COMPUTE_BOND_MIN_TNZO,
        tighten: Tighten::Up,
        description: "Least compute bond a provider posts to be probed and routed to, \
                      whole TNZO.",
    },
    GovernedParam {
        key: crate::native::COMPUTE_BOND_COOLDOWN_PARAM,
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::DEFAULT_COMPUTE_BOND_COOLDOWN_MS,
        tighten: Tighten::Up,
        description: "Milliseconds between starting a compute-bond withdrawal and \
                      finalizing it; the bond stays slashable meanwhile.",
    },
    GovernedParam {
        key: crate::native::AGENT_BOND_COOLDOWN_PARAM,
        min: 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: crate::native::DEFAULT_AGENT_BOND_COOLDOWN_MS,
        tighten: Tighten::Up,
        description: "Milliseconds between starting an agent-bond withdrawal and \
                      finalizing it; the bond stays slashable meanwhile.",
    },
    GovernedParam {
        key: crate::native::BOND_MIN_RESIDUAL_PARAM,
        min: 0,
        max: 1_000_000,
        genesis: crate::native::DEFAULT_BOND_MIN_RESIDUAL_TNZO,
        tighten: Tighten::Up,
        description: "Whole TNZO below which a slashed bond is drained entirely and \
                      marked slashed.",
    },
    GovernedParam {
        key: VOTING_PERIOD_PARAM,
        min: 24 * 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: VOTING_PERIOD_MS as u64,
        tighten: Tighten::Neither,
        description: "Voting window on the standard and Ratify tracks, ms. A \
                      proposal keeps the rules it opened under.",
    },
    GovernedParam {
        key: EXPEDITED_VOTING_PERIOD_PARAM,
        min: 60 * 60 * 1000,
        max: 3 * 24 * 60 * 60 * 1000,
        genesis: EXPEDITED_VOTING_PERIOD_MS as u64,
        tighten: Tighten::Neither,
        description: "Voting window on the expedited and security-fix tracks, ms.",
    },
    GovernedParam {
        key: TIMELOCK_PARAM,
        min: 4 * 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: TIMELOCK_DELAY_MS as u64,
        tighten: Tighten::Neither,
        description: "How long a passed standard proposal waits before it may \
                      execute, ms: the window in which guardians and holders can \
                      still respond.",
    },
    GovernedParam {
        key: EXPEDITED_TIMELOCK_PARAM,
        min: 60 * 60 * 1000,
        max: 3 * 24 * 60 * 60 * 1000,
        genesis: EXPEDITED_TIMELOCK_DELAY_MS as u64,
        tighten: Tighten::Neither,
        description: "Timelock on the expedited and security-fix tracks, ms.",
    },
    GovernedParam {
        key: RATIFY_TIMELOCK_PARAM,
        min: 7 * 24 * 60 * 60 * 1000,
        max: 180 * 24 * 60 * 60 * 1000,
        genesis: RATIFY_TIMELOCK_MS as u64,
        tighten: Tighten::Neither,
        description: "Timelock of a proposal re-passed on the Ratify track, ms, so \
                      holders who contested it can leave before it applies.",
    },
    GovernedParam {
        key: QUORUM_PARAM,
        min: 2_000,
        max: 6_667,
        genesis: QUORUM_BPS,
        tighten: Tighten::Neither,
        description: "Share of all bonded stake that must take part in a vote, bps.",
    },
    GovernedParam {
        key: THRESHOLD_PARAM,
        min: 5_001,
        max: 9_000,
        genesis: THRESHOLD_BPS,
        tighten: Tighten::Neither,
        description: "Share of participating stake that must vote yes on the \
                      standard track, bps.",
    },
    GovernedParam {
        key: EXPEDITED_THRESHOLD_PARAM,
        min: 6_667,
        max: 9_500,
        genesis: EXPEDITED_THRESHOLD_BPS,
        tighten: Tighten::Neither,
        description: "Share of participating stake that must vote yes on the \
                      expedited and security-fix tracks, bps; never below the \
                      standard threshold.",
    },
    GovernedParam {
        key: LARGE_SPEND_PARAM,
        min: 1,
        max: u64::MAX,
        genesis: LARGE_SPEND_TNZO,
        tighten: Tighten::Down,
        description: "Whole TNZO from which a payment out of the treasury or \
                      its running-cost reserve is a large spend and waits the \
                      large-spend timelock.",
    },
    GovernedParam {
        key: LARGE_SPEND_APPROVAL_PARAM,
        min: 5_001,
        max: 10_000,
        genesis: LARGE_SPEND_APPROVAL_BPS,
        tighten: Tighten::Up,
        description: "Yes votes any payment out of the treasury or its \
                      running-cost reserve, and any change that loosens a \
                      capture guard (an economic safety bound), needs, bps of \
                      all stake eligible when it opened rather than of the \
                      stake that voted.",
    },
    GovernedParam {
        key: LARGE_SPEND_TIMELOCK_PARAM,
        min: 24 * 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: LARGE_SPEND_TIMELOCK_MS as u64,
        tighten: Tighten::Up,
        description: "Least timelock of a large spend, ms.",
    },
    GovernedParam {
        key: MAX_PROPOSAL_OUTFLOW_PARAM,
        min: 1,
        max: 10_000,
        genesis: MAX_PROPOSAL_OUTFLOW_BPS,
        tighten: Tighten::Down,
        description: "Most one proposal pays out of the treasury, bps of the \
                      treasury balance when it enacts.",
    },
    GovernedParam {
        key: MAX_PERIOD_OUTFLOW_PARAM,
        min: 1,
        max: 10_000,
        genesis: MAX_PERIOD_OUTFLOW_BPS,
        tighten: Tighten::Down,
        description: "Most the treasury pays out within one outflow period, bps \
                      of its balance when the period began.",
    },
    GovernedParam {
        key: OUTFLOW_PERIOD_PARAM,
        min: 60 * 60 * 1000,
        max: 365 * 24 * 60 * 60 * 1000,
        genesis: OUTFLOW_PERIOD_MS,
        tighten: Tighten::Up,
        description: "Length of a treasury outflow period, ms.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::FILL_SHARE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::treasury_reserve::DEFAULT_FILL_SHARE_BPS,
        tighten: Tighten::Neither,
        description: "Share of the fee revenue the treasury realised since the last \
                      epoch boundary that moves into the running-cost reserve at the \
                      boundary, while the reserve is under its target and only as far \
                      as the target, bps.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::TARGET_MONTHS_PARAM,
        min: 0,
        max: 120,
        genesis: crate::native::treasury_reserve::DEFAULT_TARGET_MONTHS,
        tighten: Tighten::Neither,
        description: "The running-cost reserve's target, in months of observed running \
                      cost: the larger of what the reserve paid over the trailing month \
                      and what that month's revenue share allowed.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::REVENUE_SHARE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::treasury_reserve::DEFAULT_REVENUE_SHARE_BPS,
        tighten: Tighten::Neither,
        description: "Share of the trailing month's realised fee revenue running-cost \
                      payments may use in that month, bps.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::DRAWDOWN_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::treasury_reserve::DEFAULT_DRAWDOWN_BPS,
        tighten: Tighten::Neither,
        description: "Share of the running-cost reserve's balance running-cost payments \
                      may draw in a trailing month beyond the revenue share, bps.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::MONTH_EPOCHS_PARAM,
        min: 1,
        max: 8_760,
        genesis: crate::native::treasury_reserve::DEFAULT_MONTH_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs one treasury accounting month spans: the window realised \
                      revenue, paid running costs and the reserve target are measured over.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::SALE_VOLUME_SHARE_PARAM,
        min: 0,
        max: 10_000,
        genesis: crate::native::treasury_reserve::DEFAULT_SALE_VOLUME_SHARE_BPS,
        tighten: Tighten::Neither,
        description: "Most the running-cost reserve pays out in one epoch, bps of the \
                      TNZO the market traded in an epoch as the validators' volume \
                      reports observe it; no recent report, no payout.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::MAX_SALE_PARAM,
        min: 1,
        max: 10_000_000,
        genesis: crate::native::treasury_reserve::DEFAULT_MAX_SALE_TNZO_EPOCH,
        tighten: Tighten::Neither,
        description: "Most the running-cost reserve pays out in one epoch, whole TNZO, \
                      however much volume the reports show. A ceiling wash trading \
                      cannot raise.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::VOLUME_MAX_AGE_PARAM,
        min: 1,
        max: 720,
        genesis: crate::native::treasury_reserve::DEFAULT_VOLUME_MAX_AGE_EPOCHS,
        tighten: Tighten::Neither,
        description: "Market epochs a traded-volume report stays usable for the \
                      running-cost sale cap; an older one counts as no volume.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::VOLUME_WINDOW_PARAM,
        min: 1,
        max: crate::native::treasury_reserve::MAX_VOLUME_WINDOW_EPOCHS,
        genesis: crate::native::treasury_reserve::DEFAULT_VOLUME_WINDOW_EPOCHS,
        tighten: Tighten::Neither,
        description: "Market epochs of traded-volume reports the running-cost sale cap \
                      takes the lowest of, so a sale sized from them does not outrun a \
                      market whose volume has since fallen.",
    },
    GovernedParam {
        key: crate::native::treasury_reserve::PAYMENT_TTL_PARAM,
        min: 1,
        max: 8_760,
        genesis: crate::native::treasury_reserve::DEFAULT_PAYMENT_TTL_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs an enacted running-cost payment stays payable; what the \
                      reserve's caps have not paid by then lapses, so a payment sized \
                      at one price is never paid out at a much later one.",
    },
    GovernedParam {
        key: MIN_BOND_AGE_PARAM,
        min: 0,
        max: MAX_MIN_BOND_AGE_MS as u64,
        genesis: MIN_BOND_AGE_MS as u64,
        tighten: Tighten::Up,
        description: "Milliseconds stake must have been bonded before a proposal \
                      opened to weigh in its vote; stake bonded later counts for \
                      nothing on that proposal.",
    },
    GovernedParam {
        key: RATIFY_THRESHOLD_PARAM,
        min: 6_667,
        max: 9_500,
        genesis: RATIFY_THRESHOLD_BPS,
        tighten: Tighten::Neither,
        description: "Share of participating stake that must vote yes on the Ratify \
                      track, bps; never below the standard threshold.",
    },
    GovernedParam {
        key: crate::native::registry::BOND_PARAM,
        min: 0,
        max: 1_000_000,
        genesis: crate::native::registry::DEFAULT_BOND_TNZO,
        tighten: Tighten::Up,
        description: "Bond the first put of a registry id locks while the entry stands, \
                      whole TNZO; returned when its owner retires it, forfeited to the \
                      insurance pool when governance does.",
    },
    GovernedParam {
        key: crate::native::registry::MAX_DATA_PARAM,
        min: 256,
        max: 1024 * 1024,
        genesis: crate::native::registry::DEFAULT_MAX_DATA_BYTES,
        tighten: Tighten::Down,
        description: "Most bytes of data one registry entry carries.",
    },
    GovernedParam {
        key: crate::native::registry::NAME_BOND_PARAM,
        min: 0,
        max: 1_000_000,
        genesis: crate::native::registry::DEFAULT_NAME_BOND_TNZO,
        tighten: Tighten::Up,
        description: "Bond the first put of a registry name locks, whole TNZO; names \
                      are first come and only governance retires one, forfeiting the \
                      bond to the insurance pool.",
    },
    GovernedParam {
        key: crate::native::registry::NAME_MIN_LEN_PARAM,
        min: 1,
        max: 32,
        genesis: crate::native::registry::DEFAULT_NAME_MIN_LEN,
        tighten: Tighten::Up,
        description: "Fewest characters in a registry name.",
    },
    GovernedParam {
        key: crate::native::registry::NAME_MAX_LEN_PARAM,
        min: 32,
        max: tenzro_types::registry::MAX_ID_LEN as u64,
        genesis: crate::native::registry::DEFAULT_NAME_MAX_LEN,
        tighten: Tighten::Down,
        description: "Most characters in a registry name.",
    },
    GovernedParam {
        key: crate::native::registry::NAME_MAX_DATA_PARAM,
        min: 32,
        max: 4096,
        genesis: crate::native::registry::DEFAULT_NAME_MAX_DATA_BYTES,
        tighten: Tighten::Down,
        description: "Most bytes of data a registry name carries (what the name points to).",
    },
    GovernedParam {
        key: crate::native::registry::STANDARD_MAX_DATA_PARAM,
        min: 64,
        max: 16 * 1024,
        genesis: crate::native::registry::DEFAULT_STANDARD_MAX_DATA_BYTES,
        tighten: Tighten::Down,
        description: "Most bytes of data a registry standard carries beside its bundle digest.",
    },
    GovernedParam {
        key: crate::native::registry::CONFORMANCE_MAX_DIGESTS_PARAM,
        min: 1,
        max: 512,
        genesis: crate::native::registry::DEFAULT_CONFORMANCE_MAX_DIGESTS,
        tighten: Tighten::Down,
        description: "Most standard bundle digests one registry conformance entry lists.",
    },
    GovernedParam {
        key: crate::native::meter_bond::DISPUTE_WINDOW_PARAM,
        min: 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: crate::native::meter_bond::DEFAULT_DISPUTE_WINDOW_MS,
        tighten: Tighten::Down,
        description: "Milliseconds after a metered record is measured that its payer \
                      may dispute it; a meter bond stays slashable this long after \
                      its owner asks to withdraw.",
    },
    GovernedParam {
        key: crate::native::meter_bond::DISPUTE_PENALTY_MULTIPLE_PARAM,
        min: 1,
        max: 100,
        genesis: crate::native::meter_bond::DEFAULT_DISPUTE_PENALTY_MULTIPLE,
        tighten: Tighten::Up,
        description: "Multiple of a disputed record's ceiling a proven dispute takes \
                      from the meter bond, capped by what the bond holds.",
    },
    GovernedParam {
        key: crate::native::economy::HTTP402_NETWORK_SHARE_PARAM,
        min: 0,
        max: 5_000,
        genesis: tenzro_types::fees::HTTP_402_NETWORK_SHARE_BPS as u64,
        tighten: Tighten::Up,
        description: "Share of an HTTP-402 payment settled off chain \
                      (delivery-versus-payment and fiat rails) offered to the \
                      network treasury, bps of the amount after the developer \
                      margin.",
    },
    GovernedParam {
        key: crate::native::economy::MAX_DEVELOPER_MARGIN_PARAM,
        min: 0,
        max: 10_000,
        genesis: tenzro_types::fees::DEFAULT_MAX_DEVELOPER_MARGIN_BPS as u64,
        tighten: Tighten::Neither,
        description: "Most a developer may add on top of a network cost as its own \
                      margin on an HTTP-402 payment, bps.",
    },
    GovernedParam {
        key: crate::native::rewards::CLAIM_WINDOW_PARAM,
        min: 1,
        max: 3_650,
        genesis: tenzro_token::rewards::DEFAULT_CLAIM_WINDOW_EPOCHS,
        tighten: Tighten::Down,
        description: "Epochs an issued reward coupon stays claimable before it \
                      expires unclaimed, its amount staying in the pool.",
    },
    GovernedParam {
        key: crate::native::rewards::CLAIM_LIQUID_PARAM,
        min: 0,
        max: 10_000,
        genesis: tenzro_token::rewards::DEFAULT_LIQUID_BPS as u64,
        tighten: Tighten::Neither,
        description: "Share of a reward claim paid liquid, bps; the rest vests.",
    },
    GovernedParam {
        key: crate::native::rewards::BASE_LIQUID_PARAM,
        min: 0,
        max: 10_000,
        genesis: 10_000,
        tighten: Tighten::Neither,
        description: "Share of a validator's running-cost base paid liquid when it claims, bps; \
                      the base is the operator's and is split before the rest of the claim.",
    },
    GovernedParam {
        key: crate::native::rewards::CLAIM_VESTING_PARAM,
        min: 0,
        max: 4 * 365 * 24 * 60 * 60 * 1000,
        genesis: tenzro_token::vesting::REWARD_VESTING_MS as u64,
        tighten: Tighten::Neither,
        description: "Milliseconds the vesting part of a reward claim vests over, \
                      linearly.",
    },
    GovernedParam {
        key: crate::native::SLA_PROBE_INTERVAL_PARAM,
        min: 60_000,
        max: 20 * 60 * 1000,
        genesis: 10 * 60 * 1000,
        tighten: Tighten::Neither,
        description: "How often validators probe each bonded provider, ms. Probe \
                      rounds align to it; at most a third of a market epoch.",
    },
    GovernedParam {
        key: crate::native::SLA_PROBE_WINDOW_PARAM,
        min: 15_000,
        max: 10 * 60 * 1000,
        genesis: 30_000,
        tighten: Tighten::Down,
        description: "How long a provider has to answer a scheduled probe, ms; never \
                      longer than the probe interval.",
    },
    GovernedParam {
        key: crate::native::SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM,
        min: 0,
        max: crate::native::MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS,
        genesis: crate::native::sla_energy_budget::DEFAULT_SLA_CHALLENGE_ENERGY_BUDGET_BPS,
        tighten: Tighten::Neither,
        description: "Most of the bonded compute fleet's own daily energy the SLA probe \
                      cadence may spend on challenges, bps. Zero disables the check.",
    },
    GovernedParam {
        key: PROPOSAL_THRESHOLD_PARAM,
        min: 0,
        max: 1_000,
        genesis: PROPOSAL_THRESHOLD_BPS,
        tighten: Tighten::Up,
        description: "Share of all bonded stake a proposer must hold to open a \
                      proposal, bps.",
    },
    GovernedParam {
        key: crate::native::CHALLENGE_COMMIT_WINDOW_PARAM,
        min: 60,
        max: 7 * 24 * 60 * 60,
        genesis: 3_600,
        tighten: Tighten::Down,
        description: "Seconds an inference challenge's committee has to commit its \
                      votes after the challenge is filed.",
    },
    GovernedParam {
        key: crate::native::CHALLENGE_REVEAL_WINDOW_PARAM,
        min: 60,
        max: 7 * 24 * 60 * 60,
        genesis: 3_600,
        tighten: Tighten::Down,
        description: "Seconds an inference challenge's committee has to reveal its \
                      votes after the commit window.",
    },
    GovernedParam {
        key: STANDING_BONDED_PARAM,
        min: 0,
        max: 10_000,
        genesis: DEFAULT_STANDING_BONDED,
        tighten: Tighten::Neither,
        description: "Routing standing a provider holds for a live serving bond alone, \
                      out of 10000.",
    },
    GovernedParam {
        key: STANDING_AVAILABILITY_PARAM,
        min: 0,
        max: 10_000,
        genesis: DEFAULT_STANDING_AVAILABILITY,
        tighten: Tighten::Neither,
        description: "Most routing standing the SLA verdicts add, scaled by the share \
                      of judged hours found available, out of 10000.",
    },
    GovernedParam {
        key: STANDING_UNJUDGED_BPS_PARAM,
        min: 0,
        max: 10_000,
        genesis: DEFAULT_STANDING_UNJUDGED_BPS,
        tighten: Tighten::Neither,
        description: "Share of the availability standing a bonded provider holds while \
                      no verdict in the window has judged it, bps.",
    },
    GovernedParam {
        key: STANDING_WINDOW_HOURS_PARAM,
        min: 1,
        max: 30 * 24,
        genesis: DEFAULT_STANDING_WINDOW_HOURS,
        tighten: Tighten::Neither,
        description: "Closed SLA hours whose verdicts count toward routing standing.",
    },
    GovernedParam {
        key: KEYSTORE_ADD_DEVICE_WAIT_PARAM,
        min: 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: tenzro_types::keystore::ADD_DEVICE_WAIT_MS,
        tighten: Tighten::Up,
        description: "How long a passkey added to an account with fewer than two independent roots waits before it counts as one, ms; any other passkey can remove it meanwhile.",
    },
    GovernedParam {
        key: tenzro_types::transfer_policy::DAILY_CEILING_PARAM,
        min: 1,
        max: 1_000_000_000,
        genesis: tenzro_types::transfer_policy::DEFAULT_DAILY_CEILING_TNZO,
        tighten: Tighten::Down,
        description: "Most one ordinary account sends in the ceiling window, whole TNZO; a wallet refuses to sign a transfer that would pass it.",
    },
    GovernedParam {
        key: tenzro_types::transfer_policy::STEP_UP_THRESHOLD_PARAM,
        min: 1,
        max: 1_000_000_000,
        genesis: tenzro_types::transfer_policy::DEFAULT_STEP_UP_THRESHOLD_TNZO,
        tighten: Tighten::Down,
        description: "A transfer of at least this much, whole TNZO, needs the amount typed back before a wallet signs it.",
    },
    GovernedParam {
        key: tenzro_types::transfer_policy::WINDOW_PARAM,
        min: 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: tenzro_types::transfer_policy::DEFAULT_WINDOW_MS,
        tighten: Tighten::Up,
        description: "The rolling window the ordinary-account sending ceiling covers, ms.",
    },
    GovernedParam {
        key: tenzro_types::recipient_guard::PREFIX_BYTES_PARAM,
        min: 1,
        max: 8,
        genesis: tenzro_types::recipient_guard::DEFAULT_PREFIX_BYTES,
        tighten: Tighten::Down,
        description: "Leading address bytes that must match a trusted address for a recipient to be flagged as a look-alike (address poisoning) before signing; fewer bytes flag more addresses.",
    },
    GovernedParam {
        key: tenzro_types::recipient_guard::SUFFIX_BYTES_PARAM,
        min: 1,
        max: 8,
        genesis: tenzro_types::recipient_guard::DEFAULT_SUFFIX_BYTES,
        tighten: Tighten::Down,
        description: "Trailing address bytes that must match a trusted address for a recipient to be flagged as a look-alike (address poisoning) before signing; fewer bytes flag more addresses.",
    },
    GovernedParam {
        key: KEYSTORE_RECOVERY_WAIT_KEY_AND_EMAIL_PARAM,
        min: 10 * 60 * 1000,
        max: 7 * 24 * 60 * 60 * 1000,
        genesis: tenzro_types::keystore::RECOVERY_WAIT_KEY_AND_EMAIL_MS,
        tighten: Tighten::Up,
        description: "How long a recovery approved by a recovery key and an email verifier waits before it completes, ms; any linked passkey can cancel it meanwhile.",
    },
    GovernedParam {
        key: KEYSTORE_RECOVERY_WAIT_KEY_PARAM,
        min: 60 * 60 * 1000,
        max: 30 * 24 * 60 * 60 * 1000,
        genesis: tenzro_types::keystore::RECOVERY_WAIT_KEY_MS,
        tighten: Tighten::Up,
        description: "How long a recovery approved by a recovery key, without an email verifier, waits before it completes, ms.",
    },
    GovernedParam {
        key: KEYSTORE_RECOVERY_WAIT_OTHER_PARAM,
        min: 24 * 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: tenzro_types::keystore::RECOVERY_WAIT_EMAIL_MS,
        tighten: Tighten::Up,
        description: "How long any other recovery waits before it completes, ms: the longest wait.",
    },
    GovernedParam {
        key: KEYSTORE_RECOVERY_CODE_WAIT_PARAM,
        min: 24 * 60 * 60 * 1000,
        max: 90 * 24 * 60 * 60 * 1000,
        genesis: 7 * 24 * 60 * 60 * 1000,
        tighten: Tighten::Up,
        description: "How long a recovery started with an account's one-time recovery code waits before it completes, ms; any linked passkey can cancel it meanwhile.",
    },
    GovernedParam {
        key: KEYSTORE_RECOVERY_CODE_REVEAL_DELAY_PARAM,
        min: 5_000,
        max: 60 * 60 * 1000,
        genesis: 60_000,
        tighten: Tighten::Neither,
        description: "Least age of a recovery code claim before the code may be revealed, ms: long enough that a claim made after seeing a revealed code is too late.",
    },
    GovernedParam {
        key: KEYSTORE_RECOVERY_CODE_CLAIM_TTL_PARAM,
        min: 10 * 60 * 1000,
        max: 7 * 24 * 60 * 60 * 1000,
        genesis: 24 * 60 * 60 * 1000,
        tighten: Tighten::Neither,
        description: "Age at which a recovery code claim expires unrevealed, ms.",
    },
    GovernedParam {
        key: CONSENSUS_LEADER_LOOKAHEAD_PARAM,
        min: 1,
        max: 64,
        genesis: 4,
        tighten: Tighten::Neither,
        description: "Rounds between the anchor that closes a checkpoint and the first round its seed draws leaders for. Read when an epoch begins and fixed for that epoch; a validator behind on its decisions waits rather than judge leaders it may yet see redrawn, so a shorter value costs speed, never safety.",
    },
    GovernedParam {
        key: CONSENSUS_SENDER_FAILOVER_PARAM,
        min: 1_000,
        max: 600_000,
        genesis: 10_000,
        tighten: Tighten::Neither,
        description: "The most a sender's ready transactions wait on the validator they are assigned to before the next validator in turn may batch them, and each further validator as long again, ms. Read when an epoch begins. Shorter takes a sender off a slow or absent validator sooner; longer orders fewer transactions twice.",
    },
    GovernedParam {
        key: ADMISSION_VERIFIED_RATE_PARAM,
        min: 1,
        max: 100_000_000,
        genesis: 50_000,
        tighten: Tighten::Down,
        description: "Transactions per second, in thousandths, a sender in the verified lane (attested identity with bonded stake) may submit.",
    },
    GovernedParam {
        key: ADMISSION_VERIFIED_BURST_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: 500,
        tighten: Tighten::Down,
        description: "Transactions a verified-lane sender may submit at once after being idle.",
    },
    GovernedParam {
        key: ADMISSION_DELEGATED_RATE_PARAM,
        min: 1,
        max: 100_000_000,
        genesis: 10_000,
        tighten: Tighten::Down,
        description: "Transactions per second, in thousandths, a sender in the delegated lane (machine identity under a verified controller, or holding an agent bond) may submit.",
    },
    GovernedParam {
        key: ADMISSION_DELEGATED_BURST_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: 100,
        tighten: Tighten::Down,
        description: "Transactions a delegated-lane sender may submit at once after being idle.",
    },
    GovernedParam {
        key: ADMISSION_OPEN_RATE_PARAM,
        min: 1,
        max: 100_000_000,
        genesis: 250,
        tighten: Tighten::Down,
        description: "Transactions per second, in thousandths, any other sender may submit.",
    },
    GovernedParam {
        key: ADMISSION_OPEN_BURST_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: 10,
        tighten: Tighten::Down,
        description: "Transactions any other sender may submit at once after being idle.",
    },
    GovernedParam {
        key: ADMISSION_VERIFIED_FEE_MULT_PARAM,
        min: 10_000,
        max: 1_000_000,
        genesis: 10_000,
        tighten: Tighten::Up,
        description: "Least gas price a verified-lane sender's transaction is admitted at, in bps of the base fee the next block charges.",
    },
    GovernedParam {
        key: ADMISSION_DELEGATED_FEE_MULT_PARAM,
        min: 10_000,
        max: 1_000_000,
        genesis: 15_000,
        tighten: Tighten::Up,
        description: "Least gas price a delegated-lane sender's transaction is admitted at, in bps of the base fee the next block charges.",
    },
    GovernedParam {
        key: ADMISSION_OPEN_FEE_MULT_PARAM,
        min: 10_000,
        max: 1_000_000,
        genesis: 40_000,
        tighten: Tighten::Up,
        description: "Least gas price any other sender's transaction is admitted at, in bps of the base fee the next block charges: what each transaction of a flood from funded fresh keys costs its owner over a verified sender's.",
    },
    GovernedParam {
        key: RPC_ADDRESS_RATE_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: 50,
        tighten: Tighten::Down,
        description: "JSON-RPC requests per second one network address may make before anything else is known about it: the floor every caller gets.",
    },
    GovernedParam {
        key: RPC_ADDRESS_BURST_PARAM,
        min: 1,
        max: 1_000_000,
        genesis: 200,
        tighten: Tighten::Down,
        description: "JSON-RPC requests one network address may make at once after being idle.",
    },
    GovernedParam {
        key: RPC_IDENTITY_CHECKS_PARAM,
        min: 0,
        max: 1_000_000,
        genesis: 500,
        tighten: Tighten::Down,
        description: "Transaction submissions per second one network address may make beyond its floor; each is admitted only if its sender is in the verified or delegated lane, and then counts against that sender's quota.",
    },
    GovernedParam {
        key: crate::native::security::GAMMA_PARAM,
        min: 2_000,
        max: 40_000,
        genesis: crate::native::security::DEFAULT_GAMMA_BPS,
        tighten: Tighten::Up,
        description: "Margin of the stake-backed bridge caps, bps: each epoch the caps \
                      of units other than TNZO shrink so that, with TNZO's cap, one \
                      epoch lets out at most two thirds of bonded stake over one plus \
                      this, valued at the safety rate.",
    },
    GovernedParam {
        key: crate::native::security::QUEUE_MAX_EPOCHS_PARAM,
        min: 1,
        max: 168,
        genesis: crate::native::security::DEFAULT_QUEUE_MAX_EPOCHS,
        tighten: Tighten::Neither,
        description: "Epochs of a unit's bridge outflow cap the exit queue may hold. An \
                      exit over the cap this epoch queues instead of failing while the \
                      queue is shorter, and anyone may release it once an epoch has room.",
    },
    GovernedParam {
        key: BRIDGE_EXIT_DELAY_THRESHOLD_PARAM,
        min: 1,
        max: 10_000,
        genesis: DEFAULT_BRIDGE_EXIT_DELAY_THRESHOLD_BPS,
        tighten: Tighten::Neither,
        description: "A bridge exit larger than this share of its outflow bucket's \
                      capacity waits out the exit delay before it leaves, bps.",
    },
    GovernedParam {
        key: BRIDGE_EXIT_DELAY_PARAM,
        min: 60 * 60 * 1000,
        max: 7 * 24 * 60 * 60 * 1000,
        genesis: DEFAULT_BRIDGE_EXIT_DELAY_MS,
        tighten: Tighten::Neither,
        description: "How long a large bridge exit waits before anyone may release \
                      it, ms: the window in which a seated guardian, or anyone after a \
                      proven fault of its route's committee, may cancel it.",
    },
    GovernedParam {
        key: MAX_CAP_RAISE_PARAM,
        min: 10_000,
        max: 100_000,
        genesis: DEFAULT_MAX_CAP_RAISE_BPS,
        tighten: Tighten::Neither,
        description: "The most one enacted proposal may raise a bridge cap or loosen \
                      an exit limit to, in bps of its value before (10 000 keeps it). \
                      Applies to this parameter too.",
    },
    status_lever!(
        VERIFICATION_RECEIPT_STATUS,
        "Whether inference at the receipt verification level is routed and \
         served: 0 enabled, 1 paused (requests at the level are refused), 2 \
         retired for good."
    ),
    status_lever!(
        VERIFICATION_OPTIMISTIC_STATUS,
        "Whether inference at the optimistic verification level is routed and \
         served: 0 enabled, 1 paused, 2 retired. Faults on answers already \
         served stay fileable."
    ),
    status_lever!(
        VERIFICATION_TEE_STATUS,
        "Whether inference at the TEE verification level is routed and served: \
         0 enabled, 1 paused, 2 retired."
    ),
    status_lever!(
        "zk.koala_bear_sha256_fri.status",
        "Whether proofs from the KoalaBear SHA-256 FRI system are accepted on \
         chain: 0 enabled, 1 paused, 2 retired. Proofs already recorded stay."
    ),
    status_lever!(
        "zk.goldilocks_blake3_fri.status",
        "Whether proofs from the Goldilocks BLAKE3 FRI system are accepted on \
         chain: 0 enabled, 1 paused, 2 retired. Proofs already recorded stay."
    ),
    status_lever!(
        "zk.halo2_ipa_pasta.status",
        "Whether proofs from the Halo2 IPA Pasta system are accepted on chain: \
         0 enabled, 1 paused, 2 retired. Proofs already recorded stay."
    ),
    status_lever!(
        "keystore.recovery.recovery_key.status",
        "Whether a recovery key may be set as a recovery signer and its approval \
         counts: 0 enabled, 1 paused (a recovery it approved cannot finish), 2 \
         retired."
    ),
    status_lever!(
        "keystore.recovery.email_verifier.status",
        "Whether an email verifier may be set as a recovery signer and its \
         approval counts: 0 enabled, 1 paused (a recovery it approved cannot \
         finish), 2 retired."
    ),
    status_lever!(
        "keystore.recovery.device.status",
        "Whether another device may be set as a recovery signer and its approval \
         counts: 0 enabled, 1 paused (a recovery it approved cannot finish), 2 \
         retired."
    ),
    status_lever!(
        RECOVERY_CODE_STATUS,
        "Whether accounts may set, claim and use a one-time recovery code: 0 \
         enabled, 1 paused (a recovery started with a code cannot finish), 2 \
         retired."
    ),
    status_lever!(
        "roles.tee.status",
        "Whether new TEE provider bonds are taken: 0 enabled (open to anyone who \
         bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.ai.status",
        "Whether new model provider bonds are taken: 0 enabled (open to anyone \
         who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.compute.status",
        "Whether new compute provider bonds are taken: 0 enabled (open to anyone \
         who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.storage.status",
        "Whether new storage provider bonds are taken: 0 enabled (open to anyone \
         who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.rpc.status",
        "Whether new RPC operator bonds are taken: 0 enabled (open to anyone who \
         bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.attestor.status",
        "Whether new attestor bonds are taken: 0 enabled (open to anyone who \
         bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.wallet.status",
        "Whether new wallet provider bonds are taken: 0 enabled (open to anyone \
         who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.catalog.status",
        "Whether new catalog publisher bonds are taken: 0 enabled (open to anyone \
         who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "roles.edge.status",
        "Whether new edge operator bonds are taken: 0 enabled (open to anyone who \
         bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual."
    ),
    status_lever!(
        "bridge.ccip.status",
        "Every CCIP route at once: 0 enabled (each route's own mode applies), 1 \
         paused (carries nothing), 2 retired (winds down: nothing new leaves, \
         TNZO already out may come back)."
    ),
    status_lever!(
        "bridge.ibc.status",
        "Every IBC route at once: 0 enabled (each route's own mode applies), 1 \
         paused (carries nothing), 2 retired (winds down: nothing new leaves, \
         TNZO already out may come back)."
    ),
    status_lever!(
        "bridge.deposit.status",
        "Every deposit route at once: 0 enabled (each route's own mode applies), \
         1 paused (carries nothing), 2 retired (winds down: nothing new is credited)."
    ),
    status_lever!(
        "bridge.contract.status",
        "Every contract route at once: 0 enabled (each route's own mode applies), \
         1 paused (carries nothing), 2 retired (winds down: nothing new leaves, \
         TNZO already out may come back)."
    ),
    GovernedParam {
        key: CONSENSUS_LEADER_TIMEOUT_MIN_PARAM,
        min: 10,
        max: 10_000,
        genesis: 100,
        tighten: Tighten::Neither,
        description: "Shortest leader timeout a validator runs with, whatever its own \
                      configuration says, ms. Read when an epoch begins.",
    },
    GovernedParam {
        key: CONSENSUS_LEADER_TIMEOUT_MAX_PARAM,
        min: 100,
        max: 600_000,
        genesis: 30_000,
        tighten: Tighten::Neither,
        description: "Longest leader timeout a validator runs with, whatever its own \
                      configuration says, ms. Read when an epoch begins.",
    },
    GovernedParam {
        key: CONSENSUS_ROUND_INTERVAL_MIN_PARAM,
        min: 0,
        max: 1_000,
        genesis: 0,
        tighten: Tighten::Neither,
        description: "Least time between a validator's rounds it may configure, at \
                      the shortest, ms. Read when an epoch begins.",
    },
    GovernedParam {
        key: CONSENSUS_ROUND_INTERVAL_MAX_PARAM,
        min: 10,
        max: 60_000,
        genesis: 2_000,
        tighten: Tighten::Neither,
        description: "Least time between a validator's rounds it may configure, at \
                      the longest, ms. Read when an epoch begins.",
    },
];

/// Governed key: an exit larger than this share of its outflow bucket's
/// capacity, bps, is queued for [`BRIDGE_EXIT_DELAY_PARAM`].
pub const BRIDGE_EXIT_DELAY_THRESHOLD_PARAM: &str = "bridge.exit_delay_threshold_bps";
/// Genesis value of [`BRIDGE_EXIT_DELAY_THRESHOLD_PARAM`]: a quarter of the
/// bucket.
pub const DEFAULT_BRIDGE_EXIT_DELAY_THRESHOLD_BPS: u64 = 2_500;
/// Governed key: how long a queued exit waits, ms.
pub const BRIDGE_EXIT_DELAY_PARAM: &str = "bridge.exit_delay_ms";
/// Genesis value of [`BRIDGE_EXIT_DELAY_PARAM`]: a day.
pub const DEFAULT_BRIDGE_EXIT_DELAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Governed key: the most one proposal may raise a cap, bps of its value.
pub const MAX_CAP_RAISE_PARAM: &str = "governance.max_cap_raise_bps";
/// Genesis value of [`MAX_CAP_RAISE_PARAM`]: double.
pub const DEFAULT_MAX_CAP_RAISE_BPS: u64 = 20_000;

/// Refuse a parameter change that loosens an exit limit, a capture guard,
/// or the raise bound itself, by more than one step allows: a limit that
/// loosens upwards rises to at most `max_raise_bps` of its value, one that
/// loosens downwards falls to no less than its value scaled down by it.
pub fn cap_change_allowed(
    key: &str,
    current: u64,
    value: u64,
    max_raise_bps: u64,
) -> Result<(), GovernanceError> {
    use tenzro_types::bridge_route::{lower_within, raise_within};
    let (current, value) = (u128::from(current), u128::from(value));
    let within = match key {
        BRIDGE_EXIT_DELAY_THRESHOLD_PARAM | MAX_CAP_RAISE_PARAM => {
            raise_within(current, value, max_raise_bps)
        }
        BRIDGE_EXIT_DELAY_PARAM => lower_within(current, value, max_raise_bps),
        _ => match capture_guard(key) {
            Some(Tighten::Down) => raise_within(current, value, max_raise_bps),
            Some(Tighten::Up) => lower_within(current, value, max_raise_bps),
            _ => true,
        },
    };
    if within {
        return Ok(());
    }
    Err(GovernanceError::InvalidPolicy(format!(
        "{key} may move from {current} to at most {max_raise_bps} bps of it in one step, \
         not to {value}"
    )))
}

/// Share of bonded stake whose machines must quote the new binary before a
/// protocol upgrade enacts.
pub const UPGRADE_READINESS_BPS_PARAM: &str = "upgrade.readiness_bps";
/// Default [`UPGRADE_READINESS_BPS_PARAM`]: 67%.
pub const DEFAULT_UPGRADE_READINESS_BPS: u64 = 6_700;
/// Blocks from an upgrade's enactment to its activation height.
pub const UPGRADE_ACTIVATION_DELAY_PARAM: &str = "upgrade.activation_delay_blocks";
/// Default [`UPGRADE_ACTIVATION_DELAY_PARAM`].
pub const DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS: u64 = 1_000;
/// How long a security fix's proposer has to reveal its vulnerability.
pub const SECURITY_REVEAL_WINDOW_PARAM: &str = "governance.security_reveal_window_ms";
/// Default [`SECURITY_REVEAL_WINDOW_PARAM`]: thirty days.
pub const DEFAULT_SECURITY_REVEAL_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Stake slashed from a proposer that never reveals.
pub const SECURITY_REVEAL_SLASH_BPS_PARAM: &str = "governance.security_reveal_slash_bps";
/// Default [`SECURITY_REVEAL_SLASH_BPS_PARAM`]: 10%.
pub const DEFAULT_SECURITY_REVEAL_SLASH_BPS: u64 = 1_000;

/// Governed key: most of the eligible stake one agent-cast ballot may weigh,
/// bps; the rest of the validator's weight abstains.
/// Share of supply locked against a proposal before its timelock stretches.
pub const VETO_SIGNAL_BPS_PARAM: &str = "veto.signal_bps";
/// Default [`VETO_SIGNAL_BPS_PARAM`]: 1%.
pub const DEFAULT_VETO_SIGNAL_BPS: u64 = 100;
/// Share of supply locked against a proposal that contests it.
pub const VETO_BLOCK_BPS_PARAM: &str = "veto.block_bps";
/// Default [`VETO_BLOCK_BPS_PARAM`]: 10%.
pub const DEFAULT_VETO_BLOCK_BPS: u64 = 1_000;
/// Most the veto escrow stretches a timelock.
pub const VETO_MAX_EXTENSION_PARAM: &str = "veto.max_extension_ms";
/// Default [`VETO_MAX_EXTENSION_PARAM`]: thirty days.
pub const DEFAULT_VETO_MAX_EXTENSION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Concerns past which a queued proposal's timelock doubles.
pub const CONCERN_QUORUM_PARAM: &str = "governance.concern_quorum";
/// Default [`CONCERN_QUORUM_PARAM`].
pub const DEFAULT_CONCERN_QUORUM: u64 = 100;
/// How long before a proposal opened a human root must have been registered
/// for its concern to count.
pub const ROOT_MIN_AGE_PARAM: &str = "governance.root_min_age_ms";
/// Default [`ROOT_MIN_AGE_PARAM`]: thirty days.
pub const DEFAULT_ROOT_MIN_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Whether holders may lock TNZO against `action` in a veto escrow: anything
/// that moves value, takes something from a named party, or upgrades the
/// protocol.
pub fn holder_veto_applies(action: &ProposalAction) -> bool {
    matches!(
        action.domain(),
        ActionDomain::Treasury | ActionDomain::Sanction
    ) || matches!(
        action,
        ProposalAction::PolicyUpdate {
            update: PolicyUpdate::ProtocolUpgrade { .. },
            ..
        }
    )
}

/// How far `locked` TNZO in a veto escrow stretches a timelock against
/// `supply`: nothing below `signal_bps` of supply, then in proportion to the
/// locked share, reaching `max_extension_ms` at `block_bps`.
pub fn veto_extension_ms(
    locked: u128,
    supply: u128,
    signal_bps: u64,
    block_bps: u64,
    max_extension_ms: u64,
) -> i64 {
    if supply == 0 || block_bps == 0 {
        return 0;
    }
    extension_for_share(
        locked_share_bps(locked, supply),
        signal_bps,
        block_bps,
        max_extension_ms,
    )
}

/// `locked` as basis points of a non-zero `supply`.
pub(crate) fn locked_share_bps(locked: u128, supply: u128) -> u128 {
    locked.saturating_mul(10_000) / supply
}

/// The veto extension for a locked share of `locked_bps` of supply.
pub(crate) fn extension_for_share(
    locked_bps: u128,
    signal_bps: u64,
    block_bps: u64,
    max_extension_ms: u64,
) -> i64 {
    if block_bps == 0 || locked_bps < u128::from(signal_bps) {
        return 0;
    }
    let share = locked_bps.min(u128::from(block_bps));
    i64::try_from(scaled_extension(max_extension_ms, share, block_bps)).unwrap_or(i64::MAX)
}

/// `max_extension_ms` scaled by `share` out of `block_bps`, rounded down.
pub(crate) fn scaled_extension(max_extension_ms: u64, share: u128, block_bps: u64) -> u128 {
    u128::from(max_extension_ms).saturating_mul(share) / u128::from(block_bps)
}

/// Whether `locked` TNZO in a veto escrow reaches the blocking share of
/// `supply`.
pub fn veto_blocks(locked: u128, supply: u128, block_bps: u64) -> bool {
    supply > 0 && locked.saturating_mul(10_000) >= supply.saturating_mul(u128::from(block_bps))
}

pub const AGENT_WEIGHT_MAX_PARAM: &str = "governance.agent_weight_max_bps";
/// Value of [`AGENT_WEIGHT_MAX_PARAM`] when governance has set none.
pub const DEFAULT_AGENT_WEIGHT_MAX_BPS: u64 = 500;

/// Governed key: block time (Unix ms) after which no steward seat holds any
/// power. A parameter change may only move it earlier.
pub const STEWARD_SUNSET_PARAM: &str = "governance.steward_sunset_ms";
/// Value of [`STEWARD_SUNSET_PARAM`] when genesis sets none: no stewardship.
pub const DEFAULT_STEWARD_SUNSET_MS: u64 = 0;
/// Governed key: most live steward seats. A parameter change may only lower it.
pub const STEWARD_MAX_SEATS_PARAM: &str = "governance.steward_max_seats";
/// Value of [`STEWARD_MAX_SEATS_PARAM`] when genesis sets none.
pub const DEFAULT_STEWARD_MAX_SEATS: u64 = 5;

/// Refuse a parameter change that, with the values `scheduled` returns for
/// the other parameters (each one's pending value, else the one in force),
/// breaks a rule that binds parameters together:
/// - the provider reward, the activity reward and the creator royalty one
///   settlement earns add up to at most
///   [`tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS`] of its fee, below
///   what it paid outside the trade;
/// - the inference penalty, in bps of the payment, times the least sampling
///   share, in bps, is at least 10^8: the expected penalty of a substituted
///   answer is at least what it was paid;
/// - the validator unbonding period is at least the standard voting period
///   plus its timelock: stake that votes is still bonded, and slashable,
///   when its decision takes effect.
pub fn joint_change_allowed(
    key: &str,
    value: u64,
    scheduled: &dyn Fn(&str) -> u64,
) -> Result<(), GovernanceError> {
    use crate::native::economy::{ACTIVITY_REWARD_FEE_PARAM, CREATOR_ROYALTY_FEE_PARAM};
    use crate::native::hardware_level::{
        LEVEL_BONUS_CAP_PARAM, LEVEL1_BONUS_PARAM, LEVEL2_BONUS_PARAM, LEVEL3_BONUS_PARAM,
        MAX_REWARD_WITH_LEVEL_BONUS_BPS,
    };
    use crate::native::inference_fault::{PENALTY_PAYMENT_PARAM, SAMPLE_BPS_PARAM};
    use crate::native::rewards::PROVIDER_REWARD_COST_PARAM;
    let get = |k: &str| if k == key { value } else { scheduled(k) };
    if key == LEVEL1_BONUS_PARAM || key == LEVEL2_BONUS_PARAM || key == LEVEL3_BONUS_PARAM {
        let (l1, l2, l3) = (
            get(LEVEL1_BONUS_PARAM),
            get(LEVEL2_BONUS_PARAM),
            get(LEVEL3_BONUS_PARAM),
        );
        if l1 > l2 || l2 > l3 {
            return Err(GovernanceError::InvalidPolicy(format!(
                "{LEVEL1_BONUS_PARAM} ({l1}), {LEVEL2_BONUS_PARAM} ({l2}) and \
                 {LEVEL3_BONUS_PARAM} ({l3}) must not decrease with the level"
            )));
        }
    }
    if key == PROVIDER_REWARD_COST_PARAM
        || key == ACTIVITY_REWARD_FEE_PARAM
        || key == CREATOR_ROYALTY_FEE_PARAM
        || key == LEVEL_BONUS_CAP_PARAM
    {
        let (p, a, r, cap) = (
            u128::from(get(PROVIDER_REWARD_COST_PARAM)),
            u128::from(get(ACTIVITY_REWARD_FEE_PARAM)),
            u128::from(get(CREATOR_ROYALTY_FEE_PARAM)),
            u128::from(get(LEVEL_BONUS_CAP_PARAM)),
        );
        let with_bonus = p * (10_000 + cap) / 10_000;
        if with_bonus + a + r > u128::from(MAX_REWARD_WITH_LEVEL_BONUS_BPS) {
            return Err(GovernanceError::InvalidPolicy(format!(
                "{PROVIDER_REWARD_COST_PARAM} ({p}) raised by {LEVEL_BONUS_CAP_PARAM} ({cap}), \
                 {ACTIVITY_REWARD_FEE_PARAM} ({a}) and {CREATOR_ROYALTY_FEE_PARAM} ({r}) may add \
                 up to at most {MAX_REWARD_WITH_LEVEL_BONUS_BPS} bps of a settlement's fee"
            )));
        }
    }
    if key == PROVIDER_REWARD_COST_PARAM
        || key == ACTIVITY_REWARD_FEE_PARAM
        || key == CREATOR_ROYALTY_FEE_PARAM
    {
        let (p, a, r) = (
            get(PROVIDER_REWARD_COST_PARAM),
            get(ACTIVITY_REWARD_FEE_PARAM),
            get(CREATOR_ROYALTY_FEE_PARAM),
        );
        if u128::from(p) + u128::from(a) + u128::from(r)
            > u128::from(tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS)
        {
            return Err(GovernanceError::InvalidPolicy(format!(
                "{PROVIDER_REWARD_COST_PARAM} ({p}), {ACTIVITY_REWARD_FEE_PARAM} ({a}) and \
                 {CREATOR_ROYALTY_FEE_PARAM} ({r}) may add up to at most {} bps of a \
                 settlement's fee",
                tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS
            )));
        }
    }
    if key == crate::native::staking::UNBONDING_PARAM
        || key == VOTING_PERIOD_PARAM
        || key == TIMELOCK_PARAM
    {
        let unbonding = get(crate::native::staking::UNBONDING_PARAM);
        let (voting, timelock) = (get(VOTING_PERIOD_PARAM), get(TIMELOCK_PARAM));
        if u128::from(unbonding) < u128::from(voting) + u128::from(timelock) {
            return Err(GovernanceError::InvalidPolicy(format!(
                "{} ({unbonding} ms) must be at least {VOTING_PERIOD_PARAM} ({voting} ms) plus \
                 {TIMELOCK_PARAM} ({timelock} ms), so stake that votes is still bonded when \
                 its decision takes effect",
                crate::native::staking::UNBONDING_PARAM
            )));
        }
    }
    {
        use crate::native::bridge_watcher::{PAUSE_MS_PARAM, REVIEW_MS_PARAM};
        if key == crate::native::staking::UNBONDING_PARAM
            || key == EXPEDITED_VOTING_PERIOD_PARAM
            || key == EXPEDITED_TIMELOCK_PARAM
            || key == PAUSE_MS_PARAM
            || key == REVIEW_MS_PARAM
        {
            let unbonding = u128::from(get(crate::native::staking::UNBONDING_PARAM));
            let fast = u128::from(get(EXPEDITED_VOTING_PERIOD_PARAM))
                + u128::from(get(EXPEDITED_TIMELOCK_PARAM));
            if unbonding < fast {
                return Err(GovernanceError::InvalidPolicy(format!(
                    "{} ({unbonding} ms) must be at least {EXPEDITED_VOTING_PERIOD_PARAM} plus \
                     {EXPEDITED_TIMELOCK_PARAM} ({fast} ms), so stake that votes on the \
                     expedited track is still bonded when its decision takes effect",
                    crate::native::staking::UNBONDING_PARAM
                )));
            }
            let watch = u128::from(get(PAUSE_MS_PARAM)) + u128::from(get(REVIEW_MS_PARAM));
            if unbonding < watch {
                return Err(GovernanceError::InvalidPolicy(format!(
                    "{} ({unbonding} ms) must be at least {PAUSE_MS_PARAM} plus {REVIEW_MS_PARAM} \
                     ({watch} ms), so a watcher's stake can still be slashed when its pause is \
                     judged",
                    crate::native::staking::UNBONDING_PARAM
                )));
            }
        }
    }
    if key == PENALTY_PAYMENT_PARAM || key == SAMPLE_BPS_PARAM {
        let (penalty, sample) = (get(PENALTY_PAYMENT_PARAM), get(SAMPLE_BPS_PARAM));
        if u128::from(penalty) * u128::from(sample) < 100_000_000 {
            return Err(GovernanceError::InvalidPolicy(format!(
                "{PENALTY_PAYMENT_PARAM} ({penalty}) times {SAMPLE_BPS_PARAM} ({sample}) must be \
                 at least 10^8, so a substituted answer's expected penalty covers its payment"
            )));
        }
    }
    Ok(())
}

/// Whether a change of `key` to `value` from `current` is permitted: the
/// steward sunset and seat cap only ever shrink.
pub fn steward_change_allowed(key: &str, current: u64, value: u64) -> Result<(), GovernanceError> {
    if (key == STEWARD_SUNSET_PARAM || key == STEWARD_MAX_SEATS_PARAM) && value > current {
        return Err(GovernanceError::InvalidPolicy(format!(
            "{key} may only be lowered (now {current}, proposed {value})"
        )));
    }
    Ok(())
}

/// Governed key: distinct guardians needed for a veto, pause or resume.
pub const GUARDIAN_THRESHOLD_PARAM: &str = "governance.guardian_threshold";
/// Genesis value of [`GUARDIAN_THRESHOLD_PARAM`].
pub const DEFAULT_GUARDIAN_THRESHOLD: u64 = 2;
/// Governed key: longest a pause holds.
pub const MAX_PAUSE_PARAM: &str = "governance.max_pause_ms";
/// Genesis value of [`MAX_PAUSE_PARAM`]: seventy-two hours.
pub const DEFAULT_MAX_PAUSE_MS: u64 = 72 * 60 * 60 * 1000;
/// Governed key: wait after a pause ends before the next.
pub const PAUSE_COOLOFF_PARAM: &str = "governance.pause_cooloff_ms";
/// Governed key: most epochs a guardian pause of one feature may last.
pub const FEATURE_PAUSE_MAX_PARAM: &str = "governance.feature_pause_max_epochs";
/// Genesis value of [`FEATURE_PAUSE_MAX_PARAM`]: seventy-two epochs, three days
/// at one-hour epochs.
pub const DEFAULT_FEATURE_PAUSE_MAX_EPOCHS: u64 = 72;
/// Governed key: epochs after a guardian pause of one feature lifts before
/// guardians may pause the same feature again.
pub const FEATURE_PAUSE_COOLOFF_PARAM: &str = "governance.feature_pause_cooloff_epochs";
/// Genesis value of [`FEATURE_PAUSE_COOLOFF_PARAM`]: one hundred and sixty-eight
/// epochs, seven days at one-hour epochs.
pub const DEFAULT_FEATURE_PAUSE_COOLOFF_EPOCHS: u64 = 168;

/// Genesis value of [`PAUSE_COOLOFF_PARAM`]: seven days.
pub const DEFAULT_PAUSE_COOLOFF_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Governed key: longest guardian term.
pub const GUARDIAN_MAX_TERM_PARAM: &str = "governance.guardian_max_term_ms";
/// Genesis value of [`GUARDIAN_MAX_TERM_PARAM`]: one year.
pub const DEFAULT_GUARDIAN_MAX_TERM_MS: u64 = 365 * 24 * 60 * 60 * 1000;
/// Governed key: how long a pause or resume signal counts.
pub const GUARDIAN_SIGNAL_WINDOW_PARAM: &str = "governance.guardian_signal_window_ms";
/// Genesis value of [`GUARDIAN_SIGNAL_WINDOW_PARAM`]: one hour.
pub const DEFAULT_GUARDIAN_SIGNAL_WINDOW_MS: u64 = 60 * 60 * 1000;

/// Governed key: routing standing for a live serving bond.
/// How long a passkey added to an account with fewer than two independent
/// roots waits before it counts as one, ms.
pub const KEYSTORE_ADD_DEVICE_WAIT_PARAM: &str = "keystore.add_device_wait_ms";
/// Recovery wait when a recovery key and an email verifier approved, ms.
pub const KEYSTORE_RECOVERY_WAIT_KEY_AND_EMAIL_PARAM: &str =
    "keystore.recovery_wait_key_and_email_ms";
/// Recovery wait when a recovery key approved without an email verifier, ms.
pub const KEYSTORE_RECOVERY_WAIT_KEY_PARAM: &str = "keystore.recovery_wait_key_ms";
/// Recovery wait for any other approval, ms.
pub const KEYSTORE_RECOVERY_WAIT_OTHER_PARAM: &str = "keystore.recovery_wait_other_ms";
/// Wait before a recovery started with the account's recovery code completes,
/// ms; any linked passkey can cancel it meanwhile.
pub const KEYSTORE_RECOVERY_CODE_WAIT_PARAM: &str = "keystore.recovery_code_wait_ms";
/// Least age of a recovery code claim before its code may be revealed, ms.
pub const KEYSTORE_RECOVERY_CODE_REVEAL_DELAY_PARAM: &str =
    "keystore.recovery_code_reveal_delay_ms";
/// Age at which a recovery code claim expires, ms.
pub const KEYSTORE_RECOVERY_CODE_CLAIM_TTL_PARAM: &str = "keystore.recovery_code_claim_ttl_ms";
/// Rounds between the anchor that closes a checkpoint and the first round
/// the seed it releases draws leaders for.
pub const CONSENSUS_LEADER_LOOKAHEAD_PARAM: &str = "consensus.leader_lookahead_rounds";
/// The most a sender's transactions wait on their assigned validator before
/// the next in turn may batch them, ms.
pub const CONSENSUS_SENDER_FAILOVER_PARAM: &str = "consensus.sender_failover_ms";
/// Verified-lane admission rate, transactions per second in thousandths.
pub const ADMISSION_VERIFIED_RATE_PARAM: &str = "admission.verified_rate_milli";
/// Verified-lane admission burst.
pub const ADMISSION_VERIFIED_BURST_PARAM: &str = "admission.verified_burst";
/// Delegated-lane admission rate, transactions per second in thousandths.
pub const ADMISSION_DELEGATED_RATE_PARAM: &str = "admission.delegated_rate_milli";
/// Delegated-lane admission burst.
pub const ADMISSION_DELEGATED_BURST_PARAM: &str = "admission.delegated_burst";
/// Open-lane admission rate, transactions per second in thousandths.
pub const ADMISSION_OPEN_RATE_PARAM: &str = "admission.open_rate_milli";
/// Open-lane admission burst.
pub const ADMISSION_OPEN_BURST_PARAM: &str = "admission.open_burst";
/// Verified-lane fee, bps of the base fee the next block charges.
pub const ADMISSION_VERIFIED_FEE_MULT_PARAM: &str = "admission.verified_fee_mult_bps";
/// Delegated-lane fee, bps of the base fee the next block charges.
pub const ADMISSION_DELEGATED_FEE_MULT_PARAM: &str = "admission.delegated_fee_mult_bps";
/// Open-lane fee, bps of the base fee the next block charges.
pub const ADMISSION_OPEN_FEE_MULT_PARAM: &str = "admission.open_fee_mult_bps";
/// JSON-RPC requests per second per network address.
pub const RPC_ADDRESS_RATE_PARAM: &str = "rpc.address_rate_per_second";
/// JSON-RPC burst per network address.
pub const RPC_ADDRESS_BURST_PARAM: &str = "rpc.address_burst";
/// Transaction submissions per second per address checked against the
/// sender's own quota once the address floor is spent.
pub const RPC_IDENTITY_CHECKS_PARAM: &str = "rpc.identity_checks_per_second";
pub const STANDING_BONDED_PARAM: &str = "routing.standing_bonded";
/// Genesis value of [`STANDING_BONDED_PARAM`].
pub const DEFAULT_STANDING_BONDED: u64 = 3_000;
/// Governed key: the most standing availability adds.
pub const STANDING_AVAILABILITY_PARAM: &str = "routing.standing_availability";
/// Genesis value of [`STANDING_AVAILABILITY_PARAM`].
pub const DEFAULT_STANDING_AVAILABILITY: u64 = 7_000;
/// Governed key: share of the availability standing held before any verdict.
pub const STANDING_UNJUDGED_BPS_PARAM: &str = "routing.standing_unjudged_bps";
/// Genesis value of [`STANDING_UNJUDGED_BPS_PARAM`]: half.
pub const DEFAULT_STANDING_UNJUDGED_BPS: u64 = 5_000;
/// Governed key: closed SLA hours that count.
pub const STANDING_WINDOW_HOURS_PARAM: &str = "routing.standing_window_hours";
/// Genesis value of [`STANDING_WINDOW_HOURS_PARAM`]: one day.
pub const DEFAULT_STANDING_WINDOW_HOURS: u64 = 24;

/// Look up a governed parameter by key.
pub fn governed_param(key: &str) -> Option<&'static GovernedParam> {
    GOVERNED_PARAMS.iter().find(|p| p.key == key)
}

/// Genesis value of a governed parameter, for a reader without chain state.
pub fn genesis_param(key: &str) -> u64 {
    governed_param(key).map_or(0, |p| p.genesis)
}

/// How urgent a proposal is, and therefore what it must clear.
///
/// One timing cannot suit every decision: either emergencies wait out a delay
/// designed for routine changes, or routine changes get no delay at all.
/// Cosmos added expedited proposals to "respond rapidly during emergency
/// situations while balancing protection of rights against abuse", and
/// Polkadot separates origins into tracks with their own durations.
///
/// The trade is explicit. Expedited is faster *and* harder — a shorter window
/// at the same threshold would just be a way to pass something while fewer
/// people are watching. An emergency worth the speed is one obviously right
/// enough to clear a higher bar in less time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProposalTrack {
    /// Full voting period, full timelock, ordinary threshold.
    #[default]
    Standard,
    /// Short voting period and timelock, higher threshold to compensate.
    Expedited,
    /// A contested proposal's second vote: three quarters in favour and a
    /// thirty-day timelock.
    Ratify,
    /// A protocol upgrade fixing a fault: the expedited window, timelock and
    /// threshold. Its readiness gate still applies.
    SecurityFix,
}

impl ProposalTrack {
    /// How long voting stays open on this track.
    pub fn voting_period_ms(&self, rules: &GovernanceRules) -> i64 {
        match self {
            ProposalTrack::Standard | ProposalTrack::Ratify => rules.voting_period_ms,
            ProposalTrack::Expedited | ProposalTrack::SecurityFix => {
                rules.expedited_voting_period_ms
            }
        }
    }

    /// The longest voting window governance may set on any track: how far
    /// back a vote may need a voter's bond.
    pub fn longest_voting_period_ms() -> i64 {
        governed_param(VOTING_PERIOD_PARAM)
            .map_or(VOTING_PERIOD_MS, |p| p.max as i64)
            .max(governed_param(EXPEDITED_VOTING_PERIOD_PARAM).map_or(0, |p| p.max as i64))
    }

    /// How long a passed proposal waits before it may execute.
    pub fn timelock_ms(&self, rules: &GovernanceRules) -> i64 {
        match self {
            ProposalTrack::Standard => rules.timelock_ms,
            ProposalTrack::Expedited | ProposalTrack::SecurityFix => rules.expedited_timelock_ms,
            ProposalTrack::Ratify => rules.ratify_timelock_ms,
        }
    }

    /// The share of participating stake that must be in favour.
    ///
    /// Higher on the expedited track, which is what pays for the shorter
    /// window.
    /// Never below the standard bar, whatever governance set.
    pub fn threshold_bps(&self, rules: &GovernanceRules) -> u64 {
        match self {
            ProposalTrack::Standard => rules.threshold_bps,
            ProposalTrack::Expedited | ProposalTrack::SecurityFix => {
                rules.expedited_threshold_bps.max(rules.threshold_bps)
            }
            ProposalTrack::Ratify => rules.ratify_threshold_bps.max(rules.threshold_bps),
        }
    }

    /// Stable label for logs and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalTrack::Standard => "standard",
            ProposalTrack::Expedited => "expedited",
            ProposalTrack::Ratify => "ratify",
            ProposalTrack::SecurityFix => "security_fix",
        }
    }
}

/// Whether `proposer_stake` is enough to open a proposal.
///
/// A fraction of bonded stake rather than an absolute, so it tracks the
/// network as it grows instead of becoming meaningless when stake inflates.
/// Zero total stake means a network with no validators, where the question
/// does not arise and refusing is the safe answer.
pub fn meets_proposal_threshold(
    proposer_stake: u128,
    total_bonded: u128,
    threshold_bps: u64,
) -> bool {
    if total_bonded == 0 {
        return false;
    }
    proposer_stake.saturating_mul(10_000) >= total_bonded.saturating_mul(u128::from(threshold_bps))
}

/// Where a proposal is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Accepting votes.
    Voting,
    /// Voting closed, quorum and threshold both met.
    Passed,
    /// Passed and waiting out the timelock. Executable once `eta_ms` is
    /// reached, and vetoable until then.
    Queued,
    /// Stopped during the timelock by a guardian. Terminal — a vetoed
    /// proposal is never executable, and re-proposing is the only route.
    Vetoed,
    /// Voting closed and it failed one of the two.
    Rejected,
    /// Passed and enacted. Terminal — an action applies exactly once.
    Executed,
    /// Holders locked the blocking share of supply against it in the veto
    /// escrow. It is voted on again on the Ratify track and accepts ballots
    /// until that window closes.
    Contested,
}

/// A governance proposal as consensus stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Hex proposal id, derived by the VM from proposer, action and nonce.
    pub id: String,
    /// Who submitted it.
    pub proposer: Address,
    /// Which track this runs on, fixing its voting window, timelock and
    /// threshold.
    ///
    /// Stored on the proposal rather than looked up at each step: the timing a
    /// proposal was opened under must not change underneath it because a
    /// parameter moved mid-vote.
    #[serde(default)]
    pub track: ProposalTrack,
    /// Earliest instant this may execute, set when it enters `Queued`.
    ///
    /// `None` while voting: a proposal that has not passed has no execution
    /// time, and defaulting it to zero would make an un-passed proposal look
    /// immediately executable to anything that checked the clock before the
    /// status.
    #[serde(default)]
    pub eta_ms: Option<i64>,
    /// What it does if it passes.
    pub action: ProposalAction,
    /// Block timestamp it was submitted under.
    pub created_ms: i64,
    /// Block timestamp after which votes are no longer accepted.
    pub voting_ends_ms: i64,
    /// Current state.
    pub status: ProposalStatus,
    /// When it entered the timelock.
    #[serde(default)]
    pub queued_ms: Option<i64>,
    /// How far the holders' veto escrow has stretched its timelock. Never
    /// shrinks.
    #[serde(default)]
    pub veto_extension_ms: i64,
    /// Distinct aged human roots that raised a concern while it was queued.
    #[serde(default)]
    pub concerns: u32,
    /// Whether the concerns doubled its timelock, which happens once only.
    #[serde(default)]
    pub concern_doubled: bool,
    /// The voting rules in force when it opened, which decide it.
    #[serde(default)]
    pub rules: GovernanceRules,
}

impl Proposal {
    /// Move a passed proposal into the timelock, fixing when it may execute.
    ///
    /// Separating \"carried\" from \"executable\" is the whole point: until this
    /// is called there is no instant anyone can act before. Returns false if
    /// the proposal is not in a state that can be queued, so a caller cannot
    /// re-queue an executed one and reset its clock.
    pub fn queue(&mut self, now_ms: i64) -> bool {
        if !matches!(self.status, ProposalStatus::Passed) {
            return false;
        }
        self.status = ProposalStatus::Queued;
        self.queued_ms = Some(now_ms);
        self.eta_ms = self.stretched_eta();
        true
    }

    /// What this commits out of the treasury: a grant's whole amount or
    /// a recovery drawn from the treasury. Zero for
    /// everything else, including the release of a tranche the grant itself
    /// committed.
    pub fn treasury_outflow(&self) -> u128 {
        match &self.action {
            // A stable payout is sized in USD and valued only against state,
            // so the vote treats it as the largest kind of spend: the
            // supermajority and the long timelock apply to every one.
            ProposalAction::TreasuryGrant { asset: Some(_), .. }
            | ProposalAction::SponsorOperatorStable { .. } => u128::MAX,
            ProposalAction::TreasuryGrant { amount, .. }
            | ProposalAction::SponsorOperatorRunningCost { amount, .. } => *amount,
            ProposalAction::TreasuryRemoteAction {
                payout: Some(_), ..
            } => u128::MAX,
            _ => 0,
        }
    }

    /// What this commits out of the treasury or its running-cost reserve.
    pub fn committed_outflow(&self) -> u128 {
        match &self.action {
            ProposalAction::RunningCostPayment { amount, .. } => *amount,
            _ => self.treasury_outflow(),
        }
    }

    /// Whether this commits at least the large-spend size in force when it
    /// opened out of the treasury or its running-cost reserve.
    pub fn is_large_spend(&self) -> bool {
        let outflow = self.committed_outflow();
        outflow > 0
            && outflow
                >= u128::from(self.rules.large_spend_tnzo).saturating_mul(1_000_000_000_000_000_000)
    }

    /// The outcome `tally` gives this proposal once voting has closed: its
    /// track's quorum and threshold, and for anything paid out of the
    /// treasury or its running-cost reserve, of any size, yes votes of at
    /// least the approval share of all eligible stake. Stake that votes
    /// while the rest stays away cannot pay itself, however little it asks.
    pub fn outcome(&self, tally: &Tally) -> ProposalStatus {
        let status = tally.outcome_on(self.track, &self.rules);
        if status == ProposalStatus::Passed
            && self.committed_outflow() > 0
            && tally.yes.saturating_mul(10_000)
                < tally
                    .total_eligible
                    .saturating_mul(u128::from(self.rules.large_spend_approval_bps))
        {
            return ProposalStatus::Rejected;
        }
        status
    }

    /// [`Proposal::outcome`], and for a change that loosens a capture guard
    /// (`loosens_guard`, judged against chain state by the caller), yes
    /// votes of at least the large-spend approval share of all eligible
    /// stake, as any treasury outflow needs. Tightening keeps the track's
    /// bars alone.
    pub fn outcome_guarded(&self, tally: &Tally, loosens_guard: bool) -> ProposalStatus {
        let status = self.outcome(tally);
        if status == ProposalStatus::Passed
            && loosens_guard
            && tally.yes.saturating_mul(10_000)
                < tally
                    .total_eligible
                    .saturating_mul(u128::from(self.rules.large_spend_approval_bps))
        {
            return ProposalStatus::Rejected;
        }
        status
    }

    /// When a queued proposal may execute: its track's timelock (doubled once
    /// by enough concerns) plus the holders' veto extension.
    pub fn stretched_eta(&self) -> Option<i64> {
        let queued = self.queued_ms?;
        let lock = self.track.timelock_ms(&self.rules);
        let lock = if self.is_large_spend() {
            lock.max(self.rules.large_spend_timelock_ms)
        } else {
            lock
        };
        let lock = if self.concern_doubled {
            lock.saturating_mul(2)
        } else {
            lock
        };
        Some(
            queued
                .saturating_add(lock)
                .saturating_add(self.veto_extension_ms),
        )
    }

    /// Where its ballots and tally live: the Ratify vote of a contested
    /// proposal starts from an empty tally.
    pub fn ballot_id(&self) -> String {
        match self.track {
            ProposalTrack::Ratify => format!("{}:ratify", self.id),
            _ => self.id.clone(),
        }
    }

    /// Stretch the timelock by the holders' veto escrow. The extension only
    /// grows, so withdrawing a lock after the decision changes nothing. The
    /// Ratify track's own thirty-day timelock is the holders' exit window, so
    /// it is not stretched further.
    pub fn extend_by_veto(&mut self, extension_ms: i64) {
        if self.track != ProposalTrack::Ratify && extension_ms > self.veto_extension_ms {
            self.veto_extension_ms = extension_ms;
            if self.status == ProposalStatus::Queued {
                self.eta_ms = self.stretched_eta();
            }
        }
    }

    /// Move a proposal the holders blocked to a fresh vote on the Ratify
    /// track. A Ratify vote is never contested again, and a decided
    /// proposal has nothing left to contest.
    pub fn contest(&mut self, now_ms: i64) -> bool {
        if self.track == ProposalTrack::Ratify
            || !matches!(
                self.status,
                ProposalStatus::Voting | ProposalStatus::Passed | ProposalStatus::Queued
            )
        {
            return false;
        }
        self.status = ProposalStatus::Contested;
        self.track = ProposalTrack::Ratify;
        self.voting_ends_ms =
            now_ms.saturating_add(ProposalTrack::Ratify.voting_period_ms(&self.rules));
        self.eta_ms = None;
        self.queued_ms = None;
        self.veto_extension_ms = 0;
        true
    }

    /// Count one more aged root's concern. Once concerns exceed `quorum`, the
    /// timelock doubles, once only. Returns whether this concern doubled it.
    pub fn raise_concern(&mut self, quorum: u64) -> bool {
        self.concerns = self.concerns.saturating_add(1);
        if self.concern_doubled || u64::from(self.concerns) <= quorum {
            return false;
        }
        self.concern_doubled = true;
        self.eta_ms = self.stretched_eta();
        true
    }

    /// True once the timelock has elapsed and this may be enacted.
    ///
    /// A queued proposal with no `eta_ms` is not executable. That combination
    /// should not arise, and treating it as ready would turn a bookkeeping
    /// slip into an immediate execution.
    pub fn is_executable_at(&self, now_ms: i64) -> bool {
        matches!(self.status, ProposalStatus::Queued)
            && matches!(self.eta_ms, Some(eta) if now_ms >= eta)
    }

    /// Stop a queued proposal during its timelock. Terminal.
    ///
    /// Only a queued proposal can be vetoed: before it carries there is
    /// nothing to stop, and after it executes there is nothing left to stop.
    pub fn veto(&mut self) -> bool {
        if !matches!(self.status, ProposalStatus::Queued) {
            return false;
        }
        self.status = ProposalStatus::Vetoed;
        true
    }

    /// Open a proposal for voting on the track its action runs on.
    pub fn open(
        id: String,
        proposer: Address,
        action: ProposalAction,
        created_ms: i64,
        rules: GovernanceRules,
    ) -> Self {
        let track = action.track();
        Self::open_on(id, proposer, action, created_ms, track, rules)
    }

    /// Open a proposal on an explicit track.
    pub fn open_on(
        id: String,
        proposer: Address,
        action: ProposalAction,
        created_ms: i64,
        track: ProposalTrack,
        rules: GovernanceRules,
    ) -> Self {
        Self {
            id,
            proposer,
            track,
            eta_ms: None,
            action,
            created_ms,
            voting_ends_ms: created_ms.saturating_add(track.voting_period_ms(&rules)),
            status: ProposalStatus::Voting,
            queued_ms: None,
            veto_extension_ms: 0,
            concerns: 0,
            concern_doubled: false,
            rules,
        }
    }

    /// Whether votes are still being accepted at `now_ms`.
    pub fn is_open_at(&self, now_ms: i64) -> bool {
        matches!(
            self.status,
            ProposalStatus::Voting | ProposalStatus::Contested
        ) && now_ms < self.voting_ends_ms
    }
}

/// Running vote totals for one proposal, in units of bonded stake.
///
/// Maintained incrementally as votes arrive rather than computed by scanning:
/// `VmState` exposes point lookups only, with no prefix iteration, so there is
/// no way to enumerate a proposal's voters at tally time. Keeping the totals as
/// running sums is what makes the tally computable at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tally {
    /// Stake voting in favour.
    pub yes: u128,
    /// Stake voting against.
    pub no: u128,
    /// Total stake bonded network-wide, the denominator for quorum.
    pub total_eligible: u128,
}

impl Tally {
    /// Stake that voted either way.
    pub fn participation(&self) -> u128 {
        self.yes.saturating_add(self.no)
    }

    /// Whether enough of the bonded stake showed up:
    /// `participation / total_eligible >= quorum_bps / 10_000`.
    pub fn quorum_met(&self, rules: &GovernanceRules) -> bool {
        if self.total_eligible == 0 {
            // No stake bonded anywhere means no electorate. A proposal cannot
            // clear a quorum of nothing — treating it as met would let the
            // treasury be drained on an empty network.
            return false;
        }
        share_at_least(self.participation(), self.total_eligible, rules.quorum_bps)
    }

    /// Whether the supermajority of participating stake is in favour.
    pub fn threshold_met(&self, rules: &GovernanceRules) -> bool {
        self.threshold_met_on(ProposalTrack::Standard, rules)
    }

    /// Whether the in-favour share clears the bar for `track`.
    ///
    /// The expedited track sets a higher bar, and that is what pays for its
    /// shorter window. A faster track at the same threshold would simply be a
    /// way to pass something while fewer people are watching.
    pub fn threshold_met_on(&self, track: ProposalTrack, rules: &GovernanceRules) -> bool {
        let participation = self.participation();
        if participation == 0 {
            return false;
        }
        share_at_least(self.yes, participation, track.threshold_bps(rules))
    }

    /// The outcome this tally implies on `track`, once voting has closed.
    pub fn outcome_on(&self, track: ProposalTrack, rules: &GovernanceRules) -> ProposalStatus {
        if self.quorum_met(rules) && self.threshold_met_on(track, rules) {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        }
    }

    /// The outcome this tally implies, once voting has closed.
    pub fn outcome(&self, rules: &GovernanceRules) -> ProposalStatus {
        if self.quorum_met(rules) && self.threshold_met(rules) {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        }
    }

    /// Why a tally failed, for an error a human can act on.
    pub fn failure_reason(&self, track: ProposalTrack, rules: &GovernanceRules) -> String {
        if !self.quorum_met(rules) {
            format!(
                "quorum not met: {} of {} bonded stake participated, need {} bps",
                self.participation(),
                self.total_eligible,
                rules.quorum_bps
            )
        } else {
            format!(
                "threshold not met: {} yes of {} cast, need {} bps",
                self.yes,
                self.participation(),
                track.threshold_bps(rules)
            )
        }
    }

    /// Apply a vote, replacing any previous vote by the same voter.
    ///
    /// `previous` is the voter's earlier `(weight, in_favour)` if they have
    /// already voted. Removing the old weight before adding the new one is what
    /// makes changing a vote safe: without it a validator could vote yes, vote
    /// no, and have both counted.
    pub fn apply_vote(&mut self, weight: u128, in_favour: bool, previous: Option<(u128, bool)>) {
        if let Some((old_weight, old_in_favour)) = previous {
            if old_in_favour {
                self.yes = self.yes.saturating_sub(old_weight);
            } else {
                self.no = self.no.saturating_sub(old_weight);
            }
        }
        if in_favour {
            self.yes = self.yes.saturating_add(weight);
        } else {
            self.no = self.no.saturating_add(weight);
        }
    }
}

/// Whether `part` is at least `bps` basis points of `whole`:
/// `part / whole >= bps / 10_000`, cross-multiplied to stay in integers.
///
/// Exact for every input: both products are taken in full width, so neither
/// can saturate or wrap into a different answer.
pub(crate) fn share_at_least(part: u128, whole: u128, bps: u64) -> bool {
    widening_mul(part, 10_000) >= widening_mul(whole, bps)
}

/// `a * b` in full, as its high and low 128 bits (the high part is below
/// 2^64). Compared as a tuple, the pair orders exactly as the products do.
fn widening_mul(a: u128, b: u64) -> (u128, u128) {
    let b = u128::from(b);
    // a = a_hi * 2^64 + a_lo, and each partial product fits in 128 bits.
    let lo = (a & u128::from(u64::MAX)) * b;
    let hi = (a >> 64) * b;
    let (low, carry) = lo.overflowing_add(hi << 64);
    ((hi >> 64) + u128::from(carry), low)
}

/// Decide a proposal whose voting window has closed.
///
/// Returns the terminal status, or an error if it is too early to ask.
pub fn decide(
    proposal: &Proposal,
    tally: &Tally,
    now_ms: i64,
) -> Result<ProposalStatus, GovernanceError> {
    if proposal.status == ProposalStatus::Executed {
        return Err(GovernanceError::AlreadyExecuted);
    }
    if now_ms < proposal.voting_ends_ms {
        return Err(GovernanceError::VotingStillOpen {
            ends_ms: proposal.voting_ends_ms,
            now_ms,
        });
    }
    // Judged on the proposal own track. Using the standard threshold here
    // would let an expedited proposal take the short window without paying
    // the higher bar that justifies it.
    Ok(proposal.outcome(tally))
}

/// [`decide`] for a proposal that `loosens_guard` says weakens a capture
/// guard against chain state: it also needs yes votes of the large-spend
/// approval share of all eligible stake.
pub fn decide_guarded(
    proposal: &Proposal,
    tally: &Tally,
    now_ms: i64,
    loosens_guard: bool,
) -> Result<ProposalStatus, GovernanceError> {
    decide(proposal, tally, now_ms)?;
    Ok(proposal.outcome_guarded(tally, loosens_guard))
}

#[cfg(test)]
mod share_tests {
    use super::share_at_least;

    /// The bar is met exactly at the share and missed one unit below it.
    #[test]
    fn the_share_is_met_exactly_at_the_bar() {
        assert!(share_at_least(1, 2, 5_000));
        assert!(!share_at_least(1, 2, 5_001));
        assert!(share_at_least(0, 0, u64::MAX));
        assert!(!share_at_least(0, 1, 1));
    }

    /// Where both products pass u128::MAX the answer is still exact: the
    /// least part that clears the bar clears it and one unit less does not.
    #[test]
    fn the_share_is_exact_past_u128_max() {
        for (bps, least) in [
            (
                6_667,
                226_866_254_026_189_673_591_031_850_774_759_866_578_u128,
            ),
            (10_000, u128::MAX),
            (1, 34_028_236_692_093_846_346_337_460_743_176_822),
        ] {
            assert!(share_at_least(least, u128::MAX, bps));
            assert!(!share_at_least(least - 1, u128::MAX, bps));
        }
        assert!(!share_at_least(u128::MAX, u128::MAX, 10_001));
        assert!(share_at_least(u128::MAX, u128::MAX / 2, 20_000));
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;

    fn revoke(did: &str, reason: &str) -> ProposalAction {
        ProposalAction::RevokeIdentity {
            did: did.to_string(),
            reason: reason.to_string(),
        }
    }

    /// A well-formed sanction passes submission validation.
    #[test]
    fn a_well_formed_revocation_validates() {
        revoke(
            "did:tenzro:human:a828941c-fe91-8250-af8b-a16527305188",
            "forged enrolment evidence; see proposal thread",
        )
        .validate()
        .unwrap();
    }

    /// A sanction nobody explained cannot later be told apart from an attack
    /// by whoever held the votes, so the reason is required rather than
    /// encouraged.
    #[test]
    fn a_revocation_without_a_reason_is_refused() {
        let err = revoke("did:tenzro:machine:x", "   ")
            .validate()
            .unwrap_err();
        assert!(matches!(err, GovernanceError::RevocationNeedsEvidence));
    }

    /// A revocation naming nobody, or naming something this network never
    /// issued, is refused before it can occupy a voting period.
    #[test]
    fn a_revocation_must_name_a_tenzro_identity() {
        assert!(matches!(
            revoke("  ", "because").validate().unwrap_err(),
            GovernanceError::RevocationNeedsSubject
        ));
        assert!(matches!(
            revoke("did:web:example.com", "because")
                .validate()
                .unwrap_err(),
            GovernanceError::NotATenzroDid { .. }
        ));
        assert!(matches!(
            revoke(
                &format!("did:tenzro:machine:{}", "x".repeat(MAX_DID_LEN)),
                "because"
            )
            .validate()
            .unwrap_err(),
            GovernanceError::TextTooLong { field: "did", .. }
        ));
        assert!(matches!(
            revoke("did:tenzro:machine:x", &"y".repeat(MAX_TEXT_LEN + 1))
                .validate()
                .unwrap_err(),
            GovernanceError::TextTooLong {
                field: "reason",
                ..
            }
        ));
    }

    /// Its own domain. `Treasury` would misdescribe it — it moves no value —
    /// and `Network` would import a reversibility it does not have.
    #[test]
    fn revocation_is_a_sanction_and_not_a_network_change() {
        assert_eq!(
            revoke("did:tenzro:machine:x", "because").domain(),
            ActionDomain::Sanction
        );
        assert_eq!(
            revoke("did:tenzro:machine:x", "because").kind(),
            "revoke_identity"
        );
    }

    /// **The boundary that decides who may strip a party's standing.** A vote
    /// for the middle agent phase said agents may tune the network. It did not
    /// say they may sanction anyone, and reading it that way would widen a
    /// decision the network already made.
    #[test]
    fn an_agent_may_not_sanction_below_the_phase_that_says_so() {
        assert!(!AgentPhase::None.permits(ActionDomain::Sanction));
        assert!(!AgentPhase::Network.permits(ActionDomain::Sanction));
        assert!(AgentPhase::All.permits(ActionDomain::Sanction));

        // And the middle phase still does what it was voted for.
        assert!(AgentPhase::Network.permits(ActionDomain::Network));
        assert!(!AgentPhase::Network.permits(ActionDomain::Treasury));
    }

    /// The record survives the wire, or a proposal would decode to a different
    /// action from the one that was voted on.
    #[test]
    fn a_revocation_survives_serialisation() {
        let a = revoke("did:tenzro:human:abc", "evidence");
        let bytes = serde_json::to_vec(&a).unwrap();
        let back: ProposalAction = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(a, back);
    }
}

#[cfg(test)]
mod large_spend_tests {
    use super::*;

    const TNZO: u128 = 1_000_000_000_000_000_000;

    fn grant(tnzo: u128) -> Proposal {
        Proposal::open(
            "p".into(),
            Address::default(),
            ProposalAction::TreasuryGrant {
                recipient: Address::new([2u8; 32]),
                amount: tnzo * TNZO,
                memo: "m".into(),
                category: String::new(),
                link: String::new(),
                tranches: Vec::new(),
                milestones: vec!["milestone".into()],
                vesting: GrantVesting::Liquid,
                asset: None,
                release: Default::default(),
            },
            0,
            GovernanceRules::GENESIS,
        )
    }

    #[test]
    fn two_thirds_of_eligible_stake_cannot_carry_a_large_spend() {
        let large = grant(u128::from(LARGE_SPEND_TNZO));
        assert!(large.is_large_spend());
        let two_thirds = Tally {
            yes: 6_668,
            no: 0,
            total_eligible: 10_000,
        };
        assert_eq!(large.outcome(&two_thirds), ProposalStatus::Rejected);
        let three_quarters = Tally {
            yes: 7_500,
            no: 0,
            total_eligible: 10_000,
        };
        assert_eq!(large.outcome(&three_quarters), ProposalStatus::Passed);
    }

    #[test]
    fn every_treasury_outflow_is_sized_against_the_large_spend() {
        let tnzo = 1_000_000_000_000_000_000u128;
        let large = u128::from(LARGE_SPEND_TNZO) * tnzo;
        let mut p = grant(1);
        // A payout sized in a stable asset is valued only against state, so
        // the vote treats every one as a large spend.
        p.action = ProposalAction::SponsorOperatorStable {
            operator: Address::new([9u8; 32]),
            from_epoch: 1,
            to_epoch: 2,
            token_id: format!("0x{}", "ab".repeat(32)),
            amount: 1,
            period_exception: false,
            memo: "m".into(),
        };
        assert_eq!(p.treasury_outflow(), u128::MAX);
        assert!(p.is_large_spend());
        // A recovery takes nothing from the treasury: it is not a source.
        p.action = ProposalAction::RecoverUnownedFunds {
            from: tenzro_types::network_treasury_address(),
            to: Address::new([9u8; 32]),
            amount: large,
            memo: "m".into(),
        };
        assert_eq!(p.treasury_outflow(), 0);
        assert!(p.action.validate().is_err());
        // A recovery from anywhere else takes nothing from the treasury.
        p.action = ProposalAction::RecoverUnownedFunds {
            from: Address::new([8u8; 32]),
            to: Address::new([9u8; 32]),
            amount: large,
            memo: "m".into(),
        };
        assert_eq!(p.treasury_outflow(), 0);
        assert!(!p.is_large_spend());
        p.action = ProposalAction::ParameterChange {
            key: QUORUM_PARAM.into(),
            value: 1,
            memo: "m".into(),
        };
        assert!(!p.is_large_spend());
    }

    #[test]
    fn treasury_guards_loosen_one_step_at_a_time() {
        let raise = DEFAULT_MAX_CAP_RAISE_BPS;
        // Caps that loosen upwards: at most double.
        assert!(cap_change_allowed(MAX_PERIOD_OUTFLOW_PARAM, 300, 600, raise).is_ok());
        assert!(cap_change_allowed(MAX_PERIOD_OUTFLOW_PARAM, 300, 601, raise).is_err());
        assert!(cap_change_allowed(LARGE_SPEND_PARAM, 100_000, 200_001, raise).is_err());
        assert!(
            cap_change_allowed(
                crate::native::insurance::MAX_CLAIM_BPS_PARAM,
                1_000,
                2_001,
                raise
            )
            .is_err()
        );
        // Bars and windows that loosen downwards: at most halved.
        assert!(cap_change_allowed(MIN_BOND_AGE_PARAM, 1_000, 499, raise).is_err());
        assert!(cap_change_allowed(OUTFLOW_PERIOD_PARAM, 30, 15, raise).is_ok());
        assert!(cap_change_allowed(OUTFLOW_PERIOD_PARAM, 30, 14, raise).is_err());
        assert!(cap_change_allowed(GUARD_LOOSENING_GRACE_PARAM, 2_160, 1_079, raise).is_err());
        // Tightening is never limited by the step.
        assert!(cap_change_allowed(MAX_PERIOD_OUTFLOW_PARAM, 300, 1, raise).is_ok());
        assert!(cap_change_allowed(OUTFLOW_PERIOD_PARAM, 30, 3_000, raise).is_ok());
        // A key that guards nothing is not limited.
        assert!(cap_change_allowed(QUORUM_PARAM, 3_334, 9_000, raise).is_ok());
    }

    #[test]
    fn only_a_loosening_guard_change_waits_the_guard_grace() {
        assert!(loosens_guard(MAX_PERIOD_OUTFLOW_PARAM, 300, 301));
        assert!(!loosens_guard(MAX_PERIOD_OUTFLOW_PARAM, 300, 299));
        assert!(loosens_guard(LARGE_SPEND_APPROVAL_PARAM, 7_500, 7_499));
        assert!(!loosens_guard(LARGE_SPEND_APPROVAL_PARAM, 7_500, 7_500));
        assert!(loosens_guard(MIN_BOND_AGE_PARAM, 10, 9));
        assert!(loosens_guard(GUARD_LOOSENING_GRACE_PARAM, 2_160, 2_000));
        assert!(loosens_guard(QUORUM_PARAM, 3_334, 1));
        assert!(!loosens_guard(QUORUM_PARAM, 3_334, 3_335));
        assert!(!loosens_guard(VOTING_PERIOD_PARAM, 7, 1));
        for key in [
            MAX_PROPOSAL_OUTFLOW_PARAM,
            MAX_PERIOD_OUTFLOW_PARAM,
            OUTFLOW_PERIOD_PARAM,
            LARGE_SPEND_PARAM,
            LARGE_SPEND_APPROVAL_PARAM,
            LARGE_SPEND_TIMELOCK_PARAM,
            MIN_BOND_AGE_PARAM,
            MAX_CAP_RAISE_PARAM,
            GUARD_LOOSENING_GRACE_PARAM,
            crate::native::insurance::MAX_CLAIM_BPS_PARAM,
            crate::native::insurance::MAX_CLAIM_TNZO_PARAM,
            crate::native::treasury_reserve::DRAWDOWN_PARAM,
            crate::native::treasury_reserve::REVENUE_SHARE_PARAM,
            crate::native::treasury_reserve::MONTH_EPOCHS_PARAM,
            crate::native::treasury_reserve::MAX_SALE_PARAM,
            crate::native::treasury_reserve::GRANT_FLOOR_PARAM,
            crate::native::insurance::MAX_PAID_EPOCH_PARAM,
        ] {
            assert!(governed_param(key).is_some(), "{key} is governed");
            assert!(capture_guard(key).is_some(), "{key} is a guard");
        }
    }

    /// Stake bought cheap after a crash, aged past the bond age, must not
    /// loosen the rules that bound issuance, slashing, exits, the fee rate or
    /// the vote itself any faster than a treasury guard: one step, after the
    /// guard grace, so every other holder sees it coming and can leave.
    #[test]
    fn crash_bought_stake_loosens_economic_safety_one_step_after_the_grace() {
        use crate::native::{bridge_committee, economy, rewards, role_stake, staking};
        let raise = DEFAULT_MAX_CAP_RAISE_BPS;
        for (key, current, looser, tighter) in [
            (rewards::MINT_BASE_PARAM, 60_000_000, 60_000_001, 59_999_999),
            (rewards::MINT_FLOOR_PARAM, 10_000_000, 10_000_001, 9_999_999),
            (rewards::MINT_MAX_MULT_PARAM, 15_000, 15_001, 14_999),
            (rewards::MINT_DECAY_PARAM, 1_500, 1_499, 1_501),
            (rewards::VALIDATOR_BASE_CAP_PARAM, 20_000, 20_001, 19_999),
            (rewards::VALIDATOR_BASE_COST_PARAM, 1_500, 1_501, 1_499),
            (rewards::VALIDATOR_BURN_SHARE_PARAM, 2_500, 2_501, 2_499),
            (economy::RATE_MAX_CHANGE_PARAM, 100, 101, 99),
            (economy::RATE_QUORUM_PARAM, 6_667, 6_666, 6_668),
            (economy::RATE_MAX_FALL_PARAM, 500, 499, 501),
            (economy::SAFETY_RATE_WINDOW_PARAM, 24, 23, 25),
            (
                role_stake::BOND_FLOOR_RATE_PARAM,
                100_000_000,
                99_999_999,
                100_000_001,
            ),
            (
                crate::native::security::MIN_RATIO_PARAM,
                15_000,
                14_999,
                15_001,
            ),
            (
                crate::native::security::ATTACK_STAKE_PARAM,
                3_000,
                3_001,
                2_999,
            ),
            (crate::native::security::ATTACK_WINDOW_PARAM, 24, 23, 25),
            (crate::native::security::GAMMA_PARAM, 10_000, 9_999, 10_001),
            (
                staking::UNBONDING_PARAM,
                604_800_000,
                604_799_999,
                604_800_001,
            ),
            (
                role_stake::UNBONDING_MS_PARAM,
                604_800_000,
                604_799_999,
                604_800_001,
            ),
            (staking::EQUIVOCATION_MIN_SLASH_PARAM, 500, 499, 501),
            (staking::CORRELATION_MULTIPLIER_PARAM, 3, 2, 4),
            (
                bridge_committee::EQUIVOCATION_SLASH_PARAM,
                9_000,
                8_999,
                9_001,
            ),
            (rewards::MINT_MIN_MULT_PARAM, 5_000, 5_001, 4_999),
            (staking::CORRELATION_WINDOW_PARAM, 100, 99, 101),
            (
                crate::native::inference_fault::CATALOG_FAULT_SLASH_BPS_PARAM,
                1_000,
                999,
                1_001,
            ),
            (
                crate::native::payment_settlement::plan::ATTESTOR_SLASH_PARAM,
                1_000,
                999,
                1_001,
            ),
            (QUORUM_PARAM, 3_334, 3_333, 3_335),
            (THRESHOLD_PARAM, 5_001, 5_000, 5_002),
            (EXPEDITED_THRESHOLD_PARAM, 6_667, 6_666, 6_668),
            (RATIFY_THRESHOLD_PARAM, 6_667, 6_666, 6_668),
        ] {
            assert!(governed_param(key).is_some(), "{key} is governed");
            assert!(
                loosens_guard(key, current, looser),
                "{key} {current}->{looser}"
            );
            assert!(
                !loosens_guard(key, current, tighter),
                "{key} {current}->{tighter}"
            );
        }
        // One step: issuance at most doubles, a quorum at most halves.
        assert!(cap_change_allowed(rewards::MINT_BASE_PARAM, 100, 201, raise).is_err());
        assert!(cap_change_allowed(rewards::MINT_BASE_PARAM, 100, 200, raise).is_ok());
        assert!(cap_change_allowed(QUORUM_PARAM, 3_334, 1, raise).is_err());
        assert!(cap_change_allowed(QUORUM_PARAM, 3_334, 1_667, raise).is_ok());
    }

    #[test]
    fn a_loosening_still_in_its_grace_is_no_base_for_another_step() {
        use crate::native::rewards::MINT_BASE_PARAM;
        // In force 100, a doubling to 200 scheduled: the next step is still
        // measured from 100, so back-to-back proposals cannot reach 400.
        assert_eq!(guard_step_base(MINT_BASE_PARAM, 100, 200), 100);
        assert_eq!(guard_step_base(QUORUM_PARAM, 3_334, 1_667), 3_334);
        // A scheduled tightening is the base: it is the stricter value.
        assert_eq!(guard_step_base(MINT_BASE_PARAM, 100, 50), 50);
        assert_eq!(guard_step_base(QUORUM_PARAM, 3_334, 5_000), 5_000);
        // Keys that guard nothing step from the scheduled value as before.
        assert_eq!(guard_step_base(VOTING_PERIOD_PARAM, 7, 9), 9);
        let raise = DEFAULT_MAX_CAP_RAISE_BPS;
        let base = guard_step_base(MINT_BASE_PARAM, 100, 200);
        assert!(cap_change_allowed(MINT_BASE_PARAM, base, 400, raise).is_err());
        assert!(cap_change_allowed(MINT_BASE_PARAM, base, 200, raise).is_ok());
    }

    /// Eleven of twenty-one equal validators vote yes at 22% honest turnout:
    /// quorum and the two-thirds-of-voters bar are met, yet a payment of any
    /// size fails because the yes votes are not three quarters of all
    /// eligible stake.
    #[test]
    fn a_bare_majority_at_low_turnout_cannot_carry_a_large_spend() {
        let tally = Tally {
            yes: 11,
            no: 2,
            total_eligible: 21,
        };
        let large = grant(u128::from(LARGE_SPEND_TNZO) * 100);
        assert!(large.is_large_spend());
        assert_eq!(
            tally.outcome_on(large.track, &large.rules),
            ProposalStatus::Passed
        );
        assert_eq!(large.outcome(&tally), ProposalStatus::Rejected);
        let small = grant(1);
        assert!(!small.is_large_spend());
        assert_eq!(small.outcome(&tally), ProposalStatus::Rejected);
        let broad = Tally {
            yes: 16,
            no: 1,
            total_eligible: 21,
        };
        assert_eq!(large.outcome(&broad), ProposalStatus::Passed);
        assert_eq!(small.outcome(&broad), ProposalStatus::Passed);
    }

    /// Thirteen of twenty-one validators propose a small grant to
    /// themselves and the rest barely vote: the track's bars are met, but
    /// thirteen is short of three quarters of all eligible stake.
    #[test]
    fn a_coalition_short_of_the_approval_cannot_pay_itself_a_small_grant() {
        let small = grant(5_000);
        assert!(!small.is_large_spend());
        for no in [0, 2, 4] {
            let tally = Tally {
                yes: 13,
                no,
                total_eligible: 21,
            };
            assert_eq!(
                tally.outcome_on(small.track, &small.rules),
                ProposalStatus::Passed
            );
            assert_eq!(small.outcome(&tally), ProposalStatus::Rejected);
        }
        // A parameter change moves nothing and keeps the track's bars alone.
        let mut change = grant(1);
        change.action = ProposalAction::ParameterChange {
            key: QUORUM_PARAM.into(),
            value: 4_000,
            memo: "m".into(),
        };
        let tally = Tally {
            yes: 13,
            no: 0,
            total_eligible: 21,
        };
        assert_eq!(change.outcome(&tally), ProposalStatus::Passed);
    }

    /// Loosening an economic safety bound needs three quarters of all
    /// eligible stake, as a large spend does; tightening the same bound, or
    /// changing a parameter that is not a guard, keeps the track's bars.
    #[test]
    fn loosening_a_safety_bound_needs_three_quarters_of_eligible_stake() {
        use crate::native::economy;
        let mut change = grant(1);
        change.action = ProposalAction::ParameterChange {
            key: economy::RATE_MAX_CHANGE_PARAM.into(),
            value: 101,
            memo: "m".into(),
        };
        let loosens = loosens_guard(economy::RATE_MAX_CHANGE_PARAM, 100, 101);
        assert!(loosens);
        let two_thirds = Tally {
            yes: 6_668,
            no: 0,
            total_eligible: 10_000,
        };
        assert_eq!(change.outcome(&two_thirds), ProposalStatus::Passed);
        assert_eq!(
            change.outcome_guarded(&two_thirds, loosens),
            ProposalStatus::Rejected
        );
        let three_quarters = Tally {
            yes: 7_500,
            no: 0,
            total_eligible: 10_000,
        };
        assert_eq!(
            change.outcome_guarded(&three_quarters, loosens),
            ProposalStatus::Passed
        );
        let tightens = loosens_guard(economy::RATE_MAX_CHANGE_PARAM, 100, 99);
        assert!(!tightens);
        assert_eq!(
            change.outcome_guarded(&two_thirds, tightens),
            ProposalStatus::Passed
        );
        for (key, current, looser) in [
            (economy::RATE_BREAKER_SPREAD_PARAM, 500, 501),
            (economy::RATE_BREAKER_GAP_PARAM, 5_000, 5_001),
            (economy::RATE_BREAKER_EPOCHS_PARAM, 3, 4),
            (economy::RATE_MIN_SOURCES_PARAM, 3, 2),
            (economy::RATE_UNOPENED_SLASH_PARAM, 10, 9),
            (economy::RATE_QUANTILE_LOW_PARAM, 3_334, 3_333),
            (economy::RATE_QUANTILE_HIGH_PARAM, 6_666, 6_667),
            (economy::RATE_STALE_QUORUM_PARAM, 5_001, 5_000),
            (crate::native::staking::EXIT_CHURN_PARAM, 400, 401),
            (MAX_PERIOD_OUTFLOW_PARAM, 300, 301),
        ] {
            assert!(governed_param(key).is_some(), "{key} is governed");
            assert!(loosens_guard(key, current, looser), "{key} loosens");
        }
        let start = Proposal::open(
            "p".into(),
            Address::default(),
            change.action.clone(),
            0,
            GovernanceRules::GENESIS,
        );
        assert_eq!(
            decide_guarded(&start, &two_thirds, VOTING_PERIOD_MS * 2, true),
            Ok(ProposalStatus::Rejected)
        );
    }

    #[test]
    fn a_large_spend_waits_the_large_spend_timelock() {
        let mut large = grant(u128::from(LARGE_SPEND_TNZO));
        large.status = ProposalStatus::Passed;
        assert!(large.queue(0));
        assert_eq!(large.eta_ms, Some(LARGE_SPEND_TIMELOCK_MS));
        let mut small = grant(1);
        small.status = ProposalStatus::Passed;
        assert!(small.queue(0));
        assert_eq!(small.eta_ms, Some(TIMELOCK_DELAY_MS));
    }
}

#[cfg(test)]
mod guardian_tests {
    use super::*;

    fn queued() -> Proposal {
        let mut p = Proposal::open(
            "p1".into(),
            Address::default(),
            ProposalAction::TreasuryGrant {
                recipient: Address::new([2u8; 32]),
                amount: 100,
                memo: "test".into(),
                category: String::new(),
                link: String::new(),
                tranches: Vec::new(),
                milestones: vec!["milestone".into()],
                vesting: GrantVesting::Liquid,
                asset: None,
                release: Default::default(),
            },
            0,
            GovernanceRules::GENESIS,
        );
        p.status = ProposalStatus::Passed;
        assert!(p.queue(0));
        p
    }

    /// The case the whole layer exists for: an agent's decision has carried,
    /// and a human can still stop it before it lands.
    #[test]
    fn a_governance_guardian_can_veto_a_queued_proposal() {
        let p = queued();
        assert!(may_veto(Some(GuardianRole::Governance), &p).is_ok());
    }

    /// Powers are separate on purpose. A protocol guardian can pause the
    /// network but must not be able to kill one specific decision — that is a
    /// different job with a different blast radius.
    #[test]
    fn a_protocol_guardian_cannot_veto() {
        let p = queued();
        assert_eq!(
            may_veto(Some(GuardianRole::Protocol), &p),
            Err(VetoRefusal::WrongRole(GuardianRole::Protocol))
        );
    }

    #[test]
    fn a_non_guardian_cannot_veto() {
        let p = queued();
        assert_eq!(may_veto(None, &p), Err(VetoRefusal::NotAGuardian));
    }

    /// Before it carries there is nothing to stop.
    #[test]
    fn a_proposal_still_voting_cannot_be_vetoed() {
        let p = Proposal::open(
            "p2".into(),
            Address::default(),
            ProposalAction::TreasuryGrant {
                recipient: Address::new([2u8; 32]),
                amount: 100,
                memo: "test".into(),
                category: String::new(),
                link: String::new(),
                tranches: Vec::new(),
                milestones: vec!["milestone".into()],
                vesting: GrantVesting::Liquid,
                asset: None,
                release: Default::default(),
            },
            0,
            GovernanceRules::GENESIS,
        );
        assert_eq!(
            may_veto(Some(GuardianRole::Governance), &p),
            Err(VetoRefusal::NotQueued(ProposalStatus::Voting))
        );
    }

    /// After it executes there is nothing left to stop. Allowing this would
    /// let a guardian rewrite history rather than prevent it.
    #[test]
    fn an_executed_proposal_cannot_be_vetoed() {
        let mut p = queued();
        p.status = ProposalStatus::Executed;
        assert_eq!(
            may_veto(Some(GuardianRole::Governance), &p),
            Err(VetoRefusal::NotQueued(ProposalStatus::Executed))
        );
    }

    /// A veto is terminal, and a vetoed proposal must never become executable
    /// again — re-proposing puts it back in front of voters instead.
    #[test]
    fn a_vetoed_proposal_is_terminal_and_never_executable() {
        let mut p = queued();
        assert!(p.veto());
        assert_eq!(p.status, ProposalStatus::Vetoed);
        assert!(
            !p.is_executable_at(i64::MAX),
            "a vetoed proposal became executable"
        );
        assert!(!p.veto(), "vetoing twice must not succeed");
    }

    /// The timelock is what gives the human layer somewhere to act: the
    /// proposal has carried, and is still not executable.
    #[test]
    fn a_queued_proposal_is_not_executable_until_its_eta() {
        let p = queued();
        assert!(!p.is_executable_at(TIMELOCK_DELAY_MS - 1));
        assert!(p.is_executable_at(TIMELOCK_DELAY_MS));
    }

    /// The starting position: agents originate nothing until a vote says
    /// otherwise. A permissive default would decide by omission the question
    /// of whether they should be trusted at all.
    #[test]
    fn agents_propose_nothing_by_default() {
        let phase = AgentPhase::default();
        assert_eq!(phase, AgentPhase::None);
        assert!(!phase.permits(ActionDomain::Network));
        assert!(!phase.permits(ActionDomain::Treasury));
    }

    /// The phase the network starts agents on: network decisions, which are
    /// reversible, and nothing that moves value.
    #[test]
    fn the_network_phase_excludes_the_treasury() {
        let phase = AgentPhase::Network;
        assert!(phase.permits(ActionDomain::Network));
        assert!(
            !phase.permits(ActionDomain::Treasury),
            "an agent reached the treasury at the network phase"
        );
    }

    /// A treasury grant is a treasury action, so an agent cannot originate one
    /// before the phase explicitly allows it.
    #[test]
    fn a_treasury_grant_is_classified_as_treasury() {
        let action = ProposalAction::TreasuryGrant {
            recipient: Address::new([2u8; 32]),
            amount: 1,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        assert_eq!(action.domain(), ActionDomain::Treasury);
        assert!(!AgentPhase::Network.permits(action.domain()));
        assert!(AgentPhase::All.permits(action.domain()));
    }

    /// A parameter change is a network decision, so an agent may originate
    /// one at the network phase while the treasury stays closed to it.
    #[test]
    fn a_parameter_change_is_a_network_action() {
        let a = ProposalAction::ParameterChange {
            key: "agent.remote_grant_budget_divisor".into(),
            value: 4,
            memo: String::new(),
        };
        assert_eq!(a.domain(), ActionDomain::Network);
        assert!(AgentPhase::Network.permits(a.domain()));
        assert!(a.validate().is_ok());
    }

    /// A value that cannot work is refused when it is written, not after it
    /// has carried a vote. Discovering it at enactment means the failure lands
    /// where nobody is watching.
    #[test]
    fn an_out_of_range_parameter_is_refused_at_submission() {
        let a = ProposalAction::ParameterChange {
            key: "agent.remote_grant_budget_divisor".into(),
            value: 0,
            memo: String::new(),
        };
        assert!(matches!(
            a.validate(),
            Err(GovernanceError::ParameterOutOfRange { .. })
        ));
    }

    #[test]
    fn an_unknown_parameter_is_refused() {
        let a = ProposalAction::ParameterChange {
            key: "consensus.does_not_exist".into(),
            value: 1,
            memo: String::new(),
        };
        assert!(matches!(
            a.validate(),
            Err(GovernanceError::UnknownParameter { .. })
        ));
    }

    /// Bounds must leave a working network at both ends, and the network
    /// must start inside them.
    #[test]
    fn every_governed_parameter_has_a_sane_range() {
        let mut seen = std::collections::BTreeSet::new();
        for p in GOVERNED_PARAMS {
            assert!(seen.insert(p.key), "{}: listed twice", p.key);
            assert!(p.min <= p.max, "{}: min exceeds max", p.key);
            assert!(
                (p.min..=p.max).contains(&p.genesis),
                "{}: genesis value {} is outside {}..={}",
                p.key,
                p.genesis,
                p.min,
                p.max
            );
            assert!(
                !p.description.is_empty(),
                "{}: no description to vote on",
                p.key
            );
        }
    }

    /// Over twenty years of monthly proposals, each lowering the validator
    /// unbonding period as far as one step allows, it never falls below the
    /// standard voting period plus its timelock, and neither of those may
    /// rise past it: stake that votes is still bonded when its decision
    /// takes effect.
    #[test]
    fn stake_that_votes_stays_bonded_until_its_decision_takes_effect() {
        use crate::native::staking::UNBONDING_PARAM;
        let mut values: std::collections::HashMap<&str, u64> = [
            UNBONDING_PARAM,
            VOTING_PERIOD_PARAM,
            TIMELOCK_PARAM,
            EXPEDITED_VOTING_PERIOD_PARAM,
            EXPEDITED_TIMELOCK_PARAM,
            crate::native::bridge_watcher::PAUSE_MS_PARAM,
            crate::native::bridge_watcher::REVIEW_MS_PARAM,
        ]
        .into_iter()
        .map(|k| (k, genesis_param(k)))
        .collect();
        let min = governed_param(UNBONDING_PARAM).unwrap().min;
        for _ in 0..240 {
            let current = values[UNBONDING_PARAM];
            let mut want = (current / 2).max(min);
            while want < current {
                let scheduled = |k: &str| values[k];
                if cap_change_allowed(UNBONDING_PARAM, current, want, DEFAULT_MAX_CAP_RAISE_BPS)
                    .is_ok()
                    && joint_change_allowed(UNBONDING_PARAM, want, &scheduled).is_ok()
                {
                    break;
                }
                want += 60 * 60 * 1000;
            }
            values.insert(UNBONDING_PARAM, want.min(current));
        }
        let (unbonding, voting, timelock) = (
            values[UNBONDING_PARAM],
            values[VOTING_PERIOD_PARAM],
            values[TIMELOCK_PARAM],
        );
        assert!(
            unbonding >= voting + timelock,
            "unbonding drifted to {unbonding} ms, below voting {voting} ms plus timelock {timelock} ms"
        );
        let scheduled = |k: &str| values[k];
        assert!(
            joint_change_allowed(VOTING_PERIOD_PARAM, unbonding - timelock + 1, &scheduled)
                .is_err()
        );
        assert!(joint_change_allowed(TIMELOCK_PARAM, unbonding - voting + 1, &scheduled).is_err());
    }

    /// No setting the registry allows breaks a joint rule at genesis, and the
    /// joint rules refuse exactly the settings past their bound.
    #[test]
    fn joint_rules_hold_at_genesis_and_refuse_past_their_bound() {
        use crate::native::economy::ACTIVITY_REWARD_FEE_PARAM;
        use crate::native::inference_fault::{PENALTY_PAYMENT_PARAM, SAMPLE_BPS_PARAM};
        use crate::native::rewards::PROVIDER_REWARD_COST_PARAM;
        let genesis = |k: &str| genesis_param(k);
        for p in GOVERNED_PARAMS {
            assert!(
                joint_change_allowed(p.key, p.genesis, &genesis).is_ok(),
                "{} breaks a joint rule at genesis",
                p.key
            );
        }
        assert!(joint_change_allowed(PROVIDER_REWARD_COST_PARAM, 4_000, &genesis).is_ok());
        assert!(joint_change_allowed(PROVIDER_REWARD_COST_PARAM, 4_001, &genesis).is_err());
        assert!(joint_change_allowed(ACTIVITY_REWARD_FEE_PARAM, 5_001, &genesis).is_err());
        assert!(joint_change_allowed(ACTIVITY_REWARD_FEE_PARAM, 0, &genesis).is_ok());
        // The royalty shares the same room: none is left at genesis, and
        // lowering the activity reward makes some.
        use crate::native::economy::CREATOR_ROYALTY_FEE_PARAM;
        assert_eq!(genesis_param(CREATOR_ROYALTY_FEE_PARAM), 0);
        assert!(joint_change_allowed(CREATOR_ROYALTY_FEE_PARAM, 1, &genesis).is_err());
        let lower_activity = |k: &str| {
            if k == ACTIVITY_REWARD_FEE_PARAM {
                4_000
            } else {
                genesis_param(k)
            }
        };
        assert!(joint_change_allowed(CREATOR_ROYALTY_FEE_PARAM, 1_000, &lower_activity).is_ok());
        assert!(joint_change_allowed(CREATOR_ROYALTY_FEE_PARAM, 1_001, &lower_activity).is_err());
        assert!(joint_change_allowed(SAMPLE_BPS_PARAM, 499, &genesis).is_err());
        assert!(joint_change_allowed(SAMPLE_BPS_PARAM, 500, &genesis).is_ok());
        assert!(joint_change_allowed(PENALTY_PAYMENT_PARAM, 199_999, &genesis).is_err());
        assert!(joint_change_allowed(PENALTY_PAYMENT_PARAM, 100_000_000, &genesis).is_ok());
        // The hardware bonus band: levels never decrease, and the cap never
        // lets a settlement's rewards with the bonus reach 9500 of its fee.
        {
            use crate::native::hardware_level::{
                LEVEL_BONUS_CAP_PARAM, LEVEL1_BONUS_PARAM, LEVEL2_BONUS_PARAM, MAX_LEVEL_BONUS_BPS,
            };
            assert!(joint_change_allowed(LEVEL1_BONUS_PARAM, 201, &genesis).is_err());
            assert!(joint_change_allowed(LEVEL2_BONUS_PARAM, 99, &genesis).is_err());
            assert!(joint_change_allowed(LEVEL1_BONUS_PARAM, 200, &genesis).is_ok());
            assert!(
                joint_change_allowed(LEVEL_BONUS_CAP_PARAM, MAX_LEVEL_BONUS_BPS, &genesis).is_ok()
            );
            let provider_heavy = |k: &str| match k {
                k if k == PROVIDER_REWARD_COST_PARAM => 9_000,
                k if k == ACTIVITY_REWARD_FEE_PARAM => 0,
                k => genesis_param(k),
            };
            assert!(joint_change_allowed(LEVEL_BONUS_CAP_PARAM, 556, &provider_heavy).is_ok());
            assert!(joint_change_allowed(LEVEL_BONUS_CAP_PARAM, 557, &provider_heavy).is_err());
            let capped = |k: &str| {
                if k == LEVEL_BONUS_CAP_PARAM {
                    MAX_LEVEL_BONUS_BPS
                } else {
                    genesis_param(k)
                }
            };
            assert!(joint_change_allowed(ACTIVITY_REWARD_FEE_PARAM, 3_000, &capped).is_ok());
            assert!(joint_change_allowed(PROVIDER_REWARD_COST_PARAM, 4_000, &capped).is_ok());
        }
        // Every reachable pair of reward settings stays below the whole fee.
        let (pm, am) = (
            governed_param(PROVIDER_REWARD_COST_PARAM).unwrap().max,
            governed_param(ACTIVITY_REWARD_FEE_PARAM).unwrap().max,
        );
        for p in (0..=pm).step_by(250) {
            for a in (0..=am).step_by(250) {
                let other = |k: &str| {
                    if k == ACTIVITY_REWARD_FEE_PARAM {
                        a
                    } else {
                        genesis_param(k)
                    }
                };
                if joint_change_allowed(PROVIDER_REWARD_COST_PARAM, p, &other).is_ok() {
                    assert!(p + a < 10_000);
                }
            }
        }
    }

    fn recovery(from: Address, to: Address, amount: u128, memo: &str) -> ProposalAction {
        ProposalAction::RecoverUnownedFunds {
            from,
            to,
            amount,
            memo: memo.into(),
        }
    }

    /// Recovery moves value, so it is a treasury action: behind the timelock,
    /// vetoable, and closed to agents at every phase short of `All`.
    #[test]
    fn recovery_is_a_treasury_action_closed_to_agents() {
        let a = recovery(
            crate::native::vault_recovery_address(),
            tenzro_types::network_treasury_address(),
            10,
            "vault imbalance",
        );
        assert_eq!(a.domain(), ActionDomain::Treasury);
        assert!(!AgentPhase::None.permits(a.domain()));
        assert!(
            !AgentPhase::Network.permits(a.domain()),
            "an agent could reach a recovery at the network phase"
        );
        assert!(a.validate().is_ok());
    }

    /// A recovery nobody explained is a transfer. The memo carries the
    /// evidence and is what a voter is actually being asked to judge.
    #[test]
    fn a_recovery_without_evidence_is_refused() {
        let a = recovery(
            crate::native::vault_recovery_address(),
            tenzro_types::network_treasury_address(),
            10,
            "   ",
        );
        assert!(matches!(
            a.validate(),
            Err(GovernanceError::RecoveryNeedsEvidence)
        ));
    }

    #[test]
    fn a_recovery_to_its_own_source_is_refused() {
        let same = Address::new([1u8; 32]);
        assert!(matches!(
            recovery(same, same, 10, "why").validate(),
            Err(GovernanceError::RecoveryToSelf)
        ));
    }

    #[test]
    fn a_zero_recovery_is_refused() {
        let a = recovery(Address::new([1u8; 32]), Address::new([2u8; 32]), 0, "why");
        assert!(matches!(a.validate(), Err(GovernanceError::ZeroAmount)));
    }

    // ---- pause ----------------------------------------------------------

    #[test]
    fn a_protocol_guardian_can_pause_and_resume() {
        assert!(may_set_pause(Some(GuardianRole::Protocol), false, true).is_ok());
        assert!(may_set_pause(Some(GuardianRole::Protocol), true, false).is_ok());
    }

    /// Powers stay separate in both directions: the guardian who can veto a
    /// specific decision must not be able to halt every decision.
    #[test]
    fn a_governance_guardian_cannot_pause() {
        assert_eq!(
            may_set_pause(Some(GuardianRole::Governance), false, true),
            Err(PauseRefusal::WrongRole(GuardianRole::Governance))
        );
    }

    #[test]
    fn a_non_guardian_cannot_pause() {
        assert_eq!(
            may_set_pause(None, false, true),
            Err(PauseRefusal::NotAGuardian)
        );
    }

    /// A no-op must not look like it did something.
    #[test]
    fn pausing_an_already_paused_chain_is_refused() {
        assert_eq!(
            may_set_pause(Some(GuardianRole::Protocol), true, true),
            Err(PauseRefusal::AlreadyInState(true))
        );
    }

    // ---- tracks ---------------------------------------------------------

    /// Expedited is faster and harder. Faster alone would be a way to pass
    /// something while fewer people are watching.
    #[test]
    fn the_expedited_track_is_faster_but_harder() {
        let s = ProposalTrack::Standard;
        let e = ProposalTrack::Expedited;

        assert!(
            e.voting_period_ms(&GovernanceRules::GENESIS)
                < s.voting_period_ms(&GovernanceRules::GENESIS)
        );
        assert!(
            e.timelock_ms(&GovernanceRules::GENESIS) < s.timelock_ms(&GovernanceRules::GENESIS)
        );

        let rules = GovernanceRules::GENESIS;
        assert!(
            e.threshold_bps(&rules) > s.threshold_bps(&rules),
            "the expedited threshold must exceed the standard one"
        );
    }

    /// The expedited timelock is shorter but must still be a real window, or
    /// a guardian has nowhere to act.
    #[test]
    fn the_expedited_timelock_is_still_a_window() {
        assert!(ProposalTrack::Expedited.timelock_ms(&GovernanceRules::GENESIS) > 0);
    }

    /// A tally that carries on the standard track can fail on the expedited
    /// one. That difference is the entire safeguard.
    #[test]
    fn a_bare_supermajority_fails_the_expedited_bar() {
        let mut t = Tally::default();
        t.apply_vote(70, true, None);
        t.apply_vote(30, false, None);

        assert!(
            t.threshold_met_on(ProposalTrack::Standard, &GovernanceRules::GENESIS),
            "70% clears 2/3"
        );
        assert!(
            !t.threshold_met_on(ProposalTrack::Expedited, &GovernanceRules::GENESIS),
            "70% must not clear the 4/5 expedited bar"
        );
    }

    /// A proposal opened on a track keeps that track timing.
    #[test]
    fn a_proposal_takes_its_timing_from_its_track() {
        let p = Proposal::open_on(
            "e1".into(),
            Address::default(),
            ProposalAction::ParameterChange {
                key: "agent.remote_grant_budget_divisor".into(),
                value: 4,
                memo: String::new(),
            },
            0,
            ProposalTrack::Expedited,
            GovernanceRules::GENESIS,
        );
        assert_eq!(p.voting_ends_ms, EXPEDITED_VOTING_PERIOD_MS);

        let mut p = p;
        p.status = ProposalStatus::Passed;
        assert!(p.queue(1_000));
        assert_eq!(p.eta_ms, Some(1_000 + EXPEDITED_TIMELOCK_DELAY_MS));
    }

    // ---- proposal threshold ---------------------------------------------

    #[test]
    fn a_proposer_below_the_threshold_is_refused() {
        // 1% of 1,000,000 is 10,000.
        assert!(!meets_proposal_threshold(
            9_999,
            1_000_000,
            PROPOSAL_THRESHOLD_BPS
        ));
        assert!(meets_proposal_threshold(
            10_000,
            1_000_000,
            PROPOSAL_THRESHOLD_BPS
        ));
    }

    /// A network with no bonded stake has no meaningful threshold, and
    /// refusing is the safe reading rather than admitting everyone.
    #[test]
    fn no_bonded_stake_admits_nobody() {
        assert!(!meets_proposal_threshold(
            u128::MAX,
            0,
            PROPOSAL_THRESHOLD_BPS
        ));
    }

    /// The distinction that nearly locked governance shut.
    ///
    /// Every validator holds a machine identity and machine identities hold
    /// the stake, so gating them as agents would leave nobody able to propose
    /// anything at the default phase. A machine identity says what the keys
    /// are bound to; an agent identity says what kind of thing decided.
    #[test]
    fn machine_identities_are_not_agent_identities() {
        assert!("did:tenzro:agent:abc".starts_with("did:tenzro:agent:"));
        assert!(
            !"did:tenzro:machine:abc".starts_with("did:tenzro:agent:"),
            "a validator machine identity must not be treated as an agent"
        );
        assert!(!"did:tenzro:human:abc".starts_with("did:tenzro:agent:"));
    }

    /// A queued proposal with no eta must not be treated as ready. The
    /// combination should not arise; if it does, the safe reading is "not yet"
    /// rather than "immediately".
    #[test]
    fn a_queued_proposal_without_an_eta_is_not_executable() {
        let mut p = queued();
        p.eta_ms = None;
        assert!(!p.is_executable_at(i64::MAX));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn canonical_addr(byte: u8) -> Address {
        let mut a = [0u8; 32];
        a[..20].fill(byte);
        Address::new(a)
    }

    fn grant(amount: u128) -> ProposalAction {
        ProposalAction::TreasuryGrant {
            recipient: canonical_addr(7),
            amount,
            memo: "founding validator allocation".to_string(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        }
    }

    // ---- action validation -------------------------------------------------

    #[test]
    fn a_zero_grant_is_refused() {
        assert_eq!(grant(0).validate(), Err(GovernanceError::ZeroAmount));
    }

    #[test]
    fn a_grant_to_the_zero_address_is_refused() {
        let action = ProposalAction::TreasuryGrant {
            recipient: Address::new([0u8; 32]),
            amount: 1,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        assert_eq!(
            action.validate(),
            Err(GovernanceError::ZeroAddress { field: "recipient" })
        );
    }

    #[test]
    fn free_text_is_bounded_because_it_lands_in_every_nodes_state() {
        let action = ProposalAction::TreasuryGrant {
            recipient: canonical_addr(7),
            amount: 1,
            memo: "x".repeat(MAX_TEXT_LEN + 1),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        };
        assert!(matches!(
            action.validate(),
            Err(GovernanceError::TextTooLong { field: "memo", .. })
        ));
    }

    // ---- quorum ------------------------------------------------------------

    #[test]
    fn quorum_needs_a_third_of_bonded_stake_to_show_up() {
        // 33 of 100 is just under a third.
        let short = Tally {
            yes: 33,
            no: 0,
            total_eligible: 100,
        };
        assert!(!short.quorum_met(&GovernanceRules::GENESIS));

        let exact = Tally {
            yes: 34,
            no: 0,
            total_eligible: 100,
        };
        assert!(exact.quorum_met(&GovernanceRules::GENESIS));
    }

    /// An empty electorate must not clear a quorum of nothing.
    ///
    /// `0 >= 0` is true, so the naive cross-multiplication passes with no stake
    /// bonded anywhere — which would let a single proposal drain the treasury on
    /// a network that had not started yet.
    #[test]
    fn an_empty_electorate_never_reaches_quorum() {
        let empty = Tally {
            yes: 0,
            no: 0,
            total_eligible: 0,
        };
        assert!(!empty.quorum_met(&GovernanceRules::GENESIS));
        assert_eq!(
            empty.outcome(&GovernanceRules::GENESIS),
            ProposalStatus::Rejected
        );
    }

    // ---- threshold ---------------------------------------------------------

    #[test]
    fn passing_needs_two_thirds_of_the_stake_that_voted() {
        let bare_majority = Tally {
            yes: 51,
            no: 49,
            total_eligible: 100,
        };
        assert!(bare_majority.quorum_met(&GovernanceRules::GENESIS));
        assert!(
            !bare_majority.threshold_met(&GovernanceRules::GENESIS),
            "a simple majority must not move the treasury"
        );
        assert_eq!(
            bare_majority.outcome(&GovernanceRules::GENESIS),
            ProposalStatus::Rejected
        );

        let supermajority = Tally {
            yes: 67,
            no: 33,
            total_eligible: 100,
        };
        assert!(supermajority.threshold_met(&GovernanceRules::GENESIS));
        assert_eq!(
            supermajority.outcome(&GovernanceRules::GENESIS),
            ProposalStatus::Passed
        );
    }

    // ---- vote replacement --------------------------------------------------

    /// Changing a vote must move weight, not add it.
    ///
    /// Without removing the previous ballot a validator votes yes, then no, and
    /// is counted on both sides — inflating participation past quorum with a
    /// single voter.
    #[test]
    fn changing_a_vote_moves_the_weight_instead_of_double_counting() {
        let mut t = Tally {
            total_eligible: 100,
            ..Default::default()
        };
        t.apply_vote(40, true, None);
        assert_eq!((t.yes, t.no), (40, 0));

        t.apply_vote(40, false, Some((40, true)));
        assert_eq!(
            (t.yes, t.no),
            (0, 40),
            "the earlier yes must be withdrawn, not kept alongside the no"
        );
        assert_eq!(t.participation(), 40, "one voter is one voter's worth");
    }

    /// A validator who bonds more after voting does not get a bigger ballot.
    #[test]
    fn weight_is_fixed_at_the_moment_the_vote_is_cast() {
        let mut t = Tally {
            total_eligible: 100,
            ..Default::default()
        };
        t.apply_vote(10, true, None);
        // The same voter re-votes after bonding up to 90. Their old ballot is
        // withdrawn at its recorded weight of 10, not at the new one.
        t.apply_vote(90, true, Some((10, true)));
        assert_eq!(t.yes, 90);
        assert_eq!(t.no, 0);
    }

    // ---- the voting window -------------------------------------------------

    #[test]
    fn a_proposal_cannot_be_decided_before_voting_closes() {
        let p = Proposal::open(
            "abc".into(),
            addr(1),
            grant(5),
            1_000,
            GovernanceRules::GENESIS,
        );
        let t = Tally {
            yes: 100,
            no: 0,
            total_eligible: 100,
        };
        assert!(matches!(
            decide(&p, &t, 1_000),
            Err(GovernanceError::VotingStillOpen { .. })
        ));
        assert_eq!(
            decide(&p, &t, 1_000 + VOTING_PERIOD_MS).unwrap(),
            ProposalStatus::Passed
        );
    }

    #[test]
    fn an_executed_proposal_cannot_be_decided_again() {
        let mut p = Proposal::open("abc".into(), addr(1), grant(5), 0, GovernanceRules::GENESIS);
        p.status = ProposalStatus::Executed;
        let t = Tally {
            yes: 100,
            no: 0,
            total_eligible: 100,
        };
        assert_eq!(
            decide(&p, &t, VOTING_PERIOD_MS * 2),
            Err(GovernanceError::AlreadyExecuted)
        );
    }

    #[test]
    fn a_proposal_is_open_only_within_its_window() {
        let p = Proposal::open(
            "abc".into(),
            addr(1),
            grant(5),
            500,
            GovernanceRules::GENESIS,
        );
        assert!(p.is_open_at(500));
        assert!(p.is_open_at(500 + VOTING_PERIOD_MS - 1));
        assert!(!p.is_open_at(500 + VOTING_PERIOD_MS));
    }

    // ---- wire format -------------------------------------------------------

    /// The action round-trips through JSON, which is how it travels in tx data.
    #[test]
    fn actions_round_trip_through_their_wire_form() {
        for action in [grant(1_000_000), grant(1)] {
            let encoded = serde_json::to_vec(&action).unwrap();
            let decoded: ProposalAction = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(action, decoded);
        }
    }

    /// A whole proposal round-trips too — this is what consensus persists.
    #[test]
    fn a_stored_proposal_round_trips() {
        let p = Proposal::open(
            "deadbeef".into(),
            addr(3),
            grant(42),
            12_345,
            GovernanceRules::GENESIS,
        );
        let encoded = serde_json::to_vec(&p).unwrap();
        let decoded: Proposal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    fn change(key: &str, value: u64) -> ProposalAction {
        ProposalAction::ParameterChange {
            key: key.into(),
            value,
            memo: "m".into(),
        }
    }

    #[test]
    fn only_a_pause_of_a_status_lever_takes_the_expedited_track() {
        let lever = "bridge.ibc.status";
        assert_eq!(change(lever, 1).track(), ProposalTrack::Expedited);
        assert_eq!(change(lever, 0).track(), ProposalTrack::Standard, "resume");
        assert_eq!(change(lever, 2).track(), ProposalTrack::Standard, "retire");
        // A value of 1 on anything that is not a status lever is not a pause.
        // The identity rule's mode is the one other key whose relaxing
        // change (1, audit) takes the expedited track, by design.
        for p in GOVERNED_PARAMS
            .iter()
            .filter(|p| p.tighten != Tighten::Retire)
            .filter(|p| p.key != crate::identity_required::MODE_KEY)
        {
            assert_eq!(
                change(p.key, 1).track(),
                ProposalTrack::Standard,
                "{}",
                p.key
            );
        }
        assert_eq!(change("no.such.key", 1).track(), ProposalTrack::Standard);
        // The foundation stewards can hold or veto an expedited pause.
        assert!(steward_scope(&change(lever, 1)));
        assert!(!steward_scope(&change(lever, 0)));
    }

    #[test]
    fn the_feature_pause_parameters_are_bounded() {
        for key in [FEATURE_PAUSE_MAX_PARAM, FEATURE_PAUSE_COOLOFF_PARAM] {
            let p = governed_param(key).unwrap();
            assert!(p.min <= p.genesis && p.genesis <= p.max, "{key}");
            assert_eq!(p.tighten, Tighten::Neither);
        }
        assert!(governed_param(FEATURE_PAUSE_MAX_PARAM).unwrap().min >= 1);
    }

    fn reinstate(validator: Address, memo: &str) -> ProposalAction {
        ProposalAction::ReinstateValidator {
            validator,
            memo: memo.into(),
        }
    }

    #[test]
    fn a_reinstatement_needs_a_validator_and_a_reason() {
        assert!(
            reinstate(addr(4), "jailed by a restored snapshot")
                .validate()
                .is_ok()
        );
        assert!(matches!(
            reinstate(Address::zero(), "why").validate(),
            Err(GovernanceError::ZeroAddress { .. })
        ));
        assert!(reinstate(addr(4), "  ").validate().is_err());
        let long = "x".repeat(MAX_TEXT_LEN + 1);
        assert!(reinstate(addr(4), &long).validate().is_err());
    }

    #[test]
    fn a_reinstatement_is_a_sanction_on_the_standard_track() {
        let a = reinstate(addr(4), "why");
        assert_eq!(a.domain(), ActionDomain::Sanction);
        assert_eq!(a.kind(), "reinstate_validator");
        assert_eq!(a.track(), ProposalTrack::Standard);
        assert!(!AgentPhase::Network.permits(a.domain()));
    }

    #[test]
    fn a_reinstatement_round_trips() {
        let a = reinstate(addr(4), "why");
        let decoded: ProposalAction =
            serde_json::from_slice(&serde_json::to_vec(&a).unwrap()).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn the_jail_term_is_bounded_and_longer_is_stricter() {
        let p = governed_param(crate::native::staking::JAIL_TERM_PARAM).unwrap();
        assert_eq!(
            p.genesis,
            tenzro_token::validator_registry::DEFAULT_JAIL_TERM_EPOCHS
        );
        assert!(p.min >= 1 && p.min <= p.genesis && p.genesis <= p.max);
        assert_eq!(p.tighten, Tighten::Up);
    }
}

#[cfg(test)]
mod supply_target_tests {
    use super::*;

    fn targets(target_annual_supply_bps: i32) -> PolicyUpdate {
        PolicyUpdate::SupplyTargetsUpdate {
            epoch_neutral_band_bps: 5,
            rolling_window_epochs: 90,
            inflation_alarm_bps: 500,
            deflation_alarm_bps: 500,
            target_annual_supply_bps,
            gain_bps_per_pct: 50,
            magnitude_cap_normal_bps: 200,
            magnitude_cap_alarm_bps: 100,
            auto_proposal_min_magnitude_bps: 25,
            alarm_fast_track_enabled: true,
        }
    }

    /// TNZO supply is fixed: governance may aim the burn dial at a flat or
    /// falling supply, never at a rising one.
    #[test]
    fn governance_cannot_set_a_rising_supply_target() {
        assert!(validate_policy_update(&targets(1)).is_err());
        assert!(validate_policy_update(&targets(50)).is_err());
        assert!(validate_policy_update(&targets(i32::MAX)).is_err());
        assert!(validate_policy_update(&targets(0)).is_ok());
        assert!(validate_policy_update(&targets(-50)).is_ok());
    }
}
