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
//! - **Quorum** — at least [`QUORUM_NUMERATOR`]/[`QUORUM_DENOMINATOR`] of all
//!   bonded stake must participate. Without it, a proposal nobody noticed passes
//!   on one vote.
//! - **Threshold** — at least [`THRESHOLD_NUMERATOR`]/[`THRESHOLD_DENOMINATOR`]
//!   of the stake that *did* vote must be in favour. A supermajority rather than
//!   a simple majority, because what these proposals move is the treasury.
//! - **The voting period closes.** A proposal is decided when
//!   [`VOTING_PERIOD_MS`] has elapsed, and not before — so a tally cannot be
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
//! Everything else depends on this. OpenZeppelin's rationale for
//! `TimelockController` is that the delay lets holders "exit the system if
//! they disagree with a decision before it is executed"; the operational one
//! is that a proposal carrying a bug has a bounded window in which it can
//! still be stopped. It is also the only place a guardian can act, the only
//! place the community sees a decision before it lands, and the natural
//! dispute period for a verifiable-inference receipt.
//!
//! **If you shorten or remove this, everything below stops working.**
//!
//! ## Guardians hold negative powers only
//!
//! Two roles, separate, on the model Aave uses — Protocol Guardians pause,
//! Governance Guardians veto. They differ in blast radius: a pause halts
//! enactment briefly, a veto kills one decision permanently. A role holding
//! both can quietly become the government.
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
//! - the source must be a system-held sink, never a user account;
//! - the destination needs a registered identity, as any recipient does;
//! - the claimed amount is settled against actual state at enactment;
//! - the memo carries the evidence, and an empty one is refused.
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
//! 4. If it moves value, it is `Treasury`, and it inherits the timelock, the
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

/// How long a proposal accepts votes, in milliseconds.
///
/// Measured against the block timestamp the transaction executes under, never
/// against wall-clock time: `Utc::now()` in a handler is a non-deterministic
/// syscall and two validators a few milliseconds apart would compute different
/// outcomes and fork.
pub const VOTING_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;

/// Quorum: the fraction of all bonded stake that must participate.
pub const QUORUM_NUMERATOR: u128 = 1;
/// Denominator of [`QUORUM_NUMERATOR`].
pub const QUORUM_DENOMINATOR: u128 = 3;

/// Threshold: the fraction of *participating* stake that must vote yes.
pub const THRESHOLD_NUMERATOR: u128 = 2;
/// Denominator of [`THRESHOLD_NUMERATOR`].
pub const THRESHOLD_DENOMINATOR: u128 = 3;

/// Longest permitted free-text field on a proposal.
///
/// Memos and reasons are written into consensus state on every node forever, so
/// they are bounded. Long enough to say why, short enough not to be storage.
pub const MAX_TEXT_LEN: usize = 512;

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
pub const EXPEDITED_THRESHOLD_NUMERATOR: u128 = 4;
/// Denominator for [`EXPEDITED_THRESHOLD_NUMERATOR`].
pub const EXPEDITED_THRESHOLD_DENOMINATOR: u128 = 5;

/// Share of bonded stake a proposer must hold to open a proposal.
///
/// Every proposal costs the network a voting period of attention, so creating
/// one has to be non-trivial or the surface is unusable through volume alone.
/// One percent: enough that a proposal represents a real position, low enough
/// that it is not a validators-only power.
pub const PROPOSAL_THRESHOLD_NUMERATOR: u128 = 1;
/// Denominator for [`PROPOSAL_THRESHOLD_NUMERATOR`].
pub const PROPOSAL_THRESHOLD_DENOMINATOR: u128 = 100;

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

/// Errors a proposal can be rejected with before it ever reaches a vote.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceError {
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
}

/// What a proposal does if it passes.
///
/// Typed rather than opaque bytes, so the VM can validate a proposal when it is
/// *submitted* instead of discovering at enactment that it decodes to nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ProposalAction {
    /// Pay `amount` from the treasury to `recipient`.
    ///
    /// The recipient must already hold a registered identity. That is the
    /// network's standing invariant — no entity holds a wallet without an
    /// identity behind it — and a treasury grant is exactly the moment it would
    /// otherwise be broken, by creating a funded address answerable to nobody.
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
    TreasuryGrant {
        /// Who is paid.
        recipient: Address,
        /// How much, in the smallest unit.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        amount: u128,
        /// Why, recorded on-chain with the proposal.
        memo: String,
    },
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
            } => {
                if *amount == 0 {
                    return Err(GovernanceError::ZeroAmount);
                }
                if recipient.as_bytes().iter().all(|b| *b == 0) {
                    return Err(GovernanceError::ZeroAddress { field: "recipient" });
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
        }
    }

    /// A short label for logs and RPC, stable across releases.
    pub fn kind(&self) -> &'static str {
        match self {
            ProposalAction::RecoverUnownedFunds { .. } => "recover_unowned_funds",
            ProposalAction::ParameterChange { .. } => "parameter_change",
            ProposalAction::TreasuryGrant { .. } => "treasury_grant",
        }
    }
}

/// What a guardian is permitted to stop.
///
/// Two powers, held separately, on the model Aave uses: Protocol Guardians
/// "handle emergency responses and can pause markets", Governance Guardians
/// "can veto malicious governance proposals". They differ in blast radius —
/// a pause halts everything for a while, a veto kills one decision forever —
/// and a role holding both is a role that can quietly become the government.
///
/// Every guardian power is negative. A guardian stops things and originates
/// nothing: none of these can move funds, change a parameter or enact a
/// proposal. The worst a captured guardian achieves is refusing to let the
/// network act, which is visible at once, rather than acting in its name,
/// which may not be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianRole {
    /// May pause execution in an emergency. Cannot veto a specific proposal.
    Protocol,
    /// May veto a queued proposal during its timelock. Cannot pause.
    Governance,
}

impl GuardianRole {
    /// Whether this role may veto a queued proposal.
    pub fn may_veto(&self) -> bool {
        matches!(self, GuardianRole::Governance)
    }

    /// Whether this role may pause execution.
    pub fn may_pause(&self) -> bool {
        matches!(self, GuardianRole::Protocol)
    }

    /// Stable label for logs and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardianRole::Protocol => "protocol",
            GuardianRole::Governance => "governance",
        }
    }
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
pub fn may_veto(
    role: Option<GuardianRole>,
    proposal: &Proposal,
) -> Result<(), VetoRefusal> {
    let Some(role) = role else {
        return Err(VetoRefusal::NotAGuardian);
    };
    if !role.may_veto() {
        return Err(VetoRefusal::WrongRole(role));
    }
    if !matches!(proposal.status, ProposalStatus::Queued) {
        return Err(VetoRefusal::NotQueued(proposal.status));
    }
    Ok(())
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
            (AgentPhase::Network, ActionDomain::Treasury) => false,
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
    /// What it does, surfaced to whoever is being asked to vote on it.
    pub description: &'static str,
}

/// Every parameter governance may set.
///
/// Adding one here is what makes it governable; a constant not in this table
/// still requires a rebuild, which is the honest signal that nobody decided it
/// should be adjustable at runtime.
pub const GOVERNED_PARAMS: &[GovernedParam] = &[
    GovernedParam {
        key: "consensus.epoch_duration_blocks",
        min: 10,
        max: 1_000_000,
        description: "Blocks per epoch. Zero would divide by zero; very small \
                      values rotate the validator set faster than it can settle.",
    },
    GovernedParam {
        key: "sync.slot_import_tolerance",
        min: 1,
        max: 1_000,
        description: "How many blocks behind a node tolerates before block-sync \
                      engages. Zero would make every node sync continuously.",
    },
    GovernedParam {
        key: "sync.max_behind_seconds",
        min: 5,
        max: 3_600,
        description: "How long a node may sit behind by any amount before sync \
                      engages regardless of the block count.",
    },
    GovernedParam {
        key: "consensus.empty_block_heartbeat_ms",
        min: 1_000,
        max: 3_600_000,
        description: "How long an idle chain waits before minting a keepalive \
                      block. Zero disables empty-block suppression entirely.",
    },
    GovernedParam {
        key: "governance.agent_phase",
        min: 0,
        max: 2,
        description: "How far agents are trusted to originate proposals: \
                      0 none, 1 network only, 2 all. Advancing this is itself \
                      a governed decision.",
    },
];

/// Look up a governed parameter by key.
pub fn governed_param(key: &str) -> Option<&'static GovernedParam> {
    GOVERNED_PARAMS.iter().find(|p| p.key == key)
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
}

impl ProposalTrack {
    /// How long voting stays open on this track.
    pub fn voting_period_ms(&self) -> i64 {
        match self {
            ProposalTrack::Standard => VOTING_PERIOD_MS,
            ProposalTrack::Expedited => EXPEDITED_VOTING_PERIOD_MS,
        }
    }

    /// How long a passed proposal waits before it may execute.
    pub fn timelock_ms(&self) -> i64 {
        match self {
            ProposalTrack::Standard => TIMELOCK_DELAY_MS,
            ProposalTrack::Expedited => EXPEDITED_TIMELOCK_DELAY_MS,
        }
    }

    /// The share of participating stake that must be in favour.
    ///
    /// Higher on the expedited track, which is what pays for the shorter
    /// window.
    pub fn threshold(&self) -> (u128, u128) {
        match self {
            ProposalTrack::Standard => (THRESHOLD_NUMERATOR, THRESHOLD_DENOMINATOR),
            ProposalTrack::Expedited => (EXPEDITED_THRESHOLD_NUMERATOR, EXPEDITED_THRESHOLD_DENOMINATOR),
        }
    }

    /// Stable label for logs and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalTrack::Standard => "standard",
            ProposalTrack::Expedited => "expedited",
        }
    }
}

/// Whether `proposer_stake` is enough to open a proposal.
///
/// A fraction of bonded stake rather than an absolute, so it tracks the
/// network as it grows instead of becoming meaningless when stake inflates.
/// Zero total stake means a network with no validators, where the question
/// does not arise and refusing is the safe answer.
pub fn meets_proposal_threshold(proposer_stake: u128, total_bonded: u128) -> bool {
    if total_bonded == 0 {
        return false;
    }
    proposer_stake.saturating_mul(PROPOSAL_THRESHOLD_DENOMINATOR)
        >= total_bonded.saturating_mul(PROPOSAL_THRESHOLD_NUMERATOR)
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
        self.eta_ms = Some(now_ms.saturating_add(self.track.timelock_ms()));
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

    /// Open a proposal for voting, closing [`VOTING_PERIOD_MS`] from now.
    pub fn open(id: String, proposer: Address, action: ProposalAction, created_ms: i64) -> Self {
        Self::open_on(id, proposer, action, created_ms, ProposalTrack::Standard)
    }

    /// Open a proposal on an explicit track.
    pub fn open_on(
        id: String,
        proposer: Address,
        action: ProposalAction,
        created_ms: i64,
        track: ProposalTrack,
    ) -> Self {
        Self {
            id,
            proposer,
            track,
            eta_ms: None,
            action,
            created_ms,
            voting_ends_ms: created_ms.saturating_add(track.voting_period_ms()),
            status: ProposalStatus::Voting,
        }
    }

    /// Whether votes are still being accepted at `now_ms`.
    pub fn is_open_at(&self, now_ms: i64) -> bool {
        self.status == ProposalStatus::Voting && now_ms < self.voting_ends_ms
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

    /// Whether enough of the bonded stake showed up.
    ///
    /// `participation / total_eligible >= QUORUM_NUMERATOR / QUORUM_DENOMINATOR`,
    /// cross-multiplied to stay in integers. Saturating rather than wrapping:
    /// the products are bounded by total supply times a small constant and
    /// cannot realistically reach `u128::MAX`, but saturating there would
    /// under-report rather than wrap into a spuriously passing tally.
    pub fn quorum_met(&self) -> bool {
        if self.total_eligible == 0 {
            // No stake bonded anywhere means no electorate. A proposal cannot
            // clear a quorum of nothing — treating it as met would let the
            // treasury be drained on an empty network.
            return false;
        }
        self.participation().saturating_mul(QUORUM_DENOMINATOR)
            >= self.total_eligible.saturating_mul(QUORUM_NUMERATOR)
    }

    /// Whether the supermajority of participating stake is in favour.
    pub fn threshold_met(&self) -> bool {
        self.threshold_met_on(ProposalTrack::Standard)
    }

    /// Whether the in-favour share clears the bar for `track`.
    ///
    /// The expedited track sets a higher bar, and that is what pays for its
    /// shorter window. A faster track at the same threshold would simply be a
    /// way to pass something while fewer people are watching.
    pub fn threshold_met_on(&self, track: ProposalTrack) -> bool {
        let participation = self.participation();
        if participation == 0 {
            return false;
        }
        let (num, den) = track.threshold();
        self.yes.saturating_mul(den) >= participation.saturating_mul(num)
    }

    /// The outcome this tally implies on `track`, once voting has closed.
    pub fn outcome_on(&self, track: ProposalTrack) -> ProposalStatus {
        if self.quorum_met() && self.threshold_met_on(track) {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        }
    }

    /// The outcome this tally implies, once voting has closed.
    pub fn outcome(&self) -> ProposalStatus {
        if self.quorum_met() && self.threshold_met() {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        }
    }

    /// Why a tally failed, for an error a human can act on.
    pub fn failure_reason(&self) -> String {
        if !self.quorum_met() {
            format!(
                "quorum not met: {} of {} bonded stake participated, need {}/{}",
                self.participation(),
                self.total_eligible,
                QUORUM_NUMERATOR,
                QUORUM_DENOMINATOR
            )
        } else {
            format!(
                "threshold not met: {} yes of {} cast, need {}/{}",
                self.yes,
                self.participation(),
                THRESHOLD_NUMERATOR,
                THRESHOLD_DENOMINATOR
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
    Ok(tally.outcome_on(proposal.track))
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
            },
            0,
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
            },
            0,
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
        assert!(!p.is_executable_at(i64::MAX), "a vetoed proposal became executable");
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
            key: "sync.slot_import_tolerance".into(),
            value: 4,
            memo: String::new(),
        };
        assert_eq!(a.domain(), ActionDomain::Network);
        assert!(AgentPhase::Network.permits(a.domain()));
        assert!(a.validate().is_ok());
    }

    /// Every constant that caused an outage today is governable now. This
    /// pins that they are actually in the table, rather than the table being
    /// a plausible-looking list that omits the ones that mattered.
    #[test]
    fn the_constants_that_broke_the_network_are_governable() {
        for key in [
            "consensus.epoch_duration_blocks",
            "sync.slot_import_tolerance",
            "sync.max_behind_seconds",
            "consensus.empty_block_heartbeat_ms",
            "governance.agent_phase",
        ] {
            assert!(
                governed_param(key).is_some(),
                "{key} needs a rebuild to change, which is what we were fixing"
            );
        }
    }

    /// A value that cannot work is refused when it is written, not after it
    /// has carried a vote. Discovering it at enactment means the failure lands
    /// where nobody is watching.
    #[test]
    fn an_out_of_range_parameter_is_refused_at_submission() {
        let a = ProposalAction::ParameterChange {
            key: "sync.slot_import_tolerance".into(),
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

    /// Bounds must leave a working network at both ends.
    #[test]
    fn every_governed_parameter_has_a_sane_range() {
        for p in GOVERNED_PARAMS {
            assert!(p.min <= p.max, "{}: min exceeds max", p.key);
            assert!(!p.description.is_empty(), "{}: no description to vote on", p.key);
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
        let a = recovery(Address::new([1u8; 32]), Address::new([2u8; 32]), 10, "vault imbalance");
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
        let a = recovery(Address::new([1u8; 32]), Address::new([2u8; 32]), 10, "   ");
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

        assert!(e.voting_period_ms() < s.voting_period_ms());
        assert!(e.timelock_ms() < s.timelock_ms());

        let (sn, sd) = s.threshold();
        let (en, ed) = e.threshold();
        assert!(
            en * sd > sn * ed,
            "the expedited threshold must exceed the standard one"
        );
    }

    /// The expedited timelock is shorter but must still be a real window, or
    /// a guardian has nowhere to act.
    #[test]
    fn the_expedited_timelock_is_still_a_window() {
        assert!(ProposalTrack::Expedited.timelock_ms() > 0);
    }

    /// A tally that carries on the standard track can fail on the expedited
    /// one. That difference is the entire safeguard.
    #[test]
    fn a_bare_supermajority_fails_the_expedited_bar() {
        let mut t = Tally::default();
        t.apply_vote(70, true, None);
        t.apply_vote(30, false, None);

        assert!(t.threshold_met_on(ProposalTrack::Standard), "70% clears 2/3");
        assert!(
            !t.threshold_met_on(ProposalTrack::Expedited),
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
                key: "sync.slot_import_tolerance".into(),
                value: 4,
                memo: String::new(),
            },
            0,
            ProposalTrack::Expedited,
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
        assert!(!meets_proposal_threshold(9_999, 1_000_000));
        assert!(meets_proposal_threshold(10_000, 1_000_000));
    }

    /// A network with no bonded stake has no meaningful threshold, and
    /// refusing is the safe reading rather than admitting everyone.
    #[test]
    fn no_bonded_stake_admits_nobody() {
        assert!(!meets_proposal_threshold(u128::MAX, 0));
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
        assert!(!short.quorum_met());

        let exact = Tally {
            yes: 34,
            no: 0,
            total_eligible: 100,
        };
        assert!(exact.quorum_met());
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
        assert!(!empty.quorum_met());
        assert_eq!(empty.outcome(), ProposalStatus::Rejected);
    }

    // ---- threshold ---------------------------------------------------------

    #[test]
    fn passing_needs_two_thirds_of_the_stake_that_voted() {
        let bare_majority = Tally {
            yes: 51,
            no: 49,
            total_eligible: 100,
        };
        assert!(bare_majority.quorum_met());
        assert!(
            !bare_majority.threshold_met(),
            "a simple majority must not move the treasury"
        );
        assert_eq!(bare_majority.outcome(), ProposalStatus::Rejected);

        let supermajority = Tally {
            yes: 67,
            no: 33,
            total_eligible: 100,
        };
        assert!(supermajority.threshold_met());
        assert_eq!(supermajority.outcome(), ProposalStatus::Passed);
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
        let p = Proposal::open("abc".into(), addr(1), grant(5), 1_000);
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
        let mut p = Proposal::open("abc".into(), addr(1), grant(5), 0);
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
        let p = Proposal::open("abc".into(), addr(1), grant(5), 500);
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
        let p = Proposal::open("deadbeef".into(), addr(3), grant(42), 12_345);
        let encoded = serde_json::to_vec(&p).unwrap();
        let decoded: Proposal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(p, decoded);
    }
}
