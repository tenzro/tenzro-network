//! Network funding: requests and tranched grants.
//!
//! Every route runs through on-chain governance and consensus state; nothing
//! here is decided by one node or one operator.
//!
//! - **Requests.** Anyone with a registered identity may file a funding
//!   request (a grant or a tranche release) with a zero balance: the
//!   treasury pays the filing's gas. Spam is bounded by the identity
//!   instead of by money: one open request per root identity, a cap on
//!   requests per window, and size limits. Bonded validators vote on the
//!   request under the ordinary governance rules.
//! - **Tranches.** A grant may be split into tranches, each for a named
//!   milestone. The first is paid when the grant enacts, the vote recording
//!   its milestone as met; each later one only when its own release proposal
//!   records its milestone as met, and exactly once. Every payment goes to an
//!   approved grantee within the governed yearly caps.
//!
//! Humans, agents and machines take part through the same identity model.
//! Limits count against the ROOT identity: a delegated machine
//! (`did:tenzro:machine:{controller}:{id}`) counts against its controller.

use serde::{Deserialize, Serialize};

use crate::governance::ProposalAction;

/// Serde for tranche amounts as decimal strings, so they survive the
/// tagged-enum encoding proposals use (which cannot carry `u128` numbers).
pub mod tranche_amounts {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u128], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|t| t.to_string()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u128>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|t| t.parse::<u128>().map_err(D::Error::custom))
            .collect()
    }
}

/// Most tranches one grant may be split into.
pub const MAX_GRANT_TRANCHES: usize = 12;

/// Default number of funding requests the network accepts per window.
pub const DEFAULT_REQUESTS_PER_WINDOW: u64 = 64;

/// Default length of the request-cap window.
pub const DEFAULT_REQUEST_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// What kind of participant an identity is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantKind {
    /// A person, rooted in a passkey.
    Human,
    /// An agent acting under a controller's delegation.
    Agent,
    /// A machine that answers for itself, rooted in its own hardware key.
    Machine,
    /// An institution.
    Institution,
}

/// The kind of participant `did` names, from its form.
pub fn participant_kind(did: &str) -> Option<ParticipantKind> {
    let rest = did.strip_prefix("did:tenzro:")?;
    let (method, id) = rest.split_once(':')?;
    if id.is_empty() {
        return None;
    }
    match method {
        "human" => Some(ParticipantKind::Human),
        "institution" => Some(ParticipantKind::Institution),
        "agent" => Some(ParticipantKind::Agent),
        "machine" => Some(if id.contains(':') {
            ParticipantKind::Agent
        } else {
            ParticipantKind::Machine
        }),
        _ => None,
    }
}

/// The identity limits count against: the controller of a delegated machine
/// (`did:tenzro:machine:{controller}:{id}` → `did:tenzro:human:{controller}`),
/// otherwise the identity itself.
pub fn root_did(did: &str) -> String {
    if let Some(rest) = did.strip_prefix("did:tenzro:machine:")
        && let Some((controller, id)) = rest.split_once(':')
        && !controller.is_empty()
        && !id.is_empty()
    {
        return format!("did:tenzro:human:{controller}");
    }
    did.to_string()
}

/// A funding operation a participant submits. The treasury pays its gas, so
/// a participant with a zero balance can take part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FundingOp {
    /// File a funding request for the governance vote.
    Request { action: ProposalAction },
    /// Record settled service as provider work in the current reward epoch:
    /// leg receipts of committed plans whose commit credited this account
    /// and that another party paid, each plan counted once, at most the
    /// governed share of the fee it paid outside the trade.
    ReportSettledWork {
        #[serde(with = "tenzro_types::agent_audit::hex32_vec")]
        legs: Vec<[u8; 32]>,
    },
    /// Claim this account's issued reward coupons from the rewards pool.
    ClaimRewards,
    /// Release what this account's vesting schedules have accrued.
    ReleaseVesting,
    /// Record that the milestone of tranche `index` of a scheduled grant is
    /// met. Only an account the approved grant named as a verifier may;
    /// each counts once, and the milestone is verified when the grant's
    /// threshold of verifiers has recorded it.
    VerifyMilestone {
        grant_id: String,
        index: u32,
        /// What was delivered, recorded with the verification.
        evidence: String,
    },
    /// Release the next tranche of a scheduled grant against its verified
    /// milestone. Anyone may send it; the tranche is paid to the grantee
    /// only, and the grantee's approval, the yearly caps and the treasury
    /// outflow limit are checked as for any tranche.
    ReleaseMilestone { grant_id: String, index: u32 },
}

/// Whether `action` may be filed as a funding request.
pub fn is_requestable(action: &ProposalAction) -> bool {
    matches!(
        action,
        ProposalAction::TreasuryGrant { .. } | ProposalAction::ReleaseGrantTranche { .. }
    )
}

/// A tranched grant in consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub recipient: tenzro_types::primitives::Address,
    #[serde(with = "tranche_amounts")]
    pub tranches: Vec<u128>,
    /// The milestone each tranche is paid against, one per tranche.
    pub milestones: Vec<String>,
    /// Number of tranches paid so far.
    pub paid: u32,
    /// How each tranche vests.
    pub vesting: crate::governance::GrantVesting,
    /// The settlement asset the grant pays in (a token id); `None` is TNZO.
    #[serde(default)]
    pub asset: Option<String>,
    /// How later tranches are released.
    #[serde(default)]
    pub release: crate::governance::GrantRelease,
}

/// The verifiers' record of one tranche's milestone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneRecord {
    /// Who recorded the milestone, in order, hex.
    pub verifiers: Vec<String>,
    /// What each recorded.
    pub evidence: Vec<String>,
    /// When the threshold was reached.
    pub verified_ms: Option<i64>,
}

/// Stake-weighted median of the capacities validators measured, if any
/// validator measured one.
pub fn median_capacity(mut measurements: Vec<(u64, u128)>) -> Option<u64> {
    let total: u128 = measurements.iter().map(|(_, w)| *w).sum();
    if measurements.is_empty() || total == 0 {
        return None;
    }
    measurements.sort_by_key(|(c, _)| *c);
    let half = total.div_ceil(2);
    let mut acc = 0u128;
    for (capacity, weight) in measurements {
        acc = acc.saturating_add(weight);
        if acc >= half {
            return Some(capacity);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegated_machines_count_against_their_controller() {
        assert_eq!(
            root_did("did:tenzro:machine:abc:def"),
            "did:tenzro:human:abc"
        );
        assert_eq!(root_did("did:tenzro:machine:def"), "did:tenzro:machine:def");
        assert_eq!(root_did("did:tenzro:human:abc"), "did:tenzro:human:abc");
        assert_eq!(
            participant_kind("did:tenzro:machine:abc:def"),
            Some(ParticipantKind::Agent)
        );
        assert_eq!(
            participant_kind("did:tenzro:machine:def"),
            Some(ParticipantKind::Machine)
        );
        assert_eq!(
            participant_kind("did:tenzro:human:abc"),
            Some(ParticipantKind::Human)
        );
        assert_eq!(participant_kind("did:other:x"), None);
    }

    #[test]
    fn median_capacity_is_stake_weighted() {
        assert_eq!(median_capacity(vec![]), None);
        assert_eq!(median_capacity(vec![(10, 1), (20, 1), (30, 5)]), Some(30));
        assert_eq!(median_capacity(vec![(10, 5), (20, 1), (30, 1)]), Some(10));
    }
}
