//! The application state machine.
//!
//! ```text
//! applied -> under review -> approved -> funded -> staked -> serving
//!    \            \
//!     +------------+--> declined        (off the ladder; the team's decision)
//! ```
//!
//! plus `NotApplied` before the first step. Who knows what:
//!
//! | state          | source of truth                                        |
//! |----------------|--------------------------------------------------------|
//! | applied        | the website's join-form backend (status endpoint)      |
//! | under review   | the website's backend                                  |
//! | approved       | the website's backend                                  |
//! | declined       | the website's backend                                  |
//! | funded         | the CHAIN: the wallet holds at least the role minimum  |
//! | staked         | the CHAIN: the role's stake is bonded / validator registered |
//! | serving        | the CHAIN + node: staked AND the role is live          |
//!
//! `funded` is deliberately derived from the wallet balance, not from the
//! website's word, so it is true however the TNZO arrived: a team transfer
//! today, a sponsor account later, or the holder's own purchase once staking
//! is open. A remote that claims `staked` or `serving` is not believed (the
//! chain is asked), and a local record is never believed past `funded`.

/// Where an application stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationState {
    NotApplied,
    Applied,
    UnderReview,
    Approved,
    Funded,
    Staked,
    Serving,
    /// The team did not approve. Off the ladder: it has no rank above others.
    Declined,
}

/// The ladder, in order.
pub const LADDER: [ApplicationState; 6] = [
    ApplicationState::Applied,
    ApplicationState::UnderReview,
    ApplicationState::Approved,
    ApplicationState::Funded,
    ApplicationState::Staked,
    ApplicationState::Serving,
];

/// A move the machine refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    pub from: ApplicationState,
    pub to: ApplicationState,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "an application cannot go from {} to {}",
            self.from.as_str(),
            self.to.as_str()
        )
    }
}
impl std::error::Error for TransitionError {}

impl ApplicationState {
    /// The wire / config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::Applied => "applied",
            Self::UnderReview => "under_review",
            Self::Approved => "approved",
            Self::Funded => "funded",
            Self::Staked => "staked",
            Self::Serving => "serving",
            Self::Declined => "declined",
        }
    }

    /// How a person reads it.
    pub fn label(self) -> &'static str {
        match self {
            Self::NotApplied => "not applied yet",
            Self::Applied => "applied",
            Self::UnderReview => "under review",
            Self::Approved => "approved",
            Self::Funded => "funded",
            Self::Staked => "staked",
            Self::Serving => "serving",
            Self::Declined => "not approved",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(
            match s
                .trim()
                .to_ascii_lowercase()
                .replace([' ', '-'], "_")
                .as_str()
            {
                "not_applied" => Self::NotApplied,
                "applied" => Self::Applied,
                "under_review" => Self::UnderReview,
                "approved" => Self::Approved,
                "funded" => Self::Funded,
                "staked" => Self::Staked,
                "serving" => Self::Serving,
                "declined" => Self::Declined,
                _ => return None,
            },
        )
    }

    /// Position on the ladder (`NotApplied` is 0, `Declined` is not on it).
    fn rank(self) -> Option<usize> {
        match self {
            Self::NotApplied => Some(0),
            Self::Declined => None,
            s => LADDER.iter().position(|x| *x == s).map(|i| i + 1),
        }
    }

    /// The next step up the ladder.
    pub fn next(self) -> Option<Self> {
        let r = self.rank()?;
        LADDER.get(r).copied()
    }

    /// Whether the stake is already in hand or in use, so no "you need more
    /// TNZO" message applies.
    pub fn stake_in_place(self) -> bool {
        matches!(self, Self::Staked | Self::Serving)
    }

    /// One explicit move. Only the next rung, staying put, a decline from the
    /// two review states, or a fresh application after a decline.
    pub fn advance(self, to: Self) -> Result<Self, TransitionError> {
        let ok = to == self
            || self.next() == Some(to)
            || (to == Self::Declined && matches!(self, Self::Applied | Self::UnderReview))
            || (self == Self::Declined && to == Self::Applied);
        if ok {
            Ok(to)
        } else {
            Err(TransitionError { from: self, to })
        }
    }
}

/// The ladder as one line with the current rung bracketed.
pub fn ladder_line(state: ApplicationState) -> String {
    let rungs: Vec<String> = LADDER
        .iter()
        .map(|s| {
            if *s == state {
                format!("[{}]", s.label())
            } else {
                s.label().to_string()
            }
        })
        .collect();
    let line = rungs.join(" > ");
    match state {
        ApplicationState::NotApplied => format!("Status: not applied yet ({line})"),
        ApplicationState::Declined => format!("Status: not approved ({line})"),
        _ => format!("Status: {line}"),
    }
}

/// Everything known about where an application is. Every field is optional
/// knowledge: `None` means "could not be read".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// What the website's backend reported, or else the last record kept
    /// locally.
    pub reported: Option<ApplicationState>,
    /// The wallet holds at least the role's stake minimum.
    pub balance_meets_minimum: Option<bool>,
    /// The role's stake is bonded on chain.
    pub chain_staked: Option<bool>,
    /// The role is live (validator active, or the node serves the role).
    pub chain_serving: Option<bool>,
}

/// Where the user actually is, from the evidence. Pure.
///
/// Rules: the chain outranks anyone's word for `funded`, `staked`, `serving`;
/// `serving` needs `staked`; a report is never believed past `funded`; a
/// `declined` report stands unless the chain shows funds or a stake (they
/// got there some other way).
pub fn resolve(ev: &Evidence) -> ApplicationState {
    use ApplicationState::*;
    let staked = ev.chain_staked == Some(true);
    let serving = staked && ev.chain_serving == Some(true);
    if serving {
        return Serving;
    }
    if staked {
        return Staked;
    }
    if ev.balance_meets_minimum == Some(true) {
        // Whatever the report says below `funded` is superseded, a decline
        // included: the wallet holds the stake regardless of how it got there.
        return Funded;
    }
    let reported = match ev.reported {
        Some(Staked | Serving) => Some(Funded),
        r => r,
    };
    match reported {
        // Reported as funded but the wallet does not show it: the transfer has
        // not landed, or was spent without bonding. Keep what the team said.
        Some(s) => s,
        None => NotApplied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ApplicationState::*;

    #[test]
    fn the_ladder_advances_one_rung_at_a_time() {
        let mut s = NotApplied;
        for next in LADDER {
            s = s.advance(next).unwrap();
        }
        assert_eq!(s, Serving);
    }

    #[test]
    fn cannot_skip_from_applied_to_serving() {
        assert!(Applied.advance(Serving).is_err());
        assert!(Applied.advance(Approved).is_err());
        assert!(UnderReview.advance(Funded).is_err());
        assert!(NotApplied.advance(Staked).is_err());
        assert!(Serving.advance(Applied).is_err(), "no moving backwards");
    }

    #[test]
    fn decline_only_from_review_and_reapply_only_after_it() {
        assert_eq!(Applied.advance(Declined), Ok(Declined));
        assert_eq!(UnderReview.advance(Declined), Ok(Declined));
        assert!(Approved.advance(Declined).is_err());
        assert!(Funded.advance(Declined).is_err());
        assert_eq!(Declined.advance(Applied), Ok(Applied));
        assert!(Declined.advance(Approved).is_err());
    }

    #[test]
    fn serving_without_a_stake_is_not_believed() {
        let ev = Evidence {
            reported: Some(Applied),
            chain_serving: Some(true),
            ..Default::default()
        };
        assert_eq!(resolve(&ev), Applied);
    }

    #[test]
    fn a_remote_claim_of_staked_or_serving_is_capped_at_funded() {
        let ev = Evidence {
            reported: Some(Serving),
            balance_meets_minimum: Some(true),
            ..Default::default()
        };
        assert_eq!(resolve(&ev), Funded);
        let ev = Evidence {
            reported: Some(Staked),
            ..Default::default()
        };
        assert_eq!(resolve(&ev), Funded);
    }

    #[test]
    fn the_chain_decides_funded_staked_serving() {
        let funded = Evidence {
            reported: Some(Approved),
            balance_meets_minimum: Some(true),
            ..Default::default()
        };
        assert_eq!(resolve(&funded), Funded);
        let staked = Evidence {
            reported: Some(Approved),
            chain_staked: Some(true),
            ..Default::default()
        };
        assert_eq!(resolve(&staked), Staked);
        let serving = Evidence {
            chain_staked: Some(true),
            chain_serving: Some(true),
            ..Default::default()
        };
        assert_eq!(resolve(&serving), Serving);
    }

    #[test]
    fn nothing_known_is_not_applied_and_a_report_is_kept() {
        assert_eq!(resolve(&Evidence::default()), NotApplied);
        for s in [Applied, UnderReview, Approved, Declined] {
            assert_eq!(
                resolve(&Evidence {
                    reported: Some(s),
                    ..Default::default()
                }),
                s
            );
        }
    }

    #[test]
    fn unreadable_chain_does_not_regress_a_report() {
        let ev = Evidence {
            reported: Some(Approved),
            balance_meets_minimum: None,
            chain_staked: None,
            ..Default::default()
        };
        assert_eq!(resolve(&ev), Approved);
    }

    #[test]
    fn ladder_line_brackets_the_current_rung() {
        let l = ladder_line(Approved);
        assert!(l.contains("[approved]") && !l.contains("[applied]"), "{l}");
        assert!(ladder_line(NotApplied).contains("not applied yet"));
    }

    #[test]
    fn spellings_round_trip() {
        for s in [
            NotApplied,
            Applied,
            UnderReview,
            Approved,
            Funded,
            Staked,
            Serving,
            Declined,
        ] {
            assert_eq!(ApplicationState::parse(s.as_str()), Some(s));
        }
        assert_eq!(ApplicationState::parse("under review"), Some(UnderReview));
        assert_eq!(ApplicationState::parse("???"), None);
    }
}
