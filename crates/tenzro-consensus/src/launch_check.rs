//! The check a genesis validator set passes before a network launches.
//!
//! A set that is exactly large enough to certify when everyone is up has no
//! fault tolerance: the first machine that stops halts the chain, and a halt
//! cannot be repaired from inside, because replacing a validator takes a
//! block. The network of 2026-10-19 launched like that: four equal
//! validators, quorum three, one of the four permanently gone, so the
//! failure of any one of the three live ones stopped it for good.
//!
//! [`check_launch_set`] refuses a set unless, at launch:
//!
//! - it has at least four validators (`n >= 3f + 1` with `f >= 1`);
//! - every validator has a working hardware identity;
//! - the live validators hold strictly more than two thirds of the stake
//!   (they can certify), and still do after the live validator with the
//!   most stake is lost (a live spare: any one failure is survived).
//!
//! "Live" is established by the launch procedure, by each validator
//! answering a challenge signed with its hardware identity, not by this
//! module.

use serde::{Deserialize, Serialize};
pub use tenzro_types::launch_rule::{MIN_LAUNCH_VALIDATORS, above_two_thirds};

/// Validators a founding set should have, so that planned stops (updates,
/// maintenance) and permanent losses over the inactivity window leave the
/// margin intact: f = 2 at seven. The launch check itself still accepts four;
/// [`founding_advisories`] says what four lacks.
pub const FOUNDING_VALIDATORS: usize = 7;
/// Independent operators (separate organisation and separate host) a founding
/// set should span. Validators of one operator or one host stop together, so
/// the planned-stop arithmetic counts them as one.
pub const FOUNDING_OPERATORS: usize = 4;

/// How much margin the live validators have, from the live and total stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Headroom {
    /// The live validators cannot certify: the chain is halted.
    Halted,
    /// They certify, but the loss of the largest live validator halts it
    /// (quorum + 0): page.
    Zero,
    /// One loss is survived, a second is not (quorum + 1): warn.
    One,
    /// Two or more losses are survived.
    Healthy,
}

/// The headroom of a set, by stake: the same arithmetic as
/// [`check_launch_set`] and [`check_stops`], applied to the live validators
/// the monitor sees right now. This is the function the alert rules mirror
/// (deploy/monitoring/alerts.yml uses the equal-stake count form).
pub fn headroom(set: &[LaunchValidator]) -> Headroom {
    let total: u128 = set.iter().map(|v| v.stake).sum();
    let mut live: Vec<u128> = set.iter().filter(|v| v.live).map(|v| v.stake).collect();
    live.sort_unstable_by(|a, b| b.cmp(a));
    let mut remaining: u128 = live.iter().sum();
    if !above_two_thirds(remaining, total) {
        return Headroom::Halted;
    }
    let mut losses = 0;
    for stake in live.iter().take(2) {
        remaining -= stake;
        if !above_two_thirds(remaining, total) {
            break;
        }
        losses += 1;
    }
    match losses {
        0 => Headroom::Zero,
        1 => Headroom::One,
        _ => Headroom::Healthy,
    }
}

/// What a set that passes [`check_launch_set`] still lacks as a founding set.
/// `operators` names the operator of each validator in `set`, in order. Empty
/// when the set meets the requirement. Advice, not a refusal: it changes no
/// rule and no governed value.
pub fn founding_advisories(set: &[LaunchValidator], operators: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    if set.len() < FOUNDING_VALIDATORS {
        out.push(format!(
            "{} validators: a founding set needs at least {FOUNDING_VALIDATORS}",
            set.len()
        ));
    }
    let mut distinct: Vec<&str> = operators.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    if operators.len() != set.len() {
        out.push("every validator must name its operator".to_string());
    } else if distinct.len() < FOUNDING_OPERATORS {
        out.push(format!(
            "{} independent operators: a founding set needs at least {FOUNDING_OPERATORS}",
            distinct.len()
        ));
    }
    out
}

/// One validator of a proposed genesis set, as the launch procedure found it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchValidator {
    /// A label for the report.
    pub name: String,
    /// Voting power in consensus units: whole TNZO rounded down, at least 1
    /// for any stake (`tenzro_types::launch_rule::voting_power`). A genesis
    /// entry's stake is already in whole TNZO.
    pub stake: u128,
    /// It answered a challenge signed by its hardware identity.
    pub live: bool,
    /// Its consensus key is held by hardware (TPM, secure element, passkey).
    pub hardware_identity: bool,
}

/// Why a genesis set is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchRefusal {
    /// Fewer than four validators.
    TooFew {
        /// Validators in the set.
        validators: usize,
    },
    /// A validator without a working hardware identity.
    NoHardwareIdentity {
        /// Names of those validators.
        names: Vec<String>,
    },
    /// The stake is zero.
    NoStake,
    /// The live validators do not hold more than two thirds of the stake.
    CannotCertify {
        /// Live stake.
        live: u128,
        /// Total stake.
        total: u128,
    },
    /// The live validators certify only while all of them stay up.
    NoLiveSpare {
        /// Live stake after the live validator with the most stake is lost.
        live_after_loss: u128,
        /// Total stake.
        total: u128,
    },
}

impl std::fmt::Display for LaunchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFew { validators } => write!(
                f,
                "{validators} validators: at least four are needed to tolerate one failure, and a \
                 founding set needs at least {FOUNDING_VALIDATORS} validators on {FOUNDING_OPERATORS} or more \
                 independent operators so planned stops and attrition do not use up the margin"
            ),
            Self::NoHardwareIdentity { names } => write!(
                f,
                "no working hardware identity at launch: {}",
                names.join(", ")
            ),
            Self::NoStake => write!(f, "the set holds no stake"),
            Self::CannotCertify { live, total } => write!(
                f,
                "the live validators hold {live} of {total}, not more than two thirds: the chain could not start"
            ),
            Self::NoLiveSpare {
                live_after_loss,
                total,
            } => write!(
                f,
                "losing the largest live validator leaves {live_after_loss} of {total}, not more than two thirds: any one failure halts the chain"
            ),
        }
    }
}

/// What a passing set tolerates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchReport {
    /// Validators in the set.
    pub validators: usize,
    /// Validators live at launch.
    pub live: usize,
}

/// Checks a proposed genesis set. See the module documentation.
pub fn check_launch_set(set: &[LaunchValidator]) -> Result<LaunchReport, LaunchRefusal> {
    if set.len() < MIN_LAUNCH_VALIDATORS {
        return Err(LaunchRefusal::TooFew {
            validators: set.len(),
        });
    }
    let no_hw: Vec<String> = set
        .iter()
        .filter(|v| !v.hardware_identity)
        .map(|v| v.name.clone())
        .collect();
    if !no_hw.is_empty() {
        return Err(LaunchRefusal::NoHardwareIdentity { names: no_hw });
    }
    let total: u128 = set.iter().map(|v| v.stake).sum();
    if total == 0 {
        return Err(LaunchRefusal::NoStake);
    }
    let live: u128 = set.iter().filter(|v| v.live).map(|v| v.stake).sum();
    if !above_two_thirds(live, total) {
        return Err(LaunchRefusal::CannotCertify { live, total });
    }
    let largest_live = set
        .iter()
        .filter(|v| v.live)
        .map(|v| v.stake)
        .max()
        .unwrap_or(0);
    let live_after_loss = live - largest_live;
    if !above_two_thirds(live_after_loss, total) {
        return Err(LaunchRefusal::NoLiveSpare {
            live_after_loss,
            total,
        });
    }
    Ok(LaunchReport {
        validators: set.len(),
        live: set.iter().filter(|v| v.live).count(),
    })
}

/// Refuses stopping, disabling or restarting the validators in `stopping`
/// together unless the live validators that remain would still certify and
/// still survive one more loss. The whole stop set is judged at once: two
/// stops that each pass alone can together leave no spare. Every stage script
/// that is about to stop a validator unit calls this (through
/// `scripts/validator-prestop-check.sh`, which keeps a ledger of the stops in
/// progress and applies the same arithmetic to them all) first. A test run, a
/// deploy and a FINAL run are all stops.
pub fn check_stops(set: &[LaunchValidator], stopping: &[&str]) -> Result<(), LaunchRefusal> {
    let after: Vec<LaunchValidator> = set
        .iter()
        .cloned()
        .map(|mut v| {
            if stopping.contains(&v.name.as_str()) {
                v.live = false;
            }
            v
        })
        .collect();
    check_launch_set(&after).map(|_| ())
}

/// [`check_stops`] for one validator.
pub fn check_stop(set: &[LaunchValidator], stopping: &str) -> Result<(), LaunchRefusal> {
    check_stops(set, &[stopping])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(live: &[bool]) -> Vec<LaunchValidator> {
        live.iter()
            .enumerate()
            .map(|(i, l)| LaunchValidator {
                name: format!("v{i}"),
                stake: 5_000_000,
                live: *l,
                hardware_identity: true,
            })
            .collect()
    }

    #[test]
    fn headroom_follows_the_arithmetic_of_the_launch_check() {
        // seven equal: all live -> two losses survived; 6 live -> one; 5 -> none; 4 -> halted
        assert_eq!(headroom(&set(&[true; 7])), Headroom::Healthy);
        assert_eq!(headroom(&set(&[true, true, true, true, true, true, false])), Headroom::One);
        assert_eq!(headroom(&set(&[true, true, true, true, true, false, false])), Headroom::Zero);
        assert_eq!(headroom(&set(&[true, true, true, true, false, false, false])), Headroom::Halted);
        // four equal: all live is one loss from halt's margin -> Zero after one loss
        assert_eq!(headroom(&set(&[true; 4])), Headroom::One);
        assert_eq!(headroom(&set(&[true, true, true, false])), Headroom::Zero);
        assert_eq!(headroom(&set(&[true, true, false, false])), Headroom::Halted);
    }

    /// The alert rules in deploy/monitoring/alerts.yml count equal-stake
    /// validators: quorum = n - floor((n - 1) / 3), headroom = live - quorum
    /// (0 pages, 1 warns, negative is a halt). They must agree with
    /// [`headroom`] for every n and every live count.
    #[test]
    fn the_alert_rule_formula_agrees_with_headroom_for_every_size() {
        for n in 4usize..=40 {
            let quorum = n - (n - 1) / 3;
            for live_n in 0..=n {
                let live: Vec<bool> = (0..n).map(|i| i < live_n).collect();
                let by_count = live_n as i64 - quorum as i64;
                let expect = match by_count {
                    i64::MIN..=-1 => Headroom::Halted,
                    0 => Headroom::Zero,
                    1 => Headroom::One,
                    _ => Headroom::Healthy,
                };
                assert_eq!(headroom(&set(&live)), expect, "n = {n}, live = {live_n}");
            }
        }
    }

    #[test]
    fn a_set_of_four_passes_the_check_but_not_the_founding_requirement() {
        let four = set(&[true; 4]);
        assert!(check_launch_set(&four).is_ok());
        let adv = founding_advisories(&four, &["a", "b", "c", "d"]);
        assert_eq!(adv.len(), 1, "{adv:?}");
        let seven = set(&[true; 7]);
        assert!(founding_advisories(&seven, &["a", "a", "b", "b", "c", "c", "d"]).is_empty());
        assert_eq!(founding_advisories(&seven, &["a", "a", "a", "b", "b", "c", "c"]).len(), 1);
        assert_eq!(founding_advisories(&seven, &["a"]).len(), 1);
    }

    #[test]
    fn the_refusal_message_states_the_founding_requirement() {
        let err = check_launch_set(&set(&[true; 3])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least 7") && msg.contains("4 or more independent operators"), "{msg}");
    }

    /// The set the network launched with: four equal validators, one of them
    /// permanently gone. It certifies, but the loss of any one more halts it.
    #[test]
    fn the_founding_set_of_2026_is_refused() {
        let err = check_launch_set(&set(&[true, true, true, false])).unwrap_err();
        assert!(matches!(err, LaunchRefusal::NoLiveSpare { .. }), "{err}");
    }

    #[test]
    fn two_live_of_four_cannot_start() {
        let err = check_launch_set(&set(&[true, true, false, false])).unwrap_err();
        assert!(matches!(err, LaunchRefusal::CannotCertify { .. }), "{err}");
    }

    #[test]
    fn four_live_of_four_pass_with_a_spare() {
        let r = check_launch_set(&set(&[true; 4])).unwrap();
        assert_eq!((r.validators, r.live), (4, 4));
    }

    #[test]
    fn seven_with_two_dead_pass_and_with_three_dead_do_not() {
        // 5 live of 7: lose one, 4 of 7 is not above two thirds.
        let err =
            check_launch_set(&set(&[true, true, true, true, true, false, false])).unwrap_err();
        assert!(matches!(err, LaunchRefusal::NoLiveSpare { .. }), "{err}");
        // 6 live of 7: lose one, 5 of 7 is above two thirds (5/7 = 0.714).
        check_launch_set(&set(&[true, true, true, true, true, true, false])).unwrap();
    }

    #[test]
    fn fewer_than_four_validators_are_refused() {
        let err = check_launch_set(&set(&[true; 3])).unwrap_err();
        assert_eq!(err, LaunchRefusal::TooFew { validators: 3 });
    }

    #[test]
    fn a_validator_without_a_hardware_identity_is_refused_by_name() {
        let mut s = set(&[true; 4]);
        s[2].hardware_identity = false;
        let err = check_launch_set(&s).unwrap_err();
        assert_eq!(
            err,
            LaunchRefusal::NoHardwareIdentity {
                names: vec!["v2".into()]
            }
        );
    }

    /// Stopping a validator of the 2026 set (three live of four) is refused:
    /// the unit stopped on 19 Oct was the third of three.
    #[test]
    fn stopping_a_validator_of_the_2026_set_is_refused() {
        let s = set(&[true, true, true, false]);
        for name in ["v0", "v1", "v2"] {
            let err = check_stop(&s, name).unwrap_err();
            assert!(matches!(err, LaunchRefusal::CannotCertify { .. }), "{err}");
        }
    }

    #[test]
    fn four_live_of_four_cannot_lose_one_to_a_test_run() {
        // 3 of 4 would certify but have no spare: refused.
        let err = check_stop(&set(&[true; 4]), "v0").unwrap_err();
        assert!(matches!(err, LaunchRefusal::NoLiveSpare { .. }), "{err}");
    }

    #[test]
    fn seven_live_may_lose_one_but_not_a_second() {
        let mut s = set(&[true; 7]);
        check_stop(&s, "v0").unwrap();
        s[0].live = false;
        let err = check_stop(&s, "v1").unwrap_err();
        assert!(matches!(err, LaunchRefusal::NoLiveSpare { .. }), "{err}");
    }

    /// Counterexample from the membership model (bug 3): at n = 7 each single
    /// stop passes, but two together leave no spare and three halt the chain.
    #[test]
    fn two_stops_that_each_pass_alone_are_refused_together() {
        let s = set(&[true; 7]);
        for i in 0..7 {
            check_stop(&s, &format!("v{i}")).unwrap();
        }
        let err = check_stops(&s, &["v0", "v1"]).unwrap_err();
        assert!(matches!(err, LaunchRefusal::NoLiveSpare { .. }), "{err}");
        let err = check_stops(&s, &["v0", "v1", "v2"]).unwrap_err();
        assert!(matches!(err, LaunchRefusal::CannotCertify { .. }), "{err}");
    }

    #[test]
    fn the_stop_set_is_exactly_the_launch_rule_over_the_remainder() {
        let s = set(&[true; 10]);
        check_stops(&s, &["v0", "v1"]).unwrap();
        assert!(check_stops(&s, &["v0", "v1", "v2"]).is_err());
    }

    #[test]
    fn unequal_stake_is_weighed_by_stake_not_count() {
        let mut s = set(&[true; 4]);
        s[0].stake = 50_000_000;
        // losing the big validator is the failure that matters
        let mut dead_big = s.clone();
        dead_big[0].live = false;
        assert!(check_launch_set(&dead_big).is_err());
        check_launch_set(&s).unwrap_err();
    }
}
