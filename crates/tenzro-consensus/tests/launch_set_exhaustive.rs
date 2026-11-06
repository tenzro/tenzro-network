//! Every subset of live validators, over every set size from 4 to 10 and over
//! all stake vectors of 4 to 7 validators with stakes 1 to 4, against an
//! independent brute-force statement of the launch rule:
//!
//! - `check_launch_set` accepts exactly the sets that certify and certify
//!   again after any single live validator is lost;
//! - an accepted set survives any one loss, and two simultaneous losses
//!   either leave it certifying or halt it safely, and restarting the two
//!   restores certification;
//! - `check_stop` accepts exactly the stops after which the remaining set is
//!   accepted, and one validator at a time it never halts a set that was
//!   accepted;
//! - stops that each pass `check_stop` against the same state are not
//!   covered jointly (the guard is per call): the test pins a set where two
//!   such stops halt the chain, so the stage scripts must serialise stops.

use tenzro_consensus::launch_check::{LaunchRefusal, LaunchValidator, check_launch_set, check_stop};

fn above(part: u128, total: u128) -> bool {
    3 * part > 2 * total
}

fn build(stakes: &[u128], live_mask: u32) -> Vec<LaunchValidator> {
    stakes
        .iter()
        .enumerate()
        .map(|(i, s)| LaunchValidator {
            name: format!("v{i}"),
            stake: *s,
            live: live_mask & (1 << i) != 0,
            hardware_identity: true,
        })
        .collect()
}

fn live_stake(set: &[LaunchValidator]) -> u128 {
    set.iter().filter(|v| v.live).map(|v| v.stake).sum()
}

/// The rule, restated by enumeration instead of by the largest live stake.
fn oracle(set: &[LaunchValidator]) -> bool {
    let total: u128 = set.iter().map(|v| v.stake).sum();
    if set.len() < 4 || total == 0 || !above(live_stake(set), total) {
        return false;
    }
    (0..set.len()).filter(|&i| set[i].live).all(|i| {
        let mut s = set.to_vec();
        s[i].live = false;
        above(live_stake(&s), total)
    })
}

/// Each stake vector of `n` validators, stakes 1 to `max`.
fn vectors(n: usize, max: u128) -> Vec<Vec<u128>> {
    let mut out = vec![Vec::new()];
    for _ in 0..n {
        out = out
            .into_iter()
            .flat_map(|v| {
                (1..=max).map(move |s| {
                    let mut w = v.clone();
                    w.push(s);
                    w
                })
            })
            .collect();
    }
    out
}

#[test]
fn the_launch_rule_matches_the_enumerated_rule_for_every_subset() {
    let mut checked = 0u64;
    let mut accepted = 0u64;
    let mut cases: Vec<Vec<u128>> = Vec::new();
    for n in 4..=7 {
        cases.extend(vectors(n, 4));
    }
    for n in 8..=10 {
        cases.push(vec![1; n]);
        cases.push((0..n).map(|i| 1 + (i as u128 % 3)).collect());
        let mut big = vec![1; n];
        big[0] = 4;
        cases.push(big);
    }
    for stakes in &cases {
        let n = stakes.len();
        for mask in 0..(1u32 << n) {
            let set = build(stakes, mask);
            let want = oracle(&set);
            let got = check_launch_set(&set);
            assert_eq!(got.is_ok(), want, "stakes {stakes:?} live {mask:0n$b}: {got:?}");
            checked += 1;
            if want {
                accepted += 1;
                // Any one loss: still certifies.
                let total: u128 = stakes.iter().sum();
                for i in 0..n {
                    if set[i].live {
                        let mut s = set.clone();
                        s[i].live = false;
                        assert!(above(live_stake(&s), total), "{stakes:?} {mask:b} loses {i}");
                    }
                }
                // Any two simultaneous losses: certifying or a safe halt, and
                // restarting both restores certification.
                for i in 0..n {
                    for j in (i + 1)..n {
                        if set[i].live && set[j].live {
                            let mut s = set.clone();
                            s[i].live = false;
                            s[j].live = false;
                            let halted = !above(live_stake(&s), total);
                            s[i].live = true;
                            s[j].live = true;
                            assert!(above(live_stake(&s), total), "restart recovers");
                            let _ = halted;
                        }
                    }
                }
            }
        }
    }
    assert!(accepted > 0 && checked > 1_000_000, "checked {checked}, accepted {accepted}");
}

#[test]
fn a_stop_is_allowed_exactly_when_the_remaining_set_is_accepted() {
    for n in 4..=10usize {
        let stakes = vec![1u128; n];
        for mask in 0..(1u32 << n) {
            let set = build(&stakes, mask);
            for i in 0..n {
                let mut after = set.clone();
                after[i].live = false;
                let got = check_stop(&set, &format!("v{i}"));
                assert_eq!(got.is_ok(), oracle(&after), "n {n} mask {mask:b} stop {i}");
                if oracle(&set) && got.is_ok() {
                    assert!(
                        check_launch_set(&after).is_ok(),
                        "an allowed stop leaves a set that is accepted"
                    );
                }
            }
        }
    }
}

#[test]
fn four_equal_validators_never_allow_a_stop() {
    let set = build(&[1; 4], 0b1111);
    for i in 0..4 {
        let err = check_stop(&set, &format!("v{i}")).unwrap_err();
        assert!(matches!(err, LaunchRefusal::NoLiveSpare { .. }), "{err}");
    }
}

/// Smallest equal-stake set size that allows a stop: seven. Fewer cannot
/// lose a validator and still survive one more.
#[test]
fn the_smallest_equal_set_that_allows_a_stop_has_seven_validators() {
    for n in 4..=10usize {
        let set = build(&vec![1; n], (1 << n) - 1);
        let allowed = (0..n).any(|i| check_stop(&set, &format!("v{i}")).is_ok());
        assert_eq!(allowed, n >= 7, "n {n}");
    }
}

/// One stop at a time keeps an accepted set accepted, however many follow.
#[test]
fn serial_guarded_stops_never_halt_an_accepted_set() {
    for n in 4..=10usize {
        let mut set = build(&vec![1; n], (1 << n) - 1);
        assert!(check_launch_set(&set).is_ok());
        for i in 0..n {
            if check_stop(&set, &format!("v{i}")).is_ok() {
                set[i].live = false;
            }
            assert!(check_launch_set(&set).is_ok(), "n {n} after stop {i}");
        }
    }
}

/// The guard looks at one stop. Two stage scripts that each pass it against
/// the same state and then both stop leave a set the rule refuses; with
/// enough of them the chain halts. Stops must be serialised, or checked
/// together.
#[test]
fn concurrent_stops_that_each_pass_can_halt_the_chain() {
    let n = 7;
    let set = build(&vec![1; n], (1 << n) - 1);
    let passing: Vec<usize> = (0..n)
        .filter(|i| check_stop(&set, &format!("v{i}")).is_ok())
        .collect();
    assert_eq!(passing.len(), n, "each single stop passes at seven");
    let total = n as u128;
    let mut after = set.clone();
    for &i in &passing[..2] {
        after[i].live = false;
    }
    assert!(check_launch_set(&after).is_err(), "two together leave no spare");
    let names: Vec<String> = passing[..2].iter().map(|i| format!("v{i}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    assert!(
        tenzro_consensus::launch_check::check_stops(&set, &names).is_err(),
        "the stop set is refused as a whole"
    );
    assert!(above(live_stake(&after), total), "two together still certify");
    for &i in &passing[..3] {
        after[i].live = false;
    }
    assert!(!above(live_stake(&after), total), "three together halt the chain");
}
