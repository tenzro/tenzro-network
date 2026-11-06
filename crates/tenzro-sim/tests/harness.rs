//! The simulator's own tests: runs replay from their seed, a healthy network
//! passes every invariant, the clients reach the chain's operations, and the
//! invariant checks catch what they exist for.
//!
//! Run with `cargo test --release -p tenzro-sim` (the debug build is slow).

use tenzro_sim::config::Faults;
use tenzro_sim::{Report, SimConfig};

fn short(profile: &str, seed: u64, days: f64) -> SimConfig {
    let mut c = SimConfig::profile(profile, seed).expect("profile");
    c.calendar_days = days;
    c
}

fn quiet(seed: u64, days: f64) -> SimConfig {
    let mut c = short("ci", seed, days);
    c.faults = Faults::none();
    c
}

fn run(c: SimConfig) -> Report {
    tenzro_sim::run(c, |_| {})
}

fn kinds(r: &Report) -> Vec<&'static str> {
    r.violations.iter().map(|v| v.kind).collect()
}

#[test]
fn a_run_replays_exactly_from_its_seed() {
    let a = run(short("ci", 11, 2.0));
    let b = run(short("ci", 11, 2.0));
    assert_eq!(
        (
            a.epochs,
            a.height,
            a.txs_submitted,
            a.checkpoints_certified,
            a.total_supply.clone()
        ),
        (
            b.epochs,
            b.height,
            b.txs_submitted,
            b.checkpoints_certified,
            b.total_supply.clone()
        )
    );
    assert_eq!(kinds(&a), kinds(&b));
    assert!(a.height > 0, "the chain grew");
}

#[test]
fn a_healthy_network_holds_every_invariant_across_epochs() {
    let r = run(quiet(3, 5.0));
    assert!(r.passed, "violations: {:#?}", r.violations);
    assert!(r.epochs >= 3, "epochs {}", r.epochs);
    assert!(
        r.ledger.applied > 100,
        "transactions applied {}",
        r.ledger.applied
    );
    assert!(r.ledger.fees_collected > 0, "fees flowed");
    assert!(r.max_commit_gap_ms < 30_000);
}

/// TNZO supply is fixed at genesis. Across fees and their burn, epoch
/// rewards released from the genesis-funded pool, validators joining and
/// leaving, and a double-signer's slash, total supply never rises above what
/// genesis allocated: every block is held to that, and the end of the run
/// is checked here.
#[test]
fn total_supply_never_exceeds_genesis_across_fees_rewards_and_slashes() {
    let healthy = run(quiet(3, 5.0));
    let slashed = run(short("double-sign", 13, 3.0));
    assert!(healthy.ledger.fees_collected > 0, "fees flowed");
    assert!(healthy.ledger.fees_burned > 0, "fees burned");
    assert!(healthy.epochs >= 3, "epochs closed {}", healthy.epochs);
    assert!(slashed.slashes >= 1, "no slash applied");
    for r in [&healthy, &slashed] {
        let genesis: u128 = r.genesis_supply.parse().expect("genesis supply");
        let supply: u128 = r.total_supply.parse().expect("total supply");
        assert!(genesis > 0);
        assert!(
            supply <= genesis,
            "{}: supply {supply} above genesis {genesis}",
            r.profile
        );
        let value: Vec<_> = r.violations.iter().filter(|v| v.kind == "value").collect();
        assert!(value.is_empty(), "{}: {value:#?}", r.profile);
    }
}

#[test]
fn clients_carry_governance_to_enactment_and_validators_join_and_leave() {
    let mut c = quiet(5, 12.0);
    c.workload.governance_every_days = 1.0;
    c.workload.stake_every_days = 2.0;
    let r = run(c);
    assert!(r.passed, "violations: {:#?}", r.violations);
    assert!(
        r.governance.enacted >= 1,
        "governance: {:?}, errors: {:?}",
        r.governance,
        r.workload_errors
    );
    assert!(
        r.stake_joins >= 1 && r.stake_exits >= 1,
        "joins {} exits {}",
        r.stake_joins,
        r.stake_exits
    );
    assert!(r.joins >= 1, "a standby validator was seated");
}

#[test]
fn a_commit_gap_beyond_the_bound_is_reported_with_its_seed() {
    // An idle committee commits a leader every few seconds: longer than a
    // bound of one millisecond.
    let mut c = quiet(7, 3.0);
    c.workload.transfers_per_s = 0.0;
    c.workload.governance_every_days = 0.0;
    c.workload.stake_every_days = 0.0;
    c.idle_round_interval_ms = 5_000;
    c.limits.commit_gap_ms = 1;
    let r = run(c);
    assert!(kinds(&r).contains(&"liveness"));
    let line = &r.failure_lines()[0];
    assert!(
        line.contains("seed 7") && line.contains("--seed 7"),
        "{line}"
    );
}

#[test]
fn consensus_state_over_its_cap_is_reported() {
    let mut c = quiet(9, 1.0);
    c.limits.max_core_entries = 1;
    let r = run(c);
    assert!(kinds(&r).contains(&"memory"));
}

#[test]
fn a_double_signing_validator_is_convicted_and_slashed() {
    let r = run(short("double-sign", 13, 3.0));
    assert!(r.equivocations_detected >= 1, "no equivocation detected");
    assert!(r.slashes >= 1, "no slash applied: {:?}", r.workload_errors);
}

/// A validator cut off while its epoch ended takes the handover from the
/// certificates the others formed, without having ordered the epoch's last
/// blocks. It enters the next epoch once it has imported and executed them,
/// from their state, so it signs that epoch's checkpoints with the others;
/// two such validators no longer stall finality. This seed has three
/// validators take a handover that way.
#[test]
fn a_validator_that_took_the_handover_from_a_certificate_signs_the_next_epoch() {
    let r = run(short("partition-heal", 885_189_281, 6.0));
    assert!(r.passed, "violations: {:#?}", r.violations);
    assert!(
        r.faults.late_handovers > 0,
        "no validator took a handover late"
    );
    assert!(r.epochs >= 5, "epochs {}", r.epochs);
}

/// The validators that formed an epoch's handover certificate may all leave
/// the committee or go down at once, before the others got it. A validator
/// that left still runs and serves the certificate, so the rest of the old
/// committee enters the next epoch. This seed stalled epoch 19 when the only
/// running holder had left the committee.
#[test]
fn a_validator_that_left_the_committee_still_serves_the_handover() {
    let r = run(short("ci", 885_189_240, 30.0));
    assert!(r.passed, "violations: {:#?}", r.violations);
    assert!(r.epochs >= 20, "epochs {}", r.epochs);
}

/// The validator that enters an epoch last is one round behind the others
/// when their round-1 vertices reach it. When it leads round 1 it proposes
/// its own round-1 vertex instead of jumping over its slot to round 2.
/// With hour-long idle epochs this seed had the last validator in skip its
/// round-1 slot at every epoch change from epoch 2.
#[test]
fn a_leader_that_enters_the_epoch_last_proposes_its_slot() {
    for seed in [1_064_921_811, 1_064_921_812] {
        let r = run(short("idle", seed, 0.13));
        assert!(r.passed, "seed {seed} violations: {:#?}", r.violations);
        assert!(r.epochs >= 2, "seed {seed} epochs {}", r.epochs);
    }
}

/// A validator that hears a withholding peer may close an epoch on that
/// peer's support before the others can, while a fifth validator is down.
/// It keeps proposing until the handover is certified, so the others close
/// the epoch too. This seed stood still when the validators that
/// closed first stopped proposing.
#[test]
fn validators_that_close_an_epoch_first_keep_proposing_until_it_hands_over() {
    let r = run(short("swarm", 8, 40.0));
    assert!(r.passed, "{:?}", r.failure_lines());
    assert!(r.epochs >= 20, "epochs {}", r.epochs);
}

/// A seed-drawn swarm run, with the node layer and every node fault, replays
/// exactly from its seed.
#[test]
fn a_swarm_run_replays_exactly_from_its_seed() {
    let mut c = short("swarm", 23, 3.0);
    c.faults.disk_stalls_per_node_hour = 40.0;
    c.faults.slow_validators = 1;
    c.faults.slow_factor = 4;
    c.workload.pipeline = 4;
    let a = run(c.clone());
    let b = run(c);
    assert_eq!(
        (
            a.epochs,
            a.height,
            a.txs_submitted,
            a.checkpoints_certified,
            a.node_store_peak_bytes,
            a.faults.disk_stalls
        ),
        (
            b.epochs,
            b.height,
            b.txs_submitted,
            b.checkpoints_certified,
            b.node_store_peak_bytes,
            b.faults.disk_stalls
        )
    );
    assert_eq!(kinds(&a), kinds(&b));
    assert!(a.node_store_peak_bytes > 0, "the node layer stored blocks");
}

/// Senders keeping several transactions in flight, routed as the node
/// routes them, never fail on their nonce, and every block reads back.
#[test]
fn pipelined_senders_keep_their_order_through_the_node_layer() {
    let r = run(short("pipeline", 5, 2.0));
    assert!(r.passed, "{:?}", r.failure_lines());
    assert!(r.txs_in_window > 0);
}

/// A block store over its bound is reported.
#[test]
fn a_block_store_over_its_bound_is_reported() {
    let mut c = quiet(9, 1.0);
    c.limits.max_node_store_bytes = 1;
    let r = run(c);
    assert!(kinds(&r).contains(&"memory"), "{:?}", kinds(&r));
}

/// A validator down for far more rounds than peers keep the DAG, but for
/// much less than an epoch, takes a certified checkpoint's ordering state
/// from a peer and orders on in the same epoch, instead of waiting for the
/// next handover. This seed restarts validators inside ten-minute epochs.
#[test]
fn a_validator_stopped_mid_epoch_rejoins_before_the_next_handover() {
    let r = run(short("restart-mid-epoch", 1, 8.0 / 1_440.0));
    assert!(r.passed, "violations: {:#?}", r.violations);
    assert_eq!(
        r.epochs, 0,
        "a handover came before the restarts were judged"
    );
    assert!(r.faults.fast_forwards > 0, "no validator fell out of reach");
}

/// A validator whose first proposal of an epoch went out a little after the
/// others' finds their next round already formed when it gets there. When
/// it leads a slot of that round it proposes its vertex in it first, rather
/// than jumping past it, so its slot is not skipped while it is up and
/// honest. In this seed validator 2 started epoch 2 half a second late and
/// led a slot of round 1.
#[test]
fn a_late_starter_leading_the_round_it_reaches_is_not_skipped() {
    let r = run(SimConfig::profile("idle", 917597314).expect("profile"));
    let skips: Vec<_> = r
        .violations
        .iter()
        .filter(|v| v.kind == "liveness")
        .collect();
    assert!(skips.is_empty(), "skipped honest leaders: {skips:#?}");
}

/// An epoch's closing checkpoint can fail to reach its quorum: a validator's
/// vote for it is lost while it signs the checkpoints after it, so the later
/// ones certify and it never does. A validator that was down when the epoch
/// closed then holds the handover with nothing to tell it is the handover,
/// and the others have moved on without it. The node that holds the closing
/// checkpoint's body names the handover to its core, so the validator
/// completes the epoch. These seeds stood still in epoch 1 and 18.
#[test]
fn a_validator_completes_an_epoch_whose_closing_checkpoint_never_certified() {
    for seed in [3_579_490_399_140_565u64, 3_579_490_399_140_538] {
        let r = run(SimConfig::profile("swarm", seed).expect("profile"));
        assert!(r.passed, "seed {seed}: {:?}", r.failure_lines());
    }
}
