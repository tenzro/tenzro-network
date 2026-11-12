//! Network emulation for the consensus core.
//!
//! The core is sans-IO, so the same code that runs in the node runs here
//! against an emulated wide-area network: per-region delays, jitter, loss,
//! per-node uplink bandwidth and per-node processing queues, with open-loop
//! transaction load. Runs are deterministic for a seed.
//!
//! Quick runs are ordinary tests. Long runs that measure the proof gates are
//! ignored by default and take their parameters from the environment; see
//! `gates.rs`.

pub mod baselines;
pub mod driver;
pub mod gates;
pub mod tdc;
pub mod wan;

#[cfg(test)]
mod tests {
    use super::driver::{Partition, Scenario, run};
    use super::tdc::{Behaviour, TdcParams, nodes};
    use super::wan::Wan;

    fn lan(n: usize, tps: f64, ms: u64) -> Scenario {
        let mut sc = Scenario::wan(n, tps, ms);
        sc.wan = Wan::spread(n, 1);
        sc.warmup_ms = 2_000;
        sc
    }

    /// The protocol's own latency under the local test genesis (500 ms
    /// checkpoints, 20 per epoch, epochs handing over), with every
    /// validator given the CPU it needs: `TDC_LAT_N` validators (default 7)
    /// on one LAN at `TDC_LAT_TPS` (default 20) for `TDC_LAT_MS` (default
    /// 120 s) of emulated time. Prints one `GATE {json}` line per load,
    /// with the wall time the emulation took on one core. Run in release
    /// with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn gate_local_genesis_latency() {
        use crate::config::TimeRules;
        let env = |k: &str, d: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let n = env("TDC_LAT_N", 7) as usize;
        let ms = env("TDC_LAT_MS", 120_000);
        let mut p = TdcParams::honest();
        p.time = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            handover_confirmations: 2,
            compact_interval_ms: 10_000,
            compact_handoff_ms: 30_000,
            leader_slots: 2,
            calendar_scale: 8_640,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        p.handover = true;
        p.sign_latency_ms = 5;
        for tps in [0, env("TDC_LAT_TPS", 20), 2_000] {
            let sc = lan(n, tps as f64, ms);
            let wall = std::time::Instant::now();
            let r = run(&sc, nodes(n, &p));
            let wall_ms = wall.elapsed().as_millis();
            let epochs = r.checkpoints_certified as f64 / p.time.epoch_checkpoints as f64;
            println!(
                "GATE {{\"validators\":{n},\"offered_tps\":{tps},\"emulated_ms\":{ms},\"ordered_p50_ms\":{:.0},\"ordered_p99_ms\":{:.0},\"certified_p50_ms\":{:.0},\"certified_p99_ms\":{:.0},\"max_stall_ms\":{:.0},\"height\":{},\"checkpoints\":{},\"epoch_s\":{:.1},\"safety_violations\":{},\"wall_ms\":{wall_ms}}}",
                r.ordered.p50,
                r.ordered.p99,
                r.certified.p50,
                r.certified.p99,
                r.max_stall_ms,
                r.common_height,
                r.checkpoints_certified,
                if epochs > 0.0 {
                    ms as f64 / 1_000.0 / epochs
                } else {
                    0.0
                },
                r.safety_violations,
            );
            assert_eq!(r.safety_violations, 0);
        }
    }

    /// Every protocol in the harness keeps up with the offered load: over a
    /// ten-region WAN, ordered throughput stays within 10% of what the
    /// clients submit.
    #[test]
    fn every_protocol_orders_the_offered_load_on_a_wan() {
        use super::baselines::{mysticeti_nodes, sailfish_nodes};
        let offered = 2_000.0;
        let sc = Scenario::wan(10, offered, 20_000);
        let reports = [
            ("tdc", run(&sc, nodes(10, &TdcParams::honest()))),
            ("sailfish", run(&sc, sailfish_nodes(10, 1_000))),
            ("mysticeti", run(&sc, mysticeti_nodes(10, 100, 1))),
        ];
        for (name, r) in &reports {
            println!(
                "THROUGHPUT {name}: ordered {:.0} of {offered} tx/s, p50 {:.0} ms, p99 {:.0} ms, height {}",
                r.ordered_tps, r.ordered.p50, r.ordered.p99, r.common_height
            );
            assert_eq!(r.safety_violations, 0, "{name}");
            assert!(
                r.ordered_tps >= 0.9 * offered,
                "{name} ordered {:.0} of {offered} tx/s: {r:?}",
                r.ordered_tps
            );
        }
    }

    #[test]
    fn four_validators_order_and_certify() {
        let sc = lan(4, 2_000.0, 10_000);
        let r = run(&sc, nodes(4, &TdcParams::honest()));
        assert_eq!(r.safety_violations, 0);
        assert!(r.common_height > 20, "{r:?}");
        assert!(r.ordered.count > 1_000.0, "{r:?}");
        assert!(r.certified.count > 1_000.0, "{r:?}");
        assert!(r.certified.p50 > r.ordered.p50);
    }

    #[test]
    fn a_single_validator_orders_and_certifies() {
        let sc = lan(1, 500.0, 6_000);
        let r = run(&sc, nodes(1, &TdcParams::honest()));
        assert!(r.common_height > 5, "{r:?}");
        // Rounds are paced, not proposed back to back: at most one per
        // minimum round interval.
        let floor = TdcParams::honest().config.min_round_interval_ms;
        assert!(r.common_height <= sc.duration_ms / floor + 1, "{r:?}");
        assert!(r.certified.count > 0.0, "{r:?}");
    }

    #[test]
    fn a_wan_committee_stays_live_with_f_crashed() {
        let mut sc = Scenario::wan(10, 2_000.0, 20_000);
        sc.crashed = vec![1, 5, 8];
        let r = run(&sc, nodes(10, &TdcParams::honest()));
        assert_eq!(r.safety_violations, 0);
        assert!(r.common_height > 10, "{r:?}");
        assert!(r.ordered.count > 1_000.0, "{r:?}");
    }

    #[test]
    fn equivocating_authors_break_neither_safety_nor_liveness() {
        let sc = Scenario::wan(10, 2_000.0, 20_000);
        let mut p = TdcParams::honest();
        p.behaviour = vec![Behaviour::Honest; 10];
        for i in [0, 3, 6] {
            p.behaviour[i] = Behaviour::Equivocate;
        }
        let r = run(&sc, nodes(10, &p));
        assert_eq!(r.safety_violations, 0);
        assert_eq!(r.certificate_conflicts, 0);
        assert!(r.common_height > 10, "{r:?}");
    }

    #[test]
    fn leaders_that_withhold_their_vertex_are_skipped() {
        let sc = Scenario::wan(10, 2_000.0, 20_000);
        let mut p = TdcParams::honest();
        p.behaviour = vec![Behaviour::Honest; 10];
        for i in [2, 4, 9] {
            p.behaviour[i] = Behaviour::WithholdLeaderVertex;
        }
        let r = run(&sc, nodes(10, &p));
        assert_eq!(r.safety_violations, 0);
        assert!(r.common_height > 10, "{r:?}");
    }

    /// Four equal validators, as the founding set of a network that
    /// stalled: one of them is gone for good. With only two
    /// of the four running, nothing is certified and no epoch ever closes,
    /// so no validator-set change (an ejection included) can be reached.
    #[test]
    fn four_equal_validators_with_two_live_certify_nothing() {
        let mut sc = lan(4, 20.0, 20_000);
        sc.crashed = vec![2, 3];
        let r = run(&sc, nodes(4, &TdcParams::honest()));
        assert_eq!(r.safety_violations, 0);
        assert_eq!(r.checkpoints_certified, 0, "{r:?}");
        assert_eq!(r.common_height, 0, "{r:?}");
    }

    /// The same set with three live: the chain advances, so epoch
    /// boundaries are reached and a set change can take effect.
    #[test]
    fn four_equal_validators_with_three_live_advance() {
        let mut sc = lan(4, 20.0, 20_000);
        sc.crashed = vec![3];
        let r = run(&sc, nodes(4, &TdcParams::honest()));
        assert_eq!(r.safety_violations, 0);
        assert_eq!(r.certificate_conflicts, 0);
        assert!(r.common_height > 5, "{r:?}");
        assert!(r.checkpoints_certified > 0, "{r:?}");
    }

    /// With the fourth gone for good and the third cut off, the two others
    /// stall at some height; when the third returns the chain continues from
    /// that height, not from the start, and nothing conflicts. The first
    /// run is the second one cut off inside the cut, so they share every
    /// event up to it.
    #[test]
    fn the_chain_resumes_from_the_same_height_when_the_third_validator_returns() {
        let cut = |duration_ms: u64| {
            let mut sc = lan(4, 20.0, duration_ms);
            sc.crashed = vec![3];
            sc.partition = Some(Partition {
                from_ms: 0,
                until_ms: 12_000,
                side_a: vec![0, 1],
            });
            run(&sc, nodes(4, &TdcParams::honest()))
        };
        let during = cut(12_000);
        assert_eq!(during.common_height, 0, "{during:?}");
        assert_eq!(during.checkpoints_certified, 0, "{during:?}");
        let after = cut(40_000);
        assert_eq!(after.safety_violations, 0);
        assert_eq!(after.certificate_conflicts, 0);
        assert!(after.common_height > during.common_height, "{after:?}");
        assert!(after.checkpoints_certified > 0, "{after:?}");
    }

    /// The dead fourth validator removed by governance, the live three
    /// remaining: the set advances on its own, which is the state an
    /// ejection leaves behind.
    #[test]
    fn three_live_validators_after_the_dead_fourth_is_ejected_advance() {
        let sc = lan(3, 20.0, 20_000);
        let r = run(&sc, nodes(3, &TdcParams::honest()));
        assert_eq!(r.safety_violations, 0);
        assert!(r.common_height > 5, "{r:?}");
        assert!(r.checkpoints_certified > 0, "{r:?}");
    }

    #[test]
    fn a_partition_orders_nothing_conflicting_and_heals() {
        let mut sc = Scenario::wan(10, 2_000.0, 30_000);
        sc.partition = Some(Partition {
            from_ms: 8_000,
            until_ms: 16_000,
            side_a: vec![0, 1, 2, 3, 4],
        });
        let r = run(&sc, nodes(10, &TdcParams::honest()));
        assert_eq!(r.safety_violations, 0);
        assert_eq!(r.certificate_conflicts, 0);
        let late = r
            .ordered_p50_by_second
            .iter()
            .filter(|(s, _)| *s >= 20)
            .count();
        assert!(late > 5, "progress after the heal: {r:?}");
    }

    #[test]
    fn validators_that_restart_recover_the_same_order_and_keep_going() {
        let sc = Scenario::wan(10, 2_000.0, 24_000);
        let mut p = TdcParams::honest();
        p.restart = Some((10_000, vec![0, 4, 7]));
        let r = run(&sc, nodes(10, &p));
        assert_eq!(r.safety_violations, 0);
        assert_eq!(r.certificate_conflicts, 0);
        let late = r
            .ordered_p50_by_second
            .iter()
            .filter(|(s, _)| *s >= 14)
            .count();
        assert!(late > 5, "progress after the restart: {r:?}");
        assert!(r.journal_mb_per_s > 0.0);
    }

    #[test]
    fn the_whole_committee_restarting_at_once_recovers() {
        let sc = Scenario::wan(7, 1_000.0, 24_000);
        let mut p = TdcParams::honest();
        p.restart = Some((10_000, (0..7).collect()));
        let r = run(&sc, nodes(7, &p));
        assert_eq!(r.safety_violations, 0);
        assert_eq!(r.certificate_conflicts, 0);
        let late = r
            .ordered_p50_by_second
            .iter()
            .filter(|(s, _)| *s >= 14)
            .count();
        assert!(late > 5, "progress after the restart: {r:?}");
    }

    #[test]
    fn a_validator_that_signs_two_checkpoints_is_convicted() {
        let sc = lan(7, 1_000.0, 8_000);
        let mut p = TdcParams::honest();
        p.behaviour = vec![Behaviour::Honest; 7];
        p.behaviour[2] = Behaviour::DoubleSign;
        let r = run(&sc, nodes(7, &p));
        assert_eq!(r.convicted, vec![2]);
        assert_eq!(r.certificate_conflicts, 0);
    }
}
