//! What a run simulates: network size, time, load, faults and the limits the
//! invariants hold the network to. Named profiles cover the release gate.

use serde::Serialize;

/// How a validator behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Behaviour {
    /// Follows the protocol.
    Honest,
    /// Sends two different vertices every round, one to each half.
    Equivocate,
    /// Never sends its vertex in rounds it leads.
    WithholdLeaderVertex,
    /// Sends half its batches to nobody and its vertices to half the
    /// committee.
    Withhold,
    /// Signs a second, conflicting checkpoint at every index and sends it to
    /// half the committee.
    DoubleSign,
    /// Receives everything and sends nothing.
    Mute,
}

/// Seeded fault injection.
#[derive(Debug, Clone, Serialize)]
pub struct Faults {
    /// Crashes per validator per simulated hour.
    pub crashes_per_node_hour: f64,
    /// Shortest and longest short downtime, milliseconds.
    pub short_down_ms: (u64, u64),
    /// Share of crashes that stay down for whole epochs, past the window
    /// peers keep the DAG for.
    pub long_down_share: f64,
    /// Shortest and longest long downtime, in epochs.
    pub long_down_epochs: (u64, u64),
    /// Partitions per simulated hour.
    pub partitions_per_hour: f64,
    /// Share of partitions that leave no side with a quorum.
    pub quorum_loss_share: f64,
    /// Shortest and longest partition, milliseconds.
    pub partition_ms: (u64, u64),
    /// Delay spikes per simulated hour.
    pub spikes_per_hour: f64,
    /// Latency multiplier of a spike.
    pub spike_factor: (u64, u64),
    /// Shortest and longest spike, milliseconds.
    pub spike_ms: (u64, u64),
    /// Probability that a frame is dropped.
    pub frame_loss: f64,
    /// Largest clock offset a validator restarts with, milliseconds either
    /// way.
    pub max_skew_ms: u64,
    /// Validators that misbehave from the start, by id. Kept within `f`
    /// together with the crashed ones.
    pub byzantine: Vec<(u32, Behaviour)>,
    /// Disk stalls per validator per simulated hour: the node's event loop
    /// blocks on storage and processes nothing until the stall ends.
    pub disk_stalls_per_node_hour: f64,
    /// Shortest and longest disk stall, milliseconds.
    pub disk_stall_ms: (u64, u64),
    /// Validators that process everything this many times slower than the
    /// rest, chosen from the seed (0: none).
    pub slow_validators: u32,
    /// How many times slower a slow validator processes.
    pub slow_factor: u64,
    /// Share of the run during which faults start; the rest runs healed,
    /// every downtime and partition ending as scheduled, so the network is
    /// judged on recovering (1.0: faults until the end).
    pub faults_until_share: f64,
    /// Most extra signing latency, drawn per checkpoint, milliseconds: a
    /// validator then signs some checkpoints after the ones that follow.
    pub sign_jitter_ms: u64,
    /// One honest validator crashed per epoch at a fixed offset from an
    /// epoch boundary (none: off).
    pub boundary_crashes: Option<BoundaryCrashes>,
    /// Extra signing latency for some validators on the last checkpoints
    /// of every epoch (none: off).
    pub boundary_sign_burst: Option<SignBurst>,
    /// Partitions placed relative to epoch boundaries (none: off).
    pub boundary_partitions: Option<BoundaryPartitions>,
    /// A validator that goes silent once its exit commits, to test that
    /// the epoch it leaves still certifies without it (false: off).
    pub exit_goes_mute: bool,
}

/// Crashes placed relative to epoch boundaries. Epochs end after a number
/// of certified checkpoints rather than on a clock, so a boundary is the
/// moment the first validator enters the next epoch; a negative offset is
/// measured back from the boundary predicted one epoch length after the
/// last entry.
#[derive(Debug, Clone, Serialize)]
pub struct BoundaryCrashes {
    /// Offsets from the boundary, milliseconds, used in turn: epoch `k`
    /// uses `offsets_ms[k % len]`.
    pub offsets_ms: Vec<i64>,
    /// How long each crashed validator stays down, milliseconds.
    pub down_ms: u64,
}

/// A signing-latency burst on the checkpoints that close an epoch.
#[derive(Debug, Clone, Serialize)]
pub struct SignBurst {
    /// First position within the epoch (0-based) the burst covers.
    pub index_from: u64,
    /// Last position within the epoch the burst covers.
    pub index_to: u64,
    /// Extra signing latency, milliseconds.
    pub extra_ms: u64,
    /// Validators slowed in each epoch; in epoch `k` they are the seated
    /// members at positions `k, k+1, ..` (mod the committee size).
    pub validators: u32,
}

/// A governed parameter change the workload drives at a calendar day,
/// through a standard-track proposal every seated honest validator votes
/// for, so its activation epoch is deterministic.
#[derive(Debug, Clone, Serialize)]
pub struct ParamChange {
    /// Calendar day the proposal opens.
    pub day: f64,
    /// Governed parameter key.
    pub name: String,
    /// Value to set, within the parameter's bounds.
    pub value: u64,
}

/// Partitions placed relative to epoch boundaries: at each boundary a
/// side of the committee is cut off from just before the boundary to
/// just after, then healed. The boundary is predicted one epoch length
/// after the last epoch entry, as for boundary crashes.
#[derive(Debug, Clone, Serialize)]
pub struct BoundaryPartitions {
    /// First and last calendar day the partitions are placed between.
    pub from_day: f64,
    /// Last calendar day.
    pub to_day: f64,
    /// Offset of the cut from the boundary, milliseconds (negative is
    /// before it).
    pub start_offset_ms: i64,
    /// How long the cut lasts, milliseconds.
    pub duration_ms: u64,
    /// How many validators are on the cut-off side.
    pub side_size: u32,
    /// Rotate the cut-off side by epoch.
    pub rotate: bool,
    /// Never cut off a slow validator.
    pub exclude_slow: bool,
    /// Never cut off a byzantine validator (so the honest quorum is the
    /// one under test).
    pub honest_only: bool,
}

impl Faults {
    /// No faults.
    pub fn none() -> Self {
        Self {
            crashes_per_node_hour: 0.0,
            short_down_ms: (2_000, 30_000),
            long_down_share: 0.0,
            long_down_epochs: (3, 30),
            partitions_per_hour: 0.0,
            quorum_loss_share: 0.0,
            partition_ms: (2_000, 30_000),
            spikes_per_hour: 0.0,
            spike_factor: (3, 10),
            spike_ms: (1_000, 20_000),
            frame_loss: 0.0,
            max_skew_ms: 0,
            byzantine: Vec::new(),
            disk_stalls_per_node_hour: 0.0,
            disk_stall_ms: (200, 5_000),
            slow_validators: 0,
            slow_factor: 1,
            faults_until_share: 1.0,
            sign_jitter_ms: 0,
            boundary_crashes: None,
            boundary_sign_burst: None,
            boundary_partitions: None,
            exit_goes_mute: false,
        }
    }

    /// Every fault class at once. Rates are per hour of simulated block
    /// time, which a compressed calendar makes short: at one epoch per
    /// calendar day, an hour of block time is about a year of epochs.
    pub fn chaos() -> Self {
        Self {
            crashes_per_node_hour: 40.0,
            long_down_share: 0.25,
            partitions_per_hour: 30.0,
            quorum_loss_share: 0.25,
            spikes_per_hour: 30.0,
            frame_loss: 0.002,
            max_skew_ms: 1_000,
            ..Self::none()
        }
    }
}

/// The client load and the operations clients run over the calendar.
#[derive(Debug, Clone, Serialize)]
pub struct Workload {
    /// Value transfers per simulated second, across the network.
    pub transfers_per_s: f64,
    /// User accounts.
    pub users: u32,
    /// Calendar days between governance proposals (0: none).
    pub governance_every_days: f64,
    /// Calendar days between stake changes: one validator exits, one
    /// registered validator without a bond joins, one tops up (0: none).
    pub stake_every_days: f64,
    /// Transactions one sender keeps in flight, each with the next nonce
    /// after the ones it is waiting on (1: one at a time).
    pub pipeline: u32,
    /// Governed parameter changes to drive at set calendar days
    /// (empty: none). Non-empty turns the governance workload on even
    /// when `governance_every_days` is zero.
    pub param_schedule: Vec<ParamChange>,
}

/// Limits the invariants hold the network to.
#[derive(Debug, Clone, Serialize)]
pub struct Limits {
    /// Longest time commits may stand still while a quorum of honest
    /// validators is up and connected, milliseconds.
    pub commit_gap_ms: u64,
    /// Longest time certification may stand still, likewise.
    pub finality_gap_ms: u64,
    /// Time a restarted or newly seated validator has to reach the
    /// network's epoch and height, milliseconds of live network.
    pub rejoin_ms: u64,
    /// Most entries any validator's consensus state may hold.
    pub max_core_entries: usize,
    /// Most bytes any validator's consensus state may buffer.
    pub max_core_bytes: usize,
    /// Most recovery journal any validator may write in one epoch, bytes.
    pub max_journal_epoch_bytes: u64,
    /// Late-run memory and storage over early-run, at most.
    pub growth_ratio: f64,
    /// A run whose commits stand still this long ends early, milliseconds.
    pub dead_after_ms: u64,
    /// Most bytes any validator's block store may hold.
    pub max_node_store_bytes: u64,
    /// A leader slot skipped while the network was calm this long before
    /// it (no partition, spike, disk stall or frame loss, every member up
    /// this long), with the leader honest, connected and not slow, is a
    /// liveness violation, milliseconds.
    pub calm_ms: u64,
    /// Most transactions, in basis points of those sent, that may run ahead
    /// of their nonce while their predecessor is in flight.
    pub max_ahead_of_nonce_bps: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            commit_gap_ms: 30_000,
            finality_gap_ms: 30_000,
            rejoin_ms: 300_000,
            max_core_entries: 2_000_000,
            max_core_bytes: 1 << 30,
            max_journal_epoch_bytes: 1 << 30,
            growth_ratio: 1.5,
            dead_after_ms: 1_800_000,
            max_node_store_bytes: 1 << 30,
            calm_ms: 10_000,
            max_ahead_of_nonce_bps: 100,
        }
    }
}

/// One run.
#[derive(Debug, Clone, Serialize)]
pub struct SimConfig {
    /// Profile name, for reports and replay lines.
    pub profile: String,
    /// RNG seed: the whole run follows from it.
    pub seed: u64,
    /// Validators bonded at genesis.
    pub validators: u32,
    /// Registered validators that join later by bonding.
    pub standby: u32,
    /// Checkpoint interval, milliseconds of block time.
    pub checkpoint_interval_ms: u64,
    /// Checkpoints per epoch.
    pub epoch_checkpoints: u64,
    /// Calendar time per epoch, milliseconds (the calendar scale follows).
    pub calendar_epoch_ms: u64,
    /// Idle round interval, milliseconds.
    pub idle_round_interval_ms: u64,
    /// Calendar days to simulate.
    pub calendar_days: f64,
    /// Hard cap on simulated block time, milliseconds (0: none).
    pub max_sim_ms: u64,
    /// Timer resolution of the validators, milliseconds.
    pub tick_ms: u64,
    /// How often validators cut client transactions into a batch.
    pub batch_interval_ms: u64,
    /// Modeled hardware signing latency of a checkpoint vote, milliseconds.
    pub sign_latency_ms: u64,
    /// One-way latency between validators, milliseconds.
    pub latency_ms: (u64, u64),
    /// Uplink per validator, bits per second.
    pub uplink_bps: u64,
    /// Cost of verifying one composite (post-quantum and classical)
    /// signature, microseconds.
    pub verify_us: u64,
    /// Certificates each validator keeps per epoch, in epochs, for peers
    /// that missed them; a validator further behind syncs from the
    /// certified chain.
    pub certificate_retention_epochs: u64,
    /// Client load and operations.
    pub workload: Workload,
    /// Faults.
    pub faults: Faults,
    /// Limits.
    pub limits: Limits,
    /// Measurement starts here, milliseconds of block time.
    pub warmup_ms: u64,
    /// Starting values of governed network parameters (genesis
    /// `[network_params]`).
    pub network_params: std::collections::BTreeMap<String, u64>,
    /// Blocks each validator's node layer keeps in its block store, written
    /// and read back through the node's block codec (0: no node layer).
    pub node_blocks_kept: u64,
}

const DAY_MS: u64 = 86_400_000;

impl SimConfig {
    /// Block time one epoch spans.
    pub fn epoch_ms(&self) -> u64 {
        self.checkpoint_interval_ms * self.epoch_checkpoints
    }

    /// Calendar milliseconds per block-time millisecond.
    pub fn calendar_scale(&self) -> u64 {
        (self.calendar_epoch_ms / self.epoch_ms()).max(1)
    }

    /// Block time the run covers.
    pub fn duration_ms(&self) -> u64 {
        let d = (self.calendar_days * DAY_MS as f64 / self.calendar_scale() as f64) as u64;
        if self.max_sim_ms > 0 {
            d.min(self.max_sim_ms)
        } else {
            d
        }
    }

    fn base(profile: &str, seed: u64) -> Self {
        Self {
            profile: profile.into(),
            seed,
            validators: 4,
            standby: 2,
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            calendar_epoch_ms: DAY_MS,
            idle_round_interval_ms: 1_000,
            calendar_days: 7.0,
            max_sim_ms: 0,
            tick_ms: 10,
            batch_interval_ms: 50,
            sign_latency_ms: 20,
            latency_ms: (10, 120),
            uplink_bps: 1_000_000_000,
            verify_us: 300,
            certificate_retention_epochs: 64,
            workload: Workload {
                transfers_per_s: 20.0,
                users: 64,
                governance_every_days: 10.0,
                stake_every_days: 15.0,
                pipeline: 1,
                param_schedule: Vec::new(),
            },
            faults: Faults::none(),
            limits: Limits::default(),
            warmup_ms: 5_000,
            network_params: Default::default(),
            node_blocks_kept: 256,
        }
    }

    /// A named profile.
    ///
    /// - `ci`: 4 validators and 2 joining later, 30 calendar days at one
    ///   epoch per day, every fault class; minutes.
    /// - `years`: the same network over three calendar years.
    /// - `idle`: 4 validators, no load, the node's default epoch, six hours
    ///   of block time.
    /// - `restart-mid-epoch`: ten-minute epochs, validators down for tens of
    ///   seconds to two minutes inside them, so each has to rejoin its epoch
    ///   well before the next handover.
    /// - `restart-past-window`, `partition-heal`, `clock-skew`,
    ///   `double-sign`, `equivocate`, `loss`: one fault class each, 10
    ///   calendar days.
    /// - `scale-<n>`: `n` validators, two minutes of block time under load,
    ///   no faults, for the throughput and latency ladder.
    /// - `node`: every fault class with the node-layer ones (disk stalls, a
    ///   slow validator, pipelined senders), faults stopping at 80% of the
    ///   run.
    /// - `block-load`: pipelined load across partitions that stop commits,
    ///   so a commit releases a backlog larger than a block.
    /// - `pipeline`: senders keeping eight transactions in flight.
    /// - `exact-quorum`: 7 validators restarting often, two at a time, so
    ///   the rest are exactly a quorum, signing checkpoints out of order.
    /// - `lookahead-1`: 7 validators, two of them slow, under a governed
    ///   leader lookahead of one round.
    /// - `slow`: 7 validators, two of them eight times slower.
    /// - `epoch-edge-crash`: 7 validators, no random faults, one validator
    ///   crashed for 3 s per epoch at an offset from the boundary that
    ///   cycles through 1.5 s and 0.4 s before it and 0, 0.6 and 1.2 s
    ///   after it, the crashed validator rotating every five epochs; it
    ///   must rejoin its epoch within 20 s.
    /// - `restart-past-retention`: peers keep two epochs of certificates
    ///   and every crash outlasts them while validators join, exit and
    ///   governance runs, so each restart syncs across set changes.
    /// - `boundary-sign-burst-a`, `-b`: no restarts; two (a) or three (b)
    ///   validators sign the last two checkpoints of every epoch 2.5 s
    ///   late; certification may stand still at most 10 s.
    /// - `swarm`: every setting drawn from the seed (fault classes on or
    ///   off, rates, committee size, load), faults stopping at 70% of the
    ///   run; the explorer runs one seed after another.
    pub fn profile(name: &str, seed: u64) -> Option<Self> {
        let mut c = Self::base(name, seed);
        match name {
            "ci" => {
                c.calendar_days = 30.0;
                c.faults = Faults::chaos();
                c.workload.governance_every_days = 6.0;
                c.workload.stake_every_days = 8.0;
            }
            "years" => {
                c.calendar_days = 3.0 * 365.0;
                c.faults = Faults::chaos();
            }
            "idle" => {
                c.epoch_checkpoints = 7_200;
                c.calendar_epoch_ms = 3_600_000;
                c.idle_round_interval_ms = 5_000;
                c.calendar_days = 0.25;
                c.workload.transfers_per_s = 0.0;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.standby = 0;
            }
            "restart-mid-epoch" => {
                c.epoch_checkpoints = 1_200;
                c.calendar_epoch_ms = 600_000;
                c.calendar_days = 20.0 / 1_440.0;
                c.standby = 0;
                c.workload.transfers_per_s = 5.0;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.faults.crashes_per_node_hour = 12.0;
                c.faults.short_down_ms = (20_000, 120_000);
            }
            "restart-past-window" => {
                c.calendar_days = 10.0;
                c.faults.crashes_per_node_hour = 60.0;
                c.faults.long_down_share = 1.0;
                c.faults.long_down_epochs = (2, 12);
            }
            "partition-heal" => {
                c.calendar_days = 10.0;
                c.faults.partitions_per_hour = 120.0;
                c.faults.quorum_loss_share = 0.5;
            }
            "clock-skew" => {
                c.calendar_days = 10.0;
                c.faults.crashes_per_node_hour = 60.0;
                c.faults.max_skew_ms = 5_000;
            }
            "double-sign" => {
                c.calendar_days = 10.0;
                c.faults.byzantine = vec![(3, Behaviour::DoubleSign)];
            }
            "equivocate" => {
                c.calendar_days = 10.0;
                c.faults.byzantine = vec![(3, Behaviour::Equivocate)];
            }
            "withhold" => {
                c.calendar_days = 10.0;
                c.faults.byzantine = vec![(3, Behaviour::WithholdLeaderVertex)];
            }
            "loss" => {
                c.calendar_days = 10.0;
                c.faults.frame_loss = 0.02;
                c.faults.spikes_per_hour = 120.0;
            }
            "node" => {
                c.calendar_days = 120.0;
                c.faults = Faults::chaos();
                c.faults.disk_stalls_per_node_hour = 20.0;
                c.faults.slow_validators = 1;
                c.faults.slow_factor = 4;
                c.faults.faults_until_share = 0.8;
                c.workload.pipeline = 4;
            }
            "block-load" => {
                c.calendar_days = 60.0;
                c.workload.transfers_per_s = 120.0;
                c.workload.users = 4_096;
                c.workload.pipeline = 4;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.faults.partitions_per_hour = 40.0;
                c.faults.quorum_loss_share = 1.0;
                c.faults.partition_ms = (10_000, 30_000);
            }
            "pipeline" => {
                c.calendar_days = 30.0;
                c.workload.transfers_per_s = 100.0;
                c.workload.users = 256;
                c.workload.pipeline = 8;
            }
            "exact-quorum" => {
                c.validators = 7;
                c.standby = 0;
                c.calendar_days = 120.0;
                c.faults.crashes_per_node_hour = 30.0;
                c.faults.short_down_ms = (2_000, 20_000);
                c.faults.sign_jitter_ms = 1_500;
                c.workload.stake_every_days = 0.0;
            }
            "lookahead-1" => {
                c.validators = 7;
                c.standby = 0;
                c.calendar_days = 60.0;
                c.faults.slow_validators = 2;
                c.faults.slow_factor = 8;
                c.faults.crashes_per_node_hour = 30.0;
                c.network_params
                    .insert("consensus.leader_lookahead_rounds".into(), 1);
            }
            "slow" => {
                c.validators = 7;
                c.standby = 0;
                c.calendar_days = 60.0;
                c.faults.slow_validators = 2;
                c.faults.slow_factor = 8;
                c.workload.pipeline = 4;
            }
            "epoch-edge-crash" => {
                c.validators = 7;
                c.standby = 1;
                c.calendar_days = 150.0;
                c.idle_round_interval_ms = 5_000;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 25.0;
                c.faults.boundary_crashes = Some(BoundaryCrashes {
                    offsets_ms: vec![-1_500, -400, 0, 600, 1_200],
                    down_ms: 3_000,
                });
                c.limits.rejoin_ms = 20_000;
            }
            "restart-past-retention" => {
                c.validators = 7;
                c.standby = 2;
                c.certificate_retention_epochs = 2;
                c.calendar_days = 120.0;
                c.workload.governance_every_days = 4.0;
                c.workload.stake_every_days = 5.0;
                c.workload.pipeline = 2;
                c.faults.crashes_per_node_hour = 40.0;
                c.faults.long_down_share = 1.0;
                c.faults.long_down_epochs = (3, 6);
                c.faults.faults_until_share = 0.9;
                c.limits.rejoin_ms = 120_000;
            }
            "boundary-sign-burst-a" | "boundary-sign-burst-b" => {
                c.validators = 7;
                c.standby = 0;
                c.calendar_days = 120.0;
                c.idle_round_interval_ms = 5_000;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.faults.boundary_sign_burst = Some(SignBurst {
                    index_from: 18,
                    index_to: 19,
                    extra_ms: 2_500,
                    validators: if name.ends_with("-a") { 2 } else { 3 },
                });
                c.limits.finality_gap_ms = 10_000;
                c.limits.commit_gap_ms = 10_000;
            }
            // 50 validators under an intercontinental one-way latency mix
            // with jitter, matching the private-network netem conditions stage.
            "netcond-intercont" => {
                c.validators = 50;
                c.standby = 0;
                c.epoch_checkpoints = 120;
                c.calendar_epoch_ms = 86_400_000;
                c.calendar_days = 1.0;
                c.max_sim_ms = 30_000;
                c.warmup_ms = 10_000;
                c.workload.transfers_per_s = 50.0;
                c.workload.users = 256;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.latency_ms = (15, 90);
                c.faults.spikes_per_hour = 120.0;
                c.faults.spike_factor = (2, 6);
                c.faults.spike_ms = (20, 80);
                c.faults.faults_until_share = 1.0;
                c.node_blocks_kept = 0;
            }
            // 50 validators under 3% frame loss, the same latency mix and
            // clock skew, matching the netem loss and skew profiles.
            "netcond-loss" => {
                c.validators = 50;
                c.standby = 0;
                c.epoch_checkpoints = 120;
                c.calendar_epoch_ms = 86_400_000;
                c.calendar_days = 1.0;
                c.max_sim_ms = 30_000;
                c.warmup_ms = 10_000;
                c.workload.transfers_per_s = 50.0;
                c.workload.users = 256;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.latency_ms = (15, 90);
                c.faults.frame_loss = 0.03;
                c.faults.spikes_per_hour = 120.0;
                c.faults.max_skew_ms = 500;
                c.faults.faults_until_share = 1.0;
                c.node_blocks_kept = 0;
            }
            // A governed leader-lookahead change activates while boundary
            // partitions straddle the activation boundary and a validator
            // joins and exits: every node must enter each epoch under one
            // leader schedule, with no fork or stall.
            "param-activation-partition" => {
                c.validators = 7;
                c.standby = 0;
                c.calendar_days = 100.0;
                c.workload.pipeline = 2;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.workload.param_schedule = vec![
                    ParamChange {
                        day: 20.0,
                        name: "consensus.leader_lookahead_rounds".into(),
                        value: 1,
                    },
                    ParamChange {
                        day: 40.0,
                        name: "consensus.leader_lookahead_rounds".into(),
                        value: 4,
                    },
                    ParamChange {
                        day: 60.0,
                        name: "consensus.leader_lookahead_rounds".into(),
                        value: 1,
                    },
                    ParamChange {
                        day: 80.0,
                        name: "consensus.leader_lookahead_rounds".into(),
                        value: 4,
                    },
                ];
                c.faults.slow_validators = 1;
                c.faults.slow_factor = 4;
                c.faults.boundary_partitions = Some(BoundaryPartitions {
                    from_day: 15.0,
                    to_day: 90.0,
                    start_offset_ms: -2_000,
                    duration_ms: 5_000,
                    side_size: 2,
                    rotate: true,
                    exclude_slow: true,
                    honest_only: true,
                });
            }
            // A validator goes silent the moment its exit commits: the epoch
            // it leaves must still certify with the rest, a joiner must seat,
            // and every node must agree on the epoch it was removed.
            "exit-mute" => {
                c.validators = 7;
                c.standby = 4;
                c.calendar_days = 90.0;
                c.workload.pipeline = 2;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 20.0;
                c.faults.crashes_per_node_hour = 20.0;
                c.faults.short_down_ms = (3_000, 8_000);
                c.faults.sign_jitter_ms = 0;
                c.faults.exit_goes_mute = true;
            }
            // One validator double-signs and is slashed; boundary partitions
            // keep a lagging honest validator over the removal boundary. No
            // certificate past the removal may carry the removed validator's
            // signature, and all honest nodes must agree on the removal epoch.
            "slash-removal-partition" => {
                c.validators = 7;
                c.standby = 0;
                c.calendar_days = 60.0;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.faults.byzantine = vec![(6, Behaviour::DoubleSign)];
                c.faults.boundary_partitions = Some(BoundaryPartitions {
                    from_day: 0.0,
                    to_day: 60.0,
                    start_offset_ms: -1_500,
                    duration_ms: 4_000,
                    side_size: 1,
                    rotate: true,
                    exclude_slow: false,
                    honest_only: true,
                });
            }
            "swarm" => c.swarm(),
            other => {
                let n: u32 = other.strip_prefix("scale-")?.parse().ok()?;
                c.validators = n;
                c.standby = 0;
                c.epoch_checkpoints = 120;
                c.calendar_epoch_ms = 3_600_000;
                c.calendar_days = 1.0;
                // One process simulates every validator, so the cost grows with
                // the square of the committee: larger rungs run shorter.
                c.max_sim_ms = match n {
                    0..=50 => 120_000,
                    51..=100 => 60_000,
                    _ => 40_000,
                };
                c.warmup_ms = 15_000;
                c.workload.transfers_per_s = 500.0;
                c.workload.users = 4_096;
                c.workload.governance_every_days = 0.0;
                c.workload.stake_every_days = 0.0;
                c.latency_ms = (20, 150);
                // The ladder measures the consensus core alone.
                c.node_blocks_kept = 0;
            }
        }
        Some(c)
    }

    /// Draws every setting from the seed, swarm style: each fault class is
    /// on or off with its own rate, so one run concentrates on a few faults
    /// and many runs cover their combinations.
    fn swarm(&mut self) {
        use rand::{Rng, SeedableRng};
        let mut r = rand::rngs::StdRng::seed_from_u64(self.seed ^ 0x5157_4152_4D00_0001);
        let on = |r: &mut rand::rngs::StdRng| r.gen_bool(0.5);
        self.validators = r.gen_range(4..=7);
        self.standby = r.gen_range(0..=2);
        self.calendar_days = r.gen_range(30..=120) as f64;
        self.workload.transfers_per_s = [0.0, 5.0, 20.0, 60.0, 150.0][r.gen_range(0..5)];
        self.workload.users = [64, 256, 4_096][r.gen_range(0..3)];
        self.workload.pipeline = [1, 2, 4, 8][r.gen_range(0..4)];
        self.workload.governance_every_days = if on(&mut r) { 3.0 } else { 0.0 };
        self.workload.stake_every_days = if on(&mut r) { 4.0 } else { 0.0 };
        let f = &mut self.faults;
        if on(&mut r) {
            f.crashes_per_node_hour = r.gen_range(5.0..120.0);
            f.long_down_share = if on(&mut r) {
                r.gen_range(0.0..0.5)
            } else {
                0.0
            };
        }
        if on(&mut r) {
            f.partitions_per_hour = r.gen_range(5.0..120.0);
            f.quorum_loss_share = r.gen_range(0.0..1.0);
            f.partition_ms = (2_000, r.gen_range(5_000..40_000));
        }
        if on(&mut r) {
            f.spikes_per_hour = r.gen_range(5.0..120.0);
        }
        if on(&mut r) {
            f.frame_loss = r.gen_range(0.0..0.02);
        }
        if on(&mut r) {
            f.max_skew_ms = r.gen_range(0..5_000);
        }
        if on(&mut r) {
            f.disk_stalls_per_node_hour = r.gen_range(5.0..60.0);
        }
        if on(&mut r) {
            f.slow_validators = 1 + (self.validators - 4) / 3;
            f.slow_factor = r.gen_range(2..=8);
        }
        if r.gen_bool(0.25) {
            let kinds = [
                Behaviour::Equivocate,
                Behaviour::WithholdLeaderVertex,
                Behaviour::Withhold,
                Behaviour::DoubleSign,
                Behaviour::Mute,
            ];
            f.byzantine = vec![(self.validators - 1, kinds[r.gen_range(0..kinds.len())])];
        }
        // Drawn last, so the draws above keep their meaning for a seed.
        if on(&mut r) {
            f.sign_jitter_ms = r.gen_range(0..2_000);
        }
        f.faults_until_share = 0.7;
        if r.gen_bool(0.25) {
            self.network_params.insert(
                "consensus.leader_lookahead_rounds".into(),
                r.gen_range(1..=4),
            );
        }
    }

    /// The profiles the CI-sized gate runs, in order.
    pub const GATE: &'static [&'static str] = &[
        "ci",
        "restart-mid-epoch",
        "restart-past-window",
        "partition-heal",
        "clock-skew",
        "double-sign",
        "equivocate",
        "withhold",
        "loss",
        "idle",
        "node",
        "block-load",
        "pipeline",
        "exact-quorum",
        "slow",
        "lookahead-1",
        "epoch-edge-crash",
        "restart-past-retention",
        "boundary-sign-burst-a",
        "boundary-sign-burst-b",
        "param-activation-partition",
        "exit-mute",
        "slash-removal-partition",
        "netcond-intercont",
        "netcond-loss",
    ];

    /// The validator counts of the scale ladder.
    pub const LADDER: &'static [u32] = &[4, 21, 50, 100, 200];
}
