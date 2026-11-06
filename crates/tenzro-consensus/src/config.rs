//! Consensus configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::core::CoreConfig;
use crate::vertex::Digest;

/// Configuration for consensus and the mempool that feeds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// How long a validator holding a quorum of a round waits for that
    /// round's missing leader vertices before it proposes the next round
    /// without them, in milliseconds, counted from when it entered the
    /// round. A validator that holds every leader vertex of the round
    /// proposes as soon as it holds the quorum, without waiting. About
    /// three one-way network delays across the committee.
    pub leader_timeout_ms: u64,

    /// Least time between two rounds a validator proposes, in milliseconds.
    /// Over a wide-area network rounds take a round trip anyway; the floor
    /// paces a committee whose members deliver each other's vertices almost
    /// instantly, down to a single validator that would otherwise propose
    /// round after round without pause.
    pub min_round_interval_ms: u64,

    /// Rounds of the DAG kept below the last committed leader.
    pub gc_depth: u64,

    /// Seats apportioned across a committee by stake.
    pub seat_budget: u64,

    /// Largest batch a validator cuts from its mempool, in bytes.
    pub batch_max_bytes: usize,

    /// A validator cuts a batch at least this often while its mempool has
    /// transactions, in milliseconds.
    pub batch_interval_ms: u64,

    /// Threads of the pool that proves and checks compact certificates, 0
    /// for half this machine's cores. The pool is one per process, sized by
    /// the first handle created in it: a process that runs several
    /// validators sets a number that leaves their other work the cores.
    pub compact_pool_threads: usize,

    /// Mempool size limit in bytes (default: 100MB)
    pub mempool_size_limit: usize,

    /// Maximum number of transactions in mempool (default: 10000)
    pub mempool_max_transactions: usize,

    /// Maximum number of pending transactions a single sender address may
    /// hold in the mempool at once (default: 64). Bounds the damage one
    /// account can do to shared mempool capacity and doubles as the
    /// admissible nonce look-ahead: a tx whose nonce exceeds
    /// `account_nonce + mempool_max_per_sender` is rejected as
    /// unexecutable-for-now spam.
    pub mempool_max_per_sender: usize,

    /// Transaction TTL in seconds (default: 600)
    pub transaction_ttl_seconds: u64,
    /// The scheme of this validator's session keys: its hardware key's
    /// scheme, which the node sets from its consensus key scheme.
    #[serde(default)]
    pub session_key_scheme: crate::validator_key::SignatureScheme,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            leader_timeout_ms: 1_000,
            min_round_interval_ms: 20,
            gc_depth: 50,
            seat_budget: crate::committee::DEFAULT_SEAT_BUDGET,
            batch_max_bytes: crate::batch::MAX_BATCH_BYTES,
            batch_interval_ms: 50,
            compact_pool_threads: 0,
            mempool_size_limit: 100 * 1024 * 1024,
            mempool_max_transactions: 10_000,
            mempool_max_per_sender: 64,
            transaction_ttl_seconds: 600,
            session_key_scheme: Default::default(),
        }
    }
}

impl ConsensusConfig {
    /// Returns the transaction TTL as a Duration
    pub fn transaction_ttl(&self) -> Duration {
        Duration::from_secs(self.transaction_ttl_seconds)
    }

    /// The protocol core's parameters for a chain whose genesis fixes
    /// `time`.
    pub fn core(&self, chain_id: u64, genesis_hash: Digest, time: &TimeRules) -> CoreConfig {
        CoreConfig {
            chain_id,
            genesis_hash,
            leader_timeout_ms: self.leader_timeout_ms,
            min_round_interval_ms: self.min_round_interval_ms,
            leader_slots: time.leader_slots.max(1) as usize,
            checkpoint_interval_ms: time.checkpoint_interval_ms.max(1),
            gc_depth: self.gc_depth,
            max_weak_refs: 64,
            max_rounds_ahead: 200,
            epoch_checkpoints: time.epoch_checkpoints.max(1),
            handover_confirmations: time.handover_confirmations,
            fetch_retry_ms: 250,
            idle_round_interval_ms: time.idle_round_interval_ms.max(self.min_round_interval_ms),
        }
    }
}

/// The network's time rules. Every validator must apply the same ones, so
/// they are fixed in the genesis, not in a node's own configuration; a test
/// network runs the protocol at a compressed timescale by choosing shorter
/// ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeRules {
    /// Minimum spacing of checkpoints, in block time (milliseconds). Each
    /// checkpoint costs every validator one session-key signature; the
    /// hardware key signs only the session certificate, once per epoch.
    pub checkpoint_interval_ms: u64,
    /// Checkpoints per epoch: the epoch length, and so how often the
    /// committee changes and each validator's hardware key certifies a new
    /// session key.
    pub epoch_checkpoints: u64,
    /// Checkpoints the outgoing committee keeps ordering after the one that
    /// ends its epoch, before the next committee takes over.
    pub handover_confirmations: u64,
    /// Lifetime of a validator's endpoint announcement, which certifies its
    /// boot session and disclosure keys; re-signed at half of it.
    pub announcement_lifetime_ms: u64,
    /// Checkpoint time between compact certificates.
    pub compact_interval_ms: u64,
    /// How long each member after an epoch's designated compact prover, in
    /// rotation order, waits for the ones before it to deliver a verified
    /// compact certificate before proving it itself.
    pub compact_handoff_ms: u64,
    /// Leader slots per round: how many of a round's vertices are candidates
    /// to be committed directly by the next round.
    pub leader_slots: u64,
    /// Calendar milliseconds per millisecond of block time since genesis.
    /// Every calendar rule the chain applies (the reward year, vesting,
    /// unbonding, campaign windows) reads the calendar
    /// clock, so a test network compresses its calendar without shortening
    /// consensus rounds. 1 on the public network.
    pub calendar_scale: u64,
    /// Least time between two rounds while no transaction waits to be
    /// ordered. An idle committee keeps proposing (leaders are still
    /// judged, a quorum still advances each round) at this heartbeat and
    /// orders no blocks; a batch reaching any validator returns it to full
    /// pace at once.
    pub idle_round_interval_ms: u64,
}

impl Default for TimeRules {
    /// The public network's rules.
    fn default() -> Self {
        Self {
            // Votes are signed by the in-memory session key, so the interval
            // is not bound by hardware signing time.
            checkpoint_interval_ms: 500,
            // About one hour of checkpoints.
            epoch_checkpoints: 7_200,
            handover_confirmations: 2,
            announcement_lifetime_ms: 6 * 3_600 * 1_000,
            compact_interval_ms: 60_000,
            compact_handoff_ms: 90_000,
            leader_slots: 2,
            calendar_scale: 1,
            idle_round_interval_ms: 5_000,
        }
    }
}

impl TimeRules {
    /// Digest of the rules, which the genesis state root commits to, so
    /// nodes running different rules do not share a chain.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/time-rules");
        for v in [
            self.checkpoint_interval_ms,
            self.epoch_checkpoints,
            self.handover_confirmations,
            self.announcement_lifetime_ms,
            self.compact_interval_ms,
            self.compact_handoff_ms,
            self.leader_slots,
            self.calendar_scale,
            self.idle_round_interval_ms,
        ] {
            h.update(&v.to_be_bytes());
        }
        h.finalize().into()
    }

    /// Checks the rules are usable: every period positive, an announcement
    /// lifetime within [`crate::announce::MAX_ANNOUNCEMENT_LIFETIME_MS`],
    /// compact certificates no more often than checkpoints, and at least one
    /// leader slot per round.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.checkpoint_interval_ms == 0 || self.epoch_checkpoints == 0 {
            return Err("checkpoint interval and epoch length must be positive".into());
        }
        if self.announcement_lifetime_ms == 0
            || self.announcement_lifetime_ms > crate::announce::MAX_ANNOUNCEMENT_LIFETIME_MS
        {
            return Err(format!(
                "announcement lifetime must be positive and at most {} ms",
                crate::announce::MAX_ANNOUNCEMENT_LIFETIME_MS
            ));
        }
        if self.compact_interval_ms < self.checkpoint_interval_ms || self.compact_handoff_ms == 0 {
            return Err("compact certificates must be no more frequent than checkpoints".into());
        }
        if self.leader_slots == 0 {
            return Err("a round needs at least one leader slot".into());
        }
        if self.calendar_scale == 0 {
            return Err("the calendar scale must be positive".into());
        }
        if self.idle_round_interval_ms == 0
            || self.idle_round_interval_ms
                > self
                    .checkpoint_interval_ms
                    .saturating_mul(self.epoch_checkpoints)
        {
            return Err("the idle round interval must be positive and at most one epoch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_core_config_follows_the_consensus_config() {
        let c = ConsensusConfig {
            leader_timeout_ms: 700,
            ..Default::default()
        };
        let time = TimeRules {
            epoch_checkpoints: 0,
            checkpoint_interval_ms: 40,
            ..TimeRules::default()
        };
        let core = c.core(9, [1; 32], &time);
        assert_eq!(
            (
                core.chain_id,
                core.leader_timeout_ms,
                core.epoch_checkpoints
            ),
            (9, 700, 1)
        );
        assert_eq!((core.checkpoint_interval_ms, core.leader_slots), (40, 2));
    }

    #[test]
    fn compressed_time_rules_validate_and_unusable_ones_do_not() {
        let compressed = TimeRules {
            checkpoint_interval_ms: 50,
            epoch_checkpoints: 20,
            handover_confirmations: 1,
            announcement_lifetime_ms: 60_000,
            compact_interval_ms: 1_000,
            compact_handoff_ms: 2_000,
            leader_slots: 3,
            calendar_scale: 8_640,
            idle_round_interval_ms: 250,
        };
        assert!(compressed.validate().is_ok());
        assert!(TimeRules::default().validate().is_ok());
        assert!(
            TimeRules {
                epoch_checkpoints: 0,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            TimeRules {
                announcement_lifetime_ms: 25 * 3_600 * 1_000,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            TimeRules {
                compact_interval_ms: 10,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            TimeRules {
                leader_slots: 0,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            TimeRules {
                calendar_scale: 0,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            TimeRules {
                idle_round_interval_ms: 0,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            TimeRules {
                idle_round_interval_ms: 1_001,
                ..compressed.clone()
            }
            .validate()
            .is_err()
        );
        let back: TimeRules =
            serde_json::from_str(&serde_json::to_string(&compressed).unwrap()).unwrap();
        assert_eq!(back, compressed);
        assert!(
            serde_json::from_str::<TimeRules>(r#"{"checkpoint_interval_ms":50}"#).is_err(),
            "every rule is required"
        );
    }
}
