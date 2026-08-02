//! Proactive Key Refresh (PKR) scheduler for DKLS23.
//!
//! Wraps the `RefreshSession` primitive in [`super::refresh`] with a
//! governance-driven rotation cadence. Every node running an MPC group
//! advances the scheduler clock on each block tick; when the configured
//! cadence elapses, the scheduler returns a `RotationTrigger` and the
//! orchestrating layer kicks off `RefreshSession::run(cfg)` for the next
//! epoch.
//!
//! The scheduler is **pure**: it only decides "when to rotate" and how to
//! compute the next epoch number + session id. It does not own the
//! refresh transport, the keyshare store, or the network — those live in
//! the node layer and consume the scheduler's trigger output.
//!
//! Source-of-truth for the cadence model: Silence Laboratories' DKLS23 R&D
//! and Trail of Bits' 2025 review of the dkls23 library, both of which
//! call out proactive refresh on a governance-set epoch as the canonical
//! production hardening over the base DKG.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{BridgeError, Result};

/// Cadence policy: how often the scheduler triggers a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkrCadence {
    /// Refresh after this many seconds elapse since the previous refresh.
    /// `0` disables refresh entirely.
    pub rotate_every_secs: u64,
    /// Maximum number of signing instances per epoch before the scheduler
    /// forces a rotation regardless of time. `0` disables the count cap.
    pub max_sigs_per_epoch: u64,
}

impl Default for PkrCadence {
    fn default() -> Self {
        // Default to daily rotation, cap each epoch at 100k signatures.
        // Both are tuneable via governance.
        Self {
            rotate_every_secs: 24 * 3600,
            max_sigs_per_epoch: 100_000,
        }
    }
}

/// Trigger returned when the scheduler decides a rotation is due.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationTrigger {
    /// Group id that needs rotation.
    pub group_id: [u8; 32],
    /// Current epoch (the one to rotate *from*).
    pub from_epoch: u64,
    /// Next epoch (the one to rotate *to*).
    pub to_epoch: u64,
    /// Cadence-side reason — used for telemetry and the audit log.
    pub reason: RotationReason,
    /// Seconds since the previous rotation.
    pub age_secs: u64,
    /// Signatures observed in `from_epoch`.
    pub sigs_in_epoch: u64,
}

/// Why this rotation fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// Cadence age window elapsed.
    AgeExpired,
    /// Per-epoch signature cap reached.
    SigCapReached,
    /// Operator-forced rotation via governance.
    OperatorForced,
}

/// PKR scheduler for a single MPC group.
#[derive(Debug)]
pub struct PkrScheduler {
    group_id: [u8; 32],
    cadence: RwLock<PkrCadence>,
    current_epoch: AtomicU64,
    last_rotation_secs: AtomicU64,
    sigs_in_epoch: AtomicU64,
    /// Lifetime rotation counter.
    rotation_count: AtomicU64,
}

impl PkrScheduler {
    /// Build a new scheduler.
    pub fn new(group_id: [u8; 32], cadence: PkrCadence, initial_epoch: u64, now_secs: u64) -> Self {
        Self {
            group_id,
            cadence: RwLock::new(cadence),
            current_epoch: AtomicU64::new(initial_epoch),
            last_rotation_secs: AtomicU64::new(now_secs),
            sigs_in_epoch: AtomicU64::new(0),
            rotation_count: AtomicU64::new(0),
        }
    }

    /// Current epoch (read-only).
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Relaxed)
    }

    /// Group id this scheduler tracks.
    pub fn group_id(&self) -> [u8; 32] {
        self.group_id
    }

    /// Cadence (snapshot).
    pub fn cadence(&self) -> PkrCadence {
        *self.cadence.read()
    }

    /// Replace the cadence (governance only). Cannot make the cadence
    /// unset retroactively — the next tick will use the new value.
    pub fn set_cadence(&self, cadence: PkrCadence) {
        *self.cadence.write() = cadence;
    }

    /// Record one signing instance in the current epoch.
    pub fn record_signing(&self) {
        self.sigs_in_epoch.fetch_add(1, Ordering::Relaxed);
    }

    /// Tick: returns a `RotationTrigger` if cadence is due.
    pub fn tick(&self, now_secs: u64) -> Option<RotationTrigger> {
        let cadence = self.cadence();
        let age = now_secs.saturating_sub(self.last_rotation_secs.load(Ordering::Relaxed));
        let sigs = self.sigs_in_epoch.load(Ordering::Relaxed);

        let reason = if cadence.rotate_every_secs > 0 && age >= cadence.rotate_every_secs {
            Some(RotationReason::AgeExpired)
        } else if cadence.max_sigs_per_epoch > 0 && sigs >= cadence.max_sigs_per_epoch {
            Some(RotationReason::SigCapReached)
        } else {
            None
        };

        reason.map(|r| RotationTrigger {
            group_id: self.group_id,
            from_epoch: self.current_epoch(),
            to_epoch: self.current_epoch() + 1,
            reason: r,
            age_secs: age,
            sigs_in_epoch: sigs,
        })
    }

    /// Force a rotation (governance / operator).
    pub fn force_rotate(&self, now_secs: u64) -> RotationTrigger {
        let from = self.current_epoch();
        RotationTrigger {
            group_id: self.group_id,
            from_epoch: from,
            to_epoch: from + 1,
            reason: RotationReason::OperatorForced,
            age_secs: now_secs.saturating_sub(self.last_rotation_secs.load(Ordering::Relaxed)),
            sigs_in_epoch: self.sigs_in_epoch.load(Ordering::Relaxed),
        }
    }

    /// Mark a rotation complete. The caller has finished the
    /// `RefreshSession`, persisted the new sealed keyshare, and is ready to
    /// switch consumers (pre-sign pool, signer config) to the new epoch.
    pub fn commit_rotation(&self, trigger: &RotationTrigger, now_secs: u64) -> Result<()> {
        if trigger.group_id != self.group_id {
            return Err(BridgeError::ConfigurationError(
                "trigger group_id does not match scheduler group_id".into(),
            ));
        }
        if trigger.from_epoch != self.current_epoch() {
            return Err(BridgeError::ConfigurationError(format!(
                "trigger from_epoch {} does not match current epoch {}",
                trigger.from_epoch,
                self.current_epoch()
            )));
        }
        self.current_epoch
            .store(trigger.to_epoch, Ordering::Relaxed);
        self.last_rotation_secs.store(now_secs, Ordering::Relaxed);
        self.sigs_in_epoch.store(0, Ordering::Relaxed);
        self.rotation_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Lifetime rotations committed.
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count.load(Ordering::Relaxed)
    }

    /// Snapshot of the scheduler state for `tenzro_getMpcPkrStatus` RPC.
    pub fn snapshot(&self) -> PkrSchedulerSnapshot {
        PkrSchedulerSnapshot {
            group_id_hex: hex::encode(self.group_id),
            current_epoch: self.current_epoch(),
            cadence: self.cadence(),
            last_rotation_secs: self.last_rotation_secs.load(Ordering::Relaxed),
            sigs_in_epoch: self.sigs_in_epoch.load(Ordering::Relaxed),
            rotation_count: self.rotation_count(),
        }
    }
}

/// Externally-visible snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkrSchedulerSnapshot {
    /// Hex-encoded group id.
    pub group_id_hex: String,
    /// Current epoch.
    pub current_epoch: u64,
    /// Active cadence policy.
    pub cadence: PkrCadence,
    /// Unix-seconds of last commit.
    pub last_rotation_secs: u64,
    /// Signing instances observed in the current epoch.
    pub sigs_in_epoch: u64,
    /// Lifetime rotations committed.
    pub rotation_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_returns_none_inside_window() {
        let s = PkrScheduler::new(
            [1u8; 32],
            PkrCadence {
                rotate_every_secs: 3600,
                max_sigs_per_epoch: 100,
            },
            0,
            1000,
        );
        assert!(s.tick(2000).is_none()); // age = 1000, window = 3600
    }

    #[test]
    fn tick_fires_when_age_exceeds_window() {
        let s = PkrScheduler::new(
            [1u8; 32],
            PkrCadence {
                rotate_every_secs: 3600,
                max_sigs_per_epoch: 100,
            },
            0,
            1000,
        );
        let trigger = s.tick(5000).unwrap();
        assert_eq!(trigger.reason, RotationReason::AgeExpired);
        assert_eq!(trigger.to_epoch, 1);
    }

    #[test]
    fn tick_fires_when_sig_cap_reached() {
        let s = PkrScheduler::new(
            [1u8; 32],
            PkrCadence {
                rotate_every_secs: 86400,
                max_sigs_per_epoch: 3,
            },
            0,
            1000,
        );
        for _ in 0..3 {
            s.record_signing();
        }
        let trigger = s.tick(1500).unwrap();
        assert_eq!(trigger.reason, RotationReason::SigCapReached);
    }

    #[test]
    fn commit_advances_epoch_and_resets_counters() {
        let s = PkrScheduler::new([1u8; 32], PkrCadence::default(), 0, 1000);
        s.record_signing();
        let trigger = s.force_rotate(2000);
        s.commit_rotation(&trigger, 2000).unwrap();
        assert_eq!(s.current_epoch(), 1);
        assert_eq!(s.snapshot().sigs_in_epoch, 0);
        assert_eq!(s.rotation_count(), 1);
    }

    #[test]
    fn commit_rejects_stale_trigger() {
        let s = PkrScheduler::new([1u8; 32], PkrCadence::default(), 5, 1000);
        let bad = RotationTrigger {
            group_id: [1u8; 32],
            from_epoch: 4,
            to_epoch: 5,
            reason: RotationReason::OperatorForced,
            age_secs: 1,
            sigs_in_epoch: 0,
        };
        let err = s.commit_rotation(&bad, 1000).unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn commit_rejects_group_mismatch() {
        let s = PkrScheduler::new([1u8; 32], PkrCadence::default(), 0, 1000);
        let bad = RotationTrigger {
            group_id: [9u8; 32],
            from_epoch: 0,
            to_epoch: 1,
            reason: RotationReason::OperatorForced,
            age_secs: 1,
            sigs_in_epoch: 0,
        };
        let err = s.commit_rotation(&bad, 1000).unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn disabled_cadence_never_fires_on_age() {
        let s = PkrScheduler::new(
            [1u8; 32],
            PkrCadence {
                rotate_every_secs: 0, // disabled
                max_sigs_per_epoch: 1_000_000,
            },
            0,
            1000,
        );
        assert!(s.tick(u64::MAX / 2).is_none());
    }
}
