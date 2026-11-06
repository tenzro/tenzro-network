//! Each validator's count of consecutive epochs without a certified
//! signature, kept in chain state.
//!
//! The count decides when an inactive validator is moved to exit, which
//! changes the next committee, so every node must derive the same count. It
//! is therefore a function of committed state only: the previous count (a
//! record in chain state), the closing epoch's tally of recorded checkpoint
//! signers (`reward_votes`, written by executed `RecordCheckpointSigners`
//! transactions) and the closing epoch's validator set (the one its committee
//! was derived from). A node that joined from a snapshot holds the same
//! record as a node that executed every block, and derives the same count
//! from the next epoch on. No local certificate log is read.
//!
//! Counting starts at the governed epoch
//! [`staking::INACTIVITY_ACTIVATION_PARAM`]: epochs before it are not
//! counted, so a running chain turns this on at an epoch every node has
//! reached the build that writes the record, never mid-way. An epoch in which
//! no checkpoint was certified counts for no one (a stalled chain is not any
//! one validator's absence).

use std::collections::BTreeMap;

use super::funding::write_json;
use super::rewards::read_epoch_votes;
use super::staking::INACTIVITY_ACTIVATION_PARAM;
use super::*;

/// Storage key, under `SYSTEM_ADDRESS`, of the participation record.
pub const PARTICIPATION_KEY: &str = "validator_participation";

/// The record: the last epoch counted, and the validators that missed it or
/// earlier epochs in a row, in account order. A validator absent from the
/// list has no missed epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Participation {
    /// The latest epoch counted.
    pub last_epoch: Option<u64>,
    /// `(validator, consecutive epochs without a certified signature)`.
    pub missed: Vec<(Address, u64)>,
}

/// The record, or an empty one before the first epoch is counted. A record
/// that is present but does not decode is an error: consensus state is never
/// read as a default.
pub fn read_participation(state: &dyn VmState) -> Result<Participation> {
    match state.get_storage(&SYSTEM_ADDRESS, PARTICIPATION_KEY.as_bytes()) {
        Some(b) if !b.is_empty() => serde_json::from_slice(&b)
            .map_err(|e| VmError::Internal(format!("{PARTICIPATION_KEY} does not decode: {e}"))),
        _ => Ok(Participation::default()),
    }
}

/// Each validator's consecutive missed epochs, for the epoch planner.
pub fn read_missed_epochs(state: &dyn VmState) -> Result<std::collections::HashMap<Address, u64>> {
    Ok(read_participation(state)?.missed.into_iter().collect())
}

/// Counts epoch `closing`: every validator in `roster` (the closing epoch's
/// validator set) that signed none of the epoch's certified rounds has one
/// more missed epoch, every other has none. Idempotent: an epoch at or below
/// the last one counted is ignored. Returns whether the epoch was counted.
pub fn begin_block(state: &mut dyn VmState, closing: u64, roster: &[Address]) -> Result<bool> {
    if closing < super::network_param(state, INACTIVITY_ACTIVATION_PARAM) {
        return Ok(false);
    }
    let mut record = read_participation(state)?;
    if record.last_epoch.is_some_and(|l| l >= closing) {
        return Ok(false);
    }
    let votes = read_epoch_votes(state, closing)?;
    let mut missed: BTreeMap<[u8; 32], u64> =
        record.missed.iter().map(|(a, n)| (a.0, *n)).collect();
    if votes.certified_rounds > 0 {
        let mut next = BTreeMap::new();
        for validator in roster {
            let signed = votes
                .signed
                .iter()
                .find(|(a, _)| a == validator)
                .map_or(0, |(_, rounds)| *rounds);
            if signed == 0 {
                let before = missed.get(&validator.0).copied().unwrap_or(0);
                next.insert(validator.0, before.saturating_add(1));
            }
        }
        missed = next;
    }
    record.last_epoch = Some(closing);
    record.missed = missed
        .into_iter()
        .map(|(a, n)| (Address::new(a), n))
        .collect();
    write_json(state, PARTICIPATION_KEY, &record, &mut Vec::new())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::super::rewards::{CheckpointSigners, record_checkpoint_signers};
    use super::*;
    use crate::StateAdapter;

    fn addr(n: u8) -> Address {
        Address::new([n; 32])
    }

    fn signed_by(state: &mut StateAdapter, epoch: u64, signers: &[Address]) {
        record_checkpoint_signers(
            state,
            &CheckpointSigners {
                epoch,
                index: 0,
                anchor_round: 10,
                signers: signers.to_vec(),
            },
        )
        .unwrap();
    }

    fn set_activation(state: &mut StateAdapter, epoch: u64) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(INACTIVITY_ACTIVATION_PARAM).as_bytes(),
            epoch.to_le_bytes().to_vec(),
        );
    }

    fn count(state: &StateAdapter, who: Address) -> u64 {
        read_missed_epochs(state)
            .unwrap()
            .get(&who)
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn consecutive_misses_count_and_a_signature_resets() {
        let mut state = StateAdapter::new();
        let roster = [addr(1), addr(2), addr(3)];
        for e in 1..=3 {
            signed_by(&mut state, e, &[addr(1), addr(2)]);
            assert!(begin_block(&mut state, e, &roster).unwrap());
        }
        assert_eq!(count(&state, addr(3)), 3);
        assert_eq!(count(&state, addr(1)), 0);
        signed_by(&mut state, 4, &[addr(1), addr(2), addr(3)]);
        begin_block(&mut state, 4, &roster).unwrap();
        assert_eq!(count(&state, addr(3)), 0);
    }

    #[test]
    fn an_epoch_with_no_certified_checkpoint_counts_for_no_one() {
        let mut state = StateAdapter::new();
        let roster = [addr(1), addr(2)];
        signed_by(&mut state, 1, &[addr(1)]);
        begin_block(&mut state, 1, &roster).unwrap();
        begin_block(&mut state, 2, &roster).unwrap(); // nothing recorded in epoch 2
        assert_eq!(count(&state, addr(2)), 1);
    }

    #[test]
    fn epochs_before_the_governed_activation_are_not_counted() {
        let mut state = StateAdapter::new();
        set_activation(&mut state, 5);
        let roster = [addr(1), addr(2)];
        for e in 1..=4 {
            signed_by(&mut state, e, &[addr(1)]);
            assert!(!begin_block(&mut state, e, &roster).unwrap());
        }
        assert!(read_missed_epochs(&state).unwrap().is_empty());
        signed_by(&mut state, 5, &[addr(1)]);
        assert!(begin_block(&mut state, 5, &roster).unwrap());
        assert_eq!(count(&state, addr(2)), 1);
    }

    /// Replaying an epoch's close, as a node does after a restart in the
    /// middle of a block, changes nothing.
    #[test]
    fn replaying_an_epoch_is_a_no_op() {
        let mut state = StateAdapter::new();
        let roster = [addr(1), addr(2)];
        signed_by(&mut state, 1, &[addr(1)]);
        assert!(begin_block(&mut state, 1, &roster).unwrap());
        let before = state.get_storage(&SYSTEM_ADDRESS, PARTICIPATION_KEY.as_bytes());
        assert!(!begin_block(&mut state, 1, &roster).unwrap());
        assert_eq!(
            state.get_storage(&SYSTEM_ADDRESS, PARTICIPATION_KEY.as_bytes()),
            before
        );
    }

    /// A node that joins from a snapshot taken after epoch 3 holds the
    /// record as it stood then; it executes epochs 4 to 8 and ends with the
    /// same record, byte for byte, as the node that executed every epoch, so
    /// both feed the epoch planner the same counts and derive the same
    /// committee.
    #[test]
    fn a_snapshot_synced_node_derives_the_same_counts_as_a_full_history_node() {
        let roster = [addr(1), addr(2), addr(3), addr(4)];
        let who_signs = |e: u64| -> Vec<Address> {
            // validator 4 is gone; validator 3 skips epochs 2, 3 and 6.
            let mut s = vec![addr(1), addr(2)];
            if ![2, 3, 6].contains(&e) {
                s.push(addr(3));
            }
            s
        };
        let mut full = StateAdapter::new();
        let mut snapshot_record = None;
        for e in 1..=8 {
            signed_by(&mut full, e, &who_signs(e));
            begin_block(&mut full, e, &roster).unwrap();
            if e == 3 {
                snapshot_record = full.get_storage(&SYSTEM_ADDRESS, PARTICIPATION_KEY.as_bytes());
            }
        }
        let mut synced = StateAdapter::new();
        synced.set_storage(
            &SYSTEM_ADDRESS,
            PARTICIPATION_KEY.as_bytes(),
            snapshot_record.unwrap(),
        );
        for e in 4..=8 {
            signed_by(&mut synced, e, &who_signs(e));
            begin_block(&mut synced, e, &roster).unwrap();
        }
        assert_eq!(
            full.get_storage(&SYSTEM_ADDRESS, PARTICIPATION_KEY.as_bytes()),
            synced.get_storage(&SYSTEM_ADDRESS, PARTICIPATION_KEY.as_bytes())
        );
        assert_eq!(count(&full, addr(4)), 8);
        assert_eq!(count(&full, addr(3)), 0); // signed again in 7 and 8
        assert_eq!(
            read_missed_epochs(&full).unwrap(),
            read_missed_epochs(&synced).unwrap()
        );
    }
}
