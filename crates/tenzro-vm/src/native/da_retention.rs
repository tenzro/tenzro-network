//! Retention of data-availability objects, executed in consensus.
//!
//! A bonded validator (every DA committee member is one) records each object
//! it certifies with its class and size. The object's expiry is fixed when it
//! is recorded: the block time plus its class's governed retention, which for
//! audit entries is never shorter than [`AUDIT_RETENTION_FLOOR_SECS`].
//!
//! Objects are bucketed by the day they expire. At the start of every block,
//! [`begin_block`] expires the objects of every bucket whose day has fully
//! passed, at most [`MAX_EXPIRIES_PER_BLOCK`] per block, carrying on in the
//! next block where it stopped. Every node derives the same expiries, and
//! committee members drop the slivers of an expired object.

use serde::{Deserialize, Serialize};
use tenzro_types::da_retention::{DaObject, DaObjectClass, DaRetentionOp};

use super::funding::{read_json, refuse, write_json};
use super::staking::bonded_stake_of;
use super::*;
use crate::governance::{AUDIT_RETENTION_FLOOR_SECS, AUDIT_RETENTION_PARAM};

/// Governed: seconds a history segment is kept in the data-availability
/// layer after it was recorded.
pub const DA_HISTORY_RETENTION_PARAM: &str = "storage.da_history_retention_seconds";

/// Genesis value of [`DA_HISTORY_RETENTION_PARAM`]: two years. REVIEW
/// before genesis against what the committee is asked to store.
pub const DEFAULT_DA_HISTORY_RETENTION_SECS: u64 = 2 * 365 * 24 * 60 * 60;

/// Gas for recording an object.
pub const GAS_DA_RECORD: u64 = 30_000;

/// Most objects one block expires.
pub const MAX_EXPIRIES_PER_BLOCK: usize = 256;

/// Topic of the log a record emits.
pub const DA_RECORDED_TOPIC: &[u8] = b"DaObjectRecorded";

const DAY_MS: i64 = 86_400_000;
const SWEEP_KEY: &str = "da_sweep";
const STATS_KEY: &str = "da_stats";

/// Where expiry stands: the next day whose bucket is swept, and how far
/// into it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSweep {
    pub day: u64,
    pub position: u64,
}

/// Totals over every object recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaStats {
    pub live_objects: u64,
    pub live_bytes: u64,
    pub expired_objects: u64,
    pub expired_bytes: u64,
}

fn object_key(commitment: &str) -> String {
    format!("da_obj:{commitment}")
}

/// Most objects one page of a day's bucket holds.
const BUCKET_PAGE: u64 = 256;

fn bucket_key(day: u64, page: u64) -> String {
    format!("da_bucket:{day:010}:{page:06}")
}

fn bucket_len_key(day: u64) -> String {
    format!("da_bucket_len:{day:010}")
}

/// The object recorded under `commitment` (hex).
pub fn read_da_object(state: &dyn VmState, commitment: &str) -> Option<DaObject> {
    read_json(state, &object_key(&commitment.to_ascii_lowercase()))
}

/// Totals over every object recorded.
pub fn read_da_stats(state: &dyn VmState) -> DaStats {
    read_json(state, STATS_KEY).unwrap_or_default()
}

/// Where expiry stands, once an object has been recorded.
pub fn read_da_sweep(state: &dyn VmState) -> Option<DaSweep> {
    read_json(state, SWEEP_KEY)
}

/// The retention of `class`, ms.
pub fn retention_ms(state: &dyn VmState, class: DaObjectClass) -> i64 {
    let secs = match class {
        DaObjectClass::Audit => {
            network_param(state, AUDIT_RETENTION_PARAM).max(AUDIT_RETENTION_FLOOR_SECS)
        }
        DaObjectClass::History => {
            network_param(state, DA_HISTORY_RETENTION_PARAM).max(AUDIT_RETENTION_FLOOR_SECS)
        }
    };
    i64::try_from(secs.saturating_mul(1_000)).unwrap_or(i64::MAX)
}

/// Apply one registry operation.
pub(super) fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    op: &DaRetentionOp,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    match op {
        DaRetentionOp::Record {
            commitment,
            class,
            size_bytes,
        } => {
            if bonded_stake_of(state, from) == 0 {
                return Err(refuse(
                    "only committee members, which are bonded validators, record DA objects",
                ));
            }
            let commitment = commitment.to_ascii_lowercase();
            if read_da_object(state, &commitment).is_some() {
                return Err(refuse(format!("object {commitment} is already recorded")));
            }
            let expires_at_ms = now_ms.saturating_add(retention_ms(state, *class));
            let object = DaObject {
                commitment: commitment.clone(),
                class: *class,
                size_bytes: *size_bytes,
                recorder: hex::encode(from),
                recorded_at_ms: now_ms,
                expires_at_ms,
                expired_at_ms: None,
            };
            let mut changes = Vec::new();
            write_json(state, &object_key(&commitment), &object, &mut changes)?;
            // A day's objects are held in pages, so recording one touches
            // one page of bounded size, never the whole day.
            let day = (expires_at_ms.max(0) / DAY_MS) as u64;
            let len: u64 = read_json(state, &bucket_len_key(day)).unwrap_or(0);
            let page_key = bucket_key(day, len / BUCKET_PAGE);
            let mut page: Vec<String> = read_json(state, &page_key).unwrap_or_default();
            page.push(commitment);
            write_json(state, &page_key, &page, &mut changes)?;
            write_json(state, &bucket_len_key(day), &(len + 1), &mut changes)?;
            match read_da_sweep(state) {
                Some(s) if s.day <= day => {}
                Some(s) if s.position == 0 => write_json(
                    state,
                    SWEEP_KEY,
                    &DaSweep { day, position: 0 },
                    &mut changes,
                )
                .map(|_| ())?,
                Some(_) => {}
                None => write_json(
                    state,
                    SWEEP_KEY,
                    &DaSweep { day, position: 0 },
                    &mut changes,
                )
                .map(|_| ())?,
            }
            let mut stats = read_da_stats(state);
            stats.live_objects += 1;
            stats.live_bytes = stats.live_bytes.saturating_add(*size_bytes);
            write_json(state, STATS_KEY, &stats, &mut changes)?;
            let log = Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![DA_RECORDED_TOPIC.to_vec()],
                serde_json::to_vec(&object)
                    .map_err(|e| VmError::Internal(format!("encode DA record log: {e}")))?,
            );
            Ok((changes, vec![log]))
        }
    }
}

/// Expire every object whose retention has passed, bucket by bucket, up to
/// [`MAX_EXPIRIES_PER_BLOCK`]. Returns how many objects it expired.
pub fn begin_block(state: &mut dyn VmState, now_ms: i64) -> Result<usize> {
    let Some(mut sweep) = read_da_sweep(state) else {
        return Ok(0);
    };
    let start = sweep;
    let mut stats = read_da_stats(state);
    let mut expired = 0usize;
    let mut work = 0usize;
    let mut changes = Vec::new();
    // A bucket is swept once its whole day has passed.
    while (sweep.day as i64 + 1).saturating_mul(DAY_MS) <= now_ms && work < MAX_EXPIRIES_PER_BLOCK {
        let len: u64 = read_json(state, &bucket_len_key(sweep.day)).unwrap_or(0);
        let mut page_at = u64::MAX;
        let mut page: Vec<String> = Vec::new();
        while sweep.position < len && work < MAX_EXPIRIES_PER_BLOCK {
            let at = sweep.position / BUCKET_PAGE;
            if at != page_at {
                page = read_json(state, &bucket_key(sweep.day, at)).unwrap_or_default();
                page_at = at;
            }
            let Some(commitment) = page.get((sweep.position % BUCKET_PAGE) as usize) else {
                sweep.position += 1;
                work += 1;
                continue;
            };
            if let Some(mut object) = read_da_object(state, commitment)
                && object.is_live()
            {
                object.expired_at_ms = Some(now_ms);
                write_json(state, &object_key(commitment), &object, &mut changes)?;
                stats.live_objects = stats.live_objects.saturating_sub(1);
                stats.live_bytes = stats.live_bytes.saturating_sub(object.size_bytes);
                stats.expired_objects += 1;
                stats.expired_bytes = stats.expired_bytes.saturating_add(object.size_bytes);
                expired += 1;
            }
            sweep.position += 1;
            work += 1;
        }
        if sweep.position >= len {
            for at in 0..len.div_ceil(BUCKET_PAGE) {
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    bucket_key(sweep.day, at).as_bytes(),
                    Vec::new(),
                );
            }
            if len > 0 {
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    bucket_len_key(sweep.day).as_bytes(),
                    Vec::new(),
                );
            }
            sweep = DaSweep {
                day: sweep.day + 1,
                position: 0,
            };
            work += 1;
        }
    }
    if sweep != start {
        write_json(state, SWEEP_KEY, &sweep, &mut changes)?;
    }
    if expired > 0 {
        write_json(state, STATS_KEY, &stats, &mut changes)?;
    }
    Ok(expired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const V: [u8; 32] = [0xA; 32];

    fn set_param(state: &mut StateAdapter, key: &str, value: u64) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(key).as_bytes(),
            value.to_le_bytes().to_vec(),
        );
    }

    fn record(state: &mut StateAdapter, commitment: u8, class: DaObjectClass, at: i64) {
        let op = DaRetentionOp::Record {
            commitment: hex::encode([commitment; 32]),
            class,
            size_bytes: 100,
        };
        apply(state, &V, at, &op).unwrap();
    }

    #[test]
    fn objects_expire_in_consensus_once_their_retention_has_passed() {
        let mut state = StateAdapter::new();
        super::super::staking::add_bond(&mut state, &V, 1, 0).unwrap();
        record(&mut state, 1, DaObjectClass::Audit, 0);
        record(&mut state, 2, DaObjectClass::History, 0);
        let audit = read_da_object(&state, &hex::encode([1u8; 32])).unwrap();
        assert_eq!(
            audit.expires_at_ms,
            (AUDIT_RETENTION_FLOOR_SECS * 1000) as i64,
            "audit is kept for the floor"
        );
        // Nothing expires before the retention and its day have passed.
        assert_eq!(begin_block(&mut state, audit.expires_at_ms).unwrap(), 0);
        assert!(
            read_da_object(&state, &hex::encode([1u8; 32]))
                .unwrap()
                .is_live()
        );
        let after_audit = audit.expires_at_ms + DAY_MS;
        assert_eq!(begin_block(&mut state, after_audit).unwrap(), 1);
        assert!(
            !read_da_object(&state, &hex::encode([1u8; 32]))
                .unwrap()
                .is_live()
        );
        assert!(
            read_da_object(&state, &hex::encode([2u8; 32]))
                .unwrap()
                .is_live(),
            "history is kept longer"
        );
        let stats = read_da_stats(&state);
        assert_eq!(
            (
                stats.live_objects,
                stats.expired_objects,
                stats.expired_bytes
            ),
            (1, 1, 100)
        );
        // Expiring again changes nothing.
        assert_eq!(begin_block(&mut state, after_audit + 1).unwrap(), 0);
    }

    #[test]
    fn governance_cannot_retain_audit_entries_for_less_than_the_floor() {
        let mut state = StateAdapter::new();
        assert_eq!(
            retention_ms(&state, DaObjectClass::Audit),
            (AUDIT_RETENTION_FLOOR_SECS * 1000) as i64
        );
        set_param(&mut state, AUDIT_RETENTION_PARAM, 1);
        assert_eq!(
            retention_ms(&state, DaObjectClass::Audit),
            (AUDIT_RETENTION_FLOOR_SECS * 1000) as i64
        );
        set_param(&mut state, DA_HISTORY_RETENTION_PARAM, 1);
        assert_eq!(
            retention_ms(&state, DaObjectClass::History),
            (AUDIT_RETENTION_FLOOR_SECS * 1000) as i64
        );
    }

    #[test]
    fn only_bonded_validators_record_and_each_object_once() {
        let mut state = StateAdapter::new();
        let op = DaRetentionOp::Record {
            commitment: hex::encode([1u8; 32]),
            class: DaObjectClass::Audit,
            size_bytes: 1,
        };
        assert!(apply(&mut state, &V, 0, &op).is_err(), "no stake");
        super::super::staking::add_bond(&mut state, &V, 1, 0).unwrap();
        apply(&mut state, &V, 0, &op).unwrap();
        assert!(apply(&mut state, &V, 0, &op).is_err(), "recorded twice");
    }

    /// Many objects expiring on one day are held in pages of a bounded size,
    /// so recording one more never rewrites the whole day, and every one of
    /// them still expires.
    #[test]
    fn a_days_objects_are_held_in_bounded_pages() {
        let mut state = StateAdapter::new();
        super::super::staking::add_bond(&mut state, &V, 1, 0).unwrap();
        let n = 600u64;
        for i in 0..n {
            let mut c = [0u8; 32];
            c[..8].copy_from_slice(&i.to_be_bytes());
            let op = DaRetentionOp::Record {
                commitment: hex::encode(c),
                class: DaObjectClass::Audit,
                size_bytes: 1,
            };
            apply(&mut state, &V, 0, &op).unwrap();
        }
        let day = (AUDIT_RETENTION_FLOOR_SECS as i64 * 1000 / DAY_MS) as u64;
        let held = |key: String| -> usize {
            read_json::<Vec<String>>(&state, &key).map_or(0, |b| b.len())
        };
        let mut total = held(format!("da_bucket:{day:010}"));
        assert!(total <= 256, "one list of {total} entries for the day");
        for page in 0..8u64 {
            let len = held(format!("da_bucket:{day:010}:{page:06}"));
            assert!(len <= 256, "page {page} holds {len}");
            total += len;
        }
        assert_eq!(total as u64, n);
        let mut expired = 0;
        let mut now = (day as i64 + 1) * DAY_MS;
        while expired < n as usize {
            let e = begin_block(&mut state, now).unwrap();
            assert!(e > 0, "the sweep stalled at {expired}");
            expired += e;
            now += 1;
        }
        assert_eq!(read_da_stats(&state).live_objects, 0);
    }

    #[test]
    fn a_large_backlog_expires_across_blocks() {
        let mut state = StateAdapter::new();
        super::super::staking::add_bond(&mut state, &V, 1, 0).unwrap();
        for i in 0..(MAX_EXPIRIES_PER_BLOCK + 10) {
            let mut c = [0u8; 32];
            c[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let op = DaRetentionOp::Record {
                commitment: hex::encode(c),
                class: DaObjectClass::Audit,
                size_bytes: 1,
            };
            apply(&mut state, &V, 0, &op).unwrap();
        }
        let later = (AUDIT_RETENTION_FLOOR_SECS * 1000) as i64 + DAY_MS;
        let first = begin_block(&mut state, later).unwrap();
        assert!(first < MAX_EXPIRIES_PER_BLOCK + 10);
        let second = begin_block(&mut state, later).unwrap();
        assert_eq!(first + second, MAX_EXPIRIES_PER_BLOCK + 10);
        assert_eq!(read_da_stats(&state).live_objects, 0);
    }
}
