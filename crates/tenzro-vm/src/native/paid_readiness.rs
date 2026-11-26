//! A paid request a provider served counts as its readiness proof for that
//! hour.
//!
//! A provider serving paid requests is shown ready by the ordinary request
//! path, so validators need not spend a synthetic probe on it. Once the
//! gate is live, every settlement that pays a provider for a request it
//! served, between a payer and a payee registered under different roots,
//! records the market hour on the payee's identity. A validator reads it
//! with [`served_paid_in_hour`] and counts that hour as answered without
//! probing. Rentals and storage claims do not count: they settle each hour
//! by its verdict, so they cannot also prove it.
//!
//! Dormant at genesis: until a vote sets the gate nothing is recorded and
//! [`served_paid_in_hour`] is false, so every provider is probed as before.

use crate::types::StateChange;

use super::MARKET_EPOCH_MS;
use super::funding::{read_json, write_json};
use crate::error::Result;
use crate::feature_gate::is_live_now;
use crate::traits::VmState;

/// Gate: the first epoch whose settlements record the hour a provider served
/// a paid request.
pub const PAID_READINESS_KEY: &str = "feature.paid_readiness.activation_epoch";

fn hour_key(did: &str) -> String {
    format!("paid_hour:{did}")
}

/// Records that `payee_did` served a paid request at `at_ms`. Nothing while
/// the gate is dormant; one write per payee per hour.
pub(super) fn record(
    state: &mut dyn VmState,
    payee_did: &str,
    at_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if !is_live_now(state, PAID_READINESS_KEY) {
        return Ok(());
    }
    let hour = (at_ms.max(0) / MARKET_EPOCH_MS) as u64;
    let key = hour_key(payee_did);
    if read_json::<u64>(state, &key).is_some_and(|h| h >= hour) {
        return Ok(());
    }
    write_json(state, &key, &hour, changes)?;
    Ok(())
}

/// Whether `provider_did` served a paid request in market hour `hour`, as
/// the last one it served. False while the gate is dormant.
pub fn served_paid_in_hour(state: &dyn VmState, provider_did: &str, hour: u64) -> bool {
    is_live_now(state, PAID_READINESS_KEY)
        && read_json::<u64>(state, &hour_key(provider_did)) == Some(hour)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::SYSTEM_ADDRESS;

    fn state_with_gate(epoch: Option<u64>) -> crate::state_adapter::StateAdapter {
        let mut s = crate::state_adapter::StateAdapter::new();
        if let Some(e) = epoch {
            crate::native::set_governed_param_for_test(&mut s, PAID_READINESS_KEY, e);
        }
        s
    }

    #[test]
    fn dormant_records_nothing_and_reads_false() {
        let mut s = state_with_gate(None);
        let mut changes = Vec::new();
        record(
            &mut s,
            "did:tenzro:machine:p",
            5 * MARKET_EPOCH_MS,
            &mut changes,
        )
        .unwrap();
        assert!(changes.is_empty());
        assert!(
            s.get_storage(&SYSTEM_ADDRESS, hour_key("did:tenzro:machine:p").as_bytes())
                .is_none()
        );
        assert!(!served_paid_in_hour(&s, "did:tenzro:machine:p", 5));
    }

    #[test]
    fn live_records_the_hour_once_and_only_that_hour_reads_true() {
        let mut s = state_with_gate(Some(0));
        let did = "did:tenzro:machine:p";
        let mut changes = Vec::new();
        record(&mut s, did, 5 * MARKET_EPOCH_MS + 10, &mut changes).unwrap();
        record(&mut s, did, 5 * MARKET_EPOCH_MS + 20, &mut changes).unwrap();
        assert_eq!(changes.len(), 1, "one write per hour");
        assert!(served_paid_in_hour(&s, did, 5));
        assert!(!served_paid_in_hour(&s, did, 4));
        assert!(!served_paid_in_hour(&s, did, 6));
        assert!(!served_paid_in_hour(&s, "did:tenzro:machine:q", 5));
        // A late settlement for an earlier hour does not move it back.
        record(&mut s, did, 4 * MARKET_EPOCH_MS, &mut changes).unwrap();
        assert!(served_paid_in_hour(&s, did, 5));
        record(&mut s, did, 6 * MARKET_EPOCH_MS, &mut changes).unwrap();
        assert!(served_paid_in_hour(&s, did, 6));
    }
}
