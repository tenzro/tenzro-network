//! A compute provider's own word on whether it is serving.
//!
//! A provider is not always on. The owner of a compute bond says when the
//! machine stops serving and when it serves again, and either change takes
//! effect at the next hour: the hour it is sent in still counts as it stood.
//! For an hour a provider was offline, and in which it delivers no held
//! claim, validators' probe outcomes for it are left out, so the hour gets no
//! availability verdict: no penalty and no availability reward. An hour it
//! owes to a held claim is judged as before, online or not. Validators and
//! storage stakes have no presence: they are always on.
//!
//! The change is a `NativeCall` ([`SELECTOR_PROVIDER_PRESENCE`], payload in
//! `tenzro-native-ops`), and the rule waits for [`GATE`]: until then nobody
//! can go offline and every hour is judged.
//!
//! The presence is a `presence` member of the compute bond's marker. Every
//! other writer of the marker (increase, withdraw, return, both slashes)
//! decodes it as a JSON value and edits named members in place, and a post
//! never overwrites an existing marker, so no path, in this binary or an
//! earlier one, drops the member.

use serde::{Deserialize, Serialize};
use tenzro_native_ops::provider_presence::ProviderPresenceOp;

use super::compute_claim::delivers_held_claim;
use super::{
    MARKET_EPOCH_MS, MARKET_SUBMIT_WINDOW, SYSTEM_ADDRESS, compute_bond_storage_key,
    require_compute_bond_owner, validate_compute_bond_provider_did,
};
use crate::error::{Result, VmError};
use crate::traits::VmState;
use crate::types::{Log, StateChange};

pub use tenzro_native_ops::SELECTOR_PROVIDER_PRESENCE;

/// Gas for a presence change, shared with the CLI, which sends it as the gas limit.
pub use tenzro_native_ops::provider_presence::GAS as GAS_PROVIDER_PRESENCE;

/// The gate of the rule.
pub const GATE: &str = "feature.provider_presence.activation_epoch";

/// Log topic when a provider's presence changes.
pub const PRESENCE_TOPIC: &[u8] = b"ProviderPresence";

/// The hours a provider has said it is offline, kept in its bond record.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    /// First hour of the offline spell still running.
    pub offline_from: Option<u64>,
    /// Finished offline spells still inside the attestation window, each
    /// from its first hour up to and excluding the hour it ended.
    pub spells: Vec<(u64, u64)>,
}

impl Presence {
    /// Whether the provider had said it was offline in `epoch`.
    pub fn offline_at(&self, epoch: u64) -> bool {
        self.offline_from.is_some_and(|from| from <= epoch)
            || self
                .spells
                .iter()
                .any(|(from, until)| *from <= epoch && epoch < *until)
    }

    /// Records a change sent in `now_epoch`, in force from the next hour.
    /// False when the provider already is what it asks to be.
    fn set(&mut self, online: bool, now_epoch: u64) -> bool {
        let next = now_epoch + 1;
        match (self.offline_from, online) {
            (None, false) => self.offline_from = Some(next),
            (Some(from), true) => {
                self.offline_from = None;
                if from < next {
                    self.spells.push((from, next));
                }
            }
            (None, true) | (Some(_), false) => return false,
        }
        // An hour older than the window can no longer be attested.
        self.spells
            .retain(|(_, until)| until + MARKET_SUBMIT_WINDOW >= now_epoch);
        true
    }
}

fn read(marker: &serde_json::Value) -> Presence {
    let Some(raw) = marker.get("presence") else {
        return Presence::default();
    };
    serde_json::from_value(raw.clone()).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "a provider's presence record does not decode; it is read as online");
        Presence::default()
    })
}

/// Whether probe outcomes for the compute bond `provider_did` in `epoch` are
/// left out: the rule is in force, the provider had said it was offline, and
/// it owed that hour to no held claim.
pub fn excused(state: &dyn VmState, owner: &[u8], provider_did: &str, epoch: u64) -> bool {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return false;
    }
    let marker: Option<serde_json::Value> = state
        .get_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(provider_did).as_bytes(),
        )
        .and_then(|b| serde_json::from_slice(&b).ok());
    marker.is_some_and(|m| read(&m).offline_at(epoch))
        && !delivers_held_claim(state, owner, provider_did, epoch)
}

/// Applies a presence change sent by `from`: only the bond's owner, only on
/// a live bond, only a real change, only once [`GATE`] is in force.
pub fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &ProviderPresenceOp,
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(VmError::InvalidTransaction(format!(
            "provider presence is not in force on this chain yet (it waits for {GATE})"
        )));
    }
    validate_compute_bond_provider_did(&payload.provider_did)?;
    let key = compute_bond_storage_key(&payload.provider_did);
    let prior = state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .ok_or_else(|| {
            VmError::InvalidTransaction(format!(
                "no compute bond exists for provider {}",
                payload.provider_did
            ))
        })?;
    let mut marker: serde_json::Value = serde_json::from_slice(&prior)
        .map_err(|e| VmError::Internal(format!("decode compute bond marker: {e}")))?;
    require_compute_bond_owner(&marker, from)?;
    let op = marker.get("op").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(op, "Posted" | "Increased") {
        return Err(VmError::InvalidTransaction(format!(
            "a compute bond in {op} state has no presence to change"
        )));
    }
    let now_epoch = (now_ms.max(0) / MARKET_EPOCH_MS) as u64;
    let mut presence = read(&marker);
    if !presence.set(payload.online, now_epoch) {
        return Err(VmError::InvalidTransaction(format!(
            "provider {} is already {}",
            payload.provider_did,
            if payload.online { "online" } else { "offline" }
        )));
    }
    marker["presence"] = serde_json::to_value(&presence)
        .map_err(|e| VmError::Internal(format!("encode provider presence: {e}")))?;
    let blob = serde_json::to_vec(&marker)
        .map_err(|e| VmError::Internal(format!("encode compute bond marker: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    let log_data = serde_json::to_vec(&serde_json::json!({
        "provider_did": payload.provider_did,
        "online": payload.online,
        "from_epoch": now_epoch + 1,
    }))
    .map_err(|e| VmError::Internal(format!("encode provider presence log: {e}")))?;
    Ok((
        vec![StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            key.into_bytes(),
            Some(prior),
            Some(blob),
        )],
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![PRESENCE_TOPIC.to_vec()],
            log_data,
        )],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_takes_effect_at_the_next_hour() {
        let mut p = Presence::default();
        assert!(p.set(false, 100));
        assert!(
            !p.offline_at(100),
            "the hour it was sent in still counts as online"
        );
        assert!(p.offline_at(101) && p.offline_at(500));
        assert!(p.set(true, 110));
        assert!(
            p.offline_at(110),
            "the hour it came back in is still excused"
        );
        assert!(!p.offline_at(111));
        assert_eq!(p.spells, [(101, 111)]);
    }

    #[test]
    fn asking_for_what_already_holds_changes_nothing() {
        let mut p = Presence::default();
        assert!(!p.set(true, 5));
        assert!(p.set(false, 5));
        assert!(!p.set(false, 6));
        assert_eq!(p.offline_from, Some(6));
    }

    #[test]
    fn off_and_on_within_one_hour_leaves_no_offline_hour() {
        let mut p = Presence::default();
        assert!(p.set(false, 7));
        assert!(p.set(true, 7));
        assert!(!p.offline_at(7) && !p.offline_at(8));
        assert!(p.spells.is_empty());
    }

    #[test]
    fn earlier_spells_stay_readable_inside_the_window_and_are_dropped_after_it() {
        let mut p = Presence::default();
        p.set(false, 10);
        p.set(true, 12);
        p.set(false, 14);
        assert!(
            p.offline_at(11)
                && p.offline_at(12)
                && !p.offline_at(13)
                && !p.offline_at(14)
                && p.offline_at(15)
        );
        p.set(true, 13 + MARKET_SUBMIT_WINDOW + 5);
        p.set(false, 13 + MARKET_SUBMIT_WINDOW + 6);
        assert!(
            !p.spells.contains(&(11, 13)),
            "a spell no attestation can reach is dropped"
        );
    }
}
