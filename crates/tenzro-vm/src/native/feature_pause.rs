//! A guardian pause of one named feature.
//!
//! Protocol guardians can stop a feature a status lever governs
//! (`<feature>.status`, see [`crate::governance::LeverStatus`]) for a bounded
//! number of epochs, without halting the chain. The power is negative and
//! narrow, like every guardian power:
//!
//! - it only moves an *enabled* feature to paused; it cannot enable anything,
//!   resume a feature a vote paused, retire one, or change a value;
//! - it names the feature and the number of epochs, at most
//!   `governance.feature_pause_max_epochs`, and takes effect once
//!   `governance.guardian_threshold` distinct protocol guardians have signalled
//!   the same feature and the same number of epochs inside the signal window;
//! - it lifts by itself when the epochs have passed, and the same feature
//!   cannot be paused again by guardians until
//!   `governance.feature_pause_cooloff_epochs` after it lifted. A vote can
//!   pause the feature longer, or resume it, in the meantime.
//!
//! The pause is not a governed value: it is a record beside the lever, and
//! [`crate::native::lever_status`] reports the lever as paused while the
//! record runs.

use serde::{Deserialize, Serialize};

use super::*;
use crate::governance::{
    FEATURE_PAUSE_COOLOFF_PARAM, FEATURE_PAUSE_MAX_PARAM, GuardianRole, LeverStatus, Tighten,
    governed_param,
};

/// Payload of a `GovernanceFeaturePause` call after the selector: the epochs
/// (u32, big endian), then the lever key as UTF-8.
pub const PAYLOAD_HEADER: usize = 4;

/// A feature pause: the first epoch it no longer holds in, and the first
/// epoch guardians may pause the same feature again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeaturePause {
    /// First epoch the pause no longer holds in.
    pub until_epoch: u64,
    /// First epoch a new guardian pause of the feature is accepted in.
    pub cooloff_until_epoch: u64,
}

/// Storage key, under the system account, of the pause of the lever `key`.
pub fn pause_key(key: &str) -> String {
    format!("governance_feature_pause:{key}")
}

/// The pause record of the lever `key`.
pub fn pause_of(state: &dyn VmState, key: &str) -> FeaturePause {
    state
        .get_storage(&SYSTEM_ADDRESS, pause_key(key).as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Whether a guardian pause of the lever `key` holds in the epoch of the block
/// being executed.
pub fn active(state: &dyn VmState, key: &str) -> bool {
    params_epoch(state) < pause_of(state, key).until_epoch
}

/// The lever key and epochs a `GovernanceFeaturePause` call carries.
pub fn parse(data: &[u8]) -> Result<(u64, String)> {
    let body = data
        .get(4..)
        .filter(|b| b.len() > PAYLOAD_HEADER)
        .ok_or_else(|| {
            VmError::InvalidTransaction(
                "feature pause payload is the epochs (4 bytes, big endian) then the lever key"
                    .into(),
            )
        })?;
    let epochs = u32::from_be_bytes(body[..PAYLOAD_HEADER].try_into().expect("four bytes"));
    let key = std::str::from_utf8(&body[PAYLOAD_HEADER..])
        .map_err(|_| VmError::InvalidTransaction("the lever key is not utf-8".into()))?;
    Ok((u64::from(epochs), key.to_string()))
}

/// `GovernanceFeaturePause`: a protocol guardian signals a pause of one
/// feature for `epochs` epochs.
pub(super) fn execute_feature_pause(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    gas_meter.consume(GAS_GOVERNANCE_EXECUTE)?;
    let refuse = |why: String| VmError::InvalidTransaction(format!("feature pause refused: {why}"));
    let (epochs, key) = parse(&tx.data)?;
    let now = tx.block_timestamp_ms.ok_or_else(|| {
        VmError::InvalidTransaction("a guardian pause executes only inside a block".into())
    })?;
    if guardian::active_role(state, &tx.from, now) != Some(GuardianRole::Protocol) {
        return Err(refuse("only a seated protocol guardian may pause".into()));
    }
    if governed_param(&key).is_none_or(|p| p.tighten != Tighten::Retire) {
        return Err(refuse(format!("{key} is not a status lever")));
    }
    let longest = network_param(state, FEATURE_PAUSE_MAX_PARAM);
    if epochs == 0 || epochs > longest {
        return Err(refuse(format!(
            "a pause lasts 1 to {longest} epochs, not {epochs}"
        )));
    }
    if LeverStatus::from_value(network_param(state, &key)) != LeverStatus::Enabled {
        return Err(refuse(format!(
            "{key} is not enabled; a guardian pause only stops a running feature"
        )));
    }
    let epoch = params_epoch(state);
    let record = pause_of(state, &key);
    if epoch < record.until_epoch {
        return Err(refuse(format!("{key} is already paused")));
    }
    if epoch < record.cooloff_until_epoch {
        return Err(refuse(format!(
            "the last pause of {key} cools off until epoch {}",
            record.cooloff_until_epoch
        )));
    }

    let gas_cost = tx.gas_price.saturating_mul(GAS_GOVERNANCE_EXECUTE as u128);
    let balance = state.get_balance(&tx.from);
    if balance < gas_cost {
        return Err(VmError::InsufficientBalance {
            required: gas_cost,
            available: balance,
        });
    }
    let mut changes = Vec::new();
    let tallied = guardian::signal_feature_pause(state, &key, epochs, &tx.from, now, &mut changes)
        .map_err(refuse)?;
    state.set_balance(&tx.from, balance.saturating_sub(gas_cost));
    let nonce = state.get_nonce(&tx.from);
    state.set_nonce(&tx.from, nonce + 1);

    let topic: &[u8] = if tallied.carried() {
        let until = epoch.saturating_add(epochs);
        let cooloff = network_param(state, FEATURE_PAUSE_COOLOFF_PARAM);
        let record = FeaturePause {
            until_epoch: until,
            cooloff_until_epoch: until.saturating_add(cooloff),
        };
        let storage_key = pause_key(&key);
        let previous = state.get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes());
        let blob = serde_json::to_vec(&record).expect("a pause record serialises");
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), blob.clone());
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            storage_key.into_bytes(),
            previous,
            Some(blob),
        ));
        b"FeaturePaused"
    } else {
        b"FeaturePauseSignalled"
    };
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        Vec::new(),
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![topic.to_vec()],
            key.into_bytes(),
        )],
        changes,
    ))
}
