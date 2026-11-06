//! A provider's standing for routing, read straight from consensus state.
//!
//! Routing ranks providers by what the chain itself records about them: the
//! bond that answers for their serving (a model-provider role stake or a
//! compute bond, which inference faults slash) and the SLA verdicts the
//! validators froze for them over the last closed hours. Nothing here is
//! written anywhere; every node computes the same number from the same state.
//! The weights and the window are governed network parameters
//! (`routing.standing_*`). Richer scoring over the same public reads belongs
//! to applications.

use tenzro_types::network::NetworkRole;
use tenzro_vm::governance as g;
use tenzro_vm::native::{self, MARKET_EPOCH_MS, network_param};
use tenzro_vm::traits::VmState;

/// The scale standing is expressed in: the router divides by it.
pub const STANDING_MAX: u64 = 10_000;

/// The standing of the provider whose account is `account`, at `now_ms`:
/// 0 without a live bond, otherwise the governed bonded standing plus the
/// governed availability standing scaled by the share of judged hours in the
/// governed window its verdicts found it available.
pub fn standing(state: &dyn VmState, account: &[u8], now_ms: i64) -> u64 {
    let stake = native::read_role_stake(state, account, NetworkRole::ModelProvider)
        .filter(|s| s.bonded > 0)
        .map(|_| native::role_stake_subject(account, NetworkRole::ModelProvider));
    let bond = native::identity_did_of(state, account)
        .and_then(|did| native::economy::compute_bond(state, &did))
        .filter(|b| b.status == "Active" && b.amount > 0)
        .map(|b| b.provider_did);
    let subjects: Vec<String> = stake.into_iter().chain(bond).collect();
    if subjects.is_empty() {
        return 0;
    }
    let bonded = network_param(state, g::STANDING_BONDED_PARAM);
    let availability_max = network_param(state, g::STANDING_AVAILABILITY_PARAM);
    let unjudged_bps = network_param(state, g::STANDING_UNJUDGED_BPS_PARAM);
    let window = network_param(state, g::STANDING_WINDOW_HOURS_PARAM);
    let now_hour = (now_ms.max(0) / MARKET_EPOCH_MS) as u64;
    let (mut judged, mut up) = (0u64, 0u64);
    for hour in now_hour.saturating_sub(window)..now_hour {
        for subject in &subjects {
            if let Some(v) = native::read_sla_verdict(state, subject, hour) {
                judged += 1;
                up += u64::from(v.available);
            }
        }
    }
    let availability = availability_max
        .saturating_mul(up)
        .checked_div(judged)
        .unwrap_or(availability_max.saturating_mul(unjudged_bps) / 10_000);
    bonded.saturating_add(availability).min(STANDING_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_vm::StateAdapter;

    const H: i64 = MARKET_EPOCH_MS;
    const BONDED: u64 = g::DEFAULT_STANDING_BONDED;
    const AVAILABILITY: u64 = g::DEFAULT_STANDING_AVAILABILITY;

    fn verdict(state: &mut StateAdapter, subject: &str, hour: u64, available: bool) {
        let v = serde_json::json!({
            "available": available, "up_stake": "1", "down_stake": "0", "attesters": 1, "measured_capacity": null
        });
        state.set_storage(
            &native::SYSTEM_ADDRESS,
            format!("sla:{hour}:{subject}").as_bytes(),
            serde_json::to_vec(&v).unwrap(),
        );
    }

    #[test]
    fn standing_follows_the_bond_and_the_verdicts() {
        let mut state = StateAdapter::new();
        let account = [7u8; 32];
        assert_eq!(
            standing(&state, &account, 30 * H),
            0,
            "no bond, no standing"
        );
        let stake = tenzro_types::token::RoleStake {
            bonded: 1_000,
            ..Default::default()
        };
        state.set_storage(
            &native::SYSTEM_ADDRESS,
            format!(
                "role_stake:{}:{}",
                hex::encode(account),
                NetworkRole::ModelProvider.as_str()
            )
            .as_bytes(),
            serde_json::to_vec(&stake).unwrap(),
        );
        assert_eq!(
            standing(&state, &account, 30 * H),
            BONDED + AVAILABILITY / 2,
            "no verdict yet"
        );
        let subject = native::role_stake_subject(&account, NetworkRole::ModelProvider);
        verdict(&mut state, &subject, 28, true);
        verdict(&mut state, &subject, 29, true);
        assert_eq!(standing(&state, &account, 30 * H), STANDING_MAX);
        verdict(&mut state, &subject, 27, false);
        verdict(&mut state, &subject, 26, false);
        assert_eq!(
            standing(&state, &account, 30 * H),
            BONDED + AVAILABILITY / 2
        );
        // Verdicts outside the window no longer count.
        assert_eq!(
            standing(&state, &account, 60 * H),
            BONDED + AVAILABILITY / 2
        );
        // Governance moves the weights and the window.
        let set = |state: &mut StateAdapter, key: &str, v: u64| {
            state.set_storage(
                &native::SYSTEM_ADDRESS,
                native::governed_param_key(key).as_bytes(),
                v.to_le_bytes().to_vec(),
            )
        };
        set(&mut state, g::STANDING_BONDED_PARAM, 1_000);
        set(&mut state, g::STANDING_WINDOW_HOURS_PARAM, 2);
        assert_eq!(standing(&state, &account, 30 * H), 1_000 + AVAILABILITY);
        set(&mut state, g::STANDING_UNJUDGED_BPS_PARAM, 0);
        assert_eq!(standing(&state, &account, 60 * H), 1_000);
    }
}
