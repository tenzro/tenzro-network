//! Storage classes: the service level a storage claim sells.
//!
//! A class is a retrieval deadline and a price range, never a device type.
//! A storage claim names its class in the tier of its unit,
//! `stored_bytes@hot`, with the bytes it keeps as the quantity. Each class
//! has three governed tunables: how long the holder has to answer a
//! possession probe for an object of that class, and the lowest and highest
//! price of a gibibyte kept for an hour.
//!
//! The rule is dormant until [`KEY`] names an epoch. From then on:
//!
//! - an offer whose unit is `stored_bytes` must be a storage claim, name one
//!   of the classes and price inside that class's range ([`check_offer`]);
//! - a validator counts an object of a class as proven only when the proof
//!   arrived within the class deadline of its probe going out
//!   ([`response_deadline_ms`]), so a holder that cannot meet the class it
//!   sold is found unavailable for the hour like one that lost the object.
//!
//! A storage claim that names no unit has no class: it is held to the probe
//! window alone, as every storage claim is while the rule is dormant.

use super::compute_claim::ClaimRecord;
use super::*;

/// First epoch whose blocks hold storage claims to their class.
pub const KEY: &str = "feature.storage_classes.activation_epoch";

/// Unit id of a storage claim's quantity: bytes kept retrievable.
pub const STORED_BYTES_UNIT: &str = "stored_bytes";

/// Bytes a class's price range is stated per: one gibibyte.
pub const PRICED_BYTES: u128 = 1 << 30;

/// A service level a storage claim can sell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    /// Shortest deadline.
    Hot,
    /// Between hot and cold.
    Warm,
    /// Longest deadline.
    Cold,
}

impl StorageClass {
    /// Every class, fastest first.
    pub const ALL: [StorageClass; 3] = [StorageClass::Hot, StorageClass::Warm, StorageClass::Cold];

    /// The tier that names the class in a unit.
    pub fn tier(self) -> &'static str {
        match self {
            StorageClass::Hot => "hot",
            StorageClass::Warm => "warm",
            StorageClass::Cold => "cold",
        }
    }

    /// The class a unit tier names.
    pub fn from_tier(tier: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.tier() == tier)
    }

    /// Governed key of the class's probe response deadline, ms.
    pub fn deadline_param(self) -> &'static str {
        match self {
            StorageClass::Hot => "feature.storage_classes.hot_deadline_ms",
            StorageClass::Warm => "feature.storage_classes.warm_deadline_ms",
            StorageClass::Cold => "feature.storage_classes.cold_deadline_ms",
        }
    }

    /// Governed key of the class's lowest price, wei per gibibyte per hour.
    pub fn price_floor_param(self) -> &'static str {
        match self {
            StorageClass::Hot => "feature.storage_classes.hot_price_floor",
            StorageClass::Warm => "feature.storage_classes.warm_price_floor",
            StorageClass::Cold => "feature.storage_classes.cold_price_floor",
        }
    }

    /// Governed key of the class's highest price, wei per gibibyte per hour.
    pub fn price_ceiling_param(self) -> &'static str {
        match self {
            StorageClass::Hot => "feature.storage_classes.hot_price_ceiling",
            StorageClass::Warm => "feature.storage_classes.warm_price_ceiling",
            StorageClass::Cold => "feature.storage_classes.cold_price_ceiling",
        }
    }

    /// The governed ceiling on what a provider charges to read this class,
    /// wei per gibibyte read.
    pub fn read_price_ceiling_param(self) -> &'static str {
        match self {
            StorageClass::Hot => "feature.storage_classes.hot_read_price_ceiling",
            StorageClass::Warm => "feature.storage_classes.warm_read_price_ceiling",
            StorageClass::Cold => "feature.storage_classes.cold_read_price_ceiling",
        }
    }
}

/// The class a claim's unit names: `Ok(None)` for a unit that is not
/// `stored_bytes`, an error for `stored_bytes` with no class or an unknown
/// one.
pub fn class_of_unit(unit: Option<&str>) -> std::result::Result<Option<StorageClass>, String> {
    let Some((id, tier)) = unit.and_then(|u| u.split_once(tenzro_types::meter::TIER_SEPARATOR))
    else {
        return match unit {
            Some(STORED_BYTES_UNIT) => Err(format!(
                "{STORED_BYTES_UNIT} needs its class: one of hot, warm, cold after '@'"
            )),
            _ => Ok(None),
        };
    };
    if id != STORED_BYTES_UNIT {
        return Ok(None);
    }
    StorageClass::from_tier(tier)
        .map(Some)
        .ok_or_else(|| format!("'{tier}' is not a storage class: hot, warm or cold"))
}

/// Whether an offer may be written under the class rule, once it is live:
/// a `stored_bytes` unit belongs to a storage claim, names a class, and
/// `strike_per_epoch` for `units_per_epoch` bytes lies inside the class's
/// price range. Everything passes while the rule is dormant.
pub fn check_offer(
    state: &dyn VmState,
    is_storage_claim: bool,
    unit: Option<&str>,
    units_per_epoch: u128,
    strike_per_epoch: u128,
) -> std::result::Result<(), String> {
    if !crate::feature_gate::is_live_now(state, KEY) {
        return Ok(());
    }
    let Some(class) = class_of_unit(unit)? else {
        return Ok(());
    };
    if !is_storage_claim {
        return Err(format!(
            "{STORED_BYTES_UNIT} is the unit of a storage claim, which names the object it keeps"
        ));
    }
    let floor = network_param(state, class.price_floor_param()) as u128;
    let ceiling = network_param(state, class.price_ceiling_param()) as u128;
    let (Some(priced), Some(least), Some(most)) = (
        strike_per_epoch.checked_mul(PRICED_BYTES),
        floor.checked_mul(units_per_epoch),
        ceiling.checked_mul(units_per_epoch),
    ) else {
        return Err(format!(
            "a {} claim's size and price must be priceable per gibibyte without overflow",
            class.tier()
        ));
    };
    if priced < least || priced > most {
        return Err(format!(
            "a {} claim is priced between {floor} and {ceiling} wei per gibibyte per hour",
            class.tier()
        ));
    }
    Ok(())
}

/// Whether a change of `key` to `value` keeps every class's price floor at
/// or below its ceiling, with `get` the value in force or scheduled for any
/// other key. A floor above its ceiling would refuse every offer of the
/// class.
pub fn joint_change_allowed(
    key: &str,
    value: u64,
    get: &dyn Fn(&str) -> u64,
) -> std::result::Result<(), String> {
    for class in StorageClass::ALL {
        let (floor_key, ceiling_key) = (class.price_floor_param(), class.price_ceiling_param());
        if key != floor_key && key != ceiling_key {
            continue;
        }
        let read = |k: &str| if k == key { value } else { get(k) };
        let (floor, ceiling) = (read(floor_key), read(ceiling_key));
        if floor > ceiling {
            return Err(format!(
                "{floor_key} ({floor}) must not exceed {ceiling_key} ({ceiling}), or no {} \
                 claim could be offered",
                class.tier()
            ));
        }
    }
    Ok(())
}

/// How long after a possession probe goes out the proof for `claim` must
/// arrive to count, ms: its class's deadline once the rule is live. `None`
/// for a claim with no class and while the rule is dormant, when only the
/// probe window binds.
pub fn response_deadline_ms(state: &dyn VmState, claim: &ClaimRecord) -> Option<u64> {
    if claim.storage_descriptor.is_none() || !crate::feature_gate::is_live_now(state, KEY) {
        return None;
    }
    let class = class_of_unit(claim.unit.as_deref()).ok().flatten()?;
    Some(network_param(state, class.deadline_param()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const GIB: u128 = PRICED_BYTES;

    fn claim(unit: Option<&str>, storage: bool) -> ClaimRecord {
        ClaimRecord {
            claim_id: "c".into(),
            writer: String::new(),
            holder: None,
            hardware_class: 1,
            region: String::new(),
            delivery_start_ms: 0,
            epochs: 1,
            strike_per_epoch: 1,
            provider_did: "did:store".into(),
            storage_descriptor: storage.then(|| "ab".repeat(32)),
            unit: unit.map(str::to_string),
            units_per_epoch: GIB,
            epochs_settled: 0,
            collateral: 0,
            payment: 0,
            placement: None,
            state: super::super::compute_claim::ClaimState::Held,
        }
    }

    #[test]
    fn a_unit_names_a_class_only_as_stored_bytes_at_a_known_tier() {
        assert_eq!(class_of_unit(None), Ok(None));
        assert_eq!(class_of_unit(Some("output_tokens@hot")), Ok(None));
        assert_eq!(class_of_unit(Some("output_tokens")), Ok(None));
        for class in StorageClass::ALL {
            let unit = format!("{STORED_BYTES_UNIT}@{}", class.tier());
            assert_eq!(class_of_unit(Some(&unit)), Ok(Some(class)));
        }
        assert!(class_of_unit(Some("stored_bytes")).is_err());
        assert!(class_of_unit(Some("stored_bytes@frozen")).is_err());
    }

    #[test]
    fn every_class_tunable_is_registered_inside_its_bounds() {
        for class in StorageClass::ALL {
            for key in [
                class.deadline_param(),
                class.price_floor_param(),
                class.price_ceiling_param(),
            ] {
                let p = crate::governance::governed_param(key)
                    .unwrap_or_else(|| panic!("{key} is not registered"));
                assert!(p.min <= p.genesis && p.genesis <= p.max, "{key}");
            }
        }
        let deadline = |c: StorageClass| crate::governance::genesis_param(c.deadline_param());
        assert!(deadline(StorageClass::Hot) < deadline(StorageClass::Warm));
        assert!(deadline(StorageClass::Warm) < deadline(StorageClass::Cold));
        assert!(
            deadline(StorageClass::Cold)
                <= crate::governance::genesis_param(SLA_PROBE_WINDOW_PARAM),
            "a deadline past the probe window never binds"
        );
    }

    #[test]
    fn a_dormant_rule_checks_no_offer_and_sets_no_deadline() {
        let state = StateAdapter::new();
        assert_eq!(
            check_offer(&state, false, Some("stored_bytes@frozen"), 1, u128::MAX),
            Ok(())
        );
        assert_eq!(
            response_deadline_ms(&state, &claim(Some("stored_bytes@hot"), true)),
            None
        );
    }

    #[test]
    fn a_live_rule_holds_an_offer_to_its_class_and_price_range() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        let hot = StorageClass::Hot;
        set_governed_param_for_test(&mut state, hot.price_floor_param(), 10);
        set_governed_param_for_test(&mut state, hot.price_ceiling_param(), 20);
        let unit = Some("stored_bytes@hot");

        // Two gibibytes: the range is 20..=40 for the hour.
        assert_eq!(check_offer(&state, true, unit, 2 * GIB, 20), Ok(()));
        assert_eq!(check_offer(&state, true, unit, 2 * GIB, 40), Ok(()));
        assert!(check_offer(&state, true, unit, 2 * GIB, 19).is_err());
        assert!(check_offer(&state, true, unit, 2 * GIB, 41).is_err());
        // The class belongs to a storage claim and must be a known one.
        assert!(check_offer(&state, false, unit, 2 * GIB, 20).is_err());
        assert!(check_offer(&state, true, Some("stored_bytes"), GIB, 15).is_err());
        assert!(check_offer(&state, true, Some("stored_bytes@frozen"), GIB, 15).is_err());
        // Other units and classless storage claims are untouched.
        assert_eq!(
            check_offer(&state, false, Some("output_tokens@hot"), 1, 1),
            Ok(())
        );
        assert_eq!(check_offer(&state, true, None, 0, 1), Ok(()));
    }

    #[test]
    fn a_size_or_price_too_large_to_price_is_refused_rather_than_passed() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        let hot = StorageClass::Hot;
        set_governed_param_for_test(&mut state, hot.price_floor_param(), 10);
        set_governed_param_for_test(&mut state, hot.price_ceiling_param(), 20);
        let unit = Some("stored_bytes@hot");
        // A ceiling product past u128 saturated before and let any price pass.
        assert!(check_offer(&state, true, unit, u128::MAX / 2, 1).is_err());
        assert!(check_offer(&state, true, unit, GIB, u128::MAX / 2).is_err());
    }

    #[test]
    fn a_class_floor_may_not_rise_above_its_ceiling() {
        let genesis = |k: &str| crate::governance::genesis_param(k);
        let hot = StorageClass::Hot;
        let ceiling = genesis(hot.price_ceiling_param());
        assert!(joint_change_allowed(hot.price_floor_param(), ceiling, &genesis).is_ok());
        assert!(joint_change_allowed(hot.price_floor_param(), ceiling + 1, &genesis).is_err());
        let floor_set = |k: &str| {
            if k == hot.price_floor_param() {
                100
            } else {
                genesis(k)
            }
        };
        assert!(joint_change_allowed(hot.price_ceiling_param(), 100, &floor_set).is_ok());
        assert!(joint_change_allowed(hot.price_ceiling_param(), 99, &floor_set).is_err());
        assert!(
            joint_change_allowed(StorageClass::Cold.price_ceiling_param(), 99, &floor_set).is_ok(),
            "each class is held to its own floor"
        );
        assert!(
            crate::governance::joint_change_allowed(hot.price_floor_param(), ceiling + 1, &genesis)
                .is_err(),
            "governance applies the rule at proposal and at enactment"
        );
    }

    #[test]
    fn a_live_rule_gives_each_class_its_own_deadline() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        for class in StorageClass::ALL {
            let unit = format!("{STORED_BYTES_UNIT}@{}", class.tier());
            assert_eq!(
                response_deadline_ms(&state, &claim(Some(&unit), true)),
                Some(crate::governance::genesis_param(class.deadline_param()))
            );
        }
        set_governed_param_for_test(&mut state, StorageClass::Hot.deadline_param(), 1_234);
        assert_eq!(
            response_deadline_ms(&state, &claim(Some("stored_bytes@hot"), true)),
            Some(1_234)
        );
        assert_eq!(response_deadline_ms(&state, &claim(None, true)), None);
        assert_eq!(
            response_deadline_ms(&state, &claim(Some("stored_bytes@hot"), false)),
            None,
            "a claim that keeps no object owes no possession proof"
        );
    }
}
