//! The charter gate on the device-class split: a class is paid only for paid
//! units it delivered, the release paid to the classes is the accounting's
//! own, and with no paid usage no class is paid or grows.

use tenzro_econsim::device_classes::{DISPATCH, DeviceClass, DeviceSettings, book, run};
use tenzro_econsim::usage::{Payout, Rules, replay};
use tenzro_econsim::usage_fixtures::{MIXES, SCALES, cells, fixture};

const DAYS: u64 = 200;

#[test]
fn with_no_paid_usage_no_class_is_paid_or_grows() {
    let base = cells().into_iter().find(|c| c.name == "baseline").unwrap();
    let t = fixture(&base, MIXES[1].1, 0.0, DAYS);
    for dispatch in DISPATCH {
        let s = DeviceSettings {
            dispatch,
            ..DeviceSettings::default()
        };
        let r = run(&book(&t, &Rules::default()), 1.0, &s);
        assert_eq!(r.paid_usd, 0.0);
        for (c, b) in &r.classes {
            assert_eq!(
                b.service_usd + b.release_usd,
                0.0,
                "{c:?} paid with no paid usage"
            );
            assert_eq!(b.units, 0.0, "{c:?} delivered units nobody paid for");
            if matches!(c, DeviceClass::Edge | DeviceClass::Desktop) {
                assert!(
                    b.devices_end <= b.devices_start,
                    "{c:?} grew with no paid usage"
                );
            }
        }
        assert_eq!(r.charter_violations, 0);
    }
}

#[test]
fn every_class_payout_is_for_delivered_paid_work() {
    for c in cells() {
        let t = fixture(&c, MIXES[0].1, SCALES[1], DAYS);
        let rules = Rules::default();
        let o = replay(&t, &rules);
        for dispatch in DISPATCH {
            for small_share in [0.0, 0.3] {
                let s = DeviceSettings {
                    dispatch,
                    small_share,
                    ..DeviceSettings::default()
                };
                let r = run(&o.tick_book, 1.0, &s);
                assert_eq!(
                    r.charter_violations, 0,
                    "{}: a class paid without delivered paid work",
                    c.name
                );
                let released: f64 = o.tick_book.iter().map(|t| t.provider_release_tnzo).sum();
                assert!(
                    r.release_split_error_tnzo.abs() <= 1e-9 * released.max(1.0),
                    "{}: classes got {} TNZO more release than the accounting paid",
                    c.name,
                    r.release_split_error_tnzo
                );
                let class_release: f64 =
                    [DeviceClass::Edge, DeviceClass::Desktop, DeviceClass::Server]
                        .iter()
                        .map(|k| r.classes[k].release_usd)
                        .sum();
                let paid = o.paths[&Payout::ProviderRelease].paid_usd;
                assert!(
                    (class_release - paid).abs() <= 1e-6 * paid.max(1.0),
                    "{}: release to classes {class_release} USD, accounting {paid} USD",
                    c.name
                );
                let units: f64 = o.tick_book.iter().map(|t| t.units).sum();
                let delivered: f64 = r.classes.values().map(|b| b.units).sum();
                assert!(
                    (units - delivered).abs() <= 1e-6 * units.max(1.0),
                    "{}: units lost in the split",
                    c.name
                );
            }
        }
    }
}

#[test]
fn critical_work_goes_to_servers_only() {
    let base = cells().into_iter().find(|c| c.name == "baseline").unwrap();
    // Every unit bought by the regulated, critical segment.
    let t = fixture(&base, [1.0, 0.0, 0.0, 0.0], SCALES[1], DAYS);
    let s = DeviceSettings {
        small_share: 1.0,
        medium_share: 0.0,
        ..DeviceSettings::default()
    };
    let r = run(&book(&t, &Rules::default()), 1.0, &s);
    assert!(r.classes[&DeviceClass::Server].units > 0.0);
    assert_eq!(r.classes[&DeviceClass::Edge].units, 0.0);
    assert_eq!(r.classes[&DeviceClass::Desktop].units, 0.0);
}
