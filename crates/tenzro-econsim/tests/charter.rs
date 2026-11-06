//! The charter gate on the usage accounting: every payout path is listed
//! with the paid, verified unit it pays for; no path pays without one; with
//! no paid usage nothing is paid; borrowing against TNZO is a violation;
//! and the trace reader reads back what it wrote.

use tenzro_econsim::usage::{Mechanisms, Payout, Rules, Trace, replay};
use tenzro_econsim::usage_fixtures::{MIXES, SCALES, cells, fixture};

const DAYS: u64 = 200;

#[test]
fn every_payout_path_in_the_accounting_is_listed_with_its_tie() {
    let src = include_str!("../src/usage.rs");
    for p in Payout::ALL {
        assert!(!p.tie().is_empty(), "{p:?} names no tie");
    }
    // Payouts are booked in one place; every booked path is listed.
    for line in src.lines().filter(|l| l.contains("book(&mut o, Payout::")) {
        let name = line
            .split("Payout::")
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_alphanumeric()).next())
            .unwrap_or("");
        assert!(
            Payout::ALL.iter().any(|p| format!("{p:?}") == name),
            "booked path {name} is not listed"
        );
    }
}

#[test]
fn with_no_paid_usage_no_path_pays() {
    let base = cells().into_iter().find(|c| c.name == "baseline").unwrap();
    let t = fixture(&base, MIXES[1].1, 0.0, DAYS);
    for avail in [0.0, 1.0] {
        let o = replay(
            &t,
            &Rules {
                availability_tnzo_hour: avail,
                ..Rules::default()
            },
        );
        assert_eq!(o.paid_usd, 0.0);
        for (p, b) in &o.paths {
            if *p == Payout::Availability {
                // Verified availability pays for answered challenges, which
                // need no paid usage; it is the only such path.
                continue;
            }
            assert_eq!(b.paid_usd, 0.0, "{p:?} paid with no paid usage");
        }
        assert_eq!(o.charter_violations, 0);
    }
}

#[test]
fn no_fixture_cell_pays_without_paid_verified_work() {
    for c in cells() {
        let t = fixture(&c, MIXES[0].1, SCALES[1], DAYS);
        let o = replay(&t, &Rules::default());
        assert_eq!(o.charter_violations, 0, "{}: {:?}", c.name, o.paths);
        assert_eq!(o.substituted_usd, 0.0, "{}: a payment fell back", c.name);
        assert!(o.residency_violations <= 1e-6, "{}: residency", c.name);
    }
}

#[test]
fn borrowing_against_tnzo_is_a_charter_violation() {
    let base = cells().into_iter().find(|c| c.name == "baseline").unwrap();
    let t = fixture(&base, MIXES[1].1, SCALES[1], DAYS);
    let o = replay(
        &t,
        &Rules {
            mechanisms: Mechanisms {
                leverage: true,
                ..Mechanisms::default()
            },
            ..Rules::default()
        },
    );
    assert!(!o.pass_charter);
}

#[test]
fn a_trace_written_reads_back_and_replays_the_same() {
    let c = cells()
        .into_iter()
        .find(|c| c.name == "stable_depeg_suspend")
        .unwrap();
    let t = fixture(&c, MIXES[2].1, SCALES[0], DAYS);
    let dir = std::env::temp_dir().join(format!("usage-trace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (m, r) = (dir.join("m.json"), dir.join("t.jsonl"));
    t.write(&m, &r).unwrap();
    let back = Trace::read(&m, &r).unwrap();
    let a = serde_json::to_string(&replay(&t, &Rules::default())).unwrap();
    let b = serde_json::to_string(&replay(&back, &Rules::default())).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(a, b);
    let o = replay(&back, &Rules::default());
    assert!(
        o.suspended_usd > 0.0,
        "the depeg suspends payments in the asset"
    );
}

/// A two-row market-stress simulation export reads with its sha256, maps a segment to
/// a buyer and a provider's capacity and utilisation to served units; one
/// byte changed is refused.
#[test]
fn the_living_worlds_reader_checks_the_sha256_and_maps_the_rows() {
    use sha2::{Digest, Sha256};
    let rows = concat!(
        r#"{"tick":0,"actor":"critical-a","kind":"segment","segment":"critical","region":"region-a","demand":10,"supply":8,"clearing_price":2,"utilisation":0.5,"unmet_demand":2}"#,
        "\n",
        r#"{"tick":0,"actor":"provider-01","kind":"provider","segment":null,"region":"region-a","demand":8,"supply":16,"clearing_price":2,"utilisation":0.5,"unmet_demand":0}"#,
        "\n"
    );
    let dir = std::env::temp_dir().join(format!("lw-trace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (m, t) = (dir.join("x.manifest.json"), dir.join("x.jsonl"));
    std::fs::write(&t, rows).unwrap();
    let manifest = |sha: &str| {
        serde_json::json!({
            "format": "lw.market-stress/1", "seed": 7, "scenario": {"name": "baseline", "variant": "posted"},
            "parameters": {"regions": [{"id": "region-a", "energy_price": 0.1}],
                "providers": [{"id": "provider-01", "region": "region-a", "capacity": 16, "capex": 1.0, "opex": 0.25, "energy": 1.0, "markup": 0.1}]},
            "shocks": [], "validation": {"inside_band": true}, "trace": {"sha256": sha}
        })
    };
    let sha = hex::encode(Sha256::digest(rows.as_bytes()));
    std::fs::write(&m, serde_json::to_vec(&manifest(&sha)).unwrap()).unwrap();
    let tr = Trace::read_lw(&m, &t).unwrap();
    let r = &tr.ticks[0];
    assert_eq!(r[0].actor_kind, "buyer");
    assert_eq!(r[0].segment.as_deref(), Some("regulated_critical"));
    assert_eq!(r[0].demand - r[0].unmet_demand, 8.0);
    assert_eq!(r[1].actor_kind, "provider");
    assert_eq!((r[1].supply, r[1].capacity), (8.0, Some(16.0)));
    assert!((r[1].cost.unwrap() - 0.35).abs() < 1e-9);
    std::fs::write(&m, serde_json::to_vec(&manifest(&"0".repeat(64))).unwrap()).unwrap();
    assert!(Trace::read_lw(&m, &t).unwrap_err().contains("sha256"));
    std::fs::remove_dir_all(&dir).ok();
}
