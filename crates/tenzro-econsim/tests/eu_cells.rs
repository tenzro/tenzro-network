//! The EU stress cells over a year: idle AI-factory capacity, a consortium
//! that goes dark or is resold cheap, and EU-only residency demand. Each
//! keeps residency, pays nothing outside the charter, and a resold
//! consortium leaves no more demand unmet than one that went dark.

use tenzro_econsim::usage::{Rules, replay};
use tenzro_econsim::usage_fixtures::{MIXES, SCALES, cells, fixture};

const DAYS: u64 = 360;

fn outcome(name: &str) -> tenzro_econsim::usage::Outcome {
    let c = cells()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no cell {name}"));
    replay(&fixture(&c, MIXES[1].1, SCALES[1], DAYS), &Rules::default())
}

#[test]
fn every_eu_cell_keeps_residency_and_the_charter() {
    let eu: Vec<_> = cells().into_iter().filter(|c| c.family == "eu").collect();
    assert_eq!(eu.len(), 4);
    for c in eu {
        let o = outcome(&c.name);
        assert!(o.regions.contains("eu"), "{}", c.name);
        assert_eq!(o.residency_violations, 0.0, "{}", c.name);
        assert!(o.pass_residency && o.pass_charter, "{}", c.name);
        assert_eq!(o.charter_violations, 0, "{}", c.name);
        assert!(o.paid_usd > 0.0, "{}", c.name);
    }
}

#[test]
fn a_resold_consortium_leaves_no_more_unmet_than_a_dark_one() {
    let dark = outcome("eu_consortium_dark");
    let resold = outcome("eu_consortium_resold");
    assert!(
        resold.unmet_share <= dark.unmet_share,
        "resold {} against dark {}",
        resold.unmet_share,
        dark.unmet_share
    );
}
