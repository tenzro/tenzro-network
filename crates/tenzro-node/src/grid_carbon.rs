//! Grid carbon intensity by coarse region, for placing work that can run
//! anywhere (spot requests) where the electricity is cleanest.
//!
//! A static table of indicative annual averages of the carbon intensity of
//! electricity generation, grams of CO2-equivalent per kWh, rounded to the
//! nearest ten, with a rough figure for each continent region. The country
//! rows for Poland, Germany, the United States and India match Ember's 2023
//! figures (662, 371, 369 and 713); the other rows are order-of-magnitude
//! values. It is an ordering hint between regions, never a measurement of
//! one provider's supply: a provider on its own renewables sits in its country's row. A
//! region not in the table reads as unknown and is placed after every
//! known one.

/// Region (ISO 3166-1 alpha-2 country code, or a coarse continent region as
/// [`tenzro_types::provider_listing::coarse_region`] accepts), grams CO2e
/// per kWh.
const GRID_G_PER_KWH: &[(&str, u32)] = &[
    ("africa", 470),
    ("AE", 400),
    ("AR", 330),
    ("asia", 560),
    ("AT", 110),
    ("AU", 550),
    ("BE", 150),
    ("BR", 100),
    ("CA", 130),
    ("CH", 40),
    ("CL", 260),
    ("CN", 580),
    ("DE", 370),
    ("DK", 150),
    ("ES", 150),
    ("europe", 270),
    ("FI", 80),
    ("FR", 60),
    ("GB", 240),
    ("ID", 680),
    ("IE", 280),
    ("IN", 710),
    ("IS", 30),
    ("IT", 330),
    ("JP", 490),
    ("KR", 430),
    ("latin-america", 210),
    ("middle-east", 550),
    ("MX", 420),
    ("NL", 270),
    ("NO", 30),
    ("north-america", 370),
    ("NZ", 110),
    ("oceania", 480),
    ("PL", 660),
    ("PT", 140),
    ("SA", 570),
    ("SE", 40),
    ("SG", 470),
    ("TW", 560),
    ("US", 370),
    ("ZA", 710),
];

/// Grams CO2e per kWh of `region`'s grid, `None` when the table does not
/// know it. Country codes match in either case.
pub(crate) fn grid_g_per_kwh(region: &str) -> Option<u32> {
    GRID_G_PER_KWH
        .iter()
        .find(|(r, _)| {
            if r.len() == 2 {
                r.eq_ignore_ascii_case(region)
            } else {
                *r == region
            }
        })
        .map(|(_, g)| *g)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countries_match_in_either_case_and_continents_exactly() {
        assert_eq!(grid_g_per_kwh("FR"), Some(60));
        assert_eq!(grid_g_per_kwh("fr"), Some(60));
        assert_eq!(grid_g_per_kwh("europe"), Some(270));
        assert_eq!(grid_g_per_kwh("Europe"), None);
        assert_eq!(grid_g_per_kwh("XX"), None);
    }

    #[test]
    fn every_continent_region_the_listing_accepts_is_in_the_table() {
        for r in [
            "africa",
            "asia",
            "europe",
            "latin-america",
            "middle-east",
            "north-america",
            "oceania",
        ] {
            assert_eq!(
                tenzro_types::provider_listing::coarse_region(r).as_deref(),
                Ok(r),
                "{r} is a coarse region"
            );
            assert!(grid_g_per_kwh(r).is_some(), "{r}");
        }
        let regions: Vec<&str> = GRID_G_PER_KWH.iter().map(|(r, _)| *r).collect();
        let mut sorted = regions.clone();
        sorted.sort_by_key(|r| r.to_ascii_lowercase());
        sorted.dedup();
        assert_eq!(regions.len(), sorted.len(), "no region twice");
    }
}
