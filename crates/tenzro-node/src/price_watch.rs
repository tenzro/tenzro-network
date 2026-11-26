//! How the prices of the live network offers for each model sit against one
//! another, served with the node's metrics.
//!
//! Providers that settle on one price show up as a group of payees quoting an
//! identical charge with no spread between the highest and the lowest. That
//! is also what competition can produce, so the numbers here are a prompt to
//! look and nothing in the node acts on them. Only offers gossiped to this
//! node are seen, and two accounts of one operator are not linked.

use std::collections::BTreeMap;

use crate::node::TenzroNode;

/// Most models reported in one scrape.
const MAX_MODELS: usize = 64;

/// How long one summary serves the metrics route. `/metrics` is open, so the
/// offers are priced at most this often however often it is scraped.
const SUMMARY_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// One live offer: the model, the account it settles to, and the card's
/// charge for the reference call.
pub(crate) struct Offer {
    pub model: String,
    pub payee: [u8; 32],
    pub price: u128,
}

/// The prices offered for one model.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ModelPrices {
    pub model: String,
    /// Distinct payees offering the model.
    pub payees: usize,
    /// The highest price over the lowest, less one, in basis points.
    pub spread_bps: u64,
    /// The largest group of distinct payees quoting one identical non-zero
    /// price. Offering a model free is not agreeing on a price, so free
    /// offers are in no group.
    pub same_price_payees: usize,
}

/// Model ids arrive by gossip; only one made of these characters becomes a
/// metric label.
fn label_safe(model: &str) -> bool {
    !model.is_empty()
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

/// The price picture of every model two or more payees offer, the models
/// with the most payees first and at most [`MAX_MODELS`] of them. A payee
/// with several offers for a model counts once, at its lowest price.
pub(crate) fn summarize(offers: &[Offer]) -> Vec<ModelPrices> {
    let mut lowest: BTreeMap<&str, BTreeMap<[u8; 32], u128>> = BTreeMap::new();
    for o in offers.iter().filter(|o| label_safe(&o.model)) {
        let price = lowest
            .entry(&o.model)
            .or_default()
            .entry(o.payee)
            .or_insert(o.price);
        *price = (*price).min(o.price);
    }
    let mut models: Vec<ModelPrices> = lowest
        .into_iter()
        .filter(|(_, by_payee)| by_payee.len() >= 2)
        .map(|(model, by_payee)| {
            let mut groups: BTreeMap<u128, usize> = BTreeMap::new();
            for price in by_payee.values() {
                *groups.entry(*price).or_default() += 1;
            }
            let same_price_payees = groups
                .iter()
                .filter(|(price, _)| **price > 0)
                .map(|(_, n)| *n)
                .max()
                .unwrap_or(0);
            let low = groups.keys().next().copied().unwrap_or(0);
            let high = groups.keys().next_back().copied().unwrap_or(0);
            let spread = match low {
                0 if high == 0 => 0,
                0 => u128::MAX,
                // Quotient and remainder apart, so a large price cannot
                // overflow the multiplication.
                _ => {
                    let over = high - low;
                    (over / low)
                        .saturating_mul(10_000)
                        .saturating_add((over % low).saturating_mul(10_000) / low)
                }
            };
            ModelPrices {
                model: model.to_string(),
                payees: by_payee.len(),
                spread_bps: u64::try_from(spread).unwrap_or(u64::MAX),
                same_price_payees,
            }
        })
        .collect();
    models.sort_by(|a, b| b.payees.cmp(&a.payees).then_with(|| a.model.cmp(&b.model)));
    models.truncate(MAX_MODELS);
    models
}

/// The live network offers this node holds whose payee can be read and
/// whose card prices the reference call.
fn live_offers(node: &TenzroNode) -> Vec<Offer> {
    let reference = tenzro_types::model::BillableUnits::tokens(
        crate::offer_ranking::REFERENCE_INPUT_TOKENS,
        crate::offer_ranking::REFERENCE_OUTPUT_TOKENS,
    );
    node.network_models_snapshot()
        .into_iter()
        .filter_map(|entry| {
            let reg = entry.registration;
            let payee = tenzro_types::primitives::Address::from_hex(&reg.provider).ok()?;
            let price =
                crate::inference_pricing::charge_wei(node, &reg.pricing, &reference).ok()?;
            Some(Offer {
                model: reg.model_id,
                payee: payee.0,
                price,
            })
        })
        .collect()
}

fn encode(models: &[ModelPrices], out: &mut String) {
    let mut gauge = |name: &str, help: &str, value: &dyn Fn(&ModelPrices) -> u64| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
        for m in models {
            out.push_str(&format!("{name}{{model=\"{}\"}} {}\n", m.model, value(m)));
        }
        out.push('\n');
    };
    gauge(
        "tenzro_model_offer_payees",
        "Distinct payees with a live priced network offer for the model",
        &|m| m.payees as u64,
    );
    gauge(
        "tenzro_model_offer_price_spread_bps",
        "Highest offered price over the lowest, less one, in basis points",
        &|m| m.spread_bps,
    );
    gauge(
        "tenzro_model_offer_same_price_payees",
        "Largest group of distinct payees quoting one identical non-zero price for the model",
        &|m| m.same_price_payees as u64,
    );
}

/// The last summary text and when it was made.
#[derive(Default)]
struct SummaryCache(parking_lot::Mutex<Option<(std::time::Instant, String)>>);

impl SummaryCache {
    /// The cached text when it is younger than [`SUMMARY_TTL`] at `now`,
    /// else `make`'s, which is then kept.
    fn text(&self, now: std::time::Instant, make: impl FnOnce() -> String) -> String {
        let mut last = self.0.lock();
        match last.as_ref() {
            Some((at, text)) if now.saturating_duration_since(*at) < SUMMARY_TTL => text.clone(),
            _ => {
                let text = make();
                *last = Some((now, text.clone()));
                text
            }
        }
    }
}

/// The price picture of the node's live network offers in Prometheus text
/// format, computed at most once every [`SUMMARY_TTL`].
pub(crate) fn encode_prometheus(node: &TenzroNode, out: &mut String) {
    static CACHE: std::sync::OnceLock<SummaryCache> = std::sync::OnceLock::new();
    let text = CACHE
        .get_or_init(Default::default)
        .text(std::time::Instant::now(), || {
            let mut text = String::new();
            encode(&summarize(&live_offers(node)), &mut text);
            text
        });
    out.push_str(&text);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(model: &str, payee: u8, price: u128) -> Offer {
        Offer {
            model: model.to_string(),
            payee: [payee; 32],
            price,
        }
    }

    #[test]
    fn payees_on_one_price_are_counted_and_show_no_spread() {
        let got = summarize(&[
            offer("qwen3-4b", 1, 500),
            offer("qwen3-4b", 2, 500),
            offer("qwen3-4b", 3, 500),
        ]);
        assert_eq!(
            got,
            vec![ModelPrices {
                model: "qwen3-4b".into(),
                payees: 3,
                spread_bps: 0,
                same_price_payees: 3,
            }]
        );
    }

    #[test]
    fn the_spread_is_the_highest_price_over_the_lowest() {
        let got = summarize(&[
            offer("m", 1, 400),
            offer("m", 2, 500),
            offer("m", 3, 500),
            offer("m", 4, 1_000),
        ]);
        assert_eq!(got[0].payees, 4);
        assert_eq!(got[0].spread_bps, 15_000);
        assert_eq!(got[0].same_price_payees, 2);
    }

    #[test]
    fn one_payee_on_several_endpoints_is_one_voice_at_its_lowest_price() {
        let alone = summarize(&[offer("m", 1, 500), offer("m", 1, 500), offer("m", 1, 700)]);
        assert!(
            alone.is_empty(),
            "one payee is nothing to compare: {alone:?}"
        );

        let got = summarize(&[offer("m", 1, 700), offer("m", 1, 500), offer("m", 2, 500)]);
        assert_eq!(got[0].payees, 2);
        assert_eq!(got[0].spread_bps, 0);
        assert_eq!(got[0].same_price_payees, 2);
    }

    #[test]
    fn the_offers_are_priced_at_most_once_per_period_however_often_they_are_read() {
        let cache = SummaryCache::default();
        let made = std::cell::Cell::new(0);
        let make = || {
            made.set(made.get() + 1);
            format!("summary {}", made.get())
        };
        let t0 = std::time::Instant::now();
        assert_eq!(cache.text(t0, make), "summary 1");
        for secs in [0, 1, 29] {
            let at = t0 + std::time::Duration::from_secs(secs);
            assert_eq!(cache.text(at, make), "summary 1", "{secs} s later");
        }
        assert_eq!(made.get(), 1);
        assert_eq!(cache.text(t0 + SUMMARY_TTL, make), "summary 2");
        assert_eq!(made.get(), 2);
    }

    /// Payees that all offer a model free are not agreeing on a price: no
    /// group forms, so the convergence alert does not trip on them.
    #[test]
    fn free_offers_form_no_price_group() {
        let free = summarize(&[offer("m", 1, 0), offer("m", 2, 0), offer("m", 3, 0)]);
        assert_eq!(free[0].payees, 3);
        assert_eq!(free[0].same_price_payees, 0);
        let mixed = summarize(&[
            offer("m", 1, 0),
            offer("m", 2, 0),
            offer("m", 3, 500),
            offer("m", 4, 500),
        ]);
        assert_eq!(
            mixed[0].same_price_payees, 2,
            "the paid pair, not the free pair"
        );
    }

    #[test]
    fn free_and_very_large_prices_do_not_overflow() {
        let free = summarize(&[offer("m", 1, 0), offer("m", 2, 0)]);
        assert_eq!(free[0].spread_bps, 0);
        let mixed = summarize(&[offer("m", 1, 0), offer("m", 2, 5)]);
        assert_eq!(mixed[0].spread_bps, u64::MAX);
        let large = summarize(&[offer("m", 1, u128::MAX / 2), offer("m", 2, u128::MAX)]);
        assert_eq!(large[0].spread_bps, 10_000);
    }

    #[test]
    fn a_model_id_that_is_not_a_plain_label_is_left_out() {
        let got = summarize(&[
            offer("ok/model-1.5:q4", 1, 5),
            offer("ok/model-1.5:q4", 2, 5),
            offer("bad\"} 1\nfake_metric{x=\"", 1, 5),
            offer("bad\"} 1\nfake_metric{x=\"", 2, 5),
            offer("", 1, 5),
            offer("", 2, 5),
        ]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].model, "ok/model-1.5:q4");
    }

    #[test]
    fn the_models_with_the_most_payees_are_kept() {
        let mut offers = Vec::new();
        for m in 0..(MAX_MODELS + 10) {
            let model = format!("m{m:03}");
            offers.push(offer(&model, 1, 5));
            offers.push(offer(&model, 2, 5));
        }
        offers.push(offer("m070", 3, 5));
        let got = summarize(&offers);
        assert_eq!(got.len(), MAX_MODELS);
        assert_eq!((got[0].model.as_str(), got[0].payees), ("m070", 3));
        assert_eq!(got[1].model, "m000");
    }

    #[test]
    fn the_summary_is_served_as_three_gauges() {
        let mut out = String::new();
        encode(
            &summarize(&[offer("m", 1, 400), offer("m", 2, 500)]),
            &mut out,
        );
        for line in [
            "# TYPE tenzro_model_offer_payees gauge",
            "tenzro_model_offer_payees{model=\"m\"} 2",
            "# TYPE tenzro_model_offer_price_spread_bps gauge",
            "tenzro_model_offer_price_spread_bps{model=\"m\"} 2500",
            "# TYPE tenzro_model_offer_same_price_payees gauge",
            "tenzro_model_offer_same_price_payees{model=\"m\"} 1",
        ] {
            assert!(out.lines().any(|l| l == line), "missing {line} in\n{out}");
        }
    }
}
