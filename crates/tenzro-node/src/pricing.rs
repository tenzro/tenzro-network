//! Provider resource pricing policies.
//!
//! Every provider chooses, per resource (AI inference per-token, compute/GPU
//! per-epoch, storage byte-epoch), how its rate is set:
//!
//! - [`PricingPolicy::Fixed`] — a flat operator-set rate.
//! - [`PricingPolicy::Dynamic`] — a network-reactive rate driven by an
//!   EIP-1559 multiplicative controller over EMA-smoothed utilization.
//! - [`PricingPolicy::OrderBook`] — a uniform clearing price computed from the
//!   intersection of ascending asks and descending bids.
//!
//! All arithmetic is integer-only (rates are base token units / wei). The
//! dynamic controller follows the EIP-1559 base-fee adjustment, the same
//! formula Ethereum and Filecoin use, with the published stability defaults:
//! a max-change denominator `D` (inverse gain) and a 2x elasticity multiplier
//! around a 50%-of-capacity target. Utilization is EMA-smoothed before it
//! reaches the controller to damp oscillation.

use serde::{Deserialize, Serialize};

/// Max-change denominator (inverse gain) for AI inference: D=8 → ±12.5%/step.
/// Fast-settling, block-cadence resource — the Ethereum/Filecoin default.
pub const INFERENCE_D: u128 = 8;

/// Max-change denominator for storage: D=16 → ±6.25%/step. Slow epochs, so a
/// gentler gain damps oscillation across long settlement windows.
pub const STORAGE_D: u128 = 16;

/// EIP-1559 elasticity multiplier: hard capacity cap = 2x target. The steady
/// state sits at 50% utilization (target), where the rate delta is zero.
pub const ELASTICITY_MULTIPLIER: u128 = 2;

/// Default EMA smoothing window (epochs). Power of two so the divide is a
/// shift. Range 2..=10 per the design; 4 is a balanced default.
pub const DEFAULT_EMA_WINDOW: u128 = 4;

/// Which resource a policy meters. Selects the controller gain default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// AI inference, per token. Fast cadence → D=8.
    Inference,
    /// Compute/GPU rental, per epoch. Fast cadence → D=8.
    Compute,
    /// Storage, per byte-epoch. Slow cadence → D=16.
    Storage,
}

impl ResourceKind {
    /// The proven max-change denominator (inverse gain) for this resource.
    pub fn default_denominator(self) -> u128 {
        match self {
            ResourceKind::Inference | ResourceKind::Compute => INFERENCE_D,
            ResourceKind::Storage => STORAGE_D,
        }
    }
}

/// A bid or ask in an order-book clearing round: `units` at `price` (per unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    pub units: u128,
    pub price: u128,
}

/// How a provider sets the rate for one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PricingPolicy {
    /// Flat operator-set rate (the override default).
    Fixed { rate: u128 },
    /// Network-reactive EIP-1559 controller. Carries its own live state.
    Dynamic(DynamicPricing),
    /// Uniform-price clearing from an order book (computed per round).
    OrderBook { current_rate: u128 },
}

impl PricingPolicy {
    /// The rate a deal opened *now* pays. For dynamic policies this is the
    /// last stepped rate; the controller advances it once per epoch via
    /// [`DynamicPricing::step`].
    pub fn effective_rate(&self) -> u128 {
        match self {
            PricingPolicy::Fixed { rate } => *rate,
            PricingPolicy::Dynamic(d) => d.current_rate,
            PricingPolicy::OrderBook { current_rate } => *current_rate,
        }
    }
}

/// Live state for the EIP-1559 dynamic controller, one per provider-resource.
///
/// Each epoch the node feeds metered `used` capacity into [`step`]: the EMA is
/// updated, then the rate is nudged toward the target with a bounded
/// multiplicative delta.
///
/// [`step`]: DynamicPricing::step
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicPricing {
    /// Provider-advertised total capacity for this resource (per epoch).
    pub capacity: u128,
    /// Max-change denominator (inverse gain). Lower = faster, more volatile.
    pub denominator: u128,
    /// EMA smoothing window (epochs). Larger = smoother, slower.
    pub ema_window: u128,
    /// Operator floor — the rate never drops below this.
    pub min_rate: u128,
    /// Network ceiling — the rate never rises above this.
    pub max_rate: u128,
    /// Current rate (base units per resource unit).
    pub current_rate: u128,
    /// EMA-smoothed utilization carried between epochs.
    pub ema_utilization: u128,
}

impl DynamicPricing {
    /// Construct with proven defaults for `kind`, starting at `start_rate`.
    pub fn new(
        kind: ResourceKind,
        capacity: u128,
        start_rate: u128,
        min_rate: u128,
        max_rate: u128,
    ) -> Self {
        Self {
            capacity,
            denominator: kind.default_denominator(),
            ema_window: DEFAULT_EMA_WINDOW,
            min_rate,
            max_rate,
            current_rate: start_rate.clamp(min_rate, max_rate),
            // Seed the EMA at target so the first few epochs don't lurch.
            ema_utilization: capacity / ELASTICITY_MULTIPLIER,
        }
    }

    /// Target utilization: 50% of capacity. Steady state (delta = 0) sits here.
    pub fn target(&self) -> u128 {
        self.capacity / ELASTICITY_MULTIPLIER
    }

    /// Advance one epoch from the metered `used` capacity, returning the new
    /// rate. Updates the EMA first, then applies the bounded EIP-1559 delta to
    /// the EMA-smoothed utilization (never the raw last-epoch value).
    pub fn step(&mut self, used: u128) -> u128 {
        // EMA update: ema += (x - ema) / W, done in integer space without
        // going negative. Equivalent to ema + (x-ema)/W for either sign.
        let w = self.ema_window.max(1);
        if used >= self.ema_utilization {
            self.ema_utilization += (used - self.ema_utilization) / w;
        } else {
            self.ema_utilization -= (self.ema_utilization - used) / w;
        }

        let target = self.target();
        if target == 0 {
            // No advertised capacity → nothing to meter against; hold rate.
            return self.current_rate;
        }

        let smoothed = self.ema_utilization;
        let parent = self.current_rate;

        // delta = parent * |smoothed - target| / target / D
        // Multiply before dividing; floor-divide twice.
        let new_rate = if smoothed > target {
            let delta = (parent.saturating_mul(smoothed - target) / target / self.denominator)
                // On the over-target branch the rate must always be able to
                // rise off a floor, so force a minimum step of 1.
                .max(1);
            parent.saturating_add(delta)
        } else if smoothed < target {
            let delta = parent.saturating_mul(target - smoothed) / target / self.denominator;
            parent.saturating_sub(delta)
        } else {
            parent
        };

        self.current_rate = new_rate.clamp(self.min_rate, self.max_rate);
        self.current_rate
    }
}

/// Uniform clearing price for an order-book round.
///
/// Asks are sorted ascending into a supply curve and bids descending into a
/// demand curve. The clearing price is the lowest ask whose cumulative supply
/// meets the cumulative demand willing to pay at least that price — i.e. the
/// marginal ask that clears the market. All matched units transact at it.
/// Returns `None` when no ask can be covered by demand (no liquidity / no
/// crossing).
pub fn clearing_price(asks: &[Order], bids: &[Order]) -> Option<u128> {
    if asks.is_empty() || bids.is_empty() {
        return None;
    }

    let mut asks: Vec<Order> = asks.to_vec();
    asks.sort_by_key(|o| o.price);

    let mut bids: Vec<Order> = bids.to_vec();
    bids.sort_by_key(|o| std::cmp::Reverse(o.price));

    let mut cumulative_supply: u128 = 0;
    for ask in &asks {
        cumulative_supply = cumulative_supply.saturating_add(ask.units);
        // Demand willing to pay >= this ask's price.
        let demand_at_price: u128 = bids
            .iter()
            .filter(|b| b.price >= ask.price)
            .map(|b| b.units)
            .fold(0u128, |acc, u| acc.saturating_add(u));
        if demand_at_price >= cumulative_supply {
            return Some(ask.price);
        }
    }

    // Demand never fully absorbs supply at the top of the book; clear at the
    // highest ask that any bid still crosses, if any.
    asks.iter()
        .rev()
        .find(|ask| bids.iter().any(|b| b.price >= ask.price))
        .map(|ask| ask.price)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_rate_is_flat() {
        let p = PricingPolicy::Fixed { rate: 42 };
        assert_eq!(p.effective_rate(), 42);
    }

    #[test]
    fn at_target_rate_holds() {
        // used == target → delta 0 → rate unchanged.
        let mut d = DynamicPricing::new(ResourceKind::Inference, 1000, 1_000_000, 1, u128::MAX);
        // Seeded EMA == target; feed exactly target.
        let r = d.step(500);
        assert_eq!(r, 1_000_000);
    }

    #[test]
    fn over_target_raises_rate() {
        let mut d = DynamicPricing::new(ResourceKind::Inference, 1000, 1_000_000, 1, u128::MAX);
        // Drive utilization to capacity for several epochs; EMA climbs, rate rises.
        let mut last = d.current_rate;
        for _ in 0..20 {
            let r = d.step(1000);
            assert!(r >= last, "rate must be monotonic up under sustained demand");
            last = r;
        }
        assert!(last > 1_000_000);
    }

    #[test]
    fn under_target_lowers_rate_but_respects_floor() {
        let mut d = DynamicPricing::new(ResourceKind::Inference, 1000, 1_000_000, 900_000, u128::MAX);
        let mut last = d.current_rate;
        for _ in 0..50 {
            let r = d.step(0);
            assert!(r <= last);
            last = r;
        }
        assert_eq!(last, 900_000, "rate must not drop below the operator floor");
    }

    #[test]
    fn storage_gain_is_gentler_than_inference() {
        let mut inf = DynamicPricing::new(ResourceKind::Inference, 1000, 1_000_000, 1, u128::MAX);
        let mut sto = DynamicPricing::new(ResourceKind::Storage, 1000, 1_000_000, 1, u128::MAX);
        // One saturated epoch each, from the same seed.
        let ri = inf.step(1000);
        let rs = sto.step(1000);
        assert!(ri >= rs, "D=8 inference should move at least as fast as D=16 storage");
    }

    #[test]
    fn rate_respects_ceiling() {
        let mut d = DynamicPricing::new(ResourceKind::Inference, 1000, 1_000_000, 1, 1_100_000);
        for _ in 0..100 {
            d.step(1000);
        }
        assert_eq!(d.current_rate, 1_100_000, "rate must not exceed the ceiling");
    }

    #[test]
    fn clearing_price_uniform_match() {
        // Asks: 2@100, 3@120. Bids: 4@130, 1@90.
        // Supply after first ask = 2; demand at >=100 = 4 (the 130 bid) ≥ 2 → clears at 100.
        let asks = [Order { units: 2, price: 100 }, Order { units: 3, price: 120 }];
        let bids = [Order { units: 4, price: 130 }, Order { units: 1, price: 90 }];
        assert_eq!(clearing_price(&asks, &bids), Some(100));
    }

    #[test]
    fn clearing_price_no_cross_is_none() {
        let asks = [Order { units: 1, price: 200 }];
        let bids = [Order { units: 1, price: 100 }];
        assert_eq!(clearing_price(&asks, &bids), None);
    }

    #[test]
    fn clearing_price_empty_is_none() {
        assert_eq!(clearing_price(&[], &[Order { units: 1, price: 100 }]), None);
        assert_eq!(clearing_price(&[Order { units: 1, price: 100 }], &[]), None);
    }
}
