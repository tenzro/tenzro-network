//! Driver that runs the per-issuer [`StableController`] on a schedule.
//!
//! For each registered stable-unit policy, one epoch:
//!   1. observe the unit's market price (Q18) and the crypto-buffer value,
//!   2. read the SecureMint floor to size the mint headroom
//!      (`reserve - circulating`) and the circulating-above-floor base,
//!   3. run the leaky-PI controller [`StableController::step`],
//!   4. apply the signed supply delta — mints go through
//!      [`SecureMintRegistry::check_and_mint`] (the hard floor gate), burns
//!      through [`SecureMintRegistry::record_burn`].
//!
//! The controller can only ever degrade capital efficiency; the SecureMint
//! invariant (`circulating + amount ≤ reserve`) is the hard backstop, so a
//! misbehaving controller can never authorize an unbacked unit.
//!
//! Price and buffer observations are injected via traits so the driver stays
//! free of a DEX / telemetry dependency and is deterministically testable.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tenzro_vm::secure_mint::SecureMintRegistry;
use tenzro_vm::stable_asset_registry::{StableAssetPolicy, StableAssetRegistry};
use tenzro_vm::stable_controller::{StableController, StableControllerOutput};

/// Observed market price of a stable unit, Q18 (1e18 = peg). The driver
/// expects this already EMA-smoothed upstream, matching the controller's
/// contract.
pub trait MarketPriceSource: Send + Sync {
    /// Latest smoothed price for the unit, or `None` if no observation is
    /// available this epoch (the driver then skips the unit).
    fn observe_price_q18(&self, unit_token: &[u8; 20], symbol: &str) -> Option<i128>;
}

/// Current crypto-buffer value for a unit, in the unit's smallest units.
pub trait BufferValueSource: Send + Sync {
    fn buffer_value(&self, unit_token: &[u8; 20]) -> u128;
}

/// One unit's epoch result, for telemetry / audit.
#[derive(Debug, Clone)]
pub struct DriverStep {
    pub symbol: String,
    pub unit_token: [u8; 20],
    pub output: StableControllerOutput,
    /// Supply delta actually applied after the SecureMint gate (may be less
    /// than `output.supply_delta` if the floor clamped a mint).
    pub applied_delta: i128,
}

/// Drives all registered stable units. Holds per-unit controller state
/// (the small leaky-integral accumulator) keyed by `(issuer, unit_token)`.
pub struct StableControllerDriver {
    stable_assets: Arc<StableAssetRegistry>,
    secure_mint: Arc<SecureMintRegistry>,
    price_source: Arc<dyn MarketPriceSource>,
    buffer_source: Arc<dyn BufferValueSource>,
    controllers: Mutex<HashMap<([u8; 32], [u8; 20]), StableController>>,
}

impl StableControllerDriver {
    pub fn new(
        stable_assets: Arc<StableAssetRegistry>,
        secure_mint: Arc<SecureMintRegistry>,
        price_source: Arc<dyn MarketPriceSource>,
        buffer_source: Arc<dyn BufferValueSource>,
    ) -> Self {
        Self {
            stable_assets,
            secure_mint,
            price_source,
            buffer_source,
            controllers: Mutex::new(HashMap::new()),
        }
    }

    /// Run one control epoch across every registered unit. `now_secs` is the
    /// unix-seconds clock used for the SecureMint attestation freshness gate.
    /// Returns one [`DriverStep`] per unit that was actuated this epoch
    /// (units with no price observation or no SecureMint policy are skipped).
    pub fn step_all(&self, now_secs: u64) -> Vec<DriverStep> {
        let mut steps = Vec::new();
        for policy in self.stable_assets.all() {
            if let Some(step) = self.step_one(&policy, now_secs) {
                steps.push(step);
            }
        }
        steps
    }

    fn step_one(&self, policy: &StableAssetPolicy, now_secs: u64) -> Option<DriverStep> {
        let unit = policy.unit_token;

        // The SecureMint policy holds the floor: reserve and circulating.
        let mint_policy = self.secure_mint.policy(&unit)?;
        let circulating_above_floor = mint_policy.circulating;
        let floor_headroom = mint_policy.reserve.saturating_sub(mint_policy.circulating);

        let market_price_q18 = self.price_source.observe_price_q18(&unit, &policy.symbol)?;
        let buffer_value = self.buffer_source.buffer_value(&unit);

        let key = (policy.issuer.0, unit);
        let mut controllers = self.controllers.lock();
        let controller = controllers.entry(key).or_insert_with(|| {
            // Config is validated at registration time; default on the
            // off-chance validation drifted so the driver can't panic.
            StableController::new(policy.controller.clone())
                .unwrap_or_else(|_| StableController::default())
        });

        let output = controller.step(
            market_price_q18,
            circulating_above_floor,
            buffer_value,
            floor_headroom,
        );
        drop(controllers);

        // Apply the supply delta. The controller already clamped a mint to
        // the floor headroom, but check_and_mint re-applies the hard gate
        // atomically against the latest circulating.
        let applied_delta = if output.supply_delta > 0 {
            let amount = output.supply_delta as u128;
            match self.secure_mint.check_and_mint(&unit, amount, now_secs) {
                Ok(_) => output.supply_delta,
                Err(_) => 0,
            }
        } else if output.supply_delta < 0 {
            let amount = output.supply_delta.unsigned_abs();
            // A contraction larger than circulating can't be applied; record
            // only what the bounded burn accepts (0 on rejection).
            match self.secure_mint.record_burn(&unit, amount) {
                Ok(_) => output.supply_delta,
                Err(_) => 0,
            }
        } else {
            0
        };

        Some(DriverStep {
            symbol: policy.symbol.clone(),
            unit_token: unit,
            output,
            applied_delta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Address;
    use tenzro_vm::secure_mint::SecureMintPolicy;
    use tenzro_vm::stable_asset_registry::{PaymentRail, ReserveSource};
    use tenzro_vm::stable_controller::{Q18, StableControllerConfig};

    struct FixedPrice(i128);
    impl MarketPriceSource for FixedPrice {
        fn observe_price_q18(&self, _unit: &[u8; 20], _symbol: &str) -> Option<i128> {
            Some(self.0)
        }
    }

    struct FixedBuffer(u128);
    impl BufferValueSource for FixedBuffer {
        fn buffer_value(&self, _unit: &[u8; 20]) -> u128 {
            self.0
        }
    }

    fn make_policy(unit: [u8; 20]) -> StableAssetPolicy {
        StableAssetPolicy {
            issuer: Address([7u8; 32]),
            unit_token: unit,
            symbol: "USDX".into(),
            reserve_source: ReserveSource::Custodial {
                attester_did: "did:tenzro:attester".into(),
                asset_caip19: "iso4217:USD".into(),
            },
            por_feed_id: "tenzro:did:tenzro:attester".into(),
            controller: StableControllerConfig::default(),
            allowed_rails: vec![PaymentRail::X402],
            settlement_dst: Address([3u8; 32]),
            created_at: 0,
        }
    }

    fn make_mint_policy(reserve: u128, circulating: u128) -> SecureMintPolicy {
        SecureMintPolicy {
            asset_id: "iso4217:USD".into(),
            reserve,
            circulating,
            por_feed_id: "tenzro:did:tenzro:attester".into(),
            attester_did: "did:tenzro:attester".into(),
            attestation_hash: Default::default(),
            attested_at: 0,
            ttl_secs: 0,
            heartbeat_secs: 0,
            mint_window_cap: 0,
            mint_window_secs: 0,
            window_minted: 0,
            window_started_at: 0,
            paused: false,
        }
    }

    fn setup(market: i128, reserve: u128, circulating: u128) -> (StableControllerDriver, [u8; 20]) {
        let unit = [9u8; 20];
        let stable = Arc::new(StableAssetRegistry::new());
        stable.register(make_policy(unit)).unwrap();
        let mint = Arc::new(SecureMintRegistry::new());
        mint.set_policy(unit, make_mint_policy(reserve, circulating));
        let driver = StableControllerDriver::new(
            stable,
            mint,
            Arc::new(FixedPrice(market)),
            Arc::new(FixedBuffer(circulating * 12 / 10)),
        );
        (driver, unit)
    }

    #[test]
    fn above_peg_mints_within_floor() {
        // 2% above peg → expand supply; reserve has room.
        let (driver, _unit) = setup(Q18 + Q18 * 2 / 100, 2_000_000, 1_000_000);
        let steps = driver.step_all(1_000);
        assert_eq!(steps.len(), 1);
        assert!(
            steps[0].applied_delta > 0,
            "expected mint, got {}",
            steps[0].applied_delta
        );
    }

    #[test]
    fn mint_clamped_when_floor_full() {
        // Reserve fully utilized → no headroom → mint gated to zero.
        let (driver, _unit) = setup(Q18 + Q18 * 2 / 100, 1_000_000, 1_000_000);
        let steps = driver.step_all(1_000);
        assert_eq!(steps[0].applied_delta, 0);
    }

    #[test]
    fn below_peg_burns() {
        let (driver, _unit) = setup(Q18 - Q18 * 2 / 100, 2_000_000, 1_000_000);
        let steps = driver.step_all(1_000);
        assert!(
            steps[0].applied_delta < 0,
            "expected burn, got {}",
            steps[0].applied_delta
        );
    }

    #[test]
    fn skips_unit_without_secure_mint_policy() {
        let unit = [9u8; 20];
        let stable = Arc::new(StableAssetRegistry::new());
        stable.register(make_policy(unit)).unwrap();
        let mint = Arc::new(SecureMintRegistry::new()); // no policy installed
        let driver = StableControllerDriver::new(
            stable,
            mint,
            Arc::new(FixedPrice(Q18 + Q18 * 2 / 100)),
            Arc::new(FixedBuffer(0)),
        );
        assert!(driver.step_all(1_000).is_empty());
    }
}
