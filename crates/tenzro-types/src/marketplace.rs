//! Shared marketplace commission constants and math.
//!
//! The Tenzro Network runs three peer marketplaces — agent templates,
//! skills, and tools — and they all use the same commission split:
//! the marketplace commission goes to the treasury, the remainder to the
//! creator's wallet. The constant and the split function live here so
//! the three marketplaces can't accidentally drift to different rates,
//! and so external crates (CLI, SDK, agent-kit) can reason about the
//! split without pulling in a specific marketplace's domain type.
//!
//! See `crates/tenzro-node/src/commission_policy.rs` for the
//! settlement path (the *moving* of tokens), and the three
//! marketplace modules (`agent_template`, `skill`, `tool`) for the
//! per-marketplace pricing structs that feed this split.

/// Splits `fee` into `(network_commission, creator_share)` using
/// `commission_bps`. Uses saturating arithmetic. `commission_bps` is
/// capped at 10_000 (100%) so a misconfigured value cannot inadvertently
/// produce a negative creator share via integer wraparound.
pub fn split_marketplace_fee(fee: u128, commission_bps: u16) -> (u128, u128) {
    let bps = (commission_bps as u128).min(10_000);
    let commission = fee.saturating_mul(bps) / 10_000u128;
    let creator_share = fee.saturating_sub(commission);
    (commission, creator_share)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_5_percent_of_one_tnzo() {
        let one_tnzo: u128 = 1_000_000_000_000_000_000;
        let (commission, creator) = split_marketplace_fee(one_tnzo, 500);
        assert_eq!(commission, 50_000_000_000_000_000); // 0.05 TNZO
        assert_eq!(creator, 950_000_000_000_000_000); // 0.95 TNZO
        assert_eq!(commission + creator, one_tnzo);
    }

    #[test]
    fn split_zero_fee_yields_zero() {
        let (c, k) = split_marketplace_fee(0, 500);
        assert_eq!(c, 0);
        assert_eq!(k, 0);
    }

    #[test]
    fn split_caps_bps_at_10_000() {
        let (c, k) = split_marketplace_fee(1_000, 20_000);
        assert_eq!(c, 1_000);
        assert_eq!(k, 0);
    }
}
