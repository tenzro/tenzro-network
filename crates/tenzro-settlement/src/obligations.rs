//! Cross-service coverage accounting for a provider's single stake.
//!
//! A node stakes once and may serve many roles at once — validating consensus
//! while also renting out capacity and hosting storage. Each serving obligation
//! exposes the provider for one settlement epoch of value: if the provider
//! misses an epoch, the counterparty is made whole from that one stake
//! (TOKENOMICS §9). The rental manager and the storage meter each enforce
//! coverage for *their own* obligations, but neither sees the other — so a
//! provider could be admitted for rentals that consume its whole stake and then
//! separately admitted for storage deals against the same stake, double-booking
//! the collateral.
//!
//! [`ProviderObligations`] is the shared ledger that closes that gap. Every
//! service that streams against provider stake registers its per-epoch exposure
//! here keyed by an [`ObligationSource`]; admission for a *new* obligation
//! checks the new exposure against the provider's stake **net of everything
//! already registered across all sources**. The tracker owns no funds and no
//! slashing policy — it is purely an additive view of "how much of this
//! provider's stake is currently spoken for."
//!
//! # Why a separate ledger rather than threading one manager into the other
//!
//! Rentals live in [`crate::rental`] and storage deals live in the
//! `tenzro-storage-market` crate, which depends on this one. Putting the shared
//! view here lets both consult a common [`Arc<ProviderObligations>`] without the
//! settlement crate having to know about storage, or the two managers having to
//! reference each other. Each manager remains the source of truth for its own
//! deals; the tracker only mirrors the aggregate exposure.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_types::primitives::Address;

/// Which service a registered exposure belongs to. Keeping sources distinct
/// lets a service replace its own contribution wholesale (`set`) without
/// disturbing another service's accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObligationSource {
    /// Capacity rental (`tenzro_settlement::rental`).
    Rental,
    /// Decentralized storage deals (`tenzro-storage-market`).
    Storage,
}

/// Shared, additive view of the per-epoch exposure a provider's stake is
/// collateralizing across every service. Cheap to clone behind an `Arc`.
#[derive(Debug, Default)]
pub struct ProviderObligations {
    /// `(provider, source) -> summed per-epoch exposure for that source`.
    exposure: DashMap<(Address, ObligationSource), u128>,
}

impl ProviderObligations {
    /// Creates an empty tracker.
    pub fn new() -> Self {
        Self {
            exposure: DashMap::new(),
        }
    }

    /// Replaces the registered per-epoch exposure for one `(provider, source)`
    /// with `amount`. Services that already maintain an authoritative sum of
    /// their own active deals call this after each change so the tracker mirrors
    /// the latest total without accumulating drift. A zero amount clears the
    /// entry.
    pub fn set(&self, provider: &Address, source: ObligationSource, amount: u128) {
        if amount == 0 {
            self.exposure.remove(&(*provider, source));
        } else {
            self.exposure.insert((*provider, source), amount);
        }
    }

    /// Per-epoch exposure currently registered for one source.
    pub fn exposure_for(&self, provider: &Address, source: ObligationSource) -> u128 {
        self.exposure
            .get(&(*provider, source))
            .map(|e| *e.value())
            .unwrap_or(0)
    }

    /// Total per-epoch exposure across every source for this provider — the
    /// full at-risk window its stake must cover.
    pub fn total_exposure(&self, provider: &Address) -> u128 {
        self.exposure
            .iter()
            .filter(|e| e.key().0 == *provider)
            .fold(0u128, |acc, e| acc.saturating_add(*e.value()))
    }

    /// Total exposure across all sources *except* `source` — what `source`'s
    /// own admission must leave room for under the provider's stake.
    pub fn exposure_excluding(&self, provider: &Address, source: ObligationSource) -> u128 {
        self.exposure
            .iter()
            .filter(|e| e.key().0 == *provider && e.key().1 != source)
            .fold(0u128, |acc, e| acc.saturating_add(*e.value()))
    }

    /// Decides whether `provider` can take on `added_exposure` more per-epoch
    /// exposure under `source`, given its `available_stake`.
    ///
    /// `new_source_total` is what `source`'s own exposure will become if the new
    /// obligation is accepted (callers that track their own running total pass
    /// `current_source_total + added` here). Admission holds iff
    /// `available_stake ≥ new_source_total + exposure_from_other_sources`.
    pub fn can_admit(
        &self,
        provider: &Address,
        source: ObligationSource,
        new_source_total: u128,
        available_stake: u128,
    ) -> bool {
        let others = self.exposure_excluding(provider, source);
        let projected = new_source_total.saturating_add(others);
        available_stake >= projected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    #[test]
    fn set_and_total_sum_across_sources() {
        let o = ProviderObligations::new();
        let p = addr(1);
        o.set(&p, ObligationSource::Rental, 1_000);
        o.set(&p, ObligationSource::Storage, 400);
        assert_eq!(o.total_exposure(&p), 1_400);
        assert_eq!(o.exposure_for(&p, ObligationSource::Rental), 1_000);
        assert_eq!(o.exposure_for(&p, ObligationSource::Storage), 400);
    }

    #[test]
    fn set_zero_clears_entry() {
        let o = ProviderObligations::new();
        let p = addr(1);
        o.set(&p, ObligationSource::Rental, 1_000);
        o.set(&p, ObligationSource::Rental, 0);
        assert_eq!(o.total_exposure(&p), 0);
    }

    #[test]
    fn exposure_excluding_drops_named_source() {
        let o = ProviderObligations::new();
        let p = addr(1);
        o.set(&p, ObligationSource::Rental, 1_000);
        o.set(&p, ObligationSource::Storage, 400);
        assert_eq!(o.exposure_excluding(&p, ObligationSource::Storage), 1_000);
        assert_eq!(o.exposure_excluding(&p, ObligationSource::Rental), 400);
    }

    #[test]
    fn admission_accounts_for_other_sources() {
        let o = ProviderObligations::new();
        let p = addr(1);
        // Rental already consumes 1000 of a 1200 stake.
        o.set(&p, ObligationSource::Rental, 1_000);
        // Storage wants a 400-per-epoch deal: 1000 + 400 = 1400 > 1200 stake.
        assert!(!o.can_admit(&p, ObligationSource::Storage, 400, 1_200));
        // A 200 storage deal fits: 1000 + 200 = 1200 == stake.
        assert!(o.can_admit(&p, ObligationSource::Storage, 200, 1_200));
    }

    #[test]
    fn admission_replaces_own_source_not_doublecounts() {
        let o = ProviderObligations::new();
        let p = addr(1);
        // Storage source already has 200 registered; growing it to 500 with a
        // 1000 rental on the side: 500 + 1000 = 1500 needs >= 1500 stake.
        o.set(&p, ObligationSource::Storage, 200);
        o.set(&p, ObligationSource::Rental, 1_000);
        assert!(o.can_admit(&p, ObligationSource::Storage, 500, 1_500));
        assert!(!o.can_admit(&p, ObligationSource::Storage, 500, 1_400));
    }

    #[test]
    fn providers_are_independent() {
        let o = ProviderObligations::new();
        let p1 = addr(1);
        let p2 = addr(2);
        o.set(&p1, ObligationSource::Rental, 1_000);
        assert_eq!(o.total_exposure(&p2), 0);
        assert!(o.can_admit(&p2, ObligationSource::Storage, 900, 1_000));
    }
}
