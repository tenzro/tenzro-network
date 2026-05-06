//! Bridge from `tenzro_payments::EscrowResolver` to the on-chain escrow
//! catalog maintained by [`EscrowManager`].
//!
//! `tenzro-payments` and `tenzro-settlement` both live below `tenzro-node`
//! in the dependency graph; only `tenzro-node` can wire the two together
//! without inverting the layering. This adapter exposes
//! `Arc<EscrowManager>` to AP2's mandate validator as
//! `Arc<dyn tenzro_payments::EscrowResolver>` so the validator can enforce
//! the **fourth ceiling** — the on-chain escrow — alongside CheckoutMandate
//! caps, TDIP `DelegationScope`, and runtime `SpendingPolicy`.
//!
//! ## Identity binding
//!
//! `EscrowAccount` records `payer`/`payee` as on-chain `Address`es, not as
//! TDIP DIDs. The bridge does **not** attempt an address → DID reverse
//! lookup: there is no canonical index for it, and treating a partial
//! result as authoritative would weaken the ceiling. Instead, the adapter
//! emits `payer_did = None` / `payee_did = None`, which causes
//! [`EscrowSnapshot::check`] to skip the DID-equality checks while still
//! enforcing `releasable`, `amount`, and `escrow_id`. The DID-binding axis
//! is enforced upstream by AP2's `cnf` claim against the
//! [`IdentityRegistry`], which is the right place for it: the on-chain
//! escrow is the source of truth for funds, the mandate-pair `cnf` is the
//! source of truth for identities.
//!
//! `Ok(None)` is returned when no escrow exists at the given ID. AP2
//! treats that as a hard failure — a mandate explicitly bound to an
//! `escrow_id` that does not resolve must not settle.

use std::sync::Arc;

use tenzro_payments::{EscrowResolver, EscrowSnapshot, Result};
use tenzro_settlement::escrow::{EscrowManager, EscrowStatus};

/// `EscrowResolver` impl backed by [`EscrowManager`]'s on-chain catalog.
/// See module docs.
pub struct EscrowManagerResolver {
    manager: Arc<EscrowManager>,
}

impl EscrowManagerResolver {
    /// Wraps an existing [`EscrowManager`] handle.
    pub fn new(manager: Arc<EscrowManager>) -> Self {
        Self { manager }
    }
}

impl EscrowResolver for EscrowManagerResolver {
    fn resolve(&self, escrow_id: &str) -> Result<Option<EscrowSnapshot>> {
        // `EscrowManager::get_escrow` returns `Err(NotFound)` for misses
        // and `Ok(account)` for hits. Map the not-found case to `Ok(None)`
        // (AP2's contract for "no such escrow on-chain") and propagate any
        // other error as a resolver-internal failure.
        let account = match self.manager.get_escrow(escrow_id) {
            Ok(account) => account,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not found") || msg.contains("Not found") {
                    return Ok(None);
                }
                return Err(tenzro_payments::PaymentError::VerificationFailed(
                    format!("EscrowManager::get_escrow failed: {e}"),
                ));
            }
        };

        // `releasable` collapses the multi-state on-chain status into a
        // boolean: `Funded` and not expired = releasable; anything else
        // (`Released` / `Refunded` / `Expired`) is final.
        let releasable = account.status == EscrowStatus::Funded && !account.is_expired();

        Ok(Some(EscrowSnapshot {
            escrow_id: account.escrow_id,
            payer_did: None,
            payee_did: None,
            amount: account.amount,
            asset: account.asset_id.0.clone(),
            releasable,
        }))
    }
}
