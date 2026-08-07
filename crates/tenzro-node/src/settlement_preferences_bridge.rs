//! Node-side resolver for payee settlement preferences.
//!
//! The only place in the workspace that depends on both the payments crate
//! (which owns the routing rule) and the node's storage (which holds what each
//! payee chose) — the same shape as
//! [`spending_policy_bridge`](crate::spending_policy_bridge).
//!
//! # Why a payee, not an address
//!
//! A settlement preference belongs to an identity. The same provider may be
//! paid at several addresses across several chains, and they meant one thing by
//! "I settle in TNZO" — not one thing per address.
//!
//! # Default is to keep what arrived
//!
//! A payee who has recorded nothing keeps the asset the payment came in. A
//! provider earning USDC generally wants spendable USDC: their costs are
//! denominated in dollars, and converting to TNZO would hand them an FX
//! position they did not ask for.

use std::sync::Arc;

use parking_lot::RwLock;
use tenzro_payments::gateway::SettlementPreferencesResolver;
use tenzro_payments::settlement_asset::{SettlementAsset, SettlementPreferences};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tracing::warn;

/// RocksDB key prefix for a payee's declared settlement asset.
const PREFIX: &[u8] = b"settlement_pref:";

/// Reads payee settlement preferences from the node's store.
pub struct NodeSettlementPreferences {
    storage: Arc<dyn KvStore>,
    /// Hydrated once and mutated on write, because the router asks on every
    /// settlement and a RocksDB scan per payment would put storage latency on
    /// the payment path.
    cache: RwLock<SettlementPreferences>,
}

impl NodeSettlementPreferences {
    /// Load every recorded preference from storage, over the network's
    /// governance-set default.
    ///
    /// `default_asset` comes from
    /// [`tenzro_types::economics::EconomicPolicy::default_conversion`]: a payee
    /// who has said nothing gets what the network takes by default, and
    /// changing that is a governance decision rather than a release.
    pub fn load(storage: Arc<dyn KvStore>, default_asset: SettlementAsset) -> Self {
        let mut prefs = SettlementPreferences::with_default(default_asset);
        match storage.scan_prefix(CF_SETTLEMENTS, PREFIX) {
            Ok(rows) => {
                for (key, value) in rows {
                    let Some(did) = key
                        .strip_prefix(PREFIX)
                        .and_then(|d| std::str::from_utf8(d).ok())
                    else {
                        continue;
                    };
                    // An unreadable row is skipped rather than defaulted:
                    // guessing a payee wants TNZO because their row was
                    // corrupt would hand them an asset they did not choose.
                    match std::str::from_utf8(&value) {
                        Ok("tnzo") => prefs.set(did, SettlementAsset::Tnzo),
                        Ok("keep_inbound") => prefs.set(did, SettlementAsset::KeepInbound),
                        other => warn!(
                            payee = did,
                            "skipping unrecognised settlement preference {other:?}"
                        ),
                    }
                }
            }
            Err(e) => warn!("could not read settlement preferences: {e}"),
        }

        Self {
            storage,
            cache: RwLock::new(prefs),
        }
    }

    /// Record a payee's choice, persisting it.
    pub fn set(&self, payee_did: &str, asset: SettlementAsset) -> Result<(), String> {
        let mut key = PREFIX.to_vec();
        key.extend_from_slice(payee_did.as_bytes());
        self.storage
            .put(CF_SETTLEMENTS, &key, asset.as_str().as_bytes())
            .map_err(|e| format!("persisting settlement preference: {e}"))?;
        self.cache.write().set(payee_did, asset);
        Ok(())
    }

    /// What this payee currently settles in.
    pub fn get(&self, payee_did: &str) -> SettlementAsset {
        self.cache.read().get(payee_did)
    }
}

impl SettlementPreferencesResolver for NodeSettlementPreferences {
    fn preferences(&self) -> SettlementPreferences {
        self.cache.read().clone()
    }
}

impl std::fmt::Debug for NodeSettlementPreferences {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSettlementPreferences").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn store() -> Arc<dyn KvStore> {
        Arc::new(MemoryStore::new())
    }

    /// A payee who has said nothing gets what the network takes by default,
    /// and that default is governance's — passed in here rather than assumed,
    /// so a node whose governance set the other answer honours it.
    #[test]
    fn an_unrecorded_payee_gets_the_network_default() {
        let prefs = NodeSettlementPreferences::load(store(), SettlementAsset::Tnzo);
        assert_eq!(
            prefs.get("did:tenzro:machine:never-configured"),
            SettlementAsset::Tnzo
        );

        let keep = NodeSettlementPreferences::load(store(), SettlementAsset::KeepInbound);
        assert_eq!(
            keep.get("did:tenzro:machine:never-configured"),
            SettlementAsset::KeepInbound
        );
    }

    #[test]
    fn a_recorded_preference_survives_a_restart() {
        let store = store();
        {
            let prefs = NodeSettlementPreferences::load(store.clone(), SettlementAsset::Tnzo);
            prefs
                .set("did:tenzro:machine:a", SettlementAsset::Tnzo)
                .unwrap();
            prefs
                .set("did:tenzro:machine:b", SettlementAsset::KeepInbound)
                .unwrap();
        }

        let restarted = NodeSettlementPreferences::load(store, SettlementAsset::Tnzo);
        assert_eq!(restarted.get("did:tenzro:machine:a"), SettlementAsset::Tnzo);
        assert_eq!(
            restarted.get("did:tenzro:machine:b"),
            SettlementAsset::KeepInbound
        );
    }

    #[test]
    fn a_preference_can_be_changed_back() {
        let prefs = NodeSettlementPreferences::load(store(), SettlementAsset::Tnzo);
        prefs
            .set("did:tenzro:machine:a", SettlementAsset::Tnzo)
            .unwrap();
        assert_eq!(prefs.get("did:tenzro:machine:a"), SettlementAsset::Tnzo);
        prefs
            .set("did:tenzro:machine:a", SettlementAsset::KeepInbound)
            .unwrap();
        assert_eq!(
            prefs.get("did:tenzro:machine:a"),
            SettlementAsset::KeepInbound
        );
    }

    /// Guessing that a payee wants TNZO because their row was corrupt would
    /// hand them an asset they did not choose. Skipping falls back to the
    /// default, which is what they had before the row existed.
    #[test]
    fn an_unreadable_row_falls_back_to_the_default_rather_than_guessing() {
        let store = store();
        let mut key = PREFIX.to_vec();
        key.extend_from_slice(b"did:tenzro:machine:corrupt");
        store.put(CF_SETTLEMENTS, &key, b"garbage").unwrap();

        let prefs = NodeSettlementPreferences::load(store, SettlementAsset::Tnzo);
        assert_eq!(
            prefs.get("did:tenzro:machine:corrupt"),
            SettlementAsset::Tnzo
        );
    }

    #[test]
    fn the_resolver_surfaces_every_recorded_payee() {
        let prefs = NodeSettlementPreferences::load(store(), SettlementAsset::Tnzo);
        prefs
            .set("did:tenzro:machine:a", SettlementAsset::Tnzo)
            .unwrap();
        let snapshot = prefs.preferences();
        assert_eq!(snapshot.get("did:tenzro:machine:a"), SettlementAsset::Tnzo);
        assert_eq!(
            snapshot.get("did:tenzro:machine:unknown"),
            SettlementAsset::Tnzo
        );
    }
}
