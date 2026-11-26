//! Who stands behind a payer, recorded on its receipt.
//!
//! A receipt names the DID that paid. When that DID is a delegated agent the
//! party answerable for the payment is its controller, possibly several
//! delegations up. [`PrincipalChains`] resolves the whole path at the moment
//! the receipt is written, so the receipt carries it and stays true after the
//! delegation changes.

use std::sync::Arc;

use tenzro_identity::IdentityRegistry;
use tenzro_types::primitives::BlockHeight;
use tenzro_types::principal_chain::{PrincipalChain, anonymous_chain_for_did};

/// Resolves the delegation path of a payer for its receipt.
pub trait PrincipalChains: Send + Sync {
    /// The chain from `payer_did` up to its controller, as it stands now.
    fn chain_of(&self, payer_did: &str) -> PrincipalChain;
}

/// No identity registry to ask: every chain is the payer alone, marked
/// unresolved so a reader can tell it from a payer that acted for itself.
pub struct Unresolved;

impl PrincipalChains for Unresolved {
    fn chain_of(&self, payer_did: &str) -> PrincipalChain {
        anonymous_chain_for_did(payer_did, BlockHeight::new(0))
    }
}

/// Chains read from an identity registry, stamped with the chain height at
/// the time of the read.
pub struct RegistryChains {
    registry: Arc<IdentityRegistry>,
    height: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl RegistryChains {
    /// Chains from `registry`; `height` gives the current chain height.
    pub fn new(
        registry: Arc<IdentityRegistry>,
        height: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self { registry, height }
    }
}

impl PrincipalChains for RegistryChains {
    fn chain_of(&self, payer_did: &str) -> PrincipalChain {
        self.registry
            .resolve_principal_chain(payer_did, BlockHeight::new((self.height)()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tenzro_identity::{IdentityData, IdentityStatus, TenzroDid, TenzroIdentity};

    fn identity(did: &str, data: IdentityData) -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::parse(did).expect("DID"),
            public_keys: Vec::new(),
            identity_data: data,
            status: IdentityStatus::Active,
            wallet_address: tenzro_types::Address::new([1u8; 32]),
            wallet_id: String::new(),
            pq_verifying_key: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        }
    }

    pub(crate) fn human_did() -> String {
        format!("did:tenzro:human:{}", hex::encode([0x11u8; 32]))
    }

    pub(crate) fn agent_did() -> String {
        format!("did:tenzro:machine:{}", hex::encode([0x22u8; 32]))
    }

    /// A registry holding a human and a machine that human controls, read
    /// at height 4242.
    pub(crate) fn chains() -> Arc<dyn PrincipalChains> {
        let registry = Arc::new(IdentityRegistry::new());
        registry.upsert_identity_for_test(identity(
            &human_did(),
            IdentityData::Human {
                display_name: "Owner".into(),
                controlled_machines: vec![agent_did()],
            },
        ));
        registry.upsert_identity_for_test(identity(
            &agent_did(),
            IdentityData::Machine {
                capabilities: Vec::new(),
                controller_did: Some(human_did()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
        ));
        Arc::new(RegistryChains::new(registry, Arc::new(|| 4242)))
    }

    #[test]
    fn a_delegated_payers_chain_reaches_its_controller_at_the_current_height() {
        let chain = chains().chain_of(&agent_did());
        assert_eq!(chain.actor, agent_did());
        assert_eq!(chain.controller_did(), human_did());
        assert_eq!(chain.chain.len(), 2);
        assert_eq!(chain.frozen_at_block, BlockHeight::new(4242));
        assert!(!chain.has_tombstone());
    }

    #[test]
    fn a_payer_acting_for_itself_is_its_own_controller() {
        let chain = chains().chain_of(&human_did());
        assert_eq!(chain.controller_did(), human_did());
        assert!(chain.chain.is_empty());
        assert!(!chain.has_tombstone());
    }

    #[test]
    fn a_payer_the_registry_does_not_know_is_recorded_as_unresolved() {
        for did in ["did:tenzro:machine:unknown", ""] {
            let chain = chains().chain_of(did);
            assert_eq!(chain.actor, did);
            assert!(chain.has_tombstone(), "{did:?}");
            assert_eq!(chain.frozen_at_block, BlockHeight::new(4242));
        }
        let none = Unresolved.chain_of(&agent_did());
        assert!(none.has_tombstone());
        assert_eq!(none.controller_did(), agent_did());
    }
}
