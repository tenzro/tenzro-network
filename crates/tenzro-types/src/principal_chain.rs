//! Principal-chain receipts (Agent-Swarm Spec 5).
//!
//! Every settlement, payment, and lifecycle receipt grows a typed
//! `principal_chain` field that, at write time, captures the full delegation
//! path from the acting identity up to the controller, plus the controller's
//! KYC tier and bond status.
//!
//! The chain is **frozen at receipt write time** — later revocations of
//! intermediate links do not invalidate the receipt's chain. Regulators and
//! insurers query the receipt directly to identify the responsible legal
//! entity, without recursive identity-registry walks.
//!
//! See `docs/architecture/agent-swarm/principal-chain-receipts.md` for the
//! full design.

use crate::identity::IdentityType;
use crate::primitives::{Address, BlockHeight, Hash};
use serde::{Deserialize, Serialize};

/// Maximum delegation depth permitted in a chain.
///
/// Enforced at delegation creation time (not at receipt write). Receipts
/// assume valid delegation chains and don't need to defend against deeply
/// nested loops. Governance-tunable.
pub const MAX_DELEGATION_DEPTH: u8 = 16;

/// Role a link plays inside a principal chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    /// The controller — top of the chain. The legally responsible principal.
    Controller,
    /// A delegated agent acting under a higher link's delegation scope.
    DelegatedAgent,
    /// An autonomous agent with no controlling principal (machine-only).
    AutonomousAgent,
}

/// One link in a principal chain.
///
/// Ordered top-down: `chain[0]` is the controller, `chain[n-1]` is the
/// `actor`'s direct delegator. The `actor` is recorded outside the chain
/// (in `PrincipalChain.actor`) and is not duplicated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalLink {
    /// DID string of the link.
    pub did: String,
    /// Whether this link is a Human or Machine identity.
    pub identity_type: IdentityType,
    /// Hash of the `DelegationScope` under which this link acted.
    /// `None` for the controller (no parent scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_scope_id: Option<Hash>,
    /// Role of this link in the chain.
    pub role: PrincipalRole,
    /// `true` when the link's identity could not be resolved at receipt
    /// write time (revoked, not-found, etc.). Receipts are still written
    /// — the regulator sees a partially-resolvable chain with an explicit
    /// gap. Defaults to `false` when omitted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tombstone: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !b
}

impl PrincipalLink {
    /// Construct a new (non-tombstoned) link.
    pub fn new(
        did: impl Into<String>,
        identity_type: IdentityType,
        delegation_scope_id: Option<Hash>,
        role: PrincipalRole,
    ) -> Self {
        Self {
            did: did.into(),
            identity_type,
            delegation_scope_id,
            role,
            tombstone: false,
        }
    }

    /// Construct a tombstoned link for an unresolvable DID.
    pub fn tombstoned(did: impl Into<String>, role: PrincipalRole) -> Self {
        Self {
            did: did.into(),
            identity_type: IdentityType::Machine,
            delegation_scope_id: None,
            role,
            tombstone: true,
        }
    }
}

/// Frozen principal chain attached to a receipt.
///
/// Captures the delegation path from `actor` (signer/acting identity) up to
/// `controller` (the legally responsible principal), with KYC tier and bond
/// snapshotted at receipt write time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalChain {
    /// DID of the identity that signed/acted.
    pub actor: String,
    /// Chain ordered top-down. Empty when the controller acted directly
    /// (`delegation_depth == 0`).
    pub chain: Vec<PrincipalLink>,
    /// Top of the chain. Equals `chain[0]` if `chain` is non-empty;
    /// otherwise refers to the actor itself (controller acted directly).
    pub controller: PrincipalLink,
    /// KYC tier of the controller, snapshotted at write time.
    /// 0 = Unverified, 1 = Basic, 2 = Enhanced, 3 = Full.
    pub controller_kyc_tier: u8,
    /// Bond posted by the controller, snapshotted at write time, in TNZO
    /// smallest unit. `None` if no bond is posted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_bond: Option<u128>,
    /// Bond posted directly against the **actor** (Spec 9). For autonomous
    /// machines this is the bond that earned them admission to the
    /// Delegated lane; for delegated agents it's a per-agent bond on top
    /// of the controller's aggregate. `None` when no bond is posted on
    /// the actor's DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_bond: Option<u128>,
    /// Sum of all promotion-eligible Active bonds posted by the
    /// controller across every agent they own (Spec 9). This is the
    /// figure regulators and insurers care about — total skin-in-the-
    /// game for the responsible principal. `None` when no resolver was
    /// wired or when the actor acted as its own controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_bond_aggregate: Option<u128>,
    /// Number of delegation levels between actor and controller. `0` when
    /// the controller acted directly.
    pub delegation_depth: u8,
    /// Block height at which the chain was resolved and frozen.
    pub frozen_at_block: BlockHeight,
}

impl PrincipalChain {
    /// Construct a chain for a controller that acted directly. `actor` is
    /// the controller; the chain itself is empty.
    pub fn direct(
        actor_did: impl Into<String>,
        identity_type: IdentityType,
        kyc_tier: u8,
        bond: Option<u128>,
        block: impl Into<BlockHeight>,
    ) -> Self {
        let did = actor_did.into();
        let role = match identity_type {
            IdentityType::Human => PrincipalRole::Controller,
            IdentityType::Machine => PrincipalRole::AutonomousAgent,
        };
        let controller = PrincipalLink::new(did.clone(), identity_type, None, role);
        Self {
            actor: did,
            chain: Vec::new(),
            controller,
            controller_kyc_tier: kyc_tier,
            controller_bond: bond,
            actor_bond: None,
            controller_bond_aggregate: None,
            delegation_depth: 0,
            frozen_at_block: block.into(),
        }
    }

    /// Construct a chain from an explicit ordered link list. Panics in debug
    /// builds if the chain is empty (callers should use `direct` for that
    /// case) or longer than `MAX_DELEGATION_DEPTH`.
    pub fn from_chain(
        actor_did: impl Into<String>,
        chain: Vec<PrincipalLink>,
        kyc_tier: u8,
        bond: Option<u128>,
        block: impl Into<BlockHeight>,
    ) -> Self {
        debug_assert!(!chain.is_empty(), "use PrincipalChain::direct for empty chain");
        debug_assert!(
            chain.len() <= MAX_DELEGATION_DEPTH as usize,
            "chain exceeds MAX_DELEGATION_DEPTH"
        );
        let controller = chain[0].clone();
        let depth = chain.len() as u8;
        Self {
            actor: actor_did.into(),
            chain,
            controller,
            controller_kyc_tier: kyc_tier,
            controller_bond: bond,
            actor_bond: None,
            controller_bond_aggregate: None,
            delegation_depth: depth,
            frozen_at_block: block.into(),
        }
    }

    /// Builder-style setter for the actor bond (Spec 9). Returns `self` so
    /// resolvers can chain `.with_actor_bond(...)` after `direct`/`from_chain`.
    pub fn with_actor_bond(mut self, bond: Option<u128>) -> Self {
        self.actor_bond = bond;
        self
    }

    /// Builder-style setter for the controller's aggregate bond across all
    /// agents (Spec 9). Returns `self` so resolvers can chain.
    pub fn with_controller_bond_aggregate(mut self, aggregate: Option<u128>) -> Self {
        self.controller_bond_aggregate = aggregate;
        self
    }

    /// Returns the controller DID.
    pub fn controller_did(&self) -> &str {
        &self.controller.did
    }

    /// Returns `true` when any link in the chain is tombstoned, including
    /// the synthetic `controller` link held outside `chain` (used for the
    /// unresolvable-DID case where the chain itself is empty).
    pub fn has_tombstone(&self) -> bool {
        self.controller.tombstone || self.chain.iter().any(|l| l.tombstone)
    }

    /// Compact summary used by list-style RPCs.
    pub fn summary(&self) -> PrincipalChainSummary {
        PrincipalChainSummary {
            actor: self.actor.clone(),
            controller: self.controller.did.clone(),
            controller_kyc_tier: self.controller_kyc_tier,
            controller_bond: self.controller_bond,
            actor_bond: self.actor_bond,
            controller_bond_aggregate: self.controller_bond_aggregate,
            delegation_depth: self.delegation_depth,
            has_tombstone: self.has_tombstone(),
            frozen_at_block: self.frozen_at_block,
        }
    }
}

/// Compact form returned by paginated receipt-listing RPCs. Inlines just
/// enough for a regulator/insurer to triage; full chain available via
/// `tenzro_getReceiptPrincipalChain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalChainSummary {
    pub actor: String,
    pub controller: String,
    pub controller_kyc_tier: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_bond: Option<u128>,
    /// Bond posted on the actor's DID (Spec 9). `None` when no bond is
    /// posted on the actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_bond: Option<u128>,
    /// Sum of promotion-eligible Active bonds the controller has posted
    /// across every agent they own (Spec 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_bond_aggregate: Option<u128>,
    pub delegation_depth: u8,
    pub has_tombstone: bool,
    pub frozen_at_block: BlockHeight,
}

/// Aggregate over a controller's activity across a window. Returned by
/// `tenzro_summarizeController`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerActivitySummary {
    pub controller_did: String,
    pub receipt_count: u64,
    /// Total settled value across the window, in TNZO smallest unit.
    pub total_value_tnzo: u128,
    /// Distinct DIDs that acted under the controller during the window.
    pub agents_acted_under: Vec<String>,
    pub kill_switch_events: u32,
    pub kyc_tier_at_oldest: u8,
    pub kyc_tier_at_newest: u8,
    pub bond_min: u128,
    pub bond_max: u128,
    /// Inclusive lower bound of the window (unix seconds). `None` if
    /// open-ended at the oldest end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// Inclusive upper bound of the window (unix seconds). `None` if
    /// open-ended at the newest end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Lookup hook for bond data on actors and controllers (Spec 9).
///
/// Implemented by `tenzro_token::bond::BondManager` (the live path that
/// reads `AgentBondState` records and aggregates by controller) and by
/// test fakes. The principal-chain resolver consults this trait at receipt
/// write time to populate `PrincipalChain::actor_bond` and
/// `PrincipalChain::controller_bond_aggregate` without depending on the
/// token crate directly (avoids the `tenzro-identity` → `tenzro-token`
/// → `tenzro-node` cycle).
///
/// All methods are infallible from the resolver's perspective: an
/// unbonded DID returns `None`, never an `Err`.
pub trait BondLookup: Send + Sync {
    /// Bond posted directly against `did`. `None` when no bond exists or
    /// the bond is in a non-promotion-eligible state (e.g., Slashed,
    /// Returned). Returns the bond `amount` in TNZO smallest unit.
    fn actor_bond(&self, did: &str) -> Option<u128>;

    /// Sum of promotion-eligible Active bonds the controller has posted
    /// across every agent they own. Returns `None` when no bonds exist.
    fn controller_aggregate(&self, controller_did: &str) -> Option<u128>;
}

/// Resolver that materializes a `PrincipalChain` for a given actor.
///
/// Implemented by `tenzro_identity::IdentityRegistry` (the live path that
/// walks delegation chains and snapshots KYC tier + bond) and by test
/// fakes. Receipt-write paths (settlement engine, escrow manager, payment
/// binder, kill-switch dispatch) take a `dyn PrincipalChainResolver` so
/// they can compute the chain inline without depending on the identity
/// crate directly.
///
/// All methods are infallible from the resolver's perspective: an
/// unresolvable DID returns a synthetic chain rooted at the actor with
/// tier 0 and a tombstoned chain entry, never an `Err`. This matches the
/// "tombstone unresolved" governance default — receipt writes never fail
/// because identity is unavailable.
pub trait PrincipalChainResolver: Send + Sync {
    /// Resolve the principal chain for the actor identified by `did`.
    ///
    /// `frozen_at_block` is stamped into the returned chain's
    /// `frozen_at_block` field so the caller does not need to mutate the
    /// resolver's output.
    fn resolve_by_did(&self, did: &str, frozen_at_block: BlockHeight) -> PrincipalChain;

    /// Resolve by wallet address. Implementations look up the address →
    /// DID binding (via `WalletBinder`) and delegate to `resolve_by_did`.
    /// When no DID is bound to the address, return a synthetic
    /// "anonymous" chain rooted at a tombstoned link with the address
    /// hex-encoded as the DID.
    fn resolve_by_address(
        &self,
        address: &Address,
        frozen_at_block: BlockHeight,
    ) -> PrincipalChain;
}

/// Synthetic-DID prefix used by the default resolver when an address has
/// no bound identity. Allows downstream tools to detect anonymous actors
/// without ambiguity against real `did:tenzro:` strings.
pub const ANONYMOUS_DID_PREFIX: &str = "did:tenzro:anonymous:";

/// Build a synthetic anonymous chain for an unbound address. Used by
/// resolvers when the binder returns no DID and by tests.
pub fn anonymous_chain_for_address(
    address: &Address,
    frozen_at_block: impl Into<BlockHeight>,
) -> PrincipalChain {
    let did = format!("{}{}", ANONYMOUS_DID_PREFIX, hex::encode(address.as_bytes()));
    let mut pc = PrincipalChain::direct(
        did,
        IdentityType::Machine,
        0,
        None,
        frozen_at_block,
    );
    pc.controller.tombstone = true;
    pc
}

/// Build a synthetic anonymous chain rooted at a given DID string. Used
/// by callers that have a DID but cannot resolve it (no live registry, or
/// unbound credential) — e.g., the payment binder when no resolver has
/// been wired. The resulting chain is tombstoned so downstream consumers
/// can detect the unresolved state.
pub fn anonymous_chain_for_did(
    did: impl Into<String>,
    frozen_at_block: impl Into<BlockHeight>,
) -> PrincipalChain {
    let mut pc = PrincipalChain::direct(
        did,
        IdentityType::Machine,
        0,
        None,
        frozen_at_block,
    );
    pc.controller.tombstone = true;
    pc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_controller_action_yields_empty_chain() {
        let pc = PrincipalChain::direct(
            "did:tenzro:human:alice:uuid",
            IdentityType::Human,
            2,
            Some(10_000_000_000_000_000_000_000u128),
            184_523,
        );
        assert_eq!(pc.delegation_depth, 0);
        assert!(pc.chain.is_empty());
        assert_eq!(pc.actor, pc.controller.did);
        assert_eq!(pc.controller.role, PrincipalRole::Controller);
    }

    #[test]
    fn machine_direct_action_uses_autonomous_role() {
        let pc = PrincipalChain::direct(
            "did:tenzro:machine:bot:uuid",
            IdentityType::Machine,
            0,
            None,
            10,
        );
        assert_eq!(pc.controller.role, PrincipalRole::AutonomousAgent);
    }

    #[test]
    fn nested_chain_records_full_path() {
        let chain = vec![
            PrincipalLink::new(
                "did:tenzro:human:alice:uuid",
                IdentityType::Human,
                None,
                PrincipalRole::Controller,
            ),
            PrincipalLink::new(
                "did:tenzro:machine:alicebot:uuid",
                IdentityType::Machine,
                Some(Hash::zero()),
                PrincipalRole::DelegatedAgent,
            ),
        ];
        let pc = PrincipalChain::from_chain(
            "did:tenzro:machine:bot42:uuid",
            chain,
            2,
            Some(1_000_000_000),
            42,
        );
        assert_eq!(pc.delegation_depth, 2);
        assert_eq!(pc.controller_did(), "did:tenzro:human:alice:uuid");
        assert!(!pc.has_tombstone());
    }

    #[test]
    fn tombstoned_link_is_detected() {
        let chain = vec![
            PrincipalLink::new(
                "did:tenzro:human:alice:uuid",
                IdentityType::Human,
                None,
                PrincipalRole::Controller,
            ),
            PrincipalLink::tombstoned(
                "did:tenzro:machine:revoked:uuid",
                PrincipalRole::DelegatedAgent,
            ),
        ];
        let pc = PrincipalChain::from_chain(
            "did:tenzro:machine:actor:uuid",
            chain,
            2,
            None,
            1,
        );
        assert!(pc.has_tombstone());
    }

    #[test]
    fn summary_round_trip() {
        let pc = PrincipalChain::direct(
            "did:tenzro:human:alice:uuid",
            IdentityType::Human,
            3,
            Some(50),
            5,
        );
        let s = pc.summary();
        assert_eq!(s.controller, pc.controller_did());
        assert_eq!(s.delegation_depth, 0);
        assert_eq!(s.controller_kyc_tier, 3);
    }

    #[test]
    fn spec9_bond_fields_default_to_none() {
        let pc = PrincipalChain::direct(
            "did:tenzro:human:alice:uuid",
            IdentityType::Human,
            2,
            None,
            10,
        );
        assert!(pc.actor_bond.is_none());
        assert!(pc.controller_bond_aggregate.is_none());
    }

    #[test]
    fn spec9_bond_fields_settable_via_builder() {
        let pc = PrincipalChain::direct(
            "did:tenzro:machine:bot:uuid",
            IdentityType::Machine,
            0,
            None,
            100,
        )
        .with_actor_bond(Some(5_000_000_000_000_000_000u128))
        .with_controller_bond_aggregate(Some(25_000_000_000_000_000_000u128));
        assert_eq!(pc.actor_bond, Some(5_000_000_000_000_000_000u128));
        assert_eq!(
            pc.controller_bond_aggregate,
            Some(25_000_000_000_000_000_000u128)
        );
        let s = pc.summary();
        assert_eq!(s.actor_bond, pc.actor_bond);
        assert_eq!(s.controller_bond_aggregate, pc.controller_bond_aggregate);
    }

}
