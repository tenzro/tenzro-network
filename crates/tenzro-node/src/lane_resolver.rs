//! Node-side `LaneResolver` impl bridging `IdentityRegistry` + `StakingManager`
//! into the `tenzro-consensus` admission controller (Agent-Swarm Spec 2).
//!
//! `tenzro-consensus` cannot depend on `tenzro-identity` or `tenzro-token`
//! (would cycle through `tenzro-node`). The trait abstraction in
//! [`tenzro_consensus::admission::LaneResolver`] is the seam; this adapter
//! is the only place in the workspace where the consensus admission path,
//! the identity registry, and the staking manager all meet.
//!
//! # Lane assignment rules (Spec 2)
//!
//! Pure function of the transaction's signer + the registry state:
//!
//! 1. **Verified** — sender's controller (or self, if a directly-registered
//!    human) has KYC tier ≥ Enhanced AND ≥ `min_verified_stake` of bonded
//!    TNZO at the controller's wallet address.
//! 2. **Delegated** — sender is a Machine identity rooted (one or more
//!    levels deep) in a Verified controller, and the identity is `Active`.
//!    OR — when `bond_promotes_to_delegated` is enabled — the sender is a
//!    Machine with an Active `AgentBond` ≥ `bond_min_for_promotion` (Spec 9).
//!    The bond lookup is a single `DashMap::get` against the in-process
//!    `BondManager` cache; only `BondLifecycle::Active` bonds count, so a
//!    Cooldown / Frozen / Slashed bond is treated as no bond at all.
//! 3. **Open** — everyone else (anonymous, unknown DID, suspended/revoked
//!    identity, machine whose controller is suspended, machine outside
//!    delegation scope, faucet-funded testers).
//!
//! Any registry lookup failure (registry not wired, DID not found, etc.)
//! falls through to **Open** rather than rejecting — admission is still
//! rate-limited at the lowest tier, so we degrade gracefully without
//! locking out legitimate Open-lane traffic.
//!
//! # Bucket key
//!
//! Per Spec 2, the rate limit is per *controller*. For Verified/Delegated
//! lanes that means the controller DID's wallet address (so an attacker
//! cannot multiplex across spawned machines). For Open it's `tx.from` —
//! anonymous senders rate-limit themselves.

use std::sync::Arc;

use tenzro_consensus::admission::{Lane, LaneResolver};
use tenzro_identity::{IdentityData, IdentityRegistry, IdentityStatus};
use tenzro_token::bond::BondManager;
use tenzro_token::staking::StakingManager;
use tenzro_types::identity::KycTier;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::SignedTransaction;

/// Production `LaneResolver` consulted by the mempool admission controller.
pub struct NodeLaneResolver {
    identity_registry: Arc<IdentityRegistry>,
    staking_manager: Arc<StakingManager>,
    bond_manager: Arc<BondManager>,
    min_verified_stake: u128,
    bond_promotes_to_delegated: bool,
    bond_min_for_promotion: u128,
}

impl NodeLaneResolver {
    /// Construct a resolver from the live identity + staking + bond handles.
    /// `min_verified_stake`, `bond_promotes_to_delegated` and
    /// `bond_min_for_promotion` should be taken from `AdmissionConfig` so
    /// the resolver and bucket policy agree on thresholds.
    pub fn new(
        identity_registry: Arc<IdentityRegistry>,
        staking_manager: Arc<StakingManager>,
        bond_manager: Arc<BondManager>,
        min_verified_stake: u128,
        bond_promotes_to_delegated: bool,
        bond_min_for_promotion: u128,
    ) -> Self {
        Self {
            identity_registry,
            staking_manager,
            bond_manager,
            min_verified_stake,
            bond_promotes_to_delegated,
            bond_min_for_promotion,
        }
    }

    /// Resolve the controller wallet address for a given identity. For
    /// Human identities the controller is the identity itself. For Machine
    /// identities we walk `controller_did` upward; if any link is broken
    /// (DID not found, identity inactive) we treat the chain as broken and
    /// return `None`.
    fn resolve_controller_address(&self, did: &str) -> Option<(Address, KycTier)> {
        // Bound the chain length so a malformed registry can't loop us.
        const MAX_DEPTH: usize = 8;
        let mut current_did = did.to_string();
        for _ in 0..MAX_DEPTH {
            let identity = self.identity_registry.resolve(&current_did).ok()?;
            if identity.status != IdentityStatus::Active {
                return None;
            }
            match &identity.identity_data {
                IdentityData::Human { kyc_tier, .. } => {
                    return Some((identity.wallet_address, *kyc_tier));
                }
                IdentityData::Institution { kyb_tier, .. } => {
                    return Some((identity.wallet_address, *kyb_tier));
                }
                IdentityData::Machine { controller_did: Some(c), .. } => {
                    current_did = c.clone();
                }
                IdentityData::Machine { controller_did: None, .. } => {
                    // Autonomous machine — itself is the principal, but it
                    // has no human KYC. Treat as Open / Delegated only via
                    // bond promotion.
                    return None;
                }
            }
        }
        None
    }

    /// Total bonded stake at `address`, or 0 if no stake recorded.
    fn bonded_stake(&self, address: &Address) -> u128 {
        self.staking_manager
            .get_stake(address)
            .map(|info| info.amount)
            .unwrap_or(0)
    }
}

impl LaneResolver for NodeLaneResolver {
    fn assign_lane(&self, tx: &SignedTransaction) -> Lane {
        // Step 1: find the DID associated with the signer address. No DID
        // → Open lane (anonymous).
        let from = &tx.transaction.from;
        let did = match self.identity_registry.find_did_by_address(from) {
            Some(d) => d,
            None => return Lane::Open,
        };

        // Step 2: resolve the identity. Inactive → Open.
        let identity = match self.identity_registry.resolve(&did) {
            Ok(id) => id,
            Err(_) => return Lane::Open,
        };
        if identity.status != IdentityStatus::Active {
            return Lane::Open;
        }

        // Step 3: walk to the controlling human (or determine self) and
        // gather their KYC + stake.
        match &identity.identity_data {
            IdentityData::Human { kyc_tier, .. } => {
                if *kyc_tier >= KycTier::Enhanced
                    && self.bonded_stake(&identity.wallet_address) >= self.min_verified_stake
                {
                    Lane::Verified
                } else {
                    Lane::Open
                }
            }
            IdentityData::Institution { kyb_tier, .. } => {
                if *kyb_tier >= KycTier::Enhanced
                    && self.bonded_stake(&identity.wallet_address) >= self.min_verified_stake
                {
                    Lane::Verified
                } else {
                    Lane::Open
                }
            }
            IdentityData::Machine { controller_did, .. } => {
                // Bond promotion (Spec 9): if enabled, the machine has an
                // Active bond ≥ `bond_min_for_promotion` → Delegated lane
                // even when its controller is unknown / anonymous /
                // sub-Enhanced KYC. The bond is the "skin in the game"
                // path that lets autonomous agents earn priority without
                // a verified human behind them.
                //
                // Bond lookup is keyed on the agent's DID (== `did` here,
                // resolved from `tx.from` two steps above). Only
                // BondLifecycle::Active counts; `has_active_bond_at_least`
                // returns 0 for Cooldown / Frozen / Slashed / Returned.
                let has_bond = self.bond_promotes_to_delegated
                    && self
                        .bond_manager
                        .has_active_bond_at_least(&did, self.bond_min_for_promotion);

                let Some(controller) = controller_did.as_deref() else {
                    // Autonomous machine. Active bond → Delegated, else Open.
                    return if has_bond { Lane::Delegated } else { Lane::Open };
                };

                match self.resolve_controller_address(controller) {
                    Some((controller_addr, kyc_tier))
                        if kyc_tier >= KycTier::Enhanced
                            && self.bonded_stake(&controller_addr)
                                >= self.min_verified_stake =>
                    {
                        // Controller is Verified → machine sits in
                        // Delegated lane (one tier below the human).
                        Lane::Delegated
                    }
                    _ if has_bond => Lane::Delegated,
                    _ => Lane::Open,
                }
            }
        }
    }

    fn bucket_key(&self, tx: &SignedTransaction) -> Address {
        // Rate-limit per controller wallet so an attacker can't multiplex
        // by spawning fresh machines under one human. For Open-lane
        // anonymous traffic we fall back to tx.from — every anonymous
        // sender carries its own bucket.
        let from = &tx.transaction.from;
        let Some(did) = self.identity_registry.find_did_by_address(from) else {
            return *from;
        };
        let Ok(identity) = self.identity_registry.resolve(&did) else {
            return *from;
        };

        match &identity.identity_data {
            IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                identity.wallet_address
            }
            IdentityData::Machine { controller_did: Some(c), .. } => {
                self.resolve_controller_address(c)
                    .map(|(addr, _)| addr)
                    .unwrap_or(*from)
            }
            IdentityData::Machine { controller_did: None, .. } => *from,
        }
    }
}

/// Live execution-state reader consulted by the mempool for stateful
/// admission (nonce ordering + balance coverage). Reads go through a fresh
/// [`tenzro_vm::StateAdapter`] per call — construction is a handful of empty
/// `DashMap`s, and a fresh adapter guarantees the mempool never serves a
/// nonce/balance cached from before the last block's execution.
pub struct NodeAccountStateReader {
    storage: Arc<dyn tenzro_storage::KvStore>,
}

impl NodeAccountStateReader {
    pub fn new(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        Self { storage }
    }
}

impl tenzro_consensus::mempool::AccountStateReader for NodeAccountStateReader {
    fn account_nonce(&self, address: &Address) -> u64 {
        use tenzro_vm::traits::VmState as _;
        tenzro_vm::StateAdapter::with_storage(self.storage.clone()).get_nonce(address.as_bytes())
    }

    fn account_balance(&self, address: &Address) -> u128 {
        use tenzro_vm::traits::VmState as _;
        tenzro_vm::StateAdapter::with_storage(self.storage.clone()).get_balance(address.as_bytes())
    }
}
