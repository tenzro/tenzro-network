//! Node-side `LaneResolver` impl bridging `IdentityRegistry` + bonded stake in consensus state
//! into the `tenzro-consensus` admission controller.
//!
//! `tenzro-consensus` cannot depend on `tenzro-identity` or `tenzro-token`
//! (would cycle through `tenzro-node`). The trait abstraction in
//! [`tenzro_consensus::admission::LaneResolver`] is the seam; this adapter
//! is the only place in the workspace where the consensus admission path,
//! the identity registry, and the staking manager all meet.
//!
//! # Lane assignment rules
//!
//! Pure function of the transaction's signer + the registry state:
//!
//! 1. **Verified** — sender's controller (or self, if a directly-registered
//!    human) has KYC tier ≥ Enhanced AND ≥ `min_verified_stake` of bonded
//!    TNZO at the controller's wallet address.
//! 2. **Delegated** — sender is a Machine identity rooted (one or more
//!    levels deep) in a Verified controller, and the identity is `Active`.
//!    OR — when `bond_promotes_to_delegated` is enabled — the sender is a
//!    Machine with an Active `AgentBond` ≥ `bond_min_for_promotion`.
//!    The bond is read from chain state; only an Active bond counts, so a
//!    Cooldown / Slashed / Returned bond is treated as no bond at all.
//! 3. **Open** — everyone else (anonymous, unknown DID, suspended/revoked
//!    identity, machine whose controller is suspended, machine outside
//!    delegation scope).
//!
//! Any registry lookup failure (registry not wired, DID not found, etc.)
//! falls through to **Open** rather than rejecting — admission is still
//! rate-limited at the lowest tier, so we degrade gracefully without
//! locking out legitimate Open-lane traffic.
//!
//! # Bucket key
//!
//! The rate limit is per *controller*. For Verified/Delegated
//! lanes that means the controller DID's wallet address (so an attacker
//! cannot multiplex across spawned machines). For Open it's `tx.from` —
//! anonymous senders rate-limit themselves.

use std::sync::Arc;
use tracing::warn;

use tenzro_consensus::admission::{Lane, LaneResolver};
use tenzro_identity::{IdentityData, IdentityRegistry, IdentityStatus};
use tenzro_types::identity::KycTier;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::SignedTransaction;

/// Production `LaneResolver` consulted by the mempool admission controller.
pub struct NodeLaneResolver {
    identity_registry: Arc<IdentityRegistry>,
    chain: Arc<dyn tenzro_storage::KvStore>,
    min_verified_stake: u128,
    bond_promotes_to_delegated: bool,
    bond_min_for_promotion: u128,
}

impl NodeLaneResolver {
    /// Construct a resolver from the live identity registry and chain state.
    /// `min_verified_stake`, `bond_promotes_to_delegated` and
    /// `bond_min_for_promotion` should be taken from `AdmissionConfig` so
    /// the resolver and bucket policy agree on thresholds.
    pub fn new(
        identity_registry: Arc<IdentityRegistry>,
        chain: Arc<dyn tenzro_storage::KvStore>,
        min_verified_stake: u128,
        bond_promotes_to_delegated: bool,
        bond_min_for_promotion: u128,
    ) -> Self {
        Self {
            identity_registry,
            chain,
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
                IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                    let tier = self.identity_registry.kyc_tier(&current_did);
                    return Some((identity.wallet_address, tier));
                }
                IdentityData::Machine {
                    controller_did: Some(c),
                    ..
                } => {
                    current_did = c.clone();
                }
                IdentityData::Machine {
                    controller_did: None,
                    ..
                } => {
                    // Autonomous machine — itself is the principal, but it
                    // has no human KYC. Treat as Open / Delegated only via
                    // bond promotion.
                    return None;
                }
            }
        }
        None
    }

    /// Stake `address` has bonded in consensus: its validator bond plus its
    /// bonds for every role.
    /// Whether `did` holds an Active agent bond of at least `min` wei.
    fn has_active_bond_at_least(&self, did: &str, min: u128) -> bool {
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        tenzro_vm::native::agent_bond(&chain, did).is_some_and(|b| b.is_active() && b.amount >= min)
    }

    fn bonded_stake(&self, address: &Address) -> u128 {
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        tenzro_vm::native::role_stakes_of(&chain, address.as_bytes())
            .into_iter()
            .fold(
                tenzro_vm::native::bonded_stake_of(&chain, address.as_bytes()),
                |acc, (_, s)| acc.saturating_add(s.bonded),
            )
    }
}

/// Agent bonds for principal-chain receipts, read from chain state.
pub struct ChainBondLookup {
    chain: Arc<dyn tenzro_storage::KvStore>,
}

impl ChainBondLookup {
    pub fn new(chain: Arc<dyn tenzro_storage::KvStore>) -> Self {
        Self { chain }
    }
}

impl tenzro_types::principal_chain::BondLookup for ChainBondLookup {
    fn actor_bond(&self, did: &str) -> Option<u128> {
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        tenzro_vm::native::agent_bond(&chain, did)
            .filter(|b| b.is_active())
            .map(|b| b.amount)
    }

    fn controller_aggregate(&self, controller_did: &str) -> Option<u128> {
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        let active: Vec<u128> =
            tenzro_vm::native::agent_bonds_of_controller(&chain, controller_did)
                .into_iter()
                .filter(|b| b.is_active())
                .map(|b| b.amount)
                .collect();
        (!active.is_empty()).then(|| active.iter().fold(0u128, |a, b| a.saturating_add(*b)))
    }
}

/// Derives KYC tiers from chain state: an identity's tier is the best live
/// `kyc` grade its wallet holds from an issuer the policy of one of the
/// operator's named assets names (`kyc_assets`).
pub struct ChainKycResolver {
    chain: Arc<dyn tenzro_storage::KvStore>,
    assets: Vec<[u8; 32]>,
}

impl ChainKycResolver {
    pub fn new(chain: Arc<dyn tenzro_storage::KvStore>, assets: Vec<[u8; 32]>) -> Self {
        Self { chain, assets }
    }

    /// Parses the operator's `kyc_assets`: 32-byte token ids, hex.
    pub fn parse_assets(assets: &[String]) -> std::result::Result<Vec<[u8; 32]>, String> {
        assets
            .iter()
            .map(|a| {
                hex::decode(a.trim().trim_start_matches("0x"))
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| format!("kyc_assets: {a:?} is not a 32-byte token id (hex)"))
            })
            .collect()
    }
}

impl tenzro_identity::KycResolver for ChainKycResolver {
    fn kyc_tier(&self, did: &str, wallet: &Address) -> KycTier {
        let state = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        let now_ms = chrono::Utc::now().timestamp_millis();
        match tenzro_vm::token_ledger::kyc_tier_under(
            &state,
            &self.assets,
            wallet.as_bytes(),
            now_ms,
        ) {
            Ok(level) => KycTier::from_level(level),
            Err(e) => {
                warn!(%did, error = %e, "KYC claims could not be read; the identity counts as unverified");
                KycTier::Unverified
            }
        }
    }
}

impl LaneResolver for NodeLaneResolver {
    /// The duties a validator performs for the protocol, sent from the
    /// account that holds its self-stake, are not held by that account's
    /// token bucket: they come at the pace of checkpoints and beacon rounds,
    /// above an Open-lane quota, and each is checked when it executes.
    fn exempt_from_rate(&self, tx: &SignedTransaction) -> bool {
        use tenzro_types::transaction::TransactionType;
        matches!(
            tx.transaction.tx_type,
            TransactionType::RecordCheckpointSigners { .. }
                | TransactionType::BeaconContribute { .. }
                | TransactionType::ReportCheckpointEquivocation { .. }
        ) && {
            let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
            tenzro_vm::native::bonded_stake_of(&chain, tx.transaction.from.as_bytes()) > 0
        }
    }

    fn limits(&self, lane: Lane) -> Option<(f64, u32)> {
        use tenzro_vm::governance as g;
        let (rate, burst) = match lane {
            Lane::Verified => (
                g::ADMISSION_VERIFIED_RATE_PARAM,
                g::ADMISSION_VERIFIED_BURST_PARAM,
            ),
            Lane::Delegated => (
                g::ADMISSION_DELEGATED_RATE_PARAM,
                g::ADMISSION_DELEGATED_BURST_PARAM,
            ),
            Lane::Open => (g::ADMISSION_OPEN_RATE_PARAM, g::ADMISSION_OPEN_BURST_PARAM),
        };
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        let rate = tenzro_vm::native::network_param(&chain, rate) as f64 / 1000.0;
        let burst =
            u32::try_from(tenzro_vm::native::network_param(&chain, burst)).unwrap_or(u32::MAX);
        Some((rate, burst))
    }

    fn fee_mult(&self, lane: Lane) -> Option<f64> {
        use tenzro_vm::governance as g;
        let key = match lane {
            Lane::Verified => g::ADMISSION_VERIFIED_FEE_MULT_PARAM,
            Lane::Delegated => g::ADMISSION_DELEGATED_FEE_MULT_PARAM,
            Lane::Open => g::ADMISSION_OPEN_FEE_MULT_PARAM,
        };
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        Some(tenzro_vm::native::network_param(&chain, key) as f64 / 10_000.0)
    }

    fn assign_lane(&self, tx: &SignedTransaction) -> Lane {
        // Step 1: find the DID associated with the signer address. No DID
        // → Open lane (anonymous).
        let from = &tx.transaction.from;
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        let did = match tenzro_vm::native::identity_of_wallet(&chain, from.as_bytes()) {
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
            IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                if self.identity_registry.kyc_tier(&did) >= KycTier::Enhanced
                    && self.bonded_stake(&identity.wallet_address) >= self.min_verified_stake
                {
                    Lane::Verified
                } else {
                    Lane::Open
                }
            }
            IdentityData::Machine { controller_did, .. } => {
                // Bond promotion: if enabled, the machine has an
                // Active bond ≥ `bond_min_for_promotion` → Delegated lane
                // even when its controller is unknown / anonymous /
                // sub-Enhanced KYC. The bond is the "skin in the game"
                // path that lets autonomous agents earn priority without
                // a verified human behind them.
                //
                // Bond lookup is keyed on the agent's DID (== `did` here,
                // resolved from `tx.from` two steps above). Only an Active
                // bond counts.
                let has_bond = self.bond_promotes_to_delegated
                    && self.has_active_bond_at_least(&did, self.bond_min_for_promotion);

                let Some(controller) = controller_did.as_deref() else {
                    // Autonomous machine. Active bond → Delegated, else Open.
                    return if has_bond {
                        Lane::Delegated
                    } else {
                        Lane::Open
                    };
                };

                match self.resolve_controller_address(controller) {
                    Some((controller_addr, kyc_tier))
                        if kyc_tier >= KycTier::Enhanced
                            && self.bonded_stake(&controller_addr) >= self.min_verified_stake =>
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
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        let Some(did) = tenzro_vm::native::identity_of_wallet(&chain, from.as_bytes()) else {
            return *from;
        };
        let Ok(identity) = self.identity_registry.resolve(&did) else {
            return *from;
        };

        match &identity.identity_data {
            IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                identity.wallet_address
            }
            IdentityData::Machine {
                controller_did: Some(c),
                ..
            } => self
                .resolve_controller_address(c)
                .map(|(addr, _)| addr)
                .unwrap_or(*from),
            IdentityData::Machine {
                controller_did: None,
                ..
            } => *from,
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
        tenzro_vm::StateAdapter::reader(self.storage.clone()).get_nonce(address.as_bytes())
    }

    fn account_balance(&self, address: &Address) -> u128 {
        use tenzro_vm::traits::VmState as _;
        tenzro_vm::StateAdapter::reader(self.storage.clone()).get_balance(address.as_bytes())
    }

    fn block_base_fee(&self) -> u128 {
        tenzro_vm::ledger::block_base_fee(&tenzro_vm::StateAdapter::reader(self.storage.clone()))
    }
}
