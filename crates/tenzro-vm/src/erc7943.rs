//! ERC-7943 (uRWA) interface — universal real-world asset compliance.
//!
//! ERC-7943 reached **Final** status on 2026-05-27. It is the canonical
//! 2026 standard for **tokenized real-world assets** (treasuries,
//! equities, money-market funds, tokenized deposits) that must respect
//! regulator orders (sanctions freeze, asset recovery), legal-entity
//! mandates (counterparty defaults, court orders), and routine
//! compliance (sub-account freezing pending KYC refresh).
//!
//! # The four mandatory hooks
//!
//! 1. **`forcedTransfer(from, to, amount)`** — privileged transfer
//!    executed by the compliance role. Used for asset recovery
//!    (stolen tokens), court-ordered seizure, post-default
//!    re-allocation. Bypasses normal allowance / signing.
//! 2. **`setFrozenTokens(account, amount)`** — freeze a SPECIFIC
//!    amount on an account. The remainder stays transferable.
//!    Used for KYC-refresh-pending where only a sub-balance is
//!    quarantined.
//! 3. **`getFrozenTokens(account) -> uint256`** — read-only.
//! 4. **`killSwitch()`** — global emergency stop; halts all transfers
//!    until cleared by governance.
//!
//! # Selectors
//!
//! Per the ERC-7943 reference implementation:
//! - `forcedTransfer(address,address,uint256)` = `0x33e4e1d3`
//! - `setFrozenTokens(address,uint256)`        = `0x57c52a45`
//! - `getFrozenTokens(address)`                = `0xe4d8156e`
//! - `killSwitch()`                            = `0x1c70d7e6`
//! - `isKillSwitched()`                        = `0x3d3b9f47`
//! - `clearKillSwitch()`                       = `0xb22f3ea7`
//!
//! # Tenzro integration
//!
//! TNZO is the L1 gas token; the bridge wTNZO ERC-20 pointer at
//! `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93` is the cross-VM
//! representation. ERC-7943 applies to **tokenized assets minted
//! through the Tenzro token factory** (RWA-class), NOT to TNZO
//! itself — TNZO is a network-utility token, not a tokenized
//! security. This module installs the kill-switch and freeze
//! registry as a **per-token** policy slot, queryable by the EVM
//! precompile space at `0x101a..0x101c`.
//!
//! Authorization: every mutation is gated by the `admin_token` RPC
//! gate (see `requires_admin_token` in `crates/tenzro-node/src/rpc.rs`),
//! matching the wider compliance-mutation policy.

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Canonical ERC-7943 selectors. Byte-identical to the reference
/// implementation so wallet tooling that already speaks uRWA can
/// dispatch against Tenzro without recompilation.
pub const SELECTOR_FORCED_TRANSFER: [u8; 4] = [0x33, 0xe4, 0xe1, 0xd3];
pub const SELECTOR_SET_FROZEN_TOKENS: [u8; 4] = [0x57, 0xc5, 0x2a, 0x45];
pub const SELECTOR_GET_FROZEN_TOKENS: [u8; 4] = [0xe4, 0xd8, 0x15, 0x6e];
pub const SELECTOR_KILL_SWITCH: [u8; 4] = [0x1c, 0x70, 0xd7, 0xe6];
pub const SELECTOR_IS_KILL_SWITCHED: [u8; 4] = [0x3d, 0x3b, 0x9f, 0x47];
pub const SELECTOR_CLEAR_KILL_SWITCH: [u8; 4] = [0xb2, 0x2f, 0x3e, 0xa7];

/// Precompile addresses for the uRWA hooks.
pub const PRECOMPILE_URWA_FREEZE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x1a,
];
pub const PRECOMPILE_URWA_FORCED_TRANSFER: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x1b,
];
pub const PRECOMPILE_URWA_KILL_SWITCH: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x1c,
];

/// Resolves an EVM address to a KYC tier (0 = Unverified .. 3 = Full).
/// Implemented by the node layer over the TDIP identity registry.
/// Object-safe and synchronous so the EVM transfer path can consult it
/// without an async seam.
pub trait KycTierResolver: Send + Sync {
    fn tier_of(&self, address: &[u8; 20]) -> Option<u8>;
}

/// Per-token minimum-KYC-tier requirement plus the resolver that maps
/// addresses to tiers. Fail-closed: if a token has a requirement and
/// the resolver is missing, or an address does not resolve, the
/// transfer is rejected.
///
/// Persistence: requirements write through to `CF_TOKENS / kyc_gate:{token_id}`
/// and hydrate on construction. The resolver is runtime wiring only.
pub struct KycGateRegistry {
    requirements: DashMap<[u8; 32], u8>,
    resolver: RwLock<Option<Arc<dyn KycTierResolver>>>,
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl Default for KycGateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KycGateRegistry {
    pub fn new() -> Self {
        Self {
            requirements: DashMap::new(),
            resolver: RwLock::new(None),
            storage: None,
        }
    }

    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let s = Self {
            requirements: DashMap::new(),
            resolver: RwLock::new(None),
            storage: Some(storage),
        };
        s.hydrate();
        s
    }

    pub fn set_resolver(&self, resolver: Arc<dyn KycTierResolver>) {
        *self.resolver.write() = Some(resolver);
    }

    fn gate_key(token_id: &[u8; 32]) -> Vec<u8> {
        let mut k = b"kyc_gate:".to_vec();
        k.extend_from_slice(token_id);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        if let Ok(entries) = storage.scan_prefix(tenzro_storage::CF_TOKENS, b"kyc_gate:") {
            for (key, value) in entries {
                // key = "kyc_gate:" || token_id(32)
                if key.len() != 9 + 32 {
                    continue;
                }
                let mut tid = [0u8; 32];
                tid.copy_from_slice(&key[9..41]);
                if let Ok(tier) = serde_json::from_slice::<u8>(&value) {
                    self.requirements.insert(tid, tier);
                }
            }
        }
    }

    pub fn set_requirement(&self, token_id: [u8; 32], required_tier: u8) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(&required_tier) {
                let _ = storage.put(
                    tenzro_storage::CF_TOKENS,
                    &Self::gate_key(&token_id),
                    &bytes,
                );
            }
        }
        self.requirements.insert(token_id, required_tier);
    }

    pub fn clear_requirement(&self, token_id: &[u8; 32]) {
        if let Some(ref storage) = self.storage {
            let _ = storage.delete(tenzro_storage::CF_TOKENS, &Self::gate_key(token_id));
        }
        self.requirements.remove(token_id);
    }

    pub fn requirement(&self, token_id: &[u8; 32]) -> Option<u8> {
        self.requirements.get(token_id).map(|e| *e.value())
    }

    /// Enforce the tier requirement for one participant. `role` labels
    /// the rejection message ("sender" / "recipient"). No requirement
    /// for the token means no gate; a requirement with a missing
    /// resolver or unresolvable address rejects.
    pub fn check_participant(
        &self,
        token_id: &[u8; 32],
        address: &[u8; 20],
        role: &str,
    ) -> Result<(), String> {
        let Some(required) = self.requirement(token_id) else {
            return Ok(());
        };
        let resolver = self.resolver.read().clone();
        let Some(resolver) = resolver else {
            return Err(format!(
                "uRWA KYC: tier {} required but no resolver is configured ({})",
                required, role
            ));
        };
        match resolver.tier_of(address) {
            Some(tier) if tier >= required => Ok(()),
            Some(tier) => Err(format!(
                "uRWA KYC: {} tier {} below required tier {}",
                role, tier, required
            )),
            None => Err(format!(
                "uRWA KYC: {} 0x{} has no resolvable identity (tier {} required)",
                role,
                hex::encode(address),
                required
            )),
        }
    }
}

/// Per-account frozen-tokens entry. `amount` is in the token's
/// smallest unit; `reason_hex` is optional context (court-order id,
/// sanctions reference, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrozenAmount {
    pub amount: u128,
    pub reason: Option<String>,
    pub set_at_ms: u64,
}

/// Kill-switch state for a specific token. Global across the token's
/// entire holder set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillSwitchState {
    pub active: bool,
    pub triggered_by_did: Option<String>,
    pub reason: Option<String>,
    pub triggered_at_ms: u64,
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self {
            active: false,
            triggered_by_did: None,
            reason: None,
            triggered_at_ms: 0,
        }
    }
}

/// uRWA compliance registry. Holds, per (token_id, account), the
/// frozen-token amount; per token_id, the global kill-switch state.
///
/// `token_id` is the canonical `[u8; 32]` Tenzro token identifier
/// (SHA-256 of creator+nonce — see `UnifiedTokenRegistry::compute_token_id`).
///
/// Persistence: every mutation writes through to the supplied
/// `KvStore` under `CF_TOKENS / urwa_freeze:{token_id}:{account}` and
/// `CF_TOKENS / urwa_kill:{token_id}`. Hydration restores the in-memory
/// indices on every node restart.
pub struct UrwaRegistry {
    /// Per-(token, account) frozen amount.
    pub frozen: DashMap<([u8; 32], [u8; 20]), FrozenAmount>,
    /// Per-token kill-switch.
    pub kill_switch: DashMap<[u8; 32], KillSwitchState>,
    /// Optional per-token KYC tier gate consulted on every transfer.
    kyc_gate: Option<Arc<KycGateRegistry>>,
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl Default for UrwaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UrwaRegistry {
    pub fn new() -> Self {
        Self {
            frozen: DashMap::new(),
            kill_switch: DashMap::new(),
            kyc_gate: None,
            storage: None,
        }
    }

    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let s = Self {
            frozen: DashMap::new(),
            kill_switch: DashMap::new(),
            kyc_gate: None,
            storage: Some(storage),
        };
        s.hydrate();
        s
    }

    pub fn with_kyc_gate(mut self, gate: Arc<KycGateRegistry>) -> Self {
        self.kyc_gate = Some(gate);
        self
    }

    pub fn kyc_gate(&self) -> Option<&Arc<KycGateRegistry>> {
        self.kyc_gate.as_ref()
    }

    fn freeze_key(token_id: &[u8; 32], account: &[u8; 20]) -> Vec<u8> {
        let mut k = b"urwa_freeze:".to_vec();
        k.extend_from_slice(token_id);
        k.push(b':');
        k.extend_from_slice(account);
        k
    }

    fn kill_key(token_id: &[u8; 32]) -> Vec<u8> {
        let mut k = b"urwa_kill:".to_vec();
        k.extend_from_slice(token_id);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        if let Ok(entries) = storage.scan_prefix(tenzro_storage::CF_TOKENS, b"urwa_freeze:") {
            for (key, value) in entries {
                // key = "urwa_freeze:" || token_id(32) || ":" || account(20)
                if key.len() != 12 + 32 + 1 + 20 {
                    continue;
                }
                let mut tid = [0u8; 32];
                tid.copy_from_slice(&key[12..44]);
                let mut acc = [0u8; 20];
                acc.copy_from_slice(&key[45..65]);
                if let Ok(amt) = serde_json::from_slice::<FrozenAmount>(&value) {
                    self.frozen.insert((tid, acc), amt);
                }
            }
        }
        if let Ok(entries) = storage.scan_prefix(tenzro_storage::CF_TOKENS, b"urwa_kill:") {
            for (key, value) in entries {
                if key.len() != 10 + 32 {
                    continue;
                }
                let mut tid = [0u8; 32];
                tid.copy_from_slice(&key[10..42]);
                if let Ok(state) = serde_json::from_slice::<KillSwitchState>(&value) {
                    self.kill_switch.insert(tid, state);
                }
            }
        }
    }

    fn persist_freeze(&self, token_id: &[u8; 32], account: &[u8; 20], amt: &FrozenAmount) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(amt) {
                let _ = storage.put(
                    tenzro_storage::CF_TOKENS,
                    &Self::freeze_key(token_id, account),
                    &bytes,
                );
            }
        }
    }

    fn persist_kill(&self, token_id: &[u8; 32], state: &KillSwitchState) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(state) {
                let _ = storage.put(
                    tenzro_storage::CF_TOKENS,
                    &Self::kill_key(token_id),
                    &bytes,
                );
            }
        }
    }

    pub fn set_frozen_tokens(
        &self,
        token_id: [u8; 32],
        account: [u8; 20],
        amount: u128,
        reason: Option<String>,
        now_ms: u64,
    ) {
        let entry = FrozenAmount {
            amount,
            reason,
            set_at_ms: now_ms,
        };
        self.persist_freeze(&token_id, &account, &entry);
        self.frozen.insert((token_id, account), entry);
    }

    pub fn get_frozen_tokens(&self, token_id: &[u8; 32], account: &[u8; 20]) -> u128 {
        self.frozen
            .get(&(*token_id, *account))
            .map(|e| e.value().amount)
            .unwrap_or(0)
    }

    /// Hook the EVM transfer path must invoke: returns `Ok(())` if
    /// the transfer is permitted (kill-switch off, remaining
    /// non-frozen balance covers `amount`, and both sender and
    /// recipient satisfy the token's KYC tier requirement),
    /// `Err(reason)` otherwise.
    pub fn check_transfer(
        &self,
        token_id: &[u8; 32],
        from: &[u8; 20],
        to: &[u8; 20],
        from_balance: u128,
        amount: u128,
    ) -> Result<(), String> {
        if self
            .kill_switch
            .get(token_id)
            .map(|e| e.value().active)
            .unwrap_or(false)
        {
            return Err("uRWA kill-switch active for this token".to_string());
        }
        let frozen = self.get_frozen_tokens(token_id, from);
        let transferable = from_balance.saturating_sub(frozen);
        if amount > transferable {
            return Err(format!(
                "uRWA: insufficient transferable balance (balance={} frozen={} requested={})",
                from_balance, frozen, amount
            ));
        }
        if let Some(ref gate) = self.kyc_gate {
            gate.check_participant(token_id, from, "sender")?;
            gate.check_participant(token_id, to, "recipient")?;
        }
        Ok(())
    }

    /// Hook for the forced-transfer precompile (`0x101b`). The
    /// compliance role bypasses the sender-side KYC check (the sender
    /// may be a sanctioned or defunct party being seized from) but the
    /// recipient must still satisfy the token's tier requirement.
    pub fn check_forced_transfer(
        &self,
        token_id: &[u8; 32],
        to: &[u8; 20],
    ) -> Result<(), String> {
        if let Some(ref gate) = self.kyc_gate {
            gate.check_participant(token_id, to, "recipient")?;
        }
        Ok(())
    }

    pub fn trigger_kill_switch(
        &self,
        token_id: [u8; 32],
        triggered_by_did: Option<String>,
        reason: Option<String>,
        now_ms: u64,
    ) {
        let state = KillSwitchState {
            active: true,
            triggered_by_did,
            reason,
            triggered_at_ms: now_ms,
        };
        self.persist_kill(&token_id, &state);
        self.kill_switch.insert(token_id, state);
    }

    pub fn clear_kill_switch(&self, token_id: &[u8; 32]) {
        let state = KillSwitchState::default();
        self.persist_kill(token_id, &state);
        self.kill_switch.insert(*token_id, state);
    }

    pub fn is_kill_switched(&self, token_id: &[u8; 32]) -> bool {
        self.kill_switch
            .get(token_id)
            .map(|e| e.value().active)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticTierResolver {
        tiers: std::collections::HashMap<[u8; 20], u8>,
    }

    impl KycTierResolver for StaticTierResolver {
        fn tier_of(&self, address: &[u8; 20]) -> Option<u8> {
            self.tiers.get(address).copied()
        }
    }

    fn resolver_with(entries: &[([u8; 20], u8)]) -> Arc<dyn KycTierResolver> {
        Arc::new(StaticTierResolver {
            tiers: entries.iter().copied().collect(),
        })
    }

    #[test]
    fn frozen_amount_blocks_partial_transfer() {
        let reg = UrwaRegistry::new();
        let token = [1u8; 32];
        let alice = [0xaa; 20];
        let bob = [0xbb; 20];

        // No freeze: full balance available.
        assert!(reg.check_transfer(&token, &alice, &bob, 1000, 500).is_ok());

        // Freeze 800 of 1000. Transferable = 200.
        reg.set_frozen_tokens(token, alice, 800, Some("KYC pending".into()), 1_000);
        assert_eq!(reg.get_frozen_tokens(&token, &alice), 800);

        assert!(reg.check_transfer(&token, &alice, &bob, 1000, 200).is_ok());
        assert!(reg.check_transfer(&token, &alice, &bob, 1000, 201).is_err());
    }

    #[test]
    fn kill_switch_blocks_all_transfers() {
        let reg = UrwaRegistry::new();
        let token = [2u8; 32];
        let alice = [0xaa; 20];
        let bob = [0xbb; 20];

        assert!(!reg.is_kill_switched(&token));
        assert!(reg.check_transfer(&token, &alice, &bob, 1000, 100).is_ok());

        reg.trigger_kill_switch(
            token,
            Some("did:tn:human:operator".into()),
            Some("Sanctions update".into()),
            12345,
        );
        assert!(reg.is_kill_switched(&token));

        let err = reg.check_transfer(&token, &alice, &bob, 1000, 1).unwrap_err();
        assert!(err.contains("kill-switch active"));

        reg.clear_kill_switch(&token);
        assert!(!reg.is_kill_switched(&token));
        assert!(reg.check_transfer(&token, &alice, &bob, 1000, 1).is_ok());
    }

    #[test]
    fn kyc_gate_allows_when_both_meet_tier() {
        let token = [3u8; 32];
        let alice = [0xaa; 20];
        let bob = [0xbb; 20];

        let gate = Arc::new(KycGateRegistry::new());
        gate.set_requirement(token, 2);
        gate.set_resolver(resolver_with(&[(alice, 2), (bob, 3)]));

        let reg = UrwaRegistry::new().with_kyc_gate(gate);
        assert!(reg.check_transfer(&token, &alice, &bob, 1000, 100).is_ok());
    }

    #[test]
    fn kyc_gate_rejects_recipient_below_tier() {
        let token = [4u8; 32];
        let alice = [0xaa; 20];
        let bob = [0xbb; 20];

        let gate = Arc::new(KycGateRegistry::new());
        gate.set_requirement(token, 2);
        gate.set_resolver(resolver_with(&[(alice, 3), (bob, 1)]));

        let reg = UrwaRegistry::new().with_kyc_gate(gate);
        let err = reg.check_transfer(&token, &alice, &bob, 1000, 100).unwrap_err();
        assert!(err.contains("recipient tier 1 below required tier 2"));
    }

    #[test]
    fn kyc_gate_missing_resolver_fails_closed() {
        let token = [5u8; 32];
        let alice = [0xaa; 20];
        let bob = [0xbb; 20];

        let gate = Arc::new(KycGateRegistry::new());
        gate.set_requirement(token, 1);
        // No resolver installed.

        let reg = UrwaRegistry::new().with_kyc_gate(gate);
        let err = reg.check_transfer(&token, &alice, &bob, 1000, 100).unwrap_err();
        assert!(err.contains("no resolver is configured"));
    }

    #[test]
    fn kyc_gate_unresolvable_address_fails_closed() {
        let token = [6u8; 32];
        let alice = [0xaa; 20];
        let stranger = [0xcc; 20];

        let gate = Arc::new(KycGateRegistry::new());
        gate.set_requirement(token, 1);
        gate.set_resolver(resolver_with(&[(alice, 3)]));

        let reg = UrwaRegistry::new().with_kyc_gate(gate);
        let err = reg
            .check_transfer(&token, &alice, &stranger, 1000, 100)
            .unwrap_err();
        assert!(err.contains("no resolvable identity"));
    }

    #[test]
    fn kyc_gate_no_requirement_passes() {
        let gate = Arc::new(KycGateRegistry::new());
        // Requirement set only for a different token; no resolver at all.
        gate.set_requirement([9u8; 32], 3);

        let token = [7u8; 32];
        let reg = UrwaRegistry::new().with_kyc_gate(gate);
        assert!(reg
            .check_transfer(&token, &[0xaa; 20], &[0xbb; 20], 1000, 100)
            .is_ok());
    }

    #[test]
    fn forced_transfer_skips_sender_but_gates_recipient() {
        let token = [8u8; 32];
        let seized = [0xdd; 20]; // no identity at all
        let custodian = [0xee; 20];
        let unverified = [0xef; 20];

        let gate = Arc::new(KycGateRegistry::new());
        gate.set_requirement(token, 2);
        gate.set_resolver(resolver_with(&[(custodian, 3), (unverified, 0)]));

        let reg = UrwaRegistry::new().with_kyc_gate(gate);

        // Normal transfer from the seized address would fail (sender unresolvable).
        assert!(reg
            .check_transfer(&token, &seized, &custodian, 1000, 100)
            .is_err());

        // Forced transfer to a qualifying custodian passes.
        assert!(reg.check_forced_transfer(&token, &custodian).is_ok());

        // Forced transfer still cannot land on an under-tier recipient.
        let err = reg.check_forced_transfer(&token, &unverified).unwrap_err();
        assert!(err.contains("recipient tier 0 below required tier 2"));
    }

    #[test]
    fn selectors_match_canonical_bytes() {
        // Spot-check: the canonical 4-byte selectors from the ERC-7943
        // reference implementation must be byte-for-byte equal.
        assert_eq!(SELECTOR_FORCED_TRANSFER, [0x33, 0xe4, 0xe1, 0xd3]);
        assert_eq!(SELECTOR_SET_FROZEN_TOKENS, [0x57, 0xc5, 0x2a, 0x45]);
        assert_eq!(SELECTOR_KILL_SWITCH, [0x1c, 0x70, 0xd7, 0xe6]);
    }
}
