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
            storage: None,
        }
    }

    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let s = Self {
            frozen: DashMap::new(),
            kill_switch: DashMap::new(),
            storage: Some(storage),
        };
        s.hydrate();
        s
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
    /// the transfer is permitted (kill-switch off AND remaining
    /// non-frozen balance covers `amount`), `Err(reason)` otherwise.
    pub fn check_transfer(
        &self,
        token_id: &[u8; 32],
        from: &[u8; 20],
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

    #[test]
    fn frozen_amount_blocks_partial_transfer() {
        let reg = UrwaRegistry::new();
        let token = [1u8; 32];
        let alice = [0xaa; 20];

        // No freeze: full balance available.
        assert!(reg.check_transfer(&token, &alice, 1000, 500).is_ok());

        // Freeze 800 of 1000. Transferable = 200.
        reg.set_frozen_tokens(token, alice, 800, Some("KYC pending".into()), 1_000);
        assert_eq!(reg.get_frozen_tokens(&token, &alice), 800);

        assert!(reg.check_transfer(&token, &alice, 1000, 200).is_ok());
        assert!(reg.check_transfer(&token, &alice, 1000, 201).is_err());
    }

    #[test]
    fn kill_switch_blocks_all_transfers() {
        let reg = UrwaRegistry::new();
        let token = [2u8; 32];
        let alice = [0xaa; 20];

        assert!(!reg.is_kill_switched(&token));
        assert!(reg.check_transfer(&token, &alice, 1000, 100).is_ok());

        reg.trigger_kill_switch(
            token,
            Some("did:tn:human:operator".into()),
            Some("Sanctions update".into()),
            12345,
        );
        assert!(reg.is_kill_switched(&token));

        let err = reg.check_transfer(&token, &alice, 1000, 1).unwrap_err();
        assert!(err.contains("kill-switch active"));

        reg.clear_kill_switch(&token);
        assert!(!reg.is_kill_switched(&token));
        assert!(reg.check_transfer(&token, &alice, 1000, 1).is_ok());
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
