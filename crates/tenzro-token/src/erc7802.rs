//! ERC-7802 Cross-Chain Token Standard
//!
//! Implements the crosschainMint/crosschainBurn interface proposed by OP Labs
//! for standardized bridge interop. Bridges are authorized via an ACL and can
//! mint/burn tokens atomically on behalf of cross-chain transfers.
//!
//! See: https://eips.ethereum.org/EIPS/eip-7802

use crate::cross_vm::TokenId;
use crate::error::{Result, TokenError};
use crate::registry::TokenRegistry;
use crate::tnzo::TnzoToken;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use tenzro_types::primitives::Address;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Portable AtomicU128 — std AtomicU128 is not available on all targets, so we
// wrap a parking_lot::Mutex<u128> behind the same load/store API.
// ---------------------------------------------------------------------------

struct AtomicU128(parking_lot::Mutex<u128>);

impl AtomicU128 {
    fn new(v: u128) -> Self {
        Self(parking_lot::Mutex::new(v))
    }

    fn load(&self) -> u128 {
        *self.0.lock()
    }

    fn store(&self, v: u128) {
        *self.0.lock() = v;
    }

    fn fetch_add(&self, v: u128) -> u128 {
        let mut guard = self.0.lock();
        let old = *guard;
        *guard = old.saturating_add(v);
        old
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Event emitted after a successful cross-chain mint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrosschainMintEvent {
    /// Unique nonce for this event.
    pub nonce: u64,
    /// Recipient address on this chain.
    pub to: Address,
    /// Amount minted (in smallest TNZO unit, 18 decimals).
    pub amount: u128,
    /// Opaque sender identifier on the source chain.
    pub sender: Vec<u8>,
    /// Bridge address that executed the mint.
    pub bridge: [u8; 20],
    /// Unix timestamp (seconds) when the event was created.
    pub timestamp: i64,
}

/// Event emitted after a successful cross-chain burn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrosschainBurnEvent {
    /// Unique nonce for this event.
    pub nonce: u64,
    /// Address whose tokens were burned.
    pub from: Address,
    /// Amount burned (in smallest TNZO unit, 18 decimals).
    pub amount: u128,
    /// Opaque destination identifier on the target chain.
    pub sender: Vec<u8>,
    /// Bridge address that executed the burn.
    pub bridge: [u8; 20],
    /// Unix timestamp (seconds) when the event was created.
    pub timestamp: i64,
}

/// Authorization record for a bridge that may call crosschainMint/crosschainBurn.
pub struct BridgeAuthorization {
    /// 20-byte bridge address (EVM-style).
    pub bridge_address: [u8; 20],
    /// Human-readable name of the bridge.
    pub name: String,
    /// Token IDs this bridge may mint/burn. Empty means all tokens.
    pub authorized_tokens: Vec<TokenId>,
    /// Maximum amount that can be minted in a single transaction.
    pub max_mint_per_tx: Option<u128>,
    /// Maximum amount that can be burned in a single transaction.
    pub max_burn_per_tx: Option<u128>,
    /// Maximum cumulative mint amount per 24-hour window.
    pub daily_mint_limit: Option<u128>,
    /// Maximum cumulative burn amount per 24-hour window.
    pub daily_burn_limit: Option<u128>,
    /// Cumulative amount minted since last daily reset.
    minted_today: AtomicU128,
    /// Cumulative amount burned since last daily reset.
    burned_today: AtomicU128,
    /// Unix timestamp of the last daily counter reset.
    last_reset: AtomicI64,
    /// Whether this authorization is currently active.
    pub enabled: bool,
}

impl BridgeAuthorization {
    /// Resets the daily counters if 24 hours have elapsed since the last reset.
    fn maybe_reset_daily(&self, now: i64) {
        let last = self.last_reset.load(Ordering::Relaxed);
        if now - last >= 86_400 {
            self.minted_today.store(0);
            self.burned_today.store(0);
            self.last_reset.store(now, Ordering::Relaxed);
        }
    }
}

/// Serializable snapshot of a bridge authorization (for API responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInfo {
    pub bridge_address: String,
    pub name: String,
    pub authorized_tokens: Vec<String>,
    pub max_mint_per_tx: Option<u128>,
    pub max_burn_per_tx: Option<u128>,
    pub daily_mint_limit: Option<u128>,
    pub daily_burn_limit: Option<u128>,
    pub minted_today: u128,
    pub burned_today: u128,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// CrosschainTokenManager
// ---------------------------------------------------------------------------

/// Manages ERC-7802 crosschainMint/crosschainBurn operations.
///
/// Bridges must be explicitly authorized before they can mint or burn tokens.
/// Per-transaction and daily limits are enforced to bound risk.
pub struct CrosschainTokenManager {
    /// Bridge address -> authorization record.
    authorized_bridges: DashMap<[u8; 20], BridgeAuthorization>,
    /// Reference to the native TNZO token (mint/burn target).
    tnzo_token: Arc<TnzoToken>,
    /// Reference to the unified token registry. Used by
    /// [`Self::resolve_authorized_tokens`] to project a bridge's
    /// `authorized_tokens` set into full `TokenInfo` records for
    /// observability and registry-aware authorization.
    registry: Arc<TokenRegistry>,
    /// Mint event log, keyed by nonce.
    mint_events: DashMap<u64, CrosschainMintEvent>,
    /// Burn event log, keyed by nonce.
    burn_events: DashMap<u64, CrosschainBurnEvent>,
    /// Monotonically increasing nonce for events.
    nonce: AtomicU64,
}

impl CrosschainTokenManager {
    /// Creates a new manager backed by the given token and registry instances.
    pub fn new(tnzo_token: Arc<TnzoToken>, registry: Arc<TokenRegistry>) -> Self {
        Self {
            authorized_bridges: DashMap::new(),
            tnzo_token,
            registry,
            mint_events: DashMap::new(),
            burn_events: DashMap::new(),
            nonce: AtomicU64::new(1),
        }
    }

    // -- Bridge management ---------------------------------------------------

    /// Authorizes a bridge to call crosschainMint/crosschainBurn.
    pub fn authorize_bridge(
        &self,
        bridge_address: [u8; 20],
        name: String,
        authorized_tokens: Vec<TokenId>,
        max_mint_per_tx: Option<u128>,
        max_burn_per_tx: Option<u128>,
        daily_mint_limit: Option<u128>,
        daily_burn_limit: Option<u128>,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let auth = BridgeAuthorization {
            bridge_address,
            name: name.clone(),
            authorized_tokens,
            max_mint_per_tx,
            max_burn_per_tx,
            daily_mint_limit,
            daily_burn_limit,
            minted_today: AtomicU128::new(0),
            burned_today: AtomicU128::new(0),
            last_reset: AtomicI64::new(now),
            enabled: true,
        };

        info!(
            "Authorized bridge {} (0x{})",
            name,
            hex::encode(bridge_address)
        );
        self.authorized_bridges.insert(bridge_address, auth);
        Ok(())
    }

    /// Revokes a bridge's authorization. In-flight operations that already
    /// passed the authorization check will still complete, but new calls will
    /// be rejected.
    pub fn revoke_bridge(&self, bridge_address: &[u8; 20]) -> Result<()> {
        match self.authorized_bridges.remove(bridge_address) {
            Some((_, auth)) => {
                info!(
                    "Revoked bridge {} (0x{})",
                    auth.name,
                    hex::encode(bridge_address)
                );
                Ok(())
            }
            None => Err(TokenError::Unauthorized {
                reason: format!(
                    "Bridge 0x{} is not authorized",
                    hex::encode(bridge_address)
                ),
            }),
        }
    }

    /// Updates the per-tx and daily limits for an authorized bridge.
    pub fn update_bridge_limits(
        &self,
        bridge_address: &[u8; 20],
        max_mint_per_tx: Option<u128>,
        max_burn_per_tx: Option<u128>,
        daily_mint_limit: Option<u128>,
        daily_burn_limit: Option<u128>,
    ) -> Result<()> {
        let mut entry = self
            .authorized_bridges
            .get_mut(bridge_address)
            .ok_or_else(|| TokenError::Unauthorized {
                reason: format!(
                    "Bridge 0x{} is not authorized",
                    hex::encode(bridge_address)
                ),
            })?;

        let auth = entry.value_mut();
        auth.max_mint_per_tx = max_mint_per_tx;
        auth.max_burn_per_tx = max_burn_per_tx;
        auth.daily_mint_limit = daily_mint_limit;
        auth.daily_burn_limit = daily_burn_limit;

        debug!(
            "Updated limits for bridge 0x{}",
            hex::encode(bridge_address)
        );
        Ok(())
    }

    /// Returns `true` if the bridge is authorized and enabled.
    pub fn is_bridge_authorized(&self, bridge_address: &[u8; 20]) -> bool {
        self.authorized_bridges
            .get(bridge_address)
            .map(|e| e.value().enabled)
            .unwrap_or(false)
    }

    /// Returns a serializable snapshot of the bridge's authorization record.
    pub fn get_bridge_info(&self, bridge_address: &[u8; 20]) -> Option<BridgeInfo> {
        self.authorized_bridges.get(bridge_address).map(|entry| {
            let auth = entry.value();
            BridgeInfo {
                bridge_address: format!("0x{}", hex::encode(auth.bridge_address)),
                name: auth.name.clone(),
                authorized_tokens: auth
                    .authorized_tokens
                    .iter()
                    .map(|t| t.to_hex())
                    .collect(),
                max_mint_per_tx: auth.max_mint_per_tx,
                max_burn_per_tx: auth.max_burn_per_tx,
                daily_mint_limit: auth.daily_mint_limit,
                daily_burn_limit: auth.daily_burn_limit,
                minted_today: auth.minted_today.load(),
                burned_today: auth.burned_today.load(),
                enabled: auth.enabled,
            }
        })
    }

    /// Resolves a bridge's `authorized_tokens` set into full
    /// [`TokenDefinition`] records via the unified token registry.
    ///
    /// Tokens that no longer exist in the registry are silently skipped,
    /// allowing operators to detect orphaned authorizations by length
    /// comparison against the bridge's raw `authorized_tokens` vector.
    pub fn resolve_authorized_tokens(
        &self,
        bridge_address: &[u8; 20],
    ) -> Vec<crate::TokenDefinition> {
        let entry = match self.authorized_bridges.get(bridge_address) {
            Some(e) => e,
            None => return Vec::new(),
        };
        entry
            .value()
            .authorized_tokens
            .iter()
            .filter_map(|tid| self.registry.get(tid))
            .collect()
    }

    /// Lists all currently authorized bridges.
    pub fn list_authorized_bridges(&self) -> Vec<BridgeInfo> {
        self.authorized_bridges
            .iter()
            .map(|entry| {
                let auth = entry.value();
                BridgeInfo {
                    bridge_address: format!("0x{}", hex::encode(auth.bridge_address)),
                    name: auth.name.clone(),
                    authorized_tokens: auth
                        .authorized_tokens
                        .iter()
                        .map(|t| t.to_hex())
                        .collect(),
                    max_mint_per_tx: auth.max_mint_per_tx,
                    max_burn_per_tx: auth.max_burn_per_tx,
                    daily_mint_limit: auth.daily_mint_limit,
                    daily_burn_limit: auth.daily_burn_limit,
                    minted_today: auth.minted_today.load(),
                    burned_today: auth.burned_today.load(),
                    enabled: auth.enabled,
                }
            })
            .collect()
    }

    // -- Core ERC-7802 operations --------------------------------------------

    /// Validates that a bridge is authorized and within limits for a given
    /// operation (mint or burn).
    fn validate_bridge(
        &self,
        bridge_address: &[u8; 20],
        amount: u128,
        is_mint: bool,
    ) -> Result<()> {
        let entry =
            self.authorized_bridges
                .get(bridge_address)
                .ok_or_else(|| TokenError::Unauthorized {
                    reason: format!(
                        "Bridge 0x{} is not authorized",
                        hex::encode(bridge_address)
                    ),
                })?;

        let auth = entry.value();

        if !auth.enabled {
            return Err(TokenError::Unauthorized {
                reason: format!(
                    "Bridge 0x{} is disabled",
                    hex::encode(bridge_address)
                ),
            });
        }

        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Cross-chain amount must be greater than zero".to_string(),
            ));
        }

        let now = chrono::Utc::now().timestamp();
        auth.maybe_reset_daily(now);

        if is_mint {
            // Per-tx limit
            if let Some(max) = auth.max_mint_per_tx
                && amount > max
            {
                return Err(TokenError::InvalidAmount(format!(
                    "Mint amount {} exceeds per-tx limit {}",
                    amount, max
                )));
            }
            // Daily limit
            if let Some(daily) = auth.daily_mint_limit {
                let already = auth.minted_today.load();
                if already.saturating_add(amount) > daily {
                    return Err(TokenError::InvalidAmount(format!(
                        "Mint amount {} would exceed daily limit {} (already minted {})",
                        amount, daily, already
                    )));
                }
            }
        } else {
            // Per-tx limit
            if let Some(max) = auth.max_burn_per_tx
                && amount > max
            {
                return Err(TokenError::InvalidAmount(format!(
                    "Burn amount {} exceeds per-tx limit {}",
                    amount, max
                )));
            }
            // Daily limit
            if let Some(daily) = auth.daily_burn_limit {
                let already = auth.burned_today.load();
                if already.saturating_add(amount) > daily {
                    return Err(TokenError::InvalidAmount(format!(
                        "Burn amount {} would exceed daily limit {} (already burned {})",
                        amount, daily, already
                    )));
                }
            }
        }

        Ok(())
    }

    /// Returns the current Unix timestamp in seconds.
    fn now_secs() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Mints tokens on this chain as part of a cross-chain transfer.
    ///
    /// The bridge must be authorized and within its per-tx and daily limits.
    /// Tokens are minted via `TnzoToken::mint()` using the treasury address as
    /// the authorized caller.
    ///
    /// # Arguments
    ///
    /// * `bridge` - 20-byte address of the calling bridge.
    /// * `to` - Recipient address on this chain.
    /// * `amount` - Amount to mint (smallest unit, 18 decimals).
    /// * `sender` - Opaque sender identifier on the source chain.
    pub fn crosschain_mint(
        &self,
        bridge: [u8; 20],
        to: Address,
        amount: u128,
        sender: Vec<u8>,
    ) -> Result<CrosschainMintEvent> {
        // 1. Validate bridge authorization and limits
        self.validate_bridge(&bridge, amount, true)?;

        // 2. Mint tokens via TnzoToken. The caller must be the treasury.
        let treasury = self
            .tnzo_token
            .treasury_address_ref()
            .ok_or_else(|| TokenError::Unauthorized {
                reason: "Treasury address not set; cannot mint cross-chain tokens".to_string(),
            })?;

        self.tnzo_token.mint(&to, amount, &treasury)?;

        // 3. Update daily tracking
        {
            let entry = self.authorized_bridges.get(&bridge).unwrap();
            entry.value().minted_today.fetch_add(amount);
        }

        // 4. Build and store event
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let event = CrosschainMintEvent {
            nonce,
            to,
            amount,
            sender,
            bridge,
            timestamp: Self::now_secs(),
        };

        info!(
            "crosschainMint: bridge=0x{} to={} amount={} nonce={}",
            hex::encode(bridge),
            to,
            amount,
            nonce
        );

        self.mint_events.insert(nonce, event.clone());
        Ok(event)
    }

    /// Burns tokens on this chain as part of a cross-chain transfer.
    ///
    /// The bridge must be authorized and within its per-tx and daily limits.
    /// Tokens are burned via `TnzoToken::burn()`.
    ///
    /// # Arguments
    ///
    /// * `bridge` - 20-byte address of the calling bridge.
    /// * `from` - Address whose tokens are burned.
    /// * `amount` - Amount to burn (smallest unit, 18 decimals).
    /// * `sender` - Opaque destination identifier on the target chain.
    pub fn crosschain_burn(
        &self,
        bridge: [u8; 20],
        from: Address,
        amount: u128,
        sender: Vec<u8>,
    ) -> Result<CrosschainBurnEvent> {
        // 1. Validate bridge authorization and limits
        self.validate_bridge(&bridge, amount, false)?;

        // 2. Burn tokens
        self.tnzo_token.burn(&from, amount)?;

        // 3. Update daily tracking
        {
            let entry = self.authorized_bridges.get(&bridge).unwrap();
            entry.value().burned_today.fetch_add(amount);
        }

        // 4. Build and store event
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let event = CrosschainBurnEvent {
            nonce,
            from,
            amount,
            sender,
            bridge,
            timestamp: Self::now_secs(),
        };

        info!(
            "crosschainBurn: bridge=0x{} from={} amount={} nonce={}",
            hex::encode(bridge),
            from,
            amount,
            nonce
        );

        self.burn_events.insert(nonce, event.clone());
        Ok(event)
    }

    // -- Event queries -------------------------------------------------------

    /// Returns all recorded mint events, newest first.
    pub fn get_mint_events(&self) -> Vec<CrosschainMintEvent> {
        let mut events: Vec<CrosschainMintEvent> = self
            .mint_events
            .iter()
            .map(|e| e.value().clone())
            .collect();
        events.sort_by_key(|e| Reverse(e.nonce));
        events
    }

    /// Returns all recorded burn events, newest first.
    pub fn get_burn_events(&self) -> Vec<CrosschainBurnEvent> {
        let mut events: Vec<CrosschainBurnEvent> = self
            .burn_events
            .iter()
            .map(|e| e.value().clone())
            .collect();
        events.sort_by_key(|e| Reverse(e.nonce));
        events
    }

    /// Returns a specific mint event by nonce.
    pub fn get_mint_event(&self, nonce: u64) -> Option<CrosschainMintEvent> {
        self.mint_events.get(&nonce).map(|e| e.value().clone())
    }

    /// Returns a specific burn event by nonce.
    pub fn get_burn_event(&self, nonce: u64) -> Option<CrosschainBurnEvent> {
        self.burn_events.get(&nonce).map(|e| e.value().clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tnzo::ONE_TNZO;

    /// Helper: creates a manager with a funded treasury and a single authorized bridge.
    fn setup() -> (CrosschainTokenManager, [u8; 20], Address) {
        let token = Arc::new(TnzoToken::new());
        let registry = Arc::new(TokenRegistry::new());

        // Set up treasury and pre-mint some tokens for burn tests
        let treasury = Address::new([0xAA; 32]);
        token.set_treasury_address(treasury);

        // Pre-mint supply so we can test minting and burning
        token
            .mint(&Address::new([0xBB; 32]), 1_000_000 * ONE_TNZO, &treasury)
            .unwrap();

        let mgr = CrosschainTokenManager::new(token, registry);

        let bridge: [u8; 20] = [0x01; 20];
        mgr.authorize_bridge(
            bridge,
            "TestBridge".to_string(),
            vec![],
            Some(10_000 * ONE_TNZO),
            Some(10_000 * ONE_TNZO),
            Some(100_000 * ONE_TNZO),
            Some(100_000 * ONE_TNZO),
        )
        .unwrap();

        (mgr, bridge, treasury)
    }

    #[test]
    fn test_authorize_bridge() {
        let token = Arc::new(TnzoToken::new());
        let registry = Arc::new(TokenRegistry::new());
        let mgr = CrosschainTokenManager::new(token, registry);

        let bridge: [u8; 20] = [0x42; 20];
        mgr.authorize_bridge(
            bridge,
            "MyBridge".to_string(),
            vec![],
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(mgr.is_bridge_authorized(&bridge));
        let info = mgr.get_bridge_info(&bridge).unwrap();
        assert_eq!(info.name, "MyBridge");
        assert!(info.enabled);
    }

    #[test]
    fn test_crosschain_mint_succeeds() {
        let (mgr, bridge, _treasury) = setup();

        let to = Address::new([0xCC; 32]);
        let event = mgr
            .crosschain_mint(bridge, to, 500 * ONE_TNZO, vec![1, 2, 3])
            .unwrap();

        assert_eq!(event.amount, 500 * ONE_TNZO);
        assert_eq!(event.to, to);
        assert_eq!(event.bridge, bridge);
        assert_eq!(mgr.tnzo_token.balance_of(&to), 500 * ONE_TNZO);
    }

    #[test]
    fn test_crosschain_mint_fails_unauthorized() {
        let (mgr, _bridge, _treasury) = setup();

        let rogue: [u8; 20] = [0xFF; 20];
        let to = Address::new([0xCC; 32]);
        let result = mgr.crosschain_mint(rogue, to, 100 * ONE_TNZO, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not authorized"));
    }

    #[test]
    fn test_crosschain_mint_per_tx_limit() {
        let (mgr, bridge, _treasury) = setup();

        // The per-tx mint limit is 10_000 TNZO
        let to = Address::new([0xCC; 32]);
        let result = mgr.crosschain_mint(bridge, to, 20_000 * ONE_TNZO, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exceeds per-tx limit"));
    }

    #[test]
    fn test_crosschain_mint_daily_limit() {
        let (mgr, bridge, _treasury) = setup();

        let to = Address::new([0xCC; 32]);

        // Mint up to close to the daily limit (100_000 TNZO) in 10_000-chunks
        for _ in 0..10 {
            mgr.crosschain_mint(bridge, to, 10_000 * ONE_TNZO, vec![])
                .unwrap();
        }

        // 100_000 already minted; next should fail
        let result = mgr.crosschain_mint(bridge, to, ONE_TNZO, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("daily limit"));
    }

    #[test]
    fn test_crosschain_burn_succeeds() {
        let (mgr, bridge, _treasury) = setup();

        // The pre-minted address has 1_000_000 TNZO
        let from = Address::new([0xBB; 32]);
        let event = mgr
            .crosschain_burn(bridge, from, 500 * ONE_TNZO, vec![4, 5, 6])
            .unwrap();

        assert_eq!(event.amount, 500 * ONE_TNZO);
        assert_eq!(event.from, from);
        assert_eq!(
            mgr.tnzo_token.balance_of(&from),
            999_500 * ONE_TNZO
        );
    }

    #[test]
    fn test_crosschain_burn_insufficient_balance() {
        let (mgr, bridge, _treasury) = setup();

        // Address with no balance
        let from = Address::new([0xDD; 32]);
        let result = mgr.crosschain_burn(bridge, from, 100 * ONE_TNZO, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Insufficient balance"));
    }

    #[test]
    fn test_crosschain_burn_per_tx_limit() {
        let (mgr, bridge, _treasury) = setup();

        let from = Address::new([0xBB; 32]);
        let result = mgr.crosschain_burn(bridge, from, 20_000 * ONE_TNZO, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exceeds per-tx limit"));
    }

    #[test]
    fn test_revoke_bridge() {
        let (mgr, bridge, _treasury) = setup();

        mgr.revoke_bridge(&bridge).unwrap();
        assert!(!mgr.is_bridge_authorized(&bridge));

        // Minting should fail now
        let to = Address::new([0xCC; 32]);
        let result = mgr.crosschain_mint(bridge, to, ONE_TNZO, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_tracking() {
        let (mgr, bridge, _treasury) = setup();

        let to = Address::new([0xCC; 32]);
        let from = Address::new([0xBB; 32]);

        let mint_evt = mgr
            .crosschain_mint(bridge, to, 100 * ONE_TNZO, vec![10])
            .unwrap();
        let burn_evt = mgr
            .crosschain_burn(bridge, from, 50 * ONE_TNZO, vec![20])
            .unwrap();

        let mints = mgr.get_mint_events();
        assert_eq!(mints.len(), 1);
        assert_eq!(mints[0].nonce, mint_evt.nonce);

        let burns = mgr.get_burn_events();
        assert_eq!(burns.len(), 1);
        assert_eq!(burns[0].nonce, burn_evt.nonce);

        // Lookup by nonce
        assert!(mgr.get_mint_event(mint_evt.nonce).is_some());
        assert!(mgr.get_burn_event(burn_evt.nonce).is_some());
        assert!(mgr.get_mint_event(999).is_none());
    }

    #[test]
    fn test_multiple_bridges() {
        let (mgr, bridge_a, _treasury) = setup();

        let bridge_b: [u8; 20] = [0x02; 20];
        mgr.authorize_bridge(
            bridge_b,
            "BridgeB".to_string(),
            vec![],
            Some(5_000 * ONE_TNZO),
            Some(5_000 * ONE_TNZO),
            None,
            None,
        )
        .unwrap();

        let to = Address::new([0xCC; 32]);

        // Both bridges should be able to mint independently
        mgr.crosschain_mint(bridge_a, to, 1_000 * ONE_TNZO, vec![])
            .unwrap();
        mgr.crosschain_mint(bridge_b, to, 2_000 * ONE_TNZO, vec![])
            .unwrap();

        assert_eq!(mgr.tnzo_token.balance_of(&to), 3_000 * ONE_TNZO);

        let bridges = mgr.list_authorized_bridges();
        assert_eq!(bridges.len(), 2);
    }

    #[test]
    fn test_crosschain_mint_zero_amount_rejected() {
        let (mgr, bridge, _treasury) = setup();

        let to = Address::new([0xCC; 32]);
        let result = mgr.crosschain_mint(bridge, to, 0, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("greater than zero"));
    }

    #[test]
    fn test_update_bridge_limits() {
        let (mgr, bridge, _treasury) = setup();

        mgr.update_bridge_limits(&bridge, Some(50_000 * ONE_TNZO), None, None, None)
            .unwrap();

        let info = mgr.get_bridge_info(&bridge).unwrap();
        assert_eq!(info.max_mint_per_tx, Some(50_000 * ONE_TNZO));
        // Burn limit was Some(10_000) but we passed None so it gets overwritten
        assert_eq!(info.max_burn_per_tx, None);
    }

    #[test]
    fn test_revoke_nonexistent_bridge_fails() {
        let (mgr, _bridge, _treasury) = setup();

        let fake: [u8; 20] = [0xFE; 20];
        let result = mgr.revoke_bridge(&fake);
        assert!(result.is_err());
    }

    #[test]
    fn test_daily_burn_limit() {
        let token = Arc::new(TnzoToken::new());
        let registry = Arc::new(TokenRegistry::new());

        let treasury = Address::new([0xAA; 32]);
        token.set_treasury_address(treasury);

        // Give the burn source a large balance
        let from = Address::new([0xBB; 32]);
        token.mint(&from, 10_000_000 * ONE_TNZO, &treasury).unwrap();

        let mgr = CrosschainTokenManager::new(token, registry);

        let bridge: [u8; 20] = [0x05; 20];
        mgr.authorize_bridge(
            bridge,
            "LimitedBridge".to_string(),
            vec![],
            None,
            Some(5_000 * ONE_TNZO),
            None,
            Some(10_000 * ONE_TNZO), // daily burn limit
        )
        .unwrap();

        // Burn twice at 5_000 each = 10_000 total
        mgr.crosschain_burn(bridge, from, 5_000 * ONE_TNZO, vec![])
            .unwrap();
        mgr.crosschain_burn(bridge, from, 5_000 * ONE_TNZO, vec![])
            .unwrap();

        // Third burn should fail
        let result = mgr.crosschain_burn(bridge, from, ONE_TNZO, vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("daily limit"));
    }
}
