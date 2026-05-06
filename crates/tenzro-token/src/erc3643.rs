//! ERC-3643 T-REX Compliance Module
//!
//! Implements global dynamic compliance for tokenized assets (RWA/security tokens).
//! Transfer rules are checked against on-chain identity claims at runtime.
//! Integrates with Tenzro's TDIP identity system for KYC and accreditation verification.
//!
//! See: https://www.erc3643.org/

use crate::cross_vm::TokenId;
use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tenzro_types::primitives::Address;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Claim topic constants
// ---------------------------------------------------------------------------

/// Claim topic: KYC verification.
pub const CLAIM_TOPIC_KYC: u64 = 1;
/// Claim topic: Accredited investor status.
pub const CLAIM_TOPIC_ACCREDITED_INVESTOR: u64 = 2;
/// Claim topic: Country of residence / tax domicile.
pub const CLAIM_TOPIC_COUNTRY: u64 = 3;
/// Claim topic: Qualified purchaser status.
pub const CLAIM_TOPIC_QUALIFIED_PURCHASER: u64 = 4;

// ---------------------------------------------------------------------------
// Violation types
// ---------------------------------------------------------------------------

/// Reason why a transfer was rejected by the compliance module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceViolation {
    /// Sender or receiver does not meet the minimum KYC tier.
    InsufficientKyc {
        address: String,
        required_tier: u8,
        actual_tier: Option<u8>,
    },
    /// Sender or receiver is not accredited.
    NotAccredited { address: String },
    /// The country of the sender or receiver is restricted.
    CountryRestricted { address: String, country_code: u16 },
    /// The address is frozen for this token.
    AddressFrozen { address: String, reason: String },
    /// The transfer amount exceeds the per-transfer limit.
    AmountExceedsLimit { amount: u128, limit: u128 },
    /// The holding period has not elapsed since the receiver acquired tokens.
    HoldingPeriodNotMet {
        address: String,
        required_secs: u64,
        elapsed_secs: u64,
    },
    /// The token has reached its maximum number of holders.
    MaxHoldersReached { max: u64, current: u64 },
    /// The address is not on the whitelist.
    NotWhitelisted { address: String },
    /// The token is globally paused.
    TokenPaused,
}

impl std::fmt::Display for ComplianceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientKyc {
                address,
                required_tier,
                actual_tier,
            } => write!(
                f,
                "Insufficient KYC for {}: required tier {}, actual {:?}",
                address, required_tier, actual_tier
            ),
            Self::NotAccredited { address } => {
                write!(f, "Address {} is not accredited", address)
            }
            Self::CountryRestricted {
                address,
                country_code,
            } => write!(
                f,
                "Country {} restricted for address {}",
                country_code, address
            ),
            Self::AddressFrozen { address, reason } => {
                write!(f, "Address {} is frozen: {}", address, reason)
            }
            Self::AmountExceedsLimit { amount, limit } => {
                write!(f, "Amount {} exceeds limit {}", amount, limit)
            }
            Self::HoldingPeriodNotMet {
                address,
                required_secs,
                elapsed_secs,
            } => write!(
                f,
                "Holding period not met for {}: required {}s, elapsed {}s",
                address, required_secs, elapsed_secs
            ),
            Self::MaxHoldersReached { max, current } => {
                write!(f, "Max holders reached: {} / {}", current, max)
            }
            Self::NotWhitelisted { address } => {
                write!(f, "Address {} is not whitelisted", address)
            }
            Self::TokenPaused => write!(f, "Token transfers are paused"),
        }
    }
}

// ---------------------------------------------------------------------------
// ComplianceCheckResult
// ---------------------------------------------------------------------------

/// Result of a `can_transfer` compliance check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    /// Whether the transfer is compliant.
    pub compliant: bool,
    /// List of violations found (empty when compliant).
    pub violations: Vec<ComplianceViolation>,
    /// Names of the rules that were evaluated.
    pub checked_rules: Vec<String>,
}

impl ComplianceCheckResult {
    fn new() -> Self {
        Self {
            compliant: true,
            violations: Vec::new(),
            checked_rules: Vec::new(),
        }
    }

    fn add_violation(&mut self, v: ComplianceViolation) {
        self.compliant = false;
        self.violations.push(v);
    }

    fn add_rule(&mut self, name: &str) {
        self.checked_rules.push(name.to_string());
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Identity claim attached to an address (mirrors ERC-735 claim structure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// Claim topic identifier (see `CLAIM_TOPIC_*` constants).
    pub topic: u64,
    /// Signature scheme (1 = ECDSA, 2 = RSA).
    pub scheme: u64,
    /// DID of the issuer that signed this claim.
    pub issuer: String,
    /// Cryptographic signature over the claim data.
    pub signature: Vec<u8>,
    /// Claim payload (topic-specific encoding).
    pub data: Vec<u8>,
    /// Optional URI for off-chain claim storage.
    pub uri: String,
    /// Unix timestamp from which the claim is valid.
    pub valid_from: i64,
    /// Unix timestamp at which the claim expires.
    pub valid_to: i64,
}

impl IdentityClaim {
    /// Returns `true` if the claim is currently within its validity window.
    pub fn is_valid(&self, now: i64) -> bool {
        now >= self.valid_from && now < self.valid_to
    }

    /// Extracts the KYC tier from the claim data (topic must be `CLAIM_TOPIC_KYC`).
    /// The tier is stored as the first byte of `data`.
    pub fn kyc_tier(&self) -> Option<u8> {
        if self.topic == CLAIM_TOPIC_KYC {
            self.data.first().copied()
        } else {
            None
        }
    }

    /// Extracts the ISO 3166-1 numeric country code from the claim data.
    /// Stored as a little-endian u16 in the first two bytes.
    pub fn country_code(&self) -> Option<u16> {
        if self.topic == CLAIM_TOPIC_COUNTRY && self.data.len() >= 2 {
            Some(u16::from_le_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }
}

/// A trusted claim issuer registered with the compliance module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedIssuer {
    /// DID of the issuer.
    pub issuer_did: String,
    /// Claim topics this issuer is trusted for.
    pub trusted_topics: Vec<u64>,
    /// Human-readable name.
    pub name: String,
    /// Whether this issuer is currently active.
    pub enabled: bool,
}

/// Claim topic metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTopicInfo {
    pub topic_id: u64,
    pub name: String,
    pub description: String,
}

/// Whitelist entry for an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    /// Unix timestamp when the address was whitelisted.
    pub added_at: i64,
    /// Who added the entry (admin DID or address).
    pub added_by: String,
}

/// Information about a frozen address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeInfo {
    /// Reason the address was frozen.
    pub reason: String,
    /// Unix timestamp when the freeze was applied.
    pub frozen_at: i64,
    /// Who froze the address.
    pub frozen_by: String,
}

/// Event emitted when tokens are forcibly recovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEvent {
    pub token_id: TokenId,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub reason: String,
    pub timestamp: i64,
}

/// Supply limits for a compliant token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupplyLimits {
    /// Maximum total supply that may be minted.
    pub max_supply: Option<u128>,
    /// Minimum tokens that must remain in circulation.
    pub min_supply: Option<u128>,
}

/// Transfer restriction rules for a compliant token.
#[derive(Debug, Clone)]
pub struct TransferRestrictions {
    /// Maximum amount per individual transfer.
    pub max_transfer_amount: Option<u128>,
    /// Minimum holding period (seconds) before tokens can be transferred out.
    pub min_holding_period_secs: Option<u64>,
    /// Whether only whitelisted addresses may hold the token.
    pub require_whitelist: bool,
    /// Per-token whitelist of addresses.
    pub whitelist: DashMap<Address, WhitelistEntry>,
    /// Whether country-of-residence checks are enforced.
    pub country_check: bool,
    /// Whether cross-border transfers are allowed.
    pub allow_cross_border: bool,
}

impl Default for TransferRestrictions {
    fn default() -> Self {
        Self {
            max_transfer_amount: None,
            min_holding_period_secs: None,
            require_whitelist: false,
            whitelist: DashMap::new(),
            country_check: false,
            allow_cross_border: true,
        }
    }
}

/// Full compliance rule set for a single token.
pub struct ComplianceRules {
    /// Token this rule set applies to.
    pub token_id: TokenId,
    /// Whether holders must have a valid KYC claim.
    pub require_kyc: bool,
    /// Minimum KYC tier required (maps to `tenzro_identity::KycTier`).
    pub min_kyc_tier: u8,
    /// Whether holders must be accredited investors.
    pub require_accreditation: bool,
    /// Maximum number of unique holders (Reg D / Reg S cap).
    pub max_holders: Option<u64>,
    /// Current unique holder count.
    current_holders: AtomicU64,
    /// Transfer restriction rules.
    pub transfer_restrictions: TransferRestrictions,
    /// Supply limits.
    pub supply_limits: SupplyLimits,
    /// Whether all transfers for this token are paused.
    pub paused: bool,
}

impl ComplianceRules {
    /// Creates a new rule set with sensible defaults (nothing enforced).
    pub fn new(token_id: TokenId) -> Self {
        Self {
            token_id,
            require_kyc: false,
            min_kyc_tier: 0,
            require_accreditation: false,
            max_holders: None,
            current_holders: AtomicU64::new(0),
            transfer_restrictions: TransferRestrictions::default(),
            supply_limits: SupplyLimits::default(),
            paused: false,
        }
    }

    /// Builder: require KYC with minimum tier.
    pub fn with_kyc(mut self, min_tier: u8) -> Self {
        self.require_kyc = true;
        self.min_kyc_tier = min_tier;
        self
    }

    /// Builder: require accredited investor claim.
    pub fn with_accreditation(mut self) -> Self {
        self.require_accreditation = true;
        self
    }

    /// Builder: cap the number of unique holders.
    pub fn with_max_holders(mut self, max: u64) -> Self {
        self.max_holders = Some(max);
        self
    }

    /// Builder: set a per-transfer amount limit.
    pub fn with_max_transfer_amount(mut self, max: u128) -> Self {
        self.transfer_restrictions.max_transfer_amount = Some(max);
        self
    }

    /// Builder: require whitelist.
    pub fn with_whitelist(mut self) -> Self {
        self.transfer_restrictions.require_whitelist = true;
        self
    }

    /// Builder: enforce country checks.
    pub fn with_country_check(mut self) -> Self {
        self.transfer_restrictions.country_check = true;
        self
    }

    /// Builder: set minimum holding period.
    pub fn with_holding_period(mut self, secs: u64) -> Self {
        self.transfer_restrictions.min_holding_period_secs = Some(secs);
        self
    }

    /// Returns the current holder count.
    pub fn holder_count(&self) -> u64 {
        self.current_holders.load(Ordering::Relaxed)
    }

    /// Increments the holder count by one. Returns the new count.
    pub fn increment_holders(&self) -> u64 {
        self.current_holders.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrements the holder count by one (saturating at zero).
    pub fn decrement_holders(&self) {
        let _ = self
            .current_holders
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

// ---------------------------------------------------------------------------
// ComplianceRegistry
// ---------------------------------------------------------------------------

/// Central compliance registry for all ERC-3643-governed tokens.
///
/// This registry stores per-token compliance rules, identity claims for
/// addresses, trusted issuers, frozen addresses, and country restrictions.
/// The primary entry point is [`can_transfer`], which evaluates all applicable
/// rules and returns a detailed [`ComplianceCheckResult`].
pub struct ComplianceRegistry {
    /// Per-token compliance rules.
    token_compliance: DashMap<TokenId, ComplianceRules>,
    /// Identity claims per address.
    identity_claims: DashMap<Address, Vec<IdentityClaim>>,
    /// Trusted claim issuers.
    trusted_issuers: DashMap<String, TrustedIssuer>,
    /// Claim topic metadata, governance-managed (`register_claim_topic` /
    /// `list_claim_topics` / `get_claim_topic`).
    claim_topics: DashMap<u64, ClaimTopicInfo>,
    /// Frozen address set: (token_id, address) -> freeze info.
    frozen_addresses: DashMap<(TokenId, Address), FreezeInfo>,
    /// Country allowlist per token: (token_id, country_code) -> allowed.
    country_restrictions: DashMap<(TokenId, u16), bool>,
    /// Timestamp of first token receipt per (address, token_id) for holding
    /// period enforcement.
    first_receipt: DashMap<(Address, TokenId), i64>,
    /// Token balances tracked by the compliance module (shadow of on-chain
    /// state) for holder-count and holding-period tracking.
    balances: DashMap<(Address, TokenId), u128>,
    /// Recovery event log.
    recovery_events: DashMap<u64, RecoveryEvent>,
    /// Monotonic nonce for recovery events.
    recovery_nonce: AtomicU64,
}

impl ComplianceRegistry {
    /// Creates a new empty compliance registry.
    pub fn new() -> Self {
        Self {
            token_compliance: DashMap::new(),
            identity_claims: DashMap::new(),
            trusted_issuers: DashMap::new(),
            claim_topics: DashMap::new(),
            frozen_addresses: DashMap::new(),
            country_restrictions: DashMap::new(),
            first_receipt: DashMap::new(),
            balances: DashMap::new(),
            recovery_events: DashMap::new(),
            recovery_nonce: AtomicU64::new(1),
        }
    }

    /// Returns the current Unix timestamp in seconds.
    fn now_secs() -> i64 {
        chrono::Utc::now().timestamp()
    }

    // -- Rule management -----------------------------------------------------

    /// Registers (or replaces) the compliance rules for a token.
    pub fn register_compliance(&self, rules: ComplianceRules) {
        info!(
            "Registered compliance rules for token {}",
            rules.token_id.to_hex()
        );
        self.token_compliance.insert(rules.token_id, rules);
    }

    /// Returns `true` if a compliance rule set is registered for the token.
    pub fn has_compliance(&self, token_id: &TokenId) -> bool {
        self.token_compliance.contains_key(token_id)
    }

    // -- Identity claims -----------------------------------------------------

    /// Adds an identity claim for a given address.
    pub fn add_identity_claim(&self, address: Address, claim: IdentityClaim) {
        debug!(
            "Adding claim topic {} for address {} from issuer {}",
            claim.topic, address, claim.issuer
        );
        self.identity_claims
            .entry(address)
            .or_default()
            .push(claim);
    }

    /// Returns `true` if the address holds a valid claim for the given topic
    /// issued by a trusted issuer.
    pub fn verify_claim(&self, address: &Address, topic: u64) -> bool {
        let now = Self::now_secs();
        let claims = match self.identity_claims.get(address) {
            Some(c) => c,
            None => return false,
        };

        claims.iter().any(|c| {
            c.topic == topic
                && c.is_valid(now)
                && self.is_trusted_issuer_for_topic(&c.issuer, topic)
        })
    }

    /// Returns the best (highest) KYC tier that the address holds via a valid,
    /// trusted claim.
    fn effective_kyc_tier(&self, address: &Address) -> Option<u8> {
        let now = Self::now_secs();
        let claims = self.identity_claims.get(address)?;
        claims
            .iter()
            .filter(|c| {
                c.topic == CLAIM_TOPIC_KYC
                    && c.is_valid(now)
                    && self.is_trusted_issuer_for_topic(&c.issuer, CLAIM_TOPIC_KYC)
            })
            .filter_map(|c| c.kyc_tier())
            .max()
    }

    /// Returns the country code from the address's valid country claim.
    fn effective_country(&self, address: &Address) -> Option<u16> {
        let now = Self::now_secs();
        let claims = self.identity_claims.get(address)?;
        claims
            .iter()
            .filter(|c| {
                c.topic == CLAIM_TOPIC_COUNTRY
                    && c.is_valid(now)
                    && self.is_trusted_issuer_for_topic(&c.issuer, CLAIM_TOPIC_COUNTRY)
            })
            .filter_map(|c| c.country_code())
            .next()
    }

    // -- Trusted issuers -----------------------------------------------------

    /// Registers a trusted claim issuer.
    pub fn add_trusted_issuer(&self, issuer: TrustedIssuer) {
        info!(
            "Added trusted issuer {} ({}) for topics {:?}",
            issuer.issuer_did, issuer.name, issuer.trusted_topics
        );
        self.trusted_issuers
            .insert(issuer.issuer_did.clone(), issuer);
    }

    /// Returns `true` if the issuer is trusted for the given claim topic.
    fn is_trusted_issuer_for_topic(&self, issuer_did: &str, topic: u64) -> bool {
        self.trusted_issuers
            .get(issuer_did)
            .map(|i| i.enabled && i.trusted_topics.contains(&topic))
            .unwrap_or(false)
    }

    // -- Claim topics --------------------------------------------------------

    /// Registers (or replaces) metadata for a claim topic.
    ///
    /// ERC-3643 claim topics are governance-managed identifiers that
    /// describe what a claim asserts (e.g. KYC tier, accredited investor
    /// status, country of residence).
    pub fn register_claim_topic(&self, info: ClaimTopicInfo) {
        info!(
            "Registered claim topic {}: {}",
            info.topic_id, info.name
        );
        self.claim_topics.insert(info.topic_id, info);
    }

    /// Returns metadata for a registered claim topic.
    pub fn get_claim_topic(&self, topic_id: u64) -> Option<ClaimTopicInfo> {
        self.claim_topics.get(&topic_id).map(|e| e.clone())
    }

    /// Lists all registered claim topics.
    pub fn list_claim_topics(&self) -> Vec<ClaimTopicInfo> {
        self.claim_topics
            .iter()
            .map(|e| e.value().clone())
            .collect()
    }

    // -- Freeze / unfreeze ---------------------------------------------------

    /// Freezes an address for a specific token.
    pub fn freeze_address(
        &self,
        token_id: TokenId,
        address: Address,
        reason: String,
        frozen_by: String,
    ) {
        info!(
            "Freezing address {} for token {}: {}",
            address,
            token_id.to_hex(),
            reason
        );
        self.frozen_addresses.insert(
            (token_id, address),
            FreezeInfo {
                reason,
                frozen_at: Self::now_secs(),
                frozen_by,
            },
        );
    }

    /// Unfreezes an address for a specific token.
    pub fn unfreeze_address(&self, token_id: &TokenId, address: &Address) {
        info!(
            "Unfreezing address {} for token {}",
            address,
            token_id.to_hex()
        );
        self.frozen_addresses.remove(&(*token_id, *address));
    }

    /// Returns `true` if the address is frozen for the given token.
    pub fn is_frozen(&self, token_id: &TokenId, address: &Address) -> bool {
        self.frozen_addresses.contains_key(&(*token_id, *address))
    }

    // -- Country restrictions ------------------------------------------------

    /// Sets whether a country is allowed for a specific token.
    pub fn set_country_restriction(&self, token_id: TokenId, country_code: u16, allowed: bool) {
        debug!(
            "Setting country {} {} for token {}",
            country_code,
            if allowed { "allowed" } else { "restricted" },
            token_id.to_hex()
        );
        self.country_restrictions
            .insert((token_id, country_code), allowed);
    }

    /// Returns `true` if the address's country is allowed (or no country
    /// restrictions are configured for the token).
    pub fn check_country(&self, token_id: &TokenId, address: &Address) -> bool {
        let country = match self.effective_country(address) {
            Some(c) => c,
            // No country claim -- the `can_transfer` caller decides via the
            // ComplianceViolation whether this is acceptable.
            None => return true,
        };

        self.country_restrictions
            .get(&(*token_id, country))
            .map(|v| *v)
            .unwrap_or(true) // default: allowed when no explicit entry exists
    }

    // -- Whitelist -----------------------------------------------------------

    /// Adds an address to the token's whitelist.
    pub fn add_to_whitelist(
        &self,
        token_id: &TokenId,
        address: Address,
        added_by: String,
    ) -> Result<()> {
        let entry = self
            .token_compliance
            .get(token_id)
            .ok_or_else(|| TokenError::AssetNotFound {
                asset_id: token_id.to_hex(),
            })?;

        entry.value().transfer_restrictions.whitelist.insert(
            address,
            WhitelistEntry {
                added_at: Self::now_secs(),
                added_by,
            },
        );
        debug!("Whitelisted {} for token {}", address, token_id.to_hex());
        Ok(())
    }

    /// Removes an address from the token's whitelist.
    pub fn remove_from_whitelist(
        &self,
        token_id: &TokenId,
        address: &Address,
    ) -> Result<()> {
        let entry = self
            .token_compliance
            .get(token_id)
            .ok_or_else(|| TokenError::AssetNotFound {
                asset_id: token_id.to_hex(),
            })?;

        entry.value().transfer_restrictions.whitelist.remove(address);
        Ok(())
    }

    // -- Balance shadow (for holder count / holding period) -------------------

    /// Records a token receipt for holding-period and holder-count tracking.
    /// Called by the settlement layer after a successful transfer.
    pub fn record_receipt(
        &self,
        token_id: &TokenId,
        address: Address,
        amount: u128,
    ) {
        let key = (address, *token_id);
        let was_zero = self
            .balances
            .get(&key)
            .map(|v| *v == 0)
            .unwrap_or(true);

        // Update balance
        self.balances
            .entry(key)
            .and_modify(|b| *b = b.saturating_add(amount))
            .or_insert(amount);

        // Track first receipt timestamp
        if was_zero {
            self.first_receipt
                .entry((address, *token_id))
                .or_insert_with(Self::now_secs);

            // Increment holder count
            if let Some(rules) = self.token_compliance.get(token_id) {
                rules.increment_holders();
            }
        }
    }

    /// Records a token send for holder-count tracking.
    pub fn record_send(
        &self,
        token_id: &TokenId,
        address: Address,
        amount: u128,
    ) {
        let key = (address, *token_id);
        let mut became_zero = false;

        self.balances.entry(key).and_modify(|b| {
            *b = b.saturating_sub(amount);
            if *b == 0 {
                became_zero = true;
            }
        });

        if became_zero {
            self.first_receipt.remove(&(address, *token_id));
            if let Some(rules) = self.token_compliance.get(token_id) {
                rules.decrement_holders();
            }
        }
    }

    // -- Forced recovery -----------------------------------------------------

    /// Forcibly transfers tokens from one address to another for compliance
    /// reasons (e.g., lost keys, court order).
    ///
    /// This bypasses normal compliance checks but logs a `RecoveryEvent`.
    pub fn recover_tokens(
        &self,
        token_id: TokenId,
        from: Address,
        to: Address,
        amount: u128,
        reason: String,
    ) -> Result<RecoveryEvent> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Recovery amount must be greater than zero".to_string(),
            ));
        }

        // Verify the `from` address has sufficient shadow balance.
        let from_key = (from, token_id);
        let from_balance = self.balances.get(&from_key).map(|v| *v).unwrap_or(0);

        if from_balance < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: from_balance,
            });
        }

        // Move shadow balances
        self.record_send(&token_id, from, amount);
        self.record_receipt(&token_id, to, amount);

        let nonce = self.recovery_nonce.fetch_add(1, Ordering::Relaxed);
        let event = RecoveryEvent {
            token_id,
            from,
            to,
            amount,
            reason: reason.clone(),
            timestamp: Self::now_secs(),
        };

        warn!(
            "RECOVERY: {} tokens of {} transferred from {} to {}: {}",
            amount,
            token_id.to_hex(),
            from,
            to,
            reason
        );

        self.recovery_events.insert(nonce, event.clone());
        Ok(event)
    }

    // -- Core compliance check -----------------------------------------------

    /// The primary compliance gate. Evaluates all registered rules for the
    /// given token and returns a detailed result.
    ///
    /// # Arguments
    ///
    /// * `token_id` - Token being transferred.
    /// * `from` - Sender address.
    /// * `to` - Receiver address.
    /// * `amount` - Transfer amount (smallest unit).
    pub fn can_transfer(
        &self,
        token_id: &TokenId,
        from: &Address,
        to: &Address,
        amount: u128,
    ) -> Result<ComplianceCheckResult> {
        let rules = self
            .token_compliance
            .get(token_id)
            .ok_or_else(|| TokenError::AssetNotFound {
                asset_id: token_id.to_hex(),
            })?;

        let mut result = ComplianceCheckResult::new();

        // 1. Token paused check
        result.add_rule("token_paused");
        if rules.paused {
            result.add_violation(ComplianceViolation::TokenPaused);
        }

        // 2. Frozen address check (both sender and receiver)
        result.add_rule("frozen_address");
        if let Some(info) = self.frozen_addresses.get(&(*token_id, *from)) {
            result.add_violation(ComplianceViolation::AddressFrozen {
                address: from.to_string(),
                reason: info.reason.clone(),
            });
        }
        if let Some(info) = self.frozen_addresses.get(&(*token_id, *to)) {
            result.add_violation(ComplianceViolation::AddressFrozen {
                address: to.to_string(),
                reason: info.reason.clone(),
            });
        }

        // 3. KYC check (both sender and receiver)
        if rules.require_kyc {
            result.add_rule("kyc_tier");
            let min_tier = rules.min_kyc_tier;

            for addr in [from, to] {
                let tier = self.effective_kyc_tier(addr);
                match tier {
                    Some(t) if t >= min_tier => { /* ok */ }
                    _ => {
                        result.add_violation(ComplianceViolation::InsufficientKyc {
                            address: addr.to_string(),
                            required_tier: min_tier,
                            actual_tier: tier,
                        });
                    }
                }
            }
        }

        // 4. Accreditation check
        if rules.require_accreditation {
            result.add_rule("accreditation");
            for addr in [from, to] {
                if !self.verify_claim(addr, CLAIM_TOPIC_ACCREDITED_INVESTOR) {
                    result.add_violation(ComplianceViolation::NotAccredited {
                        address: addr.to_string(),
                    });
                }
            }
        }

        // 5. Country restriction check
        if rules.transfer_restrictions.country_check {
            result.add_rule("country_restriction");
            for addr in [from, to] {
                if let Some(country) = self.effective_country(addr) {
                    let allowed = self
                        .country_restrictions
                        .get(&(*token_id, country))
                        .map(|v| *v)
                        .unwrap_or(true);

                    if !allowed {
                        result.add_violation(ComplianceViolation::CountryRestricted {
                            address: addr.to_string(),
                            country_code: country,
                        });
                    }
                }
            }
        }

        // 6. Transfer amount limit
        if let Some(max) = rules.transfer_restrictions.max_transfer_amount {
            result.add_rule("max_transfer_amount");
            if amount > max {
                result.add_violation(ComplianceViolation::AmountExceedsLimit {
                    amount,
                    limit: max,
                });
            }
        }

        // 7. Whitelist check
        if rules.transfer_restrictions.require_whitelist {
            result.add_rule("whitelist");
            for addr in [from, to] {
                if !rules.transfer_restrictions.whitelist.contains_key(addr) {
                    result.add_violation(ComplianceViolation::NotWhitelisted {
                        address: addr.to_string(),
                    });
                }
            }
        }

        // 8. Holding period check (sender only)
        if let Some(min_secs) = rules.transfer_restrictions.min_holding_period_secs {
            result.add_rule("holding_period");
            let now = Self::now_secs();
            if let Some(first) = self.first_receipt.get(&(*from, *token_id)) {
                let elapsed = (now - *first).max(0) as u64;
                if elapsed < min_secs {
                    result.add_violation(ComplianceViolation::HoldingPeriodNotMet {
                        address: from.to_string(),
                        required_secs: min_secs,
                        elapsed_secs: elapsed,
                    });
                }
            }
            // If no first_receipt, the sender has never received tokens, so
            // the transfer will fail at the balance check anyway.
        }

        // 9. Max holders check (receiver only, if they don't already hold)
        if let Some(max) = rules.max_holders {
            result.add_rule("max_holders");
            let to_key = (*to, *token_id);
            let to_balance = self.balances.get(&to_key).map(|v| *v).unwrap_or(0);
            if to_balance == 0 {
                // This would be a new holder
                let current = rules.holder_count();
                if current >= max {
                    result.add_violation(ComplianceViolation::MaxHoldersReached {
                        max,
                        current,
                    });
                }
            }
        }

        Ok(result)
    }
}

impl Default for ComplianceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tnzo::ONE_TNZO;

    /// Helper: a token ID for testing.
    fn test_token() -> TokenId {
        TokenId::new([0x42; 32])
    }

    /// Helper: creates a claim with the given topic, issuer, tier, and validity window.
    fn make_kyc_claim(issuer: &str, tier: u8, valid_from: i64, valid_to: i64) -> IdentityClaim {
        IdentityClaim {
            topic: CLAIM_TOPIC_KYC,
            scheme: 1,
            issuer: issuer.to_string(),
            signature: vec![0xAA; 64],
            data: vec![tier],
            uri: String::new(),
            valid_from,
            valid_to,
        }
    }

    fn make_accreditation_claim(issuer: &str, valid_from: i64, valid_to: i64) -> IdentityClaim {
        IdentityClaim {
            topic: CLAIM_TOPIC_ACCREDITED_INVESTOR,
            scheme: 1,
            issuer: issuer.to_string(),
            signature: vec![0xBB; 64],
            data: vec![1],
            uri: String::new(),
            valid_from,
            valid_to,
        }
    }

    fn make_country_claim(issuer: &str, country: u16, valid_from: i64, valid_to: i64) -> IdentityClaim {
        IdentityClaim {
            topic: CLAIM_TOPIC_COUNTRY,
            scheme: 1,
            issuer: issuer.to_string(),
            signature: vec![0xCC; 64],
            data: country.to_le_bytes().to_vec(),
            uri: String::new(),
            valid_from,
            valid_to,
        }
    }

    fn trusted_issuer(did: &str, topics: Vec<u64>) -> TrustedIssuer {
        TrustedIssuer {
            issuer_did: did.to_string(),
            trusted_topics: topics,
            name: "TestIssuer".to_string(),
            enabled: true,
        }
    }

    /// Setup: registry with a token that requires KYC tier 2.
    fn setup_kyc_registry() -> (ComplianceRegistry, Address, Address) {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(
            ComplianceRules::new(token).with_kyc(2),
        );

        reg.add_trusted_issuer(trusted_issuer(
            "did:tenzro:human:issuer1",
            vec![CLAIM_TOPIC_KYC, CLAIM_TOPIC_ACCREDITED_INVESTOR, CLAIM_TOPIC_COUNTRY],
        ));

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let now = chrono::Utc::now().timestamp();

        // Both addresses have KYC tier 3 (satisfies tier 2 requirement)
        reg.add_identity_claim(from, make_kyc_claim("did:tenzro:human:issuer1", 3, now - 1000, now + 100_000));
        reg.add_identity_claim(to, make_kyc_claim("did:tenzro:human:issuer1", 3, now - 1000, now + 100_000));

        (reg, from, to)
    }

    #[test]
    fn test_register_compliance() {
        let reg = ComplianceRegistry::new();
        let token = test_token();
        assert!(!reg.has_compliance(&token));

        reg.register_compliance(ComplianceRules::new(token));
        assert!(reg.has_compliance(&token));
    }

    #[test]
    fn test_can_transfer_passes() {
        let (reg, from, to) = setup_kyc_registry();
        let token = test_token();

        let result = reg.can_transfer(&token, &from, &to, 100 * ONE_TNZO).unwrap();
        assert!(result.compliant);
        assert!(result.violations.is_empty());
        assert!(result.checked_rules.contains(&"kyc_tier".to_string()));
    }

    #[test]
    fn test_insufficient_kyc_blocks() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(ComplianceRules::new(token).with_kyc(2));
        reg.add_trusted_issuer(trusted_issuer(
            "did:tenzro:human:issuer1",
            vec![CLAIM_TOPIC_KYC],
        ));

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let now = chrono::Utc::now().timestamp();

        // `from` has tier 1 (below required 2)
        reg.add_identity_claim(from, make_kyc_claim("did:tenzro:human:issuer1", 1, now - 100, now + 100_000));
        // `to` has tier 2 (exactly meets requirement)
        reg.add_identity_claim(to, make_kyc_claim("did:tenzro:human:issuer1", 2, now - 100, now + 100_000));

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 1);
        assert!(matches!(
            &result.violations[0],
            ComplianceViolation::InsufficientKyc { actual_tier: Some(1), .. }
        ));
    }

    #[test]
    fn test_frozen_address_blocks() {
        let (reg, from, to) = setup_kyc_registry();
        let token = test_token();

        reg.freeze_address(token, from, "Suspicious activity".to_string(), "admin".to_string());
        assert!(reg.is_frozen(&token, &from));

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(v, ComplianceViolation::AddressFrozen { .. })));

        // Unfreeze and retry
        reg.unfreeze_address(&token, &from);
        assert!(!reg.is_frozen(&token, &from));
        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_country_restriction_blocks() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(ComplianceRules::new(token).with_country_check());
        reg.add_trusted_issuer(trusted_issuer(
            "did:tenzro:human:issuer1",
            vec![CLAIM_TOPIC_COUNTRY],
        ));

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let now = chrono::Utc::now().timestamp();

        // US = 840, restricted
        reg.add_identity_claim(from, make_country_claim("did:tenzro:human:issuer1", 840, now - 100, now + 100_000));
        reg.add_identity_claim(to, make_country_claim("did:tenzro:human:issuer1", 276, now - 100, now + 100_000)); // Germany

        reg.set_country_restriction(token, 840, false); // US not allowed
        reg.set_country_restriction(token, 276, true);  // Germany allowed

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(
            v,
            ComplianceViolation::CountryRestricted { country_code: 840, .. }
        )));
    }

    #[test]
    fn test_amount_limit_blocks() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(
            ComplianceRules::new(token).with_max_transfer_amount(1_000 * ONE_TNZO),
        );

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let result = reg
            .can_transfer(&token, &from, &to, 2_000 * ONE_TNZO)
            .unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(
            v,
            ComplianceViolation::AmountExceedsLimit { .. }
        )));

        // Under limit passes
        let result = reg
            .can_transfer(&token, &from, &to, 500 * ONE_TNZO)
            .unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_whitelist_enforcement() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(ComplianceRules::new(token).with_whitelist());

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        // Neither address is whitelisted
        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(v, ComplianceViolation::NotWhitelisted { .. })));

        // Whitelist both
        reg.add_to_whitelist(&token, from, "admin".to_string()).unwrap();
        reg.add_to_whitelist(&token, to, "admin".to_string()).unwrap();

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_claim_verification() {
        let reg = ComplianceRegistry::new();
        let addr = Address::new([0x01; 32]);

        reg.add_trusted_issuer(trusted_issuer(
            "did:tenzro:human:issuer1",
            vec![CLAIM_TOPIC_KYC],
        ));

        let now = chrono::Utc::now().timestamp();
        reg.add_identity_claim(addr, make_kyc_claim("did:tenzro:human:issuer1", 2, now - 100, now + 100_000));

        assert!(reg.verify_claim(&addr, CLAIM_TOPIC_KYC));
        // Different topic, no claim
        assert!(!reg.verify_claim(&addr, CLAIM_TOPIC_ACCREDITED_INVESTOR));
    }

    #[test]
    fn test_trusted_issuer_check() {
        let reg = ComplianceRegistry::new();
        let addr = Address::new([0x01; 32]);

        // Add a claim from an untrusted issuer
        let now = chrono::Utc::now().timestamp();
        reg.add_identity_claim(addr, make_kyc_claim("did:tenzro:human:untrusted", 3, now - 100, now + 100_000));

        // No trusted issuers registered, so claim should not verify
        assert!(!reg.verify_claim(&addr, CLAIM_TOPIC_KYC));

        // Register the issuer as trusted
        reg.add_trusted_issuer(trusted_issuer(
            "did:tenzro:human:untrusted",
            vec![CLAIM_TOPIC_KYC],
        ));
        assert!(reg.verify_claim(&addr, CLAIM_TOPIC_KYC));
    }

    #[test]
    fn test_forced_recovery() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(ComplianceRules::new(token));

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        // Give `from` a shadow balance
        reg.record_receipt(&token, from, 1_000);

        let event = reg
            .recover_tokens(token, from, to, 500, "Court order #123".to_string())
            .unwrap();

        assert_eq!(event.amount, 500);
        assert_eq!(event.from, from);
        assert_eq!(event.to, to);

        // Verify shadow balances updated
        assert_eq!(
            reg.balances.get(&(from, token)).map(|v| *v).unwrap_or(0),
            500
        );
        assert_eq!(
            reg.balances.get(&(to, token)).map(|v| *v).unwrap_or(0),
            500
        );
    }

    #[test]
    fn test_max_holders_limit() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(ComplianceRules::new(token).with_max_holders(2));

        let addr1 = Address::new([0x01; 32]);
        let addr2 = Address::new([0x02; 32]);
        let addr3 = Address::new([0x03; 32]);
        let _addr4 = Address::new([0x04; 32]);

        // Record two existing holders
        reg.record_receipt(&token, addr1, 100);
        reg.record_receipt(&token, addr2, 100);

        // Transfer to a third address (new holder) should fail
        let result = reg.can_transfer(&token, &addr1, &addr3, 50).unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(
            v,
            ComplianceViolation::MaxHoldersReached { max: 2, current: 2 }
        )));

        // Transfer to an existing holder should succeed
        let result = reg.can_transfer(&token, &addr1, &addr2, 50).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_holding_period_check() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        // Require 1-day holding period
        reg.register_compliance(ComplianceRules::new(token).with_holding_period(86_400));

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        // Record receipt just now
        reg.record_receipt(&token, from, 1_000);

        // Try to transfer immediately -- holding period not met
        let result = reg.can_transfer(&token, &from, &to, 500).unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(
            v,
            ComplianceViolation::HoldingPeriodNotMet { .. }
        )));

        // Manually backdate the first receipt to simulate time passing
        let old_ts = chrono::Utc::now().timestamp() - 100_000;
        reg.first_receipt.insert((from, token), old_ts);

        let result = reg.can_transfer(&token, &from, &to, 500).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_token_paused_blocks() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        let mut rules = ComplianceRules::new(token);
        rules.paused = true;
        reg.register_compliance(rules);

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(!result.compliant);
        assert!(result.violations.iter().any(|v| matches!(v, ComplianceViolation::TokenPaused)));
    }

    #[test]
    fn test_accreditation_check() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        reg.register_compliance(ComplianceRules::new(token).with_accreditation());
        reg.add_trusted_issuer(trusted_issuer(
            "did:tenzro:human:issuer1",
            vec![CLAIM_TOPIC_ACCREDITED_INVESTOR],
        ));

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let now = chrono::Utc::now().timestamp();

        // Only `from` is accredited
        reg.add_identity_claim(from, make_accreditation_claim("did:tenzro:human:issuer1", now - 100, now + 100_000));

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(!result.compliant);
        // `to` is not accredited
        assert!(result.violations.iter().any(|v| matches!(v, ComplianceViolation::NotAccredited { .. })));

        // Accredit `to` as well
        reg.add_identity_claim(to, make_accreditation_claim("did:tenzro:human:issuer1", now - 100, now + 100_000));

        let result = reg.can_transfer(&token, &from, &to, 100).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_recovery_fails_insufficient_balance() {
        let reg = ComplianceRegistry::new();
        let token = test_token();

        let from = Address::new([0x01; 32]);
        let to = Address::new([0x02; 32]);

        let result = reg.recover_tokens(token, from, to, 100, "test".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Insufficient balance"));
    }
}
