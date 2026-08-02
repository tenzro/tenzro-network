//! Unified payment gateway
//!
//! Routes payment operations across multiple protocols (MPP, x402)
//! with identity binding and settlement. Uses a shared ChallengeStore
//! to look up original challenges during verification and settlement.

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::traits::{PaymentGateway, PaymentProtocol};
use crate::types::{PaymentChallenge, PaymentCredential, PaymentReceipt};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_storage::kv::KvStore;
use tracing::{debug, info, warn};

/// Callback for settling payments on-chain after protocol verification.
///
/// Implementations bridge the payment gateway to the on-chain settlement
/// engine and token layer, so that protocol-level settlements (MPP, x402,
/// etc.) are reflected in TNZO balances.
#[async_trait]
pub trait SettlementCallback: Send + Sync {
    /// Settle a verified payment on-chain.
    ///
    /// # Arguments
    /// * `payer` - Payer address bytes (up to 32 bytes)
    /// * `payee` - Payee address bytes (up to 32 bytes)
    /// * `amount` - Amount in smallest token unit. When `margin_bps > 0`,
    ///   this is the margin-inclusive total the payer authorized.
    /// * `asset` - Asset identifier (e.g. "TNZO", "USDC")
    /// * `receipt_id` - The payment receipt ID for correlation
    /// * `app_wallet` - Registered app's wallet receiving the developer-margin
    ///   carve, snapshot at challenge creation. `None` disables the carve.
    /// * `margin_bps` - Developer margin, in basis points, already included in
    ///   `amount`; the on-chain settlement carves
    ///   `amount * margin_bps / (10_000 + margin_bps)` to `app_wallet`.
    ///
    /// # Returns
    /// A settlement reference string (e.g. transaction hash) on success.
    async fn settle_on_chain(
        &self,
        payer: &[u8],
        payee: &[u8],
        amount: u128,
        asset: &str,
        receipt_id: &str,
        app_wallet: Option<&[u8]>,
        margin_bps: u32,
    ) -> std::result::Result<String, PaymentError>;
}

/// Outcome of converting a payer-denominated amount into the asset the
/// payee settles in.
#[derive(Debug, Clone)]
pub struct Conversion {
    /// Amount, in smallest unit, of `to_asset` the payee receives.
    pub amount_out: u128,
    /// The asset the on-chain settlement should record (the payee's asset).
    pub to_asset: String,
    /// Opaque reference to the conversion (rate quote id) for the receipt
    /// audit trail.
    pub quote_ref: String,
}

/// Optional conversion hook bridging a stable unit to the payee's asset.
///
/// An agent may choose to spend a stable unit (e.g. "USDX") while the payee
/// is denominated in some token (e.g. "USDC"). The gateway runs this hook
/// between protocol settlement and on-chain settle: it converts the payer's
/// `from_asset` into the payee's `to_asset` at the oracle rate and returns
/// the converted amount to record on-chain.
///
/// Direct-token mode (`from_asset == to_asset`) is the no-op default
/// implemented by [`IdentityConversionHook`], so a gateway without a stable
/// unit configured behaves exactly as before.
#[async_trait]
pub trait ConversionHook: Send + Sync {
    /// Convert `amount` of `from_asset` into the equivalent in `to_asset`.
    ///
    /// Implementations must treat `from_asset == to_asset` as an identity
    /// (no rate lookup, `amount_out == amount`).
    async fn convert(
        &self,
        from_asset: &str,
        to_asset: &str,
        amount: u128,
    ) -> std::result::Result<Conversion, PaymentError>;
}

/// No-op conversion hook: passes the amount through unchanged. Used when the
/// agent transacts directly in the payee's asset (direct-token mode) or when
/// no stable unit is configured.
pub struct IdentityConversionHook;

#[async_trait]
impl ConversionHook for IdentityConversionHook {
    async fn convert(
        &self,
        _from_asset: &str,
        to_asset: &str,
        amount: u128,
    ) -> std::result::Result<Conversion, PaymentError> {
        Ok(Conversion {
            amount_out: amount,
            to_asset: to_asset.to_string(),
            quote_ref: String::new(),
        })
    }
}

/// Resolves a payee's declared settlement preference.
///
/// Separated from the gateway because the preference lives with the payee's
/// identity, not with the payment: the same payee settles the same way
/// whichever protocol a payer used to reach them.
///
/// A gateway with no resolver treats every payee as
/// [`SettlementAsset::KeepInbound`](crate::settlement_asset::SettlementAsset::KeepInbound),
/// which is the default and the behaviour before this existed.
pub trait SettlementPreferencesResolver: Send + Sync {
    /// The preferences to apply to this settlement.
    fn preferences(&self) -> crate::settlement_asset::SettlementPreferences;
}

/// Adapts a [`ConversionHook`] into the [`SwapQuoter`] the settlement router
/// asks for a TNZO route.
///
/// The hook is the node's swap venue; the router only needs to know whether a
/// route exists and what comes out. Keeping the adapter here rather than
/// making `ConversionHook` implement `SwapQuoter` directly means a node can
/// have a conversion hook for stable-unit spending without thereby claiming it
/// can swap anything to TNZO.
struct HookQuoter<'a> {
    hook: &'a dyn ConversionHook,
    handle: tokio::runtime::Handle,
}

impl crate::settlement_asset::SwapQuoter for HookQuoter<'_> {
    fn quote_to_tnzo(
        &self,
        from: &crate::settlement_asset::Caip19,
        amount_in: u128,
    ) -> Result<Option<u128>> {
        // The router is synchronous by design — it is a policy decision, not
        // an I/O path — so the async hook is driven to completion here rather
        // than making every caller of `route_settlement` async.
        let asset = from.to_string();
        let result = tokio::task::block_in_place(|| {
            self.handle
                .block_on(async { self.hook.convert(&asset, "TNZO", amount_in).await })
        });
        match result {
            Ok(conv) => Ok(Some(conv.amount_out)),
            // "No route" is a normal answer from a venue that does not cover
            // this pair, not a failure of the venue.
            Err(_) => Ok(None),
        }
    }
}

/// Multi-protocol payment gateway for Tenzro Network
pub struct TenzroPaymentGateway {
    protocols: DashMap<String, Arc<dyn PaymentProtocol>>,
    /// Shared challenge store — same instance passed to protocol servers
    challenge_store: ChallengeStore,
    /// Optional on-chain settlement callback (bridges to SettlementEngine + TnzoToken)
    settlement_callback: Option<Arc<dyn SettlementCallback>>,
    /// Optional payee settlement-preference resolver. When unset, every payee
    /// keeps the asset that arrived.
    settlement_preferences: Option<Arc<dyn SettlementPreferencesResolver>>,
    /// Optional stable-unit conversion hook. When unset, the payer's asset
    /// settles directly (no conversion).
    conversion_hook: Option<Arc<dyn ConversionHook>>,
}

impl TenzroPaymentGateway {
    /// Creates a new payment gateway
    pub fn new() -> Self {
        Self {
            protocols: DashMap::new(),
            challenge_store: ChallengeStore::new(),
            settlement_callback: None,
            settlement_preferences: None,
            conversion_hook: None,
        }
    }

    /// Creates a new payment gateway backed by persistent storage (MEDIUM #127).
    ///
    /// The challenge store is initialized with storage so challenges
    /// survive node restarts.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self {
            protocols: DashMap::new(),
            challenge_store: ChallengeStore::with_storage(storage),
            settlement_callback: None,
            settlement_preferences: None,
            conversion_hook: None,
        }
    }

    /// Attaches an on-chain settlement callback.
    ///
    /// When set, `verify_and_settle` will invoke the callback after
    /// successful protocol-level settlement to record the transfer
    /// on the TNZO token layer.
    /// Attach the payee settlement-preference resolver.
    pub fn with_settlement_preferences(
        mut self,
        resolver: Arc<dyn SettlementPreferencesResolver>,
    ) -> Self {
        self.settlement_preferences = Some(resolver);
        self
    }

    pub fn with_settlement_callback(mut self, callback: Arc<dyn SettlementCallback>) -> Self {
        self.settlement_callback = Some(callback);
        self
    }

    /// Attaches a stable-unit conversion hook.
    ///
    /// When set, `verify_and_settle` converts the payer's asset into the
    /// payee's asset at the oracle rate before recording the on-chain
    /// settlement. Without it, the payer's asset settles directly.
    pub fn with_conversion_hook(mut self, hook: Arc<dyn ConversionHook>) -> Self {
        self.conversion_hook = Some(hook);
        self
    }

    /// Creates a new payment gateway with a shared challenge store
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Returns a clone of the challenge store (shares underlying state)
    pub fn challenge_store(&self) -> ChallengeStore {
        self.challenge_store.clone()
    }

    /// Registers a payment protocol (stored with lowercase name for case-insensitive lookup)
    pub fn register_protocol(&self, protocol: Arc<dyn PaymentProtocol>) {
        let name = protocol.protocol_name().to_lowercase();
        info!("Registering payment protocol: {}", name);
        self.protocols.insert(name, protocol);
    }

    /// Gets a protocol by name (case-insensitive lookup)
    fn get_protocol(&self, name: &str) -> Result<Arc<dyn PaymentProtocol>> {
        let normalized = name.to_lowercase();
        self.protocols
            .get(&normalized)
            .map(|p| p.clone())
            .ok_or_else(|| PaymentError::UnsupportedProtocol(name.to_string()))
    }
}

impl Default for TenzroPaymentGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl TenzroPaymentGateway {
    /// Which asset this payee settles in, per their declared preference.
    ///
    /// `Ok(None)` means "no preference configured" — keep whatever the
    /// protocol produced, which is the default and the pre-existing behaviour.
    /// `Err` means the payee asked for something this node cannot deliver, and
    /// the settlement must not proceed.
    fn resolve_settlement_asset(
        &self,
        challenge: &PaymentChallenge,
        receipt: &PaymentReceipt,
    ) -> Result<Option<String>> {
        use crate::settlement_asset::{Caip19, SettlementRoute, route_settlement};

        let Some(resolver) = self.settlement_preferences.as_ref() else {
            return Ok(None);
        };

        // The payee is identified by DID where the challenge carries one —
        // a settlement preference belongs to an identity, not to an address,
        // and the same payee may be paid at several addresses.
        let payee_did = challenge
            .extra
            .get("payee_did")
            .and_then(|v| v.as_str())
            .unwrap_or(&challenge.recipient);

        // A non-CAIP asset string (bare "USDC", "TNZO") is what most protocols
        // produce today. Routing needs a chain-qualified identifier to quote
        // against, so a bare symbol means "nothing to route" rather than a
        // parse failure that would block an otherwise fine payment.
        let Ok(inbound) = Caip19::parse(&receipt.asset) else {
            return Ok(None);
        };

        let prefs = resolver.preferences();
        let quoter = self.conversion_hook.as_ref().and_then(|hook| {
            tokio::runtime::Handle::try_current()
                .ok()
                .map(|handle| HookQuoter {
                    hook: hook.as_ref(),
                    handle,
                })
        });

        let route = route_settlement(
            payee_did,
            &inbound,
            receipt.amount,
            &prefs,
            quoter
                .as_ref()
                .map(|q| q as &dyn crate::settlement_asset::SwapQuoter),
        )?;

        Ok(match route {
            SettlementRoute::Direct { asset, .. } => Some(asset.to_string()),
            SettlementRoute::Swap { .. } => Some("TNZO".to_string()),
        })
    }
}

#[async_trait]
impl PaymentGateway for TenzroPaymentGateway {
    fn supported_protocols(&self) -> Vec<String> {
        self.protocols
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    async fn create_challenge(
        &self,
        protocol: &str,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let proto = self.get_protocol(protocol)?;
        proto
            .create_challenge(resource, amount, asset, recipient)
            .await
    }

    async fn verify_and_settle(&self, credential: &PaymentCredential) -> Result<PaymentReceipt> {
        let proto = self.get_protocol(&credential.protocol)?;

        // Look up the original challenge from the shared store
        let challenge = self
            .challenge_store
            .get(&credential.challenge_id)
            .map_err(|_| {
                PaymentError::ChallengeError(format!(
                    "Challenge {} not found — it may have expired or already been settled",
                    credential.challenge_id
                ))
            })?;

        debug!(
            "Found challenge {} for credential {} (amount={}, chain={})",
            challenge.challenge_id, credential.credential_id, challenge.amount, challenge.chain
        );

        let verification = proto.verify_credential(&challenge, credential).await?;
        let mut receipt = proto.settle(&verification).await?;

        // Settle on-chain if a settlement callback is configured
        if let Some(callback) = &self.settlement_callback {
            let payer_bytes =
                hex::decode(credential.payer_address.trim_start_matches("0x")).unwrap_or_default();
            let payee_bytes =
                hex::decode(challenge.recipient.trim_start_matches("0x")).unwrap_or_default();

            // What asset the payee actually settles in. A payee who declared
            // TNZO gets TNZO or nothing: crediting them the inbound stablecoin
            // instead would hand them an asset they did not choose, and the
            // discrepancy would be silent exactly where it matters. The router
            // refuses rather than falling back.
            let target_asset = self
                .resolve_settlement_asset(&challenge, &receipt)
                .map_err(|e| {
                    warn!(
                        "settlement routing refused for receipt {}: {}",
                        receipt.receipt_id, e
                    );
                    e
                })?;
            if let Some(asset) = target_asset.as_ref() {
                receipt.extra.insert(
                    "settlement_asset".to_string(),
                    serde_json::Value::String(asset.clone()),
                );
            }
            let payee_asset = target_asset.unwrap_or_else(|| receipt.asset.clone());

            // Dual-mode settlement: if the payer spends a stable unit
            // (`credential.asset`) different from the asset the payee settles
            // in, convert at the oracle rate before recording the on-chain
            // transfer. Direct-token mode (assets equal, or no hook
            // configured) settles the payer's amount unchanged.
            let (settle_amount, settle_asset) = if credential.asset != payee_asset {
                if let Some(hook) = &self.conversion_hook {
                    match hook
                        .convert(&credential.asset, &payee_asset, receipt.amount)
                        .await
                    {
                        Ok(conv) => {
                            debug!(
                                "Converted {} {} -> {} {} for receipt {} (quote={})",
                                receipt.amount,
                                credential.asset,
                                conv.amount_out,
                                conv.to_asset,
                                receipt.receipt_id,
                                conv.quote_ref
                            );
                            if !conv.quote_ref.is_empty() {
                                receipt.extra.insert(
                                    "conversion_quote".to_string(),
                                    serde_json::Value::String(conv.quote_ref),
                                );
                                receipt.extra.insert(
                                    "from_asset".to_string(),
                                    serde_json::Value::String(credential.asset.clone()),
                                );
                            }
                            (conv.amount_out, conv.to_asset)
                        }
                        Err(e) => {
                            warn!(
                                "Conversion {}->{} failed for receipt {}: {}",
                                credential.asset, payee_asset, receipt.receipt_id, e
                            );
                            return Err(e);
                        }
                    }
                } else {
                    (receipt.amount, payee_asset.clone())
                }
            } else {
                (receipt.amount, payee_asset.clone())
            };

            // Developer-margin attribution snapshot from challenge creation:
            // `handle_create_payment_challenge` resolved the app registry and
            // stamped the wallet + margin into `challenge.extra`, so the
            // settlement path never consults the registry.
            let app_wallet_bytes: Option<Vec<u8>> = challenge
                .extra
                .get("app_wallet")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok());
            let margin_bps: u32 = challenge
                .extra
                .get("margin_bps")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            if margin_bps > 0 {
                let developer_margin = settle_amount.saturating_mul(margin_bps as u128)
                    / (10_000u128 + margin_bps as u128);
                receipt
                    .extra
                    .insert("margin_bps".to_string(), serde_json::json!(margin_bps));
                receipt.extra.insert(
                    "developer_margin".to_string(),
                    serde_json::Value::String(developer_margin.to_string()),
                );
                if let Some(app_id) = challenge.extra.get("app_id") {
                    receipt.extra.insert("app_id".to_string(), app_id.clone());
                }
                if let Some(app_wallet) = challenge.extra.get("app_wallet") {
                    receipt
                        .extra
                        .insert("app_wallet".to_string(), app_wallet.clone());
                }
            }

            match callback
                .settle_on_chain(
                    &payer_bytes,
                    &payee_bytes,
                    settle_amount,
                    &settle_asset,
                    &receipt.receipt_id,
                    app_wallet_bytes.as_deref(),
                    margin_bps,
                )
                .await
            {
                Ok(settlement_ref) => {
                    info!(
                        "On-chain settlement succeeded for receipt {}: ref={}",
                        receipt.receipt_id, settlement_ref
                    );
                    receipt.settlement_tx = Some(settlement_ref);
                }
                Err(e) => {
                    warn!(
                        "On-chain settlement failed for receipt {} (protocol settlement succeeded): {}",
                        receipt.receipt_id, e
                    );
                    // Don't fail the overall operation — protocol settlement already succeeded
                }
            }
        }

        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PaymentVerification;
    use chrono::Utc;
    use std::collections::HashMap;

    /// Minimal test protocol that uses the gateway's challenge store
    struct TestProtocol;

    #[async_trait]
    impl PaymentProtocol for TestProtocol {
        fn protocol_name(&self) -> &str {
            "test"
        }

        async fn create_challenge(
            &self,
            resource: &str,
            amount: u128,
            asset: &str,
            recipient: &str,
        ) -> Result<PaymentChallenge> {
            Ok(PaymentChallenge {
                challenge_id: uuid::Uuid::new_v4().to_string(),
                protocol: "test".to_string(),
                resource: resource.to_string(),
                amount,
                asset: asset.to_string(),
                recipient: recipient.to_string(),
                chain: "tenzro".to_string(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
                extra: HashMap::new(),
            })
        }

        async fn verify_credential(
            &self,
            challenge: &PaymentChallenge,
            credential: &PaymentCredential,
        ) -> Result<PaymentVerification> {
            // Verify the challenge has the correct data (not empty defaults)
            assert!(
                !challenge.resource.is_empty(),
                "resource should not be empty"
            );
            assert!(
                !challenge.recipient.is_empty(),
                "recipient should not be empty"
            );
            assert!(!challenge.chain.is_empty(), "chain should not be empty");
            assert_eq!(challenge.amount, credential.amount);

            Ok(PaymentVerification {
                verified: true,
                credential_id: credential.credential_id.clone(),
                challenge_id: challenge.challenge_id.clone(),
                payer_did: credential.payer_did.clone(),
                verified_at: Utc::now(),
                settlement_ref: None,
            })
        }

        async fn settle(&self, verification: &PaymentVerification) -> Result<PaymentReceipt> {
            Ok(PaymentReceipt {
                receipt_id: uuid::Uuid::new_v4().to_string(),
                protocol: "test".to_string(),
                challenge_id: verification.challenge_id.clone(),
                credential_id: verification.credential_id.clone(),
                amount: 3000,
                asset: "USDC".to_string(),
                settlement_tx: None,
                chain: "tenzro".to_string(),
                settled_at: Utc::now(),
                principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                    verification.payer_did.clone(),
                    tenzro_types::primitives::BlockHeight::new(0),
                ),
                extra: HashMap::new(),
            })
        }

        async fn create_credential(
            &self,
            challenge: &PaymentChallenge,
            payer_did: &str,
            _wallet_id: &str,
        ) -> Result<PaymentCredential> {
            Ok(PaymentCredential {
                credential_id: uuid::Uuid::new_v4().to_string(),
                challenge_id: challenge.challenge_id.clone(),
                protocol: "test".to_string(),
                payer_did: payer_did.to_string(),
                payer_address: String::new(),
                amount: challenge.amount,
                asset: challenge.asset.clone(),
                signature: Vec::new(),
                pq_signature: Vec::new(),
                pq_public_key: Vec::new(),
                extra: HashMap::new(),
            })
        }
    }

    #[tokio::test]
    async fn test_gateway_challenge_lookup() {
        let store = ChallengeStore::new();
        let gateway = TenzroPaymentGateway::new().with_challenge_store(store.clone());
        gateway.register_protocol(Arc::new(TestProtocol));

        // Create a challenge through the gateway (stores it via protocol)
        let challenge = gateway
            .create_challenge("test", "/api/paid", 3000, "USDC", "0xrecipient")
            .await
            .unwrap();

        // Manually store the challenge in the shared store
        // (in production, the protocol server shares the same store)
        store.store(&challenge);

        // Create a credential that references this challenge
        let credential = PaymentCredential {
            credential_id: "cred-gw-1".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "test".to_string(),
            payer_did: "did:tenzro:human:alice".to_string(),
            payer_address: String::new(),
            amount: 3000,
            asset: "USDC".to_string(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        };

        // verify_and_settle should find the real challenge (not reconstruct empty one)
        let receipt = gateway.verify_and_settle(&credential).await.unwrap();
        assert_eq!(receipt.amount, 3000);
        assert_eq!(receipt.protocol, "test");
    }

    use std::sync::Mutex;

    /// Records what was handed to `settle_on_chain` so tests can assert on
    /// the converted amount/asset.
    struct RecordingCallback {
        seen: Arc<Mutex<Option<(u128, String)>>>,
    }

    #[async_trait]
    impl SettlementCallback for RecordingCallback {
        async fn settle_on_chain(
            &self,
            _payer: &[u8],
            _payee: &[u8],
            amount: u128,
            asset: &str,
            _receipt_id: &str,
            _app_wallet: Option<&[u8]>,
            _margin_bps: u32,
        ) -> std::result::Result<String, PaymentError> {
            *self.seen.lock().unwrap() = Some((amount, asset.to_string()));
            Ok("0xsettled".to_string())
        }
    }

    /// Halves the amount on convert (stand-in for a 2:1 rate) and renames the
    /// asset to the payee's.
    struct HalvingHook;

    #[async_trait]
    impl ConversionHook for HalvingHook {
        async fn convert(
            &self,
            from_asset: &str,
            to_asset: &str,
            amount: u128,
        ) -> std::result::Result<Conversion, PaymentError> {
            if from_asset == to_asset {
                return Ok(Conversion {
                    amount_out: amount,
                    to_asset: to_asset.to_string(),
                    quote_ref: String::new(),
                });
            }
            Ok(Conversion {
                amount_out: amount / 2,
                to_asset: to_asset.to_string(),
                quote_ref: "quote-1".to_string(),
            })
        }
    }

    async fn settle_with(
        hook: Option<Arc<dyn ConversionHook>>,
        credential_asset: &str,
    ) -> (u128, String, PaymentReceipt) {
        let store = ChallengeStore::new();
        let seen = Arc::new(Mutex::new(None));
        let mut gateway = TenzroPaymentGateway::new()
            .with_challenge_store(store.clone())
            .with_settlement_callback(Arc::new(RecordingCallback { seen: seen.clone() }));
        if let Some(h) = hook {
            gateway = gateway.with_conversion_hook(h);
        }
        gateway.register_protocol(Arc::new(TestProtocol));

        let challenge = gateway
            .create_challenge("test", "/api/paid", 3000, "USDC", "0xrecipient")
            .await
            .unwrap();
        store.store(&challenge);

        let credential = PaymentCredential {
            credential_id: "cred-conv".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "test".to_string(),
            payer_did: "did:tenzro:human:alice".to_string(),
            payer_address: String::new(),
            amount: 3000,
            asset: credential_asset.to_string(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        };

        let receipt = gateway.verify_and_settle(&credential).await.unwrap();
        let (amt, asset) = seen.lock().unwrap().clone().unwrap();
        (amt, asset, receipt)
    }

    #[tokio::test]
    async fn test_direct_mode_no_conversion() {
        // Payer spends the same asset the payee settles in — amount passes
        // through even with a hook attached.
        let (amt, asset, _) = settle_with(Some(Arc::new(HalvingHook)), "USDC").await;
        assert_eq!(amt, 3000);
        assert_eq!(asset, "USDC");
    }

    #[tokio::test]
    async fn test_stable_unit_conversion() {
        // Payer spends USDX, payee settles USDC — hook halves (2:1 rate).
        let (amt, asset, receipt) = settle_with(Some(Arc::new(HalvingHook)), "USDX").await;
        assert_eq!(amt, 1500);
        assert_eq!(asset, "USDC");
        assert_eq!(
            receipt
                .extra
                .get("conversion_quote")
                .and_then(|v| v.as_str()),
            Some("quote-1")
        );
        assert_eq!(
            receipt.extra.get("from_asset").and_then(|v| v.as_str()),
            Some("USDX")
        );
    }

    #[tokio::test]
    async fn test_mismatch_without_hook_settles_payee_asset() {
        // Asset mismatch but no hook configured — settle the receipt's asset
        // and amount unchanged (no silent conversion).
        let (amt, asset, _) = settle_with(None, "USDX").await;
        assert_eq!(amt, 3000);
        assert_eq!(asset, "USDC");
    }

    #[tokio::test]
    async fn test_gateway_fails_for_missing_challenge() {
        let gateway = TenzroPaymentGateway::new();
        gateway.register_protocol(Arc::new(TestProtocol));

        let credential = PaymentCredential {
            credential_id: "cred-gw-2".to_string(),
            challenge_id: "nonexistent".to_string(),
            protocol: "test".to_string(),
            payer_did: "payer".to_string(),
            payer_address: String::new(),
            amount: 1000,
            asset: "USDC".to_string(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        };

        let result = gateway.verify_and_settle(&credential).await;
        assert!(result.is_err());
    }
}
