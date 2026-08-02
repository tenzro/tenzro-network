//! Executes developer-signed settlement authorizations.
//!
//! A developer's backend charges an end user in fiat on the developer's own
//! payment-provider account, then signs a
//! [`tenzro_types::SettlementAuthorization`] with a key registered in the
//! app's on-chain [`crate::app_registry::AppRecord`]. Any node executes it:
//! after signature, expiry, chain-id, and per-key ceiling checks, TNZO moves
//! from the developer's app wallet to the payer's wallet, with the network
//! commission ([`tenzro_types::SETTLEMENT_AUTHORIZATION_COMMISSION_BPS`])
//! routed to the treasury. The node never touches a payment-provider secret
//! and never holds a fiat float.
//!
//! Outcomes persist to `CF_SETTLEMENTS` under `settle_auth:` keyed by
//! `SHA-256(app_id, external_ref)` — resubmitting the same `external_ref`
//! for the same app returns the original outcome verbatim (including
//! recorded failures), so a developer retry after a network error is safe
//! and a consumed provider reference can never pay twice.
//!
//! These settlements are excluded from reward metering by construction:
//! nothing here reports work to the `RewardEngine` or `UsageTracker`, so a
//! developer cannot farm reward-eligible activity by fabricating provider
//! references against their own wallet.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::Signature;
use tenzro_identity::IdentityRegistry;
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_token::TnzoToken;
use tenzro_types::{Address, SettlementAuthorization, split_settlement_authorization};

use crate::app_registry::AppRegistry;

/// RocksDB key prefix for settlement-authorization outcome rows.
const SETTLE_AUTH_PREFIX: &[u8] = b"settle_auth:";

/// RocksDB key prefix for per-key daily spend counters.
const SETTLE_AUTH_SPEND_PREFIX: &[u8] = b"settle_auth_spend:";

/// Errors from settlement-authorization execution.
///
/// None of these persist an outcome row — they are all either malformed
/// requests or transient/retryable conditions. Only authenticated execution
/// attempts (fund movements and underfunded-wallet failures) consume the
/// `(app_id, external_ref)` idempotency slot.
#[derive(Debug, thiserror::Error)]
pub enum SettleAuthorizedError {
    /// Malformed or unresolvable request (bad params, unknown app,
    /// wrong chain, expired quote, unresolvable payer).
    #[error("{0}")]
    InvalidRequest(String),
    /// The authorization is not authorized to execute (inactive app,
    /// unknown key, bad signature, ceiling exceeded).
    #[error("{0}")]
    Unauthorized(String),
    /// Node-side capability missing or storage failure.
    #[error("{0}")]
    Unavailable(String),
}

/// Persisted outcome of an executed settlement authorization.
///
/// Replays of the same `(app_id, external_ref)` return this row verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleAuthorizedOutcome {
    /// App the authorization settled against
    pub app_id: String,
    /// Developer's payment-provider reference (idempotency key)
    pub external_ref: String,
    /// Payer DID from the authorization
    pub payer_did: String,
    /// Wallet the payer amount was sent to
    pub payer_wallet: Address,
    /// Authorized amount (total debit from the app wallet on success)
    pub amount_tnzo: u128,
    /// Amount the payer received (`amount_tnzo` minus commission)
    pub payer_net_tnzo: u128,
    /// Network commission routed to the treasury
    pub commission_tnzo: u128,
    /// Signing key that authorized the settlement
    pub key_id: String,
    /// Unix milliseconds the outcome was recorded
    pub settled_at: u64,
    /// Whether the TNZO movement completed
    pub success: bool,
    /// Failure detail when `success` is false. Per the app-registry
    /// convention the developer refunds the fiat charge on failure; the
    /// provider reference stays consumed either way.
    pub failure_reason: Option<String>,
    /// Whether the app wallet still meets its committed `min_balance`
    /// after this settlement (false = underfunded flag for clients)
    pub app_wallet_funded: bool,
}

/// Executes a settlement authorization against the app registry, identity
/// registry, and TNZO ledger.
///
/// Returns the outcome plus `true` when the outcome was replayed from a
/// previously recorded row rather than executed now.
pub fn execute_settle_authorized(
    auth: &SettlementAuthorization,
    node_chain_id: u64,
    apps: &AppRegistry,
    identities: &IdentityRegistry,
    token: &TnzoToken,
    storage: &Arc<dyn KvStore>,
) -> Result<(SettleAuthorizedOutcome, bool), SettleAuthorizedError> {
    validate_shape(auth)?;

    let record = apps.get(&auth.app_id).ok_or_else(|| {
        SettleAuthorizedError::InvalidRequest(format!("unknown app_id '{}'", auth.app_id))
    })?;
    if !record.active {
        return Err(SettleAuthorizedError::Unauthorized(format!(
            "app '{}' is inactive",
            auth.app_id
        )));
    }
    if auth.chain_id != node_chain_id {
        return Err(SettleAuthorizedError::InvalidRequest(format!(
            "authorization is for chain {} but this node settles chain {}",
            auth.chain_id, node_chain_id
        )));
    }

    // The signature binds key_id inside the preimage, so a signature can
    // never be re-attributed to a different registered key with a
    // different ceiling.
    let key = record
        .signing_pubkeys
        .iter()
        .find(|k| k.key_id == auth.key_id)
        .ok_or_else(|| {
            SettleAuthorizedError::Unauthorized(format!(
                "key_id '{}' is not registered for app '{}'",
                auth.key_id, auth.app_id
            ))
        })?;
    let public_key = PublicKey::new(KeyType::Ed25519, key.public_key.clone());
    let signature = Signature::new(KeyType::Ed25519, auth.signature.clone());
    tenzro_crypto::signatures::verify(&public_key, &auth.signing_hash(), &signature).map_err(
        |_| SettleAuthorizedError::Unauthorized("signature verification failed".to_string()),
    )?;

    // Idempotency: an authenticated resubmission returns the recorded
    // outcome verbatim, even after the quote expiry has passed.
    let dedup_key = outcome_key(&auth.app_id, &auth.external_ref);
    if let Some(bytes) = storage
        .get(CF_SETTLEMENTS, &dedup_key)
        .map_err(|e| SettleAuthorizedError::Unavailable(format!("storage error: {e}")))?
    {
        let outcome: SettleAuthorizedOutcome = serde_json::from_slice(&bytes)
            .map_err(|e| SettleAuthorizedError::Unavailable(format!("corrupt outcome row: {e}")))?;
        return Ok((outcome, true));
    }

    let now = now_ms();
    if now > auth.expiry {
        return Err(SettleAuthorizedError::InvalidRequest(format!(
            "authorization expired at {} (now {})",
            auth.expiry, now
        )));
    }

    // Per-key daily ceiling (UTC-day bucket). Not persisted as a failure —
    // the developer can re-sign under an unrestricted key or wait for the
    // next bucket without consuming the provider reference.
    let day = now / 86_400_000;
    let spend_key = spend_key(&auth.app_id, &auth.key_id, day);
    let spent = if key.daily_limit_tnzo.is_some() {
        read_spend(storage, &spend_key)?
    } else {
        0
    };
    if let Some(limit) = key.daily_limit_tnzo {
        let projected = spent.checked_add(auth.amount_tnzo).ok_or_else(|| {
            SettleAuthorizedError::Unauthorized("daily spend overflow".to_string())
        })?;
        if projected > limit {
            return Err(SettleAuthorizedError::Unauthorized(format!(
                "key '{}' daily limit exceeded: {} spent + {} requested > {} limit",
                auth.key_id, spent, auth.amount_tnzo, limit
            )));
        }
    }

    let payer_identity = identities.resolve(&auth.payer_did).map_err(|_| {
        SettleAuthorizedError::InvalidRequest(format!(
            "payer DID '{}' does not resolve",
            auth.payer_did
        ))
    })?;
    let payer_wallet = payer_identity.wallet_address;
    if payer_wallet == Address::default() {
        return Err(SettleAuthorizedError::InvalidRequest(format!(
            "payer DID '{}' has no bound wallet",
            auth.payer_did
        )));
    }

    let treasury = token.treasury_address_ref().ok_or_else(|| {
        SettleAuthorizedError::Unavailable("treasury address not configured".to_string())
    })?;
    let (payer_net, commission) = split_settlement_authorization(auth.amount_tnzo);

    let mut outcome = SettleAuthorizedOutcome {
        app_id: auth.app_id.clone(),
        external_ref: auth.external_ref.clone(),
        payer_did: auth.payer_did.clone(),
        payer_wallet,
        amount_tnzo: auth.amount_tnzo,
        payer_net_tnzo: payer_net,
        commission_tnzo: commission,
        key_id: auth.key_id.clone(),
        settled_at: now,
        success: false,
        failure_reason: None,
        app_wallet_funded: false,
    };

    // Authenticated execution begins: from here every path records an
    // outcome row, consuming the (app_id, external_ref) slot. A failed
    // settlement is a real event the developer must reconcile (fiat
    // refund), not a retryable request error.
    let app_balance = token.balance_of(&record.app_wallet);
    if app_balance < auth.amount_tnzo {
        outcome.failure_reason = Some(format!(
            "app wallet underfunded: balance {} < authorized {}",
            app_balance, auth.amount_tnzo
        ));
        outcome.app_wallet_funded = app_balance >= record.min_balance;
        persist_outcome(storage, &dedup_key, &outcome)?;
        return Ok((outcome, false));
    }

    if let Err(e) = token.transfer(&record.app_wallet, &payer_wallet, payer_net) {
        outcome.failure_reason = Some(format!("payer transfer failed: {e}"));
        outcome.app_wallet_funded = token.balance_of(&record.app_wallet) >= record.min_balance;
        persist_outcome(storage, &dedup_key, &outcome)?;
        return Ok((outcome, false));
    }
    if commission > 0
        && let Err(e) = token.transfer(&record.app_wallet, &treasury, commission)
    {
        // Payer leg already settled; record the partial state honestly
        // so the developer's reconciliation sees exactly what moved.
        outcome.failure_reason = Some(format!(
            "payer received {} but commission transfer failed: {e}",
            payer_net
        ));
        outcome.app_wallet_funded = token.balance_of(&record.app_wallet) >= record.min_balance;
        persist_outcome(storage, &dedup_key, &outcome)?;
        return Ok((outcome, false));
    }

    if key.daily_limit_tnzo.is_some() {
        write_spend(storage, &spend_key, spent.saturating_add(auth.amount_tnzo))?;
    }

    outcome.success = true;
    outcome.app_wallet_funded = token.balance_of(&record.app_wallet) >= record.min_balance;
    persist_outcome(storage, &dedup_key, &outcome)?;
    Ok((outcome, false))
}

/// Reads a previously recorded outcome without executing anything.
pub fn get_outcome(
    storage: &Arc<dyn KvStore>,
    app_id: &str,
    external_ref: &str,
) -> Result<Option<SettleAuthorizedOutcome>, SettleAuthorizedError> {
    let key = outcome_key(app_id, external_ref);
    match storage
        .get(CF_SETTLEMENTS, &key)
        .map_err(|e| SettleAuthorizedError::Unavailable(format!("storage error: {e}")))?
    {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| SettleAuthorizedError::Unavailable(format!("corrupt outcome row: {e}"))),
        None => Ok(None),
    }
}

fn validate_shape(auth: &SettlementAuthorization) -> Result<(), SettleAuthorizedError> {
    if auth.app_id.is_empty() || auth.app_id.len() > 128 {
        return Err(SettleAuthorizedError::InvalidRequest(
            "app_id must be 1..=128 bytes".to_string(),
        ));
    }
    if auth.external_ref.is_empty() || auth.external_ref.len() > 256 {
        return Err(SettleAuthorizedError::InvalidRequest(
            "external_ref must be 1..=256 bytes".to_string(),
        ));
    }
    if auth.payer_did.is_empty() {
        return Err(SettleAuthorizedError::InvalidRequest(
            "payer_did must not be empty".to_string(),
        ));
    }
    if auth.key_id.is_empty() || auth.key_id.len() > 64 {
        return Err(SettleAuthorizedError::InvalidRequest(
            "key_id must be 1..=64 bytes".to_string(),
        ));
    }
    if auth.amount_tnzo == 0 {
        return Err(SettleAuthorizedError::InvalidRequest(
            "amount_tnzo must be positive".to_string(),
        ));
    }
    if auth.nonce == [0u8; 32] {
        return Err(SettleAuthorizedError::InvalidRequest(
            "nonce must not be all zeros".to_string(),
        ));
    }
    if auth.signature.len() != 64 {
        return Err(SettleAuthorizedError::InvalidRequest(
            "signature must be 64 bytes (Ed25519)".to_string(),
        ));
    }
    Ok(())
}

/// Outcome-row key: prefix + hex(SHA-256 over length-separated components).
///
/// Both components are arbitrary developer-chosen strings, so the hash uses
/// u32-BE length prefixes rather than a delimiter to keep `("ab","c")` and
/// `("a","bc")` distinct.
fn outcome_key(app_id: &str, external_ref: &str) -> Vec<u8> {
    let mut key = SETTLE_AUTH_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(pair_hash(app_id, external_ref)).as_bytes());
    key
}

fn spend_key(app_id: &str, key_id: &str, day: u64) -> Vec<u8> {
    let mut key = SETTLE_AUTH_SPEND_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(pair_hash(app_id, key_id)).as_bytes());
    key.push(b':');
    key.extend_from_slice(day.to_string().as_bytes());
    key
}

fn pair_hash(a: &str, b: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((a.len() as u32).to_be_bytes());
    hasher.update(a.as_bytes());
    hasher.update((b.len() as u32).to_be_bytes());
    hasher.update(b.as_bytes());
    hasher.finalize().into()
}

fn read_spend(storage: &Arc<dyn KvStore>, key: &[u8]) -> Result<u128, SettleAuthorizedError> {
    match storage
        .get(CF_SETTLEMENTS, key)
        .map_err(|e| SettleAuthorizedError::Unavailable(format!("storage error: {e}")))?
    {
        Some(bytes) => {
            let raw: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                SettleAuthorizedError::Unavailable("corrupt spend counter".to_string())
            })?;
            Ok(u128::from_be_bytes(raw))
        }
        None => Ok(0),
    }
}

fn write_spend(
    storage: &Arc<dyn KvStore>,
    key: &[u8],
    value: u128,
) -> Result<(), SettleAuthorizedError> {
    storage
        .put(CF_SETTLEMENTS, key, &value.to_be_bytes())
        .map_err(|e| SettleAuthorizedError::Unavailable(format!("storage error: {e}")))
}

fn persist_outcome(
    storage: &Arc<dyn KvStore>,
    key: &[u8],
    outcome: &SettleAuthorizedOutcome,
) -> Result<(), SettleAuthorizedError> {
    let bytes = serde_json::to_vec(outcome)
        .map_err(|e| SettleAuthorizedError::Unavailable(format!("serialize outcome: {e}")))?;
    storage
        .put(CF_SETTLEMENTS, key, &bytes)
        .map_err(|e| SettleAuthorizedError::Unavailable(format!("storage error: {e}")))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_registry::{AppRecord, AppRegistry, AppSigningKey, METHOD_REGISTER_APP};
    use tenzro_crypto::keys::KeyPair;
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_identity::canonical_preimage;
    use tenzro_identity::envelope::{TenzroDidEnvelope, params_hash};
    use tenzro_storage::MemoryStore;
    use tenzro_types::identity::KycTier;

    fn did_key_signer() -> (String, Ed25519SignerImpl) {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pk = kp.public_key().as_bytes().to_vec();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&pk);
        let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
        (did, Ed25519SignerImpl::new(kp).unwrap())
    }

    struct Fixture {
        apps: Arc<AppRegistry>,
        identities: IdentityRegistry,
        token: TnzoToken,
        storage: Arc<dyn KvStore>,
        app_wallet: Address,
        treasury: Address,
        payer_did: String,
        payer_wallet: Address,
        /// Signs settlement authorizations under key_id "backend-1".
        auth_signer: Ed25519SignerImpl,
    }

    async fn fixture(daily_limit: Option<u128>, app_wallet_balance: u128) -> Fixture {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let apps = AppRegistry::new(storage.clone()).unwrap();
        let identities = IdentityRegistry::new();
        let token = TnzoToken::new();

        let treasury = Address::new([0x01; 32]);
        let app_wallet = Address::new([0x02; 32]);
        token.set_treasury_address(treasury);
        if app_wallet_balance > 0 {
            token
                .mint(&app_wallet, app_wallet_balance, &treasury)
                .unwrap();
        }

        // Register the app with a developer-signed envelope.
        let (dev_did, dev_signer) = did_key_signer();
        let auth_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let auth_pubkey = auth_kp.public_key().as_bytes().to_vec();
        let auth_signer = Ed25519SignerImpl::new(auth_kp).unwrap();
        let record = AppRecord {
            app_id: "demo-app".to_string(),
            developer_did: dev_did.clone(),
            app_wallet,
            signing_pubkeys: vec![AppSigningKey {
                key_id: "backend-1".to_string(),
                public_key: auth_pubkey,
                daily_limit_tnzo: daily_limit,
            }],
            margin_bps: 0,
            min_balance: 100,
            created_at: 0,
            active: true,
        };
        let mut env = TenzroDidEnvelope {
            did: dev_did,
            method: METHOD_REGISTER_APP.to_string(),
            params_hash: params_hash(&record.canonical_params()),
            timestamp: now_ms(),
            nonce: [7u8; 16],
            signature: Vec::new(),
        };
        env.signature = dev_signer
            .sign(&canonical_preimage(&env))
            .unwrap()
            .as_bytes()
            .to_vec();
        apps.register_signed(record, &env, &identities).unwrap();

        // Register a payer identity (default placeholder wallet is derived
        // from the DID, so it is non-zero and receivable).
        let result = identities
            .register_human_with_fee(vec![9u8; 32], "payer".to_string(), KycTier::Unverified)
            .await
            .unwrap();
        let payer_did = result.identity.did.to_string();
        let payer_wallet = result.identity.wallet_address;

        Fixture {
            apps,
            identities,
            token,
            storage,
            app_wallet,
            treasury,
            payer_did,
            payer_wallet,
            auth_signer,
        }
    }

    fn signed_auth(fx: &Fixture, amount: u128, external_ref: &str) -> SettlementAuthorization {
        let mut auth = SettlementAuthorization {
            app_id: "demo-app".to_string(),
            chain_id: 1337,
            payer_did: fx.payer_did.clone(),
            amount_tnzo: amount,
            external_ref: external_ref.to_string(),
            nonce: [5u8; 32],
            expiry: now_ms() + 60_000,
            key_id: "backend-1".to_string(),
            signature: Vec::new(),
        };
        auth.signature = fx
            .auth_signer
            .sign(&auth.signing_hash())
            .unwrap()
            .as_bytes()
            .to_vec();
        auth
    }

    fn run(
        fx: &Fixture,
        auth: &SettlementAuthorization,
    ) -> Result<(SettleAuthorizedOutcome, bool), SettleAuthorizedError> {
        execute_settle_authorized(auth, 1337, &fx.apps, &fx.identities, &fx.token, &fx.storage)
    }

    #[tokio::test]
    async fn settles_and_splits_commission() {
        let fx = fixture(None, 1_000_000).await;
        let auth = signed_auth(&fx, 10_000, "pi_1");

        let (outcome, duplicate) = run(&fx, &auth).unwrap();
        assert!(!duplicate);
        assert!(outcome.success);
        // 50 bps of 10_000 = 50.
        assert_eq!(outcome.commission_tnzo, 50);
        assert_eq!(outcome.payer_net_tnzo, 9_950);
        assert_eq!(fx.token.balance_of(&fx.payer_wallet), 9_950);
        assert_eq!(fx.token.balance_of(&fx.treasury), 50);
        assert_eq!(fx.token.balance_of(&fx.app_wallet), 990_000);
        assert!(outcome.app_wallet_funded);
    }

    #[tokio::test]
    async fn replay_returns_original_outcome_without_moving_funds() {
        let fx = fixture(None, 1_000_000).await;
        let auth = signed_auth(&fx, 10_000, "pi_1");

        let (first, _) = run(&fx, &auth).unwrap();
        let (second, duplicate) = run(&fx, &auth).unwrap();
        assert!(duplicate);
        assert_eq!(first, second);
        // Funds moved exactly once.
        assert_eq!(fx.token.balance_of(&fx.payer_wallet), 9_950);
        assert_eq!(fx.token.balance_of(&fx.app_wallet), 990_000);
    }

    #[tokio::test]
    async fn wrong_chain_is_rejected() {
        let fx = fixture(None, 1_000_000).await;
        let mut auth = signed_auth(&fx, 10_000, "pi_1");
        auth.chain_id = 1;
        auth.signature = fx
            .auth_signer
            .sign(&auth.signing_hash())
            .unwrap()
            .as_bytes()
            .to_vec();
        // Signature is valid for chain 1, but this node settles chain 1337.
        assert!(matches!(
            run(&fx, &auth),
            Err(SettleAuthorizedError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn tampered_amount_fails_signature() {
        let fx = fixture(None, 1_000_000).await;
        let mut auth = signed_auth(&fx, 10_000, "pi_1");
        auth.amount_tnzo = 999_999;
        assert!(matches!(
            run(&fx, &auth),
            Err(SettleAuthorizedError::Unauthorized(_))
        ));
        // Nothing persisted: original amount still settles.
        let auth = signed_auth(&fx, 10_000, "pi_1");
        assert!(run(&fx, &auth).unwrap().0.success);
    }

    #[tokio::test]
    async fn expired_authorization_is_rejected_without_consuming_ref() {
        let fx = fixture(None, 1_000_000).await;
        let mut auth = signed_auth(&fx, 10_000, "pi_1");
        auth.expiry = now_ms().saturating_sub(1_000);
        auth.signature = fx
            .auth_signer
            .sign(&auth.signing_hash())
            .unwrap()
            .as_bytes()
            .to_vec();
        assert!(matches!(
            run(&fx, &auth),
            Err(SettleAuthorizedError::InvalidRequest(_))
        ));
        // A fresh authorization for the same external_ref still settles.
        let auth = signed_auth(&fx, 10_000, "pi_1");
        assert!(run(&fx, &auth).unwrap().0.success);
    }

    #[tokio::test]
    async fn underfunded_wallet_records_terminal_failure() {
        let fx = fixture(None, 5_000).await;
        let auth = signed_auth(&fx, 10_000, "pi_1");

        let (outcome, duplicate) = run(&fx, &auth).unwrap();
        assert!(!duplicate);
        assert!(!outcome.success);
        assert!(
            outcome
                .failure_reason
                .as_deref()
                .unwrap()
                .contains("underfunded")
        );
        assert_eq!(fx.token.balance_of(&fx.payer_wallet), 0);

        // Funding the wallet does NOT resurrect the consumed reference —
        // the developer refunds the fiat and issues a new charge.
        fx.token
            .mint(&fx.app_wallet, 1_000_000, &fx.treasury)
            .unwrap();
        let (replay, duplicate) = run(&fx, &auth).unwrap();
        assert!(duplicate);
        assert!(!replay.success);
    }

    #[tokio::test]
    async fn daily_limit_blocks_excess_spend() {
        let fx = fixture(Some(15_000), 1_000_000).await;

        let first = signed_auth(&fx, 10_000, "pi_1");
        assert!(run(&fx, &first).unwrap().0.success);

        // 10_000 spent; another 10_000 would exceed the 15_000 ceiling.
        let second = signed_auth(&fx, 10_000, "pi_2");
        assert!(matches!(
            run(&fx, &second),
            Err(SettleAuthorizedError::Unauthorized(_))
        ));

        // A smaller amount inside the remaining headroom settles.
        let third = signed_auth(&fx, 5_000, "pi_3");
        assert!(run(&fx, &third).unwrap().0.success);
    }

    #[tokio::test]
    async fn unknown_key_id_is_rejected() {
        let fx = fixture(None, 1_000_000).await;
        let mut auth = signed_auth(&fx, 10_000, "pi_1");
        auth.key_id = "other-key".to_string();
        auth.signature = fx
            .auth_signer
            .sign(&auth.signing_hash())
            .unwrap()
            .as_bytes()
            .to_vec();
        assert!(matches!(
            run(&fx, &auth),
            Err(SettleAuthorizedError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn get_outcome_reads_recorded_row() {
        let fx = fixture(None, 1_000_000).await;
        assert!(
            get_outcome(&fx.storage, "demo-app", "pi_1")
                .unwrap()
                .is_none()
        );
        let auth = signed_auth(&fx, 10_000, "pi_1");
        let (outcome, _) = run(&fx, &auth).unwrap();
        assert_eq!(
            get_outcome(&fx.storage, "demo-app", "pi_1")
                .unwrap()
                .unwrap(),
            outcome
        );
    }
}
