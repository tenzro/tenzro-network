//! Unified payment gateway
//!
//! Routes payment operations across the protocols a node serves (MPP, x402)
//! and settles every verified payment on a settlement rail before a receipt
//! exists.
//!
//! The order of operations in [`TenzroPaymentGateway::verify_and_settle`] is
//! the security argument:
//!
//! 1. **Claim** the challenge atomically, so two submissions of one credential
//!    cannot both proceed.
//! 2. **Check the expectation**: a gate serving a priced resource only accepts
//!    a challenge minted for that resource, that payee, at least that price,
//!    in that asset.
//! 3. **Verify** the credential through its protocol. A failed verification is
//!    an error; there is no "unverified" value to settle by mistake.
//! 4. **Validate the payer's identity** (delegation scope, spending policy,
//!    lifecycle) when the payer names a DID.
//! 5. **Settle** on the rail that carries the asset, and wait for the rail to
//!    report the funds moved. The Tenzro Ledger rail reports after the
//!    settlement transaction executed in a finalized block; an asynchronous
//!    rail reports pending, and the resource is not served until it settles.
//! 6. **Consume** the challenge and issue the receipt.
//!
//! Any failure before step 6 releases the claim, so a valid credential can
//! still pay the challenge later.

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::payer_auth::{
    APP_WALLET_KEY, MARGIN_BPS_KEY, PayerKeyResolver, VerifiedPayer, parse_tenzro_address,
};
use crate::receipt_ledger::ReceiptLedger;
use crate::terms_gate::{PaymentIntent, TermsGate};
use crate::traits::{PaymentGateway, PaymentProtocol};
use crate::types::{
    PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification, SettlementLeg,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use tenzro_storage::kv::KvStore;
use tenzro_types::Address;
use tracing::{debug, info, warn};

/// What a settlement rail is asked to move.
#[derive(Debug, Clone)]
pub struct SettlementInstruction {
    /// The replay key on every rail: the challenge id. A second settlement
    /// under the same id is refused by the rail itself.
    pub payment_id: String,
    /// The payer, with the authorization it signed.
    pub payer: VerifiedPayer,
    /// The payee named by the challenge.
    pub payee: Address,
    /// Amount to move, never above the signed ceiling.
    pub amount: u128,
    /// Asset symbol, as signed. Any developer margin is the one in the
    /// payer's signed binding.
    pub asset: String,
}

/// What a rail reports after being asked to settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailOutcome {
    /// Funds moved. `reference` identifies the movement on the rail (the
    /// Tenzro transaction hash, or the rail's transfer id).
    Settled {
        /// Rail-side reference.
        reference: String,
    },
    /// The rail accepted the instruction and will settle asynchronously.
    Pending {
        /// Rail-side reference to poll or reconcile.
        reference: String,
    },
    /// The rail will not move these funds (returned, canceled, reverted).
    Failed {
        /// Why.
        reason: String,
    },
}

/// A place a verified payment can settle.
#[async_trait]
pub trait SettlementRail: Send + Sync {
    /// Stable rail name for receipts and logs.
    fn name(&self) -> &'static str;

    /// Whether this rail moves `asset` (compared case-insensitively).
    fn carries(&self, asset: &str) -> bool;

    /// Move the funds, returning only once the rail can say what happened.
    async fn settle(&self, instruction: &SettlementInstruction) -> Result<RailOutcome>;

    /// The current outcome of an instruction previously accepted as pending.
    async fn status(&self, payment_id: &str) -> Result<RailOutcome>;
}

/// Settles a payer's own signed settlement plan: admits the plan
/// transaction the payer signed and reads the plan it opened from chain
/// state. The plan's value moves only by that transaction, under the
/// payer's key.
#[async_trait]
pub trait PlanRail: Send + Sync {
    /// Admit `signed` and wait for it to execute: settled under its hash
    /// once it executed successfully, failed with its revert reason, or
    /// pending when it has not executed within the wait.
    async fn open(
        &self,
        signed: &tenzro_types::transaction::SignedTransaction,
    ) -> Result<RailOutcome>;

    /// The plan `plan_id` and the receipts of its decided legs, by leg
    /// index, from chain state.
    fn plan(
        &self,
        plan_id: &[u8; 32],
    ) -> Option<(
        tenzro_types::settlement::SettlementPlan,
        Vec<tenzro_types::settlement::LegReceipt>,
    )>;
}

/// Accepts cumulative vouchers drawn on on-chain escrows.
///
/// The escrow is funded on the Tenzro Ledger by the payer's own signed
/// transaction; a voucher lets the payee claim from it. Accepting a voucher as
/// payment is sound only after checking the escrow on consensus state, which
/// is what an implementation must do before answering `Settled`.
#[async_trait]
pub trait VoucherRail: Send + Sync {
    /// Accept `voucher` as payment of `charge` to `payee`. Implementations
    /// check that the escrow exists and is funded, pays `payee`, is owed by
    /// the voucher key's account, holds at least the cumulative amount, will
    /// not expire before it can be claimed, and that the voucher advances the
    /// highest voucher already accepted by at least `charge`.
    async fn accept(
        &self,
        voucher: &tenzro_types::payment_authorization::EscrowVoucher,
        payee: &Address,
        charge: u128,
    ) -> Result<RailOutcome>;

    /// Every check [`Self::accept`] makes, accepting nothing: a facilitator
    /// answers `/verify` with it.
    async fn check(
        &self,
        voucher: &tenzro_types::payment_authorization::EscrowVoucher,
        payee: &Address,
        charge: u128,
    ) -> Result<RailOutcome>;
}

/// Resolves a payee's declared settlement preference.
///
/// A gateway with no resolver treats every payee as
/// [`SettlementAsset::KeepInbound`](crate::settlement_asset::SettlementAsset::KeepInbound).
pub trait SettlementPreferencesResolver: Send + Sync {
    /// The preferences to apply to this settlement.
    fn preferences(&self) -> crate::settlement_asset::SettlementPreferences;
}

/// What the party accepting a payment expects it to pay for.
#[derive(Debug, Clone, Copy)]
pub enum PaymentExpectation<'a> {
    /// The payer is settling a challenge it was issued, and the challenge
    /// itself defines what is bought (the JSON-RPC pay methods).
    Challenge,
    /// A gate is serving a priced resource. The challenge must have been
    /// minted for this resource and payee, for at least this price, in this
    /// asset.
    Resource {
        /// The resource path being served.
        resource: &'a str,
        /// The address the gate's operator is paid at.
        payee: &'a str,
        /// The price of this request.
        min_amount: u128,
        /// The asset the price is in.
        asset: &'a str,
    },
}

impl PaymentExpectation<'_> {
    fn check(&self, challenge: &PaymentChallenge) -> Result<()> {
        let PaymentExpectation::Resource {
            resource,
            payee,
            min_amount,
            asset,
        } = *self
        else {
            return Ok(());
        };
        if challenge.resource != resource {
            return Err(PaymentError::WrongResource(format!(
                "challenge {} was minted for resource '{}', not '{}'",
                challenge.challenge_id, challenge.resource, resource
            )));
        }
        let challenge_payee = parse_tenzro_address(&challenge.recipient)?;
        let gate_payee = parse_tenzro_address(payee)?;
        if challenge_payee != gate_payee {
            return Err(PaymentError::WrongResource(format!(
                "challenge {} pays {}, not this resource's payee",
                challenge.challenge_id, challenge.recipient
            )));
        }
        if challenge.amount < min_amount {
            return Err(PaymentError::WrongResource(format!(
                "challenge {} is for {}, below the price {}",
                challenge.challenge_id, challenge.amount, min_amount
            )));
        }
        if !challenge.asset.eq_ignore_ascii_case(asset) {
            return Err(PaymentError::WrongResource(format!(
                "challenge {} is in {}, the price is in {}",
                challenge.challenge_id, challenge.asset, asset
            )));
        }
        Ok(())
    }
}

/// Multi-protocol payment gateway for Tenzro Network
pub struct TenzroPaymentGateway {
    protocols: DashMap<String, Arc<dyn PaymentProtocol>>,
    /// Shared challenge store — same instance passed to protocol servers
    challenge_store: ChallengeStore,
    /// Chain id stamped on every challenge; payer authorizations sign it.
    chain_id: u64,
    /// Rails a verified payment can settle on, tried in order by asset.
    rails: Vec<Arc<dyn SettlementRail>>,
    /// Rail accepting escrow vouchers, when the node can read escrow state.
    voucher_rail: Option<Arc<dyn VoucherRail>>,
    /// Optional payee settlement-preference resolver. When unset, every payee
    /// keeps the asset that arrived.
    settlement_preferences: Option<Arc<dyn SettlementPreferencesResolver>>,
    /// Resolves a payer DID to the keys and account it stands behind.
    payer_resolver: Option<Arc<dyn PayerKeyResolver>>,
    /// The ML-DSA-65 keys accounts enrolled in chain state, which payers'
    /// signatures verify against.
    enrolled_keys: Arc<dyn crate::payer_auth::EnrolledKeys>,
    /// The payer's consensus Terms check. Set once chain state is readable,
    /// after the gateway is built; a payer DID is refused until it is.
    terms_gate: OnceLock<Arc<dyn TermsGate>>,
    /// Receipts of settled challenges, so a retried credential gets its
    /// receipt back instead of an error.
    receipts: Arc<ReceiptLedger>,
    /// Instructions a rail accepted as pending, keyed by challenge id.
    pending: DashMap<String, PendingSettlement>,
}

#[derive(Debug, Clone)]
struct PendingSettlement {
    credential_id: String,
    rail: &'static str,
    receipt: PaymentReceipt,
}

impl TenzroPaymentGateway {
    /// Creates a new payment gateway settling challenges for `chain_id`,
    /// verifying payers against the keys their accounts enrolled.
    pub fn new(chain_id: u64, enrolled_keys: Arc<dyn crate::payer_auth::EnrolledKeys>) -> Self {
        Self {
            protocols: DashMap::new(),
            challenge_store: ChallengeStore::new(),
            chain_id,
            rails: Vec::new(),
            voucher_rail: None,
            settlement_preferences: None,
            payer_resolver: None,
            enrolled_keys,
            terms_gate: OnceLock::new(),
            receipts: Arc::new(ReceiptLedger::new()),
            pending: DashMap::new(),
        }
    }

    /// Creates a new payment gateway backed by persistent storage.
    ///
    /// The challenge store is initialized with storage so challenges
    /// survive node restarts.
    pub fn with_storage(
        chain_id: u64,
        enrolled_keys: Arc<dyn crate::payer_auth::EnrolledKeys>,
        storage: Arc<dyn KvStore>,
    ) -> Self {
        Self {
            challenge_store: ChallengeStore::with_storage(storage),
            ..Self::new(chain_id, enrolled_keys)
        }
    }

    /// The reader of the keys accounts enrolled, for the protocol servers
    /// this gateway registers.
    pub fn enrolled_keys(&self) -> Arc<dyn crate::payer_auth::EnrolledKeys> {
        Arc::clone(&self.enrolled_keys)
    }

    /// Attach a settlement rail. Rails are consulted in the order attached;
    /// the first that carries the payment's asset settles it.
    pub fn with_rail(mut self, rail: Arc<dyn SettlementRail>) -> Self {
        self.rails.push(rail);
        self
    }

    /// Attach the rail that accepts escrow vouchers.
    pub fn with_voucher_rail(mut self, rail: Arc<dyn VoucherRail>) -> Self {
        self.voucher_rail = Some(rail);
        self
    }

    /// Attach the payee settlement-preference resolver.
    pub fn with_settlement_preferences(
        mut self,
        resolver: Arc<dyn SettlementPreferencesResolver>,
    ) -> Self {
        self.settlement_preferences = Some(resolver);
        self
    }

    /// Attach the resolver that binds a payer DID to its keys and account.
    pub fn with_payer_resolver(mut self, resolver: Arc<dyn PayerKeyResolver>) -> Self {
        self.payer_resolver = Some(resolver);
        self
    }

    /// Attach the durable receipt ledger for settled challenges.
    pub fn with_receipt_ledger(mut self, ledger: Arc<ReceiptLedger>) -> Self {
        self.receipts = ledger;
        self
    }

    /// Install the Terms check once chain state is readable. Returns `false`
    /// if one was already installed.
    pub fn set_terms_gate(&self, gate: Arc<dyn TermsGate>) -> bool {
        self.terms_gate.set(gate).is_ok()
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

    /// The chain id this gateway stamps on challenges.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Names of the attached rails, in order.
    pub fn rail_names(&self) -> Vec<&'static str> {
        self.rails.iter().map(|r| r.name()).collect()
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

    fn rail_for(&self, asset: &str) -> Result<Arc<dyn SettlementRail>> {
        self.rails
            .iter()
            .find(|r| r.carries(asset))
            .cloned()
            .ok_or_else(|| {
                PaymentError::SettlementError(format!(
                    "no settlement rail on this node moves {asset}; the payment is refused \
                     rather than accepted without moving funds"
                ))
            })
    }

    /// Refuse a payment the payee's declared preference cannot be met with.
    fn check_settlement_preference(&self, challenge: &PaymentChallenge) -> Result<()> {
        use crate::settlement_asset::{Caip19, route_settlement};
        let Some(resolver) = self.settlement_preferences.as_ref() else {
            return Ok(());
        };
        // A bare symbol ("TNZO", "USDC") names the asset the rail moves; only
        // a chain-qualified asset has a preference to route against.
        let Ok(inbound) = Caip19::parse(&challenge.asset) else {
            return Ok(());
        };
        let payee_did = challenge
            .extra
            .get("payee_did")
            .and_then(|v| v.as_str())
            .unwrap_or(&challenge.recipient);
        // No swap venue moves funds on this node, so a payee who asked for a
        // different asset than the one inbound is refused, not converted.
        route_settlement(
            payee_did,
            &inbound,
            challenge.amount,
            &resolver.preferences(),
            None,
        )
        .map(|_| ())
    }

    /// Mint a challenge through a protocol and stamp it with this gateway's
    /// chain id, which every payer authorization signs.
    async fn mint(
        &self,
        protocol: &str,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        // The payee must be a Tenzro address: that is what the payer signs
        // and what the settlement rail credits.
        parse_tenzro_address(recipient)?;
        let proto = self.get_protocol(protocol)?;
        let mut challenge = proto
            .create_challenge(resource, amount, asset, recipient)
            .await?;
        challenge.extra.insert(
            crate::payer_auth::CHAIN_ID_KEY.to_string(),
            serde_json::json!(self.chain_id),
        );
        self.challenge_store.store(&challenge)?;
        Ok(challenge)
    }

    /// One challenge for a quote, offered over every protocol in
    /// `protocols`: the payer signs one authorization for it, bound to the
    /// quote, and presents it over whichever protocol it holds. Each
    /// protocol's own challenge fields are kept, the first protocol is the
    /// challenge's, and the challenge settles once, whichever protocol pays
    /// it.
    pub async fn create_quote_challenge(
        &self,
        protocols: &[&str],
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
        quote_digest: [u8; 32],
    ) -> Result<PaymentChallenge> {
        let (first, rest) = protocols.split_first().ok_or_else(|| {
            PaymentError::ChallengeError("a quote is offered over at least one protocol".into())
        })?;
        parse_tenzro_address(recipient)?;
        let mut challenge = self
            .get_protocol(first)?
            .create_challenge(resource, amount, asset, recipient)
            .await?;
        for name in rest {
            let other = self
                .get_protocol(name)?
                .create_challenge(resource, amount, asset, recipient)
                .await?;
            for (k, v) in other.extra {
                challenge.extra.entry(k).or_insert(v);
            }
        }
        challenge.extra.insert(
            crate::payer_auth::CHAIN_ID_KEY.to_string(),
            serde_json::json!(self.chain_id),
        );
        challenge.extra.insert(
            crate::payer_auth::QUOTE_DIGEST_KEY.to_string(),
            serde_json::json!(hex::encode(quote_digest)),
        );
        challenge.extra.insert(
            OFFERED_PROTOCOLS_KEY.to_string(),
            serde_json::json!(
                protocols
                    .iter()
                    .map(|p| p.to_lowercase())
                    .collect::<Vec<_>>()
            ),
        );
        self.challenge_store.store(&challenge)?;
        Ok(challenge)
    }

    /// A settled or pending outcome for a credential whose challenge is no
    /// longer claimable.
    async fn resume(&self, credential: &PaymentCredential) -> Option<Result<PaymentReceipt>> {
        if let Some(prior) = self.receipts.get(&credential.challenge_id) {
            if prior.credential_id == credential.credential_id {
                return Some(Ok(prior));
            }
            return Some(Err(PaymentError::ReplayDetected(format!(
                "challenge {} was already paid by another credential",
                credential.challenge_id
            ))));
        }
        let pending = self
            .pending
            .get(&credential.challenge_id)
            .map(|p| p.clone())?;
        if pending.credential_id != credential.credential_id {
            return Some(Err(PaymentError::ReplayDetected(format!(
                "challenge {} is being paid by another credential",
                credential.challenge_id
            ))));
        }
        Some(self.poll_pending(&credential.challenge_id, pending).await)
    }

    async fn poll_pending(
        &self,
        challenge_id: &str,
        pending: PendingSettlement,
    ) -> Result<PaymentReceipt> {
        let rail = self
            .rails
            .iter()
            .find(|r| r.name() == pending.rail)
            .cloned()
            .ok_or_else(|| {
                PaymentError::SettlementError(format!(
                    "rail {} is no longer attached",
                    pending.rail
                ))
            })?;
        match rail.status(challenge_id).await? {
            RailOutcome::Settled { reference } => {
                let mut receipt = pending.receipt;
                receipt.settlement_tx = Some(reference);
                receipt.settled_at = chrono::Utc::now();
                self.pending.remove(challenge_id);
                self.challenge_store.consume(challenge_id);
                self.receipts.record(challenge_id, receipt)
            }
            RailOutcome::Pending { reference } => Err(PaymentError::SettlementPending(format!(
                "{} transfer {} for challenge {} has not settled",
                pending.rail, reference, challenge_id
            ))),
            RailOutcome::Failed { reason } => {
                // The rail will not move these funds: free the challenge so a
                // new credential can pay it.
                self.pending.remove(challenge_id);
                self.challenge_store.release(challenge_id);
                Err(PaymentError::SettlementError(format!(
                    "{} settlement for challenge {} failed: {}",
                    pending.rail, challenge_id, reason
                )))
            }
        }
    }

    /// See [`PaymentGateway::verify_metered`]. Unlike [`preflight`](Self::preflight)
    /// it does not run the protocol's own verification, which for a metered
    /// challenge checks a usage record that exists only once the work is done.
    async fn verify_metered_inner(
        &self,
        credential: &PaymentCredential,
        expect: PaymentExpectation<'_>,
    ) -> Result<PaymentChallenge> {
        if credential
            .extra
            .contains_key(crate::payer_auth::CUMULATIVE_AMOUNT_KEY)
            && !credential
                .extra
                .contains_key(crate::payer_auth::UPTO_MAX_KEY)
        {
            return self.verify_metered_voucher(credential, expect).await;
        }
        if !credential
            .extra
            .contains_key(crate::payer_auth::UPTO_MAX_KEY)
        {
            return Err(PaymentError::CredentialError(
                "only a metered credential (one carrying upto_max) is checked before serving"
                    .to_string(),
            ));
        }
        let challenge = self.challenge_store.get(&credential.challenge_id)?;
        if challenge.expires_at <= chrono::Utc::now() {
            return Err(PaymentError::ChallengeError(format!(
                "Challenge {} has expired",
                challenge.challenge_id
            )));
        }
        expect.check(&challenge)?;
        if !offers_protocol(&challenge, &credential.protocol) {
            return Err(PaymentError::VerificationFailed(format!(
                "credential protocol {} is not one challenge {} is offered over",
                credential.protocol, challenge.challenge_id
            )));
        }
        let mut payer =
            crate::payer_auth::verify_payer(self.enrolled_keys.as_ref(), &challenge, credential)?;
        crate::payer_auth::bind_payer_did(
            &mut payer,
            &credential.payer_did,
            self.payer_resolver.as_deref(),
        )?;
        let ceiling = payer.authorization.max_amount;
        let verification = PaymentVerification {
            credential_id: credential.credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: credential.payer_did.clone(),
            verified_at: chrono::Utc::now(),
            amount: ceiling,
            leg: SettlementLeg::Payer(payer),
            detail: None,
        };
        self.check_payer_identity(&challenge, &verification)?;
        Ok(challenge)
    }

    /// A voucher credential answering a metered challenge, checked before the
    /// work: the challenge offered the voucher's scheme, the voucher is the
    /// payer's (or its serving node's, for an agent), and this node's voucher
    /// rail would accept it now with room for a charge. Its declared amount is
    /// the ceiling; the metered cost is charged against it once known.
    async fn verify_metered_voucher(
        &self,
        credential: &PaymentCredential,
        expect: PaymentExpectation<'_>,
    ) -> Result<PaymentChallenge> {
        let challenge = self.challenge_store.get(&credential.challenge_id)?;
        if challenge.expires_at <= chrono::Utc::now() {
            return Err(PaymentError::ChallengeError(format!(
                "Challenge {} has expired",
                challenge.challenge_id
            )));
        }
        expect.check(&challenge)?;
        if !offers_protocol(&challenge, &credential.protocol) {
            return Err(PaymentError::VerificationFailed(format!(
                "credential protocol {} is not one challenge {} is offered over",
                credential.protocol, challenge.challenge_id
            )));
        }
        if !crate::x402::wire::offered_schemes(&challenge)
            .iter()
            .any(|s| s == crate::x402::BATCH_SETTLEMENT_SCHEME)
        {
            return Err(PaymentError::VerificationFailed(format!(
                "challenge {} does not take vouchers",
                challenge.challenge_id
            )));
        }
        let voucher = crate::payer_auth::verify_escrow_voucher(
            self.enrolled_keys.as_ref(),
            &challenge,
            credential,
        )?;
        let rail = self.voucher_rail.as_ref().ok_or_else(|| {
            PaymentError::SettlementError(
                "this node cannot read escrow state, so it cannot accept vouchers".to_string(),
            )
        })?;
        let payee = parse_tenzro_address(&challenge.recipient)?;
        match rail.check(&voucher, &payee, 1).await? {
            RailOutcome::Settled { .. } => Ok(challenge),
            RailOutcome::Pending { reference: why } | RailOutcome::Failed { reason: why } => Err(
                PaymentError::VerificationFailed(format!("voucher would not pay: {why}")),
            ),
        }
    }

    async fn settle_claimed(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
        expect: &PaymentExpectation<'_>,
    ) -> Result<PaymentReceipt> {
        expect.check(challenge)?;
        if !offers_protocol(challenge, &credential.protocol) {
            return Err(PaymentError::VerificationFailed(format!(
                "credential protocol {} is not one challenge {} is offered over",
                credential.protocol, challenge.challenge_id
            )));
        }
        let proto = self.get_protocol(&credential.protocol)?;
        let mut verification = proto.verify_credential(challenge, credential).await?;
        // The DID the protocol attributes the payment to must stand behind the
        // key that authorized the payment.
        let payer_did = verification.payer_did.clone();
        if let SettlementLeg::Payer(payer) = &mut verification.leg {
            crate::payer_auth::bind_payer_did(payer, &payer_did, self.payer_resolver.as_deref())?;
        }
        self.check_payer_identity(challenge, &verification)?;
        self.check_settlement_preference(challenge)?;

        let mut receipt = proto.settle(challenge, credential, &verification).await?;
        receipt.amount = verification.amount;

        let payer = match &verification.leg {
            SettlementLeg::Payer(payer) => payer,
            SettlementLeg::Foreign => {
                // The scheme settled on its own chain inside `settle`; it
                // must have produced that chain's transaction.
                if receipt.settlement_tx.is_none() {
                    return Err(PaymentError::SettlementError(format!(
                        "scheme for challenge {} reported no settlement transaction",
                        challenge.challenge_id
                    )));
                }
                receipt
                    .extra
                    .insert("settlement_rail".to_string(), serde_json::json!("foreign"));
                return Ok(receipt);
            }
            SettlementLeg::Voucher(voucher) => {
                let rail = self.voucher_rail.as_ref().ok_or_else(|| {
                    PaymentError::SettlementError(
                        "this node cannot read escrow state, so it cannot accept vouchers"
                            .to_string(),
                    )
                })?;
                let payee = parse_tenzro_address(&challenge.recipient)?;
                return match rail.accept(voucher, &payee, verification.amount).await? {
                    RailOutcome::Settled { reference } => {
                        receipt.settlement_tx = Some(reference);
                        receipt
                            .extra
                            .insert("settlement_rail".to_string(), serde_json::json!("escrow"));
                        receipt.extra.insert(
                            "escrow_id".to_string(),
                            serde_json::json!(hex::encode(voucher.escrow_id)),
                        );
                        receipt.extra.insert(
                            "cumulative_amount".to_string(),
                            serde_json::json!(voucher.cumulative_amount.to_string()),
                        );
                        Ok(receipt)
                    }
                    RailOutcome::Pending { reference }
                    | RailOutcome::Failed { reason: reference } => {
                        Err(PaymentError::SettlementError(format!(
                            "voucher for challenge {} not accepted: {}",
                            challenge.challenge_id, reference
                        )))
                    }
                };
            }
        };

        let instruction = settlement_instruction(challenge, payer, verification.amount)?;
        let rail = self.rail_for(&instruction.asset)?;
        receipt.extra.insert(
            "settlement_rail".to_string(),
            serde_json::json!(rail.name()),
        );
        receipt.extra.insert(
            "payer_address".to_string(),
            serde_json::json!(hex::encode(payer.address.as_bytes())),
        );
        if let Some(margin) = payer.authorization.binding.app_margin {
            receipt.extra.insert(
                MARGIN_BPS_KEY.to_string(),
                serde_json::json!(margin.margin_bps),
            );
            receipt.extra.insert(
                APP_WALLET_KEY.to_string(),
                serde_json::json!(hex::encode(margin.app_wallet.as_bytes())),
            );
            if let Some(v) = challenge.extra.get("app_id") {
                receipt.extra.insert("app_id".to_string(), v.clone());
            }
        }

        match rail.settle(&instruction).await? {
            RailOutcome::Settled { reference } => {
                info!(
                    "payment {} settled on {}: {}",
                    challenge.challenge_id,
                    rail.name(),
                    reference
                );
                receipt.settlement_tx = Some(reference);
                Ok(receipt)
            }
            RailOutcome::Pending { reference } => {
                self.pending.insert(
                    challenge.challenge_id.clone(),
                    PendingSettlement {
                        credential_id: credential.credential_id.clone(),
                        rail: rail.name(),
                        receipt,
                    },
                );
                Err(PaymentError::SettlementPending(format!(
                    "{} accepted transfer {} for challenge {}",
                    rail.name(),
                    reference,
                    challenge.challenge_id
                )))
            }
            RailOutcome::Failed { reason } => Err(PaymentError::SettlementError(format!(
                "{} refused challenge {}: {}",
                rail.name(),
                challenge.challenge_id,
                reason
            ))),
        }
    }

    fn check_payer_identity(
        &self,
        challenge: &PaymentChallenge,
        verification: &PaymentVerification,
    ) -> Result<()> {
        let SettlementLeg::Payer(payer) = &verification.leg else {
            return Ok(());
        };
        let Some(did) = payer.did.as_deref() else {
            return Ok(());
        };
        let gate = self.terms_gate.get().ok_or_else(|| {
            PaymentError::VerificationFailed("payer Terms cannot be read yet".to_string())
        })?;
        gate.authorize(&PaymentIntent {
            payer_did: did,
            amount: verification.amount,
            operation: "payment",
            protocol: Some(&challenge.protocol),
            chain: Some(&challenge.chain),
            counterparty: Some(&challenge.recipient),
        })
    }

    /// Check a credential against its challenge without settling or claiming
    /// it: the signature, the payer binding and the payer DID. Refused for
    /// protocols whose verification spends a replay nonce, since checking
    /// would spend the credential.
    pub async fn preflight(&self, credential: &PaymentCredential) -> Result<PaymentVerification> {
        let challenge = self.challenge_store.get(&credential.challenge_id)?;
        if challenge.expires_at <= chrono::Utc::now() {
            return Err(PaymentError::ChallengeError(format!(
                "Challenge {} has expired",
                challenge.challenge_id
            )));
        }
        if !offers_protocol(&challenge, &credential.protocol) {
            return Err(PaymentError::VerificationFailed(format!(
                "credential protocol {} is not one challenge {} is offered over",
                credential.protocol, challenge.challenge_id
            )));
        }
        let proto = self.get_protocol(&credential.protocol)?;
        if proto.verification_consumes_nonce() {
            return Err(PaymentError::UnsupportedProtocol(format!(
                "{} verification spends its nonce; present the credential for payment instead",
                challenge.protocol
            )));
        }
        let mut verification = proto.verify_credential(&challenge, credential).await?;
        let payer_did = verification.payer_did.clone();
        if let SettlementLeg::Payer(payer) = &mut verification.leg {
            crate::payer_auth::bind_payer_did(payer, &payer_did, self.payer_resolver.as_deref())?;
        }
        self.check_payer_identity(&challenge, &verification)?;
        Ok(verification)
    }

    /// Verify and settle a credential against what the caller expects it to
    /// pay for. See the module docs for the order of operations.
    async fn verify_and_settle_inner(
        &self,
        credential: &PaymentCredential,
        expect: PaymentExpectation<'_>,
    ) -> Result<PaymentReceipt> {
        let challenge = match self.challenge_store.claim(&credential.challenge_id) {
            Ok(c) => c,
            Err(claim_err) => {
                if let Some(outcome) = self.resume(credential).await {
                    return outcome;
                }
                return Err(claim_err);
            }
        };
        debug!(
            "claimed challenge {} for credential {} (amount={}, chain={})",
            challenge.challenge_id, credential.credential_id, challenge.amount, challenge.chain
        );

        match self.settle_claimed(&challenge, credential, &expect).await {
            Ok(receipt) => {
                self.challenge_store.consume(&challenge.challenge_id);
                self.receipts.record(&challenge.challenge_id, receipt)
            }
            // A pending rail keeps the claim until it settles or fails.
            Err(PaymentError::SettlementPending(msg)) => Err(PaymentError::SettlementPending(msg)),
            Err(e) => {
                warn!(
                    "payment for challenge {} refused: {}",
                    challenge.challenge_id, e
                );
                self.challenge_store.release(&challenge.challenge_id);
                Err(e)
            }
        }
    }
}

/// Key in `challenge.extra` listing every protocol a quote challenge is
/// offered over (see [`TenzroPaymentGateway::create_quote_challenge`]).
pub const OFFERED_PROTOCOLS_KEY: &str = "protocols";

/// Whether `challenge` may be paid over `protocol`: its own protocol, or one
/// it lists under [`OFFERED_PROTOCOLS_KEY`].
pub fn offers_protocol(challenge: &PaymentChallenge, protocol: &str) -> bool {
    challenge.protocol.eq_ignore_ascii_case(protocol)
        || challenge
            .extra
            .get(OFFERED_PROTOCOLS_KEY)
            .and_then(|v| v.as_array())
            .is_some_and(|a| {
                a.iter()
                    .any(|p| p.as_str().is_some_and(|p| p.eq_ignore_ascii_case(protocol)))
            })
}

/// Build the rail instruction for a payer-authorized payment.
fn settlement_instruction(
    challenge: &PaymentChallenge,
    payer: &VerifiedPayer,
    amount: u128,
) -> Result<SettlementInstruction> {
    Ok(SettlementInstruction {
        payment_id: challenge.challenge_id.clone(),
        payer: payer.clone(),
        payee: parse_tenzro_address(&challenge.recipient)?,
        amount,
        asset: payer.authorization.asset.clone(),
    })
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
        self.mint(protocol, resource, amount, asset, recipient)
            .await
    }

    async fn verify_and_settle(
        &self,
        credential: &PaymentCredential,
        expect: PaymentExpectation<'_>,
    ) -> Result<PaymentReceipt> {
        self.verify_and_settle_inner(credential, expect).await
    }

    async fn verify_metered(
        &self,
        credential: &PaymentCredential,
        expect: PaymentExpectation<'_>,
    ) -> Result<PaymentChallenge> {
        self.verify_metered_inner(credential, expect).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{RecordingRail, TestProtocol, signer};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PAYEE: &str = "0909090909090909090909090909090909090909";
    const OTHER: &str = "0707070707070707070707070707070707070707";

    /// One signed intent per quote, paid over whichever protocol the buyer
    /// holds: a quote challenge offered over x402 and MPP takes the one
    /// authorization the payer signed, over either protocol, and every rail
    /// it reaches is asked to move exactly what the quote states, by exactly
    /// that authorization; the receipt states the same, and the quote is paid
    /// once.
    #[tokio::test]
    async fn one_signed_intent_per_quote_pays_over_either_protocol_alike() {
        let rail = RecordingRail::new(RailOutcome::Failed {
            reason: "held".to_string(),
        });
        let keys: Arc<dyn crate::payer_auth::EnrolledKeys> =
            Arc::new(crate::test_support::SeedKeys);
        let gw = TenzroPaymentGateway::new(1337, keys.clone()).with_rail(rail.clone());
        gw.register_protocol(Arc::new(crate::x402::X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            keys.clone(),
        )));
        gw.register_protocol(Arc::new(crate::mpp::MppPaymentServer::new(keys)));
        let quote = [0x5a; 32];
        let ch = gw
            .create_quote_challenge(&["x402", "mpp"], "/quoted", 3000, "TNZO", PAYEE, quote)
            .await
            .expect("quote challenge");

        // The payer signs once.
        let s = signer();
        let signed =
            crate::payer_auth::sign_credential(&ch, "x402", "", &s, 3000, 3000).expect("signed");
        let over = |protocol: &str| {
            let mut c = signed.clone();
            c.protocol = protocol.to_string();
            c
        };

        // While the rail holds the payment, each protocol reaches it with the
        // same instruction, and the quote stays payable.
        for protocol in ["x402", "mpp"] {
            let refused = gw
                .verify_and_settle(&over(protocol), PaymentExpectation::Challenge)
                .await;
            assert!(refused.is_err(), "{protocol}: the rail held it");
        }
        let seen = rail.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "both protocols reached the rail");
        for i in &seen {
            assert_eq!(i.payment_id, ch.challenge_id, "one payment id per quote");
            assert_eq!(i.amount, 3000);
            assert_eq!(i.asset, "TNZO");
            assert_eq!(i.payee, parse_tenzro_address(PAYEE).unwrap());
            assert_eq!(i.payer.authorization.binding.quote_digest, quote);
            assert_eq!(i.payer.authorization, seen[0].payer.authorization);
            assert_eq!(i.payer.address, seen[0].payer.address);
        }

        // A protocol the quote is not offered over is refused, and does not reach the rail.
        assert!(
            gw.verify_and_settle(&over("test"), PaymentExpectation::Challenge)
                .await
                .is_err()
        );
        assert_eq!(rail.seen.lock().unwrap().len(), 2);

        // Released, it pays once over MPP, and the receipt states the quote.
        *rail.answer.lock().unwrap() = RailOutcome::Settled {
            reference: "0xtx".to_string(),
        };
        let receipt = gw
            .verify_and_settle(&over("mpp"), PaymentExpectation::Challenge)
            .await
            .expect("paid");
        assert_eq!(receipt.challenge_id, ch.challenge_id);
        assert_eq!((receipt.amount, receipt.asset.as_str()), (3000, "TNZO"));
        assert_eq!(receipt.settlement_tx.as_deref(), Some("0xtx"));
        assert_eq!(
            rail.seen.lock().unwrap()[2].payer.authorization,
            seen[0].payer.authorization
        );

        // The same intent over the other protocol does not pay again: it is
        // answered with the receipt it already has.
        let again = gw
            .verify_and_settle(&over("x402"), PaymentExpectation::Challenge)
            .await
            .expect("answered from the receipt");
        assert_eq!(again.receipt_id, receipt.receipt_id);
        assert_eq!(rail.seen.lock().unwrap().len(), 3);
    }

    fn gateway(rail: Arc<RecordingRail>) -> TenzroPaymentGateway {
        let gw =
            TenzroPaymentGateway::new(1337, std::sync::Arc::new(crate::test_support::SeedKeys))
                .with_rail(rail);
        gw.register_protocol(Arc::new(TestProtocol));
        gw
    }

    #[tokio::test]
    async fn a_verified_payment_settles_on_the_rail_before_a_receipt_exists() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xtx".to_string(),
        });
        let gw = gateway(rail.clone());
        let ch = gw
            .create_challenge("test", "/paid", 3000, "TNZO", PAYEE)
            .await
            .unwrap();
        let s = signer();
        let cred = TestProtocol.create_credential(&ch, "", &s).await.unwrap();
        let receipt = gw
            .verify_and_settle(&cred, PaymentExpectation::Challenge)
            .await
            .unwrap();
        assert_eq!(receipt.settlement_tx.as_deref(), Some("0xtx"));
        let seen = rail.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].payment_id, ch.challenge_id);
        assert_eq!(seen[0].amount, 3000);
        assert_eq!(
            seen[0].payer.address,
            Address::new(tenzro_crypto::composite::HybridSigner::public_key(&s).account_slot())
        );
    }

    #[tokio::test]
    async fn a_rail_failure_is_an_error_and_frees_the_challenge() {
        let rail = RecordingRail::new(RailOutcome::Failed {
            reason: "reverted: insufficient balance".to_string(),
        });
        let gw = gateway(rail.clone());
        let ch = gw
            .create_challenge("test", "/paid", 10, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&ch, "", &signer())
            .await
            .unwrap();
        assert!(
            gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
                .await
                .is_err()
        );
        // The claim was released: the challenge can be claimed again.
        assert!(gw.challenge_store().claim(&ch.challenge_id).is_ok());
    }

    #[tokio::test]
    async fn an_asset_no_rail_moves_is_refused() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "x".to_string(),
        });
        let gw = gateway(rail.clone());
        let ch = gw
            .create_challenge("test", "/paid", 10, "USDC", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&ch, "", &signer())
            .await
            .unwrap();
        let err = gw
            .verify_and_settle(&cred, PaymentExpectation::Challenge)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no settlement rail"), "{err}");
        assert_eq!(rail.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn concurrent_submissions_of_one_credential_settle_once() {
        let rail = Arc::new(RecordingRail {
            seen: Mutex::new(Vec::new()),
            answer: Mutex::new(RailOutcome::Settled {
                reference: "0xonce".to_string(),
            }),
            calls: AtomicUsize::new(0),
            delay_ms: 50,
        });
        let gw = Arc::new(gateway(rail.clone()));
        let ch = gw
            .create_challenge("test", "/paid", 10, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&ch, "", &signer())
            .await
            .unwrap();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let gw = gw.clone();
            let cred = cred.clone();
            tasks.push(tokio::spawn(async move {
                gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
                    .await
            }));
        }
        for t in tasks {
            let _ = t.await.unwrap();
        }
        assert_eq!(rail.calls.load(Ordering::SeqCst), 1);
        // A retry after settlement returns the same receipt, not a second charge.
        let again = gw
            .verify_and_settle(&cred, PaymentExpectation::Challenge)
            .await
            .unwrap();
        assert_eq!(again.settlement_tx.as_deref(), Some("0xonce"));
        assert_eq!(rail.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_gate_refuses_a_challenge_for_another_resource_or_payee_or_price() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "x".to_string(),
        });
        let gw = gateway(rail.clone());
        // The attacker mints a one-unit challenge paying themselves.
        let cheap = gw
            .create_challenge("test", "/paid", 1, "TNZO", OTHER)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&cheap, "", &signer())
            .await
            .unwrap();
        let gate = PaymentExpectation::Resource {
            resource: "/paid",
            payee: PAYEE,
            min_amount: 1000,
            asset: "TNZO",
        };
        let err = gw.verify_and_settle(&cred, gate).await.unwrap_err();
        assert!(matches!(err, PaymentError::WrongResource(_)), "{err}");
        assert_eq!(rail.calls.load(Ordering::SeqCst), 0);

        // Right payee, wrong resource.
        let other_res = gw
            .create_challenge("test", "/other", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&other_res, "", &signer())
            .await
            .unwrap();
        assert!(matches!(
            gw.verify_and_settle(&cred, gate).await,
            Err(PaymentError::WrongResource(_))
        ));

        // Right resource and payee, price too low.
        let low = gw
            .create_challenge("test", "/paid", 999, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&low, "", &signer())
            .await
            .unwrap();
        assert!(matches!(
            gw.verify_and_settle(&cred, gate).await,
            Err(PaymentError::WrongResource(_))
        ));

        // The matching challenge settles.
        let good = gw
            .create_challenge("test", "/paid", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&good, "", &signer())
            .await
            .unwrap();
        assert!(gw.verify_and_settle(&cred, gate).await.is_ok());
        assert_eq!(rail.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_pending_rail_withholds_the_receipt_until_it_settles() {
        let rail = RecordingRail::new(RailOutcome::Pending {
            reference: "tr_1".to_string(),
        });
        let gw = gateway(rail.clone());
        let ch = gw
            .create_challenge("test", "/paid", 10, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&ch, "", &signer())
            .await
            .unwrap();
        assert!(matches!(
            gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
                .await,
            Err(PaymentError::SettlementPending(_))
        ));
        // Still pending on retry.
        assert!(matches!(
            gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
                .await,
            Err(PaymentError::SettlementPending(_))
        ));
        *rail.answer.lock().unwrap() = RailOutcome::Settled {
            reference: "tr_1".to_string(),
        };
        let receipt = gw
            .verify_and_settle(&cred, PaymentExpectation::Challenge)
            .await
            .unwrap();
        assert_eq!(receipt.settlement_tx.as_deref(), Some("tr_1"));
        // Settled once; retries polled status, never re-instructed the rail.
        assert_eq!(rail.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_forged_payer_is_refused_before_the_rail_is_asked() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "x".to_string(),
        });
        let gw = gateway(rail.clone());
        let ch = gw
            .create_challenge("test", "/paid", 10, "TNZO", PAYEE)
            .await
            .unwrap();
        let mut cred = TestProtocol
            .create_credential(&ch, "", &signer())
            .await
            .unwrap();
        cred.payer_address = hex::encode([0x55u8; 20]);
        assert!(
            gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
                .await
                .is_err()
        );
        assert_eq!(rail.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn preflight_checks_without_claiming_or_settling() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "x".to_string(),
        });
        let gw = gateway(rail.clone());
        let ch = gw
            .create_challenge("test", "/paid", 10, "TNZO", PAYEE)
            .await
            .unwrap();
        let cred = TestProtocol
            .create_credential(&ch, "", &signer())
            .await
            .unwrap();
        assert!(gw.preflight(&cred).await.is_ok());
        let mut forged = cred.clone();
        forged.payer_address = hex::encode([0x55u8; 20]);
        assert!(gw.preflight(&forged).await.is_err());
        assert_eq!(rail.calls.load(Ordering::SeqCst), 0);
        // Still payable afterwards.
        assert!(
            gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_challenge_must_name_a_tenzro_payee() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "x".to_string(),
        });
        let gw = gateway(rail);
        assert!(
            gw.create_challenge("test", "/paid", 10, "TNZO", "0xrecipient")
                .await
                .is_err()
        );
    }
}
