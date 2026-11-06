//! x402 facilitator: verification and settlement for resource servers.
//!
//! A resource server that sells over x402 hands the buyer's payload and its
//! own requirement to a facilitator (`POST /verify`, `POST /settle`). Every
//! scheme it serves ends in consensus state; the facilitator only answers
//! whether the ledger holds the payment for this requirement:
//!
//! - `tenzro-hybrid`, `upto`: the payload is the buyer's signed credential.
//!   Its signature covers the chain, the challenge id, payer, payee, ceiling
//!   and asset, so it is verified against the requirement alone and settled
//!   with an `X402Settle` transaction. The ledger moves the funds, takes the
//!   network share and refuses a second settlement of the same challenge id.
//! - `batch-settlement`: a cumulative voucher on an escrow the payer, or a
//!   delegated agent's wallet, funded. The voucher rail checks it against the
//!   escrow in chain state (an agent's voucher against the node its terms
//!   assign) and the payee claims the highest voucher later.
//! - `dvp`: the buyer funds escrows locked by the hash of the key a sealed
//!   delivery is encrypted under. The seller is paid exactly when it reveals
//!   the key on the ledger, so settling only confirms both legs are locked.
//! - `proven`: a payment a delegated agent made through `tenzro_agentAct`
//!   and the ledger recorded: on this Tenzro network (`tenzro:<chain id>`)
//!   the agent paid from its wallet within its Terms; on another chain its
//!   account paid and the light client of the route that account reports
//!   over proved the payment onto Tenzro. Each record buys one requirement.
//! - EVM schemes (`exact-eip3009`, `permit2`): delegated to the scheme's
//!   [`FacilitatorVerifier`](super::scheme::FacilitatorVerifier).
//!
//! A payment whose payer names a DID is bound to that DID's key and held to
//! the payer's consensus Terms before it is answered valid or settled, the
//! same check the node's own 402 gates make.
//!
//! Every answer is a real outcome. A payload the facilitator cannot settle
//! gets a failed settlement response, never a placeholder transaction.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tenzro_types::settlement::{PaymentRecord, RecordClass};
use tracing::{debug, info};

use crate::error::{PaymentError, Result};
use crate::gateway::{PlanRail, RailOutcome, SettlementInstruction, SettlementRail, VoucherRail};
use crate::mpp::{EscrowReader, EscrowView};
use crate::payer_auth::{PayerKeyResolver, VerifiedPayer, bind_payer_did, parse_tenzro_address};
use crate::terms_gate::{PaymentIntent, TermsGate};
use crate::types::SettlementLeg;
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequirement;
use crate::x402::receipt::X402SettlementResponse;
use crate::x402::scheme::SchemeRegistry;
use crate::x402::wire;
use crate::x402::wire::DVP_SCHEME;

/// Scheme: a delegated agent's payment the Tenzro ledger records, made on
/// Tenzro itself or on another chain and proven onto Tenzro.
pub const PROVEN_SCHEME: &str = "proven";
/// Scheme: a multi-leg settlement plan the payer signed, opened through the
/// facilitator's plan rail.
pub const PLAN_SCHEME: &str = "plan";

/// Payload key: the delivery statement a `dvp` payment locks against.
pub const DELIVERY_KEY: &str = "delivery";
/// Payload key: the escrow holding the network's share of a `dvp` payment.
pub const NETWORK_ESCROW_ID_KEY: &str = "network_escrow_id";
/// Payload key: the reference of a proven payment record.
pub const PAY_REF_KEY: &str = "pay_ref";
/// Payload key: the payer's signed plan transaction (a `SignedTransaction`
/// carrying `SettlementPlan` `Open`, as JSON).
pub const SIGNED_TX_KEY: &str = "signed_tx";

/// An escrow a facilitator accepts must outlive the answer by this much, so
/// the payee can still claim or capture from it.
pub const ESCROW_CLAIM_MARGIN_MS: i64 = 120_000;

/// A chain delegated agents hold accounts on, as consensus lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAccountNetwork {
    /// The chain, CAIP-2.
    pub caip2: String,
    /// The chain's name on the route that proves its accounts' payments.
    pub route_chain: String,
}

/// Payment records and agent account chains, read from consensus state.
pub trait LedgerRecords: Send + Sync {
    /// The payment record at `pay_ref`.
    fn payment(&self, pay_ref: &[u8; 32]) -> Option<PaymentRecord>;
    /// The open agent account chains whose accounts' payments a route
    /// proves back.
    fn agent_account_networks(&self) -> Vec<AgentAccountNetwork>;
}

/// A verified payload: who pays, and how the payment settles.
#[derive(Debug, Clone)]
pub struct FacilitatorVerification {
    /// The paying address.
    pub payer: String,
    /// How it settles.
    leg: VerifiedLeg,
}

#[derive(Debug, Clone)]
enum VerifiedLeg {
    Ledger {
        payer: VerifiedPayer,
        payment_id: String,
        amount: u128,
    },
    Voucher {
        voucher: tenzro_types::payment_authorization::EscrowVoucher,
        payee: tenzro_types::Address,
        charge: u128,
    },
    Locked {
        lock: [u8; 32],
        amount: u128,
    },
    Proven {
        pay_ref: [u8; 32],
        amount: u128,
    },
    Plan {
        signed: Box<tenzro_types::transaction::SignedTransaction>,
        plan_id: [u8; 32],
        legs: u8,
        amount: u128,
    },
    Foreign,
}

/// x402 facilitator.
pub struct X402Facilitator {
    chain_id: u64,
    /// CAIP-2 networks accepted besides this Tenzro network.
    external_networks: Vec<String>,
    scheme_registry: SchemeRegistry,
    /// The Tenzro Ledger rail Tenzro-scheme payments settle on.
    ledger: Option<Arc<dyn SettlementRail>>,
    /// Accepts escrow vouchers against chain state.
    vouchers: Option<Arc<dyn VoucherRail>>,
    /// Reads escrows from chain state.
    escrows: Option<Arc<dyn EscrowReader>>,
    /// Reads payment records and agent account chains from chain state.
    records: Option<Arc<dyn LedgerRecords>>,
    plans: Option<Arc<dyn PlanRail>>,
    /// Binds a payer DID to the key that signed the payment.
    payer_resolver: Option<Arc<dyn PayerKeyResolver>>,
    /// The payer's consensus Terms.
    terms: Option<Arc<dyn TermsGate>>,
    /// Reads controllers and DID keys for AP2 mandates.
    mandate_keys: Option<Arc<dyn crate::ap2::MandateKeys>>,
    /// Proven records already spent on a requirement, with the challenge
    /// that spent them.
    proven_spent: DashMap<[u8; 32], String>,
}

impl X402Facilitator {
    /// A facilitator for the Tenzro network `chain_id`, also accepting the
    /// EVM `external_networks` (CAIP-2) its scheme registry can reach.
    pub fn new(
        chain_id: u64,
        external_networks: Vec<String>,
        keys: Arc<dyn crate::payer_auth::EnrolledKeys>,
    ) -> Self {
        Self {
            chain_id,
            external_networks,
            scheme_registry: SchemeRegistry::with_defaults(keys),
            ledger: None,
            vouchers: None,
            escrows: None,
            records: None,
            plans: None,
            payer_resolver: None,
            terms: None,
            mandate_keys: None,
            proven_spent: DashMap::new(),
        }
    }

    /// Replace the scheme registry.
    pub fn with_scheme_registry(mut self, registry: SchemeRegistry) -> Self {
        self.scheme_registry = registry;
        self
    }

    /// Settle Tenzro-scheme payments on `rail`.
    pub fn with_ledger_rail(mut self, rail: Arc<dyn SettlementRail>) -> Self {
        self.ledger = Some(rail);
        self
    }

    /// Accept `batch-settlement` vouchers through `rail`.
    pub fn with_voucher_rail(mut self, rail: Arc<dyn VoucherRail>) -> Self {
        self.vouchers = Some(rail);
        self
    }

    /// Serve `auth-capture` and `dvp` over escrows `reader` reads.
    pub fn with_escrow_reader(mut self, reader: Arc<dyn EscrowReader>) -> Self {
        self.escrows = Some(reader);
        self
    }

    /// Serve `proven` payments from the records `records` reads.
    pub fn with_ledger_records(mut self, records: Arc<dyn LedgerRecords>) -> Self {
        self.records = Some(records);
        self
    }

    /// Settle `plan` payments: payer-signed settlement plans, admitted
    /// through `rail`.
    pub fn with_plan_rail(mut self, rail: Arc<dyn PlanRail>) -> Self {
        self.plans = Some(rail);
        self
    }

    /// Bind payer DIDs to the keys that signed through `resolver`. Without
    /// one, a payment naming a DID is refused.
    pub fn with_payer_resolver(mut self, resolver: Arc<dyn PayerKeyResolver>) -> Self {
        self.payer_resolver = Some(resolver);
        self
    }

    /// Hold every payment by a DID to that DID's Terms through `gate`.
    /// Without one, a payment naming a DID is refused.
    pub fn with_terms_gate(mut self, gate: Arc<dyn TermsGate>) -> Self {
        self.terms = Some(gate);
        self
    }

    /// Check AP2 mandates a payment carries in `extensions.ap2` through
    /// `keys`. Without it, a payment carrying mandates is refused.
    pub fn with_mandate_keys(mut self, keys: Arc<dyn crate::ap2::MandateKeys>) -> Self {
        self.mandate_keys = Some(keys);
        self
    }

    /// The payer's Terms decide a payment by `did` of `amount` to `payee`.
    fn authorize(
        &self,
        did: &str,
        amount: u128,
        requirement: &X402PaymentRequirement,
    ) -> Result<()> {
        let gate = self.terms.as_ref().ok_or_else(|| {
            PaymentError::VerificationFailed("payer Terms cannot be read here".to_string())
        })?;
        gate.authorize(&PaymentIntent {
            payer_did: did,
            amount,
            operation: "payment",
            protocol: Some("x402"),
            chain: Some(&requirement.network),
            counterparty: Some(&requirement.pay_to),
        })
    }

    /// The scheme registry.
    pub fn scheme_registry(&self) -> &SchemeRegistry {
        &self.scheme_registry
    }

    /// This facilitator's Tenzro network, `tenzro:<chain id>`.
    pub fn tenzro_network(&self) -> String {
        format!("tenzro:{}", self.chain_id)
    }

    /// Every `(scheme, network)` pair this facilitator can settle.
    pub fn supported_kinds(&self) -> Vec<(String, String)> {
        let tenzro = self.tenzro_network();
        let mut kinds = Vec::new();
        if self.ledger.is_some() {
            for scheme in [super::DEFAULT_SCHEME, super::UPTO_SCHEME] {
                kinds.push((scheme.to_string(), tenzro.clone()));
            }
        }
        if self.vouchers.is_some() {
            kinds.push((super::BATCH_SETTLEMENT_SCHEME.to_string(), tenzro.clone()));
        }
        if self.escrows.is_some() {
            kinds.push((DVP_SCHEME.to_string(), tenzro.clone()));
        }
        if self.plans.is_some() {
            kinds.push((PLAN_SCHEME.to_string(), tenzro.clone()));
        }
        if let Some(records) = &self.records {
            kinds.push((PROVEN_SCHEME.to_string(), tenzro.clone()));
            for network in records.agent_account_networks() {
                kinds.push((PROVEN_SCHEME.to_string(), network.caip2));
            }
        }
        for scheme in self.scheme_registry.ids() {
            if wire::is_tenzro_scheme(&scheme) {
                continue;
            }
            for network in &self.external_networks {
                kinds.push((scheme.clone(), network.clone()));
            }
        }
        kinds
    }

    /// Verify `payload` against the resource server's `requirement`. A
    /// refusal is an `Err`. Nothing is reserved or accepted.
    pub async fn verify(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<FacilitatorVerification> {
        self.check(requirement, payload, false).await
    }

    async fn check(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
        commit: bool,
    ) -> Result<FacilitatorVerification> {
        wire::check_accepted_matches(payload, requirement)?;
        // Mandates narrow a payment the payer signed for this requirement;
        // no other scheme carries one.
        if payload
            .extensions
            .as_ref()
            .is_some_and(|e| e.get(crate::ap2::AP2_EXTENSION_KEY).is_some())
            && ![super::DEFAULT_SCHEME, super::UPTO_SCHEME]
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&requirement.scheme))
        {
            return Err(PaymentError::VerificationFailed(format!(
                "AP2 mandates ride on {} or {} payments",
                super::DEFAULT_SCHEME,
                super::UPTO_SCHEME
            )));
        }
        if requirement.scheme.eq_ignore_ascii_case(PROVEN_SCHEME) {
            return self.check_proven(requirement, payload, commit);
        }
        if requirement.scheme.eq_ignore_ascii_case(PLAN_SCHEME) {
            return self.check_plan(requirement, payload);
        }
        if wire::is_tenzro_scheme(&requirement.scheme) {
            return self.check_tenzro(requirement, payload, commit).await;
        }

        let backend = self.scheme_registry.lookup_for_requirement(requirement)?;
        if !self.external_networks.contains(&requirement.network) {
            return Err(PaymentError::VerificationFailed(format!(
                "network {} is not supported",
                requirement.network
            )));
        }
        backend.verify_payload(requirement, payload).await?;
        let payer = payload
            .exact_payload()
            .map(|e| e.authorization.from)
            .unwrap_or_default();
        info!(
            "x402 payload from {} verified under scheme {}",
            payer,
            backend.name()
        );
        Ok(FacilitatorVerification {
            payer,
            leg: VerifiedLeg::Foreign,
        })
    }

    async fn check_tenzro(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
        commit: bool,
    ) -> Result<FacilitatorVerification> {
        if requirement.network != self.tenzro_network() {
            return Err(PaymentError::VerificationFailed(format!(
                "{} settles on {}, not {}",
                requirement.scheme,
                self.tenzro_network(),
                requirement.network
            )));
        }
        let resource = payload
            .resource
            .as_ref()
            .map(|r| r.url.as_str())
            .unwrap_or_default();
        let challenge = wire::challenge_from_requirement(requirement, resource)?;
        let credential = wire::credential_from_payload(payload)?;
        if credential.challenge_id != challenge.challenge_id {
            return Err(PaymentError::VerificationFailed(
                "the payload answers another challenge".to_string(),
            ));
        }
        let payee = parse_tenzro_address(&requirement.pay_to)?;

        if requirement.scheme.eq_ignore_ascii_case(DVP_SCHEME) {
            let escrows = self.escrows()?;
            let delivery: crate::dvp::SealedDelivery = credential
                .extra
                .get(DELIVERY_KEY)
                .cloned()
                .ok_or_else(|| {
                    PaymentError::CredentialError(format!(
                        "a dvp payment carries its {DELIVERY_KEY}"
                    ))
                })
                .and_then(|v| {
                    serde_json::from_value(v)
                        .map_err(|e| PaymentError::CredentialError(format!("delivery: {e}")))
                })?;
            delivery.verify()?;
            if delivery.price != challenge.amount
                || !delivery.asset.eq_ignore_ascii_case(&requirement.asset)
                || parse_tenzro_address(&delivery.payee)? != payee
            {
                return Err(PaymentError::VerificationFailed(
                    "the delivery was sealed for another price, asset or payee".to_string(),
                ));
            }
            let read = |key: &str| -> Result<Option<EscrowView>> {
                match credential.extra.get(key) {
                    None => Ok(None),
                    Some(_) => escrows.escrow(&escrow_id_field(&credential.extra, key)?),
                }
            };
            let seller = read(crate::payer_auth::ESCROW_ID_KEY)?.ok_or_else(|| {
                PaymentError::VerificationFailed("the seller's escrow does not exist".to_string())
            })?;
            let network = read(NETWORK_ESCROW_ID_KEY)?;
            check_asset(&seller, &requirement.asset)?;
            let lock = delivery
                .check_locked(
                    &payee,
                    &seller,
                    network.as_ref(),
                    escrows.now_ms(),
                    ESCROW_CLAIM_MARGIN_MS,
                )
                .map_err(PaymentError::VerificationFailed)?;
            return Ok(FacilitatorVerification {
                payer: hex::encode(seller.payer.as_bytes()),
                leg: VerifiedLeg::Locked {
                    lock,
                    amount: delivery.price,
                },
            });
        }

        let backend = self.scheme_registry.lookup_for_requirement(requirement)?;
        let leg = backend.verify(&challenge, &credential).await?;
        if credential.amount > challenge.amount {
            return Err(PaymentError::VerificationFailed(format!(
                "charge {} exceeds the required {}",
                credential.amount, challenge.amount
            )));
        }
        match leg {
            SettlementLeg::Payer(mut payer) => {
                bind_payer_did(
                    &mut payer,
                    &credential.payer_did,
                    self.payer_resolver.as_deref(),
                )?;
                if let Some(did) = payer.did.as_deref() {
                    self.authorize(did, credential.amount, requirement)?;
                }
                if let Some(presented) = crate::ap2::presentation_in(payload.extensions.as_ref())? {
                    let did = payer.did.as_deref().ok_or_else(|| {
                        PaymentError::VerificationFailed(
                            "a payment carrying AP2 mandates names its payer DID".to_string(),
                        )
                    })?;
                    let (Some(keys), Some(terms)) = (&self.mandate_keys, &self.terms) else {
                        return Err(PaymentError::VerificationFailed(
                            "this facilitator reads no AP2 mandates".to_string(),
                        ));
                    };
                    crate::ap2::verify(
                        &presented,
                        &crate::ap2::ProposedPayment {
                            agent_did: did,
                            payee: &requirement.pay_to,
                            amount: credential.amount,
                            currency: &requirement.asset,
                            chain: &requirement.network,
                        },
                        None,
                        keys.as_ref(),
                        terms.as_ref(),
                    )?;
                }
                Ok(FacilitatorVerification {
                    payer: hex::encode(payer.address.as_bytes()),
                    leg: VerifiedLeg::Ledger {
                        payer,
                        payment_id: challenge.challenge_id,
                        amount: credential.amount,
                    },
                })
            }
            SettlementLeg::Voucher(voucher) => {
                let rail = self.vouchers.as_ref().ok_or_else(|| {
                    PaymentError::VerificationFailed(
                        "this facilitator reads no escrow state, so it accepts no vouchers"
                            .to_string(),
                    )
                })?;
                if commit {
                    // Settling accepts the voucher itself, below.
                } else {
                    match rail.check(&voucher, &payee, credential.amount).await? {
                        RailOutcome::Settled { .. } => {}
                        RailOutcome::Pending { reference }
                        | RailOutcome::Failed { reason: reference } => {
                            return Err(PaymentError::VerificationFailed(reference));
                        }
                    }
                }
                Ok(FacilitatorVerification {
                    payer: hex::encode(crate::payer_auth::voucher_payer(&voucher).as_bytes()),
                    leg: VerifiedLeg::Voucher {
                        voucher,
                        payee,
                        charge: credential.amount,
                    },
                })
            }
            SettlementLeg::Foreign => Err(PaymentError::VerificationFailed(format!(
                "scheme {} produced no ledger payment",
                requirement.scheme
            ))),
        }
    }

    /// A `plan` payment: the payer's own signed transaction opening a
    /// settlement plan for this requirement's quote, whose Tenzro legs carry
    /// at least the requirement's amount and whose split pays the
    /// requirement's payee. Its signature is checked here and again when the
    /// plan rail admits it; the plan must not be open yet.
    fn check_plan(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<FacilitatorVerification> {
        use tenzro_types::settlement::{LegKind, PlanOp};
        use tenzro_types::split::{SplitRecipient, SplitRole};
        use tenzro_types::transaction::{SignedTransaction, TransactionType};

        let plans = self.plans.as_ref().ok_or_else(|| {
            PaymentError::VerificationFailed(
                "this facilitator opens no settlement plans".to_string(),
            )
        })?;
        if requirement.network != self.tenzro_network() {
            return Err(PaymentError::VerificationFailed(format!(
                "plans settle on {}, not {}",
                self.tenzro_network(),
                requirement.network
            )));
        }
        if !requirement.asset.eq_ignore_ascii_case("TNZO") {
            return Err(PaymentError::VerificationFailed(
                "a plan pays its Tenzro legs in TNZO".to_string(),
            ));
        }
        let signed: SignedTransaction = payload
            .payload
            .get(SIGNED_TX_KEY)
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .ok_or_else(|| {
                PaymentError::CredentialError(format!("a plan payment carries its {SIGNED_TX_KEY}"))
            })?;
        signed
            .validate()
            .map_err(|e| PaymentError::CredentialError(e.to_string()))?;
        verify_signed_tx(&signed)?;
        let tx = &signed.transaction;
        if tx.chain_id.as_u64() != self.chain_id {
            return Err(PaymentError::VerificationFailed(
                "the plan transaction is for another chain".to_string(),
            ));
        }
        let TransactionType::SettlementPlan {
            op:
                PlanOp::Open {
                    nonce,
                    quote_digest,
                    split,
                    legs,
                    ..
                },
        } = &tx.tx_type
        else {
            return Err(PaymentError::CredentialError(
                "the transaction does not open a settlement plan".to_string(),
            ));
        };
        let quoted = requirement
            .extra_str(crate::payer_auth::QUOTE_DIGEST_KEY)
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "the requirement names no {}",
                    crate::payer_auth::QUOTE_DIGEST_KEY
                ))
            })?;
        if *quote_digest != quoted {
            return Err(PaymentError::VerificationFailed(
                "the plan settles another quote".to_string(),
            ));
        }
        let payee = parse_tenzro_address(&requirement.pay_to)?;
        if !split
            .lines
            .iter()
            .any(|l| l.role == SplitRole::Payee && l.recipient == SplitRecipient::Address(payee))
        {
            return Err(PaymentError::VerificationFailed(
                "the plan's split does not pay the payee".to_string(),
            ));
        }
        let tenzro_value = legs.iter().try_fold(0u128, |acc, leg| match &leg.kind {
            LegKind::NativeTransfer { amount, .. } => acc.checked_add(*amount),
            _ => Some(acc),
        });
        let amount = requirement.amount_u128()?;
        match tenzro_value {
            Some(v) if v >= amount => {}
            _ => {
                return Err(PaymentError::InsufficientFunds(format!(
                    "the plan's Tenzro legs carry less than {amount}"
                )));
            }
        }
        let plan_id =
            tenzro_types::settlement::plan_id(self.chain_id, &tx.from, quote_digest, *nonce);
        if plans.plan(&plan_id).is_some() {
            return Err(PaymentError::VerificationFailed(format!(
                "plan {} is already open",
                hex::encode(plan_id)
            )));
        }
        Ok(FacilitatorVerification {
            payer: format!("0x{}", hex::encode(tx.from.as_bytes())),
            leg: VerifiedLeg::Plan {
                legs: legs.len() as u8,
                signed: Box::new(signed.clone()),
                plan_id,
                amount,
            },
        })
    }

    fn check_proven(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
        commit: bool,
    ) -> Result<FacilitatorVerification> {
        let records = self.records.as_ref().ok_or_else(|| {
            PaymentError::VerificationFailed(
                "this facilitator reads no payment records".to_string(),
            )
        })?;
        let route_chain = if requirement.network == self.tenzro_network() {
            None
        } else {
            let network = records
                .agent_account_networks()
                .into_iter()
                .find(|n| n.caip2 == requirement.network)
                .ok_or_else(|| {
                    PaymentError::VerificationFailed(format!(
                        "no route proves agent account payments on {}",
                        requirement.network
                    ))
                })?;
            Some(network.route_chain)
        };
        let challenge_id = requirement
            .extra_str(wire::CHALLENGE_ID_KEY)
            .ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "the requirement names no {}",
                    wire::CHALLENGE_ID_KEY
                ))
            })?;
        let pay_ref = payload
            .payload
            .get(PAY_REF_KEY)
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| {
                PaymentError::CredentialError(format!("a proven payment names its {PAY_REF_KEY}"))
            })?;
        let record = records.payment(&pay_ref).ok_or_else(|| {
            PaymentError::SettlementPending(format!(
                "payment {} is not proven yet",
                hex::encode(pay_ref)
            ))
        })?;
        check_proven_record(&record, route_chain.as_deref(), requirement)?;
        let spent_by = self.proven_spent.get(&pay_ref).map(|c| c.value().clone());
        match spent_by {
            Some(c) if c != challenge_id => {
                return Err(PaymentError::VerificationFailed(format!(
                    "payment {} already bought another requirement",
                    hex::encode(pay_ref)
                )));
            }
            Some(_) => {}
            None if commit => {
                if let Some(other) = self.proven_spent.insert(pay_ref, challenge_id.to_string())
                    && other != challenge_id
                {
                    self.proven_spent.insert(pay_ref, other);
                    return Err(PaymentError::VerificationFailed(format!(
                        "payment {} already bought another requirement",
                        hex::encode(pay_ref)
                    )));
                }
            }
            None => {}
        }
        Ok(FacilitatorVerification {
            payer: record.payer.clone(),
            leg: VerifiedLeg::Proven {
                pay_ref,
                amount: record.amount.saturating_sub(record.refunded),
            },
        })
    }

    fn escrows(&self) -> Result<&Arc<dyn EscrowReader>> {
        self.escrows.as_ref().ok_or_else(|| {
            PaymentError::VerificationFailed("this facilitator reads no escrow state".to_string())
        })
    }

    /// Verify and settle `payload`. A payload that does not settle yields a
    /// failed response carrying the reason.
    pub async fn settle(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> X402SettlementResponse {
        match self.settle_inner(requirement, payload).await {
            Ok(response) => response,
            Err(e) => {
                debug!("x402 facilitator settle refused: {e}");
                let reason = match e {
                    PaymentError::SettlementPending(_) => "settlement_pending",
                    PaymentError::InsufficientFunds(_) => "insufficient_funds",
                    PaymentError::VerificationFailed(_) | PaymentError::CredentialError(_) => {
                        "invalid_payload"
                    }
                    _ => "unexpected_settle_error",
                };
                X402SettlementResponse::failed(requirement.network.clone(), reason)
            }
        }
    }

    async fn settle_inner(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<X402SettlementResponse> {
        let verified = self.check(requirement, payload, true).await?;
        let mut plan_settlement = None;
        let (transaction, amount) = match verified.leg {
            VerifiedLeg::Ledger {
                payer,
                payment_id,
                amount,
            } => {
                let rail = self.ledger.as_ref().ok_or_else(|| {
                    PaymentError::SettlementError("this facilitator has no ledger rail".to_string())
                })?;
                let instruction = SettlementInstruction {
                    payment_id,
                    asset: payer.authorization.asset.clone(),
                    payer,
                    payee: parse_tenzro_address(&requirement.pay_to)?,
                    amount,
                };
                if !rail.carries(&instruction.asset) {
                    return Err(PaymentError::SettlementError(format!(
                        "the ledger rail does not carry {}",
                        instruction.asset
                    )));
                }
                match rail.settle(&instruction).await? {
                    RailOutcome::Settled { reference } => (reference, amount),
                    RailOutcome::Pending { reference } => {
                        return Err(PaymentError::SettlementPending(reference));
                    }
                    RailOutcome::Failed { reason } => {
                        return Err(PaymentError::SettlementError(reason));
                    }
                }
            }
            VerifiedLeg::Voucher {
                voucher,
                payee,
                charge,
            } => {
                let rail = self.vouchers.as_ref().ok_or_else(|| {
                    PaymentError::SettlementError(
                        "this facilitator accepts no vouchers".to_string(),
                    )
                })?;
                match rail.accept(&voucher, &payee, charge).await? {
                    RailOutcome::Settled { reference } => (reference, charge),
                    RailOutcome::Pending { reference }
                    | RailOutcome::Failed { reason: reference } => {
                        return Err(PaymentError::VerificationFailed(reference));
                    }
                }
            }
            VerifiedLeg::Locked { lock, amount } => (format!("dvp:{}", hex::encode(lock)), amount),
            VerifiedLeg::Proven { pay_ref, amount } => {
                (format!("pay:{}", hex::encode(pay_ref)), amount)
            }
            VerifiedLeg::Plan {
                signed,
                plan_id,
                legs,
                amount,
            } => {
                let rail = self.plans.as_ref().ok_or_else(|| {
                    PaymentError::SettlementError(
                        "this facilitator opens no settlement plans".to_string(),
                    )
                })?;
                let reference = match rail.open(&signed).await? {
                    RailOutcome::Settled { reference } => reference,
                    RailOutcome::Pending { reference } => {
                        return Err(PaymentError::SettlementPending(reference));
                    }
                    RailOutcome::Failed { reason } => {
                        return Err(PaymentError::SettlementError(reason));
                    }
                };
                let (plan, receipts) = rail.plan(&plan_id).ok_or_else(|| {
                    PaymentError::SettlementError(format!(
                        "the plan transaction {reference} executed but plan {} is not in state",
                        hex::encode(plan_id)
                    ))
                })?;
                plan_settlement = Some(super::receipt::PlanSettlement {
                    plan_id: hex::encode(plan_id),
                    status: plan.status,
                    leg_ids: (0..legs)
                        .map(|i| hex::encode(tenzro_types::settlement::leg_id(&plan_id, i)))
                        .collect(),
                    receipts,
                });
                (reference, amount)
            }
            VerifiedLeg::Foreign => {
                let backend = self.scheme_registry.lookup_for_requirement(requirement)?;
                let tx = backend.settle_payload(requirement, payload).await?;
                (tx, requirement.amount_u128()?)
            }
        };
        Ok(X402SettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(verified.payer),
            transaction,
            network: requirement.network.clone(),
            amount: Some(amount.to_string()),
            usage_record: None,
            plan: plan_settlement,
        })
    }
}

/// Check a signed transaction's P-256 leg over its hash, and that its key
/// derives the sender account. The ML-DSA-65 leg, when the account has one
/// enrolled, is enforced against chain state when the transaction executes.
fn verify_signed_tx(signed: &tenzro_types::transaction::SignedTransaction) -> Result<()> {
    use tenzro_crypto::composite::{SignatureContext, verify_classical_component};
    let tx = &signed.transaction;
    if !tenzro_crypto::controls_account(&signed.public_key, tx.from.as_bytes()) {
        return Err(PaymentError::CredentialError(
            "the plan transaction's key does not derive its sender".to_string(),
        ));
    }
    verify_classical_component(
        &signed.public_key,
        SignatureContext::Transaction,
        tx.hash().as_bytes(),
        &signed.signature.classical,
    )
    .map_err(|e| {
        PaymentError::CredentialError(format!(
            "the plan transaction's signature does not verify: {e}"
        ))
    })
}

fn escrow_id_field(extra: &HashMap<String, serde_json::Value>, key: &str) -> Result<[u8; 32]> {
    extra
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| PaymentError::CredentialError(format!("{key} must be 32 bytes of hex")))
}

fn check_asset(view: &EscrowView, asset: &str) -> Result<()> {
    if view.asset.eq_ignore_ascii_case(asset) {
        Ok(())
    } else {
        Err(PaymentError::VerificationFailed(format!(
            "the escrow holds {}, the requirement asks for {asset}",
            view.asset
        )))
    }
}

/// Whether `record` pays `requirement`: a delegated agent's payment, made on
/// the Tenzro ledger when `route_chain` is `None` and otherwise proven
/// through that chain's route, to the required payee, in the required asset,
/// for at least the required amount net of refunds.
fn check_proven_record(
    record: &PaymentRecord,
    route_chain: Option<&str>,
    requirement: &X402PaymentRequirement,
) -> Result<()> {
    let refuse = |why: &str| {
        Err(PaymentError::VerificationFailed(format!(
            "payment {}: {why}",
            record.pay_ref
        )))
    };
    if record.agent_did.is_none() {
        return refuse("was not made by a delegated agent");
    }
    match route_chain {
        None => {
            if record.class != RecordClass::Native {
                return refuse("was not settled on the Tenzro ledger");
            }
        }
        Some(route_chain) => {
            if record.class != RecordClass::Proven {
                return refuse("is not proven from another chain");
            }
            if record.source.as_deref() != Some(route_chain) {
                return refuse("was proven from another chain");
            }
        }
    }
    if record.payee != parse_tenzro_address(&requirement.pay_to)? {
        return refuse("pays another account");
    }
    if !record.asset.eq_ignore_ascii_case(&requirement.asset) {
        return refuse("is in another asset");
    }
    if record.amount.saturating_sub(record.refunded) < requirement.amount_u128()? {
        return refuse("pays less than required");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payer_auth::CHAIN_ID_KEY;
    use crate::test_support::{RecordingRail, signer};
    use crate::traits::PaymentProtocol;
    use crate::x402::X402PaymentServer;
    use crate::x402::wire::CHALLENGE_ID_KEY;

    const PAYEE: &str = "0909090909090909090909090909090909090909";

    async fn signed_payload(amount: u128) -> (X402PaymentRequirement, X402PaymentPayload) {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            Arc::new(crate::test_support::SeedKeys),
        );
        let mut ch = server
            .create_challenge("/paid", amount, "TNZO", PAYEE)
            .await
            .unwrap();
        ch.extra
            .insert(CHAIN_ID_KEY.to_string(), serde_json::json!(1337u64));
        let cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        let payload = wire::payload_for_credential(&ch, &cred).unwrap();
        (wire::requirement_for(&ch), payload)
    }

    fn facilitator(rail: Arc<RecordingRail>) -> X402Facilitator {
        X402Facilitator::new(
            1337,
            vec!["eip155:8453".to_string()],
            Arc::new(crate::test_support::SeedKeys),
        )
        .with_ledger_rail(rail)
    }

    #[tokio::test]
    async fn a_signed_tenzro_payment_settles_on_the_ledger_rail() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xledger".to_string(),
        });
        let f = facilitator(rail.clone());
        let (req, payload) = signed_payload(900).await;
        let resp = f.settle(&req, &payload).await;
        assert!(resp.success, "{resp:?}");
        assert_eq!(resp.transaction, "0xledger");
        assert_eq!(resp.network, "tenzro:1337");
        assert_eq!(resp.amount.as_deref(), Some("900"));
        let seen = rail.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].amount, 900);
    }

    #[tokio::test]
    async fn a_requirement_rewritten_after_signing_is_refused() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xledger".to_string(),
        });
        let f = facilitator(rail.clone());
        let (req, payload) = signed_payload(900).await;

        let mut other_payee = req.clone();
        other_payee.pay_to = "0808080808080808080808080808080808080808".to_string();
        assert!(!f.settle(&other_payee, &payload).await.success);

        let mut other_challenge = req.clone();
        other_challenge.set_extra(CHALLENGE_ID_KEY, serde_json::json!("another"));
        assert!(!f.settle(&other_challenge, &payload).await.success);

        let mut other_chain = req.clone();
        other_chain.network = "tenzro:1".to_string();
        assert!(!f.settle(&other_chain, &payload).await.success);

        assert!(rail.seen.lock().unwrap().is_empty());
    }

    struct AnyDid;
    impl PayerKeyResolver for AnyDid {
        fn did_binds_payer(
            &self,
            _did: &str,
            _public_key: &[u8],
            _payer: &tenzro_types::Address,
        ) -> Result<bool> {
            Ok(true)
        }
    }

    /// Terms that let an agent pay at most `cap` per payment.
    struct Cap(u128);
    impl TermsGate for Cap {
        fn authorize(&self, intent: &PaymentIntent<'_>) -> Result<()> {
            assert_eq!(intent.protocol, Some("x402"));
            if intent.amount > self.0 {
                return Err(PaymentError::VerificationFailed(
                    "over the per-transaction limit".to_string(),
                ));
            }
            Ok(())
        }
    }

    async fn agent_payload(amount: u128) -> (X402PaymentRequirement, X402PaymentPayload) {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            Arc::new(crate::test_support::SeedKeys),
        );
        let mut ch = server
            .create_challenge("/paid", amount, "TNZO", PAYEE)
            .await
            .unwrap();
        ch.extra
            .insert(CHAIN_ID_KEY.to_string(), serde_json::json!(1337u64));
        let cred = server
            .create_credential(&ch, "did:tenzro:machine:agent", &signer())
            .await
            .unwrap();
        let payload = wire::payload_for_credential(&ch, &cred).unwrap();
        (wire::requirement_for(&ch), payload)
    }

    #[tokio::test]
    async fn an_agent_pays_through_the_facilitator_only_inside_its_terms() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xledger".to_string(),
        });
        let f = facilitator(rail.clone())
            .with_payer_resolver(Arc::new(AnyDid))
            .with_terms_gate(Arc::new(Cap(500)));

        let (req, payload) = agent_payload(900).await;
        assert!(f.verify(&req, &payload).await.is_err());
        assert!(!f.settle(&req, &payload).await.success);
        assert!(rail.seen.lock().unwrap().is_empty());

        let (req, payload) = agent_payload(400).await;
        let verified = f.verify(&req, &payload).await.unwrap();
        assert!(!verified.payer.is_empty());
        assert!(f.settle(&req, &payload).await.success);
        assert_eq!(rail.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_payment_naming_a_did_is_refused_where_terms_cannot_be_read() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xledger".to_string(),
        });
        let (req, payload) = agent_payload(10).await;
        // No resolver: the DID cannot be bound to the signing key.
        assert!(
            !facilitator(rail.clone())
                .settle(&req, &payload)
                .await
                .success
        );
        // A resolver but no Terms gate.
        let f = facilitator(rail.clone()).with_payer_resolver(Arc::new(AnyDid));
        assert!(!f.settle(&req, &payload).await.success);
        assert!(rail.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mandates_are_checked_never_ignored() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xledger".to_string(),
        });
        let mandates = serde_json::json!({ "ap2": {
            "checkout_jwt": "a.b.c", "payment_mandate": "x~" } });
        // A payer with no DID cannot pay by mandate.
        let (req, mut payload) = signed_payload(10).await;
        payload.extensions = Some(mandates.clone());
        assert!(
            !facilitator(rail.clone())
                .settle(&req, &payload)
                .await
                .success
        );
        // An agent paying by mandate where no mandate can be read is refused,
        // even inside its Terms.
        let (req, mut payload) = agent_payload(10).await;
        payload.extensions = Some(mandates);
        let f = facilitator(rail.clone())
            .with_payer_resolver(Arc::new(AnyDid))
            .with_terms_gate(Arc::new(Cap(500)));
        assert!(!f.settle(&req, &payload).await.success);
        assert!(rail.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn without_a_ledger_rail_nothing_settles() {
        let f = X402Facilitator::new(1337, vec![], Arc::new(crate::test_support::SeedKeys));
        let (req, payload) = signed_payload(5).await;
        let resp = f.settle(&req, &payload).await;
        assert!(!resp.success);
        assert!(resp.transaction.is_empty());
    }

    #[tokio::test]
    async fn a_pending_settlement_is_reported_as_pending() {
        let rail = RecordingRail::new(RailOutcome::Pending {
            reference: "tr_1".to_string(),
        });
        let (req, payload) = signed_payload(5).await;
        let resp = facilitator(rail).settle(&req, &payload).await;
        assert!(!resp.success);
        assert_eq!(resp.error_reason.as_deref(), Some("settlement_pending"));
    }

    #[tokio::test]
    async fn an_unsupported_external_network_is_refused() {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "x".to_string(),
        });
        let f = facilitator(rail);
        let req =
            X402PaymentRequirement::new("exact-eip3009", "eip155:1", "1", "0xto", "0xusdc", 60);
        let payload = X402PaymentPayload::new(req.clone(), serde_json::json!({}));
        assert!(f.verify(&req, &payload).await.is_err());
    }
}

#[cfg(test)]
mod escrow_scheme_tests {
    use super::*;
    use crate::payer_auth::{CHAIN_ID_KEY, ESCROW_ID_KEY};
    use crate::test_support::signer;
    use crate::traits::PaymentProtocol;
    use crate::x402::X402PaymentServer;
    use crate::x402::wire::CHALLENGE_ID_KEY;
    use parking_lot::Mutex;
    use tenzro_types::Address;
    use tenzro_types::settlement::ReleaseConditions;

    const PAYEE_HEX: &str = "0909090909090909090909090909090909090909";
    const NOW: i64 = 1_800_000_000_000;

    #[derive(Default)]
    struct Ledger {
        escrows: Mutex<HashMap<[u8; 32], EscrowView>>,
        records: Mutex<HashMap<[u8; 32], PaymentRecord>>,
    }

    impl EscrowReader for Ledger {
        fn escrow(&self, id: &[u8; 32]) -> Result<Option<EscrowView>> {
            Ok(self.escrows.lock().get(id).cloned())
        }
        fn now_ms(&self) -> i64 {
            NOW
        }
        fn check_signer(
            &self,
            _: &tenzro_types::payment_authorization::EscrowVoucher,
            _: &EscrowView,
        ) -> Result<()> {
            Ok(())
        }
    }

    impl LedgerRecords for Ledger {
        fn payment(&self, pay_ref: &[u8; 32]) -> Option<PaymentRecord> {
            self.records.lock().get(pay_ref).cloned()
        }
        fn agent_account_networks(&self) -> Vec<AgentAccountNetwork> {
            vec![AgentAccountNetwork {
                caip2: "eip155:8453".into(),
                route_chain: "base".into(),
            }]
        }
    }

    fn payee() -> Address {
        parse_tenzro_address(PAYEE_HEX).unwrap()
    }

    fn escrow(
        payer: Address,
        to: Address,
        amount: u128,
        conditions: ReleaseConditions,
    ) -> EscrowView {
        EscrowView {
            payer,
            payee: to,
            amount,
            claimed: 0,
            expires_at_ms: NOW + 3_600_000,
            funded: true,
            asset: "TNZO".into(),
            conditions,
        }
    }

    fn facilitator(ledger: Arc<Ledger>) -> X402Facilitator {
        X402Facilitator::new(1337, vec![], Arc::new(crate::test_support::SeedKeys))
            .with_escrow_reader(ledger.clone())
            .with_ledger_records(ledger)
    }

    #[tokio::test]
    async fn a_sealed_delivery_settles_only_when_both_legs_are_locked_by_its_key() {
        let ledger = Arc::new(Ledger::default());
        let f = facilitator(ledger.clone());
        let session = tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::random()));
        let (delivery, _key) = crate::dvp::SealedDelivery::seal(
            "/paid",
            b"the answer",
            10_000,
            "TNZO",
            PAYEE_HEX,
            1_000,
            &session,
        )
        .unwrap();
        let lock = delivery.lock().unwrap();
        let buyer = Address::new([4; 32]);
        let (seller_id, network_id) = ([1u8; 32], [2u8; 32]);
        ledger.escrows.lock().insert(
            seller_id,
            escrow(
                buyer,
                payee(),
                delivery.seller_amount(),
                ReleaseConditions::HashLock { hash: lock },
            ),
        );

        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            Arc::new(crate::test_support::SeedKeys),
        );
        let mut ch = server
            .create_challenge("/paid", 10_000, "TNZO", PAYEE_HEX)
            .await
            .unwrap();
        ch.extra
            .insert(CHAIN_ID_KEY.to_string(), serde_json::json!(1337u64));
        ch.extra
            .insert("scheme".to_string(), serde_json::json!(DVP_SCHEME));
        let mut cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        cred.extra.insert(
            DELIVERY_KEY.to_string(),
            serde_json::to_value(&delivery).unwrap(),
        );
        cred.extra.insert(
            ESCROW_ID_KEY.to_string(),
            serde_json::json!(hex::encode(seller_id)),
        );
        cred.extra.insert(
            NETWORK_ESCROW_ID_KEY.to_string(),
            serde_json::json!(hex::encode(network_id)),
        );
        let req = wire::requirement_for(&ch);
        let payload = wire::payload_for_credential(&ch, &cred).unwrap();

        // The network's share is not locked yet.
        assert!(f.verify(&req, &payload).await.is_err());
        ledger.escrows.lock().insert(
            network_id,
            escrow(
                buyer,
                tenzro_types::network_treasury_address(),
                delivery.network_share,
                ReleaseConditions::HashLock { hash: lock },
            ),
        );
        let settled = f.settle(&req, &payload).await;
        assert!(settled.success, "{settled:?}");
        assert_eq!(settled.transaction, format!("dvp:{}", hex::encode(lock)));

        // A seller escrow under another lock pays nothing for this delivery.
        ledger.escrows.lock().insert(
            seller_id,
            escrow(
                buyer,
                payee(),
                delivery.seller_amount(),
                ReleaseConditions::HashLock { hash: [9; 32] },
            ),
        );
        assert!(f.verify(&req, &payload).await.is_err());
    }

    fn proven_record(pay_ref: [u8; 32], amount: u128, source: &str) -> PaymentRecord {
        PaymentRecord {
            pay_ref: hex::encode(pay_ref),
            class: RecordClass::Proven,
            payer: "0xabc".into(),
            payee: payee(),
            asset: "USDC".into(),
            amount,
            fee: 0,
            settled: Default::default(),
            binding: Default::default(),
            nonce: "n".into(),
            agent_did: Some("did:tenzro:agent:a".into()),
            source: Some(source.into()),
            attestor: None,
            receipts: Vec::new(),
            refunded: 0,
            recorded_at_ms: NOW,
        }
    }

    fn proven_payload(
        challenge: &str,
        pay_ref: [u8; 32],
    ) -> (X402PaymentRequirement, X402PaymentPayload) {
        let mut req =
            X402PaymentRequirement::new(PROVEN_SCHEME, "eip155:8453", "500", PAYEE_HEX, "USDC", 60);
        req.set_extra(CHALLENGE_ID_KEY, serde_json::json!(challenge));
        let payload = X402PaymentPayload::new(
            req.clone(),
            serde_json::json!({ PAY_REF_KEY: hex::encode(pay_ref) }),
        );
        (req, payload)
    }

    #[tokio::test]
    async fn a_proven_payment_buys_one_requirement_on_its_own_chain() {
        let ledger = Arc::new(Ledger::default());
        let f = facilitator(ledger.clone());
        let pay_ref = [5u8; 32];
        let (req, payload) = proven_payload("c1", pay_ref);
        let pending = f.settle(&req, &payload).await;
        assert_eq!(pending.error_reason.as_deref(), Some("settlement_pending"));

        ledger
            .records
            .lock()
            .insert(pay_ref, proven_record(pay_ref, 500, "ethereum"));
        assert!(
            f.verify(&req, &payload).await.is_err(),
            "proven from another chain"
        );
        ledger
            .records
            .lock()
            .insert(pay_ref, proven_record(pay_ref, 499, "base"));
        assert!(
            f.verify(&req, &payload).await.is_err(),
            "pays less than required"
        );
        ledger
            .records
            .lock()
            .insert(pay_ref, proven_record(pay_ref, 500, "base"));
        let settled = f.settle(&req, &payload).await;
        assert!(settled.success, "{settled:?}");
        assert_eq!(settled.transaction, format!("pay:{}", hex::encode(pay_ref)));

        let (other, again) = proven_payload("c2", pay_ref);
        assert!(
            !f.settle(&other, &again).await.success,
            "a record buys one requirement"
        );
        assert!(
            f.settle(&req, &payload).await.success,
            "the same requirement settles idempotently"
        );
    }

    #[tokio::test]
    async fn an_agents_ledger_payment_buys_one_requirement_on_tenzro() {
        let ledger = Arc::new(Ledger::default());
        let f = facilitator(ledger.clone());
        let pay_ref = [6u8; 32];
        let tenzro = |challenge: &str| {
            let mut req = X402PaymentRequirement::new(
                PROVEN_SCHEME,
                "tenzro:1337",
                "500",
                PAYEE_HEX,
                "TNZO",
                60,
            );
            req.set_extra(CHALLENGE_ID_KEY, serde_json::json!(challenge));
            let payload = X402PaymentPayload::new(
                req.clone(),
                serde_json::json!({ PAY_REF_KEY: hex::encode(pay_ref) }),
            );
            (req, payload)
        };
        let (req, payload) = tenzro("t1");
        let mut record = proven_record(pay_ref, 500, "base");
        record.asset = "TNZO".into();
        ledger.records.lock().insert(pay_ref, record.clone());
        assert!(
            f.verify(&req, &payload).await.is_err(),
            "a record proven from another chain"
        );

        record.class = RecordClass::Native;
        record.source = None;
        record.agent_did = None;
        ledger.records.lock().insert(pay_ref, record.clone());
        assert!(
            f.verify(&req, &payload).await.is_err(),
            "a ledger payment no agent made"
        );

        record.agent_did = Some("did:tenzro:agent:a".into());
        ledger.records.lock().insert(pay_ref, record);
        let settled = f.settle(&req, &payload).await;
        assert!(settled.success, "{settled:?}");
        assert_eq!(settled.network, "tenzro:1337");
        assert_eq!(settled.transaction, format!("pay:{}", hex::encode(pay_ref)));

        let (other, again) = tenzro("t2");
        assert!(
            !f.settle(&other, &again).await.success,
            "a record buys one requirement"
        );
    }

    /// The payer SDKs' agent voucher payload decodes into the credential and
    /// agent voucher the facilitator and the ledger check.
    #[test]
    fn the_sdk_agent_voucher_vector_decodes_as_the_node_reads_it() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../sdk/fixtures/payments/x402_agent_voucher.json"
        ))
        .unwrap();
        let payload =
            X402PaymentPayload::from_base64(v["payment_signature"].as_str().unwrap()).unwrap();
        let requirement: X402PaymentRequirement =
            serde_json::from_value(v["requirement"].clone()).unwrap();
        assert_eq!(payload.accepted, requirement);
        let credential = wire::credential_from_payload(&payload).unwrap();
        assert_eq!(credential.amount, 90_071_992_547_409_930);
        let challenge =
            wire::challenge_from_requirement(&requirement, "https://pub.example/articles/1")
                .unwrap();
        let voucher = crate::payer_auth::verify_escrow_voucher(
            &crate::test_support::SeedKeys,
            &challenge,
            &credential,
        )
        .unwrap();
        assert_eq!(
            hex::encode(voucher.escrow_id),
            v["channel_id"].as_str().unwrap()
        );
        assert_eq!(voucher.cumulative_amount, 180_143_985_094_819_860);
        assert!(matches!(
            &voucher.signature.classical,
            tenzro_crypto::ClassicalProof::Raw { signature } if signature == &vec![0x11u8; 64]
        ));
        let agent = voucher.agent.unwrap();
        assert_eq!(agent.agent_did, "did:tenzro:agent:a");
        assert_eq!(agent.machine_did, "did:tenzro:machine:m");
        assert_eq!(agent.as_of_ms, 1_800_000_000_000);
    }

    #[tokio::test]
    async fn supported_lists_every_scheme_it_can_settle_and_agent_account_networks() {
        let ledger = Arc::new(Ledger::default());
        let sessions = Arc::new(crate::mpp::MppSessionManager::new(ledger.clone()));
        let f = facilitator(ledger).with_voucher_rail(sessions);
        let kinds = f.supported_kinds();
        for (scheme, network) in [
            (crate::x402::BATCH_SETTLEMENT_SCHEME, "tenzro:1337"),
            (DVP_SCHEME, "tenzro:1337"),
            (PROVEN_SCHEME, "tenzro:1337"),
            (PROVEN_SCHEME, "eip155:8453"),
        ] {
            assert!(
                kinds.contains(&(scheme.to_string(), network.to_string())),
                "{scheme} on {network}: {kinds:?}"
            );
        }
    }

    mod plans {
        use super::super::*;
        use parking_lot::Mutex;
        const PAYEE: &str = "0909090909090909090909090909090909090909";
        use crate::test_support::signer;
        use tenzro_crypto::composite::{HybridSigner, SignatureContext};
        use tenzro_types::primitives::{ChainId, Nonce};
        use tenzro_types::settlement::{
            AtomicityTier, Leg, LegClass, LegKind, LegReceipt, PlanOp, PlanStatus, SettlementPlan,
            leg_id, plan_id,
        };
        use tenzro_types::split::{
            SPLIT_RULE_VERSION, SplitBasis, SplitLine, SplitRecipient, SplitRole, SplitRule,
        };
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        const QUOTE: [u8; 32] = [0x51; 32];

        /// Opens the plan in memory when its transaction is admitted, as an
        /// all-Tenzro plan decides in the opening transaction.
        #[derive(Default)]
        struct MemoryPlans {
            opened: Mutex<Option<(SettlementPlan, Vec<LegReceipt>)>>,
            admitted: Mutex<Vec<SignedTransaction>>,
        }

        #[async_trait::async_trait]
        impl PlanRail for MemoryPlans {
            async fn open(&self, signed: &SignedTransaction) -> Result<RailOutcome> {
                let tx = &signed.transaction;
                let TransactionType::SettlementPlan {
                    op:
                        PlanOp::Open {
                            nonce,
                            quote_digest,
                            split,
                            legs,
                            decide_deadline_ms,
                            ..
                        },
                } = &tx.tx_type
                else {
                    return Ok(RailOutcome::Failed {
                        reason: "not a plan".into(),
                    });
                };
                let id = plan_id(1337, &tx.from, quote_digest, *nonce);
                let receipts = legs
                    .iter()
                    .enumerate()
                    .map(|(i, l)| LegReceipt {
                        plan_id: id,
                        leg_id: leg_id(&id, i as u8),
                        index: i as u8,
                        committed: true,
                        class_achieved: Some(LegClass::Native),
                        amount: match l.kind {
                            LegKind::NativeTransfer { amount, .. } => amount,
                            _ => 0,
                        },
                        proof_digest: None,
                        decided_at_ms: 1,
                        compensation: None,
                        network_fee: 0,
                        relayer: None,
                    })
                    .collect();
                let plan = SettlementPlan {
                    plan_id: id,
                    opened_by: tx.from,
                    agent_did: None,
                    quote_digest: *quote_digest,
                    split: split.clone(),
                    legs: legs.clone(),
                    tier: AtomicityTier::Native,
                    funded: 0,
                    opened_at_ms: 1,
                    decide_deadline_ms: *decide_deadline_ms,
                    status: PlanStatus::Committed,
                    achieved: vec![Some(LegClass::Native); legs.len()],
                    decision: None,
                    relays: vec![],
                    attribution: None,
                };
                *self.opened.lock() = Some((plan, receipts));
                self.admitted.lock().push(signed.clone());
                Ok(RailOutcome::Settled {
                    reference: "0xplan".into(),
                })
            }

            fn plan(&self, id: &[u8; 32]) -> Option<(SettlementPlan, Vec<LegReceipt>)> {
                self.opened.lock().clone().filter(|(p, _)| &p.plan_id == id)
            }
        }

        fn payee() -> tenzro_types::Address {
            parse_tenzro_address(PAYEE).unwrap()
        }

        fn signed_plan(
            amount: u128,
            pays: tenzro_types::Address,
            quote: [u8; 32],
        ) -> SignedTransaction {
            let signer = signer();
            let pk = signer.public_key().clone();
            let from = tenzro_types::Address::new(pk.account_slot());
            let split = SplitRule {
                version: SPLIT_RULE_VERSION,
                lines: vec![SplitLine {
                    role: SplitRole::Payee,
                    recipient: SplitRecipient::Address(pays),
                    basis: SplitBasis::Remainder,
                    cap: None,
                }],
            };
            let op = PlanOp::Open {
                attribution: None,
                nonce: 1,
                quote_digest: quote,
                split_hash: split.hash(),
                split,
                legs: vec![Leg {
                    kind: LegKind::NativeTransfer {
                        amount,
                        escrow_id: None,
                    },
                    class_required: LegClass::Native,
                    usd_e6: 0,
                    max_network_fee: 0,
                }],
                decide_deadline_ms: 10_000,
                agent: None,
            };
            let tx = Transaction::new(
                ChainId::from(1337),
                from,
                from,
                Nonce::from(0u64),
                TransactionType::SettlementPlan { op },
                500_000,
                1,
            );
            let sig = signer
                .sign(SignatureContext::Transaction, tx.hash().as_bytes())
                .unwrap();
            SignedTransaction::new(tx, pk.p256.clone(), sig)
        }

        fn plan_request(
            signed: &SignedTransaction,
            amount: &str,
        ) -> (X402PaymentRequirement, X402PaymentPayload) {
            let mut req =
                X402PaymentRequirement::new(PLAN_SCHEME, "tenzro:1337", amount, PAYEE, "TNZO", 60);
            req.set_extra(
                crate::payer_auth::QUOTE_DIGEST_KEY,
                serde_json::json!(hex::encode(QUOTE)),
            );
            let payload =
                X402PaymentPayload::new(req.clone(), serde_json::json!({ "signed_tx": signed }));
            (req, payload)
        }

        fn facilitator(plans: Arc<MemoryPlans>) -> X402Facilitator {
            X402Facilitator::new(1337, vec![], Arc::new(crate::test_support::SeedKeys))
                .with_plan_rail(plans)
        }

        #[tokio::test]
        async fn a_signed_plan_settles_with_its_plan_id_and_leg_receipts() {
            let plans = Arc::new(MemoryPlans::default());
            let f = facilitator(plans.clone());
            let signed = signed_plan(100, payee(), QUOTE);
            let (req, payload) = plan_request(&signed, "100");
            let verified = f.verify(&req, &payload).await.unwrap();
            assert_eq!(
                verified.payer,
                format!("0x{}", hex::encode(signed.transaction.from.as_bytes()))
            );
            assert!(plans.admitted.lock().is_empty(), "verifying admits nothing");

            let response = f.settle(&req, &payload).await;
            assert!(response.success, "{:?}", response.error_reason);
            assert_eq!(response.transaction, "0xplan");
            let plan = response.plan.expect("a plan payment reports its plan");
            let id = plan_id(1337, &signed.transaction.from, &QUOTE, 1);
            assert_eq!(plan.plan_id, hex::encode(id));
            assert_eq!(plan.status, PlanStatus::Committed);
            assert_eq!(plan.leg_ids, vec![hex::encode(leg_id(&id, 0))]);
            assert_eq!(plan.receipts.len(), 1);
            assert_eq!(plan.receipts[0].amount, 100);
            assert_eq!(plans.admitted.lock().len(), 1);

            let again = f.settle(&req, &payload).await;
            assert!(!again.success, "an opened plan does not settle twice");
            assert!(
                f.supported_kinds()
                    .contains(&(PLAN_SCHEME.to_string(), "tenzro:1337".to_string()))
            );
        }

        #[tokio::test]
        async fn a_plan_that_does_not_pay_the_requirement_is_refused() {
            let f = facilitator(Arc::new(MemoryPlans::default()));
            let signed = signed_plan(100, payee(), QUOTE);
            let (req, payload) = plan_request(&signed, "101");
            assert!(matches!(
                f.verify(&req, &payload).await,
                Err(PaymentError::InsufficientFunds(_))
            ));

            let other = signed_plan(100, tenzro_types::Address::new([3; 32]), QUOTE);
            let (req, payload) = plan_request(&other, "100");
            assert!(
                f.verify(&req, &payload).await.is_err(),
                "the split pays someone else"
            );

            let requoted = signed_plan(100, payee(), [0x52; 32]);
            let (req, payload) = plan_request(&requoted, "100");
            assert!(f.verify(&req, &payload).await.is_err(), "another quote");
        }

        #[tokio::test]
        async fn a_tampered_plan_signature_is_refused() {
            let f = facilitator(Arc::new(MemoryPlans::default()));
            let mut signed = signed_plan(100, payee(), QUOTE);
            if let TransactionType::SettlementPlan {
                op: PlanOp::Open { legs, .. },
            } = &mut signed.transaction.tx_type
            {
                legs[0].kind = LegKind::NativeTransfer {
                    amount: 1_000,
                    escrow_id: None,
                };
            }
            let (req, payload) = plan_request(&signed, "100");
            assert!(matches!(
                f.verify(&req, &payload).await,
                Err(PaymentError::CredentialError(_))
            ));
        }

        #[tokio::test]
        async fn without_a_plan_rail_no_plan_settles() {
            let f = X402Facilitator::new(1337, vec![], Arc::new(crate::test_support::SeedKeys));
            let signed = signed_plan(100, payee(), QUOTE);
            let (req, payload) = plan_request(&signed, "100");
            assert!(f.verify(&req, &payload).await.is_err());
            assert!(!f.settle(&req, &payload).await.success);
        }
    }
}
