//! What the extensions ask of Tenzro.
//!
//! An extension never decides on its own whether an agent may act. It asks
//! the [`Authority`] for the agent's Terms and revocation state and holds the
//! action to them with [`tenzro_types::agent_terms::check_action`], the same
//! check the chain runs.
//!
//! The agent's delegation comes from [`Delegations`]: its Terms as the
//! controller approved them, whether it or the root that delegated it was
//! revoked, and what it has spent against its limits. In service that is a
//! running Tenzro node, read over its RPC on every decision
//! ([`crate::node::NodeDelegations`]), so a revocation on Tenzro stops the
//! next action. [`LocalDelegations`] holds the same in this process, for
//! tests.
//!
//! [`StateAuthority`] adds what belongs to this serving host: the operator
//! principals bound to controller accounts, which agent each sandbox runs,
//! the actions it authorized that the node does not count yet, and the
//! balances payments settle on. It also answers the payment stack's
//! questions (Terms gate, payer DID binding, enrolled keys and the
//! settlement rail), so a payee gate built from `tenzro-payments` settles
//! against the same state the sandbox's extensions check.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_payments::gateway::{RailOutcome, SettlementInstruction, SettlementRail};
use tenzro_payments::payer_auth::{EnrolledKeys, PayerKeyResolver};
use tenzro_payments::terms_gate::{PaymentIntent, TermsGate};
use tenzro_payments::{PaymentError, Result as PayResult};
use tenzro_types::agent_terms::{
    ActionHistory, AgentAction, AgentPayment, AgentTerms, DAY_MS, HOUR_MS, OP_PAY, agent_wallet,
    check_action,
};
use tenzro_types::primitives::Address;
use tenzro_types::split::{FeeParams, SplitRule, apply as apply_split};

/// The refusal reason for an agent that was revoked, directly or through
/// the root that delegated it.
pub const REVOKED: &str = "agent revoked";

/// Where an agent's delegation stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// It may act within its Terms.
    Active,
    /// It, or the root that delegated it, was revoked.
    Revoked,
    /// It is quarantined pending review.
    Quarantined,
    /// Its Terms expired.
    Expired,
}

/// What an agent has spent against its limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spent {
    /// Value moved in the last day.
    pub today: u128,
    /// Value moved in the last hour.
    pub this_hour: u128,
    /// Actions in the last day.
    pub actions_today: u32,
    /// Actions in the last hour.
    pub actions_this_hour: u32,
}

/// An agent's delegation: the Terms its controller approved, where it
/// stands and what it has spent.
#[derive(Debug, Clone)]
pub struct Delegation {
    /// The Terms, naming the controller (the root) that approved them.
    pub terms: AgentTerms,
    /// Where it stands.
    pub standing: Standing,
    /// What it has spent, as Tenzro counts it.
    pub spent: Spent,
}

/// Where the extensions read an agent's delegation.
pub trait Delegations: Send + Sync {
    /// The agent's delegation, `None` when no controller approved Terms for
    /// it. An error means the answer could not be read; callers refuse.
    fn delegation(&self, agent_did: &str, now_ms: u64) -> Result<Option<Delegation>, String>;
}

/// Delegations held in this process.
#[derive(Default)]
pub struct LocalDelegations {
    terms: RwLock<HashMap<String, AgentTerms>>,
    revoked: RwLock<HashMap<String, String>>,
}

impl LocalDelegations {
    /// Install Terms the controller approved for an agent.
    pub fn install_terms(&self, agent_did: &str, terms: AgentTerms) {
        self.terms.write().insert(agent_did.to_string(), terms);
    }

    /// Revoke an agent or a root, as the kill switch does: every agent the
    /// root delegated stops with it.
    pub fn revoke(&self, did: &str, reason: &str) {
        self.revoked
            .write()
            .insert(did.to_string(), reason.to_string());
    }
}

impl Delegations for LocalDelegations {
    fn delegation(&self, agent_did: &str, now_ms: u64) -> Result<Option<Delegation>, String> {
        let Some(terms) = self.terms.read().get(agent_did).cloned() else {
            return Ok(None);
        };
        let revoked = self.revoked.read();
        let standing = if let Some(why) = revoked
            .get(agent_did)
            .or_else(|| revoked.get(&terms.controller_did))
        {
            tracing::debug!("{agent_did} revoked: {why}");
            Standing::Revoked
        } else if terms.expires_at_ms.is_some_and(|at| now_ms >= at) {
            Standing::Expired
        } else {
            Standing::Active
        };
        Ok(Some(Delegation {
            terms,
            standing,
            spent: Spent::default(),
        }))
    }
}

/// Why an action was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// One action an extension asks to take for an agent.
#[derive(Debug, Clone, Default)]
pub struct Proposed {
    /// The operation, as Terms name it (`sandbox`, `sandbox.policy`,
    /// `fetch`, `inference`, `pay`).
    pub operation: String,
    /// Payee, hex address, for a payment or a metered call.
    pub counterparty: String,
    /// Value moved, smallest unit of TNZO.
    pub amount: u128,
    /// Payment protocol, for a payment.
    pub payment_protocol: Option<String>,
    /// Chain the payment settles on.
    pub chain: String,
    /// Model, for an inference call.
    pub model: Option<String>,
    /// The payment, for `pay`: its id and the request it pays for.
    pub payment: Option<(String, [u8; 32])>,
}

/// Tenzro state the extensions read and the actions they report.
pub trait Authority: Send + Sync {
    /// The agent's Terms, if its controller approved any.
    fn terms(&self, agent_did: &str) -> Option<AgentTerms>;
    /// Why the agent may no longer act: it, or the root that delegated it,
    /// was revoked, or its Terms expired. `None` while it may act.
    fn revoked(&self, agent_did: &str, now_ms: u64) -> Option<String>;
    /// The controller DID an OpenShell principal subject is bound to.
    fn controller_of(&self, principal_subject: &str) -> Option<String>;
    /// The agent a sandbox (name or id) runs.
    fn agent_of_sandbox(&self, sandbox: &str) -> Option<String>;
    /// Record that `sandbox` (each of its names) runs `agent_did`.
    fn bind_sandbox(&self, names: &[&str], agent_did: &str);
    /// The serving node's machine DID the extensions act as.
    fn machine_did(&self) -> String;
    /// Hold `proposed` to the agent's Terms and revocation state without
    /// counting it.
    fn check(&self, agent_did: &str, proposed: &Proposed, now_ms: u64) -> Result<(), Refusal>;
    /// Hold `proposed` to the agent's Terms and revocation state and, when it
    /// passes, count it against the agent's limits.
    fn authorize(&self, agent_did: &str, proposed: &Proposed, now_ms: u64) -> Result<(), Refusal>;
    /// Move `amount` from the agent's wallet to `payee` for an action it was
    /// authorized for, returning the settlement reference.
    fn settle(
        &self,
        agent_did: &str,
        payee: &Address,
        amount: u128,
        reference: &str,
    ) -> Result<String, Refusal>;
}

#[derive(Debug, Clone)]
struct Act {
    at_ms: u64,
    amount: u128,
    counterparty: String,
}

#[derive(Default)]
struct State {
    principals: HashMap<String, String>,
    sandboxes: HashMap<String, String>,
    acts: HashMap<String, Vec<Act>>,
    balances: HashMap<Address, u128>,
    settled: HashMap<String, String>,
    serving_keys: HashMap<String, Vec<u8>>,
    payee_rules: HashMap<Address, SplitRule>,
    did_keys: HashMap<String, Vec<p256::ecdsa::VerifyingKey>>,
    mandates: HashMap<(String, String), String>,
    nonce: u64,
}

/// The serving host's view of Tenzro: delegations read from
/// [`Delegations`], the rest held here.
pub struct StateAuthority {
    machine_did: String,
    chain_id: u64,
    serving: CompositePublicKey,
    delegations: Arc<dyn Delegations>,
    local: Option<Arc<LocalDelegations>>,
    state: RwLock<State>,
}

impl StateAuthority {
    /// An authority for the serving node `machine_did`, whose composite key
    /// (P-256 `x || y` and the enrolled ML-DSA-65 key) signs the agents' payments, with delegations held in this
    /// process ([`StateAuthority::install_terms`], [`StateAuthority::revoke`]).
    pub fn new(
        machine_did: impl Into<String>,
        serving: CompositePublicKey,
        chain_id: u64,
    ) -> Arc<Self> {
        let local = Arc::new(LocalDelegations::default());
        Self::build(
            machine_did.into(),
            serving,
            chain_id,
            local.clone(),
            Some(local),
        )
    }

    /// An authority for the serving node `machine_did` that reads every
    /// agent's delegation from `delegations`: a running Tenzro node.
    pub fn over(
        machine_did: impl Into<String>,
        serving: CompositePublicKey,
        chain_id: u64,
        delegations: Arc<dyn Delegations>,
    ) -> Arc<Self> {
        Self::build(machine_did.into(), serving, chain_id, delegations, None)
    }

    fn build(
        machine_did: String,
        serving: CompositePublicKey,
        chain_id: u64,
        delegations: Arc<dyn Delegations>,
        local: Option<Arc<LocalDelegations>>,
    ) -> Arc<Self> {
        let mut state = State::default();
        state
            .serving_keys
            .insert(machine_did.clone(), serving.p256.clone());
        Arc::new(Self {
            machine_did,
            chain_id,
            serving,
            delegations,
            local,
            state: RwLock::new(state),
        })
    }

    fn local(&self) -> &LocalDelegations {
        self.local
            .as_deref()
            .expect("this authority reads delegations from Tenzro; change them there")
    }

    /// The agent's delegation if it may act now, or why it may not.
    fn standing(&self, agent_did: &str, now_ms: u64) -> Result<Delegation, Refusal> {
        let d = self
            .delegations
            .delegation(agent_did, now_ms)
            .map_err(|e| Refusal(format!("the agent's delegation could not be read: {e}")))?
            .ok_or_else(|| Refusal("the agent has no Terms".to_string()))?;
        match d.standing {
            Standing::Revoked => Err(Refusal(REVOKED.to_string())),
            Standing::Quarantined => Err(Refusal("agent quarantined".to_string())),
            Standing::Expired => Err(Refusal("terms expired".to_string())),
            Standing::Active if d.terms.expires_at_ms.is_some_and(|at| now_ms >= at) => {
                Err(Refusal("terms expired".to_string()))
            }
            Standing::Active => Ok(d),
        }
    }

    /// Why the agent may not act now; `None` while it may, or when it has
    /// no Terms at all.
    fn stopped(&self, agent_did: &str, now_ms: u64) -> Option<String> {
        match self.standing(agent_did, now_ms) {
            Ok(_) => None,
            Err(r) if r.0 == "the agent has no Terms" => None,
            Err(r) => Some(r.0),
        }
    }

    /// The chain payments settle on.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Install Terms the controller approved for an agent, on an authority
    /// that holds delegations in this process.
    pub fn install_terms(&self, agent_did: &str, terms: AgentTerms) {
        self.local().install_terms(agent_did, terms);
    }

    /// Revoke an agent or a root, on an authority that holds delegations in
    /// this process: every agent the root delegated stops with it.
    pub fn revoke(&self, did: &str, reason: &str) {
        self.local().revoke(did, reason);
    }

    /// Bind an OpenShell principal subject to a controller account.
    pub fn bind_principal(&self, subject: &str, controller_did: &str) {
        self.state
            .write()
            .principals
            .insert(subject.to_string(), controller_did.to_string());
    }

    /// Credit an account.
    pub fn fund(&self, account: Address, amount: u128) {
        let mut s = self.state.write();
        let b = s.balances.entry(account).or_default();
        *b = b.saturating_add(amount);
    }

    /// An account's balance.
    pub fn balance(&self, account: &Address) -> u128 {
        self.state
            .read()
            .balances
            .get(account)
            .copied()
            .unwrap_or(0)
    }

    /// Divide what `payee` is paid by `rule`: an agent paid for work it
    /// serves, with its controller and collaborators taking their lines.
    pub fn set_payee_split(&self, payee: Address, rule: SplitRule) -> Result<(), Refusal> {
        rule.validate()
            .map_err(|e| Refusal(format!("split rule: {e}")))?;
        self.state.write().payee_rules.insert(payee, rule);
        Ok(())
    }

    /// Record that `did` lists `key` for authentication or assertion: a
    /// controller's passkey, which signs its AP2 mandates.
    pub fn register_did_key(&self, did: &str, key: p256::ecdsa::VerifyingKey) {
        self.state
            .write()
            .did_keys
            .entry(did.to_string())
            .or_default()
            .push(key);
    }

    /// Lodge a Payment Mandate the agent's controller signed for the
    /// checkout `transaction_id`.
    pub fn lodge_mandate(&self, agent_did: &str, transaction_id: &str, mandate: String) {
        self.state
            .write()
            .mandates
            .insert((agent_did.to_string(), transaction_id.to_string()), mandate);
    }

    /// The settlement reference recorded for a payment id, once settled.
    pub fn settlement_of(&self, payment_id: &str) -> Option<String> {
        self.state.read().settled.get(payment_id).cloned()
    }

    /// The agent's wallet address.
    pub fn wallet(agent_did: &str) -> Address {
        Address::new(agent_wallet(agent_did))
    }

    /// What Tenzro counts the agent has spent, plus what this host
    /// authorized since.
    fn history(
        s: &State,
        agent_did: &str,
        counterparty: &str,
        spent: &Spent,
        now_ms: u64,
    ) -> ActionHistory {
        let mut h = ActionHistory {
            spent_today: spent.today,
            spent_this_hour: spent.this_hour,
            actions_today: spent.actions_today,
            actions_this_hour: spent.actions_this_hour,
            ..Default::default()
        };
        for a in s.acts.get(agent_did).map(Vec::as_slice).unwrap_or_default() {
            let age = now_ms.saturating_sub(a.at_ms);
            if age < DAY_MS {
                h.spent_today = h.spent_today.saturating_add(a.amount);
                h.actions_today += 1;
            }
            if age < HOUR_MS {
                h.spent_this_hour = h.spent_this_hour.saturating_add(a.amount);
                h.actions_this_hour += 1;
            }
            if !counterparty.is_empty() && a.counterparty.eq_ignore_ascii_case(counterparty) {
                h.known_counterparty = true;
            }
        }
        h
    }

    fn debit(s: &mut State, from: &Address, amount: u128) -> Result<(), Refusal> {
        let have = s.balances.get(from).copied().unwrap_or(0);
        if have < amount {
            return Err(Refusal(format!(
                "insufficient balance: {have} held, {amount} needed"
            )));
        }
        s.balances.insert(*from, have - amount);
        Ok(())
    }

    /// Credit `payee`, divided by its split rule when it has one.
    fn credit(s: &mut State, payee: &Address, amount: u128) -> Result<(), Refusal> {
        let Some(rule) = s.payee_rules.get(payee).cloned() else {
            *s.balances.entry(*payee).or_default() += amount;
            return Ok(());
        };
        let none = FeeParams {
            fee_bps: 0,
            min_fee: 0,
            burn_bps: 0,
            insurance_bps: 0,
        };
        let allocation =
            apply_split(amount, &rule, &none, 0).map_err(|e| Refusal(format!("split: {e}")))?;
        for (line, credit) in rule.lines.iter().zip(allocation.credits.iter()) {
            let to = match &line.recipient {
                tenzro_types::split::SplitRecipient::Address(a) => *a,
                tenzro_types::split::SplitRecipient::DidDerived(did) => Self::wallet(did),
                tenzro_types::split::SplitRecipient::LegSubmitter => *payee,
            };
            *s.balances.entry(to).or_default() += *credit;
        }
        Ok(())
    }

    fn action(&self, agent_did: &str, p: &Proposed, nonce: u64) -> AgentAction {
        AgentAction {
            agent_did: agent_did.to_string(),
            machine_did: self.machine_did.clone(),
            operation: p.operation.clone(),
            counterparty: p.counterparty.clone(),
            amount: p.amount,
            asset: None,
            usd_e6: 0,
            payment: p.payment.as_ref().map(|(id, request)| AgentPayment {
                payment_id: id.clone(),
                request_digest: *request,
                quote_digest: [0; 32],
            }),
            chain: p.chain.clone(),
            payment_protocol: p.payment_protocol.clone(),
            model: p.model.clone(),
            calls: Vec::new(),
            escrow: None,
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce,
            tainted: false,
            step_up: None,
        }
    }
}

impl Authority for StateAuthority {
    fn terms(&self, agent_did: &str) -> Option<AgentTerms> {
        match self.delegations.delegation(agent_did, crate::now_ms()) {
            Ok(d) => d.map(|d| d.terms),
            Err(e) => {
                tracing::warn!("{agent_did}: delegation not read: {e}");
                None
            }
        }
    }

    fn revoked(&self, agent_did: &str, now_ms: u64) -> Option<String> {
        self.stopped(agent_did, now_ms)
    }

    fn controller_of(&self, principal_subject: &str) -> Option<String> {
        self.state.read().principals.get(principal_subject).cloned()
    }

    fn agent_of_sandbox(&self, sandbox: &str) -> Option<String> {
        self.state.read().sandboxes.get(sandbox).cloned()
    }

    fn bind_sandbox(&self, names: &[&str], agent_did: &str) {
        let mut s = self.state.write();
        for n in names.iter().filter(|n| !n.is_empty()) {
            s.sandboxes.insert((*n).to_string(), agent_did.to_string());
        }
    }

    fn machine_did(&self) -> String {
        self.machine_did.clone()
    }

    fn check(&self, agent_did: &str, proposed: &Proposed, now_ms: u64) -> Result<(), Refusal> {
        let d = self.standing(agent_did, now_ms)?;
        let s = self.state.read();
        let history = Self::history(&s, agent_did, &proposed.counterparty, &d.spent, now_ms);
        let action = self.action(agent_did, proposed, s.nonce + 1);
        check_action(&d.terms, &action, &history, false, now_ms)
            .map_err(|d| Refusal(format!("outside the agent's approved terms: {d}")))
    }

    fn authorize(&self, agent_did: &str, proposed: &Proposed, now_ms: u64) -> Result<(), Refusal> {
        let d = self.standing(agent_did, now_ms)?;
        let mut s = self.state.write();
        let history = Self::history(&s, agent_did, &proposed.counterparty, &d.spent, now_ms);
        s.nonce += 1;
        let action = self.action(agent_did, proposed, s.nonce);
        check_action(&d.terms, &action, &history, false, now_ms)
            .map_err(|d| Refusal(format!("outside the agent's approved terms: {d}")))?;
        s.acts.entry(agent_did.to_string()).or_default().push(Act {
            at_ms: now_ms,
            amount: proposed.amount,
            counterparty: proposed.counterparty.clone(),
        });
        Ok(())
    }

    fn settle(
        &self,
        agent_did: &str,
        payee: &Address,
        amount: u128,
        reference: &str,
    ) -> Result<String, Refusal> {
        let mut s = self.state.write();
        if let Some(done) = s.settled.get(reference) {
            return Err(Refusal(format!("{reference} already settled as {done}")));
        }
        let from = Self::wallet(agent_did);
        Self::debit(&mut s, &from, amount)?;
        Self::credit(&mut s, payee, amount)?;
        let tx = hex::encode(crate::digest(
            b"tenzro/openshell/settlement/v1",
            &[
                agent_did.as_bytes(),
                payee.as_bytes(),
                &amount.to_le_bytes(),
                reference.as_bytes(),
            ],
        ));
        s.settled.insert(reference.to_string(), tx.clone());
        Ok(tx)
    }
}

/// A payee gate built from `tenzro-payments` checks a paying agent against
/// the same Terms its sandbox is held to. The sandbox side already counted the
/// payment when it authorized it, so this check reads the limits without
/// counting it a second time.
impl TermsGate for StateAuthority {
    fn authorize(&self, intent: &PaymentIntent<'_>) -> PayResult<()> {
        let now = crate::now_ms();
        let d = match self.standing(intent.payer_did, now) {
            Ok(d) => d,
            // Not a delegated agent: it pays under its own key.
            Err(r) if r.0 == "the agent has no Terms" => return Ok(()),
            Err(r) => return Err(PaymentError::VerificationFailed(r.0)),
        };
        let s = self.state.read();
        let counterparty = intent.counterparty.unwrap_or_default().to_string();
        let mut history = Self::history(&s, intent.payer_did, &counterparty, &d.spent, now);
        // The authorization the sandbox side counted is this payment.
        history.spent_today = history.spent_today.saturating_sub(intent.amount);
        history.spent_this_hour = history.spent_this_hour.saturating_sub(intent.amount);
        history.actions_today = history.actions_today.saturating_sub(1);
        history.actions_this_hour = history.actions_this_hour.saturating_sub(1);
        let p = Proposed {
            operation: OP_PAY.to_string(),
            counterparty,
            amount: intent.amount,
            payment_protocol: intent.protocol.map(str::to_string),
            chain: String::new(),
            model: None,
            payment: Some(("gate".to_string(), [1; 32])),
        };
        let action = self.action(intent.payer_did, &p, 0);
        check_action(&d.terms, &action, &history, false, now).map_err(|d| {
            PaymentError::VerificationFailed(format!("outside the agent's approved terms: {d}"))
        })
    }
}

/// An agent's DID binds the serving nodes its Terms name: they sign its
/// payments, and the agent holds no key.
impl PayerKeyResolver for StateAuthority {
    fn did_binds_payer(&self, did: &str, public_key: &[u8], _payer: &Address) -> PayResult<bool> {
        let d = self
            .standing(did, crate::now_ms())
            .map_err(|r| PaymentError::IdentityError(format!("payer DID {did}: {r}")))?;
        let s = self.state.read();
        Ok(d.terms.serving_nodes.iter().any(|n| {
            s.serving_keys
                .get(&n.machine_did)
                .is_some_and(|k| k.as_slice() == public_key)
        }))
    }
}

/// The serving node's own key is the only one this authority knows; its
/// ML-DSA-65 key is the one enrolled for the account that P-256 key controls.
impl EnrolledKeys for StateAuthority {
    fn enrolled_pq_key(&self, p256_xy: &[u8]) -> PayResult<Option<Vec<u8>>> {
        Ok((p256_xy == self.serving.p256.as_slice())
            .then(|| self.serving.pq.clone())
            .flatten())
    }
}

/// Settles a verified payment from the paying agent's wallet.
#[async_trait]
impl SettlementRail for StateAuthority {
    fn name(&self) -> &'static str {
        "tenzro-state"
    }

    fn carries(&self, asset: &str) -> bool {
        asset.eq_ignore_ascii_case("TNZO")
    }

    async fn settle(&self, i: &SettlementInstruction) -> PayResult<RailOutcome> {
        let Some(did) = i.payer.did.as_deref() else {
            return Ok(RailOutcome::Failed {
                reason: "the payer named no agent DID".to_string(),
            });
        };
        match Authority::settle(self, did, &i.payee, i.amount, &i.payment_id) {
            Ok(reference) => Ok(RailOutcome::Settled { reference }),
            Err(r) => Ok(RailOutcome::Failed { reason: r.0 }),
        }
    }

    async fn status(&self, payment_id: &str) -> PayResult<RailOutcome> {
        Ok(match self.settlement_of(payment_id) {
            Some(reference) => RailOutcome::Settled { reference },
            None => RailOutcome::Failed {
                reason: "unknown payment".to_string(),
            },
        })
    }
}

impl tenzro_payments::ap2::MandateKeys for StateAuthority {
    fn controller_of(&self, agent_did: &str) -> Option<String> {
        Authority::terms(self, agent_did).map(|t| t.controller_did)
    }

    fn did_lists_key(&self, did: &str, key: &p256::ecdsa::VerifyingKey) -> PayResult<bool> {
        Ok(self
            .state
            .read()
            .did_keys
            .get(did)
            .is_some_and(|keys| keys.contains(key)))
    }
}

impl crate::payments::Mandates for StateAuthority {
    fn payment_mandate(&self, agent_did: &str, transaction_id: &str) -> Option<String> {
        self.state
            .read()
            .mandates
            .get(&(agent_did.to_string(), transaction_id.to_string()))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_driver::tests::{MACHINE, ROOT, agent, terms};
    use tenzro_types::agent_terms::AgentTerms;

    fn authority(edit: impl FnOnce(&mut AgentTerms)) -> Arc<StateAuthority> {
        let a = StateAuthority::new(
            MACHINE,
            CompositePublicKey {
                p256: vec![7; 64],
                pq: None,
            },
            1337,
        );
        let mut t = terms(&["fetch", "pay"]);
        edit(&mut t);
        a.install_terms(&agent(), t);
        a
    }

    fn fetch() -> Proposed {
        Proposed {
            operation: "fetch".into(),
            ..Default::default()
        }
    }

    /// Delegations that cannot be read.
    struct Down;

    impl Delegations for Down {
        fn delegation(&self, _: &str, _: u64) -> Result<Option<Delegation>, String> {
            Err("node unreachable".into())
        }
    }

    #[test]
    fn an_agent_with_no_terms_is_refused_and_is_not_reported_stopped() {
        let a = StateAuthority::new(
            MACHINE,
            CompositePublicKey {
                p256: vec![7; 64],
                pq: None,
            },
            1337,
        );
        let r = a.check(&agent(), &fetch(), 1_000).unwrap_err();
        assert_eq!(r.0, "the agent has no Terms");
        assert!(Authority::authorize(&*a, &agent(), &fetch(), 1_000).is_err());
        assert!(a.terms(&agent()).is_none());
        assert!(a.revoked(&agent(), 1_000).is_none());
    }

    #[test]
    fn an_operation_outside_the_terms_is_refused() {
        let a = authority(|_| {});
        assert!(a.check(&agent(), &fetch(), 1_000).is_ok());
        let inference = Proposed {
            operation: "inference".into(),
            ..Default::default()
        };
        let r = a.check(&agent(), &inference, 1_000).unwrap_err();
        assert!(r.0.starts_with("outside the agent's approved terms"), "{r}");
        assert!(Authority::authorize(&*a, &agent(), &inference, 1_000).is_err());
    }

    #[test]
    fn a_revoked_agent_and_every_agent_of_a_revoked_root_stop() {
        let a = authority(|_| {});
        a.revoke(&agent(), "compromised");
        assert_eq!(a.check(&agent(), &fetch(), 1_000).unwrap_err().0, REVOKED);
        assert_eq!(a.revoked(&agent(), 1_000).as_deref(), Some(REVOKED));

        let b = authority(|_| {});
        assert!(b.revoked(&agent(), 1_000).is_none());
        b.revoke(ROOT, "root withdrawn");
        assert_eq!(
            Authority::authorize(&*b, &agent(), &fetch(), 1_000)
                .unwrap_err()
                .0,
            REVOKED
        );
    }

    #[test]
    fn terms_stop_at_their_expiry() {
        let a = authority(|t| t.expires_at_ms = Some(5_000));
        assert!(a.check(&agent(), &fetch(), 4_999).is_ok());
        assert_eq!(
            a.check(&agent(), &fetch(), 5_000).unwrap_err().0,
            "terms expired"
        );
        assert_eq!(a.revoked(&agent(), 5_000).as_deref(), Some("terms expired"));
    }

    #[test]
    fn an_unreadable_delegation_refuses_and_reports_the_agent_stopped() {
        let a = StateAuthority::over(
            MACHINE,
            CompositePublicKey {
                p256: vec![7; 64],
                pq: None,
            },
            1337,
            Arc::new(Down),
        );
        let r = a.check(&agent(), &fetch(), 1_000).unwrap_err();
        assert!(r.0.contains("could not be read"), "{r}");
        assert!(a.terms(&agent()).is_none());
        assert!(
            a.revoked(&agent(), 1_000).is_some(),
            "a delegation that cannot be read stops the agent"
        );
    }

    #[test]
    fn the_hourly_action_limit_counts_authorized_actions_and_not_checks() {
        let a = authority(|t| t.delegation_scope.max_actions_per_hour = Some(2));
        for _ in 0..5 {
            a.check(&agent(), &fetch(), 1_000).unwrap();
        }
        Authority::authorize(&*a, &agent(), &fetch(), 1_000).unwrap();
        Authority::authorize(&*a, &agent(), &fetch(), 2_000).unwrap();
        let r = Authority::authorize(&*a, &agent(), &fetch(), 3_000).unwrap_err();
        assert!(r.0.starts_with("outside the agent's approved terms"), "{r}");
        assert!(a.check(&agent(), &fetch(), 3_000).is_err());
        // The window slides: an hour after the first two, the agent may act.
        Authority::authorize(&*a, &agent(), &fetch(), 2_000 + HOUR_MS + 1).unwrap();
    }

    #[test]
    fn the_daily_spend_limit_holds_across_authorized_payments() {
        let a = authority(|t| t.delegation_scope.max_daily_spend = Some("100".into()));
        let pay = |amount| Proposed {
            operation: "pay".into(),
            counterparty: "0xaa".into(),
            amount,
            payment_protocol: Some("x402".into()),
            payment: Some(("p".into(), [1; 32])),
            ..Default::default()
        };
        Authority::authorize(&*a, &agent(), &pay(60), 1_000).unwrap();
        assert!(
            Authority::authorize(&*a, &agent(), &pay(60), 2_000).is_err(),
            "120 > 100"
        );
        Authority::authorize(&*a, &agent(), &pay(40), 3_000).unwrap();
        assert!(Authority::authorize(&*a, &agent(), &pay(1), 4_000).is_err());
        assert!(
            Authority::authorize(&*a, &agent(), &pay(60), 1_000 + DAY_MS).is_ok(),
            "a day later the first payment has aged out"
        );
    }

    #[test]
    fn a_settlement_needs_the_funds_and_is_made_once_per_reference() {
        let a = authority(|_| {});
        let payee = Address::new([9; 32]);
        let wallet = StateAuthority::wallet(&agent());
        let r = Authority::settle(&*a, &agent(), &payee, 10, "ref-1").unwrap_err();
        assert!(r.0.starts_with("insufficient balance"), "{r}");
        assert_eq!(a.balance(&payee), 0);
        assert!(a.settlement_of("ref-1").is_none());

        a.fund(wallet, 25);
        let tx = Authority::settle(&*a, &agent(), &payee, 10, "ref-1").unwrap();
        assert_eq!(a.settlement_of("ref-1"), Some(tx));
        assert_eq!((a.balance(&wallet), a.balance(&payee)), (15, 10));
        let again = Authority::settle(&*a, &agent(), &payee, 10, "ref-1").unwrap_err();
        assert!(again.0.contains("already settled"), "{again}");
        assert_eq!((a.balance(&wallet), a.balance(&payee)), (15, 10));
    }

    #[test]
    fn a_malformed_split_rule_is_refused() {
        let a = authority(|_| {});
        let rule = SplitRule {
            version: 0,
            lines: Vec::new(),
        };
        let r = a.set_payee_split(Address::new([3; 32]), rule).unwrap_err();
        assert!(r.0.starts_with("split rule"), "{r}");
    }

    #[test]
    fn the_payee_gate_holds_a_delegated_payer_to_its_terms() {
        let a = authority(|t| t.delegation_scope.max_transaction_value = Some("50".into()));
        let intent = |payer: &'static str, amount| PaymentIntent {
            payer_did: payer,
            amount,
            operation: OP_PAY,
            protocol: Some("x402"),
            chain: None,
            counterparty: Some("0xaa"),
        };
        let me: &'static str = Box::leak(agent().into_boxed_str());
        assert!(TermsGate::authorize(&*a, &intent(me, 10)).is_ok());
        assert!(
            TermsGate::authorize(&*a, &intent(me, 500)).is_err(),
            "over the per-transaction ceiling"
        );
        assert!(
            TermsGate::authorize(&*a, &intent("did:tenzro:human:nobody", 500)).is_ok(),
            "a payer with no Terms pays under its own key"
        );
        a.revoke(me, "stopped");
        assert!(TermsGate::authorize(&*a, &intent(me, 10)).is_err());
    }

    #[test]
    fn a_did_binds_only_the_serving_keys_its_terms_name() {
        let a = authority(|_| {});
        let payer = Address::new([1; 32]);
        assert!(a.did_binds_payer(&agent(), &[7; 64], &payer).unwrap());
        assert!(!a.did_binds_payer(&agent(), &[8; 64], &payer).unwrap());
        assert!(
            a.did_binds_payer("did:tenzro:human:nobody", &[7; 64], &payer)
                .is_err(),
            "a DID with no Terms binds no key"
        );
        a.revoke(&agent(), "stopped");
        assert!(a.did_binds_payer(&agent(), &[7; 64], &payer).is_err());
    }

    #[test]
    fn a_sandbox_binds_each_non_empty_name_and_an_unknown_one_runs_no_agent() {
        let a = authority(|_| {});
        a.bind_sandbox(&["sb-1", "", "id-1"], &agent());
        assert_eq!(a.agent_of_sandbox("sb-1"), Some(agent()));
        assert_eq!(a.agent_of_sandbox("id-1"), Some(agent()));
        assert_eq!(a.agent_of_sandbox(""), None);
        assert_eq!(a.agent_of_sandbox("sb-2"), None);
        assert_eq!(a.controller_of("subject"), None);
        a.bind_principal("subject", ROOT);
        assert_eq!(a.controller_of("subject").as_deref(), Some(ROOT));
    }

    #[tokio::test]
    async fn the_settlement_rail_carries_tnzo_and_reports_unknown_payments() {
        use tenzro_payments::gateway::SettlementRail;
        let a = authority(|_| {});
        assert!(SettlementRail::carries(&*a, "tnzo"));
        assert!(!SettlementRail::carries(&*a, "USDC"));
        assert!(matches!(
            SettlementRail::status(&*a, "never-settled").await.unwrap(),
            RailOutcome::Failed { .. }
        ));
    }
}
