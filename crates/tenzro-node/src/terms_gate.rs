//! The one place a payment's authority is decided: the payer's consensus
//! Terms, read from chain state.
//!
//! Every payment entry point (the gateway behind x402, MPP and the HTTP 402
//! gates, the x402 facilitator, AP2 mandates, ACP checkouts, intent-routed
//! inference) asks
//! [`check_payment`]. A payer with no Terms is not a delegated agent and pays
//! under its own key; a delegated agent pays only inside the scope, limits and
//! counterparties its root granted, and not at all once paused, quarantined
//! or revoked.

use std::sync::Arc;

use tenzro_payments::{PaymentError, PaymentIntent, TermsGate};
use tenzro_storage::KvStore;

use crate::node::TenzroNode;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Hold `intent` to the payer's Terms in `chain`.
fn check_on(chain: &dyn tenzro_vm::VmState, intent: &PaymentIntent<'_>) -> Result<(), String> {
    tenzro_vm::native::check_agent_payment(
        chain,
        &tenzro_vm::native::PaymentProposal {
            payer_did: intent.payer_did,
            operation: intent.operation,
            amount: intent.amount,
            counterparty: intent.counterparty.unwrap_or(""),
            chain: intent.chain.unwrap_or(""),
            protocol: intent.protocol,
            tainted: crate::agent_guardrails::is_tainted(intent.payer_did),
        },
        now_ms(),
    )
}

/// [`TermsGate`] over a node's chain state.
pub struct ChainTermsGate {
    storage: Arc<dyn KvStore>,
}

impl ChainTermsGate {
    /// The gate over `storage`.
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn decide(&self, intent: &PaymentIntent<'_>) -> Result<(), String> {
        check_on(
            &tenzro_vm::StateAdapter::with_storage(self.storage.clone()),
            intent,
        )
    }
}

impl TermsGate for ChainTermsGate {
    fn authorize(&self, intent: &PaymentIntent<'_>) -> tenzro_payments::Result<()> {
        self.decide(intent)
            .map_err(PaymentError::VerificationFailed)
    }
}

/// The intent tier's spend check: an intent-routed call is a payment the
/// payer's Terms must allow.
impl tenzro_model::routing::intent::BudgetGate for ChainTermsGate {
    fn check(&self, payer_did: &str, amount: u128) -> tenzro_model::Result<()> {
        self.decide(&PaymentIntent {
            payer_did,
            amount,
            operation: "inference",
            protocol: None,
            chain: None,
            counterparty: None,
        })
        .map_err(tenzro_model::ModelError::InferenceError)
    }
}

/// Install the Terms check on the node's payment gateway.
pub fn install(node: &Arc<TenzroNode>) {
    // The agent key directory named in signed agent requests derives from
    // the same Terms; it is served under the operator-published origin.
    crate::agent_http_signature::set_directory_origin(crate::exposure::rpc_url(node.config()));
    if let (Some(gateway), Some(storage)) = (node.payment_gateway(), node.storage()) {
        gateway.set_terms_gate(Arc::new(ChainTermsGate::new(
            storage.clone() as Arc<dyn KvStore>
        )));
    }
}

/// The controller and DID keys AP2 mandates are checked against: the
/// controller from the agent's consensus Terms, keys from the identity
/// registry.
pub struct ChainMandateKeys {
    chain: Arc<dyn KvStore>,
    registry: Arc<tenzro_identity::IdentityRegistry>,
}

impl ChainMandateKeys {
    pub fn new(chain: Arc<dyn KvStore>, registry: Arc<tenzro_identity::IdentityRegistry>) -> Self {
        Self { chain, registry }
    }
}

impl tenzro_payments::ap2::MandateKeys for ChainMandateKeys {
    fn controller_of(&self, agent_did: &str) -> Option<String> {
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        tenzro_vm::native::read_agent_terms(&chain, agent_did).map(|t| t.terms.controller_did)
    }

    fn did_lists_key(
        &self,
        did: &str,
        key: &p256::ecdsa::VerifyingKey,
    ) -> tenzro_payments::Result<bool> {
        tenzro_payments::ap2::identity_lists_key(&self.registry, did, key)
    }
}

/// Whether an agent holds consensus Terms, for the identity registry's KYA
/// records and checks.
pub struct ChainTermsLookup {
    chain: Arc<dyn KvStore>,
}

impl ChainTermsLookup {
    pub fn new(chain: Arc<dyn KvStore>) -> Self {
        Self { chain }
    }
}

impl tenzro_identity::AgentTermsLookup for ChainTermsLookup {
    fn has_terms(&self, agent_did: &str) -> bool {
        let chain = tenzro_vm::StateAdapter::with_storage(self.chain.clone());
        tenzro_vm::native::read_agent_terms(&chain, agent_did).is_some()
    }
}
