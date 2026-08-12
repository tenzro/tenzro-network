//! Credential-aware inference admission for the Web API `/chat` payment gate.
//!
//! The HTTP-402 payment gate in `tenzro-payments` only understands payment
//! credentials. This module supplies the node-side knowledge the gate lacks —
//! subscription api-keys, rental service-keys, and per-model visibility — via
//! the [`InferenceAdmission`] trait, so `/chat` requests are classified before
//! the gate decides whether to charge.
//!
//! Decision order:
//! 1. A valid subscription api-key (`X-Tenzro-Api-Key`, scope Inference) →
//!    [`InferenceAccess::Allow`] (pre-paid), subject to model attenuation and
//!    rate limit.
//! 2. A rental service-key (`x-tenzro-service-key`) admitted on the WebApi
//!    surface → [`InferenceAccess::Allow`] (pre-authorized).
//! 3. Otherwise decide by the model's visibility: `Network` (open) → x402
//!    on-demand payment; `Gated` → refuse without a challenge unless the
//!    operator enabled the on-demand fallback; `Private`/unknown → refuse.

use std::sync::Arc;

use axum::http::HeaderMap;
use tenzro_payments::middleware::{InferenceAccess, InferenceAdmission};

use crate::TenzroNode;

/// Node-backed [`InferenceAdmission`]: classifies `/chat` requests using the
/// node's api-key manager, admission gate, and served-model visibility.
pub struct NodeInferenceAdmission {
    /// The node whose credentials and served models drive the decision.
    pub node: Arc<TenzroNode>,
    /// Operator opt-in: allow x402 pay-per-call on Gated models lacking a credential.
    pub gated_on_demand_fallback: bool,
}

const API_KEY_HEADER: &str = "x-tenzro-api-key";
const SERVICE_KEY_HEADER: &str = "x-tenzro-service-key";

impl NodeInferenceAdmission {
    /// Core admission decision, independent of transport. Takes the raw
    /// credentials directly so both the HTTP path (headers) and the iroh
    /// `tenzro/infer` path (JSON-RPC frame fields) can share the exact same
    /// gating logic.
    pub fn decide_creds(
        &self,
        api_key: Option<&str>,
        service_key: Option<&str>,
        model_id: Option<&str>,
    ) -> InferenceAccess {
        // 1. Subscription api-key — pre-paid, skip payment.
        if let Some(v) = api_key
            && let Some(mgr) = self.node.api_key_manager()
            && let Some(rec) = mgr.lookup(v)
            && rec.has_scope(crate::api_key::ApiKeyScope::Inference)
        {
            // Model attenuation: a key may be restricted to specific models.
            if let Some(m) = model_id
                && !rec.allows_model(m)
            {
                return InferenceAccess::Refuse(403, format!("api key not authorized for model {m}"));
            }
            if mgr.check_rate_limit(&rec).is_err() {
                return InferenceAccess::Refuse(429, "api key rate limit exceeded".into());
            }
            return InferenceAccess::Allow;
        }

        // 2. Rental service-key — pre-authorized on the WebApi surface. Only
        //    meaningful when the admission gate is enabled.
        if let Some(v) = service_key {
            let gate = self.node.admission_gate();
            if gate.is_enabled()
                && matches!(
                    gate.admit(tenzro_auth::ServiceSurface::WebApi, "/chat", Some(v)),
                    tenzro_auth::Admission::Allow
                )
            {
                return InferenceAccess::Allow;
            }
        }

        // 3. No pre-paid credential — decide by model visibility.
        let Some(model) = model_id else {
            return InferenceAccess::Refuse(400, "missing model".into());
        };
        match self.node.served_models.get(model).map(|v| *v.value()) {
            // Open on-demand → issue an x402 challenge.
            Some(vis) if vis.is_network() => InferenceAccess::NeedPayment,
            // Gated → refuse without a challenge unless the operator opted in.
            Some(vis) if vis.requires_credential() => {
                if self.gated_on_demand_fallback {
                    InferenceAccess::NeedPayment
                } else {
                    InferenceAccess::Refuse(
                        402,
                        format!(
                            "model {model} is gated; provide X-Tenzro-Api-Key or x-tenzro-service-key"
                        ),
                    )
                }
            }
            // Private → never servable off-node.
            Some(_) => InferenceAccess::Refuse(403, format!("model {model} is not offered off-node")),
            // Unknown / not served here.
            None => InferenceAccess::Refuse(404, format!("model {model} not served here")),
        }
    }
}

impl InferenceAdmission for NodeInferenceAdmission {
    fn decide(&self, headers: &HeaderMap, model_id: Option<&str>) -> InferenceAccess {
        // HTTP path: extract credentials from headers and delegate to the
        // transport-independent core. No behavior change from the original.
        let api_key = headers.get(API_KEY_HEADER).and_then(|h| h.to_str().ok());
        let service_key = headers.get(SERVICE_KEY_HEADER).and_then(|h| h.to_str().ok());
        self.decide_creds(api_key, service_key, model_id)
    }
}
