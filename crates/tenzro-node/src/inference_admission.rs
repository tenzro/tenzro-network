//! Inference admission: whether a caller may run a model, and on what terms.
//!
//! The HTTP-402 payment gate in `tenzro-payments` only understands payment
//! credentials. This module supplies what the gate lacks — the node's access
//! policy and each model's visibility — via the [`InferenceAdmission`] trait,
//! so inference requests are classified before the gate decides whether to
//! charge. Every transport (HTTP, JSON-RPC, the iroh overlay) and every model
//! runtime asks the same function.
//!
//! Decision order:
//! 1. The access policy for the inference class on the caller's surface. A
//!    refusal refuses, a `paid` rule asks for payment.
//! 2. A caller the policy admitted *by name* (an allow list, a credential,
//!    Terms, a sign-in tier) is pre-authorized: served without per-use
//!    payment, and the only kind of caller a `Gated` model serves.
//! 3. Anyone else is decided by the model's effective visibility: `Public` →
//!    pay the operator's per-use price (free at `0`); `Gated` → refuse;
//!    `Private` → this node's own callers only.

use std::sync::Arc;

use axum::http::HeaderMap;
use axum::response::IntoResponse;
use tenzro_payments::middleware::{InferenceAccess, InferenceAdmission};
use tenzro_types::Visibility;

use crate::TenzroNode;

/// Node-backed [`InferenceAdmission`]: classifies inference requests using
/// the node's access policy and served-model visibility.
pub struct NodeInferenceAdmission {
    /// The node whose credentials and served models drive the decision.
    pub node: Arc<TenzroNode>,
    /// The operator's per-use price for a `Public` model. `0` serves it free.
    /// Read identically by every transport, so HTTP, JSON-RPC and the iroh
    /// overlay cannot disagree about who may use this node.
    pub price: u128,
}

tokio::task_local! {
    /// Set while a request that arrived over the iroh overlay is handled.
    static FROM_OVERLAY: ();
}

/// Run `f` as the handling of a request that arrived over the iroh overlay.
///
/// A peer on the overlay is by definition off this machine, however the
/// node's RPC listener is bound. Inside this scope the loopback exemption for
/// unpublished and private models does not apply, both to the transport's own
/// admission check and to the runtime check the model makes before it runs.
pub async fn from_overlay<F: std::future::Future>(f: F) -> F::Output {
    FROM_OVERLAY.scope((), f).await
}

fn arrived_over_overlay() -> bool {
    FROM_OVERLAY.try_with(|_| ()).is_ok()
}

impl NodeInferenceAdmission {
    /// The one way to build this.
    ///
    /// Five call sites used to fill these fields by hand — two in the overlay
    /// dispatcher, one in the JSON-RPC gate, two at startup — each reading
    /// config separately. Nothing forced them to agree, and a field added for
    /// one transport is a field the others silently default. A caller now meets
    /// the same policy whichever port they arrived on, because there is one
    /// place that decides what the policy is.
    pub fn for_node(node: &Arc<TenzroNode>) -> Self {
        Self {
            node: node.clone(),
            price: crate::visibility_rpc::operator_price(node),
        }
    }
}

impl NodeInferenceAdmission {
    /// Whether this node's RPC listener can only be reached from this machine.
    ///
    /// Read from the bind address rather than from the request, because a bind address is a fact
    /// about the socket and a request header is a claim by whoever sent it. `127.0.0.0/8` and `::1`
    /// are not routable off-host, so anything arriving on such a listener is on-node.
    ///
    /// # A loopback bind is not always the whole story
    ///
    /// The kernel will not route off-host traffic to `127.0.0.0/8`. A process
    /// on the same machine will, and that is a thing operators deploy on
    /// purpose: a `systemd-socket-proxyd` accepting on a routable address and
    /// forwarding to the loopback port is a standard way to expose a service
    /// that binds locally. The node then reads its own bind address, concludes
    /// every caller is on-node, and hands `Private` models -- the ones defined
    /// as never leaving this machine, and the default for everything loaded
    /// through the `load_*` RPCs -- to anyone who can reach the proxy.
    ///
    /// Reading the connection's peer address instead does not help, because the
    /// proxy is the peer: it rewrites every caller to `127.0.0.1`. The socket
    /// simply stops being evidence once something is relaying onto it.
    ///
    /// What remains is the operator's own declaration. `external_rpc_addr` is
    /// the address this node advertises for its RPC surface, gossiped so peers
    /// elsewhere can dial in. Setting it says, in the operator's own words,
    /// that this RPC port is reachable from off-host. Whether the reachability
    /// arrives via a wildcard bind or a proxy in front of a loopback one is an
    /// implementation detail; the claim is the same either way, and it
    /// contradicts the inference this function exists to make.
    fn listener_is_loopback(&self) -> bool {
        // The bind address says nothing about a request that did not come in
        // through the listener at all.
        if arrived_over_overlay() {
            return false;
        }
        /*
         * `rpc_addr` is a String, not a SocketAddr, so this has to parse -- and the parse can
         * fail. It fails CLOSED: an address we cannot read is not an address we can prove is
         * loopback, and the cost of the two mistakes is not symmetric. Guessing "loopback" on an
         * unparseable bind address would expose private models to the network; guessing
         * "not loopback" only declines a local call that the operator can still make explicit.
         *
         * A bare `:8545` or `0.0.0.0:8545` is NOT loopback -- those are wildcard binds reachable
         * from off-host, which is exactly the case this guard exists to catch.
         */
        let bound_locally = self
            .node
            .config()
            .rpc_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);

        // Published by the operator through their own edge: a loopback
        // connection may be that edge relaying a remote caller.
        bound_locally && !self.advertises_routable_rpc()
    }

    /// Whether the operator published this node's RPC surface through their
    /// own edge. Startup refuses any published URL that is not a public https
    /// URL, so a published one always means "reachable from elsewhere": a
    /// loopback connection may then be the operator's proxy relaying a remote
    /// caller.
    fn advertises_routable_rpc(&self) -> bool {
        crate::exposure::rpc_url(self.node.config()).is_some()
    }

    /// The transport decision for `caller_did` (the DID a valid access
    /// token proved, if any) asking for `model_id` on `surface`.
    pub fn decide_as(
        &self,
        surface: tenzro_types::node_access::Surface,
        caller_did: Option<&str>,
        model_id: Option<&str>,
    ) -> InferenceAccess {
        self.decide_for(surface, caller_did, model_id, Asking::Transport)
    }

    fn decide_for(
        &self,
        surface: tenzro_types::node_access::Surface,
        caller_did: Option<&str>,
        model_id: Option<&str>,
        asking: Asking,
    ) -> InferenceAccess {
        use crate::access::Decision;
        let policy = self.node.access().policy();
        let caller = crate::access::Caller {
            did: caller_did.map(str::to_string),
            ip: None,
        };
        let named = match crate::access::evaluate(
            &self.node,
            &policy,
            &caller,
            surface,
            tenzro_types::node_access::MethodClass::Inference,
        ) {
            Decision::Refuse(why) => return InferenceAccess::Refuse(403, why),
            Decision::Pay { .. } => return InferenceAccess::NeedPayment,
            Decision::Allow { tier, named } => {
                // Counted once, by the transport. The runtime's check of the
                // same request must not spend a second request of the budget.
                if let (Some(tier), Asking::Transport) = (tier, asking)
                    && let Err(m) = self.node.access().charge_tier(
                        &policy,
                        &tier,
                        caller_did.unwrap_or_default(),
                    )
                {
                    return InferenceAccess::Refuse(429, m);
                }
                named
            }
        };

        let Some(model) = model_id else {
            return InferenceAccess::Refuse(400, "missing model".into());
        };
        // A caller the policy admitted by name is pre-authorized, and is who a
        // gated model serves. A private model still never leaves this machine.
        if named && !matches!(self.node.model_visibility(model), Some(Visibility::Private)) {
            return InferenceAccess::Allow;
        }

        // Anyone else: decide by model visibility.
        // A model under a non-commercial licence is never sold, so no path
        // below asks for payment for one.
        let non_commercial = crate::catalog_sync::non_commercial(&self.node, model);
        match self.node.model_visibility(model) {
            // Public: anyone may use it by paying the operator's price.
            Some(Visibility::Public) => public_access(self.price, non_commercial),
            // Gated: callers the access policy admits by name only. There is
            // no pay-per-use path.
            Some(Visibility::Gated) => InferenceAccess::Refuse(
                402,
                format!("model {model} is gated; sign in as a caller this node admits"),
            ),
            /*
             * Private → never servable OFF-node. On-node is the case this used to refuse too.
             *
             * `private` means the model is never announced and never leaves this machine. It was
             * being read as "never served to anyone", so a node serving a model privately could
             * not use its own model: `tenzro_chat` on 127.0.0.1 came back
             * "not offered off-node", and the CLI then fell back to loading a SECOND copy of the
             * weights in its own process — which on a 16 GB card OOMs against the copy the node
             * already has resident.
             *
             * A request that arrived on a loopback-bound listener cannot have come from off-node:
             * the kernel will not route off-host traffic to 127.0.0.0/8. That is a property of the
             * socket, not a claim by the caller, so it cannot be spoofed by a header. When the
             * listener is bound to a routable address this stays exactly as strict as before,
             * because then a caller's origin genuinely is unknown here.
             */
            Some(Visibility::Private) if self.listener_is_loopback() => InferenceAccess::Allow,
            Some(Visibility::Private) => {
                InferenceAccess::Refuse(403, format!("model {model} is not offered off-node"))
            }
            // Not served HERE — but this node may know who does serve it, and
            // `handle_chat_simple` / `handle_chat_rich` carry the leg that
            // forwards to them (iroh `tenzro/infer` first, HTTP as fallback).
            // The provider's own admission still applies at the far end; this
            // gate decides who pays this node for the forward.
            //
            // The runtime only asks about a model it holds. Holding one that was
            // never given a visibility means nobody published it, so it is
            // treated as private rather than as someone else's to forward.
            None if asking == Asking::Runtime => {
                if self.listener_is_loopback() {
                    InferenceAccess::Allow
                } else {
                    InferenceAccess::Refuse(403, format!("model {model} is not offered off-node"))
                }
            }
            // Forwarded at the operator's expense.
            None if self.known_on_network(model) => {
                forwarded_access(self.node.visibility(), model, non_commercial)
            }
            None => InferenceAccess::Refuse(404, format!("model {model} not served here")),
        }
    }
}

impl NodeInferenceAdmission {
    /// Is some peer announcing this model right now?
    ///
    /// Both sources are already freshness-bounded — gossiped registrations
    /// expire on their own TTL, and a service endpoint carries a last-seen —
    /// so a provider that stopped serving stops being an answer here without
    /// anything having to prune it.
    fn known_on_network(&self, model: &str) -> bool {
        self.node
            .network_models_snapshot()
            .iter()
            .any(|nm| nm.registration.model_id == model)
            || self
                .node
                .list_model_services()
                .iter()
                .any(|svc| svc.model_id == model)
    }
}

/// Which check is being made.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asking {
    /// A transport admitting a request: counts it against the key's rate limit,
    /// and lets through a model this node does not serve so it can be forwarded.
    Transport,
    /// A runtime about to run a model it holds.
    Runtime,
}

/// The check every model runtime makes before running a model.
///
/// Installed once at startup (see `tenzro_model::access`). It is the same
/// decision the transports make, so a gated model needs the same key whichever
/// protocol asked for it, and a transport that never asks cannot serve it.
///
/// Payment is left to the transports: only HTTP can run the x402 round trip,
/// and the others already refuse a model that needs one.
pub struct RuntimeAccess {
    node: std::sync::Weak<TenzroNode>,
}

impl RuntimeAccess {
    pub fn for_node(node: &Arc<TenzroNode>) -> Self {
        Self {
            node: Arc::downgrade(node),
        }
    }
}

impl tenzro_model::access::AccessPolicy for RuntimeAccess {
    fn check(
        &self,
        caller: &tenzro_model::access::Caller,
        model_id: &str,
    ) -> std::result::Result<(), String> {
        let did = match caller {
            tenzro_model::access::Caller::Node => return Ok(()),
            tenzro_model::access::Caller::Remote { did } => did.as_deref(),
        };
        let Some(node) = self.node.upgrade() else {
            return Err("node is shutting down".to_string());
        };
        match NodeInferenceAdmission::for_node(&node).decide_for(
            tenzro_types::node_access::Surface::Rpc,
            did,
            Some(model_id),
            Asking::Runtime,
        ) {
            InferenceAccess::Allow | InferenceAccess::NeedPayment => Ok(()),
            InferenceAccess::Refuse(_, msg) => Err(msg),
        }
    }
}

/// Names the caller of every request on an HTTP listener: the DID its access
/// token proves, checked against its DPoP proof for this exact request. A
/// request presenting an invalid token is refused here; one presenting none
/// runs as an anonymous caller.
pub async fn identify_caller(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let auth = auth_context(&node, &req);
    let claims = match crate::access::proved_token(&node, &auth) {
        Ok(c) => c,
        Err(e) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(
                    serde_json::json!({ "error": { "code": e.code, "message": e.message } }),
                ),
            )
                .into_response();
        }
    };
    match (claims, auth.dpop) {
        (Some(claims), Some(dpop)) => {
            let did = claims.sub.clone();
            req.extensions_mut().insert(crate::rpc::ProvedToken {
                dpop: dpop.clone(),
                claims: claims.clone(),
            });
            crate::rpc::with_proved_token(
                dpop,
                claims,
                tenzro_model::access::as_caller(
                    tenzro_model::access::Caller::Remote { did: Some(did) },
                    next.run(req),
                ),
            )
            .await
        }
        _ => {
            tenzro_model::access::as_caller(
                tenzro_model::access::Caller::anonymous(),
                next.run(req),
            )
            .await
        }
    }
}

/// The auth context of an HTTP request, with the URL its DPoP proof covers.
/// Read in a plain function so no borrow of the request lives across the
/// middleware's await, which would make its future not `Send`.
pub(crate) fn auth_context(
    node: &TenzroNode,
    req: &axum::extract::Request,
) -> crate::rpc::AuthContext {
    let headers = req.headers();
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| node.config().rpc_addr.to_string());
    let uri = format!("{scheme}://{host}{}", req.uri().path());
    crate::rpc::AuthContext::from_headers(headers, req.method().as_str(), &uri)
}

impl InferenceAdmission for NodeInferenceAdmission {
    /// The HTTP decision. The caller was named by [`identify_caller`], which
    /// wraps every inference route, from the request's access token.
    fn decide(&self, _headers: &HeaderMap, model_id: Option<&str>) -> InferenceAccess {
        let did = match tenzro_model::access::current() {
            Some(tenzro_model::access::Caller::Remote { did }) => did,
            _ => None,
        };
        self.decide_as(
            tenzro_types::node_access::Surface::Openai,
            did.as_deref(),
            model_id,
        )
    }
}

/// A keyless call for a `Public` model this node serves: pay the operator's
/// per-use price, or nothing when the price is `0`. A model under a
/// non-commercial licence is never sold, so it is always free.
fn public_access(price: u128, non_commercial: bool) -> InferenceAccess {
    if price == 0 || non_commercial {
        InferenceAccess::Allow
    } else {
        InferenceAccess::NeedPayment
    }
}

/// A keyless call for a model another provider serves, which this node would
/// forward and pay for out of the operator's own payee. A public node lets the
/// caller pay here before anything is forwarded, whatever this node's own
/// price, because the forward spends the operator's money at another provider.
/// A non-commercial model is priced at zero by every provider, so forwarding
/// one costs nothing and is not charged for. A gated or private node forwards
/// only for key holders.
fn forwarded_access(node: Visibility, model: &str, non_commercial: bool) -> InferenceAccess {
    if node.is_payable() {
        if non_commercial {
            InferenceAccess::Allow
        } else {
            InferenceAccess::NeedPayment
        }
    } else {
        InferenceAccess::Refuse(
            402,
            format!(
                "model {model} is served by another provider through this node; \
                 this node forwards only for callers holding a key"
            ),
        )
    }
}

#[cfg(test)]
mod keyless_access_tests {
    use super::{Visibility, forwarded_access, public_access};
    use tenzro_payments::middleware::InferenceAccess;

    #[test]
    fn a_public_model_is_free_at_price_zero_and_paid_otherwise() {
        assert!(matches!(public_access(0, false), InferenceAccess::Allow));
        assert!(matches!(
            public_access(1, false),
            InferenceAccess::NeedPayment
        ));
    }

    /// A non-commercial model is never charged for, whatever the price, and
    /// a gated or private node still forwards it only for key holders.
    #[test]
    fn a_non_commercial_model_is_never_charged() {
        assert!(matches!(public_access(1, true), InferenceAccess::Allow));
        assert!(matches!(
            forwarded_access(Visibility::Public, "m", true),
            InferenceAccess::Allow
        ));
        for v in [Visibility::Gated, Visibility::Private] {
            assert!(matches!(
                forwarded_access(v, "m", true),
                InferenceAccess::Refuse(402, _)
            ));
        }
    }

    /// A forward spends the operator's money at another provider, so no
    /// setting lets a keyless caller through without paying.
    #[test]
    fn a_keyless_forward_is_never_free() {
        assert!(matches!(
            forwarded_access(Visibility::Public, "m", false),
            InferenceAccess::NeedPayment
        ));
        for v in [Visibility::Gated, Visibility::Private] {
            assert!(matches!(
                forwarded_access(v, "m", false),
                InferenceAccess::Refuse(402, _)
            ));
        }
    }
}
