//! Who may use a model, decided once, whichever protocol the request came in on.
//!
//! A node's models are reachable over JSON-RPC, the OpenAI-shaped HTTP routes,
//! MCP (over HTTP and over iroh), A2A and the iroh inference overlay. Each of
//! those used to decide for itself whether a caller could use a gated model, and
//! a transport that did not ask served the model to anyone: MCP's chat tool,
//! every overlay method other than chat, and any JSON-RPC method missing from a
//! hand-kept list. Visibility is a property of the model, so it is enforced
//! here, in the runtimes every transport has to go through to run one.
//!
//! A transport names its caller by running the request inside [`as_caller`].
//! A runtime calls [`check`] before it runs a model. Work that no transport
//! named is treated as an anonymous remote caller, so a transport that forgets
//! to name its callers refuses gated models instead of serving them.

use std::future::Future;
use std::sync::{Arc, OnceLock};

use crate::error::{ModelError, Result};

/// Who is asking for a model to run.
#[derive(Clone, Debug)]
pub enum Caller {
    /// The node working on its own behalf, choosing the model itself: agent
    /// memory, prompt-difficulty routing.
    Node,
    /// A request from outside this process, with the DID its access token
    /// proved, if it presented one.
    Remote { did: Option<String> },
}

impl Caller {
    /// A remote caller that presented nothing.
    pub fn anonymous() -> Self {
        Caller::Remote { did: None }
    }
}

/// The decision itself, supplied by whatever hosts the runtimes.
pub trait AccessPolicy: Send + Sync {
    /// `Err` carries the refusal the caller sees.
    fn check(&self, caller: &Caller, model_id: &str) -> std::result::Result<(), String>;
}

tokio::task_local! {
    static CALLER: Caller;
}

static POLICY: OnceLock<Arc<dyn AccessPolicy>> = OnceLock::new();

/// Install the policy every runtime consults. Only the first call takes effect.
///
/// A process that installs none, such as the CLI running a model in-process,
/// has no notion of visibility and runs whatever it loaded.
pub fn install(policy: Arc<dyn AccessPolicy>) -> bool {
    POLICY.set(policy).is_ok()
}

/// Run `f` on behalf of `caller`.
pub async fn as_caller<F: Future>(caller: Caller, f: F) -> F::Output {
    CALLER.scope(caller, f).await
}

/// Run `f` as the node itself.
pub async fn as_node<F: Future>(f: F) -> F::Output {
    as_caller(Caller::Node, f).await
}

/// The caller the current task is running for, if a transport named one.
pub fn current() -> Option<Caller> {
    CALLER.try_with(Clone::clone).ok()
}

/// Carry the current caller into work handed to another task.
///
/// A task-local does not cross `tokio::spawn`. Without this, a request that
/// generates on a spawned task would arrive at the runtime as anonymous.
pub fn inherit<F: Future>(f: F) -> impl Future<Output = F::Output> {
    CALLER.scope(current().unwrap_or_else(Caller::anonymous), f)
}

/// Refuse unless the current caller may use `model_id`.
pub fn check(model_id: &str) -> Result<()> {
    match POLICY.get() {
        Some(policy) => decide(policy.as_ref(), current(), model_id),
        None => Ok(()),
    }
}

fn decide(policy: &dyn AccessPolicy, caller: Option<Caller>, model_id: &str) -> Result<()> {
    let caller = caller.unwrap_or_else(Caller::anonymous);
    policy
        .check(&caller, model_id)
        .map_err(ModelError::AccessDenied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Admits the node and `did:good`, and nobody else.
    struct KeyOnly;

    impl AccessPolicy for KeyOnly {
        fn check(&self, caller: &Caller, model_id: &str) -> std::result::Result<(), String> {
            match caller {
                Caller::Node => Ok(()),
                Caller::Remote { did: Some(d) } if d == "did:good" => Ok(()),
                Caller::Remote { .. } => Err(format!("model {model_id} is gated")),
            }
        }
    }

    fn keyed(key: &str) -> Caller {
        Caller::Remote {
            did: Some(format!("did:{key}")),
        }
    }

    #[test]
    fn an_unnamed_caller_is_anonymous_and_refused() {
        let err = decide(&KeyOnly, None, "m").unwrap_err();
        assert!(matches!(err, ModelError::AccessDenied(ref m) if m.contains("gated")));
    }

    #[test]
    fn the_policy_sees_the_identity_presented() {
        assert!(decide(&KeyOnly, Some(keyed("good")), "m").is_ok());
        assert!(decide(&KeyOnly, Some(keyed("bad")), "m").is_err());
        assert!(decide(&KeyOnly, Some(Caller::Node), "m").is_ok());
    }

    #[tokio::test]
    async fn a_scope_names_the_caller_and_ends_with_the_future() {
        assert!(current().is_none());
        let inside = as_caller(keyed("good"), async { current() }).await;
        assert!(matches!(inside, Some(Caller::Remote { did: Some(ref k) }) if k == "did:good"));
        assert!(current().is_none());
    }

    #[tokio::test]
    async fn spawned_work_loses_the_caller_unless_it_inherits() {
        let (lost, kept) = as_caller(keyed("good"), async {
            let lost = tokio::spawn(async { current() }).await.unwrap();
            let kept = tokio::spawn(inherit(async { current() })).await.unwrap();
            (lost, kept)
        })
        .await;
        assert!(lost.is_none());
        assert!(matches!(kept, Some(Caller::Remote { did: Some(ref k) }) if k == "did:good"));
    }

    #[tokio::test]
    async fn inheriting_outside_any_scope_is_anonymous() {
        let got = tokio::spawn(inherit(async { current() })).await.unwrap();
        assert!(matches!(got, Some(Caller::Remote { did: None })));
    }
}
