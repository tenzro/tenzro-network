//! Agents' delegations read from a running Tenzro node.
//!
//! [`NodeDelegations`] asks the node's JSON-RPC `tenzro_getAgentTerms` on
//! every decision: the Terms chain state records for the agent, the root
//! kind that approved them, its status (active, quarantined, expired, or
//! revoked, directly, by the kill switch or through the root that delegated
//! it) and what it has spent today and this hour. Nothing is cached, so a
//! revocation that reaches the chain stops the agent's next action, and a
//! node that cannot be reached refuses every action rather than allowing it.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tenzro_types::agent_terms::AgentTerms;

use crate::authority::{Delegation, Delegations, Spent, Standing};

/// How long one read may take before the action is refused.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A running node's identity, as `tenzro_getNodeStatus` reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeStatus {
    /// The node's machine DID: the serving node agents' Terms name.
    pub machine_did: String,
    /// The operator the node runs for.
    #[serde(default)]
    pub operator_did: Option<String>,
}

/// Delegations read from the node at `url` over JSON-RPC.
pub struct NodeDelegations {
    url: String,
    client: reqwest::Client,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for NodeDelegations {
    fn drop(&mut self) {
        // Dropped from inside an async runtime, a runtime may not block on
        // its worker; let it wind down on its own.
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

#[derive(Deserialize)]
struct SpentJson {
    today: String,
    this_hour: String,
    actions_today: u32,
    actions_this_hour: u32,
}

#[derive(Deserialize)]
struct TermsJson {
    status: String,
    terms: AgentTerms,
    spent: SpentJson,
}

fn amount(v: &str, what: &str) -> Result<u128, String> {
    v.parse()
        .map_err(|_| format!("the node reported {what} {v:?}, not an amount"))
}

impl NodeDelegations {
    /// Delegations from the node whose JSON-RPC endpoint is `url`.
    pub fn new(url: impl Into<String>) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(READ_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("tenzro-node-rpc")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            url: url.into(),
            client,
            runtime: Some(runtime),
        })
    }

    async fn call_async(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let reply: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("{method}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("{method}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("{method}: {e}"))?;
        if let Some(err) = reply.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: {err}"));
        }
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Call `method` and wait for its result. The extensions' checks are
    /// synchronous and may run inside an async runtime, so the call runs on
    /// this reader's own runtime from a thread of its own.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        std::thread::scope(|s| {
            s.spawn(|| match &self.runtime {
                Some(rt) => rt.block_on(self.call_async(method, params)),
                None => Err(format!("{method}: the reader is shut down")),
            })
            .join()
            .unwrap_or_else(|_| Err(format!("{method}: the RPC thread panicked")))
        })
    }

    /// The node's identity.
    pub fn status(&self) -> Result<NodeStatus, String> {
        serde_json::from_value(self.call("tenzro_getNodeStatus", json!({}))?)
            .map_err(|e| format!("tenzro_getNodeStatus: {e}"))
    }

    /// Parse a `tenzro_getAgentTerms` result.
    pub fn parse(result: Value) -> Result<Option<Delegation>, String> {
        if result.is_null() {
            return Ok(None);
        }
        let t: TermsJson =
            serde_json::from_value(result).map_err(|e| format!("tenzro_getAgentTerms: {e}"))?;
        let standing = match t.status.as_str() {
            "active" => Standing::Active,
            "revoked" => Standing::Revoked,
            "quarantined" => Standing::Quarantined,
            "expired" => Standing::Expired,
            other => return Err(format!("the node reported status {other:?}")),
        };
        Ok(Some(Delegation {
            terms: t.terms,
            standing,
            spent: Spent {
                today: amount(&t.spent.today, "spent today")?,
                this_hour: amount(&t.spent.this_hour, "spent this hour")?,
                actions_today: t.spent.actions_today,
                actions_this_hour: t.spent.actions_this_hour,
            },
        }))
    }
}

impl Delegations for NodeDelegations {
    fn delegation(&self, agent_did: &str, _now_ms: u64) -> Result<Option<Delegation>, String> {
        Self::parse(self.call("tenzro_getAgentTerms", json!({"agent_did": agent_did}))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::authority::{Authority, Proposed, StateAuthority};

    const AGENT: &str = "did:tenzro:machine:a:b";

    fn reply(status: &str, spent_today: &str) -> Value {
        let mut terms = crate::credential_driver::tests::terms(&["fetch"]);
        terms.delegation_scope.max_daily_spend = Some("1000".into());
        json!({
            "agent_did": AGENT, "root_kind": "passkey", "status": status, "version": 1,
            "terms": terms,
            "spent": {"today": spent_today, "this_hour": "0", "actions_today": 1, "actions_this_hour": 0,
                      "remaining_today": null, "remaining_this_hour": null, "assets": []}
        })
    }

    /// A node answering `tenzro_getAgentTerms` from `answer`, counting calls.
    async fn node(answer: Arc<parking_lot::Mutex<Value>>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(b): axum::Json<Value>| {
                let answer = answer.clone();
                async move {
                    assert_eq!(b["method"], "tenzro_getAgentTerms");
                    assert_eq!(b["params"]["agent_did"], AGENT);
                    axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": *answer.lock()}))
                }
            }),
        );
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://127.0.0.1:{port}/")
    }

    fn fetch(amount: u128) -> Proposed {
        Proposed {
            operation: "fetch".into(),
            amount,
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_decision_reads_the_nodes_current_answer() {
        let answer = Arc::new(parking_lot::Mutex::new(reply("active", "0")));
        let url = node(answer.clone()).await;
        let d = Arc::new(NodeDelegations::new(url).unwrap());
        let a = StateAuthority::over(crate::credential_driver::tests::MACHINE, vec![], 1337, d);
        let now = crate::now_ms();
        assert!(a.authorize(AGENT, &fetch(0), now).is_ok());
        assert_eq!(
            a.terms(AGENT).unwrap().controller_did,
            crate::credential_driver::tests::ROOT
        );
        *answer.lock() = reply("revoked", "0");
        assert_eq!(
            a.authorize(AGENT, &fetch(0), now).unwrap_err().0,
            "agent revoked"
        );
        assert_eq!(a.revoked(AGENT, now).as_deref(), Some("agent revoked"));
        *answer.lock() = reply("quarantined", "0");
        assert!(a.check(AGENT, &fetch(0), now).is_err());
        *answer.lock() = Value::Null;
        assert!(a.terms(AGENT).is_none());
        assert_eq!(
            a.check(AGENT, &fetch(0), now).unwrap_err().0,
            "the agent has no Terms"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn what_the_chain_counts_spent_counts_against_the_limits() {
        let answer = Arc::new(parking_lot::Mutex::new(reply("active", "990")));
        let url = node(answer).await;
        let d = Arc::new(NodeDelegations::new(url).unwrap());
        let a = StateAuthority::over(crate::credential_driver::tests::MACHINE, vec![], 1337, d);
        let now = crate::now_ms();
        assert!(a.check(AGENT, &fetch(5), now).is_ok());
        assert!(
            a.check(AGENT, &fetch(20), now).is_err(),
            "990 spent + 20 is over the daily 1000"
        );
    }

    #[test]
    fn an_unreachable_node_refuses_everything() {
        let d = Arc::new(NodeDelegations::new("http://127.0.0.1:9/").unwrap());
        let a = StateAuthority::over(crate::credential_driver::tests::MACHINE, vec![], 1337, d);
        let now = crate::now_ms();
        let r = a.check(AGENT, &fetch(0), now).unwrap_err();
        assert!(r.0.contains("could not be read"), "{r}");
        assert!(a.revoked(AGENT, now).is_some());
    }

    #[test]
    fn an_unknown_status_is_an_error_not_a_pass() {
        assert!(NodeDelegations::parse(reply("pending", "0")).is_err());
        assert!(NodeDelegations::parse(reply("active", "x")).is_err());
    }
}
