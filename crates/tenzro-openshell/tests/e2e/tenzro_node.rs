//! A Tenzro developer chain for the end-to-end test, and the roots that
//! delegate agents on it.
//!
//! `TENZRO_NODE_LAUNCH` names the program that runs the chain:
//! `tenzro-node --dev`, a single-validator chain keyed by a TPM of its own
//! (for example `devnode-swtpm.sh`, on a software TPM, so it never shares a
//! TPM with a node in service). Its roots are machine roots keyed in that
//! TPM: each bonds and delegates an agent under Terms, and revokes itself,
//! with transactions and approvals its hardware key signs, through the
//! node's RPC. The program answers
//!
//! - `start`: `url <rpc url>`, `log <where>`, `root <namespace> <account>`;
//! - `admit`: register the node's machine identity on chain, once it
//!   answers;
//! - `delegate <namespace> <name>` (Terms on stdin): `agent <did>`,
//!   `controller <did>`;
//! - `revoke-root <namespace> <reason>`;
//! - `stop`.

use std::io::Write as _;
use std::time::Duration;

use serde_json::{Value, json};

/// A running developer-chain node.
pub struct DevNode {
    /// Its JSON-RPC endpoint.
    pub url: String,
    /// Its machine DID: the serving node agents' Terms name.
    pub machine_did: String,
    /// Where its log is.
    pub log: String,
    launch: String,
    client: reqwest::Client,
}

fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .map(str::trim)
}

impl DevNode {
    async fn run(launch: &str, args: &[&str], stdin: Option<&str>) -> String {
        let mut child = std::process::Command::new(launch)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "{launch} {args:?}: {text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        text
    }

    /// Start the chain and wait until it produces blocks.
    pub async fn start() -> Self {
        let launch = std::env::var("TENZRO_NODE_LAUNCH")
            .expect("TENZRO_NODE_LAUNCH is required: run tests/e2e/run-docker.sh");
        let text = Self::run(&launch, &["start"], None).await;
        let mut node = Self {
            url: field(&text, "url ").expect("an RPC url").to_string(),
            machine_did: String::new(),
            log: field(&text, "log ").unwrap_or_default().to_string(),
            launch,
            client: reqwest::Client::new(),
        };
        let mut first = None;
        for _ in 0..180 {
            if let Ok(h) = node.call("eth_blockNumber", json!([])).await {
                let h = Self::quantity(&h);
                match first {
                    None => first = Some(h),
                    Some(f) if h > f => break,
                    Some(_) => {}
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(
            first.is_some(),
            "tenzro-node never answered; see {}",
            node.log
        );
        let status = node.call("tenzro_getNodeStatus", json!({})).await.unwrap();
        node.machine_did = status["machine_did"]
            .as_str()
            .expect("the node's machine DID")
            .to_string();
        Self::run(&node.launch, &["admit"], None).await;
        node
    }

    /// One JSON-RPC call.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let reply: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| format!("{method}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("{method}: {e}"))?;
        if let Some(e) = reply.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: {e}"));
        }
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    }

    fn quantity(v: &Value) -> u64 {
        match v {
            Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0),
            Value::Number(n) => n.as_u64().unwrap_or(0),
            _ => 0,
        }
    }

    /// The chain's clock, ms.
    pub async fn chain_ms(&self) -> u64 {
        let b = self
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await
            .unwrap();
        Self::quantity(&b["timestamp"]) * 1000
    }

    /// The root `namespace` bonds and delegates the agent `name` under
    /// `scope`, served by this node, for a week; returns the agent's DID and
    /// its root's once the Terms are on chain.
    pub async fn delegate(&self, namespace: &str, name: &str, scope: Value) -> (String, String) {
        let terms = json!({
            "agent_name": name, "delegation_scope": scope, "capabilities": [],
            "min_distinct_operators": 1, "expires_at_ms": self.chain_ms().await + 7 * 86_400_000
        });
        let text = Self::run(
            &self.launch,
            &["delegate", namespace, name],
            Some(&terms.to_string()),
        )
        .await;
        let agent = field(&text, "agent ").expect("the agent's DID").to_string();
        let root = field(&text, "controller ")
            .expect("the root's DID")
            .to_string();
        self.agent_status(&agent, "active").await;
        (agent, root)
    }

    /// The root `namespace` revokes itself on chain; returns once the
    /// revocation is in a block.
    pub async fn revoke_root(&self, namespace: &str, reason: &str) {
        Self::run(&self.launch, &["revoke-root", namespace, reason], None).await;
    }

    /// Wait until `tenzro_getAgentTerms` reports `status` for `agent`.
    pub async fn agent_status(&self, agent: &str, status: &str) {
        let mut last = Value::Null;
        for _ in 0..120 {
            last = self
                .call("tenzro_getAgentTerms", json!({"agent_did": agent}))
                .await
                .unwrap_or(Value::Null);
            if last["status"] == status {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!(
            "{agent} never reached {status}: {last}; node log {}",
            self.log
        );
    }

    /// Stop the chain.
    pub async fn stop(self) {
        Self::run(&self.launch, &["stop"], None).await;
    }
}
