//! Follows a node from a trust anchor to its newest certified checkpoint and
//! proves one value of the state that checkpoint certifies. Read-only.
//!
//! ```text
//! cargo run -p tenzro-light --example follow -- \
//!     --rpc https://rpc.example --genesis <hex32> --epoch 0 --committee-root <hex32>
//! ```
//!
//! `--chain-id` defaults to 13380 and `--max-age-secs`, the oldest the newest
//! checkpoint may be against this machine's clock, to 600. Without `--state-key` (hex, with
//! `--namespace`, `state` by default) the value proven is the chain id the
//! network wrote into its own state at genesis, which must equal `--chain-id`.

use std::collections::HashMap;

use serde_json::{Value, json};
use tenzro_light::driver::{self, Node};
use tenzro_light::{Clock, LightClient, TrustAnchor, identity, rpc, wire};

/// JSON-RPC over HTTP.
struct Http {
    url: String,
    client: reqwest::Client,
    runtime: tokio::runtime::Runtime,
    next_id: u64,
}

impl Node for Http {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        if method == "tenzro_getEpochHandover" {
            println!("fetching the handover of epoch {}", params["epoch"]);
        }
        let body =
            json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        let reply: Value = self
            .runtime
            .block_on(async {
                self.client
                    .post(&self.url)
                    .json(&body)
                    .send()
                    .await?
                    .json()
                    .await
            })
            .map_err(|e| e.to_string())?;
        if let Some(error) = reply.get("error") {
            return Err(error.to_string());
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| "reply has neither result nor error".to_string())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: HashMap<String, String> = HashMap::new();
    let mut argv = std::env::args().skip(1);
    while let Some(name) = argv.next() {
        let value = argv.next().ok_or(format!("{name} needs a value"))?;
        args.insert(name, value);
    }
    let arg = |name: &str| args.get(name).ok_or(format!("{name} is required"));

    let chain_id: u64 = match args.get("--chain-id") {
        Some(id) => id.parse()?,
        None => 13380,
    };
    let anchor = TrustAnchor {
        chain_id,
        genesis_hash: wire::digest("--genesis", arg("--genesis")?)?,
        epoch: arg("--epoch")?.parse()?,
        committee_root: wire::digest("--committee-root", arg("--committee-root")?)?,
    };
    let mut node = Http {
        url: arg("--rpc")?.clone(),
        client: reqwest::Client::new(),
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
        next_id: 0,
    };

    let committee = node.call("tenzro_getCommittee", json!({ "epoch": anchor.epoch }))?;
    let members = rpc::committee_members(&committee)?;
    println!(
        "epoch {}: the node names {} members",
        anchor.epoch,
        members.len()
    );
    let mut client = LightClient::new(&anchor, members)?;
    println!("the members hash to the anchor's committee root");

    let max_age_secs: u64 = match args.get("--max-age-secs") {
        Some(secs) => secs.parse()?,
        None => 600,
    };
    let clock = Clock {
        now_ms: u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?,
        max_age_ms: max_age_secs * 1_000,
        max_ahead_ms: 30_000,
    };
    let checkpoint = driver::sync(&mut client, &mut node, &clock)?;
    println!(
        "{} handovers verified, each under the committee before it",
        client.epoch() - anchor.epoch
    );
    // A checkpoint decided while no block was ordered covers none: its first
    // height is one past its last, and it certifies the state after its last
    // block.
    let blocks = if checkpoint.first_height > checkpoint.last_height {
        format!("no new blocks after {}", checkpoint.last_height)
    } else {
        format!(
            "blocks {}..={}",
            checkpoint.first_height, checkpoint.last_height
        )
    };
    println!(
        "certified checkpoint {} of epoch {}: {blocks}, state height {}, state root {}, block time {} ms",
        checkpoint.index,
        checkpoint.epoch,
        checkpoint.state_height,
        hex::encode(checkpoint.state_root),
        checkpoint.timestamp_ms,
    );
    println!(
        "the client now trusts the committee of epoch {} (root {})",
        client.epoch(),
        hex::encode(client.committee_root()),
    );

    let namespace = args.get("--namespace").map_or("state", String::as_str);
    let (key, expect_chain_id) = match args.get("--state-key") {
        Some(key) => (wire::bytes("--state-key", key)?, false),
        None => (identity::system_slot("network:chain_id"), true),
    };
    match driver::state_value(&mut node, &checkpoint, &clock, namespace, &key)? {
        Some(value) => {
            println!(
                "proven under that state root: {namespace} {} = {}",
                hex::encode(&key),
                hex::encode(&value)
            );
            if expect_chain_id && value != chain_id.to_le_bytes() {
                return Err("the chain id in state is not the anchor's".into());
            }
        }
        None => {
            println!(
                "proven absent under that state root: {namespace} {}",
                hex::encode(&key)
            );
            if expect_chain_id {
                return Err("the state holds no chain id".into());
            }
        }
    }
    Ok(())
}
