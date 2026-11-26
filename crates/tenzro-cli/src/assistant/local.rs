//! The assistant's calls to the person's own node: which served model can
//! answer, what the node's catalog offers this machine, and one chat request.
//! Every call is one the node already serves to any caller.

use std::net::IpAddr;

use serde_json::{Value, json};
use tenzro_catalog::CatalogEntry;

use super::model::{self, Offer, Picked};
use crate::rpc::RpcClient;

/// Whether `url` names a node on this machine. The assistant's model runs on
/// the person's own node and nowhere else. The host is read by the same URL
/// parser the HTTP client uses, so a URL cannot name this machine here and
/// another one on the wire.
pub fn is_own_node(url: &str) -> bool {
    let url = if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    };
    let Ok(url) = reqwest::Url::parse(&url) else {
        return false;
    };
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

/// This machine's memory, to the nearest GB.
fn memory_gb() -> u64 {
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    (system.total_memory() + (1 << 29)) >> 30
}

async fn catalog(rpc: &RpcClient) -> Result<Vec<CatalogEntry>, String> {
    let reply: Value = rpc
        .call("tenzro_listCatalog", json!({}))
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_value(reply["entries"].clone())
        .map_err(|e| format!("the node's catalog could not be read: {e}"))
}

async fn loaded(rpc: &RpcClient) -> Result<Vec<String>, String> {
    let reply: Value = rpc
        .call("tenzro_listModels", json!({ "loaded": true }))
        .await
        .map_err(|e| e.to_string())?;
    let ids = reply["models"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|row| row["model_id"].as_str())
        .map(str::to_string)
        .collect();
    Ok(ids)
}

/// The model the node serves now that the assistant's questions can go to.
/// A node that serves nothing is asked nothing more.
pub async fn served(rpc: &RpcClient) -> Option<String> {
    let ids = loaded(rpc).await.ok()?;
    if ids.is_empty() {
        return None;
    }
    let entries = catalog(rpc).await.ok()?;
    model::serving(&entries, &ids, memory_gb())
}

/// What `/assistant` reports: this machine's memory, the catalog's entry for
/// it, and the model that answers now.
pub async fn offer(rpc: &RpcClient) -> Result<Offer, String> {
    let memory_gb = memory_gb();
    let entries = catalog(rpc).await?;
    let ids = loaded(rpc).await?;
    Ok(Offer {
        memory_gb,
        serving: model::serving(&entries, &ids, memory_gb),
        pick: model::pick(&entries, memory_gb).map(Picked::of),
    })
}

/// One chat request to the node, and its reply.
pub async fn ask(rpc: &RpcClient, request: Value) -> Result<Value, String> {
    rpc.call("tenzro_chat", request)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_machine_is_the_persons_own_node() {
        for url in [
            "http://127.0.0.1:8545",
            "http://localhost:8545/",
            "http://LOCALHOST",
            "http://[::1]:8545",
            "127.0.0.1:8545",
            "http://127.8.9.10:1/path?x=1",
        ] {
            assert!(is_own_node(url), "{url}");
        }
        for url in [
            "https://rpc.tenzro.com",
            "http://192.168.1.20:8545",
            "http://localhost.example.com:8545",
            "http://localhost@example.com:8545",
            "http://example.com/127.0.0.1",
            "http://[2001:db8::1]:8545",
            "http://0.0.0.0:8545",
            "http://evil.com\\@127.0.0.1",
            "http://evil.com\\@127.0.0.1:8545/",
            "http://127.0.0.1@evil.com",
            "http://127.0.0.1 @evil.com",
            "",
        ] {
            assert!(!is_own_node(url), "{url}");
        }
    }
}
