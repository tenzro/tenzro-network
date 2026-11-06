//! Provider discovery for apps that choose providers themselves: where a
//! provider is (coarsely), how loaded each of its models is right now, and
//! what a given request would cost at each provider.
//!
//! - `tenzro_listProviders { provider_type?, limit?, cursor? }`: every
//!   provider this node knows, a page at a time, with its coarse region,
//!   jurisdiction and the live load of each model (this node's read now; a
//!   peer's from its latest heartbeat, with the time it was taken).
//! - `tenzro_quoteInference { model, units, verification?, provider? }`: the
//!   price of one request at each provider serving `model`, priced on the
//!   rate card the provider announced plus the governed surcharge for the
//!   verification level, cheapest first.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tenzro_types::model::BillableUnits;
use tenzro_types::price_card::RateCard;
use tenzro_types::provider_listing::ModelLoad;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// This node's coarse region, canonical, when it declares one.
fn own_region(node: &TenzroNode) -> Option<String> {
    node.config()
        .region
        .as_deref()
        .and_then(|r| tenzro_types::provider_listing::coarse_region(r).ok())
}

/// The live load of this node's announced models.
fn own_load(node: &TenzroNode, served: &[String]) -> Vec<ModelLoad> {
    crate::provider_heartbeat::model_load(
        served,
        Some(node.load_tracker.as_ref()),
        Some(node.lifecycle().as_ref()),
    )
}

/// A provider's hardware level and type as the chain derives them from
/// verified attestation, never what the provider announced; null when the
/// address does not parse or chain state is not available.
fn attested_hardware(
    chain: Option<&tenzro_vm::StateAdapter>,
    address: &str,
) -> Option<AttestedHardware> {
    let (Some(chain), Ok(address)) = (chain, tenzro_types::primitives::Address::parse(address))
    else {
        return None;
    };
    let (stamp, _, _) = tenzro_vm::native::hardware_level::derive(
        chain,
        address.as_bytes(),
        crate::calendar::now_ms() as i64,
    );
    serde_json::to_value(stamp)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
}

/// The shape of a provider's attested hardware in a listing: the chain's
/// derivation for the provider's account (`tenzro_types::hardware_level::HardwareStamp`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttestedHardware {
    /// The hardware level, `l0` upward.
    pub level: String,
    /// The kind of hardware: `software` or `tpm2`.
    pub kind: String,
    /// The TPM manufacturer from the endorsement certificate; empty when unknown.
    pub vendor: String,
    /// The TPM specification from the endorsement certificate; empty when it names none.
    pub spec: String,
    /// The attestation signature scheme, with `+ml-dsa-65` when the identity enrolled one.
    pub scheme: String,
}

/// Most providers one `tenzro_listProviders` page carries.
const MAX_PROVIDER_PAGE: usize = 200;
/// Providers a page carries when the caller names no limit.
const DEFAULT_PROVIDER_PAGE: usize = 50;

/// Where a served model stands, as a listing reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServingState {
    /// Not loaded; the first request pays the load.
    Cold,
    /// Loading; requests wait for it.
    Warming,
    /// Loaded and serving.
    Warm,
    /// Being unloaded.
    Evicting,
}

/// The live load of one served model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderModelLoad {
    pub model_id: String,
    pub state: ServingState,
    /// Requests admitted and not yet finished.
    pub in_flight: u32,
    /// Most requests it admits at once.
    pub max_concurrent: u32,
    /// Requests waiting for it to finish loading.
    pub queue_depth: u32,
    /// Estimated time until it is loaded, ms, while warming.
    pub warm_eta_ms: Option<u64>,
}

impl From<ModelLoad> for ProviderModelLoad {
    fn from(l: ModelLoad) -> Self {
        use tenzro_types::provider_listing::ModelServingState as S;
        Self {
            model_id: l.model_id,
            state: match l.state {
                S::Cold => ServingState::Cold,
                S::Warming => ServingState::Warming,
                S::Warm => ServingState::Warm,
                S::Evicting => ServingState::Evicting,
            },
            in_flight: l.in_flight,
            max_concurrent: l.max_concurrent,
            queue_depth: l.queue_depth,
            warm_eta_ms: l.warm_eta_ms,
        }
    }
}

/// A node that serves models: this node, or a peer from its gossip
/// announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelProvider {
    pub endpoint_id: String,
    /// Its hardware level and type as the chain derives them from verified
    /// attestation, never what the provider announced; null when the address
    /// does not parse or chain state is not available.
    pub attested_hardware: Option<AttestedHardware>,
    /// The account the provider is paid to, `0x` hex; empty when this node
    /// has no operator payee.
    pub provider_address: String,
    pub provider_type: String,
    pub served_models: Vec<String>,
    /// The served models a caller needs a key for.
    pub key_required_models: Vec<String>,
    pub capabilities: Vec<String>,
    pub status: String,
    /// Coarse region: a country code or a wide region.
    pub region: Option<String>,
    /// Declared jurisdiction (ISO 3166-1 alpha-2).
    pub jurisdiction: Option<String>,
    /// The live load of each served model.
    pub model_load: Option<Vec<ProviderModelLoad>>,
    /// When `model_load` was read, ms since the Unix epoch.
    pub load_as_of_ms: Option<i64>,
    /// The hardware tier, when the provider detected its hardware.
    pub hardware_tier: Option<String>,
    /// The kind of hardware its identity key is held in: `tpm`, `enclave`,
    /// `delegated_tpm` or `passkey`.
    pub identity_anchor: Option<String>,
    /// When the announcement was made, ms since the Unix epoch; absent for
    /// this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    /// How the provider is reached; absent for this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachability: Option<String>,
    /// `local` for this node, `network` for a peer.
    pub source: String,
}

/// A node that serves delegated agents, by identity only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentServingNode {
    pub machine_did: String,
    pub operator_did: String,
    pub capabilities: Vec<String>,
    /// Whether its compute bond is live on chain.
    pub live: bool,
}

/// One entry of `tenzro_listProviders`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ProviderEntry {
    Model(ModelProvider),
    AgentServing(AgentServingNode),
}

impl ProviderEntry {
    /// What a page cursor names this entry by.
    fn key(&self) -> &str {
        match self {
            Self::Model(p) => &p.endpoint_id,
            Self::AgentServing(a) => &a.machine_did,
        }
    }

    fn provider_type(&self) -> Option<&str> {
        match self {
            Self::Model(p) => Some(&p.provider_type),
            Self::AgentServing(_) => None,
        }
    }
}

/// One page of `tenzro_listProviders`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderPage {
    pub providers: Vec<ProviderEntry>,
    /// Pass as `cursor` for the next page; absent on the last one.
    pub next_cursor: Option<String>,
}

/// Cut `entries` to the page after `cursor`, at most `limit` long.
/// `cursor` is the key of the last entry a prior page ended on; one that
/// names no entry ends the listing rather than silently restarting it.
fn page_after(entries: Vec<ProviderEntry>, cursor: Option<&str>, limit: usize) -> ProviderPage {
    let start = match cursor {
        None => 0,
        Some(c) => entries
            .iter()
            .position(|e| e.key() == c)
            .map_or(entries.len(), |i| i + 1),
    };
    let rest = &entries[start..];
    let next_cursor = (rest.len() > limit).then(|| rest[limit - 1].key().to_string());
    ProviderPage {
        providers: rest.iter().take(limit).cloned().collect(),
        next_cursor,
    }
}

/// The page parameters of `tenzro_listProviders`.
struct ListParams {
    provider_type: Option<String>,
    limit: usize,
    cursor: Option<String>,
}

fn list_params(params: Option<Value>) -> Result<ListParams, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let text = |name: &str| match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(bad(format!("{name} is a string"))),
    };
    let limit = match params.get("limit") {
        None | Some(Value::Null) => DEFAULT_PROVIDER_PAGE,
        Some(v) => v
            .as_u64()
            .filter(|l| *l > 0)
            .map(|l| (l as usize).min(MAX_PROVIDER_PAGE))
            .ok_or_else(|| bad("limit is a positive integer"))?,
    };
    Ok(ListParams {
        provider_type: text("provider_type")?,
        limit,
        cursor: text("cursor")?,
    })
}

/// `tenzro_listProviders { provider_type?, limit?, cursor? }`: this node
/// first when it serves, then every peer serving models in endpoint order,
/// then the nodes that serve delegated agents in DID order, one page at a
/// time. `provider_type` keeps only model providers of that type. `cursor`
/// is the `endpoint_id` (or, for an agent-serving node, the `machine_did`)
/// of the last entry a prior page ended on, echoed back as `next_cursor`.
pub(crate) async fn handle_list_providers(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = list_params(params)?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let now = chrono::Utc::now().timestamp_millis();
    let chain = crate::rpc::chain_state_of(node);

    let (served, key_required_models) =
        crate::visibility_rpc::announced_models(&node.served_models, node.visibility());
    if !served.is_empty() {
        let endpoint = node
            .iroh_resolver()
            .map(|r| r.endpoint_id().to_string())
            .unwrap_or_else(|| "local".to_string());
        seen.insert(endpoint.clone());
        let model_load = own_load(node, &served)
            .into_iter()
            .map(Into::into)
            .collect();
        let address = node
            .operator_payee()
            .map(|a| format!("0x{}", hex::encode(a.as_bytes())))
            .unwrap_or_default();
        out.push(ProviderEntry::Model(ModelProvider {
            endpoint_id: endpoint,
            attested_hardware: attested_hardware(chain.as_ref(), &address),
            provider_address: address,
            provider_type: tenzro_network::message::PROVIDER_TYPE_AI.to_string(),
            served_models: served,
            key_required_models,
            capabilities: vec!["inference".to_string()],
            status: "active".to_string(),
            region: own_region(node),
            jurisdiction: node.config().jurisdiction_country.clone(),
            model_load: Some(model_load),
            load_as_of_ms: Some(now),
            hardware_tier: Some(crate::work_settlements::local_tier().await.to_string()),
            identity_anchor: crate::network_rpc::local_anchor_kind().map(str::to_string),
            timestamp: None,
            reachability: None,
            source: "local".to_string(),
        }));
    }

    let mut peers = Vec::new();
    for entry in node.network_providers_snapshot() {
        let a = &entry.announcement;
        if !seen.insert(a.iroh_endpoint_id.clone()) {
            continue;
        }
        let (as_of, load) = entry.live_load.clone().unzip();
        peers.push(ProviderEntry::Model(ModelProvider {
            endpoint_id: a.iroh_endpoint_id.clone(),
            attested_hardware: attested_hardware(chain.as_ref(), &a.provider_address),
            provider_address: a.provider_address.clone(),
            provider_type: a.provider_type.clone(),
            served_models: a.served_models.clone(),
            key_required_models: a.key_required_models.clone(),
            capabilities: a.capabilities.clone(),
            status: a.status.clone(),
            region: a.region.clone(),
            jurisdiction: a.capacity.jurisdiction.as_ref().map(|j| j.country.clone()),
            model_load: load.map(|l| l.into_iter().map(Into::into).collect()),
            load_as_of_ms: as_of,
            hardware_tier: a
                .hardware
                .detected
                .then(|| crate::work_settlements::tier_name(a.hardware.class()).to_string()),
            identity_anchor: crate::network_rpc::anchor_kind(&a.trust_profile.identity_root)
                .map(str::to_string),
            timestamp: Some(a.timestamp),
            reachability: Some(a.network_profile.reachability.clone()),
            source: "network".to_string(),
        }));
    }
    // Gossip state has no order of its own; endpoint order keeps a cursor
    // meaning the same entry from one page to the next.
    peers.sort_by(|x, y| x.key().cmp(y.key()));
    out.extend(peers);

    let mut agents = crate::agent_delegation::serving_provider_entries(node)
        .into_iter()
        .map(serde_json::from_value::<AgentServingNode>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("agent-serving entry: {e}"),
            data: None,
        })?;
    agents.sort_by(|x, y| x.machine_did.cmp(&y.machine_did));
    out.extend(agents.into_iter().map(ProviderEntry::AgentServing));

    if let Some(t) = &params.provider_type {
        out.retain(|e| e.provider_type() == Some(t.as_str()));
    }
    serde_json::to_value(page_after(out, params.cursor.as_deref(), params.limit)).map_err(|e| {
        JsonRpcError {
            code: -32603,
            message: e.to_string(),
            data: None,
        }
    })
}

/// What one request costs on `card`, in TNZO base units at the rate in
/// force; `None` when the card does not price every unit the request meters.
pub(crate) fn quote_card(
    node: &TenzroNode,
    card: &RateCard,
    units: &BillableUnits,
) -> Option<u128> {
    crate::inference_pricing::charge_wei(node, card, units).ok()
}

/// `tenzro_quoteInference { model, units, verification?, provider? }`.
pub(crate) async fn handle_quote_inference(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let model = params
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("Missing 'model'"))?;
    // Units the request leaves out are zero. A card that does not price a
    // unit the request names quotes no price.
    let mut units = BillableUnits::default();
    if let Some(given) = params.get("units") {
        let given = given
            .as_object()
            .ok_or_else(|| bad("'units' maps meter keys to quantities"))?;
        for (k, v) in given {
            let quantity = v
                .as_u64()
                .map(u128::from)
                .or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))
                .ok_or_else(|| bad(format!("invalid quantity for billable unit '{k}'")))?;
            units
                .set(k, quantity)
                .map_err(|e| bad(format!("invalid billable unit '{k}': {e}")))?;
        }
    }
    let level = crate::verifiable_inference::level_param(params.get("verification"))?;
    let only = params
        .get("provider")
        .and_then(Value::as_str)
        .map(|p| p.trim_start_matches("0x").to_ascii_lowercase());
    let surcharge = crate::verifiable_inference::surcharge_bps(node, level);
    let chain = crate::rpc::chain_state_of(node);

    let mut offers = Vec::new();
    let (served, _) =
        crate::visibility_rpc::announced_models(&node.served_models, node.visibility());
    if served.iter().any(|m| m == model)
        && crate::verifiable_inference::offered_levels(node).contains(&level)
    {
        let card = node.provider_pricing.read().card_for(model).clone();
        let hardware = node.operator_payee().and_then(|a| {
            attested_hardware(chain.as_ref(), &format!("0x{}", hex::encode(a.as_bytes())))
        });
        offers.push(offer(
            node,
            "local",
            None,
            &card,
            &units,
            surcharge,
            own_region(node),
            own_load(node, &[model.to_string()]).into_iter().next(),
            hardware,
        ));
    }
    for e in node.network_models_snapshot() {
        let reg = &e.registration;
        if reg.model_id != model
            || only
                .as_deref()
                .is_some_and(|p| reg.provider.trim_start_matches("0x").to_ascii_lowercase() != p)
            || !crate::verifiable_inference::offer_meets(node, reg, level)
        {
            continue;
        }
        let provider = node.network_providers.get(&reg.iroh_endpoint_id);
        let region = provider
            .as_ref()
            .and_then(|p| p.announcement.region.clone());
        let load = provider
            .as_ref()
            .and_then(|p| p.live_load.as_ref())
            .and_then(|(_, loads)| loads.iter().find(|l| l.model_id == model).cloned());
        offers.push(offer(
            node,
            &reg.iroh_endpoint_id,
            Some(&reg.provider),
            &reg.pricing,
            &units,
            surcharge,
            region,
            load,
            attested_hardware(chain.as_ref(), &reg.provider),
        ));
    }
    if only.is_some() {
        offers.retain(|o| o["source"] != "local");
    }
    offers.sort_by_key(|o| {
        o["price_wei"]
            .as_str()
            .and_then(|p| p.parse::<u128>().ok())
            .unwrap_or(u128::MAX)
    });
    Ok(json!({
        "model": model,
        "verification": level.as_str(),
        "surcharge_bps": surcharge,
        "offers": offers,
        // The legs this node declares on top of a price it settles: the
        // payer signs each in its payment authorization.
        "declared_legs": node.declared_platform_fee().map(|f| vec![json!({
            "kind": "platform_fee",
            "wallet": format!("0x{}", hex::encode(f.app_wallet.as_bytes())),
            "bps": f.margin_bps,
        })]).unwrap_or_default(),
    }))
}

fn offer(
    node: &TenzroNode,
    endpoint: &str,
    provider: Option<&str>,
    card: &RateCard,
    units: &BillableUnits,
    surcharge: u64,
    region: Option<String>,
    load: Option<ModelLoad>,
    hardware: Option<AttestedHardware>,
) -> Value {
    let base = quote_card(node, card, units);
    json!({
        "source": if provider.is_some() { "network" } else { "local" },
        "endpoint_id": endpoint,
        "provider_address": provider,
        "card": card,
        "base_wei": base.map(|b| b.to_string()),
        "price_wei": base.map(|b| crate::verifiable_inference::priced(b, surcharge).to_string()),
        "region": region,
        "load": load,
        "attested_hardware": hardware,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn node() -> (Arc<TenzroNode>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        (Arc::new(TenzroNode::new(cfg).await.unwrap()), tmp)
    }

    async fn call(node: &Arc<TenzroNode>, params: Value) -> Value {
        crate::rpc::dispatch_embedded(
            node,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tenzro_listProviders", "params": params }),
            crate::rpc::EmbeddedAuth::default(),
        )
        .await
    }

    fn agent(did: &str) -> ProviderEntry {
        ProviderEntry::AgentServing(AgentServingNode {
            machine_did: did.to_string(),
            operator_did: "did:tenzro:human:op".to_string(),
            capabilities: vec![],
            live: true,
        })
    }

    #[tokio::test]
    async fn the_provider_listing_is_a_page_with_a_cursor() {
        let (node, _tmp) = node().await;
        let page = call(&node, json!({ "limit": 10 })).await;
        assert_eq!(page["result"]["providers"], json!([]), "{page}");
        assert!(page["result"]["next_cursor"].is_null(), "{page}");
        let refused = call(&node, json!({ "limit": 0 })).await;
        assert_eq!(refused["error"]["code"], -32602, "{refused}");
    }

    #[test]
    fn pages_follow_the_cursor_to_the_end() {
        let all: Vec<_> = ["a", "b", "c", "d", "e"].into_iter().map(agent).collect();
        let first = page_after(all.clone(), None, 2);
        assert_eq!(first.providers, all[..2]);
        assert_eq!(first.next_cursor.as_deref(), Some("b"));
        let second = page_after(all.clone(), first.next_cursor.as_deref(), 2);
        assert_eq!(second.providers, all[2..4]);
        let last = page_after(all.clone(), second.next_cursor.as_deref(), 2);
        assert_eq!(last.providers, all[4..]);
        assert_eq!(last.next_cursor, None);
        assert!(page_after(all, Some("zz"), 2).providers.is_empty());
    }
}
