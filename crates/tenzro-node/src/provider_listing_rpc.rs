//! Provider discovery for apps that choose providers themselves: where a
//! provider is (coarsely), how loaded each of its models is right now, and
//! what a given request would cost at each provider.
//!
//! - `tenzro_listProviders { provider_type?, limit?, cursor? }`: every
//!   provider this node knows, a page at a time, with its coarse region,
//!   jurisdiction and the live load of each model (this node's read now; a
//!   peer's from its latest heartbeat, with the time it was taken).
//! - `tenzro_quoteInference { model, units, verification?, provider?, order? }`:
//!   the price of one request at each provider serving `model`, priced on
//!   the rate card the provider announced plus the governed surcharge for
//!   the verification level, with the carbon intensity of the provider's
//!   region's grid. Cheapest first, or with `order: "carbon"` (for spot work
//!   that can run anywhere) cleanest grid first and cheapest among equals,
//!   with `carbon_effect`: the grid intensity saved and the extra price and
//!   warm-up wait against the cheapest offer.

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
/// The root id of the operator behind the account `address` (`0x` hex);
/// `None` when the address does not parse, chain state is not available or
/// no identity is registered to it.
fn operator(chain: Option<&tenzro_vm::StateAdapter>, address: &str) -> Option<String> {
    let address = tenzro_types::primitives::Address::parse(address).ok()?;
    crate::operator_counts::operator_of_account(chain?, address.as_bytes())
}

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
    Some(AttestedHardware::from_stamp(stamp))
}

/// The shape of a provider's attested hardware in a listing: the chain's
/// derivation for the provider's account (`tenzro_types::hardware_level::HardwareStamp`),
/// plus whether any verified attestation stands behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttestedHardware {
    /// Whether verified attestation for the current or previous epoch
    /// raises the account above `l0`. False means no hardware is proven yet
    /// (no attestation record, or none fresh for this epoch); it says
    /// nothing about what the key is held in, so show it as "not attested
    /// yet", not as software.
    pub attested: bool,
    /// The hardware level, `l0` upward.
    pub level: String,
    /// The kind of hardware the chain derives: `tpm2`, or `software` when no
    /// hardware is proven (see `attested`).
    pub kind: String,
    /// The TPM manufacturer from the endorsement certificate; empty when unknown.
    pub vendor: String,
    /// The TPM specification from the endorsement certificate; empty when it names none.
    pub spec: String,
    /// The attestation signature scheme, with `+ml-dsa-65` when the identity enrolled one.
    pub scheme: String,
}

/// A level or kind as its wire name (`l0`, `tpm2`).
fn label(v: &impl Serialize) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

impl AttestedHardware {
    fn from_stamp(stamp: tenzro_types::hardware_level::HardwareStamp) -> Self {
        Self {
            attested: stamp.level != tenzro_types::hardware_level::HardwareLevel::L0,
            level: label(&stamp.level),
            kind: label(&stamp.kind),
            vendor: stamp.vendor,
            spec: stamp.spec,
            scheme: stamp.scheme,
        }
    }
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
    /// The root id of the operator behind that account as the chain derives
    /// it; null when the account has no identity on chain.
    pub operator: Option<String>,
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
    /// The confidential-compute hardware the provider announces its
    /// `tee`-level answers are attested by; null when it announces none.
    /// `nvidia-gpu` is a GPU attested together with its confidential VM; any
    /// other name is the processor alone, which leaves an accelerator's
    /// memory outside. Announced, not proven here: every `tee` answer carries
    /// the report its caller verifies.
    pub confidential_compute: Option<String>,
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
    /// The machines of the whole listing, not of this page, and the
    /// operators behind them.
    pub operators: crate::operator_counts::OperatorCounts,
    /// Pass as `cursor` for the next page; absent on the last one.
    pub next_cursor: Option<String>,
}

/// Cut `entries` to the page after `cursor`, at most `limit` long.
/// `cursor` is the key of the last entry a prior page ended on; one that
/// names no entry ends the listing rather than silently restarting it.
fn page_after(
    entries: Vec<ProviderEntry>,
    operators: crate::operator_counts::OperatorCounts,
    cursor: Option<&str>,
    limit: usize,
) -> ProviderPage {
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
        operators,
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
            operator: operator(chain.as_ref(), &address),
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
            confidential_compute: node
                .tee_provider()
                .map(|p| crate::verifiable_inference::tee_vendor_name(p.vendor()).to_string()),
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
            operator: operator(chain.as_ref(), &a.provider_address),
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
            confidential_compute: Some(a.trust_profile.tee_vendor.clone())
                .filter(|v| !v.is_empty()),
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
    let operators: Vec<Option<String>> = out
        .iter()
        .map(|e| match e {
            ProviderEntry::Model(p) => p.operator.clone(),
            ProviderEntry::AgentServing(a) => chain
                .as_ref()
                .map(|c| crate::operator_counts::operator_of_did(c, &a.operator_did)),
        })
        .collect();
    let counts = crate::operator_counts::count(operators.iter().map(Option::as_deref));
    serde_json::to_value(page_after(
        out,
        counts,
        params.cursor.as_deref(),
        params.limit,
    ))
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: e.to_string(),
        data: None,
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

/// How quoted offers are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteOrder {
    /// Cheapest first.
    Price,
    /// Cleanest grid first, unknown regions last, cheapest among equals.
    Carbon,
}

fn quote_order(v: Option<&Value>) -> Result<QuoteOrder, JsonRpcError> {
    match v {
        None | Some(Value::Null) => Ok(QuoteOrder::Price),
        Some(v) if v.as_str() == Some("price") => Ok(QuoteOrder::Price),
        Some(v) if v.as_str() == Some("carbon") => Ok(QuoteOrder::Carbon),
        _ => Err(bad("'order' is \"price\" or \"carbon\"")),
    }
}

/// Orders quoted offers in place.
fn order_offers(offers: &mut [Value], order: QuoteOrder) {
    let price = |o: &Value| {
        o["price_wei"]
            .as_str()
            .and_then(|p| p.parse::<u128>().ok())
            .unwrap_or(u128::MAX)
    };
    match order {
        QuoteOrder::Price => offers.sort_by_key(price),
        QuoteOrder::Carbon => offers.sort_by_key(|o| {
            (
                o["grid_g_co2_per_kwh"].as_u64().unwrap_or(u64::MAX),
                price(o),
            )
        }),
    }
}

/// What putting the cleanest grid first costs against the cheapest offer:
/// grams CO2e per kWh saved, extra price and extra wait for a warm model
/// (both signed; negative is a gain). Network latency between regions is
/// not known here and not counted.
fn carbon_effect(cheapest: &Value, cleanest: &Value) -> Value {
    let grid = |o: &Value| o["grid_g_co2_per_kwh"].as_i64();
    let price = |o: &Value| o["price_wei"].as_str().and_then(|p| p.parse::<i128>().ok());
    let wait = |o: &Value| o["load"]["warm_eta_ms"].as_i64().unwrap_or(0);
    json!({
        "same_offer": cheapest["endpoint_id"] == cleanest["endpoint_id"],
        "grid_g_co2_per_kwh_saved": match (grid(cheapest), grid(cleanest)) {
            (Some(a), Some(b)) => Some(a - b),
            _ => None,
        },
        "extra_price_wei": match (price(cheapest), price(cleanest)) {
            (Some(a), Some(b)) => Some((b - a).to_string()),
            _ => None,
        },
        "extra_warm_wait_ms": wait(cleanest) - wait(cheapest),
    })
}

/// `tenzro_quoteInference { model, units, verification?, provider?, order? }`.
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
    let order = quote_order(params.get("order"))?;
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
    let cheapest = {
        let mut by_price = offers.clone();
        order_offers(&mut by_price, QuoteOrder::Price);
        by_price.into_iter().next()
    };
    order_offers(&mut offers, order);
    let effect = match (order, cheapest.as_ref(), offers.first()) {
        (QuoteOrder::Carbon, Some(c), Some(g)) => carbon_effect(c, g),
        _ => Value::Null,
    };
    Ok(json!({
        "model": model,
        "verification": level.as_str(),
        "surcharge_bps": surcharge,
        "offers": offers,
        "carbon_effect": effect,
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
        "grid_g_co2_per_kwh": region.as_deref().and_then(crate::grid_carbon::grid_g_per_kwh),
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
        assert_eq!(
            page["result"]["operators"],
            json!({ "machines": 0, "distinct_operators": 0, "without_identity": 0 }),
            "{page}"
        );
        let refused = call(&node, json!({ "limit": 0 })).await;
        assert_eq!(refused["error"]["code"], -32602, "{refused}");
    }

    #[test]
    fn hardware_with_no_attestation_reads_as_not_attested() {
        let chain = tenzro_vm::StateAdapter::new();
        let none = attested_hardware(Some(&chain), &format!("0x{}", "11".repeat(20)))
            .expect("a parsable address on available state is derived");
        assert!(!none.attested, "{none:?}");
        assert_eq!(
            (none.level.as_str(), none.kind.as_str()),
            ("l0", "software")
        );
        assert!(attested_hardware(Some(&chain), "not-an-address").is_none());
        assert!(attested_hardware(None, &format!("0x{}", "11".repeat(20))).is_none());

        use tenzro_types::hardware_level::{HardwareKind, HardwareLevel, HardwareStamp};
        let tpm = AttestedHardware::from_stamp(HardwareStamp {
            level: HardwareLevel::L2,
            kind: HardwareKind::Tpm2,
            vendor: "id:494E5443".into(),
            spec: String::new(),
            scheme: "ecdsa-p256+ml-dsa-65".into(),
        });
        assert!(tpm.attested);
        assert_eq!((tpm.level.as_str(), tpm.kind.as_str()), ("l2", "tpm2"));
        // The fields a quote copies keep the chain's derivation.
        let stamp: HardwareStamp =
            serde_json::from_value(serde_json::to_value(&tpm).unwrap()).unwrap();
        assert_eq!(stamp.level, HardwareLevel::L2);
        assert_eq!(stamp.kind, HardwareKind::Tpm2);
    }

    #[test]
    fn pages_follow_the_cursor_to_the_end() {
        let all: Vec<_> = ["a", "b", "c", "d", "e"].into_iter().map(agent).collect();
        let counts = crate::operator_counts::count(vec![Some("op"); 5]);
        let first = page_after(all.clone(), counts, None, 2);
        assert_eq!(first.providers, all[..2]);
        assert_eq!(first.next_cursor.as_deref(), Some("b"));
        let second = page_after(all.clone(), counts, first.next_cursor.as_deref(), 2);
        assert_eq!(second.providers, all[2..4]);
        let last = page_after(all.clone(), counts, second.next_cursor.as_deref(), 2);
        assert_eq!(last.providers, all[4..]);
        assert_eq!(last.next_cursor, None);
        // Every page carries the counts of the whole listing.
        assert_eq!(last.operators, counts);
        assert_eq!((counts.machines, counts.distinct_operators), (5, 1));
        assert!(page_after(all, counts, Some("zz"), 2).providers.is_empty());
    }

    #[test]
    fn carbon_order_puts_the_cleanest_grid_first_and_unknown_regions_last() {
        let o = |id: &str, price: u128, region: Option<&str>| {
            json!({
                "endpoint_id": id,
                "price_wei": price.to_string(),
                "grid_g_co2_per_kwh": region.and_then(crate::grid_carbon::grid_g_per_kwh),
            })
        };
        let mut offers = vec![
            o("pl", 1, Some("PL")),
            o("fr-dear", 9, Some("FR")),
            o("unknown", 0, None),
            o("fr-cheap", 5, Some("FR")),
            o("se", 7, Some("SE")),
        ];
        order_offers(&mut offers, quote_order(Some(&json!("carbon"))).unwrap());
        let ids: Vec<&str> = offers
            .iter()
            .map(|o| o["endpoint_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["se", "fr-cheap", "fr-dear", "pl", "unknown"]);
        order_offers(&mut offers, quote_order(None).unwrap());
        let ids: Vec<&str> = offers
            .iter()
            .map(|o| o["endpoint_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["unknown", "pl", "fr-cheap", "se", "fr-dear"]);
        assert_eq!(
            quote_order(Some(&json!("price"))).unwrap(),
            QuoteOrder::Price
        );
        assert!(quote_order(Some(&json!("green"))).is_err());
    }

    #[test]
    fn the_carbon_effect_weighs_the_cleanest_offer_against_the_cheapest() {
        let cheap = json!({"endpoint_id": "pl", "price_wei": "5", "grid_g_co2_per_kwh": 660,
            "load": {"warm_eta_ms": 0}});
        let clean = json!({"endpoint_id": "se", "price_wei": "7", "grid_g_co2_per_kwh": 40,
            "load": {"warm_eta_ms": 1500}});
        let e = carbon_effect(&cheap, &clean);
        assert_eq!(e["same_offer"], false);
        assert_eq!(e["grid_g_co2_per_kwh_saved"], 620);
        assert_eq!(e["extra_price_wei"], "2");
        assert_eq!(e["extra_warm_wait_ms"], 1500);
        let unknown = json!({"endpoint_id": "x", "price_wei": null, "grid_g_co2_per_kwh": null});
        let e = carbon_effect(&unknown, &clean);
        assert!(e["grid_g_co2_per_kwh_saved"].is_null() && e["extra_price_wei"].is_null());
    }
}
