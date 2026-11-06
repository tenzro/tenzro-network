//! Salted prefix probes between routers and providers.
//!
//! Provider side: [`handle_prefix_probe`] answers `tenzro_prefixProbe` with how
//! many leading runs of the probed prompt each served model holds warm. The
//! probe carries digests, never text, and only digests computed under the salt
//! a prompt was served with can match (see [`tenzro_model::prefix_affinity`]).
//!
//! Router side: [`probe_providers`] asks the providers that report warm runs
//! how much of this caller's conversation they hold, and returns the answers
//! as [`PrefixMatches`] for the routing decision.
//!
//! Both sides name a request's salt with [`request_salt`]: a salt a
//! forwarding node attached for its own caller, else one derived from the
//! principal this node authenticated. An anonymous caller has no salt, and
//! so neither records nor probes anything.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tenzro_model::prefix_affinity::{
    MAX_PROBE_DIGESTS, PrefixDigest, PrefixMatches, Salt, parse_salt, principal_salt,
    salted_prefix_digests,
};
use tenzro_types::primitives::Address;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Most providers probed for one request. Probes run concurrently.
const MAX_PROBED_PROVIDERS: usize = 4;

/// A probe slower than this is treated as a miss: affinity saves one
/// prefill, which is not worth stalling routing for.
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// The cache salt for one request: an explicit salt (hex) carried by a
/// forwarding node, else the salt of the principal this node authenticated
/// (its fair-share caller id), else none for an anonymous caller.
pub fn request_salt(explicit: Option<&str>, principal: Option<&str>) -> Option<Salt> {
    if let Some(s) = explicit.and_then(parse_salt) {
        return Some(s);
    }
    principal.filter(|p| *p != "anonymous").map(principal_salt)
}

/// Fill `intent`'s probe results for a caller with a salt. A caller without
/// one routes with no affinity at all.
pub async fn probe_for_intent(
    node: &Arc<TenzroNode>,
    intent: tenzro_model::routing::intent::RouteIntent,
    salt: Option<Salt>,
) -> tenzro_model::routing::intent::RouteIntent {
    let Some(salt) = salt else {
        return intent;
    };
    let Some(conversation) = intent
        .affinity_prefix
        .clone()
        .or_else(|| intent.prompt.clone())
    else {
        return intent;
    };
    let matches = probe_providers(node, conversation.as_bytes(), &salt).await;
    intent.with_prefix_matches(matches)
}

/// `tenzro_prefixProbe`: `{digests: [hex; <=256]}` to
/// `{matches: {model_id: runs}}`.
pub(crate) async fn handle_prefix_probe(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let bad = |message: String| JsonRpcError {
        code: -32602,
        message,
        data: None,
    };
    let params = params.ok_or_else(|| bad("missing params".into()))?;
    let raw = params
        .get("digests")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("digests must be an array of hex strings".into()))?;
    if raw.len() > MAX_PROBE_DIGESTS {
        return Err(bad(format!(
            "at most {MAX_PROBE_DIGESTS} digests per probe"
        )));
    }
    let mut digests: Vec<PrefixDigest> = Vec::with_capacity(raw.len());
    for d in raw {
        let bytes = d
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <PrefixDigest>::try_from(b).ok())
            .ok_or_else(|| bad("each digest is 32 hex characters".into()))?;
        digests.push(bytes);
    }
    #[cfg(feature = "inference")]
    let matches = node
        .model_runtime
        .as_ref()
        .map(|rt| rt.probe_warm_prefix(&digests))
        .unwrap_or_default();
    // The light build serves no model, so it holds no prefix warm.
    #[cfg(not(feature = "inference"))]
    let matches = {
        let _ = digests;
        serde_json::Map::new()
    };
    Ok(json!({ "matches": matches }))
}

/// Probe the providers that report warm runs for this conversation under
/// `salt`, and return what each holds warm, per model. Providers that do not
/// answer in time, or answer nonsense, contribute nothing.
pub async fn probe_providers(
    node: &Arc<TenzroNode>,
    conversation: &[u8],
    salt: &Salt,
) -> PrefixMatches {
    let digests: Vec<String> = salted_prefix_digests(salt, conversation)
        .iter()
        .take(MAX_PROBE_DIGESTS)
        .map(hex::encode)
        .collect();
    if digests.is_empty() {
        return PrefixMatches::new();
    }
    let own = node.operator_payee();
    let mut candidates: Vec<_> = node
        .network_providers_snapshot()
        .into_iter()
        .map(|e| e.announcement)
        .filter(|a| a.capacity.prefix_cache.warm_runs > 0)
        .filter_map(|a| {
            let addr = Address::from_hex(a.provider_address.trim_start_matches("0x")).ok()?;
            (Some(addr) != own).then_some((addr, a))
        })
        .collect();
    candidates.sort_by_key(|(_, a)| std::cmp::Reverse(a.capacity.prefix_cache.warm_runs));
    candidates.truncate(MAX_PROBED_PROVIDERS);

    let frame = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tenzro_prefixProbe",
        "params": { "digests": digests },
    });
    let probes = candidates.into_iter().map(|(addr, ann)| {
        let node = node.clone();
        let frame = frame.clone();
        async move {
            let reply = tokio::time::timeout(PROBE_TIMEOUT, probe_one(&node, &ann, &frame)).await;
            (addr, reply.ok().flatten())
        }
    });
    let mut out = PrefixMatches::new();
    for (addr, reply) in futures::future::join_all(probes).await {
        let Some(matches) = reply
            .as_ref()
            .and_then(|r| r.get("result"))
            .and_then(|r| r.get("matches"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for (model, runs) in matches {
            if let Some(runs) = runs.as_u64() {
                // A provider cannot hold more runs of a prompt than it has.
                let runs = runs.min(MAX_PROBE_DIGESTS as u64) as u32;
                out.insert((addr, model.clone()), runs);
            }
        }
    }
    out
}

/// One probe, sent to the provider's announced endpoint id on `tenzro/infer`.
async fn probe_one(
    node: &Arc<TenzroNode>,
    ann: &tenzro_network::ProviderAnnouncementMessage,
    frame: &Value,
) -> Option<Value> {
    let resolver = node.iroh_resolver.as_ref()?;
    let endpoint_id = ann
        .iroh_endpoint_id
        .parse::<tenzro_iroh::EndpointId>()
        .ok()?;
    let bytes = serde_json::to_vec(frame).ok()?;
    let resp = tenzro_iroh::request(
        resolver.endpoint(),
        endpoint_id,
        tenzro_iroh::ALPN_INFER,
        &bytes,
    )
    .await
    .ok()?;
    let body = resp.bytes(tenzro_iroh::MAX_INFER_BYTES).await.ok()?;
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anonymous_caller_has_no_salt() {
        assert!(request_salt(None, Some("anonymous")).is_none());
        assert!(request_salt(None, None).is_none());
    }

    #[test]
    fn an_authenticated_principal_has_a_stable_salt_of_its_own() {
        let a = request_salt(None, Some("key:a")).unwrap();
        assert_eq!(a, request_salt(None, Some("key:a")).unwrap());
        assert_ne!(a, request_salt(None, Some("key:b")).unwrap());
    }

    #[test]
    fn a_forwarded_salt_wins_over_the_local_principal() {
        let s = [7u8; 32];
        assert_eq!(request_salt(Some(&hex::encode(s)), Some("key:a")), Some(s));
        // Malformed salts are ignored, not trusted.
        assert!(request_salt(Some("zz"), None).is_none());
    }
}
