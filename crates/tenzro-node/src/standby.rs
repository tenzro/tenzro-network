//! Opt-in standby replicas.
//!
//! An operator who enables `[standby]` lets the node hold catalogued models
//! on standby: their weights are staged in host memory, locked where the
//! process may, with no engine context and no device memory. The node
//! announces which models it holds this way, so a continuity session picks it
//! as a successor ahead of nodes that would have to load from storage, and a
//! surge load prefers it too.
//!
//! A standby model activates through the node's ordinary serve path: the load
//! finds the staged weights and skips the read from storage. That happens on a
//! failover (a session this node succeeds is routed here) or a surge. A node
//! that charges a standby fee holds a session as its successor only against a
//! funded stream escrow (see [`crate::kv_continuity`]).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::node::TenzroNode;

/// Operator standby policy. Off unless the operator turns it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct StandbyConfig {
    /// Whether the node holds standby replicas at all.
    pub enabled: bool,
    /// Catalog ids to stage. Each must already be downloaded.
    pub models: Vec<String>,
    /// TNZO per hour this operator charges a session's payer while it holds
    /// the session as its successor. `0` holds for free.
    #[serde(with = "crate::config::u128_as_string")]
    pub fee_per_hour: u128,
}

/// Stage every configured standby model that is downloaded and not serving.
/// Staged models also serve continuity sessions once activated.
#[cfg(feature = "inference")]
pub async fn start(node: &Arc<TenzroNode>) {
    let config = node.config().standby.clone();
    if !config.enabled {
        return;
    }
    let (Some(runtime), Some(downloader)) = (node.model_runtime_arc(), node.hf_downloader.clone())
    else {
        return warn!("standby: no model runtime on this node; nothing staged");
    };
    for model_id in config.models {
        if runtime.is_loaded(&model_id) {
            continue;
        }
        let Some(path) = downloader.resolve_local_gguf(&model_id) else {
            warn!(model_id, "standby: model not downloaded; not staged");
            continue;
        };
        let rt = runtime.clone();
        let id = model_id.clone();
        match tokio::task::spawn_blocking(move || rt.stage_standby(&id, &path)).await {
            Ok(Ok(staged)) => info!(
                model_id,
                bytes = staged.bytes,
                pinned = staged.pinned,
                "standby: weights staged in host memory"
            ),
            Ok(Err(e)) => warn!(model_id, error = %e, "standby: staging failed"),
            Err(e) => warn!(model_id, error = %e, "standby: staging panicked"),
        }
    }
}

/// A live quote for reserving standby capacity ahead of any session: an
/// operator currently holding `model_id` on standby, what it advertises
/// charging, and how to reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbyQuote {
    /// The account a reservation escrow must pay.
    pub operator: String,
    /// The iroh `EndpointId` the reservation would be held on.
    pub endpoint_id: String,
    /// TNZO per hour, as advertised ([`tenzro_types::AdvertisedCapacity::standby_fee_per_hour`]).
    pub fee_per_hour: u128,
}

/// Standby quotes for `model_id` in `jurisdiction`, cheapest first: every
/// live node currently holding the model on standby, with a usable payee
/// address. A buyer funds a stream escrow against the returned `operator`,
/// referencing the session id it intends to use later ([`crate::kv_continuity::standby_digest`]),
/// before that session ever starts: `assign`'s "funded standby" path then
/// tries every eligible candidate until the one the escrow pays accepts,
/// so the reservation is honored once the session actually starts, and the
/// stream accrues the fee whether or not it does.
pub fn standby_quotes(node: &TenzroNode, model_id: &str, jurisdiction: &str) -> Vec<StandbyQuote> {
    let now = std::time::Instant::now();
    let providers = node.network_providers_snapshot();
    let live = providers.iter().filter(|e| {
        now.duration_since(e.last_seen) < std::time::Duration::from_secs(e.announcement.ttl_secs)
    });
    standby_quotes_from(live.map(|e| &e.announcement), model_id, jurisdiction)
}

/// The pure half of [`standby_quotes`]: quotes from already-live
/// announcements, so it is testable without a running node.
fn standby_quotes_from<'a>(
    live: impl Iterator<Item = &'a tenzro_network::ProviderAnnouncementMessage>,
    model_id: &str,
    jurisdiction: &str,
) -> Vec<StandbyQuote> {
    let mut quotes: Vec<StandbyQuote> = live
        .filter(|ann| !ann.iroh_endpoint_id.is_empty() && !ann.provider_address.is_empty())
        .filter(|ann| ann.capacity.standby_models.iter().any(|m| m == model_id))
        .filter(|ann| {
            ann.capacity
                .jurisdiction
                .as_ref()
                .is_some_and(|j| j.matches(jurisdiction))
        })
        .map(|ann| StandbyQuote {
            operator: ann.provider_address.clone(),
            endpoint_id: ann.iroh_endpoint_id.clone(),
            fee_per_hour: ann.capacity.standby_fee_per_hour,
        })
        .collect();
    quotes.sort_by_key(|q| q.fee_per_hour);
    quotes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(country: &str) -> tenzro_types::JurisdictionClaim {
        tenzro_types::JurisdictionClaim {
            country: country.into(),
            blocs: Vec::new(),
            attestation_hash: None,
            declared_at: tenzro_types::Timestamp(0),
        }
    }

    fn announcement(
        operator: u8,
        endpoint_id: &str,
        standby_models: &[&str],
        fee_per_hour: u128,
        country: &str,
    ) -> tenzro_network::ProviderAnnouncementMessage {
        tenzro_network::ProviderAnnouncementMessage {
            provider_address: hex::encode([operator; 32]),
            iroh_endpoint_id: endpoint_id.into(),
            capacity: tenzro_types::AdvertisedCapacity {
                standby_models: standby_models.iter().map(|m| m.to_string()).collect(),
                standby_fee_per_hour: fee_per_hour,
                jurisdiction: Some(claim(country)),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn standby_quotes_finds_a_live_holder_with_its_advertised_fee() {
        let anns = [announcement(0xb, "s", &["m1"], 100, "DE")];
        let quotes = standby_quotes_from(anns.iter(), "m1", "DE");
        assert_eq!(
            quotes,
            vec![StandbyQuote {
                operator: hex::encode([0xb; 32]),
                endpoint_id: "s".into(),
                fee_per_hour: 100,
            }]
        );
    }

    #[test]
    fn standby_quotes_excludes_what_does_not_match() {
        let anns = [
            // Holds a different model.
            announcement(0xb, "s1", &["other"], 100, "DE"),
            // Right model, wrong jurisdiction.
            announcement(0xc, "s2", &["m1"], 50, "FR"),
            // Right model and jurisdiction, but no endpoint to reach it on.
            announcement(0xd, "", &["m1"], 10, "DE"),
            // Not holding anything on standby at all.
            announcement(0xe, "s4", &[], 0, "DE"),
        ];
        assert!(standby_quotes_from(anns.iter(), "m1", "DE").is_empty());
    }

    #[test]
    fn standby_quotes_sort_cheapest_first() {
        let anns = [
            announcement(0xb, "expensive", &["m1"], 300, "DE"),
            announcement(0xc, "free", &["m1"], 0, "DE"),
            announcement(0xd, "mid", &["m1"], 100, "DE"),
        ];
        let fees: Vec<u128> = standby_quotes_from(anns.iter(), "m1", "DE")
            .iter()
            .map(|q| q.fee_per_hour)
            .collect();
        assert_eq!(fees, vec![0, 100, 300]);
    }
}
