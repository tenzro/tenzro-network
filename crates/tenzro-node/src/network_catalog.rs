//! Hands the live network model-offer set to intent routing.
//!
//! Providers broadcast signed [`ModelRegistrationMessage`]s on `tenzro/models`
//! carrying the model's modality, capabilities, context length, the provider's
//! own price, a serving schedule, a TTL, and the address that serves the call.
//! The event loop verifies each announcement, pins the signing key per
//! `(model_id, provider)` pair, and keeps the unexpired set in
//! [`crate::node::NetworkModelEntry`] records.
//!
//! [`tenzro_model::meta_router::MetaRouter`] scores candidates over its own
//! catalog, which is whatever this operator registered locally. Without this
//! adapter it never sees what the rest of the network is serving, so intent
//! routing would depend on per-node curation. Implementing
//! [`NetworkCatalog`] over the announcement map makes every live offer a
//! candidate scored on the price and capabilities its provider signed — and
//! because the offer names its own payee, the settlement split follows from the
//! winning offer instead of node configuration.
//!
//! The adapter holds the announcement map directly rather than an
//! `Arc<TenzroNode>`, so attaching it to the router the node owns creates no
//! reference cycle.

use std::sync::Arc;

use chrono::{Datelike, Timelike, Utc};
use dashmap::DashMap;
use tenzro_model::catalog::parse_params_active_b;
use tenzro_model::meta_router::{ModelOffer, NetworkCatalog};
use tenzro_network::{ModelRegistrationMessage, ModelSchedule};
use tenzro_types::model::{
    ModalityRates, ModelInfo, ModelModality, ModelStatus, PricingConfig, PricingModel,
};
use tenzro_types::primitives::Address;

use crate::node::NetworkModelEntry;

/// [`NetworkCatalog`] over the gossip announcement map. See module docs.
pub struct GossipNetworkCatalog {
    models: Arc<DashMap<String, NetworkModelEntry>>,
}

impl GossipNetworkCatalog {
    /// Wraps the node's announcement map.
    pub fn new(models: Arc<DashMap<String, NetworkModelEntry>>) -> Self {
        Self { models }
    }
}

impl NetworkCatalog for GossipNetworkCatalog {
    fn live_offers(&self, modality: ModelModality) -> Vec<ModelOffer> {
        let now = std::time::Instant::now();
        self.models
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.registration.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .filter_map(|entry| {
                let reg = &entry.registration;
                if reg.withdrawn || reg.rpc_endpoint.is_empty() {
                    return None;
                }
                if !schedule_admits(reg.schedule.as_ref()) {
                    return None;
                }
                let model = offer_model(reg)?;
                // Compound modalities are supersets of their components, so
                // `supports` — not equality — decides whether an offer can
                // serve the intent.
                if !model.modality.supports(modality) {
                    return None;
                }
                Some(ModelOffer {
                    model,
                    endpoint: reg.rpc_endpoint.clone(),
                })
            })
            .collect()
    }
}

/// Whether the provider's serving schedule admits a call right now. An offer
/// with no schedule, or with scheduling switched off, is always available.
fn schedule_admits(schedule: Option<&ModelSchedule>) -> bool {
    let Some(s) = schedule else {
        return true;
    };
    if !s.enabled {
        return true;
    }
    let now = Utc::now();
    // `days_of_week` is 0=Sunday on the wire.
    let today = now.weekday().num_days_from_sunday() as u8;
    if !s.days_of_week.contains(&today) {
        return false;
    }
    let hour = now.hour() as u8;
    hour >= s.start_hour && hour < s.end_hour
}

/// Projects an announcement into the [`ModelInfo`] shape scoring reads.
///
/// Returns `None` for an announcement whose provider address or modality does
/// not parse — an offer that cannot name its payee is not payable, and one
/// whose modality is unknown cannot be matched to an intent.
fn offer_model(reg: &ModelRegistrationMessage) -> Option<ModelInfo> {
    let provider = Address::from_hex(&reg.provider).ok()?;
    let modality = parse_modality(&reg.modality)?;

    let mut model = ModelInfo::new(
        reg.model_id.clone(),
        reg.name.clone(),
        String::new(),
        modality,
        provider,
    );
    model.description = reg.description.clone();
    // Announced offers are live by construction: the provider is serving the
    // model now and refreshes the announcement within its TTL.
    model.status = ModelStatus::Active;

    let active_b = parse_params_active_b(&reg.parameters);
    if active_b > 0.0 {
        model.parameters.parameter_count = Some((active_b * 1e9) as u64);
    }
    if reg.context_length > 0 {
        model.parameters.context_window = reg.context_length;
    }
    // The category is what the provider says the model is for ("chat",
    // "embedding", "code", …), which is the axis quality tiering reads
    // capabilities on.
    if !reg.category.is_empty() {
        model.parameters.capabilities.push(reg.category.clone());
    }

    // The provider's own advertised rate. `per_token` prices input and output
    // alike — the announcement carries one token rate, not a split — and
    // `per_request` is the floor the provider charges regardless of length.
    model.pricing = announced_pricing(&reg.pricing);

    Some(model)
}

/// Projects an announced rate card into the [`PricingConfig`] the meter reads.
///
/// An announcement carries one token rate — it does not split input from output
/// — and a flat per-request floor. Every other billable dimension reads as
/// unpriced: falling back to [`ModalityRates::default`] would quote a caller for
/// audio seconds or denoising steps at a rate the provider never advertised, in
/// a different unit scale. A provider that wants to charge those dimensions
/// prices them on the service row it serves the call from.
///
/// The flat charge lands in both `minimum_price` and
/// [`ModalityRates::price_per_request`] because the two are read by different
/// arms of the meter: the former floors a metered quote, the latter *is* the
/// quote under [`PricingModel::PerRequest`].
pub fn announced_pricing(pricing: &tenzro_network::PricingInfo) -> PricingConfig {
    let per_token = pricing.per_token.unwrap_or(0);
    PricingConfig {
        price_per_input_token: per_token,
        price_per_output_token: per_token,
        minimum_price: pricing.per_request,
        pricing_model: if per_token > 0 {
            PricingModel::PerToken
        } else {
            PricingModel::PerRequest
        },
        modality_rates: ModalityRates {
            price_per_request: pricing.per_request,
            ..ModalityRates::unpriced()
        },
    }
}

/// Parses the announcement's modality string. Specialized task names collapse
/// onto the modality that carries them, matching how the catalog and the model
/// registry classify the same families.
fn parse_modality(s: &str) -> Option<ModelModality> {
    match s.to_lowercase().as_str() {
        "text" | "text-embedding" | "text_embedding" | "embedding" => Some(ModelModality::Text),
        "image" | "segmentation" | "segment" | "detection" | "detect" => {
            Some(ModelModality::Image)
        }
        "audio" => Some(ModelModality::Audio),
        "timeseries" | "ts" => Some(ModelModality::Timeseries),
        "video" => Some(ModelModality::Video),
        "text_image" | "textimage" => Some(ModelModality::TextImage),
        "text_audio" | "textaudio" => Some(ModelModality::TextAudio),
        "multimodal" => Some(ModelModality::Multimodal),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement() -> ModelRegistrationMessage {
        ModelRegistrationMessage {
            model_id: "qwen3-8b".to_string(),
            name: "Qwen3 8B".to_string(),
            modality: "text".to_string(),
            category: "chat".to_string(),
            parameters: "8B".to_string(),
            context_length: 32_768,
            provider: hex::encode([7u8; 32]),
            pricing: tenzro_network::PricingInfo {
                per_request: 500,
                per_token: Some(12),
            },
            ttl_secs: 120,
            rpc_endpoint: "http://10.0.0.4:8545".to_string(),
            ..Default::default()
        }
    }

    fn catalog(entries: Vec<ModelRegistrationMessage>) -> GossipNetworkCatalog {
        let map = Arc::new(DashMap::new());
        for (i, reg) in entries.into_iter().enumerate() {
            map.insert(
                format!("{}:{i}", reg.model_id),
                NetworkModelEntry {
                    registration: reg,
                    last_seen: std::time::Instant::now(),
                },
            );
        }
        GossipNetworkCatalog::new(map)
    }

    #[test]
    fn announcement_becomes_a_priced_offer_naming_its_payee() {
        let offers = catalog(vec![announcement()]).live_offers(ModelModality::Text);
        assert_eq!(offers.len(), 1);
        let offer = &offers[0];
        assert_eq!(offer.endpoint, "http://10.0.0.4:8545");
        assert_eq!(offer.model.provider, Address::new([7u8; 32]));
        assert_eq!(offer.model.pricing.price_per_input_token, 12);
        assert_eq!(offer.model.pricing.minimum_price, 500);
        assert_eq!(offer.model.parameters.context_window, 32_768);
        assert_eq!(offer.model.parameters.parameter_count, Some(8_000_000_000));
        assert_eq!(offer.model.status, ModelStatus::Active);
    }

    #[test]
    fn two_providers_of_one_model_are_two_offers() {
        let mut cheap = announcement();
        cheap.provider = hex::encode([8u8; 32]);
        cheap.pricing.per_token = Some(3);
        cheap.rpc_endpoint = "http://10.0.0.5:8545".to_string();

        let offers = catalog(vec![announcement(), cheap]).live_offers(ModelModality::Text);
        assert_eq!(offers.len(), 2);
        assert!(offers.iter().any(|o| o.model.pricing.price_per_input_token == 12));
        assert!(offers.iter().any(|o| o.model.pricing.price_per_input_token == 3));
    }

    #[test]
    fn withdrawn_endpointless_and_off_modality_offers_are_dropped() {
        let mut withdrawn = announcement();
        withdrawn.withdrawn = true;
        let mut endpointless = announcement();
        endpointless.rpc_endpoint = String::new();
        let mut unparseable_provider = announcement();
        unparseable_provider.provider = "not-an-address".to_string();

        let c = catalog(vec![withdrawn, endpointless, unparseable_provider, announcement()]);
        assert_eq!(c.live_offers(ModelModality::Text).len(), 1);
        assert!(c.live_offers(ModelModality::Audio).is_empty());
    }

    #[test]
    fn expired_announcements_are_dropped() {
        let map = Arc::new(DashMap::new());
        let mut reg = announcement();
        reg.ttl_secs = 0;
        map.insert(
            "qwen3-8b:0".to_string(),
            NetworkModelEntry {
                registration: reg,
                last_seen: std::time::Instant::now(),
            },
        );
        assert!(
            GossipNetworkCatalog::new(map)
                .live_offers(ModelModality::Text)
                .is_empty()
        );
    }

    #[test]
    fn a_disabled_schedule_never_blocks_an_offer() {
        let mut reg = announcement();
        reg.schedule = Some(ModelSchedule {
            enabled: false,
            start_hour: 9,
            end_hour: 10,
            timezone: "UTC".to_string(),
            days_of_week: vec![],
        });
        assert_eq!(catalog(vec![reg]).live_offers(ModelModality::Text).len(), 1);
    }

    #[test]
    fn a_schedule_excluding_today_blocks_the_offer() {
        let today = Utc::now().weekday().num_days_from_sunday() as u8;
        let mut reg = announcement();
        reg.schedule = Some(ModelSchedule {
            enabled: true,
            start_hour: 0,
            end_hour: 24,
            timezone: "UTC".to_string(),
            days_of_week: (0u8..7).filter(|d| *d != today).collect(),
        });
        assert!(
            catalog(vec![reg])
                .live_offers(ModelModality::Text)
                .is_empty()
        );
    }

    #[test]
    fn a_multimodal_offer_serves_a_text_intent() {
        let mut reg = announcement();
        reg.modality = "multimodal".to_string();
        assert_eq!(catalog(vec![reg]).live_offers(ModelModality::Text).len(), 1);
    }
}
