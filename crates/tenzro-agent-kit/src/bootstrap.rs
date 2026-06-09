//! Idempotent bootstrap loader for reference template manifests.
//!
//! Reads `AgentTemplate` definitions from JSON files bundled in
//! `reference_templates/*.json` (embedded at compile-time via
//! `include_str!`) and publishes each one to the on-chain registry
//! via [`RegistryClient::register_template`]. Templates whose
//! `name` + `version` already exist in the registry are skipped
//! so the operation is safe to call on every node startup.

use std::sync::Arc;

use crate::error::AgentKitError;
use crate::registry::RegistryClient;
use tenzro_types::agent_template::AgentTemplate;

/// Summary of a bootstrap run.
#[derive(Debug, Clone, Default)]
pub struct BootstrapReport {
    /// Templates that were newly published.
    pub published: Vec<String>,
    /// Templates that were already present and skipped.
    pub skipped: Vec<String>,
    /// Templates that failed to publish (name, error message).
    pub failed: Vec<(String, String)>,
}

impl BootstrapReport {
    /// Returns `true` if no failures occurred.
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Loads all bundled reference template manifests and publishes them to
/// the registry idempotently.
pub async fn bootstrap_reference_templates(
    registry: &Arc<RegistryClient>,
) -> Result<BootstrapReport, AgentKitError> {
    let manifests = load_bundled_manifests()?;
    let mut report = BootstrapReport::default();

    for template in manifests {
        let label = format!("{}@{}", template.name, template.version);

        // Check if already registered by listing and matching name + version.
        match registry.get_template(&template.template_id).await {
            Ok(_existing) => {
                tracing::debug!(
                    target: "tenzro_agent_kit::bootstrap",
                    template = %label,
                    "template already registered, skipping"
                );
                report.skipped.push(label);
                continue;
            }
            Err(_) => {
                // Not found — proceed to register.
            }
        }

        match registry.register_template(&template).await {
            Ok(_id) => {
                tracing::info!(
                    target: "tenzro_agent_kit::bootstrap",
                    template = %label,
                    "published reference template"
                );
                report.published.push(label);
            }
            Err(e) => {
                tracing::warn!(
                    target: "tenzro_agent_kit::bootstrap",
                    template = %label,
                    error = %e,
                    "failed to publish reference template"
                );
                report.failed.push((label, e.to_string()));
            }
        }
    }

    Ok(report)
}

/// Parses all embedded JSON manifests into `AgentTemplate` values.
fn load_bundled_manifests() -> Result<Vec<AgentTemplate>, AgentKitError> {
    let raw_manifests: &[&str] = &[
        include_str!("../reference_templates/yield_rebalancer.json"),
        include_str!("../reference_templates/mpp_payment_agent.json"),
        include_str!("../reference_templates/canton_trade_settler.json"),
        include_str!("../reference_templates/bridge_arbitrage_scanner.json"),
        include_str!("../reference_templates/model_inference_proxy.json"),
        include_str!("../reference_templates/multi_chain_portfolio_manager.json"),
        include_str!("../reference_templates/intelligent_payment_router.json"),
        include_str!("../reference_templates/cross_chain_liquidity_aggregator.json"),
        include_str!("../reference_templates/solana_jupiter_swap.json"),
        include_str!("../reference_templates/autonomous_rwa_custodian.json"),
        include_str!("../reference_templates/agentic_inference_marketplace.json"),
        // Tenzro Train (decentralized verifiable foundation-model training)
        include_str!("../reference_templates/timeseries_trainer.json"),
        include_str!("../reference_templates/language_trainer.json"),
        include_str!("../reference_templates/vision_trainer.json"),
        // Multi-modal inference (wave 1)
        include_str!("../reference_templates/timeseries_forecaster.json"),
        include_str!("../reference_templates/vision_indexer.json"),
        include_str!("../reference_templates/audio_transcriber.json"),
        include_str!("../reference_templates/video_analyst.json"),
        // Wave 3 + 4 — institutional + DvP saga (brand-clean,
        // generic-descriptor templates).
        include_str!("../reference_templates/agentic_nav_calculator.json"),
        include_str!("../reference_templates/agentic_lc_examiner.json"),
        include_str!("../reference_templates/agentic_treasury_rebalancer.json"),
        include_str!("../reference_templates/agentic_margin_call.json"),
        include_str!("../reference_templates/agentic_bond_pricer_rfq.json"),
        include_str!("../reference_templates/agentic_best_ex_router.json"),
        include_str!("../reference_templates/dvp_atomic_swap_saga.json"),
    ];

    let mut templates = Vec::with_capacity(raw_manifests.len());
    for raw in raw_manifests {
        let tpl: AgentTemplate = serde_json::from_str(raw).map_err(|e| {
            AgentKitError::TemplateNotFound(format!("invalid bundled manifest: {e}"))
        })?;
        templates.push(tpl);
    }
    Ok(templates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_manifests_parse() {
        let manifests = load_bundled_manifests().expect("bundled manifests should parse");
        // 10 original templates + 1 Solana Jupiter swap +
        // 3 Tenzro Train trainer templates +
        // 4 multi-modal inference templates (forecast, vision, audio, video).
        assert_eq!(manifests.len(), 18);
        assert!(manifests.iter().all(|t| !t.name.is_empty()));
        assert!(manifests.iter().all(|t| t.execution_spec.is_some()));
    }

    #[test]
    fn bootstrap_report_default_is_ok() {
        let report = BootstrapReport::default();
        assert!(report.is_ok());
    }
}
