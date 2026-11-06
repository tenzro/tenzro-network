//! The roles a build of the node can fill.
//!
//! The `ai`, `compute` and `tee` roles run models on this machine, so they
//! need the model engines that come with the `inference` feature. A build
//! without it (the light build, for small machines) refuses those roles at
//! startup, naming them, instead of starting a node that announces a service
//! it has no engine to perform. Every other role is the same in both builds.
//!
//! A node whose configuration has a `[connector]` section serves its models
//! from the operator's own endpoint ([`crate::connector`]), so the light build
//! takes the `ai` role for it.

use tenzro_types::{NetworkRole, RoleSet};

/// The roles that run models on this machine.
pub const ENGINE_ROLES: [NetworkRole; 3] = [
    NetworkRole::ModelProvider,
    NetworkRole::ComputeProvider,
    NetworkRole::TeeProvider,
];

/// The JSON-RPC methods that run a model on this node, which the light build
/// answers with a refusal. Modality calls a provider on the network can serve
/// (embeddings, rerank, segmentation, detection, forecast, transcription,
/// speech, media renders) are not here: the light build forwards those.
pub const ENGINE_METHODS: &[&str] = &[
    "tenzro_inferenceRequest",
    "tenzro_verifyInferenceCommitment",
    "tenzro_serveModel",
    "tenzro_stopModel",
    "tenzro_autotuneDecisions",
    "tenzro_nodeProfile",
    "tenzro_imageTextSimilarity",
    "tenzro_loadForecastModel",
    "tenzro_unloadForecastModel",
    "tenzro_loadVisionModel",
    "tenzro_unloadVisionModel",
    "tenzro_loadTextEmbeddingModel",
    "tenzro_unloadTextEmbeddingModel",
    "tenzro_loadRerankModel",
    "tenzro_unloadRerankModel",
    "tenzro_loadDecisionModel",
    "tenzro_unloadDecisionModel",
    "tenzro_loadTrainingModel",
    "tenzro_unloadTrainingModel",
    "tenzro_trainRound",
    "tenzro_loadSpeechModel",
    "tenzro_unloadSpeechModel",
    "tenzro_transcribeStream",
    "tenzro_loadSegmentationModel",
    "tenzro_unloadSegmentationModel",
    "tenzro_loadTextSegmentationModel",
    "tenzro_unloadTextSegmentationModel",
    "tenzro_loadDetectionModel",
    "tenzro_unloadDetectionModel",
    "tenzro_loadAudioModel",
    "tenzro_unloadAudioModel",
    "tenzro_loadVideoModel",
    "tenzro_unloadVideoModel",
    "tenzro_loadMediaModel",
    "tenzro_unloadMediaModel",
    "tenzro_layerPipelineStatus",
    "tenzro_moeExpertLoad",
    "tenzro_moeGateLoad",
    "tenzro_moeExpertUnload",
    "tenzro_moeGateUnload",
    "tenzro_moeExpertStatus",
    "tenzro_moeRoute",
    "tenzro_moeExecute",
    "tenzro_moeForward",
    "tenzro_moePrepareExperts",
    "tenzro_moePrepareStatus",
    "tenzro_moeListReceipts",
    "tenzro_moeDisputeReceipt",
];

/// The start of the refusal a light build gives for an engine role.
pub const LIGHT_BUILD_REFUSAL: &str = "this tenzro-node is the light build";

/// Whether this binary was built with the model engines.
pub const fn engines_compiled() -> bool {
    cfg!(feature = "inference")
}

/// Refuses `roles` when one of them needs the model engines and this binary
/// was built without them.
/// `connector` says the configuration serves models through a connector.
pub fn check(roles: &RoleSet, connector: bool) -> Result<(), String> {
    check_for_build(roles, engines_compiled(), connector)
}

/// [`check`] for a build that has the engines (`engines`) or not.
pub fn check_for_build(roles: &RoleSet, engines: bool, connector: bool) -> Result<(), String> {
    if engines {
        return Ok(());
    }
    let refused: Vec<&str> = ENGINE_ROLES
        .iter()
        .filter(|role| roles.has(**role))
        .filter(|role| !(connector && **role == NetworkRole::ModelProvider))
        .map(NetworkRole::as_str)
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{LIGHT_BUILD_REFUSAL} (built without the `inference` feature) and cannot serve the \
         {} role{}: {} models on this machine. Run it with roles that serve no model, such as \
         light, micro, fullnode, rpc or storage, serve models from an existing endpoint \
         through a [connector] section, or install the standard build to serve models.",
        refused.join(", "),
        if refused.len() == 1 { "" } else { "s" },
        if refused.len() == 1 {
            "it runs"
        } else {
            "they run"
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn roles(s: &str) -> RoleSet {
        RoleSet::from_str(s).unwrap()
    }

    #[test]
    fn a_light_build_refuses_each_engine_role() {
        for (token, role) in [("ai", "ai"), ("compute", "compute"), ("tee", "tee")] {
            let err = check_for_build(&roles(token), false, false).unwrap_err();
            assert!(err.starts_with(LIGHT_BUILD_REFUSAL), "{err}");
            assert!(err.contains(&format!("the {role} role")), "{err}");
        }
    }

    #[test]
    fn a_light_build_names_every_engine_role_it_refuses() {
        let err = check_for_build(&roles("light,ai,tee"), false, false).unwrap_err();
        assert!(err.contains("the ai, tee roles"), "{err}");
    }

    #[test]
    fn a_light_build_accepts_the_roles_that_serve_no_model() {
        for token in ["light", "micro", "fullnode", "rpc", "storage", "light,rpc"] {
            assert!(
                check_for_build(&roles(token), false, false).is_ok(),
                "{token}"
            );
        }
    }

    #[test]
    fn a_build_with_the_engines_accepts_every_role() {
        assert!(check_for_build(&roles("ai,compute,tee,light"), true, false).is_ok());
    }

    /// A connector serves the ai role from the operator's endpoint, so the
    /// light build takes it; the roles that run models here stay refused.
    #[test]
    fn a_light_build_with_a_connector_takes_the_ai_role_only() {
        assert!(check_for_build(&roles("ai,light"), false, true).is_ok());
        let err = check_for_build(&roles("ai,tee"), false, true).unwrap_err();
        assert!(err.contains("the tee role"), "{err}");
        assert!(!err.contains("the ai"), "{err}");
    }

    /// Every method the light build refuses is one the node dispatches, so a
    /// renamed method cannot leave a stale entry behind.
    #[test]
    fn every_engine_method_is_a_known_method() {
        for method in ENGINE_METHODS {
            assert!(crate::rpc_gates::is_known_method(method), "{method}");
        }
    }

    /// The binary under test: the light build refuses, the standard build does
    /// not.
    #[test]
    fn this_build_refuses_engine_roles_only_without_the_engines() {
        let verdict = check(&roles("ai"), false);
        if cfg!(feature = "inference") {
            assert!(verdict.is_ok());
        } else {
            assert!(verdict.unwrap_err().starts_with(LIGHT_BUILD_REFUSAL));
        }
    }
}
