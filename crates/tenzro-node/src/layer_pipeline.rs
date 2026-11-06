//! One model served across several of an operator's own machines.
//!
//! The `[layer_pipeline]` table names a model and the machines that run it, in
//! order, each by its machine DID and the local-network address its stage
//! listens on. Every machine carries the same table and finds its place by its
//! own DID: the first loads the first blocks and serves the model through the
//! node's normal inference surfaces (text only); every other machine loads its
//! share of the blocks and serves its stage. Hidden states travel between the
//! machines; the weights never do.
//!
//! Only machines the operator approved take part: every DID in the table must
//! be an accepted member of this machine's cluster (an operator-approved list
//! that each member accepted with its own hardware key, see
//! [`crate::cluster_identity`]). Each link is authenticated by both ends
//! signing the handshake transcript with the hardware key their machine DID
//! derives from; the link's session keys come from an ephemeral exchange that
//! the signatures bind, so no key is distributed in advance and no key leaves
//! the TPM or Secure Enclave. A peer also proves membership on every handshake:
//! a DID outside the cluster is refused even if the table names it.
//!
//! A machine that fails or stops answering fails the request in flight with an
//! error naming its stage; the driver reconnects to the same machines on the
//! next request and never serves the model any other way.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_cluster::VerifiedMembership;
use tenzro_device_key::HardwareSigner;
#[cfg(feature = "inference")]
use tenzro_model::layer_pipeline::{
    LayerPipelinePlan, LayerRange, PipelineDriverOptions, PipelineStageOptions, StageAuthenticator,
    StageSpec, StageState, split_layers,
};
#[cfg(feature = "inference")]
use tenzro_model::runtime::ModelRuntime;
use tracing::{info, warn};

use crate::config::LayerPipelineConfig;

const DID_PREFIX: &str = "did:tenzro:machine:";
/// How long the driver waits between attempts while the other machines start.
const RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// Check a `[layer_pipeline]` table on its own (the model's block count is
/// checked when the plan is built from the weights).
///
/// # Errors
///
/// A description of the first problem.
pub fn check_config(c: &LayerPipelineConfig) -> Result<(), String> {
    if c.model_id.trim().is_empty() {
        return Err("model_id is empty".into());
    }
    if c.stages.len() < 2 {
        return Err("a pipeline needs at least two machines".into());
    }
    if c.micro_batch == 0 || c.context_length == 0 || c.answer_timeout_secs == 0 {
        return Err("micro_batch, context_length and answer_timeout_secs must be positive".into());
    }
    for (i, s) in c.stages.iter().enumerate() {
        if !s.machine_did.starts_with(DID_PREFIX) || s.machine_did.len() == DID_PREFIX.len() {
            return Err(format!("stage {i}: {} is not a machine DID", s.machine_did));
        }
        if c.stages[..i].iter().any(|o| o.machine_did == s.machine_did) {
            return Err(format!("stage {i}: {} appears twice", s.machine_did));
        }
        if i > 0
            && s.address
                .rsplit_once(':')
                .is_none_or(|(h, p)| h.is_empty() || p.parse::<u16>().is_err())
        {
            return Err(format!(
                "stage {i}: address {:?} is not host:port",
                s.address
            ));
        }
        if s.weight == Some(0) {
            return Err(format!("stage {i}: weight 0"));
        }
    }
    let named = c.stages.iter().filter(|s| s.layers.is_some()).count();
    if named != 0 && named != c.stages.len() {
        return Err("either every stage names its layers or none does".into());
    }
    Ok(())
}

/// The plan every machine computes from the same table and the same weights.
///
/// # Errors
///
/// Layer ranges that do not cover the model's blocks, or a plan that does not
/// validate.
#[cfg(feature = "inference")]
pub fn build_plan(
    c: &LayerPipelineConfig,
    model_digest: [u8; 32],
    n_layer: u32,
    n_embd: u32,
) -> Result<LayerPipelinePlan, String> {
    check_config(c)?;
    let ranges: Vec<LayerRange> = if c.stages.iter().all(|s| s.layers.is_some()) {
        c.stages
            .iter()
            .map(|s| {
                s.layers
                    .map(|[begin, end]| LayerRange { begin, end })
                    .unwrap_or(LayerRange { begin: 0, end: 0 })
            })
            .collect()
    } else {
        let weights: Vec<u64> = c.stages.iter().map(|s| s.weight.unwrap_or(1)).collect();
        split_layers(n_layer, &weights).map_err(|e| e.to_string())?
    };
    let plan = LayerPipelinePlan {
        model_digest,
        n_layer,
        n_embd,
        stages: c
            .stages
            .iter()
            .zip(ranges)
            .map(|(s, layers)| StageSpec {
                identity: s.machine_did.as_bytes().to_vec(),
                address: s.address.clone(),
                layers,
            })
            .collect(),
    };
    plan.validate().map_err(|e| e.to_string())?;
    Ok(plan)
}

/// Authenticates pipeline links with this machine's hardware identity key.
///
/// The identity is the machine DID. A signature is the signer's SEC1 public key
/// followed by its P-256 signature; it verifies for a DID only when the DID
/// derives from that key and the DID is a member of the cluster the pipeline
/// runs in.
#[cfg(feature = "inference")]
pub struct MachineStageAuth {
    did: String,
    signer: &'static dyn HardwareSigner,
    membership: VerifiedMembership,
}

#[cfg(feature = "inference")]
impl MachineStageAuth {
    /// An authenticator over `signer`, accepting peers of `membership`.
    ///
    /// # Errors
    ///
    /// The key cannot be read, or this machine is not in `membership`.
    pub fn new(
        signer: &'static dyn HardwareSigner,
        membership: VerifiedMembership,
    ) -> Result<Self, String> {
        let key = signer
            .public_key_sec1()
            .map_err(|e| format!("hardware key: {e}"))?;
        let did = tenzro_types::did_derivation::machine_did(&key);
        if !membership.contains(&did) {
            return Err(format!(
                "{did} is not a member of {}",
                membership.cluster_did()
            ));
        }
        Ok(Self {
            did,
            signer,
            membership,
        })
    }

    /// This machine's DID.
    pub fn did(&self) -> &str {
        &self.did
    }
}

#[cfg(feature = "inference")]
impl StageAuthenticator for MachineStageAuth {
    fn identity(&self) -> Vec<u8> {
        self.did.as_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.signer.public_key_sec1().map_err(|e| e.to_string())?;
        let signature = self.signer.sign(message).map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(key.len() + signature.len());
        out.extend_from_slice(&key);
        out.extend_from_slice(&signature);
        Ok(out)
    }

    fn verify(&self, identity: &[u8], message: &[u8], signature: &[u8]) -> bool {
        verify_machine_signature(&self.membership, identity, message, signature)
    }
}

/// Check a [`MachineStageAuth`] signature against the DID `identity` and the
/// cluster `membership`.
#[cfg(feature = "inference")]
pub fn verify_machine_signature(
    membership: &VerifiedMembership,
    identity: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(did) = std::str::from_utf8(identity) else {
        return false;
    };
    if signature.len() != 65 + 64 || !membership.contains(did) {
        return false;
    }
    let (key, sig) = signature.split_at(65);
    if tenzro_types::did_derivation::machine_did(key) != did {
        return false;
    }
    let digest: [u8; 32] = Sha256::digest(message).into();
    tenzro_device_key::signer::verify_p256_prehash(key, &digest, sig)
}

/// What this machine does in the pipeline, for the status RPC.
#[cfg(feature = "inference")]
#[derive(Debug, Clone)]
struct Status {
    model_id: String,
    index: usize,
    stages: usize,
    layers: LayerRange,
    plan_digest: [u8; 32],
    state: Option<Arc<RwLock<StageState>>>,
    error: Option<String>,
}

#[cfg(feature = "inference")]
static STATUS: RwLock<Option<Status>> = RwLock::new(None);

#[cfg(feature = "inference")]
fn set_error(model_id: &str, error: String) {
    warn!(model_id, %error, "layer pipeline");
    let mut s = STATUS.write();
    match s.as_mut() {
        Some(st) => st.error = Some(error),
        None => {
            *s = Some(Status {
                model_id: model_id.to_string(),
                index: usize::MAX,
                stages: 0,
                layers: LayerRange { begin: 0, end: 0 },
                plan_digest: [0; 32],
                state: None,
                error: Some(error),
            });
        }
    }
}

/// Everything the pipeline needs from the node, taken at startup.
#[cfg(feature = "inference")]
pub struct Context {
    pub runtime: Arc<ModelRuntime>,
    pub gguf_path: Option<std::path::PathBuf>,
    pub membership: Option<VerifiedMembership>,
    pub signer: Option<&'static dyn HardwareSigner>,
}

/// Start this machine's part of the configured pipeline in the background.
/// A machine the table does not name does nothing. Failures are logged and
/// reported by the status RPC; the driver keeps retrying until every stage
/// answers.
#[cfg(feature = "inference")]
pub fn spawn(config: LayerPipelineConfig, ctx: Context) {
    tokio::spawn(async move {
        if let Err(e) = run(&config, ctx).await {
            set_error(&config.model_id, e);
        }
    });
}

#[cfg(feature = "inference")]
async fn run(config: &LayerPipelineConfig, ctx: Context) -> Result<(), String> {
    let signer = ctx
        .signer
        .ok_or("this machine has no TPM or Secure Enclave identity key")?;
    let key = signer
        .public_key_sec1()
        .map_err(|e| format!("hardware key: {e}"))?;
    let own_did = tenzro_types::did_derivation::machine_did(&key);
    let Some(index) = config.stages.iter().position(|s| s.machine_did == own_did) else {
        info!(did = %own_did, "this machine is not part of the configured layer pipeline");
        return Ok(());
    };
    let membership = ctx.membership.ok_or(
        "this machine holds no accepted cluster membership; a layer pipeline runs only within one",
    )?;
    if let Some(outsider) = config
        .stages
        .iter()
        .find(|s| !membership.contains(&s.machine_did))
    {
        return Err(format!(
            "{} is not a member of {}",
            outsider.machine_did,
            membership.cluster_did()
        ));
    }
    let auth: Arc<dyn StageAuthenticator> = Arc::new(MachineStageAuth::new(signer, membership)?);

    let model_id = config.model_id.as_str();
    let gguf = ctx.gguf_path.ok_or_else(|| {
        format!(
            "{model_id} is not downloaded on this machine; download it before serving the pipeline"
        )
    })?;
    let shape_path = gguf.clone();
    let shape = tokio::task::spawn_blocking(move || {
        tenzro_model::gguf_shape::read_model_shape(&shape_path)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("reading {}: {e}", gguf.display()))?;
    let digest = ctx
        .runtime
        .weights_digest(model_id, &gguf)
        .await
        .map_err(|e| e.to_string())?;
    let plan = build_plan(config, digest, shape.layers, shape.hidden_dim)?;
    let layers = plan.stages[index].layers;
    *STATUS.write() = Some(Status {
        model_id: model_id.to_string(),
        index,
        stages: plan.stages.len(),
        layers,
        plan_digest: plan.digest(),
        state: None,
        error: None,
    });

    let stage_opts = PipelineStageOptions {
        n_ctx: config.context_length,
        max_rows: config.micro_batch,
        n_seq_max: 1,
        n_threads: None,
        connect_timeout: Duration::from_secs(10),
    };
    if index > 0 {
        let address = config.stages[index].address.clone();
        let state = ctx
            .runtime
            .serve_pipeline_stage(
                model_id,
                &gguf,
                plan,
                index,
                address.clone(),
                auth,
                stage_opts,
            )
            .await
            .map_err(|e| e.to_string())?;
        info!(model_id, index, %address, begin = layers.begin, end = layers.end, "serving layer-pipeline stage");
        if let Some(s) = STATUS.write().as_mut() {
            s.state = Some(state);
        }
        return Ok(());
    }

    let opts = PipelineDriverOptions {
        stage: stage_opts,
        max_in_flight: 8,
        answer_timeout: Duration::from_secs(config.answer_timeout_secs),
    };
    loop {
        match ctx
            .runtime
            .load_model_pipelined(
                model_id,
                &gguf,
                plan.clone(),
                Arc::clone(&auth),
                opts.clone(),
            )
            .await
        {
            Ok(()) => {
                info!(
                    model_id,
                    stages = plan.stages.len(),
                    "serving model across a layer pipeline"
                );
                if let Some(s) = STATUS.write().as_mut() {
                    s.error = None;
                }
                return Ok(());
            }
            Err(e) => {
                set_error(
                    model_id,
                    format!("{e}; retrying in {}s", RETRY_INTERVAL.as_secs()),
                );
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// `tenzro_layerPipelineStatus`: what this machine does in the configured
/// pipeline.
#[cfg(feature = "inference")]
pub fn status_json(runtime: Option<&Arc<ModelRuntime>>) -> Value {
    let machine_did = crate::identity_bootstrap::machine_did();
    let Some(st) = STATUS.read().clone() else {
        return json!({ "configured": false, "machine_did": machine_did });
    };
    let state = if st.index == 0 {
        runtime
            .and_then(|r| r.pipeline_driver(&st.model_id))
            .map(|d| serde_json::to_value(d.state()).unwrap_or(Value::Null))
            .unwrap_or_else(|| json!({ "state": "connecting" }))
    } else {
        st.state
            .as_ref()
            .map(|s| serde_json::to_value(&*s.read()).unwrap_or(Value::Null))
            .unwrap_or_else(|| json!({ "state": "loading" }))
    };
    json!({
        "configured": true,
        "machine_did": machine_did,
        "model_id": st.model_id,
        "role": if st.index == 0 { "driver" } else { "stage" },
        "stage": if st.index == usize::MAX { Value::Null } else { json!(st.index) },
        "stages": st.stages,
        "layers": [st.layers.begin, st.layers.end],
        "plan_digest": hex::encode(st.plan_digest),
        "state": state,
        "error": st.error,
    })
}

#[cfg(all(test, feature = "inference"))]
mod tests {
    use super::*;
    use crate::config::LayerPipelineStage;

    fn stage(did: &str, address: &str, layers: Option<[u32; 2]>) -> LayerPipelineStage {
        LayerPipelineStage {
            machine_did: did.into(),
            address: address.into(),
            layers,
            weight: None,
        }
    }

    fn config(stages: Vec<LayerPipelineStage>) -> LayerPipelineConfig {
        LayerPipelineConfig {
            model_id: "m".into(),
            stages,
            micro_batch: 32,
            context_length: 4096,
            answer_timeout_secs: 60,
        }
    }

    fn proof(key: &tenzro_cluster::membership::testing::Key, message: &[u8]) -> Vec<u8> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        let mut out = key.public();
        out.extend(key.sign(&digest));
        out
    }

    #[test]
    fn a_link_signature_verifies_only_for_a_member_whose_did_derives_from_the_key() {
        use tenzro_cluster::membership::testing::{Key, RP_ID, custody_digest, membership};
        let (operator, a, b, outsider) = (Key::new(1), Key::new(2), Key::new(3), Key::new(4));
        let members = VerifiedMembership::verify(
            membership(&operator, "lab", 1, &[&a, &b]),
            RP_ID,
            custody_digest,
        )
        .unwrap();
        let msg = b"transcript";
        let a_did = a.machine_did();

        assert!(verify_machine_signature(
            &members,
            a_did.as_bytes(),
            msg,
            &proof(&a, msg)
        ));
        // another message, another member's key, or a forged signature
        assert!(!verify_machine_signature(
            &members,
            a_did.as_bytes(),
            b"other",
            &proof(&a, msg)
        ));
        assert!(!verify_machine_signature(
            &members,
            a_did.as_bytes(),
            msg,
            &proof(&b, msg)
        ));
        let mut forged = proof(&a, msg);
        *forged.last_mut().unwrap() ^= 1;
        assert!(!verify_machine_signature(
            &members,
            a_did.as_bytes(),
            msg,
            &forged
        ));
        // a valid signature by a machine outside the cluster
        let out_did = outsider.machine_did();
        assert!(!verify_machine_signature(
            &members,
            out_did.as_bytes(),
            msg,
            &proof(&outsider, msg)
        ));
        // truncated
        assert!(!verify_machine_signature(
            &members,
            a_did.as_bytes(),
            msg,
            &proof(&a, msg)[..100]
        ));
    }

    #[test]
    fn config_rejects_bad_tables() {
        let ok = config(vec![
            stage("did:tenzro:machine:a", "", None),
            stage("did:tenzro:machine:b", "10.0.0.2:7300", None),
        ]);
        check_config(&ok).unwrap();
        let mut c = ok.clone();
        c.stages.truncate(1);
        assert!(check_config(&c).is_err());
        let mut c = ok.clone();
        c.stages[1].address = "10.0.0.2".into();
        assert!(check_config(&c).is_err());
        let mut c = ok.clone();
        c.stages[1].machine_did = "did:tenzro:human:b".into();
        assert!(check_config(&c).is_err());
        let mut c = ok.clone();
        c.stages[1].machine_did = c.stages[0].machine_did.clone();
        assert!(check_config(&c).is_err());
        let mut c = ok.clone();
        c.stages[0].layers = Some([0, 4]);
        assert!(
            check_config(&c).is_err(),
            "layers named on some stages only"
        );
    }

    #[test]
    fn plan_uses_named_layers_or_weights_and_binds_the_dids() {
        let named = config(vec![
            stage("did:tenzro:machine:a", "", Some([0, 10])),
            stage("did:tenzro:machine:b", "10.0.0.2:7300", Some([10, 28])),
        ]);
        let plan = build_plan(&named, [1; 32], 28, 1024).unwrap();
        assert_eq!(plan.stages[1].layers, LayerRange { begin: 10, end: 28 });
        assert_eq!(plan.stages[1].identity, b"did:tenzro:machine:b".to_vec());
        assert!(
            build_plan(&named, [1; 32], 30, 1024).is_err(),
            "ranges must cover the model"
        );

        let mut weighted = config(vec![
            stage("did:tenzro:machine:a", "", None),
            stage("did:tenzro:machine:b", "h:1", None),
        ]);
        weighted.stages[0].weight = Some(3);
        let plan = build_plan(&weighted, [1; 32], 28, 1024).unwrap();
        assert_eq!(plan.stages[0].layers, LayerRange { begin: 0, end: 21 });
        assert_eq!(plan.stages[1].layers, LayerRange { begin: 21, end: 28 });
    }
}
