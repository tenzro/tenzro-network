//! Training: `tenzro_loadTrainingModel`, `tenzro_unloadTrainingModel` and
//! `tenzro_trainRound`.
//!
//! Training is compute the operator sells, like serving. A node loads a
//! downloaded catalog model for training on its CUDA device
//! ([`tenzro_model::training_runtime`]) and runs supervised `LoRA` rounds on
//! it. A round is metered in trained tokens against the node's rate card,
//! answered with a signed receipt, and its products (the adapter, the state
//! it ended at, the step log) are put in the node's content store.
//!
//! Every round also answers with `result_digest` ([`round_result_digest`])
//! and this machine's attestation of it, in the form of the network's
//! existing signed-reading evidence: the machine's hardware identity key
//! signs [`sensor_reading_digest`] over `result_digest`, so
//! `tenzro_verifyEvidence` checks it against the key the machine registered
//! (`sensor_data`). Rounds run in deterministic mode, so a second machine of
//! the same kernel class that replays the round with the same inputs reaches
//! the same digest; an application that pays per round (a task whose
//! milestones are rounds) releases a milestone when the attestations of two
//! machines over the same digest both verify. A round paid through a
//! milestone escrow can instead be committed on chain as a signed training
//! receipt (the training proof transaction,
//! [`tenzro_types::training_verification`]): anyone may challenge it, a
//! verifier replays sampled steps, and the milestone is released only after
//! the challenge window closes without an upheld fault.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_model::training_runtime::{
    LoraRecipe, RoundRequest, RoundResult, RoundStart, TextRecord, records_digest,
};
use tenzro_types::evidence::{Evidence, sensor_reading_digest};
use tenzro_types::model::BillableUnits;

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, bill_local_units, forecast_err, missing_param, units_to_json};
use crate::verifiable_inference::{attach_task_receipt, task_level};

/// Domain of [`round_result_digest`].
pub const TRAINING_ROUND_DOMAIN: &[u8] = b"tenzro/training/round/v1";

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn failed(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

fn hex32(v: &Value, name: &str) -> Result<[u8; 32], JsonRpcError> {
    v.as_str()
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid(format!("'{name}' is 32 bytes of hex")))
}

/// What a round's two replays agree on: the model, its weights, the shard as
/// the job stated it, the round's own commitment (base weights, tokenized
/// shard, recipe, seed, kernel class, steps, start and end state, step log)
/// and the adapter it produced.
pub fn round_result_digest(model_id: &str, r: &RoundResult, records_sha256: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(TRAINING_ROUND_DOMAIN)
        .chain_update((model_id.len() as u32).to_le_bytes())
        .chain_update(model_id.as_bytes())
        .chain_update(r.base_sha256)
        .chain_update(records_sha256)
        .chain_update(r.commitment)
        .chain_update(r.adapter_sha256)
        .finalize()
        .into()
}

/// This machine's attestation of `result_digest`, signed by its hardware
/// identity key as a reading it measured: a `sensor_data` evidence item.
async fn attest(result_digest: [u8; 32]) -> Result<Evidence, JsonRpcError> {
    let measured_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    tokio::task::spawn_blocking(move || {
        use tenzro_crypto::HybridSigner as _;
        let signer = tenzro_device_key::HardwareHybridSigner::open_or_create(
            tenzro_types::did_derivation::MACHINE_KEY_LABEL,
        )
        .map_err(|e| format!("this machine has no hardware identity key: {e}"))?;
        let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
        let device_did = tenzro_types::did_derivation::machine_did(&sec1);
        let signature = signer
            .sign(
                tenzro_crypto::SignatureContext::SensorReading,
                &sensor_reading_digest(&device_did, &result_digest, measured_at_ms),
            )
            .map_err(|e| format!("signing the round's result: {e}"))?;
        Ok::<_, String>(Evidence::SensorData {
            device_did,
            payload_digest: result_digest,
            measured_at_ms,
            signature,
        })
    })
    .await
    .map_err(|e| failed(format!("attestation task: {e}")))?
    .map_err(failed)
}

/// `tenzro_loadTrainingModel { model_id }`: load a downloaded catalog
/// language model for training on this node's CUDA device. The model is
/// fetched through the catalog first (`tenzro model download`).
pub(crate) async fn handle_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?
        .to_string();
    tenzro_model::get_model_by_id(&model_id)
        .ok_or_else(|| invalid(format!("{model_id} is not a language model in the catalog")))?;
    let path = node
        .hf_downloader
        .as_ref()
        .map(|d| d.model_path(&model_id))
        .filter(|p| p.exists())
        .ok_or_else(|| {
            invalid(format!(
                "{model_id} is not downloaded on this node: fetch it from the catalog with `tenzro model download`"
            ))
        })?;
    let rt = node.training_runtime.clone();
    let id = model_id.clone();
    tokio::task::spawn_blocking(move || rt.load(&id, &path))
        .await
        .map_err(|e| failed(format!("training load task: {e}")))?
        .map_err(forecast_err)?;
    Ok(json!({ "model_id": model_id, "loaded": true }))
}

/// `tenzro_unloadTrainingModel { model_id }`.
pub(crate) async fn handle_unload(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let removed = node.training_runtime.unload(model_id);
    Ok(json!({ "model_id": model_id, "removed": removed }))
}

/// Where a round starts, from its params: fresh weights from
/// `adapter_seed`, or `start: { state_uri, start_root, steps_taken }`, the
/// state a previous round ended at, fetched by content and checked against
/// the root that round committed to.
async fn round_start(node: &Arc<TenzroNode>, p: &Value) -> Result<RoundStart, JsonRpcError> {
    let adapter_seed = p
        .get("adapter_seed")
        .and_then(Value::as_u64)
        .ok_or_else(|| missing_param("adapter_seed"))?;
    let Some(start) = p.get("start").filter(|v| !v.is_null()) else {
        return Ok(RoundStart::Fresh { adapter_seed });
    };
    let uri = start
        .get("state_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("start.state_uri"))?;
    let root = hex32(
        start
            .get("start_root")
            .ok_or_else(|| missing_param("start.start_root"))?,
        "start.start_root",
    )?;
    let steps_taken = start
        .get("steps_taken")
        .and_then(Value::as_u64)
        .ok_or_else(|| missing_param("start.steps_taken"))?;
    let uri = tenzro_types::tenzro_uri::TenzroUri::parse(uri)
        .map_err(|e| invalid(format!("start.state_uri: {e}")))?;
    let resolver = node
        .iroh_resolver
        .as_ref()
        .ok_or_else(|| failed("this node has no content store to fetch the starting state from"))?;
    let state = {
        use tenzro_iroh::IrohResolver as _;
        resolver
            .fetch_bytes(&uri)
            .await
            .map_err(|e| failed(format!("fetching the starting state: {e}")))?
            .to_vec()
    };
    let held = praecise_train_root(&state)?;
    if held != root {
        return Err(invalid(format!(
            "the starting state's root is {}, not the {} the previous round committed to",
            hex::encode(held),
            hex::encode(root)
        )));
    }
    Ok(RoundStart::Resume {
        adapter_seed,
        state,
        steps_taken,
    })
}

fn praecise_train_root(state: &[u8]) -> Result<[u8; 32], JsonRpcError> {
    tenzro_model::training_runtime::state_root(state)
        .map_err(|e| invalid(format!("start state: {e}")))
}

async fn publish(
    node: &Arc<TenzroNode>,
    bytes: Vec<u8>,
    what: &str,
) -> Result<String, JsonRpcError> {
    use tenzro_iroh::IrohResolver as _;
    let resolver = node
        .iroh_resolver
        .as_ref()
        .ok_or_else(|| failed(format!("this node has no content store to hold the {what}")))?;
    let uri = resolver
        .publish_bytes(bytes.into())
        .await
        .map_err(|e| failed(format!("storing the {what}: {e}")))?;
    Ok(uri.to_string())
}

/// `tenzro_trainRound`: run one supervised `LoRA` round.
///
/// Params: `{ model_id, recipe, records: [{ prompt, completion }],
/// sample_seed, steps, adapter_seed, start?: { state_uri, start_root,
/// steps_taken }, verification?, receipt_nonce?, payment?, channel_voucher? }`.
/// Answers with the round's commitment and roots, each step's loss, the
/// adapter's SHA-256 and content URI, the ending state's URI, the step log's
/// URI, `result_digest` with this machine's `attestation`, the units billed,
/// the cost, the settlement and the signed receipt.
pub(crate) async fn handle_round(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?
        .to_string();
    if !node.training_runtime.contains(&model_id) {
        return Err(invalid(format!(
            "{model_id} is not loaded for training on this node (tenzro_loadTrainingModel)"
        )));
    }
    let recipe: LoraRecipe = serde_json::from_value(
        p.get("recipe")
            .cloned()
            .ok_or_else(|| missing_param("recipe"))?,
    )
    .map_err(|e| invalid(format!("'recipe': {e}")))?;
    let records: Vec<TextRecord> = serde_json::from_value(
        p.get("records")
            .cloned()
            .ok_or_else(|| missing_param("records"))?,
    )
    .map_err(|e| invalid(format!("'records': {e}")))?;
    let sample_seed = p
        .get("sample_seed")
        .and_then(Value::as_u64)
        .ok_or_else(|| missing_param("sample_seed"))?;
    let steps = p
        .get("steps")
        .and_then(Value::as_u64)
        .ok_or_else(|| missing_param("steps"))?;
    let level = task_level(node, &p, &model_id)?;
    let start = round_start(node, &p).await?;
    let records_sha256 = records_digest(&records);
    let bytes_in = serde_json::to_vec(&records).map_or(0, |b| b.len() as u64);

    let started = Instant::now();
    let result = node
        .training_runtime
        .run_round(
            &model_id,
            RoundRequest {
                recipe,
                records,
                sample_seed,
                steps,
                start,
            },
        )
        .await
        .map_err(forecast_err)?;
    let latency_ms = started.elapsed().as_millis() as u64;

    let result_digest = round_result_digest(&model_id, &result, &records_sha256);
    let attestation = attest(result_digest).await?;
    let adapter_uri = publish(node, result.adapter.clone(), "adapter").await?;
    let state_uri = publish(node, result.state.clone(), "state").await?;
    let log_uri = publish(node, result.log.clone(), "step log").await?;

    let units = BillableUnits::default().with_trained_tokens(result.trained_tokens);
    let bytes_out = (result.adapter.len() + result.state.len()) as u64;
    let (cost_wei, settlement) = bill_local_units(
        node,
        &p,
        &model_id,
        units.clone(),
        bytes_in,
        bytes_out,
        latency_ms,
    )
    .await?;

    let mut out = json!({
        "model_id": model_id,
        "base_sha256": hex::encode(result.base_sha256),
        "records_sha256": hex::encode(records_sha256),
        "data_root": hex::encode(result.data_root),
        "recipe_hash": hex::encode(result.recipe_hash),
        "kernel_class": result.kernel_class,
        "first_step": result.first_step,
        "steps": result.steps,
        "start_root": hex::encode(result.start_root),
        "end_root": hex::encode(result.end_root),
        "log_head": hex::encode(result.log_head),
        "commitment": hex::encode(result.commitment),
        "losses": result.losses,
        "adapter_sha256": hex::encode(result.adapter_sha256),
        "adapter_uri": adapter_uri,
        "state_uri": state_uri,
        "log_uri": log_uri,
        "result_digest": hex::encode(result_digest),
        "attestation": attestation,
    });
    attach_task_receipt(
        node,
        &p,
        &model_id,
        "training",
        level,
        units.clone(),
        &mut out,
    )
    .await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".into(), units_to_json(&units));
        obj.insert("cost_wei".into(), json!(cost_wei.to_string()));
        obj.insert("settlement".into(), settlement.to_json());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result() -> RoundResult {
        RoundResult {
            commitment: [1; 32],
            base_sha256: [2; 32],
            data_root: [3; 32],
            recipe_hash: [4; 32],
            kernel_class: "cuda/x/ks1".into(),
            first_step: 0,
            steps: 2,
            start_root: [5; 32],
            end_root: [6; 32],
            log_head: [7; 32],
            log: vec![],
            losses: vec![2.0, 1.0],
            state: vec![],
            adapter: vec![],
            adapter_sha256: [8; 32],
            trained_tokens: 256,
        }
    }

    #[test]
    fn the_result_digest_binds_model_weights_shard_commitment_and_adapter() {
        let r = result();
        let d = round_result_digest("m", &r, &[9; 32]);
        assert_eq!(d, round_result_digest("m", &r, &[9; 32]));
        assert_ne!(d, round_result_digest("n", &r, &[9; 32]));
        assert_ne!(d, round_result_digest("m", &r, &[0; 32]));
        for changed in [
            RoundResult {
                commitment: [0; 32],
                ..result()
            },
            RoundResult {
                base_sha256: [0; 32],
                ..result()
            },
            RoundResult {
                adapter_sha256: [0; 32],
                ..result()
            },
        ] {
            assert_ne!(d, round_result_digest("m", &changed, &[9; 32]));
        }
        // the losses are reported, not committed twice: the commitment holds the log
        let mut same = result();
        same.losses = vec![];
        assert_eq!(d, round_result_digest("m", &same, &[9; 32]));
    }
}
