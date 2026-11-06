//! Attestation-bound key release in consensus state (see
//! [`tenzro_types::key_release`]).
//!
//! A model's owner registers a release policy; from then on the owner's
//! broker records every release of the model's content key here before it
//! hands the wrapped key over. The chain re-checks the release itself at
//! the block's time, with [`tenzro_tee::key_release::verify_release`]: the
//! operator is a registered, unrevoked machine whose TPM is manufacturer
//! certified and whose admitted attestation key quoted the release binding;
//! its measured boot, its confidential VM measurement and its GPU satisfy
//! the policy, the GPU against the roots and reference values governance
//! sets. A binding is recorded once. After the owner revokes the policy no
//! release is recorded, so no broker following the chain releases the key
//! again.

use sha2::{Digest, Sha256};
use tenzro_types::key_release::{KeyReleaseOp, ModelKeyRelease, ReleaseEvent};

use super::funding::{machine_attestation, machine_endorsed, read_json, refuse, write_json};
use super::hardware_level::{read_gpu_references, read_gpu_roots};
use super::*;

/// Selector of a `KeyRelease` transaction.
pub const SELECTOR_KEY_RELEASE: [u8; 4] = [0x01, 0x00, 0x00, 0xD8];

/// Gas for one key-release operation: at most a TPM quote, a confidential
/// VM report and a GPU chain verified, and three record writes.
pub const GAS_KEY_RELEASE: u64 = 250_000;

/// Topic of every key-release log.
pub const KEY_RELEASE_TOPIC: &[u8] = b"KeyRelease";

fn model_key(model_id: &str) -> String {
    format!("key_release:{model_id}")
}

fn binding_key(model_id: &str, binding: &str) -> String {
    format!("key_release:{model_id}:binding:{binding}")
}

fn event_key(model_id: &str, index: u64) -> String {
    format!("key_release:{model_id}:event:{index}")
}

/// `model_id`'s release policy, when its owner registered one.
pub fn read_model(state: &dyn VmState, model_id: &str) -> Option<ModelKeyRelease> {
    read_json(state, &model_key(model_id))
}

/// Release `index` of `model_id`.
pub fn read_event(state: &dyn VmState, model_id: &str, index: u64) -> Option<ReleaseEvent> {
    read_json(state, &event_key(model_id, index))
}

/// The release of `model_id` recorded for `binding` (hex), if any.
pub fn read_event_by_binding(
    state: &dyn VmState,
    model_id: &str,
    binding: &str,
) -> Option<ReleaseEvent> {
    let index: u64 = read_json(state, &binding_key(model_id, binding))?;
    read_event(state, model_id, index)
}

/// The GPU roots and reference values governance recognises, parsed.
pub fn gpu_governance(
    state: &dyn VmState,
) -> std::result::Result<(Vec<tenzro_tee::x509::Cert>, Vec<(u8, Vec<Vec<u8>>)>), String> {
    let roots = read_gpu_roots(state)
        .iter()
        .map(|pem| tenzro_tee::x509::parse_pem_chain(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?
        .concat();
    let references =
        tenzro_types::hardware_level::decode_gpu_references(&read_gpu_references(state))?;
    Ok((roots, references))
}

/// What an accepted operation writes.
enum Planned {
    Register(ModelKeyRelease),
    Revoke(ModelKeyRelease),
    Release(ModelKeyRelease, ReleaseEvent),
}

/// Check `op` sent by `from` at `now_ms` against state, writing nothing.
/// Every refusal [`apply`] would make is made here first, so a node refuses
/// at admission what the chain would refuse.
pub fn authorize(state: &dyn VmState, from: &[u8], now_ms: i64, op: &KeyReleaseOp) -> Result<()> {
    plan(state, from, now_ms, op).map(|_| ())
}

fn plan(state: &dyn VmState, from: &[u8], now_ms: i64, op: &KeyReleaseOp) -> Result<Planned> {
    op.validate().map_err(refuse)?;
    let sender = hex::encode(from);
    let model = op.model_id();
    let current = read_model(state, model);
    let owned = |m: &ModelKeyRelease| -> Result<()> {
        if m.owner != sender {
            return Err(refuse(format!(
                "{model}'s key-release policy belongs to another account"
            )));
        }
        if m.revoked_at_ms.is_some() {
            return Err(refuse(format!(
                "{model}'s key-release policy is revoked; its key is released no more"
            )));
        }
        Ok(())
    };
    match op {
        KeyReleaseOp::Register { policy, .. } => {
            let releases = match &current {
                Some(m) => {
                    owned(m)?;
                    m.releases
                }
                None => 0,
            };
            Ok(Planned::Register(ModelKeyRelease {
                owner: sender.clone(),
                policy: policy.clone(),
                releases,
                revoked_at_ms: None,
            }))
        }
        KeyReleaseOp::Revoke { .. } => {
            let mut m = current
                .ok_or_else(|| refuse(format!("{model} has no key-release policy to revoke")))?;
            owned(&m)?;
            m.revoked_at_ms = Some(now_ms);
            Ok(Planned::Revoke(m))
        }
        KeyReleaseOp::Release { request } => {
            let mut m = current.ok_or_else(|| {
                refuse(format!(
                    "{model} has no key-release policy; its key is never released"
                ))
            })?;
            owned(&m)?;
            let did = &request.evidence.operator_did;
            if is_identity_revoked(state, did) {
                return Err(refuse(format!("{did} is revoked")));
            }
            let admitted = machine_attestation(state, did)
                .map_err(|e| refuse(format!("a key release needs a TPM-admitted operator: {e}")))?;
            machine_endorsed(state, did, now_ms).map_err(|e| {
                refuse(format!(
                    "a key release needs an operator whose TPM is manufacturer certified: {e}"
                ))
            })?;
            let (roots, references) = gpu_governance(state).map_err(refuse)?;
            let verified = tenzro_tee::key_release::verify_release(
                request,
                &m.policy,
                &tenzro_tee::key_release::ReleaseContext {
                    admitted: &admitted.evidence,
                    gpu_roots: &roots,
                    gpu_references: &references,
                    now: (now_ms.max(0) / 1000) as u64,
                },
            )
            .map_err(|e| refuse(format!("key release refused: {e}")))?;
            let binding = hex::encode(verified.binding);
            if read_event_by_binding(state, model, &binding).is_some() {
                return Err(refuse("this release binding has already been recorded"));
            }
            let event = ReleaseEvent {
                model_id: model.to_string(),
                index: m.releases,
                operator_did: did.clone(),
                terms_digest: hex::encode(request.terms_digest),
                release_key: hex::encode(request.release_key.fingerprint()),
                binding,
                evidence: hex::encode(request.evidence.digest()),
                pcr_digest: hex::encode(&verified.pcr_digest),
                cvm_measurement: verified.cvm_measurement.as_ref().map(hex::encode),
                gpu_device: verified.gpu_device.clone(),
                at_ms: now_ms,
            };
            m.releases += 1;
            Ok(Planned::Release(m, event))
        }
    }
}

fn log(kind: &[u8], body: serde_json::Value) -> Result<Log> {
    Ok(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![KEY_RELEASE_TOPIC.to_vec(), kind.to_vec()],
        serde_json::to_vec(&body)
            .map_err(|e| VmError::Internal(format!("encode key-release log: {e}")))?,
    ))
}

/// Apply one key-release operation sent by `from`.
pub(super) fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let op: KeyReleaseOp = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid KeyRelease payload: {e}")))?;
    let planned = plan(state, from, now_ms, &op)?;
    let model = op.model_id().to_string();
    let mut changes = Vec::new();
    let logs = match planned {
        Planned::Register(m) => {
            write_json(state, &model_key(&model), &m, &mut changes)?;
            vec![log(
                b"register",
                serde_json::json!({ "model_id": model, "policy": m.policy }),
            )?]
        }
        Planned::Revoke(m) => {
            write_json(state, &model_key(&model), &m, &mut changes)?;
            let reason = match &op {
                KeyReleaseOp::Revoke { reason, .. } => reason.clone(),
                _ => String::new(),
            };
            vec![log(
                b"revoke",
                serde_json::json!({ "model_id": model, "reason": reason, "at_ms": now_ms }),
            )?]
        }
        Planned::Release(m, event) => {
            write_json(
                state,
                &binding_key(&model, &event.binding),
                &event.index,
                &mut changes,
            )?;
            write_json(state, &event_key(&model, event.index), &event, &mut changes)?;
            write_json(state, &model_key(&model), &m, &mut changes)?;
            let digest =
                hex::encode(Sha256::digest(serde_json::to_vec(&event).map_err(|e| {
                    VmError::Internal(format!("encode release event: {e}"))
                })?));
            vec![log(
                b"release",
                serde_json::json!({ "event": event, "digest": digest }),
            )?]
        }
    };
    Ok((changes, logs))
}
