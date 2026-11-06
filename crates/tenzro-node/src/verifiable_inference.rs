//! Verification levels for inference, and checking what a receipt proves.
//!
//! A request names the verification it needs (`verification`: `none`,
//! `receipt`, `optimistic` or `tee`, see [`VerificationLevel`]). A node
//! serving it locally first [`admit`]s the level: it must be able to sign a
//! receipt for the model, and for `tee` it must have detected confidential
//! compute at startup. A level the node cannot meet is refused before any
//! work is done; it is never served at a lower level.
//!
//! `tenzro_verifyInferenceReceipt` (open) checks a receipt held by anyone,
//! without contacting the provider that signed it: the signature against the
//! key and session certificate the receipt carries, as of when it was signed,
//! and the model hash against the one this node's catalog states for the
//! model the receipt names. A receipt with TEE evidence is also checked end
//! to end: the report against the vendor's roots, its user data against the
//! receipt's binding, and its measurement against the attestation
//! transparency log.

use serde_json::{Value, json};
use tenzro_types::inference_verification::VerificationLevel;

use crate::inference_receipt::{
    InferenceReceipt, ReceiptError, catalog_identity, expected_identity,
};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// Read a request's `verification` field. Absent is [`VerificationLevel::None`];
/// an unknown name is refused rather than read as none.
pub(crate) fn level_param(v: Option<&Value>) -> Result<VerificationLevel, JsonRpcError> {
    match v {
        None | Some(Value::Null) => Ok(VerificationLevel::None),
        Some(Value::String(s)) => VerificationLevel::parse(s).ok_or_else(|| {
            bad(format!(
                "verification must be one of none, receipt, optimistic, tee; got {s}"
            ))
        }),
        Some(_) => Err(bad("verification must be a string")),
    }
}

/// Refuse a level governance has paused or retired, before any routing or
/// work: a level the network turned off is refused, never downgraded.
pub(crate) fn governed_open(
    node: &TenzroNode,
    level: VerificationLevel,
) -> Result<(), JsonRpcError> {
    let Some(key) = tenzro_vm::governance::verification_status_key(level) else {
        return Ok(());
    };
    let status = crate::rpc::chain_state_of(node)
        .map(|chain| tenzro_vm::native::lever_status(&chain, key))
        .unwrap_or_else(|| {
            tenzro_vm::governance::LeverStatus::from_value(tenzro_vm::governance::genesis_param(
                key,
            ))
        });
    if status == tenzro_vm::governance::LeverStatus::Enabled {
        return Ok(());
    }
    Err(JsonRpcError {
        code: -32021,
        message: format!(
            "verification {} is {} by governance ({key})",
            level.as_str(),
            status.as_str()
        ),
        data: None,
    })
}

/// Whether this node can serve `model_id` at `level`. Checked before any
/// work, so a level the node cannot meet is refused, never downgraded.
pub(crate) fn admit(
    node: &TenzroNode,
    level: VerificationLevel,
    model_id: &str,
) -> Result<(), JsonRpcError> {
    governed_open(node, level)?;
    if !level.requires_receipt() {
        return Ok(());
    }
    let unavailable = |why: &str| JsonRpcError {
        code: -32021,
        message: format!(
            "verification {} requested but this node cannot provide it: {why}",
            level.as_str()
        ),
        data: None,
    };
    if node.records().is_none() {
        return Err(unavailable(
            "it has no hardware identity key to sign receipts",
        ));
    }
    if crate::identity_bootstrap::machine_did().is_none() {
        return Err(unavailable("its machine has no hardware identity"));
    }
    if catalog_identity(model_id).is_none() {
        return Err(unavailable("the catalog states no identity for the model"));
    }
    if level == VerificationLevel::Tee && node.tee_provider().is_none() {
        return Err(unavailable("it has no confidential compute"));
    }
    if level == VerificationLevel::Optimistic && !answers_for_receipts_with_bond(node) {
        return Err(unavailable(
            "no active compute bond registers the key that signs its receipts",
        ));
    }
    Ok(())
}

/// Whether an active compute bond is held for this machine's identity, so a
/// fault upheld against receipts its hardware identity key signed can be paid
/// from the bond.
pub(crate) fn answers_for_receipts_with_bond(node: &TenzroNode) -> bool {
    let (Some(_), Some(chain), Some(did)) = (
        node.records(),
        node.chain_state(),
        crate::identity_bootstrap::machine_did(),
    ) else {
        return false;
    };
    bonded_machine(&chain, &did)
}

/// Whether an eligible compute bond is held for `machine_did`. The bond
/// answers for receipts signed by the hardware identity key registered for
/// that DID.
pub fn bonded_machine(chain: &dyn tenzro_vm::VmState, machine_did: &str) -> bool {
    tenzro_vm::native::compute_bond(chain, machine_did).is_some_and(|b| b.is_eligible())
}

/// The levels this node serves at, as its provider announcement states them.
/// [`admit`] holds each request to the same conditions per model.
pub fn offered_levels(node: &TenzroNode) -> Vec<VerificationLevel> {
    let mut levels = vec![VerificationLevel::None];
    if node.records().is_none() || crate::identity_bootstrap::machine_did().is_none() {
        return levels;
    }
    levels.push(VerificationLevel::Receipt);
    // A connector's answers come from the operator's own endpoint: they carry
    // a receipt, but no re-execution or enclave report can be held to them,
    // and the announcement states the node's levels, not each model's.
    if node.connector().is_some() {
        return levels;
    }
    if answers_for_receipts_with_bond(node) {
        levels.push(VerificationLevel::Optimistic);
    }
    if node.tee_provider().is_some() {
        levels.push(VerificationLevel::Tee);
    }
    levels
}

/// The levels a consumer routes to a provider at: those it announced that the
/// consumer can check for itself. `tee` needs the provider's announcement to
/// name confidential-compute hardware (each answer's report is verified on
/// arrival); `optimistic` needs a bond in the consumer's own view of chain
/// state registering the provider's key, and another provider serving the
/// same model to re-execute on.
pub fn routable_levels(
    announced: &[VerificationLevel],
    tee_vendor: &str,
    bonded: bool,
    witnesses: usize,
) -> Vec<VerificationLevel> {
    let mut out = vec![VerificationLevel::None];
    for &level in announced {
        let keep = match level {
            VerificationLevel::None => false,
            VerificationLevel::Receipt => true,
            VerificationLevel::Tee => !tee_vendor.is_empty(),
            VerificationLevel::Optimistic => bonded && witnesses > 0,
        };
        if keep && !out.contains(&level) {
            out.push(level);
        }
    }
    out
}

/// Whether the network announcement `reg` may be routed a request at
/// `level`, judged from this node's view of the provider's announcement and
/// of chain state.
pub(crate) fn offer_meets(
    node: &TenzroNode,
    reg: &tenzro_network::ModelRegistrationMessage,
    level: VerificationLevel,
) -> bool {
    if level == VerificationLevel::None {
        return true;
    }
    let Some(provider) = node.network_providers.get(&reg.iroh_endpoint_id) else {
        return false;
    };
    let announcement = &provider.announcement;
    let bonded = node
        .chain_state()
        .is_some_and(|chain| bonded_machine(&chain, &reg.machine_did));
    let witnesses = node
        .network_models_snapshot()
        .iter()
        .filter(|e| {
            e.registration.model_id == reg.model_id && e.registration.provider != reg.provider
        })
        .count();
    routable_levels(
        &announcement.capacity.verification,
        &announcement.trust_profile.tee_vendor,
        bonded,
        witnesses,
    )
    .contains(&level)
}

/// The surcharge, in bps of the base price, governance sets for `level`.
pub fn surcharge_bps(node: &TenzroNode, level: VerificationLevel) -> u64 {
    use tenzro_vm::native::inference_fault as p;
    let key = match level {
        VerificationLevel::None => return 0,
        VerificationLevel::Receipt => p::RECEIPT_SURCHARGE_PARAM,
        VerificationLevel::Optimistic => p::OPTIMISTIC_SURCHARGE_PARAM,
        VerificationLevel::Tee => p::TEE_SURCHARGE_PARAM,
    };
    crate::rpc::chain_state_of(node)
        .map(|chain| tenzro_vm::native::network_param(&chain, key))
        .unwrap_or_else(|| tenzro_vm::governance::genesis_param(key))
}

/// Carry the intent's `verification` into routing: the level, its governed
/// surcharge, and the levels this node itself serves at for candidates from
/// its own catalog.
pub(crate) fn apply_to_intent(
    node: &TenzroNode,
    intent: tenzro_model::routing::intent::RouteIntent,
    params: &Value,
) -> Result<tenzro_model::routing::intent::RouteIntent, JsonRpcError> {
    let level = level_param(params.get("verification"))?;
    governed_open(node, level)?;
    Ok(intent.with_verification(level, surcharge_bps(node, level), offered_levels(node)))
}

/// `cost` with the surcharge for `level` added.
pub fn priced(cost: u128, surcharge_bps: u64) -> u128 {
    cost.saturating_add(cost.saturating_mul(surcharge_bps as u128) / 10_000)
}

/// The error for a forwarded answer without the evidence its level requires.
/// The answer is withheld: the caller asked for evidence, so an answer
/// without it is no answer.
pub(crate) fn answer_refused(
    provider: &str,
    level: VerificationLevel,
    why: String,
) -> JsonRpcError {
    JsonRpcError {
        code: -32021,
        message: format!(
            "provider {provider} did not provide verification {}: {why}",
            level.as_str()
        ),
        data: None,
    }
}

/// Check that a forwarded answer carries the evidence `level` requires: a
/// receipt from the pinned provider key that names the routed model's
/// catalog identity, this request's nonce and the output received; for
/// `optimistic`, a greedy decode; for `tee`, a report whose chain verifies
/// against this node's attestation transparency log.
pub(crate) fn check_answer(
    node: &TenzroNode,
    level: VerificationLevel,
    model_id: &str,
    nonce: &str,
    pinned_key: Option<&tenzro_crypto::composite::CompositePublicKey>,
    receipt: Option<&Value>,
    received_output_hash: &str,
) -> Result<(), String> {
    if !level.requires_receipt() {
        return Ok(());
    }
    let pinned = pinned_key.ok_or(
        "the provider's machine identity has no registered key to check its receipt against",
    )?;
    let receipt: InferenceReceipt = receipt
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or("the provider returned no receipt")?;
    let identity =
        expected_identity(model_id).ok_or("the catalog states no identity for the model")?;
    receipt
        .verify_signature(pinned)
        .map_err(|e| e.to_string())?;
    if receipt.model_id != model_id
        || receipt.model_hash != identity.model_hash
        || receipt.engine != identity.engine
        || receipt.nonce != nonce
        || receipt.output_hash != received_output_hash
        || receipt.machine_did.is_empty()
    {
        return Err(
            "the receipt does not bind this request, its model identity and its output".to_string(),
        );
    }
    match level {
        VerificationLevel::Optimistic if !crate::optimistic::is_greedy(&receipt) => {
            Err("an optimistic answer must be decoded greedily".to_string())
        }
        VerificationLevel::Tee => {
            let log = crate::attestation_log::load(
                node.storage()
                    .map(|s| s.as_ref() as &dyn tenzro_storage::KvStore),
            )
            .map_err(|e| e.message)?;
            receipt
                .verify_tee(&log)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        _ => Ok(()),
    }
}

/// The error for a receipt a request needed and the node could not produce.
pub(crate) fn receipt_refused(e: ReceiptError) -> JsonRpcError {
    JsonRpcError {
        code: -32021,
        message: format!("the requested verification could not be provided: {e}"),
        data: None,
    }
}

/// `tenzro_verifyInferenceReceipt { receipt, level? }` → `{ valid, error?, ... }`.
/// With `level: "tee"` a receipt without TEE evidence is not valid.
pub(crate) fn handle_verify_receipt(
    node: &TenzroNode,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| bad("missing params"))?;
    let level = level_param(p.get("level"))?;
    let receipt: InferenceReceipt = p
        .get("receipt")
        .cloned()
        .ok_or_else(|| bad("missing receipt"))
        .and_then(|v| {
            serde_json::from_value(v).map_err(|e| bad(format!("receipt does not parse: {e}")))
        })?;
    if let Err(e) = receipt.verify_against_catalog() {
        return Ok(json!({ "valid": false, "error": e.to_string() }));
    }
    let tee = match (&receipt.tee, level) {
        (None, VerificationLevel::Tee) => {
            return Ok(json!({ "valid": false, "error": ReceiptError::NoTeeEvidence.to_string() }));
        }
        (None, _) => Value::Null,
        (Some(_), _) => {
            let log = crate::attestation_log::load(
                node.storage()
                    .map(|s| s.as_ref() as &dyn tenzro_storage::KvStore),
            )?;
            match receipt.verify_tee(&log) {
                Ok(v) => json!({
                    "vendor": v.vendor.as_str(),
                    "measurement": hex::encode(&v.measurement),
                    "tcb_status": v.tcb_status,
                }),
                Err(e) => return Ok(json!({ "valid": false, "error": e.to_string() })),
            }
        }
    };
    Ok(json!({
        "valid": true,
        "model_id": receipt.model_id,
        "model_hash": receipt.model_hash,
        "engine": receipt.engine,
        "machine_did": receipt.machine_did,
        "input_commitment": receipt.input_commitment,
        "output_hash": receipt.output_hash,
        "signed_at_ms": receipt.signed_at_ms,
        "public_key": receipt.public_key,
        "tee": tee,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_levels_the_consumer_can_check_are_routable() {
        use VerificationLevel as L;
        let all = [L::None, L::Receipt, L::Optimistic, L::Tee];
        // A provider claiming everything, with nothing to back it.
        assert_eq!(
            routable_levels(&all, "", false, 0),
            vec![L::None, L::Receipt]
        );
        // TEE hardware named in its announcement.
        assert!(routable_levels(&all, "intel-tdx", false, 0).contains(&L::Tee));
        // A bond without anyone to re-execute on is not enough, nor a witness
        // without a bond.
        assert!(!routable_levels(&all, "", true, 0).contains(&L::Optimistic));
        assert!(!routable_levels(&all, "", false, 3).contains(&L::Optimistic));
        assert!(routable_levels(&all, "", true, 1).contains(&L::Optimistic));
        // Nothing announced, nothing but none.
        assert_eq!(routable_levels(&[], "intel-tdx", true, 1), vec![L::None]);
    }

    #[test]
    fn a_surcharge_is_added_in_basis_points() {
        assert_eq!(priced(10_000, 0), 10_000);
        assert_eq!(priced(10_000, 2_000), 12_000);
        assert_eq!(priced(u128::MAX, 10_000), u128::MAX);
    }

    #[test]
    fn an_unknown_level_is_refused_not_read_as_none() {
        assert_eq!(level_param(None).unwrap(), VerificationLevel::None);
        assert_eq!(
            level_param(Some(&json!("tee"))).unwrap(),
            VerificationLevel::Tee
        );
        assert!(level_param(Some(&json!("strong"))).is_err());
        assert!(level_param(Some(&json!(true))).is_err());
    }
}

/// Request fields that steer payment, routing and verification rather than
/// the computation; a task's input commitment leaves them out.
const NON_TASK_FIELDS: &[&str] = &[
    "payment",
    "channel_voucher",
    "verification",
    "receipt_nonce",
    "app_id",
    "visibility",
    "provider",
    "caller_address",
    "provider_access_token",
    "provider_dpop",
];

/// `v` as JSON with every object's keys in sorted order, so two parties
/// encoding the same value get the same bytes.
pub(crate) fn canonical_json(v: &Value) -> Vec<u8> {
    // serde_json writes a map in its iteration order; build the output by
    // hand so the order is the sorted one whatever map type is compiled in.
    fn write(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                out.push(b'{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(k).unwrap_or_default());
                    out.push(b':');
                    write(&m[k], out);
                }
                out.push(b'}');
            }
            Value::Array(a) => {
                out.push(b'[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write(x, out);
                }
                out.push(b']');
            }
            other => out.extend(serde_json::to_vec(other).unwrap_or_default()),
        }
    }
    let mut out = Vec::new();
    write(v, &mut out);
    out
}

/// The verification a modality request asks for, admitted for `model_id`
/// before any work. A call this node does not serve itself is forwarded
/// before it gets here, see [`crate::task_route`].
pub(crate) fn task_level(
    node: &TenzroNode,
    params: &Value,
    model_id: &str,
) -> Result<VerificationLevel, JsonRpcError> {
    let level = level_param(params.get("verification"))?;
    admit(node, level, model_id)?;
    Ok(level)
}

/// Sign the receipt of a modality call and put it into `out` as
/// `tenzro_receipt`: the input commitment covers the request's computational
/// fields (`params` without payment and verification fields), the output
/// commitment the engine's answer (`out` before billing fields are added).
pub(crate) async fn attach_task_receipt(
    node: &TenzroNode,
    params: &Value,
    model_id: &str,
    task: &str,
    level: VerificationLevel,
    units: tenzro_types::model::BillableUnits,
    out: &mut Value,
) -> Result<(), JsonRpcError> {
    let mut input = params.clone();
    if let Some(obj) = input.as_object_mut() {
        for f in NON_TASK_FIELDS {
            obj.remove(*f);
        }
    }
    let receipt = crate::inference_receipt::sign_task(
        node,
        crate::inference_receipt::ServedTask {
            model_id,
            task,
            nonce: params.get("receipt_nonce").and_then(Value::as_str),
            input: &canonical_json(&input),
            // Large parts (masks, long vectors) are bound by content hash, so
            // a dispute over this answer fits a fault.
            output: &canonical_json(&crate::optimistic::content_committed(out).0),
            units,
            sampling: crate::inference_receipt::deterministic_sampling(),
            level,
        },
    )
    .await
    .map_err(receipt_refused)?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("tenzro_receipt".to_string(), json!(receipt));
    }
    Ok(())
}

#[cfg(test)]
mod canonical_tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let a = json!({"b": 1, "a": {"y": [1, {"d": 2, "c": 3}], "x": "s"}});
        assert_eq!(
            canonical_json(&a),
            br#"{"a":{"x":"s","y":[1,{"c":3,"d":2}]},"b":1}"#.to_vec()
        );
    }
}
