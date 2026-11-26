//! The challenge RPCs that let a committee seat check and vote, and anyone
//! check the outcome.
//!
//! * `tenzro_reexecuteChallenge` (admin) runs on a **seat's own node**: it
//!   takes the challenged inputs from the node holding the challenge, checks
//!   them against the provider's receipt, re-executes them and records the
//!   verdict.
//! * `tenzro_signChallengeVote` (admin) runs on the voter's own node. It
//!   signs a commit or a reveal of the recorded verdict with that node's
//!   validator key, which never leaves the node.
//! * `tenzro_listSeatDuties` (admin) lists the open challenges this node holds
//!   a seat on and where its vote stands.
//! * `tenzro_getChallengeInputs` (open) serves the inputs, on the node holding
//!   the challenge, to a seat that signed for them.
//! * `tenzro_auditInferenceChallenge` (open) re-checks a challenge record —
//!   from this node's own store, or a record fetched from any other node —
//!   with [`crate::inference_challenge::audit_challenge`], and also checks
//!   that every seat's key is the consensus key this node's validator
//!   registry holds for that address.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::inference_challenge::{
    ChallengeInputs, ChallengeManager, InferenceChallenge, Reexecution, audit_challenge,
    canonical_voter, commit_signing_bytes, compute_vote_commit, inputs_request_bytes, now_secs,
    reveal_signing_bytes,
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

/// This node's seat identity: its validator address and P-256 key.
struct OwnSeat {
    voter: String,
    public_key: Vec<u8>,
}

fn own_seat(node: &TenzroNode) -> Result<OwnSeat, JsonRpcError> {
    let signer = node.identity_signer().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "this node has no hardware identity key".to_string(),
        data: None,
    })?;
    let public_key = signer.public_key().p256.clone();
    let account = signer.public_key().account_slot();
    let voter = node
        .validator_registry()
        .and_then(|r| {
            r.list_active()
                .into_iter()
                .find(|e| e.address.as_bytes() == account.as_slice())
        })
        .map(|e| canonical_voter(&hex::encode(e.address.as_bytes())))
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "this node's validator key is not an active registered validator".to_string(),
            data: None,
        })?;
    Ok(OwnSeat { voter, public_key })
}

/// Signs `message` with this node's validator key under the challenge-vote
/// context, as `hex(p256 key || signature)`.
fn sign_as_seat(node: &TenzroNode, seat: &OwnSeat, message: &[u8]) -> Result<String, JsonRpcError> {
    let signer = node.identity_signer().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "this node has no hardware identity key".to_string(),
        data: None,
    })?;
    let signature = signer
        .sign(
            tenzro_crypto::composite::SignatureContext::ChallengeVote,
            message,
        )
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("signing failed: {e}"),
            data: None,
        })?;
    let tenzro_crypto::composite::ClassicalProof::Raw {
        signature: raw_signature,
    } = signature.classical
    else {
        return Err(JsonRpcError {
            code: -32603,
            message: "the identity key returned a WebAuthn assertion, not a raw signature"
                .to_string(),
            data: None,
        });
    };
    Ok(hex::encode(
        [seat.public_key.as_slice(), raw_signature.as_slice()].concat(),
    ))
}

fn manager_of(node: &TenzroNode) -> Result<Arc<ChallengeManager>, JsonRpcError> {
    node.challenge_manager()
        .cloned()
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "Verifiable inference is unavailable: node has no durable storage".to_string(),
            data: None,
        })
}

fn challenge_id_param(p: &Value) -> Result<&str, JsonRpcError> {
    p.get("challenge_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing challenge_id"))
}

/// `tenzro_signChallengeVote { phase, challenge_id, verdict, salt }`.
///
/// Runs on the **voter's own node** and signs with its validator key, which
/// never leaves the node. It signs only the verdict this node's own
/// re-execution of the challenge found (`tenzro_reexecuteChallenge`), so a
/// seat cannot vote on a response it has not checked. `phase: "commit"`
/// returns `{ voter, public_key, commit_hash, signature }`; `phase: "reveal"`
/// returns `{ voter, public_key, signature }`.
pub(crate) async fn handle_sign_challenge_vote(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| bad("missing params"))?;
    let challenge_id = challenge_id_param(&p)?;
    let phase = p
        .get("phase")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing phase (\"commit\" or \"reveal\")"))?;
    let verdict = p
        .get("verdict")
        .and_then(Value::as_bool)
        .ok_or_else(|| bad("missing verdict"))?;
    let salt = p
        .get("salt")
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .ok_or_else(|| bad("salt must be hex"))?;
    let recorded = manager_of(node)?
        .reexecution(challenge_id)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("re-execution lookup failed: {e}"),
            data: None,
        })?
        .ok_or_else(|| {
            bad(format!(
                "this node has not re-executed challenge {challenge_id}; run \
                 tenzro_reexecuteChallenge first"
            ))
        })?;
    if recorded.verdict != verdict {
        return Err(bad(format!(
            "this node's re-execution found verdict {}, not {verdict}",
            recorded.verdict
        )));
    }
    let seat = own_seat(node)?;
    match phase {
        "commit" => {
            let commit_hash = compute_vote_commit(verdict, &salt, challenge_id, &seat.voter);
            let signature = sign_as_seat(
                node,
                &seat,
                &commit_signing_bytes(challenge_id, &commit_hash),
            )?;
            Ok(json!({
                "voter": seat.voter,
                "public_key": hex::encode(&seat.public_key),
                "commit_hash": commit_hash,
                "signature": signature,
            }))
        }
        "reveal" => {
            let signature = sign_as_seat(
                node,
                &seat,
                &reveal_signing_bytes(challenge_id, verdict, &salt),
            )?;
            Ok(json!({
                "voter": seat.voter,
                "public_key": hex::encode(&seat.public_key),
                "signature": signature,
            }))
        }
        other => Err(bad(format!(
            "phase must be \"commit\" or \"reveal\", not {other:?}"
        ))),
    }
}

/// `tenzro_getChallengeInputs { challenge_id, voter, requested_at, signature }`
/// → the challenged inputs, served by the node the challenge was filed on to
/// a drawn seat whose key signed [`inputs_request_bytes`].
pub(crate) async fn handle_challenge_inputs(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| bad("missing params"))?;
    let challenge_id = challenge_id_param(&p)?;
    let voter = p
        .get("voter")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing voter"))?;
    let requested_at = p
        .get("requested_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("missing requested_at (Unix seconds)"))?;
    let signature = p
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing signature"))?;
    let inputs = manager_of(node)?
        .serve_inputs(challenge_id, voter, requested_at, signature, now_secs())
        .map_err(|e| bad(format!("inputs refused: {e}")))?;
    serde_json::to_value(inputs).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("inputs encode: {e}"),
        data: None,
    })
}

/// Asks the node holding `challenge` for its inputs, as `seat`.
async fn fetch_inputs(
    node: &TenzroNode,
    seat: &OwnSeat,
    challenge: &InferenceChallenge,
) -> Result<ChallengeInputs, JsonRpcError> {
    crate::exposure::check_public_https(&challenge.holder_rpc)
        .map_err(|e| bad(format!("the challenge's holder URL {e}")))?;
    let requested_at = now_secs();
    let signature = sign_as_seat(
        node,
        seat,
        &inputs_request_bytes(&challenge.challenge_id, &seat.voter, requested_at),
    )?;
    let unreachable = |e: String| JsonRpcError {
        code: -32000,
        message: format!("the node holding the challenge did not hand over its inputs: {e}"),
        data: None,
    };
    let reply: Value = reqwest::Client::new()
        .post(&challenge.holder_rpc)
        .timeout(std::time::Duration::from_secs(30))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tenzro_getChallengeInputs",
            "params": {
                "challenge_id": challenge.challenge_id,
                "voter": seat.voter,
                "requested_at": requested_at,
                "signature": signature,
            },
        }))
        .send()
        .await
        .map_err(|e| unreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| unreachable(e.to_string()))?;
    if let Some(error) = reply.get("error") {
        return Err(unreachable(error.to_string()));
    }
    serde_json::from_value(reply.get("result").cloned().unwrap_or(Value::Null))
        .map_err(|e| unreachable(format!("unreadable inputs: {e}")))
}

/// `tenzro_reexecuteChallenge { challenge_id, inputs? }` → `{ challenge_id,
/// voter, verdict, scored }`.
///
/// Runs on a seat's own node: takes the inputs from the node holding the
/// challenge (or from `inputs`), checks them against the provider's receipt,
/// re-executes them through the model and records the verdict this node may
/// then sign. `verdict` is `true` when the commitment did not verify.
pub(crate) async fn handle_reexecute_challenge(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| bad("missing params"))?;
    let challenge_id = challenge_id_param(&p)?;
    let manager = manager_of(node)?;
    let challenge = manager
        .get(challenge_id)
        .ok_or_else(|| bad(format!("this node does not hold challenge {challenge_id}")))?;
    if challenge.status.is_terminal() {
        return Err(bad(format!("challenge {challenge_id} has ended")));
    }
    let seat = own_seat(node)?;
    if challenge.committee.iter().all(|s| s.voter != seat.voter) {
        return Err(bad(format!(
            "{} holds no seat on challenge {challenge_id}",
            seat.voter
        )));
    }
    let inputs = match p.get("inputs").filter(|v| !v.is_null()) {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| bad(format!("inputs do not parse: {e}")))?,
        None => match manager.inputs(challenge_id).map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("inputs lookup failed: {e}"),
            data: None,
        })? {
            Some(held) => held,
            None => fetch_inputs(node, &seat, &challenge).await?,
        },
    };
    inputs
        .check(&challenge.receipt)
        .map_err(|e| bad(format!("inputs refused: {e}")))?;
    let prompt = match &inputs {
        ChallengeInputs::Prompt { prompt } => prompt.clone(),
        ChallengeInputs::Chat { media, .. } if !media.is_empty() => {
            return Err(bad(
                "a turn with attached media cannot be re-executed here".to_string()
            ));
        }
        // A build without the model engine renders no turn, so a seat there
        // cannot re-execute a conversation.
        #[cfg(not(feature = "inference"))]
        ChallengeInputs::Chat { .. } => {
            return Err(JsonRpcError {
                code: -32000,
                message: "this build has no model runtime to render the turn".to_string(),
                data: None,
            });
        }
        #[cfg(feature = "inference")]
        ChallengeInputs::Chat {
            messages, render, ..
        } => {
            let runtime = node.model_runtime.as_ref().ok_or_else(|| JsonRpcError {
                code: -32000,
                message: "Model runtime not initialized".to_string(),
                data: None,
            })?;
            runtime
                .chat_prompt(
                    &challenge.model_id,
                    messages,
                    &render.tools,
                    &render.config(challenge.receipt.sampling.max_output_tokens),
                )
                .await
                .map_err(|e| JsonRpcError {
                    code: -32000,
                    message: format!("the turn does not render: {e}"),
                    data: None,
                })?
        }
    };
    let stored = manager
        .get_commitment(&challenge.commitment_hash)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("commitment lookup failed: {e}"),
            data: None,
        })?
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: format!("this node holds no commitment for challenge {challenge_id}"),
            data: None,
        })?;
    let checked =
        crate::rpc::check_commitment(node, stored, Some(&challenge.receipt), &prompt).await?;
    let reexecution = Reexecution {
        verdict: !checked.pass(),
        steps_total: checked.outcome.steps_total,
        steps_passed: checked.outcome.steps_passed,
        failing_steps: checked.outcome.failing_steps.clone(),
        at: now_secs(),
    };
    manager
        .record_reexecution(challenge_id, &reexecution)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("recording the re-execution failed: {e}"),
            data: None,
        })?;
    Ok(json!({
        "challenge_id": challenge_id,
        "voter": seat.voter,
        "verdict": reexecution.verdict,
        "scored": scored(&reexecution),
    }))
}

fn scored(r: &Reexecution) -> Value {
    json!({
        "steps_total": r.steps_total,
        "steps_passed": r.steps_passed,
        "failing_steps": r.failing_steps,
    })
}

/// `tenzro_listSeatDuties` → the open challenges this node holds a seat on,
/// with their deadlines, and whether this node has re-executed (with the
/// verdict found), committed and revealed.
pub(crate) async fn handle_list_seat_duties(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let manager = manager_of(node)?;
    let seat = own_seat(node)?;
    let mut duties = Vec::new();
    for challenge in manager.list(None, None) {
        if challenge.status.is_terminal()
            || challenge.committee.iter().all(|s| s.voter != seat.voter)
        {
            continue;
        }
        let reexecution =
            manager
                .reexecution(&challenge.challenge_id)
                .map_err(|e| JsonRpcError {
                    code: -32000,
                    message: format!("re-execution lookup failed: {e}"),
                    data: None,
                })?;
        let vote = challenge.votes.iter().find(|v| v.voter == seat.voter);
        duties.push(json!({
            "challenge_id": challenge.challenge_id,
            "voter": seat.voter,
            "model_id": challenge.model_id,
            "status": challenge.status,
            "commit_deadline": challenge.commit_deadline,
            "reveal_deadline": challenge.reveal_deadline,
            "reexecuted": reexecution.is_some(),
            "verdict": reexecution.as_ref().map(|r| r.verdict),
            "scored": reexecution.as_ref().map(scored),
            "committed": vote.is_some(),
            "revealed": vote.is_some_and(|v| v.is_revealed()),
        }));
    }
    Ok(json!({ "voter": seat.voter, "duties": duties }))
}

/// `tenzro_auditInferenceChallenge { challenge_id }` or `{ challenge }` →
/// the audit, plus whether each seat's key is the one this node's registry
/// holds for it.
pub(crate) async fn handle_audit_challenge(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| bad("missing params"))?;
    let challenge: InferenceChallenge = match p.get("challenge") {
        Some(record) => serde_json::from_value(record.clone())
            .map_err(|e| bad(format!("challenge record does not parse: {e}")))?,
        None => {
            let id = p
                .get("challenge_id")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("pass challenge_id or a challenge record"))?;
            node.challenge_manager()
                .and_then(|m| m.get(id))
                .ok_or_else(|| bad(format!("unknown challenge {id}")))?
        }
    };
    let audit = audit_challenge(&challenge);
    let registry = node.validator_registry();
    let seats_registered = challenge.committee.iter().all(|seat| {
        let Ok(addr) =
            tenzro_types::primitives::Address::from_hex(seat.voter.trim_start_matches("0x"))
        else {
            return false;
        };
        registry
            .and_then(|r| r.get(&addr))
            .is_some_and(|e| hex::encode(e.node_key) == seat.consensus_pubkey)
    });
    Ok(json!({
        "challenge_id": challenge.challenge_id,
        "status": challenge.status,
        "audit": audit,
        "seats_registered": seats_registered,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_vote_needs_a_challenge_a_phase_a_verdict_and_a_salt() {
        let (node, _tmp) = crate::bare_node().await;
        let refused = |params: Option<Value>| {
            let node = node.clone();
            async move { handle_sign_challenge_vote(&node, params).await.unwrap_err() }
        };
        assert_eq!(refused(None).await.code, -32602);
        assert_eq!(refused(Some(json!({}))).await.code, -32602);
        let e = refused(Some(json!({"challenge_id": "c1"}))).await;
        assert_eq!(e.code, -32602);
        assert!(e.message.contains("phase"), "{}", e.message);
        let e = refused(Some(json!({"challenge_id": "c1", "phase": "commit"}))).await;
        assert_eq!(e.code, -32602);
        assert!(e.message.contains("verdict"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_vote_needs_a_hex_salt() {
        let (node, _tmp) = crate::bare_node().await;
        for salt in [json!(null), json!("zz"), json!(7)] {
            let e = handle_sign_challenge_vote(
                &node,
                Some(json!({
                    "challenge_id": "c1", "phase": "reveal", "verdict": true, "salt": salt
                })),
            )
            .await
            .unwrap_err();
            assert_eq!((e.code, e.message.as_str()), (-32602, "salt must be hex"));
        }
    }

    #[tokio::test]
    async fn a_node_with_no_identity_key_has_no_seat() {
        let (node, _tmp) = crate::bare_node().await;
        let e = own_seat(&node).err().expect("a bare node has no seat");
        assert_eq!(e.code, -32000);
        assert!(
            e.message.contains("no hardware identity key"),
            "{}",
            e.message
        );
    }

    #[tokio::test]
    async fn an_audit_needs_a_known_challenge_or_a_parsable_record() {
        let (node, _tmp) = crate::bare_node().await;
        let e = handle_audit_challenge(&node, None).await.unwrap_err();
        assert_eq!(e.code, -32602);
        let e = handle_audit_challenge(&node, Some(json!({})))
            .await
            .unwrap_err();
        assert!(e.message.contains("challenge_id or a challenge record"));
        let e = handle_audit_challenge(&node, Some(json!({"challenge_id": "ghost"})))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            (-32602, "unknown challenge ghost")
        );
        let e = handle_audit_challenge(&node, Some(json!({"challenge": {"nonsense": 1}})))
            .await
            .unwrap_err();
        assert!(
            e.message.starts_with("challenge record does not parse"),
            "{}",
            e.message
        );
    }
}
