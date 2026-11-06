//! The two challenge RPCs that let a committee seat vote and anyone check the
//! outcome.
//!
//! * `tenzro_signChallengeVote` (admin) runs on the **voter's own node**. It
//!   signs a commit or a reveal with that node's validator consensus key,
//!   which never leaves the node, and returns the signature for the voter to
//!   submit to the node holding the dispute.
//! * `tenzro_auditInferenceChallenge` (open) re-checks a challenge record —
//!   from this node's own store, or a record fetched from any other node —
//!   with [`crate::inference_challenge::audit_challenge`], and also checks
//!   that every seat's key is the consensus key this node's validator
//!   registry holds for that address.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::inference_challenge::{
    InferenceChallenge, audit_challenge, canonical_voter, commit_signing_bytes,
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

/// `tenzro_signChallengeVote { challenge_id, commit_hash }` or
/// `{ challenge_id, verdict, salt }` → `{ voter, public_key, signature }`.
pub(crate) async fn handle_sign_challenge_vote(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| bad("missing params"))?;
    let challenge_id = p
        .get("challenge_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing challenge_id"))?;
    let message = match p.get("commit_hash").and_then(Value::as_str) {
        Some(commit_hash) => commit_signing_bytes(challenge_id, commit_hash),
        None => {
            let verdict = p.get("verdict").and_then(Value::as_bool).ok_or_else(|| {
                bad("pass commit_hash to sign a commit, or verdict and salt to sign a reveal")
            })?;
            let salt = p
                .get("salt")
                .and_then(Value::as_str)
                .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                .ok_or_else(|| bad("salt must be hex"))?;
            reveal_signing_bytes(challenge_id, verdict, &salt)
        }
    };
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
    let signature = signer
        .sign(
            tenzro_crypto::composite::SignatureContext::ChallengeVote,
            &message,
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
    Ok(json!({
        "voter": voter,
        "public_key": hex::encode(&public_key),
        "signature": hex::encode([public_key.as_slice(), raw_signature.as_slice()].concat()),
    }))
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
    async fn a_vote_needs_params_a_challenge_and_a_commit_or_a_reveal() {
        let (node, _tmp) = crate::bare_node().await;
        let code = |r: Result<Value, JsonRpcError>| r.unwrap_err().code;
        assert_eq!(code(handle_sign_challenge_vote(&node, None).await), -32602);
        assert_eq!(
            code(handle_sign_challenge_vote(&node, Some(json!({}))).await),
            -32602
        );
        let e = handle_sign_challenge_vote(&node, Some(json!({"challenge_id": "c1"})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32602);
        assert!(e.message.contains("commit_hash"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_reveal_needs_a_hex_salt() {
        let (node, _tmp) = crate::bare_node().await;
        for salt in [json!(null), json!("zz"), json!(7)] {
            let e = handle_sign_challenge_vote(
                &node,
                Some(json!({"challenge_id": "c1", "verdict": true, "salt": salt})),
            )
            .await
            .unwrap_err();
            assert_eq!((e.code, e.message.as_str()), (-32602, "salt must be hex"));
        }
    }

    #[tokio::test]
    async fn a_node_with_no_identity_key_signs_no_vote() {
        let (node, _tmp) = crate::bare_node().await;
        let commit = handle_sign_challenge_vote(
            &node,
            Some(json!({"challenge_id": "c1", "commit_hash": "ab"})),
        )
        .await
        .unwrap_err();
        assert_eq!(commit.code, -32000);
        assert!(commit.message.contains("no hardware identity key"));
        let reveal = handle_sign_challenge_vote(
            &node,
            Some(json!({"challenge_id": "c1", "verdict": false, "salt": "0x0102"})),
        )
        .await
        .unwrap_err();
        assert_eq!(reveal.code, -32000, "a reveal is refused the same way");
    }

    #[tokio::test]
    async fn an_audit_needs_a_known_challenge_or_a_parsable_record() {
        let (node, _tmp) = crate::bare_node().await;
        let e = handle_audit_challenge(&node, None).await.unwrap_err();
        assert_eq!(e.code, -32602);
        let e = handle_audit_challenge(&node, Some(json!({}))).await.unwrap_err();
        assert!(e.message.contains("challenge_id or a challenge record"));
        let e = handle_audit_challenge(&node, Some(json!({"challenge_id": "ghost"})))
            .await
            .unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-32602, "unknown challenge ghost"));
        let e = handle_audit_challenge(&node, Some(json!({"challenge": {"nonsense": 1}})))
            .await
            .unwrap_err();
        assert!(e.message.starts_with("challenge record does not parse"), "{}", e.message);
    }
}
