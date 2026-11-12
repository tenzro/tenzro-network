//! Clear-signing for privileged actions.
//!
//! A privileged transaction (a governance or guardian action, an issuer
//! power over a token, an agent's Terms, an agent action carrying its
//! controller's step-up) is signed over a typed preimage rather than an
//! opaque byte string. [`typed_action_digest`] is that digest, and it is what
//! [`Transaction::hash`] returns for these transactions, so the digest a
//! signer approves is the one the VM verifies. A wallet renders the action
//! from [`decode_preimage`] of the preimage bytes, never from text supplied
//! by the application asking for the signature, and a privileged transaction
//! carries no memo, so no free text enters what is signed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_terms::{
    OP_AGENT_STEP_UP, OP_DELEGATE_AGENT, OP_UPDATE_AGENT_TERMS, custody_challenge_digest,
};
use crate::transaction::{Transaction, TransactionType};

/// Domain of every typed action preimage.
pub const TYPED_ACTION_DOMAIN: &str = "tenzro/typed-action";

/// Which privileged power an action exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    /// Proposing, voting, enacting, holder escrow, concerns, readiness and
    /// disclosures.
    Governance,
    /// A guardian's veto or pause.
    Guardian,
    /// An issuer power over a token.
    Issuer,
    /// Delegating, re-scoping or revoking an agent.
    Terms,
    /// An agent action carrying its controller's step-up approval.
    StepUp,
}

/// The privileged class of `tx_type`, if it has one.
pub fn action_class(tx_type: &TransactionType) -> Option<ActionClass> {
    use TransactionType as T;
    match tx_type {
        T::GovernancePropose { .. }
        | T::GovernanceVote { .. }
        | T::GovernanceExecute { .. }
        | T::GovernanceVetoSignal { .. }
        | T::GovernanceVetoWithdraw { .. }
        | T::GovernanceConcern { .. }
        | T::UpgradeReady { .. }
        | T::GovernanceSecurityDisclosure { .. } => Some(ActionClass::Governance),
        T::GovernanceVeto { .. } | T::GovernancePause { .. } => Some(ActionClass::Guardian),
        T::Token { op } if op.is_issuer_power() => Some(ActionClass::Issuer),
        T::SetAgentTerms { .. } | T::RevokeDelegatedAgent { .. } => Some(ActionClass::Terms),
        T::AgentAct { action, .. } if action.step_up.is_some() => Some(ActionClass::StepUp),
        _ => None,
    }
}

/// A passkey approval carried inside the action, with the custody digest
/// the passkey signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPreimage {
    /// The custody operation.
    pub operation: String,
    /// Hex account the challenge named.
    pub account: String,
    /// Hex digest of what was approved.
    pub target: String,
    /// Hex challenge nonce.
    pub nonce: String,
    /// Hex custody digest the passkey signed.
    pub digest: String,
}

/// The typed preimage of a privileged transaction. Field order is the
/// encoding order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPreimage {
    /// [`TYPED_ACTION_DOMAIN`].
    pub domain: String,
    /// The power exercised.
    pub class: ActionClass,
    /// Chain id.
    pub chain_id: u64,
    /// Hex signer.
    pub from: String,
    /// Hex recipient field of the envelope.
    pub to: String,
    /// Account nonce.
    pub nonce: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas price.
    pub gas_price: u64,
    /// Signing time, ms.
    pub timestamp: i64,
    /// Last block time it may execute at, ms.
    pub valid_until: i64,
    /// The action, as the transaction type encodes it.
    pub action: serde_json::Value,
    /// Passkey approvals the action carries.
    pub approvals: Vec<ApprovalPreimage>,
}

/// The approvals `tx_type` carries, each digest bound to the transaction's
/// `chain_id` as the VM checks it.
fn approvals(chain_id: u64, tx_type: &TransactionType) -> Vec<ApprovalPreimage> {
    let one = |op: &[u8], account: &[u8], target: &[u8], nonce: &[u8; 16]| ApprovalPreimage {
        operation: String::from_utf8_lossy(op).into_owned(),
        account: hex::encode(account),
        target: hex::encode(target),
        nonce: hex::encode(nonce),
        digest: hex::encode(custody_challenge_digest(
            chain_id, account, op, target, nonce,
        )),
    };
    match tx_type {
        TransactionType::SetAgentTerms {
            terms,
            rotate,
            approval,
        } => {
            let op = if rotate.is_some() {
                OP_UPDATE_AGENT_TERMS
            } else {
                OP_DELEGATE_AGENT
            };
            vec![one(
                op,
                &approval.account,
                &terms.target(*rotate),
                &approval.nonce,
            )]
        }
        TransactionType::AgentAct { action, .. } => action
            .step_up
            .iter()
            .map(|a| one(OP_AGENT_STEP_UP, &a.account, &action.digest(), &a.nonce))
            .collect(),
        _ => Vec::new(),
    }
}

/// The action as a preimage shows it. An action holding a number no JSON
/// number can carry exactly is named by the SHA-256 of its encoding instead:
/// its digest stays distinct, no wallet can show what it does, so nobody
/// approves it, and [`crate::transaction::SignedTransaction::validate`]
/// refuses it.
fn action_value(tx_type: &TransactionType) -> serde_json::Value {
    serde_json::to_value(tx_type).unwrap_or_else(|_| {
        let bytes = serde_json::to_vec(tx_type).unwrap_or_default();
        serde_json::json!({ "unencodable": hex::encode(Sha256::digest(bytes)) })
    })
}

/// Whether a privileged transaction's action is expressible in its preimage.
pub fn action_encodes(tx_type: &TransactionType) -> bool {
    action_class(tx_type).is_none() || serde_json::to_value(tx_type).is_ok()
}

/// The typed preimage of `tx`, if it is privileged.
pub fn action_preimage(tx: &Transaction) -> Option<ActionPreimage> {
    let class = action_class(&tx.tx_type)?;
    Some(ActionPreimage {
        domain: TYPED_ACTION_DOMAIN.to_string(),
        class,
        chain_id: tx.chain_id.0,
        from: hex::encode(tx.from.as_bytes()),
        to: hex::encode(tx.to.as_bytes()),
        nonce: tx.nonce.0,
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        timestamp: tx.timestamp.0,
        valid_until: tx.valid_until.0,
        action: action_value(&tx.tx_type),
        approvals: approvals(tx.chain_id.0, &tx.tx_type),
    })
}

/// The bytes a privileged transaction's digest is taken over.
pub fn preimage_bytes(preimage: &ActionPreimage) -> Vec<u8> {
    serde_json::to_vec(preimage).expect("a preimage is JSON-safe")
}

/// SHA-256 of `preimage`'s bytes.
pub fn preimage_digest(preimage: &ActionPreimage) -> [u8; 32] {
    Sha256::digest(preimage_bytes(preimage)).into()
}

/// The digest a privileged transaction is signed over and the VM verifies,
/// or `None` for any other transaction.
pub fn typed_action_digest(tx: &Transaction) -> Option<[u8; 32]> {
    action_preimage(tx).map(|p| preimage_digest(&p))
}

/// Parse preimage bytes, refusing any that are not the canonical encoding
/// of what they parse to: the digest of the returned preimage is the digest
/// of `bytes`.
pub fn decode_preimage(bytes: &[u8]) -> Result<(ActionPreimage, [u8; 32]), String> {
    let preimage: ActionPreimage =
        serde_json::from_slice(bytes).map_err(|e| format!("not a typed action preimage: {e}"))?;
    if preimage.domain != TYPED_ACTION_DOMAIN {
        return Err(format!(
            "domain {} is not {TYPED_ACTION_DOMAIN}",
            preimage.domain
        ));
    }
    if preimage_bytes(&preimage) != bytes {
        return Err("the preimage is not canonically encoded".into());
    }
    Ok((preimage.clone(), preimage_digest(&preimage)))
}

/// What the action does, in words, generated from the preimage alone.
pub fn describe(preimage: &ActionPreimage) -> Vec<String> {
    let (kind, body) = match preimage.action.as_object().and_then(|o| o.iter().next()) {
        Some((k, v)) => (k.as_str(), v),
        None => ("unknown", &preimage.action),
    };
    let s = |k: &str| {
        body.get(k).map(|v| {
            v.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string())
        })
    };
    let id = s("proposal_id").unwrap_or_default();
    let mut lines = vec![match kind {
        "GovernancePropose" => {
            let action = body
                .get("proposal")
                .and_then(|p| serde_json::from_value::<Vec<u8>>(p.clone()).ok())
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .unwrap_or_default();
            format!("Open a governance proposal: {action}")
        }
        "GovernanceVote" => format!(
            "Vote {} on proposal {id} with the bond of validator {}{}",
            if body.get("vote").and_then(|v| v.as_bool()) == Some(true) {
                "YES"
            } else {
                "NO"
            },
            s("validator").unwrap_or_default(),
            if body.get("root_approval").is_some_and(|a| !a.is_null()) {
                ", approved by its machine root"
            } else {
                ""
            }
        ),
        "GovernanceExecute" => format!("Enact proposal {id}"),
        "GovernanceVeto" => format!("Veto proposal {id} as a guardian"),
        "GovernancePause" => {
            if body.get("paused").and_then(|v| v.as_bool()) == Some(true) {
                "Pause governance enactment as a guardian".to_string()
            } else {
                "Resume governance enactment as a guardian".to_string()
            }
        }
        "GovernanceVetoSignal" => {
            format!(
                "Lock {} TNZO base units against proposal {id}",
                s("amount").unwrap_or_default()
            )
        }
        "GovernanceVetoWithdraw" => format!(
            "Withdraw the veto lock of {} on proposal {id}",
            s("holder").unwrap_or_default()
        ),
        "GovernanceConcern" => format!("Raise a concern on proposal {id}"),
        "UpgradeReady" => format!(
            "Signal readiness for binary {}",
            s("code_hash").unwrap_or_default()
        ),
        "GovernanceSecurityDisclosure" => {
            let empty = body
                .get("disclosure")
                .and_then(|d| d.as_array())
                .is_none_or(|d| d.is_empty());
            if empty {
                format!("Claim the lapse of security fix {id}'s commitment, slashing its proposer")
            } else {
                format!("Reveal the vulnerability security fix {id} committed to")
            }
        }
        "Token" => format!(
            "Exercise an issuer power: {}",
            body.get("op").cloned().unwrap_or_default()
        ),
        "SetAgentTerms" => format!(
            "{} agent terms: {}",
            if body.get("rotate").is_some_and(|r| !r.is_null()) {
                "Replace"
            } else {
                "Delegate an agent under"
            },
            body.get("terms").cloned().unwrap_or_default()
        ),
        "RevokeDelegatedAgent" => format!("Revoke agent {}", s("agent_did").unwrap_or_default()),
        "AgentAct" => format!(
            "Approve one agent action by step-up: {}",
            body.get("action")
                .map(|a| {
                    let mut a = a.clone();
                    if let Some(o) = a.as_object_mut() {
                        o.remove("step_up");
                    }
                    a
                })
                .unwrap_or_default()
        ),
        other => format!("{other}: {body}"),
    }];
    for a in &preimage.approvals {
        lines.push(format!(
            "Passkey approval {} over {} (signs {})",
            a.operation, a.target, a.digest
        ));
    }
    lines.push(format!(
        "From {} on chain {}, nonce {}",
        preimage.from, preimage.chain_id, preimage.nonce
    ));
    lines.push(validity_line(preimage.timestamp, preimage.valid_until));
    lines
}

/// How long the signature stays usable, in words, and when it stops. A long
/// window is called out, since a signature collected now and used weeks later
/// is how pre-signed approvals are abused.
pub fn validity_line(timestamp_ms: i64, valid_until_ms: i64) -> String {
    let window = valid_until_ms.saturating_sub(timestamp_ms).max(0);
    let minutes = window / 60_000;
    let span = if minutes >= 2 * 24 * 60 {
        format!("{} days", minutes / (24 * 60))
    } else if minutes >= 120 {
        format!("{} hours", minutes / 60)
    } else if minutes >= 1 {
        format!("{minutes} minutes")
    } else {
        "under a minute".to_string()
    };
    let until = chrono::DateTime::from_timestamp_millis(valid_until_ms)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("{valid_until_ms} ms"));
    let mut line = format!(
        "Valid for {span} after signing, until {until}; after that this signature can never be used"
    );
    if window > 24 * 60 * 60 * 1000 {
        line.push_str(". This is a long window: whoever holds this signature can use it at any time until then");
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Address, ChainId, Nonce, Timestamp};

    fn vote() -> Transaction {
        Transaction {
            chain_id: ChainId(1337),
            from: Address::new([1; 32]),
            to: Address::new([0; 32]),
            nonce: Nonce(7),
            tx_type: TransactionType::GovernanceVote {
                proposal_id: "ab".repeat(32),
                vote: true,
                validator: Address::new([2; 32]),
                root_approval: None,
            },
            gas_limit: 30_000,
            gas_price: 1,
            timestamp: Timestamp(1_000),
            valid_until: Timestamp(61_000),
            memo: None,
        }
    }

    #[test]
    fn validity_is_stated_in_words_and_long_windows_are_called_out() {
        let short = validity_line(0, 5 * 60_000);
        assert!(
            short.contains("Valid for 5 minutes after signing"),
            "{short}"
        );
        assert!(!short.contains("long window"));
        let long = validity_line(0, 3 * 24 * 60 * 60 * 1000);
        assert!(long.contains("3 days"), "{long}");
        assert!(long.contains("long window"));
        assert!(long.contains("1970-01-04 00:00 UTC"), "{long}");
    }

    #[test]
    fn the_signed_hash_of_a_privileged_action_is_its_typed_digest() {
        let tx = vote();
        assert_eq!(tx.hash().as_bytes(), &typed_action_digest(&tx).unwrap());
        let mut transfer = vote();
        transfer.tx_type = TransactionType::Transfer { amount: 1 };
        assert!(typed_action_digest(&transfer).is_none());
    }

    #[test]
    fn an_action_too_large_for_its_preimage_hashes_and_is_refused() {
        let action = crate::agent_terms::AgentAction {
            agent_did: "did:tenzro:agent:a".into(),
            machine_did: "did:tenzro:machine:m".into(),
            operation: "pay".into(),
            counterparty: String::new(),
            amount: u128::MAX,
            asset: None,
            usd_e6: 0,
            payment: None,
            chain: "tenzro".into(),
            payment_protocol: None,
            model: None,
            calls: Vec::new(),
            escrow: None,
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce: 1,
            tainted: false,
            step_up: Some(crate::agent_terms::AgentTermsApproval {
                account: vec![1; 32],
                nonce: [0; 16],
                root_public_key: Vec::new(),
                signature: crate::account_signature::CompositeSignature::classical(
                    crate::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            }),
        };
        let mut tx = vote();
        tx.tx_type = TransactionType::AgentAct {
            action,
            signature: Vec::new(),
        };
        let p = action_preimage(&tx).expect("still privileged");
        assert!(p.action.get("unencodable").is_some());
        let mut bigger = tx.clone();
        if let TransactionType::AgentAct { action, .. } = &mut bigger.tx_type {
            action.amount -= 1;
        }
        assert_ne!(tx.hash(), bigger.hash());
        assert!(!action_encodes(&tx.tx_type));
        let signed = crate::transaction::SignedTransaction::external(tx);
        assert!(signed.validate().unwrap_err().contains("JSON number"));
    }

    #[test]
    fn decode_round_trips_and_names_the_action() {
        let tx = vote();
        let p = action_preimage(&tx).unwrap();
        let bytes = preimage_bytes(&p);
        let (decoded, digest) = decode_preimage(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(&digest, tx.hash().as_bytes());
        assert!(describe(&decoded)[0].starts_with("Vote YES on proposal abab"));

        let mut spaced = bytes.clone();
        spaced.insert(1, b' ');
        assert!(
            decode_preimage(&spaced).is_err(),
            "a non-canonical encoding is refused"
        );
    }

    #[test]
    fn a_description_never_enters_the_digest() {
        let tx = vote();
        let mut described = tx.clone();
        described.memo = Some("approve the routine parameter change".into());
        assert_eq!(typed_action_digest(&tx), typed_action_digest(&described));
        let signed = crate::transaction::SignedTransaction::new(
            described,
            vec![1; 64],
            crate::account_signature::CompositeSignature::hybrid(
                crate::account_signature::ClassicalProof::Raw {
                    signature: vec![1; 64],
                },
                vec![0; 3309],
            ),
        );
        assert_eq!(
            signed.validate(),
            Err("A privileged transaction carries no memo")
        );
        let mut changed = tx.clone();
        changed.tx_type = TransactionType::GovernanceVote {
            proposal_id: "ab".repeat(32),
            vote: false,
            validator: Address::new([2; 32]),
            root_approval: None,
        };
        assert_ne!(typed_action_digest(&tx), typed_action_digest(&changed));
    }
}
