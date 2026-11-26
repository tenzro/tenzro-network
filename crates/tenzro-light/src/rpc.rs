//! The node's replies, read and checked.
//!
//! Each function takes the JSON result of one read method as the node
//! returned it. The caller does the transport; every SDK shares what is
//! checked.

use serde_json::Value;
use tenzro_finality::checkpoint::Checkpoint;
use tenzro_finality::committee::Member;
use tenzro_state_proof::StateProof;
use tenzro_types::hash_scheme::HashScheme;

use crate::client::{Clock, LightClient};
use crate::error::{Result, malformed};
use crate::state::{StateClaim, verify_state};
use crate::wire;

fn text<'a>(reply: &'a Value, what: &'static str, field: &str) -> Result<&'a str> {
    reply
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(what, format!("no '{field}'")))
}

/// The members in a `tenzro_getCommittee` reply. They are not trusted until
/// [`LightClient::new`] holds them to an anchor's root.
pub fn committee_members(reply: &Value) -> Result<Vec<Member>> {
    wire::members(text(reply, "committee reply", "members")?)
}

/// [`LightClient::certified`] over a `tenzro_getCheckpointCertificate` reply.
pub fn certified(client: &mut LightClient, reply: &Value) -> Result<Checkpoint> {
    let certificate = wire::certificate(text(reply, "certificate reply", "certificate")?)?;
    let sessions = wire::sessions(text(reply, "certificate reply", "sessions")?)?;
    client.certified(&certificate, sessions)
}

/// [`LightClient::advance`] over a `tenzro_getCheckpointCertificate` reply.
pub fn advance(client: &mut LightClient, reply: &Value, clock: &Clock) -> Result<Checkpoint> {
    let certificate = wire::certificate(text(reply, "certificate reply", "certificate")?)?;
    let sessions = wire::sessions(text(reply, "certificate reply", "sessions")?)?;
    client.advance(&certificate, sessions, clock).cloned()
}

/// [`LightClient::advance_compact`] over a `tenzro_getCompactCertificate`
/// reply.
#[cfg(feature = "compact")]
pub fn advance_compact(
    client: &mut LightClient,
    reply: &Value,
    clock: &Clock,
) -> Result<Checkpoint> {
    let what = "compact certificate reply";
    let certificate = wire::compact_certificate(text(reply, what, "certificate")?)?;
    let sessions = wire::sessions(text(reply, what, "sessions")?)?;
    client
        .advance_compact(&certificate, sessions, clock)
        .cloned()
}

/// [`LightClient::hand_over`] over a `tenzro_getEpochHandover` reply.
pub fn hand_over(client: &mut LightClient, reply: &Value) -> Result<()> {
    let certificate = wire::certificate(text(reply, "handover reply", "certificate")?)?;
    let sessions = wire::sessions(text(reply, "handover reply", "sessions")?)?;
    let next = wire::members(text(reply, "handover reply", "next_members")?)?;
    client.hand_over(&certificate, sessions, next)
}

/// The value a `tenzro_getStateProof` reply gives for the entry
/// (`namespace`, `key`) the caller asked for, checked against the state root
/// `checkpoint` certifies. `None` is a proven absence.
pub fn state_value(
    checkpoint: &Checkpoint,
    namespace: &str,
    key: &[u8],
    reply: &Value,
) -> Result<Option<Vec<u8>>> {
    let what = "state proof reply";
    let field = |name: &str| {
        reply
            .get(name)
            .ok_or_else(|| malformed(what, format!("no '{name}'")))
    };
    let height = field("height")?
        .as_u64()
        .ok_or_else(|| malformed(what, "'height' is not a number"))?;
    let scheme: HashScheme = serde_json::from_value(field("state_trie_hash")?.clone())
        .map_err(|e| malformed(what, e))?;
    let proof: StateProof =
        serde_json::from_value(field("proof")?.clone()).map_err(|e| malformed(what, e))?;
    let value = match reply.get("value") {
        None | Some(Value::Null) => None,
        Some(Value::String(v)) => Some(wire::bytes(what, v)?),
        Some(_) => return Err(malformed(what, "'value' is not hex")),
    };
    verify_state(
        checkpoint,
        &StateClaim {
            height,
            scheme,
            namespace,
            key,
            value: value.as_deref(),
            proof: &proof,
        },
    )?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LightError;
    use crate::testkit::Net;
    use serde_json::json;
    use tenzro_state_proof::hashing::{
        EMPTY, leaf_hash, slots_root_from_path, split_tree_key, stem_hash, tree_key,
    };
    use tenzro_state_proof::{ProofError, ProofTerminal};

    fn hex_bincode<T: serde::Serialize>(v: &T) -> String {
        format!("0x{}", hex::encode(bincode::serialize(v).unwrap()))
    }

    /// The root of a state holding the one entry (`namespace`, `key`) =
    /// `value`, and the entry's proof.
    fn one_entry_state(namespace: &str, key: &[u8], value: &[u8]) -> ([u8; 32], StateProof) {
        let scheme = HashScheme::Sha256;
        let (stem, slot) = split_tree_key(&tree_key(namespace, key));
        let slot_siblings = [EMPTY; 8];
        let slots = slots_root_from_path(scheme, slot, leaf_hash(scheme, value), &slot_siblings);
        let proof = StateProof {
            siblings: Vec::new(),
            terminal: ProofTerminal::Stem { slot_siblings },
        };
        (stem_hash(scheme, &stem, &slots), proof)
    }

    #[test]
    fn replies_drive_the_client_from_anchor_through_a_handover() {
        let net = Net::new(4);
        let next = net.next_epoch(4);
        let members = committee_members(&json!({ "members": hex_bincode(&net.members) })).unwrap();
        let mut lc = LightClient::new(&net.anchor(), members).unwrap();

        let (cert, sessions) = net.certify(&net.checkpoint(2), &[0, 1, 3]);
        let reply =
            json!({ "certificate": hex_bincode(&cert), "sessions": hex_bincode(&sessions) });
        assert_eq!(advance(&mut lc, &reply, &Net::clock()).unwrap().index, 2);

        let mut last = net.checkpoint(3);
        last.next_committee_root = Some(next.committee().root());
        let (cert, sessions) = net.certify(&last, &[0, 1, 2]);
        let reply = json!({
            "certificate": hex_bincode(&cert),
            "sessions": hex_bincode(&sessions),
            "next_members": hex_bincode(&next.members),
        });
        hand_over(&mut lc, &reply).unwrap();
        assert_eq!(lc.epoch(), 1);
    }

    #[test]
    fn a_reply_with_trailing_or_truncated_bytes_is_refused() {
        let net = Net::new(4);
        let (cert, sessions) = net.certify(&net.checkpoint(2), &[0, 1, 2]);
        let good = hex_bincode(&cert);
        for bad in [format!("{good}00"), good[..good.len() - 2].to_string()] {
            let reply = json!({ "certificate": bad, "sessions": hex_bincode(&sessions) });
            assert!(matches!(
                advance(&mut net.client(), &reply, &Net::clock()),
                Err(LightError::Malformed { .. })
            ));
        }
    }

    #[test]
    fn a_state_value_is_accepted_only_under_the_certified_root() {
        let net = Net::new(4);
        let (root, proof) = one_entry_state("state", b"k", b"value");
        let mut cp = net.checkpoint(5);
        cp.state_root = root;
        let reply = |height: u64, value: &[u8]| {
            json!({
                "height": height,
                "state_trie_hash": "sha256",
                "value": hex::encode(value),
                "proof": proof,
            })
        };
        let honest = reply(cp.state_height, b"value");
        assert_eq!(
            state_value(&cp, "state", b"k", &honest).unwrap().as_deref(),
            Some(&b"value"[..])
        );
        // Another value, another key, another height, another root.
        assert!(matches!(
            state_value(&cp, "state", b"k", &reply(cp.state_height, b"other")),
            Err(LightError::Proof(ProofError::RootMismatch { .. }))
        ));
        assert!(matches!(
            state_value(&cp, "state", b"j", &honest),
            Err(LightError::Proof(_))
        ));
        assert!(matches!(
            state_value(&cp, "state", b"k", &reply(cp.state_height + 1, b"value")),
            Err(LightError::HeightMismatch { .. })
        ));
        let elsewhere = net.checkpoint(5);
        assert!(matches!(
            state_value(&elsewhere, "state", b"k", &honest),
            Err(LightError::Proof(ProofError::RootMismatch { .. }))
        ));
    }

    #[test]
    fn a_proof_under_a_scheme_the_trie_never_holds_is_refused() {
        let net = Net::new(4);
        let (root, proof) = one_entry_state("state", b"k", b"value");
        let mut cp = net.checkpoint(5);
        cp.state_root = root;
        let reply = json!({
            "height": cp.state_height,
            "state_trie_hash": "blake3",
            "value": hex::encode(b"value"),
            "proof": proof,
        });
        assert!(matches!(
            state_value(&cp, "state", b"k", &reply),
            Err(LightError::UnknownScheme)
        ));
    }
}
