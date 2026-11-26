//! Finding an identity's keys without trusting the node that answers.
//!
//! An identity's registration is a record in consensus state. The node's
//! copy of it is checked against the state root of a certified checkpoint,
//! with a proof that the identity is or is not revoked under the same root,
//! so a node cannot show different keys to different callers: any answer but
//! the committed one fails the proof. The same holds for its key history:
//! each key with the time it took effect, so a record is judged by the key in
//! force when it was made.

use sha2::{Digest as _, Sha256};
use tenzro_finality::checkpoint::Checkpoint;
pub use tenzro_native_ops::identity_keys::{IdentityHead, IdentityKeyEpoch, IdentityKeyHistory};
use tenzro_native_ops::identity_keys::{identity_head_slot, identity_keys_slot};
use tenzro_types::identity::{RegisterIdentityPayload, identity_slot};

use crate::client::Clock;
use crate::driver::{self, Node};
use crate::error::{Result, malformed};

/// State namespace of account storage.
pub const STATE_NAMESPACE: &str = "state";

/// The account whose storage holds the network's own records.
const SYSTEM_ACCOUNT: [u8; 20] = [0xFF; 20];

/// State key of `slot` in the system account's storage.
pub fn system_slot(slot: &str) -> Vec<u8> {
    format!(
        "storage:{}:{}",
        hex::encode(SYSTEM_ACCOUNT),
        hex::encode(slot)
    )
    .into_bytes()
}

/// The system storage slot holding `did`'s registration record.
pub fn registration_slot(did: &str) -> String {
    identity_slot(did)
}

/// The system storage slot holding `did`'s key history.
pub fn key_history_slot(did: &str) -> String {
    identity_keys_slot(did)
}

/// The system storage slot holding the head of `did`'s logs.
pub fn head_slot(did: &str) -> String {
    identity_head_slot(did)
}

/// System storage slot that is set once an identity is revoked.
pub fn revocation_slot(did: &str) -> String {
    format!("identity_revoked:{did}")
}

/// An identity's keys as consensus state holds them at one certified
/// checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenIdentity {
    /// The DID.
    pub did: String,
    /// Identity class: `human`, `machine` or `institution`.
    pub identity_type: String,
    /// The controller's public key.
    pub controller_key: Vec<u8>,
    /// Key type of `controller_key`.
    pub key_type: String,
    /// The ML-DSA-65 verifying key; empty when the identity enrolled none.
    pub ml_dsa_key: Vec<u8>,
    /// Whether the identity is revoked.
    pub revoked: bool,
    /// Index of the checkpoint the answer is proven under.
    pub checkpoint_index: u64,
    /// Block time of that checkpoint's last block, milliseconds.
    pub checkpoint_time_ms: u64,
}

impl ProvenIdentity {
    /// A digest of the keys and the revocation flag, and of nothing else. An
    /// owner's device keeps it and compares at every start: a different
    /// digest is a key change, and one the owner did not make is an alarm.
    pub fn key_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"tenzro/light/identity-keys/v1");
        for part in [
            self.did.as_bytes(),
            self.key_type.as_bytes(),
            &self.controller_key,
            &self.ml_dsa_key,
        ] {
            h.update((part.len() as u32).to_be_bytes());
            h.update(part);
        }
        h.update([u8::from(self.revoked)]);
        h.finalize().into()
    }
}

/// Resolves `did` at `checkpoint`: its registration record and whether it is
/// revoked, each proven against the checkpoint's state root. `None` is a
/// proof that the DID is not registered. The checkpoint must be within
/// `clock`'s bounds: keys as they were before a change are not an answer.
pub fn resolve(
    node: &mut impl Node,
    checkpoint: &Checkpoint,
    clock: &Clock,
    did: &str,
) -> Result<Option<ProvenIdentity>> {
    let slot = system_slot(&registration_slot(did));
    let Some(record) = driver::state_value(node, checkpoint, clock, STATE_NAMESPACE, &slot)? else {
        return Ok(None);
    };
    let revocation = driver::state_value(
        node,
        checkpoint,
        clock,
        STATE_NAMESPACE,
        &system_slot(&revocation_slot(did)),
    )?;
    proven(checkpoint, did, Some(record), revocation)
}

/// `did`'s identity from the values of its registration slot
/// (`system_slot(&registration_slot(did))`) and its revocation slot
/// (`system_slot(&revocation_slot(did))`), each already checked against the
/// state root `checkpoint` certifies, as [`crate::rpc::state_value`] does. For
/// a caller with its own transport; [`resolve`] fetches and checks both.
pub fn proven(
    checkpoint: &Checkpoint,
    did: &str,
    record: Option<Vec<u8>>,
    revocation: Option<Vec<u8>>,
) -> Result<Option<ProvenIdentity>> {
    let Some(record) = record else {
        return Ok(None);
    };
    let record: RegisterIdentityPayload =
        serde_json::from_slice(&record).map_err(|e| malformed("identity record", e))?;
    if record.did != did {
        return Err(malformed("identity record", "it is another DID's"));
    }
    Ok(Some(ProvenIdentity {
        did: record.did,
        identity_type: record.identity_type,
        controller_key: record.controller_pubkey,
        key_type: record.key_type,
        ml_dsa_key: record.pq_verifying_key,
        revoked: revocation.is_some_and(|marker| !marker.is_empty()),
        checkpoint_index: checkpoint.index,
        checkpoint_time_ms: checkpoint.timestamp_ms,
    }))
}

/// An identity's key history and the head of its chain of logs as consensus
/// state holds them at one certified checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenKeyHistory {
    /// The DID.
    pub did: String,
    /// The keys, oldest first, versions rising by one from 1. Empty while the
    /// identity has recorded no key.
    pub epochs: Vec<IdentityKeyEpoch>,
    /// The head of the identity's logs; zero before the first.
    pub head: IdentityHead,
    /// Index of the checkpoint the answer is proven under.
    pub checkpoint_index: u64,
    /// Block time of that checkpoint, milliseconds.
    pub checkpoint_time_ms: u64,
}

impl ProvenKeyHistory {
    /// The key a record made at `time_ms` must be signed with: the newest
    /// recorded at or before that time. `None` before the first key, after
    /// the checkpoint (the history may have moved on since), and when that
    /// key was declared compromised at or before `time_ms`.
    pub fn key_at(&self, time_ms: u64) -> Option<&IdentityKeyEpoch> {
        if time_ms > self.checkpoint_time_ms {
            return None;
        }
        let key = self
            .epochs
            .iter()
            .rev()
            .find(|k| k.effective_from_ms <= time_ms)?;
        match key.compromised_from_ms {
            Some(from) if from <= time_ms => None,
            _ => Some(key),
        }
    }
}

/// `did`'s key history and log head at `checkpoint`, each proven against its
/// state root. The checkpoint must be within `clock`'s bounds.
pub fn key_history(
    node: &mut impl Node,
    checkpoint: &Checkpoint,
    clock: &Clock,
    did: &str,
) -> Result<ProvenKeyHistory> {
    let keys = driver::state_value(
        node,
        checkpoint,
        clock,
        STATE_NAMESPACE,
        &system_slot(&key_history_slot(did)),
    )?;
    let head = driver::state_value(
        node,
        checkpoint,
        clock,
        STATE_NAMESPACE,
        &system_slot(&head_slot(did)),
    )?;
    proven_key_history(checkpoint, did, keys, head)
}

/// `did`'s key history from the values of its key slot
/// (`system_slot(&key_history_slot(did))`) and its head slot
/// (`system_slot(&head_slot(did))`), each already checked against
/// the state root `checkpoint` certifies. For a caller with its own
/// transport; [`key_history`] fetches and checks both.
pub fn proven_key_history(
    checkpoint: &Checkpoint,
    did: &str,
    keys: Option<Vec<u8>>,
    head: Option<Vec<u8>>,
) -> Result<ProvenKeyHistory> {
    let history: IdentityKeyHistory = match keys.filter(|v| !v.is_empty()) {
        Some(v) => serde_json::from_slice(&v).map_err(|e| malformed("key history", e))?,
        None => IdentityKeyHistory::default(),
    };
    let mut after = 0;
    for (i, key) in history.epochs.iter().enumerate() {
        if key.version != i as u64 + 1 {
            return Err(malformed(
                "key history",
                "versions do not rise by one from 1",
            ));
        }
        if key.effective_from_ms < after || key.effective_from_ms > checkpoint.timestamp_ms {
            return Err(malformed("key history", "a key takes effect out of order"));
        }
        after = key.effective_from_ms;
    }
    let head: IdentityHead = match head.filter(|v| !v.is_empty()) {
        Some(v) => serde_json::from_slice(&v).map_err(|e| malformed("identity head", e))?,
        None => IdentityHead::default(),
    };
    Ok(ProvenKeyHistory {
        did: did.to_string(),
        epochs: history.epochs,
        head,
        checkpoint_index: checkpoint.index,
        checkpoint_time_ms: checkpoint.timestamp_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LightError;
    use crate::testkit::{Net, State};
    use serde_json::Value;
    use tenzro_types::identity::RegistrationProof;
    use tenzro_types::primitives::Address;

    const DID: &str = "did:tenzro:human:7f1c";

    fn record(did: &str, key: u8) -> Vec<u8> {
        serde_json::to_vec(&RegisterIdentityPayload {
            did: did.to_string(),
            identity_type: "human".into(),
            display_name: "A".into(),
            controller_pubkey: vec![key; 65],
            key_type: "P256".into(),
            wallet_id: "w".into(),
            wallet_address: Address::new([9; 32]),
            pq_verifying_key: vec![key; 1952],
            metadata: Default::default(),
            proof: RegistrationProof::Hardware {
                signature: Default::default(),
            },
        })
        .unwrap()
    }

    /// A node answering state proofs from `serves`, whatever the chain holds.
    struct Serving<'a>(&'a State);

    impl Node for Serving<'_> {
        fn call(&mut self, method: &str, params: Value) -> std::result::Result<Value, String> {
            assert_eq!(method, "tenzro_getStateProof");
            self.0.reply(&params)
        }
    }

    /// The chain's state with `entries` in the system account, and a
    /// checkpoint certifying it.
    fn chain(entries: &[(String, Vec<u8>)]) -> (State, Checkpoint) {
        let mut cp = Net::new(4).checkpoint(5);
        let keyed: Vec<(Vec<u8>, &[u8])> = entries
            .iter()
            .map(|(slot, value)| (system_slot(slot), value.as_slice()))
            .collect();
        let entries: Vec<(&str, &[u8], &[u8])> = keyed
            .iter()
            .map(|(key, value)| (STATE_NAMESPACE, key.as_slice(), *value))
            .collect();
        let state = State::new(cp.state_height, &entries);
        cp.state_root = state.root();
        (state, cp)
    }

    fn registered(key: u8) -> Vec<(String, Vec<u8>)> {
        vec![
            (identity_slot(DID), record(DID, key)),
            (
                identity_slot("did:tenzro:human:other"),
                record("did:tenzro:human:other", 7),
            ),
            ("unrelated".to_string(), vec![1]),
        ]
    }

    #[test]
    fn the_committed_keys_are_returned_with_the_checkpoint_they_are_proven_under() {
        let (state, cp) = chain(&registered(1));
        let id = resolve(&mut Serving(&state), &cp, &Net::clock_after(&cp), DID)
            .unwrap()
            .unwrap();
        assert_eq!(id.controller_key, vec![1; 65]);
        assert_eq!(id.ml_dsa_key, vec![1; 1952]);
        assert_eq!(id.key_type, "P256");
        assert!(!id.revoked);
        assert_eq!(id.checkpoint_index, cp.index);
    }

    #[test]
    fn a_node_that_serves_another_key_set_is_detected() {
        let (_, cp) = chain(&registered(1));
        // The node answers from a state in which the DID holds other keys.
        let (forged, _) = chain(&registered(2));
        assert!(matches!(
            resolve(&mut Serving(&forged), &cp, &Net::clock_after(&cp), DID),
            Err(LightError::Proof(_))
        ));
    }

    #[test]
    fn a_node_that_serves_the_keys_from_before_a_change_is_detected() {
        let (old_state, old_cp) = chain(&registered(1));
        let mut newer = registered(2);
        newer.push(("later".to_string(), vec![1]));
        let (_, mut new_cp) = chain(&newer);
        new_cp.index = old_cp.index + 1;
        new_cp.state_height = old_cp.state_height + 4;
        // Asked at the newer checkpoint, the old state's proof is for
        // another height; relabelled to the new height it misses the root.
        assert!(
            resolve(
                &mut Serving(&old_state),
                &new_cp,
                &Net::clock_after(&new_cp),
                DID
            )
            .is_err()
        );
        let mut relabelled = new_cp.clone();
        relabelled.state_height = old_cp.state_height;
        assert!(matches!(
            resolve(
                &mut Serving(&old_state),
                &relabelled,
                &Net::clock_after(&relabelled),
                DID
            ),
            Err(LightError::Proof(_))
        ));
    }

    #[test]
    fn a_revocation_is_seen_and_cannot_be_hidden() {
        let mut entries = registered(1);
        entries.push((revocation_slot(DID), vec![1]));
        let (state, cp) = chain(&entries);
        assert!(
            resolve(&mut Serving(&state), &cp, &Net::clock_after(&cp), DID)
                .unwrap()
                .unwrap()
                .revoked
        );
        // A node hiding the marker answers from the state without it.
        let (hiding, _) = chain(&registered(1));
        assert!(matches!(
            resolve(&mut Serving(&hiding), &cp, &Net::clock_after(&cp), DID),
            Err(LightError::Proof(_))
        ));
    }

    #[test]
    fn an_unregistered_did_is_a_proven_absence() {
        let (state, cp) = chain(&registered(1));
        assert_eq!(
            resolve(
                &mut Serving(&state),
                &cp,
                &Net::clock_after(&cp),
                "did:tenzro:human:nobody"
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn a_record_of_another_did_under_this_did_s_slot_is_refused() {
        let (state, cp) = chain(&[(identity_slot(DID), record("did:tenzro:human:other", 1))]);
        assert!(matches!(
            resolve(&mut Serving(&state), &cp, &Net::clock_after(&cp), DID),
            Err(LightError::Malformed { .. })
        ));
    }

    #[test]
    fn the_key_digest_moves_with_the_keys_and_the_revocation_only() {
        let (state, cp) = chain(&registered(1));
        let id = resolve(&mut Serving(&state), &cp, &Net::clock_after(&cp), DID)
            .unwrap()
            .unwrap();
        let mut later = id.clone();
        later.checkpoint_index += 9;
        later.checkpoint_time_ms += 9_000;
        assert_eq!(later.key_digest(), id.key_digest());
        let mut rotated = id.clone();
        rotated.ml_dsa_key = vec![2; 1952];
        assert_ne!(rotated.key_digest(), id.key_digest());
        let mut revoked = id.clone();
        revoked.revoked = true;
        assert_ne!(revoked.key_digest(), id.key_digest());
    }

    fn key(version: u64, from: u64, compromised: Option<u64>) -> IdentityKeyEpoch {
        IdentityKeyEpoch {
            version,
            ed25519: [version as u8; 32],
            ml_dsa: vec![version as u8; 1952],
            effective_from_ms: from,
            compromised_from_ms: compromised,
            next_commitment: None,
        }
    }

    fn with_keys(epochs: Vec<IdentityKeyEpoch>, head: IdentityHead) -> Vec<(String, Vec<u8>)> {
        let mut entries = registered(1);
        entries.push((
            identity_keys_slot(DID),
            serde_json::to_vec(&IdentityKeyHistory { epochs }).unwrap(),
        ));
        entries.push((identity_head_slot(DID), serde_json::to_vec(&head).unwrap()));
        entries
    }

    fn head(n: u64) -> IdentityHead {
        (0..n).fold(IdentityHead::default(), |h, i| {
            h.advanced(DID, b"IdentityKeyUpdated", &[i as u8])
        })
    }

    #[test]
    fn the_key_in_force_when_a_record_was_made_is_proven() {
        let (_, probe) = chain(&[]);
        let t = probe.timestamp_ms;
        let keys = vec![key(1, t - 3_000, None), key(2, t - 2_000, Some(t - 1_000))];
        let (state, cp) = chain(&with_keys(keys, head(3)));
        let h = key_history(&mut Serving(&state), &cp, &Net::clock_after(&cp), DID).unwrap();
        assert_eq!(h.epochs.len(), 2);
        assert_eq!(h.head, head(3));
        assert_eq!(h.checkpoint_index, cp.index);
        assert!(h.key_at(t - 3_001).is_none());
        assert_eq!(h.key_at(t - 2_500).unwrap().version, 1);
        // Once the second key took effect the first one signs nothing new.
        assert_eq!(h.key_at(t - 1_500).unwrap().version, 2);
        // From its declared compromise the second key signs nothing.
        assert!(h.key_at(t - 1_000).is_none());
        assert!(h.key_at(t + 1).is_none());
    }

    #[test]
    fn a_node_that_hides_a_key_change_is_detected() {
        let (_, probe) = chain(&[]);
        let t = probe.timestamp_ms;
        let (_, cp) = chain(&with_keys(
            vec![key(1, t - 3_000, None), key(2, t - 2_000, None)],
            head(2),
        ));
        let (forged, _) = chain(&with_keys(vec![key(1, t - 3_000, None)], head(1)));
        assert!(matches!(
            key_history(&mut Serving(&forged), &cp, &Net::clock_after(&cp), DID),
            Err(LightError::Proof(_))
        ));
    }

    #[test]
    fn an_identity_with_no_recorded_key_has_an_empty_proven_history() {
        let (state, cp) = chain(&registered(1));
        let h = key_history(&mut Serving(&state), &cp, &Net::clock_after(&cp), DID).unwrap();
        assert!(h.epochs.is_empty());
        assert_eq!(h.head, IdentityHead::default());
        assert!(h.key_at(cp.timestamp_ms).is_none());
    }

    #[test]
    fn a_history_out_of_order_is_refused() {
        let (_, cp) = chain(&[]);
        let t = cp.timestamp_ms;
        let bytes = |epochs| Some(serde_json::to_vec(&IdentityKeyHistory { epochs }).unwrap());
        for epochs in [
            vec![key(2, t - 1, None)],
            vec![key(1, t - 1, None), key(3, t, None)],
            vec![key(1, t - 1, None), key(2, t - 2, None)],
            vec![key(1, t + 1, None)],
        ] {
            assert!(matches!(
                proven_key_history(&cp, DID, bytes(epochs), None),
                Err(LightError::Malformed { .. })
            ));
        }
    }
}
