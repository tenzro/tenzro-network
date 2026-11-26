//! The Tenzro light client for apps on Android, iOS and macOS.
//!
//! One Rust core, exported through UniFFI, so Kotlin and Swift run the same
//! checks as the Rust and TypeScript SDKs instead of a copy of them. The app
//! supplies the transport ([`Transport`]: one JSON-RPC call over its own HTTP
//! stack), so the library carries no network code. Every call is
//! synchronous; the app runs it off its main thread.
//!
//! Preview: the surface may change before it is stable.

use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::Value;
use tenzro_light::driver::{self, Node};
use tenzro_light::{Checkpoint, identity, rpc, wire};

uniffi::setup_scaffolding!();

/// Why a call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LightError {
    /// The node's answer, or the check of it, failed: the answer is not
    /// taken.
    #[error("{reason}")]
    Refused {
        /// What was refused and why.
        reason: String,
    },
    /// The client found two certificates that contradict each other and
    /// checks nothing until [`LightClient::resume`].
    #[error("the client stopped on conflicting certificates")]
    Stopped,
    /// An argument could not be read.
    #[error("{reason}")]
    Argument {
        /// Which argument and why.
        reason: String,
    },
    /// No checkpoint is certified yet: call [`LightClient::sync`] first.
    #[error("no checkpoint is certified yet")]
    NotSynced,
}

impl From<tenzro_light::LightError> for LightError {
    fn from(e: tenzro_light::LightError) -> Self {
        match e {
            tenzro_light::LightError::Stopped | tenzro_light::LightError::Conflict(_) => {
                LightError::Stopped
            }
            other => LightError::Refused {
                reason: other.to_string(),
            },
        }
    }
}

/// Why the app's transport could not deliver a call.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TransportError {
    /// The call failed: no connection, an HTTP error, or the node's JSON-RPC
    /// error.
    #[error("{reason}")]
    Failed {
        /// What the transport or the node reported.
        reason: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for TransportError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TransportError::Failed { reason: e.reason }
    }
}

/// One JSON-RPC call to a node, made by the app.
#[uniffi::export(with_foreign)]
pub trait Transport: Send + Sync {
    /// Calls `method` with `params_json` (a JSON value) and returns the
    /// reply's `result` as JSON.
    fn call(&self, method: String, params_json: String) -> Result<String, TransportError>;
}

/// The light client's driver over the app's transport.
struct Foreign<'a>(&'a dyn Transport);

impl Node for Foreign<'_> {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let reply = self
            .0
            .call(method.to_string(), params.to_string())
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&reply).map_err(|e| format!("the reply is not JSON: {e}"))
    }
}

/// The caller's clock and how far a checkpoint's block time may be from it.
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct Clock {
    /// The device's time, milliseconds since the Unix epoch.
    pub now_ms: u64,
    /// Oldest a checkpoint may be.
    pub max_age_ms: u64,
    /// Furthest a checkpoint's time may be ahead of `now_ms`.
    pub max_ahead_ms: u64,
}

impl From<Clock> for tenzro_light::Clock {
    fn from(c: Clock) -> Self {
        tenzro_light::Clock {
            now_ms: c.now_ms,
            max_age_ms: c.max_age_ms,
            max_ahead_ms: c.max_ahead_ms,
        }
    }
}

/// A certified checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CertifiedCheckpoint {
    /// Epoch.
    pub epoch: u64,
    /// Index, counted from genesis.
    pub index: u64,
    /// First block height covered; one past `last_height` when it covers
    /// none.
    pub first_height: u64,
    /// Last block height covered.
    pub last_height: u64,
    /// The height whose state `state_root` is.
    pub state_height: u64,
    /// The certified state root.
    pub state_root: Vec<u8>,
    /// Block time of the last covered block, milliseconds.
    pub timestamp_ms: u64,
}

impl From<&Checkpoint> for CertifiedCheckpoint {
    fn from(c: &Checkpoint) -> Self {
        CertifiedCheckpoint {
            epoch: c.epoch,
            index: c.index,
            first_height: c.first_height,
            last_height: c.last_height,
            state_height: c.state_height,
            state_root: c.state_root.to_vec(),
            timestamp_ms: c.timestamp_ms,
        }
    }
}

/// An identity's keys as a certified checkpoint holds them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProvenIdentity {
    /// The DID.
    pub did: String,
    /// `human`, `machine` or `institution`.
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
    /// Block time of that checkpoint, milliseconds.
    pub checkpoint_time_ms: u64,
    /// Digest of the keys and the revocation flag. An owner's device keeps
    /// it and compares at every start: a change it did not make is an alarm.
    pub key_digest: Vec<u8>,
}

impl From<identity::ProvenIdentity> for ProvenIdentity {
    fn from(p: identity::ProvenIdentity) -> Self {
        let key_digest = p.key_digest().to_vec();
        ProvenIdentity {
            did: p.did,
            identity_type: p.identity_type,
            controller_key: p.controller_key,
            key_type: p.key_type,
            ml_dsa_key: p.ml_dsa_key,
            revoked: p.revoked,
            checkpoint_index: p.checkpoint_index,
            checkpoint_time_ms: p.checkpoint_time_ms,
            key_digest,
        }
    }
}

/// One identity key and when it was in force.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyEpoch {
    /// The key's version: 1 for the first, rising by one.
    pub version: u64,
    /// The Ed25519 public key.
    pub ed25519: Vec<u8>,
    /// The ML-DSA-65 public key.
    pub ml_dsa: Vec<u8>,
    /// Block time (ms) the chain recorded the key.
    pub effective_from_ms: u64,
    /// Block time (ms) the identity declared the key compromised.
    pub compromised_from_ms: Option<u64>,
}

impl From<&identity::IdentityKeyEpoch> for KeyEpoch {
    fn from(k: &identity::IdentityKeyEpoch) -> Self {
        KeyEpoch {
            version: k.version,
            ed25519: k.ed25519.to_vec(),
            ml_dsa: k.ml_dsa.clone(),
            effective_from_ms: k.effective_from_ms,
            compromised_from_ms: k.compromised_from_ms,
        }
    }
}

/// An identity's key history and the head of its logs as a certified
/// checkpoint holds them.
#[derive(uniffi::Object)]
pub struct KeyHistory(tenzro_light::ProvenKeyHistory);

#[uniffi::export]
impl KeyHistory {
    /// The keys, oldest first.
    pub fn epochs(&self) -> Vec<KeyEpoch> {
        self.0.epochs.iter().map(KeyEpoch::from).collect()
    }

    /// The key a record made at `time_ms` must be signed with: the newest
    /// recorded at or before that time; `None` before the first key, after
    /// the checkpoint, and from a declared compromise of that key.
    pub fn key_at(&self, time_ms: u64) -> Option<KeyEpoch> {
        self.0.key_at(time_ms).map(KeyEpoch::from)
    }

    /// Logs recorded about the identity so far.
    pub fn sequence(&self) -> u64 {
        self.0.head.sequence
    }

    /// Digest of the identity's latest log; zero before the first.
    pub fn head(&self) -> Vec<u8> {
        self.0.head.head.to_vec()
    }

    /// Index of the checkpoint the answer is proven under.
    pub fn checkpoint_index(&self) -> u64 {
        self.0.checkpoint_index
    }
}

fn argument(what: &str, e: impl std::fmt::Display) -> LightError {
    LightError::Argument {
        reason: format!("{what}: {e}"),
    }
}

/// A light client of one chain.
#[derive(uniffi::Object)]
pub struct LightClient {
    inner: Mutex<tenzro_light::LightClient>,
}

impl LightClient {
    fn client(&self) -> MutexGuard<'_, tenzro_light::LightClient> {
        // A panic inside a check leaves the client as it was before the
        // check: every change is made after the checks pass.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn certified(&self) -> Result<Checkpoint, LightError> {
        self.client().latest().cloned().ok_or(LightError::NotSynced)
    }
}

#[uniffi::export]
impl LightClient {
    /// A client trusting the committee of `epoch` whose root is
    /// `committee_root` (32 bytes, hex). `committee_reply_json` is a node's
    /// reply to `tenzro_getCommittee` for that epoch; its members are kept
    /// only when they hash to the root.
    #[uniffi::constructor]
    pub fn new(
        chain_id: u64,
        genesis_hash: String,
        epoch: u64,
        committee_root: String,
        committee_reply_json: String,
    ) -> Result<Arc<Self>, LightError> {
        let anchor = tenzro_light::TrustAnchor {
            chain_id,
            genesis_hash: wire::digest("genesis hash", &genesis_hash)?,
            epoch,
            committee_root: wire::digest("committee root", &committee_root)?,
        };
        let reply: Value = serde_json::from_str(&committee_reply_json)
            .map_err(|e| argument("committee reply", e))?;
        let members = rpc::committee_members(&reply)?;
        Ok(Arc::new(LightClient {
            inner: Mutex::new(tenzro_light::LightClient::new(&anchor, members)?),
        }))
    }

    /// A client from bytes [`Self::save`] wrote, refused when damaged, of
    /// another chain, or behind `at_least_index`, the checkpoint index the
    /// app last saw this client reach.
    #[uniffi::constructor]
    pub fn restore(
        saved: Vec<u8>,
        chain_id: u64,
        genesis_hash: String,
        at_least_index: u64,
    ) -> Result<Arc<Self>, LightError> {
        let genesis = wire::digest("genesis hash", &genesis_hash)?;
        let client =
            tenzro_light::LightClient::restore(&saved, chain_id, &genesis, at_least_index)?;
        Ok(Arc::new(LightClient {
            inner: Mutex::new(client),
        }))
    }

    /// The client's state for the app to keep. Keeping it from being
    /// replaced by an older copy is the app's job.
    pub fn save(&self) -> Vec<u8> {
        self.client().save()
    }

    /// Epoch of the committee the client trusts now.
    pub fn epoch(&self) -> u64 {
        self.client().epoch()
    }

    /// The newest checkpoint certified so far.
    pub fn latest(&self) -> Option<CertifiedCheckpoint> {
        self.client().latest().map(CertifiedCheckpoint::from)
    }

    /// The two certificates that stopped the client, as JSON, if any.
    pub fn conflict_json(&self) -> Option<String> {
        self.client()
            .conflict()
            .map(|c| serde_json::to_string(c).expect("a conflict encodes"))
    }

    /// Lets a stopped client check certificates again.
    pub fn resume(&self) {
        self.client().resume();
    }

    /// Follows the node to its newest certified checkpoint, through every
    /// epoch handover since the client's committee, and returns it. The
    /// checkpoint must be within `clock`'s bounds.
    pub fn sync(
        &self,
        transport: Arc<dyn Transport>,
        clock: Clock,
    ) -> Result<CertifiedCheckpoint, LightError> {
        let mut client = self.client();
        let checkpoint =
            driver::sync(&mut client, &mut Foreign(transport.as_ref()), &clock.into())?;
        Ok(CertifiedCheckpoint::from(&checkpoint))
    }

    /// The value of the entry (`namespace`, `key`) in the state of the newest
    /// certified checkpoint, checked against its root. `None` is a proven
    /// absence.
    pub fn state_value(
        &self,
        transport: Arc<dyn Transport>,
        namespace: String,
        key: Vec<u8>,
        clock: Clock,
    ) -> Result<Option<Vec<u8>>, LightError> {
        let checkpoint = self.certified()?;
        Ok(driver::state_value(
            &mut Foreign(transport.as_ref()),
            &checkpoint,
            &clock.into(),
            &namespace,
            &key,
        )?)
    }

    /// `did`'s keys and whether it is revoked, proven against the newest
    /// certified checkpoint. `None` is a proof that the DID is not
    /// registered.
    pub fn resolve_identity(
        &self,
        transport: Arc<dyn Transport>,
        did: String,
        clock: Clock,
    ) -> Result<Option<ProvenIdentity>, LightError> {
        let checkpoint = self.certified()?;
        Ok(identity::resolve(
            &mut Foreign(transport.as_ref()),
            &checkpoint,
            &clock.into(),
            &did,
        )?
        .map(ProvenIdentity::from))
    }

    /// `did`'s key history and the head of its logs, proven against the
    /// newest certified checkpoint.
    pub fn key_history(
        &self,
        transport: Arc<dyn Transport>,
        did: String,
        clock: Clock,
    ) -> Result<Arc<KeyHistory>, LightError> {
        let checkpoint = self.certified()?;
        Ok(Arc::new(KeyHistory(identity::key_history(
            &mut Foreign(transport.as_ref()),
            &checkpoint,
            &clock.into(),
            &did,
        )?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tenzro_light::identity::IdentityKeyHistory;
    use tenzro_light::testkit::{CHAIN_ID, GENESIS, Net, State};
    use tenzro_types::identity::{RegisterIdentityPayload, RegistrationProof, identity_slot};
    use tenzro_types::primitives::Address;

    const DID: &str = "did:tenzro:human:7f1c";

    fn hex_bincode<T: serde::Serialize>(v: &T) -> String {
        format!("0x{}", hex::encode(bincode::serialize(v).unwrap()))
    }

    fn record(key: u8) -> Vec<u8> {
        serde_json::to_vec(&RegisterIdentityPayload {
            did: DID.to_string(),
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

    /// A node of one epoch whose newest certified checkpoint commits a state
    /// holding the chain id and one identity with keys `key` and one recorded
    /// key change.
    struct OneEpoch {
        net: Net,
        checkpoint: Checkpoint,
        state: State,
    }

    impl OneEpoch {
        fn new(key: u8) -> Self {
            let net = Net::new(4);
            let mut checkpoint = net.checkpoint(5);
            let chain_slot = identity::system_slot("network:chain_id");
            let id_slot = identity::system_slot(&identity_slot(DID));
            let chain_id = CHAIN_ID.to_le_bytes();
            let id = record(key);
            let keys_slot = identity::system_slot(&identity::key_history_slot(DID));
            let keys = serde_json::to_vec(&IdentityKeyHistory {
                epochs: vec![identity::IdentityKeyEpoch {
                    version: 1,
                    ed25519: [key; 32],
                    ml_dsa: vec![key; 1952],
                    effective_from_ms: checkpoint.timestamp_ms - 1_000,
                    compromised_from_ms: None,
                    next_commitment: None,
                }],
            })
            .unwrap();
            let head_slot = identity::system_slot(&identity::head_slot(DID));
            let head = identity::IdentityHead::default().advanced(DID, b"IdentityKeyUpdated", b"k");
            let head = serde_json::to_vec(&head).unwrap();
            let ns = identity::STATE_NAMESPACE;
            let state = State::new(
                checkpoint.state_height,
                &[
                    (ns, &chain_slot, &chain_id),
                    (ns, &id_slot, &id),
                    (ns, &keys_slot, &keys),
                    (ns, &head_slot, &head),
                ],
            );
            checkpoint.state_root = state.root();
            OneEpoch {
                net,
                checkpoint,
                state,
            }
        }

        fn committee_reply(&self) -> String {
            json!({ "members": hex_bincode(&self.net.members) }).to_string()
        }

        fn clock(&self) -> Clock {
            Clock {
                now_ms: self.checkpoint.timestamp_ms + 1_000,
                max_age_ms: 60_000,
                max_ahead_ms: 5_000,
            }
        }

        fn client(&self) -> Arc<LightClient> {
            LightClient::new(
                CHAIN_ID,
                hex::encode(GENESIS),
                0,
                hex::encode(self.net.anchor().committee_root),
                self.committee_reply(),
            )
            .unwrap()
        }
    }

    impl Transport for OneEpoch {
        fn call(&self, method: String, params_json: String) -> Result<String, TransportError> {
            let params: Value = serde_json::from_str(&params_json).unwrap();
            let fail = |reason: String| TransportError::Failed { reason };
            let reply = match method.as_str() {
                "tenzro_getCheckpointCertificate" => {
                    let (cert, sessions) = self.net.certify(&self.checkpoint, &[0, 1, 2]);
                    json!({
                        "epoch": 0,
                        "certificate": hex_bincode(&cert),
                        "sessions": hex_bincode(&sessions),
                    })
                }
                "tenzro_getStateProof" => self.state.reply(&params).map_err(fail)?,
                other => return Err(fail(format!("unexpected call {other}"))),
            };
            Ok(reply.to_string())
        }
    }

    /// A transport that only fails.
    struct Down;

    impl Transport for Down {
        fn call(&self, _: String, _: String) -> Result<String, TransportError> {
            Err(TransportError::Failed {
                reason: "connection refused".into(),
            })
        }
    }

    #[test]
    fn a_client_syncs_and_proves_keys_and_state_through_the_app_s_transport() {
        let node = Arc::new(OneEpoch::new(1));
        let lc = node.client();
        let cp = lc.sync(node.clone(), node.clock()).unwrap();
        assert_eq!(cp, CertifiedCheckpoint::from(&node.checkpoint));
        assert_eq!(lc.latest(), Some(cp));

        let id = lc
            .resolve_identity(node.clone(), DID.into(), node.clock())
            .unwrap()
            .unwrap();
        assert_eq!(id.controller_key, vec![1; 65]);
        assert_eq!(id.ml_dsa_key, vec![1; 1952]);
        assert!(!id.revoked);
        assert_eq!(id.key_digest.len(), 32);

        let chain_id = lc
            .state_value(
                node.clone(),
                identity::STATE_NAMESPACE.into(),
                identity::system_slot("network:chain_id"),
                node.clock(),
            )
            .unwrap();
        assert_eq!(chain_id, Some(CHAIN_ID.to_le_bytes().to_vec()));
        assert_eq!(
            lc.resolve_identity(node.clone(), "did:tenzro:human:nobody".into(), node.clock())
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_node_that_serves_another_key_set_is_refused() {
        let honest = Arc::new(OneEpoch::new(1));
        let lc = honest.client();
        lc.sync(honest.clone(), honest.clock()).unwrap();
        // Same committee and checkpoint, a state in which the DID holds other keys.
        let forged = Arc::new(OneEpoch {
            state: OneEpoch::new(2).state,
            ..OneEpoch::new(1)
        });
        assert!(matches!(
            lc.resolve_identity(forged, DID.into(), honest.clock()),
            Err(LightError::Refused { .. })
        ));
    }

    #[test]
    fn nothing_is_read_before_a_checkpoint_is_certified() {
        let node = Arc::new(OneEpoch::new(1));
        assert!(matches!(
            node.client()
                .resolve_identity(node.clone(), DID.into(), node.clock()),
            Err(LightError::NotSynced)
        ));
    }

    #[test]
    fn a_transport_failure_is_reported_and_nothing_is_taken() {
        let node = OneEpoch::new(1);
        let lc = node.client();
        match lc.sync(Arc::new(Down), node.clock()) {
            Err(LightError::Refused { reason }) => {
                assert!(reason.contains("connection refused"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(lc.latest(), None);
    }

    #[test]
    fn saved_state_restores_and_refuses_a_rollback() {
        let node = Arc::new(OneEpoch::new(1));
        let lc = node.client();
        let before = lc.save();
        lc.sync(node.clone(), node.clock()).unwrap();
        let back = LightClient::restore(lc.save(), CHAIN_ID, hex::encode(GENESIS), 5).unwrap();
        assert_eq!(back.latest(), lc.latest());
        assert!(matches!(
            LightClient::restore(before, CHAIN_ID, hex::encode(GENESIS), 5),
            Err(LightError::Refused { .. })
        ));
    }

    #[test]
    fn members_that_do_not_hash_to_the_root_are_refused() {
        let node = OneEpoch::new(1);
        let other = Net::new(5);
        let reply = json!({ "members": hex_bincode(&other.members) }).to_string();
        assert!(matches!(
            LightClient::new(
                CHAIN_ID,
                hex::encode(GENESIS),
                0,
                hex::encode(node.net.anchor().committee_root),
                reply,
            ),
            Err(LightError::Refused { .. })
        ));
    }

    /// A transport that records every call for the shared fixture.
    struct Recorder {
        node: Arc<OneEpoch>,
        calls: Mutex<Vec<Value>>,
    }

    impl Transport for Recorder {
        fn call(&self, method: String, params_json: String) -> Result<String, TransportError> {
            let result = self.node.call(method.clone(), params_json.clone())?;
            self.calls.lock().unwrap().push(json!({
                "method": method,
                "params": params_json,
                "result": result,
            }));
            Ok(result)
        }
    }

    /// A transport that answers each call with the reply the fixture recorded.
    struct Replay(Vec<Value>);

    impl Transport for Replay {
        fn call(&self, method: String, params_json: String) -> Result<String, TransportError> {
            self.0
                .iter()
                .find(|c| c["method"] == method.as_str() && c["params"] == params_json.as_str())
                .and_then(|c| c["result"].as_str())
                .map(str::to_string)
                .ok_or_else(|| TransportError::Failed {
                    reason: format!("no recorded reply to {method} {params_json}"),
                })
        }
    }

    /// The fixture the Kotlin and Swift packages replay through their own
    /// transports.
    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/light-client/fixture.json")
    }

    /// What one session yields: a sync, a registered DID and an absent one,
    /// and the registered DID's key history.
    fn session(lc: &LightClient, transport: Arc<dyn Transport>, clock: Clock) -> Value {
        let cp = lc.sync(transport.clone(), clock).unwrap();
        let id = lc
            .resolve_identity(transport.clone(), DID.into(), clock)
            .unwrap()
            .unwrap();
        let absent = "did:tenzro:human:nobody";
        assert!(
            lc.resolve_identity(transport.clone(), absent.into(), clock)
                .unwrap()
                .is_none()
        );
        let history = lc.key_history(transport, DID.into(), clock).unwrap();
        let key = history.key_at(cp.timestamp_ms).unwrap();
        assert!(history.key_at(key.effective_from_ms - 1).is_none());
        json!({
            "checkpoint": {
                "epoch": cp.epoch,
                "index": cp.index,
                "state_root": hex::encode(&cp.state_root),
                "timestamp_ms": cp.timestamp_ms,
            },
            "identity": {
                "did": id.did,
                "identity_type": id.identity_type,
                "key_type": id.key_type,
                "controller_key": hex::encode(&id.controller_key),
                "ml_dsa_key": hex::encode(&id.ml_dsa_key),
                "revoked": id.revoked,
                "checkpoint_index": id.checkpoint_index,
                "key_digest": hex::encode(&id.key_digest),
            },
            "absent_did": absent,
            "key_history": {
                "keys": history.epochs().len(),
                "version": key.version,
                "ed25519": hex::encode(&key.ed25519),
                "effective_from_ms": key.effective_from_ms,
                "sequence": history.sequence(),
                "head": hex::encode(history.head()),
            },
        })
    }

    #[test]
    fn the_shared_fixture_replays_through_the_ffi() {
        // TENZRO_WRITE_LIGHT_FIXTURE=1 records a fresh session into the fixture.
        if std::env::var_os("TENZRO_WRITE_LIGHT_FIXTURE").is_some() {
            let node = Arc::new(OneEpoch::new(1));
            let recorder = Arc::new(Recorder {
                node: node.clone(),
                calls: Mutex::new(Vec::new()),
            });
            let clock = node.clock();
            let expect = session(&node.client(), recorder.clone(), clock);
            let fixture = json!({
                "chain_id": CHAIN_ID,
                "genesis_hash": hex::encode(GENESIS),
                "epoch": 0,
                "committee_root": hex::encode(node.net.anchor().committee_root),
                "committee_reply": node.committee_reply(),
                "clock": {
                    "now_ms": clock.now_ms,
                    "max_age_ms": clock.max_age_ms,
                    "max_ahead_ms": clock.max_ahead_ms,
                },
                "calls": recorder.calls.lock().unwrap().clone(),
                "expect": expect,
            });
            let path = fixture_path();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&fixture).unwrap() + "\n",
            )
            .unwrap();
        }
        let f: Value =
            serde_json::from_str(&std::fs::read_to_string(fixture_path()).unwrap()).unwrap();
        let text = |k: &str| f[k].as_str().unwrap().to_string();
        let lc = LightClient::new(
            f["chain_id"].as_u64().unwrap(),
            text("genesis_hash"),
            f["epoch"].as_u64().unwrap(),
            text("committee_root"),
            text("committee_reply"),
        )
        .unwrap();
        let c = &f["clock"];
        let clock = Clock {
            now_ms: c["now_ms"].as_u64().unwrap(),
            max_age_ms: c["max_age_ms"].as_u64().unwrap(),
            max_ahead_ms: c["max_ahead_ms"].as_u64().unwrap(),
        };
        let replay = Arc::new(Replay(f["calls"].as_array().unwrap().clone()));
        assert_eq!(session(&lc, replay, clock), f["expect"]);
    }
}
