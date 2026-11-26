//! A light client over this SDK's node connection (feature `light`, preview).
//!
//! It starts from a committee the caller trusts, follows the committee from
//! epoch to epoch through the handover each epoch's last checkpoint commits,
//! and accepts a checkpoint only under a certificate a quorum of the current
//! committee's seats signed. State values and identity keys are then checked
//! against the certified state root, so nothing the node says is taken on
//! trust. The checks are `tenzro-light`'s, the same the Kotlin and Swift
//! packages run; this module only fetches what they check.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_light::{identity, rpc};

pub use tenzro_light::{
    Checkpoint, Clock, LightError, ProvenIdentity, ProvenKeyHistory, TrustAnchor,
};

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;

/// A light client of one chain, reading through the SDK's node connection.
pub struct LightClient {
    rpc: Arc<RpcClient>,
    inner: tenzro_light::LightClient,
}

impl LightClient {
    /// A client trusting `anchor`'s committee. The node's members for that
    /// epoch are kept only when they hash to the anchor's root.
    pub async fn new(rpc: Arc<RpcClient>, anchor: &TrustAnchor) -> SdkResult<Self> {
        let reply: Value = rpc
            .call("tenzro_getCommittee", json!([anchor.epoch]))
            .await?;
        let members = rpc::committee_members(&reply)?;
        let inner = tenzro_light::LightClient::new(anchor, members)?;
        Ok(Self { rpc, inner })
    }

    /// A client from bytes [`Self::save`] wrote, refused when damaged, of
    /// another chain, or behind `at_least_index`, the checkpoint index the
    /// caller last saw this client reach.
    pub fn restore(
        rpc: Arc<RpcClient>,
        saved: &[u8],
        chain_id: u64,
        genesis_hash: &[u8; 32],
        at_least_index: u64,
    ) -> SdkResult<Self> {
        let inner =
            tenzro_light::LightClient::restore(saved, chain_id, genesis_hash, at_least_index)?;
        Ok(Self { rpc, inner })
    }

    /// The client's state for the caller to keep.
    pub fn save(&self) -> Vec<u8> {
        self.inner.save()
    }

    /// The epoch of the committee the client trusts now.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch()
    }

    /// The newest checkpoint the client accepted.
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.inner.latest()
    }

    /// Follows the node to its newest certified checkpoint, through every
    /// epoch handover since the client's committee, and returns it. The
    /// checkpoint must be within `clock`'s bounds: a node serving an old
    /// checkpoint as its newest is refused.
    pub async fn sync(&mut self, clock: &Clock) -> SdkResult<Checkpoint> {
        let newest: Value = self
            .rpc
            .call("tenzro_getCheckpointCertificate", json!({}))
            .await?;
        let epoch = newest
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| SdkError::RpcError("certificate reply has no 'epoch'".into()))?;
        while self.inner.epoch() < epoch {
            let handover: Value = self
                .rpc
                .call(
                    "tenzro_getEpochHandover",
                    json!({ "epoch": self.inner.epoch() }),
                )
                .await?;
            rpc::hand_over(&mut self.inner, &handover)?;
        }
        Ok(rpc::advance(&mut self.inner, &newest, clock)?)
    }

    /// The value of the entry (`namespace`, `key`) in the state of the newest
    /// certified checkpoint, checked against its root. `None` is a proven
    /// absence.
    pub async fn state_value(
        &self,
        namespace: &str,
        key: &[u8],
        clock: &Clock,
    ) -> SdkResult<Option<Vec<u8>>> {
        let checkpoint = self.certified(clock)?;
        self.read(&checkpoint, namespace, key).await
    }

    /// `did`'s keys and whether it is revoked, proven against the newest
    /// certified checkpoint. `None` is a proof that the DID is not
    /// registered.
    pub async fn resolve_identity(
        &self,
        did: &str,
        clock: &Clock,
    ) -> SdkResult<Option<ProvenIdentity>> {
        let checkpoint = self.certified(clock)?;
        let ns = identity::STATE_NAMESPACE;
        let record_slot = identity::system_slot(&identity::registration_slot(did));
        let Some(record) = self.read(&checkpoint, ns, &record_slot).await? else {
            return Ok(None);
        };
        let revocation_slot = identity::system_slot(&identity::revocation_slot(did));
        let revocation = self.read(&checkpoint, ns, &revocation_slot).await?;
        Ok(identity::proven(
            &checkpoint,
            did,
            Some(record),
            revocation,
        )?)
    }

    /// `did`'s key history (each key with the time it took effect and any
    /// declared compromise) and the head of its logs, proven against the
    /// newest certified checkpoint. [`ProvenKeyHistory::key_at`] names the
    /// key a record made at a given time must be signed with.
    pub async fn key_history(&self, did: &str, clock: &Clock) -> SdkResult<ProvenKeyHistory> {
        let checkpoint = self.certified(clock)?;
        let ns = identity::STATE_NAMESPACE;
        let keys_slot = identity::system_slot(&identity::key_history_slot(did));
        let keys = self.read(&checkpoint, ns, &keys_slot).await?;
        let head_slot = identity::system_slot(&identity::head_slot(did));
        let head = self.read(&checkpoint, ns, &head_slot).await?;
        Ok(identity::proven_key_history(&checkpoint, did, keys, head)?)
    }

    /// The newest certified checkpoint, still within `clock`'s bounds.
    fn certified(&self, clock: &Clock) -> SdkResult<Checkpoint> {
        let checkpoint = self.inner.latest().cloned().ok_or_else(|| {
            SdkError::InvalidConfiguration(
                "the light client holds no certified checkpoint: sync first".into(),
            )
        })?;
        clock.check(&checkpoint)?;
        Ok(checkpoint)
    }

    async fn read(
        &self,
        checkpoint: &Checkpoint,
        namespace: &str,
        key: &[u8],
    ) -> SdkResult<Option<Vec<u8>>> {
        let reply: Value = self
            .rpc
            .call(
                "tenzro_getStateProof",
                json!({
                    "namespace": namespace,
                    "key": hex::encode(key),
                    "height": checkpoint.state_height,
                }),
            )
            .await?;
        Ok(rpc::state_value(checkpoint, namespace, key, &reply)?)
    }
}
