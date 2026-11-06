//! Consensus queries and operations served by a node.

use crate::rpc::RpcClient;
use std::sync::Arc;

/// Client for the node's consensus RPC methods.
#[derive(Clone)]
pub struct ConsensusClient {
    rpc: Arc<RpcClient>,
}

impl ConsensusClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }
}

impl ConsensusClient {
    /// Calls `tenzro_getCheckpointCertificate`: get checkpoint certificate.
    pub async fn get_checkpoint_certificate(
        &self,
        index: Option<u64>,
    ) -> crate::error::SdkResult<CheckpointCertificate> {
        self.rpc
            .call(
                "tenzro_getCheckpointCertificate",
                match index {
                    Some(v) => serde_json::json!([v]),
                    None => serde_json::json!([]),
                },
            )
            .await
    }

    /// Calls `tenzro_getCommittee`: get committee.
    pub async fn get_committee(&self, epoch: u64) -> crate::error::SdkResult<Committee> {
        self.rpc
            .call("tenzro_getCommittee", serde_json::json!([epoch]))
            .await
    }

    /// Calls `tenzro_getCompactCertificate`: get compact certificate.
    pub async fn get_compact_certificate(&self) -> crate::error::SdkResult<CheckpointCertificate> {
        self.rpc
            .call("tenzro_getCompactCertificate", serde_json::json!([]))
            .await
    }

    /// Calls `tenzro_getEpochHandover`: get epoch handover.
    pub async fn get_epoch_handover(&self, epoch: u64) -> crate::error::SdkResult<EpochHandover> {
        self.rpc
            .call("tenzro_getEpochHandover", serde_json::json!([epoch]))
            .await
    }

    /// Calls `tenzro_getMempoolLane`: get mempool lane.
    pub async fn get_mempool_lane(
        &self,
        address: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getMempoolLane",
                serde_json::json!([{ "address": address }]),
            )
            .await
    }

    /// Calls `tenzro_getMempoolStats`: get mempool stats.
    pub async fn get_mempool_stats(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getMempoolStats", serde_json::json!([]))
            .await
    }
}

impl ConsensusClient {
    /// Calls `tenzro_getConsensusMetrics`: get consensus metrics.
    pub async fn get_consensus_metrics(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getConsensusMetrics", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_getFinality`: get finality.
    pub async fn get_finality(&self) -> crate::error::SdkResult<Finality> {
        self.rpc
            .call("tenzro_getFinality", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_getRewardEpoch`: get reward epoch.
    pub async fn get_reward_epoch(&self, epoch: u64) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getRewardEpoch",
                serde_json::json!({ "epoch": epoch }),
            )
            .await
    }

    /// Calls `tenzro_getRewardSchedule`: get reward schedule.
    pub async fn get_reward_schedule(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getRewardSchedule", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_listRewardCoupons`: list reward coupons.
    pub async fn list_reward_coupons(
        &self,
        address: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_listRewardCoupons",
                serde_json::json!({ "address": address }),
            )
            .await
    }

    /// Calls `tenzro_getHardwareLevel`: an address's hardware security level
    /// and hardware type, derived on chain from verified attestation.
    pub async fn get_hardware_level(
        &self,
        address: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getHardwareLevel",
                serde_json::json!({ "address": address }),
            )
            .await
    }

    /// Calls `tenzro_getVesting`: get vesting.
    pub async fn get_vesting(&self, address: &str) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getVesting",
                serde_json::json!({ "address": address }),
            )
            .await
    }

    /// Calls `tenzro_validatorSelfStake`: validator self stake.
    pub async fn validator_self_stake(
        &self,
        additional: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_validatorSelfStake",
                serde_json::json!({ "additional": additional }),
            )
            .await
    }
}

/// The node's finality: the height it has ordered, the height a checkpoint
/// certificate covers, and that certificate (`tenzro_getFinality`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finality {
    /// Highest height ordered by consensus.
    pub ordered: u64,
    /// Highest height a certified checkpoint covers.
    pub certified: u64,
    /// The latest certificate, when one is kept.
    #[serde(default)]
    pub certificate: Option<FinalityCertificate>,
}

/// The checkpoint the latest certificate covers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityCertificate {
    /// Epoch of the checkpoint.
    pub epoch: u64,
    /// Checkpoint index.
    pub index: u64,
    /// First block height it covers.
    pub first_height: u64,
    /// Last block height it covers.
    pub last_height: u64,
    /// Height of the state root it commits to.
    pub state_height: u64,
    /// The committed state root, 0x-prefixed hex.
    pub state_root: String,
    /// Number of validators that signed it.
    pub signers: u64,
}

/// A checkpoint certificate with the session bundle that verifies it
/// (`tenzro_getCheckpointCertificate`, `tenzro_getCompactCertificate`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckpointCertificate {
    /// Epoch of the checkpoint.
    pub epoch: u64,
    /// Checkpoint index.
    pub index: u64,
    /// Last block height it covers.
    pub last_height: u64,
    /// The checkpoint digest, 0x-prefixed hex (full certificates only).
    #[serde(default)]
    pub digest: Option<String>,
    /// The certificate, bincode, 0x-prefixed hex.
    pub certificate: String,
    /// The signers' sessions, bincode, 0x-prefixed hex.
    pub sessions: String,
}

/// An epoch's committee (`tenzro_getCommittee`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Committee {
    /// The epoch.
    pub epoch: u64,
    /// The committee root, 0x-prefixed hex.
    pub root: String,
    /// The members, bincode, 0x-prefixed hex.
    pub members: String,
}

/// The certificate that hands an epoch to the next committee
/// (`tenzro_getEpochHandover`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochHandover {
    /// The epoch handed over.
    pub epoch: u64,
    /// Index of the checkpoint that carries the handover.
    pub index: u64,
    /// The certificate, bincode, 0x-prefixed hex.
    pub certificate: String,
    /// The signers' sessions, bincode, 0x-prefixed hex.
    pub sessions: String,
    /// The next committee's members, bincode, 0x-prefixed hex.
    pub next_members: String,
}
