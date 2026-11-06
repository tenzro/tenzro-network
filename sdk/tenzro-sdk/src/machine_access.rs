//! Machine access: what a machine's owner lets agents, tools and models on a
//! node reach.
//!
//! Nothing on a node can reach its loopback services, its LAN, cloud metadata
//! endpoints or host folders unless the machine's owner signed a grant for it.
//! Every change here is signed by the owner in two steps:
//!
//! 1. [`MachineAccessClient::challenge`] names the change and returns a custody
//!    challenge bound to exactly that change.
//! 2. The owner approves the challenge in their wallet (a passkey assertion
//!    and an ML-DSA-65 signature over the digest), and the approval is passed
//!    to [`add`](MachineAccessClient::add), [`list`](MachineAccessClient::list)
//!    or [`revoke`](MachineAccessClient::revoke) as `authorization`, with
//!    `challenge_id` set.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::Value;
use std::sync::Arc;

/// Owner-signed machine-access client.
#[derive(Clone)]
pub struct MachineAccessClient {
    rpc: Arc<RpcClient>,
}

impl MachineAccessClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Issue the custody challenge for `change`: `{"action":"add", ...terms}`,
    /// `{"action":"list"}` or `{"action":"revoke","grant_id":...}`. Returns
    /// `challenge_id`, `webauthn_challenge` (what the owner's passkey signs) and the owner's
    /// `account_address`. Terms the node would refuse are refused here, before
    /// the owner is asked to sign them.
    pub async fn challenge(&self, change: Value) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::json!({ "operation": "machine_access", "machine_access": change }),
            )
            .await
    }

    /// Add a grant. `terms` carries `grantee_did`, `resources`, `operations`,
    /// `expires_at_ms` and optionally `max_uses_per_minute` and `max_bytes`,
    /// exactly as they were given to [`challenge`](Self::challenge).
    pub async fn add(&self, terms: Value, authorization: Value) -> SdkResult<Value> {
        let mut params = terms;
        params["authorization"] = authorization;
        self.rpc.call("tenzro_addMachineAccess", params).await
    }

    /// The grants on the node, with their use, refusal and byte counts.
    pub async fn list(&self, authorization: Value) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_listMachineAccess",
                serde_json::json!({ "authorization": authorization }),
            )
            .await
    }

    /// Revoke a grant. It stops applying at once.
    pub async fn revoke(&self, grant_id: &str, authorization: Value) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_revokeMachineAccess",
                serde_json::json!({ "grant_id": grant_id, "authorization": authorization }),
            )
            .await
    }
}
