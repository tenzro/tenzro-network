//! Cluster identity on a node: the verified membership lists this node holds,
//! the machines of its own cluster it has found on the local network, and the
//! RPC surface to create a cluster, accept and set membership, and list
//! members.
//!
//! A cluster DID derives from the operator's DID and the cluster name. Its
//! members are an operator-approved list (a passkey assertion over the custody
//! challenge for the list) that every listed machine has accepted with its own
//! hardware key. Lists travel inside each member's provider announcement
//! ([`tenzro_types::ClusterProfile::memberships`]); every node that receives
//! one checks it and keeps the latest per cluster.
//!
//! The cluster DID never signs. Announcements, receipts, votes and cluster
//! sessions stay signed by the individual machine; the cluster only decides
//! which machines are planned together:
//!
//! - split inference plans only over verified members found on the LAN
//!   ([`members`], through [`tenzro_model::cluster::admit_members`]);
//! - `lan_cluster` database placement gives the local tier only to them
//!   ([`database_candidates`]);
//! - a machine serves its accelerator only to heads that are verified
//!   co-members ([`ClusterIdentity::is_verified_peer`]);
//! - a cluster DID resolves as one serving entry to its members, and its
//!   reputation record is the aggregate of theirs.
//!
//! Members find each other through multicast discovery on the local network
//! ([`tenzro_iroh::lan_discovery`]); a sighting counts only when its binding
//! signature checks against the membership list.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::Value;
use tenzro_cluster::{MembershipBook, MembershipError, VerifiedMembership};
use tenzro_device_key::HardwareSigner;
use tenzro_iroh::lan_discovery::{LanBinding, LanDiscovery, Sighting};
use tenzro_model::cluster::{self, ClusterMember, MemberReachability};
use tenzro_storage::{CF_IDENTITIES, KvStore};
use tenzro_types::cluster_membership::{
    MemberAcceptance, SignedClusterMembership, acceptance_digest, lan_binding_digest,
    membership_digest,
};
use tracing::{debug, info, warn};

use crate::node::{NetworkProviderEntry, TenzroNode};
use crate::passkey_rpc::{CustodyOperation, custody_challenge_digest, parse_params};
use crate::rpc::JsonRpcError;

/// Storage key prefix of a held membership list, under `CF_IDENTITIES`.
const MEMBERSHIP_PREFIX: &str = "cluster_membership:";

/// How often a member re-checks what it announces on the local network.
const LAN_ANNOUNCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The custody challenge an operator's passkey answers to approve a list on
/// the network `chain_id`.
pub fn custody_digest(
    chain_id: u64,
    operator_did: &str,
    membership: &[u8; 32],
    nonce: &[u8; 16],
) -> [u8; 32] {
    custody_challenge_digest(
        chain_id,
        operator_did.as_bytes(),
        CustodyOperation::SetClusterMembership,
        membership,
        nonce,
    )
}

/// This machine's hardware key: the key its machine DID derives from and the
/// key that accepts memberships and signs local-network bindings.
fn machine_signer() -> Option<&'static dyn HardwareSigner> {
    crate::identity_bootstrap::machine_signer()
}

/// This machine's DID, derived from its hardware key. `None` on a machine with
/// no TPM or Secure Enclave, which therefore cannot be a cluster member.
pub fn machine_did() -> Option<String> {
    let key = machine_signer()?.public_key_sec1().ok()?;
    Some(format!(
        "did:tenzro:machine:{}",
        tenzro_types::did_derivation::machine_device_id(&key)
    ))
}

/// A co-member found on the local network whose binding checked.
#[derive(Debug, Clone)]
struct LanMember {
    member_did: String,
    /// The iroh endpoint the member's hardware-signed binding names: the
    /// endpoint a head dials it at and a member admits it by.
    endpoint_id: tenzro_iroh::EndpointId,
}

/// The membership lists a node holds and the co-members it has found.
pub struct ClusterIdentity {
    book: RwLock<MembershipBook>,
    storage: Option<Arc<dyn KvStore>>,
    /// Verified co-members seen on the local network, by the iroh endpoint
    /// id (lowercase hex) their binding names.
    lan: RwLock<HashMap<String, LanMember>>,
    /// The network whose custody challenges approve the lists held.
    chain_id: u64,
}

impl std::fmt::Debug for ClusterIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterIdentity").finish_non_exhaustive()
    }
}

impl ClusterIdentity {
    /// An identity holding nothing and persisting nothing, used until storage
    /// is open, for lists approved on the network `chain_id`.
    pub fn new(chain_id: u64) -> Self {
        Self {
            book: RwLock::new(MembershipBook::new()),
            storage: None,
            lan: RwLock::new(HashMap::new()),
            chain_id,
        }
    }

    /// An identity backed by `storage`, holding every list persisted there
    /// that still verifies.
    pub fn with_storage(storage: Arc<dyn KvStore>, rp_id: &str, chain_id: u64) -> Self {
        let this = Self {
            storage: Some(storage.clone()),
            ..Self::new(chain_id)
        };
        let keys = storage
            .get_keys_with_prefix(CF_IDENTITIES, MEMBERSHIP_PREFIX.as_bytes())
            .unwrap_or_default();
        for key in keys {
            let Ok(Some(bytes)) = storage.get(CF_IDENTITIES, &key) else {
                continue;
            };
            match serde_json::from_slice::<SignedClusterMembership>(&bytes) {
                Ok(record) => {
                    if let Err(e) = this.offer(record, rp_id) {
                        warn!(error = %e, "Stored cluster membership no longer verifies");
                    }
                }
                Err(e) => warn!(error = %e, "Stored cluster membership does not decode"),
            }
        }
        this
    }

    /// Verify `record` and hold it if it is newer than the list held for its
    /// cluster. Returns whether anything changed.
    pub fn offer(
        &self,
        record: SignedClusterMembership,
        rp_id: &str,
    ) -> Result<bool, MembershipError> {
        // Every announcement repeats the lists its sender holds; the one
        // already held needs no second verification.
        if self
            .book
            .read()
            .get(&record.cluster_did)
            .is_some_and(|held| held.record() == &record)
        {
            return Ok(false);
        }
        let chain_id = self.chain_id;
        self.hold(VerifiedMembership::verify(
            record,
            rp_id,
            |operator: &str, membership: &[u8; 32], nonce: &[u8; 16]| {
                custody_digest(chain_id, operator, membership, nonce)
            },
        )?)
    }

    /// Hold `verified` if it is newer than the list held for its cluster, and
    /// persist it. Returns whether anything changed.
    pub fn hold(&self, verified: VerifiedMembership) -> Result<bool, MembershipError> {
        let key = format!("{MEMBERSHIP_PREFIX}{}", verified.cluster_did());
        let bytes = serde_json::to_vec(verified.record()).unwrap_or_default();
        let changed = self.book.write().offer(verified)?;
        if changed
            && let Some(storage) = &self.storage
            && let Err(e) = storage.put(CF_IDENTITIES, key.as_bytes(), &bytes)
        {
            warn!(error = %e, "Could not persist cluster membership");
        }
        Ok(changed)
    }

    /// Offer every membership list carried by `providers`' announcements.
    /// Lists that do not verify, or are older than the one held, are dropped.
    fn ingest(&self, providers: &[NetworkProviderEntry], rp_id: &str) {
        for entry in providers {
            let Some(profile) = entry.announcement.cluster_profile.as_ref() else {
                continue;
            };
            for record in &profile.memberships {
                if let Err(e) = self.offer(record.clone(), rp_id) {
                    debug!(endpoint = %entry.announcement.iroh_endpoint_id, error = %e, "Cluster membership not taken");
                }
            }
        }
    }

    /// The verified list of `cluster_did`.
    pub fn membership(&self, cluster_did: &str) -> Option<VerifiedMembership> {
        self.book.read().get(cluster_did).cloned()
    }

    /// The cluster this machine plans with: the first cluster that lists it.
    pub fn own_cluster(&self) -> Option<VerifiedMembership> {
        let did = machine_did()?;
        self.book.read().clusters_of(&did).next().cloned()
    }

    /// The machines a serving entry stands for (see
    /// [`MembershipBook::resolve_serving_entry`]).
    pub fn resolve_serving_entry(&self, entry: &str) -> Option<Vec<String>> {
        self.book.read().resolve_serving_entry(entry)
    }

    /// The cluster profile this node announces: its serving facts and every
    /// list naming it. `None` when this machine is in no cluster.
    pub fn profile(&self) -> Option<tenzro_types::ClusterProfile> {
        let did = machine_did()?;
        let memberships: Vec<SignedClusterMembership> = self
            .book
            .read()
            .clusters_of(&did)
            .map(|m| m.record().clone())
            .collect();
        if memberships.is_empty() {
            return None;
        }
        #[cfg(feature = "inference")]
        {
            let device = cluster::detect_node_profile();
            Some(tenzro_types::ClusterProfile {
                memberships,
                llama_commit: device.llama_commit.clone(),
                backend: device.serving_backend().ggml_name().to_string(),
                cap_key: device.serving_cap_key(),
            })
        }
        // A cluster serves a model together; the light build serves none, so
        // it has no profile to offer one.
        #[cfg(not(feature = "inference"))]
        {
            let _ = memberships;
            None
        }
    }

    /// Record a local-network sighting if its binding checks against a
    /// cluster this machine shares with it. Returns the member DID.
    fn record_sighting(&self, self_did: &str, sighting: &Sighting) -> Option<String> {
        let member = self.book.read().verify_lan_peer(
            self_did,
            &sighting.binding.member_id,
            sighting.endpoint_id.as_bytes(),
            &sighting.binding.signature,
        )?;
        self.lan.write().insert(
            sighting.endpoint_id.to_string(),
            LanMember {
                member_did: member.clone(),
                endpoint_id: sighting.endpoint_id,
            },
        );
        Some(member)
    }

    /// The verified co-member of `self_did` behind the iroh endpoint
    /// `endpoint_id` (lowercase hex), when it is found on the LAN and its
    /// operator has not removed it since.
    fn lan_member_of(&self, self_did: &str, endpoint_id: &str) -> Option<LanMember> {
        let found = self.lan.read().get(endpoint_id).cloned()?;
        self.book
            .read()
            .co_members(self_did)
            .contains(&found.member_did)
            .then_some(found)
    }

    /// The verified co-member of this machine behind `endpoint_id`.
    fn lan_member(&self, endpoint_id: &str) -> Option<LanMember> {
        self.lan_member_of(&machine_did()?, endpoint_id)
    }

    /// Whether the session authenticated as `endpoint` comes from a verified
    /// co-member found on the local network, whose hardware-signed binding
    /// names that endpoint: the only heads a member serves its accelerator
    /// to.
    pub fn is_verified_endpoint(&self, endpoint: &tenzro_iroh::EndpointId) -> bool {
        let Some(self_did) = machine_did() else {
            return false;
        };
        let co_members = self.book.read().co_members(&self_did);
        self.lan
            .read()
            .values()
            .any(|m| m.endpoint_id == *endpoint && co_members.contains(&m.member_did))
    }

    /// Announce this machine on the local network and admit the co-members it
    /// finds there, for as long as the node runs.
    pub fn spawn_lan_discovery(self: &Arc<Self>, endpoint: tenzro_iroh::Endpoint) {
        let Some(self_did) = machine_did() else {
            return;
        };
        let discovery = match LanDiscovery::start(endpoint.id()) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Local-network cluster discovery not started");
                return;
            }
        };
        let this = Arc::clone(self);
        let listener = discovery.clone();
        let did = self_did.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut sightings = listener.sightings().await;
            while let Some(s) = sightings.next().await {
                if let Some(member) = this.record_sighting(&did, &s) {
                    debug!(member = %member, endpoint = %s.endpoint_id, "Cluster member found on the local network");
                }
            }
        });
        tokio::spawn(async move {
            let Some(signer) = machine_signer() else {
                return;
            };
            let member_id = self_did.rsplit(':').next().unwrap_or_default().to_string();
            let mut interval = tokio::time::interval(LAN_ANNOUNCE_INTERVAL);
            loop {
                interval.tick().await;
                let addrs: Vec<std::net::SocketAddr> =
                    endpoint.addr().ip_addrs().copied().collect();
                let digest = lan_binding_digest(&self_did, endpoint.id().as_bytes());
                let binding = match signer.sign_prehash(&digest) {
                    Ok(sig) => LanBinding {
                        member_id: member_id.clone(),
                        signature: sig.to_vec(),
                    },
                    Err(e) => {
                        warn!(error = %e, "Could not sign the local-network cluster binding");
                        continue;
                    }
                };
                if let Err(e) = discovery.announce(addrs, &binding) {
                    warn!(error = %e, "Local-network cluster announcement failed");
                }
            }
        });
        info!("Local-network cluster discovery started");
    }
}

/// Take in the membership lists carried by current announcements.
fn refresh(node: &Arc<TenzroNode>) -> Vec<NetworkProviderEntry> {
    let providers = node.network_providers_snapshot();
    node.cluster_identity()
        .ingest(&providers, node.http_surface().webauthn_rp_id());
    providers
}

/// A member's endpoint as the planners carry it: the host is cosmetic, and
/// the iroh endpoint id after `#` is what the head dials. For a verified
/// co-member that is the endpoint its hardware-signed binding names.
fn member_endpoint(endpoint_id: &str) -> String {
    format!("member#{endpoint_id}")
}

/// This node's own candidate: the head, serving the first stage locally.
async fn self_member(node: &Arc<TenzroNode>, self_did: &str) -> Option<ClusterMember> {
    let peer = node.iroh_resolver()?.endpoint_id().to_string();
    let address = node
        .operator_payee()
        .unwrap_or_else(tenzro_types::primitives::Address::zero);
    #[cfg(feature = "inference")]
    {
        let profile = cluster::detect_node_profile();
        Some(profile.to_member(
            self_did,
            address,
            format!("self#{peer}"),
            MemberReachability::LocalDirect,
        ))
    }
    // The light build runs no model, so it is no serving member of a cluster.
    #[cfg(not(feature = "inference"))]
    {
        let _ = (self_did, address, peer);
        None
    }
}

/// The split-inference candidates: this node as head, then every verified
/// member of its cluster found on the local network. Members the cluster's
/// verified list does not name never appear. A node in no cluster plans
/// alone.
pub(crate) async fn members(node: &Arc<TenzroNode>) -> Vec<ClusterMember> {
    let providers = refresh(node);
    let identity = node.cluster_identity();
    let Some(self_did) = machine_did() else {
        return Vec::new();
    };
    let Some(head) = self_member(node, &self_did).await else {
        return Vec::new();
    };
    let Some(membership) = identity.own_cluster() else {
        return vec![head];
    };
    let mut candidates = vec![head];
    for entry in providers {
        let ann = entry.announcement;
        let (Some(cp), Some(found)) = (
            ann.cluster_profile.as_ref(),
            identity.lan_member(&ann.iroh_endpoint_id),
        ) else {
            continue;
        };
        let Ok(address) = tenzro_types::primitives::Address::from_hex(&ann.provider_address) else {
            continue;
        };
        candidates.push(ClusterMember {
            machine_did: found.member_did,
            address,
            vram_gb: ann.hardware.vram_gb as f32,
            backend: cluster::Backend::from_ggml_name(&cp.backend),
            cap_key: cp.cap_key.clone(),
            llama_commit: cp.llama_commit.clone(),
            local_endpoint: member_endpoint(&found.endpoint_id.to_string()),
            reachability: MemberReachability::LocalDirect,
        });
    }
    cluster::admit_members(&membership, candidates)
}

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32001,
        message: message.into(),
        data: None,
    }
}

/// Params of `tenzro_deriveClusterMembership`.
#[derive(Debug, Deserialize)]
struct DeriveRequest {
    operator_did: String,
    name: String,
    seq: u64,
    members: Vec<String>,
}

/// `tenzro_deriveClusterMembership` — the first step of creating a cluster
/// or changing its members. Derives the cluster DID from the operator and
/// name and returns what must be signed: the custody challenge request the
/// operator's passkey answers, and the digest each member's hardware key
/// accepts. Computes only; stores nothing.
pub(crate) async fn handle_derive_membership(params: Option<Value>) -> Result<Value, JsonRpcError> {
    let mut req: DeriveRequest = parse_params(params)?;
    if !req.operator_did.starts_with("did:tenzro:human:") {
        return Err(invalid("operator_did must be a human DID"));
    }
    if req.name.trim().is_empty() {
        return Err(invalid("name must not be empty"));
    }
    req.members.sort();
    req.members.dedup();
    if req.members.is_empty()
        || !req
            .members
            .iter()
            .all(|m| m.starts_with("did:tenzro:machine:"))
    {
        return Err(invalid("members must be one or more machine DIDs"));
    }
    let cluster = tenzro_types::did_derivation::cluster_did(&req.operator_did, &req.name);
    let digest = membership_digest(
        &cluster,
        &req.operator_did,
        &req.name,
        req.seq,
        &req.members,
    );
    let acceptances: Vec<Value> = req
        .members
        .iter()
        .map(|m| {
            serde_json::json!({
                "member_did": m,
                "acceptance_digest_hex": hex::encode(acceptance_digest(&cluster, m, req.seq)),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "cluster_did": cluster,
        "operator_did": req.operator_did,
        "name": req.name,
        "seq": req.seq,
        "members": req.members,
        "membership_digest_hex": hex::encode(digest),
        "custody_challenge": {
            "account_address": hex::encode(req.operator_did.as_bytes()),
            "operation": CustodyOperation::SetClusterMembership,
            "target_hex": hex::encode(digest),
        },
        "acceptances": acceptances,
    }))
}

/// Params of `tenzro_acceptClusterMembership`.
#[derive(Debug, Deserialize)]
struct AcceptRequest {
    cluster_did: String,
    seq: u64,
}

/// `tenzro_acceptClusterMembership` — this machine accepts its inclusion in
/// list `seq` of `cluster_did`, signing with its own hardware key. For node
/// administrators only: only the machine's operator decides which clusters
/// it joins.
pub(crate) async fn handle_accept_membership(params: Option<Value>) -> Result<Value, JsonRpcError> {
    let req: AcceptRequest = parse_params(params)?;
    if !req
        .cluster_did
        .starts_with(tenzro_types::did_derivation::CLUSTER_DID_PREFIX)
    {
        return Err(invalid("cluster_did must be a cluster DID"));
    }
    let (Some(signer), Some(did)) = (machine_signer(), machine_did()) else {
        return Err(refused(
            "this machine has no hardware key, so it cannot be a cluster member",
        ));
    };
    let public_key = signer
        .public_key_sec1()
        .map_err(|e| refused(format!("hardware key unavailable: {e}")))?;
    let signature = signer
        .sign_prehash(&acceptance_digest(&req.cluster_did, &did, req.seq))
        .map_err(|e| refused(format!("hardware key refused to sign: {e}")))?;
    let acceptance = MemberAcceptance {
        member_did: did,
        public_key: public_key.to_vec(),
        signature: signature.to_vec(),
    };
    serde_json::to_value(acceptance).map_err(|e| invalid(e.to_string()))
}

/// Params of `tenzro_setClusterMembership`.
#[derive(Debug, Deserialize)]
struct SetRequest {
    membership: SignedClusterMembership,
    /// The custody challenge the operator's approval answers, issued by this
    /// node for operation `set_cluster_membership`.
    challenge_id: String,
}

/// `tenzro_setClusterMembership` — hold a new membership list: the first list
/// creates the cluster, a later one with a higher sequence number adds or
/// removes members. The operator's passkey must have answered a custody
/// challenge this node issued for exactly this list, and every member must
/// have accepted with its own hardware key.
pub(crate) async fn handle_set_membership(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: SetRequest = parse_params(params)?;
    let record = req.membership;
    let digest = record.membership_digest();
    let issued = node
        .custody_challenges()
        .consume(
            &req.challenge_id,
            record.operator_did.as_bytes(),
            CustodyOperation::SetClusterMembership,
            &digest,
        )
        .map_err(refused)?;
    let nonce: [u8; 16] = record
        .operator_approval
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| invalid("operator_approval.nonce must be 16 bytes"))?;
    let chain_id = node.custody_challenges().chain_id();
    if issued != custody_digest(chain_id, &record.operator_did, &digest, &nonce) {
        return Err(refused(
            "the approval answers a different custody challenge",
        ));
    }
    let (cluster, seq, members) = (
        record.cluster_did.clone(),
        record.seq,
        record.members.clone(),
    );
    let verified = VerifiedMembership::verify(
        record,
        node.http_surface().webauthn_rp_id(),
        |operator: &str, membership: &[u8; 32], nonce: &[u8; 16]| {
            custody_digest(chain_id, operator, membership, nonce)
        },
    )
    .map_err(|e| refused(e.to_string()))?;
    let changed = node
        .cluster_identity()
        .hold(verified)
        .map_err(|e| refused(e.to_string()))?;
    Ok(serde_json::json!({
        "cluster_did": cluster,
        "seq": seq,
        "members": members,
        "changed": changed,
    }))
}

fn backend_name(b: cluster::Backend) -> &'static str {
    match b {
        cluster::Backend::Cpu => "cpu",
        cluster::Backend::Cuda => "cuda",
        cluster::Backend::Metal => "metal",
        cluster::Backend::Vulkan => "vulkan",
        cluster::Backend::Hip => "hip",
        cluster::Backend::Sycl => "sycl",
    }
}

fn reach_name(r: MemberReachability) -> &'static str {
    match r {
        MemberReachability::LocalDirect => "local_direct",
        MemberReachability::Direct => "direct",
        MemberReachability::RelayOnly => "relay_only",
        MemberReachability::SymmetricNat => "symmetric_nat",
    }
}

/// Params of `tenzro_clusterMembers`.
#[derive(Debug, Default, Deserialize)]
struct MembersRequest {
    /// A cluster DID (or a machine DID) to resolve. Defaults to this node's
    /// own cluster.
    #[serde(default)]
    entry: Option<String>,
}

/// `tenzro_clusterMembers` — the members of a cluster. For a cluster DID, its
/// verified member DIDs and its aggregated reputation record; for this node's
/// own cluster, also the members found on the local network with the
/// hardware each one announced. Nothing is disclosed about a member beyond
/// its DID and what that machine itself chose to announce.
pub(crate) async fn handle_cluster_members(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: MembersRequest = match params {
        Some(Value::Null) | None => MembersRequest::default(),
        p => parse_params(p)?,
    };
    let planned = members(node).await;
    let identity = node.cluster_identity();
    let own = identity.own_cluster();
    let cluster_did = match req.entry {
        Some(e) => e,
        None => own
            .as_ref()
            .map(|m| m.cluster_did().to_string())
            .unwrap_or_default(),
    };
    let verified = if cluster_did.is_empty() {
        Vec::new()
    } else {
        identity
            .resolve_serving_entry(&cluster_did)
            .ok_or_else(|| {
                invalid(format!(
                    "{cluster_did} is not a machine DID or a known cluster"
                ))
            })?
    };
    let is_own = own.as_ref().is_some_and(|m| m.cluster_did() == cluster_did);
    let found: Vec<&ClusterMember> = if is_own {
        planned.iter().collect()
    } else {
        Vec::new()
    };
    let members_json: Vec<Value> = found
        .iter()
        .map(|m| {
            serde_json::json!({
                "machine_did": m.machine_did,
                "address": hex::encode(m.address.as_bytes()),
                "vram_gb": m.vram_gb,
                "backend": backend_name(m.backend),
                "cap_key": m.cap_key,
                "reachability": reach_name(m.reachability),
                "is_head": planned.first().map(|h| h.address) == Some(m.address),
            })
        })
        .collect();
    let record = node.provider_manager().map(|pm| {
        let addresses: Vec<_> = found.iter().map(|m| m.address).collect();
        pm.cluster_record(&cluster_did, &addresses)
    });
    Ok(serde_json::json!({
        "cluster_did": cluster_did,
        "verified_members": verified,
        "members": members_json,
        "member_count": members_json.len(),
        "local_count": found.iter().filter(|m| m.reachability.is_local()).count(),
        "total_vram_gb": found.iter().map(|m| m.vram_gb).sum::<f32>(),
        "self_did": machine_did(),
        "record": record,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHAIN: u64 = 1337;

    #[test]
    fn the_operator_approves_through_the_custody_challenge_digest() {
        let digest = [3u8; 32];
        let nonce = [4u8; 16];
        assert_eq!(
            custody_digest(TEST_CHAIN, "did:tenzro:human:x", &digest, &nonce),
            custody_challenge_digest(
                TEST_CHAIN,
                b"did:tenzro:human:x",
                CustodyOperation::SetClusterMembership,
                &digest,
                &nonce
            )
        );
        assert_ne!(
            custody_digest(TEST_CHAIN, "did:tenzro:human:x", &digest, &nonce),
            custody_challenge_digest(
                TEST_CHAIN,
                b"did:tenzro:human:x",
                CustodyOperation::BindDevice,
                &digest,
                &nonce
            )
        );
    }

    #[test]
    fn a_stored_list_is_held_again_only_if_it_still_verifies() {
        use tenzro_cluster::membership::testing::{Key, RP_ID};
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::kv::MemoryStore::new());
        let (op, a) = (Key::new(1), Key::new(2));
        let record = signed(&op, "lab", 1, &[&a]);
        let cluster = record.cluster_did.clone();
        let identity = ClusterIdentity::with_storage(store.clone(), RP_ID, TEST_CHAIN);
        assert_eq!(identity.offer(record, RP_ID), Ok(true));

        let reopened = ClusterIdentity::with_storage(store.clone(), RP_ID, TEST_CHAIN);
        assert!(reopened.membership(&cluster).is_some());

        // A tampered stored list is not held.
        let key = format!("{MEMBERSHIP_PREFIX}{cluster}");
        let mut stored: SignedClusterMembership =
            serde_json::from_slice(&store.get(CF_IDENTITIES, key.as_bytes()).unwrap().unwrap())
                .unwrap();
        stored.members.push("did:tenzro:machine:zzz".into());
        store
            .put(
                CF_IDENTITIES,
                key.as_bytes(),
                &serde_json::to_vec(&stored).unwrap(),
            )
            .unwrap();
        assert!(
            ClusterIdentity::with_storage(store, RP_ID, TEST_CHAIN)
                .membership(&cluster)
                .is_none()
        );
    }

    /// A list approved on one network is not held on another.
    #[test]
    fn a_list_approved_for_another_network_is_refused() {
        use tenzro_cluster::membership::testing::{Key, RP_ID};
        let (op, a) = (Key::new(1), Key::new(2));
        assert!(
            ClusterIdentity::new(13380)
                .offer(signed(&op, "lab", 1, &[&a]), RP_ID)
                .is_err()
        );
        assert_eq!(
            ClusterIdentity::new(TEST_CHAIN).offer(signed(&op, "lab", 1, &[&a]), RP_ID),
            Ok(true)
        );
    }

    /// A member serves its accelerator only to a head whose local-network
    /// binding checks against a list both share, and stops the moment the
    /// operator's next list removes that head.
    #[test]
    fn only_verified_co_members_on_the_lan_are_heads_and_removal_takes_effect() {
        use tenzro_cluster::membership::testing::{Key, RP_ID};
        use tenzro_iroh::lan_discovery::{LanBinding, Sighting};

        let (op, a, b, stranger) = (Key::new(1), Key::new(2), Key::new(3), Key::new(4));
        let identity = ClusterIdentity::new(TEST_CHAIN);
        identity
            .offer(signed(&op, "lab", 1, &[&a, &b]), RP_ID)
            .unwrap();
        let endpoint_of = |key: &Key| iroh::SecretKey::from_bytes(&[key.public()[1]; 32]).public();
        let sighting = |key: &Key| {
            let endpoint = endpoint_of(key);
            Sighting {
                endpoint_id: endpoint,
                addrs: Vec::new(),
                binding: LanBinding {
                    member_id: key.machine_did().rsplit(':').next().unwrap().to_string(),
                    signature: key.bind_lan(endpoint.as_bytes()),
                },
            }
        };
        let a_did = a.machine_did();
        let b_endpoint = endpoint_of(&b).to_string();
        let s_endpoint = endpoint_of(&stranger).to_string();

        assert_eq!(
            identity.record_sighting(&a_did, &sighting(&b)),
            Some(b.machine_did())
        );
        assert!(identity.lan_member_of(&a_did, &b_endpoint).is_some());
        // A stranger's own valid binding names no member of a's cluster.
        assert_eq!(identity.record_sighting(&a_did, &sighting(&stranger)), None);
        assert!(identity.lan_member_of(&a_did, &s_endpoint).is_none());
        // An endpoint never sighted is not a head.
        assert!(identity.lan_member_of(&a_did, "never-sighted").is_none());

        identity.offer(signed(&op, "lab", 2, &[&a]), RP_ID).unwrap();
        assert!(identity.lan_member_of(&a_did, &b_endpoint).is_none());
    }

    /// A list approved through this node's real custody digest.
    fn signed(
        operator: &tenzro_cluster::membership::testing::Key,
        name: &str,
        seq: u64,
        members: &[&tenzro_cluster::membership::testing::Key],
    ) -> SignedClusterMembership {
        use tenzro_cluster::membership::testing::{approve, membership};
        let mut record = membership(operator, name, seq, members);
        let nonce = [7u8; 16];
        let challenge = custody_digest(
            TEST_CHAIN,
            &record.operator_did,
            &record.membership_digest(),
            &nonce,
        );
        record.operator_approval = approve(operator, &challenge, nonce);
        record
    }
}
