//! Machine access: what the machine's owner lets jobs on this node reach.
//!
//! Agents, tools, models and hosted functions run with no access to the
//! machine that hosts them: no loopback services, no LAN, no metadata
//! endpoints, no host folders. The only thing that opens any of it is a grant
//! the machine's owner signed. A grant is a [`DelegationEntry`] from the owner
//! to a grantee whose [`DelegationScope`] names the machine resources
//! (`machine_resources`), the operations (`connect`, `read`, `write`), an
//! expiry (`time_bound`) and optionally a use rate (`max_uses_per_minute`)
//! and a byte allowance (`max_bytes`). It carries no spending authority.
//!
//! # Who the owner is
//!
//! The node's machine identity is `operator_did` in the node configuration,
//! named explicitly; an inferred identity never authorises machine access. The
//! machine's controller is its owner, and the owner signs with the passkey
//! account enrolled for that controller: a WebAuthn assertion and an ML-DSA-65
//! signature over a custody challenge ([`CustodyOperation::MachineAccess`])
//! whose target names the exact change. Nothing else adds, lists or revokes a
//! grant: not a node administrator, not an agent or a model.
//!
//! A grant is the owner's for as long as they own the machine. When the
//! machine changes hands, every grant the previous owner signed is revoked.
//!
//! # Grantees
//!
//! A grant to the node's own machine DID covers any sandboxed job on the node:
//! its guarded fetches, hosted functions and sandboxed skills and tools. A
//! grant to another DID covers only work attributed to that DID: requests the
//! egress guard makes on its behalf ([`crate::egress_guard::EgressGuard::for_grantee`])
//! and sandboxed skill and tool invocations it makes.
//!
//! # Enforcement and metering
//!
//! [`crate::egress_guard::AddressPolicy`] asks [`MachineAccessGrants`] about
//! every destination it would otherwise refuse, with the destination's port,
//! and the skill sandbox mounts the folders granted to its caller. Every use,
//! and every refusal of a destination or folder a grant names, is logged under
//! the `machine_access` target with the grant id, the grantee and the
//! destination, and counted per grant, as are the bytes moved through a grant
//! when its scope limits them. A revocation applies from the next check.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tenzro_identity::{
    DelegationEntry, DelegationScope, MachineResource, OperationBound, TimeBound,
};
use tenzro_storage::{CF_METADATA, KvStore};
use tracing::{info, warn};

use crate::egress_guard::Cidr;
use crate::node::TenzroNode;
use crate::passkey_rpc::{CustodyAuthorization, CustodyOperation};
use crate::rpc::JsonRpcError;

/// Key prefix of persisted grants in `CF_METADATA`.
const KEY_PREFIX: &str = "machine_access:";

/// Opening a connection to a granted network destination.
pub const OP_CONNECT: &str = "connect";
/// Reading a granted folder.
pub const OP_READ: &str = "read";
/// Writing a granted folder.
pub const OP_WRITE: &str = "write";

/// The window `max_uses_per_minute` counts over.
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// A stored grant, its parsed network ranges and its meters.
struct Grant {
    entry: DelegationEntry,
    networks: Vec<(Cidr, Option<u16>)>,
    uses: u64,
    refusals: u64,
    bytes: u64,
    window_start: Instant,
    window_uses: u32,
}

impl Grant {
    fn from_entry(entry: DelegationEntry) -> Result<Self, String> {
        let networks = entry
            .scope
            .machine_resources
            .iter()
            .filter_map(|r| match r {
                MachineResource::Network { cidr, port } => Some(
                    Cidr::parse(cidr)
                        .map(|c| (c, *port))
                        .map_err(|e| e.to_string()),
                ),
                MachineResource::Folder { .. } | MachineResource::Device { .. } => None,
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            entry,
            networks,
            uses: 0,
            refusals: 0,
            bytes: 0,
            window_start: Instant::now(),
            window_uses: 0,
        })
    }

    /// Whether the grant names `ip` on `port`. `port` 0 means the port is not
    /// known, which a grant limited to a port never matches.
    fn names(&self, ip: IpAddr, port: u16) -> bool {
        self.networks
            .iter()
            .any(|(cidr, p)| cidr.contains(ip) && p.is_none_or(|p| p == port))
    }

    /// Whether the byte allowance, if the grant has one, is used up.
    fn bytes_spent(&self) -> bool {
        self.entry
            .scope
            .max_bytes
            .is_some_and(|max| self.bytes >= max)
    }

    /// Why the grant does not apply at all right now.
    fn lapsed(&self) -> Option<&'static str> {
        if self.entry.revoked {
            Some("revoked")
        } else if !self.entry.scope.is_active() {
            Some("outside its validity window")
        } else {
            None
        }
    }

    /// Whether `operation` is named by the grant. A machine-access grant lists
    /// its operations explicitly; an empty list grants none.
    fn allows(&self, operation: &str) -> bool {
        self.entry
            .scope
            .allowed_operations
            .iter()
            .any(|o| o == operation)
    }

    /// Count one use against the rate limit. `false`, and nothing counted,
    /// when the limit for the current minute is reached.
    fn take_use(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= RATE_WINDOW {
            self.window_start = now;
            self.window_uses = 0;
        }
        if let Some(max) = self.entry.scope.max_uses_per_minute
            && self.window_uses >= max
        {
            return false;
        }
        self.window_uses += 1;
        self.uses += 1;
        true
    }

    fn summary(&self) -> Value {
        json!({
            "grant_id": self.entry.delegation_id,
            "owner_did": self.entry.grantor_did,
            "grantee_did": self.entry.grantee_did,
            "resources": self.entry.scope.machine_resources,
            "operations": self.entry.scope.allowed_operations,
            "max_uses_per_minute": self.entry.scope.max_uses_per_minute,
            "max_bytes": self.entry.scope.max_bytes,
            "operation_bounds": self.entry.scope.operation_bounds,
            "not_after": self.entry.scope.time_bound.as_ref().map(|t| t.not_after),
            "created_at": self.entry.created_at,
            "revoked": self.entry.revoked,
            "revoked_at": self.entry.revoked_at,
            "uses": self.uses,
            "refusals": self.refusals,
            "bytes": self.bytes,
        })
    }
}

/// The owner-signed machine-access grants on this node, with a use meter per
/// grant.
pub struct MachineAccessGrants {
    /// This node's machine DID, as configured. A grant to it covers any job on
    /// the node.
    node_did: Option<String>,
    grants: RwLock<HashMap<String, Grant>>,
}

impl std::fmt::Debug for MachineAccessGrants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineAccessGrants")
            .field("node_did", &self.node_did)
            .field("grants", &self.grants.read().len())
            .finish()
    }
}

impl MachineAccessGrants {
    /// An empty store for the node whose machine DID is `node_did`.
    pub fn new(node_did: Option<String>) -> Self {
        Self {
            node_did,
            grants: RwLock::new(HashMap::new()),
        }
    }

    fn covers_node(&self, grant: &Grant) -> bool {
        self.node_did.as_deref() == Some(grant.entry.grantee_did.as_str())
    }

    /// Whether `grant` covers work done for `grantee`: every grant to the node
    /// does, and a grant to a DID covers that DID.
    fn covers(&self, grant: &Grant, grantee: Option<&str>) -> bool {
        self.covers_node(grant) || grantee == Some(grant.entry.grantee_did.as_str())
    }

    /// Whether any network grant is made out to `did` itself.
    pub fn has_network_grant_for(&self, did: &str) -> bool {
        self.grants
            .read()
            .values()
            .any(|g| g.entry.grantee_did == did && !g.networks.is_empty())
    }

    /// Whether a grant covering `grantee` is limited to `port`.
    pub fn names_port(&self, port: u16, grantee: Option<&str>) -> bool {
        self.grants
            .read()
            .values()
            .any(|g| self.covers(g, grantee) && g.networks.iter().any(|(_, p)| *p == Some(port)))
    }

    /// The grant that currently opens `ip:port` for `grantee`, without
    /// counting a use. Used to attribute bytes to the grant a connection went
    /// through.
    pub fn grant_for(&self, ip: IpAddr, port: u16, grantee: Option<&str>) -> Option<String> {
        self.grants
            .read()
            .iter()
            .find(|(_, g)| {
                g.names(ip, port)
                    && self.covers(g, grantee)
                    && g.lapsed().is_none()
                    && g.allows(OP_CONNECT)
            })
            .map(|(id, _)| id.clone())
    }

    /// Count `bytes` moved through grant `id`. `false` once the grant's byte
    /// allowance is exceeded, after which it opens nothing.
    pub fn charge_bytes(&self, id: &str, bytes: u64) -> bool {
        let mut grants = self.grants.write();
        let Some(grant) = grants.get_mut(id) else {
            return false;
        };
        grant.bytes = grant.bytes.saturating_add(bytes);
        match grant.entry.scope.max_bytes {
            Some(max) if grant.bytes > max => {
                grant.refusals += 1;
                warn!(
                    target: "machine_access",
                    grant = %id,
                    grantee = %grant.entry.grantee_did,
                    bytes = grant.bytes,
                    max_bytes = max,
                    "machine-access grant's byte allowance is spent"
                );
                false
            }
            _ => true,
        }
    }

    /// Revoke every unrevoked grant not signed by `owner_did` (every grant,
    /// when the machine has no owner), returning them as they now stand.
    fn revoke_not_granted_by(&self, owner_did: Option<&str>) -> Vec<DelegationEntry> {
        let mut revoked = Vec::new();
        for grant in self.grants.write().values_mut() {
            if !grant.entry.revoked && owner_did != Some(grant.entry.grantor_did.as_str()) {
                grant.entry.revoke();
                revoked.push(grant.entry.clone());
            }
        }
        revoked
    }

    /// Hold `entry`. Callers insert only what the owner signed, or what was
    /// persisted after the owner signed it.
    fn insert(&self, entry: DelegationEntry) -> Result<(), String> {
        let grant = Grant::from_entry(entry)?;
        self.grants
            .write()
            .insert(grant.entry.delegation_id.clone(), grant);
        Ok(())
    }

    /// Mark grant `id` revoked and return it as it now stands.
    pub(crate) fn revoke(&self, id: &str) -> Option<DelegationEntry> {
        let mut grants = self.grants.write();
        let grant = grants.get_mut(id)?;
        if !grant.entry.revoked {
            grant.entry.revoke();
        }
        Some(grant.entry.clone())
    }

    /// Every grant held, as the owner signed it, including revoked and
    /// expired ones; a reader checks them.
    pub fn entries(&self) -> Vec<DelegationEntry> {
        self.grants
            .read()
            .values()
            .map(|g| g.entry.clone())
            .collect()
    }

    /// This node's machine DID, the grantee of grants covering the node.
    pub fn node_did(&self) -> Option<&str> {
        self.node_did.as_deref()
    }

    fn list(&self) -> Vec<Value> {
        let grants = self.grants.read();
        let mut rows: Vec<&Grant> = grants.values().collect();
        rows.sort_by_key(|a| a.entry.created_at);
        rows.into_iter().map(Grant::summary).collect()
    }

    /// The grant that opens `ip` to work done for `grantee` (or to any job on
    /// the node, when `grantee` is `None`), if one does, counting the use.
    /// `port` is the destination port, or 0 when the caller cannot know it; a
    /// grant limited to a port never matches an unknown one.
    pub fn authorize_network(
        &self,
        host: &str,
        ip: IpAddr,
        port: u16,
        grantee: Option<&str>,
    ) -> Option<String> {
        let now = Instant::now();
        let mut grants = self.grants.write();
        for (id, grant) in grants.iter_mut() {
            if !grant.names(ip, port) || !self.covers(grant, grantee) {
                continue;
            }
            let refusal = grant
                .lapsed()
                .or_else(|| (!grant.allows(OP_CONNECT)).then_some("connect is not granted"))
                .or_else(|| grant.bytes_spent().then_some("its byte allowance is spent"))
                .or_else(|| (!grant.take_use(now)).then_some("its rate limit is reached"));
            if let Some(reason) = refusal {
                grant.refusals += 1;
                warn!(
                    target: "machine_access",
                    grant = %id,
                    grantee = %grant.entry.grantee_did,
                    host,
                    %ip,
                    port,
                    reason,
                    "machine-access grant names this destination but does not apply"
                );
                continue;
            }
            info!(
                target: "machine_access",
                grant = %id,
                grantee = %grant.entry.grantee_did,
                host,
                %ip,
                port,
                uses = grant.uses,
                "egress through machine-access grant"
            );
            return Some(id.clone());
        }
        None
    }

    /// Load the grants persisted on this node.
    pub fn load(&self, store: &dyn KvStore) {
        let rows = match store.scan_prefix(CF_METADATA, KEY_PREFIX.as_bytes()) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(target: "machine_access", error = %e, "could not list machine-access grants");
                return;
            }
        };
        let mut loaded = 0usize;
        for (key, value) in rows {
            let outcome = serde_json::from_slice::<DelegationEntry>(&value)
                .map_err(|e| e.to_string())
                .and_then(|entry| self.insert(entry));
            match outcome {
                Ok(()) => loaded += 1,
                Err(e) => warn!(
                    target: "machine_access",
                    key = %String::from_utf8_lossy(&key),
                    error = %e,
                    "dropping unreadable machine-access grant"
                ),
            }
        }
        info!(target: "machine_access", loaded, "machine-access grants loaded");
    }
}

/// What the owner signs to add a grant. The node derives the challenge target
/// from exactly these fields, so a signature covers the whole grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantTerms {
    /// This node's machine DID for any sandboxed job on the node, or the DID
    /// of the agent or tool the grant is for.
    pub grantee_did: String,
    pub resources: Vec<MachineResource>,
    /// `connect` for network resources, `read` and/or `write` for folders.
    pub operations: Vec<String>,
    /// When the grant ends, in milliseconds since the Unix epoch.
    pub expires_at_ms: i64,
    pub max_uses_per_minute: Option<u32>,
    /// Most bytes, sent and received, moved through the grant.
    pub max_bytes: Option<u64>,
    /// Per-operation limits; machine grants take none.
    #[serde(default)]
    pub operation_bounds: Vec<OperationBound>,
}

impl GrantTerms {
    /// The custody-challenge target for adding a grant with these terms.
    pub fn challenge_target(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        let mut target = b"add:".to_vec();
        target.extend_from_slice(&Sha256::digest(&encoded));
        target
    }
}

fn revoke_target(grant_id: &str) -> Vec<u8> {
    let mut target = b"revoke:".to_vec();
    target.extend_from_slice(grant_id.as_bytes());
    target
}

const LIST_TARGET: &[u8] = b"list";

/// A machine-access change the owner is about to sign, as named in
/// `tenzro_createCustodyChallenge` (`machine_access`), so a client can ask for
/// the challenge without computing the account or the target itself.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum MachineAccessChange {
    Add(GrantTerms),
    List,
    Revoke { grant_id: String },
}

/// The owner's account and the challenge target for `change`. Terms are
/// checked first, so the owner is never asked to sign a grant the node would
/// refuse.
pub(crate) fn challenge_subject(
    node: &TenzroNode,
    change: &MachineAccessChange,
) -> Result<(Vec<u8>, Vec<u8>), JsonRpcError> {
    let target = match change {
        MachineAccessChange::Add(terms) => {
            validate_terms(terms, now_ms())?;
            crate::agent_guardrails::check_new_grant(node, &terms.grantee_did, &terms.resources)
                .map_err(invalid)?;
            terms.challenge_target()
        }
        MachineAccessChange::List => LIST_TARGET.to_vec(),
        MachineAccessChange::Revoke { grant_id } => revoke_target(grant_id),
    };
    Ok((machine_owner(node)?.account, target))
}

#[derive(Debug, Deserialize)]
struct AddRequest {
    #[serde(flatten)]
    terms: GrantTerms,
    authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Deserialize)]
struct ListRequest {
    authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    grant_id: String,
    authorization: Option<CustodyAuthorization>,
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
        code: -32003,
        message: message.into(),
        data: None,
    }
}

fn internal(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

/// The machine owner as this node knows it.
struct MachineOwner {
    owner_did: String,
    account: Vec<u8>,
}

/// The owner of the machine named by `operator_did`: its controller.
fn owner_did(node: &TenzroNode) -> Result<String, JsonRpcError> {
    use tenzro_identity::identity::IdentityData;
    let machine_did = node.config().operator_did.clone().ok_or_else(|| {
        refused(
            "this node names no operator_did, so no machine owner can be established and no \
             machine access can be granted",
        )
    })?;
    let registry = node
        .identity_registry()
        .ok_or_else(|| internal("identity registry not initialized"))?;
    let machine = registry.resolve(&machine_did).map_err(|e| {
        refused(format!(
            "cannot resolve the node's machine identity {machine_did}: {e}"
        ))
    })?;
    match &machine.identity_data {
        IdentityData::Machine {
            controller_did: Some(controller),
            ..
        } => Ok(controller.clone()),
        _ => Err(refused(format!(
            "{machine_did} is not a machine with an owner, so no one can grant access to it"
        ))),
    }
}

/// Resolve the owner of the machine named by `operator_did`: its controller,
/// and the passkey account enrolled for that controller.
fn machine_owner(node: &TenzroNode) -> Result<MachineOwner, JsonRpcError> {
    let owner_did = owner_did(node)?;
    let registry = node
        .identity_registry()
        .ok_or_else(|| internal("identity registry not initialized"))?;
    let owner = registry
        .resolve(&owner_did)
        .map_err(|e| refused(format!("cannot resolve the machine owner {owner_did}: {e}")))?;
    let account_hex = owner.metadata.get("smart_account_address").ok_or_else(|| {
        refused(format!(
            "the machine owner {owner_did} has no passkey account to sign machine access with"
        ))
    })?;
    let account = hex::decode(account_hex.trim_start_matches("0x"))
        .map_err(|e| internal(format!("owner account address is not hex: {e}")))?;
    Ok(MachineOwner { owner_did, account })
}

/// Refuse unless the machine owner signed a custody challenge for exactly
/// `target`: the passkey assertion and the ML-DSA-65 leg, both verified by
/// [`crate::passkey_rpc::require_account_control`].
async fn require_machine_owner(
    node: &Arc<TenzroNode>,
    target: &[u8],
    authorization: Option<CustodyAuthorization>,
) -> Result<MachineOwner, JsonRpcError> {
    let owner = machine_owner(node)?;
    let Some(authorization) = authorization else {
        return Err(JsonRpcError {
            code: -32001,
            message: "machine access changes only with the machine owner's signature: request \
                      a custody challenge for the account, operation and target in `data`, sign \
                      it with the owner's passkey and ML-DSA-65 key, and send it as \
                      `authorization`"
                .to_string(),
            data: Some(json!({
                "account_address": format!("0x{}", hex::encode(&owner.account)),
                "operation": "machine_access",
                "target_hex": hex::encode(target),
            })),
        });
    };
    crate::passkey_rpc::require_account_control(
        node,
        &owner.account,
        CustodyOperation::MachineAccess,
        target,
        Some(authorization),
    )
    .await?;
    Ok(owner)
}

/// Check terms before anyone signs them: every resource parses, every
/// operation is known and matches a resource, and the grant expires.
fn validate_terms(terms: &GrantTerms, now_ms: i64) -> Result<(), JsonRpcError> {
    if terms.grantee_did.trim().is_empty() {
        return Err(invalid("grantee_did is required"));
    }
    if terms.operations.is_empty() {
        return Err(invalid(
            "a grant names its operations: connect, read or write",
        ));
    }
    if terms.expires_at_ms <= now_ms {
        return Err(invalid("expires_at_ms must be in the future"));
    }
    if !terms.operation_bounds.is_empty() {
        return Err(invalid("a machine grant takes no operation_bounds"));
    }
    if terms.resources.is_empty() {
        return Err(invalid("a grant names at least one resource"));
    }
    if let Some(op) = terms
        .operations
        .iter()
        .find(|op| ![OP_CONNECT, OP_READ, OP_WRITE].contains(&op.as_str()))
    {
        return Err(invalid(format!(
            "unknown operation {op:?}; use connect, read or write"
        )));
    }
    let has = |op: &str| terms.operations.iter().any(|o| o == op);
    for resource in &terms.resources {
        match resource {
            MachineResource::Network { cidr, .. } => {
                Cidr::parse(cidr).map_err(|e| invalid(e.to_string()))?;
                if !has(OP_CONNECT) {
                    return Err(invalid("a network resource needs the connect operation"));
                }
            }
            MachineResource::Folder { path } => {
                let p = std::path::Path::new(path);
                if !p.is_absolute()
                    || p.components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(invalid(format!(
                        "folder {path:?} must be an absolute path without .."
                    )));
                }
                if !has(OP_READ) && !has(OP_WRITE) {
                    return Err(invalid("a folder resource needs read or write"));
                }
            }
            MachineResource::Device { path } => {
                return Err(invalid(format!(
                    "device {path:?}: the sandbox on this node has no device access, so a device \
                     grant would open nothing"
                )));
            }
        }
    }
    Ok(())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Revoke, and persist the revocation of, every grant not signed by the
/// machine's current owner: all of them when the machine has no owner. Runs
/// once the identity registry is up and whenever the machine changes hands.
pub fn reconcile_owner(node: &TenzroNode) {
    let owner = owner_did(node).ok();
    let revoked = node
        .egress()
        .address_policy()
        .grants()
        .revoke_not_granted_by(owner.as_deref());
    for entry in &revoked {
        if let Err(e) = persist(node, entry) {
            warn!(
                target: "machine_access",
                grant = %entry.delegation_id,
                error = %e.message,
                "could not persist a revocation after an ownership change"
            );
        }
        info!(
            target: "machine_access",
            grant = %entry.delegation_id,
            previous_owner = %entry.grantor_did,
            owner = ?owner,
            "machine-access grant revoked: the machine has a different owner"
        );
    }
}

/// Called after `machine_did` changed hands. Grants on this node end when the
/// node's own machine does.
pub(crate) fn machine_owner_changed(node: &TenzroNode, machine_did: &str) {
    if node.config().operator_did.as_deref() == Some(machine_did) {
        reconcile_owner(node);
    }
}

fn persist(node: &TenzroNode, entry: &DelegationEntry) -> Result<(), JsonRpcError> {
    let store = node
        .storage()
        .ok_or_else(|| internal("storage not initialized"))?;
    let value = serde_json::to_vec(entry).map_err(|e| internal(format!("encode grant: {e}")))?;
    store
        .put(
            CF_METADATA,
            format!("{KEY_PREFIX}{}", entry.delegation_id).as_bytes(),
            &value,
        )
        .map_err(|e| internal(format!("persist grant: {e}")))
}

fn grants(node: &Arc<TenzroNode>) -> &Arc<MachineAccessGrants> {
    node.egress().address_policy().grants()
}

/// `tenzro_addMachineAccess`: add a grant the machine owner signed.
pub(crate) async fn handle_add_machine_access(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: AddRequest = crate::passkey_rpc::parse_params(params)?;
    let store = grants(node);
    validate_terms(&req.terms, now_ms())?;
    crate::agent_guardrails::check_new_grant(node, &req.terms.grantee_did, &req.terms.resources)
        .map_err(invalid)?;
    let owner =
        require_machine_owner(node, &req.terms.challenge_target(), req.authorization).await?;

    let terms = req.terms;
    let not_after = chrono::DateTime::from_timestamp_millis(terms.expires_at_ms)
        .ok_or_else(|| invalid("expires_at_ms is out of range"))?;
    let scope = DelegationScope {
        max_transaction_value: Some(0),
        max_daily_spend: Some(0),
        allowed_operations: terms.operations,
        time_bound: Some(TimeBound::new(chrono::Utc::now(), not_after)),
        machine_resources: terms.resources,
        max_uses_per_minute: terms.max_uses_per_minute,
        max_bytes: terms.max_bytes,
        operation_bounds: terms.operation_bounds,
        ..DelegationScope::unrestricted()
    };
    let entry = DelegationEntry::new(owner.owner_did, terms.grantee_did, scope);
    persist(node, &entry)?;
    store.insert(entry.clone()).map_err(invalid)?;
    info!(
        target: "machine_access",
        grant = %entry.delegation_id,
        owner = %entry.grantor_did,
        grantee = %entry.grantee_did,
        resources = ?entry.scope.machine_resources,
        "machine-access grant added"
    );
    Ok(json!({
        "grant_id": entry.delegation_id,
        "owner_did": entry.grantor_did,
        "grantee_did": entry.grantee_did,
        "not_after": not_after,
    }))
}

/// `tenzro_listMachineAccess`: the grants on this node and their meters.
pub(crate) async fn handle_list_machine_access(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ListRequest = crate::passkey_rpc::parse_params(params)?;
    require_machine_owner(node, LIST_TARGET, req.authorization).await?;
    Ok(json!({ "grants": grants(node).list() }))
}

/// `tenzro_revokeMachineAccess`: end a grant. The next check refuses it.
pub(crate) async fn handle_revoke_machine_access(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RevokeRequest = crate::passkey_rpc::parse_params(params)?;
    require_machine_owner(node, &revoke_target(&req.grant_id), req.authorization).await?;
    let entry = grants(node)
        .revoke(&req.grant_id)
        .ok_or_else(|| invalid(format!("no machine-access grant {}", req.grant_id)))?;
    persist(node, &entry)?;
    info!(
        target: "machine_access",
        grant = %entry.delegation_id,
        grantee = %entry.grantee_did,
        "machine-access grant revoked"
    );
    Ok(json!({
        "grant_id": entry.delegation_id,
        "revoked_at": entry.revoked_at,
    }))
}

#[cfg(test)]
impl MachineAccessGrants {
    /// A store for node `did:tenzro:machine:test` holding one grant to the
    /// node, as if its owner had signed it. Returns the store and the grant id.
    pub(crate) fn with_node_grant_for_test(
        resources: Vec<MachineResource>,
        operations: &[&str],
        ttl: chrono::Duration,
        max_uses_per_minute: Option<u32>,
    ) -> (Arc<Self>, String) {
        let store = Arc::new(Self::new(Some(TEST_NODE_DID.to_string())));
        let id = store.grant_for_test(
            TEST_NODE_DID,
            resources,
            operations,
            ttl,
            max_uses_per_minute,
        );
        (store, id)
    }

    fn grant_for_test(
        &self,
        grantee: &str,
        resources: Vec<MachineResource>,
        operations: &[&str],
        ttl: chrono::Duration,
        max_uses_per_minute: Option<u32>,
    ) -> String {
        self.grant_with_limits_for_test(
            grantee,
            resources,
            operations,
            ttl,
            max_uses_per_minute,
            None,
        )
    }

    pub(crate) fn grant_with_limits_for_test(
        &self,
        grantee: &str,
        resources: Vec<MachineResource>,
        operations: &[&str],
        ttl: chrono::Duration,
        max_uses_per_minute: Option<u32>,
        max_bytes: Option<u64>,
    ) -> String {
        let now = chrono::Utc::now();
        let (from, to) = if ttl >= chrono::Duration::zero() {
            (now, now + ttl)
        } else {
            (now + ttl - chrono::Duration::hours(1), now + ttl)
        };
        let scope = DelegationScope {
            allowed_operations: operations.iter().map(|s| s.to_string()).collect(),
            time_bound: Some(TimeBound::new(from, to)),
            machine_resources: resources,
            max_uses_per_minute,
            max_bytes,
            ..DelegationScope::unrestricted()
        };
        let entry = DelegationEntry::new(TEST_OWNER_DID.into(), grantee.into(), scope);
        let id = entry.delegation_id.clone();
        self.insert(entry).expect("test grant");
        id
    }

    fn uses_for_test(&self, id: &str) -> (u64, u64) {
        let grants = self.grants.read();
        let g = &grants[id];
        (g.uses, g.refusals)
    }

    /// Whether a job on the node, attributed to no agent, may reach `ip:port`.
    fn node_check(&self, ip: IpAddr, port: u16) -> Option<String> {
        self.authorize_network("h", ip, port, None)
    }
}

#[cfg(test)]
const TEST_OWNER_DID: &str = "did:tenzro:human:owner";

#[cfg(test)]
pub(crate) const TEST_NODE_DID: &str = "did:tenzro:machine:test";

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(cidr: &str, port: Option<u16>) -> MachineResource {
        MachineResource::Network {
            cidr: cidr.into(),
            port,
        }
    }

    fn hour() -> chrono::Duration {
        chrono::Duration::hours(1)
    }

    #[test]
    fn a_grant_opens_exactly_its_destination() {
        let (store, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("10.20.0.0/16", Some(8080))],
            &[OP_CONNECT],
            hour(),
            None,
        );
        assert_eq!(store.node_check(ip("10.20.5.5"), 8080), Some(id.clone()));
        assert_eq!(store.node_check(ip("10.20.5.5"), 8081), None);
        assert_eq!(store.node_check(ip("10.20.5.5"), 0), None);
        assert_eq!(store.node_check(ip("10.21.0.1"), 8080), None);
        assert_eq!(store.node_check(ip("127.0.0.1"), 8080), None);
        assert_eq!(store.node_check(ip("169.254.169.254"), 8080), None);
        assert_eq!(store.uses_for_test(&id), (1, 0));
    }

    #[test]
    fn an_expired_grant_opens_nothing_and_the_refusal_is_counted() {
        let (store, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            chrono::Duration::seconds(-1),
            None,
        );
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
        assert_eq!(store.uses_for_test(&id), (0, 1));
    }

    #[test]
    fn a_revoked_grant_stops_opening_at_once() {
        let (store, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        assert!(store.node_check(ip("127.0.0.1"), 80).is_some());
        assert!(store.revoke(&id).expect("known grant").revoked);
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
        assert_eq!(store.uses_for_test(&id), (1, 1));
    }

    #[test]
    fn a_grant_without_connect_opens_no_destination() {
        let (store, _) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_READ],
            hour(),
            None,
        );
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
    }

    #[test]
    fn a_grant_to_an_agent_opens_only_that_agents_requests() {
        let store = MachineAccessGrants::new(Some(TEST_NODE_DID.into()));
        let id = store.grant_for_test(
            "did:tenzro:machine:agent",
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        let agent = Some("did:tenzro:machine:agent");
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
        assert_eq!(
            store.authorize_network("h", ip("127.0.0.1"), 80, Some("did:tenzro:machine:other")),
            None
        );
        assert_eq!(
            store.authorize_network("h", ip("127.0.0.1"), 80, agent),
            Some(id)
        );
        assert!(store.has_network_grant_for("did:tenzro:machine:agent"));
        assert!(!store.has_network_grant_for("did:tenzro:machine:other"));
    }

    #[test]
    fn a_grant_to_the_node_covers_every_agent_on_it() {
        let (store, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        assert_eq!(
            store.authorize_network("h", ip("127.0.0.1"), 80, Some("did:tenzro:machine:agent")),
            Some(id)
        );
    }

    #[test]
    fn only_ports_a_grant_names_get_a_port_of_their_own() {
        let (store, _) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("10.20.0.0/16", Some(8080))],
            &[OP_CONNECT],
            hour(),
            None,
        );
        assert!(store.names_port(8080, None));
        assert!(store.names_port(8080, Some("did:tenzro:machine:agent")));
        assert!(!store.names_port(8081, None));
    }

    #[test]
    fn the_byte_allowance_closes_the_grant_once_spent() {
        let (store, _) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        let id = store.grant_with_limits_for_test(
            TEST_NODE_DID,
            vec![net("10.0.0.0/8", None)],
            &[OP_CONNECT],
            hour(),
            None,
            Some(100),
        );
        assert_eq!(store.grant_for(ip("10.1.2.3"), 443, None), Some(id.clone()));
        assert!(store.charge_bytes(&id, 60));
        assert!(store.node_check(ip("10.1.2.3"), 443).is_some());
        assert!(store.charge_bytes(&id, 40));
        assert!(!store.charge_bytes(&id, 1));
        assert_eq!(store.node_check(ip("10.1.2.3"), 443), None);
        // A grant without an allowance is not affected.
        assert!(store.node_check(ip("127.0.0.1"), 80).is_some());
    }

    #[test]
    fn a_new_owner_revokes_every_grant_the_previous_owner_signed() {
        let (store, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        assert!(store.revoke_not_granted_by(Some(TEST_OWNER_DID)).is_empty());
        assert!(store.node_check(ip("127.0.0.1"), 80).is_some());

        let revoked = store.revoke_not_granted_by(Some("did:tenzro:human:new-owner"));
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].delegation_id, id);
        assert!(revoked[0].revoked);
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
    }

    #[test]
    fn a_machine_without_an_owner_keeps_no_grants() {
        let (store, _) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        assert_eq!(store.revoke_not_granted_by(None).len(), 1);
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
    }

    #[test]
    fn the_rate_limit_caps_uses_per_minute() {
        let (store, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            Some(2),
        );
        assert!(store.node_check(ip("127.0.0.1"), 80).is_some());
        assert!(store.node_check(ip("127.0.0.1"), 80).is_some());
        assert_eq!(store.node_check(ip("127.0.0.1"), 80), None);
        assert_eq!(store.uses_for_test(&id), (2, 1));
    }

    #[test]
    fn a_malformed_range_is_refused() {
        let store = MachineAccessGrants::new(None);
        let mut scope = DelegationScope::unrestricted();
        scope.machine_resources = vec![net("10.0.0.0/40", None)];
        let entry = DelegationEntry::new("o".into(), "g".into(), scope);
        assert!(store.insert(entry).is_err());
    }

    fn terms(grantee: &str, resources: Vec<MachineResource>, ops: &[&str]) -> GrantTerms {
        GrantTerms {
            grantee_did: grantee.into(),
            resources,
            operations: ops.iter().map(|s| s.to_string()).collect(),
            expires_at_ms: now_ms() + 60_000,
            max_uses_per_minute: None,
            max_bytes: None,
            operation_bounds: Vec::new(),
        }
    }

    #[test]
    fn terms_are_checked_before_anyone_signs() {
        let ok = terms(
            TEST_NODE_DID,
            vec![net("127.0.0.1/32", Some(9000))],
            &[OP_CONNECT],
        );
        assert!(validate_terms(&ok, now_ms()).is_ok());
        let for_agent = terms(
            "did:tenzro:machine:agent",
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
        );
        assert!(validate_terms(&for_agent, now_ms()).is_ok());

        let mut expired = ok.clone();
        expired.expires_at_ms = now_ms() - 1;
        let bad = [
            terms(TEST_NODE_DID, vec![], &[OP_CONNECT]),
            terms(TEST_NODE_DID, vec![net("127.0.0.1/32", None)], &[]),
            terms(TEST_NODE_DID, vec![net("127.0.0.1/32", None)], &["admin"]),
            terms(TEST_NODE_DID, vec![net("127.0.0.1/32", None)], &[OP_READ]),
            terms(TEST_NODE_DID, vec![net("not-a-range", None)], &[OP_CONNECT]),
            terms(
                TEST_NODE_DID,
                vec![MachineResource::Folder {
                    path: "/data/../etc".into(),
                }],
                &[OP_READ],
            ),
            terms(
                TEST_NODE_DID,
                vec![MachineResource::Device {
                    path: "/dev/video0".into(),
                }],
                &[OP_READ],
            ),
            expired,
        ];
        for t in bad {
            assert!(
                validate_terms(&t, now_ms()).is_err(),
                "{t:?} must be refused"
            );
        }
    }

    #[test]
    fn the_challenge_target_binds_every_term() {
        let base = terms(
            TEST_NODE_DID,
            vec![net("127.0.0.1/32", Some(9000))],
            &[OP_CONNECT],
        );
        let mut wider = base.clone();
        wider.resources = vec![net("127.0.0.0/8", Some(9000))];
        let mut longer = base.clone();
        longer.expires_at_ms += 1;
        let mut faster = base.clone();
        faster.max_uses_per_minute = Some(1000);
        let mut bigger = base.clone();
        bigger.max_bytes = Some(1 << 30);
        let mut bounded = base.clone();
        bounded.operation_bounds = vec![OperationBound {
            operation: OP_CONNECT.into(),
            allowed_values: vec![],
            min: None,
            max: None,
            max_per_hour: Some(1),
        }];
        for other in [wider, longer, faster, bigger, bounded] {
            assert_ne!(base.challenge_target(), other.challenge_target());
        }
        assert_ne!(revoke_target("a"), base.challenge_target());
    }

    #[test]
    fn grants_survive_a_restart() {
        let store = tenzro_storage::MemoryStore::new();
        let (grants, id) = MachineAccessGrants::with_node_grant_for_test(
            vec![net("127.0.0.1/32", None)],
            &[OP_CONNECT],
            hour(),
            None,
        );
        let entry = grants.grants.read()[&id].entry.clone();
        store
            .put(
                CF_METADATA,
                format!("{KEY_PREFIX}{id}").as_bytes(),
                &serde_json::to_vec(&entry).unwrap(),
            )
            .unwrap();
        let reloaded = MachineAccessGrants::new(Some(TEST_NODE_DID.into()));
        reloaded.load(&store);
        assert_eq!(reloaded.node_check(ip("127.0.0.1"), 80), Some(id));
    }
}
