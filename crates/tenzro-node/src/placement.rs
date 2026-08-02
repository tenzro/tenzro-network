//! App-hosting placement and economics: choosing which nodes serve a deployment,
//! recording the resulting leases, and re-placing on liveness failure.
//!
//! # What placement decides
//!
//! A deployment (a static site, a `function`, or a `machine`) names a runtime
//! class and a resource envelope but not a node. Placement resolves that into a
//! concrete set of serving nodes: it takes a snapshot of the provider
//! announcements the node has heard on `tenzro/providers`, hard-filters them to
//! the ones that can actually run the deployment — advertising the deployment's
//! runtime class in `runtime_support.hosting_runtimes`, a TEE when the
//! deployment demands one, enough CPU / RAM / disk headroom, a bound iroh
//! endpoint to receive `tenzro/http` forwards, and a `direct` reachability tier
//! so the edge can dial them — then ranks the survivors and leases the top `N`
//! (the replica count) across distinct nodes.
//!
//! # Leases are the economic record
//!
//! Each chosen node is recorded as a [`LeaseRecord`] — `{app_id, node_id,
//! runtime_class, resources, price_per_hour, region, capability_set,
//! leased_at, expires_at}` — write-through to `CF_METADATA` under
//! `hosting_lease:<app_id>:<node_id>` and hydrated on boot. A lease is the
//! metered claim: the deployer owes `price_per_hour` for the window the node
//! serves, and the node earns it. Bandwidth relayed through the edge and per-
//! request compute meter against the same lease via [`LeaseMeter`].
//!
//! # Bidding
//!
//! The default in-process scheduler ranks announcements directly (cheapest
//! capable node first) — the announcement's advertised price *is* the bid. A
//! node that wants to be chosen advertises capacity and a competitive price; a
//! node that is saturated advertises no headroom and is filtered out. This keeps
//! placement a pure function of the announcement snapshot: no extra round-trip,
//! no parallel bid topic to keep in sync with the liveness topic already in use.
//!
//! # Failover
//!
//! [`PlacementScheduler::handle_liveness_loss`] is called by the `tenzro/sla`
//! subscriber when a serving node misses its liveness window. It drops that
//! node's lease, re-runs selection over the remaining capable nodes to restore
//! the replica count, and re-writes the [`crate::ingress::IngressTable`] so the
//! edge stops routing to the dead node on the next request.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_METADATA, KvStore};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::ingress::IngressTable;

/// Key prefix for lease records within `CF_METADATA`.
const LEASE_PREFIX: &str = "hosting_lease:";

/// Default lease window when a deployment does not request one, in
/// milliseconds. A lease expires unless renewed; expiry is the natural GC for
/// leases whose deployer has stopped paying.
pub const DEFAULT_LEASE_MS: u64 = 3_600_000; // one hour

fn lease_key(app_id: &str, node_id: &str) -> Vec<u8> {
    format!("{LEASE_PREFIX}{app_id}:{node_id}").into_bytes()
}

fn lease_app_prefix(app_id: &str) -> Vec<u8> {
    format!("{LEASE_PREFIX}{app_id}:").into_bytes()
}

#[derive(Debug, Error)]
pub enum PlacementError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("no capable node found for runtime class {0}")]
    NoCapableNode(String),
    #[error("could not lease {want} replica(s); only {got} capable node(s) available")]
    InsufficientReplicas { want: usize, got: usize },
    #[error("ingress error: {0}")]
    Ingress(String),
}

/// The runtime class a deployment requests. Matched against a node's advertised
/// `runtime_support.hosting_runtimes` (which carries the same string values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeClass {
    Static,
    Function,
    Machine,
}

impl RuntimeClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeClass::Static => "static",
            RuntimeClass::Function => "function",
            RuntimeClass::Machine => "machine",
        }
    }

    // Returns Option, not the FromStr `Result<Self, _>` contract.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "static" => Some(RuntimeClass::Static),
            "function" => Some(RuntimeClass::Function),
            "machine" => Some(RuntimeClass::Machine),
            _ => None,
        }
    }
}

/// What a deployment needs from a serving node. `machine` deployments carry a
/// full CPU/RAM/disk envelope; `static` and `function` deployments are light and
/// leave the resource fields at zero, so any capable node clears the headroom
/// check.
#[derive(Debug, Clone)]
pub struct PlacementRequest {
    /// The deployment id — shared naming space across static / function / machine.
    pub app_id: String,
    pub class: RuntimeClass,
    /// Minimum CPU cores the serving node must report free (0 = don't care).
    pub min_cpu_cores: u32,
    /// Minimum RAM in GiB the serving node must report (0 = don't care).
    pub min_ram_gb: u32,
    /// Minimum free disk in GiB the serving node must report (0 = don't care).
    pub min_disk_gb: u32,
    /// When true, the serving node must advertise a usable TEE.
    pub tee_required: bool,
    /// Number of distinct nodes to lease. Clamped to at least 1.
    pub replicas: usize,
    /// Preferred region hint. A node whose announced region matches is ranked
    /// ahead of one that does not; a non-match is not disqualifying.
    pub region_hint: Option<String>,
    /// Ceiling on the per-hour price (in TNZO) the deployer will pay a node.
    /// A node quoting above this is filtered out. `None` = no ceiling.
    pub max_price_per_hour: Option<u128>,
}

impl PlacementRequest {
    pub fn replica_count(&self) -> usize {
        self.replicas.max(1)
    }
}

/// One candidate serving node, distilled from a `ProviderAnnouncementMessage`
/// into just the fields placement ranks on. Decoupling from the announcement
/// type keeps [`select`] a pure function that is trivial to unit-test.
#[derive(Debug, Clone)]
pub struct NodeCandidate {
    /// The iroh `EndpointId` string the edge dials for `tenzro/http` forwards.
    /// A node with no bound endpoint cannot serve a forward and is skipped.
    pub endpoint_id: String,
    /// Runtime classes this node advertises it can serve.
    pub hosting_runtimes: Vec<String>,
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub disk_gb: u32,
    pub tee_available: bool,
    /// Earned reachability tier (`direct` / `relay_only` / other). Only `direct`
    /// nodes are dialable by the edge without a relay hop, so placement requires
    /// it.
    pub reachability: String,
    pub region: Option<String>,
    /// Per-hour price (TNZO) this node quotes for hosting. The bid.
    pub price_per_hour: u128,
}

impl NodeCandidate {
    fn serves(&self, class: RuntimeClass) -> bool {
        self.hosting_runtimes.iter().any(|c| c == class.as_str())
    }

    fn has_headroom(&self, req: &PlacementRequest) -> bool {
        self.cpu_cores >= req.min_cpu_cores
            && self.ram_gb >= req.min_ram_gb
            && self.disk_gb >= req.min_disk_gb
    }
}

/// A recorded placement lease: the durable, metered claim that a specific node
/// serves a specific app for a price over a window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub app_id: String,
    /// The serving node's iroh `EndpointId` string.
    pub node_id: String,
    /// Runtime class this lease covers (`static` / `function` / `machine`).
    pub runtime_class: String,
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub disk_gb: u32,
    pub tee: bool,
    /// TNZO the deployer owes the node per hour of serving.
    pub price_per_hour: u128,
    pub region: Option<String>,
    /// The runtime classes the node advertised when the lease was struck — the
    /// capability set the deployer relied on.
    pub capability_set: Vec<String>,
    pub leased_at: u64,
    pub expires_at: u64,
    /// TNZO metered against this lease so far: compute (per-request) plus relay
    /// bandwidth. Settlement debits the deployer and credits the node from this.
    #[serde(default)]
    pub metered_tnzo: u128,
}

impl LeaseRecord {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }
}

/// The placement scheduler: owns the lease table (write-through + hydrated) and
/// drives selection, leasing, and failover against a live candidate snapshot.
///
/// The scheduler does not itself hold a provider registry — the caller passes a
/// candidate snapshot into [`select_and_lease`] and [`handle_liveness_loss`].
/// That keeps this module free of the node's discovery internals and testable in
/// isolation.
pub struct PlacementScheduler {
    /// `(app_id, node_id) → lease`. Keyed by the composite so an app's replicas
    /// each get a row.
    leases: DashMap<(String, String), LeaseRecord>,
    ingress: Arc<IngressTable>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for PlacementScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlacementScheduler")
            .field("leases", &self.leases.len())
            .finish()
    }
}

impl PlacementScheduler {
    pub fn new(ingress: Arc<IngressTable>) -> Self {
        Self {
            leases: DashMap::new(),
            ingress,
            storage: None,
        }
    }

    /// Storage-backed scheduler: hydrates existing leases from `CF_METADATA`
    /// under the `hosting_lease:` prefix.
    pub fn with_storage(
        ingress: Arc<IngressTable>,
        storage: Arc<dyn KvStore>,
    ) -> Result<Self, PlacementError> {
        let scheduler = Self {
            leases: DashMap::new(),
            ingress,
            storage: Some(storage.clone()),
        };
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, LEASE_PREFIX.as_bytes())
            .map_err(|e| PlacementError::Storage(format!("lease scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<LeaseRecord>(&bytes) {
                    Ok(record) => {
                        scheduler
                            .leases
                            .insert((record.app_id.clone(), record.node_id.clone()), record);
                        restored += 1;
                    }
                    Err(e) => warn!("skipping undecodable hosting lease: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(PlacementError::Storage(format!("lease get: {e}"))),
            }
        }
        if restored > 0 {
            debug!("hydrated {restored} hosting lease record(s)");
        }
        Ok(scheduler)
    }

    fn persist(&self, record: &LeaseRecord) -> Result<(), PlacementError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(record)
                .map_err(|e| PlacementError::Serialization(e.to_string()))?;
            storage
                .put(
                    CF_METADATA,
                    &lease_key(&record.app_id, &record.node_id),
                    &bytes,
                )
                .map_err(|e| PlacementError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    fn drop_lease_row(&self, app_id: &str, node_id: &str) -> Result<(), PlacementError> {
        self.leases
            .remove(&(app_id.to_string(), node_id.to_string()));
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &lease_key(app_id, node_id))
                .map_err(|e| PlacementError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    /// Select serving nodes for a request, record their leases, and write the
    /// chosen node set into the ingress table so the edge routes to them.
    /// Returns the leased node ids in preference order (index 0 primary).
    pub fn select_and_lease(
        &self,
        req: &PlacementRequest,
        candidates: &[NodeCandidate],
        now_ms: u64,
        lease_window_ms: u64,
    ) -> Result<Vec<String>, PlacementError> {
        let chosen = select(req, candidates);
        if chosen.is_empty() {
            return Err(PlacementError::NoCapableNode(
                req.class.as_str().to_string(),
            ));
        }
        let want = req.replica_count();
        if chosen.len() < want {
            return Err(PlacementError::InsufficientReplicas {
                want,
                got: chosen.len(),
            });
        }
        let picked: Vec<&NodeCandidate> = chosen.into_iter().take(want).collect();
        let window = if lease_window_ms == 0 {
            DEFAULT_LEASE_MS
        } else {
            lease_window_ms
        };

        // Drop any prior leases for this app that are not in the new set — a
        // re-placement replaces the serving set atomically.
        let keep: std::collections::HashSet<String> =
            picked.iter().map(|c| c.endpoint_id.clone()).collect();
        let stale: Vec<String> = self
            .leases
            .iter()
            .filter(|e| e.key().0 == req.app_id && !keep.contains(&e.key().1))
            .map(|e| e.key().1.clone())
            .collect();
        for node_id in stale {
            self.drop_lease_row(&req.app_id, &node_id)?;
        }

        let mut node_ids = Vec::with_capacity(picked.len());
        for cand in &picked {
            let record = LeaseRecord {
                app_id: req.app_id.clone(),
                node_id: cand.endpoint_id.clone(),
                runtime_class: req.class.as_str().to_string(),
                cpu_cores: cand.cpu_cores,
                ram_gb: cand.ram_gb,
                disk_gb: cand.disk_gb,
                tee: cand.tee_available,
                price_per_hour: cand.price_per_hour,
                region: cand.region.clone(),
                capability_set: cand.hosting_runtimes.clone(),
                leased_at: now_ms,
                expires_at: now_ms.saturating_add(window),
                metered_tnzo: self
                    .leases
                    .get(&(req.app_id.clone(), cand.endpoint_id.clone()))
                    .map(|l| l.metered_tnzo)
                    .unwrap_or(0),
            };
            self.persist(&record)?;
            self.leases
                .insert((req.app_id.clone(), cand.endpoint_id.clone()), record);
            node_ids.push(cand.endpoint_id.clone());
        }

        self.ingress
            .set_placement(&req.app_id, node_ids.clone(), now_ms)
            .map_err(|e| PlacementError::Ingress(e.to_string()))?;

        Ok(node_ids)
    }

    /// A serving node missed its liveness window. Drop its lease, then re-run
    /// selection over the remaining candidates to restore the replica count and
    /// re-write the ingress table. Returns the new serving-node set.
    ///
    /// `candidates` must exclude the dead node (the caller has just observed it
    /// unreachable). If no replacement is available the app runs at reduced
    /// replica count until the next candidate appears; the ingress table is
    /// still updated so the edge stops dialing the dead node.
    pub fn handle_liveness_loss(
        &self,
        app_id: &str,
        dead_node_id: &str,
        req: &PlacementRequest,
        candidates: &[NodeCandidate],
        now_ms: u64,
        lease_window_ms: u64,
    ) -> Result<Vec<String>, PlacementError> {
        self.drop_lease_row(app_id, dead_node_id)?;

        // Surviving leased nodes keep serving; only the missing slot is re-let.
        let mut serving: Vec<String> = self
            .leases
            .iter()
            .filter(|e| e.key().0 == app_id)
            .map(|e| e.key().1.clone())
            .collect();

        let want = req.replica_count();
        if serving.len() < want {
            // Re-select excluding nodes already serving this app.
            let already: std::collections::HashSet<&str> =
                serving.iter().map(|s| s.as_str()).collect();
            let already_dead = dead_node_id;
            let fresh: Vec<NodeCandidate> = candidates
                .iter()
                .filter(|c| {
                    c.endpoint_id != already_dead && !already.contains(c.endpoint_id.as_str())
                })
                .cloned()
                .collect();
            let ranked = select(req, &fresh);
            let window = if lease_window_ms == 0 {
                DEFAULT_LEASE_MS
            } else {
                lease_window_ms
            };
            for cand in ranked.into_iter().take(want - serving.len()) {
                let record = LeaseRecord {
                    app_id: app_id.to_string(),
                    node_id: cand.endpoint_id.clone(),
                    runtime_class: req.class.as_str().to_string(),
                    cpu_cores: cand.cpu_cores,
                    ram_gb: cand.ram_gb,
                    disk_gb: cand.disk_gb,
                    tee: cand.tee_available,
                    price_per_hour: cand.price_per_hour,
                    region: cand.region.clone(),
                    capability_set: cand.hosting_runtimes.clone(),
                    leased_at: now_ms,
                    expires_at: now_ms.saturating_add(window),
                    metered_tnzo: 0,
                };
                self.persist(&record)?;
                self.leases
                    .insert((app_id.to_string(), cand.endpoint_id.clone()), record);
                serving.push(cand.endpoint_id.clone());
            }
        }

        // Rewrite the routing table to the surviving + replacement set. An empty
        // set clears the placement, reverting the app to local serving.
        self.ingress
            .set_placement(app_id, serving.clone(), now_ms)
            .map_err(|e| PlacementError::Ingress(e.to_string()))?;
        Ok(serving)
    }

    /// Meter TNZO against a lease — compute for a served request, or bytes
    /// relayed through the edge. Accumulates onto the lease's `metered_tnzo`,
    /// which settlement later debits. Returns the running total, or `None` if
    /// there is no lease for that `(app_id, node_id)` pair.
    pub fn meter(&self, app_id: &str, node_id: &str, tnzo: u128) -> Option<u128> {
        let mut entry = self
            .leases
            .get_mut(&(app_id.to_string(), node_id.to_string()))?;
        entry.metered_tnzo = entry.metered_tnzo.saturating_add(tnzo);
        let total = entry.metered_tnzo;
        let record = entry.clone();
        drop(entry);
        if let Err(e) = self.persist(&record) {
            warn!("failed to persist metered lease: {e}");
        }
        Some(total)
    }

    /// All leases for an app, in no particular order.
    pub fn leases_for(&self, app_id: &str) -> Vec<LeaseRecord> {
        self.leases
            .iter()
            .filter(|e| e.key().0 == app_id)
            .map(|e| e.value().clone())
            .collect()
    }

    /// Every lease the scheduler holds.
    pub fn all_leases(&self) -> Vec<LeaseRecord> {
        self.leases.iter().map(|e| e.value().clone()).collect()
    }

    /// Drop every lease for an app (a deployment removal) and clear its ingress
    /// placement so the edge reverts to local serving / 404.
    pub fn release_app(&self, app_id: &str, now_ms: u64) -> Result<(), PlacementError> {
        let node_ids: Vec<String> = self
            .leases
            .iter()
            .filter(|e| e.key().0 == app_id)
            .map(|e| e.key().1.clone())
            .collect();
        for node_id in node_ids {
            self.drop_lease_row(app_id, &node_id)?;
        }
        // Storage-authoritative sweep: delete any lease row under this app's
        // prefix that the in-memory map did not cover (e.g. a row persisted by a
        // prior process instance that failed to hydrate).
        if let Some(storage) = &self.storage {
            let prefix = lease_app_prefix(app_id);
            let keys = storage
                .get_keys_with_prefix(CF_METADATA, &prefix)
                .map_err(|e| PlacementError::Storage(e.to_string()))?;
            for key in keys {
                storage
                    .delete(CF_METADATA, &key)
                    .map_err(|e| PlacementError::Storage(e.to_string()))?;
            }
        }
        // Empty serving set removes the placement record.
        self.ingress
            .set_placement(app_id, Vec::new(), now_ms)
            .map_err(|e| PlacementError::Ingress(e.to_string()))?;
        Ok(())
    }

    /// Sweep expired leases: drop each lease past its window and re-write the
    /// ingress placement for any app that lost a node. Returns the number of
    /// leases dropped.
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        let expired: Vec<(String, String)> = self
            .leases
            .iter()
            .filter(|e| e.value().is_expired(now_ms))
            .map(|e| e.key().clone())
            .collect();
        let mut affected: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (app_id, node_id) in &expired {
            if self.drop_lease_row(app_id, node_id).is_ok() {
                affected.insert(app_id.clone());
            }
        }
        for app_id in affected {
            let surviving: Vec<String> = self
                .leases
                .iter()
                .filter(|e| e.key().0 == app_id)
                .map(|e| e.key().1.clone())
                .collect();
            if let Err(e) = self.ingress.set_placement(&app_id, surviving, now_ms) {
                warn!("failed to rewrite placement after lease expiry for {app_id}: {e}");
            }
        }
        expired.len()
    }

    /// Reconstruct the placement request for an app from its surviving leases.
    /// The original request is not persisted, but every field needed to re-lease
    /// a lost replica is recoverable from the lease group: the desired replica
    /// count is the number of nodes that were placed, and the resource / TEE
    /// floor is the max across the group's records (so a replacement is at least
    /// as capable as the surviving replicas). Returns `None` for an app with no
    /// leases.
    fn request_from_leases(&self, app_id: &str) -> Option<PlacementRequest> {
        let group: Vec<LeaseRecord> = self.leases_for(app_id);
        let first = group.first()?;
        let class = RuntimeClass::from_str(&first.runtime_class)?;
        let min_cpu_cores = group.iter().map(|l| l.cpu_cores).max().unwrap_or(0);
        let min_ram_gb = group.iter().map(|l| l.ram_gb).max().unwrap_or(0);
        let min_disk_gb = group.iter().map(|l| l.disk_gb).max().unwrap_or(0);
        let tee_required = group.iter().any(|l| l.tee);
        Some(PlacementRequest {
            app_id: app_id.to_string(),
            class,
            min_cpu_cores,
            min_ram_gb,
            min_disk_gb,
            tee_required,
            replicas: group.len().max(1),
            region_hint: first.region.clone(),
            max_price_per_hour: None,
        })
    }

    /// Periodic reconcile against the live candidate set. Sweeps expired leases,
    /// then for every lease whose serving node is no longer a fresh, capable
    /// candidate (its provider announcement went stale, or it dropped below the
    /// resource / reachability floor), evicts that node and re-lets its replica
    /// slot over the surviving candidates. This is the failover driver: a node
    /// that stops announcing on `tenzro/status` falls out of `candidates`, so
    /// the next reconcile tick moves its apps. Returns the number of leases
    /// evicted for staleness (not counting expiry sweeps).
    pub fn reconcile(&self, candidates: &[NodeCandidate], now_ms: u64) -> usize {
        self.sweep_expired(now_ms);

        let live: std::collections::HashSet<&str> =
            candidates.iter().map(|c| c.endpoint_id.as_str()).collect();
        // Snapshot the (app, node) pairs whose node is no longer a live
        // candidate, so we can mutate the map without holding a `Ref`.
        let stale: Vec<(String, String)> = self
            .leases
            .iter()
            .filter(|e| !live.contains(e.key().1.as_str()))
            .map(|e| e.key().clone())
            .collect();

        let mut evicted = 0usize;
        for (app_id, dead_node) in stale {
            let Some(req) = self.request_from_leases(&app_id) else {
                continue;
            };
            let fresh: Vec<NodeCandidate> = candidates
                .iter()
                .filter(|c| c.endpoint_id != dead_node)
                .cloned()
                .collect();
            match self.handle_liveness_loss(
                &app_id,
                &dead_node,
                &req,
                &fresh,
                now_ms,
                DEFAULT_LEASE_MS,
            ) {
                Ok(serving) => {
                    evicted += 1;
                    info!(
                        app_id = %app_id,
                        dead_node = %dead_node,
                        replicas = serving.len(),
                        "placement reconcile: evicted stale serving node, re-let replica slot"
                    );
                }
                Err(e) => {
                    warn!(
                        app_id = %app_id,
                        dead_node = %dead_node,
                        "placement reconcile: failed to re-let after eviction: {e}"
                    );
                }
            }
        }
        evicted
    }
}

/// Rank capable candidates for a request, cheapest region-matching first.
///
/// A candidate is kept only if it (1) advertises the runtime class, (2) has a
/// bound iroh endpoint, (3) is `direct`-reachable, (4) meets the TEE demand,
/// (5) clears the resource headroom, and (6) is at or under the price ceiling.
/// Survivors sort by: region match first, then lowest price, then most
/// headroom, then endpoint id for a stable deterministic order.
fn select<'a>(req: &PlacementRequest, candidates: &'a [NodeCandidate]) -> Vec<&'a NodeCandidate> {
    let mut kept: Vec<&NodeCandidate> = candidates
        .iter()
        .filter(|c| !c.endpoint_id.is_empty())
        .filter(|c| c.serves(req.class))
        .filter(|c| c.reachability == "direct")
        .filter(|c| !req.tee_required || c.tee_available)
        .filter(|c| c.has_headroom(req))
        .filter(|c| match req.max_price_per_hour {
            Some(ceiling) => c.price_per_hour <= ceiling,
            None => true,
        })
        .collect();

    let hint = req.region_hint.as_deref();
    kept.sort_by(|a, b| {
        let a_match = region_matches(a.region.as_deref(), hint);
        let b_match = region_matches(b.region.as_deref(), hint);
        // Region match ranks first (true before false).
        b_match
            .cmp(&a_match)
            // Then cheapest.
            .then(a.price_per_hour.cmp(&b.price_per_hour))
            // Then most CPU headroom.
            .then(b.cpu_cores.cmp(&a.cpu_cores))
            // Stable tiebreak.
            .then(a.endpoint_id.cmp(&b.endpoint_id))
    });
    kept
}

fn region_matches(region: Option<&str>, hint: Option<&str>) -> bool {
    match (region, hint) {
        (Some(r), Some(h)) => r.eq_ignore_ascii_case(h),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, class: &str, price: u128, region: Option<&str>) -> NodeCandidate {
        NodeCandidate {
            endpoint_id: id.to_string(),
            hosting_runtimes: vec![class.to_string()],
            cpu_cores: 8,
            ram_gb: 16,
            disk_gb: 100,
            tee_available: false,
            reachability: "direct".to_string(),
            region: region.map(|s| s.to_string()),
            price_per_hour: price,
        }
    }

    fn req(class: RuntimeClass, replicas: usize) -> PlacementRequest {
        PlacementRequest {
            app_id: "app1".to_string(),
            class,
            min_cpu_cores: 0,
            min_ram_gb: 0,
            min_disk_gb: 0,
            tee_required: false,
            replicas,
            region_hint: None,
            max_price_per_hour: None,
        }
    }

    #[test]
    fn select_filters_by_class() {
        let cands = vec![
            candidate("a", "static", 10, None),
            candidate("b", "machine", 10, None),
        ];
        let r = req(RuntimeClass::Machine, 1);
        let chosen = select(&r, &cands);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].endpoint_id, "b");
    }

    #[test]
    fn select_ranks_cheapest_first() {
        let cands = vec![
            candidate("a", "function", 30, None),
            candidate("b", "function", 10, None),
            candidate("c", "function", 20, None),
        ];
        let r = req(RuntimeClass::Function, 3);
        let chosen = select(&r, &cands);
        assert_eq!(
            chosen
                .iter()
                .map(|c| c.endpoint_id.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c", "a"]
        );
    }

    #[test]
    fn select_prefers_region_match_over_price() {
        let mut cheap = candidate("cheap", "static", 5, Some("us-central1"));
        cheap.region = Some("europe-west1".to_string());
        let matching = candidate("match", "static", 20, Some("us-central1"));
        let cands = vec![cheap, matching];
        let mut r = req(RuntimeClass::Static, 2);
        r.region_hint = Some("us-central1".to_string());
        let chosen = select(&r, &cands);
        assert_eq!(chosen[0].endpoint_id, "match");
    }

    #[test]
    fn select_excludes_relay_only() {
        let mut relay = candidate("relay", "machine", 1, None);
        relay.reachability = "relay_only".to_string();
        let cands = vec![relay];
        let r = req(RuntimeClass::Machine, 1);
        assert!(select(&r, &cands).is_empty());
    }

    #[test]
    fn select_enforces_tee() {
        let no_tee = candidate("a", "machine", 1, None);
        let cands = vec![no_tee];
        let mut r = req(RuntimeClass::Machine, 1);
        r.tee_required = true;
        assert!(select(&r, &cands).is_empty());
    }

    #[test]
    fn select_enforces_headroom_and_price_ceiling() {
        let small = {
            let mut c = candidate("small", "machine", 1, None);
            c.cpu_cores = 2;
            c
        };
        let expensive = {
            let mut c = candidate("exp", "machine", 100, None);
            c.cpu_cores = 16;
            c
        };
        let good = {
            let mut c = candidate("good", "machine", 5, None);
            c.cpu_cores = 16;
            c
        };
        let cands = vec![small, expensive, good];
        let mut r = req(RuntimeClass::Machine, 1);
        r.min_cpu_cores = 8;
        r.max_price_per_hour = Some(50);
        let chosen = select(&r, &cands);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].endpoint_id, "good");
    }

    #[test]
    fn lease_and_meter_roundtrip() {
        let ingress = Arc::new(IngressTable::new());
        let sched = PlacementScheduler::new(ingress.clone());
        // Real 64-hex endpoint ids so ingress set_placement accepts them.
        let a = "1".repeat(64);
        let b = "2".repeat(64);
        let cands = vec![
            candidate(&a, "machine", 10, None),
            candidate(&b, "machine", 20, None),
        ];
        let r = req(RuntimeClass::Machine, 2);
        let nodes = sched
            .select_and_lease(&r, &cands, 1_000, DEFAULT_LEASE_MS)
            .unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0], a); // cheaper first
        assert_eq!(sched.leases_for("app1").len(), 2);
        assert_eq!(sched.meter("app1", &a, 42), Some(42));
        assert_eq!(sched.meter("app1", &a, 8), Some(50));
        // Ingress table now routes app1 to both nodes.
        let placement = ingress.get_placement("app1").unwrap();
        assert_eq!(placement.serving_nodes.len(), 2);
    }

    #[test]
    fn failover_replaces_dead_node() {
        let ingress = Arc::new(IngressTable::new());
        let sched = PlacementScheduler::new(ingress.clone());
        let a = "1".repeat(64);
        let b = "2".repeat(64);
        let c = "3".repeat(64);
        let r = req(RuntimeClass::Machine, 2);
        // Initial: lease a + b.
        let initial = vec![
            candidate(&a, "machine", 10, None),
            candidate(&b, "machine", 20, None),
        ];
        sched
            .select_and_lease(&r, &initial, 1_000, DEFAULT_LEASE_MS)
            .unwrap();
        // a dies; candidate pool now has b (surviving) + c (fresh).
        let survivors = vec![
            candidate(&b, "machine", 20, None),
            candidate(&c, "machine", 15, None),
        ];
        let serving = sched
            .handle_liveness_loss("app1", &a, &r, &survivors, 2_000, DEFAULT_LEASE_MS)
            .unwrap();
        assert_eq!(serving.len(), 2);
        assert!(serving.contains(&b));
        assert!(serving.contains(&c));
        assert!(!serving.contains(&a));
    }

    #[test]
    fn sweep_drops_expired() {
        let ingress = Arc::new(IngressTable::new());
        let sched = PlacementScheduler::new(ingress.clone());
        let a = "1".repeat(64);
        let cands = vec![candidate(&a, "static", 10, None)];
        let r = req(RuntimeClass::Static, 1);
        sched.select_and_lease(&r, &cands, 1_000, 500).unwrap();
        assert_eq!(sched.all_leases().len(), 1);
        // now past expiry (1_000 + 500 = 1_500).
        assert_eq!(sched.sweep_expired(2_000), 1);
        assert_eq!(sched.all_leases().len(), 0);
    }
}
