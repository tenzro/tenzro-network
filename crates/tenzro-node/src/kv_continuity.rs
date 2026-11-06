//! Continuity for inference sessions: the KV cache follows the session.
//!
//! A chat request that names a `session` with a continuity level above `none`
//! is served from a session whose KV cache persists across turns (see
//! [`tenzro_model::SequenceEngine`]). When the session starts, the serving node
//! also assigns it a successor ([`crate::continuity::pick_successors`]): a node
//! that serves or stages the model, whose declared jurisdiction satisfies the
//! session's pin, in a different failure domain. Nodes holding the model on
//! standby ([`crate::standby`]) are preferred. After a turn (`hot_successor`) or once the level's
//! interval has passed (`standby`), and never more often than the node's
//! checkpoint interval, the serving node exports the positions the
//! session appended, seals them under a fresh data key wrapped to the
//! successor's sealing key, and sends them over `tenzro/kv-checkpoint`.
//!
//! The successor holds the sealed chain. A request for the session that
//! reaches it (routing sends it there once the serving provider is marked
//! down) opens the chain, rebuilds the session's cache without prefill, and
//! serves the turn; the successor is then the session's primary and assigns a
//! successor of its own. A successor refuses an assignment for other weights
//! or outside its jurisdiction, and a delta from a node that is not the
//! session's primary. If the successor stops announcing, a new one is
//! assigned and the chain restarts from position 0 on it.
//!
//! A successor that charges for standby holds a session only against a
//! funded escrow in consensus state: the payer opens a stream escrow to the
//! successor's account whose reference is [`standby_digest`] of the session
//! id, at a rate covering the successor's hourly fee and an amount covering it
//! to the escrow's expiry, and names the escrow in the request's `session`.
//! The successor claims the stream as it accrues and the payer may stop it at
//! any time; this node keeps no charge book.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_crypto::encryption::{EncryptedEnvelope, SymmetricKey};
use tenzro_crypto::hybrid_seal::{HybridPublicKey, HybridRecipient};
use tenzro_iroh::{EndpointId, Reply, RequestHandler};
use tenzro_model::{ChatMessage, GenerationConfig, SequenceEngine};
use tracing::{debug, info, warn};

use crate::continuity::{
    ContinuityError, ContinuityLevel, FailureDomain, NodeCandidate, open_stream, pick_successors,
    seal_stream, unwrap_data_key, wrap_data_key,
};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// How often the serving node flushes due deltas and checks its successors.
const TICK_SECS: u64 = 10;
/// A session with no turn for this long is closed and its successor released.
const SESSION_IDLE_MS: u64 = 3_600_000;
/// How long one exchange with a successor may take.
const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What a continuity session is: which weights, how much continuity, where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpec {
    pub session_id: String,
    pub model_id: String,
    /// Fingerprint (SHA-256 hex) of the weights the session's cache was built
    /// with. A successor serving other weights refuses the session.
    pub fingerprint: String,
    pub level: ContinuityLevel,
    /// The jurisdiction pin the session, its successor and every delta stay in.
    pub jurisdiction: String,
    /// The account the session's turns bill to.
    pub payer: Option<String>,
    /// The escrow (hex id) that funds the successor's standby.
    #[serde(default)]
    pub standby_escrow: Option<String>,
}

/// The reference a session's standby escrow carries: SHA-256 of its id.
pub fn standby_digest(session_id: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(session_id.as_bytes()).into()
}

/// Reads an escrow from consensus state by id.
pub type EscrowReader =
    Arc<dyn Fn(&[u8; 32]) -> Option<tenzro_settlement::EscrowAccount> + Send + Sync>;

/// The successor designated for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvAssignment {
    pub spec: SessionSpec,
    pub primary: FailureDomain,
    pub successor: FailureDomain,
    /// The successor's sealing key (hex); delta data keys are wrapped to it.
    pub successor_sealing_key: String,
    pub assigned_at_ms: u64,
}

/// One sealed KV-cache delta, addressed to the session's successor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvDelta {
    pub session_id: String,
    /// Which chain of the session it extends.
    pub chain: u32,
    /// Position of the delta in its chain.
    pub seq: u64,
    /// The sealed blob, hex.
    pub sealed: String,
    /// SHA-256 hex of the plaintext blob, checked after opening.
    pub sha256: String,
    /// The data key wrapped to the successor.
    pub wrapped_key: EncryptedEnvelope,
}

/// A request on `tenzro/kv-checkpoint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KvRequest {
    Assign { assignment: Box<KvAssignment> },
    Offer { delta: Box<KvDelta> },
    Release { session_id: String },
}

/// A successor's acceptance of an assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvAccepted {
    pub sealing_key: String,
    pub jurisdiction: tenzro_types::JurisdictionClaim,
}

/// A session this node serves.
#[derive(Debug, Clone)]
struct Served {
    spec: SessionSpec,
    assignment: Option<KvAssignment>,
    chain: u32,
    next_seq: u64,
    last_export_ms: u64,
    last_turn_ms: u64,
    /// Turns ran since the last export.
    dirty: bool,
}

/// A session this node holds as successor.
#[derive(Debug, Clone)]
pub struct Held {
    pub assignment: KvAssignment,
    pub chain: u32,
    pub deltas: Vec<KvDelta>,
}

/// Where a session is served, as a node routing to it last saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRoute {
    /// The serving provider's payee address.
    pub primary: String,
    /// The successor's payee address, once one is assigned.
    pub successor: Option<String>,
}

/// Session continuity on one node: the sessions it serves, the chains it
/// holds as a successor, and where sessions it routes are served.
pub struct KvContinuity {
    engine: Arc<dyn SequenceEngine>,
    endpoint_id: String,
    jurisdiction: Option<tenzro_types::JurisdictionClaim>,
    sealing_key: HybridPublicKey,
    data_dir: PathBuf,
    standby_fee_per_hour: u128,
    served: DashMap<String, Served>,
    held: DashMap<String, Held>,
    routes: DashMap<String, SessionRoute>,
    /// This node's account and a reader of consensus state, against which a
    /// charged standby is checked for a funded escrow.
    funding: Option<(String, EscrowReader)>,
    /// Least time between two exports of one session, in milliseconds.
    checkpoint_interval_ms: u64,
}

impl std::fmt::Debug for KvContinuity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvContinuity")
            .field("endpoint_id", &self.endpoint_id)
            .field("served", &self.served.len())
            .field("held", &self.held.len())
            .finish()
    }
}

/// The successors a session may have, best first: live nodes holding the
/// model on standby, then live nodes serving it.
fn session_candidates(node: &TenzroNode, model_id: &str) -> Vec<NodeCandidate> {
    let now = std::time::Instant::now();
    let providers = node.network_providers_snapshot();
    let live: Vec<_> = providers
        .iter()
        .filter(|e| {
            now.duration_since(e.last_seen)
                < std::time::Duration::from_secs(e.announcement.ttl_secs)
        })
        .map(|e| &e.announcement)
        .filter(|ann| !ann.iroh_endpoint_id.is_empty())
        .collect();
    let standby = live
        .iter()
        .filter(|ann| ann.capacity.standby_models.iter().any(|m| m == model_id));
    let serving = live.iter().filter(|ann| {
        ann.served_models.iter().any(|m| m == model_id)
            && !ann.capacity.standby_models.iter().any(|m| m == model_id)
    });
    standby
        .chain(serving)
        .map(|ann| NodeCandidate::of(ann))
        .collect()
}

impl KvContinuity {
    pub fn new(
        engine: Arc<dyn SequenceEngine>,
        endpoint_id: String,
        jurisdiction: Option<tenzro_types::JurisdictionClaim>,
        sealing_key: HybridPublicKey,
        data_dir: PathBuf,
        standby_fee_per_hour: u128,
    ) -> Self {
        Self {
            engine,
            endpoint_id,
            jurisdiction,
            sealing_key,
            data_dir,
            standby_fee_per_hour,
            served: DashMap::new(),
            held: DashMap::new(),
            routes: DashMap::new(),
            funding: None,
            checkpoint_interval_ms: 0,
        }
    }

    /// Export a session at most once per `interval`.
    pub fn with_checkpoint_interval(mut self, interval: std::time::Duration) -> Self {
        self.checkpoint_interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        self
    }

    /// Whether `served` may be exported now: it ran a turn since its last
    /// export, and the level's interval (never shorter than the checkpoint
    /// interval) has passed.
    fn export_due(&self, served: &Served, now: u64) -> bool {
        let level_ms = match served.spec.level {
            ContinuityLevel::HotSuccessor => 0,
            level => level.default_interval_secs() * 1000,
        };
        served.dirty
            && now.saturating_sub(served.last_export_ms)
                >= level_ms.max(self.checkpoint_interval_ms)
    }

    /// Check charged standby against escrows paying `payee`, read through
    /// `reader`.
    pub fn with_funding(mut self, payee: String, reader: EscrowReader) -> Self {
        self.funding = Some((payee, reader));
        self
    }

    /// Refuse a charged standby unless the session names a funded stream
    /// escrow paying this node's account, referencing this session, at a rate
    /// covering the hourly fee and an amount covering it to the expiry.
    fn check_funded(&self, spec: &SessionSpec) -> Result<(), ContinuityError> {
        if self.standby_fee_per_hour == 0 {
            return Ok(());
        }
        let refuse = |why: &str| {
            Err(ContinuityError::Refused(format!(
                "standby not funded: {why}"
            )))
        };
        let Some((payee, read)) = &self.funding else {
            return refuse("this node reads no chain state");
        };
        let Some(id) = spec
            .standby_escrow
            .as_deref()
            .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return refuse("the session names no standby escrow");
        };
        let Some(escrow) = read(&id) else {
            return refuse("no such escrow");
        };
        if escrow.status != tenzro_settlement::EscrowStatus::Funded {
            return refuse("the escrow is not funded");
        }
        if !hex::encode(escrow.payee.as_bytes())
            .eq_ignore_ascii_case(payee.trim_start_matches("0x"))
        {
            return refuse("the escrow pays another account");
        }
        if escrow.reference != Some(standby_digest(&spec.session_id)) {
            return refuse("the escrow is not this session's standby");
        }
        let tenzro_types::settlement::ReleaseConditions::Stream {
            rate_per_epoch,
            epoch_ms,
        } = escrow.release_conditions
        else {
            return refuse("a standby is paid by a stream escrow");
        };
        let per_hour = rate_per_epoch.saturating_mul(3_600_000) / u128::from(epoch_ms.max(1));
        if per_hour < self.standby_fee_per_hour {
            return refuse("the stream pays less than the standby fee");
        }
        let now = now_ms();
        let expires = u64::try_from(escrow.expires_at.0).unwrap_or(0);
        let hours = expires.saturating_sub(now).div_ceil(3_600_000);
        if hours == 0 {
            return refuse("the escrow has expired");
        }
        let left = escrow.amount.saturating_sub(escrow.claimed);
        if left < self.standby_fee_per_hour.saturating_mul(hours as u128) {
            return refuse("the escrow does not cover the standby fee to its expiry");
        }
        Ok(())
    }

    /// The chain this node holds for `session_id`, if it is its successor.
    pub fn held(&self, session_id: &str) -> Option<Held> {
        self.held.get(session_id).map(|h| h.clone())
    }

    /// Whether this node serves or holds `session_id`.
    pub fn knows(&self, session_id: &str) -> bool {
        self.served.contains_key(session_id) || self.held.contains_key(session_id)
    }

    // -- successor side -----------------------------------------------------

    /// Accept designation as `assignment`'s successor, sent by `remote`.
    pub fn accept_assign(
        &self,
        remote: &str,
        assignment: KvAssignment,
    ) -> Result<KvAccepted, ContinuityError> {
        if assignment.successor.endpoint_id != self.endpoint_id {
            return Err(ContinuityError::NotDesignated);
        }
        if assignment.primary.endpoint_id != remote {
            return Err(ContinuityError::WrongPrimary);
        }
        let pin = &assignment.spec.jurisdiction;
        let claim = self
            .jurisdiction
            .clone()
            .filter(|c| c.matches(pin))
            .ok_or_else(|| ContinuityError::OutsideJurisdiction(pin.clone()))?;
        let ours = self
            .engine
            .fingerprint(&assignment.spec.model_id)
            .map_err(|e| ContinuityError::Refused(format!("model not held here: {e}")))?;
        if ours.to_hex() != assignment.spec.fingerprint {
            return Err(ContinuityError::Refused(format!(
                "session built with weights {}, this node holds {}",
                assignment.spec.fingerprint,
                ours.to_hex()
            )));
        }
        self.check_funded(&assignment.spec)?;
        let session_id = assignment.spec.session_id.clone();
        self.held.insert(
            session_id.clone(),
            Held {
                assignment,
                chain: 0,
                deltas: Vec::new(),
            },
        );
        info!(session = %session_id, "session successor assignment accepted");
        Ok(KvAccepted {
            sealing_key: hex::encode(self.sealing_key.encode()),
            jurisdiction: claim,
        })
    }

    /// Hold one delta of a session this node succeeds.
    pub fn accept_offer(&self, remote: &str, delta: KvDelta) -> Result<(), ContinuityError> {
        let mut held = self
            .held
            .get_mut(&delta.session_id)
            .ok_or_else(|| ContinuityError::NotHeld(delta.session_id.clone()))?;
        if held.assignment.primary.endpoint_id != remote {
            return Err(ContinuityError::WrongPrimary);
        }
        if delta.chain < held.chain {
            return Err(ContinuityError::OutOfOrder(format!(
                "chain {} is older than the held chain {}",
                delta.chain, held.chain
            )));
        }
        if delta.chain > held.chain {
            held.chain = delta.chain;
            held.deltas.clear();
        }
        if delta.seq != held.deltas.len() as u64 {
            return Err(ContinuityError::OutOfOrder(format!(
                "delta {} after {} held",
                delta.seq,
                held.deltas.len()
            )));
        }
        held.deltas.push(delta);
        Ok(())
    }

    /// Drop a session its primary released.
    pub fn accept_release(&self, remote: &str, session_id: &str) -> Result<(), ContinuityError> {
        let primary = self
            .held
            .get(session_id)
            .map(|h| h.assignment.primary.endpoint_id.clone())
            .ok_or_else(|| ContinuityError::NotHeld(session_id.to_string()))?;
        if primary != remote {
            return Err(ContinuityError::WrongPrimary);
        }
        self.held.remove(session_id);
        Ok(())
    }

    /// Open every delta of a held chain, in order.
    pub fn open_chain(
        held: &Held,
        recipient: &dyn HybridRecipient,
    ) -> Result<Vec<Vec<u8>>, ContinuityError> {
        held.deltas
            .iter()
            .map(|d| {
                let key = unwrap_data_key(recipient, &d.wrapped_key)?;
                let sealed = hex::decode(&d.sealed)
                    .map_err(|e| ContinuityError::Seal(format!("delta {}: {e}", d.seq)))?;
                let mut plain = Vec::new();
                open_stream(&sealed[..], &mut plain, &key, &d.sha256)?;
                Ok(plain)
            })
            .collect()
    }

    /// Rebuild a held session on this node's engine and serve it from here.
    /// Blocks on the engine.
    pub fn take_over(
        &self,
        session_id: &str,
        recipient: &dyn HybridRecipient,
    ) -> Result<SessionSpec, ContinuityError> {
        let held = self
            .held(session_id)
            .ok_or_else(|| ContinuityError::NotHeld(session_id.to_string()))?;
        let chain = Self::open_chain(&held, recipient)?;
        let spec = held.assignment.spec.clone();
        let rebuilt = self
            .engine
            .import_chain(&spec.model_id, session_id, &chain)
            .map_err(|e| ContinuityError::Refused(e.to_string()))?;
        self.held.remove(session_id);
        self.served.insert(
            session_id.to_string(),
            Served {
                spec: spec.clone(),
                assignment: None,
                chain: 0,
                next_seq: 0,
                last_export_ms: 0,
                last_turn_ms: now_ms(),
                dirty: true,
            },
        );
        info!(session = %session_id, positions = rebuilt, "session taken over from its KV chain");
        Ok(spec)
    }

    // -- primary side -------------------------------------------------------

    /// Export what `session_id` appended and seal it to its successor.
    /// Blocks on the engine.
    pub fn next_delta(
        &self,
        session_id: &str,
    ) -> Result<Option<(KvAssignment, KvDelta)>, ContinuityError> {
        let Some(mut served) = self.served.get_mut(session_id) else {
            return Err(ContinuityError::NotHeld(session_id.to_string()));
        };
        let Some(assignment) = served.assignment.clone() else {
            return Ok(None);
        };
        let Some(exported) = self
            .engine
            .export_delta(session_id)
            .map_err(|e| ContinuityError::Refused(e.to_string()))?
        else {
            served.dirty = false;
            return Ok(None);
        };
        if exported.chain != served.chain {
            served.chain = exported.chain;
            served.next_seq = 0;
        }
        let recipient = hex::decode(&assignment.successor_sealing_key)
            .ok()
            .and_then(|b| HybridPublicKey::decode(&b))
            .ok_or_else(|| ContinuityError::Seal("successor key malformed".into()))?;
        let key = SymmetricKey::generate();
        let mut sealed = Vec::new();
        let sha256 = seal_stream(&exported.blob[..], &mut sealed, &key)?;
        let delta = KvDelta {
            session_id: session_id.to_string(),
            chain: served.chain,
            seq: served.next_seq,
            sealed: hex::encode(sealed),
            sha256,
            wrapped_key: wrap_data_key(&key, &recipient)?,
        };
        served.next_seq += 1;
        served.last_export_ms = now_ms();
        served.dirty = false;
        Ok(Some((assignment, delta)))
    }

    /// Record the route a session request was served on.
    pub fn observe_route(&self, session_id: &str, route: SessionRoute) {
        self.routes.insert(session_id.to_string(), route);
    }

    /// The payee to pin a session request to: the successor when the serving
    /// provider is marked down, otherwise the serving provider.
    pub fn route_for(&self, session_id: &str, is_down: impl Fn(&str) -> bool) -> Option<String> {
        let route = self.routes.get(session_id)?;
        if is_down(&route.primary) {
            return route.successor.clone();
        }
        Some(route.primary.clone())
    }
}

#[async_trait::async_trait]
impl RequestHandler for KvContinuity {
    async fn handle(&self, remote: EndpointId, request: bytes::Bytes) -> Reply {
        let request = match serde_json::from_slice::<KvRequest>(&request) {
            Ok(r) => r,
            Err(e) => return Reply::full(400, format!("undecodable request: {e}")),
        };
        let remote = remote.to_string();
        let result = match request {
            KvRequest::Assign { assignment } => {
                self.accept_assign(&remote, *assignment).and_then(|a| {
                    serde_json::to_vec(&a).map_err(|e| ContinuityError::Transport(e.to_string()))
                })
            }
            KvRequest::Offer { delta } => {
                self.accept_offer(&remote, *delta).map(|()| b"{}".to_vec())
            }
            KvRequest::Release { session_id } => self
                .accept_release(&remote, &session_id)
                .map(|()| b"{}".to_vec()),
        };
        match result {
            Ok(body) => Reply::full(200, body),
            Err(e) => {
                debug!(peer = %remote, error = %e, "kv-checkpoint request refused");
                Reply::full(403, e.to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transport and assignment
// ---------------------------------------------------------------------------

async fn call(
    node: &TenzroNode,
    endpoint_id: &str,
    request: &KvRequest,
) -> Result<bytes::Bytes, ContinuityError> {
    let resolver = node
        .iroh_resolver()
        .ok_or_else(|| ContinuityError::Transport("this node has no transport endpoint".into()))?;
    let peer: EndpointId = endpoint_id
        .parse()
        .map_err(|e| ContinuityError::Transport(format!("endpoint {endpoint_id}: {e}")))?;
    let body =
        serde_json::to_vec(request).map_err(|e| ContinuityError::Transport(e.to_string()))?;
    let exchange = async {
        let response = tenzro_iroh::request(
            resolver.endpoint(),
            peer,
            tenzro_iroh::ALPN_KV_CHECKPOINT,
            &body,
        )
        .await?;
        let ok = response.is_success();
        let bytes = response
            .bytes(tenzro_iroh::MAX_KV_CHECKPOINT_REQUEST)
            .await?;
        Ok::<_, tenzro_iroh::IrohError>((ok, bytes))
    };
    let (ok, bytes) = tokio::time::timeout(PEER_TIMEOUT, exchange)
        .await
        .map_err(|_| ContinuityError::Transport("timed out".into()))?
        .map_err(|e| ContinuityError::Transport(e.to_string()))?;
    if !ok {
        return Err(ContinuityError::Refused(
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    Ok(bytes)
}

/// Assign `spec` a successor, trying eligible nodes best first until one
/// accepts with a compliant jurisdiction, and record it.
async fn assign(
    node: &TenzroNode,
    kv: &KvContinuity,
    spec: &SessionSpec,
    exclude: &[&str],
) -> Result<KvAssignment, ContinuityError> {
    let primary = crate::continuity::local_domain(node)
        .ok_or_else(|| ContinuityError::Transport("this node has no transport endpoint".into()))?;
    let candidates = session_candidates(node, &spec.model_id);
    let eligible = pick_successors(&spec.jurisdiction, &primary, &candidates, exclude)?;
    let mut last_error = ContinuityError::NoSuccessor(spec.jurisdiction.clone());
    // A funded standby names its successor through the escrow's payee, so
    // every eligible node is asked until the paid one accepts.
    let tries = if spec.standby_escrow.is_some() {
        eligible.len()
    } else {
        3
    };
    for candidate in eligible.iter().take(tries) {
        let mut assignment = KvAssignment {
            spec: spec.clone(),
            primary: primary.clone(),
            successor: FailureDomain::of(candidate),
            successor_sealing_key: String::new(),
            assigned_at_ms: now_ms(),
        };
        let request = KvRequest::Assign {
            assignment: Box::new(assignment.clone()),
        };
        let accepted = match call(node, &candidate.endpoint_id, &request)
            .await
            .and_then(|b| {
                serde_json::from_slice::<KvAccepted>(&b)
                    .map_err(|e| ContinuityError::Transport(e.to_string()))
            }) {
            Ok(a) => a,
            Err(e) => {
                debug!(successor = %candidate.endpoint_id, error = %e, "session successor declined");
                last_error = e;
                continue;
            }
        };
        if !accepted.jurisdiction.matches(&spec.jurisdiction) {
            last_error = ContinuityError::OutsideJurisdiction(spec.jurisdiction.clone());
            continue;
        }
        assignment.successor_sealing_key = accepted.sealing_key;
        if let Some(mut served) = kv.served.get_mut(&spec.session_id) {
            served.assignment = Some(assignment.clone());
            served.next_seq = 0;
        }
        info!(session = %spec.session_id, successor = %assignment.successor.endpoint_id, "session successor assigned");
        return Ok(assignment);
    }
    Err(last_error)
}

/// Export and send `session_id`'s pending delta. A successor that refuses or
/// cannot be reached is replaced, and the chain restarts on the new one.
async fn flush(node: &Arc<TenzroNode>, kv: &Arc<KvContinuity>, session_id: &str) {
    let job = {
        let kv = kv.clone();
        let id = session_id.to_string();
        tokio::task::spawn_blocking(move || kv.next_delta(&id)).await
    };
    let (assignment, delta) = match job {
        Ok(Ok(Some(pair))) => pair,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => return warn!(session = %session_id, error = %e, "session export failed"),
        Err(e) => return warn!(session = %session_id, error = %e, "session export panicked"),
    };
    let request = KvRequest::Offer {
        delta: Box::new(delta),
    };
    if let Err(e) = call(node, &assignment.successor.endpoint_id, &request).await {
        warn!(session = %session_id, successor = %assignment.successor.endpoint_id, error = %e,
            "session delta not accepted; assigning a new successor");
        reassign(node, kv, &assignment).await;
    }
}

/// Replace a session's successor, excluding the one that failed, and restart
/// its chain so the new successor receives the whole cache.
async fn reassign(node: &Arc<TenzroNode>, kv: &Arc<KvContinuity>, failed: &KvAssignment) {
    let id = failed.spec.session_id.clone();
    release(node, failed).await;
    if let Some(mut served) = kv.served.get_mut(&id) {
        served.assignment = None;
        served.dirty = true;
    }
    match assign(
        node,
        kv,
        &failed.spec,
        &[failed.successor.endpoint_id.as_str()],
    )
    .await
    {
        Ok(_) => {
            if let Err(e) = kv.engine.restart_export(&id) {
                warn!(session = %id, error = %e, "session chain restart failed");
            }
        }
        Err(e) => {
            warn!(session = %id, error = %e, "no replacement successor; session runs without one")
        }
    }
}

/// Tell a successor to drop what it holds of a session. Best effort: a
/// successor only acts on a session when requests for it are routed there.
async fn release(node: &TenzroNode, assignment: &KvAssignment) {
    let request = KvRequest::Release {
        session_id: assignment.spec.session_id.clone(),
    };
    if let Err(e) = call(node, &assignment.successor.endpoint_id, &request).await {
        debug!(session = %assignment.spec.session_id, error = %e, "session release not delivered");
    }
}

/// Flush sessions whose interval has passed, replace successors that stopped
/// announcing, and close sessions left idle.
async fn tick(node: &Arc<TenzroNode>, kv: &Arc<KvContinuity>) {
    let live: std::collections::HashSet<String> = node
        .network_providers_snapshot()
        .into_iter()
        .map(|e| e.announcement.iroh_endpoint_id)
        .collect();
    let now = now_ms();
    let sessions: Vec<Served> = kv.served.iter().map(|s| s.clone()).collect();
    for served in sessions {
        let id = served.spec.session_id.clone();
        if now.saturating_sub(served.last_turn_ms) >= SESSION_IDLE_MS {
            kv.served.remove(&id);
            kv.engine.close_session(&id);
            if let Some(a) = &served.assignment {
                release(node, a).await;
            }
            info!(session = %id, "idle session closed");
            continue;
        }
        match &served.assignment {
            Some(a) if !live.contains(&a.successor.endpoint_id) => {
                warn!(session = %id, successor = %a.successor.endpoint_id, "session successor gone; assigning a new one");
                reassign(node, kv, a).await;
            }
            None => {
                if let Err(e) = assign(node, kv, &served.spec, &[]).await {
                    debug!(session = %id, error = %e, "session still without a successor");
                } else if let Err(e) = kv.engine.restart_export(&id) {
                    warn!(session = %id, error = %e, "session chain restart failed");
                }
            }
            Some(_) => {}
        }
        if kv.export_due(&served, now) {
            flush(node, kv, &id).await;
        }
    }
}

/// Serve `tenzro/kv-checkpoint` and run the delta and successor loop. Needs
/// the model runtime and the transport endpoint.
pub fn start(node: &Arc<TenzroNode>) {
    let (Some(runtime), Some(resolver)) = (node.model_runtime_arc(), node.iroh_resolver()) else {
        return;
    };
    let sealing_key = match node.machine_sealing_public_key() {
        Ok(k) => k,
        Err(e) => return warn!("session continuity off: no sealing key ({e})"),
    };
    let mut kv = KvContinuity::new(
        runtime as Arc<dyn SequenceEngine>,
        resolver.endpoint_id().to_string(),
        node.jurisdiction_claim().cloned(),
        sealing_key,
        node.config().data_dir.clone(),
        node.config().standby.fee_per_hour,
    )
    .with_checkpoint_interval(std::time::Duration::from_secs(
        node.config().session_checkpoint_interval_secs,
    ));
    match node.payee_hex() {
        Some(payee) => {
            let chain = node.clone();
            let reader: EscrowReader = Arc::new(move |id: &[u8; 32]| {
                let state = crate::rpc::chain_state_of(&chain)?;
                tenzro_vm::native::read_escrow(&state, id)
            });
            kv = kv.with_funding(payee, reader);
        }
        None => warn!("session continuity: no payee, charged standby refused"),
    }
    let kv = Arc::new(kv);
    resolver.kv_checkpoint_handler().set(kv.clone());
    if node.kv_continuity.set(kv.clone()).is_err() {
        return;
    }
    let weak = Arc::downgrade(node);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(TICK_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(node) = weak.upgrade() else { break };
            tick(&node, &kv).await;
        }
    });
    info!("session continuity: kv-checkpoint server and loop running");
}

// ---------------------------------------------------------------------------
// The chat surface
// ---------------------------------------------------------------------------

fn rpc_err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn continuity_rpc_err(e: ContinuityError) -> JsonRpcError {
    let code = match e {
        ContinuityError::OutsideJurisdiction(_) | ContinuityError::NoSuccessor(_) => -32024,
        _ => -32000,
    };
    rpc_err(code, format!("session continuity: {e}"))
}

/// The `session` object of a chat request: `{ id, continuity }`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionParams {
    pub id: String,
    pub continuity: ContinuityLevel,
    /// The escrow funding the successor's standby, hex.
    #[serde(default)]
    pub standby_escrow: Option<String>,
}

/// The session a chat request names, when it asks for continuity.
pub(crate) fn session_params(params: &Value) -> Result<Option<SessionParams>, JsonRpcError> {
    let Some(raw) = params.get("session") else {
        return Ok(None);
    };
    let session: SessionParams = serde_json::from_value(raw.clone())
        .map_err(|e| rpc_err(-32602, format!("invalid 'session': {e}")))?;
    if session.id.is_empty() || session.id.len() > 128 {
        return Err(rpc_err(-32602, "session.id must be 1..=128 characters"));
    }
    Ok(session.continuity.needs_successor().then_some(session))
}

/// Whether this node answers the session itself rather than routing it: it
/// serves or holds the session, or serves the model and nothing pins the
/// request elsewhere.
pub(crate) fn serves_locally(node: &TenzroNode, params: &Value, session: &SessionParams) -> bool {
    let Some(kv) = node.kv_continuity() else {
        return false;
    };
    if kv.knows(&session.id) {
        return true;
    }
    let model = params
        .get("model_id")
        .or_else(|| params.get("model"))
        .and_then(|v| v.as_str());
    let pinned_elsewhere = params
        .get("provider")
        .and_then(|v| v.as_str())
        .is_some_and(|p| {
            node.payee_hex()
                .is_none_or(|own| !own.eq_ignore_ascii_case(p))
        });
    !pinned_elsewhere
        && model.is_some_and(|m| node.model_runtime.as_ref().is_some_and(|r| r.is_loaded(m)))
}

/// Pin a routed session request to where the session is served: the
/// successor once the serving provider is marked down.
pub(crate) fn pin_route(node: &TenzroNode, params: &mut Value, session: &SessionParams) {
    let Some(kv) = node.kv_continuity() else {
        return;
    };
    let is_down = |payee: &str| {
        let Some(pm) = node.provider_manager() else {
            return false;
        };
        tenzro_types::primitives::Address::from_hex(payee.trim_start_matches("0x"))
            .is_ok_and(|a| pm.liveness().is_down(&a))
    };
    if let Some(payee) = kv.route_for(&session.id, is_down)
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("provider".to_string(), Value::String(payee));
    }
}

/// Remember where a routed session was served, from the provider's answer.
pub(crate) fn observe(node: &TenzroNode, session: &SessionParams, result: &Value) {
    let Some(kv) = node.kv_continuity() else {
        return;
    };
    let Some(c) = result.get("continuity") else {
        return;
    };
    if let Ok(route) = serde_json::from_value::<SessionRoute>(c.clone()) {
        kv.observe_route(&session.id, route);
    }
}

/// Serve one turn of a continuity session on this node.
pub(crate) async fn handle_session_chat(
    node: &Arc<TenzroNode>,
    params: &Value,
    session: &SessionParams,
) -> Result<Value, JsonRpcError> {
    let kv = node
        .kv_continuity()
        .cloned()
        .ok_or_else(|| rpc_err(-32000, "session continuity is not running on this node"))?;
    let model_id = params
        .get("model_id")
        .or_else(|| params.get("model"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| rpc_err(-32602, "Missing 'model_id' (or 'model') parameter"))?
        .to_string();
    let messages: Vec<ChatMessage> = serde_json::from_value(
        params
            .get("messages")
            .cloned()
            .ok_or_else(|| rpc_err(-32602, "a session turn takes 'messages'"))?,
    )
    .map_err(|e| {
        rpc_err(
            -32602,
            format!("session 'messages' are {{role, content}} strings: {e}"),
        )
    })?;
    if messages.is_empty() || messages.len() > tenzro_types::validation::MAX_CHAT_MESSAGES {
        return Err(rpc_err(-32602, "'messages' length out of range"));
    }
    if messages
        .iter()
        .any(|m| m.content.len() > tenzro_types::validation::MAX_CHAT_MESSAGE_LEN)
    {
        return Err(rpc_err(-32602, "a message exceeds the content limit"));
    }
    let jurisdiction = params
        .get("jurisdiction")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| rpc_err(-32602, "a continuity session needs a 'jurisdiction'"))?
        .to_string();
    if !crate::rpc::local_claim_satisfies_pin(node, &jurisdiction) {
        return Err(continuity_rpc_err(ContinuityError::OutsideJurisdiction(
            jurisdiction,
        )));
    }
    // The account the session bills to is the payer of the payment the caller
    // signed, not a name it merely asserts.
    let caller = crate::ledger_payment::payment_param(params)?
        .map(|p| format!("0x{}", hex::encode(p.payer.as_bytes())));

    // A held session is taken over: its primary is gone and routing sent the
    // session here.
    if kv.held.contains_key(&session.id) {
        let held_model = kv
            .held
            .get(&session.id)
            .map(|h| h.assignment.spec.model_id.clone());
        if held_model.as_deref() != Some(model_id.as_str()) {
            return Err(rpc_err(-32602, "the session runs another model"));
        }
        if !node
            .model_runtime
            .as_ref()
            .is_some_and(|r| r.is_loaded(&model_id))
        {
            crate::rpc::handle_serve_model(node, Some(serde_json::json!({ "model_id": model_id })))
                .await?;
        }
        let recipient = crate::keygen::NodeKeys::open(&kv.data_dir)
            .map_err(|e| rpc_err(-32000, format!("session continuity: node keys: {e}")))?
            .machine_sealing()
            .map_err(|e| rpc_err(-32000, format!("session continuity: sealing key: {e}")))?;
        let (k, id) = (kv.clone(), session.id.clone());
        tokio::task::spawn_blocking(move || k.take_over(&id, &recipient))
            .await
            .map_err(|e| rpc_err(-32000, e.to_string()))?
            .map_err(continuity_rpc_err)?;
    }

    if !kv.served.contains_key(&session.id) {
        let fingerprint = {
            let (e, m) = (kv.engine.clone(), model_id.clone());
            tokio::task::spawn_blocking(move || e.fingerprint(&m))
                .await
                .map_err(|e| rpc_err(-32000, e.to_string()))?
                .map_err(|e| rpc_err(-32000, crate::rpc::sanitize_model_error(&e)))?
        };
        let spec = SessionSpec {
            session_id: session.id.clone(),
            model_id: model_id.clone(),
            fingerprint: fingerprint.to_hex(),
            level: session.continuity,
            jurisdiction: jurisdiction.clone(),
            payer: caller.clone(),
            standby_escrow: session.standby_escrow.clone(),
        };
        kv.served.insert(
            session.id.clone(),
            Served {
                spec,
                assignment: None,
                chain: 0,
                next_seq: 0,
                last_export_ms: 0,
                last_turn_ms: now_ms(),
                dirty: false,
            },
        );
    }
    let spec = kv
        .served
        .get(&session.id)
        .map(|s| s.spec.clone())
        .ok_or_else(|| rpc_err(-32000, "session vanished"))?;
    if spec.model_id != model_id || spec.jurisdiction != jurisdiction {
        return Err(rpc_err(
            -32602,
            "a session keeps its model and jurisdiction",
        ));
    }
    // Prepared, not reactive: the successor exists before the turn runs.
    if kv
        .served
        .get(&session.id)
        .is_some_and(|s| s.assignment.is_none())
    {
        match assign(node, &kv, &spec, &[]).await {
            Ok(_) => {
                if let Err(e) = kv.engine.restart_export(&session.id)
                    && kv.engine.has_session(&session.id)
                {
                    warn!(session = %session.id, error = %e, "session chain restart failed");
                }
            }
            Err(e) => {
                kv.served.remove(&session.id);
                return Err(continuity_rpc_err(e));
            }
        }
    }

    let mut config = GenerationConfig::default();
    if let Some(n) = params.get("max_tokens").and_then(|v| v.as_u64()) {
        config.max_tokens = u32::try_from(n)
            .ok()
            .filter(|n| u64::from(*n) <= tenzro_types::validation::MAX_INFERENCE_TOKENS)
            .ok_or_else(|| rpc_err(-32602, "max_tokens out of range"))?;
    }
    if let Some(t) = params.get("temperature").and_then(|v| v.as_f64()) {
        config.temperature = t;
    }
    let turn = {
        let (e, m, s) = (kv.engine.clone(), model_id.clone(), session.id.clone());
        tokio::task::spawn_blocking(move || e.turn(&m, &s, &messages, &config))
            .await
            .map_err(|e| rpc_err(-32000, e.to_string()))?
            .map_err(|e| rpc_err(-32000, crate::rpc::sanitize_model_error(&e)))?
    };
    node.metrics().record_inference();
    let units =
        tenzro_types::model::BillableUnits::tokens(turn.prompt_tokens, turn.completion_tokens);
    let cost_wei = crate::rpc::price_local_units(node, &model_id, &units)?;
    let settlement = crate::rpc::settle_inference_cost(
        node,
        params.get("payment"),
        params.get("channel_voucher"),
        None,
        &model_id,
        &units,
        cost_wei,
    )
    .await?;

    let (assignment, due) = kv
        .served
        .get_mut(&session.id)
        .map(|mut s| {
            s.dirty = true;
            s.last_turn_ms = now_ms();
            (s.assignment.clone(), kv.export_due(&s, now_ms()))
        })
        .unwrap_or((None, false));
    // Otherwise the loop exports it once the interval has passed.
    if session.continuity == ContinuityLevel::HotSuccessor && due {
        let (n, k, id) = (node.clone(), kv.clone(), session.id.clone());
        tokio::spawn(async move { flush(&n, &k, &id).await });
    }
    let payee = node
        .operator_payee()
        .map(|a| format!("0x{}", hex::encode(a.as_bytes())));
    Ok(serde_json::json!({
        "output": turn.text,
        "model_id": model_id,
        "input_tokens": turn.prompt_tokens,
        "output_tokens": turn.completion_tokens,
        "cached_tokens": turn.reused_tokens,
        "location": "local",
        "cost_wei": cost_wei.to_string(),
        "settlement": settlement.to_json(),
        "continuity": {
            "session_id": session.id,
            "level": session.continuity,
            "primary": payee,
            "successor": assignment.as_ref().and_then(|a| a.successor.operator.clone()),
            "successor_endpoint": assignment.as_ref().map(|a| a.successor.endpoint_id.clone()),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use tenzro_crypto::hybrid_seal::HybridSecretKey;
    use tenzro_model::{
        ExportedDelta, ImportChain, KvBlob, ModelError, ModelFingerprint, SessionTurn,
    };

    /// A sequence engine without a model: its "cache" is the token list, and
    /// export and import run the real blob format and chain rules.
    struct MockEngine {
        weights: ModelFingerprint,
        sessions: Mutex<HashMap<String, (Vec<i32>, u32, [u8; 32])>>,
        prefilled: Mutex<u32>,
    }

    impl MockEngine {
        fn new(weights: u8) -> Self {
            Self {
                weights: ModelFingerprint::from_digest([weights; 32]),
                sessions: Mutex::new(HashMap::new()),
                prefilled: Mutex::new(0),
            }
        }
    }

    impl SequenceEngine for MockEngine {
        fn fingerprint(&self, _model_id: &str) -> tenzro_model::Result<ModelFingerprint> {
            Ok(self.weights)
        }
        fn turn(
            &self,
            _model_id: &str,
            session: &str,
            messages: &[ChatMessage],
            _config: &GenerationConfig,
        ) -> tenzro_model::Result<SessionTurn> {
            let wanted: Vec<i32> = messages
                .iter()
                .flat_map(|m| m.content.bytes().map(i32::from))
                .collect();
            let mut sessions = self.sessions.lock();
            let (tokens, _, _) =
                sessions
                    .entry(session.to_string())
                    .or_insert((Vec::new(), 0, [0; 32]));
            let held = tokens
                .iter()
                .zip(&wanted)
                .take_while(|(a, b)| a == b)
                .count();
            *self.prefilled.lock() += (wanted.len() - held) as u32;
            tokens.truncate(held);
            tokens.extend_from_slice(&wanted[held..]);
            tokens.push(b'!' as i32);
            Ok(SessionTurn {
                text: "!".into(),
                prompt_tokens: wanted.len() as u32,
                reused_tokens: held as u32,
                completion_tokens: 1,
            })
        }
        fn export_delta(&self, session: &str) -> tenzro_model::Result<Option<ExportedDelta>> {
            let mut sessions = self.sessions.lock();
            let (tokens, exported, last) = sessions
                .get_mut(session)
                .ok_or_else(|| ModelError::InferenceError("no session".into()))?;
            let blob = KvBlob {
                model: self.weights,
                prev_digest: *last,
                base_pos: *exported,
                tokens: tokens[*exported as usize..].to_vec(),
                payload: vec![7; tokens.len() - *exported as usize],
            };
            let encoded = blob.encode();
            *last = KvBlob::digest_of(&encoded).unwrap();
            *exported = tokens.len() as u32;
            Ok(Some(ExportedDelta {
                chain: 0,
                blob: encoded,
            }))
        }
        fn restart_export(&self, session: &str) -> tenzro_model::Result<()> {
            if let Some((_, exported, last)) = self.sessions.lock().get_mut(session) {
                *exported = 0;
                *last = [0; 32];
            }
            Ok(())
        }
        fn import_chain(
            &self,
            _model_id: &str,
            session: &str,
            chain: &[Vec<u8>],
        ) -> tenzro_model::Result<u32> {
            let mut import = ImportChain::new(self.weights);
            let mut tokens = Vec::new();
            for encoded in chain {
                let blob = KvBlob::decode(encoded)
                    .map_err(|e| ModelError::InferenceError(e.to_string()))?;
                import
                    .check(&blob)
                    .map_err(|e| ModelError::InferenceError(e.to_string()))?;
                tokens.extend_from_slice(&blob.tokens);
                import.advance(&blob, KvBlob::digest_of(encoded).unwrap());
            }
            let n = import.next_pos();
            self.sessions
                .lock()
                .insert(session.to_string(), (tokens, 0, [0; 32]));
            Ok(n)
        }
        fn has_session(&self, session: &str) -> bool {
            self.sessions.lock().contains_key(session)
        }
        fn close_session(&self, session: &str) {
            self.sessions.lock().remove(session);
        }
    }

    fn claim(country: &str) -> tenzro_types::JurisdictionClaim {
        tenzro_types::JurisdictionClaim {
            country: country.into(),
            blocs: Vec::new(),
            attestation_hash: None,
            declared_at: tenzro_types::Timestamp(0),
        }
    }

    fn node(engine: MockEngine, id: &str, country: &str, key: HybridPublicKey) -> KvContinuity {
        KvContinuity::new(
            Arc::new(engine),
            id.into(),
            Some(claim(country)),
            key,
            PathBuf::new(),
            0,
        )
    }

    fn domain(id: &str, operator: &str) -> FailureDomain {
        FailureDomain {
            endpoint_id: id.into(),
            operator: Some(operator.into()),
            site: None,
        }
    }

    fn user(text: &str) -> ChatMessage {
        ChatMessage {
            role: "user".into(),
            content: text.into(),
            ..Default::default()
        }
    }

    fn spec(weights: &ModelFingerprint) -> SessionSpec {
        SessionSpec {
            session_id: "s1".into(),
            model_id: "m".into(),
            fingerprint: weights.to_hex(),
            level: ContinuityLevel::HotSuccessor,
            jurisdiction: "DE".into(),
            payer: None,
            standby_escrow: None,
        }
    }

    #[test]
    fn a_kv_delta_chain_resumes_on_the_successor_without_prefill() {
        let successor_keys = HybridSecretKey::generate();
        let primary = node(
            MockEngine::new(1),
            "p",
            "DE",
            HybridSecretKey::generate().public().clone(),
        );
        let successor = node(
            MockEngine::new(1),
            "s",
            "DE",
            successor_keys.public().clone(),
        );
        let weights = ModelFingerprint::from_digest([1; 32]);

        let accepted = successor
            .accept_assign(
                "p",
                KvAssignment {
                    spec: spec(&weights),
                    primary: domain("p", "0xa"),
                    successor: domain("s", "0xb"),
                    successor_sealing_key: String::new(),
                    assigned_at_ms: 0,
                },
            )
            .expect("successor accepts");
        primary.served.insert(
            "s1".into(),
            Served {
                spec: spec(&weights),
                assignment: Some(KvAssignment {
                    spec: spec(&weights),
                    primary: domain("p", "0xa"),
                    successor: domain("s", "0xb"),
                    successor_sealing_key: accepted.sealing_key,
                    assigned_at_ms: 0,
                }),
                chain: 0,
                next_seq: 0,
                last_export_ms: 0,
                last_turn_ms: 0,
                dirty: false,
            },
        );

        // Two turns on the primary, each shipped as a delta.
        let config = GenerationConfig::default();
        primary
            .engine
            .turn("m", "s1", &[user("hello")], &config)
            .unwrap();
        let (_, d0) = primary.next_delta("s1").unwrap().unwrap();
        primary
            .engine
            .turn("m", "s1", &[user("hello!"), user("more")], &config)
            .unwrap();
        let (_, d1) = primary.next_delta("s1").unwrap().unwrap();
        assert_eq!((d0.seq, d1.seq), (0, 1));
        // Only the primary may extend the chain, in order.
        assert!(successor.accept_offer("x", d0.clone()).is_err());
        assert!(successor.accept_offer("p", d1.clone()).is_err());
        successor.accept_offer("p", d0).unwrap();
        successor.accept_offer("p", d1).unwrap();

        // The primary is gone: the successor rebuilds and continues.
        successor
            .take_over("s1", &successor_keys)
            .expect("take over");
        assert!(successor.served.contains_key("s1") && successor.held("s1").is_none());
        let turn = successor
            .engine
            .turn("m", "s1", &[user("hello!more!"), user("next")], &config)
            .unwrap();
        assert_eq!(
            turn.reused_tokens,
            "hello!more!".len() as u32,
            "history came from the chain"
        );
    }

    #[test]
    fn a_successor_with_other_weights_refuses_the_session() {
        let successor = node(
            MockEngine::new(2),
            "s",
            "DE",
            HybridSecretKey::generate().public().clone(),
        );
        let weights = ModelFingerprint::from_digest([1; 32]);
        let assignment = KvAssignment {
            spec: spec(&weights),
            primary: domain("p", "0xa"),
            successor: domain("s", "0xb"),
            successor_sealing_key: String::new(),
            assigned_at_ms: 0,
        };
        let err = successor
            .accept_assign("p", assignment.clone())
            .unwrap_err();
        assert!(err.to_string().contains("weights"), "{err}");

        // And a chain made with other weights is refused at import.
        let other = MockEngine::new(2);
        let blob = KvBlob {
            model: weights,
            prev_digest: [0; 32],
            base_pos: 0,
            tokens: vec![1, 2],
            payload: vec![0; 2],
        };
        assert!(other.import_chain("m", "s1", &[blob.encode()]).is_err());

        // Outside the successor's jurisdiction is refused too.
        let french = node(
            MockEngine::new(1),
            "s",
            "FR",
            HybridSecretKey::generate().public().clone(),
        );
        assert!(matches!(
            french.accept_assign("p", assignment),
            Err(ContinuityError::OutsideJurisdiction(_))
        ));
    }

    fn standby_escrow(
        payee: u8,
        rate_per_hour: u128,
        amount: u128,
        session: &str,
    ) -> tenzro_settlement::EscrowAccount {
        use tenzro_types::primitives::{Address, Timestamp};
        let mut e = tenzro_settlement::EscrowAccount::new(
            Address::new([1; 32]),
            Address::new([payee; 32]),
            amount,
            tenzro_types::AssetId::tnzo(),
            Timestamp::new((now_ms() + 2 * 3_600_000 - 1) as i64),
            tenzro_types::settlement::ReleaseConditions::Stream {
                rate_per_epoch: rate_per_hour,
                epoch_ms: 3_600_000,
            },
        );
        e.reference = Some(standby_digest(session));
        e
    }

    #[test]
    fn a_charged_standby_is_held_only_against_a_funded_escrow() {
        let keys = HybridSecretKey::generate();
        let escrows: std::collections::HashMap<[u8; 32], tenzro_settlement::EscrowAccount> = [
            ([1; 32], standby_escrow(0xb, 100, 200, "s1")),
            ([2; 32], standby_escrow(0xb, 100, 199, "s1")),
            ([3; 32], standby_escrow(0xc, 100, 200, "s1")),
            ([4; 32], standby_escrow(0xb, 100, 200, "s2")),
            ([5; 32], standby_escrow(0xb, 99, 200, "s1")),
        ]
        .into();
        let successor = KvContinuity::new(
            Arc::new(MockEngine::new(1)),
            "s".into(),
            Some(claim("DE")),
            keys.public().clone(),
            PathBuf::new(),
            100,
        )
        .with_funding(
            hex::encode([0xb; 32]),
            Arc::new(move |id: &[u8; 32]| escrows.get(id).cloned()),
        );
        let weights = ModelFingerprint::from_digest([1; 32]);
        let assign = |escrow: Option<u8>| {
            let mut session = spec(&weights);
            session.standby_escrow = escrow.map(|b| hex::encode([b; 32]));
            successor.accept_assign(
                "p",
                KvAssignment {
                    spec: session,
                    primary: domain("p", "0xa"),
                    successor: domain("s", "0xb"),
                    successor_sealing_key: String::new(),
                    assigned_at_ms: 0,
                },
            )
        };
        for refused in [None, Some(9), Some(2), Some(3), Some(4), Some(5)] {
            let err = assign(refused).unwrap_err();
            assert!(
                err.to_string().contains("standby not funded"),
                "{refused:?}: {err}"
            );
            assert!(successor.held("s1").is_none());
        }
        assign(Some(1)).expect("two hours at 100 per hour are funded");
        assert!(successor.held("s1").is_some());
    }

    #[test]
    fn routing_sends_a_session_to_its_successor_once_the_primary_is_down() {
        let kv = node(
            MockEngine::new(1),
            "g",
            "DE",
            HybridSecretKey::generate().public().clone(),
        );
        kv.observe_route(
            "s1",
            SessionRoute {
                primary: "0xa".into(),
                successor: Some("0xb".into()),
            },
        );
        assert_eq!(kv.route_for("s1", |_| false).as_deref(), Some("0xa"));
        assert_eq!(kv.route_for("s1", |p| p == "0xa").as_deref(), Some("0xb"));
        assert_eq!(kv.route_for("unknown", |_| true), None);
    }
}
