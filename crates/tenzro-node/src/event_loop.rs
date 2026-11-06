//! Node event loop that coordinates all subsystems
//!
//! This module wires together Network ↔ Consensus ↔ VM ↔ Storage into a working pipeline.
//! It handles events from the network and RPC, processes transactions, and finalizes blocks.
//!
//! # Transaction Pipeline
//!
//! 1. RPC/Network submits `NodeEvent::NewTransaction` via the event sender
//! 2. Event loop validates signature, gas limit, public key
//! 3. Validated transactions are forwarded to the consensus mempool
//! 4. On a validator, consensus cuts them into batches and orders them
//! 5. Each ordered segment arrives here; the event loop builds its block,
//!    executes it via the VM and reports the block hash and state root back
//! 6. State changes are committed to RocksDB with fsync
//!
//! A follower executes blocks received from validators only once a
//! checkpoint certificate covering them has been verified (see
//! [`crate::certified_import`]).

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, error, info, warn};

use tenzro_consensus::Certificate;
use tenzro_identity::IdentityRegistry;
use tenzro_iroh::IrohResolver;
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService};

use crate::consensus_driver::{ConsensusHandle, OrderedSegment};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{
    BlockStoreImpl, CF_MODEL_SERVICES, CF_MODELS, CF_TRANSACTIONS, KvStore, RocksDbStore, WriteOp,
};
use tenzro_types::block::Block;
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_types::transaction::{SignedTransaction, TransactionType};
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmTransaction, VmType};

use crate::error::{NodeError, Result};
use crate::metrics::MetricsCollector;

/// Static context needed to assemble periodic `ProviderAnnouncementMessage`
/// broadcasts from inside the event loop.
///
/// Snapshot semantics: `hardware`, `region`, `provider_address`,
/// `provider_type`, `capabilities` are captured once at node
/// startup. Per-tick we still re-read `served_models` from the live
/// `Arc<DashMap>` so additions / withdrawals propagate without a node restart.
#[derive(Clone, Debug)]
pub struct ProviderAnnouncementContext {
    /// `tenzro_types::HardwareCapabilities::detect()` evaluated once at startup.
    pub hardware: tenzro_types::HardwareCapabilities,
    /// Operator-declared coarse region (`NodeConfig::region`). `None` means
    /// "unknown" — receivers must NOT treat it as a wildcard.
    pub region: Option<String>,
    /// Provider wallet address (hex-encoded with `0x` prefix or empty if
    /// the node has no provisioned identity yet).
    pub provider_address: String,
    /// Provider class string (`"ai"`, `"tee"`, `"storage"`, `"general"`, ...).
    pub provider_type: String,
    /// Capability labels (e.g. `"inference"`, `"tee-attestation"`).
    pub capabilities: Vec<String>,
    /// TTL in seconds for each announcement record. Receivers evict entries
    /// whose `last_seen + ttl_secs < now`.
    pub ttl_secs: u64,
    /// Cluster membership held by this node, present only when it serves AI.
    /// Each announcement carries the cluster profile built from it, so a
    /// membership change reaches peers on the next heartbeat.
    pub cluster_identity: Option<std::sync::Arc<crate::cluster_identity::ClusterIdentity>>,
    /// Advertised serving throughput/concurrency envelope broadcast on each
    /// provider heartbeat. Captured from the node's `ProviderCapacity` at the
    /// point the announcement context is built.
    pub capacity: tenzro_types::AdvertisedCapacity,
    /// `(machine_did, operator_did)` when this node's operator opted in to
    /// serving delegated agents; `capabilities` then carries
    /// `agent_serving`.
    pub agent_serving: Option<(String, String)>,
}

/// The identity a node signs its gossip announcements as: its record signer
/// (a hardware batch of the machine identity key) and the machine DID that
/// key derives. Receivers verify against the key registered for the DID, so
/// both come from the one key.
#[derive(Clone)]
pub struct AnnounceIdentity {
    machine_did: String,
    signer: AnnounceSigner,
}

/// Signs from the event loop without stalling its runtime thread while the
/// hardware batch is signed.
pub type AnnounceSigner = crate::batch_signing::RuntimeSigner;

impl AnnounceIdentity {
    /// Announce as the machine whose identity key `signer` signs for.
    pub fn new(signer: Arc<dyn tenzro_crypto::batch::RecordSigner>) -> Self {
        let sec1 = [&[0x04u8][..], &signer.identity().p256].concat();
        Self {
            machine_did: tenzro_types::did_derivation::machine_did(&sec1),
            signer: AnnounceSigner::new(signer),
        }
    }

    /// `did:tenzro:machine:...`, resolved by receivers to its registered key.
    pub fn machine_did(&self) -> &str {
        &self.machine_did
    }

    /// The record signer of the machine identity.
    pub fn signer(&self) -> &AnnounceSigner {
        &self.signer
    }
}

/// The hardware identity key `registry` holds for `machine_did`: the only
/// key an announcement naming that DID may be signed under.
fn announcer_key_in(
    registry: Option<&IdentityRegistry>,
    machine_did: &str,
) -> std::result::Result<tenzro_crypto::composite::CompositePublicKey, String> {
    let registry = registry.ok_or("no identity registry to resolve announcers")?;
    let identity = registry
        .resolve(machine_did)
        .map_err(|_| format!("{machine_did} has no registered identity"))?;
    tenzro_identity::identity_key(&identity)
        .ok_or_else(|| format!("{machine_did} has no registered hardware key"))
}

/// Verify a gossip announcement against the key `registry` holds for the
/// machine DID it names.
fn verify_announcement_in<A: tenzro_network::SignedAnnouncement>(
    registry: Option<&IdentityRegistry>,
    ann: &A,
) -> std::result::Result<(), String> {
    ann.verify(&announcer_key_in(registry, ann.machine_did())?)
}

/// Segments ordered past the local tip kept while the blocks before them
/// are imported, at most.
const MAX_ORDERED_AHEAD: usize = 65_536;

/// Most ordered segments executed as one run under a single sync of the
/// store. Segments that queued while the previous run executed are taken
/// together, so a node that falls behind its ordering pays the sync once
/// per run rather than once per block, and catches up.
const MAX_SEGMENTS_PER_RUN: usize = 64;

/// Gossiped transactions this validator's mempool refused for a reason that
/// passes: the sender's nonce window, its pending cap, the rate limit, the
/// fee floor or a full mempool. Gossip delivers a transaction once and its
/// origin publishes it once, so a validator that dropped one would leave
/// the sender's later transactions waiting behind it for good. Each is
/// offered again every `retry_interval_ms`, until it is admitted, refused
/// for good or held `max_age_secs`; at most `max_held` are held, and the
/// oldest goes first ([`crate::config::HeldTransactionsConfig`]).
#[derive(Default)]
struct Parked {
    held: HashMap<Hash, (SignedTransaction, Instant)>,
    config: crate::config::HeldTransactionsConfig,
}

impl Parked {
    fn hold(&mut self, tx: SignedTransaction, now: Instant) {
        self.held.insert(tx.transaction.hash(), (tx, now));
        while self.held.len() > self.config.max_held {
            let Some(oldest) = self
                .held
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(h, _)| *h)
            else {
                break;
            };
            self.held.remove(&oldest);
        }
    }

    /// The held transactions to offer again, by sender and nonce, with the
    /// expired ones dropped.
    fn due(&mut self, now: Instant) -> Vec<SignedTransaction> {
        let max_age = Duration::from_secs(self.config.max_age_secs);
        self.held
            .retain(|_, (_, at)| now.duration_since(*at) < max_age);
        let mut due: Vec<SignedTransaction> =
            self.held.values().map(|(tx, _)| tx.clone()).collect();
        due.sort_by(|a, b| {
            (a.transaction.from.as_bytes(), a.transaction.nonce.0)
                .cmp(&(b.transaction.from.as_bytes(), b.transaction.nonce.0))
        });
        due
    }
}

/// Whether the mempool refused a transaction for a reason that passes as
/// blocks execute.
fn refusal_passes(e: &NodeError) -> bool {
    use tenzro_consensus::ConsensusError as C;
    match e {
        NodeError::Consensus(
            C::RateLimited { .. }
            | C::FeeFloorTooLow { .. }
            | C::NonceGapTooLarge { .. }
            | C::SenderCapExceeded { .. },
        ) => true,
        NodeError::Consensus(C::Mempool(m)) => {
            m.starts_with("Mempool full") || m.starts_with("Mempool size limit")
        }
        _ => false,
    }
}

/// How long a transaction this node published waits for a block before it
/// is published again; each later wait doubles, up to [`REANNOUNCE_MAX`].
const REANNOUNCE_FIRST: Duration = Duration::from_secs(5);

/// The longest wait between two publications of one transaction.
const REANNOUNCE_MAX: Duration = Duration::from_secs(60);

/// Transactions published again at most per tick, the longest waiting
/// first: a backlog is spread over ticks, never sent in one burst.
const REANNOUNCE_PER_TICK: usize = 512;

/// How often the published transactions are checked.
const REANNOUNCE_TICK: Duration = Duration::from_secs(1);

/// Transactions this node admitted from its own clients and published on
/// gossip, until a block includes them or the mempool lets them go.
///
/// Gossip delivers once and on a best-effort basis: a neighbour that falls
/// behind loses messages, and a validator sheds a transaction it cannot
/// take now. The node that admitted a transaction still holds it, counts it
/// in its sender's pending nonce and per-sender cap, and is the only one that
/// knows it was accepted, so it publishes it again until it leaves the
/// mempool. Without this, one lost transaction left a nonce gap that every
/// later transaction of the sender waited behind for good.
#[derive(Default)]
struct Announced {
    /// When each is published next, and how many times it was published again.
    due: HashMap<Hash, (Instant, u32)>,
}

impl Announced {
    /// `hash` was published at `now`.
    fn published(&mut self, hash: Hash, now: Instant) {
        self.due.insert(hash, (now + REANNOUNCE_FIRST, 0));
    }

    /// The transactions to publish again at `now`, the longest waiting
    /// first and at most `limit`; those `pooled` no longer holds are
    /// forgotten.
    fn due(&mut self, now: Instant, limit: usize, pooled: impl Fn(&Hash) -> bool) -> Vec<Hash> {
        self.due.retain(|h, _| pooled(h));
        let mut ready: Vec<(Instant, Hash)> = self
            .due
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(h, (at, _))| (*at, *h))
            .collect();
        ready.sort_unstable_by(|a, b| (a.0, a.1.as_bytes()).cmp(&(b.0, b.1.as_bytes())));
        ready.truncate(limit);
        for (_, h) in &ready {
            if let Some((at, times)) = self.due.get_mut(h) {
                *times = times.saturating_add(1);
                let wait = REANNOUNCE_FIRST
                    .saturating_mul(1u32 << (*times).min(5))
                    .min(REANNOUNCE_MAX);
                *at = now + wait;
            }
        }
        ready.into_iter().map(|(_, h)| h).collect()
    }
}

/// The transactions in `announced` due to be published again at `now` that
/// `mempool` still holds, each sender's in nonce order.
fn due_for_publishing(
    announced: &mut Announced,
    mempool: &tenzro_consensus::Mempool,
    now: Instant,
) -> Vec<SignedTransaction> {
    let due = announced.due(now, REANNOUNCE_PER_TICK, |h| mempool.contains(h));
    let mut txs: Vec<SignedTransaction> = due
        .iter()
        .filter_map(|h| mempool.get_transaction(h))
        .collect();
    txs.sort_by(|a, b| {
        (a.transaction.from.as_bytes(), a.transaction.nonce.0)
            .cmp(&(b.transaction.from.as_bytes(), b.transaction.nonce.0))
    });
    txs
}

/// Transactions waiting for the ingress task. Past this many the newest is
/// dropped: a flood is shed here, never queued in front of blocks.
const INGRESS_QUEUE: usize = 4_096;

/// Held transactions handed back to the event loop, which offers them to the
/// mempool again as blocks execute.
const PARKED_BACK_QUEUE: usize = 4_096;

/// Checks transactions from gossip, and from the RPC layer of a node that
/// does not propose blocks, and offers them to the mempool, on a task of its
/// own. Checking signatures is the costliest step a transaction takes; done
/// on the event loop, a flood of transactions held up the blocks queued
/// behind them and finality stood still.
struct Ingress {
    chain_id: u64,
    storage: Arc<RocksDbStore>,
    state_adapter: Arc<Mutex<StateAdapter>>,
    consensus: Option<Arc<ConsensusHandle>>,
    chain_tip: Arc<AtomicU64>,
    parked: mpsc::Sender<SignedTransaction>,
    /// Whether GPU proofs are checked for revoked certificates first.
    gpu_revocation: crate::config::GpuRevocationConfig,
}

impl Ingress {
    async fn run(self, mut rx: mpsc::Receiver<SignedTransaction>) {
        while let Some(tx) = rx.recv().await {
            if let Err(e) = self.admit(tx).await {
                debug!(error = %e, "transaction refused at ingress");
            }
        }
    }

    /// Whether this node proposes blocks now, as the event loop decides it,
    /// with its executed tip read from the shared chain tip.
    fn orders_blocks(&self) -> bool {
        let tip = self.chain_tip.load(Ordering::Acquire);
        self.consensus.as_ref().is_some_and(|c| {
            c.is_validator()
                && !c.awaiting_handover()
                && c.fast_forward_target().is_none_or(|to| tip >= to)
        })
    }

    async fn admit(&self, mut tx: SignedTransaction) -> Result<()> {
        let tx_hash = tx.hash();

        // Basic validation; an external wallet transaction carries its
        // signature inside its raw bytes.
        let external = tx.transaction.tx_type.is_external();
        if !external && !tx.signature.has_classical_leg() && tx.signature.pq.is_none() {
            return Err(NodeError::InvalidTransaction("Empty signature".to_string()));
        }
        if !external && tx.public_key.is_empty() {
            return Err(NodeError::InvalidTransaction(
                "Empty public key".to_string(),
            ));
        }
        if tx.transaction.gas_limit == 0 {
            return Err(NodeError::InvalidTransaction("Zero gas limit".to_string()));
        }
        // A transaction signed for another network never enters this one's pool.
        if !external && tx.transaction.chain_id.0 != self.chain_id {
            return Err(NodeError::InvalidTransaction(format!(
                "signed for chain id {}; this network is chain id {}",
                tx.transaction.chain_id.0, self.chain_id
            )));
        }
        // A sender holding nothing cannot pay for gas, so its transaction is
        // refused before any signature is checked: a flood from fresh
        // accounts then costs one balance read each. The treasury pays a
        // Funding transaction's gas, so its sender may hold nothing.
        if !external && !matches!(tx.transaction.tx_type, TransactionType::Funding { .. }) {
            use tenzro_vm::traits::VmState as _;
            let balance = StateAdapter::with_storage(self.storage.clone())
                .get_balance(tx.transaction.from.as_bytes());
            if balance == 0 {
                return Err(NodeError::InvalidTransaction(
                    "sender holds nothing to pay gas with".to_string(),
                ));
            }
        }

        // Verify transaction signature cryptographically.
        let verified = match verify_transaction_signature(&tx) {
            Ok(()) => {
                let state = self.state_adapter.lock().await;
                verify_transaction_pq_leg(&tx, &*state)
                    .and_then(|()| verify_transaction_sender(&tx, &*state))
            }
            Err(e) => Err(e),
        };
        if let Err(e) = verified {
            warn!(hash = %tx_hash, error = %e, "Rejecting transaction with invalid signature");
            return Err(NodeError::InvalidTransaction(format!(
                "Invalid signature: {e}"
            )));
        }
        if self.gpu_revocation.enabled {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default();
            for chain in crate::gpu_revocation::gpu_chains(&tx.transaction.tx_type) {
                crate::gpu_revocation::check_chain(
                    &self.gpu_revocation,
                    crate::http_client::shared(),
                    &chain,
                    now,
                )
                .await
                .map_err(|e| {
                    NodeError::InvalidTransaction(format!("GPU certificate revocation: {e}"))
                })?;
            }
        }
        info!(
            hash = %tx_hash,
            from = %tx.transaction.from,
            to = %tx.transaction.to,
            gas_limit = tx.transaction.gas_limit,
            gas_price = tx.transaction.gas_price,
            "New transaction received and validated"
        );

        // Never re-broadcast here: gossip already carried it on, and
        // republishing under a new envelope defeats gossip's dedup.
        if self.orders_blocks()
            && let Some(consensus) = &self.consensus
        {
            match consensus.submit_transaction(tx.clone()) {
                Ok(()) => {
                    info!(hash = %tx_hash, "Transaction submitted to consensus mempool");
                }
                Err(e) if refusal_passes(&e) => {
                    // Held by the event loop and offered to the mempool again
                    // as blocks execute.
                    debug!(hash = %tx_hash, error = %e, "Holding a transaction from the network refused for now");
                    if self.parked.try_send(tx).is_err() {
                        debug!(hash = %tx_hash, "held transactions full: transaction dropped");
                    }
                }
                Err(e) => {
                    debug!(hash = %tx_hash, error = %e, "Dropping non-admittable transaction received from network");
                }
            }
        } else {
            // This node does not propose blocks: gossip has carried the tx
            // on to the validators and nothing is kept here.
            debug!(hash = %tx_hash, "Transaction relayed (node does not propose blocks)");
        }
        Ok(())
    }
}

/// Maximum tolerated forward clock skew for announcement timestamps (ms).
/// Announcements dated further into the future than this are rejected —
/// a signer can't pre-date announcements to extend their replay window.
const ANNOUNCE_MAX_FUTURE_SKEW_MS: i64 = 60_000;

/// Replay-window check applied to every signed announcement on ingest.
/// The signature covers `timestamp` + `ttl_secs`, so a captured
/// announcement is only replayable inside its own TTL window; after the
/// provider stops serving (or changes endpoint), the stale capture expires.
fn check_announcement_freshness(
    timestamp_ms: i64,
    ttl_secs: u64,
) -> std::result::Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let age_ms = now.saturating_sub(timestamp_ms);
    let ttl_ms = (ttl_secs as i64).saturating_mul(1000);
    if age_ms > ttl_ms {
        return Err(format!(
            "stale announcement: age {}ms exceeds ttl {}s",
            age_ms, ttl_secs
        ));
    }
    if age_ms < -ANNOUNCE_MAX_FUTURE_SKEW_MS {
        return Err(format!(
            "future-dated announcement: {}ms ahead of local clock",
            -age_ms
        ));
    }
    Ok(())
}

/// The pending gossip verdict on a received block. Reported once, after the
/// event loop has checked the block: accept (forward it), reject (invalid,
/// penalize the relayer) or ignore (cannot be judged here). Dropped
/// unreported, it ignores.
#[derive(Debug, Clone)]
pub struct GossipVerdict(
    pub(crate) Arc<parking_lot::Mutex<Option<tenzro_network::ValidationTicket>>>,
);

impl GossipVerdict {
    /// Wraps a ticket from a validated gossip subscription.
    pub fn new(ticket: tenzro_network::ValidationTicket) -> Self {
        Self(Arc::new(parking_lot::Mutex::new(Some(ticket))))
    }

    fn take(&self) -> Option<tenzro_network::ValidationTicket> {
        self.0.lock().take()
    }

    fn accept(&self) {
        if let Some(t) = self.take() {
            t.accept();
        }
    }

    fn reject(&self) {
        if let Some(t) = self.take() {
            t.reject();
        }
    }
}

/// Where a block being executed came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockSource {
    /// Built by this validator from a segment its consensus ordered.
    Ordered,
    /// Received from a peer and imported under a checkpoint certificate.
    Imported,
}

/// Event types flowing through the node
// In-process event message; the largest variant is the common hot path, so
// boxing to equalize variant sizes would pessimize the common case.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// New transaction received (from network gossip or unauthenticated RPC fallback).
    /// The event loop runs full validation + consensus admission for these.
    NewTransaction(SignedTransaction),
    /// Transaction that was already admitted to the local consensus mempool by
    /// the RPC layer (`tenzro_sendRawTransaction`).
    /// The event loop skips re-admission (which would double-charge the admission
    /// per-DID token bucket) and only handles gossip propagation + local pending
    /// bookkeeping.
    LocallyAdmittedTransaction(SignedTransaction),
    /// A transaction the RPC layer admitted to the local mempool and
    /// published itself. The event loop publishes it again while the mempool
    /// still holds it and no block has taken it.
    PublishedTransaction(Hash),
    /// Block received from the network via gossip (from a validator),
    /// with the verdict that decides whether gossip passes it on.
    NetworkBlock(Block, GossipVerdict),
    /// A checkpoint certificate received from the network.
    NetworkCertificate(Box<tenzro_consensus::PublishedCertificate>),
    /// Model registration received from gossip
    ModelAnnouncement(tenzro_network::ModelRegistrationMessage),
    /// Provider announcement received from gossip (from another node)
    ProviderAnnouncement(tenzro_network::ProviderAnnouncementMessage),
    /// Provider heartbeat received from gossip, fed into the router's
    /// liveness view.
    ProviderHeartbeat(tenzro_network::ProviderHeartbeatMessage),
    /// Blob availability announcement received from gossip (from another
    /// node). Verified and folded into the iroh resolver's blob-provider
    /// hint cache.
    BlobAnnouncement(tenzro_network::BlobAnnouncementMessage),
    /// Shard replication request received from gossip. Storage-serving
    /// nodes run rendezvous (HRW) self-selection per shard and pin the
    /// shards they rank for into their local iroh blob store, spreading the
    /// object across independent providers.
    ShardReplication(tenzro_network::ShardReplicationMessage),
    /// Shutdown signal
    Shutdown,
}

/// Persisted per-transaction receipt record written to `CF_TRANSACTIONS`
/// under the key `receipt:<hex_tx_hash>` after each block is finalized.
///
/// This is the source of truth consumed by `eth_getTransactionReceipt` —
/// it lets the RPC layer report the *real* execution status, gas used,
/// emitted logs, and any deployed contract address rather than fabricating
/// a synthetic `0x1` / `gas_limit` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxReceiptRecord {
    /// Whether VM execution succeeded (false on revert or VM error).
    pub success: bool,
    /// Actual gas consumed by this transaction.
    pub gas_used: u64,
    /// Sum of `gas_used` for this tx and every preceding tx in the same block.
    pub cumulative_gas_used: u64,
    /// Effective gas price the sender paid (post-EIP-1559 base fee burn semantics):
    /// the offered price, or less when the sender could not pay its whole fee.
    pub effective_gas_price: u64,
    /// The fee actually taken from the sender, wei: what the block's fee pool
    /// received and what its burn is computed from. Below gas used times the
    /// offered price when the sender could not cover it; zero for a
    /// transaction that never executed.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub fee_paid: u128,
    /// Revert reason, when `success == false`.
    pub revert_reason: Option<String>,
    /// Contract address (raw 20 bytes, hex without 0x prefix) for deployment txs.
    pub contract_address: Option<String>,
    /// Raw logs emitted during execution. Encoded with hex addresses/topics/data
    /// so the receipt JSON can be served without re-decoding VM types.
    pub logs: Vec<TxReceiptLog>,
    /// Net native TNZO the transaction minted (positive) or burned
    /// (negative), as its execution declared it. Zero in a receipt written
    /// before the field was kept.
    #[serde(default)]
    pub supply_change: i128,
    /// The treasury leg a provider-work settlement in the transaction paid,
    /// for a transaction type that declares it.
    #[serde(default)]
    pub treasury_leg: Option<u128>,
}

impl TxReceiptRecord {
    /// The receipt's Ethereum consensus encoding for a transaction of
    /// `tx_type` (see [`tenzro_types::eth_receipt`]).
    pub(crate) fn eth_encoding(&self, tx_type: u8) -> Vec<u8> {
        let logs: Vec<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)> = self
            .logs
            .iter()
            .map(|l| {
                (
                    hex::decode(&l.address).unwrap_or_default(),
                    l.topics
                        .iter()
                        .map(|t| hex::decode(t).unwrap_or_default())
                        .collect(),
                    hex::decode(&l.data).unwrap_or_default(),
                )
            })
            .collect();
        let topics: Vec<Vec<&[u8]>> = logs
            .iter()
            .map(|(_, t, _)| t.iter().map(Vec::as_slice).collect())
            .collect();
        tenzro_types::eth_receipt::encode_receipt(
            tx_type,
            self.success,
            self.cumulative_gas_used,
            logs.iter().zip(&topics).map(|((a, _, d), t)| {
                tenzro_types::eth_receipt::ReceiptLogRef {
                    address: a,
                    topics: t,
                    data: d,
                }
            }),
        )
    }
}

/// The Ethereum transaction type of a transaction: the EIP-2718 type byte of
/// an external EVM envelope, 0 for a legacy envelope and every native kind.
pub(crate) fn eth_tx_type(signed_tx: &SignedTransaction) -> u8 {
    match &signed_tx.transaction.tx_type {
        tenzro_types::TransactionType::ExternalEvm { raw } => match raw.first() {
            Some(b) if *b < 0x7f => *b,
            _ => 0,
        },
        _ => 0,
    }
}

/// Per-log entry inside a `TxReceiptRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxReceiptLog {
    /// Hex-encoded contract address that emitted the log (no 0x prefix).
    pub address: String,
    /// Hex-encoded indexed topics (no 0x prefix).
    pub topics: Vec<String>,
    /// Hex-encoded log data payload (no 0x prefix).
    pub data: String,
}

/// The node event loop coordinates all subsystems
/// How often the blob availability heartbeat runs.
///
/// Named because the announcement TTL is derived from it: a hash must be
/// re-announced before peers forget it, and how long a full rotation takes
/// depends on this interval and on how many chunks each tick sends.
const BLOB_HEARTBEAT_SECS: u64 = 60;

/// Hashes per gossip message. Each hash is 64 hex characters, so 512 is about
/// a 34 KiB payload — comfortably under the 1 MiB transmit ceiling.
const HASHES_PER_ANNOUNCEMENT: usize = 512;

/// Hashes per heartbeat tick.
///
/// Sixteen messages' worth, ~545 KiB a minute. Fixed rather than proportional
/// to the store, which is the property that was missing: a node that stores
/// more should not talk more.
const BLOB_HASHES_PER_TICK: usize = HASHES_PER_ANNOUNCEMENT * 16;

/// Models announced per tick.
///
/// A node serving a handful sends them all in one tick; a node serving
/// hundreds takes a few. Either way the tick costs the same.
const MODELS_PER_TICK: usize = 16;

/// The most bytes of blocks a node holds while it waits for a certificate
/// covering them. Blocks carry no signature, so anyone can gossip
/// self-consistent ones; this bounds what they cost a node however many
/// arrive. It holds a full block-sync range of the largest blocks.
const UNCERTIFIED_BYTES: usize = 128 << 20;

/// Blocks received from peers and not yet covered by a verified
/// certificate, by height, holding at most [`UNCERTIFIED_BYTES`]. When full,
/// the blocks nearest the tip are kept: those are imported first, and a
/// dropped later one is fetched again by block-sync.
#[derive(Default)]
struct HeldBlocks {
    blocks: std::collections::BTreeMap<u64, (Block, usize)>,
    bytes: usize,
}

impl HeldBlocks {
    /// Holds `block` at height `h`, replacing any block held there; false
    /// when it does not fit under the budget.
    fn insert(&mut self, h: u64, block: Block) -> bool {
        let Ok(size) = serde_json::to_vec(&block).map(|v| v.len()) else {
            return false;
        };
        if size > UNCERTIFIED_BYTES {
            return false;
        }
        let replaced = self.blocks.get(&h).map_or(0, |(_, s)| *s);
        while self.bytes - replaced + size > UNCERTIFIED_BYTES {
            match self.blocks.last_key_value() {
                Some((&top, _)) if top > h => {
                    if let Some((_, (_, s))) = self.blocks.pop_last() {
                        self.bytes -= s;
                    }
                }
                _ => return false,
            }
        }
        if let Some((_, s)) = self.blocks.insert(h, (block, size)) {
            self.bytes -= s;
        }
        self.bytes += size;
        true
    }

    fn get(&self, h: &u64) -> Option<&Block> {
        self.blocks.get(h).map(|(b, _)| b)
    }

    fn contains_key(&self, h: &u64) -> bool {
        self.blocks.contains_key(h)
    }

    fn remove(&mut self, h: &u64) -> Option<Block> {
        let (b, s) = self.blocks.remove(h)?;
        self.bytes -= s;
        Some(b)
    }

    /// Drops every block at or below `height`.
    fn drop_through(&mut self, height: u64) {
        let kept = self.blocks.split_off(&(height + 1));
        let dropped = std::mem::replace(&mut self.blocks, kept);
        self.bytes -= dropped.values().map(|(_, s)| *s).sum::<usize>();
    }

    #[cfg(test)]
    fn values(&self) -> impl Iterator<Item = &Block> {
        self.blocks.values().map(|(b, _)| b)
    }
}

/// Shards of one replication request this node fetches at most.
const MAX_SHARDS_PER_REPLICATION: usize = 64;
/// The longest one shard fetch may take before it is given up.
const SHARD_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Replication requests fetched at once. One that arrives while all are
/// busy is dropped; the other replicas the origin selected still pin it.
const REPLICATIONS_AT_ONCE: usize = 4;

/// What the storage role consults before it writes a shard, and records
/// after. Nothing here is reachable from block application or consensus.
#[derive(Clone)]
struct ShardGate {
    quarantine: Arc<crate::shard_quarantine::ShardQuarantine>,
    disk: Option<Arc<crate::storage_maintenance::DiskGuard>>,
}

impl ShardGate {
    fn none() -> Self {
        Self {
            quarantine: Arc::new(crate::shard_quarantine::ShardQuarantine::default()),
            disk: None,
        }
    }
}

/// The hash a blob URI names, for the quarantine's key.
fn shard_key(uri: &tenzro_iroh::TenzroUri) -> String {
    match uri {
        tenzro_iroh::TenzroUri::Blob { hash, .. } => hash.clone(),
        other => other.to_string(),
    }
}

/// Fetches the shards one replication request selected this node for, each
/// under [`SHARD_FETCH_TIMEOUT`]. Returns how many were pinned.
///
/// A shard is contained on every failure path: a refusal by the disk guard
/// skips the whole request (shards are non-essential data), a quarantined
/// shard is skipped without touching the blob store, and a fetch that fails,
/// times out or panics counts against that shard alone. The caller runs this
/// off the event loop, so nothing here can delay a block.
async fn pin_shards(
    resolver: &dyn IrohResolver,
    uris: &[tenzro_iroh::TenzroUri],
    gate: &ShardGate,
) -> usize {
    use futures::FutureExt;
    if let Some(disk) = gate.disk.as_ref()
        && let Some(reason) = disk.refusal("shard replication")
    {
        warn!(%reason, "Shard replication: request skipped, disk past the refuse watermark");
        return 0;
    }
    let mut pinned = 0;
    for uri in uris {
        let key = shard_key(uri);
        let now = tokio::time::Instant::now().into_std();
        if !gate.quarantine.admit(&key, now) {
            debug!(%uri, "Shard replication: shard held back after earlier failures");
            continue;
        }
        let fetch = std::panic::AssertUnwindSafe(resolver.fetch_bytes(uri)).catch_unwind();
        let failed = match tokio::time::timeout(SHARD_FETCH_TIMEOUT, fetch).await {
            Ok(Ok(Ok(_))) => {
                gate.quarantine.record_success(&key);
                pinned += 1;
                false
            }
            Ok(Ok(Err(e))) => {
                warn!(%uri, error = %e, "Shard replication: failed to pin shard");
                true
            }
            Ok(Err(_)) => {
                warn!(%uri, "Shard replication: the blob store panicked on this shard; it is quarantined and the node carries on");
                true
            }
            Err(_) => {
                warn!(%uri, "Shard replication: shard fetch timed out");
                true
            }
        };
        if failed {
            gate.quarantine
                .record_failure(&key, tokio::time::Instant::now().into_std());
        }
    }
    pinned
}

pub struct EventLoop {
    /// Event sender for submitting events (used by RPC/network)
    event_tx: mpsc::Sender<NodeEvent>,
    /// Event receiver
    event_rx: mpsc::Receiver<NodeEvent>,
    /// Shutdown broadcast
    shutdown_tx: broadcast::Sender<()>,
    /// Storage
    storage: Arc<RocksDbStore>,
    /// VM runtime
    vm_runtime: Arc<MultiVmRuntime>,
    /// State adapter for VM execution (tokio::Mutex for async-safe access during block execution)
    state_adapter: Arc<Mutex<StateAdapter>>,
    /// Consensus: the mempool, finality, and the committee certificates are
    /// checked against. Present on every networked node.
    consensus: Option<Arc<ConsensusHandle>>,
    /// Network service (for broadcasting blocks over gossip)
    network: Option<Arc<TenzroNetworkService>>,
    /// Segments this validator's consensus ordered, in height order.
    ordered_rx: Option<mpsc::Receiver<OrderedSegment>>,
    /// Set while a run of blocks executes under one sync of the store: each
    /// block is written as one batch without syncing, and the run is synced
    /// once at its end.
    sync_deferred: bool,
    /// Blocks of the current run executed but not yet synced, as (height,
    /// block hash, post-state root): consensus learns of them, and signs
    /// checkpoints over them, only once they are durable.
    unsynced: Vec<(u64, Hash, Hash)>,
    /// Certificates to import under: formed by this validator, or received
    /// by a follower from the network.
    certificates_rx: Option<mpsc::UnboundedReceiver<Certificate>>,
    /// Blocks received from peers and not yet covered by a verified
    /// certificate, by height, bounded in bytes.
    uncertified: HeldBlocks,
    /// Segments this validator's consensus ordered past the local tip: its
    /// core resumed from a certified checkpoint whose blocks are still being
    /// imported. Each executes once the tip reaches it.
    ordered_ahead: std::collections::BTreeMap<u64, OrderedSegment>,
    /// Gossiped transactions refused for a reason that passes.
    parked: Parked,
    /// Hands transactions to the ingress task; set when the loop starts.
    ingress: Option<mpsc::Sender<SignedTransaction>>,
    /// Held transactions the ingress task hands back.
    parked_rx: Option<mpsc::Receiver<SignedTransaction>>,
    /// Transactions this node admitted and published, until a block takes them.
    announced: Announced,
    /// Consensus epoch of the last executed block.
    last_block_epoch: u64,
    /// Current finalized block height (synced from storage on startup)
    current_height: u64,
    /// Hash of the last finalized block
    last_block_hash: Hash,
    /// Live chain tip — shared with TenzroNode so RPC handlers can read it without
    /// storage I/O. Updated atomically on every finalized block (both local consensus
    /// and gossiped network blocks). Initialized from storage on startup.
    ///
    /// Why not read CF_METADATA:latest_height?  BlockStoreImpl::put_block has a
    /// `should_update = height > latest` guard that freezes CF_METADATA when new
    /// blocks arrive at heights below the stored max (e.g. after a fresh start
    /// with stale PVC data).  This atomic bypasses that guard entirely.
    chain_tip: Arc<AtomicU64>,
    /// Metrics collector — updated on every finalized block (block count,
    /// transaction count, and live peer count from the network service).
    metrics: Arc<MetricsCollector>,
    /// Shared reference to the node's network_models map for gossip model discovery
    network_models: Option<Arc<DashMap<String, crate::node::NetworkModelEntry>>>,
    /// Shared reference to the node's served_models for heartbeat re-announcements
    served_models: Option<Arc<DashMap<String, Option<tenzro_types::Visibility>>>>,
    /// The node's visibility, the default for every resource without an
    /// override.
    ///
    /// Read live per tick rather than captured at startup, so a change takes
    /// effect on the next heartbeat instead of at the next restart.
    node_visibility: Option<Arc<parking_lot::RwLock<tenzro_types::Visibility>>>,
    /// Shared reference to the node's provider pricing for heartbeat announcements
    provider_pricing: Option<Arc<parking_lot::RwLock<crate::node::ProviderPricing>>>,
    /// Shared reference to the node's provider schedule for heartbeat announcements
    provider_schedule: Option<Arc<parking_lot::RwLock<crate::node::ProviderSchedule>>>,
    /// Shared reference to model_services for cleanup of expired network endpoints
    model_services: Option<Arc<DashMap<String, tenzro_types::model::ModelServiceInstance>>>,
    /// Shared reference to the node's network_providers map for gossip provider discovery
    network_providers: Option<Arc<DashMap<String, crate::node::NetworkProviderEntry>>>,
    /// Shared reference to the node's `ProviderManager`. Verified provider
    /// announcements are bridged into it (`upsert_from_announcement`) so the
    /// `InferenceRouter` scoring path — which routes real chat traffic —
    /// actually sees gossip-discovered providers with their advertised
    /// `HardwareCapabilities`. `None` on nodes with no router (light clients).
    provider_manager: Option<Arc<tenzro_model::ProviderManager>>,
    /// This node's own provider address. Heartbeated every tick so the
    /// local-served-models provider entry stays healthy for intent dispatch
    /// (chatByIntent) — local serving has no gossip heartbeat of its own.
    local_provider_address: Option<Address>,
    /// Provider announcement broadcast context. When `Some`, the periodic
    /// `provider_heartbeat` tick rebuilds a `ProviderAnnouncementMessage`
    /// from the current `served_models` / `provider_pricing` / hardware
    /// snapshot and broadcasts it on `tenzro/providers` so peers can
    /// merge it into their `network_providers` cache. `None` on light
    /// clients that never serve.
    provider_announcement_ctx: Option<ProviderAnnouncementContext>,
    /// The machine identity every outbound announcement is signed as. `None`
    /// disables announcement broadcast (unsigned announcements are rejected
    /// network-wide).
    announce_identity: Option<AnnounceIdentity>,
    /// Shared reference to the ModelRuntime for idle-TTL liveness checks of
    /// local model service instances.
    #[cfg(feature = "inference")]
    model_runtime: Option<Arc<tenzro_model::ModelRuntime>>,
    /// Shared reference to the node's load tracker, so that when we evict an
    /// idle local model service we also unregister the per-model concurrency
    /// slot.
    load_tracker: Option<Arc<tenzro_model::LoadTracker>>,
    /// Model lifecycle (load state and warm-up queue), read for heartbeats.
    lifecycle: Option<Arc<tenzro_model::lifecycle::ModelLifecycle>>,
    /// Shared reference to the node's iroh resolver. The periodic
    /// `blob_heartbeat` tick enumerates the local blob store and broadcasts
    /// signed `BlobAnnouncementMessage`s on `tenzro/blobs`; inbound
    /// announcements from peers are folded into the resolver's
    /// blob-provider hint cache so `tenzro://blob/...` URIs resolve
    /// cross-node without an explicit provider hint.
    iroh_resolver: Option<Arc<tenzro_iroh::IrohBackedResolver>>,
    /// Endpoints the operator named to sync from (`--state-sync-from`):
    /// asked for blocks whether or not gossip has connected them.
    sync_peers: Vec<[u8; 32]>,
    block_sync: crate::config::BlockSyncConfig,
    gpu_revocation: crate::config::GpuRevocationConfig,
    /// Where each announcement rotation stopped.
    ///
    /// Every heartbeat used to enumerate its whole inventory and publish one
    /// message per item, all spawned at the instant of the tick. The cost grew
    /// with what the node held, and it arrived as a burst on the same per-peer
    /// gossip queue consensus uses — on this network that queue overflowed and
    /// the drops included blocks. See [`crate::announce`].
    blob_rotation: crate::announce::Rotation,
    model_rotation: crate::announce::Rotation,
    /// Identity registry. Wired so the post-execute scan can resolve a
    /// machine DID (carried on the kill-switch log) to the staker
    /// `Address` that the staking manager keys on.
    identity_registry: Option<Arc<IdentityRegistry>>,
    /// The auth engine whose tokens a consensus revocation revokes.
    auth_engine: Option<Arc<tenzro_auth::AuthEngine>>,
    /// Token metadata index. The post-execute scan reflects every
    /// `TokenCreated` log the token ledger emits into it, so lookups by
    /// symbol and address cover tokens created on chain.
    token_registry: Option<Arc<tenzro_token::TokenRegistry>>,
    /// Permissionless validator registry (Dynamic Validator Set).
    ///
    /// The on-chain source of truth for who is a validator. The post-execute
    /// scan mirrors VM-emitted `ValidatorRegister` / `ValidatorExit` /
    /// `ValidatorMetadataUpdate` logs into this registry; the periodic epoch
    /// hook calls `compute_epoch_transition()` and feeds the resulting plan
    /// to the consensus `EpochManager`'s `pending_validators` /
    /// `pending_removals` queues. Persistence is RocksDB-backed under
    /// `CF_TOKENS / validator:*` so the active set survives restarts.
    validator_registry: Option<Arc<tenzro_token::ValidatorRegistry>>,

    /// Adaptive burn rate manager — receives `SupplyMetricsSnapshot` records
    /// at every epoch boundary so the transfer function can score the
    /// supply's deviation from its target and surface a burn-rate
    /// recommendation through `tenzro_getBurnRateRecommendation`.
    /// Without this wired, `record_metrics` never gets called and the
    /// recommendation engine reports against stale/empty metrics.
    burn_rate_manager: Option<Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>>,

    /// Token reference — used by the epoch observer to read total supply
    /// for the snapshot.

    /// Jails the signer of a recorded checkpoint equivocation.
    equivocation_jailer: Option<Arc<crate::node::EquivocationJailer>>,
    /// Applies the network policy on-chain governance enacts, from the
    /// `PolicyEnacted` logs of each executed block.
    policy_applier: Option<Arc<crate::policy_reflection::PolicyApplier>>,
    /// This validator's SLA tally, fed each imported certificate's signers as
    /// consensus participation.
    sla_tally: Option<Arc<crate::sla_attest::SlaTally>>,

    /// Statistics for the gas fees each block settles in state: what was
    /// burned and what went to the treasury.
    fee_processor: Option<Arc<tenzro_token::FeeProcessor>>,

    /// Consensus total supply and cumulative burn at the previous epoch
    /// observation, the anchors of the next snapshot's per-epoch deltas.
    /// None until the first observation, which reports zero deltas.
    last_observed_supply: Option<(u128, u128)>,
    /// Receives `BlockImport` requests from the `BlockSyncEngine`: a served
    /// range with its checkpoint evidence, plus a oneshot `result` channel
    /// the event loop replies on after `handle_block_imported_from_sync`.
    ///
    /// Initialized inside `run()` once the engine has been spawned; `None`
    /// on a node with no iroh endpoint.
    block_import_rx: Option<mpsc::Receiver<crate::block_sync::BlockImport>>,

    /// Cosmos-style snapshot ABCI store. On producer nodes, the
    /// post-finality hook calls `produce_at(height, state_root)` at the
    /// configured [`crate::snapshot::SnapshotConfig::interval_blocks`]
    /// cadence. `None` until wired by the node.
    snapshot_store: Option<Arc<crate::snapshot::SnapshotStore>>,

    /// The durable event log every executed block's events are written to.
    event_log: Option<Arc<tenzro_events::EventLog>>,

    /// The committed state: every block's execution writes are committed as
    /// the trie version of the block's height, and a block's header must
    /// carry the root of version `height - STATE_ROOT_LAG`.
    state_trie: Arc<tenzro_storage::StateTrie>,

    /// Desired replica count per shard for storage placement. `Some(r)`
    /// marks this node as storage-serving: inbound `ShardReplication`
    /// requests trigger rendezvous (HRW) self-selection against the local
    /// membership view, and shards this node ranks in the top `r` are pinned
    /// into its iroh blob store. `None` on non-storage nodes — they ignore
    /// replication requests entirely.
    storage_replicas: Option<usize>,
    /// Replication requests whose shards are being fetched, at most
    /// [`REPLICATIONS_AT_ONCE`].
    replication_slots: Arc<tokio::sync::Semaphore>,
    /// Which shards failed and when each may be tried again, and the disk
    /// flag shard writes obey.
    shard_gate: ShardGate,

    /// Weak-subjectivity checkpoint `(height, block_hash)` enforced on every
    /// import path. QC verification proves each imported block carries a
    /// valid commit certificate, but a long-range fork forged by an old
    /// validator supermajority is self-consistent under that check. The
    /// checkpoint pins one finalized block the node trusts a priori, by
    /// hash: when import reaches `height`, the block must be that block or
    /// it (and everything built on it) is rejected. `None` disables the
    /// check.
    weak_subjectivity_anchor: Option<(u64, Hash)>,
}

/// Heights of committed state kept provable. Older trie versions are pruned.
const STATE_TRIE_RETAIN_HEIGHTS: u64 = 10_000;

/// Prune the state trie once every this many heights.
const STATE_TRIE_PRUNE_EVERY: u64 = 1_000;

impl EventLoop {
    /// Creates a new event loop
    ///
    /// # Arguments
    ///
    /// * `storage` - RocksDB storage backend
    /// * `vm_runtime` - Multi-VM runtime for executing transactions
    /// * `consensus` - Optional consensus engine (for validators)
    /// * `network` - Optional network service (for P2P communication)
    /// * `chain_tip` - Shared atomic tracking the live chain tip height (owned by TenzroNode,
    ///   updated here on every finalized block so RPC can read it lock-free)
    pub fn new(
        storage: Arc<RocksDbStore>,
        vm_runtime: Arc<MultiVmRuntime>,
        consensus: Option<Arc<ConsensusHandle>>,
        network: Option<Arc<TenzroNetworkService>>,
        chain_tip: Arc<AtomicU64>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(10000);
        let (shutdown_tx, _) = broadcast::channel(1);

        // Create state adapter with storage backend, behind Mutex for shared access
        let state_adapter = Arc::new(Mutex::new(StateAdapter::with_storage(
            storage.clone() as Arc<dyn KvStore>
        )));
        let state_trie = Arc::new(tenzro_storage::StateTrie::new(
            storage.clone() as Arc<dyn KvStore>
        ));

        Self {
            event_tx,
            event_rx,
            shutdown_tx,
            storage,
            vm_runtime,
            state_adapter,
            consensus,
            network,
            ordered_rx: None,
            sync_deferred: false,
            unsynced: Vec::new(),
            certificates_rx: None,
            uncertified: HeldBlocks::default(),
            ordered_ahead: std::collections::BTreeMap::new(),
            parked: Parked::default(),
            ingress: None,
            parked_rx: None,
            announced: Announced::default(),
            last_block_epoch: 0,
            current_height: 0,
            last_block_hash: Hash::zero(),
            chain_tip,
            metrics,
            network_models: None,
            served_models: None,
            node_visibility: None,
            provider_pricing: None,
            provider_schedule: None,
            model_services: None,
            network_providers: None,
            provider_manager: None,
            local_provider_address: None,
            provider_announcement_ctx: None,
            announce_identity: None,
            #[cfg(feature = "inference")]
            model_runtime: None,
            load_tracker: None,
            lifecycle: None,
            iroh_resolver: None,
            sync_peers: Vec::new(),
            block_sync: crate::config::BlockSyncConfig::default(),
            gpu_revocation: crate::config::GpuRevocationConfig::default(),
            blob_rotation: crate::announce::Rotation::new(
                BLOB_HASHES_PER_TICK,
                std::time::Duration::from_secs(BLOB_HEARTBEAT_SECS),
            ),
            model_rotation: crate::announce::Rotation::new(
                MODELS_PER_TICK,
                std::time::Duration::from_secs(BLOB_HEARTBEAT_SECS),
            ),
            identity_registry: None,
            auth_engine: None,
            token_registry: None,
            validator_registry: None,
            block_import_rx: None,
            burn_rate_manager: None,
            equivocation_jailer: None,
            policy_applier: None,
            sla_tally: None,
            fee_processor: None,
            last_observed_supply: None,
            snapshot_store: None,
            event_log: None,
            state_trie,
            storage_replicas: None,
            replication_slots: Arc::new(tokio::sync::Semaphore::new(REPLICATIONS_AT_ONCE)),
            shard_gate: ShardGate::none(),
            weak_subjectivity_anchor: None,
        }
    }

    /// Pins the weak-subjectivity checkpoint `(height, block_hash)` enforced
    /// on every import path. When an import reaches `height`, the block must
    /// hash to `block_hash` or the import is rejected — defeating long-range
    /// forks that pass QC verification. Left unset, imports are accepted on
    /// QC verification alone.
    pub fn with_weak_subjectivity_anchor(mut self, height: u64, block_hash: Hash) -> Self {
        self.weak_subjectivity_anchor = Some((height, block_hash));
        self
    }

    /// Makes shard replication obey the node's disk flag: past the refuse
    /// watermark inbound shards are skipped, as other non-essential data is.
    pub fn with_disk_guard(mut self, guard: Arc<crate::storage_maintenance::DiskGuard>) -> Self {
        self.shard_gate.disk = Some(guard);
        self
    }

    /// Marks this node as storage-serving with the given per-shard replica
    /// target. Inbound `ShardReplication` requests then run rendezvous (HRW)
    /// self-selection and pin the shards this node ranks for.
    pub fn with_storage_replicas(mut self, replicas: usize) -> Self {
        self.storage_replicas = Some(replicas.max(1));
        self
    }

    /// Wires the snapshot ABCI store. Once set, `process_finality_notification`
    /// triggers `produce_at` at the store's configured interval on producer
    /// nodes (a no-op when the producer is disabled).
    pub fn with_snapshot_store(
        mut self,
        snapshot_store: Arc<crate::snapshot::SnapshotStore>,
    ) -> Self {
        self.snapshot_store = Some(snapshot_store);
        self
    }

    /// Wires the durable event log each executed block's events go to.
    pub fn with_event_log(mut self, log: Arc<tenzro_events::EventLog>) -> Self {
        self.event_log = Some(log);
        self
    }

    /// Returns a clone of the event sender for RPC/network to submit events
    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.event_tx.clone()
    }

    /// Wires the segments this validator's consensus orders.
    pub fn with_ordered_segments(mut self, rx: mpsc::Receiver<OrderedSegment>) -> Self {
        self.ordered_rx = Some(rx);
        self
    }

    /// Wires the certificates blocks are imported under.
    pub fn with_certificates(mut self, rx: mpsc::UnboundedReceiver<Certificate>) -> Self {
        self.certificates_rx = Some(rx);
        self
    }

    /// Wires this node's visibility into the event loop.
    ///
    /// Absent, the loop uses the default visibility (public).
    pub fn with_node_visibility(
        mut self,
        visibility: Arc<parking_lot::RwLock<tenzro_types::Visibility>>,
    ) -> Self {
        self.node_visibility = Some(visibility);
        self
    }

    /// The node's visibility right now.
    fn node_visibility(&self) -> tenzro_types::Visibility {
        self.node_visibility
            .as_ref()
            .map(|p| *p.read())
            .unwrap_or_default()
    }

    /// The served models whose effective visibility is announced, sorted, and
    /// the gated subset of them.
    fn announced_models(&self) -> (Vec<String>, Vec<String>) {
        self.served_models
            .as_ref()
            .map(|served| crate::visibility_rpc::announced_models(served, self.node_visibility()))
            .unwrap_or_default()
    }

    /// Wires the network model discovery state into the event loop.
    pub fn with_model_discovery(
        mut self,
        network_models: Arc<DashMap<String, crate::node::NetworkModelEntry>>,
        served_models: Arc<DashMap<String, Option<tenzro_types::Visibility>>>,
        provider_pricing: Arc<parking_lot::RwLock<crate::node::ProviderPricing>>,
        provider_schedule: Arc<parking_lot::RwLock<crate::node::ProviderSchedule>>,
    ) -> Self {
        self.network_models = Some(network_models);
        self.served_models = Some(served_models);
        self.provider_pricing = Some(provider_pricing);
        self.provider_schedule = Some(provider_schedule);
        self
    }

    /// Wires the identity registry, which resolves the identities named in
    /// replayed logs.
    pub fn with_identity_registry(mut self, identity_registry: Arc<IdentityRegistry>) -> Self {
        self.identity_registry = Some(identity_registry);
        self
    }

    /// Wires the auth engine, whose tokens for an identity consensus revokes
    /// are revoked when the block's `IdentityRevoked` log is mirrored.
    pub fn with_auth_engine(mut self, auth_engine: Arc<tenzro_auth::AuthEngine>) -> Self {
        self.auth_engine = Some(auth_engine);
        self
    }

    /// Wires the token metadata index the post-execute scan reflects
    /// `TokenCreated` logs into.
    pub fn with_token_registry(mut self, token_registry: Arc<tenzro_token::TokenRegistry>) -> Self {
        self.token_registry = Some(token_registry);
        self
    }

    /// Wires the permissionless validator registry (Dynamic Validator Set).
    ///
    /// The post-execute scan in `handle_block_finalized` consumes the
    /// VM-emitted `ValidatorRegister` / `ValidatorExit` /
    /// `ValidatorMetadataUpdate` logs and applies them to this registry; the
    /// per-block epoch hook calls `compute_epoch_transition()` at every epoch
    /// boundary and stages the resulting plan into the consensus
    /// `EpochManager`'s `pending_validators` / `pending_removals` queues.
    /// Without this manager wired, validator transactions are accepted by
    /// the VM (logs land in receipts) but the consensus active set never
    /// rotates.
    pub fn with_validator_registry(
        mut self,
        validator_registry: Arc<tenzro_token::ValidatorRegistry>,
    ) -> Self {
        self.validator_registry = Some(validator_registry);
        self
    }

    /// Wires the adaptive-burn manager.
    ///
    /// At every epoch transition the event loop computes a
    /// `SupplyMetricsSnapshot` from consensus counters (total supply, epoch
    /// supply delta, burn, mint, rolling-window bps) and feeds it into
    /// `BurnRateConfigManager::record_metrics`. The transfer function
    /// (`current_recommendation()`) and the
    /// `tenzro_getBurnRateRecommendation` RPC then read from the
    /// freshly-persisted snapshot. Without this wire, `record_metrics`
    /// is dead code and the recommendation engine scores against
    /// `SupplyMetricsSnapshot::default()`.
    pub fn with_burn_rate_manager(
        mut self,
        burn_rate_manager: Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>,
    ) -> Self {
        self.burn_rate_manager = Some(burn_rate_manager);
        self
    }

    /// Wires the model_services map for periodic cleanup of expired endpoints.
    pub fn with_model_services(
        mut self,
        model_services: Arc<DashMap<String, tenzro_types::model::ModelServiceInstance>>,
    ) -> Self {
        self.model_services = Some(model_services);
        self
    }

    /// Wires the ModelRuntime + load_tracker so the heartbeat tick can run the
    /// 1-hour idle TTL cleanup against live runtime state.
    #[cfg(feature = "inference")]
    pub fn with_model_runtime(
        mut self,
        model_runtime: Arc<tenzro_model::ModelRuntime>,
        load_tracker: Arc<tenzro_model::LoadTracker>,
        lifecycle: Arc<tenzro_model::lifecycle::ModelLifecycle>,
    ) -> Self {
        self.model_runtime = Some(model_runtime);
        self.load_tracker = Some(load_tracker);
        self.lifecycle = Some(lifecycle);
        self
    }

    /// Wires the network_providers map for gossip-discovered provider merging.
    pub fn with_provider_discovery(
        mut self,
        network_providers: Arc<DashMap<String, crate::node::NetworkProviderEntry>>,
    ) -> Self {
        self.network_providers = Some(network_providers);
        self
    }

    /// Wires the `ProviderManager` so verified provider announcements are
    /// bridged into the `InferenceRouter` scoring path. Without this, a
    /// gossip-discovered provider lives only in `network_providers` and is
    /// invisible to the router that dispatches chat traffic.
    pub fn with_provider_manager(
        mut self,
        provider_manager: Arc<tenzro_model::ProviderManager>,
        local_provider_address: Option<Address>,
    ) -> Self {
        self.provider_manager = Some(provider_manager);
        self.local_provider_address = local_provider_address;
        self
    }

    /// Wires the static context required to broadcast `ProviderAnnouncementMessage`
    /// from the periodic `provider_heartbeat` tick.
    ///
    /// Without this wired, the heartbeat only evicts stale `network_providers`
    /// entries — peers will never learn about this node's served models /
    /// hardware / region.
    pub fn with_provider_announcement(mut self, ctx: ProviderAnnouncementContext) -> Self {
        self.provider_announcement_ctx = Some(ctx);
        self
    }

    /// Wires the machine identity every outbound announcement is signed as.
    /// Without it the heartbeat ticks skip broadcasting, because unsigned
    /// announcements are rejected by every consumer.
    pub fn with_announce_identity(mut self, identity: AnnounceIdentity) -> Self {
        self.announce_identity = Some(identity);
        self
    }

    /// The hardware identity key registered for the machine DID an
    /// announcement names: the only key it may be signed under.
    fn announcer_key(
        &self,
        machine_did: &str,
    ) -> std::result::Result<tenzro_crypto::composite::CompositePublicKey, String> {
        announcer_key_in(self.identity_registry.as_deref(), machine_did)
    }

    /// Verify a gossip announcement against the key registered for the
    /// machine DID it names.
    fn verify_announcement<A: tenzro_network::SignedAnnouncement>(
        &self,
        ann: &A,
    ) -> std::result::Result<(), String> {
        verify_announcement_in(self.identity_registry.as_deref(), ann)
    }

    /// Wires the node's iroh resolver so the `blob_heartbeat` tick can
    /// announce locally held blobs on `tenzro/blobs` and inbound peer
    /// announcements can populate the resolver's blob-provider hint cache.
    pub fn with_iroh_resolver(mut self, resolver: Arc<tenzro_iroh::IrohBackedResolver>) -> Self {
        self.iroh_resolver = Some(resolver);
        self
    }

    /// Names the endpoints block sync asks first. What they serve is
    /// imported only when it verifies against the certified checkpoints, so
    /// naming a peer trusts nothing it says.
    pub fn with_sync_peers(mut self, peers: Vec<[u8; 32]>) -> Self {
        self.sync_peers = peers;
        self
    }

    /// How long, how many and how often gossiped transactions refused for
    /// a reason that passes are held and offered to the mempool again.
    pub fn with_held_transactions(mut self, config: crate::config::HeldTransactionsConfig) -> Self {
        self.parked.config = config;
        self
    }

    /// Whether gossiped GPU proofs are checked for revoked certificates.
    pub fn with_gpu_revocation(mut self, config: crate::config::GpuRevocationConfig) -> Self {
        self.gpu_revocation = config;
        self
    }

    /// How block sync paces itself and scores peers.
    pub fn with_block_sync(mut self, config: crate::config::BlockSyncConfig) -> Self {
        self.block_sync = config;
        self
    }

    /// Wires the jail path a replayed `CheckpointEquivocation` log takes.
    pub fn with_equivocation_jailer(
        mut self,
        jailer: Arc<crate::node::EquivocationJailer>,
    ) -> Self {
        self.equivocation_jailer = Some(jailer);
        self
    }

    /// Wires the SLA tally consensus participation is recorded in.
    pub fn with_sla_tally(mut self, tally: Arc<crate::sla_attest::SlaTally>) -> Self {
        self.sla_tally = Some(tally);
        self
    }

    /// Wires the applier of governance-enacted network policy.
    pub fn with_policy_applier(
        mut self,
        applier: Arc<crate::policy_reflection::PolicyApplier>,
    ) -> Self {
        self.policy_applier = Some(applier);
        self
    }

    /// Wires the fee processor that accounts for the gas debited by the
    /// executor. Without it, gas fees leave payer balances and are recorded
    /// nowhere.
    pub fn with_fee_processor(mut self, processor: Arc<tenzro_token::FeeProcessor>) -> Self {
        self.fee_processor = Some(processor);
        self
    }

    /// Returns the current finalized block height as a `BlockHeight`.
    ///
    /// Used by RPC handlers (e.g., `eth_blockNumber`) and consensus to query
    /// the latest finalized height without needing direct storage access.
    pub fn current_height(&self) -> BlockHeight {
        BlockHeight::from(self.current_height)
    }

    /// Returns the hash of the last finalized block.
    pub fn last_block_hash(&self) -> Hash {
        self.last_block_hash
    }

    /// Produces a snapshot of the committed state at `height -
    /// STATE_ROOT_LAG` when one is due: that height starts an epoch, and the
    /// blocks up to `height` that commit its root are all stored. Runs off
    /// the event loop; the trie version it reads is immutable.
    fn maybe_produce_snapshot(&self, height: BlockHeight) {
        let (Some(store), Some(consensus)) = (self.snapshot_store.clone(), self.consensus.as_ref())
        else {
            return;
        };
        let Some(state_height) = height
            .as_u64()
            .checked_sub(tenzro_consensus::STATE_ROOT_LAG)
        else {
            return;
        };
        let starts_epoch = consensus
            .epoch_manager()
            .get_epoch_for_height(BlockHeight::from(state_height))
            .is_some_and(|e| e.start_height.as_u64() == state_height);
        match store.due(state_height, starts_epoch) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                warn!(error = %e, "Snapshot index unreadable");
                return;
            }
        }
        tokio::spawn(async move {
            match store.produce(state_height).await {
                Ok(m) => info!(
                    height = m.height,
                    buckets = m.buckets.len(),
                    state_root = %m.state_root,
                    "Produced state snapshot"
                ),
                Err(e) => {
                    warn!(height = state_height, error = %e, "Failed to produce state snapshot")
                }
            }
        });
    }

    /// Syncs the current block height from storage on startup.
    ///
    /// This ensures the event loop knows where to continue from after a restart,
    /// so block execution resumes at the correct height.
    async fn sync_height_from_storage(&mut self) -> Result<()> {
        let block_store = BlockStoreImpl::new(self.storage.clone())
            .map_err(|e| NodeError::Other(format!("Block store error: {}", e)))?;

        match block_store.latest_height().await {
            // The `latest_height` metadata key can outlive the blocks it points
            // at after a genesis reset (the chain CF is cleared but the key is
            // not), leaving an orphan height with no backing block. Trust the
            // marker only when the block it names is actually present; otherwise
            // the store is effectively empty and we resume from genesis.
            Ok(Some(height))
                if height.0 == 0
                    || block_store
                        .get_block_by_height(height)
                        .await
                        .ok()
                        .flatten()
                        .is_some() =>
            {
                self.current_height = height.0;
                if let Ok(Some(tip)) = block_store.get_block_by_height(height).await {
                    self.last_block_hash = tip.hash();
                    self.last_block_epoch = tip.header.epoch;
                }
                // Publish to the shared atomic so RPC can read it without storage I/O
                self.chain_tip.store(self.current_height, Ordering::Release);
                info!(
                    height = self.current_height,
                    "Synced block height from storage"
                );
            }
            Ok(Some(orphan)) => {
                warn!(
                    orphan_height = orphan.0,
                    "latest_height marker has no backing block (stale after genesis reset); resuming from height 0"
                );
                self.current_height = 0;
                self.chain_tip.store(0, Ordering::Release);
            }
            Ok(None) => {
                self.current_height = 0;
                self.chain_tip.store(0, Ordering::Release);
                info!("No blocks in storage, starting from height 0");
            }
            Err(e) => {
                warn!(error = %e, "Failed to read latest height from storage, starting from 0");
                self.current_height = 0;
                self.chain_tip.store(0, Ordering::Release);
            }
        }

        Ok(())
    }

    /// Main event loop - processes events until shutdown
    ///
    /// This is the core coordination point. It:
    /// 1. Syncs block height from storage on startup
    /// 2. Subscribes to consensus finality notifications (if consensus is active)
    /// 3. Processes RPC/network events (new transactions, manual block submissions)
    /// 4. On finality notification: executes transactions, commits state, persists block
    /// 5. Periodically refreshes peer count (every 30s) so non-validator nodes report
    ///    accurate peer_count even when they never finalize blocks locally.
    pub async fn run(mut self) -> Result<()> {
        info!("Event loop starting");

        // Sync block height from persistent storage
        self.sync_height_from_storage().await?;
        // The consensus driver bases an epoch start on the last executed
        // block: hand it the tip this node executed before it stopped.
        if let Some(consensus) = self.consensus.clone() {
            let root = match self.state_trie.root_at(self.current_height) {
                Ok(Some(root)) => Some(root),
                _ => match BlockStoreImpl::new(self.storage.clone()) {
                    Ok(store) => store
                        .get_block_by_height(BlockHeight(self.current_height))
                        .await
                        .ok()
                        .flatten()
                        .map(|b| b.header.state_root),
                    Err(_) => None,
                },
            };
            if let Some(root) = root {
                consensus.seed_executed(self.current_height, self.last_block_hash, root);
            }
        }

        let (ingress_tx, ingress_rx) = mpsc::channel(INGRESS_QUEUE);
        let (parked_tx, parked_rx) = mpsc::channel(PARKED_BACK_QUEUE);
        tokio::spawn(
            Ingress {
                chain_id: self.vm_runtime.config().chain_id,
                storage: self.storage.clone(),
                state_adapter: self.state_adapter.clone(),
                consensus: self.consensus.clone(),
                chain_tip: self.chain_tip.clone(),
                parked: parked_tx,
                gpu_revocation: self.gpu_revocation.clone(),
            }
            .run(ingress_rx),
        );
        self.ingress = Some(ingress_tx);
        self.parked_rx = Some(parked_rx);

        // Block sync over the iroh endpoint: serve the blocks this node has,
        // and catch up from committee members and connected peers when
        // behind. Neither waits for
        // this node's own consensus, which may itself need the blocks.
        if let (Some(resolver), Some(consensus)) =
            (self.iroh_resolver.clone(), self.consensus.clone())
        {
            resolver
                .block_sync_server()
                .set(Arc::new(crate::block_sync::BlockSyncService::new(
                    self.storage.clone(),
                    consensus.clone(),
                )));
            let (importer_tx, importer_rx) = mpsc::channel::<crate::block_sync::BlockImport>(64);
            self.block_import_rx = Some(importer_rx);
            let network = self.network.clone();
            let named = self.sync_peers.clone();
            let connected: crate::block_sync::ConnectedPeers = Arc::new(move || {
                let mut peers = named.clone();
                if let Some(n) = network.as_ref() {
                    peers.extend(n.gossip_peers().iter().map(|p| *p.as_bytes()));
                }
                peers
            });
            let engine = crate::block_sync::BlockSyncEngine::new(
                resolver.endpoint().clone(),
                self.storage.clone(),
                consensus,
                importer_tx,
                self.block_sync.clone(),
                connected,
            );
            tokio::spawn(engine.run(self.shutdown_tx.subscribe()));
            info!("Block-sync engine spawned");
        }

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        // Periodic peer-count refresh: runs every 3 seconds regardless of block production.
        // Without this, non-validator nodes (model-provider, light clients) that never call
        // handle_block_finalized() would always report peer_count=0 in /status even when
        // they have active P2P connections. The interval is deliberately short (was 30s) so
        // the desktop UI status bar flips from "Connecting · Peers 0" to "Connected" within a
        // few seconds of the first peer handshake instead of lagging up to half a minute —
        // `peer_count()` is a cheap in-memory gossip query, so polling at 3s is fine.
        let mut held_retry = tokio::time::interval(Duration::from_millis(
            self.parked.config.retry_interval_ms.max(1),
        ));
        held_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut reannounce = tokio::time::interval(REANNOUNCE_TICK);
        reannounce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut peer_refresh = tokio::time::interval(std::time::Duration::from_secs(3));
        peer_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Heartbeat: re-announce locally served models every 60s so peers know they're still alive.
        // Also evicts expired entries from network_models.
        let mut model_heartbeat = tokio::time::interval(std::time::Duration::from_secs(60));
        model_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Heartbeat: evict expired provider entries every 60s.
        let mut provider_heartbeat = tokio::time::interval(std::time::Duration::from_secs(60));
        provider_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Proof of life: a signed heartbeat every few seconds, so peers stop
        // routing to this node within seconds of it failing.
        let mut liveness_heartbeat =
            tokio::time::interval(crate::provider_heartbeat::HEARTBEAT_INTERVAL);
        liveness_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Heartbeat: announce locally held iroh blobs every 60s so peers can
        // populate their blob-provider hint caches and fetch
        // `tenzro://blob/...` URIs without an explicit provider hint.
        let mut blob_heartbeat =
            tokio::time::interval(std::time::Duration::from_secs(BLOB_HEARTBEAT_SECS));
        blob_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Announcements are signed on these lanes, never in the loop: a
        // hardware batch takes seconds and the loop also drains blocks.
        let lanes = crate::announce::SigningLanes::new();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Event loop shutting down");
                    break;
                }
                // Block-sync engine has a peer-served range ready to import,
                // with the checkpoint evidence covering it. Nothing in it is
                // trusted until the certificate verifies.
                //
                // Branch is gated by `block_import_rx.is_some()`: nodes
                // without a network service have no engine and therefore no
                // channel — the inner future stays pending forever.
                Some(import) = async {
                    match self.block_import_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<crate::block_sync::BlockImport>>().await,
                    }
                } => {
                    let crate::block_sync::BlockImport { blocks, checkpoints, certificate, result } = import;
                    let first = blocks.first().map(|b| b.height().0).unwrap_or(0);
                    let outcome = self.handle_block_imported_from_sync(blocks, checkpoints, certificate).await;
                    let reply = match outcome {
                        Ok(()) => Ok(()),
                        Err(e) => Err(format!("import from height {} failed: {}", first, e)),
                    };
                    // The engine drops the receiver if it has lost interest
                    // (peer disconnected, sync run aborted) — silent send
                    // failure is not an error here.
                    let _ = result.send(reply);
                }
                // Periodic peer count refresh — independent of block finalization.
                // Ensures /status always reflects the current P2P connection state.
                // Gossiped transactions refused for a reason that passes are
                // offered to the mempool again.
                _ = held_retry.tick() => {
                    self.offer_parked_again();
                }
                // Transactions this node admitted that no block has taken yet
                // are published again.
                _ = reannounce.tick() => {
                    self.publish_announced_again().await;
                }
                _ = peer_refresh.tick() => {
                    if let Some(ref network) = self.network {
                        let count = network.peer_count() as u64;
                        self.metrics.set_peer_count(count);
                        debug!(peer_count = count, "Periodic peer count refresh");
                    }
                }
                // Model heartbeat: re-announce served models + evict expired network entries
                _ = model_heartbeat.tick() => {
                    // 1. Evict expired network model entries
                    if let Some(ref nm) = self.network_models {
                        let now = std::time::Instant::now();
                        nm.retain(|_key, entry| {
                            let ttl = std::time::Duration::from_secs(entry.registration.ttl_secs);
                            now.duration_since(entry.last_seen) < ttl
                        });
                    }

                    // 1b. Evict expired model service instances (network endpoints)
                    // Removes from in-memory DashMap AND persists deletion to RocksDB
                    if let Some(ref services) = self.model_services {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let ttl = 300; // 5 minutes
                        let expired: Vec<String> = services.iter()
                            .filter(|e| {
                                let svc = e.value();
                                matches!(svc.location, tenzro_types::model::ModelLocation::Network)
                                    && svc.last_seen > 0
                                    && now.saturating_sub(svc.last_seen) > ttl
                            })
                            .map(|e| e.key().clone())
                            .collect();
                        for id in &expired {
                            services.remove(id);
                            let _ = self.storage.delete(CF_MODEL_SERVICES, id.as_bytes());
                            info!("Removed expired network model service: {}", id);
                        }
                    }

                    // 1c. Idle-TTL cleanup for LOCAL model service instances.
                    // If the ModelRuntime is not currently serving the model AND
                    // the entry has been silent for >= 1 hour, evict it and
                    // clear the corresponding served_models flag.
                    // Runtime-live entries have their last_seen refreshed so the
                    // idle clock resets on every heartbeat.
                    #[cfg(feature = "inference")]
                    if let (Some(services), Some(runtime)) =
                        (&self.model_services, &self.model_runtime)
                    {
                        const IDLE_TTL_SECS: u64 = 3600; // 1 hour
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let local_entries: Vec<(String, String, u64)> = services.iter()
                            .filter(|e| matches!(
                                e.value().location,
                                tenzro_types::model::ModelLocation::Local,
                            ))
                            .map(|e| (
                                e.key().clone(),
                                e.value().model_id.clone(),
                                e.value().last_seen,
                            ))
                            .collect();

                        let mut evicted = 0usize;
                        for (instance_id, model_id, last_seen) in local_entries {
                            if runtime.is_loaded(&model_id) {
                                // Runtime-live — refresh last_seen and persist
                                if let Some(mut svc) = services.get_mut(&instance_id)
                                    && svc.last_seen < now {
                                        svc.last_seen = now;
                                        if let Ok(data) = serde_json::to_vec(svc.value()) {
                                            let _ = self.storage.put(
                                                CF_MODEL_SERVICES,
                                                instance_id.as_bytes(),
                                                &data,
                                            );
                                        }
                                    }
                                continue;
                            }

                            let idle = last_seen == 0
                                || now.saturating_sub(last_seen) >= IDLE_TTL_SECS;
                            if !idle {
                                continue;
                            }

                            services.remove(&instance_id);
                            let _ = self.storage.delete(
                                CF_MODEL_SERVICES,
                                instance_id.as_bytes(),
                            );
                            evicted += 1;

                            // Clear served_models flag + CF_MODELS if no other
                            // live Local instance exists for this model.
                            let still_served_locally = services.iter().any(|e| {
                                e.value().model_id == model_id
                                    && matches!(
                                        e.value().location,
                                        tenzro_types::model::ModelLocation::Local,
                                    )
                            });
                            if !still_served_locally {
                                if let Some(ref served) = self.served_models {
                                    served.remove(&model_id);
                                }
                                if let Some(ref lt) = self.load_tracker {
                                    lt.unregister_model(&model_id);
                                }
                                let _ = self.storage.delete(
                                    CF_MODELS,
                                    format!("served:{}", model_id).as_bytes(),
                                );
                                info!(
                                    "Cleared idle local serving state for model: {}",
                                    model_id,
                                );
                            }
                        }
                        if evicted > 0 {
                            info!(
                                "Evicted {} idle local model service(s) after 1h TTL",
                                evicted,
                            );
                        }
                    }

                    // 1b. Keep THIS node's own provider entry healthy so intent
                    // dispatch (chatByIntent) keeps routing to locally-served
                    // models. Independent of network advertisement — local
                    // serving works even when AI is private, and the entry
                    // otherwise goes stale (no gossip heartbeat of its own) and
                    // is dropped by the router's health filter.
                    if let (Some(pm), Some(addr)) =
                        (&self.provider_manager, &self.local_provider_address)
                    {
                        let _ = pm.heartbeat(addr);
                    }

                    // 2. Re-announce locally served models via gossip.
                    // Requires the provider-announcement context (provider address +
                    // signer) so the heartbeat carries the same `provider` key and
                    // signature that consumers require — an unsigned or provider-empty
                    // heartbeat is dropped on ingest and never refreshes the TTL.
                    //
                    // Each model is announced when its effective visibility (its
                    // override, else the node's visibility) is public or gated.
                    // Read per tick, so a change to the node's visibility
                    // re-announces or stops announcing every model without an
                    // override on the next heartbeat.
                    if let (Some(network), Some(served), Some(ctx), Some(signer)) = (
                        &self.network,
                        &self.served_models,
                        &self.provider_announcement_ctx,
                        &self.announce_identity,
                    ) {
                        let provider_address = ctx.provider_address.clone();
                        let signer = signer.clone();
                        let pricing = self.provider_pricing.as_ref().map(|p| p.read().clone());
                        let schedule = self.provider_schedule.as_ref().map(|s| s.read().clone());

                        // Gathered, ordered and sliced before anything is
                        // built. A node serving many models used to publish one
                        // message per model at the instant of the tick; the
                        // rotation makes that cost the same whatever it serves,
                        // and the stable order is what stops the cursor
                        // stepping over a model indefinitely.
                        let node_visibility = self.node_visibility();
                        let mut announceable: Vec<String> = served
                            .iter()
                            // Private models are never announced — no
                            // heartbeat, no TTL refresh on remote nodes, no
                            // discovery.
                            .filter(|e| {
                                tenzro_types::Visibility::resolve(*e.value(), node_visibility)
                                    .is_announced()
                            })
                            .map(|e| e.key().clone())
                            .collect();
                        announceable.sort();

                        let plan = self.model_rotation.plan(announceable.len());
                        if plan.is_empty() {
                            continue;
                        }
                        let mut messages = Vec::new();

                        for model_id_key in announceable[plan.range.clone()].iter() {
                            let Some(entry) = served.get(model_id_key) else {
                                // Unserved between gathering and sending. Its
                                // absence is the announcement.
                                continue;
                            };
                            let model_id = entry.key().clone();
                            let visibility =
                                tenzro_types::Visibility::resolve(*entry.value(), node_visibility);
                            if !visibility.is_announced() {
                                // Made private between gathering and sending.
                                continue;
                            }
                            let pricing_info = pricing
                                .as_ref()
                                .map(|p| p.card_for(&model_id).clone())
                                .unwrap_or_default();
                            let msg_schedule = schedule.as_ref().and_then(|s| {
                                if s.enabled {
                                    let days: Vec<u8> = s.days_of_week.iter()
                                        .enumerate()
                                        .filter_map(|(i, &enabled)| if enabled { Some(i as u8) } else { None })
                                        .collect();
                                    Some(tenzro_network::ModelSchedule {
                                        enabled: true,
                                        start_hour: s.start_hour,
                                        end_hour: s.end_hour,
                                        timezone: s.timezone.clone(),
                                        days_of_week: days,
                                    })
                                } else {
                                    None
                                }
                            });
                            let reg = tenzro_network::ModelRegistrationMessage {
                                model_id: model_id.clone(),
                                name: model_id.clone(),
                                description: String::new(),
                                modality: "text".to_string(),
                                category: String::new(),
                                parameters: String::new(),
                                context_length: 0,
                                provider: provider_address.clone(),
                                pricing: pricing_info,
                                schedule: msg_schedule,
                                visibility: visibility.as_str().to_string(),
                                ttl_secs: plan.ttl_secs,
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                withdrawn: false,
                                iroh_endpoint_id: self
                                    .iroh_resolver
                                    .as_ref()
                                    .map(|r| r.endpoint_id().to_string())
                                    .unwrap_or_default(),
                                ..Default::default()
                            };
                            messages.push(reg);
                        }

                        let (network, signer, pace) = (network.clone(), signer.clone(), plan.pace);
                        let (total, ttl_secs) = (announceable.len(), plan.ttl_secs);
                        lanes.models.submit(move || {
                            let mut out = Vec::new();
                            for mut reg in messages {
                                if let Err(e) = tenzro_network::SignedAnnouncement::sign(&mut reg, signer.machine_did(), signer.signer()) {
                                    warn!(error = %e, model_id = %reg.model_id, "Skipping model heartbeat: signing failed");
                                    continue;
                                }
                                out.push(tenzro_network::NetworkMessage::new(
                                    tenzro_network::MessagePayload::ModelRegistration(reg),
                                ));
                            }
                            debug!(announced = out.len(), total, ttl_secs, "Model heartbeat");
                            crate::announce::emit_paced(network, "tenzro/models", out, pace);
                        });
                    }
                }
                // Provider heartbeat: evict expired network_providers entries every 60s
                // AND re-broadcast a `ProviderAnnouncementMessage` so peers learn about
                // this node's served models, hardware envelope, and declared region.
                _ = provider_heartbeat.tick() => {
                    if let Some(ref np) = self.network_providers {
                        let now = std::time::Instant::now();
                        // Collect the provider addresses evicted this pass so
                        // the ProviderManager can prune them too — an expired
                        // gossip entry must stop being routable, not just
                        // vanish from the discovery cache.
                        let mut evicted: Vec<String> = Vec::new();
                        np.retain(|_key, entry| {
                            let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                            let alive = now.duration_since(entry.last_seen) < ttl;
                            if !alive {
                                evicted.push(entry.announcement.provider_address.clone());
                            }
                            alive
                        });
                        if let Some(ref pm) = self.provider_manager {
                            for addr_hex in &evicted {
                                if let Ok(address) =
                                    tenzro_types::primitives::Address::from_hex(addr_hex)
                                {
                                    pm.remove_provider(&address);
                                }
                            }
                        }
                    }

                    // Broadcast our own provider announcement (only if context +
                    // announce signer wired — unsigned announcements are rejected
                    // by every consumer).
                    if let (Some(network), Some(ctx), Some(signer)) = (
                        &self.network,
                        &self.provider_announcement_ctx,
                        &self.announce_identity,
                    ) {
                        // Private models are excluded from provider announcements;
                        // gated ones are listed and flagged as key-required.
                        let (served, key_required_models) = self.announced_models();

                        // A storage-serving node advertises its iroh EndpointId
                        // so HRW replica self-selection has a stable candidate id
                        // per peer. Empty on nodes without a bound resolver.
                        let iroh_endpoint_id = self
                            .iroh_resolver
                            .as_ref()
                            .map(|r| r.endpoint_id().to_string())
                            .unwrap_or_default();

                        // Advertised capacity is read live from the self entry
                        // in the ProviderManager each tick — MoE expert-shard
                        // declarations installed after startup (expert/gate
                        // loads) must ride the next heartbeat, so the static
                        // context snapshot is only the no-entry fallback.
                        let capacity = self
                            .provider_manager
                            .as_ref()
                            .and_then(|pm| {
                                let hexstr = ctx
                                    .provider_address
                                    .strip_prefix("0x")
                                    .unwrap_or(&ctx.provider_address);
                                tenzro_types::primitives::Address::from_hex(hexstr)
                                    .ok()
                                    .and_then(|addr| pm.get_provider(&addr).ok())
                            })
                            .map(|p| {
                                let mut c = p.capacity.advertised();
                                c.verifiable_inference =
                                    c.verifiable_inference || ctx.capacity.verifiable_inference;
                                // Node config is the single source of truth for
                                // this node's jurisdiction claim — a self
                                // provider entry never overrides it.
                                c.jurisdiction = ctx.capacity.jurisdiction.clone();
                                c.verification = ctx.capacity.verification.clone();
                                c.standby_fee_per_hour = ctx.capacity.standby_fee_per_hour;
                                c
                            })
                            .unwrap_or_else(|| ctx.capacity.clone());

                        // Refresh the advertised warm-prefix count from the
                        // serving runtime each tick. Only the count rides the
                        // announcement; which prefixes are warm is answered to
                        // a salted probe (see `PrefixCacheSummary`).
                        let mut capacity = capacity;
                        #[cfg(feature = "inference")]
                        if let Some(ref rt) = self.model_runtime {
                            capacity.prefix_cache = rt.warm_prefix_summary();
                            capacity.standby_models =
                                rt.standby_models().into_iter().map(|m| m.model_id).collect();
                            // Speculative capability is read live for the same
                            // reason the warm-prefix summary is: drafters load
                            // asynchronously (the GGUF may still be
                            // downloading when the node starts announcing), so
                            // a startup snapshot pins `mtp_enabled` to false
                            // permanently and no consumer can ever route
                            // speculative work here. Advertising it is what
                            // makes the capability usable without the operator
                            // configuring anything.
                            //
                            // Computed over `served` — the models actually on
                            // this announcement — not over every drafter in
                            // memory. Consumers treat `mtp_enabled` as a hard
                            // filter and the serving path answers a
                            // non-speculative model with `MtpUnavailable`, so
                            // a node-wide claim covering a model that cannot
                            // honour it turns a preference into a failed
                            // request.
                            capacity.mtp_enabled = rt.any_can_speculate(&served);
                        }

                        // In-flight requests across the announced models, read
                        // live from the load tracker every inference path
                        // acquires a slot from, so consumers see how busy this
                        // node is rather than a constant.
                        if let Some(ref lt) = self.load_tracker {
                            capacity.active_requests = served
                                .iter()
                                .filter_map(|m| lt.snapshot(m))
                                .fold(0u32, |acc, s| acc.saturating_add(s.active_requests));
                        }

                        let mut ann = tenzro_network::ProviderAnnouncementMessage {
                            provider_address: ctx.provider_address.clone(),
                            provider_type: ctx.provider_type.clone(),
                            served_models: served,
                            key_required_models,
                            capabilities: ctx.capabilities.clone(),
                            status: "active".to_string(),
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            ttl_secs: ctx.ttl_secs,
                            runtime_support: tenzro_types::RuntimeSupport::default(),
                            network_profile: tenzro_types::NodeNetworkProfile::default(),
                            trust_profile: tenzro_types::TrustProfile {
                                // Report the root this node actually started
                                // with. Left empty if identity has not been
                                // derived, which consumers read as the weakest
                                // tier rather than the strongest.
                                identity_root: tenzro_network::service::identity_root()
                                    .map(|r| r.as_str().to_string())
                                    .unwrap_or_default(),
                                ..Default::default()
                            },
                            worker_roles: Vec::new(),
                            hardware: ctx.hardware.clone(),
                            capacity,
                            region: ctx.region.clone(),
                            iroh_endpoint_id,
                            cluster_profile: ctx.cluster_identity.as_ref().and_then(|c| c.profile()),
                            machine_did: String::new(),
                            operator_did: ctx.agent_serving.as_ref().map(|(_, o)| o.clone()),
                            signature: None,
                            // Filled by sign_bound below.
                            endpoint_binding_sig: Vec::new(),
                        };
                        // Strip what is not announced before signing, rather
                        // than suppressing the whole announcement: a private
                        // node may still announce a resource whose own override
                        // is public or gated.
                        {
                            let node_visibility = self.node_visibility();
                            let node_announced = node_visibility.is_announced();
                            let models_announced = !ann.served_models.is_empty();
                            let storage_announced = node_announced;
                            if !node_announced && !models_announced {
                                ann.capacity.max_concurrent_requests = 0;
                                ann.cluster_profile = None;
                            }
                            ann.capabilities.retain(|c| match c.as_str() {
                                "inference" | "ai" => node_announced || models_announced,
                                "storage" => storage_announced,
                                _ => node_announced,
                            });

                            // Everything hidden means there is nothing to say.
                            // Skip the heartbeat rather than publish an empty
                            // record that still tells peers this node exists.
                            let nothing_left =
                                ann.capabilities.is_empty() && ann.served_models.is_empty();
                            if nothing_left {
                                continue;
                            }
                        }
                        // Bind the announce key to this node's iroh endpoint.
                        // Without it the signature proves only that somebody
                        // signed the struct, not that they own the endpoint
                        // inside it — which would let a peer publish another
                        // node's endpoint and inherit its advertised
                        // capability. A node with no endpoint bound announces
                        // unbound, and consumers read it as unproven.
                        let endpoint_key = self
                            .iroh_resolver
                            .as_ref()
                            .map(|r| r.endpoint().secret_key().clone());
                        let (network, signer) = (network.clone(), signer.clone());
                        lanes.providers.submit(move || {
                            let mut ann = ann;
                            let bound = match endpoint_key.as_ref() {
                                Some(key) => ann.sign_bound(signer.machine_did(), signer.signer(), key),
                                None => tenzro_network::SignedAnnouncement::sign(&mut ann, signer.machine_did(), signer.signer()),
                            }
                            .map_err(|e| e.to_string());
                            if let Err(e) = bound {
                                warn!(error = %e, "Skipping provider announcement: signing failed");
                                return;
                            }
                            crate::announce::emit_paced(
                                network,
                                "tenzro/providers",
                                vec![tenzro_network::NetworkMessage::new(
                                    tenzro_network::MessagePayload::ProviderAnnouncement(ann),
                                )],
                                std::time::Duration::ZERO,
                            );
                        });
                    }
                }
                _ = liveness_heartbeat.tick() => {
                    if let (Some(network), Some(ctx), Some(signer), Some(resolver)) = (
                        &self.network,
                        &self.provider_announcement_ctx,
                        &self.announce_identity,
                        &self.iroh_resolver,
                    ) {
                        let (served, _) = self.announced_models();
                        let load = crate::provider_heartbeat::model_load(
                            &served,
                            self.load_tracker.as_deref(),
                            self.lifecycle.as_deref(),
                        );
                        let provider_address = ctx.provider_address.clone();
                        let endpoint_id = resolver.endpoint_id().to_string();
                        let (network, signer) = (network.clone(), signer.clone());
                        lanes.liveness.submit(move || {
                            match crate::provider_heartbeat::build(
                                &provider_address,
                                &endpoint_id,
                                false,
                                load,
                                &signer,
                            ) {
                                Ok(hb) => crate::announce::emit_paced(
                                    network,
                                    "tenzro/providers",
                                    vec![tenzro_network::NetworkMessage::new(
                                        tenzro_network::MessagePayload::ProviderHeartbeat(hb),
                                    )],
                                    std::time::Duration::ZERO,
                                ),
                                Err(e) => warn!(error = %e, "Skipping provider heartbeat: signing failed"),
                            }
                        });
                    }
                }
                // Blob availability heartbeat: enumerate the local iroh blob
                // store and broadcast signed announcements on `tenzro/blobs`.
                // Skipped when the resolver / network / signer are not wired
                // (unsigned announcements are rejected by every consumer).
                _ = blob_heartbeat.tick() => {
                    if let (Some(network), Some(resolver), Some(signer)) = (
                        &self.network,
                        &self.iroh_resolver,
                        &self.announce_identity,
                    ) {
                        let hashes = match resolver.local_blob_hashes().await {
                            Ok(h) => h,
                            Err(e) => {
                                debug!(error = %e, "Skipping blob announcement: blob enumeration failed");
                                continue;
                            }
                        };
                        if hashes.is_empty() {
                            continue;
                        }

                        let endpoint_id = resolver.endpoint_id().to_string();

                        // Sorted so the rotation is stable across ticks. An
                        // enumeration order that changes between calls would
                        // let the cursor skip hashes indefinitely.
                        let mut hashes = hashes;
                        hashes.sort_unstable();
                        hashes.dedup();

                        let plan = self.blob_rotation.plan(hashes.len());
                        if plan.is_empty() {
                            continue;
                        }
                        let slice = &hashes[plan.range.clone()];

                        let mut messages = Vec::new();
                        for chunk in slice.chunks(HASHES_PER_ANNOUNCEMENT) {
                            let ann = tenzro_network::BlobAnnouncementMessage {
                                endpoint_id: endpoint_id.clone(),
                                blob_hashes: chunk.to_vec(),
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                ttl_secs: plan.ttl_secs,
                                machine_did: String::new(),
                                signature: None,
                            };
                            messages.push(ann);
                        }

                        let (network, signer, pace) = (network.clone(), signer.clone(), plan.pace);
                        let (announced, total, cursor, ttl_secs) = (
                            slice.len(),
                            hashes.len(),
                            self.blob_rotation.cursor(),
                            plan.ttl_secs,
                        );
                        lanes.blobs.submit(move || {
                            let mut out = Vec::new();
                            for mut ann in messages {
                                if let Err(e) = tenzro_network::SignedAnnouncement::sign(&mut ann, signer.machine_did(), signer.signer()) {
                                    warn!(error = %e, "Skipping blob announcement: signing failed");
                                    break;
                                }
                                out.push(tenzro_network::NetworkMessage::new(
                                    tenzro_network::MessagePayload::BlobAnnouncement(ann),
                                ));
                            }
                            debug!(announced, total, cursor, ttl_secs, "Blob availability heartbeat");
                            crate::announce::emit_paced(network, "tenzro/blobs", out, pace);
                        });
                    }
                }
                // A segment this validator's consensus ordered: build its
                // block, execute it, report the result back.
                segment = async {
                    match self.ordered_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(segment) = segment {
                        // With it, every segment that queued meanwhile.
                        let mut run = vec![segment];
                        if let Some(rx) = self.ordered_rx.as_mut() {
                            while run.len() < MAX_SEGMENTS_PER_RUN {
                                match rx.try_recv() {
                                    Ok(s) => run.push(s),
                                    Err(_) => break,
                                }
                            }
                        }
                        self.execute_ordered_run(run).await;
                    }
                }
                // A certificate: import the uncertified blocks it covers.
                certificate = async {
                    match self.certificates_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(certificate) = certificate
                        && let Err(e) = self.handle_certificate(certificate).await {
                            warn!("Certificate import failed: {}", e);
                        }
                }
                // Held transactions the ingress task hands back.
                held = async {
                    match self.parked_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(tx) = held {
                        self.parked.hold(tx, Instant::now());
                    }
                }
                // Handle events from RPC/network
                Some(event) = self.event_rx.recv() => {
                    match event {
                        NodeEvent::NewTransaction(mut tx) => {
                            let hash = tx.hash();
                            match self.ingress.as_ref().map(|i| i.try_send(tx)) {
                                Some(Ok(())) => {}
                                Some(Err(mpsc::error::TrySendError::Full(_))) => {
                                    debug!(%hash, "ingress full: transaction dropped");
                                }
                                Some(Err(mpsc::error::TrySendError::Closed(_))) | None => {
                                    warn!(%hash, "ingress stopped: transaction dropped");
                                }
                            }
                        }
                        NodeEvent::LocallyAdmittedTransaction(tx) => {
                            if let Err(e) = self.handle_locally_admitted_transaction(tx).await {
                                error!("Failed to handle locally-admitted transaction: {}", e);
                            }
                        }
                        NodeEvent::PublishedTransaction(hash) => {
                            self.announced.published(hash, Instant::now());
                        }
                        NodeEvent::NetworkBlock(block, verdict) => {
                            // Held until a certificate covering it arrives; see
                            // `handle_network_block`.
                            if let Err(e) = self.handle_network_block(block, verdict).await {
                                warn!("Refused network block: {}", e);
                            }
                        }
                        NodeEvent::NetworkCertificate(published) => {
                            // A validator's certificates come from its own
                            // consensus; a follower imports under these. A
                            // validator whose epoch the network has left
                            // becomes a follower here.
                            let tenzro_consensus::PublishedCertificate { certificate: cert, sessions } = *published;
                            if let Some(c) = self.consensus.as_ref() {
                                c.admit_sessions(cert.checkpoint.epoch, sessions);
                                c.on_network_certificate(&cert);
                            }
                            if !self.orders_blocks()
                                && let Err(e) = self.handle_certificate(cert).await {
                                    debug!("Certificate from the network not imported: {}", e);
                                }
                        }
                        NodeEvent::ModelAnnouncement(reg) => {
                            if let Err(e) = self.verify_announcement(&reg) {
                                warn!(
                                    model_id = %reg.model_id,
                                    provider = %reg.provider,
                                    error = %e,
                                    "Rejecting model announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(reg.timestamp, reg.ttl_secs) {
                                warn!(
                                    model_id = %reg.model_id,
                                    provider = %reg.provider,
                                    error = %e,
                                    "Rejecting model announcement (replay window)"
                                );
                            } else if let Some(ref nm) = self.network_models {
                                let key = format!("{}:{}", reg.model_id, reg.provider);
                                // First-seen identity pinning + monotonic timestamps:
                                // the map key is attacker-choosable, so a signature
                                // alone only proves which machine signed. Pin the
                                // machine DID that first claimed this (model,
                                // provider) pair and reject updates — including
                                // withdrawals — signed as any other identity, plus
                                // replays of older signed states.
                                // Read prior fields into locals and drop the Ref
                                // before mutating the same map (DashMap deadlock rule).
                                let prior = nm
                                    .get(&key)
                                    .map(|e| (e.registration.machine_did.clone(), e.registration.timestamp));
                                if let Some((pinned_did, prev_ts)) = prior {
                                    if pinned_did != reg.machine_did {
                                        warn!(
                                            model_id = %reg.model_id,
                                            provider = %reg.provider,
                                            "Rejecting model announcement (signed as another identity than the pinned one)"
                                        );
                                        continue;
                                    }
                                    if reg.timestamp <= prev_ts {
                                        debug!(
                                            model_id = %reg.model_id,
                                            provider = %reg.provider,
                                            "Dropping model announcement (non-monotonic timestamp)"
                                        );
                                        continue;
                                    }
                                }
                                if reg.withdrawn {
                                    nm.remove(&key);
                                    // Remove from persistent storage
                                    {
                                        let storage_key = format!("net_model:{}", key);
                                        let _ = self.storage.delete(tenzro_storage::CF_MODEL_SERVICES, storage_key.as_bytes());
                                    }
                                    info!(
                                        model_id = %reg.model_id,
                                        provider = %reg.provider,
                                        "Network model withdrawn"
                                    );
                                } else if tenzro_types::Visibility::parse(&reg.visibility)
                                    .is_some_and(|v| v.is_announced())
                                {
                                    nm.insert(key.clone(), crate::node::NetworkModelEntry {
                                        registration: reg.clone(),
                                        last_seen: std::time::Instant::now(),
                                    });
                                    // Persist to RocksDB so model endpoints survive restart
                                    {
                                        let storage_key = format!("net_model:{}", key);
                                        if let Ok(bytes) = serde_json::to_vec(&reg) {
                                            let _ = self.storage.put(tenzro_storage::CF_MODEL_SERVICES, storage_key.as_bytes(), &bytes);
                                        }
                                    }
                                    info!(
                                        model_id = %reg.model_id,
                                        provider = %reg.provider,
                                        endpoint_id = %reg.iroh_endpoint_id,
                                        "Network model discovered via gossip (persisted)"
                                    );
                                }
                            }
                        }
                        NodeEvent::ProviderHeartbeat(hb) => {
                            if let (Some(np), Some(pm)) = (&self.network_providers, &self.provider_manager) {
                                let pinned = np.get(&hb.iroh_endpoint_id).map(|e| {
                                    (e.announcement.provider_address.clone(), e.announcement.machine_did.clone())
                                });
                                let key = pinned.as_ref().and_then(|(_, did)| self.announcer_key(did).ok());
                                match crate::provider_heartbeat::accept(
                                    &hb,
                                    pinned.as_ref().zip(key.as_ref()).map(|((a, d), k)| (a.as_str(), d.as_str(), k)),
                                    chrono::Utc::now().timestamp_millis(),
                                    pm.liveness(),
                                ) {
                                    Ok(_) => {
                                        if let Some(mut entry) = np.get_mut(&hb.iroh_endpoint_id) {
                                            entry.live_load = Some((hb.timestamp, hb.model_load.clone()));
                                        }
                                    }
                                    Err(e) => {
                                        debug!(endpoint = %hb.iroh_endpoint_id, error = %e, "Dropping provider heartbeat");
                                    }
                                }
                            }
                        }
                        NodeEvent::ProviderAnnouncement(ann) => {
                            // Providers are keyed by their iroh endpoint, so an
                            // announcement must prove it speaks for the
                            // endpoint it names. A wrong binding is a forgery
                            // attempt; a missing one names no endpoint anyone
                            // can hold it to. Both are dropped.
                            match ann.verify_endpoint_binding() {
                                Ok(true) => {}
                                Ok(false) => {
                                    debug!(
                                        provider = %ann.provider_address,
                                        "Dropping provider announcement with no endpoint binding"
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    warn!(
                                        endpoint = %ann.iroh_endpoint_id,
                                        error = %e,
                                        "Rejecting provider announcement (endpoint binding invalid \
                                         — this announcement claims an endpoint its key does not own)"
                                    );
                                    continue;
                                }
                            }
                            if let Err(e) = self.verify_announcement(&ann) {
                                warn!(
                                    endpoint = %ann.iroh_endpoint_id,
                                    provider_type = %ann.provider_type,
                                    error = %e,
                                    "Rejecting provider announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(ann.timestamp, ann.ttl_secs) {
                                warn!(
                                    endpoint = %ann.iroh_endpoint_id,
                                    error = %e,
                                    "Rejecting provider announcement (replay window)"
                                );
                            } else if let Some(Err(e)) =
                                ann.region.as_deref().map(tenzro_types::provider_listing::coarse_region)
                            {
                                debug!(
                                    endpoint = %ann.iroh_endpoint_id,
                                    error = %e,
                                    "Rejecting provider announcement (region finer than a country)"
                                );
                            } else if let Some(ref np) = self.network_providers {
                                // First-seen identity pinning + monotonic timestamps
                                // (see ModelAnnouncement handler for rationale).
                                let prior = np
                                    .get(&ann.iroh_endpoint_id)
                                    .map(|e| (e.announcement.machine_did.clone(), e.announcement.timestamp));
                                if let Some((pinned_did, prev_ts)) = prior {
                                    if pinned_did != ann.machine_did {
                                        warn!(
                                            endpoint = %ann.iroh_endpoint_id,
                                            "Rejecting provider announcement (signed as another identity than the pinned one)"
                                        );
                                        continue;
                                    }
                                    if ann.timestamp <= prev_ts {
                                        debug!(
                                            endpoint = %ann.iroh_endpoint_id,
                                            "Dropping provider announcement (non-monotonic timestamp)"
                                        );
                                        continue;
                                    }
                                }
                                let live_load = np.get(&ann.iroh_endpoint_id).and_then(|e| e.live_load.clone());
                                np.insert(ann.iroh_endpoint_id.clone(),crate::node::NetworkProviderEntry {
                                    announcement: ann.clone(),
                                    last_seen: std::time::Instant::now(),
                                    live_load,
                                });
                                info!(
                                    endpoint = %ann.iroh_endpoint_id,
                                    provider_type = %ann.provider_type,
                                    "Network provider discovered via gossip"
                                );

                                // Bridge the verified announcement into the
                                // ProviderManager so the InferenceRouter can
                                // score and dispatch to this provider by its
                                // advertised HardwareCapabilities. Skip
                                // providers with no reachable endpoint, and
                                // providers that neither serve models nor
                                // declare MoE expert shards — those cannot be
                                // routed to. A pure expert holder (empty
                                // served_models, non-empty moe_holdings) must
                                // be admitted or the MoE shard view never sees
                                // it.
                                if let Some(ref pm) = self.provider_manager
                                    && !ann.iroh_endpoint_id.is_empty()
                                    && (!ann.served_models.is_empty()
                                        || !ann.capacity.moe_holdings.is_empty()
                                        || !ann.capacity.moe_roles.is_empty())
                                    && let Ok(address) =
                                        tenzro_types::primitives::Address::from_hex(&ann.provider_address)
                                {
                                    let has_tee = ann.hardware.tee_available
                                        || ann
                                            .capabilities
                                            .iter()
                                            .any(|c| c.contains("tee"));
                                    let status = match ann.status.as_str() {
                                        "active" | "" => {
                                            tenzro_types::model::ProviderStatus::Active
                                        }
                                        "draining" | "inactive" => {
                                            tenzro_types::model::ProviderStatus::Inactive
                                        }
                                        _ => tenzro_types::model::ProviderStatus::Active,
                                    };
                                    let machine_did = Some(ann.machine_did.clone());
                                    let iroh_endpoint_id = if ann.iroh_endpoint_id.is_empty() {
                                        None
                                    } else {
                                        Some(ann.iroh_endpoint_id.clone())
                                    };
                                    pm.upsert_from_announcement(
                                        address,
                                        ann.iroh_endpoint_id.clone(),
                                        ann.served_models.clone(),
                                        ann.hardware.clone(),
                                        ann.capacity.clone(),
                                        status,
                                        has_tee,
                                        machine_did,
                                        iroh_endpoint_id,
                                    );
                                }
                            }
                        }
                        NodeEvent::BlobAnnouncement(ann) => {
                            if let Err(e) = self.verify_announcement(&ann) {
                                warn!(
                                    endpoint_id = %ann.endpoint_id,
                                    error = %e,
                                    "Rejecting blob announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(ann.timestamp, ann.ttl_secs) {
                                warn!(
                                    endpoint_id = %ann.endpoint_id,
                                    error = %e,
                                    "Rejecting blob announcement (replay window)"
                                );
                            } else if let Some(ref resolver) = self.iroh_resolver {
                                match ann.endpoint_id.parse::<tenzro_iroh::EndpointId>() {
                                    Ok(provider) => {
                                        for hash in &ann.blob_hashes {
                                            resolver.record_blob_provider(hash, provider);
                                        }
                                        debug!(
                                            endpoint_id = %ann.endpoint_id,
                                            blobs = ann.blob_hashes.len(),
                                            "Recorded blob providers from gossip announcement"
                                        );
                                    }
                                    Err(e) => warn!(
                                        endpoint_id = %ann.endpoint_id,
                                        error = %e,
                                        "Rejecting blob announcement (unparseable endpoint id)"
                                    ),
                                }
                            }
                        }
                        NodeEvent::ShardReplication(req) => {
                            if let Err(e) = self.verify_announcement(&req) {
                                warn!(
                                    object_id = %req.object_id,
                                    error = %e,
                                    "Rejecting shard replication request (signature verification failed)"
                                );
                            } else if let Err(e) =
                                check_announcement_freshness(req.timestamp, req.ttl_secs)
                            {
                                warn!(
                                    object_id = %req.object_id,
                                    error = %e,
                                    "Rejecting shard replication request (replay window)"
                                );
                            } else if let (Some(replicas), Some(resolver)) =
                                (self.storage_replicas, self.iroh_resolver.as_ref())
                            {
                                let own_endpoint = resolver.endpoint_id().to_string();
                                // Never pin from ourselves — the origin already
                                // holds every shard.
                                if own_endpoint != req.origin_endpoint_id {
                                    // Candidate membership view: storage-capable
                                    // providers discovered via gossip, plus the
                                    // origin, plus self — each tagged with its
                                    // data-plane reachability. Self is
                                    // LocalDirect; every announced endpoint is
                                    // reachable over iroh, directly or through
                                    // its relay. The view is a local snapshot; skew self-heals
                                    // as heartbeats converge.
                                    use tenzro_storage_provider::TieredCandidate;
                                    let mut candidates: Vec<TieredCandidate> = vec![
                                        // Self is always on its own segment.
                                        TieredCandidate::local(own_endpoint.clone()),
                                        // The origin is directly reachable — it
                                        // just published the shards.
                                        TieredCandidate::direct(req.origin_endpoint_id.clone()),
                                    ];
                                    if let Some(ref np) = self.network_providers {
                                        for entry in np.iter() {
                                            let ann = &entry.value().announcement;
                                            if ann
                                                .capabilities
                                                .iter()
                                                .any(|c| c == "storage")
                                                && !ann.iroh_endpoint_id.is_empty()
                                            {
                                                // Every announced endpoint is
                                                // reachable over iroh, directly
                                                // or through its relay.
                                                candidates.push(TieredCandidate::direct(
                                                    ann.iroh_endpoint_id.clone(),
                                                ));
                                            }
                                        }
                                    }

                                    let origin = req.origin_endpoint_id.clone();
                                    // The fetches run off the event loop; only
                                    // the choice of shards is made here.
                                    let mut selected = Vec::new();
                                    for shard in &req.shards {
                                        if selected.len() == MAX_SHARDS_PER_REPLICATION {
                                            break;
                                        }
                                        if tenzro_storage_provider::should_replicate_tiered(
                                            &shard.commitment,
                                            &own_endpoint,
                                            true,
                                            &candidates,
                                            replicas,
                                        ) {
                                            resolver.record_blob_provider(
                                                &shard.blob_hash,
                                                match origin.parse::<tenzro_iroh::EndpointId>() {
                                                    Ok(ep) => ep,
                                                    Err(e) => {
                                                        warn!(
                                                            object_id = %req.object_id,
                                                            origin = %origin,
                                                            error = %e,
                                                            "Shard replication: unparseable origin endpoint id"
                                                        );
                                                        break;
                                                    }
                                                },
                                            );
                                            selected.push(tenzro_iroh::TenzroUri::Blob {
                                                hash: shard.blob_hash.clone(),
                                                provider_hint: Some(origin.clone()),
                                            });
                                        }
                                    }
                                    if !selected.is_empty() {
                                        match self.replication_slots.clone().try_acquire_owned() {
                                            Ok(slot) => {
                                                let resolver: Arc<dyn IrohResolver> =
                                                    resolver.clone();
                                                let object_id = req.object_id.to_string();
                                                let total_shards = req.shards.len();
                                                let gate = self.shard_gate.clone();
                                                tokio::spawn(async move {
                                                    let pinned =
                                                        pin_shards(resolver.as_ref(), &selected, &gate)
                                                            .await;
                                                    drop(slot);
                                                    if pinned > 0 {
                                                        info!(
                                                            object_id = %object_id,
                                                            pinned,
                                                            total_shards,
                                                            "Pinned shards via rendezvous self-selection"
                                                        );
                                                    }
                                                });
                                            }
                                            Err(_) => warn!(
                                                object_id = %req.object_id,
                                                "Shard replication: every replication slot is busy; request dropped"
                                            ),
                                        }
                                    }
                                }
                            }
                        }
                        NodeEvent::Shutdown => {
                            info!("Shutdown event received");
                            break;
                        }
                    }
                }
            }
        }

        info!("Event loop stopped");
        self.shutdown();
        Ok(())
    }

    /// Handles a transaction that was already admitted to the consensus
    /// mempool synchronously by the RPC layer.
    ///
    /// The admission controller is consume-on-admit (each accepted tx
    /// drains one token from the controller's bucket). RPC paths that report
    /// `RateLimited` synchronously (via JSON-RPC error -32011) call
    /// `consensus.submit_transaction` *first*, then dispatch this event for
    /// gossip propagation. We must NOT re-submit through the consensus
    /// mempool here — that would double-charge the bucket and reject the
    /// second attempt as a "transaction already in mempool" anyway.
    ///
    /// Path skipped vs. `Ingress::admit`:
    ///   1. signature verify  — already done at RPC
    ///   2. consensus admission — already done at RPC
    ///
    /// Path executed:
    ///   3. broadcast on `tenzro/transactions` so peers can pick it up
    async fn handle_locally_admitted_transaction(&mut self, tx: SignedTransaction) -> Result<()> {
        let tx_hash = tx.transaction.hash();
        if self.publish_transaction(tx).await {
            self.announced.published(tx_hash, Instant::now());
        }
        Ok(())
    }

    /// Publishes `tx` on the transactions topic under a fresh envelope;
    /// false when this node has no network to publish on.
    async fn publish_transaction(&self, mut tx: SignedTransaction) -> bool {
        let tx_hash = tx.hash();
        let Some(ref network) = self.network else {
            debug!(
                hash = %tx_hash,
                "Locally-admitted transaction has no network — skipping broadcast"
            );
            return false;
        };
        // Same typed-variant rationale as `Ingress::admit` above:
        // peers route on `MessagePayload::Transaction(_)`, so wrapping in
        // `Custom` would silently drop the message on every receiver.
        let msg =
            tenzro_network::NetworkMessage::new(tenzro_network::MessagePayload::Transaction(tx));
        match network.broadcast("tenzro/transactions", msg).await {
            Ok(()) => {
                debug!(
                    hash = %tx_hash,
                    "Locally-admitted transaction forwarded to peers via gossip"
                );
                true
            }
            Err(e) => {
                warn!(
                    hash = %tx_hash,
                    error = %e,
                    "Failed to broadcast locally-admitted transaction over gossip"
                );
                // Published again on the next pass while the mempool holds it.
                true
            }
        }
    }

    /// Publishes again the transactions this node admitted that are still
    /// in its mempool past their wait, each sender's in nonce order.
    async fn publish_announced_again(&mut self) {
        let Some(consensus) = self.consensus.clone() else {
            return;
        };
        let txs = due_for_publishing(&mut self.announced, consensus.mempool(), Instant::now());
        for tx in txs {
            debug!(hash = %tx.transaction.hash(), nonce = tx.transaction.nonce.0, "Published a transaction again: no block has taken it");
            self.publish_transaction(tx).await;
        }
    }

    /// Executes `run`, segments this validator ordered, in order, each as
    /// [`Self::handle_ordered_segment`] does, under one sync of the store at
    /// the end; consensus learns of the blocks once they are synced. A
    /// segment that fails is logged and the run goes on, as each segment
    /// arriving alone would.
    async fn execute_ordered_run(&mut self, run: Vec<OrderedSegment>) {
        let started = Instant::now();
        let segments = run.len();
        self.sync_deferred = true;
        for seg in run {
            if let Err(e) = self.handle_ordered_segment(seg).await {
                error!("Failed to execute an ordered segment: {}", e);
            }
        }
        self.sync_deferred = false;
        let executed = Instant::now();
        if let Err(e) = self.sync_executed().await {
            error!("Failed to sync executed blocks: {}", e);
        }
        debug!(
            segments,
            tip = self.current_height,
            execute_ms = executed.duration_since(started).as_secs_f64() * 1e3,
            sync_ms = executed.elapsed().as_secs_f64() * 1e3,
            "ordered run executed"
        );
    }

    /// Reports an executed block to consensus: at once, or, within a run,
    /// once the run is synced. A block that ends the epoch ends the run
    /// there: the next committee is derived from the state it leaves, before
    /// any later block executes.
    async fn report_executed(&mut self, height: u64, hash: Hash, post_root: Hash) -> Result<()> {
        if !self.sync_deferred {
            if let Some(consensus) = self.consensus.as_ref() {
                consensus.on_executed(height, hash, post_root);
            }
            return Ok(());
        }
        self.unsynced.push((height, hash, post_root));
        if self
            .consensus
            .as_ref()
            .is_some_and(|c| c.closes_epoch_at(height))
        {
            self.sync_executed().await?;
        }
        Ok(())
    }

    /// Syncs the store and reports the blocks executed since the last sync
    /// to consensus, in height order.
    async fn sync_executed(&mut self) -> Result<()> {
        if self.unsynced.is_empty() {
            return Ok(());
        }
        let storage = self.storage.clone();
        tokio::task::spawn_blocking(move || storage.sync_wal())
            .await
            .map_err(|e| NodeError::Other(format!("Store sync task panicked: {}", e)))?
            .map_err(NodeError::Storage)?;
        if let Some(consensus) = self.consensus.clone() {
            for (height, hash, post_root) in self.unsynced.drain(..) {
                consensus.on_executed(height, hash, post_root);
            }
        }
        self.unsynced.clear();
        Ok(())
    }

    /// Builds, executes and records the block of a segment this validator's
    /// consensus ordered, and reports its hash and post-state root back.
    ///
    /// Every validator builds the same header: the segment fixes the height,
    /// epoch, anchor, timestamp, proposer and transactions; the previous
    /// block fixes `prev_hash` and the base fee; this node's state trie fixes
    /// the lagged state root, which every honest validator computes alike.
    /// Gas used and the event root are filled in after execution, before the
    /// block is hashed.
    async fn handle_ordered_segment(&mut self, seg: OrderedSegment) -> Result<()> {
        if seg.height <= self.current_height {
            debug!(
                height = seg.height,
                tip = self.current_height,
                "ordered segment already imported"
            );
            return Ok(());
        }
        if seg.height > self.current_height + 1 {
            self.ordered_ahead.insert(seg.height, seg);
            while self.ordered_ahead.len() > MAX_ORDERED_AHEAD {
                self.ordered_ahead.pop_last();
            }
            return Ok(());
        }
        self.execute_ordered_segment(seg).await?;
        self.run_ordered_ahead().await
    }

    /// Offers the held gossiped transactions to the mempool again, each
    /// sender's in nonce order: one refused again holds back the sender's
    /// later ones until the next try.
    fn offer_parked_again(&mut self) {
        if self.parked.held.is_empty() {
            return;
        }
        let Some(consensus) = self.consensus.clone() else {
            return;
        };
        let mut waiting: HashSet<Address> = HashSet::new();
        for tx in self.parked.due(Instant::now()) {
            let from = tx.transaction.from;
            if waiting.contains(&from) {
                continue;
            }
            let h = tx.transaction.hash();
            match consensus.submit_transaction(tx) {
                Ok(()) => {
                    self.parked.held.remove(&h);
                }
                Err(e) if refusal_passes(&e) => {
                    waiting.insert(from);
                }
                Err(_) => {
                    self.parked.held.remove(&h);
                }
            }
        }
    }

    /// Executes the segments ordered past the tip that now follow it.
    async fn run_ordered_ahead(&mut self) -> Result<()> {
        self.ordered_ahead = self.ordered_ahead.split_off(&(self.current_height + 1));
        while let Some(seg) = self.ordered_ahead.remove(&(self.current_height + 1)) {
            self.execute_ordered_segment(seg).await?;
        }
        Ok(())
    }

    async fn execute_ordered_segment(&mut self, seg: OrderedSegment) -> Result<()> {
        let state_height = tenzro_consensus::state_root_height(seg.height);
        let state_root = self
            .state_trie
            .root_at(state_height)
            .map_err(NodeError::Storage)?
            .ok_or_else(|| {
                NodeError::Other(format!("no committed state root at height {state_height}"))
            })?;
        let parent = BlockStoreImpl::new(self.storage.clone())
            .map_err(NodeError::Storage)?
            .get_block_by_height(BlockHeight::from(self.current_height))
            .await
            .map_err(NodeError::Storage)?
            .ok_or_else(|| {
                NodeError::Other(format!("parent block {} missing", self.current_height))
            })?;
        // The header records the base fee this block's execution charges,
        // so wallets estimating from it offer what the ledger takes.
        let base_fee = tenzro_vm::ledger::block_base_fee(&*self.state_adapter.lock().await);
        let transactions = seg.transactions;
        let header = tenzro_types::block::BlockHeader {
            height: BlockHeight::from(seg.height),
            epoch: seg.epoch,
            round: seg.round,
            anchor: seg.anchor,
            prev_hash: parent.hash(),
            tx_root: Block::compute_tx_root(&transactions),
            state_root,
            event_root: Hash::zero(),
            receipts_root: Hash::new(tenzro_types::eth_receipt::EMPTY_TRIE_ROOT),
            logs_bloom: tenzro_types::LogsBloom::default(),
            timestamp: tenzro_types::primitives::Timestamp::new(seg.timestamp_ms as i64),
            proposer: seg.proposer,
            metadata: tenzro_types::block::BlockMetadata {
                gas_used: 0,
                gas_limit: transactions.iter().map(|t| t.transaction.gas_limit).sum(),
                tx_count: transactions.len() as u64,
                protocol_version: block_protocol_version(
                    parent.header.metadata.protocol_version,
                    seg.height,
                    tenzro_vm::native::read_upgrade_activation(&*self.state_adapter.lock().await)
                        .as_ref(),
                ),
                base_fee_per_gas: Some(base_fee),
            },
        };
        let block = Block::new(header, transactions);
        if let Some((hash, post_root)) = self
            .handle_block_finalized_inner(block, BlockSource::Ordered)
            .await?
        {
            // Derives the next committee when this block ends the epoch.
            self.report_executed(seg.height, hash, post_root).await?;
        }
        Ok(())
    }

    /// The last executed blocks as (height, hash, post-state root), oldest
    /// first: what a core starting after them builds its first checkpoints'
    /// lagged state roots from.
    async fn recent_executed_blocks(&self) -> Result<Vec<(u64, [u8; 32], [u8; 32])>> {
        let store = BlockStoreImpl::new(self.storage.clone()).map_err(NodeError::Storage)?;
        let first = self
            .current_height
            .saturating_sub(tenzro_consensus::STATE_ROOT_LAG);
        let mut out = Vec::new();
        for h in first..=self.current_height {
            let Some(block) = store
                .get_block_by_height(BlockHeight::from(h))
                .await
                .map_err(NodeError::Storage)?
            else {
                continue;
            };
            let Some(root) = self.state_trie.root_at(h).map_err(NodeError::Storage)? else {
                continue;
            };
            out.push((h, block.hash().0, root.0));
        }
        Ok(out)
    }

    /// Whether this node's own consensus orders its blocks: a validator,
    /// unless its core took the epoch's handover before the blocks it covers
    /// were executed here, or fast-forwards to a certified checkpoint past
    /// them; those blocks then come in under certificates as on a follower.
    fn orders_blocks(&self) -> bool {
        self.consensus.as_ref().is_some_and(|c| {
            c.is_validator()
                && !c.awaiting_handover()
                && c.fast_forward_target()
                    .is_none_or(|to| self.current_height >= to)
        })
    }

    /// Block-sync entry point: a range of blocks from a peer, with the
    /// checkpoint bodies covering it and a certificate for the last of them.
    /// The blocks are held like gossiped ones; the certificate authenticates
    /// the bodies through their predecessor digests, and every authenticated
    /// body imports its range.
    pub(crate) async fn handle_block_imported_from_sync(
        &mut self,
        blocks: Vec<Block>,
        checkpoints: Vec<tenzro_consensus::Checkpoint>,
        certificate: Option<tenzro_consensus::PublishedCertificate>,
    ) -> Result<()> {
        for b in blocks {
            self.hold_uncertified(b);
        }
        let Some(tenzro_consensus::PublishedCertificate {
            certificate: cert,
            sessions,
        }) = certificate
        else {
            return Ok(());
        };
        let consensus = self
            .consensus
            .as_ref()
            .ok_or_else(|| {
                NodeError::Other("importing under a certificate needs consensus".into())
            })?
            .clone();
        consensus.admit_sessions(cert.checkpoint.epoch, sessions);
        // A validator orders these blocks itself, unless the evidence shows
        // the network certified past what its core can still order: then it
        // stands down and imports them like any follower.
        if self.orders_blocks() && !consensus.on_served_certificate(&cert, self.current_height) {
            return Ok(());
        }
        consensus.accept_certificate(&cert)?;
        let chain = crate::certified_import::authenticate_chain_to(
            &cert.checkpoint,
            &checkpoints,
            self.current_height,
            |i| consensus.checkpoint(i),
        );
        for cp in chain {
            consensus.record_body(&cp);
            consensus.keep_handover(&cert);
            if cp.last_height > self.current_height {
                // The evidence may run past the blocks served with it (the
                // nearest kept certificate lies beyond the range): import up
                // to there, and the next range carries on from the tip.
                if !self.holds_range(&cp) {
                    break;
                }
                self.import_certified_range(&cp).await?;
            }
            self.after_certified_import(&consensus, &cp).await?;
        }
        self.run_ordered_ahead().await
    }

    /// Whether every block `cp` covers past the local tip is held.
    fn holds_range(&self, cp: &tenzro_consensus::Checkpoint) -> bool {
        (self.current_height.max(cp.first_height.saturating_sub(1)) + 1..=cp.last_height)
            .all(|h| self.uncertified.contains_key(&h))
    }

    /// On a follower, after a certified checkpoint's blocks are imported: at
    /// an epoch's last checkpoint derive and check the next committee, and at
    /// the handover start validating if this node is seated next.
    async fn after_certified_import(
        &mut self,
        consensus: &Arc<ConsensusHandle>,
        cp: &tenzro_consensus::Checkpoint,
    ) -> Result<()> {
        consensus.adopt_next_committee(cp)?;
        let base = self.recent_executed_blocks().await?;
        consensus.on_imported(cp, base)
    }

    /// Holds a block received from a peer until a certificate covering its
    /// height arrives. Only the successor range of the local tip is kept.
    fn hold_uncertified(&mut self, block: Block) {
        const MAX_HELD: u64 = 20_000;
        let h = block.height().0;
        if h <= self.current_height || h > self.current_height + MAX_HELD {
            return;
        }
        if block.verify_body().is_err() {
            return;
        }
        self.uncertified.insert(h, block);
    }

    /// Imports every block a verified certificate covers.
    ///
    /// On a validator the blocks were built and executed from its own
    /// ordering already; the certificate then only confirms that this node
    /// computed the state root a quorum signed. On a follower the held
    /// blocks are checked against the certificate and executed in order.
    async fn handle_certificate(&mut self, cert: Certificate) -> Result<()> {
        let consensus = self
            .consensus
            .as_ref()
            .ok_or_else(|| {
                NodeError::Other("importing under a certificate needs consensus".into())
            })?
            .clone();
        let follower = !self.orders_blocks();
        if follower {
            if cert.checkpoint.first_height > self.current_height + 1 {
                consensus.note_behind_hint(cert.checkpoint.first_height);
                return Err(NodeError::Other(format!(
                    "certificate {} starts at height {}, past the local tip {}; block-sync will fetch the gap",
                    cert.checkpoint.index, cert.checkpoint.first_height, self.current_height
                )));
            }
            if cert.checkpoint.epoch > consensus.known_epoch() {
                // The end of an epoch this node missed: block-sync fetches it.
                consensus.note_behind_hint(cert.checkpoint.first_height);
            }
            consensus.accept_certificate(&cert)?;
        }
        self.import_certified_range(&cert.checkpoint).await?;
        if follower {
            self.after_certified_import(&consensus, &cert.checkpoint)
                .await?;
        }
        Ok(())
    }

    /// Imports the range an authenticated checkpoint covers: the held blocks
    /// (and any already executed) must rebuild its blocks root; each new one
    /// is checked as the successor of the tip and executed; and this node's
    /// state root at the checkpoint's state height must be the one it
    /// commits.
    async fn import_certified_range(&mut self, cp: &tenzro_consensus::Checkpoint) -> Result<()> {
        if cp.last_height > self.current_height {
            if cp.first_height > self.current_height + 1 {
                return Err(NodeError::Other(format!(
                    "checkpoint {} starts at height {}, past the local tip {}",
                    cp.index, cp.first_height, self.current_height
                )));
            }
            let mut range = Vec::with_capacity((cp.last_height - cp.first_height + 1) as usize);
            let store = BlockStoreImpl::new(self.storage.clone()).map_err(NodeError::Storage)?;
            for h in cp.first_height..=cp.last_height {
                let b = if h <= self.current_height {
                    store
                        .get_block_by_height(BlockHeight::from(h))
                        .await
                        .map_err(NodeError::Storage)?
                } else {
                    self.uncertified.get(&h).cloned()
                };
                match b {
                    Some(b) => range.push(b),
                    None => {
                        return Err(NodeError::Other(format!(
                            "checkpoint {} covers height {h}, which this node has not received",
                            cp.index
                        )));
                    }
                }
            }
            crate::certified_import::check_range(cp, &range).map_err(NodeError::Other)?;
            // Read the tip before the loop: the filter closure would
            // otherwise hold `self` borrowed across the `&mut self` import.
            let from_height = self.current_height;
            for block in range.into_iter().filter(|b| b.height().0 > from_height) {
                let tip = self.chain_tip().await?;
                crate::certified_import::check_successor(&block, &tip).map_err(NodeError::Other)?;
                let local_root = self
                    .state_trie
                    .root_at(tenzro_consensus::state_root_height(block.height().0))
                    .map_err(NodeError::Storage)?;
                crate::certified_import::check_state_root(&block, local_root)
                    .map_err(NodeError::Other)?;
                crate::certified_import::check_checkpoint(&block, self.weak_subjectivity_anchor)
                    .map_err(NodeError::Other)?;
                let h = block.height().0;
                if let Some((hash, post_root)) = self
                    .handle_block_finalized_inner(block, BlockSource::Imported)
                    .await?
                    && let Some(consensus) = self.consensus.as_ref()
                {
                    consensus.on_executed(h, hash, post_root);
                }
                self.uncertified.remove(&h);
            }
        }
        let local = self
            .state_trie
            .root_at(cp.state_height)
            .map_err(NodeError::Storage)?;
        crate::certified_import::check_certified_state(cp, local).map_err(NodeError::Other)?;
        self.uncertified.drop_through(self.current_height);
        Ok(())
    }

    /// The local chain tip a certified block must extend.
    async fn chain_tip(&self) -> Result<crate::certified_import::ChainTip> {
        let block_store = BlockStoreImpl::new(self.storage.clone())
            .map_err(|e| NodeError::Other(format!("Block store error: {}", e)))?;
        let tip = block_store
            .get_block_by_height(BlockHeight::from(self.current_height))
            .await
            .map_err(NodeError::Storage)?
            .ok_or_else(|| {
                NodeError::Other(format!(
                    "the local tip block at height {} is not in storage",
                    self.current_height
                ))
            })?;
        Ok(crate::certified_import::ChainTip {
            height: self.current_height,
            hash: tip.hash(),
            timestamp_ms: tip.header.timestamp.as_millis(),
        })
    }

    /// Epoch and registry records to commit with block `height`; empty unless
    /// `height` starts an epoch. See [`crate::state_commitment`].
    fn epoch_start_records(
        &self,
        height: BlockHeight,
    ) -> tenzro_storage::state_trie::capture::Writes {
        let Some(consensus) = self.consensus.as_ref() else {
            return Default::default();
        };
        let previous_index = self
            .state_trie
            .latest_version()
            .ok()
            .flatten()
            .and_then(|v| {
                self.state_trie
                    .get(
                        v,
                        tenzro_storage::state_trie::NS_VALIDATOR_REGISTRY,
                        crate::state_commitment::REGISTRY_INDEX_KEY,
                    )
                    .ok()
                    .flatten()
            })
            .and_then(|b| bincode::deserialize(&b).ok());
        crate::state_commitment::epoch_start_records(
            consensus.epoch_manager(),
            self.validator_registry.as_deref(),
            height,
            previous_index,
        )
    }

    /// Stages the validator-registry transition plan for the next epoch onto
    /// the `EpochManager` pending queues (`add_pending_validator` /
    /// `remove_pending_validator`). `transition_epoch` drains those queues.
    ///
    /// Called from exactly one place: the consensus driver, immediately
    /// before it computes the next committee, through
    /// [`crate::consensus_driver::EpochPlanner`].
    pub(crate) fn stage_registry_epoch_plan(
        em: &Arc<tenzro_consensus::EpochManager>,
        registry: &Arc<tenzro_token::ValidatorRegistry>,
        admitted: &dyn Fn(&[u8]) -> bool,
    ) {
        let next_epoch = em.current_epoch().number + 1;
        let plan = registry.compute_epoch_transition_with(next_epoch, admitted);
        debug!(
            next_epoch = next_epoch,
            activations = plan.effective_activations.len(),
            exits = plan.effective_exits.len(),
            "Computed registry epoch transition plan"
        );

        // Exits first: a validator that has left must not be re-seated by the
        // reconcile below on the strength of a stale registry row.
        // Effective exits → drop from active set in next epoch.
        for addr in &plan.effective_exits {
            em.remove_pending_validator(addr);
        }
        // A key whose scheme governance retired leaves the set once its
        // grace has passed; a rotated key is restaged by the reconcile below.
        for addr in &plan.unseated {
            em.remove_pending_validator(addr);
        }

        // Reconcile the seated set against the registry.
        //
        // This used to stage `plan.effective_activations` — the validators
        // that changed state at this boundary — which is correct only if
        // every boundary is observed exactly once. Two ways of missing one
        // have already turned up: the engine crossed boundaries without
        // staging at all, and a transition that opened its gate but refused
        // to commit re-ran the plan on every block, promoting Candidate to
        // PendingActive to Active without seating anyone. After that the
        // validators are Active, so they never change state again, so they
        // never appear in a plan again, so nothing would ever seat them.
        //
        // Stating the desired set instead of replaying the changes makes a
        // missed boundary something the next one repairs. `transition_epoch`
        // upserts onto continuing members in its phase 2 and does not charge
        // that against the entrant churn budget — a stake update is not churn
        // — and genuinely new entrants are still capped there as before.
        //
        // Entries that already match are skipped, so the common boundary
        // where nothing moved stages nothing.
        let live_set = em.current_validator_set();
        for entry in registry.list_active() {
            let power = Self::consensus_voting_power(entry.self_stake);
            let seated = live_set.get_by_address(&entry.address);
            // A seat matches when its power, its composite key and its node
            // key all agree with the registry.
            if seated.is_some_and(|v| {
                v.stake == power
                    && v.public_key.ml_dsa == entry.ml_dsa_pubkey
                    && v.public_key.p256 == entry.p256_pubkey
                    && v.node_key == entry.node_key
            }) {
                continue;
            }
            let key = match tenzro_consensus::ValidatorPublicKey::new(
                entry.ml_dsa_pubkey.clone(),
                entry.p256_pubkey.clone(),
            ) {
                Ok(key) => key,
                Err(e) => {
                    warn!(
                        address = %entry.address,
                        error = %e,
                        "Skipping restage: registry key is malformed"
                    );
                    continue;
                }
            };
            debug!(
                address = %entry.address,
                seated = seated.map(|v| v.stake),
                staking = power,
                registry_wei = entry.self_stake,
                "Staging Active validator whose seat does not match the registry"
            );
            em.add_pending_validator(tenzro_consensus::validator::ValidatorInfo::new(
                entry.address,
                key,
                entry.node_key,
                power,
            ));
        }
    }

    /// Converts a registry stake (wei) into consensus voting power (whole TNZO).
    ///
    /// The two sides of this seam have always disagreed about the unit. The
    /// registry holds wei — `MIN_VALIDATOR_STAKE` is `10_000 * ONE_TNZO` — while
    /// the genesis validator set was seeded with whole TNZO, and
    /// `ValidatorInfo::voting_power()` returns whatever it was given. Copying
    /// one into the other unconverted gives a staged validator 10^18 times the
    /// weight of a seated one.
    ///
    /// Whole TNZO is the direction of travel, not wei. Scaling the set the
    /// other way was tried on this chain and broke it: a commit-QC records the
    /// voting power it was formed under and is verified against the epoch
    /// snapshot, so restating the genesis set in wei made every historical QC
    /// unverifiable. Whole TNZO is what epoch 0 committed to.
    ///
    /// A non-zero stake never rounds to zero voting power — that would seat a
    /// validator that cannot vote, which reads as a silent exclusion. It cannot
    /// arise below the 10,000 TNZO floor anyway; the clamp is here so it cannot
    /// arise at all.
    fn consensus_voting_power(self_stake_wei: u128) -> u128 {
        tenzro_types::launch_rule::voting_power(self_stake_wei)
    }

    /// Executes `block`, commits its state, persists it, and returns its
    /// hash and post-state root (`None` when the height is already
    /// executed). A block this validator's consensus ordered gets its gas
    /// used filled in before it is hashed, and is published to followers.
    async fn handle_block_finalized_inner(
        &mut self,
        mut block: Block,
        source: BlockSource,
    ) -> Result<Option<(Hash, Hash)>> {
        let mut block_hash = block.hash();
        let block_height = block.height();
        let tx_count = block.tx_count();

        // Idempotency guard: if we've already finalized this height locally, do
        // not re-execute. Re-execution against current state writes garbage
        // state roots, double-broadcasts the block back into gossip, and
        // amplifies a self-sustaining storm with peers — the underlying cause
        // of the testnet OOMKill cycle. Every source (own ordering, certified
        // import) goes through this guard.
        if block_height.0 <= self.current_height {
            debug!(
                received = %block_height,
                current = self.current_height,
                hash = %block_hash,
                "Skipping finalized-block event at or below current height"
            );
            return Ok(None);
        }

        // Whatever the source, the body executed must be the one the block
        // hash commits to. A certificate covers the header only; a relay can
        // pair a genuine header and certificate with a different body.
        block
            .verify_body()
            .map_err(|e| NodeError::Other(format!("refusing finalized block: {e}")))?;

        // From an upgrade's activation height the network runs the binary it
        // names; executing on with another one would fork this node off.
        if let Some(upgrade) = self
            .policy_applier
            .as_ref()
            .and_then(|p| p.superseded_at(block_height.0))
        {
            return Err(NodeError::Other(format!(
                "protocol upgrade {} (binary {}) activated at height {}; this node runs another binary \
                 and stops executing blocks until it is replaced",
                upgrade.version, upgrade.code_hash, upgrade.activation_height
            )));
        }

        info!(
            height = %block_height,
            hash = %block_hash,
            tx_count = tx_count,
            "Processing finalized block"
        );

        // Update block/transaction metrics
        self.metrics.record_block();
        self.metrics.record_transaction(tx_count as u64);
        // Refresh peer count on every finalized block so the metric stays current
        if let Some(ref network) = self.network {
            self.metrics.set_peer_count(network.peer_count() as u64);
        }

        // Execute all transactions in the block
        let started = Instant::now();
        let mut gas_used_total = 0u64;
        let mut successful_txs = 0;
        let mut failed_txs = 0;

        // Everything execution writes to a committed column family is
        // recorded here and committed as this height's state-trie version.
        // Only the executor's own writes are recorded: the log mirrors below
        // and any concurrent RPC writer run outside the recording scope.
        let block_writes = tenzro_storage::state_trie::capture::WriteSet::new();

        // Per-tx receipts collected during execution; persisted alongside the
        // tx index after the block commits so `eth_getTransactionReceipt` can
        // report real status/gas_used/logs instead of fabricating values.
        let mut receipts_for_index: Vec<(Hash, TxReceiptRecord)> =
            Vec::with_capacity(block.transactions.len());

        // The events execution emits, in cursor order: what the header's
        // event root commits and the durable event log records. A
        // transaction's index is its first position in the block.
        let mut chain_events: Vec<tenzro_types::chain_event::ChainEvent> = Vec::new();
        let mut logs_bloom = tenzro_types::LogsBloom::default();
        let mut tx_positions: std::collections::HashMap<Hash, u32> =
            std::collections::HashMap::with_capacity(block.transactions.len());
        for (i, t) in block.transactions.iter().enumerate() {
            tx_positions.entry(t.transaction.hash()).or_insert(i as u32);
        }

        // Hot-state local fee market: per-account contention samples for
        // this block: one write per unique address per tx, plus the number of
        // times parallel execution had to re-run that tx.
        let mut block_contention: std::collections::HashMap<Vec<u8>, tenzro_vm::AccountSample> =
            std::collections::HashMap::new();

        // Base fee this block charges, from consensus state, and the fees its
        // transactions pay as they execute.
        let block_base_fee = tenzro_vm::ledger::block_base_fee(&*self.state_adapter.lock().await);
        // Calendar rules read the calendar clock, which genesis may run faster
        // than block time.
        let calendar_now_ms = tenzro_vm::native::calendar_ms(
            &*self.state_adapter.lock().await,
            block.header.timestamp.as_millis(),
        )
        .map_err(|e| NodeError::Other(format!("block {block_height} calendar: {e}")))?;
        let mut block_fees = tenzro_vm::ledger::BlockFees::default();

        let mut admitted = Vec::with_capacity(block.transactions.len());
        let mut vm_txs = Vec::with_capacity(block.transactions.len());
        // Transactions a block carries that were already included at an
        // earlier height. Validators batch what their mempools hold, so one
        // transaction can be ordered in more than one segment; the copy could
        // only fail on its spent nonce, so it is not executed again and the
        // first inclusion keeps its index and receipt.
        let mut repeated: std::collections::HashSet<Hash> = std::collections::HashSet::new();
        for signed_tx in &block.transactions {
            let tx_hash = signed_tx.transaction.hash();

            if self
                .storage
                .get(CF_TRANSACTIONS, format!("idx:{tx_hash}").as_bytes())
                .ok()
                .flatten()
                .is_some()
            {
                debug!(tx_hash = %tx_hash, "Skipping a transaction included at an earlier height");
                repeated.insert(tx_hash);
                continue;
            }

            // Defense-in-depth: verify signature even for consensus-approved transactions.
            // This catches any bugs in consensus signature verification.
            if let Err(e) = verify_transaction_signature(signed_tx) {
                error!(
                    tx_hash = %tx_hash,
                    error = %e,
                    "Skipping transaction with invalid signature in finalized block"
                );
                failed_txs += 1;
                // No receipt is emitted: a sig-invalid tx that reached a finalized
                // block represents a consensus-level violation, not a normal failure
                // observable via eth_getTransactionReceipt.
                continue;
            }

            // Stamp the finalized block's timestamp onto the VmTransaction
            // so native-VM handlers that depend on wall-clock state read
            // a deterministic value across all validators (vs each one's
            // `Utc::now()`). Without this, escrow-expiry / time-bound
            // delegation / lifecycle TTL checks could diverge between
            // validators and split finalized state.
            let converted = if signed_tx.transaction.tx_type.is_external() {
                match external_vm_transaction(signed_tx, block_base_fee) {
                    Ok(vm_tx) => vm_tx,
                    Err(e) => {
                        warn!(tx_hash = %tx_hash, error = %e, "Skipping an external transaction that does not execute");
                        failed_txs += 1;
                        continue;
                    }
                }
            } else {
                convert_transaction(signed_tx)
            };
            let mut vm_tx = converted
                .with_block_timestamp_ms(calendar_now_ms)
                .with_block_height(block_height.0)
                .with_block_base_fee(block_base_fee);

            // A recorded checkpoint certificate reaches the VM only as the
            // signers' accounts, once it verifies against the committee of
            // its epoch. Every node reaches the same verdict. One that does
            // not verify still executes, with no signers, so the VM refuses
            // it and spends its nonce: left out, it would hold its nonce open
            // and every later transaction of the recording validator's
            // account would fail behind it. A record pays no fee either way.
            if let tenzro_types::TransactionType::RecordCheckpointSigners { certificate } =
                &signed_tx.transaction.tx_type
            {
                let verified = match self.consensus.as_ref() {
                    Some(c) => c
                        .certified_signers(certificate, block.header.epoch)
                        .map_err(|e| {
                            NodeError::Other(format!("block {block_height} refused: {e}"))
                        })?,
                    None => Err("this node runs no consensus".to_string()),
                };
                let mut data = tenzro_vm::native::SELECTOR_CHECKPOINT_SIGNERS.to_vec();
                match verified {
                    Ok(signers) => data.extend_from_slice(
                        &serde_json::to_vec(&signers).expect("checkpoint signers are JSON-safe"),
                    ),
                    Err(reason) => {
                        warn!(tx_hash = %tx_hash, %reason, "Checkpoint certificate does not verify; it executes as refused");
                    }
                }
                vm_tx.data = data;
            }
            vm_txs.push(vm_tx);
            admitted.push((signed_tx, tx_hash));
        }

        // Parameter and reward accounting for this block run before its
        // transactions, in consensus state: a block that opens an epoch
        // first applies the governed parameter changes due by it, then runs
        // the running-cost reserve's boundary; epochs older than the block's
        // own close into coupons, the proposer earns its block-proposal
        // unit, and settlement plans past their deadline abort and refund
        // their payers. Every node that executes this block derives
        // the same records.
        {
            let mut state_adapter = self.state_adapter.lock().await;
            let now_ms = calendar_now_ms;
            let outcome = tenzro_vm::native::begin_block_params(&mut *state_adapter, block.header.epoch)
                .map_err(|e| format!("parameter schedule failed: {e}"))
                .and_then(|applied| {
                    for (key, value) in &applied {
                        info!(height = %block_height, epoch = block.header.epoch, %key, value, "Governed parameter applies");
                    }
                    tenzro_vm::native::begin_block_treasury(
                        &mut *state_adapter,
                        block.header.epoch,
                        now_ms,
                    )
                    .map_err(|e| format!("running-cost reserve failed: {e}"))
                })
                .and_then(|_| {
                    tenzro_vm::native::begin_block_rewards(
                        &mut *state_adapter,
                        block.header.epoch,
                        &block.header.proposer,
                        now_ms,
                    )
                    .map(|logs| {
                        for log in &logs {
                            warn!(
                                height = %block_height,
                                topic = %String::from_utf8_lossy(log.topics.first().map(Vec::as_slice).unwrap_or_default()),
                                data = %String::from_utf8_lossy(&log.data),
                                "Epoch close event"
                            );
                        }
                    })
                    .map_err(|e| format!("reward accounting failed: {e}"))
                })
            .and_then(|_| {
                // The epoch that just closed is counted for inactivity from
                // chain state and the closing epoch's validator set, the
                // same inputs on every node.
                let epoch = block.header.epoch;
                let roster = epoch.checked_sub(1).and_then(|closing| {
                    let set = self
                        .consensus
                        .as_ref()?
                        .epoch_manager()
                        .get_validator_set(closing)?;
                    Some((closing, set.iter().map(|v| v.address).collect::<Vec<_>>()))
                });
                match roster {
                    Some((closing, roster)) => tenzro_vm::native::begin_block_participation(
                        &mut *state_adapter,
                        closing,
                        &roster,
                    )
                    .map(|_| ())
                    .map_err(|e| format!("participation accounting failed: {e}")),
                    None => Ok(()),
                }
            })
            .and_then(|_| {
                tenzro_vm::native::begin_block_plans(&mut *state_adapter, now_ms)
                    .map_err(|e| format!("settlement plan deadlines failed: {e}"))
            })
            .and_then(|_| {
                tenzro_vm::native::begin_block_da_retention(&mut *state_adapter, now_ms)
                    .map_err(|e| format!("data-availability expiry failed: {e}"))
            });
            if let Err(e) = outcome {
                state_adapter.rollback();
                error!(height = %block_height, error = %e, "Refusing block");
                return Err(NodeError::Other(format!(
                    "block {block_height} refused: {e}"
                )));
            }
            // A Solana account's EVM alias is recorded the first time it
            // signs, so EVM wallets and contracts can name it.
            for (signed_tx, _) in &admitted {
                if let TransactionType::ExternalSvm { raw } = &signed_tx.transaction.tx_type
                    && let Ok(ext) = tenzro_vm::external_tx::decode_svm_wire(raw)
                {
                    for signer in &ext.signers {
                        tenzro_vm::external_tx::record_svm_alias(&mut *state_adapter, signer);
                    }
                }
            }
        }

        // Execute the block with Block-STM. Each transaction runs under the
        // value rules in `tenzro_vm::ledger`: a failed transaction, or one
        // whose balance movement does not match its fee and declared supply
        // change, is undone and charged gas; a kept one pays its fee into the
        // block's fee pool. The outcome of every transaction, the state and
        // the fees are exactly those of running the block in order. The lock
        // is held for the whole block so no other writer interleaves with it.
        // Execution runs with this block's write set installed, so every
        // write it makes to a committed column family enters the state trie.
        let executed = {
            let mut state_adapter = self.state_adapter.lock().await;
            tenzro_storage::state_trie::capture::in_task(
                block_writes.clone(),
                tenzro_vm::parallel::execute_block(
                    &self.vm_runtime,
                    &mut state_adapter,
                    &vm_txs,
                    block_base_fee,
                    &mut block_fees,
                    &tenzro_vm::BlockStmConfig::default(),
                ),
            )
            .await
        };

        let mut pending_again: std::collections::HashSet<Hash> = std::collections::HashSet::new();
        for ((signed_tx, tx_hash), executed_tx) in admitted.into_iter().zip(executed) {
            let reexecutions = u64::from(executed_tx.reexecutions);
            let result = match executed_tx.outcome {
                tenzro_vm::ledger::TxOutcome::Applied { result, fee } => Ok((result, fee)),
                tenzro_vm::ledger::TxOutcome::Reverted { result, fee, .. } => Ok((result, fee)),
                tenzro_vm::ledger::TxOutcome::Rejected(e) => Err(e),
            };

            match result {
                Ok((result, fee_paid)) => {
                    gas_used_total += result.gas_used;

                    // Hot-state attribution: every distinct address
                    // touched by a successful or reverted tx counts as one
                    // write toward this block's contention sample, and
                    // carries the tx's Block-STM re-executions; the surcharge
                    // fires on sustained write volume and re-execution over
                    // the 64-block window.
                    {
                        let mut seen: std::collections::HashSet<Vec<u8>> =
                            std::collections::HashSet::new();
                        for sc in &result.state_changes {
                            if seen.insert(sc.address.clone()) {
                                let entry = block_contention.entry(sc.address.clone()).or_default();
                                entry.merge(tenzro_vm::AccountSample {
                                    reexecutions,
                                    writes: 1,
                                });
                            }
                        }
                    }

                    if result.success {
                        successful_txs += 1;
                        debug!(
                            tx_hash = %tx_hash,
                            gas_used = result.gas_used,
                            "Transaction executed successfully"
                        );

                        // Token creations, from the factory precompile or a
                        // native `Token` transaction, into the metadata index.
                        self.process_token_created_logs(&result);

                        // Post-execute ERC-8004 `Registered` scan: reflects
                        // the canonical `IdentityRegistry` proxy's
                        // `Registered(uint256,string,address)` event into
                        // the off-chain `erc8004_did_index:` keyspace in
                        // CF_IDENTITIES and patches the matching TDIP
                        // `Machine` identity's `erc8004_agent_id` field.
                        // This is the listener half of the
                        // `NativeErc8004Mirror` async-detached-spawn
                        // architecture — the EVM tx is submitted by the
                        // mirror's `tokio::spawn`, and the resulting log
                        // lands here when the block applies.
                        self.process_erc8004_registered_logs(&result, block_height)
                            .await;

                        // Same pattern for ValidatorRegister / ValidatorExit /
                        // ValidatorMetadataUpdate logs — drive the off-chain
                        // ValidatorRegistry from VM-emitted events. The VM
                        // has already deducted gas and persisted markers.
                        self.process_validator_logs(&result, block_height).await;

                        // Identities — mirror the consensus-decided DID record
                        // into the local IdentityRegistry read model so an
                        // identity created on any node resolves on all nodes
                        //. The VM already enforced DID uniqueness and
                        // persisted the `identity:<did>` marker; this only
                        // records it into the resolve path.
                        self.process_identity_logs(&result, block_height).await;
                        if let Some(policy) = self.policy_applier.as_ref() {
                            policy.reflect_logs(&result.logs);
                        }
                    } else {
                        failed_txs += 1;
                        warn!(
                            tx_hash = %tx_hash,
                            gas_used = result.gas_used,
                            revert_reason = ?result.revert_reason,
                            "Transaction execution reverted"
                        );
                    }

                    let logs: Vec<TxReceiptLog> = result
                        .logs
                        .iter()
                        .map(|l| TxReceiptLog {
                            address: hex::encode(&l.address),
                            topics: l.topics.iter().map(hex::encode).collect(),
                            data: hex::encode(&l.data),
                        })
                        .collect();

                    for l in &result.logs {
                        logs_bloom.accrue_log(&l.address, &l.topics);
                    }
                    chain_events.extend(tenzro_types::chain_event::transaction_events(
                        block_height.0,
                        tx_positions[&tx_hash],
                        tx_hash,
                        result.success,
                        result.gas_used,
                        result.contract_address.clone(),
                        result
                            .logs
                            .iter()
                            .map(|l| (&l.address[..], &l.topics[..], &l.data[..])),
                    ));
                    receipts_for_index.push((
                        tx_hash,
                        TxReceiptRecord {
                            success: result.success,
                            gas_used: result.gas_used,
                            cumulative_gas_used: gas_used_total,
                            effective_gas_price: charged_gas_price(
                                paid_gas_price(signed_tx, block_base_fee),
                                result.gas_used,
                                fee_paid,
                            ),
                            fee_paid,
                            revert_reason: result.revert_reason.clone(),
                            contract_address: result.contract_address.as_ref().map(hex::encode),
                            logs,
                            supply_change: result.supply_change,
                            treasury_leg: result.treasury_leg,
                        },
                    ));
                }
                Err(e) => {
                    failed_txs += 1;
                    error!(
                        tx_hash = %tx_hash,
                        error = %e,
                        "Transaction execution failed"
                    );

                    // A transaction that never executed stays in the mempool
                    // only when a later block can still run it: its nonce is
                    // ahead of the account (the predecessor may yet arrive),
                    // or it offered less than this block's base fee, which
                    // moves. Every other refusal is permanent.
                    let retry = match &e {
                        tenzro_vm::VmError::InvalidNonce { expected, got } => got > expected,
                        // A record that pays no fee is held to no base fee,
                        // so a lower one never makes it executable later.
                        _ => {
                            !signed_tx.transaction.tx_type.pays_no_fee()
                                && u128::from(signed_tx.transaction.gas_price) < block_base_fee
                        }
                    };
                    if retry {
                        // Not included: no receipt and no index, so the
                        // block that can run it executes it then. Indexed
                        // here, every later copy would be skipped as
                        // already included and dropped from the mempool,
                        // and the sender's later transactions would wait
                        // behind the gap for good.
                        pending_again.insert(tx_hash);
                        continue;
                    }
                    // Record an explicit failure receipt so downstream callers
                    // get a deterministic answer rather than a missing-record
                    // null. A transaction that never executed wrote nothing and
                    // was charged nothing, so its receipt reports no gas.
                    let charged = 0;
                    chain_events.extend(tenzro_types::chain_event::transaction_events(
                        block_height.0,
                        tx_positions[&tx_hash],
                        tx_hash,
                        false,
                        charged,
                        None,
                        [],
                    ));
                    receipts_for_index.push((
                        tx_hash,
                        TxReceiptRecord {
                            success: false,
                            gas_used: charged,
                            cumulative_gas_used: gas_used_total,
                            effective_gas_price: paid_gas_price(signed_tx, block_base_fee),
                            fee_paid: 0,
                            revert_reason: Some(format!("vm_error: {}", e)),
                            contract_address: None,
                            logs: Vec::new(),
                            supply_change: 0,
                            treasury_leg: None,
                        },
                    ));
                }
            }
        }

        // Every validator executes the same ordered transactions, so the gas
        // they use and the events they emit are the same everywhere; both go
        // into the header before the block is hashed and certified. An
        // imported block's header already commits its events, and execution
        // here must reproduce them.
        let event_root = tenzro_types::chain_event::event_root(&chain_events);
        let tx_types: std::collections::HashMap<Hash, u8> = block
            .transactions
            .iter()
            .map(|t| (t.transaction.hash(), eth_tx_type(t)))
            .collect();
        let receipts_root = tenzro_types::eth_receipt::receipts_root(
            receipts_for_index
                .iter()
                .map(|(h, r)| (u64::from(tx_positions[h]), r.eth_encoding(tx_types[h]))),
        );
        if source == BlockSource::Ordered {
            block.header.metadata.gas_used = gas_used_total;
            block.header.event_root = event_root;
            block.header.receipts_root = receipts_root;
            block.header.logs_bloom = logs_bloom;
            block_hash = block.hash();
        } else if block.header.event_root != event_root
            || block.header.receipts_root != receipts_root
            || block.header.logs_bloom != logs_bloom
        {
            self.state_adapter.lock().await.rollback();
            error!(
                height = %block_height,
                committed = %block.header.event_root,
                executed = %event_root,
                "Refusing block: execution emitted different events, receipts or logs than its header commits"
            );
            return Err(NodeError::Other(format!(
                "block {block_height} refused: its events do not match the header's event root, receipts root and logs bloom"
            )));
        }
        // Settle the block's fees in state and hold the whole block to the
        // value rule before anything is written. A block whose balance writes
        // do not net to its recorded supply change, or that adds to total
        // supply, is refused: its writes are discarded and the height does
        // not advance.
        let fee_settlement = {
            let mut state_adapter = self.state_adapter.lock().await;
            let settlement = tenzro_vm::ledger::settle_block(&mut state_adapter, &block_fees);
            if let Err(e) = tenzro_vm::ledger::verify_executed_block(&state_adapter) {
                state_adapter.rollback();
                error!(height = %block_height, error = %e, "Refusing block");
                return Err(NodeError::Other(format!(
                    "block {block_height} refused: {e}"
                )));
            }
            settlement
        };

        // Commit state changes to storage.
        // Use spawn_blocking to offload synchronous RocksDB writes to the blocking thread
        // pool (separate from tokio worker threads). This keeps worker threads free to
        // respond to health probes and RPC requests even when only 1 worker thread is
        // available (as under a fractional CPU limit).
        //
        // block_in_place() would NOT work here because it "migrates async tasks to other
        // worker threads" — but with only 1 worker thread, there are no other threads to
        // migrate to, so the health endpoint still starves. spawn_blocking() uses a
        // completely separate thread pool (default: up to 512 threads) and immediately
        // yields the worker thread back to the async scheduler.
        // The records a node derives at an epoch's first block (the epoch's
        // validator set, and the registry the next transition is computed
        // from) are committed with this block's writes.
        let epoch_records = self.epoch_start_records(block_height);

        let executed_at = Instant::now();

        // The block, its transaction index and receipts, and its events, kept
        // under CF_TRANSACTIONS and the event log:
        //   1. `<hex_hash>` → JSON-encoded SignedTransaction
        //      (format matches rpc::handle_get_transaction reader)
        //   2. `idx:<hex_hash>` → JSON { block_height, block_hash, tx_index }
        //      (lets eth_getTransactionReceipt locate the containing block
        //      without scanning CF_BLOCKS)
        //   3. `receipt:<hex_hash>` → JSON-encoded TxReceiptRecord
        //      (real exec status, gas_used, logs — read by
        //      eth_getTransactionReceipt instead of fabricating)
        let block_for_store = block.clone();
        let txs_for_index: Vec<(usize, SignedTransaction)> = block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                let h = t.transaction.hash();
                !repeated.contains(&h) && !pending_again.contains(&h)
            })
            .map(|(i, t)| (i, t.clone()))
            .collect();
        let receipts_for_persist = receipts_for_index;
        let event_log_writes = self
            .event_log
            .is_some()
            .then(|| tenzro_events::EventLog::block_writes(block_height.0, &chain_events));

        // The state commit, the state trie version, the block and its index
        // are written as one atomic batch, so a crash never leaves the state
        // of a height without its block or the other way round. Ordered
        // blocks executed in a run are synced once, at the end of the run
        // (see `execute_ordered_run`); every other block is synced here.
        let sync = !self.sync_deferred;
        let state_arc = self.state_adapter.clone();
        let trie = self.state_trie.clone();
        let writes = block_writes.clone();
        let version = block_height.as_u64();
        let storage = self.storage.clone();
        let (state_root, committed_at) =
            tokio::task::spawn_blocking(move || -> std::result::Result<(Hash, Instant), NodeError> {
                let (root, ops) = storage.hold_synced_writes(|| -> std::result::Result<Hash, NodeError> {
                    let state_adapter = state_arc.blocking_lock();
                    tenzro_storage::state_trie::capture::in_thread(writes.clone(), || {
                        state_adapter.commit()
                    })
                    .map_err(|e| NodeError::Other(format!("State commit error: {}", e)))?;
                    let mut committed = writes.take();
                    committed.extend(epoch_records);
                    // A protocol version that names another node hash
                    // re-commits the whole state under it at its first block.
                    let trie_scheme = tenzro_types::hash_scheme::block_hash_scheme(
                        block_for_store.header.metadata.protocol_version,
                        tenzro_types::hash_scheme::STATE_TRIE_HASH_SCHEMES,
                    );
                    if trie
                        .scheme_at(version)
                        .map_err(|e| NodeError::Other(format!("State trie scheme: {e}")))?
                        != trie_scheme
                    {
                        trie.recommit_under(version, trie_scheme).map_err(|e| {
                            NodeError::Other(format!("State trie re-commit error: {e}"))
                        })?;
                    }
                    let root = trie
                        .commit(version, &committed)
                        .map_err(|e| NodeError::Other(format!("State trie commit error: {}", e)))?;

                    tokio::runtime::Handle::current().block_on(async {
                        BlockStoreImpl::new(storage.clone())
                            .map_err(NodeError::Storage)?
                            .put_block(&block_for_store)
                            .await
                            .map_err(NodeError::Storage)
                    })?;
                    if !txs_for_index.is_empty() {
                        let block_hash_hex = block_hash.to_string();
                        let block_height_u64 = block_height.0;
                        let mut ops: Vec<WriteOp> = Vec::with_capacity(txs_for_index.len() * 3);
                        for (tx_index, signed_tx) in &txs_for_index {
                            let tx_hash = signed_tx.transaction.hash();
                            let hex_key = tx_hash.to_string();
                            match serde_json::to_vec(signed_tx) {
                                Ok(value) => ops.push(WriteOp::Put {
                                    cf: CF_TRANSACTIONS.to_string(),
                                    key: hex_key.as_bytes().to_vec(),
                                    value,
                                }),
                                Err(e) => {
                                    warn!(
                                        tx_hash = %tx_hash,
                                        error = %e,
                                        "Failed to serialize transaction for CF_TRANSACTIONS index; skipping"
                                    );
                                    continue;
                                }
                            }
                            let idx_value = serde_json::json!({
                                "block_height": block_height_u64,
                                "block_hash": block_hash_hex,
                                "tx_index": tx_index,
                            });
                            if let Ok(idx_bytes) = serde_json::to_vec(&idx_value) {
                                ops.push(WriteOp::Put {
                                    cf: CF_TRANSACTIONS.to_string(),
                                    key: format!("idx:{}", hex_key).into_bytes(),
                                    value: idx_bytes,
                                });
                            }
                        }

                        // Persist per-tx receipts. A sig-invalid tx in a finalized
                        // block has no receipt entry by design (see exec loop).
                        for (tx_hash, receipt) in &receipts_for_persist {
                            let hex_key = tx_hash.to_string();
                            match serde_json::to_vec(receipt) {
                                Ok(value) => ops.push(WriteOp::Put {
                                    cf: CF_TRANSACTIONS.to_string(),
                                    key: format!("receipt:{}", hex_key).into_bytes(),
                                    value,
                                }),
                                Err(e) => {
                                    warn!(
                                        tx_hash = %tx_hash,
                                        error = %e,
                                        "Failed to serialize tx receipt; skipping"
                                    );
                                }
                            }
                        }

                        // Each transaction under its sender and recipient.
                        ops.extend(
                            crate::transaction_index::block_ops(
                                storage.as_ref(),
                                block_height_u64,
                                &txs_for_index,
                            )
                            .map_err(NodeError::Other)?,
                        );

                        if !ops.is_empty() {
                            storage.write_batch_sync(ops).map_err(NodeError::Storage)?;
                        }
                    }

                    // The block's events, and the event log's tip at this height.
                    if let Some(ops) = event_log_writes {
                        storage.write_batch_sync(ops).map_err(NodeError::Storage)?;
                    }
                    Ok(root)
                });
                let root = root?;
                let committed_at = Instant::now();
                storage.write_held(ops, sync).map_err(NodeError::Storage)?;
                if version.is_multiple_of(STATE_TRIE_PRUNE_EVERY) && version > STATE_TRIE_RETAIN_HEIGHTS {
                    trie.prune(version - STATE_TRIE_RETAIN_HEIGHTS)
                        .map_err(|e| NodeError::Other(format!("State trie prune error: {}", e)))?;
                }
                Ok((root, committed_at))
            })
            .await
            .map_err(|e| NodeError::Other(format!("Block commit task panicked: {}", e)))??;

        info!(
            height = %block_height,
            state_root = %state_root,
            "State committed"
        );

        // The block's transactions leave the mempool, whichever node ordered
        // them, so no validator batches them again; only those a later block
        // can still run stay. They leave only now that the state they wrote is
        // in the store: until then the executed nonce read from storage does
        // not count them, and a `pending` nonce read in between would hand
        // their nonce out again. A block refused before this point keeps them.
        if let Some(consensus) = &self.consensus {
            let done: Vec<Hash> = block
                .transactions
                .iter()
                .map(|t| t.transaction.hash())
                .filter(|h| !pending_again.contains(h))
                .collect();
            consensus.mempool().remove_transactions(&done);
        }
        let persisted_at = Instant::now();
        debug!(
            height = block_height.0,
            execute_ms = executed_at.duration_since(started).as_secs_f64() * 1e3,
            commit_ms = committed_at.duration_since(executed_at).as_secs_f64() * 1e3,
            persist_ms = persisted_at.duration_since(committed_at).as_secs_f64() * 1e3,
            "block timings"
        );
        if let Some(log) = &self.event_log {
            log.advance(block_height.0);
        }

        // Update local height and hash tracking — only when this block extends the tip.
        // During gossip-driven catch-up the network may deliver historical blocks (out-of-order
        // or fork-resolution backfills) that finalize successfully but must NOT rewind the tip.
        // The block_hash mirror is only valid for the actual tip, so it's only updated alongside.
        if block_height.0 > self.current_height {
            self.current_height = block_height.0;
            self.last_block_hash = block_hash;
        }

        // Publish the new chain tip to the shared atomic so RPC can read the live height
        // without any storage I/O.  Use fetch_max so historical-block finalization (out-of-order
        // gossip during catch-up, fork-resolution backfills) cannot rewind the published tip.
        // Release ordering ensures all prior writes (block persist, state commit) are visible
        // to the Acquire load in the RPC handler.
        self.chain_tip.fetch_max(block_height.0, Ordering::Release);

        self.maybe_produce_snapshot(block_height);

        info!(
            height = %block_height,
            hash = %block_hash,
            tx_count = tx_count,
            successful = successful_txs,
            failed = failed_txs,
            gas_used = gas_used_total,
            state_root = %state_root,
            "Block finalized and persisted"
        );

        // Mirror the block's settled fees into the gas oracle, which serves
        // fee quotes and history to RPC callers and prices admission. The
        // values are the ones the block wrote to state, so every node quotes
        // the base fee the next block will actually charge.
        self.vm_runtime
            .gas_oracle()
            .record_settled_block(&fee_settlement)
            .await;
        // A block whose transactions paid nothing has no fee to record.
        if let Some(processor) = self.fee_processor.as_ref()
            && fee_settlement
                .to_treasury
                .saturating_add(fee_settlement.burned)
                > 0
            && let Err(e) = processor.process_fee(
                tenzro_types::asset::AssetId::tnzo(),
                tenzro_token::FeeSource::Transaction,
                fee_settlement.to_treasury,
                fee_settlement.burned,
                0,
            )
        {
            warn!(error = %e, "Fee processor accounting failed");
        }

        // roll the hot-state contention window forward by exactly one
        // block. The window is per-account, length-bounded at
        // `HOT_STATE_WINDOW_BLOCKS`; eviction happens inside the market.
        // Surcharge collection on hot accounts will be charged at admission
        // time (RPC) once per-tx fee accounting is wired through; this hook
        // is the per-block sample feed.
        self.vm_runtime
            .gas_oracle()
            .record_block_contention(block_contention);

        // Broadcast finalized block over gossip so other nodes can sync.
        // Only the block producer (node with consensus engine) broadcasts.
        // Non-validators receive blocks via gossip and should NOT re-broadcast
        // (the gossip layer passes accepted blocks on itself).
        //
        // This is done via tokio::spawn (fire-and-forget) so the event loop
        // never waits on the network while it is also the consumer of the
        // block subscription.
        // Skip gossip rebroadcast for sync-imported blocks. Rebroadcasting
        // historical blocks would amplify into the live topic and interleave
        // with current-tip blocks.
        if source == BlockSource::Ordered
            && let Some(ref network) = self.network
        {
            let network_clone = network.clone();
            let msg = NetworkMessage::new(MessagePayload::Block(block.clone()));
            let height_for_log = block_height;
            let hash_for_log = block_hash;
            tokio::spawn(async move {
                if let Err(e) = network_clone.broadcast("tenzro/blocks", msg).await {
                    warn!(
                        height = %height_for_log,
                        error = %e,
                        "Failed to broadcast finalized block over gossip"
                    );
                } else {
                    info!(
                        height = %height_for_log,
                        hash = %hash_for_log,
                        "Broadcast finalized block to network"
                    );
                }
            });
        }

        // The first block of a new consensus epoch closes the previous one:
        // every node sees it at the same height, because the epoch is part of
        // the header every validator built alike.
        let closing_epoch =
            (block.header.epoch > self.last_block_epoch).then_some(self.last_block_epoch);
        self.last_block_epoch = block.header.epoch;

        // Supply metrics for the adaptive-burn dial, once per epoch boundary,
        // from consensus state only (total supply and cumulative burn), so
        // every node, ordering or importing, records the same snapshot at the
        // same height.
        if closing_epoch.is_some()
            && let Some(burn_rate) = self.burn_rate_manager.as_ref()
        {
            let (supply, burned) = {
                let state = self.state_adapter.lock().await;
                (state.total_supply(), state.total_burned())
            };
            let snapshot = supply_snapshot(
                self.last_observed_supply,
                supply,
                burned,
                block_height,
                block.header.timestamp,
                burn_rate.targets().rolling_window_epochs,
            );
            match burn_rate.record_metrics(snapshot) {
                Ok(()) => self.last_observed_supply = Some((supply, burned)),
                Err(e) => {
                    warn!(error = %e, height = block_height.0, "Adaptive-burn record_metrics failed")
                }
            }
        }

        Ok(Some((block_hash, state_root)))
    }

    /// Handles a block received from the network via gossip.
    ///
    /// A block carries no signature of its own, so nothing about it can be
    /// trusted until a certificate covering its height arrives. It is held:
    /// gossip passes it on if its body matches its header, and refuses it
    /// (penalising the relay) otherwise. A validator executes its own
    /// ordering and ignores gossiped blocks.
    pub(crate) async fn handle_network_block(
        &mut self,
        block: Block,
        verdict: GossipVerdict,
    ) -> Result<()> {
        if block.height().0 <= self.current_height {
            return Ok(());
        }
        if block.verify_body().is_err() {
            verdict.reject();
            return Err(NodeError::Other(format!(
                "gossiped block at height {} carries a body its header does not commit",
                block.height()
            )));
        }
        verdict.accept();
        if !self.orders_blocks() {
            self.hold_uncertified(block);
        }
        Ok(())
    }

    /// Initiates shutdown
    pub fn shutdown(&self) {
        let _ = self.event_tx.try_send(NodeEvent::Shutdown);
        let _ = self.shutdown_tx.send(());
    }

    /// Index each token a transaction created.
    fn process_token_created_logs(&self, result: &tenzro_vm::ExecutionResult) {
        let Some(registry) = self.token_registry.as_ref() else {
            return;
        };
        let topic = tenzro_vm::token_ledger::token_created_topic();
        for log in &result.logs {
            if log.address != tenzro_vm::precompiles::PRECOMPILE_TOKEN_FACTORY
                || log.topics.first().map(|t| t.as_slice()) != Some(topic.as_slice())
            {
                continue;
            }
            let (Some(id), Ok(record)) = (
                log.topics
                    .get(1)
                    .and_then(|t| <[u8; 32]>::try_from(t.as_slice()).ok()),
                serde_json::from_slice::<tenzro_vm::token_ledger::TokenRecord>(&log.data),
            ) else {
                warn!("Malformed TokenCreated log, skipping");
                continue;
            };
            if let Err(e) = registry.index_created(
                id,
                &record.name,
                &record.symbol,
                record.decimals,
                &record.creator,
            ) {
                warn!(token = %hex::encode(id), error = %e, "Token index did not take a creation");
            }
        }
    }

    /// Reflect the canonical ERC-8004 `Registered(uint256 indexed
    /// agentId, string agentURI, address indexed owner)` event emitted
    /// by the on-chain `IdentityRegistry` proxy at
    /// `tenzro_identity::erc8004::addresses::IDENTITY_REGISTRY` into the
    /// off-chain `did → agentId` index stored in `CF_IDENTITIES` under
    /// the `erc8004_did_index:` prefix (see
    /// `crate::erc8004_mirror::ERC8004_DID_INDEX_PREFIX`), and patch
    /// the matching TDIP `Machine` identity's `erc8004_agent_id` field
    /// via `IdentityRegistry::apply_erc8004_registered_event`.
    ///
    /// This is the **other half** of the locked async-detached-spawn
    /// architecture (see `project_erc8004_evm_architecture` memory):
    /// `NativeErc8004Mirror::mirror_register_agent` dispatches the
    /// signed EVM tx and returns immediately; the resulting
    /// `Registered` event lands here when the block is applied, and
    /// this function closes the loop by populating the off-chain
    /// index that `lookup_agent_id_by_did` reads.
    ///
    /// The function is filter-by-address + filter-by-topic[0]: it only
    /// considers logs whose address matches `IDENTITY_REGISTRY` and
    /// whose first topic is
    /// `keccak256("Registered(uint256,string,address)")`. Logs that
    /// fail either filter are ignored.
    ///
    /// Decoded event layout (per Solidity ABI):
    /// - `topics[0]` = 32-byte event signature hash
    /// - `topics[1]` = 32-byte big-endian `uint256 agentId` (indexed)
    /// - `topics[2]` = 32-byte left-padded `address owner` (indexed)
    /// - `data`      = ABI-encoded `string agentURI`:
    ///   `offset(32)=0x20 || length_be(32) || padded_utf8_bytes`
    ///
    /// **DID derivation:** the canonical contract has no DID concept;
    /// the `did:tenzro:...` is conveyed in the `agentURI` payload
    /// itself. We parse it by recognising the well-known prefix
    /// `did:tenzro:` at the very start of the decoded URI string. Any
    /// other URI shape (HTTP, IPFS, plain text) is logged and skipped
    /// — it's a legitimate non-Tenzro agent registration that we have
    /// no DID to index.
    ///
    /// Idempotent: re-applying the same `Registered` event after a
    /// reorg / restart writes the same `(did, agent_id)` pair and
    /// leaves the TDIP record's `erc8004_agent_id` unchanged.
    async fn process_erc8004_registered_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        use std::sync::OnceLock;
        use tenzro_identity::erc8004::addresses;

        // Lazy-compute the event signature hash once per process.
        // `keccak256("Registered(uint256,string,address)")`.
        static REGISTERED_TOPIC: OnceLock<[u8; 32]> = OnceLock::new();
        let registered_topic = REGISTERED_TOPIC.get_or_init(|| {
            tenzro_crypto::hash::keccak256(b"Registered(uint256,string,address)").to_bytes()
        });

        // Fast-path: most blocks have no ERC-8004 logs at all.
        let any_registered = result.logs.iter().any(|l| {
            l.address.as_slice() == addresses::IDENTITY_REGISTRY
                && l.topics
                    .first()
                    .map(|t| t.as_slice() == registered_topic.as_slice())
                    .unwrap_or(false)
        });
        if !any_registered {
            return;
        }

        for log in &result.logs {
            if log.address.as_slice() != addresses::IDENTITY_REGISTRY {
                continue;
            }
            if log.topics.first().map(|t| t.as_slice()) != Some(registered_topic.as_slice()) {
                continue;
            }
            // Need topics[0..=2] for sig / agentId / owner.
            if log.topics.len() < 3 {
                warn!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    topic_count = log.topics.len(),
                    "Registered log has fewer than 3 topics; skipping"
                );
                continue;
            }

            // Decode agentId from topics[1] (32-byte big-endian uint256).
            // We accept anything that fits in u64 — Tenzro genesis allocates
            // ids from 1 and will not overflow u64 within any realistic
            // testnet/mainnet horizon. Values with non-zero high 192 bits
            // are rejected loudly.
            let id_bytes = log.topics[1].as_slice();
            if id_bytes.len() != 32 {
                warn!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    len = id_bytes.len(),
                    "Registered topic[1] (agentId) has unexpected length; skipping"
                );
                continue;
            }
            if id_bytes[..24].iter().any(|b| *b != 0) {
                warn!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    "Registered agentId exceeds u64 — high 192 bits non-zero; skipping"
                );
                continue;
            }
            let mut id_buf = [0u8; 8];
            id_buf.copy_from_slice(&id_bytes[24..32]);
            let agent_id = u64::from_be_bytes(id_buf);

            // Decode the `string agentURI` from `data`. The ABI layout
            // for a single dynamic string is:
            //   offset (32)  = always 0x20
            //   length (32)  = big-endian byte count
            //   payload      = utf-8 bytes, right-padded to 32-byte word
            let did = match decode_single_string_abi(&log.data) {
                Some(s) => s,
                None => {
                    warn!(
                        target: "tenzro::erc8004::listener",
                        block_height = block_height.0,
                        agent_id,
                        data_len = log.data.len(),
                        "Registered.agentURI ABI-decode failed; skipping"
                    );
                    continue;
                }
            };

            // Only index DIDs that start with `did:tenzro:`. Any other URI
            // shape (HTTPS metadata, IPFS, opaque agentURI from a
            // non-Tenzro registrant) is a legitimate canonical-contract
            // registration but carries no DID we can key on.
            if !did.starts_with("did:tenzro:") {
                debug!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    agent_id,
                    uri_prefix = %did.chars().take(16).collect::<String>(),
                    "Registered.agentURI is not a did:tenzro: URI; not indexed"
                );
                continue;
            }

            // 1. Write the off-chain did → agentId index.
            let key = crate::erc8004_mirror::did_index_key(&did);
            let val = agent_id.to_be_bytes();
            if let Err(e) = self.storage.put(tenzro_storage::CF_IDENTITIES, &key, &val) {
                warn!(
                    target: "tenzro::erc8004::listener",
                    did = %did,
                    agent_id,
                    error = %e,
                    "Failed to write erc8004_did_index entry; subsequent lookups will miss"
                );
                continue;
            }

            // 2. Patch the in-memory TDIP record's `erc8004_agent_id`
            //    field so callers reading the identity see the bound
            //    agent id without an extra RocksDB hop. The patch is a
            //    no-op on remote-node records that haven't been
            //    locally registered.
            if let Some(registry) = self.identity_registry.as_ref() {
                match registry.apply_erc8004_registered_event(&did, agent_id) {
                    Ok(true) => {
                        debug!(
                            target: "tenzro::erc8004::listener",
                            block_height = block_height.0,
                            did = %did,
                            agent_id,
                            "ERC-8004 Registered event reflected into TDIP identity"
                        );
                    }
                    Ok(false) => {
                        debug!(
                            target: "tenzro::erc8004::listener",
                            block_height = block_height.0,
                            did = %did,
                            agent_id,
                            "ERC-8004 Registered event indexed in RocksDB; \
                             no local TDIP identity to patch (foreign-node registration)"
                        );
                    }
                    Err(e) => {
                        warn!(
                            target: "tenzro::erc8004::listener",
                            block_height = block_height.0,
                            did = %did,
                            agent_id,
                            error = %e,
                            "Failed to apply Registered event to TDIP identity"
                        );
                    }
                }
            }
        }
    }

    /// Mirror VM-emitted `IdentityRegister` logs into the local
    /// [`IdentityRegistry`].
    ///
    /// DID uniqueness was already decided by `execute_identity_register`
    /// against consensus state — every node re-ran the same handler over the
    /// same ordered transactions, so the `identity:<did>` marker under
    /// `SYSTEM_ADDRESS` is the source of truth. This only reflects that
    /// decision into the DID→identity read model the RPC resolve path uses,
    /// which is what makes an identity created on ANY node resolve on ALL
    /// nodes.
    ///
    /// Errors are logged and never abort the block: a divergent read model is
    /// recoverable on restart via `load_from_storage`, and the origin node's
    /// authoritative record is left untouched (`upsert_from_chain` is
    /// origin-safe and idempotent).
    async fn process_identity_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        let any_identity = result.logs.iter().any(|l| {
            l.topics
                .first()
                .map(|t| {
                    let s = t.as_slice();
                    s == b"IdentityRegister"
                        || s == b"IdentityRevoked"
                        || s == tenzro_vm::native::machine_attestation::MACHINE_ATTESTATION_ATTACHED_TOPIC
                })
                .unwrap_or(false)
        });
        if !any_identity {
            return;
        }

        let Some(registry) = self.identity_registry.as_ref() else {
            debug!(
                block_height = block_height.0,
                "Identity log observed but IdentityRegistry not wired; skipping reflection"
            );
            return;
        };

        crate::identity_mirror::mirror_identity_logs(
            registry,
            self.auth_engine.as_deref(),
            &result.logs,
        );
    }

    /// Reflect VM-emitted validator-registry logs into the off-chain
    /// `ValidatorRegistry` (Dynamic Validator Set).
    ///
    /// Decodes `ValidatorRegister` / `ValidatorExit` / `ValidatorMetadataUpdate`
    /// log payloads matching the wire layouts produced by the native VM
    /// handlers in `tenzro-vm/src/native/mod.rs` and applies them to the
    /// registry. The registry is the read model consensus reads from at
    /// epoch boundaries; the VM is the source of truth for the on-chain
    /// `validator_register:<hex>` / `validator_exit:<hex>` markers.
    ///
    /// Errors are logged but never abort the block — divergence between
    /// the VM marker and the registry is recoverable on restart via
    /// `load_from_storage`.
    async fn process_validator_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        let any_validator = result.logs.iter().any(|l| {
            l.topics
                .first()
                .map(|t| {
                    let s = t.as_slice();
                    s == b"ValidatorRegister"
                        || s == b"ValidatorExit"
                        || s == tenzro_vm::native::VALIDATOR_KEY_ROTATION_TOPIC
                        || s == b"ValidatorMetadataUpdate"
                        || s == b"ValidatorStakeIncreased"
                        || s == b"CheckpointEquivocation"
                        || s == tenzro_vm::native::sponsored_bond::SPONSORED_TOPIC
                        || s == tenzro_vm::native::sponsored_bond::RECALLED_TOPIC
                })
                .unwrap_or(false)
        });
        if !any_validator {
            return;
        }

        let registry = match self.validator_registry.as_ref() {
            Some(r) => r.clone(),
            None => {
                debug!(
                    block_height = block_height.0,
                    "Validator log observed but ValidatorRegistry not wired; skipping reflection"
                );
                return;
            }
        };

        // Map block height → epoch via the consensus engine, falling back to
        // 0 when no consensus is wired (e.g. unit tests). The registry only
        // uses the epoch number for ordering and cooldown gating, so a
        // monotonic stand-in is acceptable in degraded mode.
        // EpochManager::current_epoch() is sync and returns Epoch (with .number).
        let current_epoch = match self.consensus.as_ref() {
            Some(c) => c.epoch_manager().current_epoch().number,
            None => 0,
        };

        for log in &result.logs {
            let topic = match log.topics.first() {
                Some(t) => t.as_slice(),
                None => continue,
            };

            if topic == tenzro_vm::native::sponsored_bond::SPONSORED_TOPIC
                || topic == tenzro_vm::native::sponsored_bond::RECALLED_TOPIC
            {
                let Ok(event) = serde_json::from_slice::<
                    tenzro_vm::native::sponsored_bond::SponsoredBondEvent,
                >(&log.data) else {
                    warn!(
                        len = log.data.len(),
                        "Malformed sponsored-bond log; skipping"
                    );
                    continue;
                };
                // The sponsored part counts toward the bond the registry
                // admits and seats by; a recall takes it back out.
                let mirrored = if topic == tenzro_vm::native::sponsored_bond::SPONSORED_TOPIC {
                    registry.increase_self_stake(&event.validator, event.amount)
                } else {
                    registry.recall_sponsored_stake(&event.validator, event.amount)
                };
                match mirrored {
                    Ok(total) => info!(
                        validator = %event.validator,
                        amount = event.amount,
                        total,
                        "Validator sponsored bond mirrored"
                    ),
                    Err(e) => warn!(
                        validator = %event.validator,
                        error = %e,
                        "ValidatorRegistry rejected a sponsored-bond mirror; \
                         registry is out of step with chain state"
                    ),
                }
                continue;
            }

            match topic {
                b"ValidatorStakeIncreased" => {
                    // Layout: from(32) || additional_le(16) || new_total_le(16)
                    if log.data.len() < 64 {
                        warn!(
                            len = log.data.len(),
                            "Malformed ValidatorStakeIncreased log; skipping"
                        );
                        continue;
                    }
                    let mut addr_bytes = [0u8; 32];
                    addr_bytes.copy_from_slice(&log.data[..32]);
                    let address = tenzro_types::primitives::Address::new(addr_bytes);
                    let mut add_bytes = [0u8; 16];
                    add_bytes.copy_from_slice(&log.data[32..48]);
                    let additional = u128::from_le_bytes(add_bytes);

                    match registry.increase_self_stake(&address, additional) {
                        Ok(total) => info!(
                            validator = %address,
                            additional,
                            total,
                            "Validator self-stake increased"
                        ),
                        // Non-fatal: the VM already moved the funds and is the
                        // source of truth. A registry that rejects the mirror is
                        // out of step with chain state and says so, rather than
                        // failing the block that already committed.
                        Err(e) => warn!(
                            validator = %address,
                            error = %e,
                            "ValidatorRegistry rejected increase_self_stake; \
                             registry is out of step with chain state"
                        ),
                    }
                }
                b"ValidatorRegister" => {
                    let parsed = match decode_validator_register_log(&log.data) {
                        Some(v) => v,
                        None => {
                            warn!(
                                data_len = log.data.len(),
                                "Malformed ValidatorRegister log payload, skipping"
                            );
                            continue;
                        }
                    };
                    let from_addr = parsed.from;
                    if let Err(e) = registry.register_candidate(
                        from_addr,
                        parsed.ml_dsa_pubkey,
                        parsed.p256_pubkey,
                        parsed.node_key,
                        parsed.withdrawal_address,
                        parsed.self_stake,
                        current_epoch,
                        parsed.metadata_uri,
                    ) {
                        warn!(
                            address = %from_addr,
                            error = %e,
                            "ValidatorRegistry rejected register_candidate; \
                             on-chain marker may have outpaced registry state"
                        );
                    } else {
                        debug!(
                            address = %from_addr,
                            self_stake = parsed.self_stake,
                            epoch = current_epoch,
                            "ValidatorRegistry reflected ValidatorRegister log"
                        );
                    }
                }

                b"ValidatorExit" => {
                    let from_addr = match tenzro_vm::native::validator_exit_log_account(&log.data)
                        .and_then(tenzro_types::primitives::Address::from_bytes)
                    {
                        Some(a) => a,
                        None => {
                            warn!(
                                data_len = log.data.len(),
                                "Malformed ValidatorExit log payload, skipping"
                            );
                            continue;
                        }
                    };
                    if let Err(e) = registry.request_exit(&from_addr) {
                        warn!(
                            address = %from_addr,
                            error = %e,
                            "ValidatorRegistry rejected request_exit"
                        );
                    } else {
                        debug!(
                            address = %from_addr,
                            "ValidatorRegistry reflected ValidatorExit log"
                        );
                    }
                }

                t if t == tenzro_vm::native::VALIDATOR_KEY_ROTATION_TOPIC => {
                    let Some((account, ml_dsa, ecdsa)) =
                        tenzro_vm::native::decode_validator_key_rotation_log(&log.data)
                    else {
                        warn!("Malformed ValidatorKeyRotation log payload, skipping");
                        continue;
                    };
                    let Some(addr) = tenzro_types::primitives::Address::from_bytes(account) else {
                        continue;
                    };
                    if let Err(e) =
                        registry.request_key_rotation(&addr, ml_dsa.to_vec(), ecdsa.to_vec())
                    {
                        warn!(address = %addr, error = %e, "ValidatorRegistry rejected a key rotation");
                    }
                }

                b"ValidatorMetadataUpdate" => {
                    let parsed = match decode_validator_metadata_update_log(&log.data) {
                        Some(v) => v,
                        None => {
                            warn!(
                                data_len = log.data.len(),
                                "Malformed ValidatorMetadataUpdate log payload, skipping"
                            );
                            continue;
                        }
                    };
                    let from_addr = parsed.from;
                    let uri = if parsed.metadata_uri.is_empty() {
                        None
                    } else {
                        Some(parsed.metadata_uri)
                    };
                    if let Err(e) =
                        registry.update_metadata(&from_addr, uri, parsed.tee_attestation_hash)
                    {
                        warn!(
                            address = %from_addr,
                            error = %e,
                            "ValidatorRegistry rejected update_metadata"
                        );
                    } else {
                        debug!(
                            address = %from_addr,
                            "ValidatorRegistry reflected ValidatorMetadataUpdate log"
                        );
                    }
                }

                b"CheckpointEquivocation" => {
                    // Layout: epoch_be(8) || index_be(8) || p256(65) || ml_dsa
                    if log.data.len() < 16 + 65 {
                        warn!(
                            len = log.data.len(),
                            "Malformed CheckpointEquivocation log; skipping"
                        );
                        continue;
                    }
                    let epoch = u64::from_be_bytes(log.data[..8].try_into().expect("8 bytes"));
                    let index = u64::from_be_bytes(log.data[8..16].try_into().expect("8 bytes"));
                    let (p256, ml_dsa) = log.data[16..].split_at(65);
                    let Some(entry) = registry
                        .list()
                        .into_iter()
                        .find(|e| e.p256_pubkey == p256 && e.ml_dsa_pubkey == ml_dsa)
                    else {
                        warn!(
                            epoch,
                            index, "Checkpoint equivocation by a key the registry does not hold"
                        );
                        continue;
                    };
                    if let Some(jailer) = self.equivocation_jailer.as_ref() {
                        jailer.report_checkpoint_equivocation(&entry.address, epoch, index);
                    }
                }

                _ => {}
            }
        }
    }
}

/// Decode a Solidity ABI-encoded single dynamic `string` from a log
/// `data` payload. Layout:
///
/// ```text
///   offset (32 bytes, big-endian) — always 0x20 for a single dynamic head
///   length (32 bytes, big-endian) — utf-8 byte count
///   payload (length bytes, right-padded to a 32-byte word)
/// ```
///
/// Returns `None` if the payload is shorter than 64 bytes, the offset
/// word is not 0x20, the declared length overflows the remaining buffer,
/// or the payload bytes are not valid UTF-8. Trailing zero-padding bytes
/// after `length` are tolerated — only the first `length` bytes are
/// decoded.
fn decode_single_string_abi(data: &[u8]) -> Option<String> {
    if data.len() < 64 {
        return None;
    }
    // Offset word: must be exactly 0x20 (32-byte big-endian) for a
    // single dynamic-string head. Anything else is a malformed payload
    // (or a multi-arg event we shouldn't be decoding with this helper).
    if data[..31].iter().any(|b| *b != 0) || data[31] != 0x20 {
        return None;
    }
    // Length word: u256 big-endian; we reject anything that doesn't
    // fit in usize on this platform.
    if data[32..56].iter().any(|b| *b != 0) {
        return None;
    }
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&data[56..64]);
    let len = u64::from_be_bytes(len_buf) as usize;
    let body = data.get(64..64usize.checked_add(len)?)?;
    std::str::from_utf8(body).ok().map(|s| s.to_string())
}

/// Parsed payload of a `ValidatorRegister` log.
struct ParsedValidatorRegister {
    from: tenzro_types::primitives::Address,
    self_stake: u128,
    node_key: [u8; 32],
    p256_pubkey: Vec<u8>,
    ml_dsa_pubkey: Vec<u8>,
    withdrawal_address: tenzro_types::primitives::Address,
    metadata_uri: String,
}

/// Decode a `ValidatorRegister` log.
///
/// Layout (mirror of the inline emit in
/// `tenzro_vm::native::execute_validator_register`):
/// `from(32) || stake_le(16) || node_key(32) || p256_pubkey(65) ||
///  ml_dsa_pubkey_len_le(4) || ml_dsa_pubkey || withdrawal(32) ||
///  metadata_uri_len_le(4) || metadata_uri`.
fn decode_validator_register_log(data: &[u8]) -> Option<ParsedValidatorRegister> {
    // 32 from + 16 stake + 32 node key + 65 p256 + 4 ml_dsa_len = 149 bytes minimum
    const HEAD: usize = 149;
    if data.len() < HEAD {
        return None;
    }
    let from = tenzro_types::primitives::Address::from_bytes(&data[0..32])?;
    let self_stake = u128::from_le_bytes(data[32..48].try_into().ok()?);
    let node_key: [u8; 32] = data[48..80].try_into().ok()?;
    let p256_pubkey = data[80..145].to_vec();
    let pq_len = u32::from_le_bytes(data[145..HEAD].try_into().ok()?) as usize;
    let after_pq = HEAD.checked_add(pq_len)?;
    // Need the ML-DSA key + 32 withdrawal + 4 uri_len after that
    if data.len() < after_pq + 32 + 4 {
        return None;
    }
    let ml_dsa_pubkey = data[HEAD..after_pq].to_vec();
    let withdrawal_address =
        tenzro_types::primitives::Address::from_bytes(&data[after_pq..after_pq + 32])?;
    let after_withdrawal = after_pq + 32;
    let uri_len = u32::from_le_bytes(
        data[after_withdrawal..after_withdrawal + 4]
            .try_into()
            .ok()?,
    ) as usize;
    let after_uri_len = after_withdrawal + 4;
    if data.len() < after_uri_len + uri_len {
        return None;
    }
    let metadata_uri = std::str::from_utf8(&data[after_uri_len..after_uri_len + uri_len])
        .ok()?
        .to_string();
    Some(ParsedValidatorRegister {
        from,
        self_stake,
        node_key,
        p256_pubkey,
        ml_dsa_pubkey,
        withdrawal_address,
        metadata_uri,
    })
}

/// Parsed payload of a `ValidatorMetadataUpdate` log.
struct ParsedValidatorMetadataUpdate {
    from: tenzro_types::primitives::Address,
    metadata_uri: String,
    tee_attestation_hash: Option<[u8; 32]>,
}

/// Decode a `ValidatorMetadataUpdate` log.
///
/// Layout (mirror of the inline emit in
/// `tenzro_vm::native::execute_validator_update_metadata`):
/// `from(32) || metadata_uri_len_le(4) || metadata_uri ||
///  tee_hash_present(1) || [tee_hash(32)]`.
fn decode_validator_metadata_update_log(data: &[u8]) -> Option<ParsedValidatorMetadataUpdate> {
    // 32 from + 4 uri_len + 1 tee_present = 37 bytes minimum
    if data.len() < 37 {
        return None;
    }
    let from = tenzro_types::primitives::Address::from_bytes(&data[0..32])?;
    let uri_len = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
    let after_uri_len = 36usize;
    let after_uri = after_uri_len.checked_add(uri_len)?;
    if data.len() < after_uri + 1 {
        return None;
    }
    let metadata_uri = std::str::from_utf8(&data[after_uri_len..after_uri])
        .ok()?
        .to_string();
    let tee_present = data[after_uri];
    let tee_attestation_hash = match tee_present {
        0 => None,
        1 => {
            if data.len() < after_uri + 1 + 32 {
                return None;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[after_uri + 1..after_uri + 1 + 32]);
            Some(h)
        }
        _ => return None,
    };
    Some(ParsedValidatorMetadataUpdate {
        from,
        metadata_uri,
        tee_attestation_hash,
    })
}

/// Verifies the P-256 leg of a transaction's signature when its key names
/// the `from` account. It reads no state. A key that does not name the
/// account must be a passkey of the account's keystore: that, and the
/// passkey's assertion for the relying party the keystore records for it,
/// are checked against state at admission by [`verify_transaction_sender`]
/// and at execution by the VM, as is the ML-DSA-65 leg against the key
/// enrolled for the P-256 key ([`verify_transaction_pq_leg`]).
///
/// The message is `Transaction::hash()` under the transaction signature
/// context, so a signature minted for another protocol does not verify here.
/// The protocol version a block at `height` carries: its parent's, or the
/// major version an enacted protocol upgrade names once the block reaches
/// the upgrade's activation height. It never goes back. The version selects
/// how the header is hashed ([`tenzro_types::hash_scheme`]).
pub(crate) fn block_protocol_version(
    parent: u32,
    height: u64,
    activation: Option<&tenzro_vm::governance::UpgradeActivation>,
) -> u32 {
    let named = activation
        .filter(|a| height >= a.activation_height)
        .and_then(|a| a.version.split('.').next()?.trim().parse::<u32>().ok());
    named.map_or(parent, |v| v.max(parent))
}

pub(crate) fn verify_transaction_signature(signed_tx: &SignedTransaction) -> Result<()> {
    use tenzro_crypto::composite::{SignatureContext, verify_classical_component};

    if signed_tx.transaction.tx_type.is_external() {
        return verify_external_transaction(signed_tx);
    }

    let classical = signed_tx.signature.has_classical_leg();
    if !classical && signed_tx.signature.pq.is_none() {
        return Err(NodeError::InvalidTransaction(
            "transaction signature is empty".to_string(),
        ));
    }
    if !tenzro_crypto::controls_account(
        &signed_tx.public_key,
        signed_tx.transaction.from.as_bytes(),
    ) {
        // A passkey of the sender's keystore: its assertion is checked
        // against state, so it must be there.
        if !classical {
            return Err(NodeError::InvalidTransaction(
                "a passkey signature has no assertion".to_string(),
            ));
        }
        return Ok(());
    }
    if !classical {
        // The account's retirement of its P-256 leg, and its ML-DSA-65 leg,
        // are checked against state.
        return Ok(());
    }
    let tx_hash = signed_tx.transaction.hash();
    verify_classical_component(
        &signed_tx.public_key,
        SignatureContext::Transaction,
        tx_hash.as_bytes(),
        &signed_tx.signature.classical,
    )
    .map_err(|e| NodeError::InvalidTransaction(format!("transaction signature: {e}")))
}

/// Verifies a transaction signed by an external wallet: decodes the raw
/// bytes, verifies the wallet's signature (secp256k1 recovery for EVM,
/// Ed25519 for every Solana signer) and checks that the envelope names what
/// the wallet signed. It reads no state.
pub(crate) fn verify_external_transaction(signed_tx: &SignedTransaction) -> Result<()> {
    use tenzro_vm::external_tx::{SVM_GAS_LIMIT, decode_evm_raw, decode_svm_wire, evm_account};

    let tx = &signed_tx.transaction;
    let refuse = |m: String| NodeError::InvalidTransaction(format!("external transaction: {m}"));
    if signed_tx.signature.has_classical_leg() || !signed_tx.public_key.is_empty() {
        return Err(refuse(
            "the signature belongs inside the raw bytes".to_string(),
        ));
    }
    match &tx.tx_type {
        TransactionType::ExternalEvm { raw } => {
            let ext = decode_evm_raw(raw, tx.chain_id.0).map_err(|e| refuse(e.to_string()))?;
            let to = ext.to.map(evm_account).unwrap_or([0u8; 32]);
            if tx.from.as_bytes()[..] != evm_account(ext.from)[..]
                || tx.to.as_bytes()[..] != to[..]
                || tx.nonce.0 != ext.nonce
                || tx.gas_limit != ext.gas_limit
            {
                return Err(refuse(
                    "the envelope differs from the signed transaction".to_string(),
                ));
            }
            let intrinsic = ext.intrinsic_gas();
            if ext.gas_limit < intrinsic {
                return Err(refuse(format!(
                    "intrinsic gas too low: gas {} below {intrinsic}",
                    ext.gas_limit
                )));
            }
        }
        TransactionType::ExternalSvm { raw } => {
            let ext = decode_svm_wire(raw).map_err(|e| refuse(e.to_string()))?;
            let payer = ext
                .signers
                .first()
                .ok_or_else(|| refuse("no fee payer".to_string()))?;
            if tx.from.as_bytes()[..] != payer[..]
                || tx.to != tx.from
                || tx.gas_limit != SVM_GAS_LIMIT
            {
                return Err(refuse(
                    "the envelope differs from the signed transaction".to_string(),
                ));
            }
        }
        _ => return Err(refuse("not an external transaction".to_string())),
    }
    Ok(())
}

/// The gas price a transaction pays per unit of gas in a block with
/// `base_fee`: an EIP-1559 or EIP-7702 wallet transaction pays
/// `min(maxFeePerGas, base_fee + maxPriorityFeePerGas)` (what the ledger
/// charges), every other transaction its gas price.
/// The gas price a receipt reports: the offered `price`, or what the sender
/// actually paid per unit of gas when the ledger could take only part of the
/// fee (or none of it), so a receipt never shows a fee that was not charged.
fn charged_gas_price(price: u64, gas_used: u64, fee_paid: u128) -> u64 {
    if gas_used == 0 || fee_paid >= u128::from(price) * u128::from(gas_used) {
        return price;
    }
    u64::try_from(fee_paid / u128::from(gas_used)).unwrap_or(price)
}

fn paid_gas_price(tx: &SignedTransaction, base_fee: u128) -> u64 {
    if let TransactionType::ExternalEvm { raw } = &tx.transaction.tx_type
        && let Ok(evm) = tenzro_vm::external_tx::decode_evm_raw(raw, tx.transaction.chain_id.0)
        && let Ok(price) = evm.effective_gas_price(base_fee)
    {
        return u64::try_from(price).unwrap_or(u64::MAX);
    }
    tx.transaction.gas_price
}

/// The consensus envelope of a signed RLP Ethereum transaction, verified.
/// Returns it with the keccak256 hash wallets look the transaction up by.
pub(crate) fn external_evm_envelope(
    raw: Vec<u8>,
    chain_id: u64,
) -> Result<(SignedTransaction, [u8; 32])> {
    use tenzro_vm::external_tx::{decode_evm_raw, evm_account};

    let ext = decode_evm_raw(&raw, chain_id)
        .map_err(|e| NodeError::InvalidTransaction(format!("external transaction: {e}")))?;
    let signed_tx = SignedTransaction::external(tenzro_types::Transaction::new(
        tenzro_types::primitives::ChainId(chain_id),
        Address(evm_account(ext.from)),
        ext.to
            .map(|a| Address(evm_account(a)))
            .unwrap_or_else(Address::zero),
        tenzro_types::primitives::Nonce(ext.nonce),
        TransactionType::ExternalEvm { raw },
        ext.gas_limit,
        u64::try_from(ext.max_fee_per_gas).unwrap_or(u64::MAX),
    ));
    verify_external_transaction(&signed_tx)?;
    Ok((signed_tx, ext.hash))
}

/// The consensus envelope of a Solana wire transaction from its fee payer at
/// ledger `nonce`, verified. Returns it with its first signature.
pub(crate) fn external_svm_envelope(
    raw: Vec<u8>,
    chain_id: u64,
    nonce: u64,
    gas_price: u64,
) -> Result<(SignedTransaction, [u8; 64])> {
    let ext = tenzro_vm::external_tx::decode_svm_wire(&raw)
        .map_err(|e| NodeError::InvalidTransaction(format!("external transaction: {e}")))?;
    let payer = Address(ext.signers[0]);
    let signed_tx = SignedTransaction::external(tenzro_types::Transaction::new(
        tenzro_types::primitives::ChainId(chain_id),
        payer,
        payer,
        tenzro_types::primitives::Nonce(nonce),
        TransactionType::ExternalSvm { raw },
        tenzro_vm::external_tx::SVM_GAS_LIMIT,
        gas_price,
    ));
    verify_external_transaction(&signed_tx)?;
    Ok((signed_tx, ext.signature))
}

/// The VM transaction an external wallet transaction executes as, at the
/// block's base fee. Called only after [`verify_external_transaction`].
fn external_vm_transaction(
    signed_tx: &SignedTransaction,
    base_fee: u128,
) -> std::result::Result<VmTransaction, tenzro_vm::VmError> {
    use tenzro_vm::external_tx::{decode_evm_raw, decode_svm_wire};

    let tx = &signed_tx.transaction;
    let mut vm_tx = match &tx.tx_type {
        TransactionType::ExternalEvm { raw } => {
            decode_evm_raw(raw, tx.chain_id.0)?.to_vm_transaction(base_fee)?
        }
        TransactionType::ExternalSvm { raw } => {
            decode_svm_wire(raw)?.to_vm_transaction(tx.nonce.0, base_fee, tx.chain_id.0)?
        }
        _ => {
            return Err(tenzro_vm::VmError::InvalidTransaction(
                "not an external transaction".to_string(),
            ));
        }
    };
    vm_tx.valid_until_ms = Some(tx.valid_until.0);
    Ok(vm_tx)
}

/// Verifies the ML-DSA-65 leg of a transaction against the key its account
/// has enrolled in `state`: once one is enrolled, a transaction without the
/// leg is refused at admission. A leg on an account with none enrolled is
/// left to execution, which sees any enrollment ordered before it.
/// Verifies that a transaction's signing key may act for its `from`
/// account: the key names the account, or it is a passkey of the account's
/// keystore on chain that may act alone (or, for a change to that keystore,
/// any of its passkeys), whose assertion is verified here for the relying
/// party the keystore records for it.
pub(crate) fn verify_transaction_sender(
    signed_tx: &SignedTransaction,
    state: &dyn tenzro_vm::traits::VmState,
) -> Result<()> {
    verify_transaction_sender_at(signed_tx, state, crate::calendar::now_ms())
}

/// [`verify_transaction_sender`] at `now_ms`.
pub(crate) fn verify_transaction_sender_at(
    signed_tx: &SignedTransaction,
    state: &dyn tenzro_vm::traits::VmState,
    now_ms: u64,
) -> Result<()> {
    let tx = &signed_tx.transaction;
    if tx.tx_type.is_external()
        || tenzro_crypto::controls_account(&signed_tx.public_key, tx.from.as_bytes())
    {
        return Ok(());
    }
    let update = match &tx.tx_type {
        TransactionType::KeystoreUpdate { update } => Some(update),
        _ => None,
    };
    tenzro_vm::keystore::authorize_signer(
        state,
        tx.from.as_bytes(),
        &signed_tx.public_key,
        Some(&signed_tx.signature),
        tx.hash().as_bytes(),
        update,
        tx.chain_id.0,
        now_ms,
    )
    .map_err(|e| NodeError::InvalidTransaction(format!("transaction sender: {e}")))
}

pub(crate) fn verify_transaction_pq_leg(
    signed_tx: &SignedTransaction,
    state: &dyn tenzro_vm::traits::VmState,
) -> Result<()> {
    use tenzro_crypto::composite::{SignatureContext, verify_pq_component};

    if signed_tx.transaction.tx_type.is_external() {
        return Ok(());
    }
    if !signed_tx.signature.has_classical_leg()
        && !tenzro_vm::account_keys::p256_retired(state, &signed_tx.public_key)
    {
        return Err(NodeError::InvalidTransaction(
            "transaction signature: no P-256 leg, and the account has not retired it".to_string(),
        ));
    }
    let op = match &signed_tx.transaction.tx_type {
        TransactionType::AccountKeys { op } => Some(op),
        _ => None,
    };
    let (expected, policy) = tenzro_vm::account_keys::pq_key_for(state, &signed_tx.public_key, op);
    let tx_hash = signed_tx.transaction.hash();
    verify_pq_component(
        expected.as_deref(),
        SignatureContext::Transaction,
        tx_hash.as_bytes(),
        signed_tx.signature.pq.as_deref(),
        policy,
    )
    .map(|_| ())
    .map_err(|e| NodeError::InvalidTransaction(format!("transaction signature: {e}")))
}

/// Converts a SignedTransaction to a VmTransaction
///
/// For native operations dispatched through 4-byte selectors (escrow,
/// kill-switch), this builds `tx.data = SELECTOR || serde_json(payload)`
/// matching the decoders in `tenzro-vm::native`. JSON serialization for
/// these well-typed payloads cannot fail in practice (no non-stringable
/// map keys, no `f32::NAN`); we panic loudly if it ever does so a bug
/// surfaces immediately rather than producing a malformed wire payload.
/// The VM transaction block execution runs for `signed_tx` (before the block's
/// timestamp, height and base fee are set).
pub fn vm_transaction(signed_tx: &SignedTransaction) -> VmTransaction {
    convert_transaction(signed_tx)
}

/// An agent action's VM payload, serialized straight to bytes: an amount above
/// `u64::MAX` (any value move over about 18.4 TNZO) has no `serde_json::Value`
/// form, so building one first failed on every validator alike.
fn agent_act_payload(action: &tenzro_types::agent_terms::AgentAction, signature: &[u8]) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        action: &'a tenzro_types::agent_terms::AgentAction,
        signature: &'a [u8],
    }
    serde_json::to_vec(&Payload { action, signature }).expect("an agent action serializes")
}

pub(crate) fn convert_transaction(signed_tx: &SignedTransaction) -> VmTransaction {
    use tenzro_vm::native::{
        SELECTOR_COMPUTE_CLAIM, SELECTOR_ESCROW_CREATE, SELECTOR_ESCROW_REFUND,
        SELECTOR_ESCROW_RELEASE, SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL,
        SELECTOR_GOVERNANCE_EXECUTE, SELECTOR_GOVERNANCE_PAUSE, SELECTOR_GOVERNANCE_PROPOSE,
        SELECTOR_GOVERNANCE_VETO, SELECTOR_GOVERNANCE_VOTE, SELECTOR_IDENTITY_REGISTER,
        SELECTOR_INCREASE_AGENT_BOND, SELECTOR_INCREASE_COMPUTE_BOND,
        SELECTOR_INCREASE_VALIDATOR_STAKE, SELECTOR_KILLSWITCH_PAUSE,
        SELECTOR_KILLSWITCH_QUARANTINE, SELECTOR_KILLSWITCH_TERMINATE,
        SELECTOR_PAY_INSURANCE_CLAIM, SELECTOR_PAYER_SETTLE, SELECTOR_POST_AGENT_BOND,
        SELECTOR_POST_COMPUTE_BOND, SELECTOR_SLA_ATTEST, SELECTOR_TREASURY_DEPOSIT,
        SELECTOR_VALIDATOR_EXIT, SELECTOR_VALIDATOR_REGISTER, SELECTOR_VALIDATOR_ROTATE_KEY,
        SELECTOR_VALIDATOR_UPDATE_METADATA, SELECTOR_WITHDRAW_AGENT_BOND,
        SELECTOR_WITHDRAW_COMPUTE_BOND,
    };

    let tx = &signed_tx.transaction;

    // Extract value, data, and VM type based on transaction type
    let (value, data, vm_type) = match &tx.tx_type {
        TransactionType::Transfer { amount } => (*amount, Vec::new(), VmType::Tenzro),
        TransactionType::ContractCall { calls } => {
            let mut data = tenzro_vm::native::SELECTOR_CONTRACT_CALL.to_vec();
            data.extend_from_slice(&tenzro_types::VmCall::encode_list(calls));
            (0, data, VmType::Tenzro)
        }
        TransactionType::ContractDeploy { code, args } => {
            let mut data = code.clone();
            data.extend_from_slice(args);
            (0, data, VmType::Evm)
        }
        // ---- Escrow primitive (native VM dispatch) ------------------------
        TransactionType::CreateEscrow {
            payee,
            amount,
            asset_id,
            usd_e6,
            expires_at,
            release_conditions,
            reference,
        } => {
            #[derive(serde::Serialize)]
            struct CreateEscrowPayload<'a> {
                payee: &'a tenzro_types::primitives::Address,
                amount: u128,
                asset_id: &'a tenzro_types::asset::AssetId,
                usd_e6: u64,
                expires_at: u64,
                release_conditions: &'a tenzro_types::settlement::ReleaseConditions,
                #[serde(with = "tenzro_types::settlement::opt_hex32")]
                reference: Option<[u8; 32]>,
            }
            let payload = CreateEscrowPayload {
                payee,
                amount: *amount,
                asset_id,
                usd_e6: *usd_e6,
                expires_at: *expires_at,
                release_conditions,
                reference: *reference,
            };
            let mut data = SELECTOR_ESCROW_CREATE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("CreateEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::ReleaseEscrow { escrow_id, proof } => {
            #[derive(serde::Serialize)]
            struct ReleaseEscrowPayload<'a> {
                escrow_id: &'a [u8; 32],
                proof: &'a tenzro_types::settlement::ServiceProof,
            }
            let payload = ReleaseEscrowPayload { escrow_id, proof };
            let mut data = SELECTOR_ESCROW_RELEASE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("ReleaseEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::RefundEscrow { escrow_id } => {
            #[derive(serde::Serialize)]
            struct RefundEscrowPayload<'a> {
                escrow_id: &'a [u8; 32],
            }
            let payload = RefundEscrowPayload { escrow_id };
            let mut data = SELECTOR_ESCROW_REFUND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("RefundEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // Field names MUST match `ClaimEscrowPayload` in
        // `tenzro-vm/src/native/payment_settlement.rs`.
        TransactionType::ClaimEscrow { claims } => {
            #[derive(serde::Serialize)]
            struct ClaimEscrowPayload<'a> {
                claims: &'a [tenzro_types::payment_authorization::EscrowClaim],
            }
            let payload = ClaimEscrowPayload { claims };
            let mut data = tenzro_vm::native::SELECTOR_ESCROW_CLAIM.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("ClaimEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // Field names MUST match `PreimageClaimPayload` in
        // `tenzro-vm/src/native/payment_settlement.rs`.
        TransactionType::ClaimEscrowPreimage {
            escrow_id,
            preimage,
        } => {
            #[derive(serde::Serialize)]
            struct PreimageClaimPayload<'a> {
                escrow_id: &'a [u8; 32],
                preimage: &'a [u8],
            }
            let payload = PreimageClaimPayload {
                escrow_id,
                preimage,
            };
            let mut data = tenzro_vm::native::SELECTOR_ESCROW_PREIMAGE_CLAIM.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("ClaimEscrowPreimage payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // Field names MUST match `StreamClaimPayload` in
        // `tenzro-vm/src/native/payment_settlement.rs`.
        TransactionType::ClaimEscrowStream { escrow_id } => {
            #[derive(serde::Serialize)]
            struct StreamClaimPayload<'a> {
                escrow_id: &'a [u8; 32],
            }
            let mut data = tenzro_vm::native::SELECTOR_ESCROW_STREAM_CLAIM.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&StreamClaimPayload { escrow_id })
                    .expect("ClaimEscrowStream payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // Field names MUST match the payloads in
        // `tenzro-vm/src/native/meter_bond.rs`.
        TransactionType::PostMeterBond {
            meter_public_key,
            amount,
            consent,
        } => {
            let payload = serde_json::json!({
                "meter_public_key": meter_public_key,
                "amount": amount.to_string(),
                "consent": consent,
            });
            let mut data = tenzro_vm::native::SELECTOR_METER_BOND_POST.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("PostMeterBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::WithdrawMeterBond { meter_id } => {
            let payload = serde_json::json!({ "meter_id": meter_id });
            let mut data = tenzro_vm::native::SELECTOR_METER_BOND_WITHDRAW.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("WithdrawMeterBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::DisputeMeteredCharge { dispute } => {
            let mut data = tenzro_vm::native::SELECTOR_METER_DISPUTE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(dispute).expect("DisputeMeteredCharge payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- Kill-switch (native VM dispatch) ---------
        TransactionType::PauseAgent {
            agent_did,
            controller_did,
            reason_code,
            reason_text,
            until,
        } => {
            #[derive(serde::Serialize)]
            struct PauseAgentPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                reason_code: u16,
                #[serde(skip_serializing_if = "Option::is_none")]
                reason_text: Option<&'a str>,
                /// `until` projected to millis-since-epoch for the VM's `u64` field.
                #[serde(skip_serializing_if = "Option::is_none")]
                until: Option<u64>,
            }
            let payload = PauseAgentPayload {
                agent_did,
                controller_did,
                reason_code: *reason_code,
                reason_text: reason_text.as_deref(),
                until: until.map(|t| t.as_millis() as u64),
            };
            let mut data = SELECTOR_KILLSWITCH_PAUSE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("PauseAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::QuarantineAgent {
            agent_did,
            controller_did,
            reason_code,
            reason_text,
            evidence_hash,
        } => {
            #[derive(serde::Serialize)]
            struct QuarantineAgentPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                reason_code: u16,
                #[serde(skip_serializing_if = "Option::is_none")]
                reason_text: Option<&'a str>,
                /// VM-side payload expects the evidence commitment as 64-char
                /// lowercase hex. We project the byte array here.
                #[serde(skip_serializing_if = "Option::is_none")]
                evidence_hash: Option<String>,
            }
            let payload = QuarantineAgentPayload {
                agent_did,
                controller_did,
                reason_code: *reason_code,
                reason_text: reason_text.as_deref(),
                evidence_hash: evidence_hash.as_ref().map(hex::encode),
            };
            let mut data = SELECTOR_KILLSWITCH_QUARANTINE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("QuarantineAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::TerminateAgent {
            agent_did,
            controller_did,
            reason_code,
            slash_bps,
            cascade,
        } => {
            #[derive(serde::Serialize)]
            struct TerminateAgentPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                reason_code: u16,
                slash_bps: u16,
                cascade: bool,
            }
            let payload = TerminateAgentPayload {
                agent_did,
                controller_did,
                reason_code: *reason_code,
                slash_bps: *slash_bps,
                cascade: *cascade,
            };
            let mut data = SELECTOR_KILLSWITCH_TERMINATE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("TerminateAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- AgentBond surety (native VM dispatch) ----
        // Payload field names MUST match the VM-side `PostAgentBondPayload`,
        // `IncreaseAgentBondPayload`, `WithdrawAgentBondPayload`, and
        // `PayInsuranceClaimPayload` structs in
        // `tenzro-vm/src/native/mod.rs` — they are deserialized via
        // `serde_json::from_slice(&tx.data[4..])`.
        TransactionType::PostAgentBond {
            agent_did,
            controller_did,
            amount,
        } => {
            #[derive(serde::Serialize)]
            struct PostAgentBondPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                amount: u128,
            }
            let payload = PostAgentBondPayload {
                agent_did,
                controller_did,
                amount: *amount,
            };
            let mut data = SELECTOR_POST_AGENT_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("PostAgentBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::IncreaseAgentBond { agent_did, amount } => {
            #[derive(serde::Serialize)]
            struct IncreaseAgentBondPayload<'a> {
                agent_did: &'a str,
                amount: u128,
            }
            let payload = IncreaseAgentBondPayload {
                agent_did,
                amount: *amount,
            };
            let mut data = SELECTOR_INCREASE_AGENT_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("IncreaseAgentBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::WithdrawAgentBond { agent_did } => {
            #[derive(serde::Serialize)]
            struct WithdrawAgentBondPayload<'a> {
                agent_did: &'a str,
            }
            let payload = WithdrawAgentBondPayload { agent_did };
            let mut data = SELECTOR_WITHDRAW_AGENT_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("WithdrawAgentBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- Compute bond (provider admission, native VM dispatch) ----
        // Payload field names MUST match the VM-side
        // `PostComputeBondPayload`, `IncreaseComputeBondPayload`,
        // `WithdrawComputeBondPayload`, `FinalizeComputeBondWithdrawalPayload`
        // structs in `tenzro-vm/src/native/mod.rs`.
        TransactionType::PostComputeBond {
            provider_did,
            amount,
        } => {
            #[derive(serde::Serialize)]
            struct PostComputeBondPayload<'a> {
                provider_did: &'a str,
                amount: u128,
            }
            let payload = PostComputeBondPayload {
                provider_did,
                amount: *amount,
            };
            let mut data = SELECTOR_POST_COMPUTE_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("PostComputeBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::IncreaseComputeBond {
            provider_did,
            amount,
        } => {
            #[derive(serde::Serialize)]
            struct IncreaseComputeBondPayload<'a> {
                provider_did: &'a str,
                amount: u128,
            }
            let payload = IncreaseComputeBondPayload {
                provider_did,
                amount: *amount,
            };
            let mut data = SELECTOR_INCREASE_COMPUTE_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("IncreaseComputeBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::WithdrawComputeBond { provider_did } => {
            #[derive(serde::Serialize)]
            struct WithdrawComputeBondPayload<'a> {
                provider_did: &'a str,
            }
            let payload = WithdrawComputeBondPayload { provider_did };
            let mut data = SELECTOR_WITHDRAW_COMPUTE_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("WithdrawComputeBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::FinalizeComputeBondWithdrawal { provider_did } => {
            #[derive(serde::Serialize)]
            struct FinalizeComputeBondWithdrawalPayload<'a> {
                provider_did: &'a str,
            }
            let payload = FinalizeComputeBondWithdrawalPayload { provider_did };
            let mut data = SELECTOR_FINALIZE_COMPUTE_BOND_WITHDRAWAL.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("FinalizeComputeBondWithdrawal payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::Registry { op } => {
            let mut data = tenzro_vm::native::SELECTOR_REGISTRY.to_vec();
            data.extend_from_slice(&serde_json::to_vec(op).expect("Registry payload is JSON-safe"));
            (0, data, VmType::Tenzro)
        }
        TransactionType::ComputeClaim { op } => {
            let mut data = SELECTOR_COMPUTE_CLAIM.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("ComputeClaim payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::InferenceFault { op } => {
            let mut data = tenzro_vm::native::SELECTOR_INFERENCE_FAULT.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("InferenceFault payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::AgentAuditCommit {
            epoch,
            root,
            sessions,
            entries_ref,
            attestation,
        } => {
            let payload = serde_json::json!({
                "epoch": epoch,
                "root": hex::encode(root),
                "sessions": sessions,
                "entries_ref": entries_ref,
                "attestation": hex::encode(attestation),
            });
            let mut data = tenzro_vm::native::SELECTOR_AGENT_AUDIT_COMMIT.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("AgentAuditCommit payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::LiftAgentQuarantine {
            agent_did,
            reason_text,
        } => {
            let payload = serde_json::json!({ "agent_did": agent_did, "reason_text": reason_text });
            let mut data = tenzro_vm::native::SELECTOR_LIFT_AGENT_QUARANTINE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("LiftAgentQuarantine payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::RevokeDelegatedAgent {
            agent_did,
            controller_did,
            approval_digest,
        } => {
            let payload = serde_json::json!({
                "agent_did": agent_did,
                "controller_did": controller_did,
                "approval_digest": hex::encode(approval_digest),
            });
            let mut data = tenzro_vm::native::SELECTOR_REVOKE_DELEGATED_AGENT.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("RevokeDelegatedAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::SetAgentTopUp {
            agent_did,
            controller_did,
            allowance,
        } => {
            let payload = serde_json::json!({
                "agent_did": agent_did,
                "controller_did": controller_did,
                "allowance": allowance.map(|(per_period, period_ms, target, expires_at_ms)| serde_json::json!({
                    "per_period": per_period.to_string(),
                    "period_ms": period_ms,
                    "target": target.to_string(),
                    "expires_at_ms": expires_at_ms,
                })),
            });
            let mut data = tenzro_vm::native::SELECTOR_SET_AGENT_TOPUP.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("SetAgentTopUp payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::TopUpAgent { agent_did } => {
            let payload = serde_json::json!({ "agent_did": agent_did });
            let mut data = tenzro_vm::native::SELECTOR_TOPUP_AGENT.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("TopUpAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::ReclaimAgentFunds {
            agent_did,
            controller_did,
            amount,
        } => {
            let payload = serde_json::json!({
                "agent_did": agent_did,
                "controller_did": controller_did,
                "amount": amount.map(|a| a.to_string()),
            });
            let mut data = tenzro_vm::native::SELECTOR_RECLAIM_AGENT_FUNDS.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("ReclaimAgentFunds payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::TrainingProof { op } => {
            let mut data = tenzro_vm::native::SELECTOR_TRAINING_PROOF.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("TrainingProof payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::HardwareProof { op } => {
            let mut data = tenzro_vm::native::SELECTOR_HARDWARE_PROOF.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("HardwareProof payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::KeyRelease { op } => {
            let mut data = tenzro_vm::native::SELECTOR_KEY_RELEASE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("KeyRelease payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::SponsoredBond { op } => {
            let mut data = tenzro_vm::native::SELECTOR_SPONSORED_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("SponsoredBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::AttachMachineAttestation { op } => {
            let mut data = tenzro_vm::native::SELECTOR_ATTACH_MACHINE_ATTESTATION.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("AttachMachineAttestation payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::SetAgentTerms {
            terms,
            rotate,
            approval,
        } => {
            let payload =
                serde_json::json!({ "terms": terms, "rotate": rotate, "approval": approval });
            let mut data = tenzro_vm::native::SELECTOR_SET_AGENT_TERMS.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("SetAgentTerms payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::AgentAct { action, signature } => {
            let mut data = tenzro_vm::native::SELECTOR_AGENT_ACT.to_vec();
            data.extend_from_slice(&agent_act_payload(action, signature));
            (0, data, VmType::Tenzro)
        }
        TransactionType::RemoteGrantSettle {
            agent_did,
            chain,
            delivery,
        } => {
            let payload = serde_json::json!({
                "agent_did": agent_did,
                "chain": chain,
                "delivery": hex::encode(delivery),
            });
            let mut data = tenzro_vm::native::SELECTOR_REMOTE_GRANT_SETTLE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("RemoteGrantSettle payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::Bridge { op } => {
            let mut data = tenzro_vm::native::SELECTOR_BRIDGE.to_vec();
            data.extend_from_slice(&serde_json::to_vec(op).expect("Bridge payload is JSON-safe"));
            (0, data, VmType::Tenzro)
        }
        TransactionType::SettlementPlan { op } => {
            let mut data = tenzro_vm::native::SELECTOR_SETTLEMENT_PLAN.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("SettlementPlan payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::Token { op } => {
            let mut data = tenzro_vm::native::SELECTOR_TOKEN.to_vec();
            data.extend_from_slice(&serde_json::to_vec(op).expect("Token payload is JSON-safe"));
            (0, data, VmType::Tenzro)
        }
        TransactionType::Stake { op } => {
            let mut data = tenzro_vm::native::SELECTOR_STAKE.to_vec();
            data.extend_from_slice(&serde_json::to_vec(op).expect("Stake payload is JSON-safe"));
            (0, data, VmType::Tenzro)
        }
        TransactionType::Payment { op } => {
            let mut data = tenzro_vm::native::SELECTOR_PAYMENT.to_vec();
            data.extend_from_slice(&serde_json::to_vec(op).expect("Payment payload is JSON-safe"));
            (0, data, VmType::Tenzro)
        }
        TransactionType::BeaconContribute { round, proof } => {
            let payload = tenzro_vm::native::beacon::BeaconContribution {
                round: *round,
                proof: hex::encode(proof),
            };
            let mut data = tenzro_vm::native::SELECTOR_BEACON_CONTRIBUTE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("BeaconContribute payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::DaRetention { op } => {
            let mut data = tenzro_vm::native::SELECTOR_DA_RETENTION.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("DaRetention payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::AccountKeys { op } => {
            let mut data = tenzro_vm::native::SELECTOR_ACCOUNT_KEYS.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("AccountKeys payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::KeystoreUpdate { update } => {
            let mut data = tenzro_vm::native::SELECTOR_KEYSTORE_UPDATE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(update).expect("KeystoreUpdate payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::IdentityServices { op } => {
            let mut data = tenzro_vm::native::SELECTOR_IDENTITY_SERVICES.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("IdentityServices payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::RevokeIdentity { op } => {
            let mut data = tenzro_vm::native::SELECTOR_IDENTITY_REVOKE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(op).expect("RevokeIdentity payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::FeeRateSubmit {
            epoch,
            commitment,
            reveal,
        } => {
            let payload = serde_json::json!({
                "epoch": epoch,
                "commitment": hex::encode(commitment),
                "reveal": reveal.as_ref().map(|r| serde_json::json!({
                    "quotes": r.quotes
                        .iter()
                        .map(|q| serde_json::json!({
                            "symbol": q.symbol,
                            "source": q.source,
                            "rate_nano_usd": q.rate_nano_usd.to_string(),
                        }))
                        .collect::<Vec<_>>(),
                    "salt": hex::encode(r.salt),
                })),
            });
            let mut data = tenzro_vm::native::SELECTOR_FEE_RATE_SUBMIT.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("FeeRateSubmit payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::AgentAuditFlag { epoch, findings } => {
            let payload = serde_json::json!({ "epoch": epoch, "findings": findings });
            let mut data = tenzro_vm::native::SELECTOR_AGENT_AUDIT_FLAG.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("AgentAuditFlag payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::SlaAttest { epoch, outcomes } => {
            let payload = serde_json::json!({ "epoch": epoch, "outcomes": outcomes });
            let mut data = SELECTOR_SLA_ATTEST.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("SlaAttest payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::PayInsuranceClaim { evidence } => {
            let mut data = SELECTOR_PAY_INSURANCE_CLAIM.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(evidence).expect("PayInsuranceClaim payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // Field names MUST match the VM-side `PayerSettlePayload` in
        // `tenzro-vm/src/native/mod.rs`.
        TransactionType::PayerSettle {
            payer,
            payee,
            amount,
            payment_id,
            authorization,
        } => {
            #[derive(serde::Serialize)]
            struct PayerSettlePayload<'a> {
                payer: &'a tenzro_types::primitives::Address,
                payee: &'a tenzro_types::primitives::Address,
                amount: u128,
                payment_id: &'a str,
                authorization: &'a tenzro_types::payment_authorization::PaymentAuthorization,
            }
            let payload = PayerSettlePayload {
                payer,
                payee,
                amount: *amount,
                payment_id,
                authorization,
            };
            let mut data = SELECTOR_PAYER_SETTLE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("PayerSettle payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- Dynamic validator set (native VM dispatch) -------------------
        // Payload field names MUST match `ValidatorRegisterPayload` and
        // `ValidatorUpdateMetadataPayload` in `tenzro-vm/src/native/mod.rs`.
        TransactionType::RegisterValidator {
            ml_dsa_pubkey,
            p256_pubkey,
            node_key,
            proof_of_possession,
            node_key_proof,
            vrf_key,
            vrf_key_proof,
            withdrawal_address,
            self_stake,
            metadata_uri,
        } => {
            #[derive(serde::Serialize)]
            struct ValidatorRegisterPayload<'a> {
                ml_dsa_pubkey: &'a [u8],
                p256_pubkey: &'a [u8],
                node_key: &'a [u8; 32],
                proof_of_possession: &'a [u8],
                node_key_proof: &'a [u8],
                vrf_key: &'a [u8; 32],
                vrf_key_proof: &'a [u8],
                withdrawal_address: &'a tenzro_types::primitives::Address,
                self_stake: u128,
                metadata_uri: &'a str,
            }
            let payload = ValidatorRegisterPayload {
                ml_dsa_pubkey,
                p256_pubkey,
                node_key,
                proof_of_possession,
                node_key_proof,
                vrf_key,
                vrf_key_proof,
                withdrawal_address,
                self_stake: *self_stake,
                metadata_uri,
            };
            let mut data = SELECTOR_VALIDATOR_REGISTER.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("RegisterValidator payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::ReportCheckpointEquivocation { evidence } => {
            let mut data = tenzro_vm::native::SELECTOR_CHECKPOINT_EQUIVOCATION.to_vec();
            data.extend_from_slice(evidence);
            (0, data, VmType::Tenzro)
        }
        // The payload is the signers' accounts, filled in only once block
        // execution verified the certificate; the selector alone records
        // nothing.
        TransactionType::RecordCheckpointSigners { .. } => (
            0,
            tenzro_vm::native::SELECTOR_CHECKPOINT_SIGNERS.to_vec(),
            VmType::Tenzro,
        ),
        TransactionType::AccountOutflow { op } => {
            let mut data = tenzro_vm::account_outflow::SELECTOR_ACCOUNT_OUTFLOW.to_vec();
            data.extend_from_slice(op);
            (0, data, VmType::Tenzro)
        }
        TransactionType::ExitValidator => {
            // No payload — selector alone signals voluntary exit.
            (0, SELECTOR_VALIDATOR_EXIT.to_vec(), VmType::Tenzro)
        }
        TransactionType::RotateValidatorKey {
            ml_dsa_pubkey,
            p256_pubkey,
            proof_of_possession,
        } => {
            let payload = serde_json::json!({
                "ml_dsa_pubkey": ml_dsa_pubkey,
                "p256_pubkey": p256_pubkey,
                "proof_of_possession": proof_of_possession,
            });
            let mut data = SELECTOR_VALIDATOR_ROTATE_KEY.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("RotateValidatorKey payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::RegisterValidatorMachine {
            machine_p256,
            machine_ml_dsa,
            p256_signature,
            ml_dsa_signature,
        } => {
            use tenzro_vm::native::validator_machine::{MachineRegistration, ValidatorMachine};
            let payload = MachineRegistration {
                machine: ValidatorMachine {
                    p256: machine_p256.clone(),
                    ml_dsa: machine_ml_dsa.clone(),
                },
                p256_signature: p256_signature.clone(),
                ml_dsa_signature: ml_dsa_signature.clone(),
            };
            let mut data = tenzro_vm::native::SELECTOR_VALIDATOR_MACHINE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("RegisterValidatorMachine payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::UpdateValidatorMetadata {
            metadata_uri,
            tee_attestation_hash,
        } => {
            #[derive(serde::Serialize)]
            struct ValidatorUpdateMetadataPayload<'a> {
                #[serde(skip_serializing_if = "Option::is_none")]
                metadata_uri: Option<&'a str>,
                /// 32-byte SHA-256 commitment (raw bytes), serialized as a
                /// JSON array — matches the VM-side `Vec<u8>` field.
                #[serde(skip_serializing_if = "Option::is_none")]
                tee_attestation_hash: Option<&'a [u8]>,
            }
            let payload = ValidatorUpdateMetadataPayload {
                metadata_uri: metadata_uri.as_deref(),
                tee_attestation_hash: tee_attestation_hash.as_ref().map(|h| h.as_slice()),
            };
            let mut data = SELECTOR_VALIDATOR_UPDATE_METADATA.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("UpdateValidatorMetadata payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::RegisterIdentity {
            did,
            identity_type,
            display_name,
            controller_pubkey,
            key_type,
            wallet_id,
            wallet_address,
            pq_verifying_key,
            metadata,
            proof,
        } => {
            // Serialize the shared `RegisterIdentityPayload` directly so the
            // JSON body is byte-identical to what the VM decoder and node-side
            // registry mirror both expect. One struct, one shape.
            let payload = tenzro_types::identity::RegisterIdentityPayload {
                did: did.clone(),
                identity_type: identity_type.clone(),
                display_name: display_name.clone(),
                controller_pubkey: controller_pubkey.clone(),
                key_type: key_type.clone(),
                wallet_id: wallet_id.clone(),
                wallet_address: *wallet_address,
                pq_verifying_key: pq_verifying_key.clone(),
                metadata: metadata.clone(),
                proof: proof.clone(),
            };
            let mut data = SELECTOR_IDENTITY_REGISTER.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload).expect("RegisterIdentity payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // All other Tenzro-native transaction types (agents, models, staking, TEE)
        TransactionType::TreasuryDeposit { amount } => {
            let mut data = SELECTOR_TREASURY_DEPOSIT.to_vec();
            data.extend_from_slice(&amount.to_le_bytes());
            (0, data, VmType::Tenzro)
        }
        TransactionType::IncreaseValidatorStake { additional } => {
            let mut data = SELECTOR_INCREASE_VALIDATOR_STAKE.to_vec();
            data.extend_from_slice(&additional.to_le_bytes());
            (0, data, VmType::Tenzro)
        }

        // Governance. These three had no arm at all and fell through to the
        // catch-all below, which produces empty data — so the transaction
        // reached the VM carrying no selector and never dispatched to a
        // governance handler. The handlers existed; nothing could reach them.
        TransactionType::GovernancePropose { proposal } => {
            let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
            data.extend_from_slice(proposal);
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceVote {
            proposal_id,
            vote,
            validator,
            root_approval,
        } => {
            let mut data = SELECTOR_GOVERNANCE_VOTE.to_vec();
            // A malformed id yields an empty body rather than a truncated one,
            // so the VM refuses it outright instead of voting on whichever
            // proposal the short bytes happened to name.
            match hex::decode(proposal_id) {
                Ok(id) if id.len() == 32 => {
                    data.extend_from_slice(&id);
                    data.push(u8::from(*vote));
                    data.push(32);
                    data.extend_from_slice(validator.as_bytes());
                    // A machine root's approval follows the ballot body.
                    if let Some(approval) = root_approval {
                        match serde_json::to_vec(approval) {
                            Ok(bytes) => data.extend_from_slice(&bytes),
                            Err(_) => data.clear(),
                        }
                    }
                }
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceVeto { proposal_id } => {
            let mut data = SELECTOR_GOVERNANCE_VETO.to_vec();
            // Carried as text, matching how the veto handler reads it back.
            data.extend_from_slice(proposal_id.as_bytes());
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernancePause { paused } => {
            let mut data = SELECTOR_GOVERNANCE_PAUSE.to_vec();
            data.push(u8::from(*paused));
            (0, data, VmType::Tenzro)
        }
        TransactionType::Funding { op } => {
            let mut data = tenzro_vm::native::SELECTOR_FUNDING.to_vec();
            data.extend_from_slice(op);
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceVetoSignal {
            proposal_id,
            amount,
        } => {
            let mut data = tenzro_vm::native::SELECTOR_GOVERNANCE_VETO_SIGNAL.to_vec();
            match hex::decode(proposal_id) {
                Ok(id) if id.len() == 32 => {
                    data.extend_from_slice(&id);
                    data.extend_from_slice(&amount.to_le_bytes());
                }
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceVetoWithdraw {
            proposal_id,
            holder,
        } => {
            let mut data = tenzro_vm::native::SELECTOR_GOVERNANCE_VETO_WITHDRAW.to_vec();
            match hex::decode(proposal_id) {
                Ok(id) if id.len() == 32 => {
                    data.extend_from_slice(&id);
                    data.push(32);
                    data.extend_from_slice(holder.as_bytes());
                }
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceConcern { proposal_id } => {
            let mut data = tenzro_vm::native::SELECTOR_GOVERNANCE_CONCERN.to_vec();
            match hex::decode(proposal_id) {
                Ok(id) if id.len() == 32 => data.extend_from_slice(&id),
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::UpgradeReady { code_hash, quote } => {
            let mut data = tenzro_vm::native::SELECTOR_UPGRADE_READY.to_vec();
            match hex::decode(code_hash) {
                Ok(h) if h.len() == 32 => {
                    data.extend_from_slice(&h);
                    data.extend_from_slice(quote);
                }
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceSecurityDisclosure {
            proposal_id,
            disclosure,
        } => {
            let mut data = tenzro_vm::native::SELECTOR_SECURITY_DISCLOSURE.to_vec();
            match hex::decode(proposal_id) {
                Ok(id) if id.len() == 32 => {
                    data.extend_from_slice(&id);
                    data.extend_from_slice(disclosure);
                }
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::GovernanceExecute { proposal_id } => {
            let mut data = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
            match hex::decode(proposal_id) {
                Ok(id) if id.len() == 32 => data.extend_from_slice(&id),
                _ => data.clear(),
            }
            (0, data, VmType::Tenzro)
        }
        TransactionType::AttestZkProof { proof } => {
            let mut data = tenzro_vm::native::SELECTOR_ZK_ATTEST.to_vec();
            data.extend_from_slice(proof);
            (0, data, VmType::Tenzro)
        }
        _ => (0, Vec::new(), VmType::Tenzro),
    };

    // A deployment has no callee: the EVM creates the contract at the
    // address the sender and its nonce give.
    let to = match &tx.tx_type {
        TransactionType::ContractDeploy { .. } => None,
        _ => Some(tx.to.as_bytes().to_vec()),
    };
    let mut vm_tx = VmTransaction::new(
        tx.from.as_bytes().to_vec(),
        to,
        value,
        data,
        tx.gas_limit,
        tx.gas_price as u128,
        tx.nonce.0,
        vm_type,
        tx.chain_id.0,
    );

    // Carry over signature and public key from the signed transaction
    // so the VM runtime can perform cryptographic verification
    // Any signature goes to the VM, which refuses one it cannot verify; only
    // a transaction carrying none is left unsigned.
    if signed_tx.signature.has_classical_leg() || signed_tx.signature.pq.is_some() {
        vm_tx.signature = Some(signed_tx.signature.clone());
    }
    if !signed_tx.public_key.is_empty() {
        vm_tx.public_key = Some(signed_tx.public_key.clone());
    }

    // Carry the canonical signing digest (Transaction::hash()) so the runtime
    // verifies against the same preimage the admission boundary verified
    // against, rather than recomputing a different hash from VmTransaction
    // fields.
    vm_tx.signing_digest = Some(signed_tx.transaction.hash().as_bytes().to_vec());
    vm_tx.valid_until_ms = Some(signed_tx.transaction.valid_until.0);

    vm_tx
}

#[cfg(test)]
mod charged_gas_price_tests {
    /// A receipt shows the price the sender was charged: the offered one when
    /// the whole fee was taken, what was taken per gas when only part of it
    /// could be, and nothing when none of it could.
    #[test]
    fn a_receipt_never_shows_a_fee_that_was_not_charged() {
        assert_eq!(super::charged_gas_price(4, 21_000, 84_000), 4);
        assert_eq!(super::charged_gas_price(4, 21_000, 42_000), 2);
        assert_eq!(super::charged_gas_price(4, 21_000, 0), 0);
        assert_eq!(super::charged_gas_price(4, 0, 0), 4);
    }
}

#[cfg(test)]
mod agent_act_payload_tests {
    /// An agent action moving more than `u64::MAX` wei, up to `u128::MAX`,
    /// reaches the VM intact instead of stopping the validator.
    #[test]
    fn a_value_move_above_u64_encodes_and_decodes() {
        for amount in [
            20_000_000_000_000_000_000u128,
            u128::from(u64::MAX) + 1,
            u128::MAX,
        ] {
            let action: tenzro_types::agent_terms::AgentAction =
                serde_json::from_value(serde_json::json!({
                    "agent_did": "did:tenzro:machine:a:b",
                    "machine_did": "did:tenzro:machine:m",
                    "operation": "create_escrow",
                    "nonce": 0,
                }))
                .map(|mut a: tenzro_types::agent_terms::AgentAction| {
                    a.amount = amount;
                    a
                })
                .unwrap();
            let bytes = super::agent_act_payload(&action, &[1, 2, 3]);
            let (back, signature) = tenzro_vm::native::agent_terms::decode_act(&bytes).unwrap();
            assert_eq!(back, action);
            assert_eq!(back.amount, amount);
            assert_eq!(signature, vec![1, 2, 3]);
        }
    }
}

#[cfg(test)]
mod epoch_staging_reconcile_tests {
    use super::EventLoop;
    use std::sync::Arc;
    use tenzro_consensus::ValidatorPublicKey;
    use tenzro_consensus::epoch_manager::EpochManager;
    use tenzro_consensus::validator::ValidatorInfo;
    use tenzro_token::validator_registry::ValidatorRegistry;
    use tenzro_types::primitives::{Address, BlockHeight};

    const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

    fn keys(seed: u8) -> (Address, ValidatorPublicKey, [u8; 32]) {
        let key = ValidatorPublicKey::new(
            tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec(),
            tenzro_crypto::P256KeyPair::generate()
                .public_key_sec1()
                .to_vec(),
        )
        .expect("well-formed key");
        (Address::new([seed; 32]), key, [seed; 32])
    }

    /// A validator that is Active in the registry but absent from the seated
    /// set must be staged.
    ///
    /// This is the state the live chain reached: repeated staging without a
    /// committing transition walked two candidates all the way to Active while
    /// the consensus set still held one validator. Their promotions are behind
    /// them, so an event-driven scheme has nothing left to replay and they
    /// would have stayed unseated permanently.
    #[tokio::test]
    async fn an_active_validator_missing_from_the_set_is_staged() {
        let (seated_addr, seated_key, seated_endpoint) = keys(0x01);
        let (missing_addr, missing_key, missing_endpoint) = keys(0x02);

        // The seated set holds one validator, in whole TNZO.
        let em = Arc::new(
            EpochManager::new(
                vec![ValidatorInfo::new(
                    seated_addr,
                    seated_key.clone(),
                    seated_endpoint,
                    10_000_000,
                )],
                100,
            )
            .expect("epoch manager"),
        );

        // The registry holds both, Active, in wei.
        let registry = Arc::new(ValidatorRegistry::new());
        registry
            .seed_genesis_active(
                seated_addr,
                seated_key.ml_dsa.clone(),
                seated_key.p256.clone(),
                seated_endpoint,
                seated_addr,
                10_000_000 * ONE_TNZO,
                String::new(),
            )
            .expect("seed seated");
        registry
            .seed_genesis_active(
                missing_addr,
                missing_key.ml_dsa.clone(),
                missing_key.p256.clone(),
                missing_endpoint,
                missing_addr,
                10_000 * ONE_TNZO,
                String::new(),
            )
            .expect("seed missing");

        assert_eq!(registry.list_active().len(), 2);
        assert!(
            registry
                .compute_epoch_transition(1)
                .effective_activations
                .is_empty(),
            "both are already Active, so no plan mentions them — which is the \
             whole problem"
        );

        EventLoop::stage_registry_epoch_plan(&em, &registry, &|_| true);

        let next = em
            .transition_epoch(BlockHeight::from(100))
            .expect("transition")
            .expect("a due transition returns the new set");

        assert_eq!(next.len(), 2, "the missing validator was never staged");
        assert_eq!(
            next.get_by_address(&missing_addr).map(|v| v.stake),
            Some(10_000),
            "staged in whole TNZO, not the registry's wei"
        );
        assert_eq!(
            next.get_by_address(&seated_addr).map(|v| v.stake),
            Some(10_000_000),
            "the already-correct validator must not be disturbed"
        );
    }

    /// When everything already agrees, staging must queue nothing — otherwise
    /// every boundary would churn the set for no reason.
    #[tokio::test]
    async fn a_set_that_already_matches_stages_nothing() {
        let (addr, key, endpoint) = keys(0x03);
        let em = Arc::new(
            EpochManager::new(
                vec![ValidatorInfo::new(addr, key.clone(), endpoint, 10_000_000)],
                100,
            )
            .expect("epoch manager"),
        );
        let registry = Arc::new(ValidatorRegistry::new());
        registry
            .seed_genesis_active(
                addr,
                key.ml_dsa.clone(),
                key.p256.clone(),
                endpoint,
                addr,
                10_000_000 * ONE_TNZO,
                String::new(),
            )
            .expect("seed");

        EventLoop::stage_registry_epoch_plan(&em, &registry, &|_| true);

        let next = em
            .transition_epoch(BlockHeight::from(100))
            .expect("transition")
            .expect("set");
        assert_eq!(next.len(), 1);
        assert_eq!(
            next.get_by_address(&addr).map(|v| v.stake),
            Some(10_000_000)
        );
    }
}

#[cfg(test)]
mod validator_power_unit_tests {
    use super::EventLoop;

    const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

    /// The genesis validator is seated with 10,000,000 and the registry holds
    /// 10^25 for it. They are the same stake, and staging must not report the
    /// difference as a change — which is exactly what was observed live:
    /// `seated=10000000 registry=10000000000000000000000000`.
    #[test]
    fn the_registry_and_the_seated_set_agree_after_conversion() {
        let seated: u128 = 10_000_000;
        let registry_wei: u128 = 10_000_000 * ONE_TNZO;
        assert_eq!(
            EventLoop::consensus_voting_power(registry_wei),
            seated,
            "the same stake must convert to the power already seated"
        );
    }

    /// The validator-set floor, in the unit the set actually uses.
    #[test]
    fn the_minimum_stake_converts_to_its_whole_tnzo_figure() {
        assert_eq!(EventLoop::consensus_voting_power(10_000 * ONE_TNZO), 10_000);
    }

    /// A validator with stake must never be seated unable to vote. Below the
    /// 10,000 TNZO floor this cannot arise, but rounding a real stake to zero
    /// power would be a silent exclusion rather than a visible rejection.
    #[test]
    fn a_non_zero_stake_never_rounds_to_no_voting_power() {
        assert_eq!(EventLoop::consensus_voting_power(1), 1);
        assert_eq!(EventLoop::consensus_voting_power(ONE_TNZO - 1), 1);
        assert_eq!(EventLoop::consensus_voting_power(0), 0);
    }
}

/// One epoch's supply snapshot from consensus counters. `prior` is the
/// (total supply, cumulative burn) of the previous observation; without one
/// the deltas are zero. Supply added is the supply change plus what was
/// burned; the ledger refuses any block that adds supply, so it reads zero
/// unless the ledger is faulty. It is reported in the snapshot's
/// `emission_breakdown.staking_rewards` field, whose name is kept for
/// readers of the record and the RPC.
fn supply_snapshot(
    prior: Option<(u128, u128)>,
    supply: u128,
    burned: u128,
    block_height: BlockHeight,
    at: tenzro_types::primitives::Timestamp,
    rolling_window_epochs: u32,
) -> tenzro_token::adaptive_burn::SupplyMetricsSnapshot {
    use tenzro_token::adaptive_burn::{BurnBreakdown, EmissionBreakdown, SupplyMetricsSnapshot};
    let (prior_supply, prior_burned) = prior.unwrap_or((supply, burned));
    let epoch_delta = (supply as i128).saturating_sub(prior_supply as i128);
    let burned_delta = burned.saturating_sub(prior_burned);
    let added = (epoch_delta.saturating_add(burned_delta as i128)).max(0) as u128;
    let rolling_bps = if supply == 0 {
        0
    } else {
        (epoch_delta
            .saturating_mul(rolling_window_epochs.max(1) as i128)
            .saturating_mul(10_000)
            / supply as i128)
            .clamp(i32::MIN as i128, i32::MAX as i128) as i32
    };
    SupplyMetricsSnapshot {
        block_height,
        captured_at: at,
        circulating_supply: supply,
        epoch_supply_delta: epoch_delta,
        rolling_window_supply_delta_bps: rolling_bps,
        burn_breakdown: BurnBreakdown {
            base_fee: burned_delta,
            local_fee: 0,
        },
        emission_breakdown: EmissionBreakdown {
            staking_rewards: added,
            treasury_emissions: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::account_signature::{
        AccountKeysOp, ClassicalProof, CompositeSignature, pq_enrollment_message,
    };
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::Transaction;
    use tenzro_vm::traits::VmState;

    /// A sender holding nothing is refused before its signature is checked:
    /// a transaction whose signature no longer matches its contents is
    /// refused for the empty balance, not for the signature.
    #[tokio::test]
    async fn ingress_refuses_an_unfunded_sender_before_checking_its_signature() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let (parked, _held) = mpsc::channel(1);
        let ingress = Ingress {
            chain_id: 1,
            storage: storage.clone(),
            state_adapter: Arc::new(Mutex::new(StateAdapter::with_storage(storage))),
            consensus: None,
            chain_tip: Arc::new(AtomicU64::new(0)),
            parked,
            gpu_revocation: Default::default(),
        };
        let mut tx = create_test_transaction(0);
        tx.transaction.gas_price += 1;
        let err = ingress.admit(tx).await.unwrap_err().to_string();
        assert!(err.contains("holds nothing"), "{err}");
    }

    fn create_test_transaction(nonce: u64) -> SignedTransaction {
        signed(
            &TestHybridSigner::hybrid(1),
            TransactionType::Transfer { amount: 1000 },
            nonce,
        )
    }

    fn unsigned(signer: &TestHybridSigner, tx_type: TransactionType, nonce: u64) -> Transaction {
        Transaction::new(
            ChainId::from(1),
            signer.address(),
            Address::default(),
            Nonce::from(nonce),
            tx_type,
            21000,
            100,
        )
    }

    /// A machine with a TPM: one hardware key per label, opened by label.
    fn machine_keys(seed: u8) -> HashMap<&'static str, Arc<TestHybridSigner>> {
        HashMap::from([
            (
                tenzro_types::did_derivation::MACHINE_KEY_LABEL,
                Arc::new(TestHybridSigner::hybrid(seed)),
            ),
            (
                tenzro_types::did_derivation::MACHINE_WALLET_KEY_LABEL,
                Arc::new(TestHybridSigner::hybrid(seed + 1)),
            ),
        ])
    }

    /// Register the machine identity of `keys` as `validator
    /// register-machine` does: the DID its identity key derives, bound to
    /// that key.
    async fn register_machine(
        registry: &IdentityRegistry,
        keys: &HashMap<&'static str, Arc<TestHybridSigner>>,
    ) -> String {
        let identity = keys[tenzro_types::did_derivation::MACHINE_KEY_LABEL].public_key();
        let sec1 = [&[0x04u8][..], &identity.p256].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        registry
            .register_autonomous_machine_with_binding(
                tenzro_identity::TenzroDid::parse(&did).unwrap(),
                tenzro_identity::WalletBinding {
                    wallet_id: "machine".into(),
                    address: Address::new(identity.account_slot()),
                    public_key: sec1,
                    pq_verifying_key: identity.pq.clone().unwrap_or_default(),
                },
                Vec::new(),
                HashMap::new(),
            )
            .await
            .unwrap();
        did
    }

    /// The identity the node holding `keys` announces as, built as the node
    /// builds it.
    fn announcer(keys: &HashMap<&'static str, Arc<TestHybridSigner>>) -> AnnounceIdentity {
        let key = keys
            .get(crate::node::SESSION_KEY_LABEL)
            .expect("the machine key")
            .clone() as Arc<dyn HybridSigner>;
        let session = tenzro_crypto::batch::ImmediateRecordSigner::new(key);
        AnnounceIdentity::new(Arc::new(session))
    }

    #[tokio::test]
    async fn an_announcement_from_one_node_is_accepted_by_another() {
        // Node B knows the machine identity of node A from the chain.
        let (a, other) = (machine_keys(40), machine_keys(50));
        let registry = IdentityRegistry::new();
        let did = register_machine(&registry, &a).await;

        let mut ann = tenzro_network::ModelRegistrationMessage {
            model_id: "qwen3-0.6b".into(),
            ..Default::default()
        };
        let identity = announcer(&a);
        assert_eq!(
            identity.machine_did(),
            did,
            "announced as its registered machine DID"
        );
        tenzro_network::SignedAnnouncement::sign(
            &mut ann,
            identity.machine_did(),
            identity.signer(),
        )
        .unwrap();
        verify_announcement_in(Some(&registry), &ann).expect("node B accepts node A");

        // Another machine claiming the DID of node A is refused.
        let impostor = announcer(&other);
        let mut forged = ann.clone();
        tenzro_network::SignedAnnouncement::sign(&mut forged, &did, impostor.signer()).unwrap();
        assert!(verify_announcement_in(Some(&registry), &forged).is_err());
    }

    #[test]
    fn supply_metrics_follow_the_consensus_counters() {
        let at = tenzro_types::primitives::Timestamp::new(1_000);
        let first = supply_snapshot(None, 1_000_000, 50, BlockHeight(10), at, 30);
        assert_eq!(first.block_height, BlockHeight(10));
        assert_eq!(first.circulating_supply, 1_000_000);
        assert_eq!(
            (
                first.epoch_supply_delta,
                first.burn_breakdown.base_fee,
                first.emission_breakdown.total()
            ),
            (0, 0, 0)
        );

        // 700 minted and 200 burned in the epoch: supply up 500.
        let next = supply_snapshot(
            Some((1_000_000, 50)),
            1_000_500,
            250,
            BlockHeight(20),
            at,
            30,
        );
        assert_eq!(next.epoch_supply_delta, 500);
        assert_eq!(next.burn_breakdown.base_fee, 200);
        assert_eq!(next.emission_breakdown.total(), 700);
        assert_eq!(next.captured_at, at);
        assert_eq!(
            next.rolling_window_supply_delta_bps,
            (500i128 * 30 * 10_000 / 1_000_500) as i32
        );
    }

    fn block_at(height: u64, prev_hash: Hash, transactions: Vec<SignedTransaction>) -> Block {
        let header = tenzro_types::block::BlockHeader {
            height: BlockHeight::from(height),
            epoch: 0,
            round: height,
            anchor: Hash::zero(),
            prev_hash,
            tx_root: Block::compute_tx_root(&transactions),
            state_root: Hash::zero(),
            event_root: Hash::zero(),
            receipts_root: Hash::new(tenzro_types::eth_receipt::EMPTY_TRIE_ROOT),
            logs_bloom: tenzro_types::LogsBloom::default(),
            timestamp: tenzro_types::primitives::Timestamp::new(1_000 * height as i64),
            proposer: Address::default(),
            metadata: tenzro_types::block::BlockMetadata {
                gas_used: 0,
                gas_limit: transactions.iter().map(|t| t.transaction.gas_limit).sum(),
                tx_count: transactions.len() as u64,
                protocol_version: 1,
                base_fee_per_gas: None,
            },
        };
        Block::new(header, transactions)
    }

    /// One transaction ordered in two segments lands in two blocks. The copy
    /// at the later height is not executed, and the first inclusion keeps its
    /// index entry and receipt.
    #[tokio::test]
    async fn a_transaction_repeated_at_a_later_height_keeps_its_first_inclusion() {
        let (mut event_loop, genesis, transfer) = funded_sender().await;
        let tx = transfer(0);
        let hash = tx.transaction.hash();
        let read = |el: &EventLoop, key: &str| {
            el.storage
                .get(CF_TRANSACTIONS, format!("{key}:{hash}").as_bytes())
                .unwrap()
        };

        let first = block_now(1, genesis, vec![tx.clone()]);
        event_loop
            .handle_block_finalized_inner(first, BlockSource::Ordered)
            .await
            .unwrap();
        let idx = read(&event_loop, "idx").expect("first inclusion indexed");
        let receipt = read(&event_loop, "receipt");
        let at: serde_json::Value = serde_json::from_slice(&idx).unwrap();
        assert_eq!(at["block_height"], 1);

        let other = transfer(1);
        let other_hash = other.transaction.hash();
        let second = block_now(2, event_loop.last_block_hash(), vec![other, tx]);
        event_loop
            .handle_block_finalized_inner(second, BlockSource::Ordered)
            .await
            .unwrap();
        let other_idx = event_loop
            .storage
            .get(CF_TRANSACTIONS, format!("idx:{other_hash}").as_bytes())
            .unwrap()
            .expect("the second block executed");
        let other_at: serde_json::Value = serde_json::from_slice(&other_idx).unwrap();
        assert_eq!(
            (
                other_at["block_height"].clone(),
                other_at["tx_index"].clone()
            ),
            (2.into(), 0.into())
        );
        assert_eq!(
            read(&event_loop, "idx"),
            Some(idx),
            "the copy must not re-index"
        );
        assert_eq!(
            read(&event_loop, "receipt"),
            receipt,
            "the copy must not overwrite the receipt"
        );
    }

    /// A transaction ordered ahead of its nonce is not included: it gets no
    /// index entry and no receipt, stays in the mempool, and executes in the
    /// block that carries it after its predecessor. Indexed at the first
    /// height, its later copy would be skipped as already included and the
    /// sender would stall behind the gap.
    #[tokio::test]
    async fn a_transaction_ahead_of_its_nonce_executes_when_ordered_again() {
        let (mut event_loop, genesis, transfer) = funded_sender().await;
        let (first_tx, ahead) = (transfer(0), transfer(1));
        let hash = ahead.transaction.hash();
        let read = |el: &EventLoop, key: &str| {
            el.storage
                .get(CF_TRANSACTIONS, format!("{key}:{hash}").as_bytes())
                .unwrap()
        };

        let first = block_now(1, genesis, vec![ahead.clone()]);
        event_loop
            .handle_block_finalized_inner(first, BlockSource::Ordered)
            .await
            .unwrap();
        assert_eq!(
            read(&event_loop, "receipt").map(|r| String::from_utf8_lossy(&r).into_owned()),
            None,
            "ahead of its nonce: not included"
        );
        assert_eq!(read(&event_loop, "idx"), None);

        let second = block_now(2, event_loop.last_block_hash(), vec![first_tx, ahead]);
        event_loop
            .handle_block_finalized_inner(second, BlockSource::Ordered)
            .await
            .unwrap();
        let idx = read(&event_loop, "idx").expect("executed once its predecessor ran");
        let at: serde_json::Value = serde_json::from_slice(&idx).unwrap();
        assert_eq!(
            (at["block_height"].clone(), at["tx_index"].clone()),
            (2.into(), 1.into())
        );
        assert!(read(&event_loop, "receipt").is_some());
    }

    /// A transaction stays in the mempool, and so in the sender's `pending`
    /// nonce, until the state its block wrote is committed. A block refused
    /// after execution commits nothing and leaves it there; once its block
    /// commits, the executed nonce counts it instead.
    #[tokio::test]
    async fn a_transaction_counts_toward_the_pending_nonce_until_its_state_commits() {
        use tenzro_vm::traits::VmState as _;

        let (mut event_loop, genesis, transfer) = funded_sender().await;
        let consensus = crate::consensus_driver::tests::handle_with_one_validator();
        event_loop.consensus = Some(consensus.clone());
        let tx = transfer(0);
        let sender = tx.transaction.from;
        consensus.mempool().add_transaction(tx.clone()).unwrap();
        let storage = event_loop.storage.clone() as Arc<dyn KvStore>;
        let pending = || {
            consensus.mempool().next_nonce(&sender, || {
                tenzro_vm::StateAdapter::with_storage(storage.clone()).get_nonce(sender.as_bytes())
            })
        };
        assert_eq!(pending(), 1);

        // A peer's block whose header does not commit what execution emits
        // is refused after the transaction has executed.
        let refused = block_now(1, genesis, vec![tx.clone()]);
        assert!(
            event_loop
                .handle_block_finalized_inner(refused, BlockSource::Imported)
                .await
                .is_err()
        );
        assert!(
            consensus
                .mempool()
                .get_transaction(&tx.transaction.hash())
                .is_some(),
            "a refused block's transaction stays in the mempool"
        );
        assert_eq!(pending(), 1, "nonce 0 is taken by the waiting transaction");

        // The refusal reloads the state from storage, which holds no
        // enrolment: the sender's key is enrolled again.
        let signer = TestHybridSigner::hybrid(1);
        enroll(
            &mut *event_loop.state_adapter.lock().await,
            &signer,
            &signer,
        );
        let executed = block_now(1, genesis, vec![tx.clone()]);
        event_loop
            .handle_block_finalized_inner(executed, BlockSource::Ordered)
            .await
            .unwrap();
        assert!(consensus.mempool().is_empty());
        assert_eq!(pending(), 1);
    }

    /// A block at `height` stamped with the current time, inside the
    /// validity window of transactions signed now.
    fn block_now(height: u64, prev_hash: Hash, transactions: Vec<SignedTransaction>) -> Block {
        let mut block = block_at(height, prev_hash, transactions);
        block.header.timestamp = tenzro_types::primitives::Timestamp::now();
        block
    }

    /// An event loop whose genesis funds one sender, and that sender's
    /// transfers at a nonce, priced over the base fee.
    async fn funded_sender() -> (EventLoop, Hash, impl Fn(u64) -> SignedTransaction) {
        let signer = TestHybridSigner::hybrid(1);
        let address: [u8; 32] = signer.address().as_bytes().try_into().unwrap();
        let funded = [(address, 1_000_000)];
        let (event_loop, genesis) = event_loop_with_genesis(&funded).await;
        enroll(
            &mut *event_loop.state_adapter.lock().await,
            &signer,
            &signer,
        );
        let price =
            tenzro_vm::ledger::block_base_fee(&*event_loop.state_adapter.lock().await).max(1) * 2;
        let transfer = move |nonce: u64| {
            let tx = Transaction::new(
                ChainId::from(1337),
                signer.address(),
                Address::new([0xee; 32]),
                Nonce::from(nonce),
                TransactionType::Transfer { amount: 1 },
                21_000,
                u64::try_from(price).expect("price fits"),
            );
            let sig = signer
                .sign(SignatureContext::Transaction, tx.hash().as_bytes())
                .unwrap();
            SignedTransaction::new(tx, signer.public_key().p256.clone(), sig)
        };
        (event_loop, genesis, transfer)
    }

    fn signed(
        signer: &TestHybridSigner,
        tx_type: TransactionType,
        nonce: u64,
    ) -> SignedTransaction {
        let tx = unsigned(signer, tx_type, nonce);
        let sig = signer
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap();
        SignedTransaction::new(tx, signer.public_key().p256.clone(), sig)
    }

    fn unsigned_signed_tx(tx: Transaction) -> SignedTransaction {
        SignedTransaction::new(
            tx,
            Vec::new(),
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        )
    }

    /// `holder` enrolls `signer`'s ML-DSA-65 key for its own account.
    fn enroll(state: &mut dyn VmState, holder: &TestHybridSigner, pq: &TestHybridSigner) {
        let key = pq.public_key().pq.clone().unwrap();
        tenzro_vm::account_keys::set_enrolled_pq_key(
            state,
            &holder.public_key().p256,
            key,
            &mut Vec::new(),
        );
    }

    /// A transaction the node signs itself takes the fee market's current
    /// minimum at signing time, so it is still admitted after the floor
    /// rises; the price it carried before is refused.
    #[test]
    fn a_node_signed_transaction_is_admitted_after_the_fee_floor_rises() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tenzro_consensus::admission::{
            AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane,
        };
        use tenzro_consensus::mempool::{AccountStateReader, Mempool};

        struct Chain(AtomicU64);
        impl AccountStateReader for Chain {
            fn account_nonce(&self, _: &Address) -> u64 {
                0
            }
            fn account_balance(&self, _: &Address) -> u128 {
                u128::MAX
            }
            fn block_base_fee(&self) -> u128 {
                u128::from(self.0.load(Ordering::SeqCst))
            }
        }

        let chain = Arc::new(Chain(AtomicU64::new(1_000_000_000)));
        let mempool = Mempool::new(Arc::new(tenzro_consensus::ConsensusConfig::default()));
        mempool
            .set_admission(Arc::new(AdmissionController::new(
                AdmissionConfig::default(),
                Arc::new(DefaultLaneResolver),
            )))
            .unwrap();
        mempool.set_state_reader(chain.clone()).unwrap();
        let signer = TestHybridSigner::hybrid(7);
        let sign = |nonce: u64, price: u64| {
            crate::node::sign_validator_transaction(
                &signer,
                1,
                nonce,
                TransactionType::Transfer { amount: 0 },
                21_000,
                price,
            )
            .unwrap()
        };

        let before = mempool.current_min_gas_price(Lane::Open);
        mempool.add_transaction(sign(0, before)).unwrap();

        chain.0.store(50_000_000_000, Ordering::SeqCst);
        let after = mempool.current_min_gas_price(Lane::Open);
        // The open lane pays its configured 4x multiple of the base fee.
        assert_eq!(after, 200_000_000_000);
        assert!(mempool.add_transaction(sign(1, before)).is_err());
        mempool.add_transaction(sign(1, after)).unwrap();
    }

    #[test]
    fn a_validator_transaction_is_from_the_account_its_keys_control() {
        let signer = TestHybridSigner::hybrid(3);
        let tx = crate::node::sign_validator_transaction(
            &signer,
            1,
            0,
            TransactionType::Transfer { amount: 0 },
            21_000,
            10_000_000_000,
        )
        .unwrap();
        let slot = signer.public_key().account_slot();
        assert_eq!(
            tx.transaction.from.as_bytes()[..],
            slot[..],
            "not the validator's funded account"
        );
        verify_transaction_signature(&tx).unwrap();
    }

    #[test]
    fn the_p256_leg_verifies() {
        verify_transaction_signature(&create_test_transaction(0)).unwrap();
    }

    /// A signature minted for an agent message over the same bytes does not
    /// authorize a transaction.
    #[test]
    fn a_signature_from_another_context_is_refused() {
        let signer = TestHybridSigner::hybrid(4);
        let tx = unsigned(&signer, TransactionType::Transfer { amount: 1 }, 0);
        let sig = signer
            .sign(SignatureContext::AgentMessage, tx.hash().as_bytes())
            .unwrap();
        let tx = SignedTransaction::new(tx, signer.public_key().p256.clone(), sig);
        assert!(verify_transaction_signature(&tx).is_err());
    }

    /// A key that does not name the `from` account cannot spend it.
    #[test]
    fn a_foreign_p256_key_cannot_spend_an_account() {
        let victim = TestHybridSigner::p256_only(5);
        let attacker = TestHybridSigner::p256_only(6);
        let mut tx = unsigned(&attacker, TransactionType::Transfer { amount: 1 }, 0);
        tx.from = victim.address();
        let sig = attacker
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap();
        let tx = SignedTransaction::new(tx, attacker.public_key().p256.clone(), sig);
        assert!(verify_transaction_sender(&tx, &tenzro_vm::StateAdapter::new()).is_err());
    }

    /// Every validator executes a finalized block whatever its proposer
    /// admitted. A transaction carrying no signature, from an account its
    /// key does not name, must not execute: the check that it is a passkey of
    /// the account's keystore runs only on a signature.
    #[tokio::test]
    async fn a_block_transaction_with_no_signature_does_not_execute() {
        use tenzro_vm::traits::VmState as _;
        let victim = TestHybridSigner::p256_only(12);
        let other = TestHybridSigner::p256_only(13);
        let mut tx = unsigned(&other, TransactionType::Transfer { amount: 1 }, 0);
        tx.from = victim.address();
        let tx = SignedTransaction::new(
            tx,
            other.public_key().p256.clone(),
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        );
        if verify_transaction_signature(&tx).is_err() {
            return;
        }
        let mut state = tenzro_vm::StateAdapter::new();
        state.set_balance(victim.address().as_bytes(), 1_000_000_000_000_000_000);
        let runtime = tenzro_vm::MultiVmRuntime::new(
            tenzro_vm::VmConfig::default().with_chain_id(tx.transaction.chain_id.0),
        )
        .await
        .unwrap();
        let r = runtime
            .execute_transaction(&convert_transaction(&tx), &mut state)
            .await;
        assert!(
            !matches!(&r, Ok(x) if x.success),
            "an unsigned transaction executed as the victim: {r:?}"
        );
    }

    /// A submission over RPC runs these two checks and then goes straight to
    /// the mempool, which checks no signature, and from there into this
    /// validator's batches. A transaction carrying no signature, from an
    /// account its key does not name, must not pass them.
    #[test]
    fn the_rpc_submission_checks_refuse_a_transaction_with_no_signature() {
        let victim = TestHybridSigner::p256_only(12);
        let other = TestHybridSigner::p256_only(13);
        let mut tx = unsigned(&other, TransactionType::Transfer { amount: 1 }, 0);
        tx.from = victim.address();
        let tx = SignedTransaction::new(
            tx,
            other.public_key().p256.clone(),
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        );
        let state = tenzro_vm::StateAdapter::new();
        assert!(
            verify_transaction_signature(&tx)
                .and_then(|()| verify_transaction_pq_leg(&tx, &state))
                .is_err()
        );
    }

    /// A block takes the version an enacted upgrade names from its
    /// activation height on, keeps its parent's before it, and never goes
    /// back to a lower one.
    #[test]
    fn a_block_takes_the_upgraded_protocol_version_from_its_activation_height() {
        let activation = tenzro_vm::governance::UpgradeActivation {
            proposal_id: "p".into(),
            version: "7.0.0".into(),
            code_hash: "00".into(),
            readiness_met_height: 90,
            activation_height: 100,
        };
        assert_eq!(block_protocol_version(1, 99, Some(&activation)), 1);
        assert_eq!(block_protocol_version(1, 100, Some(&activation)), 7);
        assert_eq!(block_protocol_version(7, 150, None), 7);
        assert_eq!(block_protocol_version(8, 150, Some(&activation)), 8);
        let unparsed = tenzro_vm::governance::UpgradeActivation {
            version: "next".into(),
            ..activation
        };
        assert_eq!(block_protocol_version(1, 150, Some(&unparsed)), 1);
    }

    /// Once an account retires its P-256 leg, admission and execution take
    /// its ML-DSA-65 leg alone; before that, admission refuses it.
    #[test]
    fn admission_takes_the_ml_dsa_leg_alone_once_p256_is_retired() {
        let owner = TestHybridSigner::hybrid(14);
        let mut state = tenzro_vm::StateAdapter::new();
        enroll(&mut state, &owner, &owner);
        let tx = unsigned(&owner, TransactionType::Transfer { amount: 1 }, 0);
        let mut sig = owner
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap();
        sig.classical = ClassicalProof::Raw {
            signature: Vec::new(),
        };
        let pq_only = SignedTransaction::new(tx, owner.public_key().p256.clone(), sig);
        verify_transaction_signature(&pq_only).unwrap();
        assert!(verify_transaction_pq_leg(&pq_only, &state).is_err());
        tenzro_vm::account_keys::retire_p256(&mut state, &owner.public_key().p256, &mut Vec::new());
        verify_transaction_pq_leg(&pq_only, &state).unwrap();
        assert!(convert_transaction(&pq_only).signature.is_some());
    }

    /// Once an account has an ML-DSA-65 key enrolled, admission refuses a
    /// transaction signed with its P-256 key alone (a stolen P-256 key), and
    /// one whose ML-DSA-65 leg is from another key.
    #[test]
    fn admission_refuses_a_stripped_or_grafted_pq_leg_once_enrolled() {
        let owner = TestHybridSigner::hybrid(8);
        let p256_alone = TestHybridSigner::p256_only(8);
        let other_pq = TestHybridSigner::hybrid(9);
        let mut state = tenzro_vm::StateAdapter::new();

        let stripped = signed(&p256_alone, TransactionType::Transfer { amount: 1 }, 0);
        verify_transaction_signature(&stripped).unwrap();
        // Before enrolling, a classical-only transaction is refused too.
        assert!(verify_transaction_pq_leg(&stripped, &state).is_err());

        enroll(&mut state, &owner, &owner);
        verify_transaction_pq_leg(
            &signed(&owner, TransactionType::Transfer { amount: 1 }, 0),
            &state,
        )
        .unwrap();
        assert!(verify_transaction_pq_leg(&stripped, &state).is_err());

        let tx = unsigned(&owner, TransactionType::Transfer { amount: 1 }, 0);
        let mut sig = owner
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap();
        sig.pq = other_pq
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap()
            .pq;
        let grafted = SignedTransaction::new(tx, owner.public_key().p256.clone(), sig);
        verify_transaction_signature(&grafted).unwrap();
        assert!(verify_transaction_pq_leg(&grafted, &state).is_err());
    }

    /// The ML-DSA-65 leg is mandatory by default: a classical-only
    /// transaction is refused, a hybrid-signed one is refused until the
    /// account enrolls its key, and once the key is enrolled the hybrid
    /// transaction is accepted and the classical-only one is not.
    #[test]
    fn a_classical_only_transaction_is_refused_and_an_enrolled_account_works_end_to_end() {
        let owner = TestHybridSigner::hybrid(30);
        let p256_alone = TestHybridSigner::p256_only(30);
        let mut state = tenzro_vm::StateAdapter::new();
        let transfer = || TransactionType::Transfer { amount: 1 };

        let classical = signed(&p256_alone, transfer(), 0);
        verify_transaction_signature(&classical).unwrap();
        let err = verify_transaction_pq_leg(&classical, &state).unwrap_err();
        assert!(err.to_string().contains("requires the hardware ML-DSA-65 leg"), "{err}");

        // A fresh account's transfer carries the leg but has no key to check
        // it against: it enrols first.
        assert!(verify_transaction_pq_leg(&signed(&owner, transfer(), 0), &state).is_err());

        let key = owner.public_key().pq.clone().unwrap();
        let msg = pq_enrollment_message(&owner.public_key().account_slot(), &key);
        let possession = owner
            .sign(SignatureContext::PqKeyEnrollment, &msg)
            .unwrap()
            .pq
            .unwrap();
        let enrol = TransactionType::AccountKeys {
            op: AccountKeysOp::EnrollPqKey {
                ml_dsa_public_key: key,
                possession,
            },
        };
        verify_transaction_pq_leg(&signed(&owner, enrol, 0), &state).unwrap();
        enroll(&mut state, &owner, &owner);

        verify_transaction_pq_leg(&signed(&owner, transfer(), 1), &state).unwrap();
        assert!(verify_transaction_pq_leg(&signed(&p256_alone, transfer(), 1), &state).is_err());
    }

    /// An enrollment carries the leg of the key it enrolls when none is
    /// enrolled, and of the enrolled key when it replaces one.
    #[test]
    fn admission_checks_an_enrollment_against_the_right_key() {
        let owner = TestHybridSigner::hybrid(10);
        let next = TestHybridSigner::hybrid(11);
        let enroll_op = |pq: &TestHybridSigner| {
            let key = pq.public_key().pq.clone().unwrap();
            let msg = pq_enrollment_message(&owner.public_key().account_slot(), &key);
            let possession = pq
                .sign(SignatureContext::PqKeyEnrollment, &msg)
                .unwrap()
                .pq
                .unwrap();
            TransactionType::AccountKeys {
                op: AccountKeysOp::EnrollPqKey {
                    ml_dsa_public_key: key,
                    possession,
                },
            }
        };
        let mut state = tenzro_vm::StateAdapter::new();
        verify_transaction_pq_leg(&signed(&owner, enroll_op(&owner), 0), &state).unwrap();
        let p256_alone = TestHybridSigner::p256_only(10);
        assert!(
            verify_transaction_pq_leg(&signed(&p256_alone, enroll_op(&owner), 0), &state).is_err()
        );

        enroll(&mut state, &owner, &owner);
        // A rotation signed by the new key alone is refused; it needs the old one.
        let tx = unsigned(&owner, enroll_op(&next), 1);
        let mut sig = owner
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap();
        sig.pq = next
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .unwrap()
            .pq;
        let by_new_key = SignedTransaction::new(tx, owner.public_key().p256.clone(), sig);
        assert!(verify_transaction_pq_leg(&by_new_key, &state).is_err());
        verify_transaction_pq_leg(&signed(&owner, enroll_op(&next), 1), &state).unwrap();
    }

    #[test]
    fn test_convert_transfer_transaction() {
        let tx = create_test_transaction(1);
        let vm_tx = convert_transaction(&tx);

        assert_eq!(vm_tx.value, 1000);
        assert_eq!(vm_tx.gas_limit, 21000);
        assert_eq!(vm_tx.gas_price, 100);
        assert_eq!(vm_tx.nonce, 1);
        assert_eq!(vm_tx.chain_id, 1);
    }

    #[test]
    fn test_convert_contract_call() {
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(5),
            TransactionType::ContractCall {
                calls: vec![tenzro_types::VmCall {
                    vm: tenzro_types::CallVm::Evm,
                    to: vec![7u8; 20],
                    value: 9,
                    data: vec![1, 2, 3, 4],
                }],
            },
            100000,
            200,
        );
        let signed_tx = unsigned_signed_tx(tx.clone());
        let vm_tx = convert_transaction(&signed_tx);

        assert_eq!(vm_tx.value, 0);
        assert_eq!(vm_tx.vm_type, VmType::Tenzro);
        let payload = vm_tx
            .data
            .strip_prefix(tenzro_vm::native::SELECTOR_CONTRACT_CALL.as_slice())
            .expect("contract calls carry the contract-call selector");
        let TransactionType::ContractCall { calls } = &tx.tx_type else {
            unreachable!()
        };
        assert_eq!(&tenzro_types::VmCall::decode_list(payload).unwrap(), calls);
        assert_eq!(vm_tx.gas_limit, 100000);
    }

    #[tokio::test]
    async fn test_shutdown() {
        use tenzro_vm::VmConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let vm_runtime = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());

        let chain_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let metrics = Arc::new(MetricsCollector::new());
        let event_loop = EventLoop::new(storage, vm_runtime, None, None, chain_tip, metrics);

        // shutdown sends both Shutdown event and broadcast
        event_loop.shutdown();
    }

    #[test]
    fn test_convert_contract_deploy() {
        let code = vec![0x60, 0x80, 0x60, 0x40];
        let args = vec![1, 2, 3];

        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(0),
            TransactionType::ContractDeploy {
                code: code.clone(),
                args: args.clone(),
            },
            500000,
            300,
        );
        let signed_tx = unsigned_signed_tx(tx);
        let vm_tx = convert_transaction(&signed_tx);

        assert_eq!(vm_tx.value, 0);
        assert!(vm_tx.data.starts_with(&code));
        assert_eq!(&vm_tx.data[code.len()..], &args[..]);
        assert_eq!(vm_tx.vm_type, VmType::Evm);
        assert_eq!(vm_tx.to, None, "a deployment creates, it calls no one");
    }

    // ---- AgentBond log decoders + reflection scan -----------------

    /// Block-sync evidence reaches the nearest kept certificate, which may
    /// lie past the blocks served with it. The bodies whose blocks are held
    /// import; the first one that runs past them ends the import there,
    /// rather than failing it and scoring the honest peer down.
    #[tokio::test]
    async fn evidence_past_the_served_blocks_imports_up_to_them() {
        let mut el = make_event_loop().await;
        el.current_height = 4;
        for h in 5..=8 {
            el.uncertified
                .insert(h, block_at(h, Hash::default(), Vec::new()));
        }
        let cp = |first_height: u64, last_height: u64| tenzro_consensus::Checkpoint {
            chain_id: 7,
            genesis_hash: [1; 32],
            epoch: 0,
            index: 0,
            prev: [0; 32],
            first_height,
            last_height,
            blocks_root: [0; 32],
            state_height: last_height,
            state_root: [0; 32],
            statement_root: [0; 32],
            next_committee_root: None,
            anchor_round: 0,
            timestamp_ms: 0,
            ordering_root: [0; 32],
        };
        assert!(el.holds_range(&cp(5, 6)));
        assert!(el.holds_range(&cp(7, 8)));
        assert!(!el.holds_range(&cp(7, 9)), "block 9 was not served");
        assert!(!el.holds_range(&cp(9, 12)));
        // Already executed heights need not be held.
        assert!(el.holds_range(&cp(3, 6)));
    }

    /// A minimal `EventLoop` with only storage and the VM runtime wired.
    async fn make_event_loop() -> EventLoop {
        use tenzro_vm::VmConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let vm_runtime = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());
        let chain_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let metrics = Arc::new(MetricsCollector::new());
        EventLoop::new(storage, vm_runtime, None, None, chain_tip, metrics)
    }

    /// Self-consistent blocks gossiped past the tip cost a follower at most
    /// a fixed budget, however many arrive; the ones nearest the tip stay.
    #[tokio::test]
    async fn gossiped_blocks_held_past_the_tip_stay_under_a_byte_budget() {
        let mut el = make_event_loop().await;
        assert!(!el.orders_blocks());
        let budget = 128usize << 20;
        let big = |h: u64| {
            let tx = Transaction::new(
                ChainId::from(1),
                Address::default(),
                Address::default(),
                Nonce::from(h),
                TransactionType::ContractDeploy {
                    code: vec![7; 512 * 1024],
                    args: Vec::new(),
                },
                500_000,
                1,
            );
            block_at(h, Hash::default(), vec![unsigned_signed_tx(tx)])
        };
        for h in 1..=200u64 {
            let verdict = GossipVerdict(Arc::new(parking_lot::Mutex::new(None)));
            el.handle_network_block(big(h), verdict).await.unwrap();
        }
        let held: usize = el
            .uncertified
            .values()
            .map(|b| serde_json::to_vec(b).unwrap().len())
            .sum();
        assert!(held <= budget, "{held} bytes held past the tip");
        assert!(
            el.uncertified.contains_key(&1),
            "the next block was dropped"
        );
    }

    /// A resolver whose fetches never finish.
    struct StalledResolver;

    #[async_trait::async_trait]
    impl IrohResolver for StalledResolver {
        async fn fetch_bytes(
            &self,
            _uri: &tenzro_iroh::TenzroUri,
        ) -> tenzro_iroh::IrohResult<bytes::Bytes> {
            std::future::pending().await
        }
        async fn publish_bytes(
            &self,
            _bytes: bytes::Bytes,
        ) -> tenzro_iroh::IrohResult<tenzro_iroh::TenzroUri> {
            unreachable!()
        }
        async fn publish_path(
            &self,
            _path: &std::path::Path,
        ) -> tenzro_iroh::IrohResult<tenzro_iroh::TenzroUri> {
            unreachable!()
        }
    }

    /// A shard whose fetch never finishes is given up after the fetch
    /// limit, so a replication request ends however its origin behaves.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_shard_fetch_is_given_up() {
        let uris: Vec<_> = (0..3u8)
            .map(|i| tenzro_iroh::TenzroUri::Blob {
                hash: hex::encode([i; 32]),
                provider_hint: None,
            })
            .collect();
        let start = tokio::time::Instant::now();
        assert_eq!(
            pin_shards(&StalledResolver, &uris, &ShardGate::none()).await,
            0
        );
        assert_eq!(start.elapsed(), 3 * SHARD_FETCH_TIMEOUT);
    }

    /// A resolver whose fetches fail the way the blob store did on
    /// 2026-10-29 after a write hit a full disk: the entry is poisoned and
    /// the store either errors or panics on every later request.
    struct PoisonedResolver {
        calls: std::sync::atomic::AtomicUsize,
        panic: bool,
    }

    #[async_trait::async_trait]
    impl IrohResolver for PoisonedResolver {
        async fn fetch_bytes(
            &self,
            _uri: &tenzro_iroh::TenzroUri,
        ) -> tenzro_iroh::IrohResult<bytes::Bytes> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.panic {
                panic!("poisoned storage should not be used");
            }
            Err(tenzro_iroh::IrohError::Backend(
                "Entity actor inbox is closed".into(),
            ))
        }
        async fn publish_bytes(
            &self,
            _bytes: bytes::Bytes,
        ) -> tenzro_iroh::IrohResult<tenzro_iroh::TenzroUri> {
            unreachable!()
        }
        async fn publish_path(
            &self,
            _path: &std::path::Path,
        ) -> tenzro_iroh::IrohResult<tenzro_iroh::TenzroUri> {
            unreachable!()
        }
    }

    fn one_shard() -> Vec<tenzro_iroh::TenzroUri> {
        vec![tenzro_iroh::TenzroUri::Blob {
            hash: hex::encode([7u8; 32]),
            provider_hint: None,
        }]
    }

    /// A panic inside the blob store on one shard is contained: the call
    /// returns, the shard counts as failed, and the next request for it
    /// does not reach the store again until its backoff has passed.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_blob_store_costs_one_shard_not_the_node() {
        let r = PoisonedResolver {
            calls: Default::default(),
            panic: true,
        };
        let gate = ShardGate::none();
        let uris = one_shard();
        assert_eq!(pin_shards(&r, &uris, &gate).await, 0);
        assert_eq!(r.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // announced again straight away: held back, the store is not touched
        assert_eq!(pin_shards(&r, &uris, &gate).await, 0);
        assert_eq!(r.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// The failing shape of 2026-10-30: the same shard objects announced
    /// over and over against a poisoned store. Attempts are bounded, then
    /// the object is quarantined and no longer reaches the store.
    #[tokio::test(start_paused = true)]
    async fn announcements_of_a_poisoned_shard_are_bounded_then_quarantined() {
        let r = PoisonedResolver {
            calls: Default::default(),
            panic: false,
        };
        let gate = ShardGate::none();
        let uris = one_shard();
        let max = crate::shard_quarantine::ShardQuarantinePolicy::default().max_attempts as usize;
        // one announcement every 20 minutes for two days
        for _ in 0..(48 * 3) {
            assert_eq!(pin_shards(&r, &uris, &gate).await, 0);
            tokio::time::advance(Duration::from_secs(20 * 60)).await;
        }
        let calls = r.calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            calls <= max * (48 / 6 + 1),
            "{calls} store calls for one object in two days"
        );
        assert!(calls >= max * 2, "too few rounds: {calls}");
        assert!(calls < 48 * 3 / 2, "not bounded: {calls}");
    }

    /// Past the refuse watermark an inbound shard is not written at all.
    #[tokio::test(start_paused = true)]
    async fn shards_are_refused_when_the_disk_is_full() {
        let r = PoisonedResolver {
            calls: Default::default(),
            panic: false,
        };
        let disk = Arc::new(crate::storage_maintenance::DiskGuard::default());
        disk.set(crate::storage_maintenance::DiskPressure::Refusing, 97);
        let gate = ShardGate {
            quarantine: Arc::new(crate::shard_quarantine::ShardQuarantine::default()),
            disk: Some(disk),
        };
        assert_eq!(pin_shards(&r, &one_shard(), &gate).await, 0);
        assert_eq!(r.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// An event loop over a chain whose genesis allocates `funded` (whole
    /// TNZO per account), so the accounts hold value the ledger already
    /// counts in total supply. Returns the genesis block hash for block 1.
    async fn event_loop_with_genesis(funded: &[([u8; 32], u128)]) -> (EventLoop, Hash) {
        use tenzro_vm::VmConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let genesis = crate::config::GenesisConfig {
            version: crate::config::GENESIS_SCHEMA_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: vec![],
            accounts: funded
                .iter()
                .map(|(address, tnzo)| crate::config::GenesisAccount {
                    address: format!("0x{}", hex::encode(address)),
                    balance: *tnzo,
                })
                .collect(),
            weak_subjectivity: None,
            time: tenzro_consensus::TimeRules::default(),
            network_params: Default::default(),
            economy: Default::default(),
            role_stakes: Vec::new(),
        };
        let genesis_block = crate::genesis::initialize_genesis(&storage, &genesis)
            .await
            .unwrap();
        let vm_runtime = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());
        let chain_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let metrics = Arc::new(MetricsCollector::new());
        let event_loop = EventLoop::new(storage, vm_runtime, None, None, chain_tip, metrics);
        (event_loop, genesis_block.hash())
    }

    /// Segments ordered at heights 1..=n, one transfer each, stamped now.
    fn ordered_segments(
        n: u64,
        transfer: &impl Fn(u64) -> SignedTransaction,
    ) -> Vec<OrderedSegment> {
        let now_ms = tenzro_types::primitives::Timestamp::now().as_millis() as u64;
        (1..=n)
            .map(|height| OrderedSegment {
                height,
                epoch: 0,
                round: height * 2,
                anchor: Hash::new([height as u8; 32]),
                proposer: Address::zero(),
                timestamp_ms: now_ms + height,
                transactions: vec![transfer(height - 1)],
            })
            .collect()
    }

    /// Segments that queued while execution was busy run together under one
    /// sync of the store, and build, execute and commit to exactly what the
    /// same segments executed one at a time do.
    #[tokio::test]
    async fn a_run_of_ordered_segments_executes_as_its_segments_one_at_a_time() {
        const N: u64 = 24;
        let (mut alone, genesis, transfer) = funded_sender().await;
        let (mut together, same_genesis, _) = funded_sender().await;
        assert_eq!(genesis, same_genesis);
        let segments = ordered_segments(N, &transfer);
        let hashes: Vec<Hash> = segments
            .iter()
            .map(|s| s.transactions[0].transaction.hash())
            .collect();

        for seg in segments.clone() {
            alone.execute_ordered_run(vec![seg]).await;
        }
        together.execute_ordered_run(segments).await;

        assert_eq!((alone.current_height, together.current_height), (N, N));
        assert!(together.unsynced.is_empty() && !together.sync_deferred);
        let blocks = |el: &EventLoop, h: u64| {
            let store = BlockStoreImpl::new(el.storage.clone()).unwrap();
            async move {
                store
                    .get_block_by_height(BlockHeight::from(h))
                    .await
                    .unwrap()
            }
        };
        for h in 1..=N {
            let (a, b) = (blocks(&alone, h).await, blocks(&together, h).await);
            assert!(a.is_some(), "height {h} executed");
            assert_eq!(a.map(|b| b.hash()), b.map(|b| b.hash()), "block at {h}");
            assert_eq!(
                alone.state_trie.root_at(h).unwrap(),
                together.state_trie.root_at(h).unwrap(),
                "state root at {h}"
            );
        }
        for hash in &hashes {
            let (a, b) = (receipt_of(&alone, hash), receipt_of(&together, hash));
            assert!(a.success);
            assert_eq!(
                serde_json::to_vec(&a).unwrap(),
                serde_json::to_vec(&b).unwrap()
            );
        }
    }

    fn receipt_of(el: &EventLoop, hash: &Hash) -> TxReceiptRecord {
        let raw = el
            .storage
            .get(CF_TRANSACTIONS, format!("receipt:{hash}").as_bytes())
            .unwrap()
            .expect("the transaction has a receipt");
        serde_json::from_slice(&raw).unwrap()
    }

    /// An EIP-1559 transfer on chain 1337 at nonce 0, signed the way a
    /// wallet library signs it.
    fn signed_eip1559(
        key: &k256::ecdsa::SigningKey,
        max_fee: u128,
        to: [u8; 20],
        value: u128,
    ) -> Vec<u8> {
        use rlp::RlpStream;
        use sha3::{Digest, Keccak256};

        let fields = |s: &mut RlpStream| {
            s.append(&1337u64)
                .append(&0u64)
                .append(&1u64)
                .append(&max_fee);
            s.append(&21_000u64)
                .append(&to.to_vec())
                .append(&value)
                .append(&Vec::<u8>::new());
            s.begin_list(0);
        };
        let mut unsigned = RlpStream::new_list(9);
        fields(&mut unsigned);
        let mut preimage = vec![2u8];
        preimage.extend_from_slice(&unsigned.out());
        let (sig, rid) = key
            .sign_prehash_recoverable(&Keccak256::digest(&preimage))
            .unwrap();
        let strip = |b: &[u8]| {
            b.iter()
                .skip_while(|x| **x == 0)
                .copied()
                .collect::<Vec<u8>>()
        };
        let rs = sig.to_bytes();
        let mut signed = RlpStream::new_list(12);
        fields(&mut signed);
        signed
            .append(&u64::from(rid.to_byte()))
            .append(&strip(&rs[..32]))
            .append(&strip(&rs[32..]));
        let mut raw = vec![2u8];
        raw.extend_from_slice(&signed.out());
        raw
    }

    fn evm_address_of(key: &k256::ecdsa::SigningKey) -> [u8; 20] {
        use sha3::{Digest, Keccak256};
        let point = key.verifying_key().to_sec1_point(false);
        Keccak256::digest(&point.as_bytes()[1..])[12..]
            .try_into()
            .unwrap()
    }

    /// One ledger: value an EVM wallet sends to a Solana account's EVM alias
    /// lands on that Solana account, and the alias holds nothing of its own.
    #[tokio::test]
    async fn an_evm_transfer_to_a_solana_alias_credits_the_solana_account() {
        use k256::ecdsa::SigningKey;

        let key = SigningKey::from_slice(&[0x43; 32]).unwrap();
        let from = evm_address_of(&key);
        let solana = ed25519_dalek::SigningKey::from_bytes(&[0x25; 32])
            .verifying_key()
            .to_bytes();
        let alias = tenzro_vm::external_tx::svm_evm_alias(&solana);
        let (mut event_loop, genesis) = event_loop_with_genesis(&[
            (tenzro_vm::external_tx::evm_account(from), 1_000),
            (solana, 5),
        ])
        .await;
        let start: u128 = 5 * 10u128.pow(18);
        let value: u128 = 4_000_000_000_000_000;
        let base_fee = tenzro_vm::ledger::block_base_fee(&*event_loop.state_adapter.lock().await);
        let max_fee = base_fee.max(1) * 2;
        {
            let mut st = event_loop.state_adapter.lock().await;
            tenzro_vm::external_tx::record_svm_alias(&mut *st, &solana);
        }

        let (tx, hash) =
            external_evm_envelope(signed_eip1559(&key, max_fee, alias, value), 1337).unwrap();
        let block = block_at(1, genesis, vec![tx]);
        event_loop
            .handle_block_finalized_inner(block, BlockSource::Ordered)
            .await
            .unwrap();
        let receipt = receipt_of(&event_loop, &Hash(hash));
        assert!(receipt.success, "reverted: {:?}", receipt.revert_reason);

        let st = event_loop.state_adapter.lock().await;
        assert_eq!(
            st.get_balance(&solana),
            start + value,
            "the Solana account is credited"
        );
        assert_eq!(
            st.get_balance(&tenzro_vm::external_tx::evm_account(alias)),
            start + value,
            "the alias reads the same account"
        );
        let alias_key = tenzro_vm::state_adapter::tnzo_balance_key(&alias);
        assert!(
            event_loop
                .storage
                .get(tenzro_storage::CF_ACCOUNTS, &alias_key)
                .unwrap()
                .is_none(),
            "no separate balance is kept under the alias"
        );
    }

    /// The header commits the root of the block's Ethereum receipts trie; a
    /// peer's block whose execution does not reproduce it is refused.
    #[tokio::test]
    async fn the_header_commits_the_receipts_root_and_import_checks_it() {
        use k256::ecdsa::SigningKey;
        use tenzro_storage::traits::BlockStore as _;

        let key = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let from = evm_address_of(&key);
        let funded = [(tenzro_vm::external_tx::evm_account(from), 1_000)];
        let (mut ordering, genesis) = event_loop_with_genesis(&funded).await;
        let base_fee = tenzro_vm::ledger::block_base_fee(&*ordering.state_adapter.lock().await);
        let (tx, hash) = external_evm_envelope(
            signed_eip1559(&key, base_fee.max(1) * 2, [0x78; 20], 5),
            1337,
        )
        .unwrap();
        let block = block_at(1, genesis, vec![tx]);
        ordering
            .handle_block_finalized_inner(block.clone(), BlockSource::Ordered)
            .await
            .unwrap();
        let receipt = receipt_of(&ordering, &Hash(hash));
        assert!(receipt.success);
        let executed = BlockStoreImpl::new(ordering.storage.clone())
            .unwrap()
            .get_block_by_height(BlockHeight::from(1))
            .await
            .unwrap()
            .expect("block 1 is stored");
        let expected = tenzro_types::eth_receipt::receipts_root([(
            0,
            tenzro_types::eth_receipt::encode_receipt(
                2,
                true,
                receipt.gas_used,
                std::iter::empty(),
            ),
        )]);
        assert_eq!(executed.header.receipts_root, expected);
        assert_ne!(
            expected,
            Hash::new(tenzro_types::eth_receipt::EMPTY_TRIE_ROOT)
        );

        let (mut importing, _) = event_loop_with_genesis(&funded).await;
        let mut forged = executed.clone();
        forged.header.receipts_root = Hash::new([1; 32]);
        assert!(
            importing
                .handle_block_finalized_inner(forged, BlockSource::Imported)
                .await
                .is_err()
        );
        importing
            .handle_block_finalized_inner(executed, BlockSource::Imported)
            .await
            .unwrap();
    }

    /// A wallet library (ethers, viem) signs an EIP-1559 transfer with a
    /// secp256k1 key the network has never seen. Submitted as raw RLP, it
    /// executes from the recovered sender, the recipient is credited, and the
    /// receipt is found under the keccak256 hash the wallet computed.
    #[tokio::test]
    async fn an_externally_signed_eip1559_transaction_executes_with_its_receipt() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest, Keccak256};

        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let from = evm_address_of(&key);
        let (mut event_loop, genesis) =
            event_loop_with_genesis(&[(tenzro_vm::external_tx::evm_account(from), 1_000)]).await;
        let to = [0x77u8; 20];
        let value: u128 = 3_000_000_000_000_000;
        let base_fee = tenzro_vm::ledger::block_base_fee(&*event_loop.state_adapter.lock().await);
        let max_fee = base_fee.max(1) * 2;

        let raw = signed_eip1559(&key, max_fee, to, value);
        let wallet_hash: [u8; 32] = Keccak256::digest(&raw).into();

        let raw_copy = raw.clone();
        let (tx, hash) = external_evm_envelope(raw, 1337).unwrap();
        assert_eq!(hash, wallet_hash);
        assert_eq!(
            tx.transaction.hash().0,
            wallet_hash,
            "recorded under the wallet's hash"
        );
        assert_eq!(tx.transaction.from.evm_address(), Some(from));
        verify_transaction_signature(&tx).unwrap();

        let block = block_at(1, genesis, vec![tx]);
        event_loop
            .handle_block_finalized_inner(block, BlockSource::Ordered)
            .await
            .unwrap();
        let receipt = receipt_of(&event_loop, &Hash(wallet_hash));
        assert!(receipt.success, "reverted: {:?}", receipt.revert_reason);
        assert!(receipt.gas_used > 0 && receipt.gas_used <= 21_000);
        assert!(u128::from(receipt.effective_gas_price) <= max_fee);
        let st = event_loop.state_adapter.lock().await;
        assert_eq!(
            st.get_balance(&tenzro_vm::external_tx::evm_account(to)),
            value
        );
        assert_eq!(st.get_nonce(&tenzro_vm::external_tx::evm_account(from)), 1);

        // An envelope that names another sender than the one who signed is
        // refused.
        drop(st);
        let (mut forged, _) = external_evm_envelope(raw_copy, 1337).unwrap();
        forged.transaction.from = Address([9u8; 32]);
        assert!(verify_transaction_signature(&forged).is_err());
    }

    /// A Solana wallet (Phantom) signs a System Program transfer with an
    /// Ed25519 key. Submitted in wire format it executes from the fee payer,
    /// the recipient is credited, the receipt is found under the hash of its
    /// signature, and the payer's EVM alias is recorded.
    #[tokio::test]
    async fn a_phantom_signed_solana_transfer_executes() {
        use ed25519_dalek::Signer;

        let payer = ed25519_dalek::SigningKey::from_bytes(&[0x24; 32]);
        let payer_pk = payer.verifying_key().to_bytes();
        let (mut event_loop, genesis) = event_loop_with_genesis(&[(payer_pk, 1_000)]).await;
        let recipient = [0x5au8; 32];
        let lamports: u64 = 2_000_000;

        // Legacy message: header, keys [payer, recipient, system program],
        // recent blockhash, one transfer instruction (discriminant 2).
        let mut msg = vec![1u8, 0, 1, 3];
        msg.extend_from_slice(&payer_pk);
        msg.extend_from_slice(&recipient);
        msg.extend_from_slice(&[0u8; 32]);
        msg.extend_from_slice(&[0xab; 32]);
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&lamports.to_le_bytes());
        msg.extend_from_slice(&[1, 2, 2, 0, 1, data.len() as u8]);
        msg.extend_from_slice(&data);
        let sig = payer.sign(&msg).to_bytes();
        let mut raw = vec![1u8];
        raw.extend_from_slice(&sig);
        raw.extend_from_slice(&msg);

        let (tx, first_sig) = external_svm_envelope(raw, 1337, 0, 1).unwrap();
        assert_eq!(first_sig, sig);
        let hash = tenzro_types::svm_signature_hash(&sig);
        assert_eq!(
            tx.transaction.hash(),
            hash,
            "recorded under the signature's hash"
        );
        verify_transaction_signature(&tx).unwrap();

        let block = block_at(1, genesis, vec![tx]);
        event_loop
            .handle_block_finalized_inner(block, BlockSource::Ordered)
            .await
            .unwrap();
        let receipt = receipt_of(&event_loop, &hash);
        assert!(receipt.success, "reverted: {:?}", receipt.revert_reason);
        let st = event_loop.state_adapter.lock().await;
        assert_eq!(
            tenzro_token::native_to_spl(st.get_balance(&recipient)).unwrap(),
            lamports
        );
        assert_eq!(st.get_nonce(&payer_pk), 1);
        let alias = tenzro_vm::external_tx::svm_evm_alias(&payer_pk);
        assert_eq!(
            tenzro_vm::external_tx::svm_alias_owner(&*st, &alias),
            Some(payer_pk)
        );
    }
}

#[cfg(test)]
mod heartbeat_budget_tests {
    use super::{BLOB_HASHES_PER_TICK, HASHES_PER_ANNOUNCEMENT, MODELS_PER_TICK};

    // The rotation arithmetic is covered in `crate::announce`. These cover the
    // budgets this module hands it, which is the part a later edit is most
    // likely to get wrong — the numbers look arbitrary unless the reasons are
    // written down next to them.

    /// A blob announcement must stay well under gossip's 1 MiB message
    /// ceiling. Each hash is 64 hex characters plus framing, so 512 is about
    /// 34 KiB. A message over the ceiling is not truncated, it is refused, and
    /// those blobs would simply never be announced.
    #[test]
    fn one_announcement_fits_the_transmit_ceiling_with_room_to_spare() {
        let bytes_per_hash = 64 + 8;
        let payload = HASHES_PER_ANNOUNCEMENT * bytes_per_hash;
        assert!(
            payload < 1_048_576 / 4,
            "{payload} bytes is too close to the 1 MiB limit"
        );
    }

    /// The per-tick budget is a whole number of messages, so a tick never ends
    /// mid-chunk and sends a short message every time round.
    #[test]
    fn the_blob_budget_is_a_whole_number_of_messages() {
        assert_eq!(BLOB_HASHES_PER_TICK % HASHES_PER_ANNOUNCEMENT, 0);
    }

    /// **What the budgets are for.** Every tick is bounded, and small enough
    /// that a minute of announcing cannot fill a queue consensus shares. This
    /// replaced ~220 blob messages a minute plus one per model,
    /// all published at the instant of the tick.
    #[test]
    fn a_minute_of_announcing_is_tens_of_messages_not_hundreds() {
        let blob_messages = BLOB_HASHES_PER_TICK / HASHES_PER_ANNOUNCEMENT;
        let worst_case = blob_messages + MODELS_PER_TICK + 1;
        assert!(
            worst_case <= 64,
            "{worst_case} messages a minute is back towards the burst this replaced"
        );
    }
}

#[cfg(test)]
mod announced_tests {
    use super::*;
    use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::Transaction;

    fn transfer(nonce: u64) -> SignedTransaction {
        let tx = Transaction::new(
            ChainId::from(1337),
            Address::new([0x11; 32]),
            Address::new([0xee; 32]),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1 },
            21_000,
            1_000_000_000,
        );
        SignedTransaction::new(
            tx,
            Vec::new(),
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        )
    }

    /// The load stage lost every transaction of a sender from one on: the RPC
    /// node admitted nonce n and published it once, gossip lost it on the way
    /// to every validator, and the RPC node held it in its mempool, counted it
    /// in the pending nonce, and never sent it again; n + 1 and later waited
    /// behind the gap until the run ended. Here the transaction gossip lost
    /// is still in the admitting node's mempool, and is published again, in
    /// nonce order with the sender's later ones, until a block takes it.
    #[test]
    fn a_transaction_gossip_lost_is_published_again_until_a_block_takes_it() {
        let mempool =
            tenzro_consensus::Mempool::new(Arc::new(tenzro_consensus::ConsensusConfig::default()));
        let t0 = Instant::now();
        let mut announced = Announced::default();
        // Nonces 37 and 38 admitted and published once each; 37 is the one
        // gossip lost, which no validator will ever ask for.
        let (lost, next) = (transfer(37), transfer(38));
        for tx in [&next, &lost] {
            mempool.add_transaction(tx.clone()).unwrap();
            announced.published(tx.transaction.hash(), t0);
        }
        assert!(
            due_for_publishing(&mut announced, &mempool, t0 + Duration::from_secs(1)).is_empty()
        );
        let again = due_for_publishing(&mut announced, &mempool, t0 + REANNOUNCE_FIRST);
        let nonces: Vec<u64> = again.iter().map(|t| t.transaction.nonce.0).collect();
        assert_eq!(nonces, vec![37, 38], "both published again, in nonce order");
        // Still not included: published again on the next wait.
        let later = t0 + REANNOUNCE_FIRST * 3;
        assert_eq!(due_for_publishing(&mut announced, &mempool, later).len(), 2);
        // A block takes them: nothing more is published, and they are forgotten.
        mempool.remove_transactions(&[lost.transaction.hash(), next.transaction.hash()]);
        assert!(due_for_publishing(&mut announced, &mempool, t0 + REANNOUNCE_MAX * 10).is_empty());
        assert!(announced.due.is_empty());
    }

    fn h(b: u8) -> Hash {
        Hash::new([b; 32])
    }

    #[test]
    fn a_published_transaction_still_pooled_is_published_again_at_doubling_waits() {
        let t0 = Instant::now();
        let mut a = Announced::default();
        a.published(h(1), t0);
        let pooled = |_: &Hash| true;
        assert!(a.due(t0 + Duration::from_secs(4), 16, pooled).is_empty());
        assert_eq!(a.due(t0 + REANNOUNCE_FIRST, 16, pooled), vec![h(1)]);
        // Published again at 5 s: next at 5 + 10 s, then 15 + 20 s.
        let second = t0 + REANNOUNCE_FIRST + REANNOUNCE_FIRST * 2;
        assert!(
            a.due(second - Duration::from_millis(1), 16, pooled)
                .is_empty()
        );
        assert_eq!(a.due(second, 16, pooled), vec![h(1)]);
        let third = second + REANNOUNCE_FIRST * 4;
        assert!(
            a.due(third - Duration::from_millis(1), 16, pooled)
                .is_empty()
        );
        assert_eq!(a.due(third, 16, pooled), vec![h(1)]);
        // The wait never passes the bound.
        let mut at = third;
        for _ in 0..10 {
            at += REANNOUNCE_MAX;
            assert_eq!(a.due(at, 16, pooled), vec![h(1)]);
        }
    }

    #[test]
    fn a_transaction_the_mempool_let_go_is_forgotten() {
        let t0 = Instant::now();
        let mut a = Announced::default();
        a.published(h(1), t0);
        a.published(h(2), t0);
        let due = a.due(t0 + REANNOUNCE_FIRST, 16, |x| *x == h(2));
        assert_eq!(due, vec![h(2)]);
        assert!(!a.due.contains_key(&h(1)));
        assert!(a.due(t0 + REANNOUNCE_MAX * 4, 16, |_| false).is_empty());
        assert!(a.due.is_empty());
    }

    #[test]
    fn a_backlog_is_published_again_the_longest_waiting_first_a_tick_at_a_time() {
        let t0 = Instant::now();
        let mut a = Announced::default();
        for i in 0..5u8 {
            a.published(h(10 - i), t0 + Duration::from_millis(u64::from(i)));
        }
        let now = t0 + REANNOUNCE_FIRST + Duration::from_secs(1);
        assert_eq!(a.due(now, 2, |_| true), vec![h(10), h(9)]);
        assert_eq!(a.due(now, 2, |_| true), vec![h(8), h(7)]);
        assert_eq!(a.due(now, 2, |_| true), vec![h(6)]);
        assert!(a.due(now, 2, |_| true).is_empty());
    }
}
