//! Verifiable indexing over the chain's events.
//!
//! Every executed block's events are in the durable [`EventLog`] under their
//! cursors, and the block header commits them. This module serves them:
//!
//! - `tenzro_subscribe { filter?, from_cursor?, from_height?, limit?,
//!   wait_ms?, proofs? }`: the next events after a cursor, waiting up to
//!   `wait_ms` for new blocks when none are ready. The answer's `cursor` is
//!   what the caller passes back as `from_cursor`, so a caller that restarts
//!   resumes with no gap and no repeat. Without `from_cursor` or
//!   `from_height` it starts at the current tip.
//! - `tenzro_queryEvents { filter?, from_cursor?, from_height?, to_cursor?,
//!   limit?, anchor_index?, completeness? }`: a page of a historical range,
//!   every event with its proof. With `completeness`, also the proof that
//!   the page left out nothing the filter selects: for every block the page
//!   covered, the block-index entries of the filter's keys, each under the
//!   block's event root (see [`tenzro_types::chain_event::block_index`]).
//!   `tenzro_subscribe` takes `completeness` too.
//! - `tenzro_getEventProof { cursor, anchor_index?, certified? }`: one
//!   event's proof; with `certified`, also the proof from genesis that its
//!   anchor checkpoint is certified.
//! - `tenzro_verifyEventProof { proof }`: checks a proof against a checkpoint
//!   this node holds a certificate for.
//! - `GET /events`: the same stream as server-sent events, each event's id
//!   its cursor, so a reconnecting client resumes from `Last-Event-ID`.
//!
//! Heights below the local retention floor are read back from the data
//! availability layer and verified against their headers before they are
//! served.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tenzro_consensus::Checkpoint;
use tenzro_consensus::event_proof::{
    BlockIndexProof, CertifiedEventProof, CompletenessProof, EventProof, IndexEntryProof,
};
use tenzro_consensus::light_client::GenesisAnchor;
use tenzro_events::log::end_of_height;
use tenzro_events::{EventFilter, EventLog, Page};
use tenzro_storage::BlockStoreImpl;
use tenzro_storage::traits::BlockStore;
use tenzro_types::block::BlockHeader;
use tenzro_types::chain_event::{
    ChainEvent, EventCursor, block_index, event_root, event_tree_leaves,
};
use tenzro_types::merkle::merkle_path;
use tenzro_types::primitives::BlockHeight;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Methods that read the chain's event stream. A delegated agent reaches
/// them only when its terms allow [`SUBSCRIBE_OPERATION`].
pub(crate) const EVENT_METHODS: &[&str] = &[
    "tenzro_subscribe",
    "tenzro_queryEvents",
    "tenzro_getEventProof",
];

/// The operation an agent's terms name to allow reading the event stream.
pub(crate) const SUBSCRIBE_OPERATION: &str = "subscribe_events";

/// Most events one page carries.
pub(crate) const MAX_PAGE: usize = 1_000;
/// Default page size.
const DEFAULT_PAGE: usize = 100;
/// Most heights one page scans.
const MAX_HEIGHTS_PER_PAGE: u64 = 4_096;
/// Most heights a page with a completeness proof scans: the proof carries a
/// header per height.
const MAX_HEIGHTS_PER_COMPLETE_PAGE: u64 = 256;
/// Longest a subscribe call waits for new events.
const MAX_WAIT_MS: u64 = 30_000;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn object(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(mut a)) if !a.is_empty() => a.swap_remove(0),
        Some(v) => v,
        None => Value::Null,
    }
}

fn cursor_param(params: &Value, key: &str) -> Result<Option<EventCursor>, JsonRpcError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|e: String| err(-32602, e)),
        Some(_) => Err(err(
            -32602,
            format!("'{key}' is a cursor string height:tx_index:event_index"),
        )),
    }
}

/// What a read asks for.
#[derive(Debug, Clone)]
pub(crate) struct ReadRequest {
    /// Which events.
    pub filter: EventFilter,
    /// Resume after this cursor; `None` starts at the first held height.
    pub after: Option<EventCursor>,
    /// Stop at this cursor, inclusive.
    pub to: Option<EventCursor>,
    /// Most events.
    pub limit: usize,
    /// Most heights one page scans.
    pub max_heights: u64,
}

impl ReadRequest {
    /// Parses `filter`, `from_cursor`, `from_height`, `to_cursor` and
    /// `limit`. With neither start given, `default_after` decides.
    pub(crate) fn parse(
        params: &Value,
        default_after: Option<EventCursor>,
    ) -> Result<Self, JsonRpcError> {
        let filter = EventFilter::from_json(params.get("filter").unwrap_or(&Value::Null))
            .map_err(|e| err(-32602, format!("filter: {e}")))?;
        let from_cursor = cursor_param(params, "from_cursor")?;
        let from_height = match params.get("from_height") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .ok_or_else(|| err(-32602, "'from_height' must be an unsigned integer"))?,
            ),
        };
        let after = match (from_cursor, from_height) {
            (Some(_), Some(_)) => {
                return Err(err(-32602, "give 'from_cursor' or 'from_height', not both"));
            }
            (Some(c), None) => Some(c),
            (None, Some(0)) => None,
            (None, Some(h)) => Some(end_of_height(h - 1)),
            (None, None) => default_after,
        };
        let limit = match params.get("limit") {
            None | Some(Value::Null) => DEFAULT_PAGE,
            Some(v) => v
                .as_u64()
                .ok_or_else(|| err(-32602, "'limit' must be an unsigned integer"))?
                as usize,
        }
        .clamp(1, MAX_PAGE);
        let max_heights = if completeness_param(params) {
            MAX_HEIGHTS_PER_COMPLETE_PAGE
        } else {
            MAX_HEIGHTS_PER_PAGE
        };
        Ok(Self {
            filter,
            after,
            to: cursor_param(params, "to_cursor")?,
            limit,
            max_heights,
        })
    }
}

fn completeness_param(params: &Value) -> bool {
    params
        .get("completeness")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn log(node: &TenzroNode) -> Result<&Arc<EventLog>, JsonRpcError> {
    node.event_log()
        .ok_or_else(|| err(-32603, "the event log is not open"))
}

fn storage_err(e: impl std::fmt::Display) -> JsonRpcError {
    err(-32603, format!("event log: {e}"))
}

/// The next page of events `req` selects, from the local log, or from the
/// data availability layer for heights below the local floor.
pub(crate) async fn read(node: &TenzroNode, req: &ReadRequest) -> Result<Page, JsonRpcError> {
    read_where(node, req, &|_| true).await
}

/// [`read`], keeping only the events `filter` selects that `also` accepts.
/// The page's `limit` counts kept events, so a narrow predicate still pages
/// with no gap.
pub(crate) async fn read_where(
    node: &TenzroNode,
    req: &ReadRequest,
    also: &(dyn Fn(&ChainEvent) -> bool + Sync),
) -> Result<Page, JsonRpcError> {
    let log = log(node)?;
    let floor = log.floor().map_err(storage_err)?;
    let to = req.to;
    let keep =
        |e: &ChainEvent| req.filter.matches_chain(e) && to.is_none_or(|t| e.cursor <= t) && also(e);
    let start = req.after.map_or(floor, |c| c.height);
    if start >= floor || floor == 0 {
        return log
            .read_after(
                req.after,
                to.map(|t| t.height),
                req.limit,
                req.max_heights,
                &keep,
            )
            .map_err(storage_err);
    }
    let archive = node.history_archive().ok_or_else(|| {
        err(-32004, format!("events below height {floor} are in the data availability layer, which this node cannot read"))
    })?;
    let segment = archive
        .archived(start)
        .await
        .map_err(|e| err(-32603, format!("archived history: {e}")))?
        .ok_or_else(|| err(-32004, format!("no archived segment covers height {start}")))?;
    let mut page = Page {
        events: Vec::new(),
        cursor: req.after,
    };
    for (block, events) in segment.blocks.iter().zip(&segment.events) {
        let height = block.height().0;
        if height < start || to.is_some_and(|t| height > t.height) {
            continue;
        }
        if height >= start.saturating_add(req.max_heights) {
            break;
        }
        for e in events {
            if req.after.is_some_and(|a| e.cursor <= a) || !keep(e) {
                continue;
            }
            if page.events.len() == req.limit {
                return Ok(page);
            }
            page.cursor = Some(e.cursor);
            page.events.push(e.clone());
        }
        page.cursor = Some(end_of_height(height));
    }
    Ok(page)
}

/// A block and its events, from the local stores or the archive.
async fn block_with_events(
    node: &TenzroNode,
    height: u64,
) -> Result<(BlockHeader, Vec<ChainEvent>), JsonRpcError> {
    let log = log(node)?;
    if height >= log.floor().map_err(storage_err)? {
        let storage = node
            .storage()
            .ok_or_else(|| err(-32603, "storage not initialised"))?;
        let block = BlockStoreImpl::new(storage.clone())
            .map_err(storage_err)?
            .get_block_by_height(BlockHeight(height))
            .await
            .map_err(storage_err)?
            .ok_or_else(|| err(-32004, format!("block {height} is not held here")))?;
        return Ok((block.header, log.block(height).map_err(storage_err)?));
    }
    let archive = node.history_archive().ok_or_else(|| {
        err(
            -32004,
            format!(
                "block {height} is in the data availability layer, which this node cannot read"
            ),
        )
    })?;
    let segment = archive
        .archived(height)
        .await
        .map_err(|e| err(-32603, format!("archived history: {e}")))?
        .ok_or_else(|| {
            err(
                -32004,
                format!("no archived segment covers height {height}"),
            )
        })?;
    segment
        .blocks
        .into_iter()
        .zip(segment.events)
        .find(|(b, _)| b.height().0 == height)
        .map(|(b, e)| (b.header, e))
        .ok_or_else(|| {
            err(
                -32004,
                format!("block {height} is missing from its archived segment"),
            )
        })
}

/// Builds proofs for events, sharing each block's and checkpoint's work.
struct Prover<'a> {
    node: &'a TenzroNode,
    anchor_index: Option<u64>,
    blocks: HashMap<u64, (BlockHeader, Vec<ChainEvent>)>,
    checkpoints: HashMap<u64, (Vec<[u8; 32]>, Vec<Checkpoint>)>,
}

impl<'a> Prover<'a> {
    fn new(node: &'a TenzroNode, anchor_index: Option<u64>) -> Self {
        Self {
            node,
            anchor_index,
            blocks: HashMap::new(),
            checkpoints: HashMap::new(),
        }
    }

    async fn block(
        &mut self,
        height: u64,
    ) -> Result<&(BlockHeader, Vec<ChainEvent>), JsonRpcError> {
        if !self.blocks.contains_key(&height) {
            let (header, events) = block_with_events(self.node, height).await?;
            if event_root(&events) != header.event_root {
                return Err(err(
                    -32603,
                    format!("the stored events of block {height} do not match its header"),
                ));
            }
            self.blocks.insert(height, (header, events));
        }
        Ok(&self.blocks[&height])
    }

    /// The block hashes the checkpoint covering `height` commits, and the
    /// checkpoint bodies from it to the anchor.
    async fn checkpoints(
        &mut self,
        height: u64,
    ) -> Result<(Vec<[u8; 32]>, Vec<Checkpoint>), JsonRpcError> {
        let consensus = self
            .node
            .consensus()
            .ok_or_else(|| err(-32004, "this node follows no consensus"))?;
        let covering = consensus.checkpoint_covering(height).ok_or_else(|| {
            err(
                -32004,
                format!("no checkpoint covering height {height} yet"),
            )
        })?;
        if let Some(hit) = self.checkpoints.get(&covering.index) {
            return Ok(hit.clone());
        }
        let latest = consensus
            .latest_certificate()
            .map(|c| c.checkpoint.index)
            .ok_or_else(|| err(-32004, "no certified checkpoint yet"))?;
        let anchor = match self.anchor_index {
            Some(a) if a < covering.index || a > latest => {
                return Err(err(
                    -32602,
                    format!(
                        "anchor checkpoint {a} is not between {} and the latest certified {latest}",
                        covering.index
                    ),
                ));
            }
            Some(a) => a,
            None => (covering.index..=latest)
                .find(|i| consensus.certificate(*i).is_some())
                .unwrap_or(latest),
        };
        let mut chain = Vec::with_capacity((anchor - covering.index + 1) as usize);
        for i in covering.index..=anchor {
            chain.push(
                consensus
                    .checkpoint(i)
                    .ok_or_else(|| err(-32004, format!("checkpoint {i} is not held here")))?,
            );
        }
        let mut hashes = Vec::new();
        for h in covering.first_height..=covering.last_height {
            hashes.push(self.block(h).await?.0.hash().0);
        }
        let out = (hashes, chain);
        self.checkpoints.insert(covering.index, out.clone());
        Ok(out)
    }

    async fn prove(&mut self, event: &ChainEvent) -> Result<EventProof, JsonRpcError> {
        let height = event.cursor.height;
        let (hashes, checkpoints) = self.checkpoints(height).await?;
        let (header, events) = self.block(height).await?.clone();
        let position = events
            .iter()
            .position(|e| e.cursor == event.cursor)
            .ok_or_else(|| err(-32004, format!("no event at {}", event.cursor)))?;
        let leaves = event_tree_leaves(&events);
        let first = checkpoints[0].first_height;
        Ok(EventProof {
            event: events[position].clone(),
            event_path: merkle_path(&leaves, position).expect("position is in range"),
            block_path: merkle_path(&hashes, (height - first) as usize)
                .expect("the checkpoint covers the height"),
            header,
            checkpoints,
        })
    }
}

impl Prover<'_> {
    /// The completeness proof of `page`, the answer to `req`, with every
    /// rejected candidate proven. Needs a single anchor.
    async fn completeness(
        &mut self,
        req: &ReadRequest,
        page: &Page,
        floor: u64,
    ) -> Result<CompletenessProof, JsonRpcError> {
        let keys = req.filter.index_keys();
        let through = page
            .cursor
            .or(req.after)
            .unwrap_or(EventCursor::block_start(floor));
        // A read that ends where it starts covers no block; any other is
        // covered from the block of its `after` cursor, or from the floor.
        let first_height = match req.after {
            Some(a) if a == through => through.height.saturating_add(1),
            Some(a) => a.height,
            None => floor,
        };
        let in_range = |c: &EventCursor| req.after.is_none_or(|a| *c > a) && *c <= through;
        let answered: std::collections::BTreeSet<EventCursor> =
            page.events.iter().map(|e| e.cursor).collect();
        let mut blocks = Vec::new();
        let mut rejected = Vec::new();
        let mut checkpoints = Vec::new();
        for height in first_height..=through.height {
            let (hashes, chain) = self.checkpoints(height).await?;
            if checkpoints.is_empty() {
                checkpoints = chain.clone();
            }
            let (header, events) = self.block(height).await?.clone();
            let index = block_index(&events);
            let leaves = event_tree_leaves(&events);
            let mut entries = Vec::with_capacity(keys.len());
            for key in &keys {
                let at = index
                    .iter()
                    .position(|e| e.covers(key).is_some())
                    .expect("the index chain starts at the empty key and covers every key");
                for c in index[at].covers(key).unwrap_or_default() {
                    if in_range(c) && !answered.contains(c) {
                        rejected.push(*c);
                    }
                }
                entries.push(IndexEntryProof {
                    entry: index[at].clone(),
                    path: merkle_path(&leaves, events.len() + at).expect("the entry is a leaf"),
                });
            }
            blocks.push(BlockIndexProof {
                block_path: merkle_path(&hashes, (height - chain[0].first_height) as usize)
                    .expect("the checkpoint covers the height"),
                header,
                entries,
            });
        }
        rejected.sort();
        rejected.dedup();
        let mut excluded = Vec::with_capacity(rejected.len());
        for c in rejected {
            let (_, events) = self.block(c.height).await?.clone();
            let event = events
                .into_iter()
                .find(|e| e.cursor == c)
                .ok_or_else(|| err(-32603, format!("no event at {c}")))?;
            excluded.push(self.prove(&event).await?);
        }
        Ok(CompletenessProof {
            keys: keys.iter().map(hex::encode).collect(),
            first_height,
            after: req.after,
            through,
            blocks,
            checkpoints,
            excluded,
        })
    }
}

/// The latest certified checkpoint: the one anchor every proof of a page
/// with a completeness proof ends at.
fn latest_anchor(node: &TenzroNode) -> Result<u64, JsonRpcError> {
    node.consensus()
        .and_then(|c| c.latest_certificate())
        .map(|c| c.checkpoint.index)
        .ok_or_else(|| err(-32004, "no certified checkpoint yet"))
}

/// `page`'s event proofs and its completeness proof, all anchored at
/// `anchor_index`, or at the latest certified checkpoint.
pub(crate) async fn prove_complete(
    node: &TenzroNode,
    req: &ReadRequest,
    page: &Page,
    anchor_index: Option<u64>,
) -> Result<(Vec<EventProof>, CompletenessProof), JsonRpcError> {
    let floor = log(node)?.floor().map_err(storage_err)?;
    let anchor = match anchor_index {
        Some(a) => a,
        None => latest_anchor(node)?,
    };
    let mut prover = Prover::new(node, Some(anchor));
    let mut proofs = Vec::with_capacity(page.events.len());
    for e in &page.events {
        proofs.push(prover.prove(e).await?);
    }
    let completeness = prover.completeness(req, page, floor).await?;
    Ok((proofs, completeness))
}

/// Proofs for `events`, anchored at `anchor_index` or at the nearest
/// checkpoint at or after each covering one whose certificate is held.
pub(crate) async fn prove(
    node: &TenzroNode,
    events: &[ChainEvent],
    anchor_index: Option<u64>,
) -> Result<Vec<EventProof>, JsonRpcError> {
    let mut prover = Prover::new(node, anchor_index);
    let mut out = Vec::with_capacity(events.len());
    for e in events {
        out.push(prover.prove(e).await?);
    }
    Ok(out)
}

pub(crate) fn anchor_param(params: &Value) -> Result<Option<u64>, JsonRpcError> {
    match params.get("anchor_index") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| err(-32602, "'anchor_index' must be an unsigned integer")),
    }
}

fn page_json(
    page: &Page,
    proofs: Option<Vec<EventProof>>,
    completeness: Option<CompletenessProof>,
    tip: Option<u64>,
) -> Value {
    let events: Vec<Value> = match proofs {
        Some(proofs) => proofs
            .into_iter()
            .map(|p| json!({ "event": p.event, "proof": p }))
            .collect(),
        None => page.events.iter().map(|e| json!({ "event": e })).collect(),
    };
    let mut out = json!({
        "events": events,
        "cursor": page.cursor.map(|c| c.to_string()),
        "tip": tip,
    });
    if let Some(c) = completeness {
        out["completeness"] = json!(c);
    }
    out
}

/// A page's proofs as `params` asks: none, every event's, or every event's
/// and the page's completeness.
async fn page_proofs(
    node: &TenzroNode,
    params: &Value,
    req: &ReadRequest,
    page: &Page,
    proofs: bool,
) -> Result<(Option<Vec<EventProof>>, Option<CompletenessProof>), JsonRpcError> {
    if completeness_param(params) {
        let (p, c) = prove_complete(node, req, page, anchor_param(params)?).await?;
        return Ok((Some(p), Some(c)));
    }
    if proofs {
        return Ok((
            Some(prove(node, &page.events, anchor_param(params)?).await?),
            None,
        ));
    }
    Ok((None, None))
}

/// `tenzro_subscribe`.
pub(crate) async fn subscribe(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object(params);
    let log = log(node)?.clone();
    let req = ReadRequest::parse(&params, log.tip().map(end_of_height))?;
    let wait_ms = params
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(MAX_WAIT_MS);
    let proofs = params
        .get("proofs")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut tip_rx = log.watch_tip();
    let mut page = read(node, &req).await?;
    // Wait only once caught up: an empty page that moved the cursor means
    // more heights remain to scan, and the caller should come straight back.
    if wait_ms > 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms);
        while page.events.is_empty()
            && page.cursor == req.after
            && tokio::time::timeout_at(deadline, tip_rx.changed())
                .await
                .is_ok_and(|r| r.is_ok())
        {
            page = read(node, &req).await?;
        }
    }
    let (proofs, completeness) = page_proofs(node, &params, &req, &page, proofs).await?;
    Ok(page_json(&page, proofs, completeness, log.tip()))
}

/// `tenzro_queryEvents`.
pub(crate) async fn query(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object(params);
    let req = ReadRequest::parse(&params, None)?;
    let page = read(node, &req).await?;
    let (proofs, completeness) = page_proofs(node, &params, &req, &page, true).await?;
    Ok(page_json(&page, proofs, completeness, log(node)?.tip()))
}

/// `tenzro_getEventProof`.
pub(crate) async fn get_proof(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object(params);
    let cursor =
        cursor_param(&params, "cursor")?.ok_or_else(|| err(-32602, "'cursor' is required"))?;
    let (_, events) = block_with_events(node, cursor.height).await?;
    let event = events
        .into_iter()
        .find(|e| e.cursor == cursor)
        .ok_or_else(|| err(-32004, format!("no event at {cursor}")))?;
    let proof = prove(node, std::slice::from_ref(&event), anchor_param(&params)?)
        .await?
        .remove(0);
    if !params
        .get("certified")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({ "proof": proof }));
    }
    let anchor = proof.anchor().expect("a built proof has an anchor").index;
    let certification = node.certification(anchor).ok_or_else(|| {
        err(
            -32004,
            format!("the certification of checkpoint {anchor} is not held here"),
        )
    })?;
    Ok(json!({ "certified_proof": CertifiedEventProof { proof, certification } }))
}

/// The genesis anchor this node follows, from its own consensus state.
fn genesis_anchor(node: &TenzroNode) -> Result<GenesisAnchor, JsonRpcError> {
    let consensus = node
        .consensus()
        .ok_or_else(|| err(-32004, "this node follows no consensus"))?;
    let latest = consensus
        .latest_certificate()
        .ok_or_else(|| err(-32004, "no certified checkpoint yet"))?;
    let genesis = consensus
        .committee_of(0)
        .ok_or_else(|| err(-32004, "the genesis committee is not known here"))?;
    Ok(GenesisAnchor {
        chain_id: latest.checkpoint.chain_id,
        genesis_hash: latest.checkpoint.genesis_hash,
        committee_root: genesis.root(),
    })
}

/// Checks `proof` against the certification this node holds for its anchor.
pub(crate) fn verify_proof(node: &TenzroNode, proof: &EventProof) -> Result<(), String> {
    let anchor = proof.anchor().ok_or("the proof has no checkpoint")?;
    let certification = node
        .certification(anchor.index)
        .ok_or_else(|| format!("checkpoint {} is not certified here", anchor.index))?;
    let genesis = genesis_anchor(node).map_err(|e| e.message)?;
    let certified =
        crate::proof_log::verify_certification(&certification, &genesis, node.handover_program())?;
    proof.verify(&certified).map_err(|e| e.to_string())
}

/// `tenzro_verifyEventProof`.
pub(crate) async fn verify(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object(params);
    let outcome = if let Some(p) = params.get("certified_proof") {
        let proof: CertifiedEventProof = serde_json::from_value(p.clone())
            .map_err(|e| err(-32602, format!("certified_proof: {e}")))?;
        let genesis = genesis_anchor(node)?;
        proof
            .verify(
                &genesis,
                node.handover_program(),
                tenzro_zk::handover_chain::verify_receipt,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    } else {
        let proof: EventProof =
            serde_json::from_value(params.get("proof").cloned().unwrap_or(Value::Null))
                .map_err(|e| err(-32602, format!("proof: {e}")))?;
        verify_proof(node, &proof)
    };
    Ok(match outcome {
        Ok(()) => json!({ "valid": true }),
        Err(e) => json!({ "valid": false, "error": e }),
    })
}

/// A reader of this node's live events, as the HTTP request presents it.
struct HttpReader<'a> {
    node: &'a TenzroNode,
    on_node: bool,
    caller: Option<&'a str>,
}

impl tenzro_events::StreamReader for HttpReader<'_> {
    fn on_node(&self) -> bool {
        self.on_node
    }

    fn visibility_of(&self, resource: &tenzro_events::EventResource) -> tenzro_types::Visibility {
        match resource {
            tenzro_events::EventResource::Model(id) => self
                .node
                .model_visibility(id)
                .unwrap_or_else(|| self.node.visibility()),
        }
    }

    fn admitted_to(&self, _resource: &tenzro_events::EventResource) -> bool {
        let caller = crate::access::Caller {
            did: self.caller.map(str::to_string),
            ip: None,
        };
        matches!(
            crate::access::evaluate(
                self.node,
                &self.node.access().policy(),
                &caller,
                tenzro_types::node_access::Surface::Rpc,
                tenzro_types::node_access::MethodClass::Inference,
            ),
            crate::access::Decision::Allow { named: true, .. }
        )
    }
}

/// `GET /events/node`: this node's live events as server-sent events. An
/// event about a model reaches an off-node reader only when the model is
/// public, or gated and the access policy admits the reader by name; a private resource's
/// events reach only readers on the node.
pub(crate) async fn node_sse(
    State(node): State<Arc<TenzroNode>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // On the node: a loopback peer that no proxy forwarded for.
    let on_node = peer.ip().is_loopback()
        && !headers.contains_key("x-forwarded-for")
        && !headers.contains_key("forwarded");
    let caller = crate::rpc::current_caller_did();
    let mut rx = node.event_bus.subscribe();
    let stream = async_stream::stream! {
        loop {
            let envelope = match rx.recv().await {
                Ok(e) => e,
                Err(tenzro_events::EventBusError::Lagged(n)) => {
                    yield Ok::<_, std::convert::Infallible>(SseEvent::default().event("lagged").data(n.to_string()));
                    continue;
                }
                Err(_) => break,
            };
            let reader = HttpReader { node: &node, on_node, caller: caller.as_deref() };
            if !tenzro_events::delivers(&envelope.event, &reader) {
                continue;
            }
            let data = serde_json::to_string(&*envelope).expect("event envelopes encode as JSON");
            yield Ok(SseEvent::default().id(envelope.sequence.to_string()).event("node_event").data(data));
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Query string of `GET /events`.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SseParams {
    /// Filter, as the JSON wire form.
    filter: Option<String>,
    /// Resume after this cursor.
    from_cursor: Option<String>,
    /// Start at this height.
    from_height: Option<u64>,
}

/// `GET /events`: the event stream as server-sent events.
pub(crate) async fn sse(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    Query(q): Query<SseParams>,
) -> Response {
    let refuse = |status: axum::http::StatusCode, msg: String| {
        (status, axum::Json(json!({ "error": msg }))).into_response()
    };
    let filter: Value = match q.filter.as_deref().map(serde_json::from_str).transpose() {
        Ok(f) => f.unwrap_or(Value::Null),
        Err(e) => return refuse(axum::http::StatusCode::BAD_REQUEST, format!("filter: {e}")),
    };
    let resume = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut params = json!({ "filter": filter });
    match (resume.or(q.from_cursor), q.from_height) {
        (Some(c), _) => params["from_cursor"] = json!(c),
        (None, Some(h)) => params["from_height"] = json!(h),
        (None, None) => {}
    }
    // The stream passes the same access policy, agent terms included, as the
    // `tenzro_subscribe` call it streams.
    let caller = crate::access::Caller {
        did: crate::rpc::current_caller_did(),
        ip: None,
    };
    if let Err(e) = crate::access::admit(
        &node,
        tenzro_types::node_access::Surface::Rpc,
        "tenzro_subscribe",
        Some(&params),
        caller,
    ) {
        return refuse(axum::http::StatusCode::FORBIDDEN, e.message);
    }
    let Ok(log) = log(&node).cloned() else {
        return refuse(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the event log is not open".into(),
        );
    };
    let req = match ReadRequest::parse(&params, log.tip().map(end_of_height)) {
        Ok(r) => r,
        Err(e) => return refuse(axum::http::StatusCode::BAD_REQUEST, e.message),
    };
    let stream = async_stream::stream! {
        let mut tip_rx = log.watch_tip();
        let mut req = req;
        loop {
            let page = match read(&node, &req).await {
                Ok(p) => p,
                Err(e) => {
                    yield Ok::<_, std::convert::Infallible>(SseEvent::default().event("error").data(e.message));
                    break;
                }
            };
            for e in &page.events {
                let data = serde_json::to_string(e).expect("chain events encode as JSON");
                yield Ok(SseEvent::default().id(e.cursor.to_string()).event("chain_event").data(data));
            }
            let advanced = page.cursor != req.after;
            req.after = page.cursor;
            if page.events.is_empty() && !advanced && tip_rx.changed().await.is_err() {
                break;
            }
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::chain_event::{ChainEventKind, Projection, transaction_events};
    use tenzro_types::primitives::Hash;

    #[test]
    fn an_answer_is_its_projection_of_the_proven_events() {
        let topics = [vec![1u8; 32]];
        let logs = [(&[2u8; 20][..], &topics[..], &b"d"[..])];
        let events = transaction_events(9, 0, Hash::new([4; 32]), true, 1, None, logs);
        assert!(matches!(events[1].kind, ChainEventKind::Log { .. }));
        assert_eq!(Projection::Count.apply(&events), json!(2));
        let latest = Projection::LatestPerAddress.apply(&events);
        assert_eq!(latest.as_object().unwrap().len(), 1);
        assert!(latest.get(hex::encode([2u8; 20])).is_some());
    }
}
