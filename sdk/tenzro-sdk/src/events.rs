//! The chain's events: follow them from a cursor, query ranges with proofs,
//! verify proofs against a certified checkpoint.
//!
//! Every block header commits the events its execution emitted, and every
//! checkpoint certificate commits the block headers it covers. An event's
//! proof links its leaf to the header's event root, the header to the
//! covering checkpoint's blocks root, and that checkpoint through the
//! following checkpoint bodies to a certified one. [`verify_event_proof`]
//! checks all of it against the digest of a checkpoint the caller already
//! holds as certified (from a light client); it trusts nothing the node says.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

/// Event client for following, querying and proving the chain's events
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let events = client.events();
/// let filter = serde_json::json!({ "event_types": ["log"] });
/// let mut cursor = None;
/// loop {
///     let page = events.subscribe(&filter, cursor.as_deref(), 20_000, false).await?;
///     for e in &page.events {
///         println!("{}", e["event"]);
///     }
///     cursor = page.cursor.or(cursor);
/// }
/// # }
/// ```
#[derive(Clone)]
pub struct EventClient {
    rpc: Arc<RpcClient>,
}

impl EventClient {
    /// Creates a new event client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The next events `filter` selects after `from_cursor` (from the tip
    /// when `None`), waiting up to `wait_ms` for new blocks. Keep the
    /// returned cursor and pass it back: a reader that restarts resumes with
    /// no gap and no repeat. With `proofs`, each event carries the proof a
    /// receiver checks with [`verify_event_proof`].
    pub async fn subscribe(
        &self,
        filter: &Value,
        from_cursor: Option<&str>,
        wait_ms: u64,
        proofs: bool,
    ) -> SdkResult<EventPage> {
        let mut params =
            serde_json::json!({ "filter": filter, "wait_ms": wait_ms, "proofs": proofs });
        if let Some(c) = from_cursor {
            params["from_cursor"] = Value::from(c);
        }
        self.rpc.call("tenzro_subscribe", params).await
    }

    /// A page of the events `filter` selects after `from_cursor` (from the
    /// first held height when `None`) up to `to_cursor`, each with its proof.
    /// With `completeness`, also the proof that the page left nothing out
    /// (check it with [`verify_completeness`]), every proof anchored at
    /// `anchor_index` or at the latest certified checkpoint.
    pub async fn query(
        &self,
        filter: &Value,
        from_cursor: Option<&str>,
        to_cursor: Option<&str>,
        limit: u32,
        completeness: bool,
        anchor_index: Option<u64>,
    ) -> SdkResult<EventPage> {
        let mut params =
            serde_json::json!({ "filter": filter, "limit": limit, "completeness": completeness });
        if let Some(a) = anchor_index {
            params["anchor_index"] = Value::from(a);
        }
        if let Some(c) = from_cursor {
            params["from_cursor"] = Value::from(c);
        }
        if let Some(c) = to_cursor {
            params["to_cursor"] = Value::from(c);
        }
        self.rpc.call("tenzro_queryEvents", params).await
    }

    /// The proof of the event at `cursor`, anchored at checkpoint
    /// `anchor_index` (a checkpoint the caller holds as certified) or at the
    /// nearest certified one.
    pub async fn proof(&self, cursor: &str, anchor_index: Option<u64>) -> SdkResult<Value> {
        let mut params = serde_json::json!({ "cursor": cursor });
        if let Some(a) = anchor_index {
            params["anchor_index"] = Value::from(a);
        }
        let out: Value = self.rpc.call("tenzro_getEventProof", params).await?;
        Ok(out["proof"].clone())
    }
}

/// A page of events, as `tenzro_subscribe` and `tenzro_queryEvents` return it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPage {
    /// Each entry holds `event`, and `proof` when proofs were asked for.
    pub events: Vec<Value>,
    /// The cursor to resume after.
    pub cursor: Option<String>,
    /// The highest height whose events the node holds.
    pub tip: Option<u64>,
    /// The proof that the page left nothing out, when asked for.
    #[serde(default)]
    pub completeness: Option<Value>,
}

// ---------------------------------------------------------------------------
// Proof verification
// ---------------------------------------------------------------------------

fn bad(msg: impl Into<String>) -> SdkError {
    SdkError::InvalidParameter(format!("event proof: {}", msg.into()))
}

fn bytes(v: &Value, what: &str) -> SdkResult<Vec<u8>> {
    v.as_array()
        .ok_or_else(|| bad(format!("{what} is not a byte array")))?
        .iter()
        .map(|b| b.as_u64().filter(|b| *b <= 255).map(|b| b as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| bad(format!("{what} holds a value that is not a byte")))
}

fn bytes32(v: &Value, what: &str) -> SdkResult<[u8; 32]> {
    bytes(v, what)?
        .try_into()
        .map_err(|_| bad(format!("{what} is not 32 bytes")))
}

fn uint(v: &Value, what: &str) -> SdkResult<u64> {
    v.as_u64()
        .ok_or_else(|| bad(format!("{what} is not an unsigned integer")))
}

fn hash_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0u8]);
    h.update(leaf);
    h.finalize().into()
}

fn hash_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// The root `leaf` reaches along an inclusion path.
fn root_from_path(leaf: &[u8; 32], path: &Value) -> SdkResult<[u8; 32]> {
    let mut acc = hash_leaf(leaf);
    for step in path.as_array().ok_or_else(|| bad("a path is not a list"))? {
        let sibling = bytes32(&step["sibling"], "a path sibling")?;
        acc = if step["left"]
            .as_bool()
            .ok_or_else(|| bad("a path step has no side"))?
        {
            hash_pair(&sibling, &acc)
        } else {
            hash_pair(&acc, &sibling)
        };
    }
    Ok(acc)
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// The leaf of an event in its block's event tree.
fn event_leaf(e: &Value) -> SdkResult<[u8; 32]> {
    let c = &e["cursor"];
    let mut out = b"tenzro/chain-event/leaf".to_vec();
    out.extend_from_slice(&uint(&c["height"], "height")?.to_le_bytes());
    out.extend_from_slice(&(uint(&c["tx_index"], "tx_index")? as u32).to_le_bytes());
    out.extend_from_slice(&(uint(&c["event_index"], "event_index")? as u32).to_le_bytes());
    out.extend_from_slice(&bytes32(&e["tx_hash"], "tx_hash")?);
    match e["kind"].as_str() {
        Some("tx_outcome") => {
            out.push(0);
            out.push(u8::from(
                e["success"]
                    .as_bool()
                    .ok_or_else(|| bad("success is not a boolean"))?,
            ));
            out.extend_from_slice(&uint(&e["gas_used"], "gas_used")?.to_le_bytes());
            match &e["contract_address"] {
                Value::Null => out.push(0),
                a => {
                    out.push(1);
                    put_bytes(&mut out, &bytes(a, "contract_address")?);
                }
            }
        }
        Some("log") => {
            out.push(1);
            put_bytes(&mut out, &bytes(&e["address"], "address")?);
            let topics = e["topics"]
                .as_array()
                .ok_or_else(|| bad("topics is not a list"))?;
            out.extend_from_slice(&(topics.len() as u32).to_le_bytes());
            for t in topics {
                put_bytes(&mut out, &bytes(t, "a topic")?);
            }
            put_bytes(&mut out, &bytes(&e["data"], "data")?);
        }
        _ => return Err(bad("unknown event kind")),
    }
    Ok(*blake3::hash(&out).as_bytes())
}

/// The hash of a block header, as the chain computes it.
fn header_hash(h: &Value) -> SdkResult<[u8; 32]> {
    let m = &h["metadata"];
    let mut s = Sha256::new();
    s.update(uint(&h["height"], "height")?.to_le_bytes());
    s.update(uint(&h["epoch"], "epoch")?.to_le_bytes());
    s.update(uint(&h["round"], "round")?.to_le_bytes());
    for field in [
        "anchor",
        "prev_hash",
        "tx_root",
        "state_root",
        "event_root",
        "receipts_root",
    ] {
        s.update(bytes32(&h[field], field)?);
    }
    let bloom = h["logs_bloom"]
        .as_str()
        .and_then(|b| hex::decode(b).ok())
        .filter(|b| b.len() == 256)
        .ok_or_else(|| bad("logs_bloom is not 256 hex bytes"))?;
    s.update(&bloom);
    s.update(
        h["timestamp"]
            .as_i64()
            .ok_or_else(|| bad("timestamp is not an integer"))?
            .to_le_bytes(),
    );
    s.update(bytes32(&h["proposer"], "proposer")?);
    s.update(uint(&m["gas_used"], "gas_used")?.to_le_bytes());
    s.update(uint(&m["gas_limit"], "gas_limit")?.to_le_bytes());
    s.update(uint(&m["tx_count"], "tx_count")?.to_le_bytes());
    s.update(uint(&m["protocol_version"], "protocol_version")?.to_le_bytes());
    match &m["base_fee_per_gas"] {
        Value::Null => s.update([0u8]),
        fee => {
            s.update([1u8]);
            s.update(u128::from(uint(fee, "base_fee_per_gas")?).to_le_bytes());
        }
    }
    Ok(s.finalize().into())
}

/// A checkpoint body as the chain encodes it, field for field.
#[derive(Serialize)]
struct CheckpointBody {
    chain_id: u64,
    genesis_hash: [u8; 32],
    epoch: u64,
    index: u64,
    prev: [u8; 32],
    first_height: u64,
    last_height: u64,
    blocks_root: [u8; 32],
    state_height: u64,
    state_root: [u8; 32],
    statement_root: [u8; 32],
    next_committee_root: Option<[u8; 32]>,
    anchor_round: u64,
    timestamp_ms: u64,
    ordering_root: [u8; 32],
}

/// The digest a checkpoint certificate signs, from the checkpoint's JSON.
pub fn checkpoint_digest(cp: &Value) -> SdkResult<[u8; 32]> {
    let body = CheckpointBody {
        chain_id: uint(&cp["chain_id"], "chain_id")?,
        genesis_hash: bytes32(&cp["genesis_hash"], "genesis_hash")?,
        epoch: uint(&cp["epoch"], "epoch")?,
        index: uint(&cp["index"], "index")?,
        prev: bytes32(&cp["prev"], "prev")?,
        first_height: uint(&cp["first_height"], "first_height")?,
        last_height: uint(&cp["last_height"], "last_height")?,
        blocks_root: bytes32(&cp["blocks_root"], "blocks_root")?,
        state_height: uint(&cp["state_height"], "state_height")?,
        state_root: bytes32(&cp["state_root"], "state_root")?,
        statement_root: bytes32(&cp["statement_root"], "statement_root")?,
        next_committee_root: match &cp["next_committee_root"] {
            Value::Null => None,
            v => Some(bytes32(v, "next_committee_root")?),
        },
        anchor_round: uint(&cp["anchor_round"], "anchor_round")?,
        timestamp_ms: uint(&cp["timestamp_ms"], "timestamp_ms")?,
        ordering_root: bytes32(&cp["ordering_root"], "ordering_root")?,
    };
    let mut h = blake3::Hasher::new();
    h.update(b"tenzro/consensus/checkpoint/body");
    h.update(&bincode::serialize(&body).map_err(|e| bad(e.to_string()))?);
    Ok(h.finalize().into())
}

/// Checks an event proof (as `tenzro_getEventProof` or `tenzro_queryEvents`
/// returns it) against the digest of a checkpoint the caller holds as
/// certified: the event under its header's event root, the header under the
/// covering checkpoint's blocks root, and each checkpoint the predecessor of
/// the next, ending at the certified one.
pub fn verify_event_proof(proof: &Value, certified_checkpoint_digest: &[u8; 32]) -> SdkResult<()> {
    let event = &proof["event"];
    let header = &proof["header"];
    let height = uint(&header["height"], "header height")?;
    if uint(&event["cursor"]["height"], "event height")? != height {
        return Err(bad("the event and the header are at different heights"));
    }
    if root_from_path(&event_leaf(event)?, &proof["event_path"])?
        != bytes32(&header["event_root"], "event_root")?
    {
        return Err(bad("the event is not under the header's event root"));
    }
    let cps = proof["checkpoints"]
        .as_array()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| bad("no checkpoint"))?;
    let covering = &cps[0];
    if height < uint(&covering["first_height"], "first_height")?
        || height > uint(&covering["last_height"], "last_height")?
    {
        return Err(bad("the first checkpoint does not cover the block"));
    }
    if root_from_path(&header_hash(header)?, &proof["block_path"])?
        != bytes32(&covering["blocks_root"], "blocks_root")?
    {
        return Err(bad("the header is not under the checkpoint's blocks root"));
    }
    let mut digest = checkpoint_digest(covering)?;
    for pair in cps.windows(2) {
        if bytes32(&pair[1]["prev"], "prev")? != digest
            || uint(&pair[1]["index"], "index")? != uint(&pair[0]["index"], "index")? + 1
        {
            return Err(bad("a checkpoint does not follow its predecessor"));
        }
        digest = checkpoint_digest(&pair[1])?;
    }
    if &digest != certified_checkpoint_digest {
        return Err(bad("the proof does not end at the certified checkpoint"));
    }
    Ok(())
}

/// Checks a paid index's answer: every proof against the certified
/// checkpoint, and the answer as the projection of exactly the proven events.
pub fn verify_index_answer(
    answer: &Value,
    certified_checkpoint_digest: &[u8; 32],
) -> SdkResult<()> {
    let proofs = answer["proofs"]
        .as_array()
        .ok_or_else(|| bad("the answer has no proofs"))?;
    let mut events = Vec::with_capacity(proofs.len());
    for p in proofs {
        verify_event_proof(p, certified_checkpoint_digest)?;
        events.push(p["event"].clone());
    }
    let key = |e: &Value| -> SdkResult<(u64, u64, u64)> {
        let c = &e["cursor"];
        Ok((
            uint(&c["height"], "height")?,
            uint(&c["tx_index"], "tx_index")?,
            uint(&c["event_index"], "event_index")?,
        ))
    };
    for w in events.windows(2) {
        if key(&w[0])? >= key(&w[1])? {
            return Err(bad("the answer's events are not in cursor order"));
        }
    }
    let expected = match answer["projection"].as_str() {
        Some("events") => Value::Array(events),
        Some("count") => Value::from(events.len()),
        Some("latest_per_address") => {
            let mut latest = serde_json::Map::new();
            for e in events.into_iter().filter(|e| e["kind"] == "log") {
                latest.insert(hex::encode(bytes(&e["address"], "address")?), e);
            }
            Value::Object(latest)
        }
        _ => return Err(bad("unknown projection")),
    };
    if expected != answer["result"] {
        return Err(bad("the answer is not the projection of its proven events"));
    }
    Ok(())
}

/// The block-index keys (hex) a filter's completeness proof covers, as the
/// node derives them from the filter's JSON wire form.
pub fn filter_index_keys(filter: &Value) -> SdkResult<Vec<String>> {
    if filter["vm_types"].as_array().is_some_and(|v| !v.is_empty()) {
        return Ok(Vec::new());
    }
    let types: Vec<&str> = filter["event_types"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let addresses = filter_addresses(filter)?;
    let topics = filter_topics(filter)?;
    let mut keys = Vec::new();
    if (types.is_empty() || types.contains(&"transaction_included"))
        && addresses.is_empty()
        && topics.is_empty()
    {
        keys.push("6b00".to_string());
    }
    if types.is_empty() || types.contains(&"log") {
        if !addresses.is_empty() {
            keys.extend(addresses.iter().map(|a| format!("61{a}")));
        } else if let Some((position, any)) = topics
            .iter()
            .enumerate()
            .find_map(|(i, s)| s.as_ref().map(|a| (i, a)))
        {
            keys.extend(any.iter().map(|t| format!("74{position:02x}{t}")));
        } else {
            keys.push("6b01".to_string());
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn hex_of_len(v: &Value, len: usize, what: &str) -> SdkResult<String> {
    let h = v
        .as_str()
        .ok_or_else(|| bad(format!("{what} is not a string")))?
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    if h.len() != 2 * len || hex::decode(&h).is_err() {
        return Err(bad(format!("{what} must be {len} bytes of hex")));
    }
    Ok(h)
}

fn filter_addresses(filter: &Value) -> SdkResult<Vec<String>> {
    filter["addresses"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| hex_of_len(a, 20, "an address"))
        .collect()
}

fn filter_topics(filter: &Value) -> SdkResult<Vec<Option<Vec<String>>>> {
    filter["topics"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|slot| match slot {
            Value::Null => Ok(None),
            Value::Array(any) => any
                .iter()
                .map(|t| hex_of_len(t, 32, "a topic"))
                .collect::<SdkResult<_>>()
                .map(Some),
            one => hex_of_len(one, 32, "a topic").map(|t| Some(vec![t])),
        })
        .collect()
}

/// Whether `filter` (its JSON wire form) selects `event`, as the node
/// decides it.
pub fn filter_selects(filter: &Value, event: &Value) -> SdkResult<bool> {
    let height = uint(&event["cursor"]["height"], "height")?;
    if filter["from_block"].as_u64().is_some_and(|f| height < f)
        || filter["to_block"].as_u64().is_some_and(|t| height > t)
    {
        return Ok(false);
    }
    if filter["vm_types"].as_array().is_some_and(|v| !v.is_empty()) {
        return Ok(false);
    }
    let types: Vec<&str> = filter["event_types"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let addresses = filter_addresses(filter)?;
    let topics = filter_topics(filter)?;
    let is_log = event["kind"] == "log";
    if !types.is_empty()
        && !types.contains(&if is_log {
            "log"
        } else {
            "transaction_included"
        })
    {
        return Ok(false);
    }
    if !is_log {
        return Ok(addresses.is_empty() && topics.is_empty());
    }
    let address = bytes(&event["address"], "address")?;
    let tail = hex::encode(if address.len() == 32 {
        &address[12..]
    } else {
        &address[..]
    });
    if !addresses.is_empty() && !addresses.contains(&tail) {
        return Ok(false);
    }
    if topics.is_empty() {
        return Ok(true);
    }
    let have: Vec<String> = event["topics"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| bytes(t, "topic").map(hex::encode))
        .collect::<SdkResult<_>>()?;
    if have.iter().any(|t| t.len() != 64) {
        return Ok(false);
    }
    Ok(topics.iter().enumerate().all(|(i, slot)| {
        slot.as_ref()
            .is_none_or(|any| have.get(i).is_some_and(|t| any.contains(t)))
    }))
}

fn cursor_of(c: &Value) -> SdkResult<(u64, u64, u64)> {
    Ok((
        uint(&c["height"], "height")?,
        uint(&c["tx_index"], "tx_index")?,
        uint(&c["event_index"], "event_index")?,
    ))
}

fn index_leaf(entry: &Value) -> SdkResult<[u8; 32]> {
    let key = hex::decode(
        entry["key"]
            .as_str()
            .ok_or_else(|| bad("an index key is missing"))?,
    )
    .map_err(|_| bad("an index key is not hex"))?;
    let mut out = b"tenzro/chain-event/index".to_vec();
    put_bytes(&mut out, &key);
    match entry["next"].as_str() {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            put_bytes(
                &mut out,
                &hex::decode(n).map_err(|_| bad("a next key is not hex"))?,
            );
        }
    }
    let cursors = entry["cursors"]
        .as_array()
        .ok_or_else(|| bad("an index entry has no cursors"))?;
    out.extend_from_slice(&(cursors.len() as u32).to_le_bytes());
    for c in cursors {
        let (h, t, e) = cursor_of(c)?;
        out.extend_from_slice(&h.to_be_bytes());
        out.extend_from_slice(&(t as u32).to_be_bytes());
        out.extend_from_slice(&(e as u32).to_be_bytes());
    }
    Ok(*blake3::hash(&out).as_bytes())
}

/// Checks that `answer` (the page's events, whose own proofs the caller
/// checked) is every event the filter selects in the completeness proof's
/// range: the block-index entries of every covered block are under
/// certified headers, and every candidate they list is answered or proven
/// rejected. `keys` are [`filter_index_keys`] of the filter, `selects`
/// [`filter_selects`].
pub fn verify_completeness(
    proof: &Value,
    certified_checkpoint_digest: &[u8; 32],
    keys: &[String],
    answer: &[Value],
    selects: &dyn Fn(&Value) -> SdkResult<bool>,
) -> SdkResult<()> {
    let proof_keys: Vec<&str> = proof["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if proof_keys != keys.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(bad(
            "the proof covers other index keys than the filter needs",
        ));
    }
    let first = uint(&proof["first_height"], "first_height")?;
    let through = cursor_of(&proof["through"])?;
    let after = if proof["after"].is_null() {
        None
    } else {
        Some(cursor_of(&proof["after"])?)
    };
    let blocks = proof["blocks"]
        .as_array()
        .ok_or_else(|| bad("no block proofs"))?;
    let span = if through.0 >= first {
        through.0 - first + 1
    } else {
        0
    };
    if blocks.len() as u64 != span {
        return Err(bad(format!(
            "{} block proofs for {span} heights",
            blocks.len()
        )));
    }
    let cps = proof["checkpoints"].as_array().cloned().unwrap_or_default();
    if span > 0 {
        let mut digest = checkpoint_digest(cps.first().ok_or_else(|| bad("no checkpoint"))?)?;
        for pair in cps.windows(2) {
            if bytes32(&pair[1]["prev"], "prev")? != digest
                || uint(&pair[1]["index"], "index")? != uint(&pair[0]["index"], "index")? + 1
            {
                return Err(bad("a checkpoint does not follow its predecessor"));
            }
            digest = checkpoint_digest(&pair[1])?;
        }
        if &digest != certified_checkpoint_digest {
            return Err(bad("the proof does not end at the certified checkpoint"));
        }
    }
    let in_range = |c: (u64, u64, u64)| after.is_none_or(|a| c > a) && c <= through;
    let mut candidates = std::collections::BTreeSet::new();
    for (i, block) in blocks.iter().enumerate() {
        let height = first + i as u64;
        let header = &block["header"];
        if uint(&header["height"], "header height")? != height {
            return Err(bad(format!("block proof {i} is not for height {height}")));
        }
        let mut covering = None;
        for c in &cps {
            if uint(&c["first_height"], "first_height")? <= height
                && height <= uint(&c["last_height"], "last_height")?
            {
                covering = Some(c);
                break;
            }
        }
        let covering =
            covering.ok_or_else(|| bad(format!("no checkpoint covers height {height}")))?;
        if root_from_path(&header_hash(header)?, &block["block_path"])?
            != bytes32(&covering["blocks_root"], "blocks_root")?
        {
            return Err(bad(format!(
                "the header of block {height} is not under its checkpoint"
            )));
        }
        let entries = block["entries"]
            .as_array()
            .ok_or_else(|| bad("no entries"))?;
        if entries.len() != keys.len() {
            return Err(bad(format!(
                "block {height} proves the wrong number of entries"
            )));
        }
        for (key, ep) in keys.iter().zip(entries) {
            let entry = &ep["entry"];
            if root_from_path(&index_leaf(entry)?, &ep["path"])?
                != bytes32(&header["event_root"], "event_root")?
            {
                return Err(bad(format!(
                    "an index entry is not under block {height}'s event root"
                )));
            }
            let ek = entry["key"].as_str().unwrap_or_default();
            let next = entry["next"].as_str();
            let listed: Vec<Value> = if ek == key {
                entry["cursors"].as_array().cloned().unwrap_or_default()
            } else if ek < key.as_str() && next.is_none_or(|n| key.as_str() < n) {
                Vec::new()
            } else {
                return Err(bad(format!(
                    "block {height}'s entry does not speak for key {key}"
                )));
            };
            for c in listed {
                let c = cursor_of(&c)?;
                if c.0 != height {
                    return Err(bad(format!("block {height}'s index lists another height")));
                }
                if in_range(c) {
                    candidates.insert(c);
                }
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in answer {
        let c = cursor_of(&e["cursor"])?;
        if !candidates.contains(&c) || !selects(e)? {
            return Err(bad(format!("event {c:?} is not a selected candidate")));
        }
        seen.insert(c);
    }
    for p in proof["excluded"].as_array().into_iter().flatten() {
        verify_event_proof(p, certified_checkpoint_digest)?;
        let c = cursor_of(&p["event"]["cursor"])?;
        if !candidates.contains(&c) || selects(&p["event"])? {
            return Err(bad(format!("event {c:?} is not a rejected candidate")));
        }
        seen.insert(c);
    }
    if let Some(missing) = candidates.difference(&seen).next() {
        return Err(bad(format!("event {missing:?} was left out")));
    }
    Ok(())
}

impl EventClient {
    /// Calls `tenzro_eventStatus`: event status.
    pub async fn event_status(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_eventStatus", serde_json::json!({}))
            .await
    }
}

impl EventClient {
    /// Calls `tenzro_verifyEventProof`: verify event proof.
    pub async fn verify_event_proof(
        &self,
        proof: Option<serde_json::Value>,
        certified_proof: Option<serde_json::Value>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyEventProof",
                serde_json::json!({ "proof": proof, "certified_proof": certified_proof }),
            )
            .await
    }
}
