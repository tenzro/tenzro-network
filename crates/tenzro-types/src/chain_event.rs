//! The events a block's execution emits, and the commitment to them its
//! header carries.
//!
//! Every validator executes the same ordered transactions, so every one
//! derives the same events: for each executed transaction, its outcome, then
//! each log it emitted, in order. Their Merkle root is the header's
//! `event_root`; the header hash is a leaf of the certified checkpoint's
//! blocks root, so any event is provable against a certified checkpoint.
//!
//! An event's position is its [`EventCursor`], `(height, tx index, event
//! index)`. Cursors are totally ordered, and a reader that resumes after a
//! cursor misses nothing and sees nothing twice.
//!
//! The same tree also commits the block's index: for every key an event is
//! filtered by (its kind, its emitting contract, each topic at its position)
//! one [`IndexEntry`] lists the cursors of every event under that key, and
//! names the next key in order. The entries form a sorted chain that starts
//! at an empty key, so one entry proves either the complete set of events
//! under a key or that the block has none: a filtered read proves it left
//! nothing out.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::merkle::{Node, merkle_root};
use crate::primitives::Hash;

/// Domain of an event's leaf digest.
const LEAF_DOMAIN: &[u8] = b"tenzro/chain-event/leaf";

/// Domain of an index entry's leaf digest.
const INDEX_DOMAIN: &[u8] = b"tenzro/chain-event/index";

/// Where an event sits in the chain. Orders by height, then transaction,
/// then event.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct EventCursor {
    /// Block height.
    pub height: u64,
    /// Index of the transaction in the block.
    pub tx_index: u32,
    /// Index of the event among the transaction's events.
    pub event_index: u32,
}

impl EventCursor {
    /// The cursor at `(height, tx_index, event_index)`.
    pub fn new(height: u64, tx_index: u32, event_index: u32) -> Self {
        Self {
            height,
            tx_index,
            event_index,
        }
    }

    /// The first position of `height`.
    pub fn block_start(height: u64) -> Self {
        Self::new(height, 0, 0)
    }

    /// Big-endian storage key: byte order is cursor order.
    pub fn to_key(&self) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[..8].copy_from_slice(&self.height.to_be_bytes());
        k[8..12].copy_from_slice(&self.tx_index.to_be_bytes());
        k[12..].copy_from_slice(&self.event_index.to_be_bytes());
        k
    }

    /// The cursor a storage key encodes.
    pub fn from_key(key: &[u8]) -> Option<Self> {
        let k: &[u8; 16] = key.try_into().ok()?;
        Some(Self {
            height: u64::from_be_bytes(k[..8].try_into().ok()?),
            tx_index: u32::from_be_bytes(k[8..12].try_into().ok()?),
            event_index: u32::from_be_bytes(k[12..].try_into().ok()?),
        })
    }
}

/// Wire form `height:tx_index:event_index`.
impl fmt::Display for EventCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.height, self.tx_index, self.event_index)
    }
}

impl FromStr for EventCursor {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let (Some(h), Some(t), Some(e), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!(
                "a cursor is height:tx_index:event_index, got {s:?}"
            ));
        };
        let bad = |what: &str| format!("cursor {s:?}: {what} is not an unsigned integer");
        Ok(Self {
            height: h.parse().map_err(|_| bad("height"))?,
            tx_index: t.parse().map_err(|_| bad("tx_index"))?,
            event_index: e.parse().map_err(|_| bad("event_index"))?,
        })
    }
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainEventKind {
    /// A transaction executed: whether it succeeded, the gas it used, and the
    /// contract it deployed, if any. Always the transaction's first event.
    TxOutcome {
        /// Whether execution succeeded.
        success: bool,
        /// Gas consumed.
        gas_used: u64,
        /// Address of a contract the transaction deployed.
        contract_address: Option<Vec<u8>>,
    },
    /// A log the transaction emitted.
    Log {
        /// Emitting contract.
        address: Vec<u8>,
        /// Indexed topics.
        topics: Vec<Vec<u8>>,
        /// Unindexed data.
        data: Vec<u8>,
    },
}

/// One event a block's execution emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    /// Position in the chain.
    pub cursor: EventCursor,
    /// Transaction that emitted it.
    pub tx_hash: Hash,
    /// What happened.
    #[serde(flatten)]
    pub kind: ChainEventKind,
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

impl ChainEvent {
    /// Canonical encoding: the leaf domain, the cursor (u64, u32, u32
    /// little-endian), the transaction hash, then a kind tag and the kind's
    /// fields, every byte string prefixed by its u32 little-endian length.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(LEAF_DOMAIN);
        out.extend_from_slice(&self.cursor.height.to_le_bytes());
        out.extend_from_slice(&self.cursor.tx_index.to_le_bytes());
        out.extend_from_slice(&self.cursor.event_index.to_le_bytes());
        out.extend_from_slice(&self.tx_hash.0);
        match &self.kind {
            ChainEventKind::TxOutcome {
                success,
                gas_used,
                contract_address,
            } => {
                out.push(0);
                out.push(u8::from(*success));
                out.extend_from_slice(&gas_used.to_le_bytes());
                match contract_address {
                    None => out.push(0),
                    Some(a) => {
                        out.push(1);
                        put_bytes(&mut out, a);
                    }
                }
            }
            ChainEventKind::Log {
                address,
                topics,
                data,
            } => {
                out.push(1);
                put_bytes(&mut out, address);
                out.extend_from_slice(&(topics.len() as u32).to_le_bytes());
                for t in topics {
                    put_bytes(&mut out, t);
                }
                put_bytes(&mut out, data);
            }
        }
        out
    }

    /// The event's leaf in its block's event tree.
    pub fn leaf(&self) -> Node {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// The emitting contract of a log, or `None` for an outcome.
    pub fn log_address(&self) -> Option<&[u8]> {
        match &self.kind {
            ChainEventKind::Log { address, .. } => Some(address),
            ChainEventKind::TxOutcome { .. } => None,
        }
    }
}

/// The events one executed transaction emits: its outcome, then its logs.
pub fn transaction_events<'a>(
    height: u64,
    tx_index: u32,
    tx_hash: Hash,
    success: bool,
    gas_used: u64,
    contract_address: Option<Vec<u8>>,
    logs: impl IntoIterator<Item = (&'a [u8], &'a [Vec<u8>], &'a [u8])>,
) -> Vec<ChainEvent> {
    let mut out = vec![ChainEvent {
        cursor: EventCursor::new(height, tx_index, 0),
        tx_hash,
        kind: ChainEventKind::TxOutcome {
            success,
            gas_used,
            contract_address,
        },
    }];
    for (address, topics, data) in logs {
        out.push(ChainEvent {
            cursor: EventCursor::new(height, tx_index, out.len() as u32),
            tx_hash,
            kind: ChainEventKind::Log {
                address: address.to_vec(),
                topics: topics.to_vec(),
                data: data.to_vec(),
            },
        });
    }
    out
}

/// What an index computes from the events its filter selects. A projection
/// is a pure function of the events, so a buyer holding their proofs
/// recomputes the answer and needs to trust no seller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    /// The events themselves.
    Events,
    /// How many events there are.
    Count,
    /// The latest log of each emitting contract, keyed by its address (hex).
    LatestPerAddress,
}

impl Projection {
    /// The projection of `events`, given in cursor order.
    pub fn apply(&self, events: &[ChainEvent]) -> serde_json::Value {
        match self {
            Projection::Events => {
                serde_json::to_value(events).expect("chain events encode as JSON")
            }
            Projection::Count => serde_json::json!(events.len()),
            Projection::LatestPerAddress => {
                let mut latest = serde_json::Map::new();
                for e in events {
                    if let Some(address) = e.log_address() {
                        latest.insert(
                            hex::encode(address),
                            serde_json::to_value(e).expect("chain events encode"),
                        );
                    }
                }
                serde_json::Value::Object(latest)
            }
        }
    }
}

/// The keys of a block's index.
pub mod index_key {
    /// Every transaction outcome.
    pub const OUTCOMES: &[u8] = b"k\x00";
    /// Every log.
    pub const LOGS: &[u8] = b"k\x01";

    /// Logs a contract emitted, by the 20-byte tail of its address.
    pub fn address(tail: &[u8]) -> Vec<u8> {
        [b"a".as_slice(), tail].concat()
    }

    /// Logs carrying `topic` at `position`.
    pub fn topic(position: u8, topic: &[u8]) -> Vec<u8> {
        [b"t".as_slice(), &[position], topic].concat()
    }
}

/// The 20-byte tail an address is indexed and filtered by: the last 20
/// bytes of a 32-byte account key, any other address as it is.
pub fn address_tail(address: &[u8]) -> &[u8] {
    if address.len() == 32 {
        &address[12..]
    } else {
        address
    }
}

impl ChainEvent {
    /// The index keys the event is listed under.
    pub fn index_keys(&self) -> Vec<Vec<u8>> {
        match &self.kind {
            ChainEventKind::TxOutcome { .. } => vec![index_key::OUTCOMES.to_vec()],
            ChainEventKind::Log {
                address, topics, ..
            } => {
                let mut keys = vec![
                    index_key::LOGS.to_vec(),
                    index_key::address(address_tail(address)),
                ];
                for (i, t) in topics.iter().enumerate().take(4) {
                    keys.push(index_key::topic(i as u8, t));
                }
                keys
            }
        }
    }
}

/// One entry of a block's index: every event under `key`, and the next key
/// the block's index holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// The key, hex on the wire. The chain starts at the empty key.
    #[serde(with = "hex_bytes")]
    pub key: Vec<u8>,
    /// The next key in byte order, or `None` for the last entry.
    #[serde(with = "hex_opt_bytes")]
    pub next: Option<Vec<u8>>,
    /// The cursors of every event under `key`, in cursor order.
    pub cursors: Vec<EventCursor>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod hex_opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|h| hex::decode(h).map_err(serde::de::Error::custom))
            .transpose()
    }
}

impl IndexEntry {
    /// The entry's leaf: the index domain, the key, the next key (a presence
    /// byte, then the key) and the cursors, every byte string and list
    /// prefixed by its u32 little-endian length.
    pub fn leaf(&self) -> Node {
        let mut out = Vec::with_capacity(64 + 16 * self.cursors.len());
        out.extend_from_slice(INDEX_DOMAIN);
        put_bytes(&mut out, &self.key);
        match &self.next {
            None => out.push(0),
            Some(next) => {
                out.push(1);
                put_bytes(&mut out, next);
            }
        }
        out.extend_from_slice(&(self.cursors.len() as u32).to_le_bytes());
        for c in &self.cursors {
            out.extend_from_slice(&c.to_key());
        }
        *blake3::hash(&out).as_bytes()
    }

    /// The events under `key` in this block, when this entry speaks for it:
    /// its own cursors when it is `key`'s entry, none when `key` falls
    /// strictly between this entry and the next. `None` when the entry says
    /// nothing about `key`.
    pub fn covers(&self, key: &[u8]) -> Option<&[EventCursor]> {
        if self.key == key {
            return Some(&self.cursors);
        }
        let after = self.key.as_slice() < key;
        let before = self.next.as_deref().is_none_or(|n| key < n);
        (after && before).then_some(&[][..])
    }
}

/// A block's index over `events`, given in cursor order: the empty-key entry,
/// then one entry per key, in byte order.
pub fn block_index(events: &[ChainEvent]) -> Vec<IndexEntry> {
    let mut by_key: std::collections::BTreeMap<Vec<u8>, Vec<EventCursor>> =
        std::collections::BTreeMap::new();
    by_key.insert(Vec::new(), Vec::new());
    for e in events {
        for key in e.index_keys() {
            let cursors = by_key.entry(key).or_default();
            if cursors.last() != Some(&e.cursor) {
                cursors.push(e.cursor);
            }
        }
    }
    let keys: Vec<Vec<u8>> = by_key.keys().cloned().collect();
    by_key
        .into_iter()
        .enumerate()
        .map(|(i, (key, cursors))| IndexEntry {
            key,
            next: keys.get(i + 1).cloned(),
            cursors,
        })
        .collect()
}

/// Every leaf of a block's event tree: the events in cursor order, then the
/// entries of [`block_index`].
pub fn event_tree_leaves(events: &[ChainEvent]) -> Vec<Node> {
    events
        .iter()
        .map(ChainEvent::leaf)
        .chain(block_index(events).iter().map(IndexEntry::leaf))
        .collect()
}

/// The root a block header commits for `events`, in cursor order: the tree
/// over the events and the block's index.
pub fn event_root(events: &[ChainEvent]) -> Hash {
    Hash::new(merkle_root(&event_tree_leaves(events)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_keys_sort_like_cursors() {
        let a = EventCursor::new(1, 300, 2);
        let b = EventCursor::new(2, 0, 0);
        let c = EventCursor::new(2, 0, 1);
        assert!(a < b && b < c);
        assert!(a.to_key() < b.to_key() && b.to_key() < c.to_key());
        assert_eq!(EventCursor::from_key(&c.to_key()), Some(c));
        assert_eq!("2:0:1".parse::<EventCursor>(), Ok(c));
        assert!("2:0".parse::<EventCursor>().is_err());
    }

    #[test]
    fn the_index_proves_every_key_present_or_absent() {
        let a = [1u8; 20];
        let topic = vec![7u8; 32];
        let topics = [topic.clone()];
        let logs = [
            (&a[..], &topics[..], &b"x"[..]),
            (&[2u8; 20][..], &[][..], &b"y"[..]),
        ];
        let events = transaction_events(9, 0, Hash::new([3; 32]), true, 1, None, logs);
        let index = block_index(&events);
        assert!(index[0].key.is_empty(), "the chain starts at the empty key");
        for w in index.windows(2) {
            assert!(w[0].key < w[1].key);
            assert_eq!(w[0].next.as_deref(), Some(w[1].key.as_slice()));
        }
        assert!(index.last().unwrap().next.is_none());
        let addr = index_key::address(&a);
        let entry = index
            .iter()
            .find(|e| e.covers(&addr).is_some_and(|c| !c.is_empty()))
            .unwrap();
        assert_eq!(entry.covers(&addr).unwrap(), &[EventCursor::new(9, 0, 1)]);
        // A key the block does not hold is covered, as empty, by exactly one entry.
        let absent = index_key::address(&[1u8; 19]);
        let covering: Vec<_> = index
            .iter()
            .filter(|e| e.covers(&absent).is_some())
            .collect();
        assert_eq!(covering.len(), 1);
        assert!(covering[0].covers(&absent).unwrap().is_empty());
        // Every key, present or not, is covered by exactly one entry.
        for key in [
            index_key::OUTCOMES.to_vec(),
            index_key::topic(0, &topic),
            index_key::topic(1, &topic),
            vec![0xff; 3],
        ] {
            assert_eq!(
                index.iter().filter(|e| e.covers(&key).is_some()).count(),
                1,
                "{key:?}"
            );
        }
        // The root commits the index: dropping a cursor from an entry changes it.
        let leaves = event_tree_leaves(&events);
        assert_eq!(leaves.len(), events.len() + index.len());
        let mut tampered = index.clone();
        let i = tampered.iter().position(|e| e.key == addr).unwrap();
        tampered[i].cursors.clear();
        assert_ne!(tampered[i].leaf(), index[i].leaf());
    }

    #[test]
    fn a_changed_event_changes_the_root() {
        let topics = [vec![7u8; 32]];
        let logs = [(&[1u8; 20][..], &topics[..], &b"x"[..])];
        let events = transaction_events(5, 0, Hash::new([9; 32]), true, 21_000, None, logs);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].cursor, EventCursor::new(5, 0, 1));
        let root = event_root(&events);
        let mut tampered = events.clone();
        if let ChainEventKind::Log { data, .. } = &mut tampered[1].kind {
            data[0] ^= 1;
        }
        assert_ne!(event_root(&tampered), root);
    }
}
