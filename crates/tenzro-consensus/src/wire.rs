//! Messages validators exchange over consensus channels.
//!
//! Everything a validator sends one peer between two flushes travels in one
//! [`Frame`], which the channel authenticates as a unit (see
//! [`crate::channel`]). Decoding is bounded: a frame larger than
//! [`MAX_FRAME_BYTES`] or with more than [`MAX_FRAME_ITEMS`] items is
//! refused before anything in it is acted on.

use serde::{Deserialize, Serialize};

use crate::batch::BatchPayload;
use crate::checkpoint::{Certificate, CheckpointVote};
use crate::error::{ConsensusError, Result};
use crate::ordering::OrderingState;
use crate::rbc::Signal;
use crate::vertex::{Digest, Round, Vertex, VertexRef};

/// Largest encoded frame.
pub const MAX_FRAME_BYTES: usize = 8 << 20;
/// Largest number of items in one frame.
pub const MAX_FRAME_ITEMS: usize = 65_536;
/// Largest number of digests in one fetch request.
pub const MAX_FETCH: usize = 1_024;

/// One consensus message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// The sender's own vertex, opening its reliable-broadcast instance.
    Propose(Vertex),
    /// Reliable-broadcast echoes, votes, acks and readies.
    Signals(Vec<Signal>),
    /// A batch the sender authored.
    Batch(BatchPayload),
    /// Asks for vertices by digest.
    FetchVertices(Vec<Digest>),
    /// Vertices answering a fetch.
    Vertices(Vec<Vertex>),
    /// Asks for batches by digest.
    FetchBatches(Vec<Digest>),
    /// Batches answering a fetch.
    Batches(Vec<BatchPayload>),
    /// A checkpoint vote.
    Vote(CheckpointVote),
    /// A checkpoint certificate, for a peer that is behind.
    Certificate(Box<Certificate>),
    /// Where the sender stands, sent when a channel comes up and while the
    /// sender's round is stalled: the receiver re-sends what the sender has
    /// not seen of the rounds still in play.
    Frontier(Frontier),
    /// Asks for the ordering state taken at a checkpoint.
    FetchOrdering(u64),
    /// The ordering state taken at a checkpoint, answering a fetch.
    Ordering(Box<OrderingState>),
}

/// A validator's position in its epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    /// The round the sender last proposed, if it has started.
    pub round: Option<Round>,
    /// The highest delivered vertex of each author the sender holds.
    pub highest: Vec<VertexRef>,
    /// The index of the first checkpoint the sender holds no certificate for.
    pub next_checkpoint: u64,
}

/// Messages to one peer, authenticated together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// Epoch every message in the frame belongs to.
    pub epoch: u64,
    /// The messages.
    pub items: Vec<Message>,
}

impl Frame {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("frame encodes")
    }

    /// The frames carrying `items` to one peer, in order and encoded, each
    /// within [`MAX_FRAME_BYTES`] and [`MAX_FRAME_ITEMS`], so a receiver
    /// never refuses one for its size. A message of vertices, batches or
    /// signals too large for one frame travels as several of its kind. A
    /// message that cannot fit a frame even alone (one vertex, batch or
    /// signal larger than a frame) is left out, since the receiver would
    /// refuse it and the channel with it; how many were left out is
    /// returned beside the frames.
    pub fn encode_bounded(epoch: u64, items: Vec<Message>) -> (Vec<Vec<u8>>, usize) {
        let mut packer = Packer {
            epoch,
            frames: Vec::new(),
            current: Vec::new(),
            used: 0,
            left_out: 0,
        };
        for m in items {
            let size = bincode::serialized_size(&m).unwrap_or(u64::MAX);
            if size <= FRAME_BUDGET {
                packer.push(m, size);
                continue;
            }
            match m {
                Message::Signals(v) => packer.split(v, Message::Signals),
                Message::Vertices(v) => packer.split(v, Message::Vertices),
                Message::Batches(v) => packer.split(v, Message::Batches),
                _ => packer.left_out += 1,
            }
        }
        packer.flush();
        (packer.frames, packer.left_out)
    }

    /// Decodes a frame, refusing oversized input and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        use bincode::Options;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ConsensusError::Malformed("frame too large".into()));
        }
        let frame: Frame = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_FRAME_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| ConsensusError::Malformed(e.to_string()))?;
        if frame.items.len() > MAX_FRAME_ITEMS {
            return Err(ConsensusError::Malformed("frame has too many items".into()));
        }
        for item in &frame.items {
            match item {
                Message::FetchVertices(d) | Message::FetchBatches(d) if d.len() > MAX_FETCH => {
                    return Err(ConsensusError::Malformed("fetch asks for too much".into()));
                }
                Message::Frontier(f) if f.highest.len() > MAX_FETCH => {
                    return Err(ConsensusError::Malformed(
                        "frontier names too many vertices".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(frame)
    }
}

/// Room for messages in one frame: the frame's epoch and item count take
/// 16 bytes of its encoding.
const FRAME_BUDGET: u64 = MAX_FRAME_BYTES as u64 - 16;
/// What a message of a list takes beside its elements: its variant tag and
/// the list's length.
const LIST_MESSAGE_OVERHEAD: u64 = 12;

/// Packs messages, in order, into frames within the bounds.
struct Packer {
    epoch: u64,
    frames: Vec<Vec<u8>>,
    current: Vec<Message>,
    used: u64,
    left_out: usize,
}

impl Packer {
    fn push(&mut self, m: Message, size: u64) {
        if !self.current.is_empty()
            && (self.used + size > FRAME_BUDGET || self.current.len() >= MAX_FRAME_ITEMS)
        {
            self.flush();
        }
        self.used += size;
        self.current.push(m);
    }

    fn flush(&mut self) {
        if self.current.is_empty() {
            return;
        }
        let items = std::mem::take(&mut self.current);
        self.frames.push(
            Frame {
                epoch: self.epoch,
                items,
            }
            .encode(),
        );
        self.used = 0;
    }

    /// Sends the elements of one list message as several messages of its
    /// kind, each fitting a frame.
    fn split<T: Serialize>(&mut self, elements: Vec<T>, wrap: fn(Vec<T>) -> Message) {
        let room = FRAME_BUDGET - LIST_MESSAGE_OVERHEAD;
        let mut chunk = Vec::new();
        let mut chunk_size = 0u64;
        for e in elements {
            let size = bincode::serialized_size(&e).unwrap_or(u64::MAX);
            if size > room {
                self.left_out += 1;
                continue;
            }
            if chunk_size + size > room {
                let full = std::mem::take(&mut chunk);
                self.push(wrap(full), chunk_size + LIST_MESSAGE_OVERHEAD);
                chunk_size = 0;
            }
            chunk_size += size;
            chunk.push(e);
        }
        if !chunk.is_empty() {
            self.push(wrap(chunk), chunk_size + LIST_MESSAGE_OVERHEAD);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbc::SignalKind;

    #[test]
    fn replies_larger_than_a_frame_travel_in_frames_a_receiver_accepts() {
        let batch = |sequence: u64| BatchPayload {
            epoch: 4,
            author: 1,
            sequence,
            transactions: 1,
            body: vec![sequence as u8; 1 << 20],
        };
        let batches: Vec<BatchPayload> = (0..30).map(batch).collect();
        let items = vec![
            Message::FetchBatches(vec![[7u8; 32]]),
            Message::Batches(batches.clone()),
            Message::Batches(vec![BatchPayload {
                body: vec![0; MAX_FRAME_BYTES],
                ..batch(99)
            }]),
            Message::FetchOrdering(5),
        ];
        let single = Frame {
            epoch: 4,
            items: items.clone(),
        }
        .encode();
        assert!(
            Frame::decode(&single).is_err(),
            "one frame of it is refused"
        );

        let (frames, left_out) = Frame::encode_bounded(4, items);
        assert!(frames.len() >= 4);
        assert_eq!(left_out, 1, "the batch larger than a frame is left out");
        let mut received = Vec::new();
        for bytes in &frames {
            assert!(bytes.len() <= MAX_FRAME_BYTES);
            received.extend(Frame::decode(bytes).expect("accepted").items);
        }
        assert_eq!(
            received.first(),
            Some(&Message::FetchBatches(vec![[7u8; 32]]))
        );
        assert_eq!(received.last(), Some(&Message::FetchOrdering(5)));
        let carried: Vec<BatchPayload> = received
            .into_iter()
            .filter_map(|m| match m {
                Message::Batches(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(carried, batches, "every batch arrives, in order");
    }

    #[test]
    fn a_frame_round_trips_and_trailing_bytes_are_refused() {
        let f = Frame {
            epoch: 3,
            items: vec![
                Message::FetchVertices(vec![[9; 32]]),
                Message::Signals(vec![Signal {
                    kind: SignalKind::Ready,
                    round: 2,
                    source: 1,
                    digest: [4; 32],
                }]),
            ],
        };
        let mut b = f.encode();
        assert_eq!(Frame::decode(&b).unwrap(), f);
        b.push(0);
        assert!(Frame::decode(&b).is_err());
    }

    #[test]
    fn a_length_prefix_claiming_more_than_the_limit_is_refused_without_allocating() {
        let mut b = 3u64.to_le_bytes().to_vec();
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(Frame::decode(&b).is_err());
    }
}
