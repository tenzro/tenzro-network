//! The durable, cursor-ordered log of the events the chain's blocks emitted.
//!
//! Each event is stored under its [`EventCursor`] key in the events column
//! family, written in the same batch as its block, so the log holds exactly
//! the executed blocks' events. Readers resume after any cursor: the log is
//! ordered by cursor and never rewritten, so a reader that passes back the
//! cursor it was last given misses nothing and sees nothing twice, across a
//! restart of either side.
//!
//! Heights below the retention floor have been handed to the data
//! availability layer with their blocks; the log reports the floor so a
//! reader can fetch those from there.

use std::sync::Arc;

use tenzro_storage::{CF_EVENTS, CF_METADATA, KvStore, StorageError, WriteOp};
use tenzro_types::chain_event::{ChainEvent, EventCursor};
use tokio::sync::watch;

/// Metadata key of the highest height whose events are written.
const TIP_KEY: &[u8] = b"event_log:tip";
/// Metadata key of the lowest height still held locally.
const FLOOR_KEY: &[u8] = b"event_log:floor";

type Result<T> = std::result::Result<T, StorageError>;

fn decode(value: &[u8]) -> Result<ChainEvent> {
    serde_json::from_slice(value)
        .map_err(|e| StorageError::DeserializationError(format!("event log entry: {e}")))
}

fn read_u64(storage: &dyn KvStore, key: &[u8]) -> Result<Option<u64>> {
    Ok(storage
        .get(CF_METADATA, key)?
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_be_bytes))
}

/// One page of a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// Events after the requested cursor, in cursor order; from
    /// [`EventLog::read_before`], events before it, newest first.
    pub events: Vec<ChainEvent>,
    /// The cursor to resume after: the last event returned, or the end of
    /// the last height read when the page stopped between blocks. From
    /// [`EventLog::read_before`], the cursor to read the older page before.
    pub cursor: Option<EventCursor>,
}

/// The cursor past every event of `height`.
pub fn end_of_height(height: u64) -> EventCursor {
    EventCursor::new(height, u32::MAX, u32::MAX)
}

/// The node's event log.
pub struct EventLog {
    storage: Arc<dyn KvStore>,
    tip: watch::Sender<Option<u64>>,
}

impl std::fmt::Debug for EventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLog")
            .field("tip", &*self.tip.borrow())
            .finish_non_exhaustive()
    }
}

impl EventLog {
    /// The log over `storage`, resuming at the tip it recorded.
    pub fn open(storage: Arc<dyn KvStore>) -> Result<Self> {
        let tip = read_u64(&*storage, TIP_KEY)?;
        Ok(Self {
            storage,
            tip: watch::Sender::new(tip),
        })
    }

    /// The writes that record `events`, all emitted by the block at
    /// `height`, and advance the tip to it. They go into the block's own
    /// batch; [`EventLog::advance`] runs once that batch is durable.
    pub fn block_writes(height: u64, events: &[ChainEvent]) -> Vec<WriteOp> {
        let mut ops: Vec<WriteOp> = events
            .iter()
            .map(|e| WriteOp::Put {
                cf: CF_EVENTS.to_string(),
                key: e.cursor.to_key().to_vec(),
                value: serde_json::to_vec(e).expect("chain events encode as JSON"),
            })
            .collect();
        ops.push(WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: TIP_KEY.to_vec(),
            value: height.to_be_bytes().to_vec(),
        });
        ops
    }

    /// Wakes readers waiting for events past the previous tip.
    pub fn advance(&self, height: u64) {
        self.tip.send_if_modified(|t| {
            if t.is_none_or(|old| height > old) {
                *t = Some(height);
                true
            } else {
                false
            }
        });
    }

    /// Highest height whose events are written, if any.
    pub fn tip(&self) -> Option<u64> {
        *self.tip.borrow()
    }

    /// Lowest height still held locally.
    pub fn floor(&self) -> Result<u64> {
        Ok(read_u64(&*self.storage, FLOOR_KEY)?.unwrap_or(0))
    }

    /// A receiver that changes whenever the tip advances.
    pub fn watch_tip(&self) -> watch::Receiver<Option<u64>> {
        self.tip.subscribe()
    }

    /// Every event the block at `height` emitted, in cursor order.
    pub fn block(&self, height: u64) -> Result<Vec<ChainEvent>> {
        let mut out = Vec::new();
        self.storage
            .scan_prefix_for_each(CF_EVENTS, &height.to_be_bytes(), &mut |_, v| {
                out.push(decode(v)?);
                Ok(())
            })?;
        // A store need not scan in key order; the log's order is the cursor's.
        out.sort_by_key(|e| e.cursor);
        Ok(out)
    }

    /// Up to `limit` events that `keep` selects, after `after` (from the
    /// first held height when `None`) through the end of `to_height` (the tip
    /// when `None`), scanning at most `max_heights` heights.
    pub fn read_after(
        &self,
        after: Option<EventCursor>,
        to_height: Option<u64>,
        limit: usize,
        max_heights: u64,
        keep: &dyn Fn(&ChainEvent) -> bool,
    ) -> Result<Page> {
        let Some(tip) = self.tip() else {
            return Ok(Page {
                events: Vec::new(),
                cursor: after,
            });
        };
        let last = to_height.map_or(tip, |h| h.min(tip));
        let start = after.map_or(self.floor()?, |c| c.height);
        let mut page = Page {
            events: Vec::new(),
            cursor: after,
        };
        let mut height = start;
        while height <= last && height < start.saturating_add(max_heights.max(1)) {
            for event in self.block(height)? {
                if after.is_some_and(|a| event.cursor <= a) || !keep(&event) {
                    continue;
                }
                if page.events.len() == limit {
                    return Ok(page);
                }
                page.cursor = Some(event.cursor);
                page.events.push(event);
            }
            page.cursor = Some(end_of_height(height));
            height += 1;
        }
        Ok(page)
    }

    /// The newest events `keep` accepts before `before` (exclusive; `None`
    /// reads from the tip), newest first: at most `limit` of them, from at
    /// most `max_heights` heights down from there, none below the floor. The
    /// page's `cursor` is the `before` that reads the page older than it, or
    /// `None` once the floor was read.
    pub fn read_before(
        &self,
        before: Option<EventCursor>,
        limit: usize,
        max_heights: u64,
        keep: &dyn Fn(&ChainEvent) -> bool,
    ) -> Result<Page> {
        let mut page = Page {
            events: Vec::new(),
            cursor: None,
        };
        let floor = self.floor()?;
        let Some(tip) = self.tip() else {
            return Ok(page);
        };
        let top = match before {
            None => tip,
            // Nothing at a height comes before its start: the page older than
            // a height read whole begins one height down.
            Some(b) if b == EventCursor::block_start(b.height) => match b.height.checked_sub(1) {
                Some(h) => h.min(tip),
                None => return Ok(page),
            },
            Some(b) => b.height.min(tip),
        };
        if top < floor {
            return Ok(page);
        }
        let mut height = top;
        let mut read = 0;
        loop {
            for event in self.block(height)?.into_iter().rev() {
                if before.is_some_and(|b| event.cursor >= b) || !keep(&event) {
                    continue;
                }
                if page.events.len() == limit {
                    page.cursor = page.events.last().map(|e| e.cursor);
                    return Ok(page);
                }
                page.events.push(event);
            }
            read += 1;
            if height == floor {
                return Ok(page);
            }
            if read >= max_heights.max(1) {
                page.cursor = Some(EventCursor::block_start(height));
                return Ok(page);
            }
            height -= 1;
        }
    }

    /// Deletes the events of heights `first..=last`, handed to the data
    /// availability layer with their blocks, and raises the floor past them.
    pub fn prune_range(&self, first: u64, last: u64) -> Result<usize> {
        let mut ops = Vec::new();
        for height in first..=last {
            for key in self
                .storage
                .get_keys_with_prefix(CF_EVENTS, &height.to_be_bytes())?
            {
                ops.push(WriteOp::Delete {
                    cf: CF_EVENTS.to_string(),
                    key,
                });
            }
        }
        let deleted = ops.len();
        ops.push(WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: FLOOR_KEY.to_vec(),
            value: (last + 1).to_be_bytes().to_vec(),
        });
        self.storage.write_batch_sync(ops)?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;
    use tenzro_types::chain_event::transaction_events;
    use tenzro_types::primitives::Hash;

    const ALL: fn(&ChainEvent) -> bool = |_| true;

    fn block(height: u64, txs: u32) -> Vec<ChainEvent> {
        let topics = [vec![1u8; 32]];
        (0..txs)
            .flat_map(|t| {
                let logs = [(&[2u8; 20][..], &topics[..], &b"d"[..])];
                transaction_events(height, t, Hash::new([t as u8; 32]), true, 1, None, logs)
            })
            .collect()
    }

    fn write(storage: &Arc<dyn KvStore>, log: &EventLog, height: u64, txs: u32) {
        storage
            .write_batch_sync(EventLog::block_writes(height, &block(height, txs)))
            .unwrap();
        log.advance(height);
    }

    #[test]
    fn resuming_after_the_returned_cursor_is_gap_free_across_a_restart() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let log = EventLog::open(storage.clone()).unwrap();
        write(&storage, &log, 1, 2);
        write(&storage, &log, 2, 0);
        write(&storage, &log, 3, 3);

        let mut seen = Vec::new();
        let mut cursor = None;
        let first = log.read_after(cursor, None, 3, 100, &ALL).unwrap();
        seen.extend(first.events.iter().map(|e| e.cursor));
        cursor = first.cursor;

        // The node restarts: a new log over the same storage, and the reader
        // resumes with the cursor it was given.
        drop(log);
        let log = EventLog::open(storage.clone()).unwrap();
        assert_eq!(log.tip(), Some(3));
        write(&storage, &log, 4, 1);
        loop {
            let page = log.read_after(cursor, None, 2, 100, &ALL).unwrap();
            if page.events.is_empty() {
                break;
            }
            seen.extend(page.events.iter().map(|e| e.cursor));
            cursor = page.cursor;
        }

        let mut all: Vec<EventCursor> = Vec::new();
        for (h, n) in [(1, 2), (3, 3), (4, 1)] {
            all.extend(block(h, n).iter().map(|e| e.cursor));
        }
        assert_eq!(seen, all, "every event once, in order");
    }

    #[test]
    fn a_page_stops_between_blocks_without_skipping() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let log = EventLog::open(storage.clone()).unwrap();
        for h in 1..=5 {
            write(&storage, &log, h, u32::from(h == 5));
        }
        let page = log.read_after(None, None, 10, 2, &ALL).unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.cursor, Some(end_of_height(1)));
        let page = log.read_after(page.cursor, None, 10, 100, &ALL).unwrap();
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events[0].cursor, EventCursor::new(5, 0, 0));
    }

    /// Every event from the tip down, newest first, paging back with the
    /// returned cursor.
    fn newest_first(log: &EventLog, limit: usize, max_heights: u64) -> Vec<EventCursor> {
        let mut seen = Vec::new();
        let mut before = None;
        // Every page moves the cursor down, so a few hundred pages read any
        // log these tests write; a cursor that stops moving fails here.
        for _ in 0..256 {
            let page = log.read_before(before, limit, max_heights, &ALL).unwrap();
            seen.extend(page.events.iter().map(|e| e.cursor));
            match page.cursor {
                Some(c) => {
                    assert!(
                        before.is_none_or(|b| c < b),
                        "the page cursor did not move: {c:?}"
                    );
                    before = Some(c);
                }
                None => return seen,
            }
        }
        panic!("paging back did not reach the floor")
    }

    #[test]
    fn paging_back_from_the_tip_reads_every_event_newest_first_once() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let log = EventLog::open(storage.clone()).unwrap();
        write(&storage, &log, 1, 2);
        write(&storage, &log, 2, 0);
        write(&storage, &log, 3, 3);
        let mut oldest_first = Vec::new();
        let mut cursor = None;
        for pages in 0.. {
            assert!(pages < 256, "reading forward did not reach the tip");
            let page = log.read_after(cursor, None, 1_000, 100, &ALL).unwrap();
            if page.events.is_empty() {
                break;
            }
            oldest_first.extend(page.events.iter().map(|e| e.cursor));
            cursor = page.cursor;
        }
        let mut expected = oldest_first.clone();
        expected.reverse();
        assert!(expected.len() > 3);
        // Pages that end inside a block, between blocks and at the floor.
        for (limit, max_heights) in [(1, 100), (2, 100), (3, 1), (1_000, 100)] {
            assert_eq!(
                newest_first(&log, limit, max_heights),
                expected,
                "{limit} {max_heights}"
            );
        }
        let first = log.read_before(None, 2, 100, &ALL).unwrap();
        assert_eq!(first.events[0].cursor, expected[0]);
        assert_eq!(first.cursor, Some(expected[1]));
    }

    #[test]
    fn paging_back_stops_at_the_floor_and_reads_nothing_below_it() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let log = EventLog::open(storage.clone()).unwrap();
        for h in 1..=3 {
            write(&storage, &log, h, 1);
        }
        log.prune_range(1, 2).unwrap();
        let page = log.read_before(None, 100, 100, &ALL).unwrap();
        assert!(page.events.iter().all(|e| e.cursor.height == 3));
        assert_eq!(page.cursor, None);
        let below = log
            .read_before(Some(EventCursor::block_start(3)), 100, 100, &ALL)
            .unwrap();
        assert!(below.events.is_empty());
        assert_eq!(below.cursor, None);
    }

    #[test]
    fn an_empty_log_has_no_newest_page() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let log = EventLog::open(storage).unwrap();
        let page = log.read_before(None, 10, 10, &ALL).unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.cursor, None);
    }

    #[test]
    fn pruning_raises_the_floor() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let log = EventLog::open(storage.clone()).unwrap();
        for h in 1..=3 {
            write(&storage, &log, h, 1);
        }
        assert_eq!(log.prune_range(1, 2).unwrap(), 4);
        assert_eq!(log.floor().unwrap(), 3);
        assert!(log.block(1).unwrap().is_empty());
        let page = log.read_after(None, None, 10, 100, &ALL).unwrap();
        assert_eq!(page.events[0].cursor.height, 3);
    }
}
