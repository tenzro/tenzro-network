//! The consensus journal's writer.
//!
//! A validator must not send a vote before the records behind it are on
//! disk, so every flush waits for a synced write. The sync is the slow part
//! of it, and it is the disk's, not the node's: on a shared device it can
//! wait behind block storage for as long as a second. Run on the async
//! executor it held a worker thread for that whole time.
//!
//! Writes here go to one dedicated thread. Whatever is queued when the
//! thread wakes is written as one batch with one sync (group commit), and
//! each caller is told once its own records are durable, so a caller still
//! sends only after its records are on disk.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use tenzro_storage::{KvStore, WriteOp};
use tokio::sync::oneshot;

/// The most writes joined into one synced batch.
const MAX_GROUP: usize = 64;

/// Warnings about slow writes are spaced at least this far apart.
const WARN_EVERY: Duration = Duration::from_secs(30);

/// The least a write may take to be worth a warning, ms.
const WARN_FLOOR_MS: u64 = 250;

struct Job {
    ops: Vec<WriteOp>,
    ack: oneshot::Sender<Result<(), String>>,
}

/// A thread that writes the consensus journal and groups the writes queued
/// behind a sync into the next one.
pub struct JournalWriter {
    jobs: Option<Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl JournalWriter {
    /// Starts the writer thread over `store`. Dropping the writer finishes
    /// the writes already queued, ends the thread and waits for it, so the
    /// store is released once the writer is gone.
    pub fn spawn(store: Arc<dyn KvStore>) -> Self {
        let (jobs, queue) = channel();
        let thread = std::thread::Builder::new()
            .name("consensus-journal".to_string())
            .spawn(move || run(store, queue))
            .expect("the journal writer thread starts");
        Self {
            jobs: Some(jobs),
            thread: Some(thread),
        }
    }

    /// Writes `ops` with a sync and returns once they are durable.
    pub async fn write(&self, ops: Vec<WriteOp>) -> Result<(), String> {
        let (ack, done) = oneshot::channel();
        self.jobs
            .as_ref()
            .expect("the queue lives as long as the writer")
            .send(Job { ops, ack })
            .map_err(|_| "the journal writer stopped".to_string())?;
        done.await
            .map_err(|_| "the journal writer stopped".to_string())?
    }
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        // Closing the queue ends the thread after its last batch.
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(store: Arc<dyn KvStore>, queue: Receiver<Job>) {
    while let Ok(first) = queue.recv() {
        let mut group = vec![first];
        while group.len() < MAX_GROUP
            && let Ok(next) = queue.try_recv()
        {
            group.push(next);
        }
        write_group(store.as_ref(), group);
    }
}

/// Writes every job's operations as one synced batch and answers each job
/// with the batch's result.
fn write_group(store: &dyn KvStore, group: Vec<Job>) {
    let mut ops = Vec::new();
    let mut acks = Vec::with_capacity(group.len());
    for job in group {
        ops.extend(job.ops);
        acks.push(job.ack);
    }
    let result = store.write_batch_sync(ops).map_err(|e| e.to_string());
    for ack in acks {
        let _ = ack.send(result.clone());
    }
}

/// How long a journal write may take before it is worth a warning, ms: half
/// the leader timeout, so a warning means the write cost a real share of a
/// round, and never below a floor that keeps a short timeout from warning on
/// every sync.
pub fn slow_threshold_ms(leader_timeout_ms: u64) -> u64 {
    (leader_timeout_ms / 2).max(WARN_FLOOR_MS)
}

/// Spaces out the warnings about slow writes, counting the ones held back.
#[derive(Default)]
pub struct SlowWriteLog {
    last: Option<Instant>,
    held_back: u64,
}

impl SlowWriteLog {
    /// For a write that took `took_ms` against `threshold_ms` at `now`: how
    /// many slow writes since the last warning to report with this one, or
    /// `None` when it should not warn.
    pub fn warn(&mut self, took_ms: u64, threshold_ms: u64, now: Instant) -> Option<u64> {
        if took_ms < threshold_ms {
            return None;
        }
        match self.last {
            Some(at) if now.duration_since(at) < WARN_EVERY => {
                self.held_back += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.held_back))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn put(key: &[u8]) -> WriteOp {
        WriteOp::Put {
            cf: tenzro_storage::CF_BLOCKS.to_string(),
            key: key.to_vec(),
            value: b"v".to_vec(),
        }
    }

    #[tokio::test]
    async fn a_write_is_durable_when_it_returns() {
        let store = Arc::new(MemoryStore::new());
        let writer = JournalWriter::spawn(store.clone());
        writer.write(vec![put(b"a")]).await.unwrap();
        assert!(
            store
                .get(tenzro_storage::CF_BLOCKS, b"a")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn dropping_the_writer_releases_the_store() {
        let store = Arc::new(MemoryStore::new());
        let writer = JournalWriter::spawn(store.clone());
        writer.write(vec![put(b"a")]).await.unwrap();
        drop(writer);
        assert_eq!(Arc::strong_count(&store), 1, "the thread still holds it");
    }

    #[tokio::test]
    async fn queued_writes_are_answered_together_and_all_land() {
        let store = Arc::new(MemoryStore::new());
        let mut acks = Vec::new();
        let mut group = Vec::new();
        for i in 0u8..5 {
            let (ack, done) = oneshot::channel();
            group.push(Job {
                ops: vec![put(&[i])],
                ack,
            });
            acks.push(done);
        }
        write_group(store.as_ref(), group);
        for done in acks {
            done.await.unwrap().unwrap();
        }
        for i in 0u8..5 {
            assert!(
                store
                    .get(tenzro_storage::CF_BLOCKS, &[i])
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn the_threshold_follows_the_leader_timeout_above_a_floor() {
        assert_eq!(slow_threshold_ms(1_000), 500);
        assert_eq!(slow_threshold_ms(4_000), 2_000);
        assert_eq!(slow_threshold_ms(100), WARN_FLOOR_MS);
    }

    #[test]
    fn fast_writes_never_warn() {
        let mut log = SlowWriteLog::default();
        assert_eq!(log.warn(499, 500, Instant::now()), None);
    }

    #[test]
    fn slow_writes_warn_once_per_interval_and_count_the_rest() {
        let mut log = SlowWriteLog::default();
        let t0 = Instant::now();
        assert_eq!(log.warn(900, 500, t0), Some(0));
        assert_eq!(log.warn(900, 500, t0 + Duration::from_secs(1)), None);
        assert_eq!(log.warn(900, 500, t0 + Duration::from_secs(2)), None);
        assert_eq!(log.warn(900, 500, t0 + WARN_EVERY), Some(2));
        assert_eq!(log.warn(900, 500, t0 + WARN_EVERY), None);
    }
}
