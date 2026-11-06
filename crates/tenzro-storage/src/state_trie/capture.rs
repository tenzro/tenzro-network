//! Recording the writes a block's execution makes, so they can be committed.
//!
//! The trie commits what executing a block wrote, not whatever a column family
//! happens to hold: several column families are shared between block execution
//! and node-local writers (RPC handlers, caches, mirrors), and only the former
//! is the same on every node. A [`WriteSet`] is installed for the duration of
//! execution; every successful write that the store performs while it is
//! installed, to a committed column family, is recorded into it.
//!
//! Installation is scoped to the executing task ([`in_task`]) or, for work the
//! executor hands to a blocking thread, to that thread ([`in_thread`]). Writes
//! from any other task or thread, including concurrent RPC handlers on the same
//! store, are not recorded.

use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

/// Last write per `(namespace, key)`: `Some(value)` for a put, `None` for a
/// delete.
pub type Writes = BTreeMap<(String, Vec<u8>), Option<Vec<u8>>>;

/// Writes recorded while installed. Later writes to the same entry replace
/// earlier ones.
#[derive(Debug, Default)]
pub struct WriteSet {
    writes: Mutex<Writes>,
}

impl WriteSet {
    /// A new, empty set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records a write.
    pub fn record(&self, namespace: &str, key: &[u8], value: Option<&[u8]>) {
        self.writes.lock().insert(
            (namespace.to_string(), key.to_vec()),
            value.map(<[u8]>::to_vec),
        );
    }

    /// Takes everything recorded so far, leaving the set empty.
    pub fn take(&self) -> Writes {
        std::mem::take(&mut *self.writes.lock())
    }
}

tokio::task_local! {
    static TASK_WRITES: Arc<WriteSet>;
}

thread_local! {
    static THREAD_WRITES: RefCell<Option<Arc<WriteSet>>> = const { RefCell::new(None) };
}

/// Runs `fut` with `set` installed for the current task.
pub async fn in_task<F: Future>(set: Arc<WriteSet>, fut: F) -> F::Output {
    TASK_WRITES.scope(set, fut).await
}

/// Runs `f` with `set` installed for the current thread.
pub fn in_thread<R>(set: Arc<WriteSet>, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Arc<WriteSet>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            THREAD_WRITES.with(|slot| *slot.borrow_mut() = prev);
        }
    }
    let prev = THREAD_WRITES.with(|slot| slot.borrow_mut().replace(set));
    let _restore = Restore(prev);
    f()
}

/// Called by the store after a successful write.
pub(crate) fn record(cf: &str, key: &[u8], value: Option<&[u8]>) {
    if !super::is_committed_cf(cf) {
        return;
    }
    if TASK_WRITES
        .try_with(|set| set.record(cf, key, value))
        .is_ok()
    {
        return;
    }
    THREAD_WRITES.with(|slot| {
        if let Some(set) = slot.borrow().as_ref() {
            set.record(cf, key, value);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CF_ACCOUNTS, CF_BLOCKS, KvStore, MemoryStore};

    #[tokio::test]
    async fn only_the_installed_task_is_recorded() {
        let store = Arc::new(MemoryStore::new());
        let set = WriteSet::new();

        // A concurrent writer on the same store, outside the scope.
        let other = {
            let store = store.clone();
            tokio::spawn(async move {
                store.put(CF_ACCOUNTS, b"rpc", b"local").unwrap();
            })
        };
        in_task(set.clone(), async {
            store.put(CF_ACCOUNTS, b"a", b"1").unwrap();
            store.put(CF_ACCOUNTS, b"a", b"2").unwrap();
            store.delete(CF_ACCOUNTS, b"b").unwrap();
            // Not a committed column family.
            store.put(CF_BLOCKS, b"x", b"y").unwrap();
        })
        .await;
        other.await.unwrap();

        let writes = set.take();
        assert_eq!(writes.len(), 2);
        assert_eq!(
            writes.get(&(CF_ACCOUNTS.to_string(), b"a".to_vec())),
            Some(&Some(b"2".to_vec()))
        );
        assert_eq!(
            writes.get(&(CF_ACCOUNTS.to_string(), b"b".to_vec())),
            Some(&None)
        );
    }

    #[test]
    fn a_thread_scope_records_and_is_removed_after() {
        let store = MemoryStore::new();
        let set = WriteSet::new();
        in_thread(set.clone(), || {
            store.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        });
        store.put(CF_ACCOUNTS, b"after", b"1").unwrap();
        let writes = set.take();
        assert_eq!(writes.len(), 1);
    }
}
