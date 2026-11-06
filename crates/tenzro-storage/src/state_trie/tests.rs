use super::capture::Writes;
use super::hashing::Subtree;
use super::proof::{ProofError, verify_state_proof};
use super::snapshot::{BUCKET_COUNT, root_from_buckets, verify_bucket};
use super::*;
use crate::MemoryStore;
use tenzro_types::hash_scheme::HashScheme::{self, Sha256 as S256};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn trie() -> (Arc<MemoryStore>, StateTrie) {
    let store = Arc::new(MemoryStore::new());
    let trie = StateTrie::new(store.clone());
    (store, trie)
}

fn entry(ns: &str, key: &[u8], value: &[u8]) -> Entry {
    Entry {
        namespace: ns.to_string(),
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

fn apply(model: &mut BTreeMap<(String, Vec<u8>), Vec<u8>>, writes: &Writes) {
    for ((ns, k), v) in writes {
        match v {
            Some(v) => {
                model.insert((ns.clone(), k.clone()), v.clone());
            }
            None => {
                model.remove(&(ns.clone(), k.clone()));
            }
        }
    }
}

fn model_root(model: &BTreeMap<(String, Vec<u8>), Vec<u8>>) -> Hash {
    let entries: Vec<Entry> = model.iter().map(|((ns, k), v)| entry(ns, k, v)).collect();
    root_of_entries(S256, entries.iter())
}

#[test]
fn an_empty_trie_has_the_zero_root() {
    let (_s, t) = trie();
    let root = t.commit(0, &Writes::new()).unwrap();
    assert_eq!(root, Hash::new(EMPTY));
    assert_eq!(t.root_at(0).unwrap(), Some(root));
}

#[test]
fn incremental_updates_match_a_rebuild_from_scratch() {
    let (_s, t) = trie();
    let mut model = BTreeMap::new();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let namespaces = [CF_ACCOUNTS, CF_STATE, CF_AGENTS, NS_EPOCH];
    for version in 0..40u64 {
        let mut writes = Writes::new();
        for _ in 0..(rng.next() % 12) {
            let ns = namespaces[(rng.next() % 4) as usize];
            let key = (rng.next() % 64).to_le_bytes().to_vec();
            let value = if rng.next().is_multiple_of(4) {
                None
            } else {
                Some(rng.next().to_le_bytes().to_vec())
            };
            writes.insert((ns.to_string(), key), value);
        }
        apply(&mut model, &writes);
        let root = t.commit(version, &writes).unwrap();
        assert_eq!(
            root,
            model_root(&model),
            "root diverged at version {version}"
        );
    }
}

#[test]
fn the_root_does_not_depend_on_write_order() {
    let writes: Vec<Writes> = (0..3)
        .map(|i| {
            let mut w = Writes::new();
            for k in 0..20u64 {
                if k % 3 == i {
                    w.insert(
                        (CF_ACCOUNTS.to_string(), k.to_le_bytes().to_vec()),
                        Some(vec![k as u8; 5]),
                    );
                }
            }
            w
        })
        .collect();
    let (_a, ta) = trie();
    let (_b, tb) = trie();
    for (v, w) in writes.iter().enumerate() {
        ta.commit(v as u64, w).unwrap();
    }
    for (v, w) in writes.iter().rev().enumerate() {
        tb.commit(v as u64, w).unwrap();
    }
    assert_eq!(ta.root_at(2).unwrap(), tb.root_at(2).unwrap());
}

fn populated(
    n: u64,
) -> (
    Arc<MemoryStore>,
    StateTrie,
    BTreeMap<(String, Vec<u8>), Vec<u8>>,
) {
    let (s, t) = trie();
    let mut model = BTreeMap::new();
    let mut writes = Writes::new();
    for k in 0..n {
        writes.insert(
            (CF_ACCOUNTS.to_string(), format!("balance:{k}").into_bytes()),
            Some((k as u128 * 1_000).to_le_bytes().to_vec()),
        );
    }
    apply(&mut model, &writes);
    t.commit(1, &writes).unwrap();
    (s, t, model)
}

#[test]
fn a_present_entry_proves_and_verifies() {
    let (_s, t, model) = populated(200);
    let root = t.root_at(1).unwrap().unwrap();
    for ((ns, k), v) in model.iter().take(50) {
        let (value, proof) = t.prove(1, ns, k).unwrap();
        assert_eq!(value.as_ref(), Some(v));
        verify_state_proof(S256, &root.0, ns, k, Some(v), &proof).unwrap();
    }
}

#[test]
fn an_absent_entry_proves_absence() {
    let (_s, t, _m) = populated(200);
    let root = t.root_at(1).unwrap().unwrap();
    for k in 1000..1050u64 {
        let key = format!("balance:{k}").into_bytes();
        let (value, proof) = t.prove(1, CF_ACCOUNTS, &key).unwrap();
        assert!(value.is_none());
        verify_state_proof(S256, &root.0, CF_ACCOUNTS, &key, None, &proof).unwrap();
    }
}

#[test]
fn a_proof_does_not_verify_a_different_value() {
    let (_s, t, _m) = populated(64);
    let root = t.root_at(1).unwrap().unwrap();
    let key = b"balance:7".to_vec();
    let (_, proof) = t.prove(1, CF_ACCOUNTS, &key).unwrap();
    let forged = 1_000_000u128.to_le_bytes();
    assert!(matches!(
        verify_state_proof(S256, &root.0, CF_ACCOUNTS, &key, Some(&forged), &proof),
        Err(ProofError::RootMismatch { .. })
    ));
    // Nor absence of an entry that is present.
    assert!(verify_state_proof(S256, &root.0, CF_ACCOUNTS, &key, None, &proof).is_err());
}

#[test]
fn a_proof_does_not_verify_under_another_root() {
    let (_s, t, _m) = populated(64);
    let key = b"balance:7".to_vec();
    let (value, proof) = t.prove(1, CF_ACCOUNTS, &key).unwrap();
    let other = [9u8; 32];
    assert!(verify_state_proof(S256, &other, CF_ACCOUNTS, &key, value.as_deref(), &proof).is_err());
}

#[test]
fn a_proof_for_one_key_does_not_verify_another() {
    let (_s, t, model) = populated(64);
    let root = t.root_at(1).unwrap().unwrap();
    let (_, proof) = t.prove(1, CF_ACCOUNTS, b"balance:7").unwrap();
    let v8 = model
        .get(&(CF_ACCOUNTS.to_string(), b"balance:8".to_vec()))
        .unwrap();
    assert!(
        verify_state_proof(S256, &root.0, CF_ACCOUNTS, b"balance:8", Some(v8), &proof).is_err()
    );
}

#[test]
fn old_versions_stay_provable_after_later_updates() {
    let (_s, t, _m) = populated(32);
    let root1 = t.root_at(1).unwrap().unwrap();
    let key = b"balance:3".to_vec();
    let mut w = Writes::new();
    w.insert(
        (CF_ACCOUNTS.to_string(), key.clone()),
        Some(b"new".to_vec()),
    );
    let root2 = t.commit(2, &w).unwrap();
    assert_ne!(root1, root2);

    let (v1, p1) = t.prove(1, CF_ACCOUNTS, &key).unwrap();
    assert_eq!(v1, Some(3_000u128.to_le_bytes().to_vec()));
    verify_state_proof(S256, &root1.0, CF_ACCOUNTS, &key, v1.as_deref(), &p1).unwrap();
    let (v2, p2) = t.prove(2, CF_ACCOUNTS, &key).unwrap();
    assert_eq!(v2, Some(b"new".to_vec()));
    verify_state_proof(S256, &root2.0, CF_ACCOUNTS, &key, v2.as_deref(), &p2).unwrap();
}

#[test]
fn pruning_keeps_retained_versions_and_drops_the_rest() {
    let (s, t) = trie();
    for v in 0..20u64 {
        let mut w = Writes::new();
        for k in 0..8u64 {
            w.insert(
                (CF_STATE.to_string(), k.to_le_bytes().to_vec()),
                Some((v * 100 + k).to_le_bytes().to_vec()),
            );
        }
        t.commit(v, &w).unwrap();
    }
    let count = |s: &MemoryStore| s.get_keys_with_prefix(CF_STATE_TRIE, b"").unwrap().len();
    let before = count(&s);
    let removed = t.prune(15).unwrap();
    assert!(removed > 0);
    assert!(count(&s) < before);
    assert!(t.root_at(14).unwrap().is_none());
    for v in 15..20u64 {
        let root = t.root_at(v).unwrap().unwrap();
        for k in 0..8u64 {
            let key = k.to_le_bytes();
            let (value, proof) = t.prove(v, CF_STATE, &key).unwrap();
            assert_eq!(value, Some((v * 100 + k).to_le_bytes().to_vec()));
            verify_state_proof(S256, &root.0, CF_STATE, &key, value.as_deref(), &proof).unwrap();
        }
    }
}

#[test]
fn a_version_cannot_go_backwards() {
    let (_s, t, _m) = populated(4);
    assert!(t.commit(0, &Writes::new()).is_err());
}

#[test]
fn an_uncommitted_namespace_is_refused() {
    let (_s, t) = trie();
    let mut w = Writes::new();
    w.insert(("blocks".to_string(), b"k".to_vec()), Some(b"v".to_vec()));
    assert!(t.commit(0, &w).is_err());
}

#[test]
fn bucket_summaries_fold_to_the_root_and_each_bucket_verifies() {
    let (_s, t, _m) = populated(3_000);
    let root = t.root_at(1).unwrap().unwrap();
    let buckets = t.bucket_summaries(1).unwrap();
    assert!(buckets.len() > 100);
    assert!(buckets.iter().all(|b| b.index < BUCKET_COUNT));
    assert_eq!(root_from_buckets(S256, &buckets).unwrap(), root);
    for b in &buckets {
        let entries = t.bucket_entries(1, b.index).unwrap();
        verify_bucket(S256, b.index, &entries, &b.subtree).unwrap();
    }
}

#[test]
fn a_tampered_bucket_is_refused() {
    let (_s, t, _m) = populated(3_000);
    let buckets = t.bucket_summaries(1).unwrap();
    let b = buckets
        .iter()
        .find(|b| t.bucket_entries(1, b.index).unwrap().len() > 1)
        .unwrap();
    let entries = t.bucket_entries(1, b.index).unwrap();

    let mut changed = entries.clone();
    changed[0].value = b"forged".to_vec();
    assert!(verify_bucket(S256, b.index, &changed, &b.subtree).is_err());

    let mut dropped = entries.clone();
    dropped.pop();
    assert!(verify_bucket(S256, b.index, &dropped, &b.subtree).is_err());

    let mut reordered = entries.clone();
    reordered.swap(0, 1);
    assert!(verify_bucket(S256, b.index, &reordered, &b.subtree).is_err());

    // An entry from another bucket cannot be smuggled in.
    let other = buckets.iter().find(|o| o.index != b.index).unwrap();
    let mut smuggled = entries.clone();
    smuggled.extend(t.bucket_entries(1, other.index).unwrap());
    assert!(verify_bucket(S256, b.index, &smuggled, &b.subtree).is_err());
}

#[test]
fn a_forged_manifest_does_not_fold_to_the_root() {
    let (_s, t, _m) = populated(500);
    let root = t.root_at(1).unwrap().unwrap();
    let mut buckets = t.bucket_summaries(1).unwrap();
    buckets[0].subtree = Subtree::Single([5u8; 32]);
    assert_ne!(root_from_buckets(S256, &buckets).unwrap(), root);
}

#[test]
fn a_snapshot_imported_bucket_by_bucket_reproduces_the_root() {
    let (_s, src, _m) = populated(2_000);
    let root = src.root_at(1).unwrap().unwrap();
    let (_d, dst) = trie();
    // Import in reverse bucket order to show order does not matter.
    for b in src.bucket_summaries(1).unwrap().iter().rev() {
        let entries = src.bucket_entries(1, b.index).unwrap();
        verify_bucket(S256, b.index, &entries, &b.subtree).unwrap();
        let mut w = Writes::new();
        for e in entries {
            w.insert((e.namespace, e.key), Some(e.value));
        }
        dst.commit(1, &w).unwrap();
    }
    assert_eq!(dst.root_at(1).unwrap(), Some(root));
}

/// A chain crosses a state trie hash switch: versions 1 to 5 commit under
/// SHA-256, version 6 re-commits the whole state under SHA3-256 and takes
/// its block's writes, and versions 7 and 8 continue under SHA3-256.
/// Earlier roots are the ones a chain that never switched has, every root
/// from the switch on is the SHA3-256 root of the state alone, proofs at
/// either side verify under their own scheme, and replaying the same writes
/// from genesis with the same switch gives the same root at every version.
#[test]
fn a_chain_crosses_a_trie_hash_switch_and_replay_from_genesis_verifies() {
    let ns = crate::CF_ACCOUNTS;
    let writes_at = |v: u64| {
        let mut w = Writes::new();
        for i in 0..6u64 {
            w.insert(
                (
                    ns.to_string(),
                    format!("acct-{}", (v * 3 + i) % 11).into_bytes(),
                ),
                Some(format!("balance {v}:{i}").into_bytes()),
            );
        }
        if v == 7 {
            w.insert((ns.to_string(), b"acct-2".to_vec()), None);
        }
        w
    };
    let run = |switch: bool| {
        let t = StateTrie::new(Arc::new(MemoryStore::new()) as Arc<dyn KvStore>);
        let mut roots = Vec::new();
        for v in 1..=8u64 {
            if switch && v == 6 {
                t.recommit_under(6, HashScheme::Sha3_256).unwrap();
            }
            roots.push(t.commit(v, &writes_at(v)).unwrap());
        }
        (t, roots)
    };
    let (switched, roots) = run(true);
    let (_, plain) = run(false);
    let (_, replayed) = run(true);
    assert_eq!(
        roots[..5],
        plain[..5],
        "roots before the switch are unchanged"
    );
    assert_ne!(roots[5], plain[5]);
    assert_eq!(
        roots, replayed,
        "replay from genesis gives every root again"
    );
    for v in 6..=8u64 {
        let mut entries = Vec::new();
        switched
            .for_each_entry(v, 0, &[0u8; 31], &mut |e| {
                entries.push(e);
                Ok(())
            })
            .unwrap();
        let independent = super::root_of_entries(HashScheme::Sha3_256, &entries);
        assert_eq!(roots[v as usize - 1], independent, "version {v}");
        assert_eq!(switched.scheme_at(v).unwrap(), HashScheme::Sha3_256);
    }
    assert_eq!(switched.scheme_at(5).unwrap(), HashScheme::Sha256);
    for (v, scheme) in [(3u64, HashScheme::Sha256), (8, HashScheme::Sha3_256)] {
        let key = b"acct-1";
        let (value, proof) = switched.prove(v, ns, key).unwrap();
        let root = roots[v as usize - 1].0;
        verify_state_proof(scheme, &root, ns, key, value.as_deref(), &proof).unwrap();
        let other = if scheme == HashScheme::Sha256 {
            HashScheme::Sha3_256
        } else {
            HashScheme::Sha256
        };
        assert!(verify_state_proof(other, &root, ns, key, value.as_deref(), &proof).is_err());
    }
}

/// A trie re-committed under SHA3-256 is snapshotted after the switch: every
/// bucket rebuilds its summary and the summaries fold to the root, under the
/// scheme the trie holds at that version.
#[test]
fn a_snapshot_after_a_trie_hash_switch_verifies_under_its_scheme() {
    let ns = crate::CF_ACCOUNTS;
    let (_, t) = trie();
    let mut w = Writes::new();
    for i in 0..40u32 {
        w.insert(
            (ns.to_string(), format!("acct-{i}").into_bytes()),
            Some(vec![i as u8; 9]),
        );
    }
    t.commit(1, &w).unwrap();
    t.recommit_under(2, HashScheme::Sha3_256).unwrap();
    let root = t.commit(2, &Writes::new()).unwrap();
    assert_eq!(t.scheme_at(2).unwrap(), HashScheme::Sha3_256);
    let summaries = t.bucket_summaries(2).unwrap();
    assert!(summaries.len() > 1);
    for s in &summaries {
        let entries = t.bucket_entries(2, s.index).unwrap();
        verify_bucket(HashScheme::Sha3_256, s.index, &entries, &s.subtree).unwrap();
        assert!(verify_bucket(S256, s.index, &entries, &s.subtree).is_err());
    }
    assert_eq!(
        root_from_buckets(HashScheme::Sha3_256, &summaries).unwrap(),
        root
    );
    assert_ne!(root_from_buckets(S256, &summaries).unwrap(), root);
}

/// A node restoring that snapshot adopts the scheme before committing the
/// buckets, and reproduces the root; without adopting it, it does not.
#[test]
fn a_restored_snapshot_after_a_switch_reproduces_the_root() {
    let ns = crate::CF_ACCOUNTS;
    let (_, src) = trie();
    let mut w = Writes::new();
    for i in 0..40u32 {
        w.insert(
            (ns.to_string(), format!("acct-{i}").into_bytes()),
            Some(vec![i as u8; 9]),
        );
    }
    src.commit(1, &w).unwrap();
    src.recommit_under(2, HashScheme::Sha3_256).unwrap();
    let root = src.commit(2, &Writes::new()).unwrap();
    let restore = |adopt: bool| {
        let (_, dst) = trie();
        if adopt {
            dst.adopt_scheme(2, HashScheme::Sha3_256).unwrap();
        }
        for s in src.bucket_summaries(2).unwrap() {
            let mut bw = Writes::new();
            for e in src.bucket_entries(2, s.index).unwrap() {
                bw.insert((e.namespace, e.key), Some(e.value));
            }
            dst.commit(2, &bw).unwrap();
        }
        dst.root_at(2).unwrap()
    };
    assert_eq!(restore(true), Some(root));
    assert_ne!(restore(false), Some(root));
    let (_, later) = trie();
    later.commit(5, &Writes::new()).unwrap();
    assert!(later.adopt_scheme(3, HashScheme::Sha3_256).is_err());
}
