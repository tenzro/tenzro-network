//! The model catalog this node serves.
//!
//! The catalog is the set of signed entries whose signing key's account holds
//! a catalog publisher bond in chain state, with no upheld catalog fault against
//! it: anyone who bonds publishes, and an
//! entry whose pinned bytes its source does not hold is a catalog fault that
//! slashes that bond. An operator may narrow what its own node serves to the
//! publishers it names (`catalog_publishers`); naming one never admits a
//! publisher that holds no bond. The catalog is re-assembled from
//! the trust ledger whenever a catalog entry or an issuer
//! revocation arrives, and periodically so bonds that change take effect,
//! and installed in place, so a newly published model is served without a
//! rebuild or a restart.
//!
//! Two recognised publishers that describe one model differently are a
//! conflict, and the model is left out until they agree or one withdraws:
//! the node never picks one silently.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Serialize;
use tenzro_trust::TrustLedger;
use tenzro_trust::catalog::CatalogRecord;
use tenzro_trust::ledger::RecordKind;

/// How often the catalog is re-assembled regardless of trust records, so a
/// publisher whose DID the identity registry revokes drops out.
pub const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a rebuild requested by a new record waits for more to arrive.
pub const REFRESH_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(500);

/// A published model the node does not serve, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refused {
    pub model: String,
    pub publishers: Vec<String>,
    pub reason: String,
}

/// What the node's catalog is assembled from and what it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CatalogStatus {
    /// The publishers the operator named, if it narrowed the catalog to some.
    pub named_publishers: Vec<String>,
    /// The publishers the catalog is assembled from: those whose entries are
    /// signed by a bonded account, narrowed to the operator's named publishers
    /// when it set any, not revoked.
    pub publishers: Vec<String>,
    /// Number of entries served.
    pub entries: usize,
    pub refused: Vec<Refused>,
    /// Set when the catalog is empty by configuration, saying what to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type DidRevoked = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Whether chain state stands behind an entry now: `(signing account,
/// document digest)` is admitted when the account holds a catalog publisher
/// bond and no catalog fault against the entry was upheld.
pub type ChainAdmits = Arc<dyn Fn(&[u8; 32], &str) -> bool + Send + Sync>;

/// Assembles and installs the catalog from the trust ledger.
pub struct CatalogSync {
    ledger: Arc<TrustLedger>,
    named: BTreeSet<String>,
    admits: ChainAdmits,
    did_revoked: DidRevoked,
    status: RwLock<CatalogStatus>,
    /// The node's catalog, which every rebuild replaces.
    cell: tenzro_model::CatalogCell,
    /// Wakes the background rebuild task; set once it is running.
    wake: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
    /// The signing account of each record read at the last rebuild.
    signers: SignerCache,
}

/// The account whose key signed each catalog record, by record digest.
///
/// A record's digest covers the signed document, so its signer never changes;
/// checking the signature again at every rebuild only spent the time. Each
/// rebuild keeps the entries of the records it read and drops the rest, so
/// the cache holds no more entries than the catalog has records.
#[derive(Default)]
struct SignerCache(parking_lot::Mutex<std::collections::HashMap<String, Option<[u8; 32]>>>);

impl SignerCache {
    /// The signing accounts of `records`, verifying with `verify` only the
    /// records not seen at the last rebuild; afterwards the cache holds
    /// exactly these records.
    fn accounts(
        &self,
        records: &[CatalogRecord],
        verify: impl Fn(&CatalogRecord) -> Option<[u8; 32]>,
    ) -> Vec<Option<[u8; 32]>> {
        let mut known = self.0.lock();
        let mut kept = std::collections::HashMap::with_capacity(records.len());
        let accounts = records
            .iter()
            .map(|r| {
                let account = known
                    .remove(&r.digest)
                    .or_else(|| kept.get(&r.digest).copied())
                    .unwrap_or_else(|| verify(r));
                kept.insert(r.digest.clone(), account);
                account
            })
            .collect();
        *known = kept;
        accounts
    }
}

impl CatalogSync {
    pub fn new(
        ledger: Arc<TrustLedger>,
        named: Vec<String>,
        admits: ChainAdmits,
        did_revoked: DidRevoked,
        cell: tenzro_model::CatalogCell,
    ) -> Self {
        CatalogSync {
            ledger,
            named: named.into_iter().filter(|o| !o.is_empty()).collect(),
            admits,
            did_revoked,
            status: RwLock::new(CatalogStatus::default()),
            cell,
            wake: std::sync::OnceLock::new(),
            signers: SignerCache::default(),
        }
    }

    /// The catalog as this sync last installed it.
    pub fn catalog(&self) -> std::sync::Arc<tenzro_model::Catalog> {
        self.cell.current()
    }

    /// Whether a newly applied record of `kind` can change the catalog.
    pub fn affected_by(kind: RecordKind) -> bool {
        matches!(
            kind,
            RecordKind::CatalogEntry | RecordKind::IssuerRevocation
        )
    }

    pub fn status(&self) -> CatalogStatus {
        self.status.read().clone()
    }

    /// Re-assemble the catalog from the ledger and install it.
    pub fn refresh(&self) -> CatalogStatus {
        let (catalog, status) = self.assemble(CatalogRecord::signer_account);
        self.cell.install(catalog);
        if *self.status.read() != status {
            tracing::info!(
                entries = status.entries,
                publishers = status.publishers.len(),
                refused = status.refused.len(),
                "model catalog installed"
            );
            for r in &status.refused {
                tracing::warn!(model = %r.model, reason = %r.reason, "published model not served");
            }
        }
        *self.status.write() = status.clone();
        status
    }

    /// The catalog the ledger's records make now, with `verify` naming the
    /// signing account of each record not seen at the last rebuild.
    fn assemble(
        &self,
        verify: impl Fn(&CatalogRecord) -> Option<[u8; 32]>,
    ) -> (tenzro_model::catalog::Catalog, CatalogStatus) {
        let mut status = CatalogStatus {
            named_publishers: self.named.iter().cloned().collect(),
            ..Default::default()
        };
        let chosen: BTreeSet<String> = if self.named.is_empty() {
            self.ledger.publishers_with_entries()
        } else {
            self.named.clone()
        };
        let publishers: BTreeSet<String> = chosen
            .into_iter()
            .filter(|p| !self.ledger.issuer_revoked(p) && !(self.did_revoked)(p))
            .collect();
        // Only a record whose signing key's account holds a catalog publisher
        // bond, and against which no catalog fault was upheld, counts: the
        // bond is what an upheld fault slashes.
        let read = self.ledger.catalog_records(&publishers);
        let accounts = self.signers.accounts(&read, verify);
        let records: Vec<CatalogRecord> = read
            .into_iter()
            .zip(accounts)
            .filter(|(r, account)| account.is_some_and(|a| (self.admits)(&a, &r.digest)))
            .map(|(r, _)| r)
            .collect();
        status.publishers = records
            .iter()
            .map(|r| r.publisher.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if status.publishers.is_empty() && status.note.is_none() {
            status.note = Some(
                "no publisher holding a catalog publisher bond has published to this node: the catalog \
                 is empty until one does"
                    .into(),
            );
        }

        let mut by_model: BTreeMap<String, Vec<CatalogRecord>> = BTreeMap::new();
        for r in records {
            by_model.entry(r.model.clone()).or_default().push(r);
        }
        let mut entries = Vec::new();
        let mut publishers_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (model, records) in by_model {
            let live: Vec<&CatalogRecord> = records.iter().filter(|r| r.entry.is_some()).collect();
            let Some(first) = live.first() else { continue };
            let names: Vec<String> = live.iter().map(|r| r.publisher.clone()).collect();
            let digests: BTreeSet<Option<String>> = live.iter().map(|r| r.entry_digest()).collect();
            if digests.len() > 1 {
                status.refused.push(Refused {
                    model,
                    publishers: names,
                    reason: "the trusted publishers describe this model differently".into(),
                });
                continue;
            }
            let Some(body) = first.entry.clone() else {
                continue;
            };
            match serde_json::from_value::<tenzro_model::catalog::CatalogEntry>(body) {
                Ok(e) => {
                    publishers_of.insert(model, names);
                    entries.push(e);
                }
                Err(e) => status.refused.push(Refused {
                    model,
                    publishers: names,
                    reason: format!("not understood by this node's engines: {e}"),
                }),
            }
        }
        let (catalog, errors) = tenzro_model::catalog::Catalog::build(entries);
        for e in errors {
            status.refused.push(Refused {
                publishers: publishers_of.remove(&e.id).unwrap_or_default(),
                model: e.id,
                reason: e.reason,
            });
        }
        status.entries = catalog.len();
        (catalog, status)
    }

    /// Ask for the catalog to be re-assembled. With the background task
    /// running (see [`Self::spawn_periodic`]) this only wakes it, so a burst of
    /// records, one per model, costs one rebuild rather than one each; without
    /// it the catalog is rebuilt here, at once.
    pub fn request_refresh(&self) {
        match self.wake.get() {
            Some(wake) => wake.notify_one(),
            None => {
                self.refresh();
            }
        }
    }

    /// Re-assemble the catalog every [`REFRESH_INTERVAL`], and shortly after
    /// [`Self::request_refresh`]. The rebuild verifies every entry's signature
    /// and reads chain state for each, so it runs on the blocking pool, never
    /// on an async worker that serves RPC and consensus.
    pub fn spawn_periodic(self: &Arc<Self>) {
        let sync = Arc::clone(self);
        let wake = Arc::new(tokio::sync::Notify::new());
        let _ = self.wake.set(wake.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REFRESH_INTERVAL);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = wake.notified() => {
                        // Let the rest of a burst arrive; they share this rebuild.
                        tokio::time::sleep(REFRESH_DEBOUNCE).await;
                    }
                }
                let s = Arc::clone(&sync);
                if let Err(e) = tokio::task::spawn_blocking(move || s.refresh()).await {
                    tracing::warn!(error = %e, "model catalog rebuild failed");
                }
            }
        });
    }
}

/// Whether `model_id` is under a non-commercial licence. Such a model is
/// never charged for: a node may serve it, but not sell it. The registry row
/// answers for a registered model, the catalog entry for any other.
pub fn non_commercial(node: &crate::node::TenzroNode, model_id: &str) -> bool {
    let registered = node
        .model_registry()
        .and_then(|r| r.get_model(model_id).ok())
        .map(|info| info.license_tier);
    let tier = registered.or_else(|| {
        node.catalog()
            .entry(model_id)
            .map(|e| e.licence.effective_tier())
    });
    tier.is_some_and(|t| !t.permits_paid_use())
}

#[cfg(test)]
mod tests {
    use super::{CatalogRecord, CatalogSync, SignerCache, TrustLedger};
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;
    use tenzro_catalog::{
        CatalogEntry, Component, HfModelEntry, Licence, LicenseTier, ModelSpec, Source,
    };
    use tenzro_crypto::p256::{P256KeyPair, P256Signer};
    use tenzro_trust::proof::{
        ProofRequest, attach_hardware, machine_did, options, signing_digest,
    };

    fn record(digest: &str) -> CatalogRecord {
        CatalogRecord {
            digest: digest.into(),
            publisher: "did:example:p".into(),
            model: "m".into(),
            sequence: 1,
            entry: None,
            document: serde_json::Value::Null,
        }
    }

    /// A rebuild verifies only the records it has not seen; a record that
    /// leaves the catalog leaves the cache, and is verified again if it
    /// comes back.
    #[test]
    fn a_second_rebuild_does_not_verify_again() {
        let cache = SignerCache::default();
        let checks = AtomicUsize::new(0);
        let verify = |_: &CatalogRecord| {
            checks.fetch_add(1, Ordering::Relaxed);
            Some([1u8; 32])
        };
        let both = [record("a"), record("b")];
        assert_eq!(cache.accounts(&both, verify), [Some([1u8; 32]); 2]);
        assert_eq!(checks.load(Ordering::Relaxed), 2);

        cache.accounts(&both, verify);
        assert_eq!(
            checks.load(Ordering::Relaxed),
            2,
            "nothing is verified again"
        );

        cache.accounts(&[record("a")], verify);
        assert_eq!(cache.0.lock().len(), 1, "a record that left is dropped");
        cache.accounts(&both, verify);
        assert_eq!(
            checks.load(Ordering::Relaxed),
            3,
            "only the returning record"
        );
    }

    fn publisher() -> P256Signer {
        P256Signer::from_keypair(&P256KeyPair::from_secret_bytes(&[42; 32]).unwrap())
    }

    fn sign(key: &P256Signer, doc: Value) -> Value {
        let opts = options(&ProofRequest {
            signer_did: machine_did(&key.public_key_sec1()),
            public_key_sec1: key.public_key_sec1(),
            purpose: "assertionMethod".into(),
            created: "2026-11-16T00:00:00Z".into(),
            rp_id: None,
        });
        let digest = signing_digest(&doc, &opts);
        let sig: [u8; 64] = key.sign_prehash(&digest).as_bytes().try_into().unwrap();
        attach_hardware(doc, opts, &sig)
    }

    /// A distinct GGUF entry, its own repository and file.
    fn entry(n: usize) -> CatalogEntry {
        let id = format!("scale-{n}");
        let repo = format!("publisher/{id}");
        let file = format!("{id}.Q4_K_M.gguf");
        CatalogEntry {
            model: ModelSpec::Gguf(HfModelEntry {
                id: id.clone(),
                name: id,
                family: "test".into(),
                hf_repo: repo.clone(),
                hf_filename: file.clone(),
                parameters: "1B".into(),
                context_length: 4096,
                quantization: "Q4_K_M".into(),
                size_bytes: 4,
                min_ram_gb: 1,
                promotable: true,
                ..Default::default()
            }),
            licence: Licence {
                name: "Apache-2.0".into(),
                id: None,
                tier: LicenseTier::Permissive,
                conditions: None,
                components: Vec::new(),
            },
            gated: false,
            components: vec![Component {
                repo,
                path: file,
                source: Source::Hub {
                    revision: "0123456789abcdef0123456789abcdef01234567".into(),
                },
                size: 4,
                sha256: "a".repeat(64),
                at: None,
            }],
            capabilities: vec![],
            capability_priors: Default::default(),
            moe_source: None,
            requires: Vec::new(),
        }
    }

    /// A rebuild of `n` published entries checks each record's signature
    /// once; the next rebuild checks none. The work is counted rather than
    /// timed, so a loaded machine cannot fail the test; the times are printed.
    #[test]
    fn a_second_rebuild_of_a_large_catalog_verifies_no_signature() {
        let n = 1_000;
        let key = publisher();
        let did = machine_did(&key.public_key_sec1());
        let ledger = TrustLedger::new();
        for i in 0..n {
            let e = entry(i);
            let body = serde_json::to_value(&e).unwrap();
            ledger
                .apply(&sign(
                    &key,
                    CatalogRecord::unsigned(&did, e.id(), 1, Some(&body)),
                ))
                .unwrap();
        }
        let sync = CatalogSync::new(
            Arc::new(ledger),
            Vec::new(),
            Arc::new(|_, _| true),
            Arc::new(|_| false),
            tenzro_model::CatalogCell::default(),
        );
        let checks = AtomicUsize::new(0);
        let verify = |r: &CatalogRecord| {
            checks.fetch_add(1, Ordering::Relaxed);
            r.signer_account()
        };

        let started = Instant::now();
        let (_, first) = sync.assemble(verify);
        let took = started.elapsed();
        assert_eq!(first.entries, n);
        assert_eq!(checks.swap(0, Ordering::Relaxed), n, "each record once");

        let started = Instant::now();
        let (_, again) = sync.assemble(verify);
        eprintln!(
            "catalog rebuild: {n} entries in {took:?}, again in {:?}",
            started.elapsed()
        );
        assert_eq!(again.entries, n);
        assert_eq!(
            checks.load(Ordering::Relaxed),
            0,
            "nothing is verified again"
        );
    }
}
