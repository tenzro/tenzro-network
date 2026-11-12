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
    /// Wakes the background rebuild task; set once it is running.
    wake: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
}

impl CatalogSync {
    pub fn new(
        ledger: Arc<TrustLedger>,
        named: Vec<String>,
        admits: ChainAdmits,
        did_revoked: DidRevoked,
    ) -> Self {
        CatalogSync {
            ledger,
            named: named.into_iter().filter(|o| !o.is_empty()).collect(),
            admits,
            did_revoked,
            status: RwLock::new(CatalogStatus::default()),
            wake: std::sync::OnceLock::new(),
        }
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
        let records: Vec<CatalogRecord> = self
            .ledger
            .catalog_records(&publishers)
            .into_iter()
            .filter(|r| {
                r.signer_account()
                    .is_some_and(|a| (self.admits)(&a, &r.digest))
            })
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
        tenzro_model::catalog::store::install(catalog);
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
    let tier = registered
        .or_else(|| tenzro_model::catalog::entry(model_id).map(|e| e.licence.effective_tier()));
    tier.is_some_and(|t| !t.permits_paid_use())
}
