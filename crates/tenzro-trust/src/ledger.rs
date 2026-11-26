//! The trust ledger: every trust record, re-verified on arrival.
//!
//! Each record carries its own proof, so the ledger never trusts whoever
//! delivered it. The state only grows or moves forward: credentials and
//! observations accumulate, a revoked bit never clears, a
//! policy is only replaced by a higher sequence from the same key. Records
//! can therefore arrive in any order, from any peer, and every holder that
//! has seen the same records computes the same state.

use std::collections::BTreeSet;
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;
use serde_json::Value;
use tenzro_storage::kv::{CF_CREDENTIALS, KvStore};

use crate::catalog::{CATALOG_ENTRY_TYPE, CatalogRecord};
use crate::credential::{CREDENTIAL_TYPE, Credential, CredentialState, Subject};
use crate::manifest::{MANIFEST_TYPE, ModelManifest};
use crate::origin::{ORIGIN_TYPE, OriginAttestation, ProvenanceStatus};
use crate::policy::{
    IdentityKeyReceipts, OperatorPolicy, POLICY_TYPE, ProvenViolation, VIOLATION_TYPE,
    verify_violation_with,
};
use crate::release::{ENGINE_RELEASE_TYPE, EngineRelease};
use crate::status_list::{
    ISSUER_REVOCATION_TYPE, IssuerRevocation, REVOCATION_TYPE, Revocation, status_list_document,
};
use crate::{Result, TrustError, has_type, invalid, record_digest};

const KEY_PREFIX: &str = "trust/";

/// The identity that authored `doc`: the DID the record names as its issuer,
/// operator, observer or publisher, whose signature over the record has been
/// verified here. `None` for the two kinds nobody authors: a model manifest is
/// named by the hash of its own content, and violation evidence is proven by
/// the operator's signatures inside it, whoever hands it in.
pub fn author(doc: &Value) -> Result<Option<String>> {
    Ok(match RecordKind::of(doc)? {
        RecordKind::Credential => Some(Credential::parse(doc)?.issuer),
        RecordKind::Revocation => Some(Revocation::parse(doc)?.issuer),
        RecordKind::IssuerRevocation => Some(IssuerRevocation::parse(doc)?.issuer),
        RecordKind::Policy => Some(OperatorPolicy::parse(doc)?.operator),
        RecordKind::Origin => Some(OriginAttestation::parse(doc)?.observer),
        RecordKind::CatalogEntry => Some(CatalogRecord::parse(doc)?.publisher),
        RecordKind::EngineRelease => Some(EngineRelease::parse(doc)?.publisher),
        RecordKind::Manifest | RecordKind::Violation => None,
    })
}

/// What kind of record was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKind {
    Credential,
    Revocation,
    IssuerRevocation,
    Policy,
    Manifest,
    Origin,
    Violation,
    CatalogEntry,
    EngineRelease,
}

impl RecordKind {
    fn key_segment(self) -> &'static str {
        match self {
            RecordKind::Credential => "credential",
            RecordKind::Revocation => "revocation",
            RecordKind::IssuerRevocation => "issuer-revocation",
            RecordKind::Policy => "policy",
            RecordKind::Manifest => "manifest",
            RecordKind::Origin => "origin",
            RecordKind::Violation => "violation",
            RecordKind::CatalogEntry => "catalog-entry",
            RecordKind::EngineRelease => "engine-release",
        }
    }

    /// Classify a document by its `type`.
    pub fn of(doc: &Value) -> Result<Self> {
        let kinds = [
            (CREDENTIAL_TYPE, RecordKind::Credential),
            (REVOCATION_TYPE, RecordKind::Revocation),
            (ISSUER_REVOCATION_TYPE, RecordKind::IssuerRevocation),
            (POLICY_TYPE, RecordKind::Policy),
            (MANIFEST_TYPE, RecordKind::Manifest),
            (ORIGIN_TYPE, RecordKind::Origin),
            (VIOLATION_TYPE, RecordKind::Violation),
            (CATALOG_ENTRY_TYPE, RecordKind::CatalogEntry),
            (ENGINE_RELEASE_TYPE, RecordKind::EngineRelease),
        ];
        kinds
            .iter()
            .find(|(t, _)| has_type(doc, t))
            .map(|(_, k)| *k)
            .ok_or_else(|| invalid("not a trust record type"))
    }
}

/// The outcome of applying one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub kind: RecordKind,
    /// The record's digest (for a manifest, its root; for a violation, its id).
    pub key: String,
    /// False when the ledger already held this record.
    pub new: bool,
    /// Set when the record proved a policy violation for the first time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation: Option<ProvenViolation>,
}

/// Most manifests kept for one model name.
pub const MAX_MANIFESTS_PER_NAME: usize = 16;
/// Most manifests kept that no origin attestation names yet, and their bytes.
/// They are held in memory only, oldest dropped first.
pub const MAX_UNREFERENCED_MANIFESTS: usize = 1024;
pub const MAX_UNREFERENCED_MANIFEST_BYTES: usize = 64 << 20;

/// A manifest kept in memory until an origin attestation names its model.
struct Unreferenced {
    digest: String,
    root: String,
    name: String,
    bytes: usize,
    doc: Value,
}

/// Every trust record this holder has seen.
///
/// A model manifest is unsigned: anyone may hand one in. It is usable at
/// once, but it is kept on disk only when an origin attestation, which its
/// author signed, names the model. Until then it is one of a bounded number
/// held in memory, and the oldest is dropped when the bound is reached. A
/// model name holds at most [`MAX_MANIFESTS_PER_NAME`] manifests.
#[derive(Default)]
pub struct TrustLedger {
    store: Option<Arc<dyn KvStore>>,
    seen: DashMap<String, ()>,
    unreferenced: std::sync::Mutex<std::collections::VecDeque<Unreferenced>>,
    credentials: DashMap<String, Credential>,
    by_subject: DashMap<String, BTreeSet<String>>,
    revoked: DashMap<String, BTreeSet<u32>>,
    revocation_docs: DashMap<String, Vec<Value>>,
    issuer_revocations: DashMap<String, IssuerRevocation>,
    policies: DashMap<String, Vec<OperatorPolicy>>,
    manifests: DashMap<String, ModelManifest>,
    roots_by_name: DashMap<String, BTreeSet<String>>,
    origins: DashMap<String, Vec<OriginAttestation>>,
    violations: DashMap<String, ProvenViolation>,
    /// The latest catalog record of each (publisher, model).
    catalog: DashMap<(String, String), CatalogRecord>,
    /// Each (publisher, version) release. A version is published once.
    releases: DashMap<(String, String), EngineRelease>,
    /// The check of receipts signed with an identity key, in violation
    /// evidence. Without it such a receipt proves nothing here.
    identity_keys: Option<IdentityKeyReceipts>,
}

impl TrustLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// A ledger persisted in `store`, reloaded from it. Every stored record
    /// is verified again on load, receipts signed with an identity key by
    /// `identity_keys`; a record that does not verify yet (the chain view
    /// behind) stays in the store and is judged again on the next load.
    pub fn with_storage(
        store: Arc<dyn KvStore>,
        identity_keys: Option<IdentityKeyReceipts>,
    ) -> Result<Self> {
        let ledger = TrustLedger {
            store: None,
            identity_keys,
            ..Default::default()
        };
        let rows = store
            .scan_prefix(CF_CREDENTIALS, KEY_PREFIX.as_bytes())
            .map_err(|e| TrustError::Storage(e.to_string()))?;
        let mut docs: Vec<Value> = rows
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        // Origin attestations load before the manifests they made durable;
        // violations are judged against policies, so they load last.
        docs.sort_by_key(|d| match RecordKind::of(d) {
            Ok(RecordKind::Origin) => 0,
            Ok(RecordKind::Manifest) => 2,
            Ok(RecordKind::Violation) | Err(_) => 3,
            Ok(_) => 1,
        });
        for d in &docs {
            if let Err(e) = ledger.apply(d) {
                tracing::warn!(error = %e, "stored trust record no longer verifies; skipped");
            }
        }
        Ok(TrustLedger {
            store: Some(store),
            ..ledger
        })
    }

    fn persist(&self, kind: RecordKind, digest: &str, doc: &Value) -> Result<()> {
        if let Some(store) = &self.store {
            let key = format!("{KEY_PREFIX}{}/{digest}", kind.key_segment());
            let bytes = serde_json::to_vec(doc).map_err(|e| TrustError::Storage(e.to_string()))?;
            store
                .put(CF_CREDENTIALS, key.as_bytes(), &bytes)
                .map_err(|e| TrustError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    /// Whether the ledger already holds `doc`.
    pub fn holds(&self, doc: &Value) -> bool {
        self.seen.contains_key(&record_digest(doc))
    }

    /// Verify `doc` and fold it into the ledger.
    pub fn apply(&self, doc: &Value) -> Result<Applied> {
        let kind = RecordKind::of(doc)?;
        let digest = record_digest(doc);
        if self.seen.contains_key(&digest) {
            return Ok(Applied {
                kind,
                key: digest,
                new: false,
                violation: None,
            });
        }
        let mut key = digest.clone();
        let mut violation = None;
        match kind {
            RecordKind::Credential => {
                let c = Credential::parse(doc)?;
                self.by_subject
                    .entry(c.subject.id())
                    .or_default()
                    .insert(c.digest.clone());
                self.credentials.insert(c.digest.clone(), c);
            }
            RecordKind::Revocation => {
                let r = Revocation::parse(doc)?;
                self.revoked
                    .entry(r.issuer.clone())
                    .or_default()
                    .extend(r.indices.iter().copied());
                self.revocation_docs
                    .entry(r.issuer.clone())
                    .or_default()
                    .push(r.document);
            }
            RecordKind::IssuerRevocation => {
                let r = IssuerRevocation::parse(doc)?;
                self.issuer_revocations.entry(r.issuer.clone()).or_insert(r);
            }
            RecordKind::Policy => {
                let p = OperatorPolicy::parse(doc)?;
                let mut history = self.policies.entry(p.operator.clone()).or_default();
                if history.iter().any(|h| h.sequence == p.sequence) {
                    return Err(TrustError::Stale(format!(
                        "{} already published policy sequence {}",
                        p.operator, p.sequence
                    )));
                }
                history.push(p);
            }
            RecordKind::Manifest => {
                let m = ModelManifest::from_json(doc)?;
                key = m.root_hex();
                let named = self.roots_by_name.get(&m.name).map_or(0, |r| r.len());
                if named >= MAX_MANIFESTS_PER_NAME {
                    return Err(TrustError::Stale(format!(
                        "{} already has {MAX_MANIFESTS_PER_NAME} manifests",
                        m.name
                    )));
                }
                let referenced = self.origins.contains_key(&m.name);
                let name = m.name.clone();
                self.roots_by_name
                    .entry(name.clone())
                    .or_default()
                    .insert(key.clone());
                self.manifests.insert(key.clone(), m);
                if !referenced {
                    self.seen.insert(digest.clone(), ());
                    self.hold(digest, key.clone(), name, doc);
                    return Ok(Applied {
                        kind,
                        key,
                        new: true,
                        violation: None,
                    });
                }
            }
            RecordKind::Origin => {
                let a = OriginAttestation::parse(doc)?;
                let name = a.name.clone();
                self.origins.entry(name.clone()).or_default().push(a);
                self.keep_manifests_named(&name)?;
            }
            RecordKind::Violation => {
                let operator = doc
                    .pointer("/policy/operator")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("the evidence names no operator"))?;
                let history = self.policies(operator);
                let v = verify_violation_with(doc, &history, self.identity_keys.as_ref())?;
                if !history.iter().any(|p| p.digest == v.policy) {
                    return Err(invalid("the policy in the evidence was never published"));
                }
                key = v.id.clone();
                if self.violations.contains_key(&key) {
                    return Ok(Applied {
                        kind,
                        key,
                        new: false,
                        violation: None,
                    });
                }
                self.violations.insert(key.clone(), v.clone());
                violation = Some(v);
            }
            RecordKind::CatalogEntry => {
                let r = CatalogRecord::parse(doc)?;
                let slot = (r.publisher.clone(), r.model.clone());
                if let Some(existing) = self.catalog.get(&slot)
                    && existing.sequence >= r.sequence
                {
                    return Err(TrustError::Stale(format!(
                        "{} already published {} at sequence {}",
                        r.publisher, r.model, existing.sequence
                    )));
                }
                self.catalog.insert(slot, r);
            }
            RecordKind::EngineRelease => {
                let r = EngineRelease::parse(doc)?;
                let slot = (r.publisher.clone(), r.version.clone());
                if self.releases.contains_key(&slot) {
                    return Err(invalid(format!(
                        "{} already published release {}",
                        r.publisher, r.version
                    )));
                }
                self.releases.insert(slot, r);
            }
        }
        self.persist(kind, &digest, doc)?;
        self.seen.insert(digest, ());
        Ok(Applied {
            kind,
            key,
            new: true,
            violation,
        })
    }

    /// Hold a manifest no origin attestation names yet, dropping the oldest
    /// held while the count or the bytes are above their bound.
    fn hold(&self, digest: String, root: String, name: String, doc: &Value) {
        let bytes = serde_json::to_vec(doc).map_or(0, |b| b.len());
        let mut held = self.unreferenced.lock().unwrap_or_else(|e| e.into_inner());
        held.push_back(Unreferenced {
            digest,
            root,
            name,
            bytes,
            doc: doc.clone(),
        });
        let mut total: usize = held.iter().map(|h| h.bytes).sum();
        while held.len() > MAX_UNREFERENCED_MANIFESTS || total > MAX_UNREFERENCED_MANIFEST_BYTES {
            let Some(old) = held.pop_front() else { break };
            total -= old.bytes;
            self.manifests.remove(&old.root);
            if let Some(mut roots) = self.roots_by_name.get_mut(&old.name) {
                roots.remove(&old.root);
            }
            self.seen.remove(&old.digest);
        }
    }

    /// Keep on disk every held manifest of `name`, now that an origin
    /// attestation names it.
    fn keep_manifests_named(&self, name: &str) -> Result<()> {
        let kept: Vec<Unreferenced> = {
            let mut held = self.unreferenced.lock().unwrap_or_else(|e| e.into_inner());
            let (kept, rest): (Vec<_>, Vec<_>) = held.drain(..).partition(|h| h.name == name);
            held.extend(rest);
            kept
        };
        for h in kept {
            self.persist(RecordKind::Manifest, &h.digest, &h.doc)?;
        }
        Ok(())
    }

    /// How many manifests are held in memory, waiting for an origin.
    pub fn unreferenced_manifests(&self) -> usize {
        self.unreferenced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Where `c` stands at `now`. `did_revoked` reports DIDs revoked outside
    /// the trust ledger (the identity registry); their credentials fail too.
    pub fn state(
        &self,
        c: &Credential,
        now: chrono::DateTime<chrono::Utc>,
        did_revoked: &dyn Fn(&str) -> bool,
    ) -> CredentialState {
        if self.issuer_revocations.contains_key(&c.issuer) || did_revoked(&c.issuer) {
            return CredentialState::IssuerRevoked;
        }
        if self
            .revoked
            .get(&c.issuer)
            .is_some_and(|set| set.contains(&c.status_index))
        {
            return CredentialState::Revoked;
        }
        c.time_state(now)
    }

    pub fn credential(&self, digest: &str) -> Option<Credential> {
        self.credentials.get(digest).map(|c| c.clone())
    }

    /// Every credential stated about `subject`.
    pub fn credentials_for(&self, subject: &Subject) -> Vec<Credential> {
        self.by_subject
            .get(&subject.id())
            .map(|set| set.iter().filter_map(|d| self.credential(d)).collect())
            .unwrap_or_default()
    }

    /// The credentials about `subject` that are valid at `now`.
    pub fn valid_credentials_for(
        &self,
        subject: &Subject,
        now: chrono::DateTime<chrono::Utc>,
        did_revoked: &dyn Fn(&str) -> bool,
    ) -> Vec<Credential> {
        self.credentials_for(subject)
            .into_iter()
            .filter(|c| self.state(c, now, did_revoked) == CredentialState::Valid)
            .collect()
    }

    /// Every policy `operator` has published, in sequence order.
    pub fn policies(&self, operator: &str) -> Vec<OperatorPolicy> {
        let mut v = self
            .policies
            .get(operator)
            .map(|h| h.clone())
            .unwrap_or_default();
        v.sort_by_key(|p| p.sequence);
        v
    }

    /// The policy in force for `operator` at `at`: the highest sequence whose
    /// window contains `at`.
    pub fn policy_in_force(
        &self,
        operator: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<OperatorPolicy> {
        self.policies(operator)
            .into_iter()
            .filter(|p| p.valid_from <= at && at <= p.valid_until)
            .max_by_key(|p| p.sequence)
    }

    /// The policy in force at `at` of the operator that bound the identity
    /// whose P-256 point is `public_key` as a receipt key. A key bound by two operators' policies in force
    /// names neither.
    pub fn policy_for_receipt_key(
        &self,
        public_key: &[u8],
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<OperatorPolicy> {
        let operators: Vec<String> = self.policies.iter().map(|h| h.key().clone()).collect();
        let mut found = operators.iter().filter_map(|op| {
            self.policy_in_force(op, at)
                .filter(|p| p.signs_with(public_key))
        });
        let first = found.next()?;
        found.next().is_none().then_some(first)
    }

    pub fn manifest(&self, root: &str) -> Option<ModelManifest> {
        self.manifests.get(root).map(|m| m.clone())
    }

    pub fn manifests_named(&self, name: &str) -> Vec<ModelManifest> {
        self.roots_by_name
            .get(name)
            .map(|roots| roots.iter().filter_map(|r| self.manifest(r)).collect())
            .unwrap_or_default()
    }

    /// A manifest, its observations and how well they corroborate it.
    pub fn provenance(
        &self,
        root: &str,
    ) -> Option<(ModelManifest, Vec<OriginAttestation>, ProvenanceStatus)> {
        let m = self.manifest(root)?;
        let atts = self
            .origins
            .get(&m.name)
            .map(|a| a.clone())
            .unwrap_or_default();
        let status = ProvenanceStatus::compute(&m, &atts);
        Some((m, atts, status))
    }

    /// A file of a model, taken from a manifest published under `name` that
    /// is verified under the network default rule and lists `path`. When
    /// several verified manifests list the file, they must agree on it.
    pub fn verified_entry(&self, name: &str, path: &str) -> Option<(String, crate::FileEntry)> {
        let mut found: Option<(String, crate::FileEntry)> = None;
        for m in self.manifests_named(name) {
            let root = m.root_hex();
            let Some(entry) = m.file(path).cloned() else {
                continue;
            };
            if !self.provenance(&root).is_some_and(|(_, _, s)| s.verified()) {
                continue;
            }
            match &found {
                None => found = Some((root, entry)),
                Some((_, prev)) if *prev == entry => {}
                Some(_) => return None,
            }
        }
        found
    }

    /// The manifest published under `name` that is verified under the
    /// network default rule, if exactly one is.
    pub fn verified_manifest_named(&self, name: &str) -> Option<ModelManifest> {
        let mut verified = self.manifests_named(name).into_iter().filter(|m| {
            self.provenance(&m.root_hex())
                .is_some_and(|(_, _, s)| s.verified())
        });
        let first = verified.next()?;
        verified.next().is_none().then_some(first)
    }

    /// The issuer's status list document.
    pub fn status_list(&self, issuer: &str) -> Value {
        let revoked = self
            .revoked
            .get(issuer)
            .map(|r| r.clone())
            .unwrap_or_default();
        let docs = self
            .revocation_docs
            .get(issuer)
            .map(|d| d.clone())
            .unwrap_or_default();
        let issuer_rev = self
            .issuer_revocations
            .get(issuer)
            .map(|r| r.document.clone());
        status_list_document(issuer, &revoked, &docs, issuer_rev.as_ref())
    }

    /// The verdict on `subject` under `requirements` at `now`: the
    /// requirements its valid credentials do not meet and, for an operator,
    /// every policy violation proven against it. An operator with a proven
    /// violation fails whatever credentials it holds.
    pub fn verdict(
        &self,
        requirements: &crate::requirements::TrustRequirements,
        subject: &Subject,
        now: chrono::DateTime<chrono::Utc>,
        did_revoked: &dyn Fn(&str) -> bool,
    ) -> crate::requirements::Verdict {
        let valid = self.valid_credentials_for(subject, now, did_revoked);
        let mut verdict = requirements.evaluate(subject, &valid);
        if let Subject::Operator(operator) = subject {
            let mut proven: Vec<String> = self
                .violations_of(operator)
                .into_iter()
                .map(|v| format!("no proven policy violation (violation {})", v.id))
                .collect();
            proven.sort();
            if !proven.is_empty() {
                verdict.passed = false;
                verdict.unmet.extend(proven);
            }
        }
        verdict
    }

    pub fn violations_of(&self, operator: &str) -> Vec<ProvenViolation> {
        self.violations
            .iter()
            .filter(|v| v.operator == operator)
            .map(|v| v.clone())
            .collect()
    }

    /// Whether `issuer` has revoked its own key.
    pub fn issuer_revoked(&self, issuer: &str) -> bool {
        self.issuer_revocations.contains_key(issuer)
    }

    /// Every release `publishers` have published, newest version first.
    pub fn engine_releases(&self, publishers: &BTreeSet<String>) -> Vec<EngineRelease> {
        let mut out: Vec<EngineRelease> = self
            .releases
            .iter()
            .filter(|r| publishers.contains(&r.key().0))
            .map(|r| r.value().clone())
            .collect();
        out.sort_by(|a, b| {
            crate::release::parse_version(&b.version)
                .cmp(&crate::release::parse_version(&a.version))
                .then_with(|| a.publisher.cmp(&b.publisher))
        });
        out
    }

    /// Every DID that has published a catalog record to this ledger.
    pub fn publishers_with_entries(&self) -> BTreeSet<String> {
        self.catalog.iter().map(|r| r.key().0.clone()).collect()
    }

    /// The latest catalog record of every model each of `publishers` has
    /// published, withdrawals included, in (model, publisher) order.
    pub fn catalog_records(&self, publishers: &BTreeSet<String>) -> Vec<CatalogRecord> {
        let mut out: Vec<CatalogRecord> = self
            .catalog
            .iter()
            .filter(|r| publishers.contains(&r.key().0))
            .map(|r| r.value().clone())
            .collect();
        out.sort_by(|a, b| (&a.model, &a.publisher).cmp(&(&b.model, &b.publisher)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::ClaimKind;
    use crate::credential::tests::{claim, issue, model, t};
    use crate::manifest::tests::sample;
    use crate::origin::{ObservedFile, OriginKind};
    use crate::policy::tests::{ReceiptSigner, policy_doc};
    use crate::policy::{Clause, violation_evidence};
    use crate::proof::testkit::TestKey;
    use crate::status_list::{bit_is_set, decode_list};

    fn never(_: &str) -> bool {
        false
    }

    /// The author of each record kind, one test per kind.
    mod author_of {
        use super::*;
        use crate::release::Artifact;

        #[test]
        fn a_credential_is_its_issuers() {
            let k = TestKey::new(1);
            let claim = claim(ClaimKind::Certification, "iso-iec-42001", None);
            let doc = issue(&k, &model(1), &claim, 42);
            assert_eq!(author(&doc).unwrap(), Some(k.did()));
        }

        #[test]
        fn a_revocation_is_its_issuers() {
            let k = TestKey::new(2);
            let doc = k.sign(Revocation::unsigned(&k.did(), &[42], now()));
            assert_eq!(author(&doc).unwrap(), Some(k.did()));
        }

        #[test]
        fn an_issuer_revocation_is_the_issuers_own() {
            let k = TestKey::new(3);
            let doc = k.sign(IssuerRevocation::unsigned(&k.did(), now(), "lost"));
            assert_eq!(author(&doc).unwrap(), Some(k.did()));
        }

        #[test]
        fn a_policy_is_its_operators() {
            let op = TestKey::new(4);
            let rs = ReceiptSigner::new();
            let doc = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
            assert_eq!(author(&doc).unwrap(), Some(op.did()));
        }

        #[test]
        fn an_origin_attestation_is_its_observers() {
            let k = TestKey::new(5);
            let m = sample("org/model");
            let files: Vec<ObservedFile> = m
                .files
                .iter()
                .map(|f| ObservedFile {
                    path: f.path.clone(),
                    size: f.size,
                    sha256: f.sha256.clone(),
                    blake3: Some(f.blake3.clone()),
                })
                .collect();
            let doc = k.sign(OriginAttestation::unsigned(
                &k.did(),
                OriginKind::Mirror,
                "https://a.example/m",
                &m.name,
                &files,
                now(),
            ));
            assert_eq!(author(&doc).unwrap(), Some(k.did()));
        }

        #[test]
        fn a_catalog_entry_is_its_publishers() {
            let k = TestKey::new(6);
            let body = serde_json::json!({"model": {"engine": "gguf", "spec": {"id": "m"}}});
            let doc = k.sign(CatalogRecord::unsigned(&k.did(), "m", 1, Some(&body)));
            assert_eq!(author(&doc).unwrap(), Some(k.did()));
        }

        #[test]
        fn an_engine_release_is_its_publishers() {
            let k = TestKey::new(7);
            let artifact = Artifact {
                platform: "x86_64-linux".into(),
                size: 10,
                sha256: "a".repeat(64),
                blake3: "b".repeat(64),
            };
            let doc = k.sign(EngineRelease::unsigned(&k.did(), "1.4.0", &[artifact]));
            assert_eq!(author(&doc).unwrap(), Some(k.did()));
        }

        #[test]
        fn a_manifest_has_no_author() {
            assert_eq!(author(&sample("org/model").to_json()).unwrap(), None);
        }

        #[test]
        fn violation_evidence_has_no_author() {
            let op = TestKey::new(8);
            let rs = ReceiptSigner::new();
            let policy = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
            let receipt = rs.receipt("other", "DE", "2026-02-01T00:00:00Z");
            let evidence = violation_evidence(&policy, &receipt, Clause::ServesModels);
            assert_eq!(author(&evidence).unwrap(), None);
        }

        #[test]
        fn a_record_signed_by_another_key_has_no_author_to_name() {
            let (k, other) = (TestKey::new(9), TestKey::new(10));
            let forged = other.sign(Revocation::unsigned(&k.did(), &[1], now()));
            assert!(author(&forged).is_err());
            assert!(author(&serde_json::json!({"type": ["Unknown"]})).is_err());
        }
    }
    fn now() -> chrono::DateTime<chrono::Utc> {
        t("2026-09-24T00:00:00Z")
    }

    #[test]
    fn a_revoked_credential_stops_being_valid() {
        let ledger = TrustLedger::new();
        let issuer = TestKey::new(1);
        ledger
            .apply(&issue(
                &issuer,
                &model(1),
                &claim(ClaimKind::Certification, "iso-iec-42001", None),
                42,
            ))
            .unwrap();
        assert_eq!(
            ledger.valid_credentials_for(&model(1), now(), &never).len(),
            1
        );

        let rev = issuer.sign(Revocation::unsigned(&issuer.did(), &[42], now()));
        ledger.apply(&rev).unwrap();
        assert!(
            ledger
                .valid_credentials_for(&model(1), now(), &never)
                .is_empty()
        );
        let c = &ledger.credentials_for(&model(1))[0];
        assert_eq!(ledger.state(c, now(), &never), CredentialState::Revoked);

        let sl = ledger.status_list(&issuer.did());
        let bits = decode_list(sl["credentialSubject"]["encodedList"].as_str().unwrap()).unwrap();
        assert!(bit_is_set(&bits, 42) && !bit_is_set(&bits, 41));
    }

    #[test]
    fn a_revoked_issuer_invalidates_everything_it_signed() {
        let ledger = TrustLedger::new();
        let issuer = TestKey::new(1);
        ledger
            .apply(&issue(
                &issuer,
                &model(1),
                &claim(ClaimKind::Certification, "x", None),
                1,
            ))
            .unwrap();
        ledger
            .apply(&issue(
                &issuer,
                &model(2),
                &claim(ClaimKind::Rating, "y", Some(1)),
                2,
            ))
            .unwrap();
        ledger
            .apply(&issuer.sign(IssuerRevocation::unsigned(
                &issuer.did(),
                now(),
                "key compromised",
            )))
            .unwrap();
        for m in [model(1), model(2)] {
            assert!(ledger.valid_credentials_for(&m, now(), &never).is_empty());
        }
        // The identity registry revoking the issuer's DID has the same effect.
        let other = TestKey::new(3);
        ledger
            .apply(&issue(
                &other,
                &model(3),
                &claim(ClaimKind::Certification, "x", None),
                1,
            ))
            .unwrap();
        let other_did = other.did();
        let revoked_elsewhere = move |d: &str| d == other_did;
        assert!(
            ledger
                .valid_credentials_for(&model(3), now(), &revoked_elsewhere)
                .is_empty()
        );
    }

    #[test]
    fn nobody_but_the_issuer_can_revoke() {
        let ledger = TrustLedger::new();
        let issuer = TestKey::new(1);
        ledger
            .apply(&issue(
                &issuer,
                &model(1),
                &claim(ClaimKind::Certification, "x", None),
                7,
            ))
            .unwrap();
        let attacker = TestKey::new(9);
        assert!(
            ledger
                .apply(&attacker.sign(Revocation::unsigned(&issuer.did(), &[7], now())))
                .is_err()
        );
        assert!(
            ledger
                .apply(&attacker.sign(IssuerRevocation::unsigned(&issuer.did(), now(), "x")))
                .is_err()
        );
        assert_eq!(
            ledger.valid_credentials_for(&model(1), now(), &never).len(),
            1
        );
    }

    #[test]
    fn a_catalog_entry_is_replaced_only_by_its_publisher_at_a_higher_sequence() {
        use crate::catalog::CatalogRecord;
        let ledger = TrustLedger::new();
        let (p, q) = (TestKey::new(7), TestKey::new(8));
        let body = |temp: &str| serde_json::json!({"model": {"engine": "gguf", "spec": {"id": "m", "t": temp}}});
        let entry = |k: &TestKey, seq, b: Option<serde_json::Value>| {
            k.sign(CatalogRecord::unsigned(&k.did(), "m", seq, b.as_ref()))
        };
        ledger.apply(&entry(&p, 2, Some(body("a")))).unwrap();
        assert!(ledger.apply(&entry(&p, 1, Some(body("b")))).is_err());
        ledger.apply(&entry(&q, 1, Some(body("c")))).unwrap();

        let only_p: BTreeSet<String> = [p.did()].into();
        let records = ledger.catalog_records(&only_p);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, 2);
        assert_eq!(ledger.catalog_records(&BTreeSet::new()).len(), 0);

        ledger.apply(&entry(&p, 3, None)).unwrap();
        assert!(ledger.catalog_records(&only_p)[0].entry.is_none());
    }

    #[test]
    fn provenance_requires_corroborated_files() {
        let ledger = TrustLedger::new();
        let m = sample("org/model");
        ledger.apply(&m.to_json()).unwrap();
        let (_, _, before) = ledger.provenance(&m.root_hex()).unwrap();
        assert!(!before.verified());

        let files: Vec<ObservedFile> = m
            .files
            .iter()
            .map(|f| ObservedFile {
                path: f.path.clone(),
                size: f.size,
                sha256: f.sha256.clone(),
                blake3: Some(f.blake3.clone()),
            })
            .collect();
        for (seed, loc) in [(11u8, "https://a.example/m"), (12, "https://b.example/m")] {
            let k = TestKey::new(seed);
            ledger
                .apply(&k.sign(OriginAttestation::unsigned(
                    &k.did(),
                    OriginKind::Mirror,
                    loc,
                    &m.name,
                    &files,
                    now(),
                )))
                .unwrap();
        }
        let (_, _, after) = ledger.provenance(&m.root_hex()).unwrap();
        assert!(after.verified());
        assert_eq!(
            ledger.verified_manifest_named("org/model").unwrap().root(),
            m.root()
        );
    }

    #[test]
    fn a_file_entry_is_taken_only_from_a_verified_manifest() {
        let ledger = TrustLedger::new();
        let m = sample("org/model");
        ledger.apply(&m.to_json()).unwrap();
        let path = m.files[0].path.clone();
        assert!(
            ledger.verified_entry("org/model", &path).is_none(),
            "an uncorroborated manifest lists nothing"
        );

        let files: Vec<ObservedFile> = m
            .files
            .iter()
            .map(|f| ObservedFile {
                path: f.path.clone(),
                size: f.size,
                sha256: f.sha256.clone(),
                blake3: Some(f.blake3.clone()),
            })
            .collect();
        let observe = |seed: u8, loc: &str| {
            let k = TestKey::new(seed);
            ledger
                .apply(&k.sign(OriginAttestation::unsigned(
                    &k.did(),
                    OriginKind::Mirror,
                    loc,
                    &m.name,
                    &files,
                    now(),
                )))
                .unwrap();
        };
        observe(11, "https://a.example/m");
        assert!(
            ledger.verified_entry("org/model", &path).is_none(),
            "one origin is not enough"
        );
        observe(12, "https://b.example/m");
        let (root, entry) = ledger.verified_entry("org/model", &path).unwrap();
        assert_eq!(root, m.root_hex());
        assert_eq!(entry, m.files[0]);
        assert!(
            ledger
                .verified_entry("org/model", "not-in-the-model")
                .is_none()
        );
        assert!(ledger.verified_entry("other/model", &path).is_none());
    }

    #[test]
    fn a_violation_is_proven_once_and_only_against_a_published_policy() {
        let ledger = TrustLedger::new();
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let policy = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
        let receipt = rs.receipt("other", "DE", "2026-02-01T00:00:00Z");
        let evidence = violation_evidence(&policy, &receipt, Clause::ServesModels);
        assert!(
            ledger.apply(&evidence).is_err(),
            "the policy was never published"
        );

        ledger.apply(&policy).unwrap();
        let first = ledger.apply(&evidence).unwrap();
        assert!(first.new && first.violation.is_some());
        let again = ledger.apply(&evidence).unwrap();
        assert!(!again.new && again.violation.is_none());
        // Repackaging the same receipt (different JSON key order) is still one violation.
        let repacked: Value =
            serde_json::from_str(&serde_json::to_string_pretty(&evidence).unwrap()).unwrap();
        let mut reordered = serde_json::Map::new();
        for k in ["clause", "receipt", "policy", "type"] {
            reordered.insert(k.into(), repacked[k].clone());
        }
        let third = ledger.apply(&Value::Object(reordered)).unwrap();
        assert!(third.violation.is_none());
        assert_eq!(ledger.violations_of(&op.did()).len(), 1);
    }

    #[test]
    fn a_proven_violation_fails_the_operators_verdict() {
        let ledger = TrustLedger::new();
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let policy = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
        ledger.apply(&policy).unwrap();
        let subject = Subject::Operator(op.did());
        let none = crate::requirements::TrustRequirements::default();
        let now = chrono::Utc::now();
        assert!(ledger.verdict(&none, &subject, now, &|_| false).passed);

        let receipt = rs.receipt("other", "DE", "2026-02-01T00:00:00Z");
        ledger
            .apply(&violation_evidence(&policy, &receipt, Clause::ServesModels))
            .unwrap();
        let verdict = ledger.verdict(&none, &subject, now, &|_| false);
        assert!(!verdict.passed);
        assert_eq!(verdict.unmet.len(), 1);
        assert!(
            verdict.unmet[0].contains("violation"),
            "{:?}",
            verdict.unmet
        );
        // Another operator is untouched by it.
        let other = Subject::Operator(TestKey::new(2).did());
        assert!(ledger.verdict(&none, &other, now, &|_| false).passed);
    }

    #[test]
    fn a_ledger_says_whether_it_holds_a_record() {
        let ledger = TrustLedger::new();
        let k = TestKey::new(1);
        let doc = k.sign(Revocation::unsigned(&k.did(), &[42], now()));
        assert!(!ledger.holds(&doc));
        ledger.apply(&doc).unwrap();
        assert!(ledger.holds(&doc));
    }

    fn manifest(name: &str, n: usize) -> ModelManifest {
        let bytes = n.to_le_bytes();
        ModelManifest::new(
            name,
            vec![crate::manifest::tests::entry("model.gguf", &bytes)],
        )
        .unwrap()
    }

    fn origin_naming(name: &str, m: &ModelManifest, seed: u8) -> Value {
        let files: Vec<ObservedFile> = m
            .files
            .iter()
            .map(|f| ObservedFile {
                path: f.path.clone(),
                size: f.size,
                sha256: f.sha256.clone(),
                blake3: Some(f.blake3.clone()),
            })
            .collect();
        let k = TestKey::new(seed);
        k.sign(OriginAttestation::unsigned(
            &k.did(),
            OriginKind::Mirror,
            "https://a.example/m",
            name,
            &files,
            now(),
        ))
    }

    #[test]
    fn a_manifest_no_origin_names_is_usable_but_kept_only_in_memory() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::kv::MemoryStore::new());
        let held = manifest("org/held", 1);
        let named = manifest("org/named", 2);
        {
            let ledger = TrustLedger::with_storage(store.clone(), None).unwrap();
            assert!(ledger.apply(&held.to_json()).unwrap().new);
            assert!(ledger.apply(&named.to_json()).unwrap().new);
            assert!(ledger.provenance(&held.root_hex()).is_some());
            assert_eq!(ledger.unreferenced_manifests(), 2);
            // An origin that names one makes it durable.
            ledger
                .apply(&origin_naming("org/named", &named, 31))
                .unwrap();
            assert_eq!(ledger.unreferenced_manifests(), 1);
            // Handed in again, a held manifest is not new.
            assert!(!ledger.apply(&held.to_json()).unwrap().new);
        }
        let reloaded = TrustLedger::with_storage(store, None).unwrap();
        assert!(reloaded.provenance(&named.root_hex()).is_some());
        assert!(reloaded.provenance(&held.root_hex()).is_none());
    }

    #[test]
    fn the_oldest_unreferenced_manifest_is_dropped_at_the_bound() {
        let ledger = TrustLedger::new();
        let first = manifest("org/m0", 0);
        ledger.apply(&first.to_json()).unwrap();
        for i in 1..=MAX_UNREFERENCED_MANIFESTS {
            ledger
                .apply(&manifest(&format!("org/m{i}"), i).to_json())
                .unwrap();
        }
        assert_eq!(ledger.unreferenced_manifests(), MAX_UNREFERENCED_MANIFESTS);
        assert!(ledger.provenance(&first.root_hex()).is_none());
        assert!(ledger.manifests_named("org/m0").is_empty());
        let last = manifest(
            &format!("org/m{MAX_UNREFERENCED_MANIFESTS}"),
            MAX_UNREFERENCED_MANIFESTS,
        );
        assert!(ledger.provenance(&last.root_hex()).is_some());
        // Dropped, it can be handed in again.
        assert!(ledger.apply(&first.to_json()).unwrap().new);
    }

    #[test]
    fn a_model_name_holds_a_bounded_number_of_manifests() {
        let ledger = TrustLedger::new();
        for i in 0..MAX_MANIFESTS_PER_NAME {
            ledger.apply(&manifest("org/one", i).to_json()).unwrap();
        }
        let err = ledger
            .apply(&manifest("org/one", MAX_MANIFESTS_PER_NAME).to_json())
            .unwrap_err();
        assert!(err.to_string().contains("already has"), "{err}");
        // The same manifest again is not a new one.
        assert!(!ledger.apply(&manifest("org/one", 0).to_json()).unwrap().new);
    }

    #[test]
    fn a_ledger_reloads_and_reverifies_its_records() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::kv::MemoryStore::new());
        let issuer = TestKey::new(1);
        let op = TestKey::new(4);
        let rs = ReceiptSigner::new();
        {
            let ledger = TrustLedger::with_storage(store.clone(), None).unwrap();
            ledger
                .apply(&issue(
                    &issuer,
                    &model(1),
                    &claim(ClaimKind::Certification, "x", None),
                    1,
                ))
                .unwrap();
            let policy = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
            ledger.apply(&policy).unwrap();
            ledger
                .apply(&violation_evidence(
                    &policy,
                    &rs.receipt("z", "DE", "2026-02-01T00:00:00Z"),
                    Clause::ServesModels,
                ))
                .unwrap();
        }
        let reloaded = TrustLedger::with_storage(store, None).unwrap();
        assert_eq!(reloaded.credentials_for(&model(1)).len(), 1);
        assert_eq!(reloaded.policies(&op.did()).len(), 1);
        assert_eq!(reloaded.violations_of(&op.did()).len(), 1);
    }
}
