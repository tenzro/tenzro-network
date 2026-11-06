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
    OperatorPolicy, POLICY_TYPE, ProvenViolation, VIOLATION_TYPE, verify_violation,
};
use crate::release::{ENGINE_RELEASE_TYPE, EngineRelease};
use crate::status_list::{
    ISSUER_REVOCATION_TYPE, IssuerRevocation, REVOCATION_TYPE, Revocation, status_list_document,
};
use crate::{Result, TrustError, has_type, invalid, record_digest};

const KEY_PREFIX: &str = "trust/";

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

/// Every trust record this holder has seen.
#[derive(Default)]
pub struct TrustLedger {
    store: Option<Arc<dyn KvStore>>,
    seen: DashMap<String, ()>,
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
}

impl TrustLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// A ledger persisted in `store`, reloaded from it. Every stored record
    /// is verified again on load.
    pub fn with_storage(store: Arc<dyn KvStore>) -> Result<Self> {
        let ledger = TrustLedger {
            store: None,
            ..Default::default()
        };
        let rows = store
            .scan_prefix(CF_CREDENTIALS, KEY_PREFIX.as_bytes())
            .map_err(|e| TrustError::Storage(e.to_string()))?;
        let mut docs: Vec<Value> = rows
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        // Violations are judged against policies, so they load last.
        docs.sort_by_key(|d| {
            RecordKind::of(d)
                .map(|k| k == RecordKind::Violation)
                .unwrap_or(true)
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
                self.roots_by_name
                    .entry(m.name.clone())
                    .or_default()
                    .insert(key.clone());
                self.manifests.insert(key.clone(), m);
            }
            RecordKind::Origin => {
                let a = OriginAttestation::parse(doc)?;
                self.origins.entry(a.name.clone()).or_default().push(a);
            }
            RecordKind::Violation => {
                let operator = doc
                    .pointer("/policy/operator")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("the evidence names no operator"))?;
                let history = self.policies(operator);
                let v = verify_violation(doc, &history)?;
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
    fn a_ledger_reloads_and_reverifies_its_records() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::kv::MemoryStore::new());
        let issuer = TestKey::new(1);
        let op = TestKey::new(4);
        let rs = ReceiptSigner::new();
        {
            let ledger = TrustLedger::with_storage(store.clone()).unwrap();
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
        let reloaded = TrustLedger::with_storage(store).unwrap();
        assert_eq!(reloaded.credentials_for(&model(1)).len(), 1);
        assert_eq!(reloaded.policies(&op.did()).len(), 1);
        assert_eq!(reloaded.violations_of(&op.did()).len(), 1);
    }
}
