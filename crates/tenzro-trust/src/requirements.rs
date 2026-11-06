//! Requirements on the credentials a model or operator holds.
//!
//! Used by operator policies (what an operator promises its models hold) and
//! by the provenance rule (how strongly a model's files must be
//! corroborated). Nothing here ranks or scores a subject: a requirement is
//! met or it is not.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::credential::{ClaimKind, Credential, MAX_SCORE, Subject};
use crate::{Result, invalid};

const MAX_ISSUERS: usize = 256;
const MAX_REQUIREMENTS: usize = 64;

/// Which kind of subject a requirement applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    Model,
    Operator,
}

/// One credential a subject must hold from a recognised issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Requirement {
    pub subject: SubjectKind,
    pub kind: ClaimKind,
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<u32>,
    /// Any of these grades satisfies the requirement; empty means any grade.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grades: Vec<String>,
}

impl Requirement {
    fn applies_to(&self, subject: &Subject) -> bool {
        match self.subject {
            SubjectKind::Model => subject.is_model(),
            SubjectKind::Operator => !subject.is_model(),
        }
    }

    fn met_by(&self, c: &Credential, issuers: &BTreeSet<String>) -> bool {
        issuers.contains(&c.issuer)
            && self.applies_to(&c.subject)
            && c.claim.kind == self.kind
            && c.claim.scheme == self.scheme
            && self
                .min_score
                .is_none_or(|min| c.claim.score.is_some_and(|s| s >= min))
            && (self.grades.is_empty()
                || c.claim
                    .grade
                    .as_ref()
                    .is_some_and(|g| self.grades.contains(g)))
    }

    pub fn describe(&self) -> String {
        let mut s = format!("{:?} {:?} {}", self.subject, self.kind, self.scheme).to_lowercase();
        if let Some(m) = self.min_score {
            s.push_str(&format!(" score>={m}"));
        }
        if !self.grades.is_empty() {
            s.push_str(&format!(" grade in {:?}", self.grades));
        }
        s
    }
}

/// How strongly a model's files must be corroborated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProvenanceRule {
    pub min_observers: u32,
    pub min_origins: u32,
    #[serde(default)]
    pub allow_conflicts: bool,
}

impl ProvenanceRule {
    /// The network default: two independent observers across two distinct
    /// origins, and nobody contradicting them.
    pub const DEFAULT: ProvenanceRule = ProvenanceRule {
        min_observers: 2,
        min_origins: 2,
        allow_conflicts: false,
    };
}

/// The recognised issuers and the credentials required from them: what an
/// operator policy promises its models hold.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRequirements {
    #[serde(default)]
    pub issuers: BTreeSet<String>,
    #[serde(default)]
    pub require: Vec<Requirement>,
}

impl TrustRequirements {
    pub fn validate(&self) -> Result<()> {
        if self.issuers.len() > MAX_ISSUERS || self.require.len() > MAX_REQUIREMENTS {
            return Err(invalid(format!(
                "at most {MAX_ISSUERS} issuers and {MAX_REQUIREMENTS} requirements"
            )));
        }
        if !self.require.is_empty() && self.issuers.is_empty() {
            return Err(invalid(
                "requirements with no recognised issuer can never be met",
            ));
        }
        for i in &self.issuers {
            if !i.starts_with("did:tenzro:") {
                return Err(invalid(format!("issuer {i} is not a DID")));
            }
        }
        for r in &self.require {
            if r.scheme.is_empty() || r.min_score.is_some_and(|m| m > MAX_SCORE) {
                return Err(invalid(
                    "a requirement needs a scheme and a score of at most 10000",
                ));
            }
        }
        Ok(())
    }

    /// Evaluate `subject` given the credentials currently valid for it.
    pub fn evaluate<'a>(
        &self,
        subject: &Subject,
        valid: impl IntoIterator<Item = &'a Credential>,
    ) -> Verdict {
        let valid: Vec<&Credential> = valid
            .into_iter()
            .filter(|c| &c.subject == subject)
            .collect();
        let mut unmet = Vec::new();
        for r in self.require.iter().filter(|r| r.applies_to(subject)) {
            if !valid.iter().any(|c| r.met_by(c, &self.issuers)) {
                unmet.push(r.describe());
            }
        }
        Verdict {
            passed: unmet.is_empty(),
            unmet,
        }
    }
}

/// The outcome of checking a subject against requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub passed: bool,
    /// The requirements the subject does not meet.
    pub unmet: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::tests::{claim, issue, model};
    use crate::proof::testkit::TestKey;

    fn req(kind: ClaimKind, scheme: &str, min: Option<u32>) -> Requirement {
        Requirement {
            subject: SubjectKind::Model,
            kind,
            scheme: scheme.into(),
            min_score: min,
            grades: vec![],
        }
    }

    #[test]
    fn a_requirement_is_met_only_by_a_recognised_issuer() {
        let known = TestKey::new(1);
        let unknown = TestKey::new(2);
        let good = Credential::parse(&issue(
            &known,
            &model(1),
            &claim(ClaimKind::Rating, "ailuminate", Some(8000)),
            1,
        ))
        .unwrap();
        let other = Credential::parse(&issue(
            &unknown,
            &model(1),
            &claim(ClaimKind::Rating, "ailuminate", Some(9999)),
            1,
        ))
        .unwrap();
        let tr = TrustRequirements {
            issuers: [known.did()].into_iter().collect(),
            require: vec![req(ClaimKind::Rating, "ailuminate", Some(7000))],
        };
        assert!(tr.evaluate(&model(1), [&good]).passed);
        let v = tr.evaluate(&model(1), [&other]);
        assert!(!v.passed);
        assert!(
            !tr.evaluate(&model(2), [&good]).passed,
            "a credential for another model does not count"
        );
    }

    #[test]
    fn a_score_below_the_minimum_fails() {
        let k = TestKey::new(1);
        let low = Credential::parse(&issue(
            &k,
            &model(1),
            &claim(ClaimKind::Rating, "ailuminate", Some(5000)),
            1,
        ))
        .unwrap();
        let tr = TrustRequirements {
            issuers: [k.did()].into_iter().collect(),
            require: vec![req(ClaimKind::Rating, "ailuminate", Some(7000))],
        };
        assert!(!tr.evaluate(&model(1), [&low]).passed);
    }

    #[test]
    fn requirements_without_issuers_are_refused() {
        let tr = TrustRequirements {
            issuers: BTreeSet::new(),
            require: vec![req(ClaimKind::Certification, "x", None)],
        };
        assert!(tr.validate().is_err());
    }
}
