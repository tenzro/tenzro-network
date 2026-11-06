//! Certification and rating credentials.
//!
//! A credential is a W3C Verifiable Credential 2.0 document that one issuer
//! signs about one subject: a model, named by its manifest root
//! (`tenzro:model:<hex>`), or an operator, named by its hardware-derived DID.
//! Any DID can issue. What a credential is worth is decided by each relying
//! party, never by the protocol.
//!
//! Every credential has a validity window and a Bitstring Status List entry
//! under its issuer, so expiry and revocation are part of what "valid" means.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, has_type, invalid, str_field, time_field, verify_signed_by};

pub const VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const CREDENTIAL_TYPE: &str = "TenzroTrustCredential";
/// Prefix of a model subject: the manifest root follows.
pub const MODEL_SUBJECT_PREFIX: &str = "tenzro:model:";
/// Prefix of the status list URI; the issuer DID follows.
pub const STATUS_LIST_PREFIX: &str = "tenzro:status:";
/// Longest validity an issuer may grant.
pub const MAX_VALIDITY_DAYS: i64 = 5 * 365;
/// Highest score a claim may carry (basis points of a perfect score).
pub const MAX_SCORE: u32 = 10_000;
/// Status list indices run below this bound (eight times the W3C minimum
/// list length of 131,072 entries).
pub const MAX_STATUS_INDEX: u32 = 1 << 20;

/// What kind of statement the issuer makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimKind {
    Certification,
    Rating,
    Evaluation,
    SafetyScan,
    PolicyConformance,
}

/// Who or what a credential is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// A model, by the hex root of its manifest.
    Model(String),
    /// An operator, by its DID.
    Operator(String),
}

impl Subject {
    pub fn parse(id: &str) -> Result<Self> {
        if let Some(root) = id.strip_prefix(MODEL_SUBJECT_PREFIX) {
            if root.len() == 64
                && root
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Ok(Subject::Model(root.to_string()));
            }
            return Err(invalid(
                "a model subject is tenzro:model: followed by a 64-digit lowercase hex root",
            ));
        }
        if id.starts_with("did:tenzro:") && id.len() <= 200 {
            return Ok(Subject::Operator(id.to_string()));
        }
        Err(invalid(format!("unknown subject {id}")))
    }

    pub fn id(&self) -> String {
        match self {
            Subject::Model(root) => format!("{MODEL_SUBJECT_PREFIX}{root}"),
            Subject::Operator(did) => did.clone(),
        }
    }

    pub fn is_model(&self) -> bool {
        matches!(self, Subject::Model(_))
    }
}

/// A verifiable reference to the report behind a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub uri: String,
    /// Hex SHA-256 of the report bytes.
    pub sha256: String,
}

/// The statement itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub kind: ClaimKind,
    /// The issuer's scheme identifier (a standard, benchmark or programme).
    pub scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    /// 0..=10000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl Claim {
    fn validate(&self) -> Result<()> {
        let scheme_ok = !self.scheme.is_empty()
            && self.scheme.len() <= 128
            && self
                .scheme
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._:/".contains(&b));
        if !scheme_ok {
            return Err(invalid(
                "scheme must be 1-128 characters of a-z 0-9 - . _ : /",
            ));
        }
        if self.score.is_some_and(|s| s > MAX_SCORE) {
            return Err(invalid(format!("score is above {MAX_SCORE}")));
        }
        if self
            .grade
            .as_ref()
            .is_some_and(|g| g.is_empty() || g.len() > 64)
        {
            return Err(invalid("grade must be 1-64 characters"));
        }
        if self.scope.as_ref().is_some_and(|s| s.len() > 1024) {
            return Err(invalid("scope is longer than 1024 characters"));
        }
        for e in &self.evidence {
            if e.uri.is_empty()
                || e.uri.len() > 512
                || e.sha256.len() != 64
                || hex::decode(&e.sha256).is_err()
            {
                return Err(invalid("evidence needs a uri and a hex SHA-256"));
            }
        }
        Ok(())
    }
}

/// A credential whose proof verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Hex SHA-256 of the canonical signed document.
    pub digest: String,
    pub issuer: String,
    pub subject: Subject,
    pub claim: Claim,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
    pub status_index: u32,
    pub document: Value,
}

/// Where a credential stands at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialState {
    Valid,
    NotYetValid,
    Expired,
    Revoked,
    IssuerRevoked,
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The unsigned credential document an issuer signs.
pub fn unsigned(
    issuer: &str,
    subject: &Subject,
    claim: &Claim,
    valid_from: chrono::DateTime<chrono::Utc>,
    valid_until: chrono::DateTime<chrono::Utc>,
    status_index: u32,
) -> Value {
    json!({
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", CREDENTIAL_TYPE],
        "issuer": issuer,
        "validFrom": rfc3339(valid_from),
        "validUntil": rfc3339(valid_until),
        "credentialSubject": {
            "id": subject.id(),
            "claim": claim,
        },
        "credentialStatus": {
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": status_index.to_string(),
            "statusListCredential": format!("{STATUS_LIST_PREFIX}{issuer}"),
        },
    })
}

impl Credential {
    /// Check the structure and the issuer's proof. Validity in time and
    /// revocation are separate questions ([`crate::ledger::TrustLedger::state`]).
    pub fn parse(document: &Value) -> Result<Self> {
        let ctx_ok = document
            .get("@context")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            == Some(VC_CONTEXT);
        if !ctx_ok {
            return Err(invalid("the first @context must be the VC 2.0 context"));
        }
        if !has_type(document, "VerifiableCredential") || !has_type(document, CREDENTIAL_TYPE) {
            return Err(invalid(format!("not a {CREDENTIAL_TYPE}")));
        }
        let issuer = str_field(document, "/issuer")?.to_string();
        verify_signed_by(document, &issuer)?;
        let valid_from = time_field(document, "/validFrom")?;
        let valid_until = time_field(document, "/validUntil")?;
        if valid_until <= valid_from {
            return Err(invalid("validUntil must be after validFrom"));
        }
        if valid_until - valid_from > chrono::Duration::days(MAX_VALIDITY_DAYS) {
            return Err(invalid(format!(
                "a credential is valid for at most {MAX_VALIDITY_DAYS} days"
            )));
        }
        let subject = Subject::parse(str_field(document, "/credentialSubject/id")?)?;
        let claim: Claim = document
            .pointer("/credentialSubject/claim")
            .cloned()
            .ok_or_else(|| invalid("credentialSubject.claim is missing"))
            .and_then(|c| serde_json::from_value(c).map_err(|e| invalid(format!("claim: {e}"))))?;
        claim.validate()?;
        if document
            .pointer("/credentialStatus/type")
            .and_then(Value::as_str)
            != Some("BitstringStatusListEntry")
            || document
                .pointer("/credentialStatus/statusPurpose")
                .and_then(Value::as_str)
                != Some("revocation")
        {
            return Err(invalid(
                "credentialStatus must be a revocation BitstringStatusListEntry",
            ));
        }
        if str_field(document, "/credentialStatus/statusListCredential")?
            != format!("{STATUS_LIST_PREFIX}{issuer}")
        {
            return Err(invalid("the status list must be the issuer's own"));
        }
        let status_index = str_field(document, "/credentialStatus/statusListIndex")?
            .parse::<u32>()
            .ok()
            .filter(|i| *i < MAX_STATUS_INDEX)
            .ok_or_else(|| invalid("statusListIndex is not an index below 2^20"))?;
        Ok(Credential {
            digest: crate::record_digest(document),
            issuer,
            subject,
            claim,
            valid_from,
            valid_until,
            status_index,
            document: document.clone(),
        })
    }

    /// The time window alone.
    pub fn time_state(&self, now: chrono::DateTime<chrono::Utc>) -> CredentialState {
        if now < self.valid_from {
            CredentialState::NotYetValid
        } else if now > self.valid_until {
            CredentialState::Expired
        } else {
            CredentialState::Valid
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::proof::testkit::TestKey;

    pub(crate) fn t(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    pub(crate) fn claim(kind: ClaimKind, scheme: &str, score: Option<u32>) -> Claim {
        Claim {
            kind,
            scheme: scheme.into(),
            grade: None,
            score,
            scope: None,
            evidence: vec![],
        }
    }

    /// A credential by `issuer` about `subject`, valid through 2027.
    pub(crate) fn issue(issuer: &TestKey, subject: &Subject, claim: &Claim, index: u32) -> Value {
        issuer.sign(unsigned(
            &issuer.did(),
            subject,
            claim,
            t("2026-01-01T00:00:00Z"),
            t("2027-12-31T00:00:00Z"),
            index,
        ))
    }

    pub(crate) fn model(n: u8) -> Subject {
        Subject::Model(hex::encode([n; 32]))
    }

    #[test]
    fn an_issued_credential_parses_with_its_issuer_and_subject() {
        let k = TestKey::new(1);
        let c = Credential::parse(&issue(
            &k,
            &model(7),
            &claim(ClaimKind::Certification, "iso-iec-42001", None),
            3,
        ))
        .unwrap();
        assert_eq!(c.issuer, k.did());
        assert_eq!(c.subject, model(7));
        assert_eq!(c.status_index, 3);
        assert_eq!(
            c.time_state(t("2026-06-01T00:00:00Z")),
            CredentialState::Valid
        );
        assert_eq!(
            c.time_state(t("2028-06-01T00:00:00Z")),
            CredentialState::Expired
        );
        assert_eq!(
            c.time_state(t("2025-06-01T00:00:00Z")),
            CredentialState::NotYetValid
        );
    }

    #[test]
    fn a_forged_credential_is_refused() {
        let issuer = TestKey::new(1);
        let forger = TestKey::new(2);
        let doc = issue(
            &issuer,
            &model(7),
            &claim(ClaimKind::Rating, "ailuminate", Some(9000)),
            1,
        );

        // Raising the score after signing breaks the proof.
        let mut raised = doc.clone();
        raised["credentialSubject"]["claim"]["score"] = 10000.into();
        assert!(Credential::parse(&raised).is_err());

        // Claiming another issuer's DID while signing with one's own key.
        let mut stolen_name = unsigned(
            &issuer.did(),
            &model(7),
            &claim(ClaimKind::Rating, "ailuminate", Some(9000)),
            t("2026-01-01T00:00:00Z"),
            t("2027-01-01T00:00:00Z"),
            1,
        );
        stolen_name = forger.sign(stolen_name);
        assert!(matches!(
            Credential::parse(&stolen_name),
            Err(crate::TrustError::WrongSigner { .. })
        ));

        // Moving the subject to another model.
        let mut moved = doc;
        moved["credentialSubject"]["id"] = model(8).id().into();
        assert!(Credential::parse(&moved).is_err());
    }

    #[test]
    fn a_status_list_other_than_the_issuers_is_refused() {
        let k = TestKey::new(1);
        let mut doc = unsigned(
            &k.did(),
            &model(7),
            &claim(ClaimKind::Certification, "x", None),
            t("2026-01-01T00:00:00Z"),
            t("2027-01-01T00:00:00Z"),
            1,
        );
        doc["credentialStatus"]["statusListCredential"] =
            format!("{STATUS_LIST_PREFIX}did:tenzro:machine:other").into();
        assert!(Credential::parse(&k.sign(doc)).is_err());
    }

    #[test]
    fn an_overlong_or_inverted_validity_is_refused() {
        let k = TestKey::new(1);
        let c = claim(ClaimKind::Certification, "x", None);
        let forever = k.sign(unsigned(
            &k.did(),
            &model(1),
            &c,
            t("2026-01-01T00:00:00Z"),
            t("2040-01-01T00:00:00Z"),
            1,
        ));
        assert!(Credential::parse(&forever).is_err());
        let inverted = k.sign(unsigned(
            &k.did(),
            &model(1),
            &c,
            t("2026-01-01T00:00:00Z"),
            t("2025-01-01T00:00:00Z"),
            1,
        ));
        assert!(Credential::parse(&inverted).is_err());
    }

    #[test]
    fn subjects_parse_strictly() {
        assert!(Subject::parse(&format!("tenzro:model:{}", "ab".repeat(32))).is_ok());
        assert!(Subject::parse("tenzro:model:ABCD").is_err());
        assert!(Subject::parse("https://example.com").is_err());
        assert!(
            Subject::parse("did:tenzro:machine:1234").unwrap()
                == Subject::Operator("did:tenzro:machine:1234".into())
        );
    }
}
