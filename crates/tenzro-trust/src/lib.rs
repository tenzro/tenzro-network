//! Certifications, ratings, operator policies and model provenance.
//!
//! One ledger of self-verifying, signed records:
//!
//! - **Credentials** ([`credential`]): a certification, rating, evaluation or
//!   safety scan that ANY issuer states about a model (named by its manifest
//!   root) or an operator (named by its hardware-derived DID). W3C VC 2.0
//!   documents with an `ecdsa-jcs-2019` proof ([`proof`]), a mandatory
//!   validity window and a Bitstring Status List entry ([`status_list`]).
//! - **Operator policies** ([`policy`]): what an operator declares it serves
//!   and refuses, signed by the operator's hardware key. The operator enforces
//!   it on its own serving path, and a signed inference receipt that
//!   contradicts a mechanically checkable clause is proof of a violation.
//! - **Model provenance** ([`manifest`], [`origin`]): a content-addressed
//!   manifest of every file of a model, and signed observations of what each
//!   origin (the creator, the Hugging Face Hub, mirrors, storage providers)
//!   serves. A model is verified when independent observers across distinct
//!   origins agree on every file and none contradicts them.
//! - **Ingest scanning** ([`scan`]): refuses pickle and malformed weights by
//!   content, not by file name.
//! - **Catalog entries** ([`catalog`]): a publisher's signed description of a
//!   model (engine, licence, the hash of every file). A node serves the
//!   entries of the bonded publishers its operator names, or of all of them.
//! - **Engine releases** ([`release`]): a publisher's signed statement of a
//!   node build (version, per-platform binary hashes). The network carries
//!   them; each operator decides whether to install one.
//!
//! The protocol privileges no issuer, keeps no allowlist, and never holds a
//! private key: every document is signed on its author's own TPM, Secure
//! Enclave or passkey, and every record re-verifies wherever it is applied
//! ([`ledger`]).

pub mod catalog;
pub mod credential;
pub mod jcs;
pub mod ledger;
pub mod manifest;
pub mod origin;
pub mod policy;
pub mod proof;
pub mod release;
pub mod requirements;
pub mod scan;
pub mod status_list;

pub use credential::{Claim, ClaimKind, Credential, CredentialState, Subject};
pub use ledger::{Applied, TrustLedger};
pub use manifest::{FileEntry, ModelManifest};
pub use origin::{OriginAttestation, OriginKind, ProvenanceStatus};
pub use policy::{OperatorPolicy, PolicyRefusal, ProvenViolation};
pub use proof::{ProofError, VerifiedProof};
pub use requirements::{TrustRequirements, Verdict};

/// Why a trust record or query was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("invalid document: {0}")]
    Invalid(String),
    #[error("the record is signed by {signer}, not by {expected}")]
    WrongSigner { signer: String, expected: String },
    #[error("{0}")]
    Stale(String),
    #[error("file {path} does not match the manifest: {reason}")]
    FileMismatch { path: String, reason: String },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for TrustError {
    fn from(e: std::io::Error) -> Self {
        TrustError::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, TrustError>;

pub(crate) fn invalid(msg: impl Into<String>) -> TrustError {
    TrustError::Invalid(msg.into())
}

/// Parse an RFC 3339 time field of `doc`.
pub(crate) fn time_field(
    doc: &serde_json::Value,
    pointer: &str,
) -> Result<chrono::DateTime<chrono::Utc>> {
    doc.pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .ok_or_else(|| invalid(format!("{pointer} is not an RFC 3339 time")))
}

pub(crate) fn str_field<'a>(doc: &'a serde_json::Value, pointer: &str) -> Result<&'a str> {
    doc.pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(format!("{pointer} is missing")))
}

/// Whether `types` (a JSON `type` value) names `wanted`.
pub(crate) fn has_type(doc: &serde_json::Value, wanted: &str) -> bool {
    match doc.get("type") {
        Some(serde_json::Value::Array(a)) => a.iter().any(|t| t.as_str() == Some(wanted)),
        Some(serde_json::Value::String(s)) => s == wanted,
        _ => false,
    }
}

/// Hex SHA-256 of the canonical form of `doc` (including its proof): the key
/// a signed record is stored and referenced under.
pub fn record_digest(doc: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(jcs::canonical_json(doc)))
}

/// Verify the proof on `doc`, require it was made by `expected_signer` for
/// `assertionMethod`, and refuse fractional numbers.
pub(crate) fn verify_signed_by(
    doc: &serde_json::Value,
    expected_signer: &str,
) -> Result<VerifiedProof> {
    if jcs::has_fractional_number(doc) {
        return Err(invalid("trust documents carry integers only"));
    }
    verify_proof_by(doc, expected_signer)
}

/// [`verify_signed_by`] for a document that describes something in numbers of
/// its own (a catalog entry's sampler settings): fractional numbers are
/// hashed in their RFC 8785 form like every other value.
pub(crate) fn verify_proof_by(
    doc: &serde_json::Value,
    expected_signer: &str,
) -> Result<VerifiedProof> {
    let v = proof::verify(doc)?;
    if v.signer_did != expected_signer {
        return Err(TrustError::WrongSigner {
            signer: v.signer_did,
            expected: expected_signer.to_string(),
        });
    }
    if v.purpose != "assertionMethod" {
        return Err(invalid("the proof purpose must be assertionMethod"));
    }
    Ok(v)
}
