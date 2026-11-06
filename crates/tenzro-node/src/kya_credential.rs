//! Know-Your-Agent credentials that anyone can check without trusting the
//! issuer's word.
//!
//! A KYA credential is a W3C Verifiable Credential 2.0 stating that an agent
//! DID is controlled by a specific key, and how that is known. Every claim in
//! it is re-checkable from the credential alone:
//!
//! - **The issuer.** The issuing node signs with a P-256 key held in its TPM
//!   or Secure Enclave, and its issuer DID is the machine DID that key
//!   derives (`did:tenzro:machine:{f(key)}`). The key travels in the
//!   credential, so a verifier checks the proof and the issuer DID with no
//!   directory lookup.
//! - **The subject.** `credentialSubject.id` must derive from
//!   `credentialSubject.controllerKey` (a passkey or device-key DID), or,
//!   for a TPM-admitted machine, the credential carries the machine's TPM
//!   attestation: the endorsement key (and its manufacturer certificate when
//!   the TPM has one), credential activation, and a quote over the DID and exactly that key. A verifier
//!   re-runs whichever applies. Whether a TPM manufacturer certified that
//!   endorsement key is reported as a separate grade, never a condition.
//! - **Validity.** `validFrom` / `validUntil` bound it in time.
//!
//! Nothing here depends on a curated list of trusted issuers: a credential
//! from any node verifies the same way, and what it proves is the binding of
//! the agent to hardware, not the issuer's reputation.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_device_key::HardwareSigner;

use crate::data_integrity;
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Credential type naming this schema.
pub const CREDENTIAL_TYPE: &str = "TenzroKnowYourAgentCredential";
/// Label of the hardware key that issues credentials.
pub const ISSUER_KEY_LABEL: &str = "tenzro/node/kya-issuer";
/// Longest validity an issuer grants.
pub const MAX_VALIDITY_SECS: i64 = 30 * 24 * 3600;

const VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32003,
        message: message.into(),
        data: None,
    }
}

/// The issuer DID a signing key derives.
pub fn issuer_did(public_key_sec1: &[u8]) -> String {
    format!(
        "did:tenzro:machine:{}",
        tenzro_types::did_derivation::machine_device_id(public_key_sec1)
    )
}

/// What the credential says about its subject.
pub struct Subject<'a> {
    pub did: &'a str,
    pub controller_key: &'a [u8],
    pub key_type: &'a str,
    /// The subject identity's recorded metadata; carries TPM evidence for a
    /// root-derived machine.
    pub metadata: &'a BTreeMap<String, String>,
    pub capabilities: &'a [String],
}

/// Issue a credential for `subject`, valid from `now` for `validity_secs`.
///
/// Refuses a subject whose binding does not hold: the credential would state
/// something a verifier could not confirm.
pub fn issue(
    signer: &dyn HardwareSigner,
    subject: &Subject<'_>,
    now: chrono::DateTime<chrono::Utc>,
    validity_secs: i64,
) -> Result<Value, String> {
    if !tenzro_tee::identity_evidence::registration_binding_holds(
        subject.did,
        subject.controller_key,
        subject.metadata,
    ) {
        return Err(format!(
            "{} does not provably belong to its controller key, so no credential can state that it does",
            subject.did
        ));
    }
    let validity = validity_secs.clamp(1, MAX_VALIDITY_SECS);
    let public_key = signer.public_key_sec1().map_err(|e| e.to_string())?;
    let issuer = issuer_did(&public_key);
    let method = format!("{issuer}#hardware-key");
    let evidence = match subject
        .metadata
        .get(tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY)
    {
        Some(att)
            if !tenzro_types::did_derivation::did_derives_from_key(
                subject.did,
                subject.controller_key,
            ) =>
        {
            json!({
                "type": "TpmAttestation",
                "attestation": serde_json::from_str::<Value>(att).map_err(|e| e.to_string())?,
            })
        }
        _ => json!({ "type": "KeyDerivation" }),
    };
    let fmt =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let credential = json!({
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", CREDENTIAL_TYPE],
        "issuer": {
            "id": issuer,
            "publicKeyJwk": data_integrity::p256_jwk(&public_key),
        },
        "validFrom": fmt(now),
        "validUntil": fmt(now + chrono::Duration::seconds(validity)),
        "credentialSubject": {
            "id": subject.did,
            "controllerKey": hex::encode(subject.controller_key),
            "keyType": subject.key_type,
            "capabilities": subject.capabilities,
            "evidence": evidence,
        },
    });
    data_integrity::sign(credential, signer, &method, "assertionMethod", &fmt(now))
        .map_err(|e| e.to_string())
}

/// A credential that verified, and what it established.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub issuer: String,
    pub subject: String,
    pub evidence: String,
    /// For TPM evidence: whether a TPM manufacturer certified the endorsement
    /// key, recomputed here. A reputation signal, not a validity condition.
    pub endorsement: Option<String>,
}

/// Verify a credential from any issuer at `now`.
pub fn verify(
    credential: &Value,
    now: chrono::DateTime<chrono::Utc>,
    roots_pem: &[String],
) -> Result<VerifiedCredential, String> {
    let types = credential
        .get("type")
        .and_then(Value::as_array)
        .ok_or("no type")?;
    if !types.iter().any(|t| t.as_str() == Some(CREDENTIAL_TYPE)) {
        return Err(format!("not a {CREDENTIAL_TYPE}"));
    }
    let issuer = credential
        .pointer("/issuer/id")
        .and_then(Value::as_str)
        .ok_or("no issuer")?;
    let issuer_key = credential
        .pointer("/issuer/publicKeyJwk")
        .and_then(data_integrity::p256_from_jwk)
        .ok_or("issuer key is not a P-256 JWK")?;
    if issuer_did(&issuer_key) != issuer {
        return Err("the issuer DID does not derive from the issuer key".into());
    }
    let method = data_integrity::verify(credential, &issuer_key).map_err(|e| e.to_string())?;
    if method != format!("{issuer}#hardware-key") {
        return Err("the proof names a key other than the issuer's".into());
    }
    let time = |p: &str| {
        credential
            .pointer(p)
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    let (from, until) = (
        time("/validFrom").ok_or("no validFrom")?,
        time("/validUntil").ok_or("no validUntil")?,
    );
    if now < from || now > until {
        return Err("the credential is outside its validity window".into());
    }

    let subject = credential
        .pointer("/credentialSubject/id")
        .and_then(Value::as_str)
        .ok_or("no subject")?;
    let key = credential
        .pointer("/credentialSubject/controllerKey")
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h).ok())
        .ok_or("no controller key")?;
    let evidence_type = credential
        .pointer("/credentialSubject/evidence/type")
        .and_then(Value::as_str)
        .ok_or("no evidence")?;
    let (holds, endorsement) = match evidence_type {
        "KeyDerivation" => (
            tenzro_types::did_derivation::did_derives_from_key(subject, &key),
            None,
        ),
        "TpmAttestation" => {
            let att = credential
                .pointer("/credentialSubject/evidence/attestation")
                .cloned()
                .and_then(|a| {
                    serde_json::from_value::<tenzro_tee::tpm_attest::MachineAttestation>(a).ok()
                });
            match att {
                Some(att) => (
                    tenzro_tee::identity_evidence::tpm_evidence_binds(subject, &key, &att),
                    Some(
                        tenzro_tee::identity_evidence::endorsement_label(&att, roots_pem)
                            .to_string(),
                    ),
                ),
                None => (false, None),
            }
        }
        other => return Err(format!("unknown evidence type {other}")),
    };
    if !holds {
        return Err("the subject DID does not provably belong to the controller key".into());
    }
    Ok(VerifiedCredential {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        evidence: evidence_type.to_string(),
        endorsement,
    })
}

fn object_params(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(a)) => a.into_iter().next().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    }
}

fn issuer_signer() -> Result<&'static dyn HardwareSigner, JsonRpcError> {
    static SIGNER: std::sync::OnceLock<Option<Box<dyn HardwareSigner>>> =
        std::sync::OnceLock::new();
    SIGNER
        .get_or_init(|| tenzro_device_key::signer::open_or_create(ISSUER_KEY_LABEL).ok())
        .as_deref()
        .ok_or_else(|| refused("this node has no TPM or Secure Enclave, so it holds no key to issue credentials with"))
}

/// `tenzro_issueKyaCredential`: params `did`, optional `validity_secs`.
pub(crate) async fn handle_issue(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object_params(params);
    let did = params
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Missing did"))?;
    let validity = params
        .get("validity_secs")
        .and_then(Value::as_i64)
        .unwrap_or(MAX_VALIDITY_SECS);
    let registry = node
        .identity_registry()
        .ok_or_else(|| refused("identity registry not initialized"))?;
    let identity = registry
        .resolve(did)
        .map_err(|e| invalid(format!("unknown DID {did}: {e}")))?;
    let key = identity
        .public_keys
        .first()
        .ok_or_else(|| refused(format!("{did} has no registered key")))?;
    let metadata: BTreeMap<String, String> = identity.metadata.clone().into_iter().collect();
    let capabilities = match &identity.identity_data {
        tenzro_identity::IdentityData::Machine { capabilities, .. } => capabilities.clone(),
        _ => Vec::new(),
    };
    let subject = Subject {
        did,
        controller_key: &key.public_key,
        key_type: &key.key_type,
        metadata: &metadata,
        capabilities: &capabilities,
    };
    let signer = issuer_signer()?;
    issue(signer, &subject, chrono::Utc::now(), validity).map_err(refused)
}

/// `tenzro_verifyKyaCredential`: params `credential` (the JSON credential).
pub(crate) async fn handle_verify(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object_params(params);
    let credential = params
        .get("credential")
        .ok_or_else(|| invalid("Missing credential"))?;
    let roots = crate::rpc::chain_state_of(node)
        .map(|chain| tenzro_vm::native::read_endorsement_roots(&chain))
        .unwrap_or_default();
    Ok(match verify(credential, chrono::Utc::now(), &roots) {
        Ok(v) => json!({
            "valid": true,
            "issuer": v.issuer,
            "subject": v.subject,
            "evidence": v.evidence,
            "endorsement": v.endorsement,
        }),
        Err(e) => json!({ "valid": false, "error": e }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_integrity::tests::test_signer;

    fn human(key: &[u8]) -> String {
        format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(key)
        )
    }

    fn issue_for(did: &str, key: &[u8]) -> Result<Value, String> {
        let md = BTreeMap::new();
        let subject = Subject {
            did,
            controller_key: key,
            key_type: "P-256",
            metadata: &md,
            capabilities: &[],
        };
        issue(&test_signer(21), &subject, chrono::Utc::now(), 3600)
    }

    #[test]
    fn a_credential_for_a_derived_did_verifies_from_its_own_contents() {
        let key = [4u8; 64];
        let vc = issue_for(&human(&key), &key).unwrap();
        let v = verify(&vc, chrono::Utc::now(), &[]).unwrap();
        assert_eq!(v.subject, human(&key));
        assert_eq!(v.evidence, "KeyDerivation");
        assert_eq!(
            v.issuer,
            issuer_did(&test_signer(21).public_key_sec1().unwrap())
        );
    }

    #[test]
    fn no_credential_is_issued_for_a_did_its_key_does_not_derive() {
        assert!(issue_for(&human(&[4u8; 64]), &[5u8; 64]).is_err());
    }

    #[test]
    fn a_swapped_subject_key_or_issuer_is_refused() {
        let key = [4u8; 64];
        let vc = issue_for(&human(&key), &key).unwrap();

        let mut swapped = vc.clone();
        swapped["credentialSubject"]["controllerKey"] = hex::encode([5u8; 64]).into();
        assert!(verify(&swapped, chrono::Utc::now(), &[]).is_err());

        let mut other_issuer = vc.clone();
        other_issuer["issuer"]["publicKeyJwk"] =
            data_integrity::p256_jwk(&test_signer(22).public_key_sec1().unwrap());
        assert!(verify(&other_issuer, chrono::Utc::now(), &[]).is_err());

        let mut claimed = vc;
        claimed["issuer"]["id"] = "did:tenzro:machine:trusted-authority".into();
        assert!(verify(&claimed, chrono::Utc::now(), &[]).is_err());
    }

    #[test]
    fn an_expired_credential_is_refused() {
        let key = [4u8; 64];
        let vc = issue_for(&human(&key), &key).unwrap();
        assert!(verify(&vc, chrono::Utc::now() + chrono::Duration::hours(2), &[]).is_err());
    }
}
