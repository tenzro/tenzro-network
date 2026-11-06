//! The node's copy of the attestation transparency log
//! ([`tenzro_tee::verify::transparency`]), persisted in node storage.
//!
//! - `tenzro_publishTeeMeasurement` appends a launch measurement. A publisher
//!   must be running the build it is publishing: the call carries an
//!   attestation report, answering a nonce this node issued, whose own
//!   measurement is the one being logged, and the publisher key must be the
//!   key that report is bound to. The entry names the publisher by the machine
//!   DID that key derives.
//!
//!   That is the gate, and it is not an allowlist: anyone who boots the build
//!   can publish it, and nobody else can. A signature alone was not a gate at
//!   all — any freshly generated P-256 key would publish any measurement, so
//!   an attacker could log their own build first and have it treated as the
//!   known-good one.
//! - `tenzro_getAttestationLog` returns the log and its head.
//! - Every accepted attestation ([`crate::attestation_rpc`]) is admitted
//!   through the log: an unlogged measurement is refused, and a chip presented
//!   from a facility other than the one it was first placed in yields the two
//!   entries as evidence.

use serde_json::{Value, json};
use tenzro_storage::KvStore;
use tenzro_tee::verify::transparency::{LogEntry, TransparencyLog};

use crate::rpc::JsonRpcError;

/// Storage key of the log under `CF_METADATA`.
const LOG_KEY: &[u8] = b"attestation_transparency_log";

/// Serialises read-modify-write of the stored log within this process.
static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

fn internal(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// Load the stored log, re-checking its hash chain. No storage, or nothing
/// stored yet, is an empty log.
pub(crate) fn load(store: Option<&dyn KvStore>) -> Result<TransparencyLog, JsonRpcError> {
    let Some(store) = store else {
        return Ok(TransparencyLog::new());
    };
    match store
        .get(tenzro_storage::CF_METADATA, LOG_KEY)
        .map_err(|e| internal(format!("read attestation log: {e}")))?
    {
        None => Ok(TransparencyLog::new()),
        Some(bytes) => {
            let entries: Vec<LogEntry> = serde_json::from_slice(&bytes)
                .map_err(|e| internal(format!("decode attestation log: {e}")))?;
            TransparencyLog::from_entries(entries)
                .ok_or_else(|| internal("the stored attestation log fails its hash chain"))
        }
    }
}

fn save(store: &dyn KvStore, log: &TransparencyLog) -> Result<(), JsonRpcError> {
    let bytes = serde_json::to_vec(log.entries()).map_err(|e| internal(e.to_string()))?;
    store
        .put(tenzro_storage::CF_METADATA, LOG_KEY, &bytes)
        .map_err(|e| internal(format!("write attestation log: {e}")))
}

/// Run `f` on the stored log and persist the result.
pub(crate) fn update<T>(
    store: Option<&dyn KvStore>,
    f: impl FnOnce(&mut TransparencyLog) -> T,
) -> Result<T, JsonRpcError> {
    let _guard = LOCK.lock();
    let mut log = load(store)?;
    let out = f(&mut log);
    if let Some(store) = store {
        save(store, &log)?;
    }
    Ok(out)
}

/// The largest measurement the log will accept, in bytes.
///
/// The longest a real one is: a TDX MRTD and an SNP measurement are 48 bytes,
/// a Nitro PCR0 is 48. The bound is what stops the log being filled with
/// megabyte "measurements" by anyone who can boot one attested build.
const MAX_MEASUREMENT_LEN: usize = 64;

pub use tenzro_types::tee::publication_statement;

/// A JSON-RPC params value as one object (first element of a positional array).
pub(crate) fn object_params(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(a)) => a.into_iter().next().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    }
}

fn hex_param(params: &Value, name: &str) -> Result<Vec<u8>, JsonRpcError> {
    let s = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Missing {name}")))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|e| invalid(format!("{name} is not hex: {e}")))
}

/// `tenzro_publishTeeMeasurement`: params `report` (a JSON attestation report),
/// `nonce` (32 bytes from `tenzro_teeAttestationChallenge`),
/// `publisher_key_hex` (uncompressed SEC1 P-256) and `signature_hex` (raw
/// `r || s` over SHA-256 of [`publication_statement`]).
///
/// The measurement published is the report's own, not one the caller names, so
/// a publisher can only log the build it is running.
pub(crate) fn handle_publish(
    store: Option<&dyn KvStore>,
    params: &Value,
) -> Result<Value, JsonRpcError> {
    let key = hex_param(params, "publisher_key_hex")?;
    let signature = hex_param(params, "signature_hex")?;
    let nonce: [u8; 32] = hex_param(params, "nonce")?
        .as_slice()
        .try_into()
        .map_err(|_| invalid("nonce must be 32 bytes"))?;
    let report: tenzro_types::tee::AttestationReport = serde_json::from_value(
        params
            .get("report")
            .cloned()
            .ok_or_else(|| invalid("Missing report"))?,
    )
    .map_err(|e| invalid(format!("report: {e}")))?;

    // The nonce is this node's, unexpired and unused, so the report was
    // produced for this publication rather than replayed from another one.
    if !crate::attestation_rpc::issuer().redeem(&nonce, crate::attestation_rpc::PUBLISH_PURPOSE) {
        return Err(JsonRpcError {
            code: -32003,
            message: "nonce was not issued by this node, has expired, or was already used"
                .to_string(),
            data: None,
        });
    }

    // The report answers that nonce AND names the publishing key, so the key
    // signing the publication is the key the attested workload holds. Without
    // the key in the challenge, a bystander could take someone else's report
    // and publish under their own key.
    let packet = crate::attestation_rpc::challenge_packet(&nonce, &key);
    let expected = tenzro_types::tee::pack_user_data_for_vendor(report.vendor, &packet);
    let verified = tenzro_tee::verify_report(&report, &tenzro_tee::VerifyPolicy::now(expected))
        .map_err(|e| JsonRpcError {
            code: -32003,
            message: format!(
                "a measurement is published by the machine running it, and this \
                 report did not verify: {e}"
            ),
            data: None,
        })?;

    if verified.measurement.len() > MAX_MEASUREMENT_LEN {
        return Err(invalid(format!(
            "measurement is {} bytes, more than the {MAX_MEASUREMENT_LEN} a real one is",
            verified.measurement.len()
        )));
    }

    let statement = publication_statement(verified.vendor, &verified.measurement);
    if !tenzro_device_key::signer::verify_p256(&key, &statement, &signature) {
        return Err(JsonRpcError {
            code: -32003,
            message: "the publisher key did not sign this measurement".to_string(),
            data: None,
        });
    }

    let publisher_did = crate::kya_credential::issuer_did(&key);
    let vendor = verified.vendor;
    let measurement = verified.measurement.clone();
    let head = update(store, |log| {
        log.publish_measurement(vendor, measurement.clone(), publisher_did.clone())
    })?;
    Ok(json!({
        "head": hex::encode(head),
        "publisher_did": publisher_did,
        "measurement_hex": format!("0x{}", hex::encode(&verified.measurement)),
    }))
}

/// `tenzro_getAttestationLog`.
pub(crate) fn handle_get(store: Option<&dyn KvStore>) -> Result<Value, JsonRpcError> {
    let log = load(store)?;
    Ok(json!({
        "head": hex::encode(log.head()),
        "entries": log.entries(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_integrity::tests::test_signer;
    use tenzro_device_key::HardwareSigner;
    use tenzro_types::tee::TeeVendor;

    fn fresh_nonce() -> [u8; 32] {
        crate::attestation_rpc::issuer()
            .issue(crate::attestation_rpc::PUBLISH_PURPOSE)
            .unwrap()
    }

    /// A publication with a real signature but fabricated evidence. This is
    /// what an attacker has: they can sign anything, and they cannot produce a
    /// report that verifies.
    fn publish_params(seed: u8, measurement: &[u8], nonce: [u8; 32]) -> Value {
        let s = test_signer(seed);
        let sig = s
            .sign(&publication_statement(TeeVendor::AmdSevSnp, measurement))
            .unwrap();
        json!({
            "report": {
                "vendor": "AmdSevSnp",
                "attestation_data": vec![0u8; 1184],
                "certificates": Vec::<Vec<u8>>::new(),
            },
            "nonce": hex::encode(nonce),
            "publisher_key_hex": hex::encode(s.public_key_sec1().unwrap()),
            "signature_hex": hex::encode(sig),
        })
    }

    /// The defect this closes: publication used to need only a signature, so
    /// any freshly generated key logged any measurement and an attacker could
    /// register their own build as the known-good one before anyone else.
    #[test]
    fn a_publication_without_verifying_evidence_is_refused() {
        let store = tenzro_storage::MemoryStore::new();
        let err = handle_publish(Some(&store), &publish_params(1, &[5; 48], fresh_nonce()))
            .expect_err("unverifiable evidence must not publish");
        assert!(
            err.message.contains("did not verify"),
            "refused for the wrong reason: {}",
            err.message
        );
        assert!(
            !load(Some(&store))
                .unwrap()
                .contains_measurement(TeeVendor::AmdSevSnp, &[5; 48]),
            "nothing may be logged when the evidence did not verify"
        );
    }

    /// A nonce this node never issued, or one already spent, means the report
    /// was not produced for this publication.
    #[test]
    fn a_publication_with_an_unissued_or_spent_nonce_is_refused() {
        let err = handle_publish(None, &publish_params(1, &[5; 48], [0xEE; 32]))
            .expect_err("an unissued nonce must be refused");
        assert!(err.message.contains("nonce"), "{}", err.message);

        let nonce = fresh_nonce();
        let params = publish_params(1, &[5; 48], nonce);
        let _ = handle_publish(None, &params);
        let err = handle_publish(None, &params).expect_err("a spent nonce must be refused");
        assert!(err.message.contains("nonce"), "{}", err.message);
    }

    #[test]
    fn a_malformed_nonce_or_missing_report_is_refused() {
        let mut p = publish_params(1, &[5; 48], fresh_nonce());
        p["nonce"] = hex::encode([1u8; 8]).into();
        assert!(handle_publish(None, &p).is_err());

        let mut p = publish_params(1, &[5; 48], fresh_nonce());
        p.as_object_mut().unwrap().remove("report");
        assert!(handle_publish(None, &p).is_err());
    }

    /// An empty log reads back cleanly rather than erroring.
    #[test]
    fn an_empty_log_reads_back() {
        let store = tenzro_storage::MemoryStore::new();
        let out = handle_get(Some(&store)).unwrap();
        assert_eq!(out["entries"].as_array().unwrap().len(), 0);
    }
}
