//! Challenge-response verification of confidential-computing attestations.
//!
//! `tenzro_teeAttestationChallenge` issues a single-use 32-byte nonce.
//! The attester asks its TEE for a report over `nonce || bound_data`
//! (`TeeProvider::generate_attestation` packs it for the vendor), and
//! `tenzro_verifyTeeAttestation` redeems the nonce and accepts the report
//! only if [`tenzro_tee::verify_report`] passes with exactly that packing as
//! the required user data. A report can therefore not be replayed from
//! another session or reused for other bound data.
//!
//! When the attester also presents a facility claim (signed by the
//! facility's hardware key), the report must commit to
//! [`tenzro_tee::verify::facility::bound_packet`] over the nonce, the claim
//! and `bound_data` instead, so the claim is part of what the vendor signed.
//!
//! A report that verifies is then admitted through the attestation
//! transparency log ([`crate::attestation_log`]): its measurement must have
//! been published, and a chip seen before in another facility is refused
//! with both log entries returned as evidence.

use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;
use tenzro_tee::verify::nonce::NonceIssuer;

use crate::rpc::JsonRpcError;

/// Purpose tag nonces from this module are issued and redeemed under.
const PURPOSE: &str = "tee-attestation";

/// How long an issued nonce stays redeemable.
const NONCE_TTL: Duration = Duration::from_secs(300);

pub(crate) fn issuer() -> &'static NonceIssuer {
    static ISSUER: OnceLock<NonceIssuer> = OnceLock::new();
    ISSUER.get_or_init(|| NonceIssuer::new(NONCE_TTL))
}

/// The purpose tag the transparency log redeems nonces under.
pub(crate) const PUBLISH_PURPOSE: &str = PURPOSE;

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn hex_param(params: &Value, name: &str) -> Result<Option<Vec<u8>>, JsonRpcError> {
    match params.get(name).and_then(Value::as_str) {
        Some(s) => hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map(Some)
            .map_err(|e| invalid(format!("{name} is not hex: {e}"))),
        None => Ok(None),
    }
}

fn object_params(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(a)) => a.into_iter().next().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    }
}

/// The packet a report answering `nonce` for `bound_data` commits to.
pub(crate) fn challenge_packet(nonce: &[u8; 32], bound_data: &[u8]) -> Vec<u8> {
    let mut packet = nonce.to_vec();
    packet.extend_from_slice(bound_data);
    packet
}

/// Measurement registers as RPC results carry them.
pub(crate) fn measurements_json(measurements: &[tenzro_types::tee::Measurement]) -> Value {
    Value::Array(
        measurements
            .iter()
            .map(|m| {
                serde_json::json!({
                    "register": m.register,
                    "algorithm": m.algorithm,
                    "value_hex": format!("0x{}", hex::encode(&m.value)),
                })
            })
            .collect(),
    )
}

/// `tenzro_teeAttestationChallenge`: a fresh nonce for one verification.
pub(crate) async fn handle_attestation_challenge(
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let nonce = issuer().issue(PURPOSE).map_err(|e| JsonRpcError {
        code: -32603,
        message: e.to_string(),
        data: None,
    })?;
    Ok(serde_json::json!({
        "nonce": format!("0x{}", hex::encode(nonce)),
        "expires_in_secs": NONCE_TTL.as_secs(),
    }))
}

/// `tenzro_verifyTeeAttestation`: redeem the nonce and verify the report.
///
/// Params: `report_hex` (hex of the JSON `AttestationReport`), `nonce`,
/// optional `bound_data`, optional `facility` (a JSON `SignedFacilityClaim`).
pub(crate) async fn handle_verify_tee_attestation(
    store: Option<&dyn tenzro_storage::KvStore>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_tee::verify::facility::{SignedFacilityClaim, bound_packet};
    use tenzro_tee::verify::transparency::Refusal;

    let params = object_params(params);
    let report_bytes =
        hex_param(&params, "report_hex")?.ok_or_else(|| invalid("Missing report_hex"))?;
    let nonce_bytes = hex_param(&params, "nonce")?.ok_or_else(|| invalid("Missing nonce"))?;
    let nonce: [u8; 32] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("nonce must be 32 bytes"))?;
    let bound_data = hex_param(&params, "bound_data")?.unwrap_or_default();
    let facility: Option<SignedFacilityClaim> = params
        .get("facility")
        .map(|f| serde_json::from_value(f.clone()))
        .transpose()
        .map_err(|e| invalid(format!("Invalid facility claim: {e}")))?;
    let report: tenzro_types::tee::AttestationReport = serde_json::from_slice(&report_bytes)
        .map_err(|e| invalid(format!("Invalid attestation report: {e}")))?;

    if !issuer().redeem(&nonce, PURPOSE) {
        return Ok(serde_json::json!({
            "valid": false,
            "error": "nonce was not issued by this node, has expired, or was already used",
        }));
    }
    let packet = match &facility {
        Some(f) => match bound_packet(&nonce, f, &bound_data) {
            Ok(p) => p,
            Err(e) => return Ok(serde_json::json!({ "valid": false, "error": e.to_string() })),
        },
        None => challenge_packet(&nonce, &bound_data),
    };
    let expected = tenzro_types::tee::pack_user_data_for_vendor(report.vendor, &packet);
    let verified =
        match tenzro_tee::verify_report(&report, &tenzro_tee::VerifyPolicy::now(expected)) {
            Ok(v) => v,
            Err(e) => {
                return Ok(serde_json::json!({
                    "valid": false,
                    "vendor": format!("{:?}", report.vendor),
                    "error": e.to_string(),
                }));
            }
        };
    let admitted =
        crate::attestation_log::update(store, |log| log.admit(&verified, facility.as_ref()))?;
    Ok(match admitted {
        Ok(()) => serde_json::json!({
            "valid": true,
            "vendor": format!("{:?}", verified.vendor),
            "measurement_hex": format!("0x{}", hex::encode(&verified.measurement)),
            "measurements": measurements_json(&verified.measurements),
            "platform_id_hex": format!("0x{}", hex::encode(&verified.platform_id)),
            "tcb_status": verified.tcb_status,
            "facility": facility.as_ref().map(|f| f.claim.facility_id.clone()),
        }),
        Err(Refusal::NotLogged) => serde_json::json!({
            "valid": false,
            "error": "the attested measurement is not in the attestation transparency log",
            "measurements": measurements_json(&verified.measurements),
        }),
        Err(Refusal::BadFacilityClaim) => serde_json::json!({
            "valid": false,
            "error": "the facility claim is not signed by the facility key",
        }),
        Err(Refusal::FacilityMismatch {
            recorded,
            presented,
        }) => serde_json::json!({
            "valid": false,
            "error": "this chip was first placed in a different facility",
            "evidence": { "recorded": recorded, "presented": presented },
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forged_report(nonce: &[u8; 32]) -> String {
        let vendor = tenzro_types::tee::TeeVendor::AmdSevSnp;
        let mut report = tenzro_types::tee::AttestationReport {
            vendor,
            attestation_data: vec![0; 1184],
            user_data: tenzro_types::tee::pack_user_data_for_vendor(
                vendor,
                &challenge_packet(nonce, b""),
            ),
            measurement: vec![1; 48],
            ..Default::default()
        };
        report.metadata.insert("simulated".into(), "true".into());
        hex::encode(serde_json::to_vec(&report).unwrap())
    }

    async fn challenge() -> [u8; 32] {
        let v = handle_attestation_challenge(None).await.unwrap();
        let h = v["nonce"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x")
            .to_string();
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn a_well_formed_but_unsigned_report_is_invalid() {
        let nonce = challenge().await;
        let v = handle_verify_tee_attestation(
            None,
            Some(serde_json::json!({
                "report_hex": forged_report(&nonce),
                "nonce": hex::encode(nonce),
            })),
        )
        .await
        .unwrap();
        assert_eq!(v["valid"], false);
    }

    #[tokio::test]
    async fn a_nonce_is_redeemed_once_and_must_be_issued() {
        let nonce = challenge().await;
        let params =
            serde_json::json!({ "report_hex": forged_report(&nonce), "nonce": hex::encode(nonce) });
        handle_verify_tee_attestation(None, Some(params.clone()))
            .await
            .unwrap();
        let again = handle_verify_tee_attestation(None, Some(params))
            .await
            .unwrap();
        assert!(again["error"].as_str().unwrap().contains("already used"));
        let unissued = [9u8; 32];
        let v = handle_verify_tee_attestation(
            None,
            Some(serde_json::json!({
                "report_hex": forged_report(&unissued),
                "nonce": hex::encode(unissued),
            })),
        )
        .await
        .unwrap();
        assert_eq!(v["valid"], false);
    }
}
