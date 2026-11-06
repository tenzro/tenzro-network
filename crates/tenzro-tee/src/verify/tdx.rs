//! Intel TDX quote verification (DCAP), through `dcap-qvl`.
//!
//! The quote's ECDSA signature is checked with the attestation key the quote
//! carries, and that key is only trusted because the Quoting Enclave's report
//! binds it (the QE report data holds a hash of the key and the QE auth data)
//! and the QE report is signed by the platform's PCK. The PCK certificate
//! chains to Intel's SGX root CA, checked against the PCK and root CRLs. The
//! QE identity and the TCB info are Intel-signed collateral that say whether
//! this QE and this platform's TCB are current. `dcap-qvl` performs every one
//! of those checks; this module supplies the collateral, refuses debug TDs,
//! refuses TCB states that need action, and binds the report data.
//!
//! The collateral is carried in the report's metadata under
//! [`COLLATERAL_KEY`] as the JSON form of `QuoteCollateralV3`. It is Intel
//! signed, so the attester may supply it; the verifier trusts only the
//! signatures, and requires it to be current at the verification time.

use std::collections::BTreeMap;

use tenzro_types::tee::{AttestationReport, Measurement, TeeVendor};

use super::{VerifiedAttestation, VerifyPolicy, ct_eq, fail};
use crate::error::Result;

/// Metadata key holding the quote's DCAP collateral (JSON).
pub const COLLATERAL_KEY: &str = "tdx_collateral";

/// TCB states a TD may be admitted with. Every other state (out of date,
/// configuration needed, revoked) means the platform owner has work to do and
/// the evidence is refused until they do it.
const ACCEPTED_TCB: &[&str] = &["UpToDate", "SWHardeningNeeded"];

pub fn verify(report: &AttestationReport, policy: &VerifyPolicy) -> Result<VerifiedAttestation> {
    let collateral_json = report
        .metadata
        .get(COLLATERAL_KEY)
        .ok_or_else(|| fail("TDX report carries no DCAP collateral"))?;
    let collateral: dcap_qvl::QuoteCollateralV3 =
        serde_json::from_str(collateral_json).map_err(|e| fail(format!("TDX collateral: {e}")))?;
    verify_quote(&report.attestation_data, &collateral, policy)
}

/// Verify a raw TDX quote against its collateral.
pub fn verify_quote(
    quote: &[u8],
    collateral: &dcap_qvl::QuoteCollateralV3,
    policy: &VerifyPolicy,
) -> Result<VerifiedAttestation> {
    let verified = dcap_qvl::verify::QuoteVerifier::new_prod()
        .with_config::<dcap_qvl::configs::RingConfig>()
        .allow_debug(false)
        .verify(quote, collateral, policy.now)
        .map_err(|e| fail(format!("TDX quote: {e}")))?;
    if !ACCEPTED_TCB.contains(&verified.status.as_str()) {
        return Err(fail(format!("TDX platform TCB is {}", verified.status)));
    }
    let td = verified
        .report
        .as_td10()
        .ok_or_else(|| fail("quote is not a TDX quote"))?;
    if !ct_eq(&td.report_data, &policy.expected_user_data) {
        return Err(fail("TDX report data does not answer this challenge"));
    }

    let mut measurements = vec![Measurement {
        index: 0,
        algorithm: "SHA384".into(),
        value: td.mr_td.to_vec(),
        register: "MRTD".into(),
        description: None,
    }];
    for (i, rtmr) in [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3]
        .iter()
        .enumerate()
    {
        measurements.push(Measurement {
            index: i as u32 + 1,
            algorithm: "SHA384".into(),
            value: rtmr.to_vec(),
            register: format!("RTMR{i}"),
            description: None,
        });
    }
    let mut details = BTreeMap::new();
    details.insert("advisory_ids".into(), verified.advisory_ids.join(","));
    details.insert("mr_seam".into(), hex::encode(td.mr_seam));
    Ok(VerifiedAttestation {
        vendor: TeeVendor::IntelTdx,
        measurement: td.mr_td.to_vec(),
        user_data: td.report_data.to_vec(),
        tcb_status: verified.status,
        platform_id: verified.ppid,
        measurements,
        details,
    })
}

#[cfg(test)]
mod tests {
    //! The quote and collateral are a recorded production TDX quote and the
    //! Intel PCS collateral for it, from the `dcap-qvl` crate's sample set
    //! (MIT licence, Phala Network). The verification time is inside the
    //! collateral's validity window.

    use super::*;

    const QUOTE: &[u8] = include_bytes!("../../testdata/tdx/tdx_quote");
    const COLLATERAL: &[u8] = include_bytes!("../../testdata/tdx/tdx_quote_collateral.json");
    /// 2025-06-20T00:00:00Z, inside every validity window of the collateral.
    const NOW: u64 = 1_750_377_600;

    fn collateral() -> dcap_qvl::QuoteCollateralV3 {
        serde_json::from_slice(COLLATERAL).unwrap()
    }

    fn report_data() -> Vec<u8> {
        let v = dcap_qvl::verify::QuoteVerifier::new_prod()
            .with_config::<dcap_qvl::configs::RingConfig>()
            .verify(QUOTE, &collateral(), NOW)
            .unwrap();
        v.report.as_td10().unwrap().report_data.to_vec()
    }

    fn policy(user_data: Vec<u8>) -> VerifyPolicy {
        VerifyPolicy {
            now: NOW,
            expected_user_data: user_data,
            max_age_secs: 600,
            nvidia_jwks: None,
        }
    }

    #[test]
    fn a_recorded_production_quote_verifies() {
        let v = verify_quote(QUOTE, &collateral(), &policy(report_data())).unwrap();
        assert_eq!(v.vendor, TeeVendor::IntelTdx);
        assert_eq!(v.measurement.len(), 48);
        assert_eq!(v.tcb_status, "UpToDate");
    }

    #[test]
    fn a_quote_answering_another_challenge_is_refused() {
        assert!(verify_quote(QUOTE, &collateral(), &policy(vec![0; 64])).is_err());
    }

    #[test]
    fn any_changed_byte_in_the_td_report_is_refused() {
        // Header is 48 bytes; the TD report body follows. Flip a byte of MRTD.
        let mut q = QUOTE.to_vec();
        q[48 + 16 + 48 + 48 + 8 + 8 + 8] ^= 1;
        assert!(verify_quote(&q, &collateral(), &policy(report_data())).is_err());
    }

    #[test]
    fn tampered_collateral_is_refused() {
        let mut c = collateral();
        c.tcb_info = c.tcb_info.replace("UpToDate", "UpToDatf");
        assert!(verify_quote(QUOTE, &c, &policy(report_data())).is_err());
    }

    #[test]
    fn expired_collateral_is_refused() {
        let mut p = policy(report_data());
        p.now = NOW + 365 * 24 * 3600;
        assert!(verify_quote(QUOTE, &collateral(), &p).is_err());
    }

    #[test]
    fn a_report_without_collateral_is_refused() {
        let report = AttestationReport {
            vendor: TeeVendor::IntelTdx,
            attestation_data: QUOTE.to_vec(),
            ..Default::default()
        };
        assert!(verify(&report, &policy(report_data())).is_err());
    }

    #[test]
    fn the_report_path_reads_collateral_from_metadata() {
        let mut report = AttestationReport {
            vendor: TeeVendor::IntelTdx,
            attestation_data: QUOTE.to_vec(),
            ..Default::default()
        };
        report.metadata.insert(
            COLLATERAL_KEY.to_string(),
            String::from_utf8(COLLATERAL.to_vec()).unwrap(),
        );
        assert!(verify(&report, &policy(report_data())).is_ok());
    }
}
