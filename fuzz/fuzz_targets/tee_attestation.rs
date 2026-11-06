//! Fuzzes TEE attestation evidence a node verifies for others: Intel TDX
//! quotes with their collateral, AMD SEV-SNP reports with their chain and
//! revocation list, AWS Nitro documents, NVIDIA composite evidence, and the
//! X.509 parsing under all of them.
//!
//! Input: a vendor byte, then length-prefixed parts (u16, little-endian):
//! the evidence, a metadata value, a second metadata value, then
//! certificates. Property: nothing panics, and no fuzzed evidence verifies
//! (it chains to no vendor root).

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use tenzro_tee::verify::{nvidia, snp, tdx};
use tenzro_tee::{AttestationReport, TeeVendor, VerifyPolicy, verify_report};

fn parts(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 && out.len() < 16 {
        let len = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let end = (2 + len).min(data.len());
        out.push(&data[2..end]);
        data = &data[end..];
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let p = parts(rest);
    let part = |i: usize| p.get(i).copied().unwrap_or_default();
    let text = |i: usize| String::from_utf8_lossy(part(i)).into_owned();
    let (vendor, keys): (TeeVendor, &[&str]) = match which % 5 {
        0 => (TeeVendor::IntelTdx, &[tdx::COLLATERAL_KEY]),
        1 => (TeeVendor::AmdSevSnp, &[snp::CRL_KEY]),
        2 => (TeeVendor::AwsNitro, &[]),
        3 => (
            TeeVendor::NvidiaGpu,
            &[nvidia::CPU_ANCHOR_KEY, nvidia::NRAS_TOKEN_KEY],
        ),
        _ => {
            let _ = tenzro_tee::x509::parse(part(0));
            let _ = tenzro_tee::x509::parse_pem_chain(&text(0));
            let _ = nvidia::verify_gpu_leg(
                &text(0),
                &serde_json::from_slice(part(1)).unwrap_or_default(),
                &text(2),
                1_790_000_000,
            );
            return;
        }
    };
    let metadata: HashMap<String, String> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ((*k).to_string(), text(i + 1)))
        .collect();
    let report = AttestationReport {
        vendor,
        attestation_data: part(0).to_vec(),
        certificates: p.iter().skip(3).map(|c| c.to_vec()).collect(),
        metadata,
        ..AttestationReport::default()
    };
    let policy = VerifyPolicy {
        now: 1_790_000_000,
        expected_user_data: vec![0; 64],
        max_age_secs: 600,
        nvidia_jwks: Some(text(2)),
    };
    assert!(
        verify_report(&report, &policy).is_err(),
        "fuzzed evidence verified"
    );
});
