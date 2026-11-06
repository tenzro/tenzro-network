//! Fuzzes device-key evidence a node verifies for others: TPM key
//! certifications, TPM wire structures and responses, TPM machine evidence
//! and its endorsement, and sealed key envelopes.
//!
//! The first byte picks the decoder. Property: nothing panics, and no
//! fuzzed certification or quote verifies.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_device_key::key_certification::{self, KeyCertification};
use tenzro_device_key::tpm_wire;
use tenzro_tee::tpm_attest::{self, MachineAttestation, TpmEvidence};

fn parts(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 && out.len() < 8 {
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
    match which % 5 {
        0 => {
            if let Ok((cert, tail)) = KeyCertification::from_bytes(rest) {
                let key = tail.get(..64).unwrap_or(tail);
                let mut attestation_key = [4u8; 65];
                if let Some(ak) = tail.get(64..129) {
                    attestation_key.copy_from_slice(ak);
                }
                assert!(
                    key_certification::verify(&cert, key, b"fuzz", &attestation_key).is_err()
                );
                assert_eq!(
                    KeyCertification::from_bytes(&cert.to_bytes()).map(|(c, _)| c),
                    Ok(cert)
                );
            }
        }
        1 => {
            if let Ok(area) = tpm_wire::parse_public(rest) {
                let _ = area.name();
            }
            let _ = tpm_wire::parse_keyedhash_public(rest);
            let _ = tpm_wire::parse_quote(rest);
            let _ = tpm_wire::parse_certify(rest);
        }
        2 => {
            let _ = tpm_wire::parse_create_primary_response(rest);
            let _ = tpm_wire::parse_read_public_response(rest);
            let _ = tpm_wire::parse_sign_response(rest);
            let _ = tpm_wire::parse_certify_response(rest);
            let _ = tpm_wire::parse_quote_response(rest);
            let _ = tpm_wire::parse_nv_read_response(rest);
            let _ = tpm_wire::parse_activate_credential_response(rest);
            let _ = tpm_wire::parse_pcr_read_response(rest);
            let _ = tpm_wire::parse_create_response(rest);
            let _ = tpm_wire::parse_hash_response(rest);
        }
        3 => {
            let p = parts(rest);
            let part = |i: usize| p.get(i).map(|b| b.to_vec()).unwrap_or_default();
            let evidence = TpmEvidence {
                ek_public: part(0),
                ek_certificate: part(1),
                ek_intermediates: vec![part(2)],
                ak_public: part(3),
                quote: part(4),
                quote_signature: part(5),
            };
            assert!(tpm_attest::verify_quote(&evidence, b"fuzz").is_err());
            assert!(tpm_attest::verify_endorsement(&evidence, &[], 1_790_000_000).is_err());
            let _ = tpm_attest::attestation_key_sec1(&evidence);
            let att = MachineAttestation {
                evidence,
                nonce: part(6),
                activated: false,
            };
            let _ = tenzro_tee::identity_evidence::endorsement_label(&att, &[]);
            let _ = tenzro_tee::identity_evidence::tpm_evidence_binds(
                "did:tenzro:machine:fuzz",
                &[4; 65],
                &att,
            );
        }
        _ => {
            let _ = tenzro_device_key::envelope::Envelope::parse(rest);
        }
    }
});
