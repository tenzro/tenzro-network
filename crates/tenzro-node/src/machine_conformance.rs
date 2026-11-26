//! The check a device maker runs on its own device before shipping it:
//! whether the machine can be admitted as an autonomous identity, by the
//! same attestation the network runs at admission
//! (docs/standards/machine-identity-onboarding.md).
//!
//! `tenzro-node tpm check` attests the local TPM (credential activation and
//! a quote over the admission challenge, both verified on the machine),
//! collects the machine's identifier sources, grades its endorsement against
//! the manufacturer roots it is given, and prints one line per requirement.
//! It exits non-zero when a required one is not met.

use tenzro_tee::tpm_attest::{EndorsementGrade, MachineAttestation};
use tenzro_types::machine_id::{IdentifierGrade, IdentifierSource};

/// One requirement of the onboarding standard and whether this machine
/// meets it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Requirement {
    /// Its name in the standard.
    pub id: &'static str,
    /// Whether admission needs it; one that is not required is a reputation
    /// signal relying parties weigh.
    pub required: bool,
    pub met: bool,
    pub detail: String,
}

/// The requirements a machine with `did`, attested as `attestation`, whose
/// identity sources are `sources` (labels) and whose endorsement grades as
/// `endorsement`, meets.
pub fn requirements(
    did: &str,
    attestation: &MachineAttestation,
    sources: &[String],
    endorsement: &EndorsementGrade,
) -> Vec<Requirement> {
    let derived = tenzro_tee::tpm_attest::attestation_key_sec1(&attestation.evidence)
        .map(|ak| tenzro_tee::tpm_attest::machine_did_for_attestation_key(&ak));
    let attestable: Vec<&str> = sources
        .iter()
        .filter_map(|s| IdentifierSource::parse(s))
        .filter(|s| s.grade() == IdentifierGrade::Attestable)
        .map(|s| s.as_str())
        .collect();
    vec![
        Requirement {
            id: "credential-activation",
            required: true,
            met: attestation.activated,
            detail: if attestation.activated {
                "the attestation key lives in the TPM that holds the endorsement key".into()
            } else {
                "credential activation did not run".into()
            },
        },
        Requirement {
            id: "did-from-attestation-key",
            required: true,
            met: derived.as_deref().is_ok_and(|d| d == did),
            detail: match &derived {
                Ok(d) => format!("the attestation key roots {d}"),
                Err(e) => format!("the attestation key does not read: {e}"),
            },
        },
        Requirement {
            id: "attestable-identifier",
            required: true,
            met: !attestable.is_empty(),
            detail: if attestable.is_empty() {
                format!("no attestable source among {sources:?}")
            } else {
                format!("attestable sources: {}", attestable.join(", "))
            },
        },
        Requirement {
            id: "manufacturer-endorsement",
            required: false,
            met: *endorsement == EndorsementGrade::ManufacturerCertified,
            detail: match endorsement {
                EndorsementGrade::ManufacturerCertified => {
                    "the EK certificate chains to a manufacturer root".into()
                }
                EndorsementGrade::FirmwareCertified => {
                    "the EK certificate chains to a manufacturer root, for a TPM implemented in the processor's firmware: a lower tier than a discrete chip".into()
                }
                EndorsementGrade::Uncertified(why) => why.clone(),
            },
        },
    ]
}

/// Whether every required requirement is met.
pub fn admissible(requirements: &[Requirement]) -> bool {
    requirements.iter().all(|r| r.met || !r.required)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation(activated: bool) -> MachineAttestation {
        MachineAttestation {
            evidence: tenzro_tee::tpm_attest::TpmEvidence {
                ek_public: Vec::new(),
                ek_certificate: Vec::new(),
                ek_intermediates: Vec::new(),
                ak_public: Vec::new(),
                quote: Vec::new(),
                quote_signature: Vec::new(),
            },
            nonce: Vec::new(),
            activated,
        }
    }

    #[test]
    fn each_requirement_reports_what_it_found() {
        let reqs = requirements(
            "did:tenzro:machine:x",
            &attestation(true),
            &["tpm:ek".into(), "smbios:platform".into()],
            &EndorsementGrade::Uncertified("the TPM holds no EK certificate".into()),
        );
        let by = |id: &str| reqs.iter().find(|r| r.id == id).unwrap().clone();
        assert!(by("credential-activation").met);
        assert!(by("attestable-identifier").met);
        assert!(by("attestable-identifier").detail.contains("tpm:ek"));
        assert!(
            !by("did-from-attestation-key").met,
            "an attestation key that does not read roots no DID"
        );
        assert!(!by("manufacturer-endorsement").met);
        assert!(!by("manufacturer-endorsement").required);
        assert!(!admissible(&reqs));
    }

    #[test]
    fn only_a_required_requirement_blocks_admission() {
        let met = |id, required, met| Requirement {
            id,
            required,
            met,
            detail: String::new(),
        };
        assert!(admissible(&[
            met("a", true, true),
            met("manufacturer-endorsement", false, false)
        ]));
        assert!(!admissible(&[met("a", true, false)]));
    }

    #[test]
    fn a_machine_with_only_readable_identifiers_is_not_admissible() {
        let reqs = requirements(
            "did:tenzro:machine:x",
            &attestation(false),
            &[
                "smbios:platform".into(),
                "arm:midr".into(),
                "intel:ppin".into(),
            ],
            &EndorsementGrade::ManufacturerCertified,
        );
        let attestable = reqs
            .iter()
            .find(|r| r.id == "attestable-identifier")
            .unwrap();
        assert!(!attestable.met);
        assert!(
            !reqs
                .iter()
                .find(|r| r.id == "credential-activation")
                .unwrap()
                .met
        );
    }
}
