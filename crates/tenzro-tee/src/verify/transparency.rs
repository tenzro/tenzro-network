//! An append-only log of attestation measurements and where each chip was
//! seen, with a verifier that refuses anything not in it.
//!
//! Two kinds of entry:
//!
//! - **Measurement**: a launch measurement (MRTD, SNP `MEASUREMENT`, Nitro
//!   PCR0) that some publisher, identified by a hardware-derived DID, states
//!   is a build it stands behind. A node whose verified measurement is not in
//!   the log is refused: every image the network runs is public, forever.
//! - **Placement**: the first time a chip (its platform id) is admitted with a
//!   facility claim, the pair is recorded. Presenting the same chip later from
//!   a different facility is a contradiction the log can prove, and
//!   [`Refusal::FacilityMismatch`] carries both entries as slashing evidence.
//!
//! Entries are hash-chained: each entry's hash covers the previous head, so
//! the log can only grow and any rewrite changes every later head. The log is
//! a pure data structure; where it is stored and replicated (consensus state)
//! and what a mismatch costs (slashing) are decided by its owner.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::tee::TeeVendor;

use super::VerifiedAttestation;
use super::facility::SignedFacilityClaim;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryBody {
    Measurement {
        vendor: TeeVendor,
        measurement: Vec<u8>,
        publisher_did: String,
    },
    Placement {
        vendor: TeeVendor,
        platform_id: Vec<u8>,
        facility: SignedFacilityClaim,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub body: EntryBody,
    /// Head of the log before this entry.
    pub prev: [u8; 32],
    /// This entry's hash, which is the new head.
    pub hash: [u8; 32],
}

fn entry_hash(prev: &[u8; 32], body: &EntryBody) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/attestation-log/v1\0");
    h.update(prev);
    h.update(serde_json::to_vec(body).expect("log entries serialize"));
    h.finalize().into()
}

/// Why the log refused a verified attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The measurement was never published.
    NotLogged,
    /// The chip was first placed in one facility and is now presented from
    /// another. Both entries are evidence of a false claim.
    FacilityMismatch {
        recorded: Box<LogEntry>,
        presented: SignedFacilityClaim,
    },
    /// The facility claim's signature does not verify.
    BadFacilityClaim,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransparencyLog {
    entries: Vec<LogEntry>,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from stored entries, re-checking the whole hash chain.
    pub fn from_entries(entries: Vec<LogEntry>) -> Option<Self> {
        let log = Self { entries };
        log.verify_chain().then_some(log)
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Current head; all zeros for an empty log.
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map(|e| e.hash).unwrap_or([0; 32])
    }

    fn push(&mut self, body: EntryBody) -> [u8; 32] {
        let prev = self.head();
        let hash = entry_hash(&prev, &body);
        self.entries.push(LogEntry { body, prev, hash });
        hash
    }

    /// Publish a measurement. Idempotent: an already-logged measurement is not
    /// appended twice.
    pub fn publish_measurement(
        &mut self,
        vendor: TeeVendor,
        measurement: Vec<u8>,
        publisher_did: String,
    ) -> [u8; 32] {
        if self.contains_measurement(vendor, &measurement) {
            return self.head();
        }
        self.push(EntryBody::Measurement {
            vendor,
            measurement,
            publisher_did,
        })
    }

    pub fn contains_measurement(&self, vendor: TeeVendor, measurement: &[u8]) -> bool {
        self.entries.iter().any(|e| {
            matches!(&e.body, EntryBody::Measurement { vendor: v, measurement: m, .. }
                if *v == vendor && m.as_slice() == measurement)
        })
    }

    fn placement(&self, vendor: TeeVendor, platform_id: &[u8]) -> Option<&LogEntry> {
        self.entries.iter().find(|e| {
            matches!(&e.body, EntryBody::Placement { vendor: v, platform_id: p, .. }
                if *v == vendor && p.as_slice() == platform_id)
        })
    }

    /// Admit a verified attestation: its measurement must be logged, and when
    /// it carries a facility claim, the chip must not have been placed in a
    /// different facility before. A first placement is recorded.
    pub fn admit(
        &mut self,
        verified: &VerifiedAttestation,
        facility: Option<&SignedFacilityClaim>,
    ) -> Result<(), Refusal> {
        if !self.contains_measurement(verified.vendor, &verified.measurement) {
            return Err(Refusal::NotLogged);
        }
        let Some(facility) = facility else {
            return Ok(());
        };
        if facility.verify().is_err() {
            return Err(Refusal::BadFacilityClaim);
        }
        match self.placement(verified.vendor, &verified.platform_id) {
            Some(entry) => match &entry.body {
                EntryBody::Placement {
                    facility: recorded, ..
                } if recorded.claim.facility_id == facility.claim.facility_id
                    && recorded.claim.facility_key == facility.claim.facility_key =>
                {
                    Ok(())
                }
                _ => Err(Refusal::FacilityMismatch {
                    recorded: Box::new(entry.clone()),
                    presented: facility.clone(),
                }),
            },
            None => {
                self.push(EntryBody::Placement {
                    vendor: verified.vendor,
                    platform_id: verified.platform_id.clone(),
                    facility: facility.clone(),
                });
                Ok(())
            }
        }
    }

    /// Check every entry's hash and link.
    pub fn verify_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for e in &self.entries {
            if e.prev != prev || e.hash != entry_hash(&prev, &e.body) {
                return false;
            }
            prev = e.hash;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::facility::tests::signed;
    use super::*;
    use std::collections::BTreeMap;

    fn verified(measurement: u8, chip: u8) -> VerifiedAttestation {
        VerifiedAttestation {
            vendor: TeeVendor::AmdSevSnp,
            measurement: vec![measurement; 48],
            user_data: vec![],
            tcb_status: String::new(),
            platform_id: vec![chip; 64],
            measurements: vec![],
            details: BTreeMap::new(),
        }
    }

    #[test]
    fn an_unlogged_measurement_is_refused() {
        let mut log = TransparencyLog::new();
        assert_eq!(log.admit(&verified(1, 1), None), Err(Refusal::NotLogged));
        log.publish_measurement(
            TeeVendor::AmdSevSnp,
            vec![1; 48],
            "did:tenzro:machine:p".into(),
        );
        assert_eq!(log.admit(&verified(1, 1), None), Ok(()));
        assert_eq!(log.admit(&verified(2, 1), None), Err(Refusal::NotLogged));
    }

    #[test]
    fn a_chip_moved_to_another_facility_yields_evidence() {
        let mut log = TransparencyLog::new();
        log.publish_measurement(TeeVendor::AmdSevSnp, vec![1; 48], "did:p".into());
        let fra = signed("fra-1", 4);
        let iad = signed("iad-1", 5);
        assert_eq!(log.admit(&verified(1, 9), Some(&fra)), Ok(()));
        assert_eq!(log.admit(&verified(1, 9), Some(&fra)), Ok(()));
        match log.admit(&verified(1, 9), Some(&iad)) {
            Err(Refusal::FacilityMismatch {
                recorded,
                presented,
            }) => {
                assert!(matches!(recorded.body, EntryBody::Placement { .. }));
                assert_eq!(presented.claim.facility_id, "iad-1");
            }
            other => panic!("expected a facility mismatch, got {other:?}"),
        }
        assert_eq!(
            log.admit(&verified(1, 10), Some(&iad)),
            Ok(()),
            "another chip may be elsewhere"
        );
    }

    #[test]
    fn the_chain_detects_a_rewritten_entry() {
        let mut log = TransparencyLog::new();
        log.publish_measurement(TeeVendor::IntelTdx, vec![1; 48], "did:a".into());
        log.publish_measurement(TeeVendor::IntelTdx, vec![2; 48], "did:a".into());
        assert!(log.verify_chain());
        let mut entries = log.entries().to_vec();
        entries[0].body = EntryBody::Measurement {
            vendor: TeeVendor::IntelTdx,
            measurement: vec![3; 48],
            publisher_did: "did:a".into(),
        };
        assert!(TransparencyLog::from_entries(entries).is_none());
    }

    #[test]
    fn a_forged_facility_claim_is_refused() {
        let mut log = TransparencyLog::new();
        log.publish_measurement(TeeVendor::AmdSevSnp, vec![1; 48], "did:p".into());
        let mut f = signed("fra-1", 4);
        f.claim.facility_id = "fra-2".into();
        assert_eq!(
            log.admit(&verified(1, 9), Some(&f)),
            Err(Refusal::BadFacilityClaim)
        );
    }
}
