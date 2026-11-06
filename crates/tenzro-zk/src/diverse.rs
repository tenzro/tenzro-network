//! k-of-n acceptance across independent proof systems.
//!
//! A statement is accepted when proofs of it verify in at least `k` distinct
//! [`ProofSystem`]s. Every leg must name the same circuit and carry the same
//! public inputs; every leg supplied must verify (a failing leg is evidence of
//! an attempted forgery and fails the whole set, rather than being skipped).
//!
//! The accepted legs must also come from at least [`MIN_IMPLEMENTATIONS`]
//! independently written implementations ([`Implementation`]). The two
//! Plonky3 systems share the uni-STARK protocol code and differ in field,
//! extension, hash and FRI rate, so a forgery that exploits one field, one
//! hash or one parameter set does not produce a second accepting leg. The
//! Halo2 system shares nothing but the statement, so a defect in either
//! implementation's protocol code does not produce an accepting leg in the
//! other.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::plonky3::verify_envelope::{VerifyEnvelopeError, verify_proof_envelope};
use crate::proof::{Implementation, Proof, ProofSystem};

/// Distinct systems a statement needs before the network treats it as
/// proven. Equal to the number of systems, so every one must verify.
pub const DIVERSE_THRESHOLD: usize = ProofSystem::ALL.len();

/// Distinct implementations the accepted legs must come from, whatever `k`.
pub const MIN_IMPLEMENTATIONS: usize = 2;

/// Why a set of legs was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum DiverseError {
    /// No legs were supplied.
    #[error("no proofs supplied")]
    Empty,
    /// A leg names a different circuit or different public inputs.
    #[error("leg {index} proves a different statement from leg 0")]
    StatementMismatch {
        /// Position of the offending leg.
        index: usize,
    },
    /// A leg failed verification.
    #[error("leg {index} ({system}) failed: {source}")]
    LegRejected {
        /// Position of the failing leg.
        index: usize,
        /// Its proof system.
        system: ProofSystem,
        /// The verifier's reason.
        source: VerifyEnvelopeError,
    },
    /// Every leg verified but too few distinct systems were represented.
    #[error("{distinct} distinct proof systems verified, {required} required")]
    TooFewSystems {
        /// Distinct systems that verified.
        distinct: usize,
        /// Systems required.
        required: usize,
    },
    /// Every leg verified but they all come from one implementation.
    #[error("proofs from {distinct} implementation(s) verified, {MIN_IMPLEMENTATIONS} required")]
    TooFewImplementations {
        /// Distinct implementations that verified.
        distinct: usize,
    },
}

/// The outcome of an accepted set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiverseVerdict {
    /// The statement the legs prove.
    pub statement: [u8; 32],
    /// Distinct systems that verified, in stable order.
    pub systems: Vec<ProofSystem>,
    /// Distinct implementations those systems belong to, in stable order.
    pub implementations: Vec<Implementation>,
}

/// Commitment to a statement, independent of any proof or proof system:
/// `SHA-256("tenzro/zk/statement" || len(circuit_id) || circuit_id ||
/// count || Σ(len(pi) || pi))`, lengths as 4-byte little-endian.
///
/// This is the value a registry should record once a statement meets the
/// diversity threshold: it is the same whichever legs proved it.
pub fn statement_commitment(circuit_id: &str, public_inputs: &[Vec<u8>]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/zk/statement");
    h.update((circuit_id.len() as u32).to_le_bytes());
    h.update(circuit_id.as_bytes());
    h.update((public_inputs.len() as u32).to_le_bytes());
    for pi in public_inputs {
        h.update((pi.len() as u32).to_le_bytes());
        h.update(pi);
    }
    h.finalize().into()
}

/// Verify `legs` and accept the statement if at least `k` distinct systems,
/// from at least [`MIN_IMPLEMENTATIONS`] implementations, prove it.
pub fn verify_k_of_n(legs: &[Proof], k: usize) -> Result<DiverseVerdict, DiverseError> {
    let first = legs.first().ok_or(DiverseError::Empty)?;
    for (index, leg) in legs.iter().enumerate() {
        if leg.circuit_id != first.circuit_id || leg.public_inputs != first.public_inputs {
            return Err(DiverseError::StatementMismatch { index });
        }
    }
    let mut systems = BTreeSet::new();
    for (index, leg) in legs.iter().enumerate() {
        verify_proof_envelope(leg).map_err(|source| DiverseError::LegRejected {
            index,
            system: leg.system,
            source,
        })?;
        systems.insert(leg.system);
    }
    if systems.len() < k {
        return Err(DiverseError::TooFewSystems {
            distinct: systems.len(),
            required: k,
        });
    }
    let implementations: BTreeSet<Implementation> =
        systems.iter().map(|s| s.implementation()).collect();
    if implementations.len() < MIN_IMPLEMENTATIONS {
        return Err(DiverseError::TooFewImplementations {
            distinct: implementations.len(),
        });
    }
    Ok(DiverseVerdict {
        statement: statement_commitment(&first.circuit_id, &first.public_inputs),
        systems: systems.into_iter().collect(),
        implementations: implementations.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::Circuit;
    use crate::plonky3::prove;

    const WITNESS: [u8; 32] = [0x42; 32];
    const BINDING: [u8; 32] = [0x99; 32];

    /// One honest leg per system, proven once for the whole module.
    fn legs() -> Vec<Proof> {
        static LEGS: std::sync::OnceLock<Vec<Proof>> = std::sync::OnceLock::new();
        LEGS.get_or_init(|| {
            ProofSystem::ALL
                .into_iter()
                .map(|s| prove(s, Circuit::Settlement, &WITNESS, &BINDING).unwrap())
                .collect()
        })
        .clone()
    }

    /// A valid proof in `system` of a different witness, relabelled as a
    /// proof of the honest statement.
    fn forged_leg(system: ProofSystem) -> Proof {
        let mut other = prove(system, Circuit::Settlement, &[0x43; 32], &BINDING).unwrap();
        other.public_inputs = legs()[0].public_inputs.clone();
        other
    }

    #[test]
    fn every_system_meets_the_threshold() {
        let v = verify_k_of_n(&legs(), DIVERSE_THRESHOLD).expect("every system");
        assert_eq!(v.systems, ProofSystem::ALL.to_vec());
        assert_eq!(
            v.implementations,
            vec![Implementation::Plonky3, Implementation::Halo2]
        );
        assert_eq!(
            v.statement,
            statement_commitment("settlement", &legs()[0].public_inputs)
        );
    }

    /// Two copies of the same system's proof do not count as two systems.
    #[test]
    fn the_same_system_twice_is_one_system() {
        let one = legs().remove(0);
        let err = verify_k_of_n(&[one.clone(), one], DIVERSE_THRESHOLD).unwrap_err();
        assert!(matches!(
            err,
            DiverseError::TooFewSystems {
                distinct: 1,
                required: DIVERSE_THRESHOLD
            }
        ));
    }

    /// A forged second leg (valid bytes for a different statement, relabelled)
    /// fails the whole set instead of being ignored.
    #[test]
    fn one_bad_leg_fails_the_set() {
        let mut set = legs();
        set[1] = forged_leg(ProofSystem::GoldilocksBlake3Fri);
        let err = verify_k_of_n(&set, DIVERSE_THRESHOLD).unwrap_err();
        assert!(matches!(err, DiverseError::LegRejected { index: 1, .. }));
    }

    /// Both Plonky3 systems accept the statement, the Halo2 verifier does
    /// not: the set is refused. And the converse.
    #[test]
    fn a_statement_one_implementation_rejects_is_refused() {
        let halo2 = ProofSystem::Halo2IpaPasta;
        let halo2_index = ProofSystem::ALL.iter().position(|s| *s == halo2).unwrap();

        let mut set = legs();
        set[halo2_index] = forged_leg(halo2);
        for (i, leg) in set.iter().enumerate() {
            let verdict = crate::verify_proof_envelope(leg);
            assert_eq!(verdict.is_ok(), i != halo2_index, "{}", leg.system);
        }
        assert!(matches!(
            verify_k_of_n(&set, DIVERSE_THRESHOLD),
            Err(DiverseError::LegRejected { index, system, .. }) if index == halo2_index && system == halo2
        ));

        let mut set = legs();
        set[0] = forged_leg(ProofSystem::KoalaBearSha256Fri);
        assert!(crate::verify_proof_envelope(&set[halo2_index]).is_ok());
        assert!(matches!(
            verify_k_of_n(&set, DIVERSE_THRESHOLD),
            Err(DiverseError::LegRejected { index: 0, .. })
        ));
    }

    /// Two systems that share one implementation are not independent: a
    /// threshold of two met only by the Plonky3 systems is refused.
    #[test]
    fn systems_of_one_implementation_alone_are_refused() {
        let plonky3: Vec<Proof> = legs()
            .into_iter()
            .filter(|p| p.system.implementation() == Implementation::Plonky3)
            .collect();
        assert_eq!(plonky3.len(), 2);
        assert!(matches!(
            verify_k_of_n(&plonky3, 2),
            Err(DiverseError::TooFewImplementations { distinct: 1 })
        ));
        let mixed = vec![legs()[0].clone(), legs()[2].clone()];
        verify_k_of_n(&mixed, 2).expect("two systems from two implementations");
    }

    #[test]
    fn legs_for_different_statements_are_refused() {
        let mut set = legs();
        set[1].public_inputs[1] = vec![0x00; 32];
        assert!(matches!(
            verify_k_of_n(&set, DIVERSE_THRESHOLD),
            Err(DiverseError::StatementMismatch { index: 1 })
        ));
        assert!(matches!(verify_k_of_n(&[], 1), Err(DiverseError::Empty)));
    }

    #[test]
    fn statement_commitment_is_length_prefixed() {
        assert_ne!(
            statement_commitment("c", &[vec![1, 2], vec![3]]),
            statement_commitment("c", &[vec![1], vec![2, 3]])
        );
        assert_ne!(
            statement_commitment("identity", &[vec![1]]),
            statement_commitment("settlement", &[vec![1]])
        );
    }
}
