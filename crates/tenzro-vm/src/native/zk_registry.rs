//! On-chain ZK proof attestations.
//!
//! `AttestZkProof` carries a full proof envelope (bincode `tenzro_zk::Proof`). Every validator runs
//! the verifier on it while executing the block, and on success records the
//! proof's commitment in the storage of the ZK_VERIFY precompile, where the
//! precompile (and anything else reading state) finds it. The record is
//! consensus state: it is written only by block execution, lands in the state
//! root, and survives restarts. No quorum, gossip or trusted attester is
//! involved, because every validator checks the proof itself.

use crate::{
    error::{Result, VmError},
    gas::GasMeter,
    precompiles::{
        PRECOMPILE_ZK_VERIFY, compute_zk_commitment, zk_attestation_slot, zk_statement_count_slot,
        zk_statement_system_slot,
    },
    traits::VmState,
    types::{ExecutionResult, Log, StateChange, VmTransaction},
};

/// Native selector of the `AttestZkProof` transaction.
pub const SELECTOR_ZK_ATTEST: [u8; 4] = [0x01, 0x00, 0x00, 0x71];

/// Base gas of an attestation: covers one Plonky3 verification.
pub const GAS_ZK_ATTEST_BASE: u64 = 2_000_000;
/// Gas per byte of proof envelope.
pub const GAS_ZK_ATTEST_PER_BYTE: u64 = 4;

/// Gas an attestation of `payload_len` envelope bytes consumes.
pub fn zk_attest_gas(payload_len: usize) -> u64 {
    GAS_ZK_ATTEST_BASE.saturating_add(GAS_ZK_ATTEST_PER_BYTE.saturating_mul(payload_len as u64))
}

/// Verify the proof in `tx.data[4..]` and record its commitment.
///
/// The sender pays `gas_price * gas` whether or not the proof verifies; a
/// proof that fails verification is an error, which reverts the transaction
/// and charges the gas it used. Attesting an already-attested proof succeeds
/// and changes nothing but the fee.
pub(super) fn execute_zk_attest(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    let payload = &tx.data[4..];
    let gas = zk_attest_gas(payload.len());
    gas_meter.consume(gas)?;

    if payload.len() > tenzro_types::transaction::MAX_ZK_PROOF_SIZE {
        return Err(VmError::InvalidTransaction(
            "AttestZkProof: proof envelope too large".to_string(),
        ));
    }
    let proof: tenzro_zk::Proof = bincode::deserialize(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("AttestZkProof: bad envelope: {e}")))?;
    super::require_lever_enabled(
        state,
        crate::governance::proof_system_status_key(proof.system),
        &format!("AttestZkProof: the {} proof system", proof.system.as_str()),
    )?;
    tenzro_zk::verify_proof_envelope(&proof).map_err(|e| {
        VmError::InvalidTransaction(format!("AttestZkProof: proof does not verify: {e}"))
    })?;

    let gas_cost = tx.gas_price.saturating_mul(gas as u128);
    let balance = state.get_balance(&tx.from);
    if balance < gas_cost {
        return Err(VmError::InsufficientBalance {
            required: gas_cost,
            available: balance,
        });
    }
    state.set_balance(&tx.from, balance - gas_cost);

    let commitment = compute_zk_commitment(&proof);
    let slot = zk_attestation_slot(&commitment);
    let previous = state.get_storage(&PRECOMPILE_ZK_VERIFY, &slot);
    let mut marker = [0u8; 32];
    marker[31] = 1;
    state.set_storage(&PRECOMPILE_ZK_VERIFY, &slot, marker.to_vec());

    // Count the proof systems that have proven this statement, once each.
    let statement = tenzro_zk::statement_commitment(&proof.circuit_id, &proof.public_inputs);
    let system_slot = zk_statement_system_slot(&statement, proof.system.as_str());
    let seen = state
        .get_storage(&PRECOMPILE_ZK_VERIFY, &system_slot)
        .is_some_and(|v| v.iter().any(|b| *b != 0));
    let mut statement_changes = Vec::new();
    if !seen {
        state.set_storage(&PRECOMPILE_ZK_VERIFY, &system_slot, marker.to_vec());
        let count_slot = zk_statement_count_slot(&statement);
        let before = state.get_storage(&PRECOMPILE_ZK_VERIFY, &count_slot);
        let mut count = [0u8; 32];
        if let Some(v) = before.as_ref().filter(|v| v.len() == 32) {
            count.copy_from_slice(v);
        }
        let n = crate::evm::precompile_host::word_to_u128(&count) + 1;
        let after = crate::evm::precompile_host::u128_to_word(n);
        state.set_storage(&PRECOMPILE_ZK_VERIFY, &count_slot, after.to_vec());
        statement_changes.push(StateChange::new(
            PRECOMPILE_ZK_VERIFY.to_vec(),
            count_slot.to_vec(),
            before,
            Some(after.to_vec()),
        ));
    }

    let log = Log::new(
        PRECOMPILE_ZK_VERIFY.to_vec(),
        vec![b"ZkProofAttested".to_vec(), commitment.to_vec()],
        proof.circuit_id.as_bytes().to_vec(),
    );
    let mut state_changes = vec![
        StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some((balance - gas_cost).to_le_bytes().to_vec()),
        ),
        StateChange::new(
            PRECOMPILE_ZK_VERIFY.to_vec(),
            slot.to_vec(),
            previous,
            Some(marker.to_vec()),
        ),
    ];
    state_changes.extend(statement_changes);
    // All of an attestation's gas is spent verifying its proof.
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        commitment.to_vec(),
        vec![log],
        state_changes,
    )
    .with_proof_gas(gas))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;
    use crate::governance::proof_system_status_key;
    use crate::native::set_genesis_param;
    use tenzro_zk::{Proof, ProofSystem};

    fn attest(state: &mut StateAdapter, system: ProofSystem) -> Result<ExecutionResult> {
        let proof = Proof {
            system,
            proof_bytes: vec![0; 8],
            public_inputs: vec![vec![0; 32], vec![0; 32]],
            circuit_id: "identity".into(),
            created_at: tenzro_types::primitives::Timestamp::new(0),
        };
        let mut data = SELECTOR_ZK_ATTEST.to_vec();
        data.extend(bincode::serialize(&proof).unwrap());
        let tx = VmTransaction::new(
            vec![1; 20],
            None,
            0,
            data,
            50_000_000,
            0,
            0,
            crate::traits::VmType::Tenzro,
            1337,
        );
        execute_zk_attest(&tx, state, &mut GasMeter::new(50_000_000))
    }

    /// A proof system governance paused is refused before its proof is
    /// checked; enabled, the proof goes on to verification (and these bytes
    /// fail it).
    #[test]
    fn a_paused_proof_system_is_refused_before_verification() {
        for system in ProofSystem::ALL {
            let mut state = StateAdapter::new();
            let key = proof_system_status_key(system);
            set_genesis_param(&mut state, key, 1);
            let err = attest(&mut state, system).unwrap_err().to_string();
            assert!(err.contains("paused by governance"), "{err}");
            set_genesis_param(&mut state, key, 2);
            let err = attest(&mut state, system).unwrap_err().to_string();
            assert!(err.contains("retired by governance"), "{err}");
            set_genesis_param(&mut state, key, 0);
            let err = attest(&mut state, system).unwrap_err().to_string();
            assert!(err.contains("does not verify"), "{err}");
        }
    }
}
