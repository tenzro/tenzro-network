// SPDX-License-Identifier: Apache-2.0
//! `verify_decision` on the shared governance receipt vectors: a decision the
//! VM recorded, proven under a final checkpoint's state root.

use solana_program::program_error::ProgramError;
use tenzro_finality_solana::{E_NO_CHECKPOINT, E_NOT_DECIDED, State, STATE_LEN, verify_decision};
use tenzro_finality_verifier::{Journal, Store};

const VECTORS: &str = include_str!("../../../sdk/fixtures/governance_receipt/vectors.json");

fn b32(v: &serde_json::Value, k: &str) -> [u8; 32] {
    hex::decode(v[k].as_str().unwrap()).unwrap().try_into().unwrap()
}

fn data(v: &serde_json::Value, id: [u8; 32], height: u64) -> Vec<u8> {
    let mut d = id.to_vec();
    d.extend_from_slice(&b32(v, "proposal_record_hash"));
    d.extend_from_slice(&height.to_le_bytes());
    d.extend(hex::decode(v["decision_proof"].as_str().unwrap()).unwrap());
    d
}

#[test]
fn a_decision_verifies_under_the_latest_final_checkpoint_only() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let id = b32(&v, "proposal_id");
    let height = v["executed_height"].as_u64().unwrap();
    let mut buf = vec![0u8; STATE_LEN];
    let mut state = State(&mut buf);
    assert_eq!(verify_decision(&state, &data(&v, id, height)), Err(ProgramError::Custom(E_NO_CHECKPOINT)));

    state.set_final(&Journal {
        chain_id: 1,
        genesis_hash: [0; 32],
        epoch: 0,
        committee_root: [0; 32],
        index: 1,
        checkpoint_digest: [1; 32],
        last_height: 1,
        state_height: 1,
        state_root: b32(&v, "state_root"),
        blocks_root: [0; 32],
        statement_root: [0; 32],
        next_committee_root: [0; 32],
        timestamp_ms: 0,
    });
    assert_eq!(verify_decision(&state, &data(&v, id, height)), Ok(()));
    assert_eq!(verify_decision(&state, &data(&v, id, height + 1)), Err(ProgramError::Custom(E_NOT_DECIDED)));
    let other = b32(&v, "absent_proposal_id");
    assert_eq!(verify_decision(&state, &data(&v, other, height)), Err(ProgramError::Custom(E_NOT_DECIDED)));
    assert_eq!(verify_decision(&state, &[0; 10]), Err(ProgramError::InvalidInstructionData));
}
