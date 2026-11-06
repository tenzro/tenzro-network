// SPDX-License-Identifier: Apache-2.0
//! The program on a real finality proof: natively, and as the compiled SBF
//! program in Solana's runtime.

use mollusk_svm::Mollusk;
use mollusk_svm::result::Check;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use tenzro_finality_solana::{State, STATE_LEN, Syscalls};
use tenzro_finality_verifier::{Journal, Params, Store};

/// A real finality proof of a test build of the finality program.
const PROOF: &str = include_str!("../../../crates/tenzro-vm/tests/fixtures/finality_proof.json");

fn proof() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let v: serde_json::Value = serde_json::from_str(PROOF).unwrap();
    let h = |k: &str| hex::decode(v[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
    (h("journal"), h("evm_seal"), h("image_id").try_into().unwrap())
}

fn init_data(image: &[u8; 32], j: &Journal) -> Vec<u8> {
    let mut d = vec![0u8];
    d.extend_from_slice(image);
    d.extend_from_slice(&j.chain_id.to_le_bytes());
    d.extend_from_slice(&j.genesis_hash);
    d.extend_from_slice(&j.committee_root);
    d
}

#[test]
fn a_real_proof_verifies_natively_and_tampering_fails() {
    let (journal, seal, image) = proof();
    let j = Journal::decode(&journal).unwrap();
    let params = Params { image_id: image, chain_id: j.chain_id, genesis_hash: j.genesis_hash };
    let mut buf = vec![0u8; STATE_LEN];
    let mut state = State(&mut buf);
    state.set_committee_root(j.epoch, j.committee_root);
    tenzro_finality_verifier::submit(&Syscalls, &params, &mut state, &journal, &seal).unwrap();
    assert_eq!(state.latest().unwrap().0, j.index);
    assert_eq!(
        tenzro_finality_verifier::submit(&Syscalls, &params, &mut state, &journal, &seal),
        Err(tenzro_finality_verifier::Error::AlreadyFinal)
    );

    let mut fresh = vec![0u8; STATE_LEN];
    let mut s = State(&mut fresh);
    s.set_committee_root(j.epoch, j.committee_root);
    let mut bad_seal = seal.clone();
    bad_seal[40] ^= 1;
    assert!(tenzro_finality_verifier::submit(&Syscalls, &params, &mut s, &journal, &bad_seal).is_err());
    let mut bad_journal = journal.clone();
    bad_journal[300] ^= 1;
    assert_eq!(
        tenzro_finality_verifier::submit(&Syscalls, &params, &mut s, &bad_journal, &seal),
        Err(tenzro_finality_verifier::Error::InvalidProof)
    );
    let other = Params { image_id: [7; 32], ..params };
    assert_eq!(
        tenzro_finality_verifier::submit(&Syscalls, &other, &mut s, &journal, &seal),
        Err(tenzro_finality_verifier::Error::InvalidProof)
    );
}

#[test]
fn the_compiled_program_accepts_the_proof_once() {
    let (journal, seal, image) = proof();
    let j = Journal::decode(&journal).unwrap();
    let program = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program, "tenzro_finality_solana");
    let state = Pubkey::new_unique();
    let state_account = solana_account::Account::new(1_000_000_000, STATE_LEN, &program);
    let init = Instruction::new_with_bytes(program, &init_data(&image, &j), vec![AccountMeta::new(state, true)]);
    let after_init = mollusk.process_and_validate_instruction(&init, &[(state, state_account)], &[Check::success()]);
    let state_account = after_init.resulting_accounts[0].1.clone();
    let mut submit = vec![1u8];
    submit.extend_from_slice(&journal);
    submit.extend_from_slice(&seal);
    let ix = Instruction::new_with_bytes(program, &submit, vec![AccountMeta::new(state, false)]);
    let done = mollusk.process_and_validate_instruction(&ix, &[(state, state_account)], &[Check::success()]);
    println!("compute units: {}", done.compute_units_consumed);
    let mut data = done.resulting_accounts[0].1.data.clone();
    assert_eq!(State(&mut data).latest().unwrap().0, j.index);
    let again = mollusk.process_instruction(&ix, &[(state, done.resulting_accounts[0].1.clone())]);
    assert!(again.program_result.is_err());
}
