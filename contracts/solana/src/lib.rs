// SPDX-License-Identifier: Apache-2.0
//! Tenzro's finality client on Solana.
//!
//! The program keeps, in one state account it owns, the finality program's
//! image id, the Tenzro chain it follows, the committee root of each recent
//! epoch (starting from the genesis committee) and the latest final
//! checkpoint. `submit` accepts a checkpoint when its Groth16 proof verifies
//! (with the `alt_bn128` syscalls) for the finality program and its journal,
//! under the committee the account holds for the journal's epoch; a
//! checkpoint that ends an epoch hands over to the next committee. Anyone may
//! submit; checkpoints are accepted in increasing order.
//!
//! Instructions (first byte):
//!
//! ```text
//! 0  initialize  image_id:32 chain_id:u64 genesis_hash:32 genesis_committee_root:32
//! 1  submit      journal:416 seal:260
//! 2  verify_decision  proposal_id:32 record_hash:32 executed_height:u64 proof
//! ```
//!
//! `verify_decision` succeeds only when, under the latest final checkpoint's
//! state root, Tenzro governance recorded that decision: another program
//! invokes it to act on a governance decision with no key of its own.
//!
//! Accounts: the state account (writable, owned by the program, at least
//! [`STATE_LEN`] bytes); `initialize` also takes the account's signer.

use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use tenzro_finality_verifier::{Bn254, Error, JOURNAL_LEN, Journal, Params, Store};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// Epochs whose committee roots the account keeps.
pub const EPOCHS: usize = 32;
/// Bytes of the state account.
pub const STATE_LEN: usize = 1 + 32 + 8 + 32 + 1 + 8 + 32 + 32 + 8 + 1 + EPOCHS * 40;
/// Bytes of a seal: selector and eight words.
pub const SEAL_LEN: usize = 4 + 8 * 32;

/// The `alt_bn128` operations: syscalls on chain, the same arithmetic in
/// Rust elsewhere.
pub struct Syscalls;

impl Bn254 for Syscalls {
    fn g1_add(&self, a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]> {
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(a);
        input[64..].copy_from_slice(b);
        solana_bn254::prelude::alt_bn128_addition(&input).ok()?.try_into().ok()
    }

    fn g1_mul(&self, p: &[u8; 64], s: &[u8; 32]) -> Option<[u8; 64]> {
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(p);
        input[64..].copy_from_slice(s);
        solana_bn254::prelude::alt_bn128_multiplication(&input).ok()?.try_into().ok()
    }

    fn pairing4(&self, pairs: &[([u8; 64], [u8; 128]); 4]) -> Option<bool> {
        let mut input = [0u8; 4 * 192];
        for (i, (g1, g2)) in pairs.iter().enumerate() {
            input[192 * i..192 * i + 64].copy_from_slice(g1);
            input[192 * i + 64..192 * (i + 1)].copy_from_slice(g2);
        }
        let out = solana_bn254::prelude::alt_bn128_pairing(&input).ok()?;
        Some(out.last() == Some(&1) && out[..out.len() - 1].iter().all(|b| *b == 0))
    }
}

/// The state account's layout over its bytes.
pub struct State<'a>(pub &'a mut [u8]);

const O_INIT: usize = 0;
const O_IMAGE: usize = 1;
const O_CHAIN: usize = 33;
const O_GENESIS: usize = 41;
const O_HAS_FINAL: usize = 73;
const O_INDEX: usize = 74;
const O_DIGEST: usize = 82;
const O_STATE_ROOT: usize = 114;
const O_STATE_HEIGHT: usize = 146;
const O_ROOTS_LEN: usize = 154;
const O_ROOTS: usize = 155;

impl State<'_> {
    fn u64_at(&self, o: usize) -> u64 {
        u64::from_le_bytes(self.0[o..o + 8].try_into().expect("8 bytes"))
    }

    fn b32_at(&self, o: usize) -> [u8; 32] {
        self.0[o..o + 32].try_into().expect("32 bytes")
    }

    pub fn initialized(&self) -> bool {
        self.0[O_INIT] == 1
    }

    pub fn params(&self) -> Params {
        Params { image_id: self.b32_at(O_IMAGE), chain_id: self.u64_at(O_CHAIN), genesis_hash: self.b32_at(O_GENESIS) }
    }

    /// The latest final checkpoint: index, digest, state root, state height.
    pub fn latest(&self) -> Option<(u64, [u8; 32], [u8; 32], u64)> {
        (self.0[O_HAS_FINAL] == 1).then(|| {
            (self.u64_at(O_INDEX), self.b32_at(O_DIGEST), self.b32_at(O_STATE_ROOT), self.u64_at(O_STATE_HEIGHT))
        })
    }

    fn init(&mut self, params: &Params, genesis_committee_root: [u8; 32]) {
        self.0.fill(0);
        self.0[O_INIT] = 1;
        self.0[O_IMAGE..O_IMAGE + 32].copy_from_slice(&params.image_id);
        self.0[O_CHAIN..O_CHAIN + 8].copy_from_slice(&params.chain_id.to_le_bytes());
        self.0[O_GENESIS..O_GENESIS + 32].copy_from_slice(&params.genesis_hash);
        self.set_committee_root(0, genesis_committee_root);
    }
}

impl Store for State<'_> {
    fn committee_root(&self, epoch: u64) -> Option<[u8; 32]> {
        (0..self.0[O_ROOTS_LEN] as usize).find_map(|i| {
            let o = O_ROOTS + 40 * i;
            (self.u64_at(o) == epoch).then(|| self.b32_at(o + 8))
        })
    }

    fn set_committee_root(&mut self, epoch: u64, root: [u8; 32]) {
        let n = self.0[O_ROOTS_LEN] as usize;
        if n == EPOCHS {
            // Drop the oldest epoch.
            self.0.copy_within(O_ROOTS + 40..O_ROOTS + 40 * EPOCHS, O_ROOTS);
        } else {
            self.0[O_ROOTS_LEN] = (n + 1) as u8;
        }
        let o = O_ROOTS + 40 * (n.min(EPOCHS - 1));
        self.0[o..o + 8].copy_from_slice(&epoch.to_le_bytes());
        self.0[o + 8..o + 40].copy_from_slice(&root);
    }

    fn is_final(&self, index: u64) -> bool {
        self.latest().is_some_and(|(latest, ..)| index <= latest)
    }

    fn set_final(&mut self, j: &Journal) {
        self.0[O_HAS_FINAL] = 1;
        self.0[O_INDEX..O_INDEX + 8].copy_from_slice(&j.index.to_le_bytes());
        self.0[O_DIGEST..O_DIGEST + 32].copy_from_slice(&j.checkpoint_digest);
        self.0[O_STATE_ROOT..O_STATE_ROOT + 32].copy_from_slice(&j.state_root);
        self.0[O_STATE_HEIGHT..O_STATE_HEIGHT + 8].copy_from_slice(&j.state_height.to_le_bytes());
    }
}

/// The program's error codes: the verifier's errors, then its own.
fn code(e: Error) -> ProgramError {
    ProgramError::Custom(match e {
        Error::MalformedSeal => 1,
        Error::WrongSelector => 2,
        Error::BadPoint => 3,
        Error::InvalidProof => 4,
        Error::MalformedJournal => 5,
        Error::WrongChain => 6,
        Error::UnknownCommittee => 7,
        Error::AlreadyFinal => 8,
    })
}

/// Already initialized.
pub const E_INITIALIZED: u32 = 20;
/// Not initialized.
pub const E_UNINITIALIZED: u32 = 21;
/// No final checkpoint is held yet.
pub const E_NO_CHECKPOINT: u32 = 22;
/// The governance decision does not verify under the latest final checkpoint.
pub const E_NOT_DECIDED: u32 = 23;

/// Check `verify_decision`'s data against the latest final checkpoint: Tenzro
/// governance enacted `proposal_id` at `executed_height`, its executed
/// record hashing to `record_hash`, by the state `proof`.
pub fn verify_decision(state: &State, data: &[u8]) -> ProgramResult {
    if data.len() < 72 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (_, _, root, _) = state.latest().ok_or(ProgramError::Custom(E_NO_CHECKPOINT))?;
    let proposal_id: [u8; 32] = data[..32].try_into().expect("32 bytes");
    let record_hash: [u8; 32] = data[32..64].try_into().expect("32 bytes");
    let height = u64::from_le_bytes(data[64..72].try_into().expect("8 bytes"));
    if tenzro_finality_verifier::governance::proven_decision(&root, &proposal_id, &record_hash, height, &data[72..]) {
        Ok(())
    } else {
        Err(ProgramError::Custom(E_NOT_DECIDED))
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let state_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if state_account.owner != program_id || !state_account.is_writable {
        return Err(ProgramError::IllegalOwner);
    }
    let mut bytes = state_account.try_borrow_mut_data()?;
    if bytes.len() < STATE_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let mut state = State(&mut bytes[..STATE_LEN]);
    match data.split_first() {
        Some((0, rest)) if rest.len() == 32 + 8 + 32 + 32 => {
            if !state_account.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            if state.initialized() {
                return Err(ProgramError::Custom(E_INITIALIZED));
            }
            let params = Params {
                image_id: rest[..32].try_into().expect("32 bytes"),
                chain_id: u64::from_le_bytes(rest[32..40].try_into().expect("8 bytes")),
                genesis_hash: rest[40..72].try_into().expect("32 bytes"),
            };
            state.init(&params, rest[72..104].try_into().expect("32 bytes"));
            Ok(())
        }
        Some((1, rest)) if rest.len() == JOURNAL_LEN + SEAL_LEN => {
            if !state.initialized() {
                return Err(ProgramError::Custom(E_UNINITIALIZED));
            }
            let params = state.params();
            tenzro_finality_verifier::submit(&Syscalls, &params, &mut state, &rest[..JOURNAL_LEN], &rest[JOURNAL_LEN..])
                .map(|_| ())
                .map_err(code)
        }
        Some((2, rest)) => {
            if !state.initialized() {
                return Err(ProgramError::Custom(E_UNINITIALIZED));
            }
            verify_decision(&state, rest)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
