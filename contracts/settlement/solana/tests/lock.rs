// SPDX-License-Identifier: Apache-2.0
//! The compiled lock program in Solana's runtime, on the shared settlement
//! vectors: lamport and SPL token legs, settled through a staged buffer
//! against the root of the finality client's final checkpoint.

use std::collections::HashMap;

use mollusk_svm::program::keyed_account_for_system_program;
use mollusk_svm::result::ProgramResult;
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use tenzro_finality_solana::{State, STATE_LEN};
use tenzro_finality_verifier::{Journal, Store};
use tenzro_settlement_lock_solana::*;

const VECTORS: &str = include_str!("../../../../sdk/fixtures/settlement_lock/vectors.json");
const HORIZON: u64 = 14 * 24 * 3600;
const CHECKPOINT: u64 = 7;
const NOW: i64 = 1_800_000_000;
const SOL: u64 = 1_000_000_000;

fn v() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn raw(x: &serde_json::Value) -> Vec<u8> {
    hex::decode(x.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn plan(which: &str) -> [u8; 32] {
    raw(&v()[which]["plan_id"]).try_into().unwrap()
}

fn finality_state(index: u64, root: [u8; 32], owner: Pubkey) -> Account {
    let mut data = vec![0u8; STATE_LEN];
    let j = Journal {
        chain_id: 1,
        genesis_hash: [0; 32],
        epoch: 0,
        committee_root: [0; 32],
        index,
        checkpoint_digest: [1; 32],
        last_height: 0,
        state_height: 0,
        state_root: root,
        blocks_root: [0; 32],
        statement_root: [0; 32],
        next_committee_root: [0; 32],
        timestamp_ms: 0,
    };
    State(&mut data).set_final(&j);
    Account { lamports: SOL, data, owner, executable: false, rent_epoch: 0 }
}

fn mint_account(decimals: u8) -> Account {
    let mut data = vec![0u8; 82];
    data[44] = decimals;
    data[45] = 1;
    Account { lamports: SOL, data, owner: TOKEN_PROGRAM, executable: false, rent_epoch: 0 }
}

fn token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Account {
    let mut data = vec![0u8; 165];
    data[..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1;
    Account { lamports: SOL, data, owner: TOKEN_PROGRAM, executable: false, rent_epoch: 0 }
}

fn token_amount(a: &Account) -> u64 {
    u64::from_le_bytes(a.data[64..72].try_into().unwrap())
}

struct H {
    m: Mollusk,
    store: HashMap<Pubkey, Account>,
    program: Pubkey,
    config: Pubkey,
    finality: Pubkey,
    payer: Pubkey,
    recipient: Pubkey,
    mint: Pubkey,
}

impl H {
    fn new() -> H {
        let program = Pubkey::new_unique();
        let mut m = Mollusk::new(&program, "tenzro_settlement_lock_solana");
        mollusk_svm_programs_token::token::add_program(&mut m);
        m.sysvars.clock.unix_timestamp = NOW;
        let finality_program = Pubkey::new_unique();
        let (config, finality, payer, recipient, mint) =
            (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let root: [u8; 32] = raw(&v()["root"]).try_into().unwrap();
        let mut store = HashMap::new();
        store.insert(config, Account::new(SOL, CONFIG_LEN, &program));
        store.insert(finality, finality_state(CHECKPOINT, root, finality_program));
        store.insert(payer, Account::new(100 * SOL, 0, &Pubkey::default()));
        store.insert(recipient, Account::new(SOL, 0, &Pubkey::default()));
        store.insert(mint, mint_account(6));
        let (sys, sys_account) = keyed_account_for_system_program();
        store.insert(sys, sys_account);
        let (tok, tok_account) = mollusk_svm_programs_token::token::keyed_account();
        store.insert(tok, tok_account);
        let mut h = H { m, store, program, config, finality, payer, recipient, mint };
        let mut init = vec![0u8];
        init.extend_from_slice(finality_program.as_ref());
        init.extend_from_slice(finality.as_ref());
        init.extend_from_slice(&HORIZON.to_le_bytes());
        h.ok(&init, vec![AccountMeta::new(config, true)]);
        h
    }

    fn run(&mut self, data: &[u8], accounts: Vec<AccountMeta>) -> Option<u32> {
        let ix = Instruction::new_with_bytes(self.program, data, accounts);
        let mut keys: Vec<Pubkey> = ix.accounts.iter().map(|a| a.pubkey).collect();
        keys.dedup();
        let input: Vec<(Pubkey, Account)> =
            keys.iter().map(|k| (*k, self.store.get(k).cloned().unwrap_or_default())).collect();
        let r = self.m.process_instruction(&ix, &input);
        match r.program_result {
            ProgramResult::Success => {
                for (k, a) in r.resulting_accounts {
                    self.store.insert(k, a);
                }
                None
            }
            ProgramResult::Failure(ProgramError::Custom(c)) => Some(c),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn ok(&mut self, data: &[u8], accounts: Vec<AccountMeta>) {
        assert_eq!(self.run(data, accounts), None);
    }

    fn leg(&self, which: &str, index: u8) -> Pubkey {
        leg_address(&self.program, &self.config, &tenzro_finality_verifier::settlement::leg_id(&plan(which), index)).0
    }

    fn lamports(&self, k: &Pubkey) -> u64 {
        self.store[k].lamports
    }

    fn lock_data(which: &str, index: u8, amount: u64, recipient: &Pubkey) -> Vec<u8> {
        let mut d = vec![1u8];
        d.extend_from_slice(&plan(which));
        d.push(index);
        d.extend_from_slice(&amount.to_le_bytes());
        d.extend_from_slice(recipient.as_ref());
        d
    }

    fn lock_sol(&mut self, which: &str, index: u8, amount: u64) -> Option<u32> {
        let leg = self.leg(which, index);
        let recipient = self.recipient;
        self.run(
            &Self::lock_data(which, index, amount, &recipient),
            vec![
                AccountMeta::new(self.config, false),
                AccountMeta::new(leg, false),
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
        )
    }

    /// A vault for leg `index` of `which` and the payer's and recipient's token accounts.
    fn token_accounts(&mut self, which: &str, index: u8) -> (Pubkey, Pubkey, Pubkey) {
        let (vault, from, to) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let leg = self.leg(which, index);
        self.store.insert(vault, token_account(&self.mint, &leg, 0));
        self.store.insert(from, token_account(&self.mint, &self.payer, 1_000));
        self.store.insert(to, token_account(&self.mint, &self.recipient, 0));
        (vault, from, to)
    }

    fn lock_token(&mut self, which: &str, index: u8, amount: u64, from: Pubkey, vault: Pubkey) -> Option<u32> {
        let leg = self.leg(which, index);
        let recipient = self.recipient;
        self.run(
            &Self::lock_data(which, index, amount, &recipient),
            vec![
                AccountMeta::new(self.config, false),
                AccountMeta::new(leg, false),
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(from, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM, false),
            ],
        )
    }

    /// A buffer holding `bytes`, staged in two writes.
    fn buffer(&mut self, bytes: &[u8]) -> Pubkey {
        let buf = Pubkey::new_unique();
        self.store.insert(buf, Account::new(SOL, BUFFER_HEADER + bytes.len(), &self.program));
        let half = bytes.len() / 2;
        let payer = self.payer;
        for (i, (offset, part)) in [(0, &bytes[..half]), (half, &bytes[half..])].into_iter().enumerate() {
            let mut d = vec![4u8];
            d.extend_from_slice(&(offset as u32).to_le_bytes());
            d.extend_from_slice(part);
            self.ok(&d, vec![AccountMeta::new(buf, i == 0), AccountMeta::new_readonly(payer, true)]);
        }
        buf
    }

    fn staged(&mut self, proof_of: &str) -> Pubkey {
        let vv = v();
        let mut bytes = raw(&vv[proof_of]["decision"]);
        bytes.extend(raw(&vv[proof_of]["proof"]));
        self.buffer(&bytes)
    }

    fn settle(&mut self, which: &str, index: u8, checkpoint: u64, buffer: Pubkey, to: Pubkey, token: Option<Pubkey>) -> Option<u32> {
        let mut d = vec![2u8];
        d.extend_from_slice(&plan(which));
        d.push(index);
        d.extend_from_slice(&checkpoint.to_le_bytes());
        let mut accounts = vec![
            AccountMeta::new(self.config, false),
            AccountMeta::new(self.leg(which, index), false),
            AccountMeta::new_readonly(self.finality, false),
            AccountMeta::new_readonly(buffer, false),
            AccountMeta::new(to, false),
        ];
        if let Some(vault) = token {
            accounts.push(AccountMeta::new_readonly(self.mint, false));
            accounts.push(AccountMeta::new(vault, false));
            accounts.push(AccountMeta::new_readonly(TOKEN_PROGRAM, false));
        }
        self.run(&d, accounts)
    }

    fn escape(&mut self, which: &str, index: u8, to: Pubkey) -> Option<u32> {
        let mut d = vec![3u8];
        d.extend_from_slice(&plan(which));
        d.push(index);
        let accounts =
            vec![AccountMeta::new(self.config, false), AccountMeta::new(self.leg(which, index), false), AccountMeta::new(to, false)];
        self.run(&d, accounts)
    }
}

#[test]
fn a_commit_pays_the_recipient_once() {
    let mut h = H::new();
    assert_eq!(h.lock_sol("committed", 2, 3 * SOL), None);
    let leg = Leg::decode(&h.store[&h.leg("committed", 2)].data).unwrap();
    assert_eq!((leg.stage, leg.amount, leg.recipient), (LOCKED, 3 * SOL, h.recipient));
    assert_eq!(leg.escape_at, NOW as u64 + HORIZON);
    let buf = h.staged("committed");
    let (payer, recipient) = (h.payer, h.recipient);
    assert_eq!(h.settle("committed", 2, CHECKPOINT, buf, payer, None), Some(E_WRONG_DESTINATION));
    let before = h.lamports(&recipient);
    assert_eq!(h.settle("committed", 2, CHECKPOINT, buf, recipient, None), None);
    assert_eq!(h.lamports(&recipient), before + 3 * SOL);
    assert_eq!(h.settle("committed", 2, CHECKPOINT, buf, recipient, None), Some(E_NOT_LOCKED));
    assert_eq!(h.escape("committed", 2, payer), Some(E_NOT_LOCKED));
}

#[test]
fn an_abort_refunds_the_payer() {
    let mut h = H::new();
    let payer = h.payer;
    let start = h.lamports(&payer);
    assert_eq!(h.lock_sol("aborted", 0, 2 * SOL), None);
    let buf = h.staged("aborted");
    assert_eq!(h.settle("aborted", 0, CHECKPOINT, buf, payer, None), None);
    let rent = h.lamports(&h.leg("aborted", 0));
    assert_eq!(h.lamports(&payer), start - rent);
    assert_eq!(Leg::decode(&h.store[&h.leg("aborted", 0)].data).unwrap().stage, REFUNDED);
}

#[test]
fn a_token_leg_pays_out_of_its_vault() {
    let mut h = H::new();
    let (vault, from, to) = h.token_accounts("committed", 1);
    assert_eq!(h.lock_token("committed", 1, 400, from, vault), None);
    assert_eq!((token_amount(&h.store[&from]), token_amount(&h.store[&vault])), (600, 400));
    let buf = h.staged("committed");
    assert_eq!(h.settle("committed", 1, CHECKPOINT, buf, from, Some(vault)), Some(E_WRONG_DESTINATION));
    assert_eq!(h.settle("committed", 1, CHECKPOINT, buf, to, Some(vault)), None);
    assert_eq!((token_amount(&h.store[&to]), token_amount(&h.store[&vault])), (400, 0));

    let (vault, from, _) = h.token_accounts("aborted", 1);
    assert_eq!(h.lock_token("aborted", 1, 250, from, vault), None);
    let buf = h.staged("aborted");
    assert_eq!(h.settle("aborted", 1, CHECKPOINT, buf, from, Some(vault)), None);
    assert_eq!(token_amount(&h.store[&from]), 1_000);
}

#[test]
fn a_foreign_forged_or_unanchored_decision_moves_nothing() {
    let mut h = H::new();
    let recipient = h.recipient;
    assert_eq!(h.lock_sol("undecided", 1, SOL), None);
    let foreign = h.staged("committed");
    assert_eq!(h.settle("undecided", 1, CHECKPOINT, foreign, recipient, None), Some(E_UNPROVEN));
    let vv = v();
    let mut forged = raw(&vv["committed"]["decision"]);
    forged[10..].copy_from_slice(&plan("undecided"));
    forged.extend(raw(&vv["committed"]["proof"]));
    let forged = h.buffer(&forged);
    assert_eq!(h.settle("undecided", 1, CHECKPOINT, forged, recipient, None), Some(E_UNPROVEN));

    assert_eq!(h.lock_sol("committed", 0, SOL), None);
    let real = h.staged("committed");
    assert_eq!(h.settle("committed", 0, CHECKPOINT + 1, real, recipient, None), Some(E_UNKNOWN_CHECKPOINT));
    let finality = h.finality;
    let owner = h.store[&finality].owner;
    h.store.insert(finality, finality_state(CHECKPOINT, [7; 32], owner));
    assert_eq!(h.settle("committed", 0, CHECKPOINT, real, recipient, None), Some(E_UNPROVEN));
    h.store.insert(finality, finality_state(CHECKPOINT, raw(&v()["root"]).try_into().unwrap(), Pubkey::new_unique()));
    assert_eq!(h.settle("committed", 0, CHECKPOINT, real, recipient, None), Some(E_WRONG_ACCOUNT));
    assert_eq!(Leg::decode(&h.store[&h.leg("undecided", 1)].data).unwrap().stage, LOCKED);
}

#[test]
fn an_undecided_leg_escapes_only_after_the_horizon() {
    let mut h = H::new();
    let (payer, recipient) = (h.payer, h.recipient);
    assert_eq!(h.lock_sol("undecided", 0, 5 * SOL), None);
    let escape_at = Leg::decode(&h.store[&h.leg("undecided", 0)].data).unwrap().escape_at as i64;
    h.m.sysvars.clock.unix_timestamp = escape_at - 1;
    assert_eq!(h.escape("undecided", 0, payer), Some(E_TOO_EARLY));
    h.m.sysvars.clock.unix_timestamp = escape_at;
    assert_eq!(h.escape("undecided", 0, recipient), Some(E_WRONG_DESTINATION));
    let before = h.lamports(&payer);
    assert_eq!(h.escape("undecided", 0, payer), None);
    assert_eq!(h.lamports(&payer), before + 5 * SOL);
    assert_eq!(h.escape("undecided", 0, payer), Some(E_NOT_LOCKED));
}

#[test]
fn a_leg_locks_once_and_buffers_are_their_authority_s() {
    let mut h = H::new();
    assert_eq!(h.lock_sol("committed", 1, 0), Some(E_BAD_AMOUNT));
    assert_eq!(h.lock_sol("committed", 1, SOL), None);
    assert_eq!(h.lock_sol("committed", 1, SOL), Some(E_ALREADY_LOCKED));
    // A token leg whose vault the leg does not own is refused.
    let (_, from, to) = h.token_accounts("committed", 2);
    assert_eq!(h.lock_token("committed", 2, 10, from, to), Some(E_WRONG_ACCOUNT));

    let buf = h.staged("committed");
    let other = Pubkey::new_unique();
    let d = [4u8, 0, 0, 0, 0, 9];
    assert_eq!(h.run(&d, vec![AccountMeta::new(buf, false), AccountMeta::new_readonly(other, true)]), Some(E_BAD_BUFFER));
    assert_eq!(h.run(&[5], vec![AccountMeta::new(buf, false), AccountMeta::new(other, true)]), Some(E_BAD_BUFFER));
    let payer = h.payer;
    let before = h.lamports(&payer);
    assert_eq!(h.run(&[5], vec![AccountMeta::new(buf, false), AccountMeta::new(payer, true)]), None);
    assert_eq!(h.lamports(&payer), before + SOL);
}

const RECEIPTS: &str = include_str!("../../../../sdk/fixtures/settlement_lock/leg_receipts.json");

impl H {
    /// Run `receipt` for `leg` over a buffer staging `bytes`: the return data
    /// on success, the error code otherwise.
    fn receipt(&mut self, leg: [u8; 32], bytes: &[u8]) -> Result<Vec<u8>, u32> {
        let buf = self.buffer(bytes);
        let mut d = vec![6u8];
        d.extend_from_slice(&leg);
        d.extend_from_slice(&CHECKPOINT.to_le_bytes());
        let accounts = vec![
            AccountMeta::new_readonly(self.config, false),
            AccountMeta::new_readonly(self.finality, false),
            AccountMeta::new_readonly(buf, false),
        ];
        let ix = Instruction::new_with_bytes(self.program, &d, accounts);
        let input: Vec<(Pubkey, Account)> =
            ix.accounts.iter().map(|a| (a.pubkey, self.store.get(&a.pubkey).cloned().unwrap_or_default())).collect();
        let r = self.m.process_instruction(&ix, &input);
        match r.program_result {
            ProgramResult::Success => Ok(r.return_data),
            ProgramResult::Failure(ProgramError::Custom(c)) => Err(c),
            other => panic!("unexpected result {other:?}"),
        }
    }
}

#[test]
fn a_leg_receipt_proves_its_outcome_and_repaid_network_fee() {
    let mut h = H::new();
    let r: serde_json::Value = serde_json::from_str(RECEIPTS).unwrap();
    let finality = h.finality;
    let owner = h.store[&finality].owner;
    h.store.insert(finality, finality_state(CHECKPOINT, raw(&r["root"]).try_into().unwrap(), owner));
    let leg: [u8; 32] = raw(&r["committed"]["leg_id"]).try_into().unwrap();
    let receipt = raw(&r["committed"]["receipt"]);
    let mut staged = receipt.clone();
    staged.extend(raw(&r["committed"]["proof"]));
    let returned = h.receipt(leg, &staged).unwrap();
    assert_eq!(returned, receipt);
    let got = tenzro_finality_verifier::settlement::decode_leg_receipt(&leg, &returned).unwrap();
    assert_eq!(got.network_fee.to_string(), r["committed"]["network_fee"].as_str().unwrap());
    assert_eq!(got.relayer.map(|a| a.to_vec()), Some(raw(&r["committed"]["relayer"])));
    // Another leg's receipt, or an altered one, proves nothing.
    let absent: [u8; 32] = raw(&r["absent"]["leg_id"]).try_into().unwrap();
    assert_eq!(h.receipt(absent, &staged), Err(E_UNPROVEN));
    staged[93 + 15] ^= 1;
    assert_eq!(h.receipt(leg, &staged), Err(E_UNPROVEN));
}

#[test]
fn the_reconciliation_hash_matches_the_shared_vector() {
    let rv: serde_json::Value =
        serde_json::from_str(include_str!("../../../../sdk/fixtures/settlement_lock/recon.json")).unwrap();
    let mut h = H::new();
    let payer = h.payer;
    h.store.get_mut(&payer).unwrap().lamports = 2_000_000_000_000_000_000;
    let recon = |h: &H| {
        let d = &h.store[&h.config].data;
        let at = CONFIG_LEN - 40;
        (u64::from_le_bytes(d[at..at + 8].try_into().unwrap()), d[at + 8..].to_vec())
    };
    assert_eq!(h.lock_sol("committed", 0, 400), None);
    assert_eq!(recon(&h), (1, raw(&rv["entries"][0]["acc"])));
    assert_eq!(h.lock_sol("aborted", 2, 1_000_000_000_000_000_000), None);
    let (recipient, buf) = (h.recipient, h.staged("committed"));
    assert_eq!(h.settle("committed", 0, CHECKPOINT, buf, recipient, None), None);
    let buf = h.staged("aborted");
    assert_eq!(h.settle("aborted", 2, CHECKPOINT, buf, payer, None), None);
    assert_eq!(h.lock_sol("undecided", 1, 250), None);
    h.m.sysvars.clock.unix_timestamp = NOW + HORIZON as i64;
    assert_eq!(h.escape("undecided", 1, payer), None);
    assert_eq!(recon(&h), (rv["count"].as_u64().unwrap(), raw(&rv["acc"])));

    let ix = Instruction::new_with_bytes(h.program, &[7], vec![AccountMeta::new_readonly(h.config, false)]);
    let r = h.m.process_instruction(&ix, &[(h.config, h.store[&h.config].clone())]);
    assert!(matches!(r.program_result, ProgramResult::Success));
    let got = hex::encode(&r.return_data);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../sdk/fixtures/settlement_lock/solana_accumulator_body.hex");
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::write(path, format!("{got}\n")).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap().trim(), got);
    assert_eq!(&r.return_data[..8], &6u64.to_be_bytes());
    assert_eq!(r.return_data[8..].to_vec(), raw(&rv["acc"]));
}
