// SPDX-License-Identifier: Apache-2.0
//! Tenzro settlement-plan legs on Solana.
//!
//! A payer locks lamports, or an amount of an SPL token, as leg `index` of
//! plan `plan_id`, payable to a recipient. The leg settles once, on the
//! plan's decision proven under the state root of the final checkpoint held
//! by Tenzro's finality client on Solana: a commit pays the recipient, an
//! abort refunds the payer. Without a proven decision the payer reclaims the
//! leg only after the escape horizon. No key holds any authority here.
//!
//! A decision and its state proof outgrow a transaction, so they are staged
//! in a buffer account first (`write`), and `settle` reads them from it.
//!
//! Instructions (first byte):
//!
//! ```text
//! 0  initialize  finality_program:32 finality_state:32 escape_horizon_s:u64
//! 1  lock        plan_id:32 index:u8 amount:u64 recipient:32
//! 2  settle      plan_id:32 index:u8 checkpoint:u64
//! 3  escape      plan_id:32 index:u8
//! 4  write       offset:u32 bytes
//! 5  close       (a buffer)
//! 6  receipt     leg_id:32 checkpoint:u64
//! 7  checkpoint
//! ```
//!
//! Accounts:
//!
//! ```text
//! initialize  config (writable, signer, owned by the program)
//! lock        config (writable), leg (writable, the PDA ["leg", config, leg_id]), payer (writable, signer),
//!             funder (writable, signer; pays the leg's rent, may be the payer), system program
//!             and for a token: mint, payer's token account (writable), vault (writable, a token
//!             account of the mint owned by the leg), token program
//! settle      config (writable), leg (writable), finality state, buffer, destination (writable)
//!             and for a token: mint, vault (writable), token program
//! escape      config (writable), leg (writable), destination (writable)
//!             and for a token: mint, vault (writable), token program
//! write       buffer (writable, owned by the program; a signer on the first write), authority (signer)
//! close       buffer (writable), authority (writable, signer)
//! receipt     config, finality state, buffer
//! checkpoint  config
//! ```
//!
//! Every lock, release and refund folds into the config's running
//! reconciliation hash; `checkpoint` logs `[accumulator, count (8, big endian)
//! || acc]` and returns the same 40 bytes, for Tenzro to compare with its
//! own books.
//!
//! `receipt` checks a leg's receipt (the record at `plr:<leg_id>`, staged in
//! the buffer with its state proof) against the checkpoint's state root and
//! returns it as the instruction's return data, so a program that calls it
//! can rely on the leg's outcome and its relayer's repaid network fee.
//!
//! The destination is the recipient on a commit and the payer otherwise:
//! the wallet itself for lamports, or its token account of the mint.

use solana_program::account_info::AccountInfo;
use solana_program::clock::Clock;
use solana_program::entrypoint::ProgramResult;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::log::sol_log_data;
use solana_program::program::{invoke, invoke_signed, set_return_data};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::Sysvar;
use tenzro_finality_solana::{State, STATE_LEN};
use tenzro_finality_verifier::settlement::{self, LegError, LegState, DECISION_LEN, LEG_RECEIPT_LEN};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// The SPL Token program.
pub const TOKEN_PROGRAM: Pubkey = solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// The SPL Token-2022 program.
pub const TOKEN_2022_PROGRAM: Pubkey = solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0; 32]);

const KIND_CONFIG: u8 = 1;
const KIND_LEG: u8 = 2;
const KIND_BUFFER: u8 = 3;

/// Config: kind, finality program, finality state account, escape horizon,
/// reconciliation entry count and running hash.
pub const CONFIG_LEN: usize = 1 + 32 + 32 + 8 + 8 + 32;
const RECON_AT: usize = 1 + 32 + 32 + 8;
/// Leg: kind, stage, payer, recipient, mint (zero for lamports), vault,
/// amount, escape_at (unix seconds), bump.
pub const LEG_LEN: usize = 1 + 1 + 32 + 32 + 32 + 32 + 8 + 8 + 1;
/// Buffer header: kind, authority, payload length.
pub const BUFFER_HEADER: usize = 1 + 32 + 4;

/// A leg's stage byte.
pub const LOCKED: u8 = 1;
pub const RELEASED: u8 = 2;
pub const REFUNDED: u8 = 3;

/// The leg is already locked.
pub const E_ALREADY_LOCKED: u32 = 1;
/// The leg is not locked, or was already settled.
pub const E_NOT_LOCKED: u32 = 2;
/// The amount is zero, or the vault did not receive exactly it.
pub const E_BAD_AMOUNT: u32 = 3;
/// The decision does not prove under the checkpoint's state root.
pub const E_UNPROVEN: u32 = 4;
/// The escape horizon has not passed.
pub const E_TOO_EARLY: u32 = 5;
/// The finality client holds no such final checkpoint.
pub const E_UNKNOWN_CHECKPOINT: u32 = 6;
/// The destination is not the leg's recipient or payer as the outcome requires.
pub const E_WRONG_DESTINATION: u32 = 7;
/// An account is not the one the leg or the config names.
pub const E_WRONG_ACCOUNT: u32 = 8;
/// The buffer is malformed, or another authority's.
pub const E_BAD_BUFFER: u32 = 9;
/// Already initialized.
pub const E_INITIALIZED: u32 = 20;
/// Not initialized.
pub const E_UNINITIALIZED: u32 = 21;

fn fail(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

fn leg_err(e: LegError) -> ProgramError {
    fail(match e {
        LegError::NotLocked => E_NOT_LOCKED,
        LegError::Unproven => E_UNPROVEN,
        LegError::TooEarly => E_TOO_EARLY,
    })
}

fn b32(b: &[u8], at: usize) -> [u8; 32] {
    b[at..at + 32].try_into().expect("32 bytes")
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// The PDA holding leg `leg_id` under `config`.
pub fn leg_address(program_id: &Pubkey, config: &Pubkey, leg_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"leg", config.as_ref(), leg_id], program_id)
}

struct Config {
    finality_program: Pubkey,
    finality_state: Pubkey,
    horizon: u64,
}

fn config(program_id: &Pubkey, a: &AccountInfo) -> Result<Config, ProgramError> {
    if a.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let d = a.try_borrow_data()?;
    if d.len() < CONFIG_LEN || d[0] != KIND_CONFIG {
        return Err(fail(E_UNINITIALIZED));
    }
    Ok(Config {
        finality_program: Pubkey::new_from_array(b32(&d, 1)),
        finality_state: Pubkey::new_from_array(b32(&d, 33)),
        horizon: u64_at(&d, 65),
    })
}

/// A locked leg as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leg {
    pub stage: u8,
    pub payer: Pubkey,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub amount: u64,
    pub escape_at: u64,
    pub bump: u8,
}

impl Leg {
    pub fn decode(d: &[u8]) -> Option<Leg> {
        (d.len() >= LEG_LEN && d[0] == KIND_LEG).then(|| Leg {
            stage: d[1],
            payer: Pubkey::new_from_array(b32(d, 2)),
            recipient: Pubkey::new_from_array(b32(d, 34)),
            mint: Pubkey::new_from_array(b32(d, 66)),
            vault: Pubkey::new_from_array(b32(d, 98)),
            amount: u64_at(d, 130),
            escape_at: u64_at(d, 138),
            bump: d[146],
        })
    }

    fn encode(&self, d: &mut [u8]) {
        d[0] = KIND_LEG;
        d[1] = self.stage;
        d[2..34].copy_from_slice(self.payer.as_ref());
        d[34..66].copy_from_slice(self.recipient.as_ref());
        d[66..98].copy_from_slice(self.mint.as_ref());
        d[98..130].copy_from_slice(self.vault.as_ref());
        d[130..138].copy_from_slice(&self.amount.to_le_bytes());
        d[138..146].copy_from_slice(&self.escape_at.to_le_bytes());
        d[146] = self.bump;
    }

    fn state(&self) -> LegState {
        match self.stage {
            LOCKED => LegState::Locked,
            RELEASED => LegState::Released,
            _ => LegState::Refunded,
        }
    }
}

/// The plan id and leg index at the head of `data`, and the rest.
fn plan_index(data: &[u8]) -> Result<([u8; 32], u8, &[u8]), ProgramError> {
    if data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok((b32(data, 0), data[32], &data[33..]))
}

fn system_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction { program_id: SYSTEM_PROGRAM, accounts, data }
}

/// Create the leg account at its PDA, funded with `lamports` by `payer`,
/// even if someone already sent lamports to the address.
fn create_leg<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    leg: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    lamports: u64,
    seeds: &[&[u8]],
) -> ProgramResult {
    let accounts = [payer.clone(), leg.clone(), system.clone()];
    if leg.lamports() == 0 {
        let mut d = vec![0, 0, 0, 0];
        d.extend_from_slice(&lamports.to_le_bytes());
        d.extend_from_slice(&(LEG_LEN as u64).to_le_bytes());
        d.extend_from_slice(program_id.as_ref());
        let ix = system_ix(vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*leg.key, true)], d);
        return invoke_signed(&ix, &accounts, &[seeds]);
    }
    let short = lamports.saturating_sub(leg.lamports());
    if short > 0 {
        let mut d = vec![2, 0, 0, 0];
        d.extend_from_slice(&short.to_le_bytes());
        invoke(&system_ix(vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*leg.key, false)], d), &accounts)?;
    }
    let mut d = vec![8, 0, 0, 0];
    d.extend_from_slice(&(LEG_LEN as u64).to_le_bytes());
    invoke_signed(&system_ix(vec![AccountMeta::new(*leg.key, true)], d), &accounts, &[seeds])?;
    let mut d = vec![1, 0, 0, 0];
    d.extend_from_slice(program_id.as_ref());
    invoke_signed(&system_ix(vec![AccountMeta::new(*leg.key, true)], d), &accounts, &[seeds])
}

/// A token account's mint, owner and amount.
fn token_account(a: &AccountInfo, token_program: &Pubkey) -> Result<(Pubkey, Pubkey, u64), ProgramError> {
    if a.owner != token_program {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    let d = a.try_borrow_data()?;
    if d.len() < 165 {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    Ok((Pubkey::new_from_array(b32(&d, 0)), Pubkey::new_from_array(b32(&d, 32)), u64_at(&d, 64)))
}

fn transfer_checked<'a>(
    token_program: &AccountInfo<'a>,
    from: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    seeds: &[&[&[u8]]],
) -> ProgramResult {
    let decimals = *mint.try_borrow_data()?.get(44).ok_or(fail(E_WRONG_ACCOUNT))?;
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    invoke_signed(&ix, &[from.clone(), mint.clone(), to.clone(), authority.clone(), token_program.clone()], seeds)
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => initialize(program_id, accounts, rest),
        1 => lock(program_id, accounts, rest),
        2 => settle(program_id, accounts, rest),
        3 => escape(program_id, accounts, rest),
        4 => write(program_id, accounts, rest),
        5 => close(program_id, accounts),
        6 => receipt(program_id, accounts, rest),
        7 => checkpoint(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [cfg, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if rest.len() != 72 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if cfg.owner != program_id || !cfg.is_writable {
        return Err(ProgramError::IllegalOwner);
    }
    if !cfg.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut d = cfg.try_borrow_mut_data()?;
    if d.len() < CONFIG_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if d[0] != 0 {
        return Err(fail(E_INITIALIZED));
    }
    d[0] = KIND_CONFIG;
    d[1..RECON_AT].copy_from_slice(rest);
    Ok(())
}

fn lock(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [cfg_a, leg_a, payer, funder, system, token @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let cfg = config(program_id, cfg_a)?;
    let (plan_id, index, rest) = plan_index(rest)?;
    if rest.len() != 40 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64_at(rest, 0);
    let recipient = Pubkey::new_from_array(b32(rest, 8));
    if amount == 0 {
        return Err(fail(E_BAD_AMOUNT));
    }
    if !payer.is_signer || !funder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *system.key != SYSTEM_PROGRAM {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    let leg_id = settlement::leg_id(&plan_id, index);
    let (address, bump) = leg_address(program_id, cfg_a.key, &leg_id);
    if *leg_a.key != address {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    if leg_a.owner == program_id {
        return Err(fail(E_ALREADY_LOCKED));
    }
    let seeds: &[&[u8]] = &[b"leg", cfg_a.key.as_ref(), &leg_id, &[bump]];
    let rent = Rent::get()?.minimum_balance(LEG_LEN);
    let (mint, vault) = match token {
        [] => {
            create_leg(program_id, funder, leg_a, system, rent, seeds)?;
            let mut d = vec![2, 0, 0, 0];
            d.extend_from_slice(&amount.to_le_bytes());
            let ix = system_ix(vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*leg_a.key, false)], d);
            invoke(&ix, &[payer.clone(), leg_a.clone(), system.clone()])?;
            (Pubkey::default(), Pubkey::default())
        }
        [mint, from, vault, token_program, ..] => {
            if *token_program.key != TOKEN_PROGRAM && *token_program.key != TOKEN_2022_PROGRAM {
                return Err(fail(E_WRONG_ACCOUNT));
            }
            if mint.owner != token_program.key {
                return Err(fail(E_WRONG_ACCOUNT));
            }
            let (vault_mint, vault_owner, before) = token_account(vault, token_program.key)?;
            if vault_mint != *mint.key || vault_owner != address {
                return Err(fail(E_WRONG_ACCOUNT));
            }
            create_leg(program_id, funder, leg_a, system, rent, seeds)?;
            transfer_checked(token_program, from, mint, vault, payer, amount, &[])?;
            let (_, _, after) = token_account(vault, token_program.key)?;
            if after.checked_sub(before) != Some(amount) {
                return Err(fail(E_BAD_AMOUNT));
            }
            (*mint.key, *vault.key)
        }
        _ => return Err(ProgramError::NotEnoughAccountKeys),
    };
    let now = Clock::get()?.unix_timestamp.max(0) as u64;
    let leg = Leg {
        stage: LOCKED,
        payer: *payer.key,
        recipient,
        mint,
        vault,
        amount,
        escape_at: now.saturating_add(cfg.horizon),
        bump,
    };
    leg.encode(&mut leg_a.try_borrow_mut_data()?);
    record(cfg_a, &plan_id, &leg_id, settlement::RECON_LOCKED, amount)?;
    sol_log_data(&[
        b"locked",
        &plan_id,
        &leg_id,
        &[index],
        payer.key.as_ref(),
        recipient.as_ref(),
        mint.as_ref(),
        &amount.to_le_bytes(),
        &leg.escape_at.to_le_bytes(),
    ]);
    Ok(())
}

/// The leg at `leg_a`, checked to be leg `index` of `plan_id` under `cfg_a`.
fn load_leg(program_id: &Pubkey, cfg_a: &AccountInfo, leg_a: &AccountInfo, plan_id: &[u8; 32], index: u8) -> Result<([u8; 32], Leg), ProgramError> {
    if leg_a.owner != program_id || !leg_a.is_writable {
        return Err(fail(E_NOT_LOCKED));
    }
    let leg = Leg::decode(&leg_a.try_borrow_data()?).ok_or(fail(E_NOT_LOCKED))?;
    let leg_id = settlement::leg_id(plan_id, index);
    let address = Pubkey::create_program_address(&[b"leg", cfg_a.key.as_ref(), &leg_id, &[leg.bump]], program_id)
        .map_err(|_| fail(E_WRONG_ACCOUNT))?;
    if address != *leg_a.key {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    Ok((leg_id, leg))
}

fn settle(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [cfg_a, leg_a, finality, buffer, to, token @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let cfg = config(program_id, cfg_a)?;
    let (plan_id, index, rest) = plan_index(rest)?;
    if rest.len() != 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let checkpoint = u64_at(rest, 0);
    let (leg_id, leg) = load_leg(program_id, cfg_a, leg_a, &plan_id, index)?;
    let root = final_root(&cfg, finality, checkpoint)?;
    let b = buffer.try_borrow_data()?;
    let payload = staged(program_id, buffer, &b)?;
    if payload.len() < DECISION_LEN {
        return Err(fail(E_UNPROVEN));
    }
    let (decision, proof) = payload.split_at(DECISION_LEN);
    let next = settlement::settle_leg(leg.state(), &root, &plan_id, decision, proof).map_err(leg_err)?;
    drop(b);
    pay(cfg_a, leg_a, to, token, plan_id, leg_id, leg, next, false)
}

/// The state root of final checkpoint `checkpoint` held by the configured
/// finality client.
fn final_root(cfg: &Config, finality: &AccountInfo, checkpoint: u64) -> Result<[u8; 32], ProgramError> {
    if *finality.key != cfg.finality_state || *finality.owner != cfg.finality_program {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    let mut state = finality.try_borrow_data()?.get(..STATE_LEN).ok_or(fail(E_WRONG_ACCOUNT))?.to_vec();
    match State(&mut state).latest() {
        Some((latest, _, root, _)) if latest == checkpoint => Ok(root),
        _ => Err(fail(E_UNKNOWN_CHECKPOINT)),
    }
}

/// The bytes staged in a buffer this program owns.
fn staged<'b>(program_id: &Pubkey, buffer: &AccountInfo, b: &'b [u8]) -> Result<&'b [u8], ProgramError> {
    if buffer.owner != program_id || b.len() < BUFFER_HEADER || b[0] != KIND_BUFFER {
        return Err(fail(E_BAD_BUFFER));
    }
    let n = u32::from_le_bytes(b[33..37].try_into().expect("4 bytes")) as usize;
    b.get(BUFFER_HEADER..BUFFER_HEADER + n).ok_or(fail(E_BAD_BUFFER))
}

fn receipt(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [cfg_a, finality, buffer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let cfg = config(program_id, cfg_a)?;
    if rest.len() != 40 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let leg_id = b32(rest, 0);
    let root = final_root(&cfg, finality, u64_at(rest, 32))?;
    let b = buffer.try_borrow_data()?;
    let payload = staged(program_id, buffer, &b)?;
    if payload.len() < LEG_RECEIPT_LEN {
        return Err(fail(E_UNPROVEN));
    }
    let (bytes, proof) = payload.split_at(LEG_RECEIPT_LEN);
    settlement::proven_leg_receipt(&root, &leg_id, bytes, proof).ok_or(fail(E_UNPROVEN))?;
    set_return_data(bytes);
    Ok(())
}

fn escape(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [cfg_a, leg_a, to, token @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    config(program_id, cfg_a)?;
    let (plan_id, index, rest) = plan_index(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (leg_id, leg) = load_leg(program_id, cfg_a, leg_a, &plan_id, index)?;
    let now = Clock::get()?.unix_timestamp.max(0) as u64;
    let next = settlement::escape_leg(leg.state(), now, leg.escape_at).map_err(leg_err)?;
    pay(cfg_a, leg_a, to, token, plan_id, leg_id, leg, next, true)
}

fn pay<'a>(
    cfg_a: &AccountInfo<'a>,
    leg_a: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    token: &[AccountInfo<'a>],
    plan_id: [u8; 32],
    leg_id: [u8; 32],
    mut leg: Leg,
    next: LegState,
    escaped: bool,
) -> ProgramResult {
    let (wallet, stage, kind, recon): (Pubkey, u8, &[u8], u8) = match next {
        LegState::Released => (leg.recipient, RELEASED, b"released", settlement::RECON_RELEASED),
        LegState::Refunded => (leg.payer, REFUNDED, b"refunded", settlement::RECON_REFUNDED),
        LegState::Locked => return Err(fail(E_NOT_LOCKED)),
    };
    leg.stage = stage;
    leg.encode(&mut leg_a.try_borrow_mut_data()?);
    record(cfg_a, &plan_id, &leg_id, recon, leg.amount)?;
    if leg.mint == Pubkey::default() {
        if *to.key != wallet {
            return Err(fail(E_WRONG_DESTINATION));
        }
        **leg_a.try_borrow_mut_lamports()? -= leg.amount;
        **to.try_borrow_mut_lamports()? += leg.amount;
    } else {
        let [mint, vault, token_program, ..] = token else { return Err(ProgramError::NotEnoughAccountKeys) };
        if *mint.key != leg.mint || *vault.key != leg.vault || vault.owner != token_program.key {
            return Err(fail(E_WRONG_ACCOUNT));
        }
        let (to_mint, to_owner, _) = token_account(to, token_program.key)?;
        if to_mint != leg.mint || to_owner != wallet {
            return Err(fail(E_WRONG_DESTINATION));
        }
        let seeds: &[&[u8]] = &[b"leg", cfg_a.key.as_ref(), &leg_id, &[leg.bump]];
        transfer_checked(token_program, vault, mint, to, leg_a, leg.amount, &[seeds])?;
    }
    sol_log_data(&[kind, &plan_id, &leg_id, wallet.as_ref(), &leg.amount.to_le_bytes(), &[escaped as u8]]);
    Ok(())
}

/// Fold an entry into the config's running reconciliation hash.
fn record(cfg_a: &AccountInfo, plan_id: &[u8; 32], leg_id: &[u8; 32], kind: u8, amount: u64) -> ProgramResult {
    if !cfg_a.is_writable {
        return Err(fail(E_WRONG_ACCOUNT));
    }
    let mut d = cfg_a.try_borrow_mut_data()?;
    let count = u64_at(&d, RECON_AT);
    let acc = settlement::recon_step(&b32(&d, RECON_AT + 8), plan_id, leg_id, kind, amount as u128);
    d[RECON_AT..RECON_AT + 8].copy_from_slice(&(count + 1).to_le_bytes());
    d[RECON_AT + 8..CONFIG_LEN].copy_from_slice(&acc);
    Ok(())
}

fn checkpoint(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [cfg_a, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    config(program_id, cfg_a)?;
    let d = cfg_a.try_borrow_data()?;
    let body = settlement::recon_checkpoint(u64_at(&d, RECON_AT), &b32(&d, RECON_AT + 8));
    sol_log_data(&[b"accumulator", &body]);
    set_return_data(&body);
    Ok(())
}

fn write(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
    let [buffer, authority, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if buffer.owner != program_id || !buffer.is_writable {
        return Err(fail(E_BAD_BUFFER));
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if rest.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let offset = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
    let bytes = &rest[4..];
    let mut d = buffer.try_borrow_mut_data()?;
    if d.len() < BUFFER_HEADER {
        return Err(fail(E_BAD_BUFFER));
    }
    match d[0] {
        0 if buffer.is_signer => {
            d[0] = KIND_BUFFER;
            d[1..33].copy_from_slice(authority.key.as_ref());
        }
        KIND_BUFFER if d[1..33] == *authority.key.as_ref() => {}
        _ => return Err(fail(E_BAD_BUFFER)),
    }
    let end = offset.checked_add(bytes.len()).ok_or(fail(E_BAD_BUFFER))?;
    let slot = d.get_mut(BUFFER_HEADER + offset..BUFFER_HEADER + end).ok_or(fail(E_BAD_BUFFER))?;
    slot.copy_from_slice(bytes);
    let len = (u32::from_le_bytes(d[33..37].try_into().expect("4 bytes")) as usize).max(end);
    d[33..37].copy_from_slice(&(len as u32).to_le_bytes());
    Ok(())
}

fn close(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [buffer, authority, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if buffer.owner != program_id || !buffer.is_writable {
        return Err(fail(E_BAD_BUFFER));
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    {
        let mut d = buffer.try_borrow_mut_data()?;
        if d.len() < BUFFER_HEADER || d[0] != KIND_BUFFER || d[1..33] != *authority.key.as_ref() {
            return Err(fail(E_BAD_BUFFER));
        }
        d.fill(0);
    }
    let lamports = buffer.lamports();
    **buffer.try_borrow_mut_lamports()? = 0;
    **authority.try_borrow_mut_lamports()? += lamports;
    Ok(())
}
