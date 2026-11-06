// SPDX-License-Identifier: Apache-2.0
//! Tenzro agent accounts on Solana.
//!
//! An agent's account is the program address `[b"agent", sha256(did)]`. It
//! holds no key: its authority is the grant Tenzro issued for the agent on
//! this chain. Anyone installs a grant with `sync`: the grant bytes and their
//! state proof under the state root of the latest checkpoint Tenzro's
//! finality client on this chain accepted. Grant and proof are larger than
//! one transaction, so a relayer first writes them into its sync buffer
//! (`[b"sync", relayer]`). An action runs with `act` when the instruction
//! before it is a secp256r1 verification of serving-node signatures over the
//! action's digest preimage, by keys in the grant's key root (two of distinct
//! operators above the cosign threshold), within the grant's budget,
//! per-action limit, time window and targets. An exact grant carries one
//! action, run once with `act_exact`. A void grant stops every action. The
//! relayer that submits an action is refunded, in lamports, up to the grant's
//! cap. Events are logged as data: `Synced`, `GrantClosed`, `Acted`.
//!
//! Instructions (first byte):
//!
//! ```text
//! 0 create      did_len:u16 did                     [payer s w, account w, system]
//! 1 write       offset:u16 bytes                    [relayer s w, buffer w, system]
//! 2 sync        payee:32 caip19_len:u16 caip19      [relayer s, account w, buffer, finality state]
//! 3 act         action, signers, target proof       [relayer s w, account w, instructions sysvar,
//!                                                    (source token, destination token, token program)
//!                                                    or for a lock: (lock program, config w, leg w, system,
//!                                                    mint, source token, vault, token program)]
//! 4 act_exact   action                              [relayer s w, account w, (token accounts as act)]
//! ```
//!
//! An action's target is the recipient (system transfer, selector `[2]`) or
//! the destination token account (token transfer, selector `[3]`), or a
//! settlement lock program (selector `[4]`, token assets): the data is the
//! lock's `lock` instruction for exactly the action's amount, the account
//! signs as payer, the relayer funds the leg's rent, and the source token
//! account must end exactly that amount lower and otherwise unchanged. A
//! transfer whose data is the 104-byte pay data (Tenzro payee, request and
//! quote digests, USD price) is a payment, logged as a `Reported` report.
use solana_program::account_info::{AccountInfo, next_account_info};
use solana_program::clock::Clock;
use solana_program::entrypoint::ProgramResult;
use solana_program::log::sol_log_data;
use solana_program::program::invoke_signed;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::{Sysvar, instructions as ix_sysvar};
use tenzro_finality_verifier::{agent, state_proof};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// Where this program's deployment points. The deployment fills these in
/// before the one immutable build; tests run against these values.
pub mod config {
    use solana_program::pubkey::Pubkey;
    /// This chain, CAIP-2.
    pub const CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    /// Tenzro's finality client program.
    pub const FINALITY_PROGRAM: Pubkey = Pubkey::new_from_array([0x0f; 32]);
    /// The finality client's state account.
    pub const FINALITY_STATE: Pubkey = Pubkey::new_from_array([0x5f; 32]);
}

/// The secp256r1 signature-verify program.
pub const SECP256R1_PROGRAM_ID: Pubkey = Pubkey::from_str_const("Secp256r1SigVerify1111111111111111111111111");
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
pub const TOKEN_PROGRAM_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

pub const ACCOUNT_LEN: usize = 447;
pub const BUFFER_LEN: usize = 4096;
const O_INIT: usize = 0;
const O_BUMP: usize = 1;
const O_AGENT: usize = 2;
const O_TREE_KEY: usize = 34;
const O_INSTALLED: usize = 66;
const O_GRANT: usize = 67;
const O_SPENT: usize = 389;
const O_NONCE: usize = 405;
const O_EXACT_USED: usize = 413;
const O_ASSET_KIND: usize = 414;
const O_MINT: usize = 415;
const ASSET_NATIVE: u8 = 1;
const ASSET_TOKEN: u8 = 2;
const SELECTOR_SYSTEM_TRANSFER: u8 = 2;
const SELECTOR_TOKEN_TRANSFER: u8 = 3;
/// Lock a settlement leg: the target is the lock program and the data its
/// `lock` instruction, for exactly the action's amount.
const SELECTOR_LOCK: u8 = 4;
/// The lock program's `lock` instruction: tag 1, plan id, index, amount
/// (u64 LE), recipient.
const LOCK_IX_LEN: usize = 1 + 32 + 1 + 8 + 32;

/// Why an instruction was refused (custom error codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AccountError {
    Malformed = 1,
    WrongAccount,
    AlreadyCreated,
    NotCreated,
    NoCheckpoint,
    BadStateProof,
    MalformedGrant,
    NotThisAccount,
    StaleGrant,
    AssetMismatch,
    NoLiveGrant,
    GrantVoid,
    OutsideWindow,
    ExactGrant,
    NotExact,
    ExactUsed,
    PayloadMismatch,
    MissingSignatures,
    SignatureMismatch,
    KeyNotInRoot,
    CosignRequired,
    TargetNotAllowed,
    OverPerAction,
    OverBudget,
    RelayOverCap,
    UnsupportedAction,
    WrongTokenAccount,
    PulledOtherThanStated,
}

impl From<AccountError> for ProgramError {
    fn from(e: AccountError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AccountError> {
        if self.0.len() < n {
            return Err(AccountError::Malformed);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, AccountError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, AccountError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }
    fn u32(&mut self) -> Result<u32, AccountError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn b32(&mut self) -> Result<[u8; 32], AccountError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
    fn u128(&mut self) -> Result<u128, AccountError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().expect("16 bytes")))
    }
}

/// An action, as the grant's digest encodes it.
pub struct Action<'a> {
    pub encoded: &'a [u8],
    pub target: &'a [u8],
    pub selector: &'a [u8],
    pub amount: u128,
    pub relay_refund: u128,
    pub data: &'a [u8],
}

/// Read one encoded action off the front of `r`.
fn action<'a>(r: &mut Reader<'a>) -> Result<Action<'a>, AccountError> {
    let start = r.0;
    let tl = r.u16()? as usize;
    let target = r.take(tl)?;
    let sl = r.u16()? as usize;
    let selector = r.take(sl)?;
    let amount = r.u128()?;
    let relay_refund = r.u128()?;
    let dl = r.u32()? as usize;
    let data = r.take(dl)?;
    let used = start.len() - r.0.len();
    Ok(Action { encoded: &start[..used], target, selector, amount, relay_refund, data })
}

/// The account of the agent with SHA-256 `agent`.
pub fn account_address(program_id: &Pubkey, agent: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"agent", agent], program_id)
}

/// A relayer's sync buffer.
pub fn buffer_address(program_id: &Pubkey, relayer: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"sync", relayer.as_ref()], program_id)
}

fn grant_of(d: &[u8]) -> Result<agent::Grant, AccountError> {
    agent::Grant::decode(&d[O_GRANT..O_GRANT + agent::GRANT_LEN]).ok_or(AccountError::MalformedGrant)
}

fn u128_at(d: &[u8], o: usize) -> u128 {
    u128::from_le_bytes(d[o..o + 16].try_into().expect("16 bytes"))
}

fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().expect("8 bytes"))
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&op, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    match op {
        0 => create(program_id, accounts, rest),
        1 => write(program_id, accounts, rest),
        2 => sync(program_id, accounts, rest),
        3 => act(program_id, accounts, rest, false),
        4 => act(program_id, accounts, rest, true),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn create_pda<'a>(
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    program_id: &Pubkey,
    space: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    let lamports = Rent::get()?.minimum_balance(space);
    let ix = solana_program::instruction::Instruction::new_with_bincode(
        SYSTEM_PROGRAM_ID,
        &(0u32, lamports, space as u64, *program_id),
        vec![
            solana_program::instruction::AccountMeta::new(*payer.key, true),
            solana_program::instruction::AccountMeta::new(*pda.key, true),
        ],
    );
    invoke_signed(&ix, &[payer.clone(), pda.clone(), system.clone()], &[seeds])
}

fn create(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let account = next_account_info(it)?;
    let system = next_account_info(it)?;
    let mut r = Reader(data);
    let n = r.u16()? as usize;
    let did = r.take(n)?;
    let agent_hash = solana_program::hash::hashv(&[did]).to_bytes();
    let (expected, bump) = account_address(program_id, &agent_hash);
    if *account.key != expected {
        return Err(AccountError::WrongAccount.into());
    }
    if account.owner == program_id {
        return Err(AccountError::AlreadyCreated.into());
    }
    create_pda(payer, account, system, program_id, ACCOUNT_LEN, &[b"agent", &agent_hash, &[bump]])?;
    let mut d = account.try_borrow_mut_data()?;
    d[O_INIT] = 1;
    d[O_BUMP] = bump;
    d[O_AGENT..O_AGENT + 32].copy_from_slice(&agent_hash);
    d[O_TREE_KEY..O_TREE_KEY + 32].copy_from_slice(&agent::grant_tree_key(did, config::CAIP2.as_bytes()));
    Ok(())
}

fn write(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let relayer = next_account_info(it)?;
    let buffer = next_account_info(it)?;
    let system = next_account_info(it)?;
    if !relayer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, bump) = buffer_address(program_id, relayer.key);
    if *buffer.key != expected {
        return Err(AccountError::WrongAccount.into());
    }
    if buffer.owner != program_id {
        create_pda(relayer, buffer, system, program_id, BUFFER_LEN, &[b"sync", relayer.key.as_ref(), &[bump]])?;
    }
    let mut r = Reader(data);
    let offset = r.u16()? as usize;
    let bytes = r.0;
    let mut d = buffer.try_borrow_mut_data()?;
    let end = offset.checked_add(bytes.len()).filter(|e| *e <= BUFFER_LEN).ok_or(AccountError::Malformed)?;
    d[offset..end].copy_from_slice(bytes);
    Ok(())
}

/// The asset a CAIP-19 id names: native SOL (`slip44:501`) or an SPL mint.
fn asset(caip19: &[u8]) -> Result<(u8, [u8; 32]), AccountError> {
    let s = core::str::from_utf8(caip19).map_err(|_| AccountError::AssetMismatch)?;
    let (chain, rest) = s.split_once('/').ok_or(AccountError::AssetMismatch)?;
    if chain != config::CAIP2 {
        return Err(AccountError::AssetMismatch);
    }
    if rest == "slip44:501" {
        return Ok((ASSET_NATIVE, [0u8; 32]));
    }
    let mint = rest.strip_prefix("token:").ok_or(AccountError::AssetMismatch)?;
    let key: Pubkey = core::str::FromStr::from_str(mint).map_err(|_| AccountError::AssetMismatch)?;
    Ok((ASSET_TOKEN, key.to_bytes()))
}

fn sync(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let relayer = next_account_info(it)?;
    let account = next_account_info(it)?;
    let buffer = next_account_info(it)?;
    let finality = next_account_info(it)?;
    if !relayer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if account.owner != program_id || buffer.owner != program_id || *buffer.key != buffer_address(program_id, relayer.key).0 {
        return Err(AccountError::WrongAccount.into());
    }
    if *finality.key != config::FINALITY_STATE || *finality.owner != config::FINALITY_PROGRAM {
        return Err(AccountError::WrongAccount.into());
    }
    let mut r = Reader(data);
    let payee = r.b32()?;
    let cl = r.u16()? as usize;
    let caip19 = r.take(cl)?;
    let root = {
        let mut f = finality.try_borrow_mut_data()?;
        let len = f.len();
        let state = tenzro_finality_solana::State(&mut f[..len]);
        state.latest().ok_or(AccountError::NoCheckpoint)?.2
    };
    let buf = buffer.try_borrow_data()?;
    let mut b = Reader(&buf);
    let gl = b.u16()? as usize;
    let grant_bytes = b.take(gl)?;
    let pl = b.u16()? as usize;
    let proof = b.take(pl)?;
    let mut d = account.try_borrow_mut_data()?;
    if d[O_INIT] != 1 {
        return Err(AccountError::NotCreated.into());
    }
    let tree_key: [u8; 32] = d[O_TREE_KEY..O_TREE_KEY + 32].try_into().expect("32 bytes");
    if !state_proof::verify_at(&root, &tree_key, Some(grant_bytes), proof) {
        return Err(AccountError::BadStateProof.into());
    }
    let g = agent::Grant::decode(grant_bytes).ok_or(AccountError::MalformedGrant)?;
    let chain = solana_program::hash::hashv(&[config::CAIP2.as_bytes()]).to_bytes();
    if g.chain != chain || g.agent[..] != d[O_AGENT..O_AGENT + 32] || g.account != account.key.to_bytes() {
        return Err(AccountError::NotThisAccount.into());
    }
    let installed = d[O_INSTALLED] == 1;
    let mut new_seq = true;
    if installed {
        let cur = grant_of(&d)?;
        let later = g.seq > cur.seq;
        let voids = g.seq == cur.seq && g.void && !cur.void;
        if !later && !voids {
            return Err(AccountError::StaleGrant.into());
        }
        if later {
            sol_log_data(&[b"GrantClosed", &cur.seq.to_be_bytes(), &u128_at(&d, O_SPENT).to_be_bytes()]);
        } else {
            new_seq = false;
        }
    }
    if solana_program::hash::hashv(&[caip19]).to_bytes() != g.asset {
        return Err(AccountError::AssetMismatch.into());
    }
    let (kind, mint) = asset(caip19)?;
    d[O_ASSET_KIND] = kind;
    d[O_MINT..O_MINT + 32].copy_from_slice(&mint);
    if new_seq {
        d[O_SPENT..O_SPENT + 16].copy_from_slice(&0u128.to_le_bytes());
        d[O_EXACT_USED] = 0;
    }
    d[O_GRANT..O_GRANT + agent::GRANT_LEN].copy_from_slice(grant_bytes);
    d[O_INSTALLED] = 1;
    sol_log_data(&[b"Synced", &g.seq.to_be_bytes(), &[u8::from(g.void)], &payee]);
    Ok(())
}

/// The signers the secp256r1 instruction before this one verified: each
/// one's compressed key, over messages that must all be `message`.
fn verified_keys(sysvar: &AccountInfo, message: &[u8]) -> Result<Vec<[u8; 33]>, ProgramError> {
    if *sysvar.key != ix_sysvar::ID {
        return Err(AccountError::WrongAccount.into());
    }
    let current = ix_sysvar::load_current_index_checked(sysvar)? as usize;
    if current == 0 {
        return Err(AccountError::MissingSignatures.into());
    }
    let ix = ix_sysvar::load_instruction_at_checked(current - 1, sysvar)?;
    if ix.program_id != SECP256R1_PROGRAM_ID {
        return Err(AccountError::MissingSignatures.into());
    }
    let d = &ix.data;
    let count = *d.first().ok_or(AccountError::MissingSignatures)? as usize;
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let base = 2 + 14 * i;
        let field = |k: usize| -> Option<usize> { Some(u16::from_le_bytes([*d.get(base + 2 * k)?, *d.get(base + 2 * k + 1)?]) as usize) };
        let f = |k| field(k).ok_or(AccountError::SignatureMismatch);
        let (sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) = (f(1)?, f(2)?, f(3)?, f(4)?, f(5)?, f(6)?);
        if sig_ix != 0xFFFF || pk_ix != 0xFFFF || msg_ix != 0xFFFF {
            return Err(AccountError::SignatureMismatch.into());
        }
        let msg = d.get(msg_off..msg_off + msg_len).ok_or(AccountError::SignatureMismatch)?;
        if msg != message {
            return Err(AccountError::SignatureMismatch.into());
        }
        let pk = d.get(pk_off..pk_off + 33).ok_or(AccountError::SignatureMismatch)?;
        keys.push(pk.try_into().expect("33 bytes"));
    }
    Ok(keys)
}

fn act(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], exact: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let relayer = next_account_info(it)?;
    let account = next_account_info(it)?;
    if !relayer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if account.owner != program_id {
        return Err(AccountError::WrongAccount.into());
    }
    let sysvar = if exact { None } else { Some(next_account_info(it)?) };
    let mut r = Reader(data);
    let a = action(&mut r)?;
    let (g, spent, nonce) = {
        let d = account.try_borrow_data()?;
        if d[O_INSTALLED] != 1 {
            return Err(AccountError::NoLiveGrant.into());
        }
        (grant_of(&d)?, u128_at(&d, O_SPENT), u64_at(&d, O_NONCE))
    };
    if g.void {
        return Err(AccountError::GrantVoid.into());
    }
    let now_ms = (Clock::get()?.unix_timestamp.max(0) as u64) * 1000;
    if now_ms < g.not_before_ms || now_ms > g.not_after_ms {
        return Err(AccountError::OutsideWindow.into());
    }
    if a.relay_refund > g.relay_fee_max {
        return Err(AccountError::RelayOverCap.into());
    }
    let digest;
    if exact {
        if !g.is_exact() {
            return Err(AccountError::NotExact.into());
        }
        if account.try_borrow_data()?[O_EXACT_USED] == 1 {
            return Err(AccountError::ExactUsed.into());
        }
        digest = agent::payload_hash(a.encoded);
        if digest != g.payload_hash {
            return Err(AccountError::PayloadMismatch.into());
        }
    } else {
        if g.is_exact() {
            return Err(AccountError::ExactGrant.into());
        }
        if a.amount > g.per_action_max {
            return Err(AccountError::OverPerAction.into());
        }
        if spent + a.amount > g.budget {
            return Err(AccountError::OverBudget.into());
        }
        let mut message = Vec::with_capacity(19 + 32 + 32 + 16 + a.encoded.len());
        message.extend_from_slice(agent::ACT_DOMAIN);
        message.extend_from_slice(&g.chain);
        message.extend_from_slice(&g.account);
        message.extend_from_slice(&g.seq.to_be_bytes());
        message.extend_from_slice(&nonce.to_be_bytes());
        message.extend_from_slice(a.encoded);
        digest = solana_program::hash::hashv(&[&message]).to_bytes();
        let verified = verified_keys(sysvar.expect("act takes the sysvar"), &message)?;
        let n = r.u8()? as usize;
        let need = if a.amount > g.cosign_above { 2 } else { 1 };
        if n < need || verified.len() < need {
            return Err(AccountError::CosignRequired.into());
        }
        let mut first_operator: Option<&[u8]> = None;
        for key in verified.iter().take(need) {
            let x = r.b32()?;
            let y = r.b32()?;
            let ol = r.u16()? as usize;
            let operator = r.take(ol)?;
            let pl = r.u8()? as usize;
            let mut proof = Vec::with_capacity(pl);
            for _ in 0..pl {
                proof.push(r.b32()?);
            }
            let mut compressed = [0u8; 33];
            compressed[0] = 2 + (y[31] & 1);
            compressed[1..].copy_from_slice(&x);
            if compressed != *key {
                return Err(AccountError::SignatureMismatch.into());
            }
            let mut sec1 = [0u8; 65];
            sec1[0] = 4;
            sec1[1..33].copy_from_slice(&x);
            sec1[33..].copy_from_slice(&y);
            if !agent::merkle_verify(&g.keys_root, &agent::key_leaf(&sec1, operator), &proof) {
                return Err(AccountError::KeyNotInRoot.into());
            }
            match first_operator {
                None => first_operator = Some(operator),
                Some(first) if first == operator => return Err(AccountError::CosignRequired.into()),
                Some(_) => {}
            }
        }
        if g.targets_root != [0u8; 32] {
            let pl = r.u8()? as usize;
            let mut proof = Vec::with_capacity(pl);
            for _ in 0..pl {
                proof.push(r.b32()?);
            }
            if !agent::merkle_verify(&g.targets_root, &agent::target_leaf(a.target, a.selector), &proof) {
                return Err(AccountError::TargetNotAllowed.into());
            }
        }
    }
    {
        let mut d = account.try_borrow_mut_data()?;
        d[O_NONCE..O_NONCE + 8].copy_from_slice(&(nonce + 1).to_le_bytes());
        d[O_SPENT..O_SPENT + 16].copy_from_slice(&(spent + a.amount).to_le_bytes());
        if exact {
            d[O_EXACT_USED] = 1;
        }
    }
    execute(account, relayer, &a, it)?;
    if a.relay_refund > 0 {
        move_lamports(account, relayer, a.relay_refund)?;
    }
    sol_log_data(&[b"Acted", &g.seq.to_be_bytes(), &nonce.to_be_bytes(), &digest, &a.amount.to_be_bytes()]);
    // A transfer whose data is the pay data (payee, request, quote, USD
    // price) is a payment: report it for Tenzro to record as this agent's.
    if a.data.len() == agent::PAY_DATA_LEN {
        let report = agent::paid_report(&g, nonce, a.data, a.amount).ok_or(AccountError::UnsupportedAction)?;
        sol_log_data(&[b"Reported", &report]);
    }
    Ok(())
}

/// Move lamports out of the account, keeping it rent-exempt.
fn move_lamports(from: &AccountInfo, to: &AccountInfo, amount: u128) -> ProgramResult {
    let amount = u64::try_from(amount).map_err(|_| AccountError::UnsupportedAction)?;
    let keep = Rent::get()?.minimum_balance(from.data_len());
    let have = from.lamports();
    if have < keep.saturating_add(amount) {
        return Err(ProgramError::InsufficientFunds);
    }
    **from.try_borrow_mut_lamports()? = have - amount;
    **to.try_borrow_mut_lamports()? = to.lamports().checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
    Ok(())
}

fn execute<'a, 'b>(
    account: &'b AccountInfo<'a>,
    relayer: &'b AccountInfo<'a>,
    a: &Action,
    it: &mut core::slice::Iter<'b, AccountInfo<'a>>,
) -> ProgramResult {
    let (kind, mint, bump, agent_hash) = {
        let d = account.try_borrow_data()?;
        let mint: [u8; 32] = d[O_MINT..O_MINT + 32].try_into().expect("32 bytes");
        let agent_hash: [u8; 32] = d[O_AGENT..O_AGENT + 32].try_into().expect("32 bytes");
        (d[O_ASSET_KIND], mint, d[O_BUMP], agent_hash)
    };
    match (a.selector, kind) {
        ([SELECTOR_SYSTEM_TRANSFER], ASSET_NATIVE) => {
            let to = next_account_info(it)?;
            if a.target != to.key.as_ref() {
                return Err(AccountError::TargetNotAllowed.into());
            }
            move_lamports(account, to, a.amount)
        }
        ([SELECTOR_TOKEN_TRANSFER], ASSET_TOKEN) => {
            let source = next_account_info(it)?;
            let destination = next_account_info(it)?;
            let token_program = next_account_info(it)?;
            if *token_program.key != TOKEN_PROGRAM_ID || a.target != destination.key.as_ref() {
                return Err(AccountError::TargetNotAllowed.into());
            }
            {
                // SPL token account: mint 0..32, owner 32..64.
                let s = source.try_borrow_data()?;
                if source.owner != &TOKEN_PROGRAM_ID || s.len() < 64 || s[..32] != mint || s[32..64] != account.key.to_bytes() {
                    return Err(AccountError::WrongTokenAccount.into());
                }
            }
            let amount = u64::try_from(a.amount).map_err(|_| AccountError::UnsupportedAction)?;
            let mut data = vec![SELECTOR_TOKEN_TRANSFER];
            data.extend_from_slice(&amount.to_le_bytes());
            let ix = solana_program::instruction::Instruction {
                program_id: TOKEN_PROGRAM_ID,
                accounts: vec![
                    solana_program::instruction::AccountMeta::new(*source.key, false),
                    solana_program::instruction::AccountMeta::new(*destination.key, false),
                    solana_program::instruction::AccountMeta::new_readonly(*account.key, true),
                ],
                data,
            };
            invoke_signed(
                &ix,
                &[source.clone(), destination.clone(), account.clone(), token_program.clone()],
                &[&[b"agent", &agent_hash, &[bump]]],
            )
        }
        ([SELECTOR_LOCK], ASSET_TOKEN) => {
            let [lock_program, config, leg, system, mint_a, source, vault, token_program] =
                core::array::from_fn(|_| next_account_info(it));
            let (lock_program, config, leg, system, mint_a, source, vault, token_program) =
                (lock_program?, config?, leg?, system?, mint_a?, source?, vault?, token_program?);
            if a.target != lock_program.key.as_ref() || *token_program.key != TOKEN_PROGRAM_ID {
                return Err(AccountError::TargetNotAllowed.into());
            }
            if mint_a.key.to_bytes() != mint {
                return Err(AccountError::WrongTokenAccount.into());
            }
            let before = source.try_borrow_data()?.to_vec();
            if source.owner != &TOKEN_PROGRAM_ID || before.len() < 72 || before[..32] != mint || before[32..64] != account.key.to_bytes() {
                return Err(AccountError::WrongTokenAccount.into());
            }
            let amount = u64::try_from(a.amount).map_err(|_| AccountError::UnsupportedAction)?;
            if a.data.len() != LOCK_IX_LEN || a.data[0] != 1 || a.data[34..42] != amount.to_le_bytes() {
                return Err(AccountError::UnsupportedAction.into());
            }
            use solana_program::instruction::AccountMeta;
            let ix = solana_program::instruction::Instruction {
                program_id: *lock_program.key,
                accounts: vec![
                    AccountMeta::new(*config.key, false),
                    AccountMeta::new(*leg.key, false),
                    AccountMeta::new(*account.key, true),
                    AccountMeta::new(*relayer.key, true),
                    AccountMeta::new_readonly(*system.key, false),
                    AccountMeta::new_readonly(*mint_a.key, false),
                    AccountMeta::new(*source.key, false),
                    AccountMeta::new(*vault.key, false),
                    AccountMeta::new_readonly(*token_program.key, false),
                ],
                data: a.data.to_vec(),
            };
            invoke_signed(
                &ix,
                &[
                    config.clone(),
                    leg.clone(),
                    account.clone(),
                    relayer.clone(),
                    system.clone(),
                    mint_a.clone(),
                    source.clone(),
                    vault.clone(),
                    token_program.clone(),
                    lock_program.clone(),
                ],
                &[&[b"agent", &agent_hash, &[bump]]],
            )?;
            // The lock took exactly the action's amount from the source and
            // left nothing else changed on it: no delegate, no new owner.
            let after = source.try_borrow_data()?;
            let had = u64::from_le_bytes(before[64..72].try_into().expect("8 bytes"));
            let has = u64::from_le_bytes(after[64..72].try_into().expect("8 bytes"));
            if had.checked_sub(amount) != Some(has) || after[..64] != before[..64] || after[72..] != before[72..] {
                return Err(AccountError::PulledOtherThanStated.into());
            }
            Ok(())
        }
        _ => Err(AccountError::UnsupportedAction.into()),
    }
}
