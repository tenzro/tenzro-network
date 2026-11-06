//! One balance store per token, shared by every VM's view of it.
//!
//! Native TNZO lives in the native balance map. Every other fungible token
//! lives in the token factory's storage, one slot per (token, account). The
//! EVM reaches both through its precompiles and the SVM through the SPL Token
//! program, and both read and write the same entries here, inside the
//! transaction's undo log. Moving a token "between VMs" is therefore an ordinary transfer
//! between two accounts of the one store: nothing is locked, minted or
//! wrapped.

use crate::error::{Result, VmError};
use crate::evm::precompile_host::{
    state_blob, state_word, state_write_blob, u128_to_word, word_to_u128,
};
use crate::evm::token_factory::{
    balance_slot, claim_slot, count_slot, frozen_slot, halted_slot, holders_slot, nonce_slot,
    token_id, token_slot,
};
use crate::precompiles::PRECOMPILE_TOKEN_FACTORY;
use crate::traits::VmState;
use crate::types::StateChange;
use tenzro_types::token_policy::{HolderKind, Rule};

pub use crate::evm::token_factory::{PendingChange, TokenRecord};

/// Longest token name or symbol.
pub const MAX_TOKEN_NAME_LEN: usize = 64;

/// Topic of the log every token creation emits from the factory's address,
/// `keccak256("TokenCreated(bytes32)")`, with the token id as the second
/// topic and its record (JSON) as data. Token indexes follow it.
pub fn token_created_topic() -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(b"TokenCreated(bytes32)").into()
}

/// The creation log of token `id`.
pub(crate) fn created_log(id: &[u8; 32], record: &TokenRecord) -> Result<crate::types::Log> {
    let data = serde_json::to_vec(record)
        .map_err(|e| VmError::Internal(format!("token record encode: {e}")))?;
    Ok(crate::types::Log::new(
        PRECOMPILE_TOKEN_FACTORY.to_vec(),
        vec![token_created_topic().to_vec(), id.to_vec()],
        data,
    ))
}
/// Most decimal places a token may declare.
pub const MAX_TOKEN_DECIMALS: u8 = 36;

/// Token id of native TNZO.
pub fn tnzo_id() -> [u8; 32] {
    tenzro_token::TokenId::tnzo().0
}

/// `owner`'s balance of `token`.
pub fn balance(state: &dyn VmState, token: &[u8; 32], owner: &[u8]) -> u128 {
    if *token == tnzo_id() {
        return state.get_balance(owner);
    }
    word_to_u128(&state_word(
        state,
        &PRECOMPILE_TOKEN_FACTORY,
        &balance_slot(token, owner),
    ))
}

fn set_balance(state: &mut dyn VmState, token: &[u8; 32], owner: &[u8], value: u128) {
    if *token == tnzo_id() {
        state.set_balance(owner, value);
    } else {
        let before = balance(state, token, owner);
        state.set_storage(
            &PRECOMPILE_TOKEN_FACTORY,
            &balance_slot(token, owner),
            u128_to_word(value).to_vec(),
        );
        let holders = word(state, &holders_slot(token));
        let next = holders_after(holders, before, value);
        if next != holders {
            state.set_storage(
                &PRECOMPILE_TOKEN_FACTORY,
                &holders_slot(token),
                u128_to_word(next).to_vec(),
            );
        }
    }
}

/// The holder count after one account's balance moves from `before` to
/// `after`.
pub(crate) fn holders_after(holders: u128, before: u128, after: u128) -> u128 {
    match (before == 0, after == 0) {
        (true, false) => holders + 1,
        (false, true) => holders.saturating_sub(1),
        _ => holders,
    }
}

fn word(state: &dyn VmState, slot: &[u8; 32]) -> u128 {
    word_to_u128(&state_word(state, &PRECOMPILE_TOKEN_FACTORY, slot))
}

fn write_word(
    state: &mut dyn VmState,
    slot: [u8; 32],
    value: u128,
    changes: &mut Vec<StateChange>,
) {
    write_raw_word(state, slot, u128_to_word(value), changes);
}

fn write_raw_word(
    state: &mut dyn VmState,
    slot: [u8; 32],
    value: [u8; 32],
    changes: &mut Vec<StateChange>,
) {
    let prior = state.get_storage(&PRECOMPILE_TOKEN_FACTORY, &slot);
    let new = value.to_vec();
    state.set_storage(&PRECOMPILE_TOKEN_FACTORY, &slot, new.clone());
    changes.push(StateChange::new(
        PRECOMPILE_TOKEN_FACTORY.to_vec(),
        slot.to_vec(),
        prior,
        Some(new),
    ));
}

/// The definition of token `id`, if it exists.
pub fn read_token(state: &dyn VmState, id: &[u8; 32]) -> Option<TokenRecord> {
    let bytes = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, token_slot(id))?;
    serde_json::from_slice(&bytes).ok()
}

fn write_token(
    state: &mut dyn VmState,
    id: &[u8; 32],
    record: &TokenRecord,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| VmError::Internal(format!("token record encode: {e}")))?;
    let slot = token_slot(id);
    let prior = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot);
    state_write_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot, &bytes);
    changes.push(StateChange::new(
        PRECOMPILE_TOKEN_FACTORY.to_vec(),
        slot.to_vec(),
        prior,
        Some(bytes),
    ));
    Ok(())
}

/// Write `owner`'s balance of factory token `id`, recording the change and
/// keeping the holder count.
fn write_balance(
    state: &mut dyn VmState,
    id: &[u8; 32],
    owner: &[u8],
    value: u128,
    changes: &mut Vec<StateChange>,
) {
    let before = word(state, &balance_slot(id, owner));
    write_word(state, balance_slot(id, owner), value, changes);
    let holders = word(state, &holders_slot(id));
    let next = holders_after(holders, before, value);
    if next != holders {
        write_word(state, holders_slot(id), next, changes);
    }
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

/// Create the token `spec` describes, issued by `creator`, and credit the
/// issuer its `total_supply`. Returns the token's id, derived from the
/// issuer and its creation count exactly as the factory precompile derives
/// it. `spec.creator` is ignored: the issuer is `creator`.
pub(crate) fn create(
    state: &mut dyn VmState,
    creator: &[u8],
    spec: &TokenRecord,
    changes: &mut Vec<StateChange>,
) -> Result<[u8; 32]> {
    if spec.name.is_empty()
        || spec.symbol.is_empty()
        || spec.name.len() > MAX_TOKEN_NAME_LEN
        || spec.symbol.len() > MAX_TOKEN_NAME_LEN
        || spec.decimals > MAX_TOKEN_DECIMALS
    {
        return Err(refuse(
            "a token needs a 1 to 64 byte name and symbol and at most 36 decimals",
        ));
    }
    if !initial_supply_within(spec.total_supply, spec.max_supply) {
        return Err(refuse("the initial supply exceeds the maximum supply"));
    }
    let nonce = word(state, &nonce_slot(creator));
    write_word(state, nonce_slot(creator), nonce + 1, changes);
    let id = token_id(creator, nonce);
    let record = TokenRecord {
        creator: crate::state_adapter::ledger_account(creator).to_vec(),
        ..spec.clone()
    };
    write_token(state, &id, &record, changes)?;
    write_facade(state, &id, changes);
    write_balance(state, &id, creator, record.total_supply, changes);
    let count = word(state, &count_slot());
    write_word(state, count_slot(), count + 1, changes);
    Ok(id)
}

/// Define token `id` with `record` unless it already exists: a token whose
/// issuance a consensus rule controls rather than an issuer's key.
pub(crate) fn define(
    state: &mut dyn VmState,
    id: &[u8; 32],
    record: &TokenRecord,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if read_token(state, id).is_some() {
        return Ok(());
    }
    write_token(state, id, record, changes)?;
    write_facade(state, id, changes);
    let count = word(state, &count_slot());
    write_word(state, count_slot(), count + 1, changes);
    Ok(())
}

/// Point token `id`'s facade address at it.
fn write_facade(state: &mut dyn VmState, id: &[u8; 32], changes: &mut Vec<StateChange>) {
    let slot =
        crate::evm::token_factory::facade_slot(&crate::evm::token_factory::facade_address(id));
    write_raw_word(state, slot, *id, changes);
}

/// Issue `amount` of token `id` to `to`, within its maximum supply. The
/// caller has checked the mint authority; this checks the recipient against
/// the token's policy at block time `now_ms`.
pub(crate) fn mint(
    state: &mut dyn VmState,
    id: &[u8; 32],
    to: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut record = read_token(state, id).ok_or_else(|| refuse("unknown token"))?;
    if let Err(r) = can_receive(&mut StateView(state), id, &record, to, amount, now_ms)? {
        return Err(refuse(r.to_string()));
    }
    let supply = supply_after_mint(record.total_supply, record.max_supply, amount)
        .ok_or_else(|| refuse("the mint exceeds the token's maximum supply"))?;
    record.total_supply = supply;
    write_token(state, id, &record, changes)?;
    let held = word(state, &balance_slot(id, to));
    let held = held
        .checked_add(amount)
        .ok_or_else(|| VmError::ExecutionFailed("token balance overflow".to_string()))?;
    write_balance(state, id, to, held, changes);
    Ok(())
}

/// Retire `amount` of token `id` from `from`'s balance. A burn spends only
/// the part of the balance that is not frozen, and nothing while the token
/// is halted: a freeze blocks a burn exactly as it blocks a transfer.
pub(crate) fn burn(
    state: &mut dyn VmState,
    id: &[u8; 32],
    from: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut record = read_token(state, id).ok_or_else(|| refuse("unknown token"))?;
    if halted(state, id) {
        return Err(refuse("the token is halted"));
    }
    let held = word(state, &balance_slot(id, from));
    let free = spendable(held, frozen(state, id, from));
    if free < amount {
        return Err(refuse(format!(
            "the holder has {free} free of {held}, the burn is {amount}"
        )));
    }
    write_balance(state, id, from, held - amount, changes);
    record.total_supply = record.total_supply.saturating_sub(amount);
    write_token(state, id, &record, changes)?;
    Ok(())
}

/// Whether a token may be created with an initial supply of `total` under
/// the maximum `max` (none: no maximum).
pub(crate) fn initial_supply_within(total: u128, max: Option<u128>) -> bool {
    max.is_none_or(|m| total <= m)
}

/// Whether a holder at `held` may take `amount` more under a holder ceiling
/// of `bps` basis points of `supply`. A balance that would wrap saturates and
/// is refused.
pub(crate) fn within_balance_ceiling(held: u128, amount: u128, supply: u128, bps: u16) -> bool {
    let ceiling = supply.saturating_mul(u128::from(bps)) / 10_000;
    held.saturating_add(amount) <= ceiling
}

/// Total supply after minting `amount`: `None` on overflow or past `max`.
pub(crate) fn supply_after_mint(total: u128, max: Option<u128>, amount: u128) -> Option<u128> {
    total
        .checked_add(amount)
        .filter(|s| max.is_none_or(|m| *s <= m))
}

/// The frozen amount once the holder keeps only `left`: a freeze never
/// exceeds the balance.
pub(crate) fn frozen_after(frozen: u128, left: u128) -> u128 {
    frozen.min(left)
}

/// The amount a freeze of `amount` sets against a balance of `held`, or
/// `None` when it exceeds the balance.
pub(crate) fn freeze_within(amount: u128, held: u128) -> Option<u128> {
    (amount <= held).then_some(amount)
}

/// The part of `held` its holder may move past a freeze of `frozen`.
pub(crate) fn spendable(held: u128, frozen: u128) -> u128 {
    held - frozen.min(held)
}

/// The part of `owner`'s balance of `id` its issuer froze.
pub fn frozen(state: &dyn VmState, id: &[u8; 32], owner: &[u8]) -> u128 {
    word(state, &frozen_slot(id, owner))
}

/// Whether the issuer of `id` has halted holder transfers.
pub fn halted(state: &dyn VmState, id: &[u8; 32]) -> bool {
    word(state, &halted_slot(id)) != 0
}

/// Freeze `amount` of `owner`'s balance of `id` (zero unfreezes it). A
/// freeze larger than the balance is refused.
pub(crate) fn set_frozen(
    state: &mut dyn VmState,
    id: &[u8; 32],
    owner: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let held = balance(state, id, owner);
    let amount = freeze_within(amount, held)
        .ok_or_else(|| refuse(format!("the holder has {held}, the freeze is {amount}")))?;
    write_word(state, frozen_slot(id, owner), amount, changes);
    Ok(())
}

/// Halt or resume holder transfers of `id`.
pub(crate) fn set_halted(
    state: &mut dyn VmState,
    id: &[u8; 32],
    halted: bool,
    changes: &mut Vec<StateChange>,
) {
    write_word(state, halted_slot(id), u128::from(halted), changes);
}

/// Move `amount` of token `id` from `from` to `to` by the force authority:
/// neither a halt, a lockup nor a frozen amount stops it, but the recipient
/// must still be eligible, and the frozen amount is lowered to what `from`
/// still holds.
pub(crate) fn forced_transfer(
    state: &mut dyn VmState,
    id: &[u8; 32],
    from: &[u8],
    to: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let record = read_token(state, id).ok_or_else(|| refuse("unknown token"))?;
    if let Err(r) = can_receive(&mut StateView(state), id, &record, to, amount, now_ms)? {
        return Err(refuse(r.to_string()));
    }
    let moved = move_balance(state, id, from, to, amount)?
        .ok_or_else(|| refuse("the holder has less than the forced transfer"))?;
    changes.extend(moved);
    let left = balance(state, id, from);
    let frozen = frozen(state, id, from);
    if frozen_after(frozen, left) != frozen {
        write_word(state, frozen_slot(id, from), left, changes);
    }
    Ok(())
}

/// Move `amount` of `token` from `from` to `to` at block time `now_ms`.
/// Returns `None`, and moves nothing, when `from` holds less than `amount`.
/// A holder transfer of a factory token goes through [`can_transfer`].
pub fn transfer(
    state: &mut dyn VmState,
    token: &[u8; 32],
    from: &[u8],
    to: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<Option<Vec<StateChange>>> {
    if let Err(r) = can_transfer(&mut StateView(state), token, from, to, amount, now_ms)? {
        return Err(refuse(r.to_string()));
    }
    move_balance(state, token, from, to, amount)
}

/// The reads the rule engine needs: token-factory storage words and
/// committed system storage. Implemented over chain state and over an EVM
/// precompile call, so every view of a token runs the same rules.
pub trait LedgerRead {
    /// A token-factory storage word.
    fn factory_word(&mut self, slot: &[u8; 32]) -> Result<[u8; 32]>;
    /// A system-storage entry.
    fn system(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;
}

/// [`LedgerRead`] over chain state.
pub struct StateView<'a>(pub &'a dyn VmState);

impl LedgerRead for StateView<'_> {
    fn factory_word(&mut self, slot: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(state_word(self.0, &PRECOMPILE_TOKEN_FACTORY, slot))
    }
    fn system(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get_storage(&crate::native::SYSTEM_ADDRESS, key))
    }
}

impl LedgerRead for crate::evm::precompile_host::PrecompileCall<'_> {
    fn factory_word(&mut self, slot: &[u8; 32]) -> Result<[u8; 32]> {
        self.state.sload(PRECOMPILE_TOKEN_FACTORY, *slot)
    }
    fn system(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.state.system_storage(key)
    }
}

fn read_u128(r: &mut impl LedgerRead, slot: &[u8; 32]) -> Result<u128> {
    Ok(word_to_u128(&r.factory_word(slot)?))
}

/// Token `id`'s record through any [`LedgerRead`].
pub fn read_record(r: &mut impl LedgerRead, id: &[u8; 32]) -> Result<Option<TokenRecord>> {
    let bytes = crate::evm::precompile_host::blob_via(|s| r.factory_word(s), token_slot(id))?;
    Ok(bytes.and_then(|b| serde_json::from_slice(&b).ok()))
}

/// Why the rule engine refused a transfer. `code()` is the stable number
/// every view reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No such token.
    UnknownToken,
    /// The issuer halted holder transfers.
    Halted,
    /// The amount reaches into the sender's frozen balance.
    Frozen,
    /// The token is locked until the given block time.
    Lockup(i64),
    /// The recipient does not meet an eligibility rule.
    Ineligible(String),
}

impl Refusal {
    /// Stable code: 1 unknown token, 2 halted, 3 frozen, 4 lockup,
    /// 5 ineligible recipient.
    pub fn code(&self) -> u8 {
        match self {
            Refusal::UnknownToken => 1,
            Refusal::Halted => 2,
            Refusal::Frozen => 3,
            Refusal::Lockup(_) => 4,
            Refusal::Ineligible(_) => 5,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::UnknownToken => write!(f, "unknown token"),
            Refusal::Halted => write!(f, "the issuer has halted transfers of this token"),
            Refusal::Frozen => write!(f, "the amount exceeds the sender's unfrozen balance"),
            Refusal::Lockup(until) => write!(f, "the token is locked until {until}"),
            Refusal::Ineligible(why) => write!(f, "the recipient is not eligible: {why}"),
        }
    }
}

/// The one rule engine: whether a holder transfer of `amount` of `token`
/// from `from` to `to` is allowed at block time `now_ms`. Native TNZO has no
/// rules. A sender holding less than `amount` is not a refusal here; the
/// move itself reports it.
pub fn can_transfer(
    r: &mut impl LedgerRead,
    token: &[u8; 32],
    from: &[u8],
    to: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<std::result::Result<(), Refusal>> {
    if *token == tnzo_id() {
        return Ok(Ok(()));
    }
    let Some(record) = read_record(r, token)? else {
        return Ok(Err(Refusal::UnknownToken));
    };
    if read_u128(r, &halted_slot(token))? != 0 {
        return Ok(Err(Refusal::Halted));
    }
    let held = read_u128(r, &balance_slot(token, from))?;
    let frozen = read_u128(r, &frozen_slot(token, from))?;
    if held >= amount && spendable(held, frozen) < amount {
        return Ok(Err(Refusal::Frozen));
    }
    for rule in &record.policy.eligibility {
        if let Rule::Lockup { until_ms } = rule
            && now_ms < *until_ms
        {
            return Ok(Err(Refusal::Lockup(*until_ms)));
        }
    }
    can_receive(r, token, &record, to, amount, now_ms)
}

/// Whether `to` may receive `amount` of `token` under its eligibility rules
/// (every rule but the lockup, which binds holders, not recipients).
pub fn can_receive(
    r: &mut impl LedgerRead,
    token: &[u8; 32],
    record: &TokenRecord,
    to: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<std::result::Result<(), Refusal>> {
    let ineligible = |why: String| Ok(Err(Refusal::Ineligible(why)));
    let held = read_u128(r, &balance_slot(token, to))?;
    for rule in &record.policy.eligibility {
        match rule {
            Rule::RequireClaim { kind, issuers } => {
                let mut ok = false;
                for issuer in issuers {
                    if live_claim(r, token, to, kind, issuer, now_ms)?.is_some() {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    return ineligible(format!(
                        "no live '{kind}' claim from an issuer the token accepts"
                    ));
                }
            }
            Rule::DenyJurisdiction { blocs } => {
                for issuer in named_issuers(record) {
                    if let Some(code) = live_claim(r, token, to, "jurisdiction", &issuer, now_ms)?
                        && blocs.iter().any(|b| b.eq_ignore_ascii_case(&code))
                    {
                        return ineligible(format!("jurisdiction {code} is refused"));
                    }
                }
            }
            Rule::AllowJurisdiction { blocs } => {
                let mut served = false;
                for issuer in named_issuers(record) {
                    if let Some(code) = live_claim(r, token, to, "jurisdiction", &issuer, now_ms)?
                        && blocs.iter().any(|b| b.eq_ignore_ascii_case(&code))
                    {
                        served = true;
                        break;
                    }
                }
                if !served {
                    return ineligible(
                        "no live jurisdiction claim in a jurisdiction the token serves".to_string(),
                    );
                }
            }
            Rule::HolderKind { kind } => {
                let class = holder_class(r, to, now_ms)?;
                let ok = match kind {
                    HolderKind::Any => true,
                    HolderKind::HumanRoot => class == HolderClass::Human,
                    HolderKind::AgentUnderTerms => matches!(class, HolderClass::Agent(_)),
                    HolderKind::Machine => {
                        matches!(class, HolderClass::Machine | HolderClass::Agent(_))
                    }
                };
                if !ok {
                    return ineligible(format!("the token is held only by {kind:?} accounts"));
                }
            }
            Rule::MaxHolders { max } => {
                let holders = read_u128(r, &holders_slot(token))?;
                if held == 0 && amount > 0 && holders >= u128::from(*max) {
                    return ineligible(format!("the token already has {holders} holders"));
                }
            }
            Rule::MaxBalanceBps { bps } => {
                if !within_balance_ceiling(held, amount, record.total_supply, *bps) {
                    return ineligible(format!("the balance would exceed {bps} bps of the supply"));
                }
            }
            Rule::Lockup { .. } => {}
            Rule::MinTermsVerification { level } => match holder_class(r, to, now_ms)? {
                HolderClass::Agent(have) | HolderClass::Unverified(have) if have < *level => {
                    return ineligible(format!(
                        "the agent's Terms verification level {have} is below {level}"
                    ));
                }
                HolderClass::Machine => {
                    return ineligible(format!(
                        "a machine without live Terms is below level {level}"
                    ));
                }
                HolderClass::Unknown => {
                    return ineligible(format!(
                        "an address with no registered identity has no Terms; level {level} is required"
                    ));
                }
                HolderClass::Human | HolderClass::Agent(_) | HolderClass::Unverified(_) => {}
            },
            Rule::MinKycTier { tier } => {
                let have = kyc_tier(r, token, record, to, now_ms)?;
                if have < *tier {
                    return ineligible(format!("the recipient's KYC tier {have} is below {tier}"));
                }
            }
        }
    }
    Ok(Ok(()))
}

/// The KYC tier `subject` holds under `token`: the highest grade among the
/// live `kyc` claims made under it by the issuers its policy names, 0 when
/// none is live.
pub fn kyc_tier(
    r: &mut impl LedgerRead,
    token: &[u8; 32],
    record: &TokenRecord,
    subject: &[u8],
    now_ms: i64,
) -> Result<u8> {
    let mut best = 0;
    for issuer in named_issuers(record) {
        if let Some(grade) = live_claim(r, token, subject, "kyc", &issuer, now_ms)?
            && let Some(tier) = tenzro_types::identity::KycTier::from_grade(&grade)
        {
            best = best.max(tier.level());
        }
    }
    Ok(best)
}

/// The KYC tier `subject` holds under the assets `assets`: the best of
/// [`kyc_tier`] under each. An asset not on chain grants nothing.
pub fn kyc_tier_under(
    state: &dyn VmState,
    assets: &[[u8; 32]],
    subject: &[u8],
    now_ms: i64,
) -> Result<u8> {
    let mut best = 0;
    for id in assets {
        let Some(record) = read_token(state, id) else {
            continue;
        };
        best = best.max(kyc_tier(
            &mut StateView(state),
            id,
            &record,
            subject,
            now_ms,
        )?);
    }
    Ok(best)
}

/// Claim issuers a token's policy names.
pub fn named_issuers(record: &TokenRecord) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for rule in &record.policy.eligibility {
        if let Rule::RequireClaim { issuers, .. } = rule {
            for i in issuers {
                if !out.contains(i) {
                    out.push(i.clone());
                }
            }
        }
    }
    out
}

/// A stored claim: its value and when it lapses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Claim {
    /// Claim value.
    pub value: String,
    /// Block time it lapses at.
    pub expires_ms: i64,
}

fn live_claim(
    r: &mut impl LedgerRead,
    token: &[u8; 32],
    subject: &[u8],
    kind: &str,
    issuer: &str,
    now_ms: i64,
) -> Result<Option<String>> {
    let bytes = crate::evm::precompile_host::blob_via(
        |s| r.factory_word(s),
        claim_slot(token, subject, kind, issuer),
    )?;
    Ok(bytes
        .and_then(|b| serde_json::from_slice::<Claim>(&b).ok())
        .filter(|c| now_ms < c.expires_ms)
        .map(|c| c.value))
}

/// What kind of account holds a balance, for the holder rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HolderClass {
    /// A registered human identity.
    Human,
    /// An agent with live Terms, at this verification level.
    Agent(u8),
    /// An agent whose Terms have lapsed (level 0).
    Unverified(u8),
    /// A machine identity with no Terms.
    Machine,
    /// No registered identity.
    Unknown,
}

fn holder_class(r: &mut impl LedgerRead, account: &[u8], now_ms: i64) -> Result<HolderClass> {
    let key = format!("identity_wallet:{}", hex::encode(account));
    let Some(did) = r
        .system(key.as_bytes())?
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|d| !d.is_empty())
    else {
        return Ok(HolderClass::Unknown);
    };
    if did.starts_with(crate::governance::HUMAN_DID_PREFIX) {
        return Ok(HolderClass::Human);
    }
    let terms = r
        .system(crate::native::agent_terms::terms_key(&did).as_bytes())?
        .and_then(|b| {
            serde_json::from_slice::<crate::native::agent_terms::StoredAgentTerms>(&b).ok()
        });
    Ok(match terms {
        Some(t) => {
            let live = t.terms.expires_at_ms.is_none_or(|e| (e as i64) > now_ms);
            if live {
                HolderClass::Agent(terms_level(&t.terms))
            } else {
                HolderClass::Unverified(0)
            }
        }
        None => HolderClass::Machine,
    })
}

/// An agent's Terms verification level: 1 for live Terms; 2 when every
/// serving node's key carries a hardware certification; 3 when, as well,
/// at least two distinct operators serve it.
pub fn terms_level(terms: &tenzro_types::agent_terms::AgentTerms) -> u8 {
    let nodes = &terms.serving_nodes;
    if nodes.is_empty() || nodes.iter().any(|n| n.key_certification.is_empty()) {
        return 1;
    }
    let operators: std::collections::BTreeSet<&str> =
        nodes.iter().map(|n| n.operator_did.as_str()).collect();
    if operators.len() >= 2 { 3 } else { 2 }
}

fn move_balance(
    state: &mut dyn VmState,
    token: &[u8; 32],
    from: &[u8],
    to: &[u8],
    amount: u128,
) -> Result<Option<Vec<StateChange>>> {
    let from_before = balance(state, token, from);
    let Some(from_after) = from_before.checked_sub(amount) else {
        return Ok(None);
    };
    set_balance(state, token, from, from_after);
    // Read the recipient after the debit, so a transfer to oneself nets to
    // zero.
    let to_before = balance(state, token, to);
    let to_after = to_before.checked_add(amount).ok_or_else(|| {
        crate::error::VmError::ExecutionFailed("token balance overflow".to_string())
    })?;
    set_balance(state, token, to, to_after);
    // The changed key: the token id followed by "balance".
    let key = || [token.as_slice(), b"balance"].concat();
    Ok(Some(vec![
        StateChange::new(
            from.to_vec(),
            key(),
            Some(from_before.to_le_bytes().to_vec()),
            Some(from_after.to_le_bytes().to_vec()),
        ),
        StateChange::new(
            to.to_vec(),
            key(),
            Some(to_before.to_le_bytes().to_vec()),
            Some(to_after.to_le_bytes().to_vec()),
        ),
    ]))
}

/// A token with no issuer powers and the given eligibility rules, issued to
/// a fixed test account.
#[cfg(test)]
pub(crate) fn test_token(state: &mut dyn VmState, eligibility: Vec<Rule>) -> [u8; 32] {
    use tenzro_types::token_policy::{PowerManifest, TokenPolicy};
    let spec = TokenRecord {
        name: "T".into(),
        symbol: "T".into(),
        decimals: 0,
        total_supply: 1_000,
        creator: Vec::new(),
        max_supply: None,
        powers: PowerManifest::NONE,
        policy: TokenPolicy {
            eligibility,
            policy_timelock_ms: 0,
        },
        council: None,
        reserve_backing: None,
        pending: None,
    };
    create(state, &[0x11; 32], &spec, &mut Vec::new()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn policy_token(state: &mut StateAdapter, rule: tenzro_types::token_policy::Rule) -> [u8; 32] {
        test_token(state, vec![rule])
    }

    fn bind(state: &mut StateAdapter, account: &[u8], did: &str) {
        let key = format!("identity_wallet:{}", hex::encode(account));
        state.set_storage(
            &crate::native::SYSTEM_ADDRESS,
            key.as_bytes(),
            did.as_bytes().to_vec(),
        );
    }

    fn agent_with_terms(state: &mut StateAdapter, account: &[u8], did: &str) {
        bind(state, account, did);
        let terms: tenzro_types::agent_terms::AgentTerms =
            serde_json::from_value(serde_json::json!({
                "controller_did": "did:tenzro:human:controller",
                "agent_name": "holder",
            }))
            .unwrap();
        let stored = crate::native::agent_terms::StoredAgentTerms {
            terms,
            root: tenzro_types::agent_terms::RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: 0,
            renewed_at_ms: None,
        };
        state.set_storage(
            &crate::native::SYSTEM_ADDRESS,
            crate::native::agent_terms::terms_key(did).as_bytes(),
            serde_json::to_vec(&stored).unwrap(),
        );
    }

    #[test]
    fn a_human_root_token_refuses_an_agent() {
        use tenzro_types::token_policy::{HolderKind, Rule};
        let mut state = StateAdapter::new();
        let token = policy_token(
            &mut state,
            Rule::HolderKind {
                kind: HolderKind::HumanRoot,
            },
        );
        let (human, agent) = ([0x21u8; 32], [0x22u8; 32]);
        bind(&mut state, &human, "did:tenzro:human:alice");
        agent_with_terms(&mut state, &agent, "did:tenzro:agent:bot");
        let from = [0x11u8; 32];
        assert!(
            can_transfer(&mut StateView(&state), &token, &from, &human, 1, 0)
                .unwrap()
                .is_ok()
        );
        assert!(
            can_transfer(&mut StateView(&state), &token, &from, &agent, 1, 0)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn min_terms_verification_refuses_an_agent_below_the_level() {
        use tenzro_types::token_policy::Rule;
        let mut state = StateAdapter::new();
        let token = policy_token(&mut state, Rule::MinTermsVerification { level: 2 });
        let agent = [0x31u8; 32];
        agent_with_terms(&mut state, &agent, "did:tenzro:agent:bot");
        let from = [0x11u8; 32];
        let refused = can_transfer(&mut StateView(&state), &token, &from, &agent, 1, 0).unwrap();
        assert!(
            matches!(refused, Err(Refusal::Ineligible(_))),
            "{refused:?}"
        );
    }

    /// An address with no registered identity has no Terms either, so a
    /// minimum Terms verification refuses it as it refuses a machine.
    #[test]
    fn min_terms_verification_refuses_an_address_with_no_identity() {
        use tenzro_types::token_policy::Rule;
        let mut state = StateAdapter::new();
        let token = policy_token(&mut state, Rule::MinTermsVerification { level: 1 });
        let from = [0x11u8; 32];
        let nobody = [0x5Eu8; 32];
        let refused = can_transfer(&mut StateView(&state), &token, &from, &nobody, 1, 0).unwrap();
        assert!(
            matches!(refused, Err(Refusal::Ineligible(_))),
            "{refused:?}"
        );
    }

    /// A relying party's tier for an account comes from a credential an issuer
    /// its asset's policy names; a claim by any other issuer, or under an
    /// asset it does not name, counts for nothing.
    #[test]
    fn a_tier_is_derived_from_a_credential_by_an_issuer_the_asset_policy_names() {
        use tenzro_types::token_policy::Rule;
        let mut state = StateAdapter::new();
        let named = "did:tenzro:human:kyc-attestor";
        let stranger = "did:tenzro:human:someone-else";
        let token = test_token(
            &mut state,
            vec![Rule::RequireClaim {
                kind: "kyc".into(),
                issuers: vec![named.into()],
            }],
        );
        let claim = |state: &mut StateAdapter, who: &[u8], issuer: &str, value: &str| {
            let bytes = serde_json::to_vec(&Claim {
                value: value.into(),
                expires_ms: 10_000,
            })
            .unwrap();
            crate::evm::precompile_host::state_write_blob(
                state,
                &crate::precompiles::PRECOMPILE_TOKEN_FACTORY,
                crate::evm::token_factory::claim_slot(&token, who, "kyc", issuer),
                &bytes,
            );
        };
        let (graded, self_graded) = ([0x61u8; 32], [0x62u8; 32]);
        claim(&mut state, &graded, named, "enhanced");
        claim(&mut state, &self_graded, stranger, "full");
        let missing = [0xEEu8; 32];
        assert_eq!(
            kyc_tier_under(&state, &[missing, token], &graded, 100).unwrap(),
            2
        );
        assert_eq!(
            kyc_tier_under(&state, &[token], &self_graded, 100).unwrap(),
            0
        );
        assert_eq!(kyc_tier_under(&state, &[], &graded, 100).unwrap(), 0);
        assert_eq!(
            kyc_tier_under(&state, &[token], &graded, 20_000).unwrap(),
            0,
            "a lapsed claim grants nothing"
        );
    }

    /// A token that needs enhanced KYC: a recipient's tier is the best live
    /// `kyc` grade from an issuer the token names; a lower, lapsed or
    /// ungraded claim is refused.
    #[test]
    fn a_kyc_tier_rule_admits_only_recipients_graded_at_or_above_it() {
        use tenzro_types::token_policy::Rule;
        let mut state = StateAdapter::new();
        let issuer = "did:tenzro:human:kyc-attestor";
        let token = test_token(
            &mut state,
            vec![
                Rule::RequireClaim {
                    kind: "kyc".into(),
                    issuers: vec![issuer.into()],
                },
                Rule::MinKycTier { tier: 2 },
            ],
        );
        let claim = |state: &mut StateAdapter, who: &[u8], value: &str, expires_ms: i64| {
            let bytes = serde_json::to_vec(&Claim {
                value: value.into(),
                expires_ms,
            })
            .unwrap();
            crate::evm::precompile_host::state_write_blob(
                state,
                &crate::precompiles::PRECOMPILE_TOKEN_FACTORY,
                crate::evm::token_factory::claim_slot(&token, who, "kyc", issuer),
                &bytes,
            );
        };
        let (full, enhanced, basic, lapsed, ungraded) = (
            [0x51u8; 32],
            [0x52u8; 32],
            [0x53u8; 32],
            [0x54u8; 32],
            [0x55u8; 32],
        );
        claim(&mut state, &full, "full", 10_000);
        claim(&mut state, &enhanced, "enhanced", 10_000);
        claim(&mut state, &basic, "basic", 10_000);
        claim(&mut state, &lapsed, "full", 5);
        claim(&mut state, &ungraded, "1", 10_000);
        let record = read_token(&state, &token).unwrap();
        assert_eq!(
            kyc_tier(&mut StateView(&state), &token, &record, &full, 100).unwrap(),
            3
        );
        assert_eq!(
            kyc_tier(&mut StateView(&state), &token, &record, &lapsed, 100).unwrap(),
            0
        );
        let from = [0x11u8; 32];
        let check = |to: &[u8; 32]| {
            can_transfer(&mut StateView(&state), &token, &from, to, 1, 100).unwrap()
        };
        assert!(check(&full).is_ok());
        assert!(check(&enhanced).is_ok());
        for refused in [&basic, &lapsed, &ungraded] {
            assert!(matches!(check(refused), Err(Refusal::Ineligible(_))));
        }
        let orphan = tenzro_types::token_policy::TokenPolicy {
            eligibility: vec![Rule::MinKycTier { tier: 1 }],
            policy_timelock_ms: 0,
        };
        assert!(
            orphan.validate().is_err(),
            "a tier rule needs a claim rule naming who grades it"
        );
        let out_of_range = tenzro_types::token_policy::TokenPolicy {
            eligibility: vec![
                Rule::RequireClaim {
                    kind: "kyc".into(),
                    issuers: vec![issuer.into()],
                },
                Rule::MinKycTier { tier: 4 },
            ],
            policy_timelock_ms: 0,
        };
        assert!(out_of_range.validate().is_err());
    }

    #[test]
    fn a_twenty_byte_address_and_its_slot_form_share_a_token_balance() {
        let mut state = StateAdapter::new();
        let token = test_token(&mut state, Vec::new());
        let evm = [0xAB; 20];
        let mut slot = [0u8; 32];
        slot[..20].copy_from_slice(&evm);
        let svm = [0xCD; 32];
        set_balance(&mut state, &token, &evm, 100);
        assert_eq!(balance(&state, &token, &slot), 100);
        assert!(
            transfer(&mut state, &token, &slot, &svm, 40, 0)
                .unwrap()
                .is_some()
        );
        assert_eq!(balance(&state, &token, &evm), 60);
        assert_eq!(balance(&state, &token, &svm), 40);
        assert!(
            transfer(&mut state, &token, &svm, &evm, 41, 0)
                .unwrap()
                .is_none()
        );
    }

    /// A stablecoin that serves some jurisdictions only: a recipient needs a
    /// live jurisdiction claim, from an issuer the token names, in one of
    /// them; a lapsed claim or another jurisdiction is refused.
    #[test]
    fn an_allowed_jurisdictions_rule_admits_only_recipients_attested_in_them() {
        use tenzro_types::token_policy::Rule;
        let mut state = StateAdapter::new();
        let issuer = "did:tenzro:human:kyb-attestor";
        let token = test_token(
            &mut state,
            vec![
                Rule::RequireClaim {
                    kind: "kyc".into(),
                    issuers: vec![issuer.into()],
                },
                Rule::AllowJurisdiction {
                    blocs: vec!["SG".into(), "US".into()],
                },
            ],
        );
        let claim =
            |state: &mut StateAdapter, who: &[u8], kind: &str, value: &str, expires_ms: i64| {
                let bytes = serde_json::to_vec(&Claim {
                    value: value.into(),
                    expires_ms,
                })
                .unwrap();
                crate::evm::precompile_host::state_write_blob(
                    state,
                    &crate::precompiles::PRECOMPILE_TOKEN_FACTORY,
                    crate::evm::token_factory::claim_slot(&token, who, kind, issuer),
                    &bytes,
                );
            };
        let (served, elsewhere, lapsed, unattested) =
            ([0x41u8; 32], [0x42u8; 32], [0x43u8; 32], [0x44u8; 32]);
        for who in [&served, &elsewhere, &lapsed, &unattested] {
            claim(&mut state, who, "kyc", "1", 10_000);
        }
        claim(&mut state, &served, "jurisdiction", "sg", 10_000);
        claim(&mut state, &elsewhere, "jurisdiction", "DE", 10_000);
        claim(&mut state, &lapsed, "jurisdiction", "US", 5);
        let from = [0x11u8; 32];
        let check = |to: &[u8; 32]| {
            can_transfer(&mut StateView(&state), &token, &from, to, 1, 100).unwrap()
        };
        assert!(check(&served).is_ok());
        for refused in [&elsewhere, &lapsed, &unattested] {
            assert!(matches!(check(refused), Err(Refusal::Ineligible(_))));
        }
        // An allow-list with no claim rule names no one who may attest.
        let orphan = tenzro_types::token_policy::TokenPolicy {
            eligibility: vec![Rule::AllowJurisdiction {
                blocs: vec!["US".into()],
            }],
            policy_timelock_ms: 0,
        };
        assert!(orphan.validate().is_err());
    }

    #[test]
    fn tnzo_is_the_native_balance() {
        let mut state = StateAdapter::new();
        let a = [1u8; 32];
        state.set_balance(&a, 5);
        assert_eq!(balance(&state, &tnzo_id(), &a), 5);
    }

    #[test]
    fn a_freeze_blocks_a_burn_as_it_blocks_a_transfer() {
        let mut state = StateAdapter::new();
        let token = test_token(&mut state, Vec::new());
        let (holder, other) = ([0x11u8; 32], [0x12u8; 32]);
        let mut changes = Vec::new();
        set_frozen(&mut state, &token, &holder, 600, &mut changes).unwrap();
        assert!(
            burn(&mut state, &token, &holder, 401, &mut changes).is_err(),
            "the burn reaches the frozen part"
        );
        assert!(transfer(&mut state, &token, &holder, &other, 401, 0).is_err());
        assert_eq!(balance(&state, &token, &holder), 1_000);
        burn(&mut state, &token, &holder, 400, &mut changes).unwrap();
        assert_eq!(balance(&state, &token, &holder), 600);
        assert_eq!(
            frozen(&state, &token, &holder),
            600,
            "the freeze is untouched"
        );
        assert_eq!(read_token(&state, &token).unwrap().total_supply, 600);
        assert!(burn(&mut state, &token, &holder, 1, &mut changes).is_err());
        set_frozen(&mut state, &token, &holder, 0, &mut changes).unwrap();
        set_halted(&mut state, &token, true, &mut changes);
        assert!(
            burn(&mut state, &token, &holder, 1, &mut changes).is_err(),
            "a halted token refuses a burn"
        );
        set_halted(&mut state, &token, false, &mut changes);
        burn(&mut state, &token, &holder, 600, &mut changes).unwrap();
        assert_eq!(read_token(&state, &token).unwrap().total_supply, 0);
    }
}
