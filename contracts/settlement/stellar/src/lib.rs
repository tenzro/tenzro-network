// SPDX-License-Identifier: Apache-2.0
//! Tenzro settlement-plan legs on Stellar.
//!
//! A payer locks an amount of one token as leg `index` of plan `plan_id`,
//! payable to a recipient. The leg settles once, on the plan's decision
//! proven under the state root of a final checkpoint held by Tenzro's
//! finality client on Stellar: a commit pays the recipient, an abort refunds
//! the payer. Without a proven decision the payer reclaims the leg only
//! after the escape horizon. No key holds any authority here.

#![no_std]

use soroban_sdk::{
    Address, Bytes, BytesN, Env, contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, token,
};
use tenzro_finality_verifier::settlement::{self, LegError, LegState, DECISION_LEN};

/// Ledgers a leg's entry lives before it must be extended (about 30 days).
const ENTRY_TTL: u32 = 518_400;
const MAX_PROOF: usize = 2 + 32 * 248 + 1 + 256;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyLocked = 1,
    NotLocked = 2,
    BadAmount = 3,
    BadIndex = 4,
    Unproven = 5,
    TooEarly = 6,
    Malformed = 7,
}

impl From<LegError> for Error {
    fn from(e: LegError) -> Self {
        match e {
            LegError::NotLocked => Error::NotLocked,
            LegError::Unproven => Error::Unproven,
            LegError::TooEarly => Error::TooEarly,
        }
    }
}

/// What Tenzro's finality client on Stellar serves.
#[contractclient(name = "FinalityClient")]
pub trait Finality {
    fn state_root(env: Env, index: u64) -> BytesN<32>;
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Locked,
    Released,
    Refunded,
}

/// A locked leg.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Leg {
    pub payer: Address,
    pub recipient: Address,
    pub token: Address,
    pub amount: i128,
    pub escape_at: u64,
    pub stage: Stage,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Client,
    Horizon,
    Leg(BytesN<32>),
    Recon,
}

/// Tenzro proves this event: topics `[locked, plan_id, leg_id]`, data the
/// remaining fields as a vector in declaration order.
#[contractevent(topics = ["locked"], data_format = "vec")]
pub struct Locked {
    #[topic]
    pub plan_id: BytesN<32>,
    #[topic]
    pub leg_id: BytesN<32>,
    pub index: u32,
    pub payer: Address,
    pub recipient: Address,
    pub token: Address,
    pub amount: i128,
    pub escape_at: u64,
}

/// The lock's reconciliation checkpoint: the entries it has recorded and the
/// running hash over them.
#[contractevent(topics = ["accumulator"], data_format = "vec")]
pub struct Accumulator {
    pub count: u64,
    pub acc: BytesN<32>,
}

#[contractevent]
pub struct Released {
    #[topic]
    pub plan_id: BytesN<32>,
    #[topic]
    pub leg_id: BytesN<32>,
    pub to: Address,
    pub amount: i128,
}

#[contractevent]
pub struct Refunded {
    #[topic]
    pub plan_id: BytesN<32>,
    #[topic]
    pub leg_id: BytesN<32>,
    pub to: Address,
    pub amount: i128,
    pub escaped: bool,
}

fn to_state(s: Stage) -> LegState {
    match s {
        Stage::Locked => LegState::Locked,
        Stage::Released => LegState::Released,
        Stage::Refunded => LegState::Refunded,
    }
}

fn id_of(env: &Env, plan_id: &BytesN<32>, index: u32) -> Result<BytesN<32>, Error> {
    let index = u8::try_from(index).map_err(|_| Error::BadIndex)?;
    Ok(BytesN::from_array(env, &settlement::leg_id(&plan_id.to_array(), index)))
}

fn load(env: &Env, id: &BytesN<32>) -> Result<Leg, Error> {
    env.storage().persistent().get(&Key::Leg(id.clone())).ok_or(Error::NotLocked)
}

fn store(env: &Env, id: &BytesN<32>, leg: &Leg) {
    let k = Key::Leg(id.clone());
    env.storage().persistent().set(&k, leg);
    env.storage().persistent().extend_ttl(&k, ENTRY_TTL, ENTRY_TTL);
}

fn copy<'a>(env: &Env, b: &Bytes, buf: &'a mut [u8]) -> &'a [u8] {
    let n = b.len() as usize;
    if n > buf.len() {
        panic_with_error!(env, Error::Malformed);
    }
    b.copy_into_slice(&mut buf[..n]);
    &buf[..n]
}

#[contract]
pub struct SettlementLock;

#[contractimpl]
impl SettlementLock {
    /// A lock reading final state roots from `client`, letting an undecided
    /// leg escape `escape_horizon` seconds after it was locked.
    pub fn __constructor(env: Env, client: Address, escape_horizon: u64) {
        env.storage().instance().set(&Key::Client, &client);
        env.storage().instance().set(&Key::Horizon, &escape_horizon);
        env.storage().instance().extend_ttl(ENTRY_TTL, ENTRY_TTL);
    }

    /// The id Tenzro gives leg `index` of `plan_id`.
    pub fn leg_id(env: Env, plan_id: BytesN<32>, index: u32) -> Result<BytesN<32>, Error> {
        id_of(&env, &plan_id, index)
    }

    /// The lock of leg `index` of `plan_id`.
    pub fn leg(env: Env, plan_id: BytesN<32>, index: u32) -> Result<Leg, Error> {
        load(&env, &id_of(&env, &plan_id, index)?)
    }

    /// Lock `amount` of `token` from `payer` as leg `index` of `plan_id`,
    /// payable to `recipient`.
    pub fn lock(
        env: Env,
        payer: Address,
        plan_id: BytesN<32>,
        index: u32,
        token: Address,
        amount: i128,
        recipient: Address,
    ) -> Result<(), Error> {
        payer.require_auth();
        let id = id_of(&env, &plan_id, index)?;
        if env.storage().persistent().has(&Key::Leg(id.clone())) {
            return Err(Error::AlreadyLocked);
        }
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        let horizon: u64 = env.storage().instance().get(&Key::Horizon).ok_or(Error::Malformed)?;
        let escape_at = env.ledger().timestamp().saturating_add(horizon);
        token::TokenClient::new(&env, &token).transfer(&payer, &env.current_contract_address(), &amount);
        let leg = Leg { payer, recipient, token, amount, escape_at, stage: Stage::Locked };
        store(&env, &id, &leg);
        record(&env, &plan_id, &id, LOCKED, amount);
        Locked {
            plan_id,
            leg_id: id,
            index,
            payer: leg.payer,
            recipient: leg.recipient,
            token: leg.token,
            amount,
            escape_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Settle leg `index` of `plan_id` on the decision at `decision:<plan_id>`,
    /// proven by `proof` under final checkpoint `checkpoint`. Anyone may call.
    pub fn settle(
        env: Env,
        plan_id: BytesN<32>,
        index: u32,
        checkpoint: u64,
        decision: Bytes,
        proof: Bytes,
    ) -> Result<(), Error> {
        let id = id_of(&env, &plan_id, index)?;
        let mut leg = load(&env, &id)?;
        let client: Address = env.storage().instance().get(&Key::Client).ok_or(Error::Malformed)?;
        let root = FinalityClient::new(&env, &client).state_root(&checkpoint).to_array();
        if decision.len() as usize != DECISION_LEN {
            return Err(Error::Unproven);
        }
        let mut db = [0u8; DECISION_LEN];
        decision.copy_into_slice(&mut db);
        let mut pb = [0u8; MAX_PROOF];
        let proof_s = copy(&env, &proof, &mut pb);
        let next = settlement::settle_leg(to_state(leg.stage), &root, &plan_id.to_array(), &db, proof_s)?;
        pay(&env, plan_id, id, &mut leg, next, false);
        Ok(())
    }

    /// Reclaim an undecided leg once its escape horizon has passed.
    /// The entries recorded and the running reconciliation hash over them.
    pub fn reconciliation(env: Env) -> (u64, BytesN<32>) {
        recon(&env)
    }

    /// Emit the running reconciliation hash and its entry count, for Tenzro
    /// to prove and compare with its own books.
    pub fn checkpoint(env: Env) {
        let (count, acc) = recon(&env);
        Accumulator { count, acc }.publish(&env);
    }

    pub fn escape(env: Env, plan_id: BytesN<32>, index: u32) -> Result<(), Error> {
        let id = id_of(&env, &plan_id, index)?;
        let mut leg = load(&env, &id)?;
        let next = settlement::escape_leg(to_state(leg.stage), env.ledger().timestamp(), leg.escape_at)?;
        pay(&env, plan_id, id, &mut leg, next, true);
        Ok(())
    }
}

fn pay(env: &Env, plan_id: BytesN<32>, id: BytesN<32>, leg: &mut Leg, next: LegState, escaped: bool) {
    let (to, stage) = match next {
        LegState::Released => (leg.recipient.clone(), Stage::Released),
        LegState::Refunded => (leg.payer.clone(), Stage::Refunded),
        LegState::Locked => panic_with_error!(env, Error::Malformed),
    };
    leg.stage = stage;
    store(env, &id, leg);
    token::TokenClient::new(env, &leg.token).transfer(&env.current_contract_address(), &to, &leg.amount);
    let kind = if stage == Stage::Released { RELEASED } else { REFUNDED };
    record(env, &plan_id, &id, kind, leg.amount);
    match stage {
        Stage::Released => Released { plan_id, leg_id: id, to, amount: leg.amount }.publish(env),
        _ => Refunded { plan_id, leg_id: id, to, amount: leg.amount, escaped }.publish(env),
    }
}

const RECON_DOMAIN: &[u8] = b"tenzro/settlement/recon/v1";
const LOCKED: u8 = 1;
const RELEASED: u8 = 2;
const REFUNDED: u8 = 3;

fn recon(env: &Env) -> (u64, BytesN<32>) {
    env.storage().instance().get(&Key::Recon).unwrap_or((0, BytesN::from_array(env, &[0u8; 32])))
}

/// Fold one entry into the running reconciliation hash:
/// `sha256(domain || acc || plan_id || leg_id || kind || amount)`, the
/// amount as a 32-byte big-endian word.
fn record(env: &Env, plan_id: &BytesN<32>, id: &BytesN<32>, kind: u8, amount: i128) {
    let (count, acc) = recon(env);
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&(amount as u128).to_be_bytes());
    let mut b = Bytes::from_slice(env, RECON_DOMAIN);
    b.append(&acc.into());
    b.append(&plan_id.clone().into());
    b.append(&id.clone().into());
    b.push_back(kind);
    b.extend_from_array(&word);
    let next: BytesN<32> = env.crypto().sha256(&b).into();
    env.storage().instance().set(&Key::Recon, &(count + 1, next));
}

#[cfg(test)]
mod test;
