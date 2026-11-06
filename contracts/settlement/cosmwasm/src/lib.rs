// SPDX-License-Identifier: Apache-2.0
//! Tenzro settlement-plan legs on CosmWasm chains.
//!
//! A payer locks one bank coin as leg `index` of plan `plan_id`, payable to
//! a recipient. The leg settles once, on the plan's decision proven under
//! the state root of a final checkpoint held by Tenzro's finality registry
//! on this chain: a commit pays the recipient, an abort refunds the payer.
//! Without a proven decision the payer reclaims the leg only after the
//! escape horizon.
//!
//! Every lock, release and refund folds into a running reconciliation hash,
//! stored with its entry count at `recon`: that stored entry is the lock's
//! checkpoint, which Tenzro proves under the chain's state root.

use cosmwasm_std::{
    Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, Event, MessageInfo, Response, StdError, StdResult,
    entry_point, from_json, to_json_binary,
};
use serde::{Deserialize, Serialize};
use tenzro_finality_verifier::settlement::{self, LegError, LegState};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InstantiateMsg {
    /// Tenzro's finality registry on this chain.
    pub registry: String,
    /// Seconds after locking before a payer may reclaim an undecided leg.
    pub escape_horizon: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Lock the single coin sent as leg `index` of `plan_id`.
    Lock { plan_id: Binary, index: u8, recipient: String },
    /// Settle a leg on the decision at `decision:<plan_id>`, proven by
    /// `proof` under final checkpoint `checkpoint`. Anyone may send it.
    Settle { plan_id: Binary, index: u8, checkpoint: u64, decision: Binary, proof: Binary },
    /// Reclaim an undecided leg once its escape horizon has passed.
    Escape { plan_id: Binary, index: u8 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// The id Tenzro gives leg `index` of `plan_id`.
    LegId { plan_id: Binary, index: u8 },
    /// The lock of leg `index` of `plan_id`.
    Leg { plan_id: Binary, index: u8 },
    /// The entries recorded and the running reconciliation hash over them.
    Reconciliation {},
}

/// The lock's reconciliation checkpoint as stored at `recon`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Recon {
    pub count: u64,
    /// The running hash, as hex.
    pub acc: String,
}

/// The registry query this lock sends for a checkpoint's state root.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryQuery {
    StateRoot { index: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Locked,
    Released,
    Refunded,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Leg {
    pub payer: Addr,
    pub recipient: Addr,
    pub coin: Coin,
    pub escape_at: u64,
    pub stage: Stage,
}

#[derive(Serialize, Deserialize)]
struct Config {
    registry: Addr,
    escape_horizon: u64,
}

const CONFIG: &[u8] = b"config";
/// Where the reconciliation checkpoint is stored.
pub const RECON: &[u8] = b"recon";

fn recon(deps: Deps) -> StdResult<(u64, [u8; 32])> {
    let Some(b) = deps.storage.get(RECON) else { return Ok((0, [0; 32])) };
    let r: Recon = from_json(b)?;
    let mut acc = [0u8; 32];
    hex::decode_to_slice(&r.acc, &mut acc).map_err(|_| err("the stored reconciliation hash is malformed"))?;
    Ok((r.count, acc))
}

/// A coin's amount as the reconciliation hash records it.
fn amount_of(coin: &Coin) -> StdResult<u128> {
    cosmwasm_std::Uint128::try_from(coin.amount).map(|a| a.u128()).map_err(|_| err("the amount exceeds 128 bits"))
}

/// Fold one entry into the running reconciliation hash.
fn record(deps: DepsMut, plan_id: &[u8; 32], leg_id: &[u8; 32], kind: u8, amount: u128) -> StdResult<()> {
    let (count, acc) = recon(deps.as_ref())?;
    let acc = settlement::recon_step(&acc, plan_id, leg_id, kind, amount);
    deps.storage.set(RECON, &to_json_binary(&Recon { count: count + 1, acc: hex::encode(acc) })?);
    Ok(())
}

fn err(m: impl Into<String>) -> StdError {
    StdError::msg(m.into())
}

fn leg_err(e: LegError) -> StdError {
    err(match e {
        LegError::NotLocked => "the leg is not locked",
        LegError::Unproven => "the decision does not prove under the checkpoint's state root",
        LegError::TooEarly => "the escape horizon has not passed",
    })
}

fn plan(b: &Binary) -> StdResult<[u8; 32]> {
    b.as_slice().try_into().map_err(|_| err("plan_id must be 32 bytes"))
}

fn leg_key(id: &[u8; 32]) -> Vec<u8> {
    [b"leg:".as_slice(), id].concat()
}

fn to_state(s: &Stage) -> LegState {
    match s {
        Stage::Locked => LegState::Locked,
        Stage::Released => LegState::Released,
        Stage::Refunded => LegState::Refunded,
    }
}

fn load_leg(deps: Deps, id: &[u8; 32]) -> StdResult<Leg> {
    from_json(deps.storage.get(&leg_key(id)).ok_or_else(|| err("the leg is not locked"))?)
}

#[entry_point]
pub fn instantiate(deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    let registry = deps.api.addr_validate(&msg.registry)?;
    deps.storage.set(CONFIG, &to_json_binary(&Config { registry, escape_horizon: msg.escape_horizon })?);
    Ok(Response::new())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let config: Config = from_json(deps.storage.get(CONFIG).ok_or_else(|| err("not instantiated"))?)?;
    match msg {
        ExecuteMsg::Lock { plan_id, index, recipient } => {
            let p = plan(&plan_id)?;
            let id = settlement::leg_id(&p, index);
            if deps.storage.get(&leg_key(&id)).is_some() {
                return Err(err("the leg is already locked"));
            }
            let [coin] = info.funds.as_slice() else {
                return Err(err("send exactly one coin"));
            };
            if coin.amount.is_zero() {
                return Err(err("send a nonzero amount"));
            }
            let recipient = deps.api.addr_validate(&recipient)?;
            let escape_at = env.block.time.seconds().saturating_add(config.escape_horizon);
            let leg = Leg { payer: info.sender, recipient, coin: coin.clone(), escape_at, stage: Stage::Locked };
            deps.storage.set(&leg_key(&id), &to_json_binary(&leg)?);
            record(deps, &p, &id, settlement::RECON_LOCKED, amount_of(&leg.coin)?)?;
            Ok(Response::new().add_event(
                Event::new("tenzro_leg_locked")
                    .add_attribute("plan_id", plan_id.to_hex())
                    .add_attribute("leg_id", Binary::from(id).to_hex())
                    .add_attribute("index", index.to_string())
                    .add_attribute("payer", leg.payer.as_str())
                    .add_attribute("recipient", leg.recipient.as_str())
                    .add_attribute("coin", leg.coin.to_string())
                    .add_attribute("escape_at", escape_at.to_string()),
            ))
        }
        ExecuteMsg::Settle { plan_id, index, checkpoint, decision, proof } => {
            let p = plan(&plan_id)?;
            let id = settlement::leg_id(&p, index);
            let mut leg = load_leg(deps.as_ref(), &id)?;
            let root: Binary = deps
                .querier
                .query_wasm_smart(&config.registry, &RegistryQuery::StateRoot { index: checkpoint })
                .map_err(|_| err(format!("no final checkpoint {checkpoint}")))?;
            let root: [u8; 32] = root.as_slice().try_into().map_err(|_| err("the registry returned a malformed root"))?;
            let next = settlement::settle_leg(to_state(&leg.stage), &root, &p, &decision, &proof).map_err(leg_err)?;
            pay(deps, p, id, &mut leg, next, plan_id, false)
        }
        ExecuteMsg::Escape { plan_id, index } => {
            let p = plan(&plan_id)?;
            let id = settlement::leg_id(&p, index);
            let mut leg = load_leg(deps.as_ref(), &id)?;
            let next = settlement::escape_leg(to_state(&leg.stage), env.block.time.seconds(), leg.escape_at).map_err(leg_err)?;
            pay(deps, p, id, &mut leg, next, plan_id, true)
        }
    }
}

fn pay(deps: DepsMut, p: [u8; 32], id: [u8; 32], leg: &mut Leg, next: LegState, plan_id: Binary, escaped: bool) -> StdResult<Response> {
    let (to, stage, kind, recon_kind) = match next {
        LegState::Released => (leg.recipient.clone(), Stage::Released, "tenzro_leg_released", settlement::RECON_RELEASED),
        LegState::Refunded => (leg.payer.clone(), Stage::Refunded, "tenzro_leg_refunded", settlement::RECON_REFUNDED),
        LegState::Locked => return Err(err("the leg did not move")),
    };
    leg.stage = stage;
    deps.storage.set(&leg_key(&id), &to_json_binary(&leg)?);
    record(deps, &p, &id, recon_kind, amount_of(&leg.coin)?)?;
    Ok(Response::new()
        .add_message(BankMsg::Send { to_address: to.to_string(), amount: vec![leg.coin.clone()] })
        .add_event(
            Event::new(kind)
                .add_attribute("plan_id", plan_id.to_hex())
                .add_attribute("leg_id", Binary::from(id).to_hex())
                .add_attribute("to", to.as_str())
                .add_attribute("coin", leg.coin.to_string())
                .add_attribute("escaped", escaped.to_string()),
        ))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::LegId { plan_id, index } => to_json_binary(&Binary::from(settlement::leg_id(&plan(&plan_id)?, index))),
        QueryMsg::Leg { plan_id, index } => to_json_binary(&load_leg(deps, &settlement::leg_id(&plan(&plan_id)?, index))?),
        QueryMsg::Reconciliation {} => {
            let (count, acc) = recon(deps)?;
            to_json_binary(&Recon { count, acc: hex::encode(acc) })
        }
    }
}

#[cfg(test)]
mod tests;
