// SPDX-License-Identifier: Apache-2.0
//! Tenzro agent accounts on CosmWasm chains.
//!
//! One code serves two roles. A registry follows Tenzro finality (Groth16
//! proofs checked with BN254 in software) and instantiates accounts with
//! instantiate2 under its own address and the salt
//! `sha256("tenzro/omni-account/v1" || did)`, so an agent's account address
//! is fixed by the registry, the code and the DID. An account holds no key:
//! its authority is the grant Tenzro issued for the agent on this chain,
//! installed by anyone with `sync` (the grant bytes and their state proof
//! under the state root of a checkpoint the registry accepted). An action
//! sends the grant's bank denomination to its target when serving nodes of
//! the agent signed the action's digest with P-256 keys in the grant's key
//! root (two of distinct operators above the cosign threshold), within the
//! grant's budget, per-action limit, time window and targets. An exact grant
//! carries one action, run once with `act_exact`. A void grant stops every
//! action. The sender of an action is refunded up to the grant's cap.

use cosmwasm_std::{
    Addr, BankMsg, Binary, CanonicalAddr, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
    Storage, WasmMsg, entry_point, from_json, instantiate2_address, to_json_binary,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_finality_verifier::{Journal, Params, Store, agent, state_proof};

const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56,
    0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InstantiateMsg {
    /// A registry following the Tenzro chain `chain_id` with genesis
    /// `genesis_hash`, from its epoch-0 committee, for the chain `caip2`.
    Registry { image_id: Binary, chain_id: u64, genesis_hash: Binary, genesis_committee_root: Binary, caip2: String },
    /// The account of `did`; only a registry instantiates one.
    Account { did: String, caip2: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Registry: accept a checkpoint proven by `seal`.
    SubmitCheckpoint { journal: Binary, seal: Binary },
    /// Registry: instantiate the account of `did`. Anyone may.
    CreateAccount { did: String },
    /// Account: install a grant proven under final checkpoint `index`.
    Sync { index: u64, grant: Binary, proof: Binary, caip19: String, payee: Binary },
    /// Account: run an action signed by serving nodes.
    Act { action: Binary, signers: Vec<ActSigner>, target_proof: Vec<Binary> },
    /// Account: run the one action of an exact grant.
    ActExact { action: Binary },
}

/// A serving node's signature over an action's digest, with its key's place
/// in the grant's key root.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ActSigner {
    pub key: Binary,
    pub operator: String,
    pub proof: Vec<Binary>,
    pub signature: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Registry: the state root of final checkpoint `index`.
    StateRoot { index: u64 },
    /// Registry: where the account of `did` is.
    AccountOf { did: String },
    /// Account: its nonce and what it moved under the live grant.
    Status {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StatusResult {
    pub seq: u64,
    pub void: bool,
    pub nonce: u64,
    pub spent: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct RegistryData {
    image_id: [u8; 32],
    chain_id: u64,
    genesis_hash: [u8; 32],
    caip2: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct AccountData {
    registry: Addr,
    agent: [u8; 32],
    chain: [u8; 32],
    tree_key: [u8; 32],
    grant: Option<Vec<u8>>,
    denom: String,
    spent: u128,
    nonce: u64,
    exact_used: bool,
}

const REGISTRY: &[u8] = b"registry";
const ACCOUNT: &[u8] = b"account";

fn committee_key(epoch: u64) -> Vec<u8> {
    [b"c:".as_slice(), &epoch.to_be_bytes()].concat()
}

fn checkpoint_key(index: u64) -> Vec<u8> {
    [b"k:".as_slice(), &index.to_be_bytes()].concat()
}

fn err(m: impl Into<String>) -> StdError {
    StdError::msg(m.into())
}

fn b32(b: &[u8], what: &str) -> StdResult<[u8; 32]> {
    b.try_into().map_err(|_| err(format!("{what} is 32 bytes")))
}

fn salt(did: &str) -> [u8; 32] {
    agent::salt(did.as_bytes())
}

struct Ledger<'a>(&'a mut dyn Storage);

impl Store for Ledger<'_> {
    fn committee_root(&self, epoch: u64) -> Option<[u8; 32]> {
        self.0.get(&committee_key(epoch)).and_then(|v| v.try_into().ok())
    }
    fn set_committee_root(&mut self, epoch: u64, root: [u8; 32]) {
        self.0.set(&committee_key(epoch), &root);
    }
    fn is_final(&self, index: u64) -> bool {
        self.0.get(&checkpoint_key(index)).is_some()
    }
    fn set_final(&mut self, j: &Journal) {
        self.0.set(&checkpoint_key(j.index), &j.state_root);
    }
}

#[entry_point]
pub fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    match msg {
        InstantiateMsg::Registry { image_id, chain_id, genesis_hash, genesis_committee_root, caip2 } => {
            let data = RegistryData {
                image_id: b32(&image_id, "image_id")?,
                chain_id,
                genesis_hash: b32(&genesis_hash, "genesis_hash")?,
                caip2,
            };
            deps.storage.set(REGISTRY, &cosmwasm_std::to_json_vec(&data)?);
            deps.storage.set(&committee_key(0), &b32(&genesis_committee_root, "genesis_committee_root")?);
            Ok(Response::new())
        }
        InstantiateMsg::Account { did, caip2 } => {
            // Only a registry instantiates an account, at the address the
            // registry derives for the DID.
            let registry = info.sender;
            let expected = account_of(deps.as_ref(), &registry, &did)?;
            if expected != env.contract.address {
                return Err(err("an account is instantiated only by its registry"));
            }
            let data = AccountData {
                registry,
                agent: Sha256::digest(did.as_bytes()).into(),
                chain: Sha256::digest(caip2.as_bytes()).into(),
                tree_key: agent::grant_tree_key(did.as_bytes(), caip2.as_bytes()),
                grant: None,
                denom: String::new(),
                spent: 0,
                nonce: 0,
                exact_used: false,
            };
            deps.storage.set(ACCOUNT, &cosmwasm_std::to_json_vec(&data)?);
            Ok(Response::new())
        }
    }
}

/// The account of `did` under `registry`: instantiate2 of this code.
fn account_of(deps: Deps, registry: &Addr, did: &str) -> StdResult<Addr> {
    let info = deps.querier.query_wasm_contract_info(registry)?;
    let code = deps.querier.query_wasm_code_info(info.code_id)?;
    let creator = deps.api.addr_canonicalize(registry.as_str())?;
    let at: CanonicalAddr = instantiate2_address(code.checksum.as_slice(), &creator, &salt(did))
        .map_err(|e| err(e.to_string()))?;
    deps.api.addr_humanize(&at)
}

fn load_registry(s: &dyn Storage) -> StdResult<RegistryData> {
    from_json(s.get(REGISTRY).ok_or_else(|| err("not a registry"))?)
}

fn load_account(s: &dyn Storage) -> StdResult<AccountData> {
    from_json(s.get(ACCOUNT).ok_or_else(|| err("not an account"))?)
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::SubmitCheckpoint { journal, seal } => {
            let r = load_registry(deps.storage)?;
            let params = Params { image_id: r.image_id, chain_id: r.chain_id, genesis_hash: r.genesis_hash };
            let j = tenzro_finality_verifier::submit(
                &tenzro_finality_verifier::arkworks::Arkworks,
                &params,
                &mut Ledger(deps.storage),
                &journal,
                &seal,
            )
            .map_err(|e| err(format!("checkpoint refused: {e:?}")))?;
            Ok(Response::new().add_attribute("index", j.index.to_string()))
        }
        ExecuteMsg::CreateAccount { did } => {
            let r = load_registry(deps.storage)?;
            let me = deps.querier.query_wasm_contract_info(&env.contract.address)?;
            let msg = WasmMsg::Instantiate2 {
                admin: None,
                code_id: me.code_id,
                label: format!("tenzro agent account {}", hex(&Sha256::digest(did.as_bytes()))),
                msg: to_json_binary(&InstantiateMsg::Account { did: did.clone(), caip2: r.caip2 })?,
                funds: vec![],
                salt: Binary::from(salt(&did).to_vec()),
            };
            Ok(Response::new().add_message(msg))
        }
        ExecuteMsg::Sync { index, grant, proof, caip19, payee } => sync(deps, env, index, &grant, &proof, &caip19, &payee),
        ExecuteMsg::Act { action, signers, target_proof } => act(deps, env, info, &action, Some((&signers, &target_proof))),
        ExecuteMsg::ActExact { action } => act(deps, env, info, &action, None),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sync(deps: DepsMut, env: Env, index: u64, grant: &[u8], proof: &[u8], caip19: &str, payee: &[u8]) -> StdResult<Response> {
    let mut a = load_account(deps.storage)?;
    let root: Binary = deps.querier.query_wasm_smart(&a.registry, &QueryMsg::StateRoot { index })?;
    if !state_proof::verify_at(&b32(&root, "state root")?, &a.tree_key, Some(grant), proof) {
        return Err(err("the grant does not prove under the checkpoint's state root"));
    }
    let g = agent::Grant::decode(grant).ok_or_else(|| err("malformed grant"))?;
    let here = deps.api.addr_canonicalize(env.contract.address.as_str())?;
    let mut word = [0u8; 32];
    let n = here.len().min(32);
    word[32 - n..].copy_from_slice(&here.as_slice()[here.len() - n..]);
    if g.chain != a.chain || g.agent != a.agent || g.account != word {
        return Err(err("the grant is of another chain, agent or account"));
    }
    let mut resp = Response::new();
    let mut new_seq = true;
    if let Some(cur) = a.grant.as_deref().and_then(agent::Grant::decode) {
        let later = g.seq > cur.seq;
        if !later && !(g.seq == cur.seq && g.void && !cur.void) {
            return Err(err("a stale grant"));
        }
        if later {
            resp = resp.add_event(
                cosmwasm_std::Event::new("grant_closed")
                    .add_attribute("seq", cur.seq.to_string())
                    .add_attribute("spent", a.spent.to_string()),
            );
        } else {
            new_seq = false;
        }
    }
    if <[u8; 32]>::from(Sha256::digest(caip19.as_bytes())) != g.asset {
        return Err(err("the asset is not the grant's"));
    }
    let denom = caip19.split_once("/bank:").map(|(_, d)| d.to_string()).ok_or_else(|| err("a CosmWasm grant names a bank denomination"))?;
    if new_seq {
        a.spent = 0;
        a.exact_used = false;
    }
    a.grant = Some(grant.to_vec());
    a.denom = denom;
    deps.storage.set(ACCOUNT, &cosmwasm_std::to_json_vec(&a)?);
    Ok(resp.add_event(
        cosmwasm_std::Event::new("synced")
            .add_attribute("seq", g.seq.to_string())
            .add_attribute("void", g.void.to_string())
            .add_attribute("payee", hex(payee)),
    ))
}

/// target (u16-prefixed), selector (u16-prefixed), amount, refund, data
/// (u32-prefixed); nothing after.
/// The selector of an action that calls a contract (a settlement lock) with
/// the action's data as its message and the action's amount as its funds.
pub const EXECUTE_SELECTOR: &[u8] = b"execute";

fn decode_action(b: &[u8]) -> Option<(&[u8], &[u8], u128, u128, &[u8])> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = b.get(at..at + n)?;
        at += n;
        Some(s)
    };
    let tl = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
    let target = take(tl)?;
    let sl = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
    let selector = take(sl)?;
    let amount = u128::from_be_bytes(take(16)?.try_into().ok()?);
    let refund = u128::from_be_bytes(take(16)?.try_into().ok()?);
    let dl = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
    let data = take(dl)?;
    (at == b.len()).then_some((target, selector, amount, refund, data))
}

fn act(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    action: &[u8],
    signed: Option<(&Vec<ActSigner>, &Vec<Binary>)>,
) -> StdResult<Response> {
    let mut a = load_account(deps.storage)?;
    let g = a.grant.as_deref().and_then(agent::Grant::decode).ok_or_else(|| err("no live grant"))?;
    if g.void {
        return Err(err("the grant is void"));
    }
    let now = env.block.time.nanos() / 1_000_000;
    if now < g.not_before_ms || now > g.not_after_ms {
        return Err(err("outside the grant's time window"));
    }
    let (target, selector, amount, refund, data) = decode_action(action).ok_or_else(|| err("malformed action"))?;
    if refund > g.relay_fee_max {
        return Err(err("the relayer refund is above the grant's cap"));
    }
    let digest: [u8; 32];
    match signed {
        None => {
            if !g.is_exact() {
                return Err(err("an open grant takes signed actions"));
            }
            if a.exact_used {
                return Err(err("the exact grant was used"));
            }
            digest = agent::payload_hash(action);
            if digest != g.payload_hash {
                return Err(err("the action is not the exact grant's"));
            }
            a.exact_used = true;
        }
        Some((signers, target_proof)) => {
            if g.is_exact() {
                return Err(err("an exact grant runs its action with act_exact"));
            }
            if amount > g.per_action_max {
                return Err(err("over the per-action limit"));
            }
            if a.spent + amount > g.budget {
                return Err(err("over the grant's budget"));
            }
            if g.targets_root != [0u8; 32] {
                let proof: Vec<[u8; 32]> = target_proof.iter().map(|p| b32(p, "proof")).collect::<StdResult<_>>()?;
                if !agent::merkle_verify(&g.targets_root, &agent::target_leaf(target, selector), &proof) {
                    return Err(err("target not allowed"));
                }
            }
            digest = agent::act_digest(&g.chain, &g.account, g.seq, a.nonce, action);
            let need = if amount > g.cosign_above { 2 } else { 1 };
            if signers.len() < need {
                return Err(err("cosign required"));
            }
            for (i, s) in signers.iter().take(need).enumerate() {
                if s.signature.len() != 64 || s.signature[32..] > P256_HALF_N[..] {
                    return Err(err("a signature is not low-S"));
                }
                let ok = deps
                    .api
                    .secp256r1_verify(&digest, &s.signature, &s.key)
                    .map_err(|e| err(format!("signature: {e}")))?;
                if !ok {
                    return Err(err("a signature does not verify"));
                }
                let key: [u8; 65] = s.key.as_slice().try_into().map_err(|_| err("a key is 65 bytes"))?;
                let proof: Vec<[u8; 32]> = s.proof.iter().map(|p| b32(p, "proof")).collect::<StdResult<_>>()?;
                if !agent::merkle_verify(&g.keys_root, &agent::key_leaf(&key, s.operator.as_bytes()), &proof) {
                    return Err(err("key not in root"));
                }
                if i == 1 && signers[0].operator == s.operator {
                    return Err(err("cosign required"));
                }
            }
        }
    }
    let n = a.nonce;
    // A paying action reports the payment, bound to what it bought, for
    // Tenzro to record as this agent's.
    let report = if selector == agent::PAY_SELECTOR {
        Some(agent::paid_report(&g, n, data, amount).ok_or_else(|| err("a payment carries payee, request, quote and price"))?)
    } else {
        None
    };
    a.nonce += 1;
    a.spent += amount;
    deps.storage.set(ACCOUNT, &cosmwasm_std::to_json_vec(&a)?);
    let to = deps.api.addr_humanize(&CanonicalAddr::from(target.to_vec()))?;
    // An `execute` action calls the target contract with the signed message
    // and exactly the action's amount attached; any other action sends it.
    let mut resp = if selector == EXECUTE_SELECTOR {
        let funds = if amount > 0 { vec![Coin::new(amount, a.denom.clone())] } else { vec![] };
        Response::new().add_message(WasmMsg::Execute { contract_addr: to.into_string(), msg: Binary::from(data.to_vec()), funds })
    } else {
        Response::new().add_message(BankMsg::Send { to_address: to.into_string(), amount: vec![Coin::new(amount, a.denom.clone())] })
    };
    if refund > 0 {
        resp = resp.add_message(BankMsg::Send { to_address: info.sender.into_string(), amount: vec![Coin::new(refund, a.denom)] });
    }
    if let Some(report) = report {
        resp = resp.add_event(cosmwasm_std::Event::new("reported").add_attribute("report", hex(&report)));
    }
    Ok(resp.add_event(
        cosmwasm_std::Event::new("acted")
            .add_attribute("seq", g.seq.to_string())
            .add_attribute("nonce", n.to_string())
            .add_attribute("digest", hex(&digest))
            .add_attribute("amount", amount.to_string()),
    ))
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::StateRoot { index } => {
            let root = deps.storage.get(&checkpoint_key(index)).ok_or_else(|| err(format!("no final checkpoint {index}")))?;
            to_json_binary(&Binary::from(root))
        }
        QueryMsg::AccountOf { did } => to_json_binary(&account_of(deps, &env.contract.address, &did)?),
        QueryMsg::Status {} => {
            let a = load_account(deps.storage)?;
            let g = a.grant.as_deref().and_then(agent::Grant::decode);
            to_json_binary(&StatusResult {
                seq: g.map(|g| g.seq).unwrap_or(0),
                void: g.map(|g| g.void).unwrap_or(false),
                nonce: a.nonce,
                spent: a.spent.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
