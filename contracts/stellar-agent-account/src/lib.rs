// SPDX-License-Identifier: Apache-2.0
//! A Tenzro agent's account on Stellar.
//!
//! The account is a custom Soroban account that holds no key. Its authority
//! is the grant Tenzro issued for the agent on this chain, installed by anyone
//! with `sync`: the grant bytes and their state proof under the state root of
//! a checkpoint Tenzro's finality client on Stellar accepted. `__check_auth`
//! authorizes one contract call at a time: the call named by an action that
//! serving nodes of the agent signed with P-256 keys in the grant's key root
//! (two of distinct operators above the cosign threshold), whose data is the
//! authorization's signature payload, within the grant's budget, per-action
//! limit, time window and targets. A call that moves the grant's asset
//! (`transfer`, `approve`, `burn`) must move exactly the action's amount. An
//! exact grant authorizes its one action once. A void grant authorizes
//! nothing.
#![no_std]

use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, String, Symbol, TryFromVal, Vec, contract, contractclient, contracterror,
    contractevent, contractimpl, contracttype, panic_with_error,
};
use tenzro_finality_verifier::{agent, state_proof};

/// Ledgers a stored entry lives before it must be extended (about 30 days).
const ENTRY_TTL: u32 = 518_400;
const MAX_PROOF: usize = 2 + 32 * 248 + 1 + 256;
const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56,
    0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    Malformed = 1,
    BadStateProof = 2,
    MalformedGrant = 3,
    NotThisAccount = 4,
    StaleGrant = 5,
    AssetMismatch = 6,
    NoLiveGrant = 7,
    GrantVoid = 8,
    OutsideWindow = 9,
    ExactUsed = 10,
    PayloadMismatch = 11,
    HighS = 12,
    KeyNotInRoot = 13,
    CosignRequired = 14,
    TargetNotAllowed = 15,
    OverPerAction = 16,
    OverBudget = 17,
    RelayOverCap = 18,
    OneCallAtATime = 19,
    AmountMismatch = 20,
}

/// What Tenzro's finality client on Stellar serves.
#[contractclient(name = "FinalityClient")]
pub trait Finality {
    fn state_root(env: Env, index: u64) -> BytesN<32>;
}

/// A serving node's signature over an action's digest preimage, with its
/// key's place in the grant's key root.
#[contracttype]
#[derive(Clone)]
pub struct Signer {
    pub key: BytesN<65>,
    pub operator: Bytes,
    pub proof: Vec<BytesN<32>>,
    pub signature: BytesN<64>,
}

/// What authorizes one call: the encoded action and, for an open grant, the
/// signers and the target's Merkle proof.
#[contracttype]
#[derive(Clone)]
pub struct ActAuth {
    pub action: Bytes,
    pub signers: Vec<Signer>,
    pub target_proof: Vec<BytesN<32>>,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Agent,
    Chain,
    TreeKey,
    Client,
    Grant,
    Caip19,
    Spent,
    Nonce,
    ExactUsed,
}

#[contractevent]
pub struct Synced {
    #[topic]
    pub seq: u64,
    pub void: bool,
    pub payee: BytesN<32>,
}

#[contractevent]
pub struct GrantClosed {
    #[topic]
    pub seq: u64,
    pub spent: u128,
}

/// A report Tenzro records through the chain's report route, in the layout
/// Tenzro decodes.
#[contractevent]
pub struct Reported {
    pub report: Bytes,
}

#[contractevent]
pub struct Acted {
    #[topic]
    pub seq: u64,
    pub nonce: u64,
    pub digest: BytesN<32>,
    pub amount: u128,
}

fn get<V: TryFromVal<Env, soroban_sdk::Val>>(env: &Env, k: Key) -> Option<V> {
    env.storage().instance().get(&k)
}

fn put<V: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, k: Key, v: &V) {
    env.storage().instance().set(&k, v);
}

/// The contract of the grant's asset, from its CAIP-19 id.
fn asset_contract(env: &Env) -> Result<Address, Error> {
    let caip19: String = get(env, Key::Caip19).ok_or(Error::Malformed)?;
    let mut cb = [0u8; 128];
    let c = copy(env, &caip19.to_bytes(), &mut cb);
    let strkey = core::str::from_utf8(c).ok().and_then(|s| s.rsplit_once(':')).map(|(_, k)| k).ok_or(Error::AssetMismatch)?;
    Ok(Address::from_str(env, strkey))
}

/// The installed grant, refused when void.
fn live_grant(env: &Env) -> Result<agent::Grant, Error> {
    let grant: Bytes = get(env, Key::Grant).ok_or(Error::NoLiveGrant)?;
    let mut gb = [0u8; agent::GRANT_LEN];
    if grant.len() as usize != agent::GRANT_LEN {
        return Err(Error::MalformedGrant);
    }
    grant.copy_into_slice(&mut gb);
    let g = agent::Grant::decode(&gb).ok_or(Error::MalformedGrant)?;
    if g.void {
        return Err(Error::GrantVoid);
    }
    Ok(g)
}

/// Copy `b` into `buf`, returning the filled prefix.
fn copy<'a>(env: &Env, b: &Bytes, buf: &'a mut [u8]) -> &'a [u8] {
    let n = b.len() as usize;
    if n > buf.len() {
        panic_with_error!(env, Error::Malformed);
    }
    b.copy_into_slice(&mut buf[..n]);
    &buf[..n]
}

fn here(env: &Env) -> [u8; 32] {
    match env.current_contract_address().to_payload() {
        Some(soroban_sdk::address_payload::AddressPayload::ContractIdHash(id)) => id.to_array(),
        _ => panic_with_error!(env, Error::Malformed),
    }
}

fn contract_id(a: &Address) -> Option<[u8; 32]> {
    match a.to_payload() {
        Some(soroban_sdk::address_payload::AddressPayload::ContractIdHash(id)) => Some(id.to_array()),
        _ => None,
    }
}

/// An encoded action: target (u16-prefixed), selector (u16-prefixed),
/// amount, refund, data (u32-prefixed).
struct Action<'a> {
    target: &'a [u8],
    selector: &'a [u8],
    amount: u128,
    refund: u128,
    data: &'a [u8],
}

fn decode_action(b: &[u8]) -> Option<Action<'_>> {
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
    (at == b.len()).then_some(Action { target, selector, amount, refund, data })
}

#[contract]
pub struct AgentAccount;

#[contractimpl]
impl AgentAccount {
    /// The account of `did` on the chain `caip2`, reading final state roots
    /// from `client`.
    pub fn __constructor(env: Env, did: Bytes, caip2: Bytes, client: Address) {
        let mut d = [0u8; 256];
        let mut c = [0u8; 64];
        let did_s = copy(&env, &did, &mut d);
        let caip2_s = copy(&env, &caip2, &mut c);
        put(&env, Key::Agent, &env.crypto().sha256(&did).to_bytes());
        put(&env, Key::Chain, &env.crypto().sha256(&caip2).to_bytes());
        put(&env, Key::TreeKey, &BytesN::from_array(&env, &agent::grant_tree_key(did_s, caip2_s)));
        put(&env, Key::Client, &client);
        env.storage().instance().extend_ttl(ENTRY_TTL, ENTRY_TTL);
    }

    /// Install `grant`, proven by `proof` under the state root of final
    /// checkpoint `index`: a later grant, or the void of the current one.
    /// `caip19` names the grant's asset; `payee` is the Tenzro account a
    /// relay task pays for installing a void.
    pub fn sync(env: Env, index: u64, grant: Bytes, proof: Bytes, caip19: String, payee: BytesN<32>) -> Result<(), Error> {
        let client: Address = get(&env, Key::Client).ok_or(Error::Malformed)?;
        let root = FinalityClient::new(&env, &client).state_root(&index).to_array();
        let tk: BytesN<32> = get(&env, Key::TreeKey).ok_or(Error::Malformed)?;
        let mut gb = [0u8; agent::GRANT_LEN];
        if grant.len() as usize != agent::GRANT_LEN {
            return Err(Error::MalformedGrant);
        }
        grant.copy_into_slice(&mut gb);
        let mut pb = [0u8; MAX_PROOF];
        let proof_s = copy(&env, &proof, &mut pb);
        if !state_proof::verify_at(&root, &tk.to_array(), Some(&gb), proof_s) {
            return Err(Error::BadStateProof);
        }
        let g = agent::Grant::decode(&gb).ok_or(Error::MalformedGrant)?;
        let chain: BytesN<32> = get(&env, Key::Chain).ok_or(Error::Malformed)?;
        let agent_hash: BytesN<32> = get(&env, Key::Agent).ok_or(Error::Malformed)?;
        if g.chain != chain.to_array() || g.agent != agent_hash.to_array() || g.account != here(&env) {
            return Err(Error::NotThisAccount);
        }
        let mut new_seq = true;
        if let Some(cur) = get::<Bytes>(&env, Key::Grant) {
            let mut cb = [0u8; agent::GRANT_LEN];
            cur.copy_into_slice(&mut cb);
            let cur = agent::Grant::decode(&cb).ok_or(Error::MalformedGrant)?;
            let later = g.seq > cur.seq;
            if !later && !(g.seq == cur.seq && g.void && !cur.void) {
                return Err(Error::StaleGrant);
            }
            if later {
                GrantClosed { seq: cur.seq, spent: get(&env, Key::Spent).unwrap_or(0u128) }.publish(&env);
            } else {
                new_seq = false;
            }
        }
        let mut ab = [0u8; 128];
        let caip19_b = caip19.to_bytes();
        let asset = copy(&env, &caip19_b, &mut ab);
        if env.crypto().sha256(&Bytes::from_slice(&env, asset)).to_array() != g.asset {
            return Err(Error::AssetMismatch);
        }
        if new_seq {
            put(&env, Key::Spent, &0u128);
            put(&env, Key::ExactUsed, &false);
        }
        put(&env, Key::Grant, &grant);
        put(&env, Key::Caip19, &caip19);
        env.storage().instance().extend_ttl(ENTRY_TTL, ENTRY_TTL);
        Synced { seq: g.seq, void: g.void, payee }.publish(&env);
        Ok(())
    }

    /// Pay `amount` of the grant's asset to `to` for the Tenzro account
    /// `payee`, bound to the request and quote it bought, and report it so
    /// Tenzro records the payment as this agent's. Runs as one action under
    /// the live grant: serving nodes sign it like any other.
    pub fn pay(
        env: Env,
        to: Address,
        amount: i128,
        payee: BytesN<32>,
        request: BytesN<32>,
        quote: BytesN<32>,
        usd_e6: u64,
    ) -> Result<(), Error> {
        env.current_contract_address().require_auth();
        let g = live_grant(&env)?;
        let token = asset_contract(&env)?;
        soroban_sdk::token::TokenClient::new(&env, &token).transfer(&env.current_contract_address(), &to, &amount);
        let nonce = get::<u64>(&env, Key::Nonce).unwrap_or(0).checked_sub(1).ok_or(Error::Malformed)?;
        let mut data = [0u8; agent::PAY_DATA_LEN];
        data[..32].copy_from_slice(&payee.to_array());
        data[32..64].copy_from_slice(&request.to_array());
        data[64..96].copy_from_slice(&quote.to_array());
        data[96..].copy_from_slice(&usd_e6.to_be_bytes());
        let amount = u128::try_from(amount).map_err(|_| Error::AmountMismatch)?;
        let report = agent::paid_report(&g, nonce, &data, amount).ok_or(Error::Malformed)?;
        Reported { report: Bytes::from_slice(&env, &report) }.publish(&env);
        Ok(())
    }

    /// The account's next action nonce.
    pub fn nonce(env: Env) -> u64 {
        get(&env, Key::Nonce).unwrap_or(0)
    }

    /// What the account has moved under the live grant.
    pub fn spent(env: Env) -> u128 {
        get(&env, Key::Spent).unwrap_or(0)
    }
}

#[contractimpl]
impl CustomAccountInterface for AgentAccount {
    type Signature = ActAuth;
    type Error = Error;

    fn __check_auth(env: Env, payload: Hash<32>, auth: ActAuth, contexts: Vec<Context>) -> Result<(), Error> {
        // One call, or one call plus the single nested transfer it makes of
        // this account's grant asset (a lock pulling exactly its amount).
        if contexts.is_empty() || contexts.len() > 2 {
            return Err(Error::OneCallAtATime);
        }
        let Context::Contract(call) = contexts.get_unchecked(0) else {
            return Err(Error::OneCallAtATime);
        };
        let nested = match contexts.len() {
            2 => match contexts.get_unchecked(1) {
                Context::Contract(n) => Some(n),
                _ => return Err(Error::OneCallAtATime),
            },
            _ => None,
        };
        let grant: Bytes = get(&env, Key::Grant).ok_or(Error::NoLiveGrant)?;
        let mut gb = [0u8; agent::GRANT_LEN];
        grant.copy_into_slice(&mut gb);
        let g = agent::Grant::decode(&gb).ok_or(Error::MalformedGrant)?;
        if g.void {
            return Err(Error::GrantVoid);
        }
        let now = env.ledger().timestamp() * 1000;
        if now < g.not_before_ms || now > g.not_after_ms {
            return Err(Error::OutsideWindow);
        }
        let mut abuf = [0u8; 1024];
        let action_s = copy(&env, &auth.action, &mut abuf);
        let a = decode_action(action_s).ok_or(Error::Malformed)?;
        // The action names the call: its contract and function.
        let target_id = contract_id(&call.contract).ok_or(Error::TargetNotAllowed)?;
        if a.target != target_id {
            return Err(Error::TargetNotAllowed);
        }
        let fn_name = core::str::from_utf8(a.selector).map_err(|_| Error::Malformed)?;
        if call.fn_name != Symbol::new(&env, fn_name) {
            return Err(Error::TargetNotAllowed);
        }
        if a.refund > g.relay_fee_max {
            return Err(Error::RelayOverCap);
        }
        // A call that moves value moves the action's amount, of the grant's
        // asset.
        let moved: Option<i128> = match fn_name {
            // The account's own payment: it moves its amount argument.
            "pay" => {
                if call.contract != env.current_contract_address() {
                    return Err(Error::TargetNotAllowed);
                }
                call.args.get(1).and_then(|v| i128::try_from_val(&env, &v).ok())
            }
            "transfer" | "approve" | "burn" => {
                if call.contract != asset_contract(&env)? {
                    return Err(Error::AssetMismatch);
                }
                let at = if fn_name == "burn" { 1 } else { 2 };
                let from = call.args.get(0).and_then(|v| Address::try_from_val(&env, &v).ok());
                if from != Some(env.current_contract_address()) {
                    return Err(Error::AmountMismatch);
                }
                call.args.get(at).and_then(|v| i128::try_from_val(&env, &v).ok())
            }
            // Any other call moves value only through the one nested
            // transfer: this account to the called contract, of the grant's
            // asset, for exactly the action's amount. Nothing stays approved.
            _ => match &nested {
                None => Some(0),
                Some(n) => {
                    if n.contract != asset_contract(&env)? {
                        return Err(Error::AssetMismatch);
                    }
                    if n.fn_name != Symbol::new(&env, "transfer") {
                        return Err(Error::OneCallAtATime);
                    }
                    let from = n.args.get(0).and_then(|v| Address::try_from_val(&env, &v).ok());
                    let to = n.args.get(1).and_then(|v| Address::try_from_val(&env, &v).ok());
                    if from != Some(env.current_contract_address()) || to != Some(call.contract.clone()) {
                        return Err(Error::AmountMismatch);
                    }
                    n.args.get(2).and_then(|v| i128::try_from_val(&env, &v).ok())
                }
            },
        };
        if nested.is_some() && matches!(fn_name, "pay" | "transfer" | "approve" | "burn") {
            return Err(Error::OneCallAtATime);
        }
        if moved.filter(|m| *m >= 0).map(|m| m as u128) != Some(a.amount) {
            return Err(Error::AmountMismatch);
        }
        let nonce: u64 = get(&env, Key::Nonce).unwrap_or(0);
        let spent: u128 = get(&env, Key::Spent).unwrap_or(0);
        let digest: [u8; 32];
        if g.is_exact() {
            if get(&env, Key::ExactUsed).unwrap_or(false) {
                return Err(Error::ExactUsed);
            }
            digest = agent::payload_hash(action_s);
            if digest != g.payload_hash {
                return Err(Error::PayloadMismatch);
            }
            put(&env, Key::ExactUsed, &true);
        } else {
            if a.data != payload.to_array() {
                return Err(Error::PayloadMismatch);
            }
            if a.amount > g.per_action_max {
                return Err(Error::OverPerAction);
            }
            if spent + a.amount > g.budget {
                return Err(Error::OverBudget);
            }
            if g.targets_root != [0u8; 32] {
                let mut proof = [[0u8; 32]; 32];
                let n = auth.target_proof.len() as usize;
                if n > proof.len() {
                    return Err(Error::Malformed);
                }
                for (i, p) in auth.target_proof.iter().enumerate() {
                    proof[i] = p.to_array();
                }
                if !agent::merkle_verify(&g.targets_root, &agent::target_leaf(a.target, a.selector), &proof[..n]) {
                    return Err(Error::TargetNotAllowed);
                }
            }
            let mut pre = Bytes::from_slice(&env, agent::ACT_DOMAIN);
            pre.extend_from_array(&g.chain);
            pre.extend_from_array(&g.account);
            pre.extend_from_array(&g.seq.to_be_bytes());
            pre.extend_from_array(&nonce.to_be_bytes());
            pre.append(&auth.action);
            let hash = env.crypto().sha256(&pre);
            digest = hash.to_array();
            let need = if a.amount > g.cosign_above { 2 } else { 1 };
            if auth.signers.len() < need {
                return Err(Error::CosignRequired);
            }
            let mut first: Option<Bytes> = None;
            for i in 0..need {
                let s = auth.signers.get_unchecked(i);
                let sig = s.signature.to_array();
                if sig[32..] > P256_HALF_N[..] {
                    return Err(Error::HighS);
                }
                env.crypto().secp256r1_verify(&s.key, &hash, &s.signature);
                let mut ob = [0u8; 256];
                let op = copy(&env, &s.operator, &mut ob);
                let mut proof = [[0u8; 32]; 32];
                let n = s.proof.len() as usize;
                if n > proof.len() {
                    return Err(Error::Malformed);
                }
                for (j, p) in s.proof.iter().enumerate() {
                    proof[j] = p.to_array();
                }
                if !agent::merkle_verify(&g.keys_root, &agent::key_leaf(&s.key.to_array(), op), &proof[..n]) {
                    return Err(Error::KeyNotInRoot);
                }
                match &first {
                    None => first = Some(s.operator.clone()),
                    Some(f) if *f == s.operator => return Err(Error::CosignRequired),
                    Some(_) => {}
                }
            }
        }
        put(&env, Key::Nonce, &(nonce + 1));
        put(&env, Key::Spent, &(spent + a.amount));
        Acted { seq: g.seq, nonce, digest: BytesN::from_array(&env, &digest), amount: a.amount }.publish(&env);
        Ok(())
    }
}

#[cfg(test)]
mod test;
