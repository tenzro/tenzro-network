// SPDX-License-Identifier: Apache-2.0
//! Tenzro's bridge contract on Stellar.
//!
//! TNZO on Stellar is a Stellar asset whose admin is this contract: it mints
//! only against TNZO locked on Tenzro and burns what goes back. A transfer to
//! Tenzro burns the asset and emits `transfer_out` with the record Tenzro's
//! Stellar route decodes as its data: sequence, source and destination
//! selectors, sender, token, endpoint, recipient and amount, big-endian. A
//! transfer from Tenzro is the record Tenzro stored for it, executed once the
//! route's committee signed its digest: `threshold` distinct members, each
//! recovered from a secp256k1 signature over Keccak-256 of the outbound
//! domain, Tenzro's chain id, the route key and the record.
//!
//! Tenzro draws each committee from its bonded attestors and numbers it with
//! a set index. The committee this contract trusts hands it over to a later
//! one by signing that committee's set index, members, threshold and expiry
//! (`handover_digest`); any relayer submits the handover, which is accepted
//! only for a higher set index. The contract stops trusting a committee at
//! its expiry, so a committee whose members may have left their bonds on
//! Tenzro can never act here.
//!
//! Amounts in records are TNZO's smallest unit (18 decimals); the asset has
//! 7, so a record's amount is the asset amount times 10^11. Recipients on
//! Stellar are accounts (Ed25519 keys).
#![no_std]

use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::crypto::Hash;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env,
    Vec,
};

/// Smallest TNZO units per asset unit.
const SCALE: u128 = 100_000_000_000;
const OUTBOUND_DOMAIN: &[u8] = b"tenzro/bridge/route-outbound";
const COMMITTEE_DOMAIN: &[u8] = b"tenzro/bridge/route-committee";
const RECORD_LEN: u32 = 168;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    BelowThreshold = 3,
    WrongRoute = 4,
    AlreadyExecuted = 5,
    BadAmount = 6,
    BadCommittee = 7,
    MalformedRecord = 8,
    Expired = 9,
    StaleSet = 10,
}

#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub asset: Address,
    pub tenzro_chain_id: u64,
    pub route_key: Bytes,
    pub stellar_selector: u64,
    pub tenzro_selector: u64,
    pub token: BytesN<32>,
    pub tenzro_endpoint: BytesN<32>,
    pub committee: Vec<BytesN<20>>,
    pub threshold: u32,
    pub set_index: u32,
    /// Unix second after which the committee is no longer trusted.
    pub expires_at: u64,
}

#[contracttype]
enum Key {
    Config,
    Sequence,
    Executed(u64),
}

/// A transfer to Tenzro: the record, as the event's one value.
#[contractevent(topics = ["transfer_out"], data_format = "single-value")]
pub struct TransferOut {
    pub record: Bytes,
}

/// A transfer from Tenzro, executed.
#[contractevent(topics = ["transfer_in"], data_format = "vec")]
pub struct TransferIn {
    pub sequence: u64,
    pub recipient: Address,
    pub amount: i128,
}

fn config(env: &Env) -> Config {
    env.storage()
        .instance()
        .get(&Key::Config)
        .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
}

fn check_committee(env: &Env, committee: &Vec<BytesN<20>>, threshold: u32) {
    let n = committee.len();
    if n == 0 || threshold <= n / 2 || threshold > n {
        panic_with_error!(env, Error::BadCommittee);
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if committee.get_unchecked(i) == committee.get_unchecked(j) {
                panic_with_error!(env, Error::BadCommittee);
            }
        }
    }
}

/// The 32 raw bytes an address carries (an account's key or a contract's id).
fn raw32(env: &Env, a: &Address) -> BytesN<32> {
    let x = a.clone().to_xdr(env);
    let tail = x.slice(x.len() - 32..);
    tail.try_into().unwrap_or_else(|_| panic_with_error!(env, Error::MalformedRecord))
}

/// The account whose Ed25519 key is `key`.
fn account(env: &Env, key: &BytesN<32>) -> Address {
    // ScVal::Address(ScAddress::Account(PublicKey::Ed25519(key))) in XDR.
    let mut x = Bytes::from_array(env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
    x.append(&Bytes::from_array(env, &key.to_array()));
    soroban_sdk::xdr::FromXdr::from_xdr(env, &x).unwrap_or_else(|_| panic_with_error!(env, Error::MalformedRecord))
}

fn be(env: &Env, v: u64) -> Bytes {
    Bytes::from_array(env, &v.to_be_bytes())
}

/// The Ethereum-style address of the key that signed `digest`.
fn signer_of(env: &Env, digest: &Hash<32>, signature: &BytesN<65>) -> BytesN<20> {
    let sig = signature.to_array();
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&sig[..64]);
    let v = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    let key = env.crypto().secp256k1_recover(digest, &BytesN::from_array(env, &rs), u32::from(v));
    let key = Bytes::from_array(env, &key.to_array()).slice(1..);
    let h = env.crypto().keccak256(&key).to_array();
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    BytesN::from_array(env, &a)
}

fn check_quorum(env: &Env, c: &Config, digest: &Hash<32>, signatures: &Vec<BytesN<65>>) {
    if env.ledger().timestamp() > c.expires_at {
        panic_with_error!(env, Error::Expired);
    }
    let mut seen: Vec<BytesN<20>> = Vec::new(env);
    for s in signatures.iter() {
        let who = signer_of(env, digest, &s);
        if c.committee.contains(&who) && !seen.contains(&who) {
            seen.push_back(who);
        }
    }
    if seen.len() < c.threshold {
        panic_with_error!(env, Error::BelowThreshold);
    }
}

/// Keccak-256 of the outbound domain, Tenzro's chain id, the route key and
/// `record`.
fn outbound_hash(env: &Env, c: &Config, record: &Bytes) -> Hash<32> {
    let mut m = Bytes::from_slice(env, OUTBOUND_DOMAIN);
    m.append(&be(env, c.tenzro_chain_id));
    m.append(&be(env, u64::from(c.route_key.len())));
    m.append(&c.route_key);
    m.append(record);
    env.crypto().keccak256(&m)
}

/// Keccak-256 of the committee domain, Tenzro's chain id, the route key, the
/// set index, the member count, the members, the threshold and the expiry.
fn handover_hash(env: &Env, c: &Config, set_index: u32, committee: &Vec<BytesN<20>>, threshold: u32, expires_at: u64) -> Hash<32> {
    let mut m = Bytes::from_slice(env, COMMITTEE_DOMAIN);
    m.append(&be(env, c.tenzro_chain_id));
    m.append(&be(env, u64::from(c.route_key.len())));
    m.append(&c.route_key);
    m.append(&Bytes::from_array(env, &set_index.to_be_bytes()));
    m.append(&Bytes::from_array(env, &committee.len().to_be_bytes()));
    for a in committee.iter() {
        m.append(&Bytes::from_array(env, &a.to_array()));
    }
    m.append(&Bytes::from_array(env, &threshold.to_be_bytes()));
    m.append(&be(env, expires_at));
    env.crypto().keccak256(&m)
}

fn read_u64(r: &Bytes, at: u32) -> u64 {
    let mut b = [0u8; 8];
    r.slice(at..at + 8).copy_into_slice(&mut b);
    u64::from_be_bytes(b)
}

fn read32(env: &Env, r: &Bytes, at: u32) -> BytesN<32> {
    r.slice(at..at + 32).try_into().unwrap_or_else(|_| panic_with_error!(env, Error::MalformedRecord))
}

#[contract]
pub struct Bridge;

#[contractimpl]
impl Bridge {
    /// Set the asset (whose admin must be this contract), the route's
    /// identifiers and the committee Tenzro drew, with its set index and
    /// expiry, once. Afterwards only the committee hands itself over.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        env: Env,
        asset: Address,
        tenzro_chain_id: u64,
        route_key: Bytes,
        stellar_selector: u64,
        tenzro_selector: u64,
        token: BytesN<32>,
        tenzro_endpoint: BytesN<32>,
        committee: Vec<BytesN<20>>,
        threshold: u32,
        set_index: u32,
        expires_at: u64,
    ) {
        if env.storage().instance().has(&Key::Config) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }
        check_committee(&env, &committee, threshold);
        let c = Config {
            asset,
            tenzro_chain_id,
            route_key,
            stellar_selector,
            tenzro_selector,
            token,
            tenzro_endpoint,
            committee,
            threshold,
            set_index,
            expires_at,
        };
        env.storage().instance().set(&Key::Config, &c);
        env.storage().instance().set(&Key::Sequence, &0u64);
    }

    /// Send `amount` of the asset from `sender` to `recipient` on Tenzro:
    /// burn it and emit the record.
    pub fn send_to_tenzro(env: Env, sender: Address, amount: i128, recipient: BytesN<32>) {
        sender.require_auth();
        let c = config(&env);
        if amount <= 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        TokenClient::new(&env, &c.asset).burn(&sender, &amount);
        let sequence: u64 = env.storage().instance().get(&Key::Sequence).unwrap_or(0) + 1;
        env.storage().instance().set(&Key::Sequence, &sequence);
        let mut record = be(&env, sequence);
        record.append(&be(&env, c.stellar_selector));
        record.append(&be(&env, c.tenzro_selector));
        record.append(&Bytes::from_array(&env, &raw32(&env, &sender).to_array()));
        record.append(&Bytes::from_array(&env, &c.token.to_array()));
        record.append(&Bytes::from_array(&env, &c.tenzro_endpoint.to_array()));
        record.append(&Bytes::from_array(&env, &recipient.to_array()));
        record.append(&Bytes::from_array(&env, &((amount as u128) * SCALE).to_be_bytes()));
        TransferOut { record }.publish(&env);
    }

    /// The digest the committee signs for outbound `record`.
    pub fn outbound_digest(env: Env, record: Bytes) -> BytesN<32> {
        outbound_hash(&env, &config(&env), &record).into()
    }

    /// Execute outbound `record` from Tenzro, signed by the committee: mint
    /// the asset to its recipient, once.
    pub fn execute(env: Env, record: Bytes, signatures: Vec<BytesN<65>>) {
        let c = config(&env);
        let digest = outbound_hash(&env, &c, &record);
        check_quorum(&env, &c, &digest, &signatures);
        if record.len() != RECORD_LEN {
            panic_with_error!(&env, Error::MalformedRecord);
        }
        let sequence = read_u64(&record, 0);
        let source_selector = read_u64(&record, 8);
        let dest_selector = read_u64(&record, 16);
        let token = read32(&env, &record, 56);
        let endpoint = read32(&env, &record, 88);
        let recipient = read32(&env, &record, 120);
        let mut amount = [0u8; 16];
        record.slice(152..168).copy_into_slice(&mut amount);
        let amount = u128::from_be_bytes(amount);
        let here = raw32(&env, &env.current_contract_address());
        if source_selector != c.tenzro_selector || dest_selector != c.stellar_selector || endpoint != here || token != c.token {
            panic_with_error!(&env, Error::WrongRoute);
        }
        if env.storage().persistent().has(&Key::Executed(sequence)) {
            panic_with_error!(&env, Error::AlreadyExecuted);
        }
        if amount == 0 || amount % SCALE != 0 || amount / SCALE > i128::MAX as u128 {
            panic_with_error!(&env, Error::BadAmount);
        }
        env.storage().persistent().set(&Key::Executed(sequence), &true);
        let to = account(&env, &recipient);
        let units = (amount / SCALE) as i128;
        StellarAssetClient::new(&env, &c.asset).mint(&to, &units);
        TransferIn { sequence, recipient: to, amount: units }.publish(&env);
    }

    /// The digest the trusted committee signs to hand the contract over to
    /// committee `set_index`.
    pub fn handover_digest(env: Env, set_index: u32, committee: Vec<BytesN<20>>, threshold: u32, expires_at: u64) -> BytesN<32> {
        handover_hash(&env, &config(&env), set_index, &committee, threshold, expires_at).into()
    }

    /// Hand the contract over to committee `set_index`, signed by the
    /// committee it trusts. Only a higher set index is accepted.
    pub fn rotate_committee(
        env: Env,
        set_index: u32,
        committee: Vec<BytesN<20>>,
        threshold: u32,
        expires_at: u64,
        signatures: Vec<BytesN<65>>,
    ) {
        let mut c = config(&env);
        if set_index <= c.set_index {
            panic_with_error!(&env, Error::StaleSet);
        }
        check_committee(&env, &committee, threshold);
        let digest = handover_hash(&env, &c, set_index, &committee, threshold, expires_at);
        check_quorum(&env, &c, &digest, &signatures);
        c.committee = committee;
        c.threshold = threshold;
        c.set_index = set_index;
        c.expires_at = expires_at;
        env.storage().instance().set(&Key::Config, &c);
    }

    /// The trusted committee's set index and expiry.
    pub fn committee_set(env: Env) -> (u32, u64) {
        let c = config(&env);
        (c.set_index, c.expires_at)
    }

    /// The last transfer sent to Tenzro.
    pub fn sequence(env: Env) -> u64 {
        env.storage().instance().get(&Key::Sequence).unwrap_or(0)
    }

    /// Whether outbound record `sequence` was executed.
    pub fn is_executed(env: Env, sequence: u64) -> bool {
        env.storage().persistent().has(&Key::Executed(sequence))
    }
}

#[cfg(test)]
mod test;
