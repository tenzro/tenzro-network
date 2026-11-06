// SPDX-License-Identifier: Apache-2.0
//! A client of Tenzro finality on Stellar.
//!
//! A finality proof is a Groth16 proof (BN254) that RISC Zero's recursion
//! circuit accepted a receipt of Tenzro's finality program; its journal states
//! one checkpoint the program verified under the committee of its epoch. The
//! client checks the proof with the BN254 host functions, through the same
//! verifier every Tenzro finality client uses, and records the checkpoint's
//! state root. A checkpoint that ends an epoch hands over to the next
//! committee.
#![no_std]

use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Bn254Fr};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Bytes, BytesN, Env, Vec,
};
use tenzro_finality_verifier::{Bn254, Error as ProofError, Journal, Params, Store};

/// Ledgers a stored entry lives before it must be extended (about 30 days).
const ENTRY_TTL: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    MalformedSeal = 1,
    WrongSelector = 2,
    BadPoint = 3,
    InvalidProof = 4,
    MalformedJournal = 5,
    WrongChain = 6,
    UnknownCommittee = 7,
    AlreadyFinal = 8,
    UnknownCheckpoint = 9,
}

impl From<ProofError> for Error {
    fn from(e: ProofError) -> Self {
        match e {
            ProofError::MalformedSeal => Error::MalformedSeal,
            ProofError::WrongSelector => Error::WrongSelector,
            ProofError::BadPoint => Error::BadPoint,
            ProofError::InvalidProof => Error::InvalidProof,
            ProofError::MalformedJournal => Error::MalformedJournal,
            ProofError::WrongChain => Error::WrongChain,
            ProofError::UnknownCommittee => Error::UnknownCommittee,
            ProofError::AlreadyFinal => Error::AlreadyFinal,
        }
    }
}

/// What the client keeps of a final checkpoint.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub digest: BytesN<32>,
    pub state_root: BytesN<32>,
    pub state_height: u64,
    pub last_height: u64,
    pub timestamp_ms: u64,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Params,
    Latest,
    Committee(u64),
    Checkpoint(u64),
}

#[contracttype]
#[derive(Clone)]
struct StoredParams {
    image_id: BytesN<32>,
    chain_id: u64,
    genesis_hash: BytesN<32>,
}

#[contractevent]
pub struct CheckpointFinalized {
    #[topic]
    pub index: u64,
    #[topic]
    pub epoch: u64,
    pub digest: BytesN<32>,
    pub state_root: BytesN<32>,
    pub state_height: u64,
}

#[contractevent]
pub struct CommitteeHandedOver {
    #[topic]
    pub epoch: u64,
    pub root: BytesN<32>,
}

/// The BN254 host functions.
struct Host<'a>(&'a Env);

impl Bn254 for Host<'_> {
    fn g1_add(&self, a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]> {
        let bn = self.0.crypto().bn254();
        Some(bn.g1_add(&Bn254G1Affine::from_array(self.0, a), &Bn254G1Affine::from_array(self.0, b)).to_array())
    }

    fn g1_mul(&self, p: &[u8; 64], s: &[u8; 32]) -> Option<[u8; 64]> {
        let bn = self.0.crypto().bn254();
        let s = Bn254Fr::from_bytes(BytesN::from_array(self.0, s));
        Some(bn.g1_mul(&Bn254G1Affine::from_array(self.0, p), &s).to_array())
    }

    fn pairing4(&self, pairs: &[([u8; 64], [u8; 128]); 4]) -> Option<bool> {
        let mut g1s = Vec::new(self.0);
        let mut g2s = Vec::new(self.0);
        for (p, q) in pairs {
            g1s.push_back(Bn254G1Affine::from_array(self.0, p));
            g2s.push_back(Bn254G2Affine::from_array(self.0, q));
        }
        Some(self.0.crypto().bn254().pairing_check(g1s, g2s))
    }
}

/// The client's state in contract storage.
struct Ledger<'a>(&'a Env);

impl Store for Ledger<'_> {
    fn committee_root(&self, epoch: u64) -> Option<[u8; 32]> {
        let root: Option<BytesN<32>> = self.0.storage().persistent().get(&Key::Committee(epoch));
        root.map(|r| r.to_array())
    }

    fn set_committee_root(&mut self, epoch: u64, root: [u8; 32]) {
        let key = Key::Committee(epoch);
        let root = BytesN::from_array(self.0, &root);
        self.0.storage().persistent().set(&key, &root);
        self.0.storage().persistent().extend_ttl(&key, ENTRY_TTL, ENTRY_TTL);
        CommitteeHandedOver { epoch, root }.publish(self.0);
    }

    fn is_final(&self, index: u64) -> bool {
        self.0.storage().persistent().has(&Key::Checkpoint(index))
    }

    fn set_final(&mut self, j: &Journal) {
        let env = self.0;
        let checkpoint = Checkpoint {
            digest: BytesN::from_array(env, &j.checkpoint_digest),
            state_root: BytesN::from_array(env, &j.state_root),
            state_height: j.state_height,
            last_height: j.last_height,
            timestamp_ms: j.timestamp_ms,
        };
        let key = Key::Checkpoint(j.index);
        env.storage().persistent().set(&key, &checkpoint);
        env.storage().persistent().extend_ttl(&key, ENTRY_TTL, ENTRY_TTL);
        let latest: u64 = env.storage().instance().get(&Key::Latest).unwrap_or(0);
        if j.index > latest {
            env.storage().instance().set(&Key::Latest, &j.index);
        }
        CheckpointFinalized {
            index: j.index,
            epoch: j.epoch,
            digest: checkpoint.digest,
            state_root: checkpoint.state_root,
            state_height: j.state_height,
        }
        .publish(env);
    }
}

fn params(env: &Env) -> Params {
    let p: StoredParams = env.storage().instance().get(&Key::Params).expect("constructed");
    Params { image_id: p.image_id.to_array(), chain_id: p.chain_id, genesis_hash: p.genesis_hash.to_array() }
}

fn checkpoint(env: &Env, index: u64) -> Checkpoint {
    env.storage()
        .persistent()
        .get(&Key::Checkpoint(index))
        .unwrap_or_else(|| panic_with_error!(env, Error::UnknownCheckpoint))
}

#[contract]
pub struct FinalityClient;

#[contractimpl]
impl FinalityClient {
    /// A client of the chain `chain_id` with genesis `genesis_hash`, whose
    /// epoch-0 committee has root `genesis_committee_root`, accepting proofs
    /// of the finality program `image_id`.
    pub fn __constructor(
        env: Env,
        image_id: BytesN<32>,
        chain_id: u64,
        genesis_hash: BytesN<32>,
        genesis_committee_root: BytesN<32>,
    ) {
        env.storage().instance().set(&Key::Params, &StoredParams { image_id, chain_id, genesis_hash });
        env.storage().instance().extend_ttl(ENTRY_TTL, ENTRY_TTL);
        let key = Key::Committee(0);
        env.storage().persistent().set(&key, &genesis_committee_root);
        env.storage().persistent().extend_ttl(&key, ENTRY_TTL, ENTRY_TTL);
    }

    /// Accept the checkpoint `journal` states, proven by `seal`. Returns its
    /// index.
    pub fn submit(env: Env, journal: Bytes, seal: Bytes) -> Result<u64, Error> {
        let journal = to_vec::<{ tenzro_finality_verifier::JOURNAL_LEN }>(&journal).ok_or(Error::MalformedJournal)?;
        let seal = to_vec::<{ 4 + 8 * 32 }>(&seal).ok_or(Error::MalformedSeal)?;
        env.storage().instance().extend_ttl(ENTRY_TTL, ENTRY_TTL);
        let j = tenzro_finality_verifier::submit(&Host(&env), &params(&env), &mut Ledger(&env), &journal, &seal)?;
        Ok(j.index)
    }

    /// The state root of the final checkpoint `index`.
    pub fn state_root(env: Env, index: u64) -> BytesN<32> {
        checkpoint(&env, index).state_root
    }

    /// When the final checkpoint `index` was made, in milliseconds.
    pub fn timestamp_ms(env: Env, index: u64) -> u64 {
        checkpoint(&env, index).timestamp_ms
    }

    pub fn latest_index(env: Env) -> u64 {
        env.storage().instance().get(&Key::Latest).unwrap_or(0)
    }

    pub fn committee_root(env: Env, epoch: u64) -> Option<BytesN<32>> {
        env.storage().persistent().get(&Key::Committee(epoch))
    }
}

/// Copy `b` into a fixed array of exactly `N` bytes.
fn to_vec<const N: usize>(b: &Bytes) -> Option<[u8; N]> {
    if b.len() as usize != N {
        return None;
    }
    let mut out = [0u8; N];
    b.copy_into_slice(&mut out);
    Some(out)
}

#[cfg(test)]
mod test;
