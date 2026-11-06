// SPDX-License-Identifier: Apache-2.0
//! A light client of Tenzro for Cosmos chains, run by ibc-go's 08-wasm
//! module.
//!
//! The client follows Tenzro's checkpoints: a client message is a Tenzro
//! finality proof (the finality program's journal and its Groth16 seal),
//! accepted when the proof verifies for the governed finality program and
//! the journal names the committee the client holds for its epoch; a
//! checkpoint that ends an epoch hands over to the next committee. Each
//! accepted checkpoint becomes a consensus state at height
//! `(0, state_height)` holding Tenzro's state root, under which membership
//! and absence of entries of Tenzro's IBC store are proven with Tenzro state
//! proofs: the path is `[b"ibc", path]` (Tenzro's commitment prefix, then
//! the ICS-24 path or IBC v2 key), which names the committed entry
//! [`ibc_store_entry`], and the proof is the state proof of that entry as
//! Tenzro serves it (JSON).
//!
//! The client stores its client and consensus states where 08-wasm reads
//! them (`clientState`, `consensusStates/{revision}-{height}`), wrapped in
//! the 08-wasm protobuf types, with this client's own data (JSON) inside.

use cosmwasm_std::{
    Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Storage, entry_point, from_json, to_json_binary,
};
use serde::{Deserialize, Serialize};
use tenzro_finality_verifier::{Error as ProofError, JOURNAL_LEN, Journal, Params, Store};


/// An IBC height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Height {
    #[serde(default)]
    pub revision_number: u64,
    #[serde(default)]
    pub revision_height: u64,
}

/// A path into the counterparty's store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    pub key_path: Vec<Binary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantiateMessage {
    pub client_state: Binary,
    pub consensus_state: Binary,
    pub checksum: Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SudoMsg {
    UpdateState { client_message: Binary },
    UpdateStateOnMisbehaviour { client_message: Binary },
    VerifyUpgradeAndUpdateState {
        upgrade_client_state: Binary,
        upgrade_consensus_state: Binary,
        proof_upgrade_client: Binary,
        proof_upgrade_consensus_state: Binary,
    },
    VerifyMembership {
        height: Height,
        delay_time_period: u64,
        delay_block_period: u64,
        proof: Binary,
        merkle_path: MerklePath,
        value: Binary,
    },
    VerifyNonMembership {
        height: Height,
        delay_time_period: u64,
        delay_block_period: u64,
        proof: Binary,
        merkle_path: MerklePath,
    },
    MigrateClientStore {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Status {},
    TimestampAtHeight { height: Height },
    VerifyClientMessage { client_message: Binary },
    CheckForMisbehaviour { client_message: Binary },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampAtHeightResult {
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStateResult {
    pub heights: Vec<Height>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckForMisbehaviourResult {
    pub found_misbehaviour: bool,
}

/// This client's state: the finality program and Tenzro chain it follows,
/// the latest height it holds, and whether it is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientData {
    pub image_id: [u8; 32],
    pub chain_id: u64,
    pub genesis_hash: [u8; 32],
    pub genesis_committee_root: [u8; 32],
    pub latest_height: u64,
    pub latest_index: u64,
    pub frozen: bool,
}

/// What a consensus state holds: a final checkpoint's state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusData {
    pub index: u64,
    pub checkpoint_digest: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp_ms: u64,
}

// ---- protobuf, as 08-wasm stores client and consensus states ----

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn field_bytes(n: u32, b: &[u8], out: &mut Vec<u8>) {
    varint(u64::from(n << 3 | 2), out);
    varint(b.len() as u64, out);
    out.extend_from_slice(b);
}

fn field_u64(n: u32, v: u64, out: &mut Vec<u8>) {
    if v != 0 {
        varint(u64::from(n << 3), out);
        varint(v, out);
    }
}

fn any(type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    field_bytes(1, type_url.as_bytes(), &mut out);
    field_bytes(2, value, &mut out);
    out
}

fn wasm_client_state(data: &[u8], checksum: &[u8], latest_height: u64) -> Vec<u8> {
    let mut height = Vec::new();
    field_u64(2, latest_height, &mut height);
    let mut cs = Vec::new();
    field_bytes(1, data, &mut cs);
    field_bytes(2, checksum, &mut cs);
    field_bytes(3, &height, &mut cs);
    any("/ibc.lightclients.wasm.v1.ClientState", &cs)
}

fn wasm_consensus_state(data: &[u8]) -> Vec<u8> {
    let mut cs = Vec::new();
    field_bytes(1, data, &mut cs);
    any("/ibc.lightclients.wasm.v1.ConsensusState", &cs)
}

// ---- storage ----

const CLIENT_STATE: &[u8] = b"clientState";
const CHECKSUM: &[u8] = b"tenzro/checksum";
const CLIENT_DATA: &[u8] = b"tenzro/client";

fn consensus_key(height: u64) -> Vec<u8> {
    format!("consensusStates/0-{height}").into_bytes()
}

fn committee_key(epoch: u64) -> Vec<u8> {
    format!("tenzro/committee/{epoch}").into_bytes()
}

fn final_key(index: u64) -> Vec<u8> {
    format!("tenzro/final/{index}").into_bytes()
}

fn load_client(storage: &dyn Storage) -> StdResult<ClientData> {
    from_json(storage.get(CLIENT_DATA).ok_or_else(|| StdError::msg("the client is not instantiated"))?)
}

fn save_client(storage: &mut dyn Storage, c: &ClientData) -> StdResult<()> {
    let data = cosmwasm_std::to_json_vec(c)?;
    storage.set(CLIENT_DATA, &data);
    let checksum = storage.get(CHECKSUM).unwrap_or_default();
    storage.set(CLIENT_STATE, &wasm_client_state(&data, &checksum, c.latest_height));
    Ok(())
}

fn save_consensus(storage: &mut dyn Storage, height: u64, c: &ConsensusData) -> StdResult<()> {
    let data = cosmwasm_std::to_json_vec(c)?;
    storage.set(&consensus_key(height), &wasm_consensus_state(&data));
    storage.set(&[b"tenzro/consensus/".as_slice(), &height.to_be_bytes()].concat(), &data);
    Ok(())
}

fn load_consensus(storage: &dyn Storage, height: u64) -> StdResult<ConsensusData> {
    from_json(
        storage
            .get(&[b"tenzro/consensus/".as_slice(), &height.to_be_bytes()].concat())
            .ok_or_else(|| StdError::msg(format!("no consensus state at height {height}")))?,
    )
}

/// The finality client's store over the contract's storage.
struct ContractStore<'a> {
    storage: &'a mut dyn Storage,
}

impl Store for ContractStore<'_> {
    fn committee_root(&self, epoch: u64) -> Option<[u8; 32]> {
        self.storage.get(&committee_key(epoch)).and_then(|v| v.try_into().ok())
    }

    fn set_committee_root(&mut self, epoch: u64, root: [u8; 32]) {
        self.storage.set(&committee_key(epoch), &root);
    }

    fn is_final(&self, index: u64) -> bool {
        self.storage.get(&final_key(index)).is_some()
    }

    fn set_final(&mut self, j: &Journal) {
        self.storage.set(&final_key(j.index), &j.checkpoint_digest);
    }
}

/// A read-only view for checking a message without storing it.
struct ReadStore<'a>(&'a dyn Storage);

impl Store for ReadStore<'_> {
    fn committee_root(&self, epoch: u64) -> Option<[u8; 32]> {
        self.0.get(&committee_key(epoch)).and_then(|v| v.try_into().ok())
    }
    fn set_committee_root(&mut self, _: u64, _: [u8; 32]) {}
    fn is_final(&self, index: u64) -> bool {
        self.0.get(&final_key(index)).is_some()
    }
    fn set_final(&mut self, _: &Journal) {}
}

fn params(c: &ClientData) -> Params {
    Params { image_id: c.image_id, chain_id: c.chain_id, genesis_hash: c.genesis_hash }
}

fn split_message(m: &[u8]) -> StdResult<(&[u8], &[u8])> {
    if m.len() <= JOURNAL_LEN {
        return Err(StdError::msg("a client message is a journal and a seal"));
    }
    Ok(m.split_at(JOURNAL_LEN))
}

fn proof_err(e: ProofError) -> StdError {
    StdError::msg(format!("finality proof refused: {e:?}"))
}

#[entry_point]
pub fn instantiate(deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMessage) -> StdResult<Response> {
    let mut client: ClientData = from_json(&msg.client_state)?;
    let consensus: ConsensusData = from_json(&msg.consensus_state)?;
    client.frozen = false;
    deps.storage.set(CHECKSUM, &msg.checksum);
    deps.storage.set(&committee_key(0), &client.genesis_committee_root);
    save_client(deps.storage, &client)?;
    save_consensus(deps.storage, client.latest_height, &consensus)?;
    Ok(Response::new())
}

#[entry_point]
pub fn sudo(deps: DepsMut, _env: Env, msg: SudoMsg) -> StdResult<Response> {
    let mut client = load_client(deps.storage)?;
    match msg {
        SudoMsg::UpdateState { client_message } => {
            if client.frozen {
                return Err(StdError::msg("the client is frozen"));
            }
            let (journal, seal) = split_message(&client_message)?;
            let mut store = ContractStore { storage: deps.storage };
            let j = tenzro_finality_verifier::submit(&tenzro_finality_verifier::arkworks::Arkworks, &params(&client), &mut store, journal, seal)
                .map_err(proof_err)?;
            save_consensus(
                deps.storage,
                j.state_height,
                &ConsensusData { index: j.index, checkpoint_digest: j.checkpoint_digest, state_root: j.state_root, timestamp_ms: j.timestamp_ms },
            )?;
            if j.state_height > client.latest_height {
                client.latest_height = j.state_height;
                client.latest_index = j.index;
            }
            save_client(deps.storage, &client)?;
            let heights = vec![Height { revision_number: 0, revision_height: j.state_height }];
            Ok(Response::new().set_data(to_json_binary(&UpdateStateResult { heights })?))
        }
        SudoMsg::UpdateStateOnMisbehaviour { .. } => {
            client.frozen = true;
            save_client(deps.storage, &client)?;
            Ok(Response::new())
        }
        SudoMsg::VerifyMembership { height, proof, merkle_path, value, .. } => {
            verify_entry(deps.storage, &client, height, &proof, &merkle_path, Some(&value))?;
            Ok(Response::new())
        }
        SudoMsg::VerifyNonMembership { height, proof, merkle_path, .. } => {
            verify_entry(deps.storage, &client, height, &proof, &merkle_path, None)?;
            Ok(Response::new())
        }
        SudoMsg::VerifyUpgradeAndUpdateState { .. } => {
            Err(StdError::msg("Tenzro clients are not upgraded: a new finality program is a new client"))
        }
        SudoMsg::MigrateClientStore {} => Err(StdError::msg("this client's store does not migrate")),
    }
}

/// Tenzro's commitment prefix: the first element of every path proven here.
pub const IBC_PREFIX: &[u8] = b"ibc";

/// The state namespace Tenzro's IBC store lives in.
pub const STATE_NAMESPACE: &str = "state";

/// The account Tenzro's IBC store is kept under (the governed-state address).
const IBC_STORE_ACCOUNT: [u8; 20] = [0xff; 20];

fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(DIGITS[(byte >> 4) as usize] as char);
        s.push(DIGITS[(byte & 15) as usize] as char);
    }
    s
}

/// The key, in Tenzro's committed state, of its IBC store's entry at
/// `path`: route state entry `ibc/{hex(path)}` of the governed-state account.
pub fn ibc_store_entry(path: &[u8]) -> String {
    let entry = format!("ibc/{}", hex(path));
    format!("storage:{}:{}", hex(&IBC_STORE_ACCOUNT), hex(entry.as_bytes()))
}

fn verify_entry(
    storage: &dyn Storage,
    client: &ClientData,
    height: Height,
    proof: &[u8],
    path: &MerklePath,
    value: Option<&[u8]>,
) -> StdResult<()> {
    if client.frozen {
        return Err(StdError::msg("the client is frozen"));
    }
    if height.revision_number != 0 {
        return Err(StdError::msg("Tenzro heights have revision 0"));
    }
    let consensus = load_consensus(storage, height.revision_height)?;
    let [prefix, ibc_path] = path.key_path.as_slice() else {
        return Err(StdError::msg("a Tenzro path is [prefix, path]"));
    };
    if prefix.as_slice() != IBC_PREFIX {
        return Err(StdError::msg("Tenzro's commitment prefix is 'ibc'"));
    }
    let key = ibc_store_entry(ibc_path);
    if !tenzro_finality_verifier::state_proof::verify(&consensus.state_root, STATE_NAMESPACE, key.as_bytes(), value, proof) {
        return Err(StdError::msg("the state proof does not verify under the checkpoint's root"));
    }
    Ok(())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let client = load_client(deps.storage)?;
    match msg {
        QueryMsg::Status {} => to_json_binary(&StatusResult { status: if client.frozen { "Frozen" } else { "Active" }.into() }),
        QueryMsg::TimestampAtHeight { height } => {
            let c = load_consensus(deps.storage, height.revision_height)?;
            to_json_binary(&TimestampAtHeightResult { timestamp: c.timestamp_ms.saturating_mul(1_000_000) })
        }
        QueryMsg::VerifyClientMessage { client_message } => {
            let (journal, seal) = split_message(&client_message)?;
            tenzro_finality_verifier::check(&tenzro_finality_verifier::arkworks::Arkworks, &params(&client), &ReadStore(deps.storage), journal, seal)
                .map_err(proof_err)?;
            to_json_binary(&())
        }
        QueryMsg::CheckForMisbehaviour { client_message } => {
            // A proven checkpoint at an index that already holds another one
            // is misbehaviour of the committee that certified both.
            let (journal, seal) = split_message(&client_message)?;
            let j = tenzro_finality_verifier::check(&tenzro_finality_verifier::arkworks::Arkworks, &params(&client), &ReadStore(deps.storage), journal, seal)
                .map_err(proof_err)?;
            let found = deps.storage.get(&final_key(j.index)).is_some_and(|d| d.as_slice() != j.checkpoint_digest.as_slice());
            to_json_binary(&CheckForMisbehaviourResult { found_misbehaviour: found })
        }
    }
}

#[cfg(test)]
mod tests;
