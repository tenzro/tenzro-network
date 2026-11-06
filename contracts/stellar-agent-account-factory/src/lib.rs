// SPDX-License-Identifier: Apache-2.0
//! Deploys Tenzro agent accounts on Stellar.
//!
//! The account of an agent is the contract this factory deploys with the
//! salt `sha256("tenzro/omni-account/v1" || did)`, so its address follows from
//! the factory, the network and the DID alone. Anyone may deploy it; the
//! account is built with the DID, the chain and the finality client the
//! factory was built with.
#![no_std]

use soroban_sdk::{Address, Bytes, BytesN, Env, contract, contractimpl, contracttype};

#[contracttype]
#[derive(Clone)]
enum Key {
    Wasm,
    Chain,
    Client,
}

fn salt(env: &Env, did: &Bytes) -> BytesN<32> {
    let mut b = Bytes::from_slice(env, b"tenzro/omni-account/v1");
    b.append(did);
    env.crypto().sha256(&b).to_bytes()
}

#[contract]
pub struct AgentAccountFactory;

#[contractimpl]
impl AgentAccountFactory {
    /// A factory of accounts built from the code `account_wasm`, on the chain
    /// `caip2`, reading final state roots from `client`.
    pub fn __constructor(env: Env, account_wasm: BytesN<32>, caip2: Bytes, client: Address) {
        env.storage().instance().set(&Key::Wasm, &account_wasm);
        env.storage().instance().set(&Key::Chain, &caip2);
        env.storage().instance().set(&Key::Client, &client);
        env.storage().instance().extend_ttl(518_400, 518_400);
    }

    /// Where the account of `did` is, deployed or not.
    pub fn account_of(env: Env, did: Bytes) -> Address {
        env.deployer().with_current_contract(salt(&env, &did)).deployed_address()
    }

    /// Deploy the account of `did`. Anyone may.
    pub fn deploy(env: Env, did: Bytes) -> Address {
        let wasm: BytesN<32> = env.storage().instance().get(&Key::Wasm).expect("constructed");
        let caip2: Bytes = env.storage().instance().get(&Key::Chain).expect("constructed");
        let client: Address = env.storage().instance().get(&Key::Client).expect("constructed");
        env.deployer().with_current_contract(salt(&env, &did)).deploy_v2(wasm, (did, caip2, client))
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger as _};

    const DID: &[u8] = b"did:tenzro:machine:vectors:agent";
    const VECTORS: &str = include_str!("../../../sdk/fixtures/remote_grant/vectors.json");

    fn sha(b: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(b).into()
    }

    #[test]
    fn an_account_lands_where_tenzro_derives_it() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        env.ledger().set_network_id(sha(b"Public Global Stellar Network ; September 2015"));
        let wasm = std::fs::read(std::env::var("AGENT_ACCOUNT_WASM").expect("AGENT_ACCOUNT_WASM names the account's wasm")).unwrap();
        let hash = env.deployer().upload_contract_wasm(Bytes::from_slice(&env, &wasm));
        // The factory at the address the shared vectors deploy from.
        let factory_id = Address::from_payload(
            &env,
            soroban_sdk::address_payload::AddressPayload::ContractIdHash(BytesN::from_array(&env, &[0x66; 32])),
        );
        let client = Address::generate(&env);
        env.register_at(&factory_id, AgentAccountFactory, (hash, Bytes::from_slice(&env, b"stellar:pubnet"), client));
        let f = AgentAccountFactoryClient::new(&env, &factory_id);
        let did = Bytes::from_slice(&env, DID);
        let at = f.account_of(&did);
        assert_eq!(f.deploy(&did), at);
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let c = v["chains"].as_array().unwrap().iter().find(|c| c["chain"] == "stellar:pubnet").unwrap();
        let s = at.to_string();
        let mut b = [0u8; 56];
        s.copy_into_slice(&mut b);
        assert_eq!(core::str::from_utf8(&b).unwrap(), c["account"].as_str().unwrap());
    }
}
