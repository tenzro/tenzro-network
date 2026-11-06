//! Agent accounts on other chains, as relayers, agents and wallets read them.
//!
//! An agent's account on each chain is derived from its DID and the chain's
//! account deployment ([`tenzro_types::omni_account`]); its authority there
//! is the grant chain state holds for it ([`tenzro_types::remote_grant`]).
//! These handlers read consensus state only: the accounts, the grant and its
//! state proof under a certified root, and the digest an action on the chain
//! is signed over. Issuing a grant is an agent action
//! (`tenzro_requestRemoteGrant`), signed by the serving node like any other.

use std::sync::Arc;

use serde_json::Value;
use tenzro_storage::KvStore;
use tenzro_storage::kv::CF_STATE;
use tenzro_types::omni_account::{AgentAccountChain, Family, omni_address};
use tenzro_types::remote_grant::{
    RemoteAction, RemoteGrant, act_digest, key_leaves, merkle_proof, payload_hash, state_tree_key,
    target_leaf,
};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn str_param<'a>(params: &'a Value, name: &str) -> Result<&'a str, JsonRpcError> {
    params
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err(-32602, format!("missing '{name}'")))
}

/// What a chain's accounts support, stated with the account.
fn support(chain: &AgentAccountChain) -> &'static str {
    match Family::of(&chain.caip2) {
        Some(Family::Aptos) => "exact grants only: each action is granted on its own",
        Some(Family::Tvm) => "open and exact grants, finality checked over BLS12-381",
        Some(_) => "open and exact grants",
        None => "unsupported",
    }
}

/// Every chain agents hold accounts on, in key order.
pub(crate) fn account_chains(node: &Arc<TenzroNode>) -> Vec<AgentAccountChain> {
    let Some(storage) = node.storage() else {
        return Vec::new();
    };
    chains_in(storage.as_ref())
}

/// The agent account chains installed in the VM state `storage` holds.
pub(crate) fn chains_in(storage: &dyn KvStore) -> Vec<AgentAccountChain> {
    let prefix = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(b"agent_account_chain:")
    );
    storage
        .scan_prefix(CF_STATE, prefix.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

/// `tenzro_agentAccounts`: the agent's account on every configured chain, as
/// CAIP-10 and ERC-7930, with the chain's status and the live grant.
pub(crate) async fn agent_accounts(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let did = str_param(&params, "did")?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let accounts: Vec<Value> = account_chains(node)
        .iter()
        .map(|c| {
            let address = omni_address(did, &c.caip2, &c.deployment);
            let grant = tenzro_vm::native::remote_grant::read_grant(&chain, did, &c.caip2);
            serde_json::json!({
                "chain": c.caip2,
                "status": if c.open { "open" } else { "closed" },
                "supports": support(c),
                "reports_proven": c.report_route.is_some(),
                "address": address.as_ref().ok().map(|a| a.address.clone()),
                "caip10": address.as_ref().ok().map(|a| a.caip10()),
                "erc7930": address.as_ref().ok().and_then(|a| a.erc7930()).map(hex::encode),
                "error": address.as_ref().err().map(|e| e.to_string()),
                "grant": grant.map(|g| grant_json(&g)),
            })
        })
        .collect();
    Ok(serde_json::json!({ "did": did, "accounts": accounts }))
}

fn grant_json(g: &RemoteGrant) -> Value {
    serde_json::json!({
        "seq": g.seq,
        "void": g.void,
        "not_before_ms": g.not_before_ms,
        "not_after_ms": g.not_after_ms,
        "budget": g.budget.to_string(),
        "per_action_max": g.per_action_max.to_string(),
        "cosign_above": g.cosign_above.to_string(),
        "relay_fee_max": g.relay_fee_max.to_string(),
        "exact": g.is_exact(),
        "terms_version": g.terms_version,
        "keys_root": hex::encode(g.keys_root),
        "targets_root": hex::encode(g.targets_root),
    })
}

/// `tenzro_requestRemoteGrant`: the agent asks its serving node to issue a
/// grant on another chain. The node fills in the share of the daily spend
/// the budget uses and signs the `remote_grant` action like any other.
pub(crate) async fn request_remote_grant(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let caip2 = str_param(&params, "chain")?.to_string();
    let request: tenzro_types::remote_grant::RemoteGrantRequest = serde_json::from_value(
        params
            .get("grant")
            .cloned()
            .ok_or_else(|| err(-32602, "missing 'grant'"))?,
    )
    .map_err(|e| err(-32602, format!("grant: {e}")))?;
    let mut act = serde_json::json!({
        "operation": tenzro_types::remote_grant::OP_REMOTE_GRANT,
        "chain": caip2,
        "remote_grant": request,
    });
    if let Some(step_up) = params.get("step_up") {
        act["step_up"] = step_up.clone();
    }
    crate::agent_delegation::handle_agent_act(node, caller, Some(act)).await
}

/// The state height a proof is made at: the given checkpoint's, or the
/// latest certified one's.
fn certified_height(node: &Arc<TenzroNode>, params: &Value) -> Result<(u64, u64), JsonRpcError> {
    let consensus = node
        .consensus()
        .ok_or_else(|| err(-32603, "consensus is not running"))?;
    let cp = match params.get("checkpoint").and_then(Value::as_u64) {
        Some(i) => consensus
            .checkpoint(i)
            .ok_or_else(|| err(-32004, format!("no checkpoint {i}")))?,
        None => consensus
            .latest_certificate()
            .map(|c| c.checkpoint)
            .ok_or_else(|| err(-32004, "no checkpoint is certified yet"))?,
    };
    Ok((cp.index, cp.state_height))
}

/// `tenzro_getAgentGrantProof`: the grant of `did` on `chain` and its state
/// proof under the state root a certified checkpoint carries, which the
/// account's `sync` checks against the chain's finality client.
pub(crate) async fn get_agent_grant_proof(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let did = str_param(&params, "did")?;
    let caip2 = str_param(&params, "chain")?;
    let (index, height) = certified_height(node, &params)?;
    let storage = node
        .storage()
        .ok_or_else(|| err(-32603, "storage not initialised"))?;
    let trie = tenzro_storage::StateTrie::new(storage.clone() as Arc<dyn tenzro_storage::KvStore>);
    let root = trie
        .root_at(height)
        .map_err(|e| err(-32603, format!("state trie: {e}")))?
        .ok_or_else(|| err(-32004, format!("no committed state at height {height}")))?;
    let key = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(tenzro_types::remote_grant::leaf_key(did, caip2).as_bytes())
    );
    let (value, proof) = trie
        .prove(height, CF_STATE, key.as_bytes())
        .map_err(|e| err(-32603, format!("prove: {e}")))?;
    let grant = value.as_deref().and_then(|v| RemoteGrant::decode(v).ok());
    Ok(serde_json::json!({
        "did": did,
        "chain": caip2,
        "checkpoint": index,
        "height": height,
        "state_root": root.to_string(),
        "tree_key": hex::encode(state_tree_key(did, caip2)),
        "grant_bytes": value.map(hex::encode),
        "grant": grant.as_ref().map(grant_json),
        "proof": proof,
        "proof_bytes": hex::encode(proof.encode()),
        "revocation": "a void reaches the chain when relayed; until then the account stops at the grant's not_after_ms",
    }))
}

/// `tenzro_buildRemoteAction`: the digest serving nodes sign for one action
/// of the agent's account on `chain`, and the proofs the account checks:
/// each serving node's key leaf and, for an open grant with targets, the
/// target's.
pub(crate) async fn build_remote_action(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let did = str_param(&params, "did")?;
    let caip2 = str_param(&params, "chain")?;
    let nonce = params
        .get("nonce")
        .and_then(Value::as_u64)
        .ok_or_else(|| err(-32602, "missing 'nonce' (the account's next action nonce)"))?;
    let action: RemoteAction = serde_json::from_value(
        params
            .get("action")
            .cloned()
            .ok_or_else(|| err(-32602, "missing 'action'"))?,
    )
    .map_err(|e| err(-32602, format!("action: {e}")))?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let config = tenzro_vm::native::remote_grant::read_account_chain(&chain, caip2)
        .ok_or_else(|| err(-32004, format!("{caip2} has no agent accounts")))?;
    let account =
        omni_address(did, caip2, &config.deployment).map_err(|e| err(-32602, e.to_string()))?;
    let grant = tenzro_vm::native::remote_grant::read_grant(&chain, did, caip2)
        .ok_or_else(|| err(-32004, format!("{did} holds no grant on {caip2}")))?;
    let terms = tenzro_vm::native::read_agent_terms(&chain, did)
        .ok_or_else(|| err(-32004, "no terms on chain"))?;
    let leaves = key_leaves(&terms.terms.serving_nodes)
        .ok_or_else(|| err(-32603, "a serving node key is malformed"))?;
    let keys: Vec<Value> = terms
        .terms
        .serving_nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            serde_json::json!({
                "machine_did": n.machine_did,
                "operator_did": n.operator_did,
                "public_key": format!("04{}", n.dpop_public_key),
                "proof": merkle_proof(&leaves, i).iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();
    let target_proof = tenzro_vm::native::remote_grant::read_grant_issue(
        &chain, did, caip2, grant.seq,
    )
    .and_then(|issue| {
        let leaves: Vec<[u8; 32]> = issue
            .targets
            .iter()
            .map(|t| target_leaf(&t.target, &t.selector))
            .collect();
        let at = leaves
            .iter()
            .position(|l| *l == target_leaf(&action.target, &action.selector))?;
        Some(
            merkle_proof(&leaves, at)
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        )
    });
    Ok(serde_json::json!({
        "did": did,
        "chain": caip2,
        "account": account.address,
        "seq": grant.seq,
        "nonce": nonce,
        "action": hex::encode(action.encode()),
        "digest": hex::encode(act_digest(&grant.chain, &grant.account, grant.seq, nonce, &action)),
        "payload_hash": hex::encode(payload_hash(&action)),
        "needs_cosign": action.amount > grant.cosign_above,
        "keys": keys,
        "target_proof": target_proof,
    }))
}

fn eth_address_param(params: &Value, name: &str) -> Result<[u8; 20], JsonRpcError> {
    let s = str_param(params, name)?;
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 20]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(-32602, format!("'{name}' is a 20-byte hex address")))
}

/// `tenzro_agentWalletConsent`: the consent that makes `did`'s account on an
/// EVM chain the `agentWallet` of its ERC-8004 entry there. The account
/// consents by approving the registry's EIP-712 `AgentWalletSet` digest as
/// its ERC-1271 signature, an `approveHash` action on itself under its live
/// grant (signed like any action: `tenzro_buildRemoteAction`, then
/// `tenzro_signRemoteAction`). The entry's owner then calls
/// `setAgentWallet` with an empty signature, and the registry asks the
/// account. The consent ends with the grant it was approved under.
pub(crate) async fn agent_wallet_consent(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_identity::erc8004::{abi, addresses, consent, selectors};
    let params = crate::rpc::unwrap_param_object(params);
    let did = str_param(&params, "did")?;
    let caip2 = str_param(&params, "chain")?;
    let chain_id: u64 = caip2
        .strip_prefix("eip155:")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| {
            err(
                -32602,
                "an ERC-8004 agent wallet is on an EVM chain (eip155:<id>)",
            )
        })?;
    let agent_id = params
        .get("agent_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| err(-32602, "missing 'agent_id'"))?;
    let owner = eth_address_param(&params, "owner")?;
    let deadline = params
        .get("deadline")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                -32602,
                "missing 'deadline' (unix seconds, at most 300 s ahead when submitted)",
            )
        })?;
    let registry = match params.get("registry").filter(|v| !v.is_null()) {
        Some(_) => eth_address_param(&params, "registry")?,
        None => addresses::IDENTITY_REGISTRY,
    };
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let config = tenzro_vm::native::remote_grant::read_account_chain(&chain, caip2)
        .ok_or_else(|| err(-32004, format!("{caip2} has no agent accounts")))?;
    let account =
        omni_address(did, caip2, &config.deployment).map_err(|e| err(-32602, e.to_string()))?;
    let wallet: [u8; 20] = hex::decode(account.address.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err(-32603, "an EVM account address is 20 bytes"))?;
    let digest =
        consent::agent_wallet_set_digest(chain_id, &registry, agent_id, &wallet, &owner, deadline);
    let action = RemoteAction {
        target: wallet.to_vec(),
        selector: consent::APPROVE_HASH_SELECTOR.to_vec(),
        amount: 0,
        relay_refund: 0,
        data: digest.to_vec(),
    };
    Ok(serde_json::json!({
        "did": did,
        "chain": caip2,
        "account": account.address,
        "registry": format!("0x{}", hex::encode(registry)),
        "agent_id": agent_id,
        "owner": format!("0x{}", hex::encode(owner)),
        "deadline": deadline,
        "digest": hex::encode(digest),
        "action": action,
        "set_agent_wallet_calldata": format!(
            "0x{}",
            hex::encode(abi::encode_set_agent_wallet(
                selectors::SET_AGENT_WALLET,
                agent_id,
                &wallet,
                u128::from(deadline),
                &[]
            ))
        ),
    }))
}

/// The `verificationMethod` entries naming `did`'s accounts on other chains,
/// one per configured chain, for its DID document.
pub(crate) fn did_document_accounts(node: &Arc<TenzroNode>, did: &str) -> Vec<Value> {
    tenzro_types::did_derivation::blockchain_account_ids(did, &account_chains(node))
        .into_iter()
        .enumerate()
        .map(|(i, caip10)| {
            serde_json::json!({
                "id": format!("{did}#account-{i}"),
                "type": "BlockchainVerificationMethod2021",
                "controller": did,
                "blockchainAccountId": caip10,
            })
        })
        .collect()
}

/// Add `did`'s accounts on other chains to its DID document.
pub(crate) fn add_accounts_to_did_document(node: &Arc<TenzroNode>, did: &str, doc: &mut Value) {
    let accounts = did_document_accounts(node, did);
    if accounts.is_empty() {
        return;
    }
    if let Some(methods) = doc
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
    {
        methods.extend(accounts);
    } else if let Some(obj) = doc.as_object_mut() {
        obj.insert("verificationMethod".into(), Value::Array(accounts));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_string_parameter_must_be_present_and_not_empty() {
        let p = json!({"did": "d", "empty": "", "number": 3});
        assert_eq!(str_param(&p, "did").unwrap(), "d");
        for name in ["empty", "number", "absent"] {
            let e = str_param(&p, name).unwrap_err();
            assert_eq!((e.code, e.message), (-32602, format!("missing '{name}'")));
        }
    }

    #[test]
    fn an_evm_address_parameter_is_twenty_bytes_of_hex() {
        let ok = format!("0x{}", "ab".repeat(20));
        assert_eq!(
            eth_address_param(&json!({"owner": ok}), "owner").unwrap(),
            [0xab; 20]
        );
        assert!(eth_address_param(&json!({"owner": "ab".repeat(20)}), "owner").is_ok());
        for bad in ["ab".repeat(19), "ab".repeat(21), "zz".repeat(20), String::new()] {
            let e = eth_address_param(&json!({"owner": bad}), "owner").unwrap_err();
            assert_eq!(e.code, -32602);
        }
    }

    #[test]
    fn chains_are_read_from_state_and_a_record_that_does_not_parse_is_skipped() {
        let store = tenzro_storage::MemoryStore::new();
        assert!(chains_in(&store).is_empty());
        let prefix = format!(
            "storage:{}:{}",
            hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
            hex::encode(b"agent_account_chain:")
        );
        store
            .put(CF_STATE, format!("{prefix}eip155:1").as_bytes(), b"not json")
            .unwrap();
        store
            .put(CF_STATE, b"storage:other:key", b"{}")
            .unwrap();
        assert!(chains_in(&store).is_empty());
    }

    #[tokio::test]
    async fn a_node_that_is_not_running_has_no_account_chains_and_no_document_entries() {
        let (node, _tmp) = crate::bare_node().await;
        assert!(account_chains(&node).is_empty());
        assert!(did_document_accounts(&node, "did:tenzro:agent:a").is_empty());
        let mut doc = json!({"id": "did:tenzro:agent:a"});
        add_accounts_to_did_document(&node, "did:tenzro:agent:a", &mut doc);
        assert_eq!(doc, json!({"id": "did:tenzro:agent:a"}), "nothing is added");
    }

    #[tokio::test]
    async fn the_account_reads_need_a_did_a_chain_and_chain_state() {
        let (node, _tmp) = crate::bare_node().await;
        let e = agent_accounts(&node, None).await.unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-32602, "missing 'did'"));
        let e = agent_accounts(&node, Some(json!({"did": "d"}))).await.unwrap_err();
        assert_eq!(e.code, -32603);

        let e = get_agent_grant_proof(&node, Some(json!({"did": "d"}))).await.unwrap_err();
        assert_eq!(e.message, "missing 'chain'");
        let e = get_agent_grant_proof(&node, Some(json!({"did": "d", "chain": "eip155:1"})))
            .await
            .unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-32603, "consensus is not running"));
    }

    #[tokio::test]
    async fn a_remote_grant_request_needs_a_chain_and_a_parsable_grant() {
        let (node, _tmp) = crate::bare_node().await;
        let e = request_remote_grant(&node, None, Some(json!({}))).await.unwrap_err();
        assert_eq!(e.message, "missing 'chain'");
        let e = request_remote_grant(&node, None, Some(json!({"chain": "eip155:1"})))
            .await
            .unwrap_err();
        assert_eq!(e.message, "missing 'grant'");
        let e = request_remote_grant(
            &node,
            None,
            Some(json!({"chain": "eip155:1", "grant": {"budget": "not a grant"}})),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, -32602);
        assert!(e.message.starts_with("grant:"), "{}", e.message);
    }

    #[tokio::test]
    async fn building_a_remote_action_needs_the_nonce_the_action_and_chain_state() {
        let (node, _tmp) = crate::bare_node().await;
        let base = json!({"did": "d", "chain": "eip155:1"});
        let with = |k: &str, v: Value| {
            let mut p = base.clone();
            p[k] = v;
            p
        };
        let e = build_remote_action(&node, Some(base.clone())).await.unwrap_err();
        assert!(e.message.contains("'nonce'"), "{}", e.message);
        let e = build_remote_action(&node, Some(with("nonce", json!(1)))).await.unwrap_err();
        assert_eq!(e.message, "missing 'action'");
        let mut p = with("nonce", json!(1));
        p["action"] = json!({"target": "zz"});
        let e = build_remote_action(&node, Some(p)).await.unwrap_err();
        assert!(e.message.starts_with("action:"), "{}", e.message);
        let mut p = with("nonce", json!(1));
        p["action"] = json!({
            "target": "00", "selector": "00", "amount": "1", "relay_refund": "0", "data": ""
        });
        let e = build_remote_action(&node, Some(p)).await.unwrap_err();
        assert_eq!(e.code, -32603, "no chain state on a node that is not running");
    }

    #[tokio::test]
    async fn the_wallet_consent_refuses_each_malformed_parameter() {
        let (node, _tmp) = crate::bare_node().await;
        let owner = format!("0x{}", "11".repeat(20));
        let ok = json!({
            "did": "d", "chain": "eip155:8453", "agent_id": 7, "owner": owner, "deadline": 99
        });
        let without = |k: &str| {
            let mut p = ok.clone();
            p.as_object_mut().unwrap().remove(k);
            p
        };
        let e = agent_wallet_consent(&node, Some(json!({"did": "d", "chain": "solana:main"})))
            .await
            .unwrap_err();
        assert!(e.message.contains("EVM chain"), "{}", e.message);
        assert_eq!(
            agent_wallet_consent(&node, Some(without("agent_id"))).await.unwrap_err().message,
            "missing 'agent_id'"
        );
        let e = agent_wallet_consent(&node, Some(without("owner"))).await.unwrap_err();
        assert!(e.message.contains("'owner'"), "{}", e.message);
        let mut bad = ok.clone();
        bad["owner"] = json!("0x1234");
        assert_eq!(agent_wallet_consent(&node, Some(bad)).await.unwrap_err().code, -32602);
        let e = agent_wallet_consent(&node, Some(without("deadline"))).await.unwrap_err();
        assert!(e.message.contains("'deadline'"), "{}", e.message);
        let mut bad = ok.clone();
        bad["registry"] = json!("0x12");
        assert_eq!(agent_wallet_consent(&node, Some(bad)).await.unwrap_err().code, -32602);
        let e = agent_wallet_consent(&node, Some(ok)).await.unwrap_err();
        assert_eq!(e.code, -32603, "no chain state on a node that is not running");
    }
}
