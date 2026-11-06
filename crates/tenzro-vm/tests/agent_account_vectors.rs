//! The shared vectors every chain's agent account is tested against: grants
//! as the VM stores them, their state proofs under real state-trie roots,
//! the digests serving nodes sign, signatures by test keys, the key and
//! target proofs, and each family's derived account address.
//!
//! The test regenerates the vectors and checks them against the files in
//! `sdk/fixtures`; run it with `TENZRO_WRITE_FIXTURES=1` to rewrite them.

use std::sync::Arc;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::{Value, json};
use tenzro_storage::state_trie::capture::Writes;
use tenzro_storage::{MemoryStore, StateTrie};
use tenzro_types::omni_account::{AccountDeployment, omni_address, salt};
use tenzro_types::remote_grant::{
    RemoteAction, RemoteGrant, act_digest, agent_hash, asset_hash, chain_hash, key_leaf, leaf_key,
    merkle_proof, merkle_root, payload_hash, state_tree_key, target_leaf,
};

const DID: &str = "did:tenzro:machine:vectors:agent";
const OTHER: &str = "did:tenzro:machine:vectors:other";
const T0: u64 = 1_800_000_000_000;

/// Test-only serving node keys (fixed scalars) and their operators. The
/// third node shares the first one's operator.
fn nodes() -> Vec<(SigningKey, &'static str)> {
    vec![
        (
            SigningKey::from_slice(&[0x11; 32]).unwrap(),
            "did:tenzro:human:operator-a",
        ),
        (
            SigningKey::from_slice(&[0x22; 32]).unwrap(),
            "did:tenzro:human:operator-b",
        ),
        (
            SigningKey::from_slice(&[0x33; 32]).unwrap(),
            "did:tenzro:human:operator-a",
        ),
    ]
}

fn sec1(k: &SigningKey) -> [u8; 65] {
    k.verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// The chains, their deployments in these vectors, and the asset and two
/// targets each grant names.
fn chains() -> Vec<(
    &'static str,
    AccountDeployment,
    &'static str,
    [(Vec<u8>, Vec<u8>); 2],
)> {
    let aptos_asset = || -> &'static str {
        Box::leak(format!("aptos:1/fa:0x{}", hex::encode(aptos_named(b"TUSD"))).into_boxed_str())
    };
    let t = |a: &[u8], s: &[u8]| (a.to_vec(), s.to_vec());
    vec![
        (
            "eip155:8453",
            AccountDeployment::Eip155 {
                factory: [0x42; 20],
                init_code_hash: [0x24; 32],
            },
            "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            [
                t(&[0xaa; 20], &[0xa9, 0x05, 0x9c, 0xbb]),
                t(&[0xbb; 20], &[0x09, 0x5e, 0xa7, 0xb3]),
            ],
        ),
        (
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            AccountDeployment::Solana {
                program_id: [0x07; 32],
            },
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            [t(&[0xaa; 32], &[3]), t(&[0xbb; 32], &[12])],
        ),
        (
            "sui:mainnet",
            // The registry a fresh Sui test scenario creates first.
            AccountDeployment::Sui {
                registry: hex::decode(
                    "d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
            "sui:mainnet/coin:0000000000000000000000000000000000000000000000000000000000000002::sui::SUI",
            [
                t(&[0xaa; 32], b"pay::split_and_transfer"),
                t(&[0xbb; 32], b"coin::join"),
            ],
        ),
        (
            "aptos:1",
            // The registry object Aptos tests publish at 0xcafe.
            AccountDeployment::Aptos {
                creator: aptos_registry(),
            },
            aptos_asset(),
            [
                t(&[0xaa; 32], b"aptos_account::transfer"),
                t(&[0xbb; 32], b"coin::transfer"),
            ],
        ),
        (
            "stellar:pubnet",
            AccountDeployment::Stellar {
                network_passphrase: "Public Global Stellar Network ; September 2015".into(),
                factory: [0x66; 32],
            },
            "stellar:pubnet/sep41:CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75",
            [t(&[0xaa; 32], b"transfer"), t(&[0xbb; 32], b"approve")],
        ),
        (
            "cosmos:cosmoshub-4",
            AccountDeployment::Cosmos {
                hrp: "cosmos".into(),
                factory: vec![0x77; 32],
                code_checksum: [0x88; 32],
            },
            "cosmos:cosmoshub-4/bank:uatom",
            [t(&[0xaa; 32], b"bank_send"), t(&[0xbb; 32], b"transfer")],
        ),
        (
            "tvm:-239",
            AccountDeployment::Tvm {
                workchain: 0,
                code_hash: [0x99; 32],
                code_depth: 1,
            },
            "tvm:-239/slip44:607",
            [
                t(&[0xaa; 32], &[0x0f, 0x8a, 0x7e, 0xa5]),
                t(&[0xbb; 32], &[0x59, 0x5f, 0x07, 0xbc]),
            ],
        ),
    ]
}

/// The named object `seed` of the address `0xcafe`.
fn aptos_named(seed: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut publisher = [0u8; 32];
    publisher[30] = 0xca;
    publisher[31] = 0xfe;
    let mut h = Sha3_256::new();
    h.update(publisher);
    h.update(seed);
    h.update([0xfe]);
    h.finalize().into()
}

/// The registry Aptos tests publish at `0xcafe`.
fn aptos_registry() -> [u8; 32] {
    aptos_named(b"tenzro/agent-registry")
}

fn sign(k: &SigningKey, digest: &[u8; 32]) -> (String, String) {
    let sig: p256::ecdsa::Signature = k.sign_prehash(digest).unwrap();
    let low = sig.normalize_s();
    // The high-S twin of the same signature.
    let (r, s) = low.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    (hex::encode(low.to_bytes()), hex::encode(high.to_bytes()))
}

fn grant(
    caip2: &str,
    account: [u8; 32],
    asset: &str,
    seq: u64,
    void: bool,
    exact: Option<[u8; 32]>,
    keys_root: [u8; 32],
    targets_root: [u8; 32],
) -> RemoteGrant {
    RemoteGrant {
        chain: chain_hash(caip2),
        account,
        agent: agent_hash(DID),
        terms_version: 1,
        seq,
        not_before_ms: T0,
        not_after_ms: T0 + 600_000,
        asset: asset_hash(asset),
        budget: 1_000,
        per_action_max: 400,
        cosign_above: 300,
        keys_root,
        targets_root: if exact.is_some() {
            [0u8; 32]
        } else {
            targets_root
        },
        payload_hash: exact.unwrap_or([0u8; 32]),
        relay_fee_max: 10,
        void,
    }
}

fn grant_json(g: &RemoteGrant) -> Value {
    json!({
        "bytes": hex::encode(g.encode()),
        "chain": hex::encode(g.chain),
        "account": hex::encode(g.account),
        "agent": hex::encode(g.agent),
        "terms_version": g.terms_version,
        "seq": g.seq,
        "not_before_ms": g.not_before_ms,
        "not_after_ms": g.not_after_ms,
        "asset": hex::encode(g.asset),
        "budget": g.budget.to_string(),
        "per_action_max": g.per_action_max.to_string(),
        "cosign_above": g.cosign_above.to_string(),
        "keys_root": hex::encode(g.keys_root),
        "targets_root": hex::encode(g.targets_root),
        "payload_hash": hex::encode(g.payload_hash),
        "relay_fee_max": g.relay_fee_max.to_string(),
        "void": g.void,
    })
}

fn system_key(did: &str, caip2: &str) -> Vec<u8> {
    format!(
        "storage:{}:{}",
        hex::encode([0xFFu8; 20]),
        hex::encode(leaf_key(did, caip2).as_bytes())
    )
    .into_bytes()
}

fn action_json(a: &RemoteAction) -> Value {
    json!({
        "target": hex::encode(&a.target),
        "selector": hex::encode(&a.selector),
        "amount": a.amount.to_string(),
        "relay_refund": a.relay_refund.to_string(),
        "data": hex::encode(&a.data),
        "encoded": hex::encode(a.encode()),
    })
}

fn vectors() -> (Value, Value) {
    let nodes = nodes();
    let leaves: Vec<[u8; 32]> = nodes.iter().map(|(k, op)| key_leaf(&sec1(k), op)).collect();
    let keys_root = merkle_root(&leaves);
    let keys: Vec<Value> = nodes
        .iter()
        .enumerate()
        .map(|(i, (k, op))| {
            json!({
                "public_key": hex::encode(sec1(k)),
                "operator_did": op,
                "leaf": hex::encode(leaves[i]),
                "proof": merkle_proof(&leaves, i).iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();

    let store = Arc::new(MemoryStore::new());
    let trie = StateTrie::new(store);
    let mut v1 = Writes::new();
    let mut v2 = Writes::new();
    // Other state around the grants, so proofs have real paths.
    for i in 0..64u32 {
        v1.insert(
            ("state".into(), format!("storage:filler:{i}").into_bytes()),
            Some(i.to_be_bytes().to_vec()),
        );
    }
    let mut per_chain = Vec::new();
    for (caip2, deployment, asset, targets) in chains() {
        let account = omni_address(DID, caip2, &deployment).unwrap();
        let target_leaves: Vec<[u8; 32]> = targets.iter().map(|(t, s)| target_leaf(t, s)).collect();
        let targets_root = merkle_root(&target_leaves);
        let open_action = RemoteAction {
            target: targets[0].0.clone(),
            selector: targets[0].1.clone(),
            amount: 100,
            relay_refund: 5,
            data: vec![0x01, 0x02, 0x03],
        };
        let exact = caip2
            .starts_with("aptos:")
            .then(|| payload_hash(&open_action));
        let g1 = grant(
            caip2,
            account.account_word(),
            asset,
            1,
            false,
            exact,
            keys_root,
            targets_root,
        );
        let mut g2 = g1.clone();
        g2.seq = 2;
        g2.void = true;
        v1.insert(("state".into(), system_key(DID, caip2)), Some(g1.encode()));
        v2.insert(("state".into(), system_key(DID, caip2)), Some(g2.encode()));
        let big_action = RemoteAction {
            amount: 350,
            ..open_action.clone()
        };
        let other_target = RemoteAction {
            target: vec![0xcc; targets[0].0.len()],
            ..open_action.clone()
        };
        let d_open = act_digest(&g1.chain, &g1.account, 1, 0, &open_action);
        let d_big = act_digest(&g1.chain, &g1.account, 1, 0, &big_action);
        let d_other = act_digest(&g1.chain, &g1.account, 1, 0, &other_target);
        let (s0, s0_high) = sign(&nodes[0].0, &d_open);
        let (b0, _) = sign(&nodes[0].0, &d_big);
        let (b1, _) = sign(&nodes[1].0, &d_big);
        let (b2, _) = sign(&nodes[2].0, &d_big);
        let (o0, _) = sign(&nodes[0].0, &d_other);
        let over = RemoteAction {
            amount: 401,
            ..open_action.clone()
        };
        let d_over = act_digest(&g1.chain, &g1.account, 1, 0, &over);
        let (ov, _) = sign(&nodes[0].0, &d_over);
        // The big action again at nonces 1 and 2, cosigned, for the budget.
        let later: Vec<Value> = (1..3u64)
            .map(|n| {
                let d = act_digest(&g1.chain, &g1.account, 1, n, &big_action);
                json!([sign(&nodes[0].0, &d).0, sign(&nodes[1].0, &d).0])
            })
            .collect();
        let stranger = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let (x0, _) = sign(&stranger, &d_open);
        per_chain.push((
            caip2,
            json!({
                "chain": caip2,
                "deployment": deployment,
                "salt": hex::encode(salt(DID)),
                "account": account.address,
                "account_raw": hex::encode(&account.raw),
                "account_word": hex::encode(account.account_word()),
                "caip10": account.caip10(),
                "erc7930": account.erc7930().map(hex::encode),
                "asset": asset,
                "tree_key": hex::encode(state_tree_key(DID, caip2)),
                "targets": targets.iter().enumerate().map(|(i, (t, s))| json!({
                    "target": hex::encode(t),
                    "selector": hex::encode(s),
                    "leaf": hex::encode(target_leaves[i]),
                    "proof": merkle_proof(&target_leaves, i).iter().map(hex::encode).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "grant": grant_json(&g1),
                "void_grant": grant_json(&g2),
                "action": action_json(&open_action),
                "action_digest": hex::encode(d_open),
                "action_signature": s0,
                "action_signature_high_s": s0_high,
                "stranger_public_key": hex::encode(sec1(&stranger)),
                "stranger_signature": x0,
                "big_action": action_json(&big_action),
                "big_action_digest": hex::encode(d_big),
                "big_action_signatures": [b0, b1, b2],
                "other_target_action": action_json(&other_target),
                "other_target_signature": o0,
                "over_per_action": action_json(&over),
                "over_per_action_signature": ov,
                "big_action_later_signatures": later,
                "payload_hash": hex::encode(payload_hash(&open_action)),
                "next_nonce_digest": hex::encode(act_digest(&g1.chain, &g1.account, 1, 1, &open_action)),
            }),
        ));
    }
    let root1 = trie.commit(1, &v1).unwrap();
    let root2 = trie.commit(2, &v2).unwrap();
    let mut chains_out = Vec::new();
    for (caip2, mut c) in per_chain {
        let (value1, proof1) = trie.prove(1, "state", &system_key(DID, caip2)).unwrap();
        let (value2, proof2) = trie.prove(2, "state", &system_key(DID, caip2)).unwrap();
        let (absent, proof_absent) = trie.prove(1, "state", &system_key(OTHER, caip2)).unwrap();
        assert!(value1.is_some() && value2.is_some() && absent.is_none());
        c["proof_v1"] = json!(hex::encode(proof1.encode()));
        c["proof_v2"] = json!(hex::encode(proof2.encode()));
        c["absent_tree_key"] = json!(hex::encode(state_tree_key(OTHER, caip2)));
        c["proof_absent_v1"] = json!(hex::encode(proof_absent.encode()));
        chains_out.push(c);
    }
    let grant_vectors = json!({
        "did": DID,
        "agent": hex::encode(agent_hash(DID)),
        "now_ms": T0 + 1_000,
        "keys_root": hex::encode(keys_root),
        "keys": keys,
        "chains": chains_out,
    });
    let state_vectors = json!({
        "root_v1": root1.to_string(),
        "root_v2": root2.to_string(),
        "entries": grant_vectors["chains"].as_array().unwrap().iter().map(|c| json!({
            "chain": c["chain"],
            "tree_key": c["tree_key"],
            "value_v1": c["grant"]["bytes"],
            "proof_v1": c["proof_v1"],
            "value_v2": c["void_grant"]["bytes"],
            "proof_v2": c["proof_v2"],
            "absent_tree_key": c["absent_tree_key"],
            "proof_absent_v1": c["proof_absent_v1"],
        })).collect::<Vec<_>>(),
    });
    (grant_vectors, state_vectors)
}

fn check(path: &str, value: &Value) {
    let full = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    let text = serde_json::to_string_pretty(value).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&full).parent().unwrap()).unwrap();
        std::fs::write(&full, text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&full).unwrap_or_default();
    assert_eq!(
        on_disk, text,
        "{path} is stale: rerun with TENZRO_WRITE_FIXTURES=1"
    );
}

#[test]
fn the_shared_vectors_are_current() {
    let (grants, state) = vectors();
    check("sdk/fixtures/remote_grant/vectors.json", &grants);
    check("sdk/fixtures/state_proof/vectors.json", &state);
}
