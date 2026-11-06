//! Every tool call an authenticated agent makes is a signed record, end to
//! end: a running node serves an MCP call over HTTP on `/mcp` and on
//! `/mcp/compact`, and an A2A message over HTTP; each leaves an entry the
//! node signed with its hardware identity, and the entries verify offline in
//! an evidence pack together with its EU AI Act profile.
//!
//! The node's epoch commitment is made here as the committer makes it (the
//! epoch root over the session lines, recorded under the committer's slot);
//! everything else is the node's own output.
//!
//! Needs this machine's hardware identity key (TPM 2.0 or Secure Enclave),
//! like every test that starts a node.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;
use tenzro_crypto::batch::RecordSigner as _;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use dpop_bearer::Bearer;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};

const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn mcp_call(url: &str, path: &str, who: &Bearer, name: &str, arguments: Value) -> Value {
    let params = json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
            "io.modelcontextprotocol/clientCapabilities": {},
            "tenzro/approval": "ticket-41",
        },
    });
    reqwest::Client::new()
        .post(format!("{url}{path}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", name)
        .header("Authorization", format!("DPoP {}", who.token))
        .header(
            "DPoP",
            who.holder
                .sign_proof("POST", &format!("{url}{path}"), Some(&who.token)),
        )
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params }))
        .send()
        .await
        .expect("mcp post")
        .json()
        .await
        .expect("mcp json")
}

/// An A2A sender: a registered identity whose wallet is an Ed25519 key.
struct A2aSender {
    did: String,
    key: tenzro_crypto::signatures::Ed25519SignerImpl,
}

impl A2aSender {
    async fn register(node: &TenzroNode) -> Self {
        use tenzro_crypto::signatures::Signer as _;
        let key = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let passkey = passkey_holder::PasskeyHolder::generate();
        let registry = node.identity_registry().expect("identity registry");
        let mut pending = registry
            .prepare_human(vec![7; 16], passkey.public_xy(), "a2a sender".into())
            .await
            .expect("prepare");
        let mut slot = [0u8; 32];
        slot[..20].copy_from_slice(key.public_key().to_address().as_bytes());
        pending.identity.wallet_address = tenzro_types::Address::new(slot);
        let did = pending.identity.did_string();
        let _ = registry.admit(pending);
        Self { did, key }
    }

    fn sign(&self, method: &str, params: &mut Value) {
        use tenzro_crypto::signatures::Signer as _;
        use tenzro_node::a2a::did_envelope as env;
        let now = chrono::Utc::now().timestamp_millis();
        let nonce = hex::encode(uuid::Uuid::new_v4().as_bytes());
        let task_id = env::envelope_task_id(method, params);
        let digest = env::params_digest_hex(method, params).unwrap();
        let preimage = env::canonical_preimage(method, &task_id, &self.did, &nonce, now, &digest);
        let sig = self.key.sign(preimage.as_bytes()).unwrap();
        let meta = params["message"]
            .as_object_mut()
            .unwrap()
            .entry("metadata")
            .or_insert_with(|| json!({}));
        let m = meta.as_object_mut().unwrap();
        m.insert(env::KEY_SENDER.into(), json!(self.did));
        m.insert(
            env::KEY_PUBLIC_KEY.into(),
            json!(hex::encode(self.key.public_key().as_bytes())),
        );
        m.insert(
            env::KEY_SIGNATURE.into(),
            json!(hex::encode(sig.as_bytes())),
        );
        m.insert(env::KEY_NONCE.into(), json!(nonce));
        m.insert(env::KEY_TIMESTAMP.into(), json!(now));
    }
}

#[tokio::test]
#[ignore = "needs this machine's hardware identity key (TPM 2.0 or Secure Enclave)"]
async fn agent_tool_calls_over_mcp_and_a2a_are_signed_records_that_verify_offline() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        ..Default::default()
    };
    let mut node = TenzroNode::new(cfg).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);
    let signer = node
        .records()
        .expect("a started node signs its records with its hardware identity")
        .clone();
    let (tx, _) = broadcast::channel::<()>(1);

    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let rx = tx.subscribe();
    tokio::spawn(async move { rpc.start_with_shutdown_and_addr(rx, addr_tx).await });
    let rpc_url = format!("http://{}", addr_rx.await.expect("bound address"));

    let web = Arc::new(tenzro_node::web::handlers::WebState::new());
    let mcp_port = free_port();
    let rx = tx.subscribe();
    let (n, w) = (node.clone(), web.clone());
    tokio::spawn(async move {
        tenzro_node::mcp::server::start_mcp_server_with_shutdown(
            format!("127.0.0.1:{mcp_port}"),
            n,
            w,
            rx,
        )
        .await
    });
    let a2a_port = free_port();
    let state = tenzro_node::a2a::server::build_a2a_state(node.clone(), web);
    let rx = tx.subscribe();
    tokio::spawn(async move {
        tenzro_node::a2a::server::start_a2a_server_with_shutdown(
            format!("127.0.0.1:{a2a_port}"),
            state,
            rx,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mcp_url = format!("http://127.0.0.1:{mcp_port}");
    let client = reqwest::Client::new();

    // An agent with a DPoP-bound access token calls a tool on /mcp and the
    // same tool through /mcp/compact.
    let agent = Bearer::onboard(&client, &rpc_url, "agent").await;
    let agent_did = {
        use base64::Engine as _;
        let payload = agent.token.split('.').nth(1).expect("a JWT");
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("base64url claims"),
        )
        .expect("claims JSON");
        claims["sub"].as_str().expect("sub").to_string()
    };
    let direct = mcp_call(&mcp_url, "/mcp", &agent, "get_node_status", json!({})).await;
    assert!(direct["result"].is_object(), "{direct}");
    let compact = mcp_call(
        &mcp_url,
        "/mcp/compact",
        &agent,
        "call",
        json!({ "name": "get_node_status", "arguments": {} }),
    )
    .await;
    assert!(compact["result"].is_object(), "{compact}");

    // A registered sender sends an A2A message.
    let sender = A2aSender::register(&node).await;
    let mut params = json!({
        "message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "what is the node status?"}]}
    });
    sender.sign("SendMessage", &mut params);
    let a2a: Value = client
        .post(format!("http://127.0.0.1:{a2a_port}/a2a"))
        .header("A2A-Version", "1.0")
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": params }))
        .send()
        .await
        .expect("a2a post")
        .json()
        .await
        .expect("a2a json");
    assert_eq!(
        a2a["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{a2a}"
    );

    // Each call left one signed entry.
    let log = node.tool_calls();
    let mut lines = Vec::new();
    let mut surfaces = Vec::new();
    for did in [&agent_did, &sender.did] {
        let sessions = log.sessions_of(did).unwrap();
        assert_eq!(sessions.len(), 1, "{did}");
        let entries = log.entries(&sessions[0]).unwrap();
        for e in &entries {
            let entry =
                tenzro_consensus::eu_ai_act::verify_tool_call(e, signer.identity()).unwrap();
            let call = entry.call.unwrap();
            assert_eq!(
                call.node,
                tenzro_node::tool_call_record::signer_did(&signer)
            );
            surfaces.push((entry.action.clone(), call.surface.clone()));
            if call.surface != "a2a" {
                assert_eq!(call.approval.as_deref(), Some("ticket-41"));
            }
            assert!(call.result.is_some());
        }
        let mmr =
            tenzro_types::agent_audit::Mmr::from_leaves(entries.iter().map(|e| e.leaf_hash()));
        lines.push(tenzro_types::agent_audit::SessionLeaf {
            session_id: sessions[0],
            mmr_root: mmr.root(),
            count: entries.len() as u64,
        });
    }
    surfaces.sort();
    assert_eq!(
        surfaces,
        vec![
            ("get_node_status".to_string(), "mcp".to_string()),
            ("get_node_status".to_string(), "mcp_compact".to_string()),
            ("message".to_string(), "a2a".to_string()),
        ]
    );

    // The epoch commitment, as the committer makes it, and the pack.
    lines.sort_by_key(|l| l.session_id);
    log.committed(&tenzro_node::tool_call_record::CommittedEpoch {
        epoch: 3,
        committer: "0xaa".into(),
        lines: lines.clone(),
    })
    .unwrap();
    let agents = vec![agent_did.clone(), sender.did.clone()];
    let audit = log.proofs(&agents, 100).unwrap();
    assert_eq!(audit.len(), 3);

    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::evidence_pack::{
        EvidencePack, Jurisdiction, Oversight, ProvenRecord, STATE_NAMESPACE, vm_storage_key,
    };
    let node_did = tenzro_node::tool_call_record::signer_did(&signer);
    let mut key = vec![0x04];
    key.extend_from_slice(&signer.identity().p256);
    let slots = [
        (
            "agent_audit:aa:0000000000000003".to_string(),
            json!({ "root": hex::encode(tenzro_types::agent_audit::epoch_root(&lines)), "sessions": 2 }),
        ),
        (
            tenzro_types::identity::identity_slot(&node_did),
            json!({
                "did": node_did, "controller_pubkey": key, "key_type": "p256",
                "pq_verifying_key": signer.identity().pq.clone().unwrap_or_default(),
            }),
        ),
    ];
    let trie = StateTrie::new(Arc::new(MemoryStore::new()));
    let mut writes = Writes::new();
    for (slot, value) in &slots {
        writes.insert(
            (
                STATE_NAMESPACE.to_string(),
                vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
            ),
            Some(serde_json::to_vec(value).unwrap()),
        );
    }
    let root = trie.commit(1, &writes).unwrap();
    let record = |kind: &str, subject: &str, slot: &str| {
        let (value, proof) = trie
            .prove(
                1,
                STATE_NAMESPACE,
                &vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
            )
            .unwrap();
        ProvenRecord {
            kind: kind.into(),
            subject: subject.into(),
            slot: slot.into(),
            value: value.map(hex::encode),
            proof: serde_json::to_value(proof).unwrap(),
        }
    };
    let mut pack = EvidencePack {
        subject: agent_did.clone(),
        agents,
        generated_at_ms: 0,
        state_height: 1,
        state_root: hex::encode(root.as_bytes()),
        state_trie_hash: trie.scheme_at(1).unwrap(),
        checkpoint: Value::Null,
        audit,
        commitments: vec![record("audit_commit", "0xaa:3", &slots[0].0)],
        oversight: Oversight {
            records: vec![],
            actions: vec![],
        },
        mandate: vec![record(
            tenzro_consensus::eu_ai_act::NODE_IDENTITY_KIND,
            &node_did,
            &slots[1].0,
        )],
        commerce: vec![],
        governance: vec![],
        token_actions: vec![],
        receipts: vec![],
        models: vec![],
        jurisdiction: Jurisdiction {
            country: None,
            blocs: vec![],
        },
        manifest: vec![],
    };
    pack.manifest = pack.build_manifest();
    let root: [u8; 32] = root.as_bytes().try_into().unwrap();
    let profile = tenzro_consensus::eu_ai_act::build_profile(&pack);
    assert_eq!(
        tenzro_consensus::eu_ai_act::verify_profile_under_root(&pack, &profile, &root).unwrap(),
        (3, 2, 3)
    );
    let approvals = &profile
        .clauses
        .iter()
        .find(|c| c.measure == "approval")
        .unwrap()
        .evidence;
    assert_eq!(
        approvals.len(),
        2,
        "the two MCP calls presented an approval"
    );

    // A record changed after the node signed it is refused.
    let mut forged = pack.clone();
    forged.audit[0].entry.body = String::from_utf8(forged.audit[0].entry.body.clone())
        .unwrap()
        .replace("get_node_status", "get_node_secret")
        .into_bytes();
    assert!(tenzro_consensus::eu_ai_act::verify_tool_calls_under_root(&forged, &root).is_err());

    let _ = tx.send(());
}
