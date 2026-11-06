//! Owner revocations reach every node through consensus.
//!
//! Three in-process nodes, each with its own chain state, VM and identity read
//! model, execute the same ordered transactions and mirror the logs through
//! the node's own `identity_mirror`, as the event loop does for every block.
//! A `RevokeIdentity` transaction carries the root's approval and every node
//! re-verifies it against keys in its chain state, so:
//!
//! 1. `an_owner_signed_revocation_applies_on_every_node`: a human revokes
//!    itself with its passkey and every node's read model shows it revoked.
//! 2. `a_strangers_revocation_is_refused_on_every_node`: a stranger's key,
//!    a stranger naming itself as approver, or a genuine approval moved onto
//!    another reason, is refused by every node and changes nothing.
//! 3. `revoking_a_root_revokes_its_agents_on_every_node`: an agent the root
//!    delegated on chain is revoked with it on every node.
//! 4. `a_delegated_agent_is_revoked_by_its_named_controller_on_every_node`:
//!    the controller the agent's terms name revokes it alone; another root
//!    cannot.
//!
//! `cargo test -p tenzro-node --test identity_revocation_consensus`

use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{CompositeSignature, HybridSigner, SignatureContext};
use tenzro_identity::{IdentityRegistry, IdentityStatus};
use tenzro_types::agent_terms::{
    AgentTerms, AgentTermsApproval, OP_DELEGATE_AGENT, ServingNode, TermsScope,
    custody_challenge_digest,
};
use tenzro_types::identity::{
    IdentityRevocationOp, OP_REVOKE_IDENTITY, RegisterIdentityPayload, RegistrationProof,
    registration_statement, revocation_target,
};
use tenzro_types::primitives::Address;
use tenzro_vm::native::{
    SELECTOR_IDENTITY_REGISTER, SELECTOR_IDENTITY_REVOKE, SELECTOR_SET_AGENT_TERMS,
};
use tenzro_vm::{
    NativeExecutor, StateAdapter, VmConfig, VmExecutor, VmState, VmTransaction, VmType,
};

const NODES: usize = 3;
const RELAYER: [u8; 32] = [0x51; 32];
/// The chain id genesis records; every approval is signed for it.
const CHAIN: u64 = 1337;

struct Node {
    state: StateAdapter,
    registry: IdentityRegistry,
    executor: NativeExecutor,
}

/// The nodes of one chain, applying the same ordered transactions.
struct Network {
    nodes: Vec<Node>,
    at_ms: i64,
}

impl Network {
    fn new() -> Self {
        let nodes = (0..NODES)
            .map(|_| {
                let mut state = StateAdapter::new();
                state.set_balance(&RELAYER, u128::MAX / 4);
                state.set_storage(
                    &tenzro_vm::native::SYSTEM_ADDRESS,
                    tenzro_vm::native::NETWORK_CHAIN_ID_KEY.as_bytes(),
                    CHAIN.to_le_bytes().to_vec(),
                );
                Node {
                    state,
                    registry: IdentityRegistry::new(),
                    executor: NativeExecutor::new(VmConfig::default()).unwrap(),
                }
            })
            .collect();
        Self {
            nodes,
            at_ms: 1_700_000_000_000,
        }
    }

    /// Every node executes `data` as the next transaction. Returns how many
    /// accepted it; the nodes must agree.
    async fn apply(&mut self, data: Vec<u8>) -> bool {
        self.at_ms += 1_000;
        let mut accepted = Vec::new();
        for node in &mut self.nodes {
            let mut tx = VmTransaction::new(
                RELAYER.to_vec(),
                None,
                0,
                data.clone(),
                10_000_000,
                1,
                0,
                VmType::Evm,
                CHAIN,
            );
            tx.block_timestamp_ms = Some(self.at_ms);
            let ok = match node
                .executor
                .execute_transaction(&tx, &mut node.state)
                .await
            {
                Ok(r) if r.success => {
                    tenzro_node::identity_mirror::mirror_identity_logs(
                        &node.registry,
                        None,
                        &r.logs,
                    );
                    true
                }
                _ => false,
            };
            accepted.push(ok);
        }
        assert!(
            accepted.iter().all(|a| *a == accepted[0]),
            "the nodes disagreed on one transaction: {accepted:?}"
        );
        accepted[0]
    }

    fn status(&self, did: &str) -> Vec<Option<IdentityStatus>> {
        self.nodes
            .iter()
            .map(|n| n.registry.resolve(did).ok().map(|i| i.status))
            .collect()
    }

    fn revoked_on_chain(&self, did: &str) -> Vec<bool> {
        self.nodes
            .iter()
            .map(|n| tenzro_vm::native::is_identity_revoked(&n.state, did))
            .collect()
    }

    fn fund(&mut self, address: &[u8]) {
        for n in &mut self.nodes {
            n.state.set_balance(address, u128::MAX / 8);
        }
    }
}

fn call(selector: [u8; 4], body: &impl serde::Serialize) -> Vec<u8> {
    let mut data = selector.to_vec();
    data.extend_from_slice(&serde_json::to_vec(body).unwrap());
    data
}

/// A person: its passkey and the human DID that derives from it.
struct Person {
    passkey: TestHybridSigner,
    did: String,
}

impl Person {
    fn new(seed: u8) -> Self {
        let passkey = TestHybridSigner::p256_only(seed);
        let did = format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(&passkey.public_key().p256)
        );
        Self { passkey, did }
    }

    fn registration(&self, wallet: u8) -> Vec<u8> {
        let mut payload = RegisterIdentityPayload {
            did: self.did.clone(),
            identity_type: "human".into(),
            display_name: "person".into(),
            controller_pubkey: self.passkey.public_key().p256.clone(),
            key_type: "P-256".into(),
            wallet_id: format!("wallet-{wallet}"),
            wallet_address: Address::new([wallet; 32]),
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof: RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let statement = registration_statement(&payload);
        payload.proof = RegistrationProof::Hardware {
            signature: self
                .passkey
                .sign(SignatureContext::IdentityRegistration, &statement)
                .unwrap(),
        };
        call(SELECTOR_IDENTITY_REGISTER, &payload)
    }

    /// This person's passkey assertion over the custody challenge for `op`
    /// over `target`.
    fn approve(&self, op: &[u8], target: &[u8]) -> AgentTermsApproval {
        let account = vec![0x0a; 32];
        let nonce = [7u8; 16];
        let digest = custody_challenge_digest(CHAIN, &account, op, target, &nonce);
        AgentTermsApproval {
            account,
            nonce,
            root_public_key: self.passkey.public_key().p256.clone(),
            signature: CompositeSignature::classical(self.passkey.sign_passkey(
                0x05,
                SignatureContext::AccountOwner,
                &digest,
            )),
        }
    }

    fn revoke(&self, did: &str, reason: &str) -> IdentityRevocationOp {
        IdentityRevocationOp {
            did: did.to_string(),
            reason: reason.to_string(),
            approver_did: self.did.clone(),
            approval: self.approve(OP_REVOKE_IDENTITY, &revocation_target(did, reason)),
        }
    }

    /// Delegate an agent named `name`: its terms and this root's approval.
    fn delegate(&self, name: &str) -> (String, Vec<u8>) {
        let terms = AgentTerms {
            controller_did: self.did.clone(),
            agent_name: name.into(),
            delegation_scope: TermsScope {
                max_daily_spend: Some("1000".into()),
                ..Default::default()
            },
            capabilities: vec![],
            serving_nodes: vec![ServingNode {
                machine_did: "did:tenzro:machine:serving".into(),
                operator_did: "did:tenzro:human:op".into(),
                dpop_public_key: hex::encode(
                    TestHybridSigner::p256_only(99).public_key().p256.clone(),
                ),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        };
        let agent = tenzro_types::agent_terms::agent_did(&self.did, name).unwrap();
        let approval = self.approve(OP_DELEGATE_AGENT, &terms.target(None));
        let data = call(
            SELECTOR_SET_AGENT_TERMS,
            &serde_json::json!({ "terms": terms, "rotate": null, "approval": approval }),
        );
        (agent, data)
    }
}

async fn registered(net: &mut Network, person: &Person, wallet: u8) {
    assert!(
        net.apply(person.registration(wallet)).await,
        "registration lands"
    );
    assert_eq!(
        net.status(&person.did),
        vec![Some(IdentityStatus::Active); NODES]
    );
}

async fn delegated(net: &mut Network, root: &Person, name: &str) -> String {
    let (agent, data) = root.delegate(name);
    net.fund(tenzro_token::bond::derive_bond_vault_address(&agent).as_bytes());
    assert!(net.apply(data).await, "the agent's terms land");
    agent
}

#[tokio::test]
async fn an_owner_signed_revocation_applies_on_every_node() {
    let mut net = Network::new();
    let alice = Person::new(1);
    registered(&mut net, &alice, 1).await;

    let op = alice.revoke(&alice.did, "passkey lost");
    assert!(net.apply(call(SELECTOR_IDENTITY_REVOKE, &op)).await);

    assert_eq!(net.revoked_on_chain(&alice.did), vec![true; NODES]);
    assert_eq!(
        net.status(&alice.did),
        vec![Some(IdentityStatus::Revoked); NODES]
    );
    for node in &net.nodes {
        assert!(node.registry.is_revoked(&alice.did));
    }
    // A second copy of the same approved revocation changes nothing.
    assert!(!net.apply(call(SELECTOR_IDENTITY_REVOKE, &op)).await);
}

#[tokio::test]
async fn a_strangers_revocation_is_refused_on_every_node() {
    let mut net = Network::new();
    let alice = Person::new(1);
    let mallory = Person::new(2);
    registered(&mut net, &alice, 1).await;
    registered(&mut net, &mallory, 2).await;

    // Mallory signs with her own key while naming Alice as the approver.
    let mut forged = mallory.revoke(&alice.did, "compromised");
    forged.approver_did = alice.did.clone();
    assert!(!net.apply(call(SELECTOR_IDENTITY_REVOKE, &forged)).await);

    // Mallory names herself as the approver of Alice's revocation.
    let own = mallory.revoke(&alice.did, "compromised");
    assert!(!net.apply(call(SELECTOR_IDENTITY_REVOKE, &own)).await);

    // Alice's genuine approval, relayed with another reason.
    let mut moved = alice.revoke(&alice.did, "passkey lost");
    moved.reason = "fraud".into();
    assert!(!net.apply(call(SELECTOR_IDENTITY_REVOKE, &moved)).await);

    assert_eq!(net.revoked_on_chain(&alice.did), vec![false; NODES]);
    assert_eq!(
        net.status(&alice.did),
        vec![Some(IdentityStatus::Active); NODES]
    );
}

#[tokio::test]
async fn revoking_a_root_revokes_its_agents_on_every_node() {
    let mut net = Network::new();
    let alice = Person::new(1);
    registered(&mut net, &alice, 1).await;
    let buyer = delegated(&mut net, &alice, "buyer").await;
    let seller = delegated(&mut net, &alice, "seller").await;

    let op = alice.revoke(&alice.did, "passkey lost");
    assert!(net.apply(call(SELECTOR_IDENTITY_REVOKE, &op)).await);

    for agent in [&buyer, &seller] {
        assert_eq!(net.revoked_on_chain(agent), vec![true; NODES]);
        for node in &net.nodes {
            assert!(
                tenzro_vm::native::check_agent_status(&node.state, agent, u64::MAX / 2).is_err(),
                "every node refuses the agent's actions"
            );
        }
    }
}

#[tokio::test]
async fn a_delegated_agent_is_revoked_by_its_named_controller_on_every_node() {
    let mut net = Network::new();
    let alice = Person::new(1);
    let mallory = Person::new(2);
    registered(&mut net, &alice, 1).await;
    registered(&mut net, &mallory, 2).await;
    let buyer = delegated(&mut net, &alice, "buyer").await;

    assert!(
        !net.apply(call(SELECTOR_IDENTITY_REVOKE, &mallory.revoke(&buyer, "x")))
            .await
    );
    assert_eq!(net.revoked_on_chain(&buyer), vec![false; NODES]);

    let op = alice.revoke(&buyer, "leaked token");
    assert!(net.apply(call(SELECTOR_IDENTITY_REVOKE, &op)).await);
    assert_eq!(net.revoked_on_chain(&buyer), vec![true; NODES]);
    for node in &net.nodes {
        assert!(tenzro_vm::native::check_agent_status(&node.state, &buyer, u64::MAX / 2).is_err());
        assert!(!tenzro_vm::native::is_identity_revoked(
            &node.state,
            &alice.did
        ));
    }
    assert_eq!(
        net.status(&alice.did),
        vec![Some(IdentityStatus::Active); NODES]
    );
}
