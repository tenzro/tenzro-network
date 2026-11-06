//! A network that starts from its genesis alone: no node holds an endpoint
//! record naming any neighbour, over real gossip on real iroh endpoints.
//!
//! A validator's endpoint is learned from its signed announcement, and a
//! record names the endpoint only after that announcement was heard (the
//! node fetches the record from the announcing validator). So a neighbour no
//! record names has to be heard on the announcements topic, or no record ever
//! names anyone and the network never forms. Everything else a neighbour no
//! record names sends on a consensus topic is still shed.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointId, SecretKey};
use parking_lot::Mutex;
use tenzro_iroh::gossip::{ALPN_GOSSIP, GossipGate, GossipTransport};
use tenzro_network::{
    GossipLimits, MessagePayload, NetworkGossip, NetworkMessage, NetworkMetrics, PeerIdentities,
    VALIDATORS_TOPIC,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

const CHAIN_ID: u64 = 4343;
const WAIT: Duration = Duration::from_secs(20);
const LIMITS: GossipLimits = GossipLimits {
    window: Duration::from_secs(10),
    consensus_messages: 1_000,
    general_messages: 1_000,
    ban: Duration::from_secs(300),
};
const STATEMENT: &[u8] = b"tenzro test endpoint announcement";

/// What one node knows: the validator set from its genesis, and the endpoint
/// records it holds. Nothing names any endpoint at the start.
struct Knowledge {
    validators: HashSet<EndpointId>,
    records: Mutex<HashMap<EndpointId, String>>,
}

impl Knowledge {
    fn new(validators: HashSet<EndpointId>) -> Arc<Self> {
        Arc::new(Self {
            validators,
            records: Mutex::new(HashMap::new()),
        })
    }

    fn name(&self, endpoint: EndpointId) {
        self.records
            .lock()
            .insert(endpoint, format!("did:tenzro:machine:{endpoint}"));
    }

    fn names(&self, endpoint: EndpointId) -> bool {
        self.records.lock().contains_key(&endpoint)
    }
}

/// The signer's endpoint id and the signature over the statement, if it is a
/// validator of the genesis set.
fn opened(validators: &HashSet<EndpointId>, bytes: &[u8]) -> Option<EndpointId> {
    let id = EndpointId::from_bytes(bytes.get(..32)?.try_into().ok()?).ok()?;
    let signature = iroh::Signature::from_bytes(bytes.get(32..96)?.try_into().ok()?);
    validators.contains(&id).then_some(())?;
    id.verify(STATEMENT, &signature).ok()?;
    Some(id)
}

impl PeerIdentities for Knowledge {
    fn machine_did(&self, endpoint: EndpointId) -> Option<String> {
        self.records.lock().get(&endpoint).cloned()
    }

    fn vouches_for_announcement(&self, announcement: &[u8]) -> bool {
        opened(&self.validators, announcement).is_some()
    }
}

fn announcement(key: &SecretKey) -> Vec<u8> {
    let mut bytes = key.public().as_bytes().to_vec();
    bytes.extend_from_slice(&key.sign(STATEMENT).to_bytes());
    bytes
}

struct Node {
    key: SecretKey,
    endpoint: Endpoint,
    gossip: NetworkGossip,
    metrics: Arc<NetworkMetrics>,
    knows: Arc<Knowledge>,
    _transport: GossipTransport,
    _router: Router,
}

impl Node {
    fn id(&self) -> EndpointId {
        self.endpoint.id()
    }
}

async fn node(lookup: &MemoryLookup, key: SecretKey, validators: HashSet<EndpointId>) -> Node {
    let gate = GossipGate::default();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key.clone())
        .hooks(gate.clone())
        .bind()
        .await
        .unwrap();
    endpoint.address_lookup().unwrap().add(lookup.clone());
    lookup.add_endpoint_info(endpoint.addr());
    let transport = GossipTransport::spawn(&endpoint, gate);
    let router = Router::builder(endpoint.clone())
        .accept(ALPN_GOSSIP, transport.protocol())
        .spawn();
    let metrics = NetworkMetrics::unregistered();
    let gossip = NetworkGossip::new(metrics.clone(), LIMITS);
    gossip.attach(transport.clone(), CHAIN_ID).unwrap();
    let knows = Knowledge::new(validators);
    gossip.set_identities(knows.clone());
    Node {
        key,
        endpoint,
        gossip,
        metrics,
        knows,
        _transport: transport,
        _router: router,
    }
}

/// Hears the announcements a node receives and, as a node does once it has
/// opened one, comes to hold the announcing validator's record.
fn learn_records(node: &Node) -> mpsc::UnboundedReceiver<EndpointId> {
    let mut rx = node.gossip.subscribe(VALIDATORS_TOPIC);
    let knows = node.knows.clone();
    let (heard_tx, heard_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let MessagePayload::ValidatorEndpoint(bytes) = message.payload else {
                continue;
            };
            if let Some(id) = opened(&knows.validators, &bytes) {
                knows.name(id);
                let _ = heard_tx.send(id);
            }
        }
    });
    heard_rx
}

async fn heard(rx: &mut mpsc::UnboundedReceiver<EndpointId>, what: &str) -> EndpointId {
    timeout(WAIT, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing arrived"))
        .expect("channel open")
}

async fn wait_for_neighbours(node: &Node, topic: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while node.gossip.neighbour_count(topic).unwrap() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{topic} never got a neighbour"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn keys(n: u8) -> Vec<SecretKey> {
    (0..n)
        .map(|i| SecretKey::from_bytes(&[100 + i; 32]))
        .collect()
}

/// Three validators and the relay machine they join the topics through. No
/// node holds a record naming a validator: the relay's own record is the one
/// each validator holds from its boot list, so each validator joins through
/// it. The announcements must reach every validator, through the relay or
/// directly, and the records they come to hold name the announcers.
#[tokio::test]
async fn validators_that_know_only_their_genesis_hear_each_others_announcements() {
    let lookup = MemoryLookup::new();
    let validator_keys = keys(3);
    let relay_key = SecretKey::from_bytes(&[200; 32]);
    let genesis: HashSet<EndpointId> = validator_keys.iter().map(|k| k.public()).collect();

    let relay = node(&lookup, relay_key, genesis.clone()).await;
    let mut validators = Vec::new();
    for key in validator_keys {
        validators.push(node(&lookup, key, genesis.clone()).await);
    }
    let mut at_relay = learn_records(&relay);
    let mut at = Vec::new();
    for v in &validators {
        // The relay's record is the one a validator holds from its boot list.
        v.knows.name(relay.id());
        at.push(learn_records(v));
    }
    for v in &validators {
        v.gossip.add_peers(&[relay.id()]).await;
    }
    for n in validators.iter().chain([&relay]) {
        wait_for_neighbours(n, VALIDATORS_TOPIC).await;
    }

    for v in &validators {
        v.gossip
            .broadcast(
                VALIDATORS_TOPIC,
                NetworkMessage::new(MessagePayload::ValidatorEndpoint(announcement(&v.key))),
            )
            .await
            .unwrap();
    }

    for (i, v) in validators.iter().enumerate() {
        let mut seen = HashSet::new();
        while seen.len() < validators.len() - 1 {
            let id = heard(&mut at[i], "an announcement").await;
            assert_ne!(id, v.id());
            seen.insert(id);
        }
        for other in validators.iter().filter(|o| o.id() != v.id()) {
            assert!(
                v.knows.names(other.id()),
                "validator {i} holds a record naming another"
            );
        }
    }
    let mut at_relay_seen = HashSet::new();
    while at_relay_seen.len() < validators.len() {
        at_relay_seen.insert(heard(&mut at_relay, "an announcement at the relay").await);
    }
}

/// A neighbour no record names is heard only on the announcements topic, and
/// only when the announcement verifies under a validator's key: a forged or
/// foreign one is dropped, and so is everything else it sends on a
/// consensus topic.
#[tokio::test]
async fn a_neighbour_no_record_names_is_heard_only_for_a_verified_announcement() {
    let lookup = MemoryLookup::new();
    let validator_keys = keys(1);
    let stranger_key = SecretKey::from_bytes(&[210; 32]);
    let genesis: HashSet<EndpointId> = validator_keys.iter().map(|k| k.public()).collect();

    let listener = node(&lookup, SecretKey::from_bytes(&[201; 32]), genesis.clone()).await;
    let validator = node(&lookup, validator_keys[0].clone(), genesis.clone()).await;
    let stranger = node(&lookup, stranger_key, genesis.clone()).await;
    let mut announcements = listener.gossip.subscribe(VALIDATORS_TOPIC);
    let mut statuses = listener.gossip.subscribe("tenzro/status");
    for n in [&validator, &stranger] {
        n.gossip.subscribe(VALIDATORS_TOPIC);
        n.gossip.subscribe("tenzro/status");
        n.gossip.add_peers(&[listener.id()]).await;
    }
    for topic in [VALIDATORS_TOPIC, "tenzro/status"] {
        wait_for_neighbours(&listener, topic).await;
        wait_for_neighbours(&validator, topic).await;
        wait_for_neighbours(&stranger, topic).await;
    }

    // A stranger signs the statement with a key outside the genesis set, and
    // sends a status message.
    let forged = NetworkMessage::new(MessagePayload::ValidatorEndpoint(announcement(
        &stranger.key,
    )));
    stranger
        .gossip
        .broadcast(VALIDATORS_TOPIC, forged)
        .await
        .unwrap();
    stranger
        .gossip
        .broadcast(
            "tenzro/status",
            NetworkMessage::new(MessagePayload::Custom {
                topic: "tenzro/status".into(),
                data: vec![1],
            }),
        )
        .await
        .unwrap();
    // A validator's announcement follows.
    validator
        .gossip
        .broadcast(
            VALIDATORS_TOPIC,
            NetworkMessage::new(MessagePayload::ValidatorEndpoint(announcement(
                &validator.key,
            ))),
        )
        .await
        .unwrap();

    let first = timeout(WAIT, announcements.recv())
        .await
        .expect("the validator's announcement arrives")
        .expect("channel open");
    let MessagePayload::ValidatorEndpoint(bytes) = first.payload else {
        panic!("not an announcement");
    };
    assert_eq!(
        opened(&genesis, &bytes),
        Some(validator.id()),
        "the first thing delivered is the validator's announcement, not the forgery"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(announcements.try_recv().is_err());
    assert!(
        statuses.try_recv().is_err(),
        "status from a neighbour no record names is shed"
    );
    assert!(listener.metrics.gossip_shed_unidentified.get() >= 1);
}
