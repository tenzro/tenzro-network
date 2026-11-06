//! Gossip between several nodes over iroh, in one process.
//!
//! Every node runs an iroh endpoint on loopback with the gossip protocol on
//! its router. Endpoints find each other through a shared in-memory address
//! lookup holding their direct addresses, so no relay or discovery service
//! is involved. Each node's topics are served by the same `NetworkGossip`
//! the node's `TenzroNetworkService` uses, with the node's validation rules.

use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointId};
use tenzro_iroh::gossip::{ALPN_GOSSIP, GossipGate, GossipTransport, topic_id};
use tenzro_network::{
    GossipLimits, MessagePayload, NetworkGossip, NetworkMessage, NetworkMetrics, NetworkService,
    TenzroNetworkService,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

const CHAIN_ID: u64 = 4242;
const WAIT: Duration = Duration::from_secs(20);

/// Per-neighbour budgets for these nodes: 1,000 messages per 10 s in each
/// traffic class.
const LIMITS: GossipLimits = GossipLimits {
    window: Duration::from_secs(10),
    consensus_messages: 1_000,
    general_messages: 1_000,
    ban: Duration::from_secs(300),
};

/// Every topic the node publishes or subscribes to.
const TOPICS: &[&str] = &[
    "tenzro/blocks",
    "tenzro/transactions",
    "tenzro/certificates",
    "tenzro/validators",
    "tenzro/status",
    "tenzro/models",
    "tenzro/providers",
    "tenzro/blobs",
    "tenzro/sla",
    "tenzro/compute-observations",
];

struct Peer {
    endpoint: Endpoint,
    gossip: GossipTransport,
    _router: Router,
}

async fn peer(lookup: &MemoryLookup) -> Peer {
    let gate = GossipGate::default();
    let endpoint = Endpoint::builder(presets::Minimal)
        .hooks(gate.clone())
        .bind()
        .await
        .unwrap();
    endpoint.address_lookup().unwrap().add(lookup.clone());
    lookup.add_endpoint_info(endpoint.addr());
    let gossip = GossipTransport::spawn(&endpoint, gate);
    let router = Router::builder(endpoint.clone())
        .accept(ALPN_GOSSIP, gossip.protocol())
        .spawn();
    Peer {
        endpoint,
        gossip,
        _router: router,
    }
}

struct Node {
    peer: Peer,
    gossip: NetworkGossip,
    metrics: Arc<NetworkMetrics>,
}

impl Node {
    fn id(&self) -> EndpointId {
        self.peer.endpoint.id()
    }
}

async fn node(lookup: &MemoryLookup) -> Node {
    let peer = peer(lookup).await;
    let metrics = NetworkMetrics::unregistered();
    let gossip = NetworkGossip::new(metrics.clone(), LIMITS);
    gossip.attach(peer.gossip.clone(), CHAIN_ID).unwrap();
    Node {
        peer,
        gossip,
        metrics,
    }
}

fn message(topic: &str, tag: u8) -> NetworkMessage {
    NetworkMessage::new(MessagePayload::Custom {
        topic: topic.to_string(),
        data: vec![tag],
    })
}

fn tag_of(message: &NetworkMessage) -> u8 {
    match &message.payload {
        MessagePayload::Custom { data, .. } => data[0],
        other => panic!("unexpected payload {other:?}"),
    }
}

async fn recv<T>(rx: &mut mpsc::Receiver<T>, what: &str) -> T {
    timeout(WAIT, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing arrived"))
        .expect("channel open")
}

/// Waits until `node` has a neighbour on every topic in `topics`.
async fn wait_for_neighbours(node: &Node, topics: &[&str]) {
    let deadline = tokio::time::Instant::now() + WAIT;
    for topic in topics {
        while node.gossip.neighbour_count(topic).unwrap() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{topic} never got a neighbour"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Four nodes; every topic is published by one node and received,
/// validated and counted by the other three. Blocks arrive held for the
/// node's verdict, as on a real node.
#[tokio::test]
async fn every_topic_reaches_every_other_node() {
    let lookup = MemoryLookup::new();
    let mut nodes = Vec::new();
    for _ in 0..4 {
        nodes.push(node(&lookup).await);
    }
    let mut plain = Vec::new();
    let mut judged = Vec::new();
    for n in &nodes {
        let mut per_topic = Vec::new();
        for topic in TOPICS {
            if *topic == "tenzro/blocks" {
                per_topic.push(None);
            } else {
                per_topic.push(Some(n.gossip.subscribe(topic)));
            }
        }
        plain.push(per_topic);
        judged.push(n.gossip.subscribe_validated("tenzro/blocks"));
    }
    let first = nodes[0].id();
    for n in &nodes[1..] {
        n.gossip.add_peers(&[first]).await;
    }
    for n in &nodes {
        wait_for_neighbours(n, TOPICS).await;
    }

    for (t, topic) in TOPICS.iter().enumerate() {
        let publisher = t % nodes.len();
        nodes[publisher]
            .gossip
            .broadcast(topic, message(topic, t as u8))
            .await
            .unwrap();
        for (i, _) in nodes.iter().enumerate().filter(|(i, _)| *i != publisher) {
            let got = if *topic == "tenzro/blocks" {
                let held = recv(&mut judged[i], topic).await;
                held.ticket.accept();
                held.message
            } else {
                recv(plain[i][t].as_mut().unwrap(), topic).await
            };
            assert_eq!(tag_of(&got), t as u8, "{topic} at node {i}");
        }
    }
    for (i, n) in nodes.iter().enumerate() {
        let received = TOPICS
            .iter()
            .enumerate()
            .filter(|(t, _)| t % nodes.len() != i)
            .count() as u64;
        assert!(
            n.metrics.gossip_accepted.get() >= received,
            "node {i} validated what it received"
        );
    }
}

/// A participant that skips the rules and sends raw bytes straight onto a
/// topic: the honest node drops every such message and passes none on.
#[tokio::test]
async fn invalid_messages_are_dropped_and_not_passed_on() {
    let lookup = MemoryLookup::new();
    let honest = node(&lookup).await;
    let far = node(&lookup).await;
    let forger = peer(&lookup).await;
    let topic = "tenzro/status";

    let mut at_honest = honest.gossip.subscribe(topic);
    let mut at_far = far.gossip.subscribe(topic);
    far.gossip.add_peers(&[honest.id()]).await;

    let mut raw = forger
        .gossip
        .protocol()
        .subscribe(topic_id(CHAIN_ID, topic), vec![honest.id()])
        .await
        .unwrap();
    raw.joined().await.unwrap();
    wait_for_neighbours(&honest, &[topic]).await;
    wait_for_neighbours(&far, &[topic]).await;

    let mut stale = message(topic, 1);
    stale.timestamp -= 2 * 3_600_000;
    let mut from_the_future = message(topic, 2);
    from_the_future.timestamp += 3_600_000;
    for bytes in [
        stale.to_bytes().unwrap(),
        from_the_future.to_bytes().unwrap(),
        bytes::Bytes::from_static(b"not a network message"),
    ] {
        raw.broadcast_neighbors(bytes).await.unwrap();
    }
    raw.broadcast_neighbors(message(topic, 9).to_bytes().unwrap())
        .await
        .unwrap();

    assert_eq!(
        tag_of(&recv(&mut at_honest, "valid message").await),
        9,
        "only the valid message is delivered"
    );
    assert_eq!(
        tag_of(&recv(&mut at_far, "valid message").await),
        9,
        "only the valid message is passed on"
    );
    assert!(honest.metrics.gossip_rejected_invalid.get() >= 3);
    assert!(at_honest.try_recv().is_err());
}

/// A participant that keeps sending invalid messages is scored down to a
/// ban: its gossip connection is closed and nothing it sends is delivered.
#[tokio::test]
async fn a_spamming_neighbour_is_banned_and_disconnected() {
    let lookup = MemoryLookup::new();
    let honest = node(&lookup).await;
    let spammer = peer(&lookup).await;
    let topic = "tenzro/transactions";
    let mut at_honest = honest.gossip.subscribe(topic);

    let mut raw = spammer
        .gossip
        .protocol()
        .subscribe(topic_id(CHAIN_ID, topic), vec![honest.id()])
        .await
        .unwrap();
    raw.joined().await.unwrap();
    wait_for_neighbours(&honest, &[topic]).await;

    for n in 0..20u8 {
        raw.broadcast_neighbors(bytes::Bytes::from(vec![n; 8]))
            .await
            .unwrap();
    }
    let deadline = tokio::time::Instant::now() + WAIT;
    while honest.gossip.neighbour_count(topic).unwrap() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the spammer was never dropped"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = raw
        .broadcast_neighbors(message(topic, 1).to_bytes().unwrap())
        .await;
    assert!(
        timeout(Duration::from_secs(3), at_honest.recv())
            .await
            .is_err(),
        "nothing from a banned neighbour is delivered"
    );
}

/// An honest neighbour relaying more transactions than its budget allows
/// keeps its standing: the excess is shed, it is neither disconnected nor
/// banned, and the certificates it relays still arrive.
#[tokio::test]
async fn a_busy_transaction_relay_still_delivers_certificates() {
    let lookup = MemoryLookup::new();
    let honest = node(&lookup).await;
    let relay = peer(&lookup).await;
    let (txs, certs) = ("tenzro/transactions", "tenzro/certificates");
    let mut tx_in = honest.gossip.subscribe(txs);
    let mut cert_in = honest.gossip.subscribe(certs);

    let mut raw_tx = relay
        .gossip
        .protocol()
        .subscribe(topic_id(CHAIN_ID, txs), vec![honest.id()])
        .await
        .unwrap();
    let mut raw_cert = relay
        .gossip
        .protocol()
        .subscribe(topic_id(CHAIN_ID, certs), vec![honest.id()])
        .await
        .unwrap();
    raw_tx.joined().await.unwrap();
    raw_cert.joined().await.unwrap();
    wait_for_neighbours(&honest, &[txs, certs]).await;

    // Over the transaction budget by enough that, were excess blamed, the
    // relay's reputation would reach the ban threshold.
    const RELAYED: u32 = 1_200;
    for n in 0..RELAYED {
        let tx = NetworkMessage::new(MessagePayload::Custom {
            topic: txs.to_string(),
            data: n.to_le_bytes().to_vec(),
        });
        raw_tx
            .broadcast_neighbors(tx.to_bytes().unwrap())
            .await
            .unwrap();
    }
    let mut delivered = 0u32;
    while timeout(Duration::from_secs(2), tx_in.recv()).await.is_ok() {
        delivered += 1;
    }
    raw_cert
        .broadcast_neighbors(message(certs, 7).to_bytes().unwrap())
        .await
        .unwrap();
    let cert = timeout(Duration::from_secs(5), cert_in.recv()).await;
    eprintln!(
        "relayed {RELAYED} transactions, {delivered} delivered; tx neighbours now {}; certificate delivered: {}",
        honest.gossip.neighbour_count(txs).unwrap(),
        matches!(cert, Ok(Some(_)))
    );
    assert!(
        matches!(cert, Ok(Some(ref m)) if tag_of(m) == 7),
        "the relay's certificate was dropped after its transactions went over budget"
    );
    assert!(
        honest.gossip.neighbour_count(txs).unwrap() > 0,
        "the honest relay was disconnected"
    );
    assert!(
        u64::from(delivered) <= LIMITS.general_messages,
        "transactions over the budget are shed"
    );
}

/// A node that joins after messages were sent receives the ones sent after
/// it joined.
#[tokio::test]
async fn a_late_joiner_receives_later_messages() {
    let lookup = MemoryLookup::new();
    let a = node(&lookup).await;
    let b = node(&lookup).await;
    let topic = "tenzro/certificates";
    let _at_a = a.gossip.subscribe(topic);
    let mut at_b = b.gossip.subscribe(topic);
    b.gossip.add_peers(&[a.id()]).await;
    wait_for_neighbours(&b, &[topic]).await;
    a.gossip.broadcast(topic, message(topic, 1)).await.unwrap();
    assert_eq!(tag_of(&recv(&mut at_b, "first").await), 1);

    let late = node(&lookup).await;
    let mut at_late = late.gossip.subscribe(topic);
    late.gossip.add_peers(&[b.id()]).await;
    wait_for_neighbours(&late, &[topic]).await;
    a.gossip.broadcast(topic, message(topic, 2)).await.unwrap();
    assert_eq!(tag_of(&recv(&mut at_late, "after joining").await), 2);
    assert!(at_late.try_recv().is_err(), "nothing from before it joined");
}

/// The node's service carries its gossip over the attached endpoint:
/// subscribe and broadcast through `NetworkService` reach another node.
#[tokio::test]
async fn the_network_service_gossips_over_the_attached_endpoint() {
    let lookup = MemoryLookup::new();
    let a_peer = peer(&lookup).await;
    let b_peer = peer(&lookup).await;
    let a = TenzroNetworkService::new(LIMITS).await.unwrap();
    let b = TenzroNetworkService::new(LIMITS).await.unwrap();
    let topic = "tenzro/transactions";

    let early = a.subscribe(topic).await.unwrap();
    assert!(
        a.broadcast(topic, message(topic, 0)).await.is_err(),
        "nothing to publish over before the endpoint is attached"
    );
    drop(early);
    a.attach_gossip(a_peer.gossip.clone(), CHAIN_ID).unwrap();
    b.attach_gossip(b_peer.gossip.clone(), CHAIN_ID).unwrap();
    let mut at_b = b.subscribe(topic).await.unwrap();
    b.add_gossip_peers(&[a_peer.endpoint.id()]).await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while b.mesh_peer_count(topic).await.unwrap() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no neighbour");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    a.broadcast(topic, message(topic, 5)).await.unwrap();
    assert_eq!(tag_of(&recv(&mut at_b, "service broadcast").await), 5);
    assert!(b.mesh_peer_count("tenzro/never-joined").await.is_err());
}
