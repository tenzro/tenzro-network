//! A release notice crossing three nodes in one process, over iroh gossip.
//!
//! A publishes, B relays, C hears only through B: C is never told A's
//! address. Each node keeps its own notice cache and judges what arrives with
//! the same code the node runs (`update_notice::serve_inbound`).

use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointId};
use tenzro_iroh::gossip::{ALPN_GOSSIP, GossipGate, GossipTransport};
use tenzro_network::{GossipLimits, NetworkGossip, NetworkMetrics};
use tenzro_node::update_notice::{self, NoticeHub, TOPIC};
use tenzro_update_notice::Severity;
use tenzro_update_notice::notice::fixture::{key, notice, signed};

const CHAIN_ID: u64 = 4243;
const WAIT: Duration = Duration::from_secs(30);

const LIMITS: GossipLimits = GossipLimits {
    window: Duration::from_secs(10),
    consensus_messages: 1_000,
    general_messages: 1_000,
    ban: Duration::from_secs(300),
};

struct Node {
    endpoint: Endpoint,
    gossip: NetworkGossip,
    hub: Arc<NoticeHub>,
    dir: tempfile::TempDir,
    _router: Router,
}

impl Node {
    fn id(&self) -> EndpointId {
        self.endpoint.id()
    }
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

/// A node that runs 0.2.1 and trusts the test key.
async fn node(lookup: &MemoryLookup) -> Node {
    let gate = GossipGate::default();
    let endpoint = Endpoint::builder(presets::Minimal)
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
    let gossip = NetworkGossip::new(NetworkMetrics::unregistered(), LIMITS);
    gossip.attach(transport, CHAIN_ID).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let hub = Arc::new(NoticeHub::new(
        dir.path(),
        "stable",
        "0.2.1".parse().unwrap(),
        vec![key(1).public_sec1()],
    ));
    tokio::spawn(update_notice::serve_inbound(
        hub.clone(),
        gossip.subscribe_validated(TOPIC),
    ));
    Node {
        endpoint,
        gossip,
        hub,
        dir,
        _router: router,
    }
}

async fn wait_for_neighbours(n: &Node) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while n.gossip.neighbour_count(TOPIC).unwrap() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no neighbour on the notice topic"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn holds(n: &Node, version: &str) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if n.hub
            .current(now_ms())
            .is_some_and(|(held, _)| held.version == version)
        {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn dated(version: &str, severity: Severity) -> tenzro_update_notice::Notice {
    let mut n = notice(version, severity);
    let now = now_ms();
    n.released_ms = now - 3_600_000;
    n.issued_ms = now - 1_000;
    n.expires_ms = now + 30 * 24 * 3_600_000;
    n
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notice_published_at_one_node_reaches_a_node_that_only_knows_the_relay() {
    let lookup = MemoryLookup::new();
    let a = node(&lookup).await;
    let b = node(&lookup).await;
    let c = node(&lookup).await;
    a.gossip.add_peers(&[b.id()]).await;
    c.gossip.add_peers(&[b.id()]).await;
    for n in [&a, &b, &c] {
        wait_for_neighbours(n).await;
    }

    // A forged and a tampered notice go first: nobody keeps or passes them on.
    let good = dated("0.2.2", Severity::Security);
    let forged = signed(&key(2), &dated("0.2.9", Severity::Normal));
    a.gossip
        .broadcast(TOPIC, update_notice::message(&forged))
        .await
        .unwrap();
    // Not published through A's own hub, as a publisher outside the network would.
    let bytes = signed(&key(1), &good);
    assert!(a.hub.accept(&bytes, now_ms()).is_ok());
    a.gossip
        .broadcast(TOPIC, update_notice::message(&bytes))
        .await
        .unwrap();

    assert!(holds(&b, "0.2.2").await, "the relay verified and kept it");
    assert!(
        holds(&c, "0.2.2").await,
        "the far node heard it through the relay"
    );
    assert!(b.hub.current(now_ms()).unwrap().0.version != "0.2.9");
    assert!(c.hub.current(now_ms()).unwrap().0.version != "0.2.9");

    // Each node's cache survives its restart: a new hub over the same directory.
    let again = NoticeHub::new(
        c.dir.path(),
        "stable",
        "0.2.1".parse().unwrap(),
        vec![key(1).public_sec1()],
    );
    assert_eq!(again.current(now_ms()).unwrap().0.version, "0.2.2");

    // A later signing of the same release (raised severity) also propagates.
    let mut raised = dated("0.2.2", Severity::RequiredByEpoch { epoch: 90 });
    raised.issued_ms = now_ms();
    let bytes = signed(&key(1), &raised);
    a.hub.accept(&bytes, now_ms()).unwrap();
    a.gossip
        .broadcast(TOPIC, update_notice::message(&bytes))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let sev = c.hub.current(now_ms()).unwrap().0.severity;
        if sev == (Severity::RequiredByEpoch { epoch: 90 }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the raised notice never arrived"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
