//! Multi-node libp2p mesh formation simulation.
//!
//! Reproduces the exact topology that fails on testnet: multiple
//! TenzroNetworkService instances, real TCP/QUIC, dialed via discovered
//! listen addresses, joining gossipsub mesh on `tenzro/consensus/1.0.0`,
//! and exchanging real `NetworkMessage::Ping` payloads.
//!
//! These tests exist because every prior `tests/integration_test.rs` test
//! creates exactly ONE node — leaving the multi-node libp2p integration
//! boundary (mesh formation between TCP-connected processes) with zero
//! coverage. That is the boundary at which the `block_height=0` testnet
//! stall lives.
//!
//! A pass here means the bug is environmental (k8s networking, TLS, etc).
//! A fail here means the bug is reproducible locally and fixable without
//! deploys.

use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tenzro_network::{
    MessagePayload, NetworkConfig, NetworkMessage, NetworkService, TenzroNetworkService,
    ValidatorRegistry,
};
use tokio::time::timeout;

const CONSENSUS_TOPIC: &str = "tenzro/consensus/1.0.0";
const MESH_WAIT: Duration = Duration::from_secs(30);
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// Filters listen addresses to TCP only — QUIC dialing is not symmetric in
/// this transport stack and tests are simpler with a single transport path.
fn tcp_addrs(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    use libp2p::multiaddr::Protocol;
    addrs
        .iter()
        .filter(|a| a.iter().any(|p| matches!(p, Protocol::Tcp(_))))
        .cloned()
        .collect()
}

/// Spawns a node bound to ephemeral 127.0.0.1 ports and waits for it to
/// emit at least one TCP listen address. Returns the service and its bound
/// TCP addresses.
async fn spawn_node() -> (TenzroNetworkService, Vec<Multiaddr>) {
    let config = NetworkConfig::local();
    let service = TenzroNetworkService::new(config)
        .await
        .expect("network service spawned");

    // Poll until the swarm reports at least one TCP listen address.
    // OS port assignment is fast but not synchronous with service creation.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let addrs = service
            .listen_addresses()
            .await
            .expect("listen_addresses() succeeds");
        let tcp = tcp_addrs(&addrs);
        if !tcp.is_empty() {
            return (service, tcp);
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "node never bound a TCP listen address after 5s; addrs={:?}",
                addrs
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Two-node mesh formation: the minimum reproduction of the testnet
/// failure mode. Both nodes subscribe to the consensus topic, node B
/// dials node A, both wait for mesh ≥1, then A broadcasts and B receives.
#[tokio::test]
async fn two_node_consensus_mesh_forms_and_broadcasts() {
    let _ = tracing_subscriber::fmt::try_init();

    let (node_a, addrs_a) = spawn_node().await;
    let (node_b, _addrs_b) = spawn_node().await;

    tracing::info!("Node A addrs: {:?}", addrs_a);

    // Both subscribe to the consensus topic. Subscription must precede the
    // dial so that GRAFTs can be sent by gossipsub once the connection is
    // established.
    let mut rx_a = node_a
        .subscribe(CONSENSUS_TOPIC)
        .await
        .expect("A subscribed");
    let mut rx_b = node_b
        .subscribe(CONSENSUS_TOPIC)
        .await
        .expect("B subscribed");

    // Node B dials node A on its first bound TCP address.
    let dial_target = addrs_a[0].clone();
    node_b
        .dial(dial_target.clone())
        .await
        .expect("B dialed A");

    // Wait for the gossipsub mesh on the consensus topic to form on BOTH
    // sides. With only 2 nodes, mesh size of 1 is the maximum possible.
    let count_a = node_a
        .wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .expect("A mesh wait");
    let count_b = node_b
        .wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .expect("B mesh wait");

    assert!(
        count_a >= 1,
        "Node A's mesh on {} never reached >= 1 peer (got {}). \
         This reproduces the testnet stall.",
        CONSENSUS_TOPIC,
        count_a
    );
    assert!(
        count_b >= 1,
        "Node B's mesh on {} never reached >= 1 peer (got {}). \
         This reproduces the testnet stall.",
        CONSENSUS_TOPIC,
        count_b
    );

    // Mesh is up. A publishes; B should receive within a few seconds.
    let outbound = NetworkMessage::new(MessagePayload::Ping);
    let outbound_id = outbound.message_id.clone();
    node_a
        .broadcast(CONSENSUS_TOPIC, outbound)
        .await
        .expect("A broadcast Ping");

    let received = timeout(RECV_TIMEOUT, rx_b.recv())
        .await
        .expect("B received within timeout")
        .expect("B's subscription channel still open");

    assert_eq!(
        received.message_id, outbound_id,
        "B should receive the exact message A broadcast"
    );

    // Sanity: A's own subscription should NOT receive its own broadcast
    // (gossipsub does not echo to the publisher). Drain briefly to confirm.
    let echo = timeout(Duration::from_millis(500), rx_a.recv()).await;
    assert!(
        echo.is_err(),
        "publisher should not receive its own broadcast"
    );
}

/// Four-node mesh: mirrors the testnet topology (3 validators + 1 RPC).
/// All nodes subscribe to the consensus topic. Nodes 1, 2, 3 dial node 0.
/// Once the mesh forms across all 4, node 0 broadcasts and all of 1, 2,
/// 3 must receive.
#[tokio::test]
async fn four_node_consensus_mesh_full_propagation() {
    let _ = tracing_subscriber::fmt::try_init();

    let (n0, addrs_0) = spawn_node().await;
    let (n1, _) = spawn_node().await;
    let (n2, _) = spawn_node().await;
    let (n3, _) = spawn_node().await;

    let mut rx0 = n0.subscribe(CONSENSUS_TOPIC).await.expect("n0 sub");
    let mut rx1 = n1.subscribe(CONSENSUS_TOPIC).await.expect("n1 sub");
    let mut rx2 = n2.subscribe(CONSENSUS_TOPIC).await.expect("n2 sub");
    let mut rx3 = n3.subscribe(CONSENSUS_TOPIC).await.expect("n3 sub");

    // Star topology: 1, 2, 3 → 0. Gossipsub will form a fuller mesh via
    // peer exchange once the initial connections are up.
    let target = addrs_0[0].clone();
    n1.dial(target.clone()).await.expect("n1 dialed n0");
    n2.dial(target.clone()).await.expect("n2 dialed n0");
    n3.dial(target.clone()).await.expect("n3 dialed n0");

    // Wait for at least 1 mesh peer on every node. With 4 nodes in a star,
    // node 0 sees up to 3 peers; nodes 1/2/3 see at least 1 (node 0) and
    // potentially more after gossipsub's PX kicks in.
    let m0 = n0.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    let m1 = n1.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    let m2 = n2.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    let m3 = n3.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();

    assert!(m0 >= 1, "n0 mesh empty (got {})", m0);
    assert!(m1 >= 1, "n1 mesh empty (got {})", m1);
    assert!(m2 >= 1, "n2 mesh empty (got {})", m2);
    assert!(m3 >= 1, "n3 mesh empty (got {})", m3);

    // n0 broadcasts; n1, n2, n3 must all receive (possibly via flood
    // through n0, possibly via PX-formed direct mesh links).
    let outbound = NetworkMessage::new(MessagePayload::Ping);
    let id = outbound.message_id.clone();
    n0.broadcast(CONSENSUS_TOPIC, outbound)
        .await
        .expect("n0 broadcast");

    for (label, rx) in [
        ("n1", &mut rx1),
        ("n2", &mut rx2),
        ("n3", &mut rx3),
    ] {
        let msg = timeout(RECV_TIMEOUT, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{} did not receive within {:?}", label, RECV_TIMEOUT))
            .unwrap_or_else(|| panic!("{} subscription channel closed", label));
        assert_eq!(msg.message_id, id, "{} got wrong message", label);
    }

    // n0 should not receive its own broadcast.
    let echo = timeout(Duration::from_millis(500), rx0.recv()).await;
    assert!(echo.is_err(), "n0 should not echo its own broadcast");
}

/// Test validator-registry that holds a static set of authorized PeerIds.
/// Mirrors what `NodeValidatorRegistry` does on the cluster: gates
/// `consensus`/`attestations` topics so that only PeerIds present in the
/// set can publish to them.
struct StaticValidatorRegistry(HashSet<PeerId>);

impl ValidatorRegistry for StaticValidatorRegistry {
    fn is_validator(&self, peer_id: &PeerId) -> bool {
        self.0.contains(peer_id)
    }
    fn validator_peer_ids(&self) -> HashSet<PeerId> {
        self.0.clone()
    }
}

/// Reproduces the testnet topology including the `ValidatorRegistry` gate
/// on validator-only topics. If the cluster failure is caused by a peer
/// being absent from the local validator registry at message-arrival time,
/// this test will hang at `wait_for_mesh` or fail at `rx.recv()`.
///
/// 4 nodes, all installed with the SAME registry containing every peer.
/// This is the "happy path" — every peer should authorize every other.
#[tokio::test]
async fn four_node_with_validator_registry_propagates() {
    let _ = tracing_subscriber::fmt::try_init();

    let (n0, addrs_0) = spawn_node().await;
    let (n1, _) = spawn_node().await;
    let (n2, _) = spawn_node().await;
    let (n3, _) = spawn_node().await;

    // Collect all peer IDs into a registry shared by every node.
    let pid0 = n0.local_peer_id().await.unwrap();
    let pid1 = n1.local_peer_id().await.unwrap();
    let pid2 = n2.local_peer_id().await.unwrap();
    let pid3 = n3.local_peer_id().await.unwrap();
    let mut set = HashSet::new();
    set.insert(pid0);
    set.insert(pid1);
    set.insert(pid2);
    set.insert(pid3);
    let registry = Arc::new(StaticValidatorRegistry(set));

    n0.set_validator_registry(registry.clone()).await.unwrap();
    n1.set_validator_registry(registry.clone()).await.unwrap();
    n2.set_validator_registry(registry.clone()).await.unwrap();
    n3.set_validator_registry(registry.clone()).await.unwrap();

    let mut rx1 = n1.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let mut rx2 = n2.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let mut rx3 = n3.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let _rx0 = n0.subscribe(CONSENSUS_TOPIC).await.unwrap();

    let target = addrs_0[0].clone();
    n1.dial(target.clone()).await.unwrap();
    n2.dial(target.clone()).await.unwrap();
    n3.dial(target.clone()).await.unwrap();

    let m0 = n0.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    let m1 = n1.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    let m2 = n2.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    let m3 = n3.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();

    assert!(m0 >= 1 && m1 >= 1 && m2 >= 1 && m3 >= 1,
        "mesh formation failed with registry installed: m0={}, m1={}, m2={}, m3={}",
        m0, m1, m2, m3);

    let outbound = NetworkMessage::new(MessagePayload::Ping);
    let id = outbound.message_id.clone();
    n0.broadcast(CONSENSUS_TOPIC, outbound).await.unwrap();

    for (label, rx) in [("n1", &mut rx1), ("n2", &mut rx2), ("n3", &mut rx3)] {
        let msg = timeout(RECV_TIMEOUT, rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} did not receive within {:?} — validator-registry gate may be blocking",
                    label, RECV_TIMEOUT
                )
            })
            .unwrap_or_else(|| panic!("{} channel closed", label));
        assert_eq!(msg.message_id, id);
    }
}

/// Reproduces the most likely testnet failure mode: validator-registry is
/// installed BUT the publisher's PeerId is **missing** from the registry
/// of receivers (which happens transiently during early startup before
/// `try_register_validator_on_identify` has fired).
///
/// Expected: messages from the unknown publisher are dropped on receipt.
/// `rx.recv()` should time out.
///
/// This test asserts the EXPECTED gating behavior — if it fails (i.e.
/// messages get through), the gate is not working as designed. If it
/// passes (timeout occurs), it confirms the gate IS the silent killer
/// and we need to look at why `try_register_validator_on_identify` isn't
/// firing on the cluster.
#[tokio::test]
async fn validator_registry_blocks_unknown_publisher() {
    let _ = tracing_subscriber::fmt::try_init();

    let (publisher, addrs_pub) = spawn_node().await;
    let (receiver, _) = spawn_node().await;

    // Receiver's registry contains ONLY the receiver itself, NOT the
    // publisher. This simulates the early-startup window before identify
    // has admitted the publisher into the validator set.
    let receiver_pid = receiver.local_peer_id().await.unwrap();
    let mut set = HashSet::new();
    set.insert(receiver_pid);
    let registry = Arc::new(StaticValidatorRegistry(set));
    receiver
        .set_validator_registry(registry)
        .await
        .unwrap();

    let mut rx = receiver.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let _publisher_rx = publisher.subscribe(CONSENSUS_TOPIC).await.unwrap();

    receiver.dial(addrs_pub[0].clone()).await.unwrap();

    // Mesh still forms at gossipsub layer — gating happens on inbound
    // *messages*, not on subscription/handshake.
    let m_pub = publisher
        .wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();
    let m_recv = receiver
        .wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();
    assert!(m_pub >= 1 && m_recv >= 1, "mesh did not form: pub={}, recv={}", m_pub, m_recv);

    let outbound = NetworkMessage::new(MessagePayload::Ping);
    publisher
        .broadcast(CONSENSUS_TOPIC, outbound)
        .await
        .expect("publisher broadcast (gossipsub layer succeeds)");

    // Receiver should NOT deliver the message because publisher's PeerId
    // is not in the validator registry. `authorize_peer_for_topic`
    // returns false → message dropped silently before forwarding.
    let result = timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        result.is_err(),
        "Receiver delivered a message from a non-validator publisher — \
         the validator-only topic gate is NOT enforcing as designed. \
         Got: {:?}",
        result
    );
}

/// Dynamic-admission registry that mirrors `NodeValidatorRegistry`: it
/// starts empty and admits peers via `try_add_validator()` once identify
/// confirms a Tenzro protocol version. This is the production behavior.
struct DynamicValidatorRegistry {
    inner: Arc<dashmap::DashMap<PeerId, ()>>,
}

impl ValidatorRegistry for DynamicValidatorRegistry {
    fn is_validator(&self, peer_id: &PeerId) -> bool {
        self.inner.contains_key(peer_id)
    }
    fn validator_peer_ids(&self) -> HashSet<PeerId> {
        self.inner.iter().map(|e| *e.key()).collect()
    }
    fn try_add_validator(&self, peer_id: &PeerId) {
        if !self.inner.contains_key(peer_id) {
            self.inner.insert(*peer_id, ());
            tracing::info!(peer = %peer_id, "DynamicValidatorRegistry admitted peer");
        }
    }
}

/// Reproduces the production code path:
///   - Each node has an EMPTY `DynamicValidatorRegistry` initially.
///   - On identify handshake, each side admits the other.
///   - First publish must wait for identify to complete on both sides
///     OR messages will be dropped.
///
/// `wait_for_mesh()` is meant to gate the first publish until the mesh
/// has enough peers — but if identify is still racing, even a non-empty
/// mesh may not deliver messages because the inbound side rejects them.
///
/// PASS = wait_for_mesh + a brief settling delay is sufficient.
/// FAIL = the dynamic-admission path has a real timing bug that needs
/// fixing on the cluster.
#[tokio::test]
async fn dynamic_admission_via_identify_propagates_consensus() {
    let _ = tracing_subscriber::fmt::try_init();

    let (n0, addrs_0) = spawn_node().await;
    let (n1, _) = spawn_node().await;
    let (n2, _) = spawn_node().await;
    let (n3, _) = spawn_node().await;

    // Each node gets ITS OWN empty registry — admission happens via
    // identify, not via prior knowledge of the validator set.
    for n in [&n0, &n1, &n2, &n3] {
        let reg = Arc::new(DynamicValidatorRegistry {
            inner: Arc::new(dashmap::DashMap::new()),
        });
        n.set_validator_registry(reg).await.unwrap();
    }

    let mut rx1 = n1.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let mut rx2 = n2.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let mut rx3 = n3.subscribe(CONSENSUS_TOPIC).await.unwrap();

    let target = addrs_0[0].clone();
    n1.dial(target.clone()).await.unwrap();
    n2.dial(target.clone()).await.unwrap();
    n3.dial(target.clone()).await.unwrap();

    // Mesh formation
    n0.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    n1.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    n2.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();
    n3.wait_for_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT).await.unwrap();

    // Identify is a separate protocol from gossipsub. wait_for_mesh
    // confirms gossipsub is ready, but does NOT confirm identify has
    // completed. Sleep briefly to let identify catch up. If THIS is the
    // missing gate on the cluster, then `wait_for_mesh()` is insufficient
    // for validator-only topic delivery and we need a `wait_for_identify`
    // too.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let outbound = NetworkMessage::new(MessagePayload::Ping);
    let id = outbound.message_id.clone();
    n0.broadcast(CONSENSUS_TOPIC, outbound).await.unwrap();

    for (label, rx) in [("n1", &mut rx1), ("n2", &mut rx2), ("n3", &mut rx3)] {
        let msg = timeout(RECV_TIMEOUT, rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} never received via dynamic admission — identify path is broken",
                    label
                )
            })
            .unwrap_or_else(|| panic!("{} channel closed", label));
        assert_eq!(msg.message_id, id);
    }
}

/// **The fix verification test.** Reproduces the testnet stall topology:
/// 4 nodes, each with an EMPTY DynamicValidatorRegistry, dialing a star
/// topology. Uses `wait_for_admitted_mesh` (the new gate) instead of
/// `wait_for_mesh` + manual sleep — proving that the new gate is the
/// correct minimum-sufficient first-publish gate for validator-only topics.
///
/// Crucially: this test does NOT use any `tokio::time::sleep`. If the gate
/// is correct, mesh+admission convergence is detected the moment it
/// happens, and the broadcast lands.
#[tokio::test]
async fn wait_for_admitted_mesh_is_sufficient_first_publish_gate() {
    let _ = tracing_subscriber::fmt::try_init();

    let (n0, addrs_0) = spawn_node().await;
    let (n1, _) = spawn_node().await;
    let (n2, _) = spawn_node().await;
    let (n3, _) = spawn_node().await;

    for n in [&n0, &n1, &n2, &n3] {
        let reg = Arc::new(DynamicValidatorRegistry {
            inner: Arc::new(dashmap::DashMap::new()),
        });
        n.set_validator_registry(reg).await.unwrap();
    }

    let mut rx1 = n1.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let mut rx2 = n2.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let mut rx3 = n3.subscribe(CONSENSUS_TOPIC).await.unwrap();

    let target = addrs_0[0].clone();
    n1.dial(target.clone()).await.unwrap();
    n2.dial(target.clone()).await.unwrap();
    n3.dial(target.clone()).await.unwrap();

    // The gate: wait until each node has at least 1 admitted mesh peer.
    // No manual sleep — the polling cycle inside `wait_for_admitted_mesh`
    // detects the moment identify completes for the first peer.
    let a0 = n0
        .wait_for_admitted_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();
    let a1 = n1
        .wait_for_admitted_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();
    let a2 = n2
        .wait_for_admitted_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();
    let a3 = n3
        .wait_for_admitted_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();

    assert!(
        a0 >= 1 && a1 >= 1 && a2 >= 1 && a3 >= 1,
        "wait_for_admitted_mesh did not converge: a0={}, a1={}, a2={}, a3={} \
         — this would mean identify is not firing or registry is not getting populated.",
        a0, a1, a2, a3
    );

    let outbound = NetworkMessage::new(MessagePayload::Ping);
    let id = outbound.message_id.clone();
    n0.broadcast(CONSENSUS_TOPIC, outbound).await.unwrap();

    for (label, rx) in [("n1", &mut rx1), ("n2", &mut rx2), ("n3", &mut rx3)] {
        let msg = timeout(RECV_TIMEOUT, rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} did not receive after wait_for_admitted_mesh succeeded — \
                     this means the gate fired prematurely",
                    label
                )
            })
            .unwrap_or_else(|| panic!("{} channel closed", label));
        assert_eq!(msg.message_id, id);
    }
}

/// Permissive mode: when no validator registry is installed,
/// `wait_for_admitted_mesh` should fall back to plain mesh peer count.
/// This guards against breaking single-node / pre-genesis startup.
#[tokio::test]
async fn wait_for_admitted_mesh_permissive_when_no_registry() {
    let _ = tracing_subscriber::fmt::try_init();

    let (n0, addrs_0) = spawn_node().await;
    let (n1, _) = spawn_node().await;

    // No validator registry installed — pre-genesis / single-node mode.
    let mut rx1 = n1.subscribe(CONSENSUS_TOPIC).await.unwrap();
    let _rx0 = n0.subscribe(CONSENSUS_TOPIC).await.unwrap();

    n1.dial(addrs_0[0].clone()).await.unwrap();

    // Without a registry, every mesh peer counts as "admitted" — gate
    // converges as soon as gossipsub mesh forms.
    let admitted = n0
        .wait_for_admitted_mesh(CONSENSUS_TOPIC, 1, MESH_WAIT)
        .await
        .unwrap();
    assert!(
        admitted >= 1,
        "permissive mode (no registry) should fall back to mesh count, got {}",
        admitted
    );

    let outbound = NetworkMessage::new(MessagePayload::Ping);
    let id = outbound.message_id.clone();
    n0.broadcast(CONSENSUS_TOPIC, outbound).await.unwrap();

    let msg = timeout(RECV_TIMEOUT, rx1.recv())
        .await
        .expect("permissive mode delivery within timeout")
        .expect("channel still open");
    assert_eq!(msg.message_id, id);
}
