//! The in-process cluster every contract test runs against.
//!
//! Four endpoints, one per way a node can sit on the network, all behind one
//! local relay started for the test (never public infrastructure):
//!
//! - `Direct`: publishes its relay and its direct addresses.
//! - `NatOnly`: publishes only its relay; peers reach it through the relay
//!   and may be upgraded to a direct path by hole punching.
//! - `OutboundOnly`: serves nothing and publishes nothing; it only dials.
//! - `RelayOnly`: has no IP transport at all; every byte goes through the
//!   relay (a private node that exposes no address).
//!
//! Every node carries the node's own gossip layer (`NetworkGossip` with the
//! node's validation rules, over the iroh gossip transport and its endpoint
//! gate). Two constructors differ in how peers find each other:
//!
//! - [`Cluster::start`]: peers find each other by endpoint id through an
//!   in-memory address lookup holding exactly what each node publishes, behind
//!   the test relay iroh ships. Needs no hardware key.
//! - [`Cluster::identified`]: the network as a node forms it. Node 0 serves
//!   the Tenzro relay role on loopback; every other node is told that one
//!   machine identity and the relay it is reached through, and learns the
//!   rest from the signed endpoint records Tenzro nodes store and serve over
//!   the discovery protocol. Each node signs its record with its own machine
//!   key, a key in the test host's TPM, so it runs where a TPM does and
//!   fails, naming the missing TPM, where none is present.

use std::any::Any;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{Builder, presets};
use iroh::protocol::{Router, RouterBuilder};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl};
use tenzro_device_key::HardwareSigner;
use tenzro_iroh::discovery::{ALPN_DISCOVERY, DiscoveryProtocol, DiscoveryRequest, ask};
use tenzro_iroh::gossip::{ALPN_GOSSIP, GossipGate, GossipTransport};
use tenzro_iroh::identity_record::BootIdentity;
use tenzro_iroh::identity_transport::{
    IdentityTransport, RelayRoleConfig, base_builder, endpoint_addr, with_relays,
};
use tenzro_iroh::{Connectivity, EndpointRecord};
use tenzro_network::{
    GossipLimits, MessagePayload, NetworkGossip, NetworkMessage, NetworkMetrics, ValidatedMessage,
};
use tokio::sync::mpsc;

/// Longest one exchange on one route may take.
pub const STEP: Duration = Duration::from_secs(30);

/// The chain the cluster's gossip topics are on.
const CHAIN_ID: u64 = 4242;

/// Per-neighbour gossip budgets for the cluster: generous, the contract is
/// about reach, not rate.
const LIMITS: GossipLimits = GossipLimits {
    window: Duration::from_secs(10),
    consensus_messages: 1_000,
    general_messages: 1_000,
    ban: Duration::from_secs(300),
};

/// How a node reaches, and is reached by, the rest of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Direct,
    NatOnly,
    OutboundOnly,
    RelayOnly,
}

impl Reach {
    /// Whether the node accepts connections.
    pub fn listens(self) -> bool {
        self != Reach::OutboundOnly
    }

    pub fn label(self) -> &'static str {
        match self {
            Reach::Direct => "direct",
            Reach::NatOnly => "nat-only",
            Reach::OutboundOnly => "outbound-only",
            Reach::RelayOnly => "relay-only",
        }
    }
}

/// The four topologies, in node-index order.
pub const TOPOLOGY: [Reach; 4] = [
    Reach::Direct,
    Reach::NatOnly,
    Reach::OutboundOnly,
    Reach::RelayOnly,
];

/// A node's machine identity and its view of the network: what the node's
/// `IdentityTransport` holds.
pub struct Identity {
    pub transport: Arc<IdentityTransport>,
    pub did: String,
    signer: &'static dyn HardwareSigner,
    /// Whether the node publishes its record (a node that serves nothing and
    /// publishes nothing only learns).
    publishes: bool,
}

impl Identity {
    /// One round of the node's record loop.
    pub async fn sync(&self, endpoint: &Endpoint) {
        let signer = self.publishes.then_some(self.signer);
        self.transport.sync_once(endpoint, signer).await;
    }
}

/// A node's gossip layer.
pub struct Gossip {
    pub layer: NetworkGossip,
}

/// One node of the cluster.
pub struct Node {
    pub index: usize,
    pub reach: Reach,
    pub endpoint: Endpoint,
    pub gossip: Gossip,
    /// Present on an [`Cluster::identified`] cluster.
    pub identity: Option<Identity>,
    /// Keeps the node's protocols served for the cluster's lifetime.
    _router: Option<Router>,
}

impl Node {
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// The node's machine identity; panics on a cluster without identities.
    pub fn identity(&self) -> &Identity {
        self.identity
            .as_ref()
            .expect("this cluster has no machine identities")
    }
}

/// A running cluster. Dropping it closes every endpoint and the relay.
pub struct Cluster {
    pub nodes: Vec<Node>,
    relay_url: RelayUrl,
    _relay: Box<dyn Any + Send>,
}

/// A message on `topic` carrying `tag`.
fn message(topic: &str, tag: u8) -> NetworkMessage {
    NetworkMessage::new(MessagePayload::Custom {
        topic: topic.to_string(),
        data: vec![tag],
    })
}

fn tag_of(message: &NetworkMessage) -> Option<u8> {
    match &message.payload {
        MessagePayload::Custom { data, .. } => data.first().copied(),
        _ => None,
    }
}

/// The node's gossip layer on `endpoint`, its protocol registered on the
/// router when the node accepts connections.
fn attach_gossip(
    endpoint: &Endpoint,
    gate: GossipGate,
    router: Option<RouterBuilder>,
) -> (Gossip, Option<RouterBuilder>) {
    let transport = GossipTransport::spawn(endpoint, gate);
    let metrics = NetworkMetrics::unregistered();
    let layer = NetworkGossip::new(metrics, LIMITS);
    layer
        .attach(transport.clone(), CHAIN_ID)
        .expect("attach gossip");
    let router = router.map(|r| r.accept(ALPN_GOSSIP, transport.protocol()));
    (Gossip { layer }, router)
}

/// The machine keys of an identified cluster: one key per node, opened once
/// per process so concurrent tests do not race to create them. A host with a
/// TPM holds them in it. A host without one is admitted all the same: each
/// node's key is then held by a provider, reached through the key holder
/// whose socket for node `i` is `$TENZRO_TEST_KEY_HOLDER_DIR/node-{i}.sock`
/// (the same delegated path a TPM-less node runs on).
fn machine_signers(count: usize) -> Vec<&'static dyn HardwareSigner> {
    static OPEN: Mutex<()> = Mutex::new(());
    let _guard = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    let holders = std::env::var_os("TENZRO_TEST_KEY_HOLDER_DIR").map(std::path::PathBuf::from);
    (0..count)
        .map(|i| {
            let label = format!("network-contract-{i}");
            let signer: Box<dyn HardwareSigner> =
                if tenzro_device_key::signer::platform_backend().is_some() {
                    tenzro_device_key::signer::open_or_create(&label).unwrap_or_else(|e| {
                        panic!("the machine key of node {i} does not open in this host's TPM: {e}")
                    })
                } else if let Some(dir) = &holders {
                    let config = tenzro_node::remote_tpm::RemoteConfig {
                        label,
                        key_holder: dir.join(format!("node-{i}.sock")),
                    };
                    Box::new(tenzro_node::remote_tpm::open(&config).unwrap_or_else(|e| {
                        panic!("the delegated machine key of node {i} does not open: {e}")
                    }))
                } else {
                    panic!(
                        "an identified cluster needs a machine key per node: this host has no TPM, \
                         so set TENZRO_TEST_KEY_HOLDER_DIR to the directory of the key holders \
                         (node-N.sock) that reach a provider"
                    )
                };
            let signer: &'static dyn HardwareSigner = Box::leak(signer);
            signer
        })
        .collect()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free port")
        .local_addr()
        .expect("local address")
        .port()
}

impl Cluster {
    /// Endpoints only; nothing is served.
    pub async fn endpoints() -> Self {
        Self::start(|_, _, router| router).await
    }

    /// Bind the four nodes. `serve(index, endpoint, router)` registers the
    /// protocols a listening node serves; the outbound-only node serves none.
    pub async fn start<F>(serve: F) -> Self
    where
        F: Fn(usize, &Endpoint, RouterBuilder) -> RouterBuilder,
    {
        let (relay_map, relay_url, relay) = iroh::test_utils::run_relay_server()
            .await
            .expect("local test relay");
        let lookup = MemoryLookup::new();
        let mut nodes = Vec::with_capacity(TOPOLOGY.len());
        for (index, reach) in TOPOLOGY.into_iter().enumerate() {
            let gate = GossipGate::default();
            let mut builder = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Custom(relay_map.clone()))
                .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                .hooks(gate.clone());
            if reach == Reach::RelayOnly {
                builder = builder.clear_ip_transports();
            }
            let endpoint = builder.bind().await.expect("bind endpoint");
            endpoint
                .address_lookup()
                .expect("open endpoint")
                .add(lookup.clone());
            tokio::time::timeout(STEP, endpoint.online())
                .await
                .unwrap_or_else(|_| panic!("{} node never reached its relay", reach.label()));
            let router = reach
                .listens()
                .then(|| serve(index, &endpoint, Router::builder(endpoint.clone())));
            let (gossip, router) = attach_gossip(&endpoint, gate, router);
            nodes.push(Node {
                index,
                reach,
                endpoint,
                gossip,
                identity: None,
                _router: router.map(RouterBuilder::spawn),
            });
        }
        let cluster = Self {
            nodes,
            relay_url,
            _relay: Box::new(relay),
        };
        for node in &cluster.nodes {
            if let Some(addr) = cluster.published(node) {
                lookup.add_endpoint_info(addr);
            }
        }
        cluster
    }

    /// The network as a node forms it, with the discovery protocol served on
    /// every node that accepts connections and `serve` registering the rest.
    ///
    /// Node 0 serves the relay role on a loopback port and signs its record
    /// first. Every other node is given one machine identity and the relay
    /// that identity is reached through, and nothing else: no address, no
    /// endpoint id, no other identity. Nodes 1 and 3 then publish their
    /// records as a node does on start. Node 2 serves nothing, publishes
    /// nothing, and has learned nothing beyond the one identity it was given.
    pub async fn identified<F>(serve: F) -> Self
    where
        F: Fn(usize, &Endpoint, &Arc<IdentityTransport>, RouterBuilder) -> RouterBuilder,
    {
        let signers = machine_signers(TOPOLOGY.len());
        let dids: Vec<String> = signers
            .iter()
            .map(|s| {
                tenzro_types::did_derivation::machine_did(
                    &s.public_key_sec1().expect("machine key"),
                )
            })
            .collect();
        let port = free_port();
        let url = url::Url::parse(&format!("http://127.0.0.1:{port}/")).expect("relay url");
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().expect("bind address"),
            public_url: url.clone(),
        };
        let boot: Vec<BootIdentity> = vec![format!("{}@{url}", dids[0]).parse().expect("boot")];

        let mut nodes: Vec<Node> = Vec::with_capacity(TOPOLOGY.len());
        let mut relay_holder: Option<Arc<IdentityTransport>> = None;
        for (index, reach) in TOPOLOGY.into_iter().enumerate() {
            let transport = if index == 0 {
                IdentityTransport::start(Vec::new(), &[], Some(&role), Some(dids[0].clone())).await
            } else {
                IdentityTransport::start(boot.clone(), &[], None, Some(dids[index].clone())).await
            }
            .unwrap_or_else(|e| panic!("{} node: identity transport: {e}", reach.label()));
            assert!(
                transport.relays().iter().any(|r| r.url == url),
                "{} node never admitted the relay its identity is reached through",
                reach.label()
            );
            let gate = GossipGate::default();
            let mut builder: Builder = with_relays(
                base_builder().portmapper_config(iroh::endpoint::PortmapperConfig::Disabled),
                transport.relays(),
                Some(transport.store().clone()),
            )
            .hooks(gate.clone());
            if reach == Reach::RelayOnly {
                builder = builder.clear_ip_transports();
            }
            let endpoint = builder.bind().await.expect("bind endpoint");
            tokio::time::timeout(STEP, endpoint.online())
                .await
                .unwrap_or_else(|_| panic!("{} node never reached its relay", reach.label()));
            let router = reach.listens().then(|| {
                let router = Router::builder(endpoint.clone()).accept(
                    ALPN_DISCOVERY,
                    DiscoveryProtocol::new(transport.store().clone()),
                );
                serve(index, &endpoint, &transport, router)
            });
            let (gossip, router) = attach_gossip(&endpoint, gate, router);
            let identity = Identity {
                transport: transport.clone(),
                did: dids[index].clone(),
                signer: signers[index],
                publishes: reach.listens(),
            };
            if index == 0 {
                // The relay answers its operator's record at /identity: it
                // must exist before any other node starts.
                identity.sync(&endpoint).await;
                relay_holder = Some(transport);
            } else if reach.listens() {
                identity.sync(&endpoint).await;
            }
            nodes.push(Node {
                index,
                reach,
                endpoint,
                gossip,
                identity: Some(identity),
                _router: router.map(RouterBuilder::spawn),
            });
        }
        // The relay operator takes the records published after its own.
        nodes[0].identity().sync(&nodes[0].endpoint).await;
        Self {
            nodes,
            relay_url: RelayUrl::from(url),
            _relay: Box::new(relay_holder),
        }
    }

    /// What `node` publishes about how to reach it: nothing for a node that
    /// accepts no connections, only its relay for a node behind NAT or
    /// without IP transports.
    pub fn published(&self, node: &Node) -> Option<EndpointAddr> {
        match node.reach {
            Reach::OutboundOnly => None,
            Reach::Direct => Some(node.endpoint.addr()),
            Reach::NatOnly | Reach::RelayOnly => {
                Some(EndpointAddr::new(node.id()).with_relay_url(self.relay_url.clone()))
            }
        }
    }

    /// The relay every node of the cluster is behind.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }

    /// Every (client, server) pair: each node dialing each other node that
    /// accepts connections.
    pub fn routes(&self) -> Vec<(&Node, &Node)> {
        let mut out = Vec::new();
        for client in &self.nodes {
            for server in &self.nodes {
                if client.index != server.index && server.reach.listens() {
                    out.push((client, server));
                }
            }
        }
        out
    }

    /// Run `exchange` on every route and fail with every route that failed.
    pub async fn on_every_route<'a, F, Fut>(&'a self, exchange: F)
    where
        F: Fn(&'a Node, &'a Node) -> Fut,
        Fut: Future<Output = Result<(), String>> + 'a,
    {
        let mut failures = Vec::new();
        let routes = self.routes();
        let count = routes.len();
        for (client, server) in routes {
            let label = format!("{} -> {}", client.reach.label(), server.reach.label());
            match tokio::time::timeout(STEP, exchange(client, server)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => failures.push(format!("{label}: {e}")),
                Err(_) => failures.push(format!("{label}: timed out")),
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {count} routes failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Publish on `topic` from every node and expect every other node to
    /// receive it, validated by the node's own rules. Every node is told one
    /// bootstrap peer, node 0, and meets the rest as gossip neighbours
    /// through it; the outbound-only node dials and is never dialed.
    pub async fn gossip_reaches_every_node(&self, topic: &str) -> Result<(), String> {
        enum Inbox {
            Plain(mpsc::Receiver<NetworkMessage>),
            Judged(mpsc::Receiver<ValidatedMessage>),
        }
        impl Inbox {
            async fn next(&mut self) -> Option<NetworkMessage> {
                match self {
                    Inbox::Plain(rx) => rx.recv().await,
                    Inbox::Judged(rx) => {
                        let held = rx.recv().await?;
                        held.ticket.accept();
                        Some(held.message)
                    }
                }
            }
        }
        let mut inboxes: Vec<Inbox> = self
            .nodes
            .iter()
            .map(|n| {
                if topic == "tenzro/blocks" {
                    Inbox::Judged(n.gossip.layer.subscribe_validated(topic))
                } else {
                    Inbox::Plain(n.gossip.layer.subscribe(topic))
                }
            })
            .collect();
        let bootstrap = self.nodes[0].id();
        for node in &self.nodes[1..] {
            node.gossip.layer.add_peers(&[bootstrap]).await;
        }
        let deadline = tokio::time::Instant::now() + STEP;
        for node in &self.nodes {
            while node.gossip.layer.neighbour_count(topic).unwrap_or(0) == 0 {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "{topic}: the {} node never got a neighbour",
                        node.reach.label()
                    ));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        for publisher in &self.nodes {
            let tag = publisher.index as u8;
            publisher
                .gossip
                .layer
                .broadcast(topic, message(topic, tag))
                .await
                .map_err(|e| {
                    format!(
                        "{topic}: {} node cannot publish: {e}",
                        publisher.reach.label()
                    )
                })?;
            for (receiver, inbox) in self.nodes.iter().zip(inboxes.iter_mut()) {
                if receiver.index == publisher.index {
                    continue;
                }
                let got = tokio::time::timeout(STEP, inbox.next())
                    .await
                    .map_err(|_| {
                        format!(
                            "{topic}: {} -> {}: nothing arrived",
                            publisher.reach.label(),
                            receiver.reach.label()
                        )
                    })?
                    .ok_or_else(|| {
                        format!("{topic}: the {} inbox closed", receiver.reach.label())
                    })?;
                if tag_of(&got) != Some(tag) {
                    return Err(format!(
                        "{topic}: {} -> {}: a different message arrived",
                        publisher.reach.label(),
                        receiver.reach.label()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Resolve `target`'s endpoint from its machine identity, starting from
    /// `from`, through Tenzro discovery alone: `from` takes rounds of the
    /// record exchange with the peers it knows until it holds `target`'s
    /// signed record, then reaches the endpoint the record names and asks it
    /// for the same record.
    pub async fn discover(&self, from: usize, target: usize) -> Result<EndpointAddr, String> {
        let asker = &self.nodes[from];
        let wanted = self.nodes[target].identity().did.clone();
        let own = asker.identity();
        let deadline = tokio::time::Instant::now() + STEP;
        let record = loop {
            if let Some(record) = own.transport.store().lookup(&wanted) {
                break record;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "node {from} never resolved node {target} ({wanted}) from the records it was given"
                ));
            }
            own.sync(&asker.endpoint).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        let addr = endpoint_addr(&record).map_err(|e| e.to_string())?;
        let answer = tokio::time::timeout(
            STEP,
            ask(
                &asker.endpoint,
                addr.clone(),
                &DiscoveryRequest::Lookup(wanted.clone()),
            ),
        )
        .await
        .map_err(|_| {
            format!("node {from} could not reach the endpoint node {target}'s record names")
        })?
        .map_err(|e| format!("node {from} could not reach node {target}: {e}"))?;
        match answer {
            tenzro_iroh::discovery::DiscoveryResponse::Record(Some(r))
                if r.machine_did() == wanted =>
            {
                Ok(addr)
            }
            other => Err(format!(
                "the endpoint node {target}'s record names did not answer its own record: {other:?}"
            )),
        }
    }

    /// What node `index` reports about its reachability from its own
    /// connections and the reports its peers made.
    pub fn connectivity(&self, index: usize) -> Connectivity {
        let node = &self.nodes[index];
        node.identity().transport.connectivity(&node.endpoint)
    }

    /// Node `index`'s current record.
    pub fn record_of(&self, holder: usize, of: usize) -> Option<EndpointRecord> {
        let did = &self.nodes[of].identity().did;
        self.nodes[holder].identity().transport.store().lookup(did)
    }

    /// Node `index`'s machine key, to sign records with in tests that
    /// publish a record of their own.
    pub fn signer_of(&self, index: usize) -> &'static dyn HardwareSigner {
        self.nodes[index].identity().signer
    }
}
