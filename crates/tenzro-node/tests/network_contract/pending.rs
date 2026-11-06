//! Paths that need more than the endpoints: the gossip layer every node
//! carries, identity discovery over signed endpoint records, acceptance of
//! certified endpoints only, and the reachability a node reports. Each runs
//! on the same cluster as the transport paths.
//!
//! The gossip tests run anywhere. The discovery, acceptance and reachability
//! tests build an identified cluster, whose nodes sign their endpoint
//! records with machine keys in the test host's TPM (see `cluster`).

use tenzro_iroh::{NatKind, Reachability};

use crate::cluster::Cluster;

/// Every node publishes on `topic` and every other node receives it,
/// whichever way it is reachable.
async fn gossip(topic: &str) {
    let cluster = Cluster::endpoints().await;
    cluster
        .gossip_reaches_every_node(topic)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
}

macro_rules! gossip_topics {
    ($($name:ident => $topic:literal),* $(,)?) => {
        mod gossip {
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    super::gossip($topic).await;
                }
            )*
        }
    };
}

gossip_topics! {
    blocks => "tenzro/blocks",
    transactions => "tenzro/transactions",
    certificates => "tenzro/certificates",
    validators => "tenzro/validators",
    status => "tenzro/status",
    models => "tenzro/models",
    providers => "tenzro/providers",
    blobs => "tenzro/blobs",
    training => "tenzro/training",
    training_syncer => "tenzro/training/syncer",
    sla => "tenzro/sla",
    compute_observations => "tenzro/compute-observations",
}

mod discovery {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use futures::StreamExt;
    use tenzro_cluster::membership::testing::{Key, RP_ID, custody_digest, membership};
    use tenzro_cluster::{MembershipBook, VerifiedMembership};
    use tenzro_iroh::discovery::{DiscoveryRequest, DiscoveryResponse, ask};
    use tenzro_iroh::identity_record::{EndpointRecord, RecordScope};
    use tenzro_iroh::identity_transport::{endpoint_addr, iroh_endpoint_key};
    use tenzro_iroh::lan_discovery::{LanBinding, LanDiscovery};

    use crate::cluster::{Cluster, STEP};

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    async fn cluster() -> Cluster {
        Cluster::identified(|_, _, _, router| router).await
    }

    /// A node that knows one peer's identity resolves every other node,
    /// through records Tenzro nodes store and serve, with no outside
    /// discovery service or DHT.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_known_peer_finds_the_cluster() {
        let cluster = cluster().await;
        // The outbound-only node was given the relay operator's identity and
        // nothing else.
        let own = cluster.nodes[2].identity();
        assert!(
            cluster.nodes.iter().filter(|n| n.index != 2).all(|n| own
                .transport
                .store()
                .lookup(&n.identity().did)
                .is_none()
                || n.index == 0),
            "node 2 already held records it was never given"
        );
        for target in 0..cluster.nodes.len() {
            if target != 2 {
                let found = cluster.discover(2, target).await.unwrap();
                assert_eq!(found.id, cluster.nodes[target].id());
            }
        }
    }

    /// Discovery succeeds with no route to any public discovery host: the
    /// cluster's endpoints reach nothing but each other and the local relay.
    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_needs_no_outside_hosts() {
        let cluster = cluster().await;
        let found = cluster.discover(0, 3).await.unwrap();
        assert_eq!(found.id, cluster.nodes[3].id());
        assert_eq!(found.ip_addrs().count(), 0, "a record names no address");
        for node in &cluster.nodes {
            let relays: Vec<String> = node
                .endpoint
                .addr()
                .relay_urls()
                .map(ToString::to_string)
                .collect();
            assert!(
                relays.iter().all(|r| r == &cluster.relay_url().to_string()),
                "{} node is homed on a relay other than the local one: {relays:?}",
                node.reach.label()
            );
            let own = node.identity();
            assert_eq!(own.transport.relays().len(), 1, "one relay, the local one");
        }
    }

    /// A record signed by another identity, or one past its expiry, does not
    /// resolve.
    #[tokio::test(flavor = "multi_thread")]
    async fn forged_and_stale_records_are_rejected() {
        let cluster = cluster().await;
        let genuine = cluster.discover(1, 0).await.unwrap();
        assert_eq!(genuine.id, cluster.nodes[0].id());
        let held = cluster
            .record_of(1, 0)
            .expect("node 1 holds node 0's record");
        let attacker = &cluster.nodes[2];
        let target = cluster.nodes[1].endpoint.addr();

        // The record node 0 signed, redirected to the attacker's endpoint.
        let mut forged = held.clone();
        forged.endpoint = iroh_endpoint_key(attacker.id());
        forged.sequence += 1;
        // Signed by another identity, claiming to be node 0 by sequence.
        let by_another = EndpointRecord::sign(
            cluster.signer_of(2),
            iroh_endpoint_key(attacker.id()),
            held.relays.clone(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            held.sequence + 1,
            now_ms(),
        )
        .unwrap();
        // Node 0's own key, a validity window that closed an hour ago.
        let expired = EndpointRecord::sign(
            cluster.signer_of(0),
            iroh_endpoint_key(attacker.id()),
            held.relays.clone(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            held.sequence + 2,
            now_ms() - 7 * 3_600_000,
        )
        .unwrap();
        // Node 0's own key, an older sequence than the one held.
        let replayed = EndpointRecord::sign(
            cluster.signer_of(0),
            iroh_endpoint_key(attacker.id()),
            held.relays.clone(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            held.sequence - 1,
            now_ms(),
        )
        .unwrap();
        for (what, record) in [
            ("a record altered after signing", forged),
            ("an expired record", expired),
            ("a replayed older record", replayed),
        ] {
            let reply = ask(
                &attacker.endpoint,
                target.clone(),
                &DiscoveryRequest::Publish(record),
            )
            .await
            .unwrap();
            match reply {
                DiscoveryResponse::Published(Err(_)) => {}
                other => panic!("{what} was not refused: {other:?}"),
            }
        }
        // A record by another identity is kept, as that identity's own: it
        // never becomes node 0's.
        let reply = ask(
            &attacker.endpoint,
            target.clone(),
            &DiscoveryRequest::Publish(by_another),
        )
        .await
        .unwrap();
        assert!(
            matches!(reply, DiscoveryResponse::Published(Ok(_))),
            "{reply:?}"
        );

        let after = cluster.discover(1, 0).await.unwrap();
        assert_eq!(
            after.id,
            cluster.nodes[0].id(),
            "node 0 still resolves to node 0"
        );
        assert_eq!(
            cluster.record_of(1, 0).unwrap(),
            held,
            "the held record is unchanged"
        );
        assert_eq!(
            endpoint_addr(&cluster.record_of(1, 0).unwrap()).unwrap().id,
            cluster.nodes[0].id()
        );
    }

    /// A cluster member on the local segment is found by its machine identity
    /// and checked against the operator-signed membership list, with no
    /// external network.
    #[tokio::test(flavor = "multi_thread")]
    async fn lan_cluster_member_discovered_locally() {
        let cluster = cluster().await;
        let (operator, listener_key, member_key, stranger) =
            (Key::new(1), Key::new(2), Key::new(3), Key::new(4));
        let mut book = MembershipBook::new();
        book.offer(
            VerifiedMembership::verify(
                membership(&operator, "lab", 1, &[&listener_key, &member_key]),
                RP_ID,
                custody_digest,
            )
            .unwrap(),
        )
        .unwrap();
        let binding = |key: &Key, id: &iroh::EndpointId| LanBinding {
            member_id: key.machine_did().rsplit(':').next().unwrap().to_string(),
            signature: key.bind_lan(id.as_bytes()),
        };
        let local = |node: &crate::cluster::Node| -> Vec<SocketAddr> {
            node.endpoint
                .bound_sockets()
                .into_iter()
                .filter(SocketAddr::is_ipv4)
                .map(|a| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.port()))
                .collect()
        };

        let (listening, member, impostor) =
            (&cluster.nodes[0], &cluster.nodes[1], &cluster.nodes[2]);
        let listener = LanDiscovery::start(listening.id()).unwrap();
        let announcing = LanDiscovery::start(member.id()).unwrap();
        let faking = LanDiscovery::start(impostor.id()).unwrap();
        let mut sightings = listener.sightings().await;
        announcing
            .announce(local(member), &binding(&member_key, &member.id()))
            .unwrap();
        // Claims to be the member, signs with a key the list does not hold.
        let mut forged = binding(&stranger, &impostor.id());
        forged.member_id = binding(&member_key, &member.id()).member_id;
        faking.announce(local(impostor), &forged).unwrap();

        let mut verified = None;
        let mut rejected = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while (verified.is_none() || !rejected) && tokio::time::Instant::now() < deadline {
            let Ok(Some(s)) = tokio::time::timeout(Duration::from_secs(5), sightings.next()).await
            else {
                continue;
            };
            let found = book.verify_lan_peer(
                &listener_key.machine_did(),
                &s.binding.member_id,
                s.endpoint_id.as_bytes(),
                &s.binding.signature,
            );
            if s.endpoint_id == member.id() {
                verified = found.map(|did| (did, s));
            } else if s.endpoint_id == impostor.id() {
                assert_eq!(found, None, "a forged binding must not verify");
                rejected = true;
            }
        }
        let (did, sighting) = verified.expect("the member was never found on the local network");
        assert_eq!(did, member_key.machine_did());
        assert!(rejected, "the impostor was never seen");

        // The sighting carries what a dial needs: the member's address on the
        // segment, with no relay or record.
        let addr = sighting
            .addrs
            .iter()
            .fold(iroh::EndpointAddr::new(sighting.endpoint_id), |a, ip| {
                a.with_ip_addr(*ip)
            });
        let reply = tokio::time::timeout(
            STEP,
            ask(
                &listening.endpoint,
                addr,
                &DiscoveryRequest::Lookup(member.identity().did.clone()),
            ),
        )
        .await
        .expect("the sighted member answered")
        .unwrap();
        assert!(
            matches!(reply, DiscoveryResponse::Record(Some(_))),
            "{reply:?}"
        );
    }
}

mod acceptance {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use parking_lot::RwLock;
    use tenzro_iroh::consensus::ConsensusProtocol;
    use tenzro_iroh::discovery::{DiscoveryRequest, DiscoveryResponse, DiscoveryStore, ask};
    use tenzro_iroh::identity_record::{EndpointRecord, RecordScope};
    use tenzro_iroh::identity_transport::{base_builder, iroh_endpoint_key, with_relays};
    use tenzro_iroh::{
        ALPN_CONSENSUS, ConsensusStreamHandler, Endpoint, EndpointId, RecvStream, SendStream,
        open_consensus_stream, read_frame, write_frame,
    };

    use crate::cluster::{Cluster, STEP};

    /// Admits an endpoint only when a current record of an identity in the
    /// accepted set names it, as the node does for its validators, and answers
    /// every frame with the caller's key.
    #[derive(Debug)]
    struct AdmitCertified {
        store: Arc<DiscoveryStore>,
        accepted: Arc<RwLock<HashSet<String>>>,
        served: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ConsensusStreamHandler for AdmitCertified {
        fn admits(&self, remote: &[u8; 32]) -> bool {
            EndpointId::from_bytes(remote)
                .is_ok_and(|id| self.store.certified_in(id, &self.accepted.read()).is_some())
        }

        async fn accept_stream(
            &self,
            remote: [u8; 32],
            _rtt: Duration,
            mut send: SendStream,
            mut recv: RecvStream,
        ) {
            self.served.fetch_add(1, Ordering::SeqCst);
            while read_frame(&mut recv, 1024).await.is_ok() {
                if write_frame(&mut send, &remote).await.is_err() {
                    return;
                }
            }
        }
    }

    /// One frame over a consensus stream: the caller's key echoed back, or
    /// the error the refusal surfaced as.
    async fn exchange(from: &Endpoint, to: EndpointId) -> Result<Vec<u8>, String> {
        tokio::time::timeout(STEP, async {
            let (mut send, mut recv) = open_consensus_stream(from, to)
                .await
                .map_err(|e| e.to_string())?;
            write_frame(&mut send, b"vote")
                .await
                .map_err(|e| e.to_string())?;
            read_frame(&mut recv, 64).await.map_err(|e| e.to_string())
        })
        .await
        .map_err(|_| "timed out".to_string())?
    }

    /// An endpoint not certified by an identity in the accepted set is
    /// refused before any stream opens.
    #[tokio::test(flavor = "multi_thread")]
    async fn non_member_refused() {
        let accepted: Arc<RwLock<HashSet<String>>> = Arc::default();
        let served = Arc::new(AtomicUsize::new(0));
        let cluster = {
            let (accepted, served) = (accepted.clone(), served.clone());
            Cluster::identified(move |_, _, transport, router| {
                router.accept(
                    ALPN_CONSENSUS,
                    ConsensusProtocol::new(Arc::new(AdmitCertified {
                        store: transport.store().clone(),
                        accepted: accepted.clone(),
                        served: served.clone(),
                    })),
                )
            })
            .await
        };
        // The accepted set: the machines that publish records. Node 2 never
        // published and is outside it.
        *accepted.write() = [0, 1, 3]
            .into_iter()
            .map(|i| cluster.nodes[i].identity().did.clone())
            .collect();
        let server = &cluster.nodes[1];
        // The server holds the members' records.
        for member in [0, 3] {
            cluster.discover(1, member).await.unwrap();
        }

        // Members are admitted, on a direct node and on a relay-only one.
        for member in [0, 3] {
            let named = exchange(&cluster.nodes[member].endpoint, server.id())
                .await
                .unwrap_or_else(|e| panic!("member {member} refused: {e}"));
            assert_eq!(named.as_slice(), cluster.nodes[member].id().as_bytes());
        }
        let admitted = served.load(Ordering::SeqCst);
        assert_eq!(admitted, 2, "one stream per member");

        // An endpoint no record names.
        let stranger = &cluster.nodes[2];
        let refused = exchange(&stranger.endpoint, server.id()).await;
        assert!(
            refused.is_err(),
            "an uncertified endpoint got a stream: {refused:?}"
        );

        // An endpoint a genuine record of an identity outside the accepted
        // set names: the record is kept, and certifies nothing here.
        let own = stranger.identity();
        let outsider = with_relays(
            base_builder().portmapper_config(iroh::endpoint::PortmapperConfig::Disabled),
            own.transport.relays(),
            Some(own.transport.store().clone()),
        )
        .bind()
        .await
        .unwrap();
        tokio::time::timeout(STEP, outsider.online()).await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let record = EndpointRecord::sign(
            cluster.signer_of(2),
            iroh_endpoint_key(outsider.id()),
            own.transport.relays().to_vec(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            now,
            now,
        )
        .unwrap();
        let kept = ask(
            &outsider,
            server.endpoint.addr(),
            &DiscoveryRequest::Publish(record),
        )
        .await
        .unwrap();
        assert!(
            matches!(kept, DiscoveryResponse::Published(Ok(true))),
            "{kept:?}"
        );
        let refused = exchange(&outsider, server.id()).await;
        assert!(
            refused.is_err(),
            "an outside identity's endpoint got a stream: {refused:?}"
        );

        assert_eq!(
            served.load(Ordering::SeqCst),
            admitted,
            "a refused connection reached the stream handler"
        );
    }
}

/// A node reports whether it is reached directly or only through a relay,
/// from the connections it holds rather than from probes.
#[tokio::test(flavor = "multi_thread")]
async fn reachability_reports_relay_only() {
    let cluster = Cluster::identified(|_, _, _, router| router).await;
    cluster.discover(3, 0).await.unwrap();
    for _ in 0..2 {
        for node in &cluster.nodes {
            node.identity().sync(&node.endpoint).await;
        }
    }
    let direct = cluster.connectivity(0);
    let relayed = cluster.connectivity(3);
    // The node with an IP transport, seen by a peer at its own address,
    // reports a direct tier.
    assert_eq!(direct.reachability, Reachability::Public, "{direct:#?}");
    assert_eq!(direct.nat, NatKind::None, "{direct:#?}");
    assert!(
        !direct.bound.is_empty() && !direct.advertised.is_empty() && !direct.observed.is_empty()
    );
    // The node with no IP transport is held only by its relay.
    assert_eq!(relayed.reachability, Reachability::Relay, "{relayed:#?}");
    assert!(
        relayed.bound.is_empty() && relayed.advertised.is_empty() && relayed.observed.is_empty()
    );
    assert!(relayed.relays.iter().any(|r| r.connected), "{relayed:#?}");
}
