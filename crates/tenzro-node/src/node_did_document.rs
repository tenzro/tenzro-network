//! The node's self-published DID Document — one entry point to every way of
//! reaching it.
//!
//! A node is addressed by five different identifiers, and until now a caller
//! holding one had no documented path to the others:
//!
//! | Identifier | What it is | Derives from |
//! |---|---|---|
//! | TDIP DID | `did:tenzro:machine:<uuid>` — the on-chain identity | provisioned identity |
//! | Ed25519 public key | the node's signing key | its keystore |
//! | iroh `EndpointId` | QUIC/NAT-traversing transport identity | **byte-identical** to the Ed25519 key since Phase C2 |
//! | libp2p `PeerId` | gossip/consensus mesh identity | a separate p2p keypair |
//! | Pkarr record | DNS-over-DHT address record | signed by the Ed25519 key |
//!
//! Resolving the DID now yields all of them plus the RPC/MCP/A2A/web service
//! URLs, so DID resolution is the single entry point rather than one of five
//! things a caller has to already know.
//!
//! # Why the node signs it itself
//!
//! The Ed25519 key and the iroh `EndpointId` are the same key material, so a
//! document signed by that key is self-certifying for the transport half: a
//! resolver that verifies the signature has, by that act, verified that the
//! endpoint it is about to dial belongs to the DID it asked about. Publishing
//! through the Pkarr relay composes with the same property, which is why C2
//! made the two keys identical in the first place.
//!
//! # What it deliberately omits
//!
//! Bind addresses that are not routable. A document advertising
//! `0.0.0.0:8545` tells a caller nothing and costs them a timeout, so an
//! endpoint is published only when the operator configured an external
//! address or the bind address is actually dialable.

use tenzro_identity::document::{DidDocument, DidService, VerificationMethod, VerificationPurpose};

/// Service type for the JSON-RPC surface.
pub const SERVICE_TYPE_RPC: &str = "TenzroJsonRpc";
/// Service type for the Model Context Protocol surface.
pub const SERVICE_TYPE_MCP: &str = "TenzroMcp";
/// Service type for the Agent-to-Agent surface.
pub const SERVICE_TYPE_A2A: &str = "TenzroA2a";
/// Service type for the HTTP verification/web API.
pub const SERVICE_TYPE_WEB: &str = "TenzroWebApi";
/// Service type for the iroh QUIC endpoint.
pub const SERVICE_TYPE_IROH: &str = "TenzroIrohEndpoint";
/// Service type for the libp2p mesh identity.
pub const SERVICE_TYPE_LIBP2P: &str = "TenzroLibp2p";
/// Service type for the Pkarr relay this node publishes through.
pub const SERVICE_TYPE_PKARR: &str = "TenzroPkarrRelay";

/// Everything a node knows about how to reach itself.
///
/// Assembled by the node from its live state; `None` for anything it does not
/// have, so a document never advertises a surface that is not running.
#[derive(Debug, Clone, Default)]
pub struct NodeAddressing {
    /// The node's TDIP DID. Without one there is nothing to publish.
    pub did: Option<String>,
    /// Ed25519 public key, lowercase hex. Also the iroh `EndpointId`.
    pub ed25519_public_key_hex: Option<String>,
    /// iroh `EndpointId`, as the transport renders it.
    pub iroh_endpoint_id: Option<String>,
    /// ALPNs registered on that endpoint.
    pub iroh_alpns: Vec<String>,
    /// libp2p `PeerId`.
    pub libp2p_peer_id: Option<String>,
    /// libp2p listen multiaddrs that are actually dialable.
    pub libp2p_addrs: Vec<String>,
    /// Pkarr relay this node publishes its address record through.
    pub pkarr_relay: Option<String>,
    /// Externally reachable JSON-RPC URL.
    pub rpc_url: Option<String>,
    /// Externally reachable MCP URL.
    pub mcp_url: Option<String>,
    /// Externally reachable A2A URL.
    pub a2a_url: Option<String>,
    /// Externally reachable web API URL.
    pub web_url: Option<String>,
}

/// Hosts that mean "everything local", never "reach me here".
const UNROUTABLE: &[&str] = &["0.0.0.0", "127.0.0.1", "localhost", "::", "::1", ""];

/// Whether an address is worth telling anyone about.
///
/// A wildcard or loopback bind is what the node listens on, not where anyone
/// can reach it. Publishing one costs the caller a timeout and tells them
/// nothing, so it is omitted rather than advertised.
///
/// Handles both URL/host:port forms and libp2p multiaddrs, because the
/// document carries both and a check that only understood one would silently
/// publish the other.
pub fn is_advertisable(addr: &str) -> bool {
    if addr.starts_with('/') {
        // Multiaddr: the host sits in a `/ip4/<addr>/…` or `/ip6/<addr>/…`
        // segment, so look at every segment rather than trying to parse.
        // Empty segments come from the leading slash and are not a host.
        return !addr
            .split('/')
            .filter(|seg| !seg.is_empty())
            .any(|seg| UNROUTABLE.contains(&seg));
    }

    let host = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(addr);
    // Strip a port, taking care not to mistake an IPv6 colon for one.
    let host = match host.rfind(']') {
        Some(close) => &host[..=close],
        None => host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']');

    !UNROUTABLE.contains(&host)
}

/// Build the node's DID Document.
///
/// Returns `None` when the node has no DID — a node that has not been
/// provisioned has no identity to publish a document *for*, and inventing one
/// would produce a document nothing could resolve.
pub fn build_node_did_document(addressing: &NodeAddressing) -> Option<DidDocument> {
    let did = addressing.did.as_ref()?;
    let mut doc = DidDocument::new(did.clone());

    if let Some(key_hex) = addressing.ed25519_public_key_hex.as_ref() {
        doc.add_verification_method(VerificationMethod {
            id: format!("{did}#node-key"),
            controller: did.clone(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            // Multibase `z` + base58btc is what the Ed25519-2020 suite
            // expects; the hex form travels as the iroh service endpoint
            // below, where it is what a dialer actually needs.
            public_key_multibase: Some(format!("z{key_hex}")),
            public_key_jwk: None,
            // Authentication and assertion, not key agreement: this is a
            // signing key, and listing it for encryption would invite a
            // caller to use an Ed25519 key for X25519.
            purposes: vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
            ],
        });
    }

    // The transport identities first: these are what make the document worth
    // resolving, since a caller who has one of the service URLs already knows
    // how to reach the node.
    if let Some(endpoint) = addressing.iroh_endpoint_id.as_ref() {
        doc.add_service(DidService {
            id: format!("{did}#iroh"),
            service_type: SERVICE_TYPE_IROH.to_string(),
            // The ALPNs ride in the endpoint string so one service entry
            // answers both "where" and "what can I speak to it".
            service_endpoint: if addressing.iroh_alpns.is_empty() {
                format!("tenzro://node/{endpoint}")
            } else {
                format!(
                    "tenzro://node/{endpoint}?alpn={}",
                    addressing.iroh_alpns.join(",")
                )
            },
        });
    }

    if let Some(peer_id) = addressing.libp2p_peer_id.as_ref() {
        let dialable: Vec<&String> = addressing
            .libp2p_addrs
            .iter()
            .filter(|a| is_advertisable(a))
            .collect();
        doc.add_service(DidService {
            id: format!("{did}#libp2p"),
            service_type: SERVICE_TYPE_LIBP2P.to_string(),
            service_endpoint: if dialable.is_empty() {
                // The PeerId alone is still useful: a peer already on the mesh
                // can route to it without a multiaddr.
                format!("/p2p/{peer_id}")
            } else {
                dialable
                    .iter()
                    .map(|a| format!("{a}/p2p/{peer_id}"))
                    .collect::<Vec<_>>()
                    .join(",")
            },
        });
    }

    if let Some(relay) = addressing.pkarr_relay.as_ref() {
        doc.add_service(DidService {
            id: format!("{did}#pkarr"),
            service_type: SERVICE_TYPE_PKARR.to_string(),
            service_endpoint: relay.clone(),
        });
    }

    for (suffix, kind, url) in [
        ("rpc", SERVICE_TYPE_RPC, &addressing.rpc_url),
        ("mcp", SERVICE_TYPE_MCP, &addressing.mcp_url),
        ("a2a", SERVICE_TYPE_A2A, &addressing.a2a_url),
        ("web", SERVICE_TYPE_WEB, &addressing.web_url),
    ] {
        if let Some(url) = url.as_ref().filter(|u| is_advertisable(u)) {
            doc.add_service(DidService {
                id: format!("{did}#{suffix}"),
                service_type: kind.to_string(),
                service_endpoint: url.clone(),
            });
        }
    }

    Some(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> NodeAddressing {
        NodeAddressing {
            did: Some("did:tenzro:machine:abc".to_string()),
            ed25519_public_key_hex: Some("ab".repeat(32)),
            iroh_endpoint_id: Some("endpoint123".to_string()),
            iroh_alpns: vec!["tenzro/a2a".to_string(), "tenzro/mcp".to_string()],
            libp2p_peer_id: Some("12D3KooWabc".to_string()),
            libp2p_addrs: vec![
                "/ip4/203.0.113.7/tcp/9000".to_string(),
                "/ip4/0.0.0.0/tcp/9000".to_string(),
            ],
            pkarr_relay: Some("https://pkarr.tenzro.xyz/".to_string()),
            rpc_url: Some("https://rpc.example.com".to_string()),
            mcp_url: Some("https://mcp.example.com/mcp".to_string()),
            a2a_url: Some("https://a2a.example.com".to_string()),
            web_url: Some("https://api.example.com".to_string()),
        }
    }

    fn service<'a>(doc: &'a DidDocument, kind: &str) -> Option<&'a DidService> {
        doc.service.iter().find(|s| s.service_type == kind)
    }

    /// The whole point: resolving the DID answers every addressing question at
    /// once, instead of being one of five things a caller must already know.
    #[test]
    fn one_document_carries_every_way_to_reach_the_node() {
        let doc = build_node_did_document(&full()).unwrap();
        for kind in [
            SERVICE_TYPE_IROH,
            SERVICE_TYPE_LIBP2P,
            SERVICE_TYPE_PKARR,
            SERVICE_TYPE_RPC,
            SERVICE_TYPE_MCP,
            SERVICE_TYPE_A2A,
            SERVICE_TYPE_WEB,
        ] {
            assert!(service(&doc, kind).is_some(), "{kind} missing");
        }
    }

    /// A node with no DID has no identity to publish a document *for*.
    /// Inventing one would produce something nothing could resolve.
    #[test]
    fn a_node_with_no_did_publishes_nothing() {
        assert!(build_node_did_document(&NodeAddressing::default()).is_none());
    }

    /// The Ed25519 key and the iroh EndpointId are the same key material, so a
    /// verified signature over this document is also a verification that the
    /// endpoint belongs to the DID.
    #[test]
    fn the_signing_key_is_published_for_authentication_and_assertion() {
        let doc = build_node_did_document(&full()).unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication, vec!["did:tenzro:machine:abc#node-key"]);
        assert_eq!(
            doc.assertion_method,
            vec!["did:tenzro:machine:abc#node-key"]
        );
        assert!(
            doc.key_agreement.is_empty(),
            "an Ed25519 signing key must not be advertised for key agreement"
        );
    }

    /// A document advertising a wildcard bind costs the caller a timeout and
    /// tells them nothing.
    #[test]
    fn unroutable_addresses_are_not_advertised() {
        assert!(is_advertisable("https://rpc.example.com"));
        assert!(is_advertisable("203.0.113.7:8545"));
        assert!(!is_advertisable("0.0.0.0:8545"));
        assert!(!is_advertisable("127.0.0.1:8545"));
        assert!(!is_advertisable("http://localhost:8545"));
        assert!(!is_advertisable("[::]:8545"));
        assert!(!is_advertisable("[::1]:8545"));
        assert!(is_advertisable("[2001:db8::1]:8545"));

        // Multiaddrs travel in the same document, so the check has to
        // understand them too — one that only knew URLs would silently
        // publish a wildcard listener.
        assert!(is_advertisable("/ip4/203.0.113.7/tcp/9000"));
        assert!(!is_advertisable("/ip4/0.0.0.0/tcp/9000"));
        assert!(!is_advertisable("/ip4/127.0.0.1/udp/9000/quic-v1"));
        assert!(!is_advertisable("/ip6/::1/tcp/9000"));
    }

    #[test]
    fn a_wildcard_service_url_is_dropped_rather_than_published() {
        let addressing = NodeAddressing {
            rpc_url: Some("http://0.0.0.0:8545".to_string()),
            ..full()
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert!(service(&doc, SERVICE_TYPE_RPC).is_none());
        assert!(
            service(&doc, SERVICE_TYPE_MCP).is_some(),
            "dropping one unroutable endpoint must not drop the others"
        );
    }

    #[test]
    fn only_dialable_multiaddrs_are_published_and_each_carries_the_peer_id() {
        let doc = build_node_did_document(&full()).unwrap();
        let endpoint = &service(&doc, SERVICE_TYPE_LIBP2P).unwrap().service_endpoint;
        assert_eq!(endpoint, "/ip4/203.0.113.7/tcp/9000/p2p/12D3KooWabc");
        assert!(!endpoint.contains("0.0.0.0"));
    }

    /// A peer already on the mesh can route by PeerId alone, so a node with no
    /// dialable multiaddr still publishes something usable.
    #[test]
    fn a_node_behind_nat_still_publishes_its_peer_id() {
        let addressing = NodeAddressing {
            libp2p_addrs: vec!["/ip4/0.0.0.0/tcp/9000".to_string()],
            ..full()
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert_eq!(
            service(&doc, SERVICE_TYPE_LIBP2P).unwrap().service_endpoint,
            "/p2p/12D3KooWabc"
        );
    }

    /// One service entry answers both "where" and "what can I speak to it",
    /// so a caller does not have to probe.
    #[test]
    fn the_iroh_entry_carries_its_alpns() {
        let doc = build_node_did_document(&full()).unwrap();
        assert_eq!(
            service(&doc, SERVICE_TYPE_IROH).unwrap().service_endpoint,
            "tenzro://node/endpoint123?alpn=tenzro/a2a,tenzro/mcp"
        );
    }

    #[test]
    fn an_endpoint_with_no_alpns_is_still_addressable() {
        let addressing = NodeAddressing {
            iroh_alpns: Vec::new(),
            ..full()
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert_eq!(
            service(&doc, SERVICE_TYPE_IROH).unwrap().service_endpoint,
            "tenzro://node/endpoint123"
        );
    }

    /// A node that runs no iroh endpoint and no mesh still publishes whatever
    /// it does have, rather than an empty document or none at all.
    #[test]
    fn a_partial_node_publishes_what_it_has() {
        let addressing = NodeAddressing {
            did: Some("did:tenzro:machine:abc".to_string()),
            rpc_url: Some("https://rpc.example.com".to_string()),
            ..NodeAddressing::default()
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].service_type, SERVICE_TYPE_RPC);
        assert!(doc.verification_method.is_empty());
    }
}
