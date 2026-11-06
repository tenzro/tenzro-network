//! Local-network discovery of cluster members.
//!
//! A cluster member announces its iroh endpoint on the local network by
//! multicast DNS: no relay, no DNS server, no DHT and no outside service is
//! involved, so discovery works on a LAN with no internet at all. With the
//! endpoint it announces a [`LanBinding`]: the identifier part of its machine
//! DID and its hardware key's signature over its claim to the endpoint.
//!
//! A [`Sighting`] is only a claim. The caller checks the binding against the
//! cluster's verified membership list (the member's own key is in the list's
//! acceptances) before treating the endpoint as that member; a sighting whose
//! binding does not check is ignored.

use std::net::SocketAddr;

use base64::Engine;
use futures_util::{Stream, StreamExt};
use iroh::EndpointId;
use iroh::address_lookup::{AddressLookup, EndpointData, UserData};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};

use crate::error::{IrohError, IrohResult};

/// The multicast DNS service name cluster members announce under.
pub const SERVICE_NAME: &str = "tenzro-cluster";

/// A member's claim to the endpoint it announces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanBinding {
    /// The identifier part of the member's machine DID (after the last `:`).
    pub member_id: String,
    /// The member's hardware-key signature over its claim to the endpoint.
    pub signature: Vec<u8>,
}

impl LanBinding {
    fn to_user_data(&self) -> IrohResult<UserData> {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.signature);
        format!("{}.{}", self.member_id, sig)
            .parse()
            .map_err(|e| IrohError::Backend(format!("cluster binding too long: {e}")))
    }

    fn parse(user_data: &UserData) -> Option<Self> {
        let mut parts = user_data.as_ref().split('.');
        let (member_id, sig) = (parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig)
            .ok()?;
        Some(Self {
            member_id: member_id.to_string(),
            signature,
        })
    }
}

/// An endpoint seen on the local network, with the binding it announced.
#[derive(Debug, Clone)]
pub struct Sighting {
    /// The announced iroh endpoint.
    pub endpoint_id: EndpointId,
    /// Its local-network addresses.
    pub addrs: Vec<SocketAddr>,
    /// The member binding it carried.
    pub binding: LanBinding,
}

/// Multicast DNS announcement and discovery of cluster members.
#[derive(Debug, Clone)]
pub struct LanDiscovery {
    mdns: MdnsAddressLookup,
}

impl LanDiscovery {
    /// Start discovery for the endpoint `endpoint_id`. Must run inside a
    /// tokio runtime.
    pub fn start(endpoint_id: EndpointId) -> IrohResult<Self> {
        let mdns = MdnsAddressLookup::builder()
            .service_name(SERVICE_NAME)
            .build(endpoint_id)
            .map_err(|e| IrohError::Backend(format!("local discovery: {e}")))?;
        Ok(Self { mdns })
    }

    /// Announce this endpoint at `addrs` with `binding`, replacing any earlier
    /// announcement.
    pub fn announce(
        &self,
        addrs: impl IntoIterator<Item = SocketAddr>,
        binding: &LanBinding,
    ) -> IrohResult<()> {
        let mut data = EndpointData::new(Vec::new());
        data.add_ip_addrs(addrs.into_iter().collect());
        self.mdns
            .publish(&data.with_user_data(binding.to_user_data()?));
        Ok(())
    }

    /// Endpoints seen on the local network that announced a well-formed
    /// binding. Endpoints without one are skipped.
    pub async fn sightings(&self) -> impl Stream<Item = Sighting> + Unpin + use<> {
        self.mdns.subscribe().await.filter_map(|event| {
            let sighting = match event {
                DiscoveryEvent::Discovered { endpoint_info, .. } => endpoint_info
                    .user_data()
                    .and_then(LanBinding::parse)
                    .map(|binding| Sighting {
                        endpoint_id: endpoint_info.endpoint_id,
                        addrs: endpoint_info.ip_addrs().copied().collect(),
                        binding,
                    }),
                _ => None,
            };
            std::future::ready(sighting)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tenzro_cluster::membership::testing::{Key, RP_ID, custody_digest, membership};
    use tenzro_cluster::{MembershipBook, VerifiedMembership};

    fn endpoint_id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn binding(key: &Key, endpoint: &EndpointId) -> LanBinding {
        LanBinding {
            member_id: key.machine_did().rsplit(':').next().unwrap().to_string(),
            signature: key.bind_lan(endpoint.as_bytes()),
        }
    }

    #[test]
    fn a_binding_fits_and_round_trips_through_user_data() {
        let b = binding(&Key::new(2), &endpoint_id(1));
        let data = b.to_user_data().unwrap();
        assert!(data.as_ref().len() <= UserData::MAX_LENGTH);
        assert_eq!(LanBinding::parse(&data), Some(b));
    }

    /// Two endpoints on this host find each other by multicast alone, and
    /// only the one whose binding checks against the membership list is
    /// accepted as a member.
    #[tokio::test(flavor = "multi_thread")]
    async fn lan_discovery_finds_members_on_loopback_without_an_external_network() {
        let (op, a, b, stranger) = (Key::new(1), Key::new(2), Key::new(3), Key::new(4));
        let mut book = MembershipBook::new();
        book.offer(
            VerifiedMembership::verify(membership(&op, "lab", 1, &[&a, &b]), RP_ID, custody_digest)
                .unwrap(),
        )
        .unwrap();

        let (ep_a, ep_b, ep_s) = (endpoint_id(11), endpoint_id(12), endpoint_id(13));
        let listener = LanDiscovery::start(ep_a).unwrap();
        let member = LanDiscovery::start(ep_b).unwrap();
        let impostor = LanDiscovery::start(ep_s).unwrap();
        let mut sightings = listener.sightings().await;

        let loopback: SocketAddr = "127.0.0.1:47001".parse().unwrap();
        member.announce([loopback], &binding(&b, &ep_b)).unwrap();
        // Claims to be b, but signs with its own key.
        let mut forged = binding(&stranger, &ep_s);
        forged.member_id = binding(&b, &ep_b).member_id;
        impostor.announce([loopback], &forged).unwrap();

        let mut verified = None;
        let mut rejected_impostor = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while (verified.is_none() || !rejected_impostor) && tokio::time::Instant::now() < deadline {
            let Ok(Some(s)) = tokio::time::timeout(Duration::from_secs(5), sightings.next()).await
            else {
                continue;
            };
            let found = book.verify_lan_peer(
                &a.machine_did(),
                &s.binding.member_id,
                s.endpoint_id.as_bytes(),
                &s.binding.signature,
            );
            if s.endpoint_id == ep_b {
                verified = found;
            } else if s.endpoint_id == ep_s {
                assert_eq!(found, None, "a forged binding must not verify");
                rejected_impostor = true;
            }
        }
        assert_eq!(verified, Some(b.machine_did()));
        assert!(rejected_impostor, "the impostor was never seen");
    }
}
