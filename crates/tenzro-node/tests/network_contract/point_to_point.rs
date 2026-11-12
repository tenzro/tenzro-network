//! Point-to-point paths on their own ALPNs: inference forwarding
//! (`tenzro/infer`), committee DA (`tenzro/da-committee`), replicated
//! database writes (`tenzro/db-replicate`), each driven through the node's
//! own adapters.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use iroh::EndpointId;
use tenzro_crypto::batch::ImmediateRecordSigner;
use tenzro_crypto::composite::HybridSigner;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_iroh::{
    ALPN_DA_COMMITTEE, ALPN_INFER, MAX_INFER_BYTES, MAX_STORE_REQUEST, Reply, RequestHandler,
    RequestProtocol,
};
use tenzro_node::da_committee::{
    CommitteeMember, CommitteeView, DaCommitteeBackend, DaCommitteeStore, DaCommitteeSurface,
    committee_address,
};
use tenzro_node::da_committee_surface::{DaCommitteeServer, IrohDaCommitteeSurface};
use tenzro_storage::da::DaBackend;
use tenzro_types::primitives::{Address, Hash};

use crate::cluster::{Cluster, TOPOLOGY};

/// A provider answering the way a node's `tenzro/infer` handler does: a
/// streamed completion for `stream: true`, a refusal status for a request
/// with no credential, a whole JSON body otherwise.
#[derive(Debug)]
struct Provider;

#[async_trait]
impl RequestHandler for Provider {
    async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
        let body: serde_json::Value = serde_json::from_slice(&request).unwrap_or_default();
        if body.get("api_key").is_none() {
            return Reply::full(402, r#"{"error":{"code":"credential_required"}}"#);
        }
        if body["stream"] == true {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                for event in [
                    "data: {\"delta\":\"he\"}\n\n",
                    "data: {\"delta\":\"llo\"}\n\n",
                    "data: [DONE]\n\n",
                ] {
                    let _ = tx.send(Ok(Bytes::from_static(event.as_bytes()))).await;
                }
            });
            return Reply::streamed(200, rx);
        }
        Reply::full(200, r#"{"choices":[{"message":{"content":"hello"}}]}"#)
    }
}

#[tokio::test]
async fn infer() {
    let cluster = Cluster::start(|_, _, router| {
        router.accept(
            ALPN_INFER,
            RequestProtocol::new(
                "infer",
                Arc::new(Provider),
                MAX_INFER_BYTES,
                tenzro_iroh::limits::AdmissionLimits::default(),
            ),
        )
    })
    .await;
    cluster
        .on_every_route(|client, server| async move {
            let ask = |body: serde_json::Value| {
                let endpoint = client.endpoint.clone();
                let id = server.id();
                async move {
                    tenzro_iroh::request(&endpoint, id, ALPN_INFER, body.to_string().as_bytes())
                        .await
                        .map_err(|e| e.to_string())
                }
            };

            let refused = ask(serde_json::json!({"messages": []})).await?;
            if refused.status != 402 {
                return Err(format!("a refusal arrived as {}", refused.status));
            }

            let whole = ask(serde_json::json!({"messages": [], "api_key": "k"})).await?;
            let body = whole
                .bytes(MAX_INFER_BYTES)
                .await
                .map_err(|e| e.to_string())?;
            let body: serde_json::Value =
                serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            if body["choices"][0]["message"]["content"] != "hello" {
                return Err(format!("wrong completion {body}"));
            }

            let mut streamed =
                ask(serde_json::json!({"messages": [], "api_key": "k", "stream": true})).await?;
            let mut events = String::new();
            while let Some(chunk) = streamed.chunk().await.map_err(|e| e.to_string())? {
                events.push_str(&String::from_utf8_lossy(&chunk));
            }
            (events.matches("data:").count() == 3 && events.ends_with("[DONE]\n\n"))
                .then_some(())
                .ok_or_else(|| format!("stream arrived as {events:?}"))
        })
        .await;
}

/// A fixed committee: one validator key per cluster node, in node order.
struct StaticCommittee(Vec<CommitteeMember>);

impl CommitteeView for StaticCommittee {
    fn members(&self) -> Vec<CommitteeMember> {
        self.0.clone()
    }
}

/// A member's hardware identity stand-in, named by its seed.
fn session_of(seed: &u8) -> Arc<ImmediateRecordSigner> {
    Arc::new(tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(
        TestHybridSigner::p256_only(*seed),
    )))
}

#[tokio::test]
async fn da_committee() {
    let keys: Vec<u8> = (1..=TOPOLOGY.len() as u8).collect();
    let committee: Arc<dyn CommitteeView> = Arc::new(StaticCommittee(
        keys.iter()
            .enumerate()
            .map(|(index, seed)| {
                let key = TestHybridSigner::p256_only(*seed).public_key().clone();
                CommitteeMember {
                    index,
                    address: committee_address(&key),
                    public_key: Some(key),
                }
            })
            .collect(),
    ));
    let stores: Vec<Arc<DaCommitteeStore>> = (0..TOPOLOGY.len())
        .map(|_| Arc::new(DaCommitteeStore::new()))
        .collect();

    let cluster = Cluster::start(|index, _, router| {
        router.accept(
            ALPN_DA_COMMITTEE,
            RequestProtocol::new(
                "da-committee",
                Arc::new(DaCommitteeServer::new(
                    committee.clone(),
                    stores[index].clone(),
                    session_of(&keys[index]),
                )),
                MAX_STORE_REQUEST,
                tenzro_iroh::limits::AdmissionLimits::default(),
            ),
        )
    })
    .await;

    // Each member is dialed at its node's endpoint, as the consensus
    // endpoint announcements would name it.
    let by_address: HashMap<Address, EndpointId> = committee
        .members()
        .iter()
        .map(|m| (m.address, cluster.nodes[m.index].id()))
        .collect();
    let by_address = Arc::new(by_address);

    let (committee, stores, keys, by_address) = (&committee, &stores, &keys, &by_address);
    cluster
        .on_every_route(|client, server| async move {
            let lookup = by_address.clone();
            let local = committee.members()[client.index].address;
            let surface = Arc::new(IrohDaCommitteeSurface::new(
                client.endpoint.clone(),
                committee.clone(),
                Arc::new(move |address: &Address| lookup.get(address).copied()),
                local,
            ));
            // The writer distributes a blob to the whole committee and needs
            // 2f+1 signed attestations back; the outbound-only member cannot
            // be reached, and the quorum holds without it.
            let backend = DaCommitteeBackend::new(
                session_of(&keys[client.index]),
                committee.clone(),
                surface.clone(),
                stores[client.index].clone(),
            )
            .map_err(|e| e.to_string())?;
            let payload = format!("blob from node {} to node {}", client.index, server.index);
            let pointer = backend
                .submit(b"contract", payload.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            let commitment = Hash::new(pointer.locator.as_slice().try_into().unwrap());

            let held = surface
                .fetch_sliver(server.index, &commitment)
                .await
                .map_err(|e| e.to_string())?;
            if held.is_none() {
                return Err("the member holds no sliver".into());
            }
            let proof = surface
                .challenge_sliver(server.index, &commitment, &[7u8; 32])
                .await
                .map_err(|e| e.to_string())?
                .ok_or("the member proved nothing")?;
            (proof.index == server.index)
                .then_some(())
                .ok_or_else(|| "the proof names another member".to_string())
        })
        .await;
}
