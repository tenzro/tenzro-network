//! In-memory chain state, committees and fixture builders for route tests.

use std::collections::HashMap;

use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey};
use sha3::{Digest, Keccak256};

use super::attestation::testing::{pq_key, sign_pq};
use super::attestation::{Delivery, MemberSignature, PqMemberSignature, attestation_digest};
use super::state::RouteState;
use super::{
    BridgeRoute, BridgeRouteAdapter, BridgeRouteMode, MintRateLimit, NetworkMintLimits,
    NetworkOutflowLimits, OutflowCap, VerifierMember, VerifierQuorum,
};
use crate::error::Result;

pub const LOCAL_CHAIN_ID: u64 = 1337;
pub const NOW_MS: i64 = 1_800_000_000_000;

#[derive(Default, Clone)]
pub struct MemState {
    pub routes: HashMap<String, BridgeRoute>,
    pub modes: HashMap<String, BridgeRouteMode>,
    pub network: Option<NetworkMintLimits>,
    pub outflow: Option<NetworkOutflowLimits>,
    pub epoch: u64,
    /// Time since [`NOW_MS`], for tests that let a lane bucket refill.
    pub elapsed_ms: i64,
    pub kv: HashMap<String, Vec<u8>>,
}

impl MemState {
    pub fn with(routes: &[BridgeRoute]) -> Self {
        Self {
            routes: routes
                .iter()
                .map(|r| (r.storage_key(), r.clone()))
                .collect(),
            network: Some(NetworkMintLimits {
                proven: MintRateLimit {
                    per_mint: u128::MAX,
                    per_epoch: u128::MAX,
                },
                attested: MintRateLimit {
                    per_mint: u128::MAX - 1,
                    per_epoch: u128::MAX - 1,
                },
                classical: MintRateLimit {
                    per_mint: u128::MAX,
                    per_epoch: u128::MAX,
                },
            }),
            outflow: Some(NetworkOutflowLimits {
                caps: ["TNZO", "BTC", "USDC", "EURC", "PYUSD"]
                    .map(|unit| OutflowCap {
                        unit: unit.into(),
                        per_epoch: u128::MAX,
                    })
                    .to_vec(),
            }),
            ..Default::default()
        }
    }
}

impl RouteState for MemState {
    fn local_chain_id(&self) -> u64 {
        LOCAL_CHAIN_ID
    }
    fn now_ms(&self) -> i64 {
        NOW_MS + self.elapsed_ms
    }
    fn epoch(&self) -> u64 {
        self.epoch
    }
    fn route(&self, adapter: BridgeRouteAdapter, chain: &str) -> Option<BridgeRoute> {
        self.routes
            .get(&super::bridge_route_storage_key(adapter, chain))
            .cloned()
    }
    fn stopped(&self, route: &BridgeRoute) -> Option<(BridgeRouteMode, String)> {
        self.modes
            .get(&route.storage_key())
            .map(|m| (*m, "anomaly evidence".to_string()))
    }
    fn network_limit(&self, route: &BridgeRoute) -> Option<MintRateLimit> {
        self.network.map(|n| n.for_route(route))
    }
    fn outflow_limits(&self) -> Option<NetworkOutflowLimits> {
        self.outflow.clone()
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.kv.get(key).cloned()
    }
    fn apply(&mut self, writes: Vec<(String, Vec<u8>)>) -> Result<()> {
        self.kv.extend(writes);
        Ok(())
    }
}

pub fn member_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    bytes[0] = 0x11;
    SigningKey::from_bytes((&bytes).into()).expect("valid scalar")
}

pub fn member_address(sk: &SigningKey) -> [u8; 20] {
    let point = sk.verifying_key().to_sec1_point(false);
    let hash: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

pub fn sign(sk: &SigningKey, prehash: &[u8; 32]) -> MemberSignature {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let (sig, rec): (K256Sig, RecoveryId) = sk.sign_prehash(prehash).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rec.to_byte();
    (member_address(sk), out)
}

/// `sk`'s ML-DSA-65 signature over `prehash`.
pub fn sign_pq_leg(sk: &SigningKey, prehash: &[u8; 32]) -> PqMemberSignature {
    sign_pq(&pq_key(&sk.to_bytes()), member_address(sk), prehash)
}

pub fn committee(seed_base: u8, n: u8, threshold: u32) -> (Vec<SigningKey>, VerifierQuorum) {
    let keys: Vec<SigningKey> = (0..n).map(|i| member_key(seed_base + i)).collect();
    let quorum = VerifierQuorum {
        set_index: 0,
        size: keys.len() as u32,
        members: keys
            .iter()
            .enumerate()
            .map(|(i, k)| VerifierMember {
                address: member_address(k),
                pq_public_key: pq_key(&k.to_bytes()).verifying_key_bytes().to_vec(),
                operator: format!("operator-{seed_base}-{i}"),
                rpc_provider: format!("rpc-{seed_base}-{i}"),
            })
            .collect(),
        threshold,
    };
    (keys, quorum)
}

/// Signing keys for a route's committees.
pub struct Signers {
    pub committee: Vec<SigningKey>,
    pub blessing: Vec<SigningKey>,
}

/// An attested delivery of `body` on `route`, signed by the first
/// `signers` members of each committee.
pub fn deliver(
    route: &BridgeRoute,
    keys: &Signers,
    signers: usize,
    nonce: u64,
    expiry_ms: i64,
    body: &[u8],
    proof: &[u8],
) -> Vec<u8> {
    let mut d = Delivery {
        dest_chain_id: LOCAL_CHAIN_ID,
        nonce,
        expiry_ms,
        body: body.to_vec(),
        proof: proof.to_vec(),
        committee: vec![],
        committee_pq: vec![],
        blessing: vec![],
        blessing_pq: vec![],
    };
    let digest = attestation_digest(route, &d);
    d.committee = keys
        .committee
        .iter()
        .take(signers)
        .map(|k| sign(k, &digest))
        .collect();
    d.committee_pq = keys
        .committee
        .iter()
        .take(signers)
        .map(|k| sign_pq_leg(k, &digest))
        .collect();
    if route.blessing.is_some() {
        d.blessing = keys
            .blessing
            .iter()
            .take(signers)
            .map(|k| sign(k, &digest))
            .collect();
        d.blessing_pq = keys
            .blessing
            .iter()
            .take(signers)
            .map(|k| sign_pq_leg(k, &digest))
            .collect();
    }
    d.encode()
}
