// SPDX-License-Identifier: Apache-2.0
//! Remote grants: an agent's authority on another chain.
//!
//! The VM writes a grant after checking it against the agent's terms, at the
//! state entry [`leaf_key`]. An agent account on the other chain reads it
//! under a final checkpoint's state root and acts within it: the budget, the
//! time window, the serving-node keys in [`RemoteGrant::keys_root`] and the
//! targets in [`RemoteGrant::targets_root`]. The layout is fixed big-endian so
//! every chain decodes it the same way.

use sha2::{Digest, Sha256};

use crate::agent_terms::ServingNode;

/// The layout version.
pub const VERSION: u8 = 1;

/// Bytes of an encoded grant.
pub const ENCODED_LEN: usize = 1 + 32 * 3 + 8 * 4 + 32 + 16 * 3 + 32 * 3 + 16 + 1;

/// Domain of the digest serving nodes sign for an action on another chain.
pub const ACT_DOMAIN: &[u8] = b"tenzro/agent-act/v1";

/// The account address the state tree keys VM system entries under.
const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];
/// The state tree namespace of VM storage.
const STATE_NAMESPACE: &str = "state";
const TREE_KEY_DOMAIN: &[u8] = b"tenzro.state-trie.key";

/// One agent's authority on one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGrant {
    /// SHA-256 of the chain's CAIP-2 id.
    pub chain: [u8; 32],
    /// The agent's account on that chain, left-padded.
    pub account: [u8; 32],
    /// SHA-256 of the agent's DID.
    pub agent: [u8; 32],
    /// The terms version the grant was issued under.
    pub terms_version: u64,
    /// Strictly increasing per agent and chain.
    pub seq: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    /// SHA-256 of the CAIP-19 id of the asset the budget is in.
    pub asset: [u8; 32],
    /// Most the account may move under the grant.
    pub budget: u128,
    /// Most one action may move.
    pub per_action_max: u128,
    /// An action moving more needs signatures from two distinct operators.
    pub cosign_above: u128,
    /// Merkle root of the serving nodes' keys ([`key_leaf`]).
    pub keys_root: [u8; 32],
    /// Merkle root of the allowed targets ([`target_leaf`]); zero allows any.
    pub targets_root: [u8; 32],
    /// Zero for an open grant; otherwise the one action the grant allows
    /// ([`payload_hash`]).
    pub payload_hash: [u8; 32],
    /// Most a relayer may be refunded per action.
    pub relay_fee_max: u128,
    /// Revoked or superseded: the account refuses every action.
    pub void: bool,
}

/// Why grant bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantDecodeError {
    #[error("a grant is {ENCODED_LEN} bytes")]
    Length,
    #[error("unknown grant version")]
    Version,
    #[error("the void flag is 0 or 1")]
    Flag,
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("length checked")
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }
    fn u128(&mut self) -> u128 {
        u128::from_be_bytes(self.take())
    }
}

impl RemoteGrant {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN);
        out.push(VERSION);
        out.extend_from_slice(&self.chain);
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.agent);
        out.extend_from_slice(&self.terms_version.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.not_before_ms.to_be_bytes());
        out.extend_from_slice(&self.not_after_ms.to_be_bytes());
        out.extend_from_slice(&self.asset);
        out.extend_from_slice(&self.budget.to_be_bytes());
        out.extend_from_slice(&self.per_action_max.to_be_bytes());
        out.extend_from_slice(&self.cosign_above.to_be_bytes());
        out.extend_from_slice(&self.keys_root);
        out.extend_from_slice(&self.targets_root);
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.relay_fee_max.to_be_bytes());
        out.push(u8::from(self.void));
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, GrantDecodeError> {
        if b.len() != ENCODED_LEN {
            return Err(GrantDecodeError::Length);
        }
        if b[0] != VERSION {
            return Err(GrantDecodeError::Version);
        }
        let mut r = Reader(&b[1..]);
        let g = Self {
            chain: r.take(),
            account: r.take(),
            agent: r.take(),
            terms_version: r.u64(),
            seq: r.u64(),
            not_before_ms: r.u64(),
            not_after_ms: r.u64(),
            asset: r.take(),
            budget: r.u128(),
            per_action_max: r.u128(),
            cosign_above: r.u128(),
            keys_root: r.take(),
            targets_root: r.take(),
            payload_hash: r.take(),
            relay_fee_max: r.u128(),
            void: match r.take::<1>()[0] {
                0 => false,
                1 => true,
                _ => return Err(GrantDecodeError::Flag),
            },
        };
        Ok(g)
    }

    /// Whether the grant allows exactly one action.
    pub fn is_exact(&self) -> bool {
        self.payload_hash != [0u8; 32]
    }

    /// Whether a serving node may sign `action` under this open grant at
    /// `now_ms`. The value an action moves is bounded by the grant the
    /// agent's root issued; the relayer that submits it is refunded at most
    /// `relay_fee_max`, so a relayer key pays fees and never moves the
    /// agent's value beyond that refund.
    pub fn admits(&self, action: &RemoteAction, now_ms: u64) -> Result<(), &'static str> {
        if self.void {
            return Err("the grant is void");
        }
        if now_ms < self.not_before_ms || now_ms > self.not_after_ms {
            return Err("the grant is outside its time window");
        }
        if self.is_exact() {
            return Err("an exact grant carries its action; it is not signed");
        }
        if action.amount > self.per_action_max {
            return Err("the action moves more than the grant allows per action");
        }
        if action.relay_refund > self.relay_fee_max {
            return Err("the relayer refund is above the grant's cap");
        }
        Ok(())
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The grant's chain field: SHA-256 of a CAIP-2 id.
pub fn chain_hash(caip2: &str) -> [u8; 32] {
    sha256(&[caip2.as_bytes()])
}

/// The grant's asset field: SHA-256 of a CAIP-19 id.
pub fn asset_hash(caip19: &str) -> [u8; 32] {
    sha256(&[caip19.as_bytes()])
}

/// The grant's agent field: SHA-256 of the agent's DID.
pub fn agent_hash(did: &str) -> [u8; 32] {
    sha256(&[did.as_bytes()])
}

/// The VM storage key of an agent's grant on a chain.
pub fn leaf_key(did: &str, caip2: &str) -> String {
    format!("agent_grant:{did}:{caip2}")
}

/// The VM storage key listing the chains an agent holds grants on.
pub fn index_key(did: &str) -> String {
    format!("agent_grants:{did}")
}

/// Where the grant of `did` on `caip2` sits in the state tree: the tree key
/// a state proof for it is checked against.
pub fn state_tree_key(did: &str, caip2: &str) -> [u8; 32] {
    system_slot_tree_key(leaf_key(did, caip2).as_bytes())
}

/// Where the system storage slot `slot` sits in the state tree.
pub fn system_slot_tree_key(slot: &[u8]) -> [u8; 32] {
    let key = format!(
        "storage:{}:{}",
        hex::encode(SYSTEM_ADDRESS),
        hex::encode(slot)
    );
    sha256(&[
        TREE_KEY_DOMAIN,
        &(STATE_NAMESPACE.len() as u16).to_le_bytes(),
        STATE_NAMESPACE.as_bytes(),
        key.as_bytes(),
    ])
}

/// A serving node's key leaf: its P-256 key (SEC1, uncompressed) and its
/// operator.
pub fn key_leaf(sec1_public_key: &[u8; 65], operator_did: &str) -> [u8; 32] {
    sha256(&[&[0x00], sec1_public_key, operator_did.as_bytes()])
}

/// The SEC1 form of a serving node's key (`x || y`, hex).
pub fn serving_node_key(node: &ServingNode) -> Option<[u8; 65]> {
    let xy = hex::decode(&node.dpop_public_key)
        .ok()
        .filter(|b| b.len() == 64)?;
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..].copy_from_slice(&xy);
    Some(out)
}

/// The key leaves of `nodes`, in their order. `None` when a node's key is
/// malformed.
pub fn key_leaves(nodes: &[ServingNode]) -> Option<Vec<[u8; 32]>> {
    nodes
        .iter()
        .map(|n| serving_node_key(n).map(|k| key_leaf(&k, &n.operator_did)))
        .collect()
}

/// A target leaf: a contract or account on the other chain and the function
/// on it, each length-prefixed (u16).
pub fn target_leaf(target: &[u8], selector: &[u8]) -> [u8; 32] {
    sha256(&[
        &[0x00],
        &(target.len() as u16).to_be_bytes(),
        target,
        &(selector.len() as u16).to_be_bytes(),
        selector,
    ])
}

fn node_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    sha256(&[&[0x01], lo, hi])
}

/// The root of a Merkle tree over `leaves`: pairs are hashed in sorted
/// order, an unpaired node moves up as it is. No leaves is the zero root.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| {
                if c.len() == 2 {
                    node_hash(&c[0], &c[1])
                } else {
                    c[0]
                }
            })
            .collect();
    }
    level[0]
}

/// The siblings from leaf `index` up to the root.
pub fn merkle_proof(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let sibling = index ^ 1;
        if sibling < level.len() {
            proof.push(level[sibling]);
        }
        level = level
            .chunks(2)
            .map(|c| {
                if c.len() == 2 {
                    node_hash(&c[0], &c[1])
                } else {
                    c[0]
                }
            })
            .collect();
        index /= 2;
    }
    proof
}

/// Whether `leaf` is under `root` with `proof`.
pub fn merkle_verify(root: &[u8; 32], leaf: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    let acc = proof.iter().fold(*leaf, |acc, s| node_hash(&acc, s));
    &acc == root
}

/// What an agent account reports back to Tenzro through the chain's route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportKind {
    /// The grant `seq` ended (expired or replaced) having moved `spent`.
    Closed { spent: u128 },
    /// Action `nonce` under grant `seq` ran: its digest and what it moved.
    Acted {
        nonce: u64,
        digest: [u8; 32],
        amount: u128,
    },
    /// The account installed grant `seq`; `payee` is the Tenzro account of
    /// the relayer that delivered it.
    Synced { void: bool, payee: [u8; 32] },
    /// Action `nonce` under grant `seq` paid `amount` of the grant's asset
    /// for a Tenzro `payee`, bound to what it bought.
    Paid {
        nonce: u64,
        payee: [u8; 32],
        binding: crate::payment_authorization::PaymentBinding,
        amount: u128,
    },
}

/// One report: the chain, account and agent it is about, and the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountReport {
    pub chain: [u8; 32],
    pub account: [u8; 32],
    pub agent: [u8; 32],
    pub seq: u64,
    pub kind: ReportKind,
}

impl AccountReport {
    /// Fixed big-endian: kind (1 closed, 2 acted, 3 synced, 4 paid), chain,
    /// account, agent, seq, then the kind's fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![match self.kind {
            ReportKind::Closed { .. } => 1,
            ReportKind::Acted { .. } => 2,
            ReportKind::Synced { .. } => 3,
            ReportKind::Paid { .. } => 4,
        }];
        out.extend_from_slice(&self.chain);
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.agent);
        out.extend_from_slice(&self.seq.to_be_bytes());
        match &self.kind {
            ReportKind::Closed { spent } => out.extend_from_slice(&spent.to_be_bytes()),
            ReportKind::Acted {
                nonce,
                digest,
                amount,
            } => {
                out.extend_from_slice(&nonce.to_be_bytes());
                out.extend_from_slice(digest);
                out.extend_from_slice(&amount.to_be_bytes());
            }
            ReportKind::Synced { void, payee } => {
                out.push(u8::from(*void));
                out.extend_from_slice(payee);
            }
            ReportKind::Paid {
                nonce,
                payee,
                binding,
                amount,
            } => {
                out.extend_from_slice(&nonce.to_be_bytes());
                out.extend_from_slice(payee);
                out.extend_from_slice(&binding.request_digest);
                out.extend_from_slice(&binding.quote_digest);
                out.extend_from_slice(&binding.usd_e6.to_be_bytes());
                out.extend_from_slice(&amount.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let (&kind, rest) = b.split_first()?;
        const HEAD: usize = 32 * 3 + 8;
        if rest.len() < HEAD {
            return None;
        }
        let mut r = Reader(rest);
        let (chain, account, agent, seq) = (r.take(), r.take(), r.take(), r.u64());
        let kind = match (kind, r.0.len()) {
            (1, 16) => ReportKind::Closed { spent: r.u128() },
            (2, 56) => ReportKind::Acted {
                nonce: r.u64(),
                digest: r.take(),
                amount: r.u128(),
            },
            (3, 33) => ReportKind::Synced {
                void: match r.take::<1>()[0] {
                    0 => false,
                    1 => true,
                    _ => return None,
                },
                payee: r.take(),
            },
            (4, 128) => ReportKind::Paid {
                nonce: r.u64(),
                payee: r.take(),
                binding: crate::payment_authorization::PaymentBinding {
                    request_digest: r.take(),
                    quote_digest: r.take(),
                    usd_e6: r.u64(),
                    app_margin: None,
                },
                amount: r.u128(),
            },
            _ => return None,
        };
        Some(Self {
            chain,
            account,
            agent,
            seq,
            kind,
        })
    }
}

/// The operation name of an agent action that issues a remote grant.
pub const OP_REMOTE_GRANT: &str = "remote_grant";

/// A target an open grant allows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteTarget {
    #[serde(with = "hex_bytes")]
    pub target: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub selector: Vec<u8>,
}

/// What an agent action asks the VM to grant on another chain (the chain is
/// the action's `chain`, CAIP-2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteGrantRequest {
    /// The asset, CAIP-19; the terms must list it in `remote_limits`.
    pub caip19: String,
    /// Most the account may move under the grant, in the asset's smallest unit.
    #[serde(with = "u128_string")]
    pub budget: u128,
    /// Most one action may move.
    #[serde(with = "u128_string")]
    pub per_action_max: u128,
    /// How long the grant lives, ms; at most the terms allow.
    pub ttl_ms: u64,
    /// The targets the grant allows; empty allows the terms' counterparties.
    #[serde(default)]
    pub targets: Vec<RemoteTarget>,
    /// For an exact grant, the one action it allows ([`payload_hash`]).
    #[serde(default, with = "opt_hex32")]
    pub payload_hash: Option<[u8; 32]>,
    /// Most a relayer may be refunded per action.
    #[serde(with = "u128_string")]
    pub relay_fee_max: u128,
}

impl RemoteGrantRequest {
    /// The bytes an agent action's digest covers.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.caip19.len() as u32).to_be_bytes());
        out.extend_from_slice(self.caip19.as_bytes());
        out.extend_from_slice(&self.budget.to_be_bytes());
        out.extend_from_slice(&self.per_action_max.to_be_bytes());
        out.extend_from_slice(&self.ttl_ms.to_be_bytes());
        out.extend_from_slice(&(self.targets.len() as u32).to_be_bytes());
        for t in &self.targets {
            out.extend_from_slice(&target_leaf(&t.target, &t.selector));
        }
        out.extend_from_slice(&self.payload_hash.unwrap_or([0u8; 32]));
        out.extend_from_slice(&self.relay_fee_max.to_be_bytes());
        out
    }

    /// The Merkle root of the targets, zero for none.
    pub fn targets_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self
            .targets
            .iter()
            .map(|t| target_leaf(&t.target, &t.selector))
            .collect();
        merkle_root(&leaves)
    }
}

mod opt_hex32 {
    pub fn serialize<S: serde::Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let s: Option<String> = serde::Deserialize::deserialize(d)?;
        s.map(|s| {
            hex::decode(s.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| serde::de::Error::custom("a 32-byte hex hash"))
        })
        .transpose()
    }
}

/// An action an agent account takes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteAction {
    /// The contract or account called, in the chain's own form.
    #[serde(with = "hex_bytes")]
    pub target: Vec<u8>,
    /// The function called (EVM: the 4-byte selector; Move: `module::function`;
    /// Solana: the instruction discriminator; Soroban: the function name;
    /// CosmWasm: the message's top-level key).
    #[serde(with = "hex_bytes")]
    pub selector: Vec<u8>,
    /// What the action moves of the grant's asset.
    #[serde(with = "u128_string")]
    pub amount: u128,
    /// What the account refunds the relayer that submits the action.
    #[serde(with = "u128_string")]
    pub relay_refund: u128,
    /// The call's arguments.
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
}

impl RemoteAction {
    /// Length-prefixed target (u16) and selector (u16), amount, refund, and
    /// length-prefixed data (u32), big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            2 + self.target.len() + 2 + self.selector.len() + 32 + 4 + self.data.len(),
        );
        out.extend_from_slice(&(self.target.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.target);
        out.extend_from_slice(&(self.selector.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.selector);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.relay_refund.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

/// The digest serving nodes sign for action number `nonce` under grant `seq`
/// of the account `account` on the chain `chain`.
pub fn act_digest(
    chain: &[u8; 32],
    account: &[u8; 32],
    seq: u64,
    nonce: u64,
    action: &RemoteAction,
) -> [u8; 32] {
    sha256(&[
        ACT_DOMAIN,
        chain,
        account,
        &seq.to_be_bytes(),
        &nonce.to_be_bytes(),
        &action.encode(),
    ])
}

/// Domain tag of a channel voucher an agent's account pays.
pub const CHANNEL_DOMAIN: &[u8] = b"tenzro/agent-channel/v1";

/// The digest a serving node signs for a voucher paying `cumulative` on
/// channel `id` of the account `account` on the chain `chain`. A voucher is
/// honoured while the agent's grant there is not void.
pub fn channel_voucher_digest(
    chain: &[u8; 32],
    account: &[u8; 32],
    id: u64,
    cumulative: u128,
) -> [u8; 32] {
    sha256(&[
        CHANNEL_DOMAIN,
        chain,
        account,
        &id.to_be_bytes(),
        &cumulative.to_be_bytes(),
    ])
}

/// The payload hash an exact grant carries for `action`.
pub fn payload_hash(action: &RemoteAction) -> [u8; 32] {
    sha256(&[&action.encode()])
}

/// Bytes as hex in JSON.
pub mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

mod u128_string {
    pub fn serialize<S: serde::Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> RemoteGrant {
        RemoteGrant {
            chain: chain_hash("eip155:8453"),
            account: [0x11; 32],
            agent: agent_hash("did:tenzro:agent:example"),
            terms_version: 3,
            seq: 7,
            not_before_ms: 1_790_000_000_000,
            not_after_ms: 1_790_000_600_000,
            asset: asset_hash("eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
            budget: 5_000_000,
            per_action_max: 1_000_000,
            cosign_above: 500_000,
            keys_root: [0x22; 32],
            targets_root: [0u8; 32],
            payload_hash: [0u8; 32],
            relay_fee_max: 20_000,
            void: false,
        }
    }

    #[test]
    fn a_channel_voucher_digest_matches_the_sdk_and_account_vector() {
        let mut account = [0u8; 32];
        account[12..].copy_from_slice(&[0x11; 20]);
        assert_eq!(
            hex::encode(channel_voucher_digest(
                &chain_hash("eip155:8453"),
                &account,
                7,
                1000
            )),
            "046c669c72b5951a78639fc0849f070e8a5c2a8d0ddc0760d631aac95a2523d9"
        );
    }

    #[test]
    fn a_proven_payment_transaction_has_the_wire_the_sdks_build() {
        let tx = crate::transaction::TransactionType::Payment {
            op: crate::settlement::PaymentOp::Proven {
                agent_did: "did:x".into(),
                chain: "eip155:1".into(),
                delivery: vec![1, 2],
            },
        };
        assert_eq!(
            serde_json::to_value(&tx).unwrap(),
            serde_json::json!({ "Payment": { "op": { "proven": { "agent_did": "did:x", "chain": "eip155:1", "delivery": "0102" } } } })
        );
    }

    #[test]
    fn a_paid_report_round_trips_and_refuses_a_wrong_length() {
        let r = AccountReport {
            chain: chain_hash("eip155:8453"),
            account: [1; 32],
            agent: agent_hash("did:tenzro:agent:example"),
            seq: 2,
            kind: ReportKind::Paid {
                nonce: 3,
                payee: [4; 32],
                binding: crate::payment_authorization::PaymentBinding {
                    request_digest: [5; 32],
                    quote_digest: [6; 32],
                    usd_e6: 7,
                    app_margin: None,
                },
                amount: 8,
            },
        };
        let b = r.encode();
        assert_eq!(b.len(), 1 + 32 * 3 + 8 + 128);
        assert_eq!(AccountReport::decode(&b), Some(r));
        assert_eq!(AccountReport::decode(&b[..b.len() - 1]), None);
        let mut longer = b.clone();
        longer.push(0);
        assert_eq!(AccountReport::decode(&longer), None);
    }

    #[test]
    fn a_grant_round_trips_at_its_fixed_length() {
        let g = grant();
        let b = g.encode();
        assert_eq!(b.len(), ENCODED_LEN);
        assert_eq!(ENCODED_LEN, 322);
        assert_eq!(RemoteGrant::decode(&b), Ok(g));
    }

    #[test]
    fn malformed_grants_are_refused() {
        let b = grant().encode();
        assert_eq!(
            RemoteGrant::decode(&b[..321]),
            Err(GrantDecodeError::Length)
        );
        let mut v = b.clone();
        v[0] = 2;
        assert_eq!(RemoteGrant::decode(&v), Err(GrantDecodeError::Version));
        let mut v = b;
        v[321] = 2;
        assert_eq!(RemoteGrant::decode(&v), Err(GrantDecodeError::Flag));
    }

    #[test]
    fn every_leaf_has_a_proof_to_the_root() {
        for n in 1..=9usize {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&[i as u8]])).collect();
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                assert!(
                    merkle_verify(&root, leaf, &merkle_proof(&leaves, i)),
                    "{n} leaves, leaf {i}"
                );
            }
            assert!(!merkle_verify(
                &root,
                &[0xee; 32],
                &merkle_proof(&leaves, 0)
            ));
        }
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn the_digest_binds_chain_account_grant_and_nonce() {
        let a = RemoteAction {
            target: vec![1; 20],
            selector: vec![0xa9, 0x05, 0x9c, 0xbb],
            amount: 10,
            relay_refund: 1,
            data: vec![7; 64],
        };
        let d = act_digest(&chain_hash("eip155:1"), &[1; 32], 1, 0, &a);
        assert_ne!(d, act_digest(&chain_hash("eip155:10"), &[1; 32], 1, 0, &a));
        assert_ne!(d, act_digest(&chain_hash("eip155:1"), &[2; 32], 1, 0, &a));
        assert_ne!(d, act_digest(&chain_hash("eip155:1"), &[1; 32], 2, 0, &a));
        assert_ne!(d, act_digest(&chain_hash("eip155:1"), &[1; 32], 1, 1, &a));
    }

    #[test]
    fn a_relayer_is_paid_its_fee_and_moves_no_value_beyond_the_grant() {
        let g = grant();
        let now = g.not_before_ms + 1;
        let ok = RemoteAction {
            target: vec![1; 20],
            selector: vec![0xa9, 0x05, 0x9c, 0xbb],
            amount: 1_000_000,
            relay_refund: 20_000,
            data: vec![],
        };
        assert_eq!(g.admits(&ok, now), Ok(()));
        let greedy_relayer = RemoteAction {
            relay_refund: 20_001,
            ..ok.clone()
        };
        assert_eq!(
            g.admits(&greedy_relayer, now),
            Err("the relayer refund is above the grant's cap")
        );
        let over = RemoteAction {
            amount: 1_000_001,
            ..ok.clone()
        };
        assert_eq!(
            g.admits(&over, now),
            Err("the action moves more than the grant allows per action")
        );
        assert!(g.admits(&ok, g.not_after_ms + 1).is_err());
        assert!(
            RemoteGrant {
                void: true,
                ..g.clone()
            }
            .admits(&ok, now)
            .is_err()
        );
        assert!(
            RemoteGrant {
                payload_hash: [1; 32],
                ..g
            }
            .admits(&ok, now)
            .is_err()
        );
    }
}
