// SPDX-License-Identifier: Apache-2.0
//! Agent grants as accounts on other chains check them: the grant's fixed
//! layout, the Merkle proofs of serving-node keys and targets, and the digest
//! serving nodes sign for an action. Byte for byte the rules Tenzro writes
//! grants by.

use sha2::{Digest, Sha256};

/// The layout version.
pub const VERSION: u8 = 1;
/// Bytes of an encoded grant.
pub const GRANT_LEN: usize = 322;
/// Domain of the digest serving nodes sign for an action.
pub const ACT_DOMAIN: &[u8] = b"tenzro/agent-act/v1";
/// Domain of the per-DID account salt.
pub const SALT_DOMAIN: &[u8] = b"tenzro/omni-account/v1";

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// One agent's authority on one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub chain: [u8; 32],
    pub account: [u8; 32],
    pub agent: [u8; 32],
    pub terms_version: u64,
    pub seq: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub asset: [u8; 32],
    pub budget: u128,
    pub per_action_max: u128,
    pub cosign_above: u128,
    pub keys_root: [u8; 32],
    pub targets_root: [u8; 32],
    pub payload_hash: [u8; 32],
    pub relay_fee_max: u128,
    pub void: bool,
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("length checked")
    }
}

impl Grant {
    /// Decode the fixed big-endian layout.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != GRANT_LEN || b[0] != VERSION {
            return None;
        }
        let mut r = Reader(&b[1..]);
        let g = Self {
            chain: r.take(),
            account: r.take(),
            agent: r.take(),
            terms_version: u64::from_be_bytes(r.take()),
            seq: u64::from_be_bytes(r.take()),
            not_before_ms: u64::from_be_bytes(r.take()),
            not_after_ms: u64::from_be_bytes(r.take()),
            asset: r.take(),
            budget: u128::from_be_bytes(r.take()),
            per_action_max: u128::from_be_bytes(r.take()),
            cosign_above: u128::from_be_bytes(r.take()),
            keys_root: r.take(),
            targets_root: r.take(),
            payload_hash: r.take(),
            relay_fee_max: u128::from_be_bytes(r.take()),
            void: match r.take::<1>()[0] {
                0 => false,
                1 => true,
                _ => return None,
            },
        };
        Some(g)
    }

    pub fn is_exact(&self) -> bool {
        self.payload_hash != [0u8; 32]
    }
}

/// A serving node's key leaf: its P-256 key (SEC1, uncompressed) and its
/// operator's DID.
pub fn key_leaf(sec1_public_key: &[u8; 65], operator_did: &[u8]) -> [u8; 32] {
    sha(&[&[0x00], sec1_public_key, operator_did])
}

/// A target leaf: the target and the function on it, each length-prefixed
/// (u16, big-endian).
pub fn target_leaf(target: &[u8], selector: &[u8]) -> [u8; 32] {
    sha(&[&[0x00], &(target.len() as u16).to_be_bytes(), target, &(selector.len() as u16).to_be_bytes(), selector])
}

/// Whether `leaf` is under `root` with `proof` (sibling hashes, pairs hashed
/// in sorted order).
pub fn merkle_verify(root: &[u8; 32], leaf: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    let mut acc = *leaf;
    for s in proof {
        let (lo, hi) = if acc <= *s { (acc, *s) } else { (*s, acc) };
        acc = sha(&[&[0x01], &lo, &hi]);
    }
    &acc == root
}

/// The digest serving nodes sign for action number `nonce` under grant `seq`
/// of `account` on `chain`, over the encoded action.
pub fn act_digest(chain: &[u8; 32], account: &[u8; 32], seq: u64, nonce: u64, action: &[u8]) -> [u8; 32] {
    sha(&[ACT_DOMAIN, chain, account, &seq.to_be_bytes(), &nonce.to_be_bytes(), action])
}

/// The selector of an action that pays: the account moves the action's
/// amount to its target and reports the payment for Tenzro to record.
pub const PAY_SELECTOR: &[u8] = b"pay";

/// What a paying action's data carries: the Tenzro payee (32), the request
/// and quote digests it bought (32 each) and the USD price (u64, big-endian).
pub const PAY_DATA_LEN: usize = 104;

/// Length of a payment report.
pub const PAID_REPORT_LEN: usize = 1 + 32 * 3 + 8 + 8 + PAY_DATA_LEN + 16;

/// The report an account emits when action `nonce` under grant `g` paid
/// `amount`, in the layout Tenzro records proven payments from: kind 4,
/// chain, account, agent, seq, nonce, the action's pay data, amount.
pub fn paid_report(g: &Grant, nonce: u64, data: &[u8], amount: u128) -> Option<[u8; PAID_REPORT_LEN]> {
    if data.len() != PAY_DATA_LEN {
        return None;
    }
    let mut out = [0u8; PAID_REPORT_LEN];
    out[0] = 4;
    let mut at = 1;
    for part in [&g.chain[..], &g.account, &g.agent, &g.seq.to_be_bytes(), &nonce.to_be_bytes(), data, &amount.to_be_bytes()] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(out)
}

/// The payload hash an exact grant carries for the encoded action.
pub fn payload_hash(action: &[u8]) -> [u8; 32] {
    sha(&[action])
}

/// The per-DID salt accounts are deployed with.
pub fn salt(did: &[u8]) -> [u8; 32] {
    sha(&[SALT_DOMAIN, did])
}

/// The tree key of the grant of `did` on `caip2`: the VM keeps it as system
/// storage, keyed `storage:<system address>:<hex of agent_grant:did:caip2>`
/// in the `state` namespace.
pub fn grant_tree_key(did: &[u8], caip2: &[u8]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut h = Sha256::new();
    h.update(b"tenzro.state-trie.key");
    h.update(5u16.to_le_bytes());
    h.update(b"state");
    h.update(b"storage:");
    h.update([b'f'; 40]);
    h.update(b":");
    for part in [b"agent_grant:".as_slice(), did, b":", caip2] {
        for byte in part {
            h.update([HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
        }
    }
    h.finalize().into()
}
