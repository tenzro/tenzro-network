//! Hash-based vouchers for payment channels on other chains.
//!
//! A channel contract that verifies hash-based vouchers commits, when the
//! channel opens, to the keys this serving node gives it for that channel
//! (see [`tenzro_crypto::hash_voucher`]). Each voucher then spends one
//! one-time key. The keys derive from the hardware root under a label
//! naming the agent, this machine, the chain and the channel, so nothing
//! secret is stored. What is stored is how many keys of each channel were
//! spent: a key signs once, so the count is written and flushed before the
//! signature leaves the node, and a crash costs a key rather than reusing
//! one.
//!
//! Contracts without hash-based vouchers keep taking the P-256 voucher.

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tenzro_crypto::hash_voucher::{VoucherKeyTree, VoucherKeys, VoucherSignature};

/// Height of a channel's key tree: 1024 vouchers per channel.
pub const TREE_HEIGHT: u8 = 10;

const LABEL_DOMAIN: &[u8] = b"tenzro/remote-voucher/keys";

/// The derivation label of the keys of `channel_id` on `chain` that this
/// machine signs for `agent_did`.
pub fn label(agent_did: &str, machine_did: &str, chain: &str, channel_id: u64) -> String {
    let mut h = Sha256::new();
    h.update(LABEL_DOMAIN);
    for part in [
        agent_did.as_bytes(),
        machine_did.as_bytes(),
        chain.as_bytes(),
    ] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.update(channel_id.to_be_bytes());
    format!("tenzro/remote-voucher/{}", hex::encode(h.finalize()))
}

/// The key tree under `label` from `root`. A root whose derived keys are
/// classical is refused: its keys would add nothing a P-256 voucher lacks.
pub fn tree(
    root: &tenzro_device_key::DerivationRoot,
    label: &str,
) -> Result<VoucherKeyTree, String> {
    let seed = root.endpoint_secret(label).map_err(|e| e.to_string())?;
    VoucherKeyTree::derive(*seed, TREE_HEIGHT).map_err(|e| e.to_string())
}

fn spent_path(data_dir: &Path, label: &str) -> PathBuf {
    let name = label.rsplit('/').next().unwrap_or(label);
    data_dir
        .join("remote-vouchers")
        .join(format!("{name}.spent"))
}

/// How many keys under `label` were spent.
pub fn spent(data_dir: &Path, label: &str) -> Result<u64, String> {
    match std::fs::read(spent_path(data_dir, label)) {
        Ok(b) => b
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| format!("the spent-key count of {label} is malformed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.to_string()),
    }
}

/// Takes the next unspent key under `label` and records it spent, flushed
/// to disk, before returning it.
pub fn take_leaf(data_dir: &Path, label: &str, capacity: u64) -> Result<u32, String> {
    let leaf = spent(data_dir, label)?;
    if leaf >= capacity {
        return Err(format!(
            "all {capacity} voucher keys of this channel are spent; open a new channel"
        ));
    }
    let path = spent_path(data_dir, label);
    let dir = path
        .parent()
        .ok_or("no directory for the spent-key count")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&(leaf + 1).to_be_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    // A directory cannot be opened for a sync on Windows; the rename there is
    // already durable once it returns.
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())?;
    u32::try_from(leaf).map_err(|e| e.to_string())
}

/// Signs `digest` with the next unspent key of `tree`, the channel's keys
/// under `label`.
pub fn sign(
    tree: &VoucherKeyTree,
    data_dir: &Path,
    label: &str,
    digest: &[u8; 32],
) -> Result<(VoucherKeys, VoucherSignature), String> {
    let leaf = take_leaf(data_dir, label, tree.capacity())?;
    let signature = tree.sign(leaf, digest).map_err(|e| e.to_string())?;
    Ok((tree.keys(), signature))
}

/// The keys as the RPC answers them.
pub fn keys_json(keys: &VoucherKeys) -> serde_json::Value {
    serde_json::json!({
        "scheme": "wots-sha256-merkle",
        "public_seed": hex::encode(keys.public_seed),
        "height": keys.height,
        "root": hex::encode(keys.root),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each voucher of a channel spends the next key and verifies under the
    /// keys the channel committed to; the count survives a restart, so no
    /// key signs twice; another channel's keys differ, and a spent-out tree
    /// signs nothing.
    #[test]
    fn each_voucher_spends_a_new_key_that_verifies_under_the_channel_keys() {
        let root = tenzro_device_key::DerivationRoot::for_tests([5; 32]);
        let dir = tempfile::tempdir().unwrap();
        let l = label("did:tenzro:agent:a", "did:tenzro:machine:m", "eip155:1", 7);
        let channel = tree(&root, &l).unwrap();
        let committed = channel.keys();
        let mut leaves = Vec::new();
        for n in 1u8..=3 {
            let digest = [n; 32];
            let (keys, sig) = sign(&channel, dir.path(), &l, &digest).unwrap();
            assert_eq!(keys, committed);
            tenzro_crypto::hash_voucher::verify(&keys, &digest, &sig).unwrap();
            leaves.push(sig.leaf);
        }
        assert_eq!(leaves, vec![0, 1, 2]);
        assert_eq!(spent(dir.path(), &l).unwrap(), 3);

        let other = label("did:tenzro:agent:a", "did:tenzro:machine:m", "eip155:1", 8);
        assert_ne!(tree(&root, &other).unwrap().keys(), committed);
        assert_eq!(spent(dir.path(), &other).unwrap(), 0);

        std::fs::write(spent_path(dir.path(), &l), 1024u64.to_be_bytes()).unwrap();
        assert!(sign(&channel, dir.path(), &l, &[9; 32]).is_err());
    }
}
