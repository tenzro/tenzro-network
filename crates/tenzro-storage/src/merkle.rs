//! Merkle Patricia Trie implementation for Tenzro Network
//!
//! This module implements a Merkle Patricia Trie for efficient state
//! commitment and proof generation.

use crate::error::{Result, StorageError};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tenzro_types::Hash;

/// A Merkle Patricia Trie for storing key-value pairs with cryptographic commitments
#[derive(Debug, Clone)]
pub struct MerklePatriciaTrie {
    root: Option<NodeHash>,
    nodes: HashMap<NodeHash, Node>,
    pending_changes: HashMap<Vec<u8>, Option<Vec<u8>>>,
    committed: bool,
}

type NodeHash = [u8; 32];

/// Node types in the Merkle Patricia Trie
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum Node {
    /// Branch node with 16 children (for hex nibbles) and optional value
    Branch {
        children: [Option<NodeHash>; 16],
        value: Option<Vec<u8>>,
    },
    /// Extension node to compress paths
    Extension {
        path: Vec<u8>,
        child: NodeHash,
    },
    /// Leaf node containing a value
    Leaf {
        path: Vec<u8>,
        value: Vec<u8>,
    },
}

impl MerklePatriciaTrie {
    /// Creates a new empty Merkle Patricia Trie
    pub fn new() -> Self {
        Self {
            root: None,
            nodes: HashMap::new(),
            pending_changes: HashMap::new(),
            committed: true,
        }
    }

    /// Inserts a key-value pair into the trie
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.pending_changes.insert(key.to_vec(), Some(value.to_vec()));
        self.committed = false;
        Ok(())
    }

    /// Gets a value from the trie
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Check pending changes first
        if let Some(change) = self.pending_changes.get(key) {
            return Ok(change.clone());
        }

        // Search in committed trie
        if let Some(root_hash) = self.root {
            let nibbles = key_to_nibbles(key);
            self.get_from_node(root_hash, &nibbles, 0)
        } else {
            Ok(None)
        }
    }

    /// Gets a value from a specific node
    fn get_from_node(
        &self,
        node_hash: NodeHash,
        nibbles: &[u8],
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        let node = self
            .nodes
            .get(&node_hash)
            .ok_or_else(|| StorageError::InvalidKey("Node not found".to_string()))?;

        match node {
            Node::Leaf { path, value } => {
                if &nibbles[depth..] == path.as_slice() {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Extension { path, child } => {
                if nibbles[depth..].starts_with(path) {
                    self.get_from_node(*child, nibbles, depth + path.len())
                } else {
                    Ok(None)
                }
            }
            Node::Branch { children, value } => {
                if depth >= nibbles.len() {
                    Ok(value.clone())
                } else {
                    let nibble = nibbles[depth] as usize;
                    if let Some(child_hash) = children[nibble] {
                        self.get_from_node(child_hash, nibbles, depth + 1)
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Deletes a key from the trie
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.pending_changes.insert(key.to_vec(), None);
        self.committed = false;
        Ok(())
    }

    /// Computes the root hash of the trie
    pub fn root_hash(&self) -> Hash {
        if let Some(root) = self.root {
            Hash::new(root)
        } else {
            Hash::zero()
        }
    }

    /// Commits pending changes and updates the root hash
    pub fn commit(&mut self) -> Result<Hash> {
        if self.committed {
            return Ok(self.root_hash());
        }

        // Collect pending changes to avoid borrow conflicts
        let pending: Vec<_> = self.pending_changes.drain().collect();

        // Apply all pending changes
        for (key, value) in pending {
            let nibbles = key_to_nibbles(&key);
            self.root = if let Some(value) = value {
                Some(self.insert_into_node(self.root, &nibbles, 0, value)?)
            } else {
                self.delete_from_node(self.root, &nibbles, 0)?
            };
        }

        self.committed = true;
        Ok(self.root_hash())
    }

    /// Inserts a value into a node
    fn insert_into_node(
        &mut self,
        node_hash: Option<NodeHash>,
        nibbles: &[u8],
        depth: usize,
        value: Vec<u8>,
    ) -> Result<NodeHash> {
        if let Some(hash) = node_hash {
            let node = self
                .nodes
                .get(&hash)
                .cloned()
                .ok_or_else(|| StorageError::InvalidKey("Node not found".to_string()))?;

            match node {
                Node::Leaf { path, value: old_value } => {
                    let remaining = &nibbles[depth..];
                    if path == remaining {
                        // Update existing leaf
                        let new_node = Node::Leaf {
                            path,
                            value,
                        };
                        Ok(self.store_node(new_node))
                    } else {
                        // Split into branch
                        let common_prefix = common_prefix(&path, remaining);
                        let new_hash = self.create_branch_from_leaves(
                            &path[common_prefix..],
                            old_value,
                            &remaining[common_prefix..],
                            value,
                        )?;

                        if common_prefix > 0 {
                            let ext_node = Node::Extension {
                                path: path[..common_prefix].to_vec(),
                                child: new_hash,
                            };
                            Ok(self.store_node(ext_node))
                        } else {
                            Ok(new_hash)
                        }
                    }
                }
                Node::Extension { path, child } => {
                    let remaining = &nibbles[depth..];
                    if remaining.starts_with(&path) {
                        let new_child = self.insert_into_node(
                            Some(child),
                            nibbles,
                            depth + path.len(),
                            value,
                        )?;
                        let new_node = Node::Extension {
                            path,
                            child: new_child,
                        };
                        Ok(self.store_node(new_node))
                    } else {
                        let common_prefix = common_prefix(&path, remaining);
                        if common_prefix > 0 {
                            let branch_hash = self.create_branch_from_extension_and_new(
                                &path[common_prefix..],
                                child,
                                &remaining[common_prefix..],
                                value,
                            )?;
                            let ext_node = Node::Extension {
                                path: path[..common_prefix].to_vec(),
                                child: branch_hash,
                            };
                            Ok(self.store_node(ext_node))
                        } else {
                            self.create_branch_from_extension_and_new(&path, child, remaining, value)
                        }
                    }
                }
                Node::Branch { mut children, value: node_value } => {
                    if depth >= nibbles.len() {
                        let new_node = Node::Branch {
                            children,
                            value: Some(value),
                        };
                        Ok(self.store_node(new_node))
                    } else {
                        let nibble = nibbles[depth] as usize;
                        let new_child = self.insert_into_node(
                            children[nibble],
                            nibbles,
                            depth + 1,
                            value,
                        )?;
                        children[nibble] = Some(new_child);
                        let new_node = Node::Branch {
                            children,
                            value: node_value,
                        };
                        Ok(self.store_node(new_node))
                    }
                }
            }
        } else {
            // Create new leaf
            let path = nibbles[depth..].to_vec();
            let node = Node::Leaf { path, value };
            Ok(self.store_node(node))
        }
    }

    /// Deletes a value from a node
    fn delete_from_node(
        &mut self,
        node_hash: Option<NodeHash>,
        nibbles: &[u8],
        depth: usize,
    ) -> Result<Option<NodeHash>> {
        if let Some(hash) = node_hash {
            let node = self
                .nodes
                .get(&hash)
                .cloned()
                .ok_or_else(|| StorageError::InvalidKey("Node not found".to_string()))?;

            match node {
                Node::Leaf { path, .. } => {
                    let remaining = &nibbles[depth..];
                    if path == remaining {
                        Ok(None)
                    } else {
                        Ok(Some(hash))
                    }
                }
                Node::Extension { path, child } => {
                    let remaining = &nibbles[depth..];
                    if remaining.starts_with(&path) {
                        if let Some(new_child) =
                            self.delete_from_node(Some(child), nibbles, depth + path.len())?
                        {
                            let new_node = Node::Extension {
                                path,
                                child: new_child,
                            };
                            Ok(Some(self.store_node(new_node)))
                        } else {
                            Ok(None)
                        }
                    } else {
                        Ok(Some(hash))
                    }
                }
                Node::Branch { mut children, value } => {
                    if depth >= nibbles.len() {
                        let new_node = Node::Branch {
                            children,
                            value: None,
                        };
                        Ok(Some(self.store_node(new_node)))
                    } else {
                        let nibble = nibbles[depth] as usize;
                        children[nibble] =
                            self.delete_from_node(children[nibble], nibbles, depth + 1)?;
                        let new_node = Node::Branch { children, value };
                        Ok(Some(self.store_node(new_node)))
                    }
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Creates a branch node from two leaves
    fn create_branch_from_leaves(
        &mut self,
        path1: &[u8],
        value1: Vec<u8>,
        path2: &[u8],
        value2: Vec<u8>,
    ) -> Result<NodeHash> {
        let mut children: [Option<NodeHash>; 16] = [None; 16];

        if path1.is_empty() && path2.is_empty() {
            return Err(StorageError::InvalidKey("Cannot create branch with empty paths".to_string()));
        }

        if !path1.is_empty() {
            let nibble1 = path1[0] as usize;
            let leaf1 = Node::Leaf {
                path: path1[1..].to_vec(),
                value: value1.clone(),
            };
            children[nibble1] = Some(self.store_node(leaf1));
        }

        if !path2.is_empty() {
            let nibble2 = path2[0] as usize;
            let leaf2 = Node::Leaf {
                path: path2[1..].to_vec(),
                value: value2.clone(),
            };
            children[nibble2] = Some(self.store_node(leaf2));
        }

        let node = Node::Branch {
            children,
            value: if path1.is_empty() { Some(value1) } else if path2.is_empty() { Some(value2) } else { None },
        };
        Ok(self.store_node(node))
    }

    /// Creates a branch from an extension and new value
    fn create_branch_from_extension_and_new(
        &mut self,
        ext_path: &[u8],
        ext_child: NodeHash,
        new_path: &[u8],
        new_value: Vec<u8>,
    ) -> Result<NodeHash> {
        let mut children: [Option<NodeHash>; 16] = [None; 16];

        if !ext_path.is_empty() {
            let nibble = ext_path[0] as usize;
            if ext_path.len() > 1 {
                let ext_node = Node::Extension {
                    path: ext_path[1..].to_vec(),
                    child: ext_child,
                };
                children[nibble] = Some(self.store_node(ext_node));
            } else {
                children[nibble] = Some(ext_child);
            }
        }

        if !new_path.is_empty() {
            let nibble = new_path[0] as usize;
            let leaf = Node::Leaf {
                path: new_path[1..].to_vec(),
                value: new_value.clone(),
            };
            children[nibble] = Some(self.store_node(leaf));
        }

        let node = Node::Branch {
            children,
            value: if new_path.is_empty() { Some(new_value) } else { None },
        };
        Ok(self.store_node(node))
    }

    /// Stores a node and returns its hash
    fn store_node(&mut self, node: Node) -> NodeHash {
        let hash = hash_node(&node);
        self.nodes.insert(hash, node);
        hash
    }

    /// Generates a Merkle proof for a key.
    ///
    /// The returned proof carries enough information (specifically: sibling
    /// child hashes for every branch node along the path) to reconstruct
    /// every node hash from the leaf back up to the root. This is what makes
    /// `verify_proof` actually bind the proof to a specific root hash.
    pub fn generate_proof(&self, key: &[u8]) -> Result<MerkleProof> {
        let nibbles = key_to_nibbles(key);
        let mut proof = Vec::new();

        if let Some(root_hash) = self.root {
            self.build_proof(root_hash, &nibbles, 0, &mut proof)?;
        }

        Ok(MerkleProof {
            key: key.to_vec(),
            proof,
        })
    }

    /// Builds a proof by traversing the trie. For branch nodes we record
    /// **all 16 child hashes** so verifiers can recompute the branch's hash;
    /// for extension nodes we record the path; for leaves we record the
    /// path and value. The terminal node may be a `LeafTerminal` (key
    /// found) or `Absent` (proof of non-membership).
    fn build_proof(
        &self,
        node_hash: NodeHash,
        nibbles: &[u8],
        depth: usize,
        proof: &mut Vec<ProofNode>,
    ) -> Result<()> {
        let node = self
            .nodes
            .get(&node_hash)
            .ok_or_else(|| StorageError::InvalidKey("Node not found".to_string()))?;

        match node {
            Node::Leaf { path, value } => {
                if &nibbles[depth..] == path.as_slice() {
                    proof.push(ProofNode::Leaf {
                        path: path.clone(),
                        value: value.clone(),
                    });
                } else {
                    // Non-membership: the trie has a leaf at this position
                    // but with a different remaining path.
                    proof.push(ProofNode::Leaf {
                        path: path.clone(),
                        value: value.clone(),
                    });
                }
            }
            Node::Extension { path, child } => {
                proof.push(ProofNode::Extension { path: path.clone() });
                if nibbles[depth..].starts_with(path) {
                    self.build_proof(*child, nibbles, depth + path.len(), proof)?;
                }
            }
            Node::Branch { children, value } => {
                proof.push(ProofNode::Branch {
                    children: *children,
                    value: value.clone(),
                });
                if depth < nibbles.len() {
                    let nibble = nibbles[depth] as usize;
                    if let Some(child_hash) = children[nibble] {
                        self.build_proof(child_hash, nibbles, depth + 1, proof)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Verifies a Merkle proof against a known root hash (HIGH #79).
    ///
    /// This performs three independent checks:
    ///
    /// 1. **Value binding** — the proof's terminal leaf (if any) actually
    ///    contains the expected value.
    /// 2. **Path consistency** — every extension/branch node on the proof
    ///    is consistent with the queried key's nibble path.
    /// 3. **Root binding** — the cryptographic hash chain reconstructed from
    ///    the leaf upward matches the supplied `root`. This is the critical
    ///    binding step that the previous implementation was missing — it
    ///    used to throw away sibling hashes and so could not actually
    ///    recompute parent hashes.
    ///
    /// All three checks must pass for the proof to be valid.
    pub fn verify_proof(proof: &MerkleProof, root: Hash, value: Option<&[u8]>) -> Result<bool> {
        if proof.proof.is_empty() {
            // An empty proof can only attest to an empty trie (zero root)
            // and a non-existent value.
            return Ok(root == Hash::zero() && value.is_none());
        }

        let nibbles = key_to_nibbles(&proof.key);

        // (1) value binding
        let extracted = Self::extract_value_from_proof(&proof.proof, &nibbles, 0)?;
        if extracted.as_deref() != value {
            return Ok(false);
        }

        // (2 + 3) path consistency + root binding
        let computed_root = match Self::compute_proof_root(&proof.proof, &nibbles, 0, 0) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };

        Ok(Hash::new(computed_root) == root)
    }

    /// Recomputes the hash of the trie node represented by `proof[index]`
    /// using the sibling/child information that the proof carries.
    ///
    /// Each call returns the hash of one node and recurses into the proof
    /// to obtain the hashes of any nested children. The recursion bottoms
    /// out at `ProofNode::Leaf`. For branch nodes, the proof carries the
    /// hashes of all 16 children, so we splice in the freshly recomputed
    /// hash for the queried child and reuse the supplied siblings for the
    /// other 15 — yielding the same hash as the original branch node.
    fn compute_proof_root(
        proof: &[ProofNode],
        nibbles: &[u8],
        index: usize,
        depth: usize,
    ) -> Result<NodeHash> {
        if index >= proof.len() {
            return Err(StorageError::InvalidMerkleProof);
        }

        match &proof[index] {
            ProofNode::Leaf { path, value } => {
                // The remaining nibbles must match the leaf's path either
                // exactly (membership) or differently (non-membership at
                // this position). For value-bound verification, the
                // extract_value step has already enforced membership; for
                // non-membership we just hash the leaf as-is.
                let _ = nibbles;
                let _ = depth;
                let node = Node::Leaf {
                    path: path.clone(),
                    value: value.clone(),
                };
                Ok(hash_node(&node))
            }
            ProofNode::Extension { path } => {
                if !nibbles[depth..].starts_with(path) {
                    return Err(StorageError::InvalidMerkleProof);
                }
                let new_depth = depth + path.len();
                let child_hash =
                    Self::compute_proof_root(proof, nibbles, index + 1, new_depth)?;
                let node = Node::Extension {
                    path: path.clone(),
                    child: child_hash,
                };
                Ok(hash_node(&node))
            }
            ProofNode::Branch { children, value } => {
                let mut reconstructed: [Option<NodeHash>; 16] = *children;

                if depth < nibbles.len() {
                    let nibble = nibbles[depth] as usize;
                    if nibble >= 16 {
                        return Err(StorageError::InvalidMerkleProof);
                    }
                    // If the proof has a continuation, recompute that
                    // child's hash and verify it matches what the branch
                    // claimed (this is the binding step that prevents
                    // a malicious prover from substituting children).
                    if index + 1 < proof.len() {
                        let recomputed = Self::compute_proof_root(
                            proof,
                            nibbles,
                            index + 1,
                            depth + 1,
                        )?;
                        match reconstructed[nibble] {
                            Some(claimed) if claimed != recomputed => {
                                return Err(StorageError::InvalidMerkleProof);
                            }
                            None => {
                                // Branch claimed there was no child at this
                                // nibble, but the proof has more nodes —
                                // contradiction.
                                return Err(StorageError::InvalidMerkleProof);
                            }
                            _ => {
                                reconstructed[nibble] = Some(recomputed);
                            }
                        }
                    }
                }

                let node = Node::Branch {
                    children: reconstructed,
                    value: value.clone(),
                };
                Ok(hash_node(&node))
            }
        }
    }

    /// Extracts the value from a proof by walking it according to the
    /// queried key's nibbles. Returns `Ok(None)` if the proof witnesses
    /// non-membership.
    fn extract_value_from_proof(
        proof: &[ProofNode],
        nibbles: &[u8],
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        if proof.is_empty() {
            return Ok(None);
        }

        match &proof[0] {
            ProofNode::Leaf { path, value } => {
                if &nibbles[depth..] == path.as_slice() {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            }
            ProofNode::Extension { path } => {
                if nibbles[depth..].starts_with(path) {
                    Self::extract_value_from_proof(&proof[1..], nibbles, depth + path.len())
                } else {
                    Ok(None)
                }
            }
            ProofNode::Branch { children: _, value } => {
                if depth >= nibbles.len() {
                    Ok(value.clone())
                } else {
                    Self::extract_value_from_proof(&proof[1..], nibbles, depth + 1)
                }
            }
        }
    }
}

impl Default for MerklePatriciaTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// A Merkle proof for verifying inclusion (or non-inclusion) of a key-value pair.
///
/// The proof is a sequence of `ProofNode`s walking from the root to (at most)
/// a terminal leaf along the queried key's nibble path. Branch nodes carry
/// the hashes of all 16 children — including the siblings of the path —
/// which is what allows `MerklePatriciaTrie::verify_proof` to recompute the
/// branch's hash and ultimately bind the proof to a specific root hash.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub proof: Vec<ProofNode>,
}

/// A node in a Merkle proof.
///
/// `Branch.children` contains all 16 sibling hashes; without these the
/// verifier could not recompute the branch's hash and so could not bind
/// the proof to the trie's root (HIGH #79).
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ProofNode {
    Leaf {
        path: Vec<u8>,
        value: Vec<u8>,
    },
    Extension {
        path: Vec<u8>,
    },
    Branch {
        /// The 16 child hashes of this branch node, in nibble order.
        /// The verifier uses these to recompute the branch's hash.
        children: [Option<[u8; 32]>; 16],
        value: Option<Vec<u8>>,
    },
}

/// Converts a key to nibbles (hex digits)
fn key_to_nibbles(key: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(key.len() * 2);
    for byte in key {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Computes the common prefix length of two paths
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// Computes the hash of a node
fn hash_node(node: &Node) -> NodeHash {
    let mut hasher = Sha256::new();

    match node {
        Node::Leaf { path, value } => {
            hasher.update(b"leaf");
            hasher.update(path);
            hasher.update(value);
        }
        Node::Extension { path, child } => {
            hasher.update(b"extension");
            hasher.update(path);
            hasher.update(child);
        }
        Node::Branch { children, value } => {
            hasher.update(b"branch");
            for child in children.iter() {
                if let Some(hash) = child {
                    hasher.update(hash);
                } else {
                    hasher.update([0u8; 32]);
                }
            }
            if let Some(v) = value {
                hasher.update(v);
            }
        }
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let mut trie = MerklePatriciaTrie::new();

        trie.insert(b"key1", b"value1").unwrap();
        trie.insert(b"key2", b"value2").unwrap();
        trie.commit().unwrap();

        assert_eq!(trie.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(trie.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(trie.get(b"key3").unwrap(), None);
    }

    #[test]
    fn test_delete() {
        let mut trie = MerklePatriciaTrie::new();

        trie.insert(b"key1", b"value1").unwrap();
        trie.commit().unwrap();

        trie.delete(b"key1").unwrap();
        trie.commit().unwrap();

        assert_eq!(trie.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_root_hash_changes() {
        let mut trie = MerklePatriciaTrie::new();

        let root1 = trie.commit().unwrap();

        trie.insert(b"key1", b"value1").unwrap();
        let root2 = trie.commit().unwrap();

        assert_ne!(root1, root2);

        trie.delete(b"key1").unwrap();
        let root3 = trie.commit().unwrap();

        assert_eq!(root1, root3);
    }

    #[test]
    fn test_merkle_proof_membership_binds_to_root() {
        // Regression test for HIGH #79: a valid membership proof must
        // verify against the trie's actual root hash, and tampering with
        // either the value or the supplied root must cause verification
        // to fail.
        let mut trie = MerklePatriciaTrie::new();
        trie.insert(b"alice", b"100").unwrap();
        trie.insert(b"bob", b"200").unwrap();
        trie.insert(b"carol", b"300").unwrap();
        let root = trie.commit().unwrap();

        let proof = trie.generate_proof(b"alice").unwrap();
        assert!(
            MerklePatriciaTrie::verify_proof(&proof, root, Some(b"100")).unwrap(),
            "valid membership proof must verify against the real root"
        );
    }

    #[test]
    fn test_merkle_proof_rejects_wrong_value() {
        let mut trie = MerklePatriciaTrie::new();
        trie.insert(b"alice", b"100").unwrap();
        trie.insert(b"bob", b"200").unwrap();
        let root = trie.commit().unwrap();

        let proof = trie.generate_proof(b"alice").unwrap();
        assert!(
            !MerklePatriciaTrie::verify_proof(&proof, root, Some(b"999")).unwrap(),
            "verification must reject a forged value"
        );
    }

    #[test]
    fn test_merkle_proof_rejects_wrong_root() {
        let mut trie = MerklePatriciaTrie::new();
        trie.insert(b"alice", b"100").unwrap();
        trie.insert(b"bob", b"200").unwrap();
        let _real_root = trie.commit().unwrap();

        let proof = trie.generate_proof(b"alice").unwrap();
        let fake_root = Hash::new([0xAAu8; 32]);
        assert!(
            !MerklePatriciaTrie::verify_proof(&proof, fake_root, Some(b"100")).unwrap(),
            "verification must reject a proof against the wrong root"
        );
    }

    #[test]
    fn test_merkle_proof_empty_trie() {
        let trie = MerklePatriciaTrie::new();
        let proof = trie.generate_proof(b"missing").unwrap();
        assert!(proof.proof.is_empty());
        assert!(MerklePatriciaTrie::verify_proof(&proof, Hash::zero(), None).unwrap());
        // An empty proof against a non-zero root must not verify.
        assert!(
            !MerklePatriciaTrie::verify_proof(&proof, Hash::new([1u8; 32]), None).unwrap()
        );
    }

    #[test]
    fn test_merkle_proof_branch_siblings_carried() {
        // Insert several keys that share a prefix to force creation of
        // branch nodes, then prove one and confirm that the other
        // siblings are present in the proof's branch entries.
        let mut trie = MerklePatriciaTrie::new();
        trie.insert(b"key10", b"v10").unwrap();
        trie.insert(b"key20", b"v20").unwrap();
        trie.insert(b"key30", b"v30").unwrap();
        trie.insert(b"key40", b"v40").unwrap();
        let root = trie.commit().unwrap();

        let proof = trie.generate_proof(b"key10").unwrap();

        // At least one branch node in the proof should carry more than
        // one populated sibling — that's the whole point of the new
        // proof format.
        let mut saw_multi_sibling_branch = false;
        for node in &proof.proof {
            if let ProofNode::Branch { children, .. } = node {
                let populated = children.iter().filter(|c| c.is_some()).count();
                if populated > 1 {
                    saw_multi_sibling_branch = true;
                    break;
                }
            }
        }
        assert!(
            saw_multi_sibling_branch,
            "proof should carry sibling hashes for branch nodes"
        );

        assert!(
            MerklePatriciaTrie::verify_proof(&proof, root, Some(b"v10")).unwrap()
        );
    }
}
