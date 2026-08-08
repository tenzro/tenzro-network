//! Node-alias applied state: `name → node`, kept in step with consensus.
//!
//! # This table is a cache, not an authority
//!
//! Ownership of a name is decided by the `ClaimNodeAlias` / `BindNodeAlias` /
//! `ReleaseNodeAlias` typed transactions in the native VM, which write into
//! `SYSTEM_ADDRESS` storage. Every node executes the same ordered
//! transactions and therefore reaches the same verdict — that is what makes
//! naming permissionless rather than a matter of which RPC endpoint a
//! claimant happened to reach.
//!
//! What lives here is the *applied result*, mirrored out of those
//! transactions' logs so hostname resolution on the request path is a
//! DashMap read instead of a VM-state lookup. Nothing in this file may
//! decide who owns a name; it only records what consensus already decided.
//!
//! # The suffix is not stored
//!
//! Records hold a bare DNS label. The public suffix lives in
//! [`crate::config::NodeConfig::public_node_suffix`] and is applied at
//! resolution time, because the testnet domain exists only to satisfy
//! WebAuthn's registrable-domain requirement and is expected to change.
//! Retiring it must not invalidate a claim.

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_storage::{CF_METADATA, KvStore};
use tenzro_types::node_alias::NodeAlias;
use thiserror::Error;
use tracing::{debug, warn};

/// Key prefix for alias records within `CF_METADATA`. Distinct from the
/// identity crate's `username:` prefix so the human and node namespaces
/// cannot collide by construction.
const NODE_ALIAS_PREFIX: &str = "node_alias:";

fn alias_key(name: &str) -> Vec<u8> {
    format!("{NODE_ALIAS_PREFIX}{name}").into_bytes()
}

#[derive(Debug, Error)]
pub enum NodeAliasError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// `name → NodeAlias`, write-through to `CF_METADATA`, hydrated on boot.
pub struct NodeAliasRegistry {
    aliases: DashMap<String, NodeAlias>,
    /// Reverse index so a node can find the name bound to its own machine
    /// DID without scanning — used by first-boot auto-bind.
    by_machine: DashMap<String, String>,
    /// The public suffix aliases are rendered under, e.g.
    /// `network.tenzro.com`. `None` disables hostname resolution entirely:
    /// a node with no configured suffix must not claim to answer for any
    /// public hostname.
    suffix: Option<String>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for NodeAliasRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeAliasRegistry")
            .field("aliases", &self.aliases.len())
            .field("suffix", &self.suffix)
            .finish()
    }
}

impl NodeAliasRegistry {
    pub fn new(suffix: Option<String>) -> Self {
        Self {
            aliases: DashMap::new(),
            by_machine: DashMap::new(),
            suffix: suffix.map(|s| s.trim_matches('.').to_ascii_lowercase()),
            storage: None,
        }
    }

    /// Storage-backed registry: hydrates existing alias records from
    /// `CF_METADATA` under the `node_alias:` prefix.
    pub fn with_storage(
        storage: Arc<dyn KvStore>,
        suffix: Option<String>,
    ) -> Result<Self, NodeAliasError> {
        let reg = Self::new(suffix);
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, NODE_ALIAS_PREFIX.as_bytes())
            .map_err(|e| NodeAliasError::Storage(format!("node-alias scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<NodeAlias>(&bytes) {
                    Ok(record) => {
                        reg.index(record);
                        restored += 1;
                    }
                    Err(e) => warn!("skipping undecodable node alias: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(NodeAliasError::Storage(format!("node-alias get: {e}"))),
            }
        }
        let mut reg = reg;
        reg.storage = Some(storage);
        if restored > 0 {
            debug!("hydrated {restored} node alias record(s)");
        }
        Ok(reg)
    }

    fn index(&self, record: NodeAlias) {
        if let Some(machine) = record.machine_did.clone() {
            self.by_machine.insert(machine, record.name.clone());
        }
        self.aliases.insert(record.name.clone(), record);
    }

    /// Apply a claim/bind observed in a finalized block.
    ///
    /// Idempotent — replaying the same log is a no-op, which matters because
    /// block re-delivery during sync must not corrupt the table.
    pub fn apply(&self, record: NodeAlias) -> Result<(), NodeAliasError> {
        if let Some(ref storage) = self.storage {
            let blob = serde_json::to_vec(&record)
                .map_err(|e| NodeAliasError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &alias_key(&record.name), &blob)
                .map_err(|e| NodeAliasError::Storage(format!("node-alias put: {e}")))?;
        }
        self.index(record);
        Ok(())
    }

    /// Apply a release observed in a finalized block.
    pub fn apply_release(&self, name: &str) -> Result<(), NodeAliasError> {
        if let Some((_, record)) = self.aliases.remove(name) {
            if let Some(machine) = record.machine_did {
                self.by_machine.remove(&machine);
            }
        }
        if let Some(ref storage) = self.storage {
            storage
                .delete(CF_METADATA, &alias_key(name))
                .map_err(|e| NodeAliasError::Storage(format!("node-alias delete: {e}")))?;
        }
        Ok(())
    }

    /// Look up a claim by its bare label.
    pub fn resolve(&self, name: &str) -> Option<NodeAlias> {
        self.aliases.get(name).map(|e| e.value().clone())
    }

    /// The name bound to `machine_did`, if any.
    pub fn name_for_machine(&self, machine_did: &str) -> Option<String> {
        self.by_machine.get(machine_did).map(|e| e.value().clone())
    }

    /// Every claim held by `owner_address` (hex, no `0x`).
    pub fn list_for_owner(&self, owner_address: &str) -> Vec<NodeAlias> {
        self.aliases
            .iter()
            .filter(|e| e.value().owner_address == owner_address)
            .map(|e| e.value().clone())
            .collect()
    }

    /// All claims. Ordered by name so callers get a stable listing.
    pub fn list(&self) -> Vec<NodeAlias> {
        let mut out: Vec<NodeAlias> = self.aliases.iter().map(|e| e.value().clone()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// The configured public suffix, if this node serves one.
    pub fn suffix(&self) -> Option<&str> {
        self.suffix.as_deref()
    }

    /// Resolve a public `Host` header to a **bound** alias.
    ///
    /// Requiring the configured suffix is what keeps this table from
    /// shadowing arbitrary hostnames: without it, a claim for `alice` would
    /// match a request for `alice.someone-elses-domain.example`. An unbound
    /// claim resolves to `None` and falls through to the ordinary 404 path.
    pub fn resolve_host(&self, raw_host: &str) -> Option<NodeAlias> {
        let suffix = self.suffix.as_deref()?;
        let host = crate::sites::normalize_hostname(raw_host)?;
        let label = host.strip_suffix(&format!(".{suffix}"))?;
        // Exactly one label — `a.b.<suffix>` is not a claim on `a`.
        if label.is_empty() || label.contains('.') {
            return None;
        }
        self.aliases
            .get(label)
            .map(|e| e.value().clone())
            .filter(|a| a.is_bound())
    }

    /// Number of claims held.
    pub fn len(&self) -> usize {
        self.aliases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::node_alias::default_exposed_prefixes;

    fn bound(name: &str) -> NodeAlias {
        NodeAlias {
            name: name.to_string(),
            owner_address: "aa".repeat(20),
            owner_did: "did:tenzro:human:x".to_string(),
            machine_did: Some(format!("did:tenzro:machine:{name}")),
            endpoint_id: Some("endpoint-1".to_string()),
            exposed_prefixes: default_exposed_prefixes(),
            claimed_at: 1,
            updated_at: 1,
        }
    }

    fn unbound(name: &str) -> NodeAlias {
        NodeAlias {
            machine_did: None,
            endpoint_id: None,
            ..bound(name)
        }
    }

    #[test]
    fn resolves_a_bound_host_under_the_configured_suffix() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(bound("alice")).unwrap();
        let found = reg
            .resolve_host("alice.network.tenzro.com")
            .expect("resolves");
        assert_eq!(found.name, "alice");
    }

    /// The suffix check is what stops this table shadowing hostnames the
    /// node has no claim to.
    #[test]
    fn refuses_a_host_outside_the_configured_suffix() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(bound("alice")).unwrap();
        assert!(reg.resolve_host("alice.attacker.example").is_none());
        assert!(
            reg.resolve_host("alice.network.tenzro.com.evil.test")
                .is_none()
        );
    }

    #[test]
    fn refuses_multi_label_prefixes() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(bound("alice")).unwrap();
        // `bob.alice.<suffix>` must not resolve to alice's node.
        assert!(reg.resolve_host("bob.alice.network.tenzro.com").is_none());
    }

    /// A claim made in the wizard, before the node ever ran, has nothing to
    /// route to yet — it must 404 rather than resolve to a half-record.
    #[test]
    fn unbound_claim_does_not_resolve_as_a_host() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(unbound("alice")).unwrap();
        assert!(reg.resolve("alice").is_some(), "claim is held");
        assert!(
            reg.resolve_host("alice.network.tenzro.com").is_none(),
            "but it is not routable until bound"
        );
    }

    /// A node with no configured suffix must not answer for any public host.
    #[test]
    fn no_suffix_disables_host_resolution() {
        let reg = NodeAliasRegistry::new(None);
        reg.apply(bound("alice")).unwrap();
        assert!(reg.resolve("alice").is_some());
        assert!(reg.resolve_host("alice.network.tenzro.com").is_none());
    }

    #[test]
    fn release_removes_the_claim_and_its_machine_index() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(bound("alice")).unwrap();
        assert_eq!(
            reg.name_for_machine("did:tenzro:machine:alice").as_deref(),
            Some("alice")
        );
        reg.apply_release("alice").unwrap();
        assert!(reg.resolve("alice").is_none());
        assert!(reg.name_for_machine("did:tenzro:machine:alice").is_none());
    }

    /// Blocks are re-delivered during sync; applying the same record twice
    /// must not double-count or corrupt the indexes.
    #[test]
    fn apply_is_idempotent() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(bound("alice")).unwrap();
        reg.apply(bound("alice")).unwrap();
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let reg = NodeAliasRegistry::new(Some("network.tenzro.com".to_string()));
        reg.apply(bound("alice")).unwrap();
        assert!(reg.resolve_host("ALICE.Network.Tenzro.Com").is_some());
    }
}
