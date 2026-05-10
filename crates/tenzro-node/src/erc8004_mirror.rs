//! ERC-8004 mirror adapter — bridges TDIP machine registrations into the
//! native on-chain `Erc8004IdentityRegistry` precompile state.
//!
//! When [`tenzro_identity::IdentityRegistry`] registers a machine identity,
//! it calls this adapter (via the [`OnChainAgentRegistry`] trait) which
//! allocates a fresh sequential `uint256 agentId` in the in-process
//! precompile registry and records the reverse `did → agentId` mapping.
//! Subsequent EVM contracts reading from the ERC-8004 IdentityRegistry
//! precompile (`0x101a`) see the agent immediately — no extra transaction
//! required. Callers that need to resolve a TDIP DID back to its allocated
//! id can do so via [`OnChainAgentRegistry::lookup_agent_id_by_did`].
//!
//! The mirror is best-effort: errors are returned as `Err` so the identity
//! crate logs them, but the TDIP registration itself never fails because
//! of mirror issues.

use std::sync::Arc;

use tenzro_identity::erc8004::{EthAddress, OnChainAgentRegistry};
use tenzro_identity::error::Result as IdentityResult;
use tenzro_vm::Erc8004IdentityRegistry;

/// Native adapter: when called by the TDIP `IdentityRegistry`, allocates a
/// fresh sequential `agentId` in the in-process `Erc8004IdentityRegistry`
/// (the precompile-backed state at `0x101a`) and stores the `did → id`
/// mapping for later lookup.
pub struct NativeErc8004Mirror {
    identity: Arc<Erc8004IdentityRegistry>,
}

impl NativeErc8004Mirror {
    /// Wrap an existing precompile-backed identity registry.
    pub fn new(identity: Arc<Erc8004IdentityRegistry>) -> Self {
        Self { identity }
    }
}

impl OnChainAgentRegistry for NativeErc8004Mirror {
    fn mirror_register_agent(
        &self,
        did: &str,
        agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> IdentityResult<u64> {
        // `register_with_did` is idempotent on the DID: a second call with
        // the same DID returns the previously allocated id and updates the
        // wallet/URI fields in place. That matches the TDIP semantics
        // where a re-registration of the same machine refreshes its
        // controller binding without minting a new ERC-8004 agentId.
        let agent_id =
            self.identity
                .register_with_did(did.to_string(), *agent_address, metadata_uri.to_string());
        Ok(agent_id)
    }

    fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64> {
        self.identity.lookup_by_did(did)
    }
}
