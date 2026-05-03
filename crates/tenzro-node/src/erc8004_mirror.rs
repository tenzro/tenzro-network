//! ERC-8004 mirror adapter — bridges TDIP machine registrations into the
//! native on-chain `Erc8004IdentityRegistry` precompile state.
//!
//! When [`tenzro_identity::IdentityRegistry`] registers a machine identity,
//! it calls this adapter (via the `OnChainAgentRegistry` trait) which writes
//! a corresponding `AgentRecord` into the in-process precompile registry.
//! Subsequent EVM contracts reading from the ERC-8004 IdentityRegistry
//! precompile (`0x101a`) see the agent immediately — no extra transaction
//! required.
//!
//! The mirror is best-effort: errors are returned as `Err` so the identity
//! crate logs them, but the TDIP registration itself never fails because
//! of mirror issues.

use std::sync::Arc;

use tenzro_identity::erc8004::{EthAddress, OnChainAgentRegistry};
use tenzro_identity::error::Result as IdentityResult;
use tenzro_vm::{Erc8004AgentRecord, Erc8004IdentityRegistry};

/// Native adapter: when called by the TDIP `IdentityRegistry`, writes an
/// `AgentRecord` straight into the in-process `Erc8004IdentityRegistry`
/// (the precompile-backed state at `0x101a`).
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
        agent_id: &[u8; 32],
        agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> IdentityResult<()> {
        let record = Erc8004AgentRecord {
            agent_id: *agent_id,
            agent_address: *agent_address,
            metadata_uri: metadata_uri.to_string(),
        };
        self.identity.register(record);
        Ok(())
    }
}
