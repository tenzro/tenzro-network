//! AgentBond constants and addresses.
//!
//! Each autonomous agent identity (`did:tenzro:machine:...`) may have a
//! bond posted by its controller on its behalf, held in a deterministic,
//! key-less vault address derived per agent. The bond lives in consensus
//! state: `PostAgentBond`, `IncreaseAgentBond` and `WithdrawAgentBond`
//! move it, and every slash goes through `tenzro_vm::native::slash_agent_bond`
//! into the InsurancePool vault. Readers use `tenzro_vm::native::agent_bond`
//! and `agent_bonds_of_controller`.

use sha2::{Digest, Sha256};
use tenzro_types::primitives::Address;

/// Domain prefix for the deterministic per-agent bond vault address.
const BOND_VAULT_DOMAIN: &[u8] = b"tenzro/agent-bond/vault";
/// Domain prefix for the deterministic InsurancePool vault address.
const INSURANCE_VAULT_DOMAIN: &[u8] = b"tenzro/insurance-pool/vault";

/// The deterministic 32-byte vault address for an agent's bond. The vault
/// has no private key; only VM execution moves its balance.
pub fn derive_bond_vault_address(agent_did: &str) -> Address {
    let digest = Sha256::new()
        .chain_update(BOND_VAULT_DOMAIN)
        .chain_update(agent_did.as_bytes())
        .finalize();
    Address::new(digest.into())
}

/// The deterministic InsurancePool vault address (singleton).
pub fn derive_insurance_pool_address() -> Address {
    let digest = Sha256::new()
        .chain_update(INSURANCE_VAULT_DOMAIN)
        .finalize();
    Address::new(digest.into())
}
