# tenzro-identity

Unified identity protocol for humans and machines on the Tenzro Network.

## Overview

**tenzro-identity** implements the **Tenzro Decentralized Identity Protocol (TDIP)**, providing an identity system in which humans and AI agents are represented by the same identity type and hold the same rights to act. The crate supports W3C DID Documents, certifications and KYC as signed credentials kept in the trust ledger (`tenzro-trust`, see `docs/TRUST.md`), fine-grained delegation scopes, cascading revocation, and automatic hardware-rooted wallet provisioning for every identity.

The protocol recognizes **three identity classes** under the `did:tenzro:` namespace:

- **Human** — `did:tenzro:human:{uuid}`, controls zero or more delegated agents
- **Delegated agent** — `did:tenzro:machine:{controller}:{uuid}`, machine under a human controller; its authority is only its consensus Terms
- **Autonomous agent** — `did:tenzro:machine:{uuid}`, self-sovereign machine, no controller

## Key Types

- **TenzroIdentity** — Unified identity type for both human and machine identities with JSON serialization (`to_bytes()`/`from_bytes()`)
- **TenzroDid** — DID parser/formatter supporting all three identity classes: `did:tenzro:human:{uuid}`, `did:tenzro:machine:{controller}:{uuid}` (delegated), `did:tenzro:machine:{uuid}` (autonomous). Constructors derive each DID from its key: `from_passkey()` (human), `delegated_machine(controller_id, device_public_key)` and `delegated_agent(controller_id, agent_name)` (delegated), `from_device_key()` (autonomous machine)
- **IdentityData** — Enum distinguishing Human (display_name, controlled_machines) from Machine (capabilities, controller_did, reputation, tenzro_agent_id). The two machine sub-classes (delegated vs autonomous) are distinguished by `controller_did: Option<String>` — `Some(human_did)` = delegated, `None` = autonomous.
- **IdentityRegistry** — Thread-safe central store using DashMap with cascading revocation mirrored from consensus, and RocksDB write-through persistence via `KvStore`
- **DelegationScope** — the resources and operation bounds of an owner-signed machine-access grant (max_transaction_value, allowed_operations, time_bound, machine resources). Agent authority is not a registry field: it is the agent's consensus Terms
- **DelegationEntry** — Delegation record with grantor, grantee, scope, and revocation status
- **DidDocument** — W3C DID Document export/import for interoperability via `identity_to_did_document()` and `extract_public_keys_from_document()`
- **WalletBinder** — Automatic hardware-rooted wallet provisioning for every identity
- **KycTier** — Verification levels: Unverified (0), Basic (1), Enhanced (2), Full (3) — derived for each relying party from the KYC certifications it recognizes; no identity carries a tier of its own

## Features

- **14 modules:** delegation, did, document, envelope, erc8004, error, identity, ivms101, keri, kya, pq_rotation, registry, w3c, wallet_binding
- **W3C Standards:** Full DID Core 1.0 and Verifiable Credentials Data Model v2.0 support
- **Unified Protocol:** Single `TenzroIdentity` type covering all three identity classes (human / delegated agent / autonomous agent)
- **Delegation Enforcement:** Fine-grained permission scopes with `enforce_operation()` returning typed `DelegationViolation` errors
- **Cascading Revocation:** Revocations are decided in consensus; `revoke_from_chain()` mirrors each one and revokes the controlled machines the registry records
- **Right to Erasure (GDPR Article 17):** Two-phase flow — `revoke_identity` propagates the status change, then `forget_identity` hard-deletes from `CF_IDENTITIES` and the in-memory registry. The DID must already be in `Revoked` status. Surfaced as `tenzro_forgetIdentity` RPC, MCP `forget_identity` tool, and CLI `tenzro identity forget <did>`.
- **KYC from credentials:** a KYC tier is what a relying party concludes from the certifications issued by the issuers it recognizes; any issuer can certify, and none is privileged
- **Auto-Provisioned Wallets:** Every identity gets a hardware-rooted wallet via `WalletBinder`
- **Write-Through Persistence:** RocksDB storage via `KvStore` trait with `CF_IDENTITIES` column family
- **ERC-8004 Trustless Agents Registry (EVM):** The `erc8004` adapter module drives the ERC-8004 (Jan 2026 revision) semantic on the EVM from one TDIP `register_machine_with_fee` write. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the allocation (sequential `uint256`, 1-indexed, server-allocated). Reverse DID → id lookup via `OnChainAgentRegistry::lookup_agent_id_by_did`.
  - `erc8004` — **EVM** adapter: calldata encoders for `register()` / `register(string)` / `register(string,(string,bytes)[])` / `getAgent` / `submitFeedback` / `validationRequest` / `validationResponse` (full Jan 2026 revision surface) plus ABI decoders. Selectors are byte-identical to the registry contracts in Tenzro's genesis, so the same calldata works against Tenzro's registries or an Ethereum deployment. Canonical OpenZeppelin-ERC721 upgradeable proxies deployed at genesis at `addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`.
- **Tests:** Unit and integration tests covering all features

## Usage

```rust
use tenzro_identity::IdentityRegistry;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create registry
    let registry = Arc::new(IdentityRegistry::new());

    // Register a human identity rooted in a passkey
    let human = registry.register_human_via_binder(
        credential_id,         // WebAuthn credential id
        passkey_public_key,    // the passkey's public key; the DID derives from it
        "Alice".to_string(),
    ).await?.identity;

    println!("Human DID: {}", human.did_string());
    // Output: did:tenzro:human:550e8400-e29b-41d4-a716-446655440000

    // Register a machine identity under the human. What it may do is its
    // consensus Terms (DelegateAgent / UpdateAgentTerms), not a registry field.
    let machine = registry.register_machine_with_fee(
        &human.did_string(),
        vec![2; 32],           // Machine public key
        vec!["inference".to_string()],
    ).await?.identity;

    println!("Machine DID: {}", machine.did_string());
    // Output: did:tenzro:machine:550e8400...:7c9e6679...

    // Export W3C DID Document
    use tenzro_identity::w3c::identity_to_did_document;
    let doc = identity_to_did_document(&machine)?;
    println!("DID Document: {}", serde_json::to_string_pretty(&doc)?);

    Ok(())
}
```

## Dependencies

- **tenzro-types** — Core types and primitives (KycTier, PaymentProtocolId, IdentityType, Address)
- **tenzro-crypto** — Cryptographic operations (Ed25519, Secp256k1, signatures::verify)
- **tenzro-wallet** — hardware-rooted wallet provisioning
- **tenzro-storage** — KvStore trait for RocksDB write-through persistence

## Production Features

All features confirmed (85 passing tests):

1. **Delegation Enforcement**: `enforce_operation()` returns typed `DelegationViolation` specifying max_value, protocol, chain, or time_bound violations
2. **Local Resolution**: DIDs resolve from the node's own state; there is no upstream resolver
3. **KYC from credentials**: tiers are derived per relying party from the KYC certifications it recognizes
4. **Revocation from consensus**: `revoke_from_chain()` applies the `IdentityRevoked` log every node re-executed
5. **RocksDB Persistence**: Write-through to `CF_IDENTITIES` via `KvStore` trait, JSON serialization for identity records

## License

Apache-2.0.

## Machine anchors and ownership

`MachineAnchor` is what holds a machine identity to the world: a delegating
party (human or institution), or a hardware root of trust standing in their
place. There is no third option — a machine that answers only to itself is a
self-issued claim, indistinguishable from ten thousand minted by the same
script. A hardware anchor must name at least one **attestable** source; a
readable serial is not proof.

`OwnershipTransfer` moves administrative ownership, and the authority required
is whatever anchors the machine: a delegated machine moves on its controller's
authority, a hardware-rooted machine on proof of its root. The two are not
interchangeable, so holding the hardware cannot take a machine that has an
accountable party. Ownership replaces rather than accumulates, and
authorisations expire.

`IdentityRegistry::set_machine_controller` records the result — detaching the
machine from the old owner and attaching it to the new one in the same step, so
no window exists in which both or neither claims it.

Reachable as `tenzro_transferMachineOwnership` (admin-token gated, authorisation
TTL-bounded against replay) and `tenzro device transfer` on the CLI.

Full model: `docs/TDIP.md`.
