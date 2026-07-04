# tenzro-identity

Unified identity protocol for humans and machines on the Tenzro Network.

## Overview

**tenzro-identity** implements the **Tenzro Decentralized Identity Protocol (TDIP)**, providing a comprehensive identity system that treats humans and AI agents as first-class citizens. The crate supports W3C DID Documents, verifiable credentials with recursive trust chain verification, fine-grained delegation scopes, cascading revocation, and automatic FROST-Ed25519 threshold wallet provisioning for every identity.

The protocol recognises **three identity classes** under the `did:tenzro:` namespace:

- **Human** — `did:tenzro:human:{uuid}`, KYC-tiered, controls zero or more delegated agents
- **Delegated agent** — `did:tenzro:machine:{controller}:{uuid}`, machine under a human controller, scoped by `DelegationScope`
- **Autonomous agent** — `did:tenzro:machine:{uuid}`, self-sovereign machine, no controller

## Key Types

- **TenzroIdentity** — Unified identity type for both human and machine identities with JSON serialization (`to_bytes()`/`from_bytes()`)
- **TenzroDid** — DID parser/formatter supporting all three identity classes: `did:tenzro:human:{uuid}`, `did:tenzro:machine:{controller}:{uuid}` (delegated), `did:tenzro:machine:{uuid}` (autonomous). Three constructors: `new_human()`, `new_machine(controller_id)`, `new_autonomous_machine()`
- **IdentityData** — Enum distinguishing Human (display_name, KYC tier, controlled_machines) from Machine (capabilities, delegation_scope, controller_did, reputation, tenzro_agent_id, `is_seed_agent`). The two machine sub-classes (delegated vs autonomous) are distinguished by `controller_did: Option<String>` — `Some(human_did)` = delegated, `None` = autonomous.
- **`is_seed_agent`** — Immutable boolean on `IdentityData::Machine` set at registration, exposed via `TenzroIdentity::is_seed_agent()`. Drives the SeedAgent counterparty filter (`CounterpartyFilter::deny_other_seed_agents`) and lets organic-activity metrics exclude protocol-owned bootstrap traffic during the 12-month earmark window.
- **IdentityRegistry** — Thread-safe central store using DashMap with cascading revocation, pluggable `DidResolutionBackend` and `RevocationBroadcaster`, username registry, and RocksDB write-through persistence via `KvStore`
- **IdentityVerifier** — Trust chain verifier with recursive `verify_credential_chain()`, cycle detection, configurable depth bound (default 10), and trust-root anchoring
- **VerifiableCredential** — W3C VC-compatible credential issuance, inheritance via `inherit_credential()`, and cryptographic proof verification
- **CredentialProof** — Ed25519/Secp256k1 signature proofs with `verify()` method using `tenzro_crypto::signatures::verify()`
- **DelegationScope** — Fine-grained permissions: max_transaction_value, max_daily_spend, allowed_operations, allowed_contracts, time_bound, allowed_payment_protocols, allowed_chains
- **DelegationEntry** — Delegation record with grantor, grantee, scope, and revocation status
- **DidDocument** — W3C DID Document export/import for interoperability via `identity_to_did_document()` and `extract_public_keys_from_document()`
- **WalletBinder** — Automatic FROST-Ed25519 wallet provisioning for every identity (2-of-3 threshold, RFC 9591)
- **KycTier** — Verification levels: Unverified (0), Basic (1), Enhanced (2), Full (3) — upgradable via `update_kyc_tier_with_credential()`

## Features

- **10 modules:** credential, delegation, did, document, error, identity, registry, verification, w3c, wallet_binding
- **W3C Standards:** Full DID Core 1.0 and Verifiable Credentials Data Model v2.0 support
- **Unified Protocol:** Single `TenzroIdentity` type covering all three identity classes (human / delegated agent / autonomous agent)
- **Delegation Enforcement:** Fine-grained permission scopes with `enforce_operation()` returning typed `DelegationViolation` errors
- **Credential Inheritance:** Machine agents inherit credentials from controllers via `inherit_credential()`
- **Recursive Trust Chain Verification:** `IdentityVerifier::verify_credential_chain()` with cycle detection, depth bound, and trust-root anchoring
- **Cascading Revocation:** Revoking a human identity automatically revokes all controlled machines via `apply_remote_revocation()`
- **Right to Erasure (GDPR Article 17):** Two-phase flow — `revoke_identity` propagates the status change, then `forget_identity` hard-deletes from `CF_IDENTITIES` and the in-memory registry. The DID must already be in `Revoked` status. Surfaced as `tenzro_forgetIdentity` RPC, MCP `forget_identity` tool, and CLI `tenzro identity forget <did>`.
- **Pluggable Backends:** `DidResolutionBackend` for RPC fallback, `RevocationBroadcaster` for cross-node propagation
- **Credential-Gated KYC:** `update_kyc_tier_with_credential()` requires valid KYC credential to upgrade tier
- **Username Registry:** Unique lowercase alphanumeric + underscore names (3-20 chars) with `register_username()` / `resolve_username()`
- **Auto-Provisioned Wallets:** Every identity gets a 2-of-3 FROST-Ed25519 threshold wallet (RFC 9591) via `WalletBinder`
- **Write-Through Persistence:** RocksDB storage via `KvStore` trait with `CF_IDENTITIES` column family
- **ERC-8004 Trustless Agents Registry (cross-VM trio):** Three adapter modules drive a single ERC-8004 v0.6+ semantic across all three VMs from one TDIP `register_machine_with_fee` write. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the EVM allocation (sequential `uint256`, 1-indexed, server-allocated); SVM and DAML use their own per-backend id shapes (32-byte Pubkey, 8-byte LE u64). Reverse DID → id lookup via `OnChainAgentRegistry::lookup_agent_id_by_did` (EVM) / `OnChainAgentSvmRegistry::lookup_agent_id_by_did` (SVM) / `OnChainAgentDamlRegistry::lookup_agent_id_by_did` (DAML).
  - `erc8004` — **EVM** adapter: calldata encoders for `register()` / `register(string)` / `register(string,(string,bytes)[])` / `getAgent` / `submitFeedback` / `validationRequest` / `validationResponse` (full v0.6+ surface) plus ABI decoders. Selectors are byte-identical to the Tenzro VM precompiles `0x101a` / `0x101b` / `0x101c`, so the same calldata works against either the native registry or an Ethereum mirror. Canonical OpenZeppelin-ERC721 upgradeable proxies deployed at genesis at `addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`.
  - `erc8004_svm` — **SVM** adapter: emits Anchor-formatted instruction calldata via the `OnChainAgentSvmRegistry` trait, targeting the vendored QuantuLabs Anchor program (`https://github.com/QuantuLabs/erc-8004-svm`). No `solana-sdk` dep is pulled into this crate by design — the operator-side mirror buffers payloads and drains to a Solana RPC.
  - `erc8004_daml` — **DAML** adapter: emits Canton Ledger JSON API v2 `submit-and-wait` commands as `serde_json::Value` via the `OnChainAgentDamlRegistry` trait, targeting the Tenzro-authored Canton package at `vendor/erc8004-daml/daml/Tenzro/Erc8004/{Identity,Reputation,Validation}.daml`. No `tonic` or Canton-client deps in this crate by design. Two-party admin+controller signatory model preserves "single canonical state" without a `msg.sender` equivalent. Package id (= SHA-256 of compiled `.dar`) is supplied at registry construction via `DamlPackageIds`.
- **85 Tests:** Comprehensive unit and integration tests covering all features

## Usage

```rust
use tenzro_identity::{IdentityRegistry, DelegationScope, IdentityVerifier};
use tenzro_types::identity::KycTier;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create registry
    let registry = Arc::new(IdentityRegistry::new());

    // Register human identity with KYC tier
    let human = registry.register_human_with_fee(
        vec![1; 32],           // Ed25519 public key
        "Alice".to_string(),
        KycTier::Enhanced,
    ).await?.identity;

    println!("Human DID: {}", human.did_string());
    // Output: did:tenzro:human:550e8400-e29b-41d4-a716-446655440000

    // Register machine identity with delegation scope
    let scope = DelegationScope::unrestricted()
        .with_max_transaction_value(10_000)
        .with_allowed_operations(vec!["inference".to_string()])
        .with_allowed_payment_protocols(vec!["mpp".to_string()]);

    let machine = registry.register_machine_with_fee(
        &human.did_string(),
        vec![2; 32],           // Machine public key
        vec!["inference".to_string()],
        scope,
    ).await?.identity;

    println!("Machine DID: {}", machine.did_string());
    // Output: did:tenzro:machine:550e8400...:7c9e6679...

    // Verify trust chain with recursive credential verification
    let verifier = IdentityVerifier::new(registry.clone())
        .with_trust_root("did:tenzro:human:root-ca")
        .with_max_chain_depth(10);

    let result = verifier.verify_trust_chain(&machine.did_string())?;
    println!("Trust chain valid: {}", result.valid);
    println!("Verified chains: {}", result.verified_chains);

    // Enforce delegation scope on operation
    let violation = registry.enforce_operation(
        &machine.did_string(),
        "governance",   // Not in allowed_operations
        None,
    );
    assert!(violation.is_err());

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
- **tenzro-wallet** — FROST-Ed25519 threshold wallet provisioning (2-of-3, RFC 9591, Argon2id keystore)
- **tenzro-storage** — KvStore trait for RocksDB write-through persistence

## Production Features

All features confirmed (85 passing tests):

1. **Delegation Enforcement**: `enforce_operation()` returns typed `DelegationViolation` specifying max_value, protocol, chain, or time_bound violations
2. **Pluggable Resolution**: `DidResolutionBackend` trait for blockchain/RPC fallback when DIDs not found locally
3. **Credential-Gated KYC**: `update_kyc_tier_with_credential()` requires valid KYC credential to upgrade tier
4. **Pluggable Revocation Broadcasting**: `RevocationBroadcaster` trait for cross-node cascading revocation + inbound `apply_remote_revocation()`
5. **Recursive Trust Chain Verification**: `IdentityVerifier::verify_credential_chain()` with cycle detection (HashSet), depth bound (default 10), trust-root anchoring
6. **RocksDB Persistence**: Write-through to `CF_IDENTITIES` via `KvStore` trait, JSON serialization for identity records
7. **Username Registry**: Unique lowercase alphanumeric + underscore names (3-20 chars), bidirectional DID↔username mapping

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
