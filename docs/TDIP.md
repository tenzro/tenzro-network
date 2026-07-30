# TDIP: Tenzro Decentralized Identity Protocol

**Standard ID:** TDIP-1
**Version:** 1.0.0
**Status:** Draft
**Authors:** Tenzro Network Contributors
**Created:** March 19, 2026
**Last Updated:** March 19, 2026
**Platform:** Tenzro Network (HotStuff-2 BFT, hybrid post-quantum signatures)

---

## Abstract

The Tenzro Decentralized Identity Protocol (TDIP) is the native identity standard for the Tenzro Network, providing a unified, W3C-compatible decentralized identity system for humans, machines, and autonomous AI agents. TDIP defines how identities are created, managed, delegated, verified, and revoked on the Tenzro Ledger.

TDIP is designed for the AI age — where autonomous agents act on behalf of humans, conduct financial transactions, access intelligence services, and interact with other agents. Every identity on Tenzro is a TDIP identity. The protocol recognises **three identity classes** — humans, delegated agents (machines under a human controller), and autonomous agents (self-sovereign machines) — under fine-grained delegation scopes, verifiable credentials with inheritance, cascading revocation, and auto-provisioned MPC wallets.

---

## 1. Design Principles

### 1.1 AI-Native
TDIP registers machines and AI agents on the same terms as humans. Machine identities have capabilities, delegation scopes, reputation scores, and can inherit credentials from their human controllers. Autonomous machines can operate without a human controller.

### 1.2 Single-Step Onboarding
Every TDIP identity is auto-provisioned with an MPC threshold wallet (default 2-of-3). No seed phrases, no manual key management. Users and agents get an identity + wallet in a single step.

### 1.3 W3C Compatible
TDIP identities are fully compatible with the W3C Decentralized Identifiers (DID) Core specification and the W3C Verifiable Credentials Data Model. Any TDIP identity can be exported as a standard DID Document and consumed by any W3C DID-compatible system.

### 1.4 Hierarchical Trust
TDIP uses a two-level identity hierarchy: humans control machines. Humans can issue credentials, delegate permissions, and revoke access. Machines inherit trust from their controllers but operate within scoped boundaries.

### 1.5 Privacy by Design
TDIP identities contain no PII on-chain. Identity data is limited to cryptographic keys, capability declarations, and credential proofs. Selective disclosure is supported through verifiable credential presentation.

---

## 2. DID Scheme

### 2.1 Format

TDIP uses the `did:tenzro:` DID method:

```
did:tenzro:human:{uuid}                     — Human identity
did:tenzro:machine:{controller-uuid}:{uuid} — Controlled machine identity
did:tenzro:machine:{uuid}                   — Autonomous machine identity
```

**Examples:**
```
did:tenzro:human:550e8400-e29b-41d4-a716-446655440000
did:tenzro:machine:550e8400-e29b-41d4-a716-446655440000:7c9e6679-7425-40de-944b-e07fc1f90ae7
did:tenzro:machine:8f14e45f-ceea-367f-a27f-c63e5f0e3e12
```

### 2.2 DID Resolution

TDIP DIDs resolve to DID Documents via the Tenzro Ledger's identity registry. Resolution can be performed:
- On-chain: via `IdentityRegistry.resolve(did)`
- Via RPC: `tenzro_resolveIdentity` and `tenzro_resolveDidDocument`
- Via SDK: `client.identity.resolve(did)`

A DID not held in the node's local registry can fall through to an upstream resolver. The upstream is configured with the `did_fallback_rpc` node configuration field (unset by default — resolution stays local-only). When set, the node forwards the resolution to the upstream with `{ "did": "<did>", "include_record": true }`; an upstream that supports `include_record` returns the identity record alongside the DID Document, which the node re-includes in its own response. An upstream that predates the field errors so the caller knows to reach a newer node. A DID that resolves neither locally nor upstream returns JSON-RPC error `-32404`.

---

## 3. Identity Types

### 3.1 Human Identities

Human identities represent real users on the Tenzro Network. They are the root of trust in TDIP's hierarchical model.

| Property | Description |
|----------|-------------|
| DID | `did:tenzro:human:{uuid}` |
| KYC Tier | Unverified / Basic / Enhanced / Full |
| Wallet | Auto-provisioned MPC wallet (2-of-3 threshold) |
| Capabilities | Issue credentials, control machines, vote in governance |
| Controlled Machines | Zero or more machine identities |

**KYC Tiers:**

| Tier | Level | Verification |
|------|-------|-------------|
| Unverified | 0 | None — identity exists but is not verified |
| Basic | 1 | Email verification |
| Enhanced | 2 | Government ID document + liveness check |
| Full | 3 | Biometric verification + institutional attestation |

KYC tiers are ordered and comparable. Operations can require a minimum tier (e.g., `tier >= Enhanced` for trading).

### 3.2 Machine Identities (Controlled)

Controlled machine identities are AI agents, bots, or automated systems that operate under a human controller's authority.

| Property | Description |
|----------|-------------|
| DID | `did:tenzro:machine:{controller-uuid}:{uuid}` |
| Controller | Human identity that owns and controls this machine |
| Capabilities | Declared skill set (e.g., `inference`, `trading`, `monitoring`) |
| Delegation Scope | Fine-grained permissions granted by the controller |
| Reputation | Activity-based score (0–1000) |
| Credential Inheritance | Can inherit valid credentials from controller |
| Tenzro Agent Link | Optional link to native Tenzro agent system |

### 3.3 Machine Identities (Autonomous)

Autonomous machines operate without a human controller. They are self-sovereign entities.

| Property | Description |
|----------|-------------|
| DID | `did:tenzro:machine:{uuid}` |
| Controller | None |
| Capabilities | Declared skill set |
| Delegation Scope | Unrestricted (self-governed) |
| Reputation | Activity-based score (0–1000) |
| Credential Inheritance | Not available (no controller) |

---

## 4. Identity Registration

### 4.1 Registration Flow

```
┌─────────────────────┐
│  Registration        │
│  Request             │
│  (pubkey, name,      │
│   type, capabilities)│
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  MPC Wallet          │
│  Auto-Provisioning   │
│  (2-of-3 threshold)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Identity Registry   │
│  On-Chain Storage    │
│  (CF_IDENTITIES)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  TenzroIdentity      │
│  ────────────────    │
│  did, wallet_address,│
│  status: Active,     │
│  credentials: []     │
└─────────────────────┘
```

### 4.2 Registration Fees

All registrations require TNZO fees, paid as part of the transaction gas:

| Registration Type | Fee (TNZO) |
|-------------------|-----------|
| Human Identity | 10 |
| Machine Identity | 5 |
| Autonomous Machine | 5 |
| Credential Issuance | 2 |
| Identity Verification | 1 |

Fees flow to validators who secure the network.

### 4.3 Registration Result

```rust
pub struct RegistrationResult {
    pub identity: TenzroIdentity,
    pub fee_required: u128,
}
```

---

## 5. Identity Structure

### 5.1 TenzroIdentity

The canonical identity record stored on-chain:

```rust
pub struct TenzroIdentity {
    pub did: TenzroDid,
    pub public_keys: Vec<PublicKeyInfo>,
    pub identity_data: IdentityData,
    pub status: IdentityStatus,
    pub wallet_address: Address,
    pub wallet_id: String,
    pub credentials: Vec<VerifiableCredential>,
    pub services: Vec<ServiceEndpoint>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}
```

### 5.2 Identity Status

```rust
pub enum IdentityStatus {
    Active,     // Fully operational
    Suspended,  // Temporarily disabled (reversible)
    Revoked,    // Permanently disabled (cascades to controlled machines)
}
```

### 5.3 Identity Data

```rust
pub enum IdentityData {
    Human {
        display_name: String,
        kyc_tier: KycTier,
        controlled_machines: Vec<String>,
    },
    Machine {
        capabilities: Vec<String>,
        delegation_scope: DelegationScope,
        controller_did: Option<String>,
        reputation: u32,
        tenzro_agent_id: Option<String>,
        is_seed_agent: bool,
    },
}
```

The `is_seed_agent` flag is **immutable** — set at registration and exposed via `TenzroIdentity::is_seed_agent()`. It drives the SeedAgent counterparty filter (`CounterpartyFilter::deny_other_seed_agents`) so organic-activity metrics can exclude protocol-owned bootstrap traffic during the 12-month treasury earmark window.

---

## 6. Delegation Scopes

### 6.1 Overview

Delegation scopes define the boundaries within which a machine identity may operate. They are granted by the controlling human identity and enforced by the network.

### 6.2 Scope Definition

```rust
pub struct DelegationScope {
    pub max_transaction_value: Option<u128>,
    pub max_daily_spend: Option<u128>,
    pub allowed_operations: Vec<String>,
    pub allowed_contracts: Vec<Vec<u8>>,
    pub time_bound: Option<TimeBound>,
    pub allowed_payment_protocols: Vec<String>,
    pub allowed_chains: Vec<String>,
}
```

**Convention:** Empty lists mean "unrestricted" (all allowed). This is the default for autonomous machines.

### 6.3 Scope Validation

Before executing any operation, the network validates:
1. `is_operation_allowed(operation)` — Is this operation in the allowed set?
2. `is_value_allowed(value)` — Does the value exceed `max_transaction_value` or `max_daily_spend`?
3. `is_protocol_allowed(protocol)` — Is this payment protocol permitted?
4. `is_chain_allowed(chain)` — Is this target chain permitted?
5. `is_active()` — Is the delegation within its time bounds?

### 6.4 Delegation Entry

```rust
pub struct DelegationEntry {
    pub delegation_id: String,
    pub grantor_did: String,
    pub grantee_did: String,
    pub scope: DelegationScope,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}
```

### 6.5 Two-Axis Ceiling: Protocol Scope vs. Runtime Policy

The `DelegationScope` above is the **structural ceiling** — set at identity registration, immutable except via cascading revocation. Every payment, mandate, and operation is also bounded by a separate **runtime ceiling**: the `SpendingPolicy`, registered per-machine-DID on `AgentRuntime` and tracking rolling daily-spend windows.

```rust
pub struct SpendingPolicy {
    pub max_per_transaction: u64,
    pub max_daily_spend: u64,
    pub current_daily_spend: u64,
    pub enabled: bool,
}
```

Both ceilings must pass for the operation to settle:

1. **Protocol-level** via `IdentityRegistry::enforce_operation` — checks `max_transaction_value`, `allowed_operations`, `allowed_payment_protocols`, `allowed_chains`, `time_bound`.
2. **Runtime-level** via `SpendingPolicySnapshot::check` — checks `max_per_transaction` and rolling-window `max_daily_spend`.

The `SpendingPolicyResolver` trait is wired into `IdentityPaymentBinder::with_spending_policy_resolver()` at node startup. The `tenzro-agent-kit` spawner default-populates the runtime registry from `DelegationSpec` at machine spawn time (u128→u64 saturation at the boundary). Absent a resolver entry, the binder falls back to DelegationScope-only.

### 6.6 AP2 Mandate Validation

For AP2-mediated agent commerce, `MandateValidator::validate_with_delegation_policy_escrow_and_spt` enforces the nested ceilings on the PaymentMandate in one pass:

1. AP2 v0.2 CheckoutMandate constraints (item set, max_amount, merchant / category / chain allow-lists).
2. TDIP DelegationScope (`enforce_operation`).
3. Runtime SpendingPolicy (`SpendingPolicySnapshot::check`).
4. On-chain escrow balance, when the mandate pair carries an `escrow_id`.
5. Stripe SPT `usage_limits`, when the mandate pair carries a `spt_grant_id`.

Ceilings 4 and 5 are skipped only when the mandate pair commits to no escrow and no SPT; an identifier that fails to resolve is a refusal, not a skip. This is wired into `tenzro_ap2ValidateMandatePair` and the `ap2-payments` A2A skill.

---

## 7. Verifiable Credentials

### 7.1 W3C VC Data Model

TDIP credentials follow the W3C Verifiable Credentials Data Model:

```rust
pub struct VerifiableCredential {
    pub context: Vec<String>,         // W3C JSON-LD contexts
    pub id: String,                   // Credential ID
    pub credential_type: Vec<String>, // Always includes "VerifiableCredential"
    pub tenzro_type: TenzroCredentialType,
    pub issuer: String,               // Issuer DID
    pub issuance_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub credential_subject: CredentialSubject,
    pub proof: Option<CredentialProof>,
}
```

### 7.2 Credential Types

| Type | Description | Typical Issuer |
|------|-------------|----------------|
| KycAttestation | KYC verification result | Identity provider |
| AgeVerification | Age threshold attestation | Identity provider |
| ResidencyProof | Jurisdiction residency | Government/institution |
| AccreditedInvestor | Accredited investor status | Financial institution |
| InstitutionalMember | Institutional membership | Organization |
| PaymentAuthorization | Payment authorization credential | Controller identity |
| ModelProvider | AI model provider attestation | Tenzro Network |
| TeeOperator | TEE operator attestation | Hardware attestation |
| Custom(String) | Application-specific credential | Any issuer |

### 7.3 Credential Proofs

```rust
pub struct CredentialProof {
    pub proof_type: String,           // "Ed25519Signature2020"
    pub created: DateTime<Utc>,
    pub verification_method: String,  // DID#key-id of issuer
    pub proof_purpose: String,        // "assertionMethod"
    pub proof_value: Vec<u8>,         // Ed25519 signature bytes
}
```

Proofs are verified using the issuer's public key from the identity registry.

### 7.4 Credential Inheritance

Machine identities can inherit valid credentials from their human controller via the `inherit_credential` method in `IdentityRegistry`:

```
Human (did:tenzro:human:abc)
  ├── KycAttestation (tier: Enhanced)
  └── AccreditedInvestor
        │
        ▼ inherit via inherit_credential()
Machine (did:tenzro:machine:abc:xyz)
  ├── KycAttestation (inherited from controller)
  └── AccreditedInvestor (inherited from controller)
```

**Rules:**
- Only controlled machines can inherit (autonomous machines cannot)
- Inheritance is verified via `IdentityVerifier::verify_trust_chain()` which checks controller credentials
- If the controller's credential expires or is revoked, the trust chain validation fails
- The inherited credential references the controller as the original issuer

---

## 8. Public Key Management

### 8.1 Key Information

```rust
pub struct PublicKeyInfo {
    pub key_id: String,
    pub key_type: String,           // "Ed25519", "Secp256k1"
    pub public_key: Vec<u8>,
    pub purposes: Vec<KeyPurpose>,
}
```

### 8.2 Key Purposes

| Purpose | W3C Relationship | Use Case |
|---------|------------------|----------|
| Authentication | `authentication` | Login, identity proof |
| AssertionMethod | `assertionMethod` | Signing credentials |
| KeyAgreement | `keyAgreement` | Encryption (X25519) |
| CapabilityInvocation | `capabilityInvocation` | Executing capabilities |
| CapabilityDelegation | `capabilityDelegation` | Delegating to machines |

### 8.3 Supported Algorithms

| Algorithm | Key Type | Use |
|-----------|----------|-----|
| Ed25519 | `Ed25519VerificationKey2020` | Signing, authentication |
| Secp256k1 | `EcdsaSecp256k1VerificationKey2019` | EVM compatibility |
| X25519 | `X25519KeyAgreementKey2020` | Key agreement |

---

## 9. DID Document

### 9.1 W3C DID Document Export

Every TDIP identity can be exported as a W3C DID Document:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://tenzro.com/ns/identity/v1"
  ],
  "id": "did:tenzro:human:550e8400-e29b-41d4-a716-446655440000",
  "verificationMethod": [
    {
      "id": "did:tenzro:human:550e8400...#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:tenzro:human:550e8400...",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL..."
    }
  ],
  "authentication": ["did:tenzro:human:550e8400...#key-1"],
  "assertionMethod": ["did:tenzro:human:550e8400...#key-1"],
  "service": [
    {
      "id": "did:tenzro:human:550e8400...#inference",
      "type": "InferenceEndpoint",
      "serviceEndpoint": "https://provider.example.com/inference"
    }
  ]
}
```

### 9.2 Machine DID Document

Machine DID Documents include a `controller` field referencing the human identity:

```json
{
  "id": "did:tenzro:machine:550e8400...:7c9e6679...",
  "controller": "did:tenzro:human:550e8400..."
}
```

---

## 10. Identity Lifecycle

### 10.1 State Machine

```
    ┌──────────┐
    │  Created  │
    └─────┬────┘
          │ register()
          ▼
    ┌──────────┐     suspend()     ┌───────────┐
    │  Active   │─────────────────▶│ Suspended  │
    │           │◀─────────────────│            │
    └─────┬────┘    reactivate()   └───────────┘
          │
          │ revoke()
          ▼
    ┌──────────┐
    │  Revoked  │  (permanent, cascades to controlled machines)
    └──────────┘
```

### 10.2 Cascading Revocation

When a human identity is revoked:
1. The human identity status is set to `Revoked`
2. All controlled machine identities are automatically revoked
3. All delegation entries for the human are marked as revoked
4. Revocation entries are created for audit

**Revocation does NOT cascade upward** — revoking a machine does not affect its controller.

### 10.3 Suspension

Suspension is temporary and reversible. Suspended identities:
- Cannot perform new operations
- Cannot sign transactions
- Retain all credentials and delegations (frozen)
- Can be reactivated by the controller or admin

---

## 11. Trust Chain Verification

### 11.1 Verification Flow

```
┌─────────────────┐
│  Verify Identity │
│  (DID)           │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Check Status    │────▶│  Active?          │
│  (Active?)       │     │  Not Revoked?     │
└────────┬────────┘     │  Not Suspended?   │
         │              └──────────────────┘
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Check Controller│────▶│  Controller exists?│
│  (if machine)    │     │  Controller active?│
└────────┬────────┘     └──────────────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Check Credentials────▶│  Valid?           │
│  (if required)   │     │  Not expired?     │
│                  │     │  Proof verified?  │
│  Recursive chain │     │  Trust root       │
│  traversal with  │     │  anchored?        │
│  cycle detection │     └──────────────────┘
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  TrustChainResult│
│  valid: true     │
│  verified_chains │
│  chain_results   │
│  issues: []      │
└─────────────────┘
```

### 11.2 Trust Chain Result

```rust
pub struct TrustChainResult {
    pub valid: bool,
    pub subject_did: String,
    pub controller_did: Option<String>,
    pub controller_kyc_tier: Option<KycTier>,
    pub valid_credentials: usize,
    pub verified_chains: usize,
    pub chain_results: Vec<CredentialChainResult>,
    pub issues: Vec<String>,
}

pub struct CredentialChainResult {
    pub valid: bool,
    pub credential_type: String,
    pub chain_length: usize,
    pub terminating_root: Option<String>,
    pub issues: Vec<String>,
}
```

**Recursive Trust Chain Traversal:**

The `IdentityVerifier::verify_credential_chain()` method walks credential issuer chains recursively from a leaf credential up to a configured trust root:

1. The issuer DID resolves to an `Active` identity in the registry
2. The credential's cryptographic proof verifies against one of the issuer's `AssertionMethod` public keys
3. The credential is not expired
4. The chain terminates at a registered trust root, OR the issuer itself holds a credential of the same type that can be recursively verified

Cycle detection is enforced via a `HashSet<String>` of visited issuer DIDs, and recursion is bounded by `max_chain_depth` (default 10) to prevent stack overflow/DoS from maliciously crafted issuer rings.

### 11.3 Trust Root Configuration

The `IdentityVerifier` supports configurable trust roots for credential chain anchoring:

```rust
let verifier = IdentityVerifier::new(registry)
    .with_trust_root("did:tenzro:human:root-ca-id")
    .with_max_chain_depth(10)
    .require_trust_root(true);
```

When trust roots are configured, credentials whose chains do not terminate at a registered root are marked invalid.

### 11.4 Operation Validation

For machine identities, the verifier checks:
1. Is the machine's identity active?
2. Is the controller's identity active?
3. Is the requested operation within the delegation scope?
4. Is the transaction value within limits?
5. Is the delegation within its time bounds?

The `IdentityRegistry::enforce_operation()` method returns a typed `DelegationViolation` error specifying the exact violation.

---

## 12. Wallet Integration

### 12.1 Auto-Provisioning

Every TDIP identity is automatically provisioned with an MPC threshold wallet:

| Property | Default |
|----------|---------|
| Threshold | 2-of-3 |
| Key Type | Ed25519 |
| Share Distribution | Device + Server + Recovery |
| KDF | Argon2id (64MB, 3 iterations) |

### 12.2 Wallet Binding

```rust
pub struct WalletBinding {
    pub wallet_id: String,
    pub address: Address,
}
```

The wallet address is stored in `TenzroIdentity.wallet_address` and is the on-chain address for all operations associated with the identity.

---

## 13. Service Endpoints

TDIP identities can declare service endpoints following the W3C DID specification:

```rust
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
}
```

**Standard Service Types:**

| Type | Description |
|------|-------------|
| `InferenceEndpoint` | AI model inference API |
| `MessagingEndpoint` | Agent-to-agent messaging |
| `SettlementEndpoint` | Payment settlement API |
| `DiscoveryEndpoint` | Agent discovery service |
| `StatusEndpoint` | Health/status monitoring |

---

## 14. Interoperability

### 14.1 ERC-8004 Compatibility

TDIP machine identities are addressable through ERC-8004 system contracts on Tenzro's EVM via three native precompiles, with calldata byte-identical to canonical Ethereum deployments:

| Precompile | Address | Function |
|------------|---------|----------|
| `ERC8004_IDENTITY` | `0x101a` | `registerAgent` / `getAgent` for native agent discovery |
| `ERC8004_REPUTATION` | `0x101b` | `submitFeedback` / `getFeedback` / `getFeedbackCount` for peer-to-peer reputation |
| `ERC8004_VALIDATION` | `0x101c` | `validationRequest` / `validationResponse` / `getValidation` for verifiable work attestation |

Selectors match `tenzro_identity::erc8004::selectors` byte-for-byte, so the same calldata works against either the native Tenzro registry or any Ethereum mirror. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side. The `IdentityData::Machine.erc8004_agent_id` field captures the allocation so the TDIP record carries the canonical id for cross-system lookup, and `OnChainAgentRegistry::lookup_agent_id_by_did` provides reverse DID → agentId resolution.

### 14.2 Cross-Chain Identity

TDIP identities can have registrations on multiple chains:

| Chain | Registration | Cost |
|-------|-------------|------|
| Tenzro (TDIP) | Always, native | TNZO fee |
| Tempo | Always, auto | Free |
| EVM (ERC-8004) | Opt-in | Gas fee |
| Solana (R8004) | Opt-in | SOL fee |
| Canton | Opt-in | Free |

---

## 15. Security Considerations

### 15.1 Key Security

- All secret keys use `ZeroizeOnDrop` to clear memory after use
- MPC wallet shares are encrypted with Argon2id-derived keys
- No single party ever holds the complete private key

### 15.2 Sybil Resistance

- Human identity registration requires TNZO fee (economic barrier)
- KYC tiers provide graduated trust levels
- Governance voting is weighted by staked TNZO balance

### 15.3 Delegation Security

- Delegation scopes enforce least-privilege access for machines
- Time-bounded delegations automatically expire
- Controllers can revoke delegations at any time

### 15.4 Credential Integrity

- All credentials carry Ed25519 cryptographic proofs
- Proof verification checks signature against issuer's registered public key
- Expired credentials automatically fail verification
- Revoked issuers' credentials become invalid

---

## 16. RPC Methods

| Method | Description |
|--------|-------------|
| `tenzro_registerIdentity` | Register a new TDIP identity (returns `RegistrationResult`) |
| `tenzro_registerMachineIdentity` | Register a machine identity under a controller DID |
| `tenzro_onboardDelegatedAgent` | Register a delegated agent together with its delegation scope |
| `tenzro_resolveIdentity` (alias `tenzro_resolveDid`) | Resolve a DID to TenzroIdentity |
| `tenzro_resolveDidDocument` | Resolve a DID to W3C DID Document |
| `tenzro_listIdentities` | List identities known to this node |
| `tenzro_updateIdentity` | Controller-signed identity update; dispatches on the `update.kind` field (`credential`, `service`) |
| `tenzro_revokeDid` (alias `tenzro_revokeIdentity`) | Revoke an identity (cascading via `apply_remote_revocation`) |
| `tenzro_forgetIdentity` | Right-to-erasure: drop the identity's off-chain record |
| `tenzro_addCredential` (alias `tenzro_issueCredential`) | Attach a verifiable credential to an identity |
| `tenzro_addService` | Attach a DID Document service endpoint |
| `tenzro_addIdentityClaim` | Attach a claim to an identity |
| `tenzro_setDelegationScope` | Set a machine's delegation scope (admin-token gated) |
| `tenzro_listMachines` | List machines under a controller |
| `tenzro_machineStatus` | Read a machine identity's current status |
| `tenzro_setUsername` (alias `tenzro_registerUsername`) | Bind a username to an identity (3-20 chars, lowercase alphanumeric + underscores) |
| `tenzro_resolveUsername` | Resolve a username to DID |
| `tenzro_exportIdentityCar` / `tenzro_importIdentityCar` | CARv1 portable identity bundle: DID + credentials + encrypted keystore |
| `tenzro_importIdentity` | Import an identity from an existing keypair |
| `tenzro_verifyDidEnvelope` | Verify a DID-signed envelope (also served at `POST /verify/did-envelope`) |

---

## 17. Implementation

### 17.1 Crate Structure

```
crates/tenzro-identity/src/
├── lib.rs              — Module declarations and re-exports
├── identity.rs         — TenzroIdentity, IdentityData, IdentityStatus
├── did.rs              — TenzroDid parsing and serialization
├── registry.rs         — IdentityRegistry (central store with DashMap)
├── credential.rs       — VerifiableCredential, CredentialProof
├── delegation.rs       — DelegationScope, DelegationEntry
├── verification.rs     — IdentityVerifier, TrustChainResult, recursive chain traversal
├── w3c.rs              — W3C DID Document conversion
├── document.rs         — DID Document types
├── wallet_binding.rs   — MPC wallet auto-provisioning
└── error.rs            — IdentityError types (DelegationViolation, TrustChainBroken, TrustChainCycle, TrustChainTooDeep)
```

### 17.2 Storage

TDIP identities are stored in RocksDB via the `KvStore` trait with write-through persistence:
- `CF_IDENTITIES` — TenzroIdentity records (JSON serialized via `to_bytes()`/`from_bytes()`)
- Identity keys: `identity:{did}` for DID→identity lookup
- Username keys: `username:{username}` for username→DID resolution

The `IdentityRegistry::with_storage()` builder wires the storage backend for durable persistence.

### 17.3 Pluggable Backends

The registry supports pluggable resolution and revocation:

```rust
pub trait DidResolutionBackend: Send + Sync {
    fn resolve_remote(&self, did: &str) -> Result<TenzroIdentity>;
}

pub trait RevocationBroadcaster: Send + Sync {
    fn broadcast_revocation(&self, entry: &RevocationEntry) -> Result<()>;
}
```

- **DidResolutionBackend**: Fallback resolver for DIDs not found locally (e.g., RPC query to another node)
- **RevocationBroadcaster**: Cross-node revocation propagation via `apply_remote_revocation()`

### 17.4 Production Features

- **Delegation enforcement**: `enforce_operation()` returns typed `DelegationViolation` specifying max_value, protocol, chain, or time_bound violations
- **Credential-gated KYC**: `update_kyc_tier_with_credential()` requires a valid KYC credential to upgrade tier
- **Trust chain verification**: Recursive `verify_credential_chain()` with cycle detection, depth bound (default 10), and trust-root anchoring
- **Cascading revocation**: `revoke()` propagates to all controlled machines; `apply_remote_revocation()` handles inbound revocation events
- **Username registry**: Unique lowercase alphanumeric + underscore names (3-20 chars) via `register_username()` / `resolve_username()`
- **Write-through persistence**: All mutations sync to RocksDB `CF_IDENTITIES` via `KvStore`

---

## 18. Test Vectors

### 18.1 DID Parsing

```
Input:  "did:tenzro:human:550e8400-e29b-41d4-a716-446655440000"
Type:   Human
ID:     "550e8400-e29b-41d4-a716-446655440000"

Input:  "did:tenzro:machine:abc:xyz"
Type:   Machine (Controlled)
Controller: "abc"
ID:     "xyz"

Input:  "did:tenzro:machine:solo123"
Type:   Machine (Autonomous)
ID:     "solo123"
```

### 18.2 Delegation Scope Validation

```
Scope: { allowed_operations: ["inference", "trading"], max_transaction_value: 1000 TNZO }

is_operation_allowed("inference")  → true
is_operation_allowed("governance") → false
is_value_allowed(500)              → true
is_value_allowed(1500)             → false
```

---

## Copyright

Copyright 2026 Tenzro Network Contributors. Licensed under MIT OR Apache-2.0.

This specification is open for adoption and implementation. Implementors may freely build TDIP-compliant systems.
