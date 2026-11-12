# TDIP: Tenzro Decentralized Identity Protocol

**Standard ID:** TDIP-1
**Version:** 1.0.0
**Status:** Draft
**Authors:** Tenzro Network Contributors
**Created:** March 19, 2026
**Last Updated:** March 19, 2026
**Platform:** Tenzro Network (DAG BFT with post-quantum checkpoint certificates, hybrid post-quantum signatures)

---

## Abstract

The Tenzro Decentralized Identity Protocol (TDIP) is the native identity standard for the Tenzro Network, providing a unified, W3C-compatible decentralized identity system for humans, machines, and autonomous AI agents. TDIP defines how identities are created, managed, delegated, verified, and revoked on the Tenzro Ledger.

TDIP is designed for the AI age — where autonomous agents act on behalf of humans, conduct financial transactions, access intelligence services, and interact with other agents. Every identity on Tenzro is a TDIP identity. The protocol recognizes **three identity classes** — humans, delegated agents (machines under a human controller), and autonomous agents (self-sovereign machines) — under fine-grained delegation scopes, verifiable credentials with inheritance, cascading revocation, and auto-provisioned wallets bound to the identity's own hardware key.

---

## 1. Design Principles

### 1.1 AI-Native
TDIP registers machines and AI agents on the same terms as humans. Machine identities have capabilities, delegation scopes, reputation scores, and can inherit credentials from their human controllers. Autonomous machines can operate without a human controller.

### 1.2 Single-Step Onboarding
Every TDIP identity is auto-provisioned with a wallet whose signing key is the identity's own hardware key: a passkey for a human, a TPM 2.0 or Secure Enclave key for a machine. No seed phrases, no key shares, no manual key management. Users and agents get an identity + wallet in a single step.

### 1.3 W3C Compatible
TDIP identities are fully compatible with the W3C Decentralized Identifiers (DID) Core specification and the W3C Verifiable Credentials Data Model. Any TDIP identity can be exported as a standard DID Document and consumed by any W3C DID-compatible system.

### 1.4 Hierarchical Trust
TDIP uses a two-level identity hierarchy: humans control machines. Humans delegate permissions and revoke access. Machines inherit trust from their controllers but operate within scoped boundaries.

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

Every node holds the identities consensus replicated, so it resolves any registered DID from its own state. A DID it does not hold is not registered, and resolution returns JSON-RPC error `-32404`; there is no upstream resolver to trust.

---

## 3. Identity Types

### 3.1 Human Identities

Human identities represent real users on the Tenzro Network. They are the root of trust in TDIP's hierarchical model.

| Property | Description |
|----------|-------------|
| DID | `did:tenzro:human:{uuid}` |
| Wallet | Auto-provisioned wallet bound to the human's passkey |
| Capabilities | Control machines, vote in governance |
| Controlled Machines | Zero or more machine identities |

**KYC Tiers:**

| Tier | Level | Credential |
|------|-------|-------------|
| Unverified | 0 | No recognized KYC certification |
| Basic | 1 | A `kyc` certification graded `basic` |
| Enhanced | 2 | A `kyc` certification graded `enhanced` |
| Full | 3 | A `kyc` certification graded `full` |

No identity carries a tier of its own, and the node derives none: a tier is whatever a relying party concludes from the KYC certifications it recognizes, off the node. Tiers are ordered and comparable, so an operation can require a minimum tier. See [TRUST.md](TRUST.md).

#### 3.1.1 Passkey accounts and multiple wallet providers

A human's wallet is a passkey account: the human's devices plus a keystore in consensus state that links the passkeys allowed to act for it, its policy, its recovery signers and any recovery in progress. The account address commits to the first passkey, the DID (`did:tenzro:human:{id}`, derived from that passkey) and a salt, so one identity can hold several wallets and an address never changes when devices change. Before the first change the keystore is the first passkey alone; every change after that is a `KeystoreUpdate` approved by the account's own passkeys (or, to recover, its recovery signers), and any node answers `tenzro_getKeystore` from the same committed record. See [security/wallet-custody.md](security/wallet-custody.md).

**Multiple wallet providers.** Each passkey in a keystore records the relying party it is registered on, the domain of the wallet that created it, and its assertions are checked against that relying party alone: its `rpIdHash` and an https origin on that domain or a subdomain of it. No related-origins list and no single domain is part of consensus, so any wallet provider (`tenzro.com` or a third party's own domain) can serve the same account once a passkey already on it approves linking the provider's passkey. `tenzro.com` is only where the network's own wallet creates first passkeys.

### 3.2 Machine Identities (Controlled)

Controlled machine identities are AI agents, bots, or automated systems that operate under a human controller's authority.

| Property | Description |
|----------|-------------|
| DID | `did:tenzro:machine:{controller-uuid}:{uuid}` |
| Controller | Human identity that owns and controls this machine |
| Capabilities | Declared skill set (e.g., `inference`, `trading`, `monitoring`) |
| Delegation Scope | Fine-grained permissions granted by the controller |
| Reputation | Activity-based score (0–1000) |
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
│  Wallet              │
│  Auto-Provisioning   │
│  (hardware-bound key)│
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
│  status: Active      │
└─────────────────────┘
```

### 4.2 Registration Fees

All registrations require TNZO fees, paid as part of the transaction gas:

| Registration Type | Fee (TNZO) |
|-------------------|-----------|
| Human Identity | 10 |
| Machine Identity | 5 |
| Autonomous Machine | 5 |

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
    pub pq_verifying_key: Vec<u8>,
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
        controlled_machines: Vec<String>,
    },
    Machine {
        capabilities: Vec<String>,
        controller_did: Option<String>,
        reputation: u32,
        tenzro_agent_id: Option<String>,
        erc8004_agent_id: Option<u64>,
    },
    Institution {
        legal_name: String,
        lei: String,
        vlei_credential_id: Option<String>,
        controlled_machines: Vec<String>,
        country_iso2: Option<String>,
    },
}
```

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

### 6.5 Agent Authority: Consensus Terms

A delegated agent's authority is its consensus Terms and nothing else: the scope, per-transaction and per-period limits, counterparties, chains, payment protocols and expiry its root (a human passkey or a machine TPM / Secure Enclave key) approved with `SetAgentTerms`. Every payment entry point (the payment gateway behind x402, MPP and the HTTP 402 gates, AP2 mandate pairs, ACP checkout, paid registry invocations, intent-routed inference, template agent steps) asks the same check over chain state, `check_agent_payment`: the agent must be live (not paused, quarantined or revoked), bonded as its Terms require, and within them. Spend is counted in consensus state by the agent's `AgentAct` transactions, so every node sees the same running totals. A DID with no Terms is not a delegated agent and pays under its own key; an agent DID with no Terms has no authority at all.

**Roots.** An agent has exactly one root, and its DID derives from it: `did:tenzro:machine:{root_id}:{id}`, with `root_id` the root's own identifier. A root is a human (`did:tenzro:human:{id}`, derived from a passkey) or an autonomous machine (`did:tenzro:machine:{id}`, derived from its TPM or Secure Enclave P-256 key and registered on chain with `RegisterIdentity`). A delegated machine or agent roots nothing. The Terms record on chain carries `root` (`passkey` or `machine`).

Every approval a root gives (creating, changing or revoking an agent's Terms, a step-up) is one custody challenge digest, `SHA-256("tenzro/custody-challenge/v2" || chain_id || len-prefixed account, operation, target || nonce)`, where `chain_id` is the network's chain id as 8 bytes big-endian (genesis records it in state, and the VM checks every approval against it, so an approval signed on one network is refused on every other), signed as a composite under the account-owner context, and validators check it with one function, `verify_root_approval`:

- For a human root, the key is any passkey a keystore of the root's identity links (any linked device, from any wallet provider, verified for the relying party the keystore records for it), unless that wallet requires two passkeys; before the identity has a keystore on chain, only the passkey its DID derives from. For a machine root it is the key its on-chain registration binds, and the registration must be live (a revoked machine identity approves nothing).
- A human root signs with a passkey (WebAuthn form, user verification required, challenge `base64url(SHA-256(M'))`); a machine root signs with its TPM or Secure Enclave (raw form, `r || s` over `SHA-256(M')`).
- The ML-DSA-65 key comes from chain state, never from the approval. The ML-DSA-65 leg is mandatory (an account with no key enrolled signs nothing until it enrols one), so the P-256 leg alone cannot pass.

A machine cannot approve Terms for another machine's agent: the approving key must be the one the controller DID derives from and is registered with. Pausing, quarantining, lifting and revoking an agent are transactions sent from the root's own account (the account the root's identity is registered with), so a machine root does them with its hardware-signed transactions.

On the node, `tenzro_createCustodyChallenge` (`delegate_agent`, `update_agent_terms`, `revoke_identity`) accepts either root and names the account the approval covers: a human's smart account, or for a machine root the account its hardware key names. A machine root then passes `authorization` = `{challenge_id, signature}`, the composite JSON its hardware produced over `challenge_hex` under the account-owner context (`tenzro agent delegation sign` in the CLI; `machine_root_authorization` and `machine_root_step_up` in the Rust SDK; `machineRootAuthorization` and `machineRootStepUp` in the TypeScript SDK). The node verifies it exactly as validators do before it submits the Terms. Which roots an application accepts is that application's policy, not a chain rule.

No node keeps a second authority store: there are no node-side spending policies, delegation-scope setters, mandate stores, or DID-to-wallet indexes beside the identity record. `tenzro_getAgentTerms` reads an agent's full Terms, its root kind (passkey or machine), its status, and its spend today and this hour against each limit from consensus.

### 6.6 AP2 Mandate Validation

For AP2-mediated agent commerce, `MandateValidator::validate_under_terms` holds the PaymentMandate to, in one pass:

1. AP2 v0.2 CheckoutMandate constraints (item set, max_amount, merchant / category / chain allow-lists).
2. The agent's consensus Terms.
3. On-chain escrow balance, when the mandate pair carries an `escrow_id`.
4. Stripe SPT `usage_limits`, when the mandate pair carries a `spt_grant_id`.

### 6.7 Delegated Agent Terms

A delegated agent's terms (`tenzro_onboardDelegatedAgent`, `tenzro_updateAgentTerms`) go on chain with its root's approval (section 6.5). Every action the agent takes (`tenzro_agentAct`) is checked by its serving node before the node signs it and again by the VM at execution, and the VM's verdict is final. The terms' `delegation_scope` holds:

| Field | Meaning |
|-------|---------|
| `max_transaction_value` | Most wei one action moves |
| `max_daily_spend` | Most wei moved in any 24 hours |
| `max_hourly_spend` | Most wei moved in any 60 minutes |
| `max_actions_per_hour`, `max_actions_per_day` | Most actions in any 60 minutes and in any 24 hours, value-moving or not |
| `allowed_hours_utc` | `[start, end)` UTC hours the agent may act in; a start after the end runs past midnight |
| `allowed_operations` | Operations the agent may perform; anything unlisted is refused |
| `allowed_chains`, `allowed_payment_protocols`, `allowed_models`, `allowed_counterparties` | Allow-lists; empty means any |
| `counterparty_kyc` | `{min_tier, registry}`: every counterparty the agent pays must hold a live `kyc` claim graded at least `min_tier` (1 basic, 2 enhanced, 3 full) under the `registry` token, from an issuer that token names |
| `asset_limits[].min_counterparty_kyc_tier` | The same floor for a payment in that asset, graded by the claims under the asset itself |
| `max_split_fee_bps` | The most the facilitator and relayer lines of a settlement plan the agent opens may take together, basis points of the value the rule divides; a plan whose rule can exceed it is refused at open |

The VM keeps the day's and the hour's spend and action counts in chain state, so every node sees the same running totals. It reads a counterparty's KYC tier from the claims in chain state at execution; a step-up does not lift a KYC floor.

**Step-up.** By default an action within the terms needs no further approval. Two optional fields hold particular actions for the controller's passkey:

| Field | Held action |
|-------|-------------|
| `step_up_above` | One moving more than this many wei |
| `step_up_new_counterparty` | The first payment to a counterparty the agent has not paid before |

`tenzro_agentAct` refuses a held action with error data `step_up`: the custody challenge for `agent_step_up` (`account`, `nonce`, `target` = the action digest, `chain_id`, `challenge_hex`, the digest a TPM or Secure Enclave signs under the account-owner context, and `webauthn_challenge`, what a passkey signs). The agent sends the same action again with `step_up` = `{account, nonce, root_public_key}` (hex) and `signature`, the root's composite signature. The VM checks it with `verify_root_approval` (section 6.5). An approval covers exactly one action, since the digest includes the action nonce, and it never lifts a hard limit.

**Typed actions only.** Everything a delegated agent asks a node to do is a typed proposal (an operation, and the model it names) that the scope check validates against the terms before anything runs:

- With the agent's access token: `tenzro_agentAct` (checked in full, then by the VM), a model call (`tenzro_chat`, `tenzro_textEmbed`, `tenzro_chatByIntent`: the `inference` operation), a tool or skill invocation, or a read (`get*`, `list*`, `estimate*`, `eth_call` and the like). Any other method is refused.
- With the agent's bearer token: the request must carry a typed intent, either `inference` or a free tool or skill invocation. A request without an intent, a paid invocation, a workflow or other resource class, and any value-moving intent are refused: an agent's value moves only through `tenzro_agentAct`.
- A tool or skill invocation is checked again once the node knows what it runs: `url_fetch` and remote tools are `fetch`, `web_search` is `web_search`, `file-manager` is `files`, `code-executor` and sandboxed bundles are `execute`, the model-backed skills are `inference`. The operation must be in `allowed_operations`.

A refusal is recorded in the agent's audit trail as a policy decision.

**Untrusted input.** When an operation that brings in outside content (`fetch`, `web_search`, `browse`, `inbound_messages`) runs for an agent, or the agent receives a message from a sender that is neither its controller nor in `allowed_counterparties`, the node labels the agent. For an hour after the last such input, every action the agent proposes through that node is marked `tainted`; the mark is part of the action digest the serving node signs, and the agent can set it itself but never clear it. The VM holds a tainted action for the controller's step-up when it moves more than `tainted_value_limit` (absent: any value) or pays a counterparty the agent has not paid before; without the step-up it is refused. `tenzro_getAgentQuarantine` reports the current label under `guardrails.tainted`. The label is kept in the node's metadata store (key prefix `agent_taint:`) as well as in memory, so a node that restarts inside the hour still holds it; a label past its hour is dropped at start. The label belongs to the serving node: another node serving the same agent does not see it, and it covers only input that passes through this node (the four operations above and inbound messages), not content an agent reads through its own MCP client.

**Private data, untrusted input and egress together.** An agent that can read private data, takes in content from outside its terms, and can send data off the network can be steered by injected content into leaking that data. Each operation and capability in the terms counts toward three exposures:

| Exposure | Operations |
|----------|------------|
| Private data | `files`, `database`, `memory`, `private_data`, and any machine-access grant (folder, device or machine-internal network) made out to the agent |
| Untrusted input | `fetch`, `web_search`, `browse`, `inbound_messages` |
| External egress | `fetch`, `web_search`, `browse`, `message`, `webhook` |

The VM refuses terms that hold all three, and the node refuses a machine-access grant that would complete them, and refuses the agent's requests while its terms and grants hold them, unless the controller's approved terms carry `trifecta_exception: true`. The exception is part of what the controller's passkey signs. `tenzro_getAgentQuarantine` reports the agent's `guardrails`: each exposure, those from grants, whether all three combine, and whether the exception is set.

---

## 7. Certifications and KYC

Certifications, ratings and KYC are not stored on the identity. They are W3C VC 2.0 credentials that any issuer (a regulator, an auditor, a KYC provider, a community) signs with its own hardware-derived DID and submits with `tenzro_submitTrustRecord`; revocation is a signed Bitstring Status List entry. The network privileges no issuer: each relying party (a user, an app, a router, a token's compliance rules) names the issuers it recognizes in its own trust list, and a credential from any other issuer counts for nothing to it. The credential model, the status lists and the trust lists are specified in [TRUST.md](TRUST.md).

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
| ML-DSA-65 (FIPS 204) | `MlDsa65VerificationKey2026` | Signing, authentication; preferred |
| Ed25519 | `Ed25519VerificationKey2020` | Signing, authentication |
| Secp256k1 | `EcdsaSecp256k1VerificationKey2019` | EVM compatibility |
| X25519 | `X25519KeyAgreementKey2020` | Key agreement |

---

## 9. DID Document

### 9.1 W3C DID Document Export

Every TDIP identity can be exported as a W3C DID Document. An identity that
holds an ML-DSA-65 key publishes it as a `MlDsa65VerificationKey2026` method
(`#pq-key-1`, `publicKeyMultibase` base58btc) and the document lists it ahead
of the classical methods, in `verificationMethod` and in the `authentication`
and `assertionMethod` relationships, so a verifier that takes the first method
it understands takes the post-quantum one. `DidDocument::
preferred_authentication_method` returns it.

KERI key event logs take ML-DSA-65 signing keys by default: a log made with
`KeyEventLog::new` refuses Ed25519 keys at inception and rotation, and
signatures on its events are ML-DSA-65 under the context
`tenzro/keri/event/ml-dsa-65`. `KeyEventLog::interoperating` also takes
Ed25519 keys, for logs that third-party KERI verifiers resolve. An example
document with a classical method follows:

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

The `service` list comes from consensus state, so every node returns the
same document for a DID. A change is an `IdentityServices` transaction that
publishes or removes one entry for the current version of the DID's list
(`tenzro_getDidServices`), approved by the DID's root: for a human, any
passkey its keystore links, as its policy allows; for an autonomous machine,
the hardware key its registration binds. Any account may send and pay for it.

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
          │ RevokeIdentity tx
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

## 11. Operation Validation

A delegated agent's operations are validated against its consensus Terms (section 6.5): the agent is live and bonded, the operation, chain, protocol, model and counterparty are within scope, and the amount is within the per-transaction and per-period limits. The VM runs the same check at execution (`AgentAct`), and refusals name the dimension exceeded ("outside the agent's approved terms: daily limit").

---

## 12. Wallet Integration

### 12.1 Auto-Provisioning

Every TDIP identity is automatically provisioned with a wallet bound to the identity's hardware key (`WalletBinder::provision_wallet`, `tenzro_wallet::WalletIdentity`):

| Property | Value |
|----------|-------|
| Signing key | P-256 key held in a passkey (human) or a TPM 2.0 / Secure Enclave (machine) |
| Post-quantum key | Hardware ML-DSA-65 verifying key; an identity whose hardware has none is not registered |
| Key shares | None: the key never leaves the device and the network holds no part of it |
| Recovery | Any linked passkey, or the account's recovery signers after a wait any passkey can cancel; never a stored share |

### 12.2 Wallet Binding

```rust
pub struct WalletBinding {
    pub wallet_id: String,
    pub address: Address,
    /// P-256 public key, x || y (64 bytes): the passkey or TPM / Secure Enclave key.
    pub public_key: Vec<u8>,
    /// Hardware ML-DSA-65 verifying key. `RegisterIdentity` is refused when it is empty.
    pub pq_verifying_key: Vec<u8>,
}
```

The wallet address is stored in `TenzroIdentity.wallet_address` and is the on-chain address for all operations associated with the identity.

---

## 13. Service Endpoints

TDIP identities can declare service endpoints following the W3C DID specification:

```rust
pub struct DidService {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
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

TDIP machine identities are addressable through the three canonical ERC-8004 registry contracts on Tenzro's EVM. They are part of genesis, at the addresses of the upstream reference deployment, so calldata is byte-identical to canonical Ethereum deployments:

| Contract | Address | Function |
|----------|---------|----------|
| `IdentityRegistry` | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | `registerAgent` / `getAgent` for native agent discovery |
| `ReputationRegistry` | `0x8004B663056A597Dffe9eCcC1965A193B7388713` | `submitFeedback` / `getFeedback` / `getFeedbackCount` for peer-to-peer reputation |
| `ValidationRegistry` | `0x8004Cb1BF31DAf7788923b405b754f57acEB4272` | `validationRequest` / `validationResponse` / `getValidation` for verifiable work attestation |

Selectors match `tenzro_identity::erc8004::selectors` byte-for-byte, so the same calldata works against either the native Tenzro registry or any Ethereum mirror. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side. The `IdentityData::Machine.erc8004_agent_id` field captures the allocation so the TDIP record carries the canonical id for cross-system lookup, and `OnChainAgentRegistry::lookup_agent_id_by_did` provides reverse DID → agentId resolution.

### 14.2 Cross-Chain Identity

TDIP identities can have registrations on multiple chains:

| Chain | Mechanism |
|-------|-----------|
| Tenzro (TDIP) | Native registration |
| EVM (ERC-8004) | The node mirrors machine registrations into the `IdentityRegistry` contract on Tenzro's EVM (`erc8004_mirror.rs`) |
| Solana | The Tenzro registrar program registers the agent in `agent_registry_8004` on behalf of a P-256 key (`erc8004_svm_registrar.rs`) |

-------|-------------|------|
| Tenzro (TDIP) | Always, native | TNZO fee |
| Tempo | Always, auto | Free |
| EVM (ERC-8004) | Opt-in | Gas fee |
| Solana (R8004) | Opt-in | SOL fee |

---

## 15. Security Considerations

### 15.1 Key Security

- All secret keys use `ZeroizeOnDrop` to clear memory after use
- Private keys exist only in a TPM 2.0, a Secure Enclave or a passkey authenticator; there are no threshold (MPC) wallets and no key shares
- Neither the node nor the network ever holds a wallet's private key

### 15.2 Sybil Resistance

- Human identity registration requires TNZO fee (economic barrier)
- KYC tiers provide graduated trust levels
- Governance voting is weighted by staked TNZO balance

### 15.3 Delegation Security

- Delegation scopes enforce least-privilege access for machines
- Time-bounded delegations automatically expire
- Controllers can revoke delegations at any time

### 15.4 Credential Integrity

- Every credential carries a Data Integrity proof by its issuer's hardware key or passkey, and the issuer's DID must derive from that key
- Expired credentials, credentials revoked in the issuer's status list, and credentials signed by a revoked issuer key count for nothing
- See [TRUST.md](TRUST.md)

---

## 16. RPC Methods

| Method | Description |
|--------|-------------|
| `tenzro_registerIdentity` | Register a new TDIP identity (returns `RegistrationResult`) |
| `tenzro_registerMachineIdentity` | Register a machine identity under a controller DID; the request carries the controller's DID envelope (`did_envelope`) over every field, as does `tenzro_registerIdentity` with `identity_type: "machine"` |
| `tenzro_onboardDelegatedAgent` | Register a delegated agent together with its delegation scope |
| `tenzro_resolveIdentity` | Resolve a DID to TenzroIdentity |
| `tenzro_resolveDidDocument` | Resolve a DID to W3C DID Document |
| `tenzro_listIdentities` | List identities known to this node |
| `tenzro_updateIdentity` | Operator-only identity update (`update.kind`: `resource`; service entries go through an `IdentityServices` transaction, section 9.1) |
| `tenzro_revokeIdentity` | Admit a signed `RevokeIdentity` transaction (any account may send it; the root's approval inside authorises it) after checking the approval against chain state; every validator re-verifies it, every node revokes the identity's tokens when it applies the block, and a root's revocation also revokes the agents it delegated |
| `tenzro_forgetIdentity` | Right-to-erasure: drop the identity's off-chain record |
| `tenzro_verifyDidEnvelope` | Verify a DID-signed envelope (also served at `POST /verify/did-envelope`) |
| `tenzro_bindDevice` | Bind a device from a WebAuthn registration; grades what the attestation actually proved (admin-token gated) |
| `tenzro_listBoundDevices` | The devices that can authenticate as an identity, and each one's grade |
| `tenzro_walletReadiness` | Whether a wallet may be created for this identity yet, and if not, the blocker and its remedy |
| `tenzro_revokeBoundDevice` | Unbind a device and end every session it authorised, in one action (admin-token gated) |
| `tenzro_transferMachineOwnership` | Move a machine to another identity under `controller` authority (a controller device assertion) or `machine_key` authority (the machine's own signature) |

The five device methods take their params as a **bare object**, not a
one-element array — the handler deserializes the params value directly, so a
wrapped array is rejected rather than silently misread.

Reachable from every surface: CLI `tenzro device {list,wallet-readiness,revoke,transfer}`,
Rust SDK `client.device()`, TypeScript SDK `client.device()`, MCP tools
`list_bound_devices` / `wallet_readiness`.

The roots an operator pins for attestation verification are
`webauthn_trusted_roots` in `NodeConfig` — base64 DER, one per entry. An entry
that does not decode is dropped rather than trusted, so a typo narrows what the
node will accept instead of widening it.

---

## 17. Implementation

### 17.1 Crate Structure

```
crates/tenzro-identity/src/
├── lib.rs              — Module declarations and re-exports
├── identity.rs         — TenzroIdentity, IdentityData, IdentityStatus
├── did.rs              — TenzroDid parsing and serialization
├── registry.rs         — IdentityRegistry (central store with DashMap)
├── delegation.rs       — DelegationScope, DelegationEntry
├── w3c.rs              — W3C DID Document conversion
├── document.rs         — DID Document types
├── wallet_binding.rs   — hardware-bound wallet auto-provisioning
├── envelope.rs         — protocol-neutral Tenzro DID envelope
├── erc8004.rs          — ERC-8004 registry calldata and selectors
├── erc8004_svm_registrar.rs — Solana registrar program transactions
├── ivms101.rs          — IVMS101 payloads
├── keri.rs             — KERI key event logs
├── kya.rs              — Know Your Agent federation primitives
├── pq_rotation.rs      — move an identity to a post-quantum key under the same DID
└── error.rs            — IdentityError types (DelegationViolation, TrustChainBroken, TrustChainCycle, TrustChainTooDeep)
```

### 17.2 Storage

TDIP identities are stored in RocksDB via the `KvStore` trait with write-through persistence:
- `CF_IDENTITIES` — TenzroIdentity records (JSON serialized via `to_bytes()`/`from_bytes()`)
- Identity keys: `identity:{did}` for DID→identity lookup

The `IdentityRegistry::with_storage()` builder wires the storage backend for durable persistence.

### 17.3 Pluggable Backends

The registry resolves DIDs from the node's own state. Revocations are never
propagated node to node; each node follows consensus:

- **Revocation through consensus**: a root's revocation is a `RevokeIdentity` transaction carrying its approval (a delegated agent's controller named in its terms, or for a machine the root its DID is derived under, approves); every node mirrors the `IdentityRevoked` log through `revoke_from_chain()`

### 17.4 Production Features

- **Agent authority**: consensus Terms only; refusals name the dimension exceeded
- **Cascading revocation**: revoking a root revokes the agents it delegated on chain (the controller's agent index); each node's `revoke_from_chain()` also cascades to the machines its read model records under the identity
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

Copyright 2026 Tenzro Network Contributors. Licensed under Apache-2.0.

This specification is open for adoption and implementation. Implementors may freely build TDIP-compliant systems.

## Machine identities must be answerable

A machine identity must be answerable to something other than itself. Either a
human (or institution) delegated it and remains accountable, or a **hardware
root of trust that can prove which machine it is** stands in their place. There
is no third option, and a machine that satisfies neither is refused before a
record exists.

A machine that answers only to itself is a self-issued claim: nothing
distinguishes it from ten thousand identical claims minted by the same script,
and there is nobody to hold to account when it misbehaves.

Agents are delegated the same way — from a human, or from the machine that owns
them.

### A readable serial is not proof

The anchor is graded (`tenzro_types::machine_id::IdentifierGrade`):

- **Attestable** — a per-unit *secret* that can prove possession without
  disclosing it: a TPM 2.0 endorsement key, a Chinese TCM/TPCM, an Apple Secure
  Enclave, AMD SEV-SNP's chip-unique VCEK, Intel SGX/TDX platform provisioning,
  Qualcomm QFPROM/StrongBox, a Microchip ATECC608 signed serial, an NXP SE050,
  an ESP32's DS/ECDSA peripheral, a Raspberry Pi device unique secret.
- **Fused** — per-unit, readable, not a secret: Intel and AMD PPIN, Apple ECID,
  Allwinner SID, Rockchip OTP, a Raspberry Pi `/proc/cpuinfo` serial, SMBIOS
  UUID.
- **Model** — identifies a design, not a unit: Arm `MIDR_EL1`, x86 CPUID
  family/model/stepping. Modelled explicitly because both are routinely
  mistaken for serials.

**Only an attestable source can anchor a machine no human delegated.** A fused
serial is readable by anything running on the machine and claimable by anything
anywhere; accepting one would make the rule cosmetic. Duplicate serials on
cloned boards are a documented field failure.

### Identity does not root in the GPU

An accelerator is the most-swapped component in a machine — cards move between
chassis, are resold, are replaced on failure, and partition (MIG, SR-IOV) so one
device presents several identifiers. Rooting identity in one would mean the
identity follows the card rather than the machine, and a node that loses a GPU
would lose the ability to prove it is itself. **GPU serials and UUIDs are not
identity sources**, and a test asserts none can reach the fingerprint.

Only the SHA-256 digest of an identifier is ever published, never the value: a
fused serial is a stable cross-service correlator, and publishing one would let
anyone track the same machine across every network it joins.

### Transferring a machine to a new owner

Machines are sold, redeployed and handed between teams. Ownership moves by an
`OwnershipTransfer`, and **the authority required is whatever anchors the
machine** — the same fact that made its identity admissible:

- A machine a human or institution **delegated** moves on that controller's
  authority alone. Holding the hardware does not override an accountable party:
  someone who gains root on a delegated machine has compromised a machine, not
  acquired it.
- A machine **nobody delegated** moves on proof of its hardware root. For an
  autonomous machine the TPM *is* the accountable party, so demonstrating
  control of it is the ownership fact — which is the honest model for selling a
  box, since the buyer ends up holding the silicon and nothing else could
  distinguish them from the seller.

The two are not interchangeable, and presenting the wrong one is refused.

A hardware-rooted machine that changes hands **keeps its root** — the silicon
did not move — and becomes delegated to the new owner, because it now has an
accountable party where before it had only hardware.

Ownership **replaces rather than accumulates**: a machine has exactly one
administering identity at a time. A window with two would let both issue
credentials on it; a window with none would leave an unowned machine still
holding keys. Authorisations carry an expiry so a signed transfer cannot be
replayed later against a machine that has since changed hands.

## Devices bound to an identity

A Tenzro identity links devices the way an Apple ID does — a phone, a laptop, a
machine — and each bound device can authenticate as that identity. Unlike an
Apple ID, **the link is not a platform account**. Nothing here trusts Apple,
Google or Microsoft as an identity provider. What is trusted is a WebAuthn
attestation: a signature, from a key the vendor put in hardware, over a
challenge we chose, verifiable against a root we pin — through the FIDO
Metadata Service by AAGUID, or the platform's own root. The platform is a
conduit, not an authority.

Types: `tenzro_types::device_binding`
(`BoundDevice`, `BindingPolicy`, `AttestationEvidence`, `KeyProtection`,
`AttestationFormat`, `Aaguid`, `DeviceSession`).

### A synced passkey is not a hardware-bound one

WebAuthn's backup-eligibility bit says whether a credential *may* sync. `BE=1`
means the platform's password manager may replicate it to every device the
user's cloud account touches — at which point the credential proves control of
an **account**, not possession of a **device**.

But `BE=0` alone is not proof of hardware either: it is a claim made by the same
software making every other claim. A software authenticator can report `BE=0`
truthfully and still keep the private key in a file. So binding requires
`BE=0` (the credential cannot be replicated off the device), and records a
second, separate fact: whether an attestation verified to a vendor root says the
key lives in a TEE or secure element. That grade is a reputation signal a
relying party can weigh; it is not required, because requiring it would make
the hardware vendors whose roots are pinned the gatekeepers of who may hold an
identity.

`BE=0` together with `BS=1` is refused outright: a credential that cannot be
backed up cannot report itself as backed up, and an authenticator that
misreports its own state is not one to bind an identity to.

The signature counter is a clone signal **only** for device-bound credentials.
Synced passkeys hold it at zero permanently, so counter-based clone detection
built without that check locks out exactly the users whose credentials are
hardest to clone.

### Phones do not expose serial numbers, and should not

For a machine, `tenzro_types::machine_id` reads chipset and processor
identifiers. For a phone there is deliberately no equivalent: Apple and Google
both removed per-unit identifiers from application reach so that apps could not
fingerprint users across installs.

That is not a gap. **For a phone the device identity *is* the attested
credential key** — a keypair the secure element generated and will not export,
whose attestation says which hardware holds it. It identifies the device better
than a serial would, because a serial can be read and repeated by anything that
has seen it once, while possession of the key can only be demonstrated by the
device that holds it.

The AAGUID names the authenticator's *make and model* and is therefore
model-grade: every Pixel of a given generation reports the same one. It is what
policy is written against ("StrongBox-class only"); it is never identity. An
all-zero AAGUID means **unknown**, not suspicious — several platform providers
report it for privacy, and alarming on it would reject them.

## A wallet needs a second device

A wallet held behind a single device is lost with that device. The first device
is the machine the user is already on — it was captured when they started — so
the requirement in practice is: **bind a phone (or another machine) before there
is anything to lose**. The user scans the pairing QR code and authenticates with
their passkey; WebAuthn's hybrid transport carries the ceremony.

The second device must be genuinely *separate*, not merely a second credential:
two passkeys on one laptop are two ways into one box, and a laptop that dies
takes both. Only device-bound (`BE=0`) credentials bind, because a syncable
credential would make the second factor an account rather than a device.

An identity may bind many devices, and each of them authenticates.

## Sessions

An authenticated session is distinct from the short-lived browser *ceremony*
session that mints it. **Every session names the bound device that authorised
it**, not only the identity — a session recording only "alice is signed in"
could not be revoked when Alice loses the phone that created it without signing
her out everywhere, including from the laptop still in her hands.

Unbinding a device therefore ends exactly the sessions it granted. Expiry and
revocation are independent: a revoked session inside its window and an expired
session never revoked are both unusable.

Sessions are stored per identity, under `identity_sessions_dir(did)` — see
"Where identity state lives" below.

## Where identity state lives

State about *who* is filed under the identity, not the machine hosting it:

| Path | Holds |
|---|---|
| `identities/<did>/sessions/` | live sessions |
| `identities/<did>/devices/` | bound devices |
| `identities/<did>/chat-history/` | conversation transcripts |
| `identities/<did>/passkey/` | passkey companion material |
| `identities/<did>/hybrid_key.json` | that identity's sealed hybrid key |

A machine hosts identities; it does not own them. Chat history and passkey
material filed at machine level answer "what happened on this box", which is
never the question asked of them. Filing them under the identity also makes
exporting or revoking an identity a directory operation.

The directory name is the DID with path-unsafe characters replaced, plus a short
digest of the original. The digest is what makes it injective: `:` must collapse
for the filesystem's sake, so without it `a:b` and `a_b` would name one
directory and two identities would share their sessions and their keys.

## A machine that holds its own key seals it

An autonomous machine answers for itself, and what makes that claim mean
anything is that the key it answers with cannot be copied off the machine. A key
in a file is copyable by anything that can read the file — a backup, a stolen
disk, a container escape, a misapplied `chmod` — and copying it makes you the
machine, with no human to notice.

So a machine that stores its own key **seals it to its hardware root**. The blob
on disk is ciphertext under the TPM's storage hierarchy: only that TPM can open
it. A host that cannot seal is refused rather than degrading to a plaintext
keyfile.

This is the same rule as the anchor rule, seen from the other side: the machines
allowed to speak for themselves are exactly the machines able to seal the key
they speak with. A machine with no attestable root was never allowed to be
autonomous, so it never reaches this path.
