# PDIS-TENZRO: Praecise Digital Identity Standard — Tenzro Network Implementation

**Standard ID:** PDIS-3
**Version:** 1.0.0
**Status:** Production
**Authors:** Praecise Standards Consortium
**Created:** March 19, 2026
**Last Updated:** March 19, 2026
**Platform:** Tenzro Network (Custom L1, HotStuff-2 Consensus)

---

## Abstract

PDIS-TENZRO (PDIS-3) defines the Tenzro Network implementation of the Praecise Digital Identity Standard as a **secondary, fully interoperable identity standard**. The native Tenzro identity protocol is **TDIP (Tenzro Decentralized Identity Protocol)**, which uses the `did:tenzro:` DID method.

PDIS-TENZRO supports systems using the `did:pdis:guardian:` (PDIS-1) and `did:pdis:agent:` (PDIS-2) formats. All PDIS identities are internally mapped to TDIP identities and benefit from Tenzro's on-chain identity registry, verifiable credentials, delegation scopes, and MPC wallet provisioning.

**Relationship to TDIP:**
- **TDIP (`did:tenzro:`)** is the primary, canonical identity standard for Tenzro Network
- **PDIS (`did:pdis:`)** is a secondary standard fully supported for interoperability
- Both DID formats are parsed by `TenzroDid::parse()` and resolve to the same underlying `TenzroIdentity` type

**Key Features**:
- Full support for PDIS-1 (Guardian) and PDIS-2 (Agent) DID formats
- Mapped to TDIP under the hood: `did:pdis:guardian:{uuid}` → `did:tenzro:human:{uuid}`
- Custom L1 with HotStuff-2 BFT consensus (sub-second finality)
- Native TNZO token for network operations
- Agent reputation system (activity-based scoring, trust decay)
- Immediate finality settlement engine (DvP alternative to Canton)
- Escrow management for multi-party settlement
- TEE attestation support for hardware-attested identity verification
- SDK-based integration via `@tenzro/sdk`

---

## 1. Tenzro Network Overview

### 1.1 Network Architecture

| Property | Value |
|----------|-------|
| Consensus | HotStuff-2 BFT |
| Finality | Sub-second (immediate) |
| Native Token | TNZO |
| Identity Standard | PDIS-1 (Guardian), PDIS-2 (Agent) |
| Client SDK | `@tenzro/sdk` (TypeScript) |
| RPC Configuration | `TENZRO_RPC_URL` environment variable |

### 1.2 Network Environments

| Environment | Detection | Factory Method |
|-------------|-----------|----------------|
| Mainnet | URL does not contain `testnet` or `localhost` | `TenzroClient.mainnet()` |
| Testnet | URL contains `testnet` | `TenzroClient.testnet()` |
| Local | URL contains `localhost` or `127.0.0.1` | `TenzroClient.local()` |

The client auto-detects the environment from the configured RPC URL and uses the appropriate factory method.

### 1.3 Design Philosophy

Tenzro serves as the **identity and verification layer** with native TDIP support and PDIS interoperability:

```
┌─────────────────────────────────────────────────────┐
│  Tenzro Network (L1 Blockchain)                     │
├─────────────┬──────────────┬────────────────────────┤
│  TDIP       │  Tempo       │  Canton (opt-in)       │
│  IDENTITY   │  PAYMENTS    │  SETTLEMENT            │
│  (primary)  │  + MPP       │  + DAML                │
│  + PDIS     │              │                        │
│  (secondary)│              │                        │
├─────────────┼──────────────┼────────────────────────┤
│ did:tenzro: │  TIP-20 USDC │  DvP settlement        │
│ did:pdis:   │  MPP sessions│  CC rewards            │
│ Reputation  │  Sub-cent    │  AgentIdentity DAML    │
│ TEE attest  │  Batch settle│  Sub-tx privacy        │
│ Settlement  │  Fee sponsor │  Regulated assets      │
│ Escrow      │              │                        │
└─────────────┴──────────────┴────────────────────────┘
        + EVM (ERC-8004) opt-in    + Solana (R8004) opt-in
```

**PDIS → TDIP Mapping:**
- `did:pdis:guardian:{uuid}` → `did:tenzro:human:{uuid}` (PDIS-1 → TDIP human)
- `did:pdis:agent:{controller}:{uuid}` → `did:tenzro:machine:{controller}:{uuid}` (PDIS-2 → TDIP machine)
- All PDIS identities benefit from TDIP features: verifiable credentials, delegation scopes, W3C DID Documents, MPC wallets

---

## 2. Identity Registration

### 2.1 Registration Parameters

Every PDIS identity registers on Tenzro using the following parameters:

```typescript
interface TenzroRegisterParams {
  name: string;                    // Human-readable identity name
  agentType: TenzroAgentType;      // Identity classification
  capabilities: string[];          // Skill/capability tags
  owner: string;                   // EVM address of the owner (secp256k1)
  did?: string;                    // W3C DID (did:web:{platform}:users/{id})
  metadata?: Record<string, unknown>; // Additional metadata
}
```

### 2.2 Agent Types

PDIS maps identity types to TDIP identity types (internally):

| PDIS Type | PDIS DID Format | TDIP DID Format | Description |
|-----------|----------------|-----------------|-------------|
| PDIS-1 (Guardian) | `did:pdis:guardian:{uuid}` | `did:tenzro:human:{uuid}` | KYC-verified human identity |
| PDIS-2 (Controlled) | `did:pdis:agent:{controller}:{uuid}` | `did:tenzro:machine:{controller}:{uuid}` | Machine with human controller |
| PDIS-2 (Autonomous) | `did:pdis:agent:{uuid}` | `did:tenzro:machine:{uuid}` | Fully autonomous machine |

**Note:** The `TenzroAgentType` enum values (`guardian`, `trading`, `research`, `assistant`, `autonomous`) are stored as capability strings in the TDIP `Machine.capabilities` field.

### 2.3 Registration Response

Successful registration returns a `TenzroAgentIdentity`:

```typescript
interface TenzroAgentIdentity {
  id: string;              // Tenzro-assigned identity ID
  address: string;         // Tenzro network address
  name: string;            // Registered name
  agentType: string;       // Registered agent type
  capabilities: string[];  // Registered capabilities
  reputation: number;      // Initial reputation score (0)
  owner: string;           // Owner EVM address
}
```

### 2.4 Registration Flow

```
┌────────────────────┐
│  Identity Created  │
│  (PDIS-1 or PDIS-2)│
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  TenzroClient      │
│  .agent.register() │
│  ────────────────  │
│  name, agentType,  │
│  capabilities,     │
│  owner, did,       │
│  metadata: {       │
│    platform: '...' │
│  }                 │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  Tenzro L1         │
│  HotStuff-2        │
│  Consensus         │
│  ─────────────     │
│  Sub-second        │
│  finality          │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  TenzroAgentIdentity│
│  ────────────────  │
│  id, address,      │
│  reputation: 0     │
└────────────────────┘
```

### 2.5 Platform Metadata

All registrations include platform metadata for cross-platform identity resolution:

```json
{
  "did": "did:web:rivier.ai:users/01JCEK...",
  "platform": "rivier",
  "registeredAt": "2026-03-19T12:00:00Z"
}
```

Implementors MUST include a `platform` field identifying the originating platform. The `did` field SHOULD be included for W3C DID interoperability.

### 2.6 Database Persistence

After successful Tenzro registration, the following fields are stored on the identity record:

| Field | Type | Description |
|-------|------|-------------|
| `tenzroAddress` | `varchar(100)` | Tenzro network address |
| `tenzroAgentId` | `text` | Tenzro-assigned agent identity ID |
| `tenzroRegistrationTxHash` | `text` | Registration transaction hash |
| `tenzroSyncStatus` | `enum` | Sync status: `SYNCED`, `PENDING`, `FAILED`, `NOT_STARTED`, `ERROR` |

---

## 3. Agent Reputation System

### 3.1 Reputation Model

Tenzro maintains a reputation score for every registered identity. Reputation is activity-based and subject to time decay.

| Property | Description |
|----------|-------------|
| Initial Score | 0 |
| Score Range | 0–1000 |
| Update Frequency | Per-settlement, per-interaction |
| Decay Model | Time-based decay (inactivity reduces score) |

### 3.2 Reputation Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Settlement Success | High | Completed settlements increase reputation |
| Settlement Failure | High (negative) | Failed settlements decrease reputation |
| Registration Age | Low | Longer registration slightly increases trust |
| Activity Frequency | Medium | Regular activity maintains reputation |
| Inactivity Decay | Medium (negative) | Prolonged inactivity reduces score |

### 3.3 Reputation Queries

Reputation is returned as part of the `TenzroAgentIdentity` object and can be queried independently for any registered address.

---

## 4. Settlement Engine

### 4.1 Overview

Tenzro provides an immediate-finality settlement engine as an alternative to Canton's DAML-based settlement. Tenzro settlement is the **default settlement layer** for non-Canton assets.

### 4.2 Settlement Parameters

```typescript
interface TenzroSettleParams {
  fromAddress: string;    // Sender's Tenzro address
  toAddress: string;      // Recipient's Tenzro address
  amount: string;         // Settlement amount (human-readable)
  asset: string;          // Asset symbol (e.g., 'USDC', 'ETH', 'BTC')
  reference?: string;     // Optional reference ID for tracking
}
```

### 4.3 Settlement Receipt

```typescript
interface TenzroSettlementReceipt {
  status: 'completed' | 'pending' | 'failed';
  txHash: string;           // On-chain transaction hash
  settlementId: string;     // Unique settlement identifier
  blockHeight: number;      // Block at which settlement was confirmed
  fee: string;              // Settlement fee (typically '0' for PDIS identities)
}
```

### 4.4 Settlement Flow

```
Quote → Risk Check → MPC Sign → Broadcast → Tenzro Settlement
                                                    │
                                                    ▼
                                              ┌──────────┐
                                              │ completed │ → Update holdings
                                              │ pending   │ → Monitor until confirmed
                                              │ failed    │ → Retry (3x, exponential backoff)
                                              └──────────┘
```

### 4.5 Retry Policy

Failed settlements are retried with exponential backoff:

| Attempt | Delay |
|---------|-------|
| 1 | 1 second |
| 2 | 2 seconds |
| 3 | 4 seconds |

After 3 failed attempts, the settlement is marked as failed and the trade is rolled back.

### 4.6 Settlement Routing

| Asset Type | Settlement Layer |
|------------|-----------------|
| Standard crypto (ETH, BTC, SOL, etc.) | Tenzro (default) |
| Canton-native tokens (CC, CBTC, USDCx, USD1, USYC, tUST) | Canton |
| Canton-opted user tokens | Canton |
| All other assets | Tenzro |

---

## 5. Escrow Management

### 5.1 Overview

Tenzro escrow is a **consensus-mediated on-chain primitive** — funds are
locked at a deterministically-derived vault address by the Native VM. Only
the original signing payer can later release funds to the payee or refund
them to themselves. There is no convenience RPC; writes flow through signed
transactions only.

### 5.2 Escrow Parameters

```typescript
interface TenzroEscrowParams {
  payer: string;            // Address depositing funds (must match the signing key)
  payee: string;            // Address receiving funds on release
  amount: string;           // Amount in wei (smallest unit)
  asset: string;            // Asset id (e.g. "TNZO")
  expiresAt: number;        // Expiration in Unix ms
  releaseConditions:        // One of: Timeout | ProviderSignature |
    | "Timeout"             //   ConsumerSignature | BothSignatures |
    | "ProviderSignature"   //   VerifierSignature | Custom
    | "ConsumerSignature"
    | "BothSignatures"
    | "VerifierSignature"
    | { type: "Custom"; data: string };
}
```

### 5.3 Submission

Escrow operations are submitted as typed transactions through
`tenzro_signAndSendTransaction` (server-side signing) or
`eth_sendRawTransaction` (locally-signed):

| Selector       | Operation        | Gas    |
|----------------|------------------|--------|
| `0x01000010`   | CreateEscrow     | 75,000 |
| `0x01000011`   | ReleaseEscrow    | 60,000 |
| `0x01000012`   | RefundEscrow     | 50,000 |

The `escrow_id` is derived deterministically by the VM as
`SHA-256("tenzro/escrow/id" || payer || nonce_le)` and emitted in the
receipt log of the `CreateEscrow` transaction. The vault address is
`Address(SHA-256("tenzro/escrow/vault" || escrow_id))` and has no private
key — release/refund payouts are a privileged VM operation.

### 5.4 Escrow Lifecycle

```
CREATE → FUNDED → RELEASED (payer-signed ReleaseEscrow + valid proof)
                → REFUNDED (payer-signed RefundEscrow after expiry,
                            or with Timeout/Custom release conditions)
```

Authorization is enforced by the VM at every step: `CreateEscrow.from` must
equal the signing payer; `ReleaseEscrow` and `RefundEscrow` are rejected
unless `tx.from == escrow.payer`. Read access is via
`tenzro_getEscrow`, `tenzro_listEscrowsByPayer`, and
`tenzro_listEscrowsByPayee`, all backed by RocksDB `CF_SETTLEMENTS`.

---

## 6. Health Monitoring

### 6.1 Health Check

Implementors SHOULD perform Tenzro health checks during application startup:

```typescript
const healthy = await tenzroHealthCheck();
// Returns true if Tenzro node is reachable
```

### 6.2 Graceful Degradation

If Tenzro is unreachable:
- Identity creation proceeds without Tenzro registration (sets `tenzroSyncStatus = 'FAILED'`)
- Settlement falls back to Canton if available, or queues for retry
- Migration retries on next user login or identity query

---

## 7. Security Considerations

### 7.1 Registration Integrity

**Threat:** Unauthorized identity registration on Tenzro.

**Mitigation:** All registrations flow through the platform's identity provisioning service, which enforces:
- Authenticated user session (httpOnly cookie)
- 1 HUMAN identity per user (partial unique index)
- Passkey verification for sensitive operations (Solana mint, autonomous agents)

### 7.2 Reputation Manipulation

**Threat:** Agent inflates reputation through self-settlement.

**Mitigation:** Tenzro's reputation algorithm weights settlement diversity (different counterparties) higher than volume. Self-referencing settlements are detected and excluded from reputation calculation.

### 7.3 Settlement Finality

**Threat:** Double-spend via concurrent settlement requests.

**Mitigation:**
- PostgreSQL advisory locks (FNV-1a hash of wallet ID) prevent concurrent trades
- Tenzro's HotStuff-2 consensus provides immediate finality
- Optimistic locking on signing requests (`WHERE status = 'APPROVED'`)

### 7.4 Network Partition

**Threat:** Tenzro node becomes unreachable.

**Mitigation:** Graceful degradation — identities continue to function via Canton/EVM/Solana registrations. Tenzro-specific features (reputation, settlement) are unavailable until reconnection. Registration retries on next user interaction.

---

## 8. Privacy Considerations

### 8.1 On-Chain Data

Tenzro identity registration stores:
- Identity name (human-readable)
- Agent type classification
- Capabilities/skills list
- Owner EVM address
- W3C DID
- Platform metadata

### 8.2 PII Protection

No PII is stored in Tenzro registrations:
- No email, phone, biometrics, or government ID
- DID is a cryptographic identifier, not a personal data store
- Owner address is a public key derivative, not linkable to personal identity without platform cooperation

### 8.3 Selective Disclosure

Implementors SHOULD allow users to control what metadata is included in Tenzro registration beyond the required fields (name, agentType, capabilities, owner).

---

## 9. Coexistence with Other Registrations

### 9.1 Canton Coexistence

PDIS-TENZRO operates alongside PDIS-CANTON:
- Tenzro is the always-on default for identity and basic settlement
- Canton remains available as opt-in for institutional settlement, DAML contracts, and regulated assets
- Both registration types can coexist on the same identity

### 9.2 EVM/Solana Independence

Tenzro registration is independent of EVM and Solana opt-in registrations. An identity can have:
- Tenzro registration (always, mandatory)
- Tempo address (always, mandatory)
- Canton party (opt-in, free)
- EVM NFT (opt-in, $0.50–$5.00)
- Solana NFT (opt-in, $0.25)

---

## 10. Reference Implementation

### 10.1 Key Files

| Component | Path |
|-----------|------|
| Tenzro Client | `packages/blockchain/src/tenzro/index.ts` |
| Identity Provisioning | `packages/api/src/services/identity-provisioning.ts` |
| Chain Configuration | `packages/blockchain/src/types.ts` |
| Database Schema | `packages/db/src/schema/identities.ts` |
| Enum Definitions | `packages/db/src/schema/enums.ts` |

### 10.2 SDK Dependency

```json
{
  "dependencies": {
    "@tenzro/sdk": "file:../../path/to/tenzro-ts-sdk"
  }
}
```

The `@tenzro/sdk` is imported dynamically to avoid hard dependencies in contexts where it may not be available (e.g., frontend builds).

### 10.3 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TENZRO_RPC_URL` | Tenzro node RPC endpoint | `http://localhost:9944` |
| `TENZRO_EXPLORER_URL` | Tenzro block explorer URL | (none) |

---

## 11. Test Cases

### 11.1 Guardian Registration

**Input:** User creates account, `ensureHumanIdentity` called
**Expected:** HUMAN identity registered on Tenzro with `agentType: 'guardian'`
**Verification:** `tenzroAddress` populated, `tenzroSyncStatus = 'SYNCED'`

### 11.2 Agent Registration

**Input:** User creates TRADING agent
**Expected:** AGENT identity registered on Tenzro with `agentType: 'trading'`, `guardian_did` in metadata
**Verification:** `tenzroAgentId` populated, `tenzroSyncStatus = 'SYNCED'`

### 11.3 Settlement

**Input:** Agent executes trade, settlement routed to Tenzro
**Expected:** `TenzroSettlementReceipt` with `status: 'completed'`
**Verification:** Holdings updated, trade status updated

### 11.4 Graceful Degradation

**Input:** Tenzro RPC unreachable during identity creation
**Expected:** Identity created with `tenzroSyncStatus = 'FAILED'`, other registrations proceed
**Verification:** Identity usable via other chains, Tenzro registration retried on next login

---

## Copyright

Copyright 2026 Praecise Standards Consortium. All rights reserved.

This specification is available under open terms for adoption and implementation. Implementors may freely build PDIS-TENZRO-compliant systems.
