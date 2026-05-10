# Mastercard KYA — Know Your Agent

**Date:** 2026-05-05
**Source:** Cloudflare blog, Trulioo white paper, Mastercard developer docs

**Scope:** identity-only. MDES tokenization / fiat card vault is OUT of scope.

## What KYA registers

Three axes:
- **Controller identity** — human/organization operating the agent
- **Agent authenticator** — TEE hardware key residency flag
- **Delegation scope** — per-session, per-merchant spend limits

Mastercard: *"In order to get access to tokens, agents need to be registered. Mastercard has a process called 'Know Your Agent' – basically a KYC process."*

Trulioo: *"an identity framework for trusted agentic commerce."* Identity, not payment-instrument metadata.

## Registry mechanics

**Closed federation, not open.** Cloudflare/Visa/Mastercard joint write-up:
> "Visa and Mastercard will be hosting their own directories for Visa-registered and Mastercard-registered agents, respectively."

Discovery: per-issuer `/.well-known/http-message-signatures-directory` at the domain in the `Signature-Agent` header. **No cross-network resolver. No on-chain anchoring.**

## Authentication

**Web Bot Auth = HTTP Message Signatures (RFC 9421).** Agents sign requests; `keyid` in `Signature-Input` resolves to public key in issuer's `.well-known` JWKS directory. Browse/purchase tag + `nonce` defeat replay. **No DIDs, no VCs, no chain anchor — RSA/Ed25519 keys in hosted JWK set.**

## Public queryability

**No.** Verification gated to network participants (issuers, acquirers, merchants behind Cloudflare/Akamai). Public web cannot enumerate the registry.

## Tenzro has all the missing pieces

- `did:tenzro:machine:*` (TDIP) — DID for any agent
- ERC-8004 Identity precompile `0x101a` — on-chain registry mirror
- ERC-8004 Reputation precompile `0x101b` — peer-attestable reputation
- `DelegationScope` with `enforce_operation()` — programmatic spend limits
- TEE attestation via `is_seed_agent`, `tee_provider` — hardware key residency proof
- RFC 9421 signing (Ed25519/Secp256k1) — already aligned with KYA's auth scheme

## Tenzro angle (YES)

**DID-anchored, on-chain-queryable, ERC-8004-bridged KYA** that closed Mastercard/Visa directories can federate into via DID `service` entries:

```json
{ "id": "did:tenzro:machine:abc",
  "service": [{
    "id": "#mastercard-kya",
    "type": "MastercardKYA",
    "serviceEndpoint": "https://kya.mastercard.com/agents/abc#keyid"
  }] }
```

**Result:** same agent identity portable between Mastercard's closed registry and Tenzro's open one. Nobody else is building DID-anchored KYA.

## Implementation order

1. **`KyaRecord` type** in `crates/tenzro-identity/src/kya.rs` — DONE. Wraps controller_did + authenticator (with `tee_attested` flag) + delegation_scope around the existing TDIP machine identity. Pure-function `compute_kya_level()` derives the four-tier ladder (Unverified / Basic / Enhanced / Full) from status + controller binding + delegation strictness. Registry surface: `IdentityRegistry::kya_record_for(did)` returns the record for a TDIP machine DID; humans return a typed error. RPC: `tenzro_getKyaRecord { did }`.
2. **DID Document `service` entries** — DONE. `SERVICE_TYPE_MASTERCARD_KYA = "MastercardKYA"` and `SERVICE_TYPE_VISA_TAP = "VisaTAP"` constants exported from `tenzro_identity`; `is_kya_service_type()` predicate. The `tenzro_addService` RPC handler now actually persists the service entry — the previous implementation resolved a clone, mutated locally, and dropped the result. Registry surface: `IdentityRegistry::add_service_to_identity(did, service)` with write-through to `CF_IDENTITIES`.
3. **ERC-8004 mirror** — DONE. `OnChainAgentRegistry::mirror_register_agent` is auto-invoked by `register_machine_with_fee` and `register_autonomous_machine_with_fee`, mirroring every TDIP machine DID into the IdentityRegistry system contract at precompile `0x101a`. The registry allocates a sequential `uint256 agentId` (1-indexed) at register-time and stores it on `IdentityData::Machine.erc8004_agent_id`; reverse DID → id resolution via `OnChainAgentRegistry::lookup_agent_id_by_did`. Any EVM tool can then resolve the same record from Ethereum, L2s, or any chain that supports ERC-8004. Profile RPC: `tenzro_mastercardKyaProtocolInfo` advertises the federation surface.
4. **No new MDES code**: tokenization stays out of scope per user direction (Mastercard = fiat).
