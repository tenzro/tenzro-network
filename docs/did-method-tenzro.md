# did:tenzro DID Method Specification

**Version:** 1.0.0
**Status:** Ready for W3C Registration
**Specification Location:** https://github.com/tenzro/did-method-tenzro/blob/main/spec.md

---

## 1. Introduction

The `did:tenzro` DID method provides decentralized identifiers anchored on the
Tenzro Ledger, the network underneath Tenzro Network, designed for AI-age identity, verification,
and settlement. The method supports both **human** and **machine** identities,
including autonomous agents and delegated-controller agents, with on-chain
verification credentials and revocation.

### 1.1 Design Goals

- Unified identity primitives for humans and autonomous machines
- On-chain anchoring with cryptographic verifiability
- Delegation scopes for principal→agent authority transfer
- W3C DID Core 1.0 compatible resolution
- W3C Verifiable Credentials Data Model v2.0 compatible

---

## 2. Method-Specific Identifier

```
did-tenzro-format   = "did:tenzro:" id-type ":" [ parent-uuid ":" ] uuid
id-type             = "human" / "machine"
parent-uuid         = 1*36idchar    ; RFC 4122 UUID of controller
uuid                = 1*36idchar    ; RFC 4122 UUID
idchar              = ALPHA / DIGIT / "-"
```

### 2.1 Examples

```text
did:tenzro:human:550e8400-e29b-41d4-a716-446655440000
did:tenzro:machine:550e8400-e29b-41d4-a716-446655440000:6ba7b810-9dad-11d1-80b4-00c04fd430c8
did:tenzro:machine:6ba7b810-9dad-11d1-80b4-00c04fd430c8
```

- **human**: A natural person identity. KYC tiers (Unverified / Basic /
  Enhanced / Full) are expressed as Verifiable Credentials.
- **machine:{parent}:{uuid}**: Machine identity controlled by `{parent}` with
  delegation scope (spending limits, allowed operations, allowed protocols).
- **machine:{uuid}**: Machine with no human controller. Admitted **only** when anchored by an attestable hardware root of trust — see "Machine identities must be answerable" below. Derived from that root rather than randomly, so the DID is reproducible from the machine.

---

## 3. CRUD Operations

### 3.1 Create

1. Generate Ed25519 or Secp256k1 keypair via `tenzro-crypto`.
2. Compose identity: `IdentityData::Human{ display_name, kyc_tier }` or
   `IdentityData::Machine{ capabilities, delegation_scope, controller_did }`.
3. Call RPC method `tenzro_registerIdentity` with the serialised identity.
4. Node emits an `IdentityRegistered` event and persists the DID Document in
   RocksDB `CF_IDENTITIES`.

### 3.2 Resolve

Resolve via RPC:
```json
{"jsonrpc":"2.0","method":"tenzro_resolveDidDocument","params":{"did":"did:tenzro:human:..."},"id":1}
```

The node returns a W3C DID Document with `verificationMethod`, `authentication`,
`assertionMethod`, `keyAgreement`, and `service` entries.

### 3.3 Update

Call `tenzro_updateIdentity` (controller-signed). Updates are appended to
the on-chain event log; the current state is always the latest-applied
record.

### 3.4 Revoke (Deactivate)

Call `tenzro_revokeIdentity` (controller-signed). Revocation cascades to all
descendants in the machine tree (a human revocation revokes all controlled
machines). Revoked DIDs resolve to a document with `deactivated: true`.

---

## 4. Security & Privacy

- **Key management**: MPC threshold wallets (2-of-3) via `tenzro-wallet`
  eliminate single points of failure.
- **Zeroization**: All sensitive key material is zeroized on drop.
- **Delegation**: Machines can only perform operations within their
  `DelegationScope`; violations are rejected at RPC boundary with typed
  `DelegationViolation` errors.
- **Revocation**: Cascading revocation ensures compromised controllers
  immediately invalidate dependent machines.
- **Privacy**: Personal data is never stored on-chain; only hashes and
  cryptographic commitments.

---

## 5. Verifiable Credentials

`did:tenzro` subjects may be issued W3C VC Data Model v2.0 credentials for
KYC attestation, capability grants, and on-chain event proofs. Credentials
are signed with Ed25519 or Secp256k1 via `tenzro_crypto::signatures::sign`.

Credential types include:
- `KycAttestation` — KYC verification level (tier 0-3)
- `AgeVerification` — Age threshold attestation
- `ResidencyProof` — Jurisdiction residency
- `AccreditedInvestor` — Accredited investor status
- `InstitutionalMember` — Institutional membership
- `PaymentAuthorization` — Payment protocol authorization
- `ModelProvider` — AI model provider attestation
- `TeeOperator` — TEE hardware operator attestation
- `Custom(String)` — Application-specific credentials

Trust chains are verified via `IdentityVerifier::verify_credential_chain()`
with recursive issuer traversal, cycle detection (via `HashSet<String>`),
configurable depth bound (default 10), and trust-root anchoring. The verifier
returns a `CredentialChainResult` containing `chain_length`, `terminating_root`,
and per-credential validation issues.

---

## 6. Conformance

An implementation conforms to this specification if it:

1. Parses DIDs matching the ABNF in §2 (via `TenzroDid::parse()`).
2. Produces DID Documents compliant with W3C DID Core 1.0 (via `identity_to_did_document()`).
3. Implements the CRUD operations in §3 with the RPC method names given.
4. Rejects operations that violate delegation scope at the RPC boundary (via `IdentityRegistry::enforce_operation()` returning typed `DelegationViolation`).
5. Implements cascading revocation for controller→machine hierarchies (via `IdentityRegistry::revoke()` and `apply_remote_revocation()`).
6. Supports recursive trust chain verification with cycle detection, depth bound, and trust-root anchoring (via `IdentityVerifier::verify_credential_chain()`).
7. Provides username registry with unique lowercase alphanumeric + underscore names (3-20 chars) via `register_username()` / `resolve_username()`.

---

## 7. Contact

- **Repository**: https://github.com/tenzro/did-method-tenzro
- **Specification**: https://github.com/tenzro/did-method-tenzro/blob/main/spec.md
- **Implementation**: https://github.com/tenzro/tenzro-network (`crates/tenzro-identity`)
- **Issues**: https://github.com/tenzro/did-method-tenzro/issues
- **W3C Working Group**: W3C Credentials Community Group

---

## 8. W3C Registration Submission

This document constitutes the method specification required by the
[W3C DID Specification Registries policies](https://www.w3.org/TR/did-spec-registries/#did-method-registration-policies).
The submission PR should be filed against
`https://github.com/w3c/did-extensions` adding the following row to the
methods table in `methods.md`:

```
| tenzro | Tenzro Network | https://github.com/tenzro/did-method-tenzro | https://github.com/tenzro/did-method-tenzro/blob/main/spec.md | PROVISIONAL |
```

### Registration Checklist

- [x] DID method name chosen and unique (no existing `did:tenzro`)
- [x] Human-readable description provided
- [x] Specification URL reachable and permanent (https://github.com/tenzro/did-method-tenzro/blob/main/spec.md)
- [x] IPR affirmed (Apache-2.0 license)
- [x] Security and privacy considerations documented (§4)
- [x] CRUD semantics fully specified (§3)
- [x] Verifiable Credentials support documented (§5, W3C VC Data Model v2.0)
- [x] Conformance requirements specified (§6)
- [x] Implementation details provided (crates/tenzro-identity, 85 tests)
- [ ] PR filed against `w3c/did-extensions` (MANUAL STEP - ready for submission)
- [ ] Editor review + merge (upstream W3C process)

**Production Readiness:**
- Full implementation in `crates/tenzro-identity` (Rust)
- 85 passing unit and integration tests covering DID parsing, credential verification, trust chain traversal, delegation enforcement, cascading revocation
- Live testnet deployment at `https://api.tenzro.xyz` with JSON-RPC interface
- Reference SDKs: Rust (`tenzro-sdk`) and TypeScript (`tenzro-ts-sdk`)

**Next step for repository owner**: Fork `https://github.com/w3c/did-extensions`,
add the table entry above to `methods.md`, and open a PR referencing this specification URL.

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
