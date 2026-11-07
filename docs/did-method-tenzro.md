# did:tenzro DID Method Specification

**Version:** 1.0.0
**Status:** Ready for W3C Registration
**Specification Location:** https://github.com/tenzro/tenzro-network/blob/main/docs/did-method-tenzro.md

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
did-tenzro-format   = "did:tenzro:" ( human / machine / delegated / institution )
human               = "human:" id
machine             = "machine:" id
delegated           = "machine:" controller-id ":" id
institution         = "institution:" lei ":" id
id                  = 36idchar      ; UUIDv8 layout (RFC 9562 section 5.8)
controller-id       = 1*36idchar    ; the controlling identity's id
lei                 = 20ALPHANUM    ; ISO 17442 Legal Entity Identifier
idchar              = ALPHA / DIGIT / "-"
```

Every `id` is **derived** from a public key, never drawn at random: the first
16 bytes of a domain-separated SHA-256, formatted as a UUIDv8.

| Form | `id` is derived from |
|---|---|
| `human:{id}` | the passkey credential's P-256 public key (`x \|\| y`) |
| `machine:{id}` (device key) | the machine's TPM or Secure Enclave P-256 device key |
| `machine:{id}` (machine root) | the machine root folded from its TPM endorsement key's name |
| `machine:{controller}:{id}` | the controller id and the machine's own device key |
| `institution:{lei}:{id}` | the LEI and the institution's controller key |

The derivation functions are specified in `tenzro_types::did_derivation`. The
same key always yields the same DID, and two keys never share one.

### 2.1 Examples

```text
did:tenzro:human:1b4e28ba-2fa1-81d2-883f-0016d3cca427
did:tenzro:machine:6ba7b810-9dad-81d1-80b4-00c04fd430c8
did:tenzro:machine:1b4e28ba-2fa1-81d2-883f-0016d3cca427:7c9e6679-7425-80de-944b-e07fc1f90ae7
did:tenzro:institution:5493001KJTIIGC8Y1R12:3f2504e0-4f89-81d3-9a0c-0305e82c3301
```

### 2.2 How a resolver verifies a DID

A DID-to-key binding is accepted only when it can be recomputed:

1. For a key-derived form, recompute `id` from the registered controller key
   and compare. A mismatch is refused.
2. For a machine-root DID, the record must carry TPM attestation evidence: the
   endorsement key, whose name folds to the root this DID derives from, and a
   quote by an attestation key (proven to live in that TPM by credential
   activation) over a challenge committing to the DID and the registered key.
   Whether a TPM manufacturer certified the endorsement key is recorded as the
   identity's `tpm_endorsement` grade, a reputation signal, and is not a
   condition of registration.

The consensus rule for `RegisterIdentity`, every node mirroring a replicated
identity, the import path and remote DID resolution all apply this check.
A record fetched from another node is dropped, not cached, when it fails.

---

## 3. CRUD Operations

### 3.1 Create

1. The key is created inside the holder's hardware: a passkey authenticator
   for a human, the TPM or Secure Enclave for a machine
   (`tenzro_device_key::signer`). The private key never leaves it.
2. The DID is derived from that key (section 2).
3. Registration proves possession: a passkey enrols by answering a
   node-issued, single-use custody challenge with user verification from a
   device-bound (not synced) credential; an autonomous machine is admitted
   only with TPM attestation.
4. The node records the identity and submits `RegisterIdentity`, which every
   validator re-checks.

### 3.2 Resolve

Resolve via RPC:
```json
{"jsonrpc":"2.0","method":"tenzro_resolveDidDocument","params":{"did":"did:tenzro:human:..."},"id":1}
```

The node returns a W3C DID Document with `verificationMethod`, `authentication`,
`assertionMethod`, `keyAgreement`, and `service` entries. A node's own
document (`tenzro_nodeDidDocument`) lists the node's ML-DSA-65 key as the
`#pq-key-1` method, ahead of the classical ones, and carries an
`ecdsa-jcs-2019` Data Integrity proof by its hardware key.

### 3.3 Update

Custody changes (adding or removing a passkey, guardians, spending limits,
binding or revoking a device, moving a machine to a new owner) each answer a
node-issued challenge naming the exact change, signed by a key the identity
already holds. Node administration authorises none of them by itself.

An identity's governing key can move to ML-DSA-65 with
`tenzro_rotateIdentityToPq`, signed by the current governing key and the new
key; the DID does not change, and after the first rotation the P-256 key no
longer governs.

### 3.4 Revoke (Deactivate)

Obtain the root's approval of a `revoke_identity` custody challenge over
`revocation_target(did, reason)`: a human approves with its passkey, an
autonomous machine with its hardware key, a delegated agent is revoked by the
controller its terms name, and a machine a root registered by the root its DID
is derived under. Put the approval in a `RevokeIdentity` transaction, sign it
with any account and submit it with `tenzro_revokeIdentity`; the node checks the
approval against chain state before admitting it, and every validator
re-verifies it against keys in chain state. When the block is applied every node
marks the identity revoked and revokes the access tokens it issued to or through
it. Revoking a root also revokes every agent it delegated. Revoked DIDs resolve
to a document with `deactivated: true`.

---

## 4. Security & Privacy

- **Key management**: private keys exist only in a TPM 2.0, an Apple Secure
  Enclave or a passkey authenticator. There are no threshold (MPC) wallets and
  no keys derived from a TEE measurement.
- **Delegation**: Machines can only perform operations within their
  `DelegationScope`; violations are rejected at RPC boundary with typed
  `DelegationViolation` errors.
- **Revocation**: Cascading revocation ensures compromised controllers
  immediately invalidate dependent machines.
- **Privacy**: Personal data is never stored on-chain; only hashes and
  cryptographic commitments.

---

## 5. Verifiable Credentials

`did:tenzro` subjects may be the subject of W3C VC Data Model v2.0
credentials: KYC certifications, audits, ratings and capability grants. A
credential is signed by its issuer's hardware key or passkey with an
`ecdsa-jcs-2019` Data Integrity proof, the issuer's DID must derive from that
key, and revocation is a Bitstring Status List entry signed by the same
issuer. Any issuer may issue; relying parties decide which issuers they
recognize in their own trust lists. The credential model, revocation and
trust lists are specified in [TRUST.md](TRUST.md).

---

## 6. Conformance

An implementation conforms to this specification if it:

1. Parses DIDs matching the ABNF in §2 (via `TenzroDid::parse()`).
2. Produces DID Documents compliant with W3C DID Core 1.0 (via `identity_to_did_document()`).
3. Implements the CRUD operations in §3 with the RPC method names given.
4. Rejects operations that violate delegation scope at the RPC boundary (via `IdentityRegistry::enforce_operation()` returning typed `DelegationViolation`).
5. Implements revocation as a consensus transaction (`RevokeIdentity`), cascading to delegated agents on chain and to controlled machines in each node's registry (via `IdentityRegistry::revoke_from_chain()`).

---

## 7. Contact

- **Specification**: this document (https://github.com/tenzro/tenzro-network/blob/main/docs/did-method-tenzro.md)
- **Implementation**: https://github.com/tenzro/tenzro-network (`crates/tenzro-identity`)
- **Issues**: https://github.com/tenzro/tenzro-network/issues
- **W3C Working Group**: W3C Credentials Community Group

---

## 8. W3C Registration Submission

This document constitutes the method specification required by the
[W3C DID Specification Registries policies](https://www.w3.org/TR/did-spec-registries/#did-method-registration-policies).
The submission PR should be filed against
`https://github.com/w3c/did-extensions` adding the following row to the
methods table in `methods.md`:

```
| tenzro | Tenzro Network | https://github.com/tenzro/tenzro-network | https://github.com/tenzro/tenzro-network/blob/main/docs/did-method-tenzro.md | PROVISIONAL |
```

### Registration Checklist

- [x] DID method name chosen and unique (no existing `did:tenzro`)
- [x] Human-readable description provided
- [x] Specification URL reachable and permanent (https://github.com/tenzro/tenzro-network/blob/main/docs/did-method-tenzro.md)
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
- 85 passing unit and integration tests covering DID parsing, delegation enforcement, cascading revocation
- JSON-RPC interface at `https://rpc.tenzro.com` (chain id 0x3444), REST verification API at `https://api.tenzro.com`
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

**Only a TPM 2.0, proven by activation and a quote (section 2.2), admits a machine no human delegated.** No vendor root decides admission. A fused
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
- A machine **nobody delegated** moves on a signature by its own registered
  key over the transfer challenge. For an autonomous machine the TPM *is* the
  accountable party, so a signature from it is the ownership fact — which is the honest model for selling a
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
