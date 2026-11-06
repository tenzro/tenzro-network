# Post-quantum guarantee and AI safety

This note states what Tenzro guarantees against a break of classical
cryptography, what it does not and why, and how an AI agent acting on the
network is bounded. Every claim names the code that enforces it.

## 1. The guarantee

> A break of classical cryptography alone (ECDSA over secp256k1 or P-256,
> Ed25519, X25519) cannot forge a validator vote or certificate, move funds
> from a Tenzro account, forge a bridge committee attestation, or read a
> protected secret that Tenzro wraps.

"Alone" matters: the guarantee holds while the post-quantum primitive of each
path holds. Breaking both legs of a path breaks the path. The exceptions are
listed in section 4; they are places where the verifier is somebody else's
(an external chain, a hardware vendor, a standard).

### Primitives and parameter sets

| Purpose | Primitive | Parameter set | Where |
|---|---|---|---|
| Signatures | ML-DSA (FIPS 204) | ML-DSA-65 by default; ML-DSA-87 for the optional validator scheme | `tenzro-types/src/signature_scheme.rs`, `tenzro-crypto/src/pq.rs` |
| Key encapsulation | ML-KEM (FIPS 203) | ML-KEM-768 | `tenzro-crypto/src/ml_kem768.rs` |
| Hashing, commitments, MACs | SHA-256, SHA-512, Keccak-256, BLAKE3 | 256-bit and above (Grover leaves about 128-bit) | `tenzro-crypto/src/hash.rs` |
| Symmetric encryption | AES-256-GCM | 256-bit keys | `tenzro-crypto/src/encryption.rs` |
| Proofs of finality | STARK (RISC Zero, FRI over hashes) | the receipt's succinct form | `tenzro-zk/src/finality_proof.rs` |
| Stateless one-time signatures | WOTS+ over SHA-256 | Winternitz 16 | channel vouchers (SPECIFICATION section 15.8) |

ML-DSA verification runs two independent implementations (`ml-dsa` and the
formally verified `libcrux-ml-dsa`); a signature is accepted only if both
accept, and a disagreement is an error that halts a validator
(`tenzro-crypto/src/pq.rs`, `tenzro-consensus/src/nversion.rs`). ML-KEM
likewise runs two implementations and refuses the exchange when they differ
(`tenzro-crypto/src/ml_kem768.rs`).

### Composition rule

Where a classical primitive remains, it is paired with a post-quantum one and
**both legs are mandatory**: a signature verifies only if every leg verifies,
a shared secret is derived from every exchange.

- **Signatures.** The composite is a conjunction. Validators sign the LAMPS
  composite `COMPSIG-MLDSA65-ECDSA-P256-SHA512` (or the ML-DSA-87 / P-384
  variant); accounts sign P-256 plus ML-DSA-65 over the transaction hash;
  bridge committee members sign secp256k1 plus ML-DSA-65 over the attestation
  digest. A verifier that sees one leg valid and the other missing or invalid
  refuses.
- **Key agreement and key wrapping.** The secret is
  `HKDF-SHA256(ikm = X25519 secret || ML-KEM-768 secret, salt = SHA-256(domain || recipient key fingerprint || sender X25519 share || ML-KEM-768 ciphertext || context))`,
  domain-separated per use (`tenzro-crypto/src/hybrid_seal.rs`). Reading the
  wrapped value needs both exchanges broken; a changed share, ciphertext or
  context derives a different key. Transport (TLS 1.3 `X25519MLKEM768`) and
  the consensus channels use the same shape (`tenzro-iroh/src/identity_transport.rs`,
  `tenzro-consensus/src/channel.rs`).
- **Proof systems.** The canonical proof is the STARK; the Groth16 wrap over
  BN254 is optional, is labelled classical-assumption wherever it is exposed,
  and is not the default form (`ProofForm::default()` is `Stark`).

## 2. What each path guarantees

| Path | Guarantee | Enforced in |
|---|---|---|
| Validator votes, session certificates, registration, epoch handover | Composite signature, both legs mandatory | `tenzro-finality/src/key.rs` (verify requires both), `tenzro-consensus/src/validator_key.rs`, `tenzro-consensus/src/core.rs` |
| Consensus channels between validators | X25519 + ML-KEM-768 into HKDF, handshake signed by composite session keys | `tenzro-consensus/src/channel.rs` |
| Account transactions and every other message an account signs (payment authorizations, escrow vouchers, payer signatures, settlement preferences, owner-signed RPC actions, smart-account validators, root approvals of agent terms) | P-256 and ML-DSA-65 both required; an account with no ML-DSA-65 key enrolled signs nothing until it enrols one (the first transaction of a new sender is its enrolment; `tenzro pq-hybrid enroll`) | `tenzro-vm/src/account_keys.rs` (`pq_key_for`, `account_pq_policy`), `tenzro-vm/src/runtime.rs`, `tenzro-node/src/event_loop.rs` (`verify_transaction_pq_leg`) |
| Bridge deliveries (inbound to Tenzro) | Each committee member counts only with a valid secp256k1 and ML-DSA-65 signature; a member without an ML-DSA-65 key cannot be seated | `tenzro-bridge/src/route/attestation.rs` (`verify_committee`, `dual_signers`), `tenzro-types/src/bridge_route.rs` |
| Bridge equivocation evidence | Needs both legs of the member on both deliveries | `tenzro-vm/src/native/bridge_committee.rs` (`report_equivocation`) |
| Node-to-node RPC authentication (A2A, MCP, MoE) | Both hardware keys (P-256 and ML-DSA-65) sign the TLS exporter on every connection; a peer without a verified ML-DSA-65 binding is refused both ways | `tenzro-iroh/src/pq_endpoint.rs`, `tenzro-iroh/src/resolver.rs` |
| Key wraps (model content keys, provider content key, node credentials, session continuity, brokered agent credentials) | Envelope version 2, hybrid X25519 + ML-KEM-768 | `tenzro-crypto/src/encryption.rs`, `tenzro-model/src/sealed.rs`, `tenzro-tee/src/key_release.rs`, `tenzro-node/src/credentials.rs` |
| TEE key release | Content key sealed to a hybrid key the attested environment made in memory | `tenzro-crypto/src/hybrid_seal.rs`, `tenzro-tee/src/key_release.rs` |
| Identity | Registration is refused for hardware with no ML-DSA-65 key, and its proof must carry the ML-DSA-65 leg; DID documents (including the node's own) list an ML-DSA-65 method first; KERI logs take ML-DSA-65 keys by default | `tenzro-identity/src/document.rs`, `tenzro-identity/src/w3c.rs`, `tenzro-identity/src/keri.rs` |
| Finality proofs | STARK is the default form | `tenzro-zk/src/finality_proof.rs` |

## 3. Every key and signature use

PQ status: **hybrid** = classical and ML-DSA/ML-KEM both mandatory;
**PQ** = post-quantum only or hash-based; **classical (reason)** = the
verifier is outside Tenzro or the key lives in hardware that has no
post-quantum operation; **symmetric** = a 256-bit symmetric key.

| Use | Key or scheme | PQ status |
|---|---|---|
| Validator checkpoint votes, certificates | ML-DSA-65 + ECDSA P-256 composite (or ML-DSA-87 + P-384), TPM-held | hybrid |
| Validator registration, endpoint announcements | same composite | hybrid |
| Machine records (batch roots, receipts, attestations, announcements) | machine P-256 + ML-DSA-65; the ML-DSA leg is required from `records.pq_leg_required_from_ms` (governed, genesis sets it) | hybrid once the governed time passes; classical before (see section 5) |
| Session keys (stored records) | Ed25519 + ML-DSA-65, certified by the hardware identity | hybrid from `session.hybrid_records_from_ms` |
| Account transactions | P-256 (passkey, TPM, Secure Enclave) + ML-DSA-65 | hybrid |
| EVM-standard transactions (`TransactionType` external) | secp256k1 ECDSA, verified by the EVM standard | classical (external standard); see section 4 |
| Passkey assertions (WebAuthn) | P-256 | classical (authenticator limit), paired with the ML-DSA-65 leg on accounts |
| Bridge committee attestations | secp256k1 + ML-DSA-65 per member, Keccak digest | hybrid |
| Bridge outbound records, committee handovers | secp256k1 only, because the contract on the external chain verifies them | classical (external verifier) |
| Bridge light clients (Ethereum BLS sync committee, Tendermint Ed25519, Bitcoin, Solana, Stellar, Sui, Aptos, TON) | each chain's own signatures | classical (external chain), capped by `NetworkMintLimits::classical` |
| Node-to-node transport key exchange | `X25519MLKEM768` | hybrid |
| Node-to-node authentication (RPC ALPNs) | iroh Ed25519 + P-256 + ML-DSA-65 over the TLS exporter | hybrid |
| Node-to-node authentication (block sync, state sync, gossip, blobs, inference requests) | iroh Ed25519 under the hybrid key exchange | classical authentication (see section 5) |
| Consensus channels | X25519 + ML-KEM-768 + composite session signatures + BLAKE3 MACs | hybrid |
| Hybrid seal / key release | X25519 + ML-KEM-768 into HKDF-SHA256, AES-256-GCM | hybrid |
| Key wraps at rest | envelope v2, X25519 + ML-KEM-768 | hybrid |
| Wallet keystore | Argon2id + AES-256-GCM | symmetric |
| Agent HTTP signatures (RFC 9421) | P-256 in the serving machine's TPM | classical (RFC 9421 verifiers outside Tenzro) |
| Agent actions on chain (`AgentAct`) | serving node's hardware key for the agent; root approval is the controller's passkey or TPM key | hybrid where the keystore enrolled ML-DSA-65 (`RequireAgentPqLeg`) |
| Identity rotation | `PqRotation` moves the governing key to ML-DSA-65 | PQ |
| DID documents (including the node's own) | ML-DSA-65 method listed first | hybrid |
| KERI events | ML-DSA-65 keys by default; Ed25519 only in an interoperating log | PQ (default) |
| Finality proofs | STARK | PQ (hash-based) |
| Finality proof, Groth16 wrap | BN254 pairing | classical (discrete log); optional, for EVM verifiers |
| Hash commitments, Merkle trees, VRF output mixing | SHA-256, Keccak-256, BLAKE3; Ed25519 VRF mixed with a hash commit-reveal | PQ (hash); the VRF alone is classical, the beacon keeps its hash secret |
| Channel vouchers on other chains | WOTS+ over SHA-256 under a Merkle root | PQ (hash-based) |
| Release signing | cosign with a hardware (PKCS#11) key | classical (toolchain) |
| TPM / Secure Enclave attestation | vendor P-256 / RSA certificate chains | classical (vendor roots) |

## 4. What stays classical, and why

1. **Hardware attestation roots.** A TPM endorsement certificate, a Secure
   Enclave attestation and a TEE quote are signed by the vendor with RSA or
   ECDSA. Tenzro verifies them (`tenzro-tee/src/tpm_attest.rs`) and cannot
   change the vendor's algorithm. They bind a machine to a key; the key's use
   on Tenzro is hybrid. A party that forges a vendor chain can claim a machine
   is genuine hardware. It still cannot sign for that machine's ML-DSA key.
2. **The P-256 leg of hardware keys.** TPM 2.0 and the Secure Enclave sign
   P-256 natively. The ML-DSA leg is derived on demand from the same hardware
   root (`tenzro-device-key/src/derive.rs`). The composite pairing is what
   makes the pair safe: breaking P-256 yields half a signature.
3. **External chains' own signatures.** Tenzro's acceptance of a bridge
   delivery is post-quantum (section 2). The external chain's finality (ECDSA,
   Ed25519, BLS12-381) is not Tenzro's to change. The classical ceiling
   (`NetworkMintLimits::classical`, defaults 500 TNZO per mint and 2,000 per
   epoch) bounds what a forged source chain can mint; each route's residual
   dependency is tabulated in `docs/BRIDGE.md`. Outbound records and handovers
   are verified by contracts on those chains with secp256k1.
4. **EVM-standard transactions.** A transaction type defined by an external
   standard (an Ethereum-style transaction signed with secp256k1) is verified
   by that standard (`tenzro-node/src/event_loop.rs`,
   `tx_type.is_external()`). Funds held at an address controlled only by a
   secp256k1 key are protected by secp256k1. A holder who wants the guarantee
   uses a native account.
5. **WebPKI certificates.** RPC and MCP endpoints presented to browsers use
   classical certificates; the key exchange offered first is hybrid.
6. **Release signing and published checksums.** Signing uses a hardware key
   through the toolchain (`scripts/supply-chain/release.sh`).

## 5. What is closed, and what remains

### Closed

- **Account-signed messages beyond transactions.** Payment authorizations,
  escrow vouchers, payer signatures (`tenzro-payments/src/payer_auth.rs`),
  settlement preferences and the owner signature that authorizes an RPC
  action on an address (`require_address_owner`) verify under `PqPolicy::Required`, as do the identity-key and passkey
  smart-account validators and the root approvals of agent terms, step-ups,
  revocations and remote grants. An account with no ML-DSA-65 key enrolled
  signs none of these until it enrols one. The identity-key validator also
  refuses to bind a key that has no ML-DSA-65 key, since no signature could
  satisfy it.
- **Identity registration.** `RegisterIdentity` is refused unless the
  registration names an ML-DSA-65 key (or the controller has one enrolled)
  and the proof carries an ML-DSA-65 leg that verifies against it. The
  registry mirror refuses a replicated record with no ML-DSA-65 key. A
  machine whose hardware root cannot derive an ML-DSA-65 key does not
  register.
- **The node's own DID document** lists the machine's ML-DSA-65 key as
  `#pq-key-1`, ahead of the classical methods, like every other DID document.
- **Where an account's ML-DSA-65 key comes from.** A TPM cannot hold ML-DSA
  unless it implements TPM 2.0 library v1.85, and most do not. Where the
  hardware implements ML-DSA, the key is created and used inside it. On every
  other machine (and on a TPM-less machine that delegates to a TPM machine) the
  key is derived from the machine's hardware-held derivation root for each
  operation and wiped after it, under the label `<account key label>/ml-dsa-65`:
  nothing is stored, the same machine always derives the same key, and without
  the hardware there is no key. This is the way the consensus and machine
  identity ML-DSA-65 keys are made. A validator's node account therefore has a
  key to enrol on any machine with a hardware root, and its first transaction
  is the enrolment.
- **Where an account's ML-DSA-65 key comes from.** A TPM cannot hold ML-DSA
  unless it implements TPM 2.0 library v1.85, and most do not. Where the
  hardware implements ML-DSA, the key is created and used inside it. On every
  other machine (and on a TPM-less machine that delegates to a TPM machine) the
  key is derived from the machine's hardware-held derivation root for each
  operation and wiped after it, under the label `<account key label>/ml-dsa-65`:
  nothing is stored, the same machine always derives the same key, and without
  the hardware there is no key. This is how the consensus and machine identity
  ML-DSA-65 keys are made. A validator's node account therefore has a key to
  enrol on any machine with a hardware root, and its first transaction is the
  enrolment.
- **Enrolment helpers.** The Rust, TypeScript and Python SDKs each have
  `send_enrolling` / `sendEnrolling`, which enrols the hardware's ML-DSA-65 key
  when a node answers that none is enrolled and sends the transaction again.

### Remaining

- **`records.pq_leg_required_from_ms`.** The default in
  `tenzro-vm/src/governance.rs` is never; the launch genesis must set it to
  zero once every launch machine holds ML-DSA-capable hardware. Machine
  records still verify under `PqPolicy::WhenPresent` until then: usage
  records and meter bond consent (`tenzro-vm/src/native/meter_bond.rs`),
  reserve attestations and sensor readings (`tenzro-vm/src/native/evidence.rs`,
  `tenzro-node/src/rpc.rs`), batch roots (`tenzro-crypto/src/batch.rs`),
  session keys (`tenzro-crypto/src/session.rs`), trust policy attestors
  (`tenzro-trust/src/policy.rs`) and TEE identity evidence
  (`tenzro-tee/src/identity_evidence.rs`, machine attestation records).
  Flipping these needs the machine side to sign with the leg first.
- **Duty handover proofs.** `HandoverDuty` takes a Groth16 seal
  (`tenzro-types/src/duty.rs`); a STARK-verified duty needs a consensus rule
  and a change to the finality guest, which this change does not touch.
- **TEE finality attestation.** `tenzro_attestFinalityProof` binds a Groth16
  wrap (`tenzro-node/src/zk_rpc.rs`); binding a STARK needs the report-data
  layout changed in `tenzro-zk`.
- **EVM external transactions** (section 4, item 4): a secp256k1 transaction
  is verified by the EVM standard and carries no ML-DSA-65 leg.
- **Authentication on the other protocols.** Block sync, state sync, gossip,
  blobs and inference requests have no versioned ALPN that carries the
  ML-DSA proof yet; they authenticate with the iroh Ed25519 key under the
  hybrid key exchange.
- **Verifiers that check the ML-DSA-65 leg only when the key has one.** These
  still use `PqPolicy::WhenPresent`: the device-signature check of sensor
  evidence (`tenzro-vm/src/native/evidence.rs`), usage records of metered
  bonds (`meter_bond.rs`), reserve attestations (`token.rs`), signed sealed-model
  manifests (`tenzro-model/src/sealed.rs`), identity envelopes
  (`tenzro-identity/src/envelope.rs`), session certificates, the operator
  binding in `tenzro-trust`, the admin audit log, and the read-only
  `tenzro_verifySignature`. A key that carries no ML-DSA-65 leg is accepted
  there. Moving each to `Required` needs its signers to hold an enrolled key.
- **Wrong-handover evidence** (`report_wrong_handover`) checks the secp256k1
  signature the external contract verifies; it does not require the ML-DSA
  leg, so a party that forges secp256k1 signatures could frame a committee
  member by reporting a handover it never signed. Closing it needs a
  committee handover format that carries both legs.
- **The node DID document's proof** is a P-256 Data Integrity proof by the
  machine key; the ML-DSA-65 method is listed in the document the P-256 proof
  covers, and the document carries no ML-DSA-65 signature of its own.

## 6. AI safety

An AI agent on Tenzro is a delegate, not a principal. The properties below
are enforced by chain state and by validators, not by the agent's prompt.

### 6.1 Agent actions are bounded by delegated capabilities

- An agent acts under **terms** approved by its controller: a human's passkey
  or an autonomous machine's TPM or Secure Enclave key (`RootKind`,
  `tenzro-types/src/agent_terms.rs`). `SetAgentTerms` records them; every
  validator re-verifies the root's signature over the custody challenge for
  exactly those terms (`tenzro-vm/src/native/agent_terms.rs`).
- Terms carry **capabilities, spend caps and expiry**: per-payment and daily
  limits (`max_daily_spend`, asset limits), allowed counterparties, remote
  limits per external chain, a delegation scope and `expires_at_ms`.
- `AgentAct` is one action. It executes only when the signing node is
  assigned in the current terms and `check_action`
  (`tenzro-types/src/agent_terms.rs:1224`) passes: capability present, amount
  within the per-action and daily limits (the running daily total is chain
  state, so every node sees the same spend), terms unexpired, agent neither
  revoked nor quarantined.
- **Step-up.** An action to a new counterparty, or above a limit, needs the
  controller's passkey again; an action marked `tainted` (derived from
  untrusted input) is held to the terms' `tainted_value_limit`, which is zero
  when unset (`step-up required: untrusted input, amount` and
  `..., new counterparty`, `check_action`). A change to the terms moves only
  the limits the controller's pre-approved bounds name and never loosens a
  term they do not (`within_bounds`); anything else needs the root's approval
  again.
- The **lethal trifecta** is refused at the terms: an agent cannot be granted
  private-data access, untrusted input and external egress together without
  an explicit exception the root approved (`check_trifecta`,
  `tenzro-types/src/agent_terms.rs:567`).

### 6.2 Agents never hold raw keys

- The agent's signing key is a P-256 key held in the TPM of each serving
  machine, derived from a label over the agent and the machine, certified by
  the TPM, and approved by the controller in the on-chain terms
  (`serving_nodes[].dpop_public_key`). It never leaves the chip and the
  agent's process never sees it (`tenzro-node/src/agent_delegation.rs`,
  `answer_key_request`; docs/AGENT_TRUST.md).
- Third-party credentials an agent uses are sealed to the serving node's
  hybrid key and attached by the node's egress guard to requests to the host
  the terms name; the agent holds the capability to use them, not the secret
  (`tenzro-node/src/egress_guard.rs`).
- The root key is a human passkey or a TPM key; no key exists in software
  that could be copied into a model's context.

### 6.3 Tool and MCP outputs are data

- Content from outside (a fetched page, a tool result, an MCP response) is
  labelled on the node (`tenzro-node/src/agent_guardrails.rs`: an operation
  that brings in untrusted input labels the agent, and for `TAINT_HOLD_MS`
  (one hour) its actions count as derived from it). The label sets
  `AgentAction.tainted`, which turns on the untrusted-input step-up and value
  limit above.
- The runtime never executes a model's output as protocol. A tool result can
  change what an agent asks for; what the agent may do is the terms.

### 6.4 No model output alters consensus or settlement unproven

- Consensus processes signed transactions and certified checkpoints; nothing
  in `tenzro-consensus` or `tenzro-vm` consumes model text.
- An inference result is paid on a **receipt** signed with a hybrid session
  key the provider's hardware identity certified. Settlement of a disputed
  result is by re-execution on independent providers and validator
  attestation, not by anything the model said
  (`tenzro-vm/src/native/inference_fault.rs`).
- Evidence a settlement or a release rests on is a signature, a TPM or TEE
  quote, or a STARK (`tenzro-vm/src/native/evidence.rs`); a sensor reading is
  accepted only with the device's hybrid signature.

### 6.5 Slashing and dispute paths

| Misbehaviour | Path | Code |
|---|---|---|
| Provider returns an answer other providers do not reproduce | A fault is filed with the signed receipt; validators re-execute; once two thirds of bonded stake attest, the compute bond refunds the requester and pays a penalty to the insurance pool | `tenzro-vm/src/native/inference_fault.rs` |
| Catalog or model publisher misrepresents a model | Catalog fault, `catalog.fault_slash_bps` of publisher stake | `tenzro-vm/src/native/inference_fault.rs` |
| Agent misbehaves or is compromised | Controller revocation and validator quarantine; every node refuses an agent chain state records as revoked or quarantined; per-epoch audit-trail commitments let an evidence pack prove entries | `tenzro-vm/src/native/agent_audit.rs`, `tenzro-vm/src/native/agent_terms.rs` |
| Bridge committee member signs two deliveries for one nonce | Equivocation report (both legs of the member on both deliveries); `bridge.equivocation_slash_bps` of its attestor stake is taken, the committees are emptied for a new draw | `tenzro-vm/src/native/bridge_committee.rs` (`report_equivocation`) |
| Committee member signs a handover to a committee the chain did not draw | Wrong-handover report, same slash and reset | `tenzro-vm/src/native/bridge_committee.rs` (`report_wrong_handover`) |
| A route misbehaves | Circuit breaker: validators holding two thirds of stake pause a route on a finding; governance disables or pauses | `tenzro-vm/src/native/bridge_circuit.rs` |
| Agent's serving node over-claims | The oversight record is public state (`tenzro_getAgentQuarantine`, revocations, audit commitments); standing is the bond and the slashes against it | docs/AGENT_TRUST.md |

The limits that bound an agent's damage are therefore in three layers: the
terms (what the agent may do), the bonds (what a provider or attestor loses),
and the breakers (what a route or the network stops doing when a finding
lands).
