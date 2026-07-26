# Tenzro Network threat model

Scope: the Rust workspace (`crates/`), the node's externally reachable
surfaces (P2P gossip, JSON-RPC, web API, MCP, A2A, bridge inbound), and
the trust relationships between them. The desktop app, SDKs, and Python
integration packages consume these surfaces and are out of scope here
except where they widen an attack surface.

## Assets

| Asset | Where it lives | Compromise impact |
|---|---|---|
| Validator signing keys (Ed25519 + ML-DSA-65 + BLS12-381) | `/var/lib/tenzro/` on each validator, fetched at boot by `tenzro-fetch-keys.service` | Consensus equivocation, vote forgery, chain forks |
| Bridge signing keys (secp256k1) | `EvmTransactionSigner` backends: raw env key, TEE-sealed (`SealedSecp256k1Key`), or DKLS23 threshold shares in RocksDB `CF_MPC_KEYSHARES` sealed by `TeeKeyshareSealer` | Unauthorized outbound transfers on connected chains |
| User/agent MPC wallet shares | `tenzro-wallet` keystore (Argon2id-encrypted) | Theft of TNZO and bridged assets |
| Ledger state (balances, staking, escrow, channels) | RocksDB column families (`CF_ACCOUNTS`, `CF_SETTLEMENTS`, `CF_CHANNELS`, ...) | Balance corruption, double-spends |
| TDIP identities + delegation scopes | `CF_IDENTITIES` | Agent impersonation, spend-ceiling bypass |
| Operator admin token | node config / env | Every admin-gated RPC (cross-chain mint/burn, compliance freeze, secure-mint policy) |
| Per-tenant API keys + tenant OAuth client secrets | `ApiKeyRecord` in RocksDB | Canton tenant impersonation, cross-tenant data access |
| TEE attestation trust roots | Pinned vendor root CAs in `tenzro-tee` | Fake attestations → unearned 1.5× consensus weight, fake confidential-tier trainers |

## Actors

| Actor | Capability assumed |
|---|---|
| Anonymous network peer | Can connect over libp2p, publish to gossipsub topics, send arbitrary bytes on request-response protocols and the iroh ALPNs |
| Anonymous RPC client | Can call every non-admin JSON-RPC method on a public RPC node, the web API, MCP tools, and A2A skills |
| Malicious counterparty chain | Can deliver arbitrary bridge messages (VAAs, CCIP reports, Hyperlane/Axelar envelopes, deBridge fills) |
| Byzantine validator (< 1/3 stake) | Signs anything with its own keys: equivocating votes, bad proposals, false training-round endorsements |
| Malicious trainer / provider | Submits crafted gradients, inflated capacity claims, garbage inference results |
| Malicious agent (registered machine DID) | Operates within a delegation scope; tries to exceed it |
| Compromised tenant API key | Full access to that key's scopes; tries lateral movement to other tenants or operator surfaces |
| Malicious operator of a single node | Full control of one node's process, disk, and keys — but not of other validators |

## Trust boundaries

1. **Gossipsub ingress** (`tenzro-network`). Every message on every
   topic is attacker-controlled bytes. Defenses: per-topic peer
   authorization for validator-only topics
   (`peer_manager.rs:386 authorize_peer_for_topic`), gossipsub peer
   scoring, rate limiting, and full signature verification before any
   state transition (votes, blocks, attestations).
2. **JSON-RPC / web / MCP / A2A ingress** (`tenzro-node`). All params
   are untrusted. Admin-only methods gated by
   `rpc.rs:641 requires_admin_token`; Canton tenant methods gated by
   API-key scope; everything else must be safe for anonymous callers.
3. **Bridge inbound** (`tenzro-bridge`). Messages originate on foreign
   chains. Defenses: outer-envelope verification where wired (Wormhole
   guardian quorum `wormhole.rs:329 verify_quorum`, Hyperlane validator
   multisig, Axelar threshold multisig, CCIP OCR + RMN sets), then the
   inner `TenzroMessage` discipline
   (`message_format.rs:449 verify_inner_message`: decode → validate →
   verify_hash → verify_signature → nonce replay check).
4. **Consensus vote ingestion** (`tenzro-consensus`).
   `voter.rs:534 VoteCollector::add_vote` gates format version
   (`VOTE_FORMAT_VERSION = 4`, `voter.rs:53`), the
   `high_qc_view < view` invariant, validator-set membership, and
   composite Ed25519 + ML-DSA-65 + BLS signature validity before a vote
   counts toward a QC. `validator.rs:654 EquivocationDetector` records
   double-votes and drives slashing via `SlashingCallback`.
5. **TEE attestation verification** (`tenzro-tee`). Attestations are
   presented by the party benefiting from them. Defenses: pinned vendor
   root CAs, full X.509 chain verification, ECDSA verification of the
   quote/report body (TDX QE P-256, Nitro COSE ES384), measurement
   checks. Simulation env vars are hard-disabled on the fleet.
6. **Signing-time custody enforcement** (`tenzro-vm` ERC-7579 modules).
   On-chain validator modules (social recovery, session keys, spending
   limits) are the primary control; the off-chain
   `SpendingPolicyResolver` is defence-in-depth only.
7. **Storage trust**. RocksDB contents are trusted (single-operator
   disk); anything hydrated from it is not re-verified. A disk-level
   attacker is equivalent to a malicious node operator.

## Attack surfaces by subsystem

### Consensus (`tenzro-consensus`)
- Crafted `Vote` / proposal bytes over gossip (bincode and JSON
  decoders both reachable). Fuzzed by `fuzz/consensus_vote`.
- Equivocation by a real validator — detected
  (`EquivocationDetector`), evidence persisted in `CF_AUDIT`, slashed
  10% via `StakingSlashingCallback`.
- Leader-selection bias: capability multiplier capped at 1.5×
  (`leader_reputation.rs:135 CAPABILITY_MAX_BPS = 15000`); a fake TEE
  attestation is the way to obtain it illegitimately, which reduces to
  boundary 5.

### Bridges (`tenzro-bridge`)
- Forged VAAs / ISM metadata / OCR reports. Quorum verification is
  fail-closed when a set is installed; **an adapter with no installed
  verifier set skips outer verification** (see Residual risks).
  Fuzzed by `fuzz/wormhole_vaa` and `fuzz/bridge_inner_message`.
- Replay: per-adapter `NonceTracker` (persistent via
  `CF_SETTLEMENTS / bridge_nonce:*`) plus payload-hash dedup.
- Key theft: threshold (DKLS23 t-of-n) and TEE-sealed backends remove
  the single raw key from disk; raw-env-key backend remains for dev.

### Settlement (`tenzro-settlement`)
- Channel-state forgery: strict Ed25519 over the 40-byte canonical
  preimage (`micropayments.rs:505 canonical_message`,
  `:489 verify_signature_with_key`); the payer address is the pinned
  public key. Fuzzed by `fuzz/settlement_channel_state`.
- Escrow authorization: create/release/refund are typed consensus
  transactions with payer-only checks; vault addresses are derived
  (no private key exists).

### Staking / token (`tenzro-token`)
- Arithmetic: all stake/slash/unstake and liquid-staking pool math is
  checked or quotient/remainder-decomposed u128. Fuzzed by
  `fuzz/staking_arithmetic`.
- Governance: stake-weighted; admin-class token mutations
  (secure-mint policy, compliance) require the operator admin token.

### Transactions (`tenzro-types` + `tenzro-node`)
- Decoder/hash/validator totality on arbitrary JSON
  (`transaction.rs:102 hash`, `:501 validate`). Fuzzed by
  `fuzz/transaction_decode`.
- Signature verification is synchronous on every submission path
  (`eth_sendRawTransaction`, `tenzro_signAndSendTransaction`, MCP
  `send_transaction`) — invalid signatures return `-32003`.

### Cross-chain intents (`tenzro-types::intent_7683`)
- uint256 → u128 truncation: `intent_7683.rs:350 uint256_be_to_u128`
  rejects non-zero high 128 bits. Order-id determinism:
  `:324 compute_order_id` (domain-tagged SHA-256). Fuzzed by
  `fuzz/intent_7683`.

### Identity / agents (`tenzro-identity`, `tenzro-agent`)
- Delegation-scope bypass: `enforce_operation` + runtime
  `SpendingPolicy` are both consulted (`IdentityPaymentBinder`);
  ERC-7579 on-chain modules enforce at signing time.
- Credential forgery: Ed25519 verification with recursive trust-chain
  traversal, cycle detection, and trust-root anchoring.

### Training (`tenzro-training`)
- Poisoned gradients: Open tier accepts Mean aggregation only;
  Byzantine-robust rules (TrimmedMean / CoordinateMedian / Krum) are
  tier-gated. Round finalization requires a k-of-N witness committee;
  `finalize_round` is idempotent, and conflicting state roots surface
  as `ConflictingFinalize` for fork detection.

### Generative media (`tenzro-media-gen`)
- Overcharging: the price is a pure function of the posted spec
  (`width × height × steps × frames`), and the requester's ceiling is
  checked at admission rather than after a worker claims, so a worker
  cannot inflate a job it already holds.
- Substituted output: receipts commit to the output's size and SHA-256
  content hash, and the requester verifies fetched bytes against that
  commitment before accepting. A receipt whose spec differs from the
  posted one is rejected, and a completed job cannot be re-completed
  with a different hash.
- Overclaimed work on a split job: the payment division reads
  `steps_completed` from the signed handoff, not from either worker's
  assertion, and a count above the job's total steps is rejected. A
  second handoff cannot displace the first.
- Job-terms substitution: the job id is a domain-tagged hash over the
  whole spec including any conditioning-image hash, and each of the
  three signed stages uses a distinct domain tag, so no signature is
  replayable across stages.
- Unlicensed weights: the node never loads media-gen weights, so
  enrollment is where terms are enforced — a worker declaring a model
  outside the catalog, or one whose license the operator did not
  accept at startup, is refused.

## Residual risks (known, accepted pre-audit)

1. **Bridge outer-envelope coverage is partial.** Wormhole, Hyperlane,
   and Axelar verify their outer envelopes when a validator/guardian
   set is installed; adapters without an installed set fall through to
   inner-message verification only. An operator misconfiguration
   (no set installed) silently weakens a lane.
2. **Training `finalizeRound` trusts coordinator-supplied
   `post_step_hashes`** — they are committed on-chain but not
   recomputed against trainer payloads. Fraud-proof verification of
   these commitments is on the roadmap.
3. **BLS aggregate verification in `tenzro-crypto` uses a SHA-256
   hash-to-curve stub** in some aggregate paths (per-crate docs);
   per-vote composite Ed25519 + ML-DSA-65 verification is the binding
   check today.
4. **Raw-env-key bridge signer backend still exists** for development;
   an operator who deploys with it holds a plaintext secp256k1 key in
   the environment.
5. **A media receipt binds bytes, not fidelity.** The commitment
   proves which bytes the worker produced, not that they are the
   result of running the named model for the named number of steps. A
   worker that renders at lower quality, or a low-noise expert that
   ignores the latent it was handed, produces a receipt that verifies.
   Requester-side rejection and reputation are the checks today;
   proof-of-inference for diffusion is not in scope.
6. **RocksDB contents are trusted on hydration.** A disk-write
   attacker on a validator can inject state; mitigations are host
   hardening, not protocol checks.
7. **No external security audit has been performed yet.** This
   document and `AUDIT_SCOPE.md` exist to scope that engagement.
