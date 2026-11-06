# Tenzro Network threat model

Scope: the Rust workspace (`crates/`), the node's externally reachable
surfaces (P2P gossip, JSON-RPC, web API, MCP, A2A, bridge inbound), and
the trust relationships between them. The desktop app, SDKs, and Python
integration packages consume these surfaces and are out of scope here
except where they widen an attack surface.

## Assets

| Asset | Where it lives | Compromise impact |
|---|---|---|
| Validator consensus keys (composite ML-DSA-65 + P-256) | nowhere at rest: the P-256 leg is a TPM or Secure Enclave key; the ML-DSA-65 leg is derived per use from the validator's TPM (a TPM-generated HMAC key usable only with a fresh signature by the machine's endorsement-certified attestation key) or Secure Enclave, and wiped after use | Checkpoint equivocation (slashable), forged checkpoint votes |
| Bridge signing keys (secp256k1) | a hardware wallet (Ledger, Trezor, GridPlus) behind `EvmTransactionSigner::from_hardware`; no raw-key backend exists | Unauthorized outbound transfers on connected chains |
| User/agent wallet keys | the holder's passkey, TPM or Secure Enclave; the node keeps watch-only bindings and mints no keys | Theft of TNZO and bridged assets |
| Ledger state (balances, staking, escrow, channels) | RocksDB column families (`CF_ACCOUNTS`, `CF_SETTLEMENTS`, `CF_CHANNELS`, ...) | Balance corruption, double-spends |
| TDIP identities + delegation scopes | `CF_IDENTITIES` | Agent impersonation, spend-ceiling bypass |
| Node access policy and the access-token signing key | `access.toml`; key derived from the node's hardware root | Every admin-class RPC (cross-chain mint/burn, compliance freeze) |
| TEE attestation trust roots | Pinned vendor root CAs in `tenzro-tee` | Fake attestations → confidential-tier work served outside a TEE |

## Actors

| Actor | Capability assumed |
|---|---|
| Anonymous network peer | Can connect over iroh, publish to gossip topics, send arbitrary bytes on the iroh ALPNs |
| Anonymous RPC client | Can call every non-admin JSON-RPC method on a public RPC node, the web API, MCP tools, and A2A skills |
| Malicious counterparty chain | Can deliver arbitrary bridge deliveries on any route (CCIP-envelope messages, IBC packets, contract-route events) |
| Byzantine validator (< 1/3 stake) | Signs anything with its own keys: equivocating votes, bad proposals |
| Malicious provider | Submits inflated capacity claims, garbage inference results |
| Malicious agent (registered machine DID) | Operates within a delegation scope; tries to exceed it |
| Stolen access token | Useless without the DPoP key it is bound to; with it, what the policy admits the DID to until expiry or revocation |
| Malicious operator of a single node | Full control of one node's process, disk, and keys — but not of other validators |

## Trust boundaries

1. **Gossip ingress** (`tenzro-iroh gossip`, `tenzro-network
   gossip_validation`). Every message on every topic is
   attacker-controlled bytes. Defenses: checks before a message is
   delivered or passed on (size, decoding, timestamps), per-neighbour
   scoring with bans that close and refuse the neighbour's gossip
   connections, rate limiting, and full signature verification before
   any state transition (blocks, certificates, announcements).
2. **JSON-RPC / web / MCP / A2A ingress** (`tenzro-node`). All params
   are untrusted. Every call passes the access policy; admin-class methods
   admit only the operator DID and policy admins; everything an open policy
   admits must be safe for anonymous callers.
3. **Bridge inbound** (`tenzro-bridge::route`). Deliveries originate on
   foreign chains. One framework applies every defence on every route:
   strict canonical decoding, committee (and blessing committee) quorum
   over a digest binding chain id, route, nonce and expiry, single-use
   nonces in consensus state, the circuit breaker, caps, and the supply
   invariant.
4. **Consensus channels and certificates** (`tenzro-consensus`).
   A channel opens only with a committee member at its registered
   endpoint after both ends prove their hardware keys
   (`channel.rs`); every frame is MAC'd and bounded-decoded
   (`wire.rs Frame::decode`). A checkpoint vote counts only if its
   composite ML-DSA-65 + P-256 signature verifies under a committee
   key (`checkpoint.rs VoteCollector::add`), and a certificate needs a
   quorum of seats (`Certificate::verify`). Two signatures on different
   checkpoints with one index are evidence, recorded on chain by
   `ReportCheckpointEquivocation` and slashed on replay.
5. **TEE attestation verification** (`tenzro-tee`). Attestations are
   presented by the party benefiting from them. Defenses: pinned vendor
   root CAs, full X.509 chain verification, ECDSA verification of the
   quote/report body (TDX QE P-256, Nitro COSE ES384), measurement
   checks. Simulation env vars are hard-disabled on the fleet.
6. **Signing-time custody enforcement** (`tenzro-vm` ERC-7579 modules).
   On-chain validator modules (social recovery, session keys, spending
   limits) gate an account's own operations; a delegated agent's authority
   is its consensus Terms.
7. **Storage trust**. RocksDB contents are trusted (single-operator
   disk); anything hydrated from it is not re-verified. A disk-level
   attacker is equivalent to a malicious node operator.

## Attack surfaces by subsystem

### Consensus (`tenzro-consensus`)
- Crafted frames from a committee member: bounded `Frame::decode`,
  then the protocol core. Fuzzed by `fuzz/consensus_frame`.
- An equivocating vertex author: the reliable broadcast delivers one
  digest or none to honest validators.
- A signer of two checkpoints with one index: evidence is recorded
  on chain once and slashed 5% (15% when correlated) into the
  insurance pool in consensus state.
- Leader-selection bias: the schedule is seats times observed
  behaviour, seeded from the committed prefix; no self-reported value
  (including TEE attestation) enters it, and stake split across many
  validators earns no extra seats.

### Bridges (`tenzro-bridge`)
- Forged deliveries. Every route requires its committee quorum (and on
  CCIP routes the blessing committee's) over a digest bound to this chain,
  the route, the nonce and an expiry; decoding is strict and canonical.
  Fuzzed by `fuzz/bridge_route_delivery`.
- Replay: each delivery nonce is recorded in consensus state
  (`bridge_nonce:<route>:<nonce>`) and refused for good once used.
- Key theft: the bridge signer is a raw secp256k1 key from operator
  config, which neither a TPM nor a Secure Enclave can hold. Hardware
  custody for EVM chains is a P-256 hardware key controlling a P-256 smart
  account on the destination chain.

### Settlement (`tenzro-settlement`)
- Channel-state forgery: strict Ed25519 over the 40-byte canonical
  preimage (`micropayments.rs:505 canonical_message`,
  `:489 verify_signature_with_key`); the payer address is the pinned
  public key. Fuzzed by `fuzz/settlement_channel_state`.
- Escrow authorization: create/release/refund are typed consensus
  transactions with payer-only checks; vault addresses are derived
  (no private key exists).

### Staking / token (`tenzro-vm` native executors)
- Arithmetic: bond additions are checked u128 and slashes are
  quotient/remainder-decomposed basis-point shares of the bond.
- Governance: stake-weighted; admin-class compliance mutations require a
  node administrator. Reserve-backed mints are decided in consensus by
  bonded attestors' signed attestations, never by a node setting.

### Transactions (`tenzro-types` + `tenzro-node`)
- Decoder/hash/validator totality on arbitrary JSON
  (`transaction.rs:102 hash`, `:501 validate`). Fuzzed by
  `fuzz/transaction_decode`.
- Signature verification is synchronous on every submission path
  `send_transaction`) — invalid signatures return `-32003`.

### Identity / agents (`tenzro-identity`, agent Terms in `tenzro-vm`)
- Authority bypass: every payment path asks the agent's consensus Terms
  (`check_agent_payment`) and the VM checks every `AgentAct`; no node keeps a
  second authority store (`agent_authority.rs` gate test).
- Credential forgery: Ed25519 verification with recursive trust-chain
  traversal, cycle detection, and trust-root anchoring.

### Generative media
- Overcharging: a render is metered from its parameters
  (`width × height × steps × frames`) against the node's published rate
  card, the same path every other modality is metered through.
- Substituted output: the receipt commits to the output's size, SHA-256
  and perceptual fingerprint, and a re-render on another provider that
  disagrees beyond the committed tolerance is an inference fault that
  refunds the caller from the provider's bond.
- Unlicensed weights: loading refuses a model outside the catalog, or one
  whose licence the operator did not accept at startup, and checks every
  file against its catalog hash.

## Residual risks (known, accepted pre-audit)

1. **Bridge routes trust their committees.** Until light clients are
   installed for a chain family, a route's safety rests on its committee
   quorum (bounded by the caps, the breaker and the supply invariant).
2. **Raw-env-key bridge signer backend still exists** for development;
   an operator who deploys with it holds a plaintext secp256k1 key in
   the environment.
3. **A media receipt binds bytes, not fidelity.** The commitment
   proves which bytes the provider produced, not that they are the
   result of running the named model for the named number of steps.
   Only a re-render that disagrees beyond the tolerance exposes it;
   proof of inference for diffusion is not in scope.
5. **RocksDB contents are trusted on hydration.** A disk-write
   attacker on a validator can inject state; mitigations are host
   hardening, not protocol checks.
6. **No external security audit has been performed yet.** This
   document scopes that engagement.
