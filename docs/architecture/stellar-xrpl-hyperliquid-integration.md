# Stellar + XRPL + Hyperliquid Integration Architecture

**Status:** Draft — pre-implementation design
**Date:** 2026-06-02
**Author:** Tenzro Network protocol team
**Companion docs:**
- `docs/architecture/cross-vm-token-architecture.md` — TNZO pointer model
- `docs/architecture/interop.md` — bridge router design + adapter contract
- `docs/protocol-research-2026-05/ap2-v02.md` — mandate envelope
- `docs/protocol-research-2026-05/stripe-spt.md` — closed-network primitive precedent

## Why

Three institutional-tokenization rails matter for agents in 2026 that are not currently covered by Tenzro's `MultiVmRuntime` (EVM + SVM + DAML):

| Rail | Institutional thesis | Live state (2026-Q2) |
|---|---|---|
| **Stellar / Soroban** | Announced market-utility partnership to tokenize trillions of dollars of custodied assets; tokenized money-market funds already on-chain; >$2B in RWAs; "Whisk" upgrade brought parallel execution to Soroban contracts | Market-utility infra integration H1 2027. Meridian 2026 in Q3 targets 15 "transformational enterprise" onboardings. |
| **XRPL (mainline + EVM sidechain)** | RLUSD ($1.2B circulating, NYDFS chartered) bridged to L2s via Wormhole NTT; XLS-33 Multi-Purpose Tokens for fractionalised RWAs; XLS-85 Token Escrow now extended to IOUs and MPTs (Feb 2026); XRPL EVM Sidechain on Cosmos SDK + IBC (mainnet June 2025) | Mainline: live, used. EVM sidechain: live, slow adoption (~$120M TVL, sidechain revenue tiny). |
| **Hyperliquid (HyperEVM + HyperCore)** | 170+ projects on HyperEVM; ~$9M/mo HYPE burned; HyperCore on-chain CLOB with ~0.07s finality and 200k+ TPS; Unit Protocol bridges BTC/ETH for institutional-grade trading | Live. Different category: trading/derivatives, not RWA. |

The agent UX claim — **one DID, one MPC wallet, many rails** — only holds if the protocol can dispatch transactions to these chains on the agent's behalf, with the same `DelegationScope` + AP2-mandate + ERC-7579-validator envelope used elsewhere.

This document maps out how to do that without breaking the `MultiVmRuntime` invariant.

## The crucial architectural distinction

`MultiVmRuntime` is **local execution on the Tenzro ledger**. EVM, SVM, and DAML run inside Tenzro validators. Stellar / XRPL / Hyperliquid run on their own validator sets, with their own consensus, on their own L1s.

**Bolting Stellar/XRPL/Hyperliquid runtimes into `MultiVmRuntime` is wrong:**
- It would duplicate work Stellar/XRPL/Hyperliquid validators are already doing.
- Tenzro can't replay external chain state without a full light-client follower per chain (massive scope creep).
- Soroban contracts and XRPL native ops are useless without the rest of the Stellar/XRPL state.

**The right answer is the same one we use for Ethereum L1, Solana mainnet, Base, etc.** — these are **destination chains**, not local VMs. The agent's MPC wallet **signs FOR** them; the protocol does **not execute** them.

So the work goes into `tenzro-bridge` (adapter layer), `tenzro-payments` (mandate envelope), and `tenzro-identity` (`allowed_chains` whitelist), not into `tenzro-vm`.

## State-of-the-art reference: NEAR Chain Signatures

NEAR shipped the SOTA pattern in 2024 and it has held up: **one home account, derivation paths, MPC ceremony, target-chain signature**.

```
home_account: tenzro_did                     (Tenzro DID — controls the key share)
        │
        ├── derive("stellar:1")     → Stellar address (Ed25519)
        ├── derive("xrpl:1")        → XRPL classic address (Ed25519 or secp256k1)
        ├── derive("xrpl_evm:1")    → XRPL EVM sidechain (secp256k1, EIP-1559)
        ├── derive("hyperevm:1")    → HyperEVM (secp256k1, EIP-1559)
        ├── derive("ethereum:1")    → Ethereum L1
        ├── derive("base:1")        → Base
        └── ...
```

NEAR's MPC uses **additive HD key derivation**: `sk_target = sk_home + e`, where `e = H(home_account, derivation_path)`. Public, deterministic, reproducible. The same `home_account + path` always produces the same target-chain address. **This is what we need.**

Tenzro already has the threshold-signing primitive (`tenzro_bridge::mpc::sign::ThresholdSigner` + DKLS23 driver shipped in Phase D wave 2). What we don't yet have is the **derivation layer** that turns one TDIP identity into many target-chain addresses.

## Tenzro adaptation

### Layer 1 — Derivation (`tenzro-identity` extension)

Add a derivation function that takes the TDIP DID's key share and a target-chain path, returning a deterministic target-chain address.

```rust
// crates/tenzro-identity/src/derivation.rs (new module)

pub struct ChainDerivation {
    home_did: String,           // "did:tenzro:machine:0x..."
    path: String,               // "stellar:1", "xrpl:1", "hyperevm:1"
}

impl ChainDerivation {
    /// Additive HD derivation: target_pk = home_pk + H(home_did || path) * G
    pub fn derive_target_pubkey(
        &self,
        home_pk: &PublicKey,
        curve: TargetCurve,           // Ed25519 | Secp256k1
    ) -> Result<TargetPublicKey>;

    /// Target-chain address from derived pubkey (Stellar StrKey, XRPL r-address,
    /// EVM 0x-address, etc.)
    pub fn derive_target_address(&self, target_pk: &TargetPublicKey) -> Result<String>;
}
```

The MPC ceremony for the **actual signature** still happens via `ThresholdSigner` — derivation just computes the target pubkey/address up front so the agent can quote, audit, and pre-fund.

**Curve mapping:**
- `Stellar` → Ed25519 (StrKey `G...` for accounts, `C...` for contracts)
- `XRPL classic` → Ed25519 (default in `xrpl.js`; secp256k1 supported by `wallet_propose`)
- `XRPL EVM sidechain` → secp256k1 (standard EVM)
- `HyperEVM` → secp256k1 (standard EVM)
- `HyperCore` → secp256k1 (HyperEVM-derived; HyperCore uses HyperEVM accounts via precompile)

### Layer 2 — Adapters (`tenzro-bridge` extension)

Three new adapter crates, all implementing the existing `BridgeAdapter` trait.

#### `StellarAdapter`

```rust
// crates/tenzro-bridge/src/stellar/mod.rs
pub struct StellarAdapter {
    horizon_url: String,           // Horizon REST API (legacy classic ops)
    soroban_rpc_url: String,       // Soroban-RPC (smart contract calls)
    network_passphrase: String,    // "Public Global Stellar Network ; September 2015"
    signer: Arc<dyn ThresholdSigner>,
    derivation: ChainDerivation,
}
```

Operations:
- **Classic payment** (`PaymentOp`) — for native XLM / classic assets / SEP-24 anchor flows
- **Asset issuance + trustlines** — for white-labelled stable issuance
- **Soroban contract invocation** — `InvokeHostFunctionOp` with `SorobanAuthorizationEntry` tree
- **SEP-10 auth** — challenge-response handshake to obtain anchor JWT (when interacting with anchors)
- **SEP-24 deposit/withdraw** — hosted on/off-ramp via interactive popup

**Soroban auth model (critical):** Soroban uses an explicit **authorization entry tree** (`SorobanAuthorizationEntry`) rooted at the invocation. When the Tenzro agent's derived address **is** the source account, source-account auth is sufficient (the tx signature implicitly authorises the invocation tree — `sorobanCredentialsSourceAccount`). When the agent needs to authorise calls on behalf of **another** address (rare in our model), full auth-entry signing is needed.

Tx envelope:
- Build `TransactionEnvelope` (XDR-encoded)
- Hash with network passphrase: `SHA-256(network_id || tx_envelope_type || tx_body)`
- Sign 32-byte hash via `ThresholdSigner::sign_prehash` (Ed25519 path)
- Append decorated signature to envelope
- Submit via Horizon `POST /transactions` or Soroban-RPC `sendTransaction`

#### `XrplAdapter`

```rust
// crates/tenzro-bridge/src/xrpl/mod.rs
pub struct XrplAdapter {
    rippled_ws_url: String,        // wss://xrplcluster.com or operator-owned node
    network: XrplNetwork,          // Mainnet | Testnet | Devnet
    signer: Arc<dyn ThresholdSigner>,
    derivation: ChainDerivation,
}
```

Operations:
- **`Payment`** — native XRP transfers, IOU trustline transfers, cross-currency paths
- **`TrustSet`** — establish a trustline (required to hold issued assets)
- **`OfferCreate` / `OfferCancel`** — XRPL DEX
- **`EscrowCreate` / `EscrowFinish` / `EscrowCancel`** — incl. XLS-85 Token Escrow (live since Feb 2026, covers IOUs + MPTs, not just XRP)
- **`MPTokenIssuanceCreate` / `MPTokenIssuanceSet` / `MPTokenAuthorize`** — XLS-33 Multi-Purpose Tokens for institutional RWAs
- **`Payment` with `Paths`** — multi-hop cross-currency routing via XRPL's pathfinder

**Canonical signing (critical):**
1. Sort fields in canonical order, prefix each with Field ID (XRPL's serialization rules).
2. Prepend prefix `0x53545800` (single-sign) or `0x534D5400` (multi-sign).
3. Hash with SHA-512Half (truncate SHA-512 to 256 bits).
4. Sign via `ThresholdSigner::sign_prehash` — Ed25519 by default (matches `xrpl.js`), secp256k1 supported.
5. Re-serialize transaction with `TxnSignature` field included.
6. **Ed25519 signatures are fully canonical by construction.** secp256k1 needs canonicality check (positive r,s; both < group order — already enforced by k256 with the right options).
7. Submit via `submit` WebSocket method or `submit_only` for known-tx-hash submission.

**Multi-Purpose Tokens (XLS-33) — institutional RWA story:**

MPTs are the protocol-native fungible token primitive for fractionalised RWAs, tokenized money-market funds, on-chain collateral. The Confidential MPT extension (eprint 2026/602) adds equality-proof-based hidden balances with cryptographic auditability — exactly the institutional privacy model. The adapter exposes both vanilla MPT ops and (when amendments enable it) the confidential-transfer variant.

#### `EvmAdapter` — extend for XRPL EVM, HyperEVM

XRPL EVM Sidechain and HyperEVM are both standard EVM chains. They register as **config entries** on the existing EVM adapter:

```rust
// In tenzro-node config:
[bridge.evm_chains.xrpl_evm]
chain_id = 1440002              # XRPL EVM mainnet
rpc_url = "https://rpc.xrplevm.org"
fee_market = "eip1559"
bridge_route = "wormhole-ntt"   # default cross-chain rail for TNZO

[bridge.evm_chains.hyperevm]
chain_id = 999                  # HyperEVM mainnet
rpc_url = "https://rpc.hyperliquid.xyz/evm"
fee_market = "eip1559"
bridge_route = "wormhole-ntt"

[bridge.evm_chains.base]
chain_id = 8453
rpc_url = "https://mainnet.base.org"
fee_market = "eip1559"
bridge_route = "wormhole-ntt"
```

Zero new code. The existing `EvmTransactionSigner::with_threshold_signer` handles signing for any chain id via EIP-155.

**HyperCore (non-EVM):** the on-chain CLOB is accessed from HyperEVM via **precompiles** that read HyperCore state directly. Trading is initiated via HyperCore JSON-RPC API (`exchange` endpoint), signed with the HyperEVM-derived secp256k1 key. The adapter wraps the HyperCore API as a special operation type on the HyperEVM chain — not a separate chain.

### Layer 3 — TNZO bridging (`tenzro-bridge` routing)

Per `project_interop_architecture`, **Wormhole NTT is the primary rail for TNZO transfers.** For the three new chains:

| Chain | TNZO bridge | Status |
|---|---|---|
| Stellar (Soroban) | Wormhole NTT — Soroban support announced via Axelar Amplifier integration (April 2026), native Wormhole deployment plausible in 2026 | Pending NTT Soroban manager deployment |
| XRPL mainline | Wormhole NTT — XRPL added to Guardian Network for high-traffic chains; NTT support announced alongside RLUSD L2 expansion | Pending NTT XRPL manager deployment |
| XRPL EVM | Wormhole NTT — standard EVM deployment | Trivial — config entry |
| HyperEVM | Wormhole NTT — deployment guide live | Available now |
| HyperCore | Bridge via HyperEVM (HyperCore accounts are HyperEVM accounts) | Indirect |

The `BridgeRouter` picks routes per-task using cost/speed/availability:

```
agent task: "swap 1000 wTNZO on Tenzro into RLUSD on XRPL"
        │
        ▼
BridgeRouter.route(source=tenzro, dest=xrpl, asset=tnzo→rlusd)
        │
        ├─ Step 1: NTT lock TNZO on Tenzro → mint wTNZO on XRPL
        │           (locking mode on Tenzro, burning mode on XRPL)
        │
        ├─ Step 2: XRPL Payment (XrplAdapter) — wTNZO → RLUSD via XRPL DEX path
        │           cross-currency Payment with Paths
        │
        └─ Receipt: AP2 PaymentMandate.chain = "xrpl"
                    settlement record in CF_SETTLEMENTS
```

### Layer 4 — Delegation + mandate enforcement (`tenzro-identity` + `tenzro-payments`)

**`DelegationScope.allowed_chains`** already exists. Extend the CAIP-2-shaped chain identifiers to include the new rails:

```
stellar:pubnet              # Stellar mainnet
xrpl:livenet                # XRPL mainline
xrpl:livenet-evm            # XRPL EVM sidechain
eip155:999                  # HyperEVM (standard CAIP-2 for EVM)
eip155:1440002              # XRPL EVM (standard CAIP-2 for EVM)
```

**AP2 `CheckoutMandate.accepted_chains`** (shipped 2026-06-02 this session) picks up automatically — the principal whitelists which rails the agent may pick; the validator enforces at mandate-validate time. No code change.

**On-chain `SPENDING_LIMIT_VALIDATOR` (0x101f)** enforces per-tx + rolling-window ceilings on the Tenzro side. For external-chain dispatch, the same ceiling applies at the **bridge entry point** (the Tenzro tx that locks TNZO into the NTT manager) — the validator module rejects if the lock amount exceeds policy. Defence-in-depth: the off-chain `SpendingPolicyResolver` cross-checks at mandate-validate time.

## End-to-end flow (worked example)

**Task:** Agent (`did:tenzro:machine:portfolio-rebalancer`) gets a mandate to "buy 10,000 RLUSD using TNZO, settle on XRPL mainline."

```
1. Principal signs AP2 CheckoutMandate
   - agent: did:tenzro:machine:portfolio-rebalancer
   - max_amount: 10000_usd_equivalent_TNZO
   - asset: "TNZO"
   - accepted_chains: ["tenzro", "xrpl:livenet"]
   - expires_at: now + 1h

2. Agent constructs AP2 PaymentMandate
   - parent: <CheckoutMandate.mandate_id>
   - chain: "xrpl:livenet"               ← matches whitelist
   - cart: [RLUSD 10000]
   - merchant: <RLUSD market-maker DID>
   - signs with agent's Tenzro MPC wallet

3. Tenzro node validates mandate pair via tenzro_validateMandatePair
   - Ed25519 sig check on both VDCs                                  ✓
   - Cart total ≤ checkout ceiling                                   ✓
   - chain ∈ accepted_chains                                         ✓
   - DelegationScope.allowed_chains contains "xrpl:livenet"          ✓
   - DelegationScope.max_transaction_value ≥ cart_total              ✓
   - Runtime SpendingPolicy daily window has headroom                ✓
   - ERC-7579 SPENDING_LIMIT_VALIDATOR(0x101f) admits the UserOp     ✓

4. BridgeRouter picks Wormhole NTT route for TNZO → XRPL
   - Step 1: Tenzro EVM tx — call NTT manager.transfer(amount, xrpl_chain_id, recipient)
     ├ Signer: EvmTransactionSigner::with_threshold_signer
     ├ MPC ceremony across validator committee (DKLS23)
     └ Tx broadcast on Tenzro, finalized in 1 block

   - Step 2: Wormhole Guardian quorum signs VAA attesting the lock event
     └ Guardian signatures collected (no Tenzro action — external)

   - Step 3: XRPL adapter executes redeem on XRPL
     ├ Build XRPL Payment with Paths (wTNZO → RLUSD via XRPL DEX path)
     ├ Source: agent's derived XRPL address = derive(home_did, "xrpl:1")
     ├ Sign 32-byte SHA-512Half of canonical tx + 0x53545800 prefix
     ├ ThresholdSigner::sign_prehash (Ed25519 path)
     └ Submit via xrpl-cluster WebSocket submit

   - Step 4: Tx finalized on XRPL (3-5s)

5. Receipt
   - PaymentReceipt envelope persisted in CF_SETTLEMENTS
   - Wormhole VAA archived for audit
   - XRPL tx hash + ledger sequence recorded
   - ERC-8004 submitFeedback(agent_id=portfolio-rebalancer, rating=+1, "xrpl_payment_succeeded")
   - Adaptive burn dial sees the bridge-out fee (paymaster burn 100%)
```

**The agent signed exactly once** (the PaymentMandate VDC). Every subsequent signature was a deterministic derivation from the agent's TDIP MPC key, executed by the validator committee, with the result accountable to the same agent identity.

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **Phase 1** — EVM-on-config | XRPL EVM Sidechain + HyperEVM as config entries on `EvmAdapter` + `BridgeRouter`. Wormhole NTT route entries for HyperEVM (live), pending for XRPL EVM (verify deployment). Test on validator-0 with small TNZO transfer. | 1 week |
| **Phase 2** — Derivation layer | `tenzro-identity::derivation` module — additive HD derivation per NEAR pattern, target-curve abstraction (Ed25519 vs secp256k1), address-encoding (StrKey, r-address, 0x-hex). Unit tests covering all three target chains. | 1-2 weeks |
| **Phase 3** — `StellarAdapter` | Soroban-RPC client + classic ops + SEP-10/SEP-24 + Soroban auth-entry signing + XDR envelope serialization. Integration tests against Stellar testnet (Futurenet). | 4-6 weeks |
| **Phase 4** — `XrplAdapter` | Rippled WS client + canonical binary serialization + Ed25519/secp256k1 signing + Payment/TrustSet/OfferCreate/Escrow/MPToken ops + path-finding. Integration tests against XRPL devnet + testnet. Token Escrow (XLS-85) + MPT (XLS-33) coverage. | 4-6 weeks |
| **Phase 5** — HyperCore precompile bridge | HyperCore JSON-RPC (`exchange` endpoint) integration, order placement / cancellation / margin queries via HyperEVM-derived keys. Optional — only if agent trading volume materializes. | 2-3 weeks |
| **Phase 6** — Confidential MPT (XRPL) | Implement XRPL Confidential MPT extension (equality proofs, selective disclosure) once mainline amendment lands. Institutional privacy use case. | 3-4 weeks, gated on XRPL amendment activation |
| **Phase 7** — Production deployments | Deploy NTT managers on Stellar Soroban + XRPL mainline (coordinate with Wormhole Foundation). Production HSM-backed MPC committee. External audit. | Multi-quarter |

## What we are NOT building

- **A Stellar/XRPL/Hyperliquid follower node inside Tenzro.** No light-client implementation, no header sync, no replay. We trust the target chain's own consensus.
- **A new VM in `MultiVmRuntime`.** EVM/SVM/DAML stay. Stellar/XRPL/Hyperliquid are destinations, not local VMs.
- **A custom bridge to replace Wormhole NTT for TNZO.** Wormhole NTT remains primary for TNZO transfers per `project_interop_architecture`. We're consumers of NTT, not builders of a competing rail.
- **An RLUSD issuer relationship.** RLUSD is Ripple/Standard Custody product. We hold and transact it via XRPL trustlines; we do not issue it.
- **An anchor service.** SEP-24 anchor implementations are TradFi on/off-ramps run by regulated entities (Mountain, Anchor USD, etc.). We integrate as an anchor **client**, not as an anchor.
- **Native Soroban contract execution.** Soroban contracts run on Stellar validators. We invoke them, we don't host them.

## Open questions

1. **MPC derivation correctness across curves.** NEAR's additive HD derivation is well-studied for secp256k1 (where the curve group is a prime-order subgroup of the elliptic curve over Fp). For Ed25519, additive derivation has subtle pitfalls around the cofactor (Curve25519 has cofactor 8). Need to either (a) use a slip10-Ed25519 variant that handles cofactor explicitly, or (b) document the limitation and use straight-up-distinct-key-shares per target chain. Prior art: Fireblocks' MPC-CMP for Ed25519 chains.

2. **Wormhole NTT for Stellar/XRPL mainline — deployment timeline.** Public-facing announcements exist (RLUSD via NTT, XRPL added to Guardian Network) but the actual NTT manager deployments on Stellar Soroban and XRPL native are unverified at audit time. Until they land, TNZO ↔ Stellar/XRPL native must route via a hop chain (Tenzro → Ethereum L1 via existing NTT → manual bridge to XRPL via existing trustline path). Phase 7 contingency: hop-route until direct manager is live.

3. **XRPL EVM sidechain adoption risk.** $120M TVL and minimal sidechain fee revenue (early 2026) suggests the EVM sidechain is not yet a primary settlement venue for institutional flows. Mainline XRPL (trustlines + MPTs) is where the institutional volume currently sits. Prioritise `XrplAdapter` over `XrplEvmAdapter`-as-config.

4. **HyperCore precompile interface surface.** HyperEVM precompiles let contracts read HyperCore state, but order placement happens through the off-chain HyperCore API. The trust model is different (HyperCore is run by Hyperliquid validators only). Document whether the agent's actions on HyperCore have the same `ERC-8004 submitFeedback` accountability as on-chain actions.

5. **SEP-10 + AP2 mandate composition.** SEP-10 issues a JWT to an "account" — the agent's Stellar-derived address. The mandate envelope says the agent is authorised by the principal. How do we encode the principal → agent → SEP-10-JWT delegation so an anchor can verify the agent is acting on the principal's behalf? Candidate: extend the SEP-10 client metadata with the principal DID + signed Tenzro mandate hash. Needs anchor-side cooperation.

## Mapping to existing Tenzro standards

| Tenzro primitive | Stellar mapping | XRPL mainline mapping | HyperEVM mapping |
|---|---|---|---|
| `did:tenzro:machine:*` (TDIP) | DID Document `service[]` carries Stellar account ID(s) | DID Document `service[]` carries XRPL r-address(es) | DID Document `service[]` carries HyperEVM 0x-address(es) |
| `DelegationScope.allowed_chains` | Whitelist `stellar:pubnet` | Whitelist `xrpl:livenet` | Whitelist `eip155:999` |
| `DelegationScope.max_transaction_value` | Enforced at `StellarAdapter` tx-build time | Enforced at `XrplAdapter` tx-build time | Enforced at EVM signer time |
| AP2 `CheckoutMandate.accepted_chains` | Member check at validate time | Member check at validate time | Member check at validate time |
| ERC-8004 `submitFeedback` | Settlement-outcome webhook from `StellarAdapter` | Settlement-outcome from `XrplAdapter` | Settlement-outcome from `EvmAdapter` |
| Wormhole NTT (TNZO rail) | NTT Soroban manager (pending) | NTT XRPL manager (pending) | NTT HyperEVM manager (live) |
| `tenzro_validateMandatePair` | Same — chain-agnostic | Same | Same |

## Comparison to Stripe SPT pattern

Stripe's Shared Payment Token (`docs/protocol-research-2026-05/stripe-spt.md`) is the closest analogue: a closed-network primitive (Visa/MC cards) wrapped in a Tenzro federation surface (TDIP DID + DelegationScope + ERC-8004). The Stellar/XRPL/Hyperliquid integration is the **on-chain version of the same pattern**:

| | Stripe SPT | Stellar/XRPL/Hyperliquid |
|---|---|---|
| Underlying network | Visa/MC card rails | Stellar / XRPL / Hyperliquid L1s |
| Tenzro doesn't own | Card vault, MDES tokenisation, dispute flow | Stellar/XRPL/Hyperliquid consensus, validator set |
| Tenzro owns | DID + DelegationScope + AP2 mandate + reputation | Same — plus the derived target-chain address |
| Federation surface | `service[].type = "StripeSPT"` | `service[].type = "StellarAccount" | "XrplAccount" | "HyperEvmAccount"` |
| Three-ceiling enforcement | DelegationScope + SpendingPolicy + SPT cap | DelegationScope + SpendingPolicy + on-chain validator-module |

The pattern composes. An agent could hold a Stripe SPT for card-rail purchases AND a derived XRPL address for RLUSD settlements AND a derived Stellar address for Franklin-Templeton-USDY redemption AND a derived HyperEVM address for perp hedging — all under one TDIP DID, one MPC home key, one AP2 mandate envelope, one reputation record.

## Conclusion

**Yes, supporting Stellar + XRPL + Hyperliquid makes sense.** The institutional thesis for Stellar (announced market-utility tokenization partnership, multi-trillion-dollar runway) and XRPL (RLUSD, MPT-based RWAs, Token Escrow) is real and accelerating in 2026. Hyperliquid is a different (trading-focused) thesis but fits the same architectural slot trivially.

**Current VMs are not enough — but they're the right thing.** `MultiVmRuntime` should stay local-execution-only. The integration is **adapter work in `tenzro-bridge`** plus a **derivation layer in `tenzro-identity`**, both consistent with the existing AP2 mandate + DelegationScope + ERC-7579 enforcement envelope.

**The one-DID-one-wallet UX continues to hold.** The agent signs the mandate once with its Tenzro MPC key; the validator committee derives target-chain addresses, runs MPC ceremonies, signs target-chain transactions, and records receipts under the same DID. The number of chains is invisible at the agent-task level.

## Sources

- [Stellar's DTCC moment: $114T tokenization](https://cryptodaily.co.uk/2026/05/stellar-dtcc-moment-xlm-tokenized-assets)
- [DTCC selects Stellar to tokenize $114T](https://www.kucoin.com/blog/dtcc-selects-stellar-tokenize-114-trillion-xlm-surge)
- [Stellar | Soroban smart contracts platform](https://stellar.org/soroban)
- [Soroban authorization (Stellar Docs)](https://soroban.stellar.org/docs/learn/authorization)
- [Signing Soroban contract invocations](https://developers.stellar.org/docs/build/guides/transactions/signing-soroban-invocations)
- [SEP-10 Stellar Web Authentication](https://developers.stellar.org/docs/build/apps/example-application-tutorial/anchor-integration/sep10)
- [SEP-24 Hosted Deposit and Withdrawal](https://developers.stellar.org/docs/build/apps/example-application-tutorial/anchor-integration/sep24)
- [Can XRP's EVM sidechain drive institutional adoption in 2026?](https://www.ainvest.com/news/xrp-evm-sidechain-native-stablecoin-drive-sustained-institutional-adoption-2026-2601/)
- [XRPL EVM sidechain mainnet is live](https://ripple.com/insights/xrpl-evm-sidechain-mainnet-is-live/)
- [Ripple taps Cosmos EVM to expand XRPL utility](https://blog.cosmos.network/ripple-taps-cosmos-evm-to-expand-the-xrp-ledgers-utility-1f780da54bcc)
- [XRPL Binary Format (canonical signing)](https://xrpl.org/docs/references/protocol/binary-format)
- [XRPL Cryptographic Keys (Ed25519 + secp256k1)](https://xrpl.org/docs/concepts/accounts/cryptographic-keys)
- [XLS-33 Multi-Purpose Tokens](https://xls.xrpl.org/xls/XLS-0033-multi-purpose-tokens.html)
- [XLS-85 Token Escrow live for IOUs and MPTs (Feb 2026)](https://www.hokanews.com/2026/02/xrpl-goes-next-level-token-escrow-now.html)
- [Confidential Transfers for MPTs on XRPL (eprint 2026/602)](https://eprint.iacr.org/2026/602)
- [RLUSD expands to L2s with Wormhole NTT](https://ripple.com/insights/ripple-usd-rlusd-expands-to-l2s-with-wormhole-ntt-standard/)
- [Wormhole Native Token Transfers (GitHub)](https://github.com/wormhole-foundation/native-token-transfers)
- [Wormhole NTT Hyperliquid Deployment](https://wormhole.com/docs/products/token-transfers/native-token-transfers/guides/deploy-to-hyperliquid/)
- [Hyperliquid Architecture Deep Dive (HyperBFT, HyperCore, HyperEVM)](https://cleansky.io/blog/hyperliquid-architecture-hypercore-hyperevm-2026/)
- [Top HyperEVM Projects 2026](https://www.datawallet.com/crypto/top-hyperevm-projects)
- [NEAR Chain Signatures (docs)](https://docs.near.org/chain-abstraction/chain-signatures)
- [NEAR Chain Signatures derivation (Alin Tomescu's notes)](https://alinush.github.io/near)
- [Chain Abstraction 2026 Guide (Eco)](https://eco.com/support/en/articles/11822744-what-is-chain-abstraction-2026-guide)
