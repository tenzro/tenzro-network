# ERC-7683 Settler Interface

**Status:** Drafting (2026-05-04)
**Phase:** 2 (cross-chain intent surface)
**Touches:** `tenzro-bridge` (adapter shim), `tenzro-vm` (settler precompiles), `tenzro-payments` (intent ingestion), `tenzro-node` (RPC + Agent Card skill)

## Context

ERC-7683 ("Cross-Chain Intents Standard") gives every chain a uniform way to expose origin and destination settler interfaces. A solver — running anywhere — picks up an order on chain A, fills it on chain B, and proves the fill back to A for repayment. By April 2026, Across alone routes 88% of cross-chain intent volume through a 7683-compatible flow; UniswapX, CoW Swap, deBridge DLN, and at least eight L2-native solvers speak it.

Tenzro's bridge stack (LayerZero V2, Wormhole NTT, Li.Fi, deBridge, Canton) is solid for *protocol-level* messaging and TNZO transfers. But agents in 2026 increasingly speak **intent**, not transaction: "give me X USDC on Base in exchange for Y TNZO on Tenzro within 30s." If we don't expose 7683, we're outside the agent intent graph — solvers can't see Tenzro orders, and Tenzro-native users can't ride solver liquidity to fill orders elsewhere.

This is pure additive surface. It does not replace the existing bridge stack; it sits on top.

## Decision

Implement both halves of ERC-7683:

1. **Origin settler (`IOriginSettler`)** — Tenzro can be the chain where a `CrossChainOrder` is opened. Solvers watch Tenzro for new orders, fill them on the destination, and come back to claim repayment.
2. **Destination settler (`IDestinationSettler`)** — Tenzro can be the chain where a 7683 order is filled. A solver, having proved a fill on Tenzro, claims the user's locked input on the origin chain via the origin's settler.

Both are thin shims over the existing bridge adapters. The 7683 surface unifies the calling convention; it does not introduce a new trust root. Settlement security is min(7683 dispute window, underlying bridge security) — 7683 itself is just message format and lifecycle.

## Architecture

### 7683 primer (just enough)

7683 defines two structs and two contract interfaces:

```solidity
// What a user signs to open an order
struct CrossChainOrder {
    address settlementContract;   // origin settler
    address swapper;
    uint256 nonce;
    uint32  originChainId;
    uint32  fillDeadline;
    bytes32 orderDataType;        // typehash for orderData decoding
    bytes   orderData;            // user-defined payload
}

// What a solver gets after filling
struct ResolvedCrossChainOrder {
    address settlementContract;
    address swapper;
    uint256 nonce;
    uint32  originChainId;
    uint32  fillDeadline;
    Output[] maxSpent;            // what the solver spent on destination
    Output[] minReceived;          // what the user receives on origin
    FillInstruction[] fillInstructions;
}

interface IOriginSettler {
    function open(GaslessCrossChainOrder calldata order, bytes calldata signature, bytes calldata fillerData) external;
    function openFor(GaslessCrossChainOrder calldata order, bytes calldata signature, bytes calldata fillerData) external;
    function resolve(CrossChainOrder calldata order, bytes calldata fillerData) external view returns (ResolvedCrossChainOrder memory);
}

interface IDestinationSettler {
    function fill(bytes32 orderId, bytes calldata originData, bytes calldata fillerData) external;
}
```

Repayment of the solver is bridge-mediated — when a solver fills on chain B, the destination settler emits a fill receipt; an underlying bridge (the user's choice or settler's choice) carries proof of fill back to chain A's origin settler, which releases the user's locked input to the solver.

### TenzroOriginSettler

Deployed as a privileged-VM contract at well-known address `0x101F00...01`.

**`open` flow:**

1. User signs an EIP-712 `GaslessCrossChainOrder` whose `orderData` carries a `TenzroOrderData` payload:
   ```
   TenzroOrderData {
       inputs:        Vec<TokenAmount>,    // what user locks on Tenzro
       outputs:       Vec<TargetOutput>,    // what user wants on dest chain
       dest_chain_id: u32,                  // EIP-155 / CAIP-2 mapped
       dest_recipient: bytes32,
       fill_deadline: u32,
       proof_route:   ProofRoute,           // {LayerZero, Wormhole, deBridge, Hyperlane}
   }
   ```
2. Settler validates signature, validates `proof_route` is in the governance-approved set.
3. Settler locks `inputs` in an internal escrow (reuses `tenzro-settlement::EscrowManager` — no new lock primitive). Escrow `payee` is left unset (filled later when solver proves).
4. Settler emits `Open(orderId, ResolvedCrossChainOrder)` event. Solvers index this.
5. Settler records `orderId → escrow_id` in CF_SETTLEMENTS under `7683_origin:<orderId>`.

**Solver-side fill (off-chain, on destination chain):**

Solver picks up the order from the indexer, fills on destination by calling that chain's `IDestinationSettler.fill`. Destination settler emits its own fill event.

**Repayment flow:**

A bridge message (per `proof_route`) carries proof-of-fill from destination back to Tenzro:
- LayerZero: `lzReceive` callback to settler
- Wormhole: `receiveMessageAndProcess` with VAA
- deBridge: solver-submitted DLN fill proof verified via deBridge adapter
- Hyperlane: ISM-mediated message

Settler validates the proof via the corresponding `tenzro-bridge` adapter, then releases the locked escrow to the solver:

1. Verify `bridge_proof` against expected dest chain + expected `orderId`.
2. Verify `fill_recipient` matches `dest_recipient` (anti-rug: solver actually paid the user).
3. Release escrow to the solver's Tenzro address.
4. Emit `Settled(orderId, solver, fill_proof_hash)`.

Failure modes:
- **Deadline passed without fill** → user calls `refund(orderId)`, escrow refunded.
- **Invalid bridge proof** → reject, escrow stays locked, settler waits for valid proof or deadline.
- **Double-fill attempt** → settler rejects (orderId is single-shot).

### TenzroDestinationSettler

Deployed at `0x101F00...02`.

**`fill` flow:**

Called by a solver who already saw an order on chain A. The solver pays the user on Tenzro per `originData`:

1. Decode `originData` into `(orderId, recipient, outputs, originChainId, originSettler, deadline)`.
2. Verify `block.timestamp < deadline`.
3. Verify `outputs` haven't already been filled (idempotent guard via CF_SETTLEMENTS `7683_dest:<orderId>` entry).
4. Pull `outputs` from solver's Tenzro balance.
5. Transfer `outputs` to `recipient`.
6. Emit `Filled(orderId, originChainId, originSettler, solver, fillData)` — this is what the bridge picks up to ferry back.
7. Trigger the bridge route specified in the order's `proof_route` to send the fill proof back to `originChainId`. The bridge adapter is responsible for the actual ferrying; the settler just calls `bridge_adapter.send_message(originChainId, originSettler, fillData)`.

The choice of bridge for the fill-proof return is **the order's choice**, encoded in `proof_route` at open time. Solvers see the route in the resolved order and can refuse to fill if they don't trust it. This avoids the "settler forces my preferred bridge" objection.

### Resolved order shape on Tenzro

When a 7683 order opens against Tenzro:

- `Output.token` → either an EVM-view ERC-20 address (e.g. wTNZO at `0x7a4bcb13...`) or a SPL/Canton view via the chain ID encoding from the multi-VM pointer model.
- `Output.amount` → uint256.
- `Output.recipient` → bytes32 (EVM = 12-byte zero-pad + 20-byte address; SVM = 32-byte pubkey; Canton = party ID).
- `Output.chainId` → 7683 chain ID for Tenzro (CAIP-2 mapping `tenzro:1` → uint32 per Tenzro registry).

The pointer model means an `Output` denominated in TNZO can settle on any of the three Tenzro VMs depending on `recipient` shape — same balance, different view. Settler reads recipient discriminator and routes accordingly.

### CAIP-2 mapping for chain ID

Tenzro registers `tenzro:1` (mainnet) and `tenzro:tenzro-testnet` per the in-flight CAIP-2 namespace work. For 7683's uint32 chain ID field, we use:

| Chain | uint32 |
|---|---|
| Tenzro mainnet | 0x10ED20 (encoded "TENZRO" lower bits) |
| Tenzro testnet | 0x10ED21 |

Chosen to not collide with EVM EIP-155 chain IDs (which are large but predictable).

### Solver discovery

Solvers don't poll RPC — that scales poorly. Two channels:

1. **Gossipsub topic** `tenzro/7683-orders` — every `Open` event is broadcast on this topic. Solvers subscribe via libp2p (existing pattern) or via a hosted indexer that bridges gossipsub → WebSocket.
2. **Indexer JSON-RPC** `tenzro_list7683Orders { open_after?, dest_chain?, min_value?, limit }` — for solvers that prefer polling.

Indexer is a thin layer over CF_SETTLEMENTS; solvers can run their own.

### RPC surface

```
tenzro_open7683Order { signed_order, fillerData? }
    → { orderId, escrow_id, resolved_order }

tenzro_resolve7683Order { order }
    → { resolved_order }                    // pure view, EIP-7683-mandated

tenzro_fill7683Order { orderId, originData, fillerData }
    → { fill_proof_hash, bridge_route }

tenzro_get7683Order { orderId }
    → { state, ResolvedCrossChainOrder, escrow_state, fill_proof? }

tenzro_list7683Orders { filter }
    → [order summaries]

tenzro_refund7683Order { orderId }          // user, after deadline
    → { refund_tx_hash }
```

CLI: `tenzro intent open ...`, `tenzro intent fill ...`, `tenzro intent list`, `tenzro intent refund`.

MCP: `open_7683_order`, `list_7683_orders`, `fill_7683_order` tools.

A2A: new skill `intent-7683` exposed via Agent Card so agent solvers can find Tenzro-side orders programmatically.

### Bridge adapter mapping

For each 7683 `proof_route`, the corresponding bridge adapter:

| proof_route | Adapter | Notes |
|---|---|---|
| LayerZero | `LayerZeroAdapter` | DVN must include Tenzro-validator DVN per `interop.md` |
| Wormhole | `WormholeAdapter` | NTT path for tokens, message path for fill proof |
| deBridge | `DeBridgeAdapter` | DLN solver flow already speaks 7683-like semantics; adapter just wraps |
| Hyperlane | not in current adapter set | Add when first counterparty solver requires |

Settler refuses orders with `proof_route` not in this allow-list.

## Interaction with existing systems

- **`tenzro-bridge`** adapters are the underlying transport; settler is the format/lifecycle layer above them. No bridge change required.
- **`tenzro-settlement::EscrowManager`** is the lock primitive. 7683 orders are escrows with a deferred payee.
- **Per-DID flow control (Spec 2)**: opening a 7683 order is a tx subject to lane assignment like any other. A swarm of agents opening orders gets its lane.
- **Principal-chain receipts (Spec 5)**: 7683 settlement receipts carry the principal chain of the `swapper` — regulators see "agent X on behalf of human Y opened intent Z."
- **Kill-switch (Spec 1)**: a Quarantined or Terminated swapper's open orders are eligible for refund on the next block (no deadline wait); a Quarantined solver's incoming fill proofs are rejected.

## PQ posture

7683 orders are signed by the swapper using EIP-712 — the underlying signature is whatever the swapper's wallet supports. Tenzro-native swappers carry hybrid Ed25519 + ML-DSA-65; foreign swappers use whatever their chain mandates. The settler verifies whichever signature scheme the order claims. No new PQ surface introduced.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `enabled` | true | Master kill switch |
| `allowed_proof_routes` | [LayerZero, Wormhole, deBridge] | |
| `min_fill_deadline_seconds` | 300 | Order's `fill_deadline` ≥ now + this |
| `max_fill_deadline_seconds` | 86400 | Cap to bound escrow exposure |
| `max_open_per_swapper` | 100 | Anti-DoS, shares bucket math with mempool |
| `solver_min_reputation` | 0 | Reserved (Spec 5 reputation feeds in here later) |
| `bridge_proof_timeout_seconds` | 7200 | After fill, how long settler waits for bridge proof before warning |

## Verification

1. **Happy path open→fill→settle:** swapper opens TNZO-for-USDC order against Base, solver fills on Base, LayerZero ferries proof, settler releases TNZO to solver.
2. **Refund path:** swapper opens, deadline passes with no fill, swapper calls refund — escrow returns full input.
3. **Double-fill rejection:** two solvers race the same orderId — second fill rejected at destination.
4. **Wrong-recipient rejection:** solver fills but pays themselves not the recipient — fill recipient mismatch detected at settle.
5. **Bridge route enforcement:** order with disallowed `proof_route` rejected at open.
6. **Quarantined swapper:** Quarantined-after-open swapper's order is force-refundable by anyone.
7. **Cross-VM destination:** 7683 order to a Canton recipient settles via the DAML adapter, not EVM.
8. **Solver indexer parity:** every `Open` event on gossipsub matches an indexer query result within 5 blocks.

## Out of scope

- **Building our own solver fleet.** Solvers are an open market; the protocol exposes the settler surface, not solver software.
- **Cross-domain MEV protection.** 7683 orders are MEV-visible during the fill window; solver competition is the intended price-discovery mechanism. Order obfuscation (commit-reveal, encrypted intents) is a Phase 3 add-on.
- **Per-token fill auctions.** 7683 supports fill-auction styles; we ship the simplest "any-solver-can-fill" path first. Auction extensions add competitive pressure on solver pricing but are not blocking.
- **Origin settler outside Tenzro for Tenzro-output orders.** I.e., a user on Base opening a 7683 order against Base whose output is on Tenzro is supported (we're the destination settler). The reverse — Tenzro-origin foreign-output — is also supported. The cross — Base-origin Base-output via Tenzro mid-route — is not in scope; Tenzro is endpoint, not waypoint.
