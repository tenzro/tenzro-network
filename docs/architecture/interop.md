# Tenzro Interoperability Architecture

**Status:** Adopted (2026-05-02)
**Scope:** TNZO and arbitrary-asset interop across EVM, SVM, Canton, and external chains.

## Context

Tenzro Ledger is a multi-VM network (EVM + SVM + Canton/DAML) where TNZO is **one native balance** with three VM views via the Sei-V2-style pointer model. This shape constrains what kinds of bridges can be the "canonical" path for TNZO:

- **Lock-and-mint with separate per-chain supply curves is incompatible.** TNZO supply lives on Tenzro; foreign chains must hold IOUs whose total never exceeds locked native balance.
- **Multi-VM views complicate the "where does TNZO live" question.** External bridges talk to one chain at a time. A foreign user's "I want TNZO" request must resolve to the native layer regardless of which VM they entered through.
- **Canton CIP-56 is finalized (March 2025) and BitGo qualified-custody (March 2026).** It's the enterprise lane and doesn't go through the bridge mesh.
- **PQ migration is in flight.** Ed25519 + ML-DSA-65 hybrid signing on every tx; bridge proofs need to ride that envelope without breaking foreign verifiers.
- **CAIP-2 namespace `tenzro:` is not yet registered.** Wallet sessions, scopes (`tenzro:mainnet`, `tenzro:testnet`), and provider discovery downstream depend on this.

## Decision

Adopt a **layered interop stack** with one canonical primitive per concern, treating aggregators as user-facing convenience and never as the trust root:

| Concern | Primitive | Rationale |
|---|---|---|
| Canonical TNZO bridging | **Wormhole NTT** | Pluggable Manager+Transceiver, supply-conserved by design (no foreign mint desync), pointer-model compatible. ZK-Wormhole roadmap rides our Plonky3 infra. |
| General message passing | **LayerZero V2** with Tenzro-validator DVN required + Polyhedra zkDVN | Only major messenger that lets us require our own validator set as a *mandatory* DVN in the X-of-Y-of-N config. |
| User-facing aggregation | **Li.Fi** (already integrated, MCP port 3008) | Aggregator only. Never the trust primitive — it just routes between the primitives below. |
| Intent-style fast-path UX | **deBridge DLN** | 0-TVL solver model; lets TNZO stay on Tenzro while a foreign user receives USDC/native on their chain. |
| Enterprise / regulated | **Canton CIP-56** | Outside the bridge mesh. Direct DAML token template, qualified custody. |
| Long-term canonical | **IBC v2 / Eureka** with SP1 Tenzro light client | Light-client trust, no third-party validator set. Same path Cosmos took to Ethereum mainnet (April 2025). |

Chainlink CCIP, Hyperlane, Across, Polymer are evaluated and **rejected as primaries** for the reasons in §"Rejected alternatives" below. CCT is reconsidered only if a counterparty L1 specifically requires it.

## Architecture

### Layer 1 — Canonical TNZO bridging (Wormhole NTT)

```
        Tenzro (native TNZO)
              │
   ┌──────────┴───────────┐
   │   NTT Manager        │
   │   (Tenzro-deployed)  │
   └──────────┬───────────┘
              │
   ┌──────────┴───────────┐
   │   Transceivers       │
   │  ┌─────┐  ┌────────┐ │
   │  │ WH  │  │ Tenzro │ │
   │  │core │  │ valBLS │ │
   │  └─────┘  └────────┘ │
   └──────────┬───────────┘
              │
        Foreign chain
        (NTT Manager mirror)
```

- **Manager:** TNZO-aware contract on each foreign chain. Receives "release N TNZO to X" attestations, mints/unlocks the foreign representation (BurnMint or LockRelease per chain).
- **Transceivers (pluggable):** Wormhole core guardians for chains where they're already deployed; **Tenzro-validator BLS aggregate** as a second mandatory transceiver so bridge security is at-least min(WH, Tenzro). Both must sign for a TNZO release.
- **Supply invariant:** Sum of all foreign-chain TNZO representations ≤ Tenzro-side locked balance. Manager enforces.
- **Pointer-model compatibility:** Native lock happens at the TnzoToken layer (not on EVM/SVM/DAML view) — same balance, no view divergence.

### Layer 2 — General message passing (LayerZero V2)

For non-TNZO arbitrary messages (governance signals, ERC-8004 reputation pings, cross-chain agent calls):

- **Required DVNs:** Tenzro-validator DVN (mandatory) + Polyhedra zkDVN (mandatory) + LZ Labs DVN (optional confirmation).
- **Optional DVNs:** Configurable per-app via `setSendLibrary` / `setReceiveLibrary`.
- **Threshold:** 2-of-3 minimum, with the Tenzro DVN as a hard veto (X-of-Y-of-N where Tenzro is in the Y set).
- **OFT:** Not used for TNZO (NTT handles that). OFT *is* available for app-deployed tokens that don't need pointer-model semantics.

### Layer 3 — Aggregation (Li.Fi)

Already integrated as `lifi-mcp.tenzro.network/mcp` (port 3008, 9 tools). dApps and wallets call Li.Fi to get a route, Li.Fi resolves to underlying primitives (NTT for TNZO, deBridge DLN for fast intents, etc.). **No trust assumption rides on Li.Fi** — it's a route-finder.

### Layer 4 — Intent fast-path (deBridge DLN)

For "foreign user wants to pay X with their USDC, recipient wants TNZO on Tenzro" or vice versa:

- TNZO never leaves Tenzro; deBridge solver fronts the foreign-side asset.
- Solver is reimbursed via a separate solver-side leg.
- Use case: agent payments where AP2 mandate names a TNZO amount but payer holds USDC on Base.

### Layer 5 — Enterprise (Canton CIP-56)

Unchanged. TNZO holds on Canton via the CIP-56 DAML token template, transferred via two-step DvP. **Does not go through Wormhole/LZ.** Bridges into the rest of the mesh via the Canton ↔ Tenzro adapter only when explicitly requested.

### Layer 6 — Long-term canonical (IBC-Eureka + SP1 light client)

Roadmap, not blocking testnet. Once IBC-Eureka tooling stabilizes:

1. Define `TenzroClientState` / `ConsensusState` per ICS-02.
2. Build SP1 circuit verifying Tenzro headers + ML-DSA-65 quorum signature.
3. Deploy `SP1TenzroLightClient.sol` on Ethereum (and any IBC-Eureka counterparty).
4. Register with Eureka relayer set.

This makes Tenzro a peer light client to Cosmos chains and Ethereum without depending on any third-party validator committee.

## PQ posture

- **Inner signature:** Tenzro txs and bridge attestations carry Ed25519 + ML-DSA-65 hybrid (FIPS 204).
- **Outer envelope:** Wrapped in the bridge's native attestation format (Wormhole guardian sig, LZ DVN sig). Foreign verifiers verify the outer envelope; Tenzro-side verifiers verify both layers.
- **Migration path:**
  - Near-term: Polyhedra zkDVN as mandatory LZ DVN (already PQ-friendly via STARK proofs).
  - Mid-term: Wormhole ZK transceiver when it ships — replaces guardian sig with STARK-verified state proof.
  - Long-term: SP1 Tenzro light client on Ethereum (IBC-Eureka path) — fully PQ at the verification surface.

## CAIP-2 namespace registration

Submit PR to `ChainAgnostic/namespaces` adding `tenzro/` folder:

- `caip2.md` — defines `tenzro:mainnet` and `tenzro:testnet` references.
- `caip10.md` — account address format (32-byte Tenzro address, hex-encoded).
- `caip19.md` — asset identifier format (TNZO = `tenzro:mainnet/native:tnzo`).
- `caip25.md` — wallet session profile listing the `tenzro_*` method namespace.

This is a hard prerequisite for `@tenzro/inject` and the wallet-extension work. Until merged, downstream tooling pins the strings as "vendor-prefixed pre-registration" and re-aliases on merge.

## Rejected alternatives

- **Chainlink CCT v1.6+ as primary canonical token bridge.** Rejected because (a) Tenzro DVN-equivalent role doesn't exist in CCIP — Tenzro can't require its own validator quorum as mandatory; (b) RMN risk network is Chainlink-controlled; (c) overlaps with NTT for our use case without offering anything NTT lacks. *Kept as a* fallback *for chains where a counterparty insists on CCIP.*
- **Hyperlane as primary messaging.** Permissionless ISM is attractive but smaller validator set + younger codebase than LZ V2; no strong reason to prefer it over LZ-with-required-Tenzro-DVN. Re-evaluate in 12 months.
- **Polymer.** Solid for IBC-on-EVM but Polymer-the-chain is a sequencer trust assumption we don't need on top of LZ. Skip.
- **Across.** Optimistic-style intent system; the dispute window is incompatible with the latency target for agent payments. deBridge DLN's solver-collateral model is a better fit.
- **EigenLayer AVS / Babylon for bridge security.** Restaking-secured bridges are a 2026 frontier but operationally untested at the volumes we'd need. Revisit when one has 12 months of mainnet incident-free operation.
- **OFT for TNZO.** OFT mints/burns per chain — same supply-desync risk as plain lock-and-mint. NTT is strictly better for the pointer-model invariant.

## Implementation order

1. **CAIP-2 namespace PR.** Unblocks `@tenzro/inject`. *Independent track, can ship now.*
2. **Wormhole NTT Manager deployment** on Tenzro + first counterparty (Base or Ethereum). TNZO release path.
3. **LayerZero V2 DVN.** Stand up Tenzro-validator DVN as a registered LZ DVN. Wire Polyhedra zkDVN as second mandatory.
4. **deBridge DLN integration.** Already have the MCP server (`crates/tenzro-node/src/mcp/debridge.rs` via external endpoint); wire intent submission into the agent payment path.
5. **Li.Fi:** No work — already integrated.
6. **Canton CIP-56:** No work — already integrated.
7. **IBC-Eureka SP1 light client.** Long-term roadmap, separate task.

## References

- Wormhole NTT: https://wormhole.com/docs/build/contract-integrations/native-token-transfers/
- LayerZero V2 Security Stack: https://docs.layerzero.network/v2/concepts/modular-security/security-stack-dvns
- Polyhedra zkDVN: https://polyhedra.network/expchain
- deBridge DLN: https://docs.debridge.finance/the-dln-protocol/overview
- Li.Fi: https://docs.li.fi/
- IBC v2 / Eureka on Ethereum (April 2025): https://www.ibcprotocol.dev/
- SP1 zkVM: https://docs.succinct.xyz/
- Canton CIP-56: https://lists.sync.global/g/cn-tokenization-standard
- ChainAgnostic CAIP-2 namespaces: https://github.com/ChainAgnostic/namespaces
