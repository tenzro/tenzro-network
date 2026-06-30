# Stable-Asset Issuance & Agent Settlement

**Version:** 0.1.0 (Draft)
**Date:** 2026-06-30
**Status:** Proposed

## Executive Summary

This document proposes two Tenzro-native primitives:

1. **A stable-asset issuance engine.** Any keyed tenant issues a tiered
   hybrid stable asset on shared rails: a hard, code-enforced reserve floor
   (RWA/fiat-backed) plus an AI-tuned crypto buffer above it. Tenzro provides
   the full engine — per-asset reserve-floor mint, a parameterized
   stabilization controller, a rate oracle, conversion, and liquidation. The
   issuer only supplies a reserve + PoR feed and configures parameters.

2. **A stable-unit settlement layer for agents.** An agent transacts in a
   stable unit while Tenzro handles the multi-token reality underneath —
   accepting and paying across whatever payment rail the counterparty speaks
   (x402, AP2, MPP, …) and converting at the oracle rate. The agent can call
   the stable unit and let Tenzro abstract conversion, **or** transact
   directly in a specific token when it wants control. Both modes are first
   class.

These are issuer-agnostic Tenzro primitives. A consumer (for example, an
external platform that wants to back a stable asset) simply requests a
scope-gated API key (`tenzro_createApiKey`) and uses the public RPC. Nothing
about any individual consumer belongs in the engine.

```
  agent  --- holds / spends --->  STABLE UNIT  (one balance)
                                       |
                            conversion at oracle rate
                                       |
        x402 / AP2 / MPP / Visa-TAP / Mastercard counterparties
              (each priced in whatever token they want)
```

```
  ISSUED STABLE ASSET, per issuer:
  +-----------------------------------+
  |  crypto buffer   <- AI tunes      |  expand / contract, rebalance, de-risk
  +-----------------------------------+
  |  RWA / fiat reserve floor         |  SecureMint invariant: circulating <= reserve
  +-----------------------------------+  (controller NEVER crosses this line)
```

## Design Principles

1. **Hard floor in code, soft control above it.** The reserve floor is the
   `SecureMintRegistry` invariant (`circulating + amount <= reserve`),
   enforced on every mint regardless of what the controller wants. A
   misbehaving controller can degrade efficiency — it can never mint an
   unbacked unit.
2. **One unit to the agent, many tokens underneath.** Conversion happens at
   the settlement layer at an oracle rate, behind the existing payment
   gateway. The agent never touches the multi-token plumbing unless it
   chooses to transact directly.
3. **Multi-tenant by construction.** `SecureMintRegistry` is already keyed
   per-token; every new primitive is per-asset and parameterized. One
   issuer's depeg, controller misbehavior, or reserve shortfall is isolated
   from every other issuer (segregated reserves/buffers per `AssetId`,
   per-asset circuit breakers).
4. **Reuse the rails, don't re-invent them.** The payment-protocol gateway,
   the cross-VM token registry, the CCT bridge, and the settlement engine
   already exist. The new work is the issuance engine and the conversion
   hook — not the rails.
5. **Control theory, not vibes.** The controller is a proportional +
   leaky-integral feedback law, bounded so the worst case is degraded
   efficiency, never an unbacked mint.

## Stabilization mechanism

The engine uses only mechanisms whose failure modes are understood, and
deliberately avoids the failure shape (unbacked supply with a soft floor)
that has historically depegged.

- **Peg controller — proportional + leaky-integral.** The controller drives
  a control signal from the error between the unit's market price and its
  target: `u = Kp*e + Ki*I`, where `I` is a leaky accumulator
  (`I = leak*I_prev + e`) for anti-windup. The **derivative term is
  deliberately omitted** — in an economic setting it amplifies price noise
  and becomes an attack vector. All math is integer-only and Q18/basis-point
  scaled, matching the EIP-1559 controller already in the VM crate.
- **Collateral stack — hard floor, soft buffer.** A reserve floor backs the
  unit 1:1 (RWA/fiat, attested) and is enforced in code; an over-collateral
  crypto buffer sits above it and absorbs volatility. Supply moves only
  within the floor's headroom.
- **Dual-threshold liquidation.** A warning band triggers rebalance and a
  lower trip band triggers partial close, with a gap between the two bands so
  the system does not oscillate across a single threshold.

**Net position:** collateral stack (floor) + leaky-PI controller
(buffer/peg) + dual-threshold liquidation (risk). A predictive/optimal-control
upgrade to the peg loop is possible later but is out of scope for v1 — the v1
controller is the simpler, better-understood feedback law.

## What already exists in Tenzro (reused)

| Capability | Primitive | Location |
|---|---|---|
| Reserve-backed mint invariant + PoR attestation + TTL | `SecureMintRegistry::check_and_mint` (`circulating + amount <= reserve`); per-token keyed | `crates/tenzro-vm/src/secure_mint.rs:204` |
| Register an asset across EVM/SVM/Canton | `TokenRegistry` (addr↔mint↔symbol↔`TokenId`); `StablecoinType` / `AssetId` | `crates/tenzro-token/src/registry.rs`, `crates/tenzro-types/src/asset.rs:47` |
| Cross-chain asset movement | CCT `BurnMint`/`LockRelease` pools + rate limits; wTNZO pointer; BitVM2 (BTC) | `crates/tenzro-bridge/src/tnzo_cct.rs:86`, `evm/wtnzo.rs`, `bitvm2.rs` |
| Payment-rail gateway (multi-protocol) | `TenzroPaymentGateway` routes x402 / AP2 / MPP / Visa-TAP / Mastercard / Tempo; `SettlementCallback` bridges protocol→on-chain (carries an `asset` arg) | `crates/tenzro-payments/src/gateway.rs:17`, `lib.rs:24` |
| Agent payment authorization | AP2 mandate/escrow binding (principal↔escrow↔agent, cart-total cap, delegation scope) | `crates/tenzro-payments/src/identity_binding.rs` |
| Intent→settlement audit loop | `MandateRef::ap2_cart` / `::x402` on receipt envelopes | `crates/tenzro-storage/src/da/mod.rs:195` |
| Multi-asset balances + fee routing | `NetworkTreasury` (balances per `AssetId`); `SettlementEngine` + `FeeCollector` | `crates/tenzro-token/src/treasury.rs:165`, `crates/tenzro-settlement/src/engine.rs:259` |
| Regulated audit / principal chains | principal-chain indexing (actor / controller / KYC-tier) | `crates/tenzro-settlement/src/engine.rs:322` |
| Outflow safety | ERC-7265 circuit breaker (10%/hr default) | `crates/tenzro-token/src/tnzo.rs` |
| Control-loop precedent | EIP-1559 integer P-controller over EMA-smoothed utilization | `crates/tenzro-vm/src/eip1559.rs:60` |

## What is missing (new build)

1. **Stable-asset registry + issuance RPC.** A `StableAssetRegistry` where a
   keyed issuer registers a policy: reserve source, `por_feed_id`, controller
   gains, buffer target, liquidation bands, allowed payment rails, optional
   settlement destination. Self-serve via an `issuer`-scoped key. The reserve
   floor itself is the existing `SecureMintRegistry`.
2. **Rate oracle (asset ↔ stable unit, shared).** Today the only rate
   machinery is the bridge *fee* oracle (TNZO↔native,
   `crates/tenzro-bridge/src/fee_oracle.rs`). There is **no general
   asset-to-asset price/swap** in the VM, settlement, or payments crates. A
   `StableRateOracle` with the same shape as `BridgeFeeOracle`
   (governance-set table + Chainlink Data Feed backend) quotes `<asset>/<unit>`
   with `quote_id`, `rate_q18`, `valid_until_ms`. Shared across issuers so
   any unit ↔ any unit (and ↔ TNZO) converts through one graph.
3. **Stabilization controller (parameterized).** A `StableController`
   implementing the leaky-PI law over peg error and buffer ratio, with
   gains supplied per issuer. Reuses the integer-only, EMA-smoothed
   controller pattern from `eip1559.rs`. Outputs: target buffer ratio, supply
   delta (mint/burn within floor), de-risk trigger.
4. **Conversion hook in the settlement callback.** The payment gateway's
   `SettlementCallback::settle_on_chain` already takes an `asset` argument.
   When the agent holds unit-A but the verified payment is denominated in
   asset-B, the callback converts A→B at the oracle rate before recording the
   transfer (and B→A on inbound). This is the entire "abstract multi-tokens"
   mechanism — no on-chain AMM in v1.
5. **Liquidation path.** Banded dual-threshold de-risking on each issuer's
   crypto buffer (warn → rebalance, trip → partial close), wired to the
   controller's risk output, per-asset.

## Component architecture

```
   agent (holds/spends a stable unit, OR a specific token directly)
                              |
                  TenzroPaymentGateway
        (x402 / AP2 / MPP / Visa-TAP / Mastercard ...)
                              |
                  SettlementCallback
                  + convert() hook  <-------- StableRateOracle (asset/unit, shared)
                              |
        +---------------------+----------------------+
        |                     |                      |
  SecureMintRegistry    TokenRegistry           CCT bridge / BitVM2
  (per-issuer floor)    (unit across VMs)        (unit across chains)
        ^                                          
        |                                          
   StableController  <----- PoR feed (issuer reserve attestation)
   (leaky-PI per issuer: peg + buffer + supply + risk)
        |
   NetworkTreasury (reserve + crypto buffer, segregated per AssetId)
        ^
        |
   StableAssetRegistry  <----- issuer policy (gains, bands, rails, settlement dst)
        ^
        |
   tenzro_createApiKey { scopes: ["issuer", ...] }   <-- consumer requests a key
```

### Issuance (self-serve)

A consumer requests an `issuer`-scoped API key:

```
tenzro_createApiKey { "label": "<consumer>", "subject": "<consumer>",
                      "scopes": ["issuer"] }
```

minted with the operator's `TENZRO_ADMIN_TOKEN`. The issuer then registers a
stable-asset policy via RPC (reserve source, PoR feed, controller gains,
buffer target, liquidation bands, allowed rails, settlement destination). The
engine creates the `SecureMintPolicy`, the `TokenRegistry` entry, and (if
bridged) CCT pools. No engine code is consumer-specific.

### Mint / redeem (the floor)

- **Mint:** issuer deposits reserve (or controller authorizes within buffer
  headroom) → `StableRateOracle` fixes the rate →
  `SecureMintRegistry::check_and_mint(unit, amount, now)` enforces the floor
  against the PoR-attested reserve → `TokenRegistry` credits the unit.
- **Redeem:** burn → `SecureMintRegistry::record_burn` decrements circulating
  → release underlying at oracle rate → `FeeCollector` routes the spread to
  `NetworkTreasury`.

### Settle across rails (the abstraction)

An x402 challenge / AP2 mandate / MPP session arrives priced in asset-B. The
agent holds unit-A. The gateway verifies the protocol payment as it does
today; in `SettlementCallback`, `convert()` debits A and credits B at the
oracle rate, then records the on-chain transfer and the `MandateRef`. The
agent's ledger view stays in A throughout. If the agent instead wants to
transact directly in B, it simply holds/spends B — the convert step is a
no-op.

### AI control (the buffer)

`StableController` runs each settlement epoch on integer-only inputs, per
issuer:
- **Peg error** `e = market_price(unit) - target` (EMA-smoothed). Output:
  leaky-PI supply delta, applied only within floor headroom.
- **Buffer ratio** = `crypto_buffer_value / circulating_above_floor`. Output:
  rebalance toward target as volatility changes.
- **Risk bands** (warn 1.2–1.3 / trip <1.2 on buffer collateralization):
  rebalance vs partial-close.

The controller authorizes; `SecureMintRegistry` is the hard gate.

## Multi-tenant isolation

- **Reserves & buffers segregated per `AssetId`** in `NetworkTreasury`; no
  shared collateral pool.
- **Per-asset circuit breaker** (ERC-7265) so one unit's outflow spike can't
  drain another's.
- **Per-issuer controller state** keyed by asset; one controller's windup or
  misconfiguration is local.
- **Shared rate oracle is read-only infra** — it quotes, it never holds
  funds; a bad quote is bounded by TTL + governance fallback, and affects a
  conversion, not a reserve.
- **Cross-asset convertibility is a network effect, not a coupling.** Unit-A
  ↔ unit-B goes through the oracle graph; A's reserve never backs B.

## Risks & failure modes

- **Floor is only as good as the PoR feed.** Stale/forged attestation =
  unbacked mint. Mitigation: `is_fresh(now)` TTL gate in SecureMint; require
  a real attester (Tenzro DID or Chainlink PoR), short TTL.
- **Controller instability.** Mitigated by leaky-I anti-windup, no
  D term, EMA smoothing, and the hard floor backstop.
- **Buffer collateral depeg/illiquidity.** Mitigated by dual-threshold
  liquidation + the circuit breaker.
- **Oracle manipulation on convert.** Mitigated by quote TTL + governance-set
  fallback table; never single-DEX spot as sole source.
- **Cross-tenant contagion.** Mitigated by the isolation guarantees above.

## Open questions

- **Q1 — Issuer scope semantics.** Define the `issuer` API-key scope and the
  registration RPC surface (`tenzro_registerStableAsset`?), including which
  fields are issuer-set vs governance-set (e.g. max gains, min reserve ratio).
- **Q2 — PoR attester options.** Tenzro DID attester vs Chainlink PoR feed
  for `por_feed_id`; allowed set governance-controlled.
- **Q3 — Settlement destination field.** Add a per-asset settlement-address
  field to the registry/key record (where redemptions/settlement land), or
  keep that consumer-side.
- **Q4 — Rate-oracle source policy.** Governance-set table, Chainlink Data
  Feeds, or both with fallback; per-pair TTL.
- **Q5 — Controller upgrade path.** Ship the leaky-PI controller for v1;
  revisit a predictive/optimal-control peg loop later if v1 proves
  insufficient under stress.

## Related

- `docs/architecture/cross-vm-token-architecture.md`
- `docs/TOKENOMICS.md`
- Payment rails: `crates/tenzro-payments`
- Reserve-floor primitive: `crates/tenzro-vm/src/secure_mint.rs`
- Rate oracle: `crates/tenzro-vm/src/stable_rate_oracle.rs`
- Peg/buffer controller: `crates/tenzro-vm/src/stable_controller.rs`
