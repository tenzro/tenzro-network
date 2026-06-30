# Bridge Fee in TNZO

Tenzro lets users pay cross-chain bridge fees in TNZO, the network's
native token, instead of needing destination-chain gas. This is the
Cosmos ICS-29 Fee Middleware / Hyperlane IGP gas-oracle / Polkadot
AssetHub `asset-conversion-tx-payment` pattern adapted to Tenzro's
multi-bridge router.

## How it works

1. **User obtains a TNZO quote** for a destination-native bridge fee:

   ```bash
   curl -s -X POST https://rpc.tenzro.network \
     -H 'content-type: application/json' \
     -d '{
       "jsonrpc": "2.0",
       "id": 1,
       "method": "tenzro_quoteBridgeFeeInTnzo",
       "params": [{
         "adapter": "ccip",
         "dest_chain": "eip155:1",
         "native_fee_smallest_unit": "1000000000000000"
       }]
     }'
   ```

   The quote envelope carries:

   - `tnzo_amount_wei` — TNZO debit due
   - `rate_q18_hex` — spot rate at quote time
   - `issued_at_ms` + `valid_until_ms` — TTL bounds (default 60s for live
     quotes)
   - `oracle_backing` — `chainlink_feed` / `governance` / `fallback`
     surfaces which oracle priced the quote
   - `quote_id_hex` — globally-unique identifier the user references in
     the matching sponsor call

2. **User signs and submits a sponsorship transaction** debiting their
   account by `tnzo_amount_wei`. The transaction validates the quote
   (TTL + signature) and credits the per-adapter sponsorship-pool vault.

3. **A registered solver / relayer fronts the destination-native fee.**
   The Tenzro on-chain receipt records the sponsorship; off-chain, the
   solver pulls TNZO from the vault after submitting delivery proof.

## Sponsorship pools

Each bridge adapter has a deterministic per-adapter pool vault address.
The 20-byte address is computed as
`SHA-256("tenzro/bridge/sponsorship-vault" || adapter_str)[0..20]`. This
means callers see exactly which vault their sponsorship debits land in
without needing to query for an address — the address is the same
across every Tenzro node and survives all restarts.

Enumerate the pool catalog:

```bash
curl -s -X POST https://rpc.tenzro.network \
  -H 'content-type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tenzro_listBridgeSponsorshipPools",
    "params": []
  }'
```

## Fee oracles

Two oracle backings ship today:

- **`GovernanceSetFeeOracle`** — operators publish per-(adapter,
  dest_chain) rate rows via the governance engine. Mirrors Hyperlane's
  `StorageGasOracle` — no on-chain price-feed dependency, easiest to
  deploy on devnet/testnet.

- **`ChainlinkFeedFeeOracle`** — reads
  `(destination_native / USD)` + `(TNZO / USD)` Chainlink data feeds to
  derive the rate. Falls back to the inner `GovernanceSetFeeOracle`
  when a feed isn't configured for a pair. The production-grade impl.

A markup over the spot rate (default 100 bps, governance-tunable)
covers FX slippage for the solver. Realised swaps optionally feed back
into the oracle via `BridgeFeeOracle::record_swap` so the rate model
drifts toward realised execution.

## Supported adapters

The `BridgeAdapterId` enum carries: `layerzero`, `ccip`, `wormhole`,
`debridge`, `hyperlane`, `axelar`, `lifi`, `canton`. Per-adapter wiring
priority reflects the current fee-token-native capability of each bridge:

- **CCIP** — easiest: `Router.ccipSend()` already accepts a feeToken
  argument (native or LINK); register TNZO as the Tenzro-side feeToken.
- **Hyperlane** — write a `TnzoIgp` implementation of
  `IPostDispatchHook`; register as the Tenzro-side default hook.
- **deBridge** — already source-chain-native; TNZO is the source input.
- **Wormhole** — wrap `paymentForExtraReceiverValue` behind the sponsor.
- **LayerZero** — OFT-Alt-style TNZO feeToken on Endpoint deployment.
- **Axelar** — use the existing `payGasForContractCall(gasToken=TNZO)`
  ERC-20 path.

## Why TNZO

- **Single-token UX.** Users hold TNZO; they should not need to
  pre-acquire ETH / SOL / MATIC just to bridge.
- **Source-side accounting.** The sponsorship pool sits on Tenzro;
  audits trace user → quote → TNZO debit → solver claim end-to-end.
- **Compose with adaptive burn.** The burn-rate dial routes a
  configurable bps of base fees to burn; bridge fees ride the same
  accounting plane (no separate deflationary path).

## Receipt model

Every sponsorship emits a `BridgeSponsorshipReceipt` mirrored to
`CF_SETTLEMENTS / bridge_sponsorship:<adapter>:<id>`. The receipt
carries:

- `sponsorship_id_hex` — SHA-256 over `(quote_id, payer_did, ts)`
- `quote_id_hex` — back-link to the consumed quote
- `adapter` + `dest_chain` — routing context
- `payer_did` — Tenzro DID who paid
- `tnzo_paid_wei` — debited amount
- `native_committed_smallest_unit` — destination-native fee the solver
  is authorised to claim
- `sponsored_at_ms` — wall-clock issue time
- `pool_address_hex` — vault that received the debit

Receipts attach to the on-chain settlement layer via the existing
`MandateRef { protocol: "bridge-sponsorship" }` model — same audit
plane as escrow / settlement / capital-intent receipts.

## RPC reference

| Method | Direction | Description |
|---|---|---|
| `tenzro_quoteBridgeFeeInTnzo` | Read | Quote a destination-native fee in TNZO for a given adapter + chain. |
| `tenzro_listBridgeSponsorshipPools` | Read | Enumerate canonical per-adapter pool vault addresses. |

The matching `BridgeFeeSponsor` / `BridgeFeeOracle` traits live in
`crates/tenzro-bridge/src/fee_sponsor.rs` +
`crates/tenzro-bridge/src/fee_oracle.rs`. SDK consumers (Rust + TS)
will surface a `BridgeFeeClient` wrapping both methods.

## Status

The protocol substrate (oracle trait + sponsor surface + pool address
derivation + quote/sponsor RPC) is live. Per-adapter wiring
(CCIP / Hyperlane / deBridge first, then Wormhole / LayerZero / Axelar)
lands in subsequent waves; ERC-7683 envelope unification across all
six adapters is the long-term UX endgame (the Across pattern: user
signs one source-chain order quoting TNZO input, solver picks the
optimal bridge).
