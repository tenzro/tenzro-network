# Dual-Rail Gas: TNZO + USDC Paymaster with Burn Quota

**Status:** Drafting (2026-05-04)
**Phase:** 2 (competitive positioning vs. Tempo's stablecoin-gas thesis)
**Touches:** `tenzro-vm` (paymaster + EIP-1559), `tenzro-token` (treasury, burn), `tenzro-payments` (settlement integration), `tenzro-bridge` (USDC sourcing), `tenzro-node` (RPC + RPC for quote)

## Context

Tempo's enterprise pitch in 2026 is "stablecoin gas, no native token tax." It's persuasive — finance teams hate volatile gas exposure, and a chain that lets them pay fees in USDC removes a procurement objection. Several other L1s (Tron-USDT, some Ethereum L2s with native account abstraction paymasters) are converging on the same UX.

Tenzro's tokenomics depend on TNZO being the gas token: every transaction burns base fee under EIP-1559, and that burn is the supply sink that backs token value. If we let users pay gas in USDC and *don't* burn TNZO, we lose the sink and Tempo's thesis wins. If we refuse USDC entirely, enterprise integrators route around us.

The compromise that kicks the can — "pay in USDC, swap to TNZO at submission, burn that" — works in theory but introduces per-tx swap latency and slippage, and the TNZO/USDC pool has to exist with deep liquidity from day one.

This spec describes a different compromise: **users pay USDC, the paymaster sponsors the TNZO gas, and the protocol burns TNZO from a treasury-funded quota that is replenished asynchronously at TWAP**. Users get stablecoin UX. The TNZO sink is preserved. The treasury, not the user, eats the swap risk.

## Decision

A protocol-owned ERC-4337 paymaster that:

1. Accepts USDC (and a governance-tunable allow-list of stablecoins) as payment for gas at the current oracle TNZO/USD rate.
2. Sponsors the equivalent TNZO gas to the EntryPoint, drawn from a **burn quota** funded by the treasury.
3. Asynchronously, on a daily epoch, swaps accumulated USDC fees for TNZO via a designated AMM/RFQ at TWAP and burns the TNZO, replenishing the quota.

Net invariant: **for every USDC-paid op, an equivalent TNZO is burned from circulating supply.** The user never holds TNZO; the protocol still extracts the sink.

## Architecture

### Components

```
                    ┌────────────────────┐
   USDC tx          │  StablecoinPaymaster│
   ───────────────▶ │  (ERC-4337 paymaster)│
                    └──────────┬──────────┘
                               │ sponsors TNZO gas
                               ▼
                    ┌────────────────────┐
                    │   EntryPoint        │  (existing)
                    └──────────┬──────────┘
                               │ burns base fee (TNZO)
                               ▼
                    ┌────────────────────┐
                    │   BurnQuota         │  (new contract)
                    │   - balance: TNZO   │
                    │   - drained per op  │
                    │   - refilled daily  │
                    └──────────┬──────────┘
                               │ daily refill
                               ▼
                    ┌────────────────────┐
                    │   QuotaReplenisher   │
                    │   - reads USDC reserve │
                    │   - swaps at TWAP    │
                    │   - burns TNZO       │
                    │   - tops up BurnQuota │
                    └────────────────────┘
```

Three new contracts at well-known protocol addresses; one extension to the existing EntryPoint.

### Per-transaction flow

User submits a UserOperation with:
- `paymaster = StablecoinPaymaster.address`
- `paymasterData = encode(USDC_amount_max, oracle_price_bound)`

`StablecoinPaymaster.validatePaymasterUserOp`:

1. Read current `tnzo_per_usdc` from oracle (Chainlink + Pyth median, see §"Oracle"). Reject if oracle is stale or median deviates > governance-tunable bound.
2. Compute `tnzo_gas_estimate = userOp.maxFeePerGas × userOp.preVerificationGas` plus exec gas estimate.
3. Compute `usdc_required = tnzo_gas_estimate × tnzo_per_usdc × (1 + swap_buffer_bps)`.
4. Reject if `usdc_required > paymasterData.USDC_amount_max` (user's pre-stated cap).
5. Reject if `BurnQuota.balance < tnzo_gas_estimate` (quota exhausted — fail closed; user retries when quota refills, or pays in TNZO directly).
6. Pull `usdc_required` from user via ERC-20 `transferFrom` to the paymaster.
7. Transfer `tnzo_gas_estimate` from BurnQuota to EntryPoint as gas sponsorship.

EntryPoint executes the op, burns the base-fee portion of the TNZO it received, refunds unused TNZO to the paymaster (which forwards a USDC refund to the user via the post-op hook).

`StablecoinPaymaster.postOp`:

1. Compute actual TNZO consumed: `actual = userOp.gasUsed × actualGasPrice`.
2. Compute USDC the user actually owed: `actual_usdc = actual × tnzo_per_usdc_locked`.
3. Refund `usdc_required - actual_usdc - postop_fee` to user.
4. Account `actual_usdc` to the paymaster's USDC reserve.

### Burn quota

The `BurnQuota` contract holds a TNZO balance that is the **only** TNZO sponsored to the EntryPoint via the stablecoin path. Drained per-op; refilled daily.

State:
```
BurnQuota {
    balance:           u128,            // current TNZO available to sponsor
    cap:               u128,            // max balance, governance-tunable
    daily_target:      u128,            // refill target per epoch
    last_refill:       Timestamp,
    deficit:           i128,            // negative if we owe burns from prior epoch
}
```

When sponsorship would drive `balance < min_reserve` (governance-tunable, default 10% of cap), the paymaster fails closed — users with USDC must wait or pay in TNZO. This is the steady-state invariant: **users never get USDC-paid gas without an equivalent TNZO burn waiting in the quota.**

### Daily refill (QuotaReplenisher)

Runs once per epoch (24h, governance-tunable). Privileged-VM tx, signed by the governance-controlled replenisher key (multisig at genesis, fully-on-chain governance executor by mainnet):

1. Read paymaster's accumulated USDC reserve.
2. Read 24h TWAP of TNZO/USDC from designated venues (Wormhole NTT-bridged USDC pool on Tenzro DEX + an external CEX feed via Pyth, median).
3. Swap `min(USDC_reserve, daily_target × tnzo_per_usdc_twap × (1 + slippage_buffer))` USDC for TNZO at TWAP via designated swap route. Slippage cap governance-tunable.
4. Burn the resulting TNZO (already in circulating supply — the swap counterparty had it).
5. Mint `equivalent` TNZO to BurnQuota from the **treasury sponsorship allocation** (a pre-allocated treasury slice, not new emission).
6. Update `BurnQuota.last_refill` and `deficit`.

Net effect per epoch: circulating TNZO decreases by the swap-and-burn amount; BurnQuota is replenished from treasury allocation. The sink is real (burn is permanent); the treasury is the float-provider.

The treasury sponsorship allocation is a one-time genesis carve-out (governance-decided %, suggest 5-10% of treasury). It's a **revolving fund**, not a recurring expense — it lends TNZO to the paymaster and gets paid back via the swap, minus the treasury's slippage exposure.

### What the treasury actually loses

Each epoch the treasury's worst-case loss is the spread between the at-tx-time oracle rate (locked by paymaster.validatePaymasterUserOp) and the TWAP rate at refill time, plus swap slippage. In a quiet market that's a few bps. In a TNZO crash, it could be material. Mitigations:

- **Slippage buffer** at validation (`swap_buffer_bps`, default 100bps) overcharges users so the treasury usually nets positive on calm days, building a reserve.
- **Hard cap on per-epoch refill**: `daily_target` bounds the worst-case TNZO the treasury commits per day. If demand exceeds that, paymaster fails closed (same as quota exhaustion).
- **Governance circuit-breaker**: a price-divergence trigger (oracle vs TWAP > 5% over 1h) halts the paymaster until governance review. USDC-paid gas is paused; TNZO-paid gas continues unaffected.

### Oracle

Two-source median:

- **Chainlink** TNZO/USD feed on Tenzro (deployed via Chainlink CCIP integration).
- **Pyth** TNZO/USD via the existing Pyth integration on the bridge mesh.

Reject if either is stale (> 60s, governance-tunable). Use median; if one source is stale, single-source is rejected (never trust one feed). Both stale → paymaster fails closed.

For the daily TWAP refill, use **24h TWAP from on-chain Tenzro DEX** (USDC-Wormhole-NTT pool) cross-checked against a Pyth 24h aggregate. If they diverge > 2%, governance review.

### Stablecoin allow-list

Genesis allow-list:

- USDC (Wormhole NTT or CCT depending on counterparty)
- USDT (Wormhole NTT)
- USDS (Sky Protocol)

Each is a separate ERC-20 on Tenzro EVM. Paymaster maintains a per-stablecoin reserve and a per-stablecoin oracle. New entries via governance. Removal also via governance — and on removal, the paymaster stops accepting new ops in that stablecoin and continues swapping the existing reserve down to zero before delisting.

### RPC surface

```
tenzro_quoteStablecoinGas { user_op }
    → returns { stablecoin, usdc_required, tnzo_equivalent, oracle_price, oracle_age_ms,
                quota_available, fail_reason? }

tenzro_getBurnQuota
    → returns { balance, cap, daily_target, last_refill, deficit }

tenzro_listSupportedStablecoins
    → list of allowed stablecoins + addresses + per-token oracle status
```

No new write RPCs; users submit UserOperations through the existing AA path.

CLI: `tenzro wallet send --gas-token=USDC` (auto-routes through paymaster).

### Treasury accounting

The paymaster's USDC reserve is treasury-owned but operationally segregated. After each refill the reserve should be approximately empty (modulo the slippage buffer accumulating as treasury surplus). Surplus accrues in a `PaymasterSurplus` sub-account; deficit is covered from main treasury and logged. Both are read by the existing treasury reporting RPCs.

## Interaction with existing systems

- **EIP-1559 base fee** is unchanged — paymaster sponsors at the prevailing rate, and the TNZO it sponsors is burned through the normal base-fee burn path. No new burn mechanism.
- **ERC-4337 v0.8 EntryPoint** already supports paymaster validation; this is a new paymaster, not an EntryPoint extension.
- **`tenzro-payments`** (MPP / x402 / Tempo): this paymaster is the gas-layer answer. The application-layer payment protocols are unchanged. An MPP session paid in USDC at the application layer still pays gas via this paymaster — no double-accounting.
- **Wormhole NTT USDC** is the canonical USDC bridge in (per `interop.md`). The paymaster accepts NTT-USDC. Other USDC representations (CCT, etc.) are separate allow-list entries with their own oracles.
- **Per-DID flow control (Spec 2)**: Open-lane senders pay 4× base fee floor *and* this paymaster's slippage buffer — the two compose, deliberately, to make Open-lane USDC-paid gas more expensive than Open-lane TNZO-paid gas. Verified-lane senders see no penalty.
- **Adaptive burn governance (Spec 8)**: aggregates this paymaster's burn volume into the global burn signal, so the burn-rate taper accounts for stablecoin-paid traffic correctly.

## PQ posture

UserOperations carry the same hybrid Ed25519 + ML-DSA-65 envelope as native txs. Paymaster contract is on EVM; signatures don't change. Oracle attestations from Chainlink/Pyth are out-of-scope for PQ in this revision (their PQ migration is on their roadmap).

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `paymaster_enabled` | true | Master kill switch |
| `swap_buffer_bps` | 100 (1%) | Validation-time overcharge |
| `slippage_cap_bps` | 200 (2%) | Refill-time slippage guard |
| `daily_refill_target` | 1,000,000 TNZO | Max sponsored per epoch |
| `min_quota_reserve_pct` | 10% | Below this, fail closed |
| `oracle_max_staleness_ms` | 60000 | |
| `oracle_max_deviation_bps` | 500 (5%) | Chainlink vs Pyth divergence trigger |
| `treasury_sponsorship_pct` | 5% | One-time treasury carve-out |
| `allowed_stablecoins` | [USDC, USDT, USDS] | |
| `replenisher_authority` | governance multisig | |

## Verification

1. **Happy path:** user submits USDC-paid op, paymaster validates, EntryPoint executes, base fee burns, post-op refunds correct USDC, BurnQuota debited.
2. **Quota exhaustion:** simulate 110% of daily refill in 12h — first 100% admit, last 10% fail closed with typed error.
3. **Oracle divergence:** Chainlink at $1.00/TNZO, Pyth at $1.10/TNZO (> 5% divergence) — paymaster pauses, falls back to TNZO-paid gas.
4. **Refill correctness:** simulate one epoch with $100k USDC accumulated, verify swap-and-burn produces the right TNZO amount within slippage_cap_bps.
5. **Refund accuracy:** user pays for max gas, op uses 60% of estimate — refund is `40% - postop_fee` USDC.
6. **Stablecoin delisting:** governance removes USDT — new USDT ops rejected; existing USDT reserve refills down to zero.
7. **Treasury isolation:** paymaster surplus/deficit accounting reconciles to treasury within 1 wei per epoch.

## Out of scope

- **Per-application paymaster overrides.** Apps that want to sponsor their users' gas wholesale build their own paymasters (standard ERC-4337 pattern); this is the protocol's stablecoin paymaster, not the only paymaster.
- **Non-stablecoin gas tokens.** WBTC-paid gas, ETH-paid gas, etc. are not in scope. The set is intentionally narrow — stablecoins only — because their oracle behavior is well-bounded.
- **Real-time TWAP swapping.** Swaps are batched daily, not per-tx. Per-tx swapping was rejected because it adds latency, slippage, and oracle-cost per tx. Daily refill amortizes those costs.
- **Stablecoin payouts to providers.** Inference/provider payouts in stablecoin are an application-layer choice; this spec is gas-only.
