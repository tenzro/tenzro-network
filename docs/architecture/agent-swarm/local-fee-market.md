# Hot-State Local Fee Market

**Status:** Drafting (2026-05-04)
**Phase:** 3 (post-mainnet hardening)
**Touches:** `tenzro-vm` (Block-STM, EIP-1559, fee market), `tenzro-storage` (per-account fee state), `tenzro-node` (RPC + metrics)

## Context

Tenzro's fee market today is **global**: one EIP-1559 base fee per block, paid by every transaction regardless of which contract or account it touches. This is correct under uniform load. It's the wrong shape under swarm load, where a small set of contracts (a popular oracle, an agent-template factory, a single high-volume marketplace) attract a disproportionate share of transactions.

Symptoms under uniform fee market + concentrated load:

- **Block-STM reexecution thrashing.** When 200 of 300 transactions in a block target the same hot account, the optimistic concurrency control hits its conflict threshold (50%) and falls back to sequential execution. Throughput collapses for that block.
- **Spillover contention pricing.** Hot-contract callers and unrelated-contract callers pay the same elevated base fee — unrelated callers subsidize the hot-contract congestion they didn't cause.
- **No per-account back-pressure signal.** A swarm spinning up 1000 callers against a hot oracle has no fee-side reason to slow down. Per-DID flow control (Spec 2) caps total submitter throughput, but doesn't redirect the swarm away from a specific hot account.

Solana's SIMD-0096 ("Local Fee Markets") and Aptos' Block-STM contention pricing both showed the right shape: per-account fee escalation when execution-time contention is detected. Tenzro has the same observability (Block-STM reexecution counter) and the same need.

## Decision

A **local base fee** per high-traffic account, in addition to the global base fee. The local fee:

- Is computed from the Block-STM **reexecution counter** for that account over a sliding window.
- Composes additively with global base fee: `effective_floor = global_base_fee × lane_mult + local_fee(account)`.
- Applies to **state-write conflicts**, not state reads. Read-only access doesn't escalate.
- Burns the same way global base fee does — same EIP-1559 burn path.

Hot accounts get expensive to write to; cold accounts are unaffected. Swarm callers see escalating fees on the hot path, naturally fan out or back off.

## Architecture

### Reexecution counter as the signal

Block-STM already tracks reexecution per transaction. Today the only consumers are the conflict-threshold (50%) circuit-breaker and the metrics endpoint. We add an aggregator:

```
struct AccountContentionCounter {
    account:                  Address,
    reexec_count_window:      u64,    // Block-STM reexecutions touching this account, last N blocks
    write_count_window:       u64,    // total write txs touching this account, last N blocks
    last_block:               u64,
    contention_score:         f64,    // = reexec / write, [0.0, 1.0]
}
```

Maintained per-account in a `DashMap<Address, AccountContentionCounter>` in the VM's `BlockStmExecutor`. Window: 64 blocks (governance-tunable). Counters decay each block (linear-decay over the window).

`contention_score`:
- 0.0 = no reexecutions in window → cold account
- 1.0 = every write reexecuted → maximally contended

Threshold for hotness: `contention_score >= 0.20` AND `write_count_window >= 50`. Both, because a low-traffic account with 1 write and 1 reexec scores 1.0 but isn't actually congested.

### Local fee curve

For accounts that crossed the hotness threshold:

```
local_fee(account) =
    global_base_fee × multiplier(contention_score)

multiplier(s) =
    if s < 0.20:  0.0
    if s < 0.50:  s × 2.0           // 0.0 → 1.0
    if s < 0.80:  1.0 + (s - 0.50) × 5.0    // 1.0 → 2.5
    else:          2.5 + (s - 0.80) × 12.5   // 2.5 → 5.0
```

Multiplier saturates at 5× — even a fully-contended account caps at 5× global base fee in addition to the global. Cap is to bound worst-case user cost while still being painful enough to redirect.

Curve adjusts each block by ±12.5% max (mirrors EIP-1559 base fee adjustment), so local fees move smoothly.

Cold accounts pay zero local fee. ~99% of accounts will be cold at any given moment.

### Effective fee floor

For a transaction `tx` writing to accounts `A1..An`:

```
effective_floor(tx) =
    global_base_fee × lane_mult(tx)
    + max(local_fee(A_i) for i in 1..n)
```

We use `max`, not `sum`, of local fees across written accounts. A cross-account tx pays the highest local fee among its writes — adversarially batching writes across hot accounts doesn't multiply the cost.

`tx.maxFeePerGas` must clear `effective_floor`; otherwise the tx is rejected at admission. Priority fee is on top, unchanged.

### Fee distribution

Local fee is **burned** like global base fee — same EIP-1559 burn path. This is deliberate:

- If we sent local fees to the hot account's owner, the owner has incentive to *encourage* contention to extract rents (perverse — exactly the wrong incentive).
- If we sent them to validators, validators have incentive to selectively include contended txs over uncontended (also bad).
- Burning is neutral; the only benefit is to overall token supply, shared by all holders.

Adaptive burn governance (Spec 8) sees these burns in its `UsageTracker` aggregate and accounts for them.

### State

Per-account contention counters are NOT persisted across restarts. They are in-memory only:

- A node restart resets every account to score 0.0. Hot accounts re-warm in 64 blocks under continued load.
- Different validators may have slightly different scores at any instant, but they all observe the same chain of write events and converge within the window.
- The local fee for a given block is computed from the **proposer's** contention counters at proposal time, not consensus across all validators. Validators verify the fee floor is internally consistent with the counter state implied by the proposed block — no need to gossip counters.

### RPC surface

```
tenzro_getAccountFee { address }
    → { contention_score, local_fee_wei, effective_floor_wei, threshold_crossed }

tenzro_listHotAccounts { min_score?, limit }
    → [{ address, contention_score, local_fee_wei, write_count }]

tenzro_estimateGasFee { tx }
    → { global_base_fee, lane_mult, max_local_fee, effective_floor }
    // pre-existing eth_estimateGas extended to include local_fee
```

CLI: `tenzro node hot-accounts`, `tenzro node fee-quote <tx-json>`.

MCP: `get_account_fee`, `list_hot_accounts`, `estimate_gas_fee` tools.

### Metrics

```
tenzro_local_fee_account_count               # distinct accounts above threshold
tenzro_local_fee_max_multiplier              # current max across all accounts
tenzro_local_fee_burn_total                  # cumulative burn from local fees
tenzro_blockstm_reexec_per_account{account}  # debug-level, may be high cardinality
```

The `_per_account` metric is opt-in (governance/operator flag) since it's high-cardinality.

### Interaction with smart contracts

The on-chain VM does NOT expose `local_fee(account)` to contract code. Contracts can't read their own contention score. This is deliberate:

- A contract that knew its score could implement adversarial gas pricing logic (refuse calls below a threshold, etc.).
- Local fees are an admission-edge concept, not a contract-visible one.

If an application needs to surface "this contract is congested" to its UI, it queries `tenzro_getAccountFee` from the client, not from inside the VM.

## Interaction with existing systems

- **EIP-1559 base fee market** is the underlying mechanism. Local fee composes additively. EIP-1559 base fee burn already exists; local fee burn rides the same path.
- **Block-STM** already produces the reexecution counter; this spec just adds an aggregation layer over it. No change to STM's correctness model.
- **Per-DID flow control (Spec 2)** still applies. A Verified-lane sender targeting a hot account pays `(1.0 × global_base_fee) + max_local_fee`. Open-lane sender pays `(4.0 × global_base_fee) + max_local_fee`. The two are independent dimensions — lane is "who you are," local fee is "what you touch."
- **Adaptive burn governance (Spec 8)** sees `tenzro_local_fee_burn_total` as part of the burn signal and adjusts the global taper accordingly.
- **DA offload (Spec 7)**: receipt entries that include the principal chain (Spec 5) are written to high-traffic CF_SETTLEMENTS prefixes — those are *storage* hot paths, not VM hot accounts, and don't trigger this fee market.

## PQ posture

No new signature surface. Local fee is a dimensionless scalar computed by every validator independently from observable on-chain state.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `enabled` | true | Master kill switch |
| `window_blocks` | 64 | Smoothing window |
| `hotness_score_threshold` | 0.20 | Below: no local fee |
| `hotness_write_threshold` | 50 | Below: no local fee |
| `multiplier_cap` | 5.0× | Max local fee multiplier |
| `adjustment_pct_per_block` | 12.5% | Mirrors EIP-1559 |
| `local_fee_burn_pct` | 100 | All burned; if changed, remainder routes to treasury |

## Verification

1. **Cold account, no fee:** account with 0 reexecutions, 1000 writes — `local_fee == 0`.
2. **Threshold crossing:** account at score 0.19 has zero fee; same account at 0.21 has nonzero.
3. **Curve smoothness:** local fee for an account ramping from 0.20 to 0.80 reexec rate moves monotonically and never jumps > 12.5% per block.
4. **Saturation:** account at score 1.0 has multiplier == 5.0, not higher.
5. **Cross-account `max` semantics:** tx writing to two hot accounts pays max(A, B), not A+B.
6. **Decay:** account stops being written to — score decays to 0 over `window_blocks`.
7. **Restart resilience:** restart drops all counters; tx fees revert to global-only until window refills.
8. **Burn accounting:** `tenzro_local_fee_burn_total` matches the sum of (effective_floor − global_base_fee × lane_mult) × gas_used over all txs hitting hot accounts.

## Out of scope

- **Per-storage-slot fee market.** Solana SIMD-0096 followups consider per-write-set granularity finer than account-level. We start at account; finer is a future tightening if data shows account-level too coarse.
- **Cross-contract congestion graphs.** Contention often clusters along call-graph edges (caller A always touches B). Modeling that graph is research-grade; account-level captures the first-order effect.
- **Read-side congestion pricing.** Hot reads don't trigger local fees. Block-STM doesn't reexecute on reads (MVCC handles them), so the signal isn't there. Pure read-heavy workloads would need a different signal (e.g., RocksDB cache miss rate); deferred.
- **Validator-coordinated counter consensus.** Each validator runs its own counter; small divergence is acceptable. If divergence ever causes validators to disagree on whether a block's fee floor is valid, we'd need gossip — not seen as necessary at testnet/mainnet scales.
