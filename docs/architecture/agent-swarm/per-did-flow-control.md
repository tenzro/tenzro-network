# Per-DID Flow Control & Admission Lanes

**Status:** Drafting (2026-05-04)
**Phase:** 1 (foundational — every other system assumes this exists)
**Touches:** `tenzro-consensus` (mempool), `tenzro-identity` (KYC tier read), `tenzro-vm` (fee floor per lane), `tenzro-node` (RPC + metrics)

## Context

Tenzro's mempool today enforces a global cap (size + per-tx-bytes) and validates each transaction in isolation. That's fine for human-rate traffic. It is not fine when a single controller spawns 10,000 autonomous agents that each submit one transaction every 200 ms. Even if every transaction is valid and pays gas, the mempool fills with *legitimate, paying* traffic from one principal, starving every other user.

Block-STM helps with execution, but execution is downstream of admission. We need accounting at the admission edge.

A second, related problem: not all agent traffic deserves the same priority. An agent under a Verified controller (KYC Enhanced+, bonded stake, on-chain reputation) is a different risk class than an anonymous agent funded from a faucet. Today they compete in the same FIFO. They shouldn't.

## Decision

Two complementary mechanisms at the mempool admission boundary:

1. **Per-controller-DID token bucket.** Every transaction's `controller_did` (resolved from the signing identity's TDIP record) gets a token bucket. Buckets refill at a controller-class-specific rate. A submitter that exhausts its bucket is rejected with a typed mempool error and a `retry_after_ms` hint.

2. **Three-lane admission with deterministic assignment.** Every transaction lands in exactly one of three lanes. Lane assignment is a pure function of `(controller_did, tx_type, attached_bond?)` — no opt-in field, nothing the submitter chooses. Lane determines: refill rate, queue priority, and fee floor.

The two compose: lane assignment sets the bucket parameters; the bucket enforces the rate.

## Architecture

### Lane definitions

| Lane | Membership criteria (any of) | Refill rate | Burst capacity | Fee floor multiplier | Queue priority |
|---|---|---|---|---|---|
| **Verified** | Controller KYC tier ≥ Enhanced AND ≥ governance-min stake bonded | 50 tx/s | 500 tx | 1.0× base fee | 0 (highest) |
| **Delegated** | Controller has TDIP DelegationScope chain rooted at a Verified controller, within bounds | 10 tx/s | 100 tx | 1.5× base fee | 1 |
| **Open** | Everyone else (incl. unverified, anonymous, faucet-funded) | 1 tx/s | 20 tx | 4× base fee | 2 |

Numbers are governance-tunable; values above are genesis defaults sized for testnet load and deliberately conservative.

The fee-floor multiplier composes with EIP-1559 base fee — Open-lane senders pay 4× the current base fee minimum, regardless of priority fee. This is not punitive; it's the price of admitting traffic the network cannot reputationally bound.

### Lane assignment function

Pure, deterministic, evaluated at the mempool ingress:

```
assign_lane(tx) -> Lane:
    controller = resolve_controller_did(tx.signer)
    if controller is None:
        return Lane::Open

    identity = identity_registry.get(controller)
    if identity is None or identity.lifecycle != Active:
        return Lane::Open  // also covers Paused/Quarantined/Terminated controllers

    if identity.kyc_tier >= Enhanced and staking.bonded(controller) >= min_verified_stake:
        return Lane::Verified

    // Delegation walk: if signer is a delegated identity whose root is Verified
    if identity.is_delegated:
        root = identity.delegation_chain_root()
        if root.kyc_tier >= Enhanced and staking.bonded(root) >= min_verified_stake:
            // Bounds check: tx must be within DelegationScope
            if delegation_scope_satisfied(tx, identity.scope):
                return Lane::Delegated
            // Out of scope: drop to Open, do not promote
        return Lane::Open

    return Lane::Open
```

Resolution is read-only against `IdentityRegistry` (in-memory + RocksDB-backed) — it adds one map lookup per tx, not a network round-trip.

### Token bucket per controller

Keyed on `controller_did` (or, for Open-lane traffic with no controller, on the signing address). Stored in-memory in the mempool subsystem:

```
struct TokenBucket {
    capacity:        u32,
    tokens:          f64,
    refill_rate:     f64,    // tokens per second
    last_refill:     Instant,
    lane:            Lane,
}
```

On admission attempt:
1. Refill: `tokens = min(capacity, tokens + (now - last_refill) * refill_rate)`
2. If `tokens >= 1.0`: `tokens -= 1.0`, admit.
3. Else: reject with `MempoolError::RateLimited { lane, retry_after_ms }`.

Buckets are not persisted across node restarts — capacity bounds the worst case, and a restart effectively resets every controller to a full bucket, which is fine because validators all restart independently.

### Lane queues

The mempool maintains three FIFOs, one per lane. Block-builder draws from queues round-robin with weights `(Verified: 8, Delegated: 4, Open: 1)` per slot — Verified gets 8 of every 13 slots, Delegated 4, Open 1. This is not strict priority; Open traffic always gets at least its 1/13 share, so a Verified-lane DoS cannot fully starve Open senders. Weights are governance-tunable.

When the mempool is under capacity, all three lanes drain freely — weights only kick in when there's contention.

### Backpressure signaling

On rejection, the mempool returns a typed JSON-RPC error:

```
{
    "code": -32011,
    "message": "rate_limited",
    "data": {
        "lane": "Open",
        "retry_after_ms": 850,
        "current_rate": 1.0,
        "burst_remaining": 0
    }
}
```

A well-behaved client (SDK, MCP client, CLI) reads `retry_after_ms` and backs off. Misbehaving clients that ignore the hint just keep getting rejected — they don't escalate to peer disconnection at the libp2p layer (rate limiting is admission-side, not transport-side; the libp2p gossip rate limiter from the existing peer-auth path is unchanged and lives one layer below this).

### Promotion / demotion

Lane assignment is computed per-transaction, not cached on the controller. This means:

- A controller crossing the KYC Enhanced threshold and bonding stake gets immediate Verified-lane treatment on its next tx.
- A controller whose KYC is downgraded or whose stake is slashed below min_verified_stake immediately drops to Open.
- A delegated identity whose delegation expires drops to Open without explicit revocation traffic.

No batch job, no heartbeat — pure pull-time evaluation.

### RPC surface

```
tenzro_getMempoolLane(did_or_address)
    → returns assigned lane + current bucket state (tokens, capacity, refill_rate)

tenzro_getMempoolStats
    → per-lane queue depth, admission rate, rejection rate (for ops dashboards)
```

No write RPCs — admission is automatic, not user-controlled.

CLI: `tenzro node mempool-lane <did>` for operator inspection.

### Metrics

Exposed on `/metrics`:

```
tenzro_mempool_admitted_total{lane}
tenzro_mempool_rejected_total{lane,reason}    // reason ∈ {rate_limited, fee_floor, mempool_full}
tenzro_mempool_queue_depth{lane}
tenzro_mempool_bucket_count                   // number of active controller buckets
```

## Interaction with existing systems

- **TDIP / `IdentityRegistry`** is the source of truth for KYC tier and delegation chain. Lane assignment is a read against the existing registry; no schema change.
- **`StakingManager`** provides `bonded(controller_did) -> u128`; new accessor on the staking crate, but no new state.
- **`tenzro-vm` fee market** consults the lane-assigned fee floor *before* its own EIP-1559 base fee check. The transaction must clear `lane.floor_multiplier × base_fee`.
- **Kill-switch (Spec 1)**: a Quarantined or Terminated controller is treated as `lifecycle != Active`, dropping the agent to Open lane immediately. A Paused controller stays in its lane (Pause does not penalize lane).
- **AgentBond (Spec 9)**: an agent with a posted bond above governance-min may be promoted into Delegated even if its controller would otherwise be Open. This is the "skin in the game" path for agents whose controllers are not KYC'd — accept the bond as a substitute for KYC.

## PQ posture

Lane assignment reads identity records that already carry hybrid Ed25519 + ML-DSA-65 keys. No new signature surface. The controller-DID resolution is the existing TDIP path.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `verified_refill_rate` | 50 tx/s | Per controller |
| `verified_burst` | 500 | |
| `delegated_refill_rate` | 10 tx/s | |
| `delegated_burst` | 100 | |
| `open_refill_rate` | 1 tx/s | |
| `open_burst` | 20 | |
| `min_verified_stake` | 10,000 TNZO | Per controller for Verified eligibility |
| `lane_weights` | (8, 4, 1) | Block-builder draw weights |
| `verified_floor_mult` | 1.0× | |
| `delegated_floor_mult` | 1.5× | |
| `open_floor_mult` | 4.0× | |
| `bond_promotes_to_delegated` | true | AgentBond override |
| `bond_min_for_promotion` | 1,000 TNZO | |

## Verification

1. **Lane assignment correctness:** test matrix covers (KYC tier × stake × delegation depth × bond present) — every input maps to exactly one lane.
2. **Bucket math:** controller submits at 60 tx/s with refill_rate=50/s — sustained rate caps at 50/s, burst absorbs first 500.
3. **Cross-lane fairness:** under saturation with 1000 Open + 100 Delegated + 10 Verified senders, observed inclusion ratio is within 5% of `(8, 4, 1)` weights.
4. **Promotion path:** controller starts Open, stakes min_verified_stake, KYC-upgrades to Enhanced — next tx admitted to Verified.
5. **Demotion path:** Verified controller's stake slashed below threshold — next tx admitted to Open.
6. **Quarantine integration:** Quarantined controller's tx is rejected at admission (lifecycle gate), not just at execution.
7. **Restart resilience:** mempool buckets reset on restart, no controller is "stuck" with empty bucket.

## Out of scope

- **Block-builder MEV-aware ordering inside a lane.** Within a lane it's FIFO. MEV strategies (priority gas auction, etc.) are a separate concern.
- **Per-application lanes.** A single application that legitimately needs 1000 tx/s should run a Verified controller; we don't add per-app fast lanes. Application-level batching is the right answer.
- **Cross-validator bucket coordination.** Each validator runs its own buckets locally. A submitter that gets rejected by validator A can retry against B — but B independently applies the same rate. Net effect: per-controller throughput is bounded by the *sum* of validator-side admission, which is a small constant multiplier on the spec'd rates and is fine for testnet. Mainnet may need a gossip-broadcast bucket consensus; deferred.
- **Smart-contract-callable lane info.** The on-chain VM does not expose lane state to contracts; it's a mempool-edge concept.
