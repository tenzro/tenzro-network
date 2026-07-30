# tenzro-cortex

Recurrent-depth reasoning as a schedulable, metered, receipted network
primitive.

## Overview

A recurrent-depth transformer answers by looping the same block a variable
number of times rather than by emitting more tokens. That loop count is the
compute. Cortex treats it as the billable unit: a caller states how much
reasoning depth it is willing to pay for, the worker runs within that ceiling,
and the receipt records how many loops were actually executed.

The Rust side of that arrangement owns metering, pricing, budget enforcement,
receipt signing, and discovery. It does not own the forward pass. The model
runs in a separate process behind a small JSON API, which is what keeps PyTorch
and GPU drivers out of the validator binary — an operator can run a validator
with no accelerator at all and simply not register a Cortex worker.

## Modules

| Module | Role |
|---|---|
| `traits` | `RecurrentDepthModel` — the backend seam. One method: run a request at a loop depth and return an unpriced response. |
| `sidecar` | `SidecarModel` / `SidecarConfig` — HTTP client for an external model process. Posts hex-encoded input to `/v1/cortex/infer` and reads back output, loops used, and the weights and runtime hashes. |
| `mock` | `MockCortexModel` — deterministic backend for tests, so the pricing and budget paths can be exercised without a model. |
| `worker` | `CortexWorker` — what a node actually exposes. Checks the caller's `ReasoningBudget` against the model's declared `CortexModelFamily`, delegates to the backend, prices the result, refuses it if the cost exceeded the budget, and re-signs the receipt at the final price. |
| `receipt` | `canonicalize_input`, `canonicalize_output`, `hash_commitment`, `sign_receipt`, `verify_receipt` — the canonical preimage and its Ed25519 signature. |
| `signer` | `PersistentCortexSigner` — loads a 32-byte Ed25519 secret from disk, generating and persisting one on first launch, owner-read-only on Unix. The `worker_did` in a receipt therefore survives a restart and historical receipts stay verifiable. |
| `attestation` | `TeeAttestationProvider` / `ZkProofProvider` / `AttestationSuite` — provider traits taking the receipt preimage and returning opaque proof blobs. Defined here rather than depending on `tenzro-tee` or `tenzro-zk` directly, which would invert the dependency graph; the node wires concrete implementations at startup. |
| `advertisement` | `CortexAdvertisement`, `AdvertisementBroadcaster`, `CortexGossipPublisher`, `RemoteWorkerRegistry` — periodic signed advertisement on the `tenzro/cortex` topic, so a caller can find a remote worker without an RPC registration step. |
| `metrics` | `CortexMetrics` — atomic counters for loops executed, cumulative cost, a latency histogram, rejections broken down by `RejectionReason`, and attestations produced. Renders to Prometheus text exposition. |

## Pricing

`CortexPricing::compute` charges `price_per_loop * loops_used` on top of base
token fees, with separate premiums when the caller asked for a TEE quote or a
ZK proof. Because the price depends on loops actually executed, a request that
converges early costs less than its ceiling — the budget is a cap, not a
quote.

`ReasoningTier` and `CortexModelFamily` bound what a caller may ask for: a
family declares its own minimum and maximum loop depth, and a budget that
exceeds the family's range is rejected before any inference runs.

## Receipts

Every response carries a signed `CortexReceipt` binding: input commitment,
output commitment, weights hash, runtime hash, loops used, price, and worker
DID. The weights hash is what makes the receipt an assertion about a specific
set of parameters rather than about a model name, so a worker that swaps
weights produces visibly different receipts.

## Used By

- **`tenzro-node`** — holds a `CortexWorker` per model id, exposes
  `tenzro_cortexReason` / `tenzro_cortexInference` /
  `tenzro_registerCortexWorker` / `tenzro_listCortexWorkers` /
  `tenzro_listRemoteCortexWorkers`, the `cortex_reason` MCP tool, the `cortex`
  A2A skill, and the `cortex_gossip` adapter that carries advertisements over
  the libp2p gossipsub service.
- **`tenzro-cli`** — the `tenzro cortex` command group.

## Tests

```bash
cargo test -p tenzro-cortex
```

## License

Apache-2.0.
