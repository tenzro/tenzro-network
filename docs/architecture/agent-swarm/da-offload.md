# DA Offload for Receipts and Inference Payloads

**Status:** Drafting (2026-05-04)
**Phase:** 3 (storage hardening)
**Touches:** `tenzro-storage` (commitment-only mode), `tenzro-settlement` (receipt schema), `tenzro-model` (inference payload schema), `tenzro-bridge` (DA adapter), `tenzro-node` (RPC + verifier)

## Context

Tenzro stores **the full payload** of every inference receipt, settlement receipt, and most agent lifecycle records on-chain. At human transaction rates this is fine. At swarm rates it isn't:

- **Inference receipts.** A single served model call returns a request/response pair that can be 1-50 KB. At 100 inferences/s that's 100-5000 KB of growth per second, all written to RocksDB and replicated via consensus. Block sizes balloon, validator sync time grows, full-node disk costs scale linearly with traffic.
- **Settlement receipts** with full principal chains (Spec 5) and cart mandates can be 2-10 KB each.
- **Agent template / spawn records.** Reference templates can be 10-100 KB JSON.

Putting all of this in consensus state is wasteful — most of it is never read again, and when it is read, it's a one-off audit query that doesn't need consensus-grade replication.

Three external DA layers are production-mature in 2026:

- **EigenDA** — 100 MB/s throughput, restaked-ETH security, attestations via Eigen attestation service.
- **Celestia** with Matcha — 128 MB blocks, namespace-scoped data sampling, light-client verifiable.
- **Avail** — 4-10 GB blocks via DAS, KZG commitments, Polygon ecosystem.

All three solve the same problem: "store this blob cheaply, prove it's available to anyone who asks." Tenzro should use them where consensus replication is overkill.

## Decision

A **commitment-only mode** for high-volume receipts. Instead of writing the full payload into CF_SETTLEMENTS / CF_MODELS, the receipt stores:

- A 32-byte commitment (KZG / Reed-Solomon / hash, depending on DA backend).
- A typed pointer (DA backend ID + namespace + chunk locator).
- A small inline summary (amount, payer, payee, timestamp — fields needed for indexing).

The full payload lives in the DA layer. Anyone who needs the payload retrieves it via the pointer and verifies it matches the commitment. The commitment is the chain's only guarantee — but that's the same guarantee Ethereum L2s rely on for billions of dollars of value, so it's enough.

Per-receipt-kind, governance-controlled toggle: receipts can be `Inline` (full payload on-chain, today's behavior) or `OffloadedDA` (commitment + pointer). Sensitive receipts (kill-switch, governance, settlement of escrow ≥ threshold) stay `Inline`. Bulk-read receipts (inference, agent message) go offloaded.

## Architecture

### Receipt envelope

```
ReceiptEnvelope {
    kind:               "Settlement" | "Inference" | "AgentMessage" | "KillSwitch" | ...,
    storage_mode:       "Inline" | "OffloadedDA",
    inline_summary:     ReceiptSummary,        // always present, ~200-400 bytes
    inline_payload:     Option<bytes>,         // present iff Inline
    da_pointer:         Option<DaPointer>,     // present iff OffloadedDA
    commitment:         Hash,                  // canonical hash over the full payload
}

ReceiptSummary {
    receipt_id:         Hash,
    payer:              Option<String>,
    payee:              Option<String>,
    amount_tnzo:        Option<u128>,
    timestamp:          Timestamp,
    principal_chain_summary: Option<{controller_did, controller_kyc_tier, depth}>,
}

DaPointer {
    backend:            "EigenDA" | "Celestia" | "Avail",
    namespace:          bytes,
    locator:            bytes,            // backend-specific (batch_id+chunk for Celestia, blob_id for Avail, etc.)
    commitment_kzg:     Option<bytes>,    // backend-attested commitment, may differ from `commitment`
    attestation_root:   Option<Hash>,     // for EigenDA: attestation service root
}
```

`commitment` is `SHA-256(canonical_payload_bytes)`. Backends that produce KZG / RS commitments store them in `commitment_kzg`, but the chain-of-custody is `commitment` (SHA-256), uniformly. Verifiers check both.

### Backend abstraction

```rust
#[async_trait]
pub trait DaBackend {
    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> Result<DaPointer>;
    async fn fetch(&self, pointer: &DaPointer) -> Result<bytes>;
    async fn verify_availability(&self, pointer: &DaPointer) -> Result<()>;
}
```

Three implementations as features (mirroring TEE provider gating):

- `da-eigenda` — submits via EigenDA disperser RPC, fetches via retrieval RPC, verifies via attestation service.
- `da-celestia` — submits via celestia-node JSON-RPC, fetches via DAS sample, verifies via Matcha namespace proof.
- `da-avail` — submits via Avail node RPC, fetches via DAS, verifies via KZG opening proof.

A node operator picks one or more at startup; offload writes go to the operator-chosen primary backend; reads can fall back to others.

### Submission path

When a receipt is being written and the kind is governance-marked OffloadedDA:

1. Compute `commitment = SHA-256(canonical_payload)`.
2. Async submit payload to DA backend. Block consensus on the submission attestation? **No.** Use a "submit-then-commit" pattern:
   - Validator who's including the receipt in a block submits to DA *first*.
   - DA backend returns `DaPointer` with attestation that the blob is available.
   - Validator includes the receipt with `da_pointer` populated.
   - Other validators verify the pointer is well-formed but DO NOT re-fetch (would be O(n²) bandwidth).
3. The chain commits the receipt envelope. The chain-side guarantee is the commitment hash; the DA-side guarantee is whatever backend was used.

If the validator's DA submission fails, the receipt is written `Inline` instead — soft fallback. Operators see this in metrics. Repeated fallbacks indicate a sick DA backend; ops can swap backend without governance.

### Retrieval path

When a client wants a payload:

1. Read receipt envelope from chain.
2. If `Inline`: payload is in the envelope. Done.
3. If `OffloadedDA`:
   - Try local cache (LRU, governance-tunable size, default 1 GB).
   - On miss, call `DaBackend::fetch(pointer)`.
   - Verify `SHA-256(returned_payload) == commitment`. Reject if mismatch.
   - Cache and return.

Verifying availability without retrieving is also offered: `tenzro_verifyDaPointer(pointer)` — validator-side, calls `DaBackend::verify_availability` and returns yes/no. Useful for clients that want to know a pointer is good before paying retrieval bandwidth.

### Per-receipt-kind defaults

| Kind | Default mode | Rationale |
|---|---|---|
| Settlement (escrow create/release/refund) | Inline | Small payload, audit-critical |
| Settlement (channel update) | OffloadedDA | High volume, summary suffices for routine queries |
| Inference receipt | OffloadedDA | High volume, large payload (request/response), rarely re-read |
| Agent message receipt | OffloadedDA | High volume, often megabytes for vision/audio |
| Kill-switch receipt | Inline | Audit-critical, low volume |
| Lifecycle (register, spawn) | Inline | Small payload, infrequent |
| Governance proposal/vote | Inline | Critical, low volume |
| Block (block bodies) | Inline | Consensus integrity — never offload |

Block bodies stay Inline always. This spec is explicitly for receipts and event records, not for state or block data.

### Indexing under offload

The `inline_summary` carries everything needed for the existing settlement/identity/agent indexes (CF_SETTLEMENTS prefixes etc). A query that just wants "list receipts by controller in window W" doesn't need the payload — it works against summaries. Only queries that need the full payload pay the DA fetch cost.

This means `tenzro_listReceiptsByController` and `tenzro_summarizeController` (Spec 5) continue to be O(index lookup), unchanged.

### Cost model

Offloading shifts cost from validator disk to DA fees. The receipt-writer pays the DA submission fee at write time, denominated in the DA backend's native gas (ETH for EigenDA, TIA for Celestia, AVAIL for Avail). Operators bridge the necessary token in via existing bridge adapters (see `interop.md`); ops budget for it.

For network sustainability, a slice of the fee burned via local fee market (Spec 6) and the global EIP-1559 burn can be earmarked to subsidize DA submissions — governance dial.

### Pruning

Inline receipts older than the retention window are pruned from full nodes (existing pruning path). Offloaded receipts:

- The chain-side `ReceiptEnvelope` (commitment + pointer + summary) is small enough that pruning is not urgent — keep indefinitely.
- The DA-side payload obeys the DA backend's retention. EigenDA: ~14-28 days configurable. Celestia: indefinite via paid storage. Avail: 28 days standard.
- For any receipt where retention beyond DA backend lifetime is needed (regulatory: 7 years for principal-chain receipts), the chain operator periodically re-pins the payload — fetches from DA, resubmits, updates pointer in a privileged-VM tx.

The re-pinning flow is a Phase 3.5 task: ship the offload mode first, build the long-term archive once we know which DA backends survive.

### RPC surface

```
tenzro_getReceiptPayload { receipt_id }
    → { payload, source: "inline"|"da_cache"|"da_fetch" }   // unified retrieval

tenzro_verifyDaPointer { pointer }
    → { available: bool, attestation: bytes }

tenzro_getDaBackends
    → [{ backend, status, last_submission_ms, last_fetch_ms, error_rate }]

tenzro_estimateOffloadCost { payload_size_bytes, backend? }
    → { cost_native, cost_tnzo_equiv, eta_ms }
```

CLI: `tenzro receipt payload <id>`, `tenzro node da-backends`.

MCP: `get_receipt_payload`, `verify_da_pointer` tools.

### Chain reorg considerations

If a block containing an offloaded receipt is reorg'd out, the DA-side payload is orphaned (still retrievable, but no longer referenced by chain state). DA backends don't care — payloads are content-addressed by commitment. The fee was paid; the blob expires per backend retention.

If the canonical chain re-includes the same receipt at a later block, the same DA payload + pointer can be reused (commitment is the same). Validator that re-includes simply quotes the existing pointer.

## Interaction with existing systems

- **`tenzro-storage`** column families CF_SETTLEMENTS / CF_MODELS / CF_AGENTS continue to be the authoritative chain state. Offloaded receipts are smaller entries there; the DA layer is a per-receipt sidecar, not a replacement.
- **Block-STM and consensus** are unaffected — block size shrinks for blocks containing offloaded-mode receipts, which is a pure win.
- **Principal-chain receipts (Spec 5)** are typed `inline_summary` carriers. Summary always carries `controller_did + controller_kyc_tier + depth`; full chain (with delegation_scope_ids) lives in payload. Regulator queries that need full chain pay the DA fetch.
- **Adaptive burn governance (Spec 8)** sees DA fees as a separate observable but does NOT burn DA fees — those are paid in foreign chain native tokens, not TNZO.
- **Wormhole NTT / LZ V2** are the bridges through which operators move ETH/TIA/AVAIL in to pay DA fees. No new bridge work.

## PQ posture

DA backends use their native attestation schemes (KZG for Avail, BN254 for EigenDA's restaking attestation, namespace-Merkle for Celestia). None are PQ-secure. The chain-side `commitment` is SHA-256 — also not PQ-secure to a quantum adversary, but matches the rest of Tenzro's hash usage.

When a PQ-secure DA backend ships, the abstraction trait makes adoption a feature flag.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `enabled` | true | Master kill switch |
| `default_mode_per_kind` | (table above) | Per-receipt-kind |
| `da_cache_size_bytes` | 1 GB | Per-node LRU |
| `inline_fallback_on_da_error` | true | Soft fallback if backend down |
| `subsidize_da_from_burn_pct` | 0% | Earmark % of burn to fund DA submissions |
| `repinning_interval_days` | 14 | For long-retention receipts (Phase 3.5) |
| `allowed_backends` | [EigenDA, Celestia, Avail] | |

## Verification

1. **Inline path:** small Settlement receipt — commitment matches inline_payload hash.
2. **Offload path happy:** Inference receipt offloaded to EigenDA — pointer well-formed, payload retrievable, commitment matches.
3. **Fallback on DA failure:** simulated DA backend down — receipt writes Inline, ops metric increments.
4. **Cache hit:** repeated `getReceiptPayload` for offloaded receipt — second hit served from cache.
5. **Commitment mismatch:** payload tampered between submit and fetch — fetch rejects with mismatch error.
6. **Index parity:** offloading does not change result of `listReceiptsByController` / `summarizeController` over the same window.
7. **Reorg correctness:** receipt R offloaded at block 100, reorg to alternate fork that doesn't include R — chain state has no R, DA still has payload (orphaned), no consistency violation.
8. **Multi-backend redundancy:** node configured with EigenDA primary + Celestia mirror — primary fail, fetch from mirror succeeds.

## Out of scope

- **Block body offloading.** Block data is consensus-critical; we never offload it.
- **State offloading (Verkle, etc.).** State pruning + state-witnesses is a different research thrust. This spec is receipts only.
- **Chain-as-DA-client (post payloads to our own chain via a different namespace).** Cute but circular. Out.
- **PQ-secure DA backend.** None production-ready in 2026. The abstraction layer absorbs one when it ships.
- **Agent-readable DA pointers from inside a contract.** Contracts get `commitment` and `pointer` as opaque bytes; they cannot fetch. Off-chain clients fetch. This is symmetric with the "no contract reads local fee" rule from Spec 6.
