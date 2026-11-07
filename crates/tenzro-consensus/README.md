# tenzro-consensus

Tenzro's consensus (TDC): signature-free DAG ordering over post-quantum authenticated channels, with checkpoints certified by hardware-held composite ML-DSA-65 + P-256 keys. The protocol and its rationale are described in [`docs/architecture/consensus.md`](../../docs/architecture/consensus.md); the node drives this crate from `crates/tenzro-node/src/consensus_driver.rs`.

## Overview

- **Seats.** Stake is apportioned into integer seats (largest remainder, 1,000 by default, 10% per-validator weight cap, no one-seat floor). Every threshold is counted in seats: `n` seats, `f = (n - 1) / 3`, quorum `n - f`.
- **Channels.** One stream per validator pair on the node's iroh endpoint (ALPN `tenzro/consensus`). A four-message handshake (X25519 + ML-KEM-768, both sides sign with their hardware keys, the responder only after authenticating the initiator) derives per-direction keys; every frame carries a keyed-BLAKE3 MAC and a strict sequence number.
- **Ordering.** Each validator proposes one unsigned vertex per round. A reliable broadcast (ECHO, VOTE, ACK, READY, with two-step delivery on a large ECHO quorum) makes every honest validator deliver the same vertex or none. A round's leader vertex commits once the next round's first proposals from a quorum of seats reference it; a leader vertex that skips the previous leader counts only with a quorum of no-votes. Each committed leader orders its causal history into one block.
- **Batches.** Pushed to every validator ahead of the vertex that introduces them; executed once the introduction and a quorum of acknowledgements are ordered.
- **Leader schedule.** Seats times observed behavior, seeded from the ordering digest of the checkpoint two back; a function of the committed prefix. No VRF or BLS key and no self-reported value enters it.
- **Checkpoints.** At the first committed leader at least 500 ms after the previous checkpoint. A validator persists that it is about to sign before signing; a quorum of composite signatures is a certificate. Two signatures on different checkpoints with one index are evidence (`CheckpointEquivocation`).
- **Epochs.** The checkpoint ending an epoch commits the next committee's root; the old committee orders two more checkpoints and hands over.
- **Recovery.** Before sending, a validator persists the records its frames commit it to (`Record`); `Core::recover` rebuilds its core after a restart without contradicting what it sent.
- **Keys.** `open_hardware_signer` opens an ML-DSA-65 key in a Secure Enclave or TPM and refuses everywhere else. There is no software signer outside tests.

## Modules

| File | Role |
|---|---|
| `core.rs` | The sans-IO protocol core: rounds, commit rule, ordering, segments, checkpoints, epoch handover, recovery |
| `rbc.rs` | Signature-free reliable broadcast |
| `dag.rs` | Causally closed DAG, strong paths, causal history, garbage collection |
| `vertex.rs` | Vertices and their structural checks |
| `schedule.rs` | Leader schedule |
| `batch.rs` | Batch payloads and the availability filter |
| `checkpoint.rs` | Checkpoints, votes, certificates, equivocation evidence, the persist-before-sign high-water mark |
| `committee.rs` | Seats and thresholds |
| `channel.rs` | The post-quantum channel handshake and frame protection |
| `wire.rs` | Messages and bounded frame decoding |
| `validator_key.rs` | Composite key, signatures, registration proof of possession, the hardware signer seam |
| `validator.rs`, `epoch_manager.rs` | Validator sets and epoch history |
| `mempool.rs`, `admission.rs` | Transaction admission |
| `eu_ai_act.rs` | The EU AI Act profile of an evidence pack: which records support Art. 12 and Art. 14, rebuilt and checked against the pack offline |
| `training_provenance.rs` | Offline check of a trained model's provenance pack from the genesis anchor |
| `light_client.rs` | The per-epoch light client that certifies state roots from genesis |
| `config.rs`, `error.rs` | Configuration and errors |
| `harness/` (tests only) | Network emulator driving the real core and reference baseline protocols, and the measurement runs |

`spec/Tdc.tla` is a TLA+ model of agreement, certificate uniqueness and epoch handover.

## Measurements

Latency and throughput are not asserted here. They are measured by the ignored gate tests in `src/harness/gates.rs`, each printing one `GATE {json}` line:

```bash
TDC_N=100 TDC_SECONDS=60 TDC_TPS=50000 \
  cargo test --release -p tenzro-consensus gate_ -- --ignored --nocapture --test-threads 1
```

## License

Apache License 2.0 — see [LICENSE](../../LICENSE).
