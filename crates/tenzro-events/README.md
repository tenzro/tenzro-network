# tenzro-events

Real-time event streaming, subscriptions, and webhook delivery for the Tenzro Network.

## Overview

**tenzro-events** provides a unified event model across all VMs (EVM, SVM, DAML), consensus, token, and identity subsystems with monotonic sequencing, cursor-based replay, and rich filtering. It is the substrate every other Tenzro crate uses to surface state changes to in-process subscribers, gossipsub broadcast, the JSON-RPC subscription surface, and downstream webhook / WebSocket / gRPC consumers.

## Key Types

- **`EventBus`** — Ring-buffered broadcast hub with monotonic sequence numbers and per-subscriber backpressure. Configurable channel capacity and history retention.
- **`TenzroEvent`** — Unified event enum covering all VM emissions (EVM Log, SVM transaction event, DAML ledger event), consensus messages (`BlockFinalized`, `ValidatorJoined`, `EpochTransition`), token economy (`Transferred`, `Staked`, `Slashed`), identity (`Registered`, `Revoked`), and provider lifecycle (`ProviderRegistered`, `ModelServed`).
- **`EventFilter`** — Query DSL: filter by event type, VM, contract address, block range, identity DID, model ID. Composable via `EventFilter::and`/`or`.
- **`EventEnvelope`** — Wire form with sequence number, timestamp, source subsystem, and the inner `TenzroEvent` payload.
- **`EventSubscriber`** — Pull-style consumer interface (`async fn next() -> EventEnvelope`).
- **`FilteredEventSubscriber`** — Subscriber that applies an `EventFilter` before yielding to the consumer.
- **`SubscriptionId`** — Opaque identifier returned from `EventBus::subscribe(...)` for cancellation and stats.
- **`EventBusStats`** — Per-subscriber counters: events delivered, dropped (backpressure), filter hits.

## Used By

- **`tenzro-node`** — Wires the event bus into the JSON-RPC subscription surface (`tenzro_subscribe`, `tenzro_unsubscribe`), the Web API SSE endpoint, and the gossipsub `tenzro/events` topic for cross-node fan-out.
- **`tenzro-vm`** — Emits VM logs / SVM events / DAML ledger events on every transaction commit.
- **`tenzro-consensus`** — Emits `BlockFinalized` and epoch lifecycle events.
- **`tenzro-token`** — Emits transfer / stake / slash events for explorer indexing.
- **`tenzro-identity`** — Emits registration / revocation events for credential consumers.

## Status

Pre-1.0. The event taxonomy and the `EventBus` API are stable for the testnet release; cross-node replay over gossipsub is shipped, and the durable persistence layer lands alongside the snapshot subsystem in `tenzro-storage`.

## License

Apache-2.0.
