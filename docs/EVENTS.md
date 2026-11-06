# Events and verifiable indexing

Every block's execution emits events, the chain commits them, and every node
keeps them in a durable log that readers follow from a cursor. Any event can
be proven against a certified checkpoint, so an index built from events, and
any answer computed from one, is checked rather than trusted.

## What is committed

For each executed transaction a block emits, in order:

1. its outcome (`tx_outcome`: success, gas used, a deployed contract), then
2. each log it emitted (`log`: contract address, topics, data).

An event's position is its cursor, `height:tx_index:event_index`. Cursors are
totally ordered.

The block header carries `event_root`, the Merkle root (BLAKE3, the tree
checkpoints use) of the block's events in cursor order. Each leaf is the BLAKE3
hash of the event's canonical encoding: the domain `tenzro/chain-event/leaf`,
the cursor (u64, u32, u32 little-endian), the transaction hash, then a kind tag
and the kind's fields, every byte string prefixed by its u32 little-endian
length. The header hash covers `event_root`, and the checkpoint certificate
covers the header hashes of the blocks it certifies. A validator fills the
root in after executing a block it ordered; a node importing a certified block
refuses it when its own execution emits different events.

## Proofs

An event proof holds the event, its path to the header's event root, the
header, the header's path to the covering checkpoint's blocks root, and the
checkpoint bodies from the covering one to a certified anchor, each the `prev`
of the next. Verifying it needs only the anchor's certification:

- a light client checks a proof against the latest checkpoint it accepted
  (`LightClient::verify_event`; the CLI's `tenzro events verify <cursor>`
  follows the chain from genesis first);
- `CertifiedEventProof` adds the proof from genesis that the anchor is
  certified, for a client holding only the genesis anchor;
- the Rust and TypeScript SDKs check a proof against the digest of a
  checkpoint the caller already holds as certified (`verify_event_proof`,
  `verifyEventProof`).

## The log

Each node writes a block's events to its events column family under their
cursor keys, together with the block. The log keeps the same retention window
as blocks: when history below the window is handed to the data availability
layer, the events go into the same segment and are deleted locally. Reads
below the local floor fetch the segment back and check every block's events
against its header before serving them.

## API

JSON-RPC:

| Method | What it does |
|---|---|
| `tenzro_subscribe { filter?, from_cursor?, from_height?, limit?, wait_ms?, proofs? }` | The next events after a cursor (the current tip when no start is given), waiting up to `wait_ms` (at most 30 s) for new blocks. The answer's `cursor` is passed back as `from_cursor`, so a reader that restarts resumes with no gap and no repeat. |
| `tenzro_queryEvents { filter?, from_cursor?, from_height?, to_cursor?, limit?, anchor_index? }` | A page of a range, every event with its proof. |
| `tenzro_getEventProof { cursor, anchor_index?, certified? }` | One event's proof; with `certified`, a `CertifiedEventProof`. |
| `tenzro_verifyEventProof { proof }` or `{ certified_proof }` | Checks a proof against the certification this node holds for its anchor. |

HTTP: `GET /events?filter=<json>&from_cursor=<cursor>` streams the same events
as server-sent events; each event's id is its cursor, so a reconnecting client
resumes from `Last-Event-ID`.

The filter: `event_types` (`log`, `transaction_included`), `addresses`
(20-byte hex; a 32-byte log address matches on its trailing 20 bytes),
`topics` (positional: `null`, one topic, or a list), `from_block`,
`to_block`. An unknown field or malformed value is refused.

The same stream is reachable through MCP (tools `subscribe_events`,
`query_events`, `verify_event_proof`, and the subscribable resource template
`tenzro://events{?filter,from_cursor}`), A2A (a data part
`{operation: "readEvents", filter, from_cursor}`), the CLI
(`tenzro events subscribe|history|verify`) and the SDKs.

## Visibility

The node's own live events (inference streams) are streamed at
`GET /events/node`. An event about a resource reaches a reader only as the
resource's visibility allows: a public resource's events reach anyone, a
gated resource's only a reader presenting a key that reaches it, and a private
resource's only readers on the node itself.

## Agents

A delegated agent reads the event stream only when its terms list the
`subscribe_events` operation. When its terms name counterparties, its filter
must name addresses, and only those. The check runs on every read, over
JSON-RPC, SSE, MCP and A2A. An agent keeps its cursor; after a restart it
resumes from it with no gap.

## Index answers

An index is a named projection of the events a filter selects: `events`,
`count`, or `latest_per_address`. An answer that carries the proof of each
event it was computed from, all anchored at one certified checkpoint, is
checked by recomputing the projection from the proven events
(`ProvenAnswer::verify`, `verify_index_answer`, `verifyIndexAnswer`). Proofs
show that every event in an answer was emitted; they do not show that no
matching event was left out. Selling indexes is a harness service over the
public event reads.
