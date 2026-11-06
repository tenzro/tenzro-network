# tenzro-iroh

QUIC-native, BLAKE3-addressed data plane for Tenzro — the bridge between the
`tenzro://` URI scheme and the [iroh](https://iroh.computer) stack.

This crate is what makes `tenzro://blob/...`, `tenzro://model/...` and
`tenzro://receipt/...` resolvable. iroh carries all of the node's networking: bulk content-addressed
transport, topic gossip (`tenzro/gossip`, see `gossip.rs`), point-to-point
protocols on their own ALPNs, and finding peers through signed identity
endpoint records and relays.

## What lives here

| Module                 | Role                                                                                                                              |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `IrohResolver`         | Dispatch trait: `fetch_bytes(&TenzroUri) -> Bytes`, `publish_bytes(Bytes) -> TenzroUri::Blob{hash, ..}`, `publish_path(&Path) -> TenzroUri`. Crates depend on this without pulling in iroh's runtime. |
| `IrohBackedResolver`   | Concrete impl wrapping a single `iroh::Endpoint` + `iroh_blobs::store::mem::MemStore` + `BlobsProtocol` router. One ALPN, one hash space. |
| `IrohBlobsDaBackend`   | `tenzro_storage::da::DaBackend` adapter. Locator = raw 32-byte BLAKE3. `commitment_kzg` / `attestation_root` both `None` (iroh-blobs verifies BLAKE3 over the whole transfer). Registered under `DaBackendId::IrohBlobs`. |
| `TenzroIrohConfig`     | Endpoint config used by `tenzro-node` to construct the resolver: bind address, boot identities, the relay role. No relay, pkarr host or peer by default. |
| `EndpointRecord`       | The machine's hardware key certifying a transport endpoint key (the per-boot `EndpointId` for iroh), its relays, scope and sequence. `verify` refuses a record signed by another identity, expired, stale, or naming another endpoint. |
| `DiscoveryStore`       | Tenzro's discovery network: verified records, answered on the `tenzro/discovery` ALPN and used as the endpoint's address lookup. |
| `RelayServer`          | The relay role: the iroh relay protocol and the operator's own record (`/identity`) on one HTTP listener. |
| `IdentityTransport`    | Admits relays by their operators' records, keeps this machine's record published to known peers and pulls theirs. |

`publish_path` is the path every large-artifact publish takes. It imports the
file with `ImportMode::TryReference`, so a multi-gigabyte model artifact is
referenced where it already sits rather than copied into the blob store or read
into memory. `publish_bytes` remains for callers that only hold bytes.
`tenzro-model`'s `BlobFetcher` exposes the matching pair (`publish_file` /
`publish`).

## Wiring

A node constructs **one** `IrohBackedResolver` at startup. The same endpoint
services every consumer above. Wiring lives in `tenzro-node`:
`init_ai_infrastructure` binds the endpoint before choosing the DA backend (so
`IrohBlobsDaBackend` is available to it) and attaches it to `TrainingRuntime`
as the payload store and to the media-gen queue as the output store.

## What runs over iroh

- **DA** — DA adapter and blob resolution.
- **Gradients** — gradient store (local-only; tickets carry distribution).
- **Sealed shards** — sealed-shard distribution via gossip + iroh-blobs.
- **Model weights** — `BlobFetcher` trait in `tenzro-model`; `IrohBlobFetcher`
  adapter in `tenzro-node`.
- **Configuration** — opt-in `NodeConfig.iroh` field; shared resolver.
- **Discovery** — Tenzro's own discovery network: endpoint records signed by
  the machine's hardware key, exchanged on the `tenzro/discovery` ALPN and
  served by operator-run relays. The default configuration names no relay,
  pkarr host or DHT; no outside relay or lookup service is wired in. The
  endpoint key is derived from the machine's hardware root, so the endpoint id
  is the same after a restart.
- **Build contracts** — multi-platform reference build contracts.
- **A2A and MCP** — A2A-over-iroh on the shared router via the
  `DeferredJsonRpcDispatcher` trampoline, plus MCP-over-iroh on the
  same router via the `DeferredMcpHandler` trampoline + `McpProtocol`
  ALPN (`tenzro/mcp`). Each inbound MCP bi-stream becomes a full rmcp
  session over `AsyncRwTransport` (newline-delimited JSON-RPC, same
  wire format as stdio MCP).

## What we never expose

The string `iroh://` does not appear in any user-facing Tenzro URI, doc, log,
or wire format. The transport is hidden behind the `tenzro://` scheme.

## License

Apache-2.0. iroh upstream is also Apache-2.0.
