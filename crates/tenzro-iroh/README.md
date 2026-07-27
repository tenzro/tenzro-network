# tenzro-iroh

QUIC-native, BLAKE3-addressed data plane for Tenzro — the bridge between the
`tenzro://` URI scheme and the [iroh](https://iroh.computer) stack.

This crate is what makes `tenzro://blob/...`, `tenzro://gradient/...`,
`tenzro://shard/...`, `tenzro://manifest/...`, and `tenzro://memory/...`
resolvable. libp2p remains the control plane (gossipsub, Kademlia, AutoNAT v2,
DCUtR); iroh handles bulk content-addressed transport.

## What lives here

| Module                 | Role                                                                                                                              |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `IrohResolver`         | Dispatch trait: `fetch_bytes(&TenzroUri) -> Bytes`, `publish_bytes(Bytes) -> TenzroUri::Blob{hash, ..}`. Crates depend on this without pulling in iroh's runtime. |
| `IrohBackedResolver`   | Concrete impl wrapping a single `iroh::Endpoint` + `iroh_blobs::store::mem::MemStore` + `BlobsProtocol` router. One ALPN, one hash space. |
| `IrohBlobsDaBackend`   | `tenzro_storage::da::DaBackend` adapter. Locator = raw 32-byte BLAKE3. `commitment_kzg` / `attestation_root` both `None` (iroh-blobs verifies BLAKE3 over the whole transfer). Registered under `DaBackendId::IrohBlobs`. |
| `IrohGradientStore`    | `tenzro_training::GradientPayloadStore` adapter. Keeps a `DashMap<SHA-256, BLAKE3-hex>` because the protocol hash (SHA-256) differs from the transport hash (BLAKE3). |
| `IrohSealedShardStore` | Sponsor-DID-signed `SealedDatasetManifest` distribution over `tenzro/training` gossipsub + per-shard ciphertext fetch via iroh-blobs. Deliberately not iroh-docs (manifest is immutable). |
| `IrohMediaGenOutputStore` | `tenzro_media_gen::MediaGenOutputStore` adapter carrying rendered images and video plus the one intermediate latent a split job hands between its two experts. Same `DashMap<SHA-256, BLAKE3-hex>` indirection as the gradient store; `record_blake3` lets a node that did not render the bytes fetch them from a gossiped receipt. |
| `TenzroIrohConfig`     | Endpoint config used by `tenzro-node` to construct the resolver — `pkarr_relay_url`, `secret_key_seed`, `enable`.                  |

## Wiring

A node constructs **one** `IrohBackedResolver` at startup. The same endpoint
services every consumer above. Wiring lives in `tenzro-node`:
`init_ai_infrastructure` binds the endpoint before initializing `MemoryManager`
(so the memory archive can pick up `IrohBlobsDaBackend`) and attaches it to
`TrainingRuntime` as the payload store and to the media-gen queue as the output
store.

## Phases implemented

- **Phase A2** — DA adapter, blob resolution.
- **Phase B1** — gradient store (local-only; ticket distribution is in B2).
- **Phase B2** — sealed-shard distribution via gossipsub + iroh-blobs.
- **Phase B3** — model-weight distribution (`BlobFetcher` trait in
  `tenzro-model`; `IrohBlobFetcher` adapter in `tenzro-node`).
- **Phase C1** — opt-in `NodeConfig.iroh` field; shared resolver.
- **Phase C2** — TDIP-anchored Pkarr discovery (`EndpointId` byte-identical to
  TDIP Ed25519 key). Local dev falls back to n0 relay.
- **Phase C3** — multi-platform reference build contracts.
- **Phase D1** — agent-memory DA flowing through iroh-blobs when bound.
- **Phase D2** — A2A-over-iroh on the shared router via the
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
