# tenzro-light-wasm

The Tenzro light client for JavaScript and TypeScript (preview): the `tenzro-light` checks compiled to WebAssembly, the same verifier the Rust SDK (`light` feature) and the Kotlin and Swift packages run. It follows the committee from a trusted anchor through each epoch's handover, accepts a checkpoint only under a quorum or compact certificate, and checks state values, identity keys and key histories against the certified state root.

The caller supplies the transport, an async `(method, paramsJson) => resultJson` over its own `fetch`, so the module carries no network code. 64-bit chain numbers (chain id, epochs, indexes, milliseconds) are `bigint`.

```js
const lc = new LightClient(call, 13380n, genesisHex, epoch, committeeRootHex, committeeReplyJson);
const checkpoint = JSON.parse(await lc.sync(BigInt(Date.now()), 3_600_000n, 30_000n));
const keys = JSON.parse(await lc.resolve_identity(did, BigInt(Date.now()), 3_600_000n, 30_000n));
const history = JSON.parse(await lc.key_history(did, BigInt(Date.now()), 3_600_000n, 30_000n));
```

`./build.sh` builds `pkg/` for Node (`./build.sh web` for a browser bundle); it needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` at the version pinned in `Cargo.toml`. `node --test test/*.test.mjs` replays the shared fixture in `sdk/fixtures/light-client/`. `node bench/measure.mjs --rpc … --chain … --genesis … --epoch … --committee-root …` times both certificate paths against a node.
