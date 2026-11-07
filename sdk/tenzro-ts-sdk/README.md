_This is a synced mirror of [tenzro-network](https://github.com/tenzro/tenzro-network)'s `sdk/tenzro-ts-sdk`. Fixes and features belong upstream; this repo exists so `npm install tenzro-sdk` has a home with its own issues and CI._

**Known test limitation**: `npm test` runs the full test suite as-is (354 of 393 individual tests pass; `npm run build` and the examples typecheck cleanly). 16 test files (agent-accounts, amounts, ap2-terms, challenge-payment, did-envelope, eip7702, event-proof, governance-receipt, hybrid-payer, keystore, nft-abi, openshell, payment-abstraction, payment-ops, settle, web-payments) fail here because they read fixture files from `../fixtures/` relative to the monorepo's `sdk/` layout, which this standalone mirror doesn't include. This is a structural gap in the mirror, not a bug in the SDK itself — fixing it means either vendoring `sdk/fixtures/` into this repo or rewriting those tests to be self-contained, neither done yet.

# Tenzro SDK for TypeScript

[![npm](https://img.shields.io/npm/v/tenzro-sdk)](https://www.npmjs.com/package/tenzro-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-tenzro.com-blue)](https://tenzro.com/docs/sdk)

The TypeScript SDK for [Tenzro Network](https://tenzro.com): a typed client for every JSON-RPC method the node serves, transactions signed by your hardware key, inference, payments, agents and settlement. It runs in Node.js 18+, browsers and edge runtimes.

## Installation

```bash
npm install tenzro-sdk
# On a server or desktop, the hardware signer (TPM 2.0, Secure Enclave):
npm install @tenzro/device-key
```

`@tenzro/device-key` is an optional peer of `@tenzro/core`: install it next to
the SDK where a TPM or Secure Enclave signs. Without it, and in a browser, the
SDK signs with a passkey or refuses to sign.

`tenzro-sdk` is the whole SDK in one import. It is built from a thin core and
one package per capability, each installable on its own:

| Package | What it holds |
| --- | --- |
| `@tenzro/core` | `RpcClient` with discovery and by-name calls, configuration, `ApiError`, types, access and sign-in (DPoP, HTTP signatures, OAuth), the `HybridSigner` interface with the hardware and passkey signers, wallets, `TypedTxClient` and every transaction builder, `SseDecoder` |
| `@tenzro/payments` | x402 payers and the publisher gate (`web`), MPP, Permit2, funding, purchases |
| `@tenzro/settlement` | escrow, the split engine, settlement plans |
| `@tenzro/agents` | delegated agents: Terms, agent wallets and bonds, payments, governance, lifecycle |
| `@tenzro/bridge` | bridge routes and fees, EIP-7702, agents' accounts on other chains |
| `@tenzro/inference` | models, chat streams, multimodal and media generation, providers, training, the model catalog |
| `@tenzro/chain` | tokens, staking, validators, governance, contracts, TEE, ZK, storage and files, events with proofs, quotas |

Every capability depends on `@tenzro/core` and on nothing else, except
`@tenzro/agents`, which pays through `@tenzro/payments`; the core depends on no
capability. A publisher that only gates paid paths installs two packages:

```typescript
import { web } from "@tenzro/payments";

const gate = new web.PublisherGate({ policy, quote });
const response = await gate.handle(request, handler); // 402 until a facilitator has settled
```

The same split holds in the Rust SDK (one cargo feature per capability) and
the Python SDK (`tenzro` and one subpackage per capability).

### Working on the SDK

The repository is an npm workspace (`packages/*` plus the `tenzro-sdk`
umbrella), built with TypeScript project references:

```bash
npm install
npm test         # tsc -b, the examples, the tests under test/, API.md up to date
```

## Quick Start

```typescript
import { HardwareKeySigner, connectToNetwork, openHardwareSigner } from "tenzro-sdk";

// Finds the staked RPC operators on chain and keeps those that agree.
const client = await connectToNetwork();

// Read the chain
const height = await client.getBlockNumber();
const balance = await client.getBalance("0x<32-byte account address>"); // bigint, in wei

// Models the network serves, and one inference request
const models = await client.inference.listModels();
const result = await client.inference.request(models[0].id, "Hello!", 100);

// Send TNZO, signed by this machine's TPM or Secure Enclave key.
// Install the optional @tenzro/device-key package; without hardware the SDK refuses to sign.
const signer = openHardwareSigner({ label: "tenzro/wallet" });
if (!(signer instanceof HardwareKeySigner)) throw new Error("no TPM or Secure Enclave on this machine");
const txHash = await client.wallet.sendSelfCustody({
  signer,
  to: "0x<recipient>",
  value: 1_000_000_000_000_000_000n, // 1 TNZO in wei
});
```

Every RPC method the client binds is listed, with its params, result and errors, in the [JSON-RPC reference](https://github.com/tenzro/tenzro-network/blob/main/docs/RPC.md).

## Connecting

```typescript
import { TenzroClient, connectToNetwork } from "tenzro-sdk";

// The preview network: staked RPC operators found on chain, chain id 13380.
const preview = await connectToNetwork();
// One endpoint of the preview network, with no discovery.
const one = TenzroClient.preview();
// A local node: `tenzro dev` serves a single-validator chain, id 1337, on 127.0.0.1:8545.
const local = new TenzroClient({ endpoint: "http://127.0.0.1:8545", chainId: 1337 });

console.log(await local.getChainId(), await local.getBlockNumber());
```

A transaction is signed for the chain id the node reports and the nonce it
reports; when either cannot be read the SDK fails rather than sign with a
default. See [Reaching the network](#reaching-the-network) for how discovery
picks operators.

## Signing

Every signature comes from hardware. On a server or desktop, `openHardwareSigner({ label })` opens a P-256 key held in the TPM 2.0 (Linux, Windows) or the Secure Enclave (macOS) through `@tenzro/device-key`; in a browser, signing is a passkey assertion (`WebAuthnSigner`). The ML-DSA-65 leg the hardware derives is added and the node checks both as one composite signature; both are required. An account signs nothing until it has enrolled an ML-DSA-65 key: `AccountKeysClient.sendEnrolling(signer, tx)` sends a transaction and, when the node answers that no key is enrolled, enrols the hardware's key and sends it again. With no hardware the SDK refuses to sign; there is no software key.

`client.transactions` builds and signs every consensus transaction type (`TX_KINDS`): `send(signer, { kind, fields })`. The node only encodes the signing payload (`tenzro_getSigningPayload`), and the SDK checks that the encoding is the transaction it built before the signer signs. `client.wallet.sendSelfCustody({ signer, to, value })` is the shorthand for a TNZO transfer. `client.transactions.prepare(from, tx)` is a dry run: the node encodes the signing payload, the SDK checks it, and nothing is signed or submitted.

## Signing in

A node's access policy may ask callers to sign in. `client.access.challenge(did, dpopJkt)` and `client.access.issue(challengeId, proof)` exchange a hardware-signed proof for a DPoP-bound access token; pass it as `access` in the client config and every request carries a fresh DPoP proof. There are no API keys. `client.auth` onboards people (passkey) and delegates agents under Terms; an action the Terms hold for the root runs through `agentAct` with the root's step-up.

## Agents

An agent acts for a root (a person's passkey or an organization) within Terms
the root signs. `client.auth.delegateAgent(..)` registers the agent and its
Terms, `client.auth.updateAgentTerms(..)` changes them, and the agent calls
`client.auth.agentAct(..)` on its serving node for each action; an action the
Terms reserve for the root carries the root's step-up. `client.agentWallet`
holds the agent's spending, `client.agentAccounts` its accounts on other
chains, and `client.agent` its audit commitments and quarantine state.

The controls a root holds are on chain and readable by anyone:

```typescript
const lifecycle = client.lifecycle();
let page = await lifecycle.listKillSwitchByAgent("did:tenzro:agent:...");
while (page.cursor) {
  // each receipt: action, reason_code, controller_did, frozen_at_block, timestamp
  page = await lifecycle.listKillSwitchByAgent("did:tenzro:agent:...", page.cursor);
}
const quarantine = await client.agent.getQuarantine("did:tenzro:agent:...");
```

## Inference and settlement

`client.inference` lists the models the network serves (`listModels`), routes
a request by intent (`routeIntent`, `chatByIntent`) and runs one
(`request`); `client.streaming` streams chat completions (below), and
`client.provider` covers serving models as a provider. Every paid call
settles on chain: `client.settlement` reads payments and escrows and settles
a payment, `client.settle` builds settlement plans across chains and reads a
plan, its decision and each leg's receipt (`getPlan`, `getDecision`,
`getLegReceipt`, `listPlans`), and `client.payment` handles x402 and MPP
payments. The publisher gate and the payers are in `@tenzro/payments`.

## Governance

```typescript
const proposals = await client.governance.listProposals({ limit: 20 });
const power = await client.governance.getVotingPower("0x<32-byte account address>");
const levers = await client.governance.listLevers();      // every governed parameter and its bounds
const params = await client.governance.getNetworkParams();
```

Votes and proposals are typed transactions signed with the voter's hardware
key (`client.transactions.send`). `getGovernanceReceipt` returns an enacted
proposal's receipt with a state proof; `verifyGovernanceReceipt` checks it
offline against a certified state root.

## Errors

A JSON-RPC error the node answers with throws `RpcCallError` with the node's
`code`, message and `data`: -32602 is invalid params, -32601 a method this
node does not serve, -32004 a resource or capability it does not have. An
error in the node's HTTP shape (`/v1/...`, and frames inside a stream) throws
`ApiError` with `type` and `code`.

```typescript
import { RpcCallError } from "tenzro-sdk";

try {
  await client.inference.request("qwen3.5-4b", "Hello", 64);
} catch (e) {
  if (e instanceof RpcCallError && e.isLightBuild) {
    // This node is the light build of tenzro-node and runs no model: send the call to a provider.
  } else {
    throw e;
  }
}
```

The SDK never substitutes a default for a value it failed to read: no
nonce, chain id or fee is guessed, and a signer that is not hardware is
refused.

## Streaming chat

`client.streaming` streams from the node's `POST /v1/chat/completions` on the RPC endpoint. `chatStream(request)` yields typed events (`reasoning`, `content`, `tool_call`, `finish`, `usage`) as they arrive; `chat(request, onEvent?)` returns the assembled `ChatCompletion` (content, reasoning, tool calls, finish reasons, usage, `cost_wei`). The request takes `messages`, `tools`, `tool_choice`, `temperature`, `max_tokens`, `reasoning_effort`, `enable_thinking`, `stream_options` and `provider: { only, ignore }`. A node error, before or during the stream, throws `ApiError` with `type` and `code`.

```typescript
// Signed in: talk to the node that issued the access token.
const client = new TenzroClient({ endpoint: "http://127.0.0.1:8545", access: credential });
const request = { model: "qwen3.5-4b", messages: [{ role: "user", content: "Is 17 prime?" }], enable_thinking: true };
for await (const event of client.streaming.chatStream(request)) {
  if (event.type === "reasoning" || event.type === "content") process.stdout.write(event.text);
}
```

`access` (an `AccessCredential`: the token from `client.access.issue(..)` and the `DpopProver` holding its key in hardware) signs every call the client makes, JSON-RPC and streaming alike, with a fresh DPoP proof per request; unset, `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` are forwarded. Use one client per DID.

## Browser-extension provider

Browser dApps can route SDK calls through `window.tenzro` (any
EIP-6963-announcing Tenzro extension) instead of opening a direct
fetch to the node. The extension owns auth (DPoP-bound JWT), session
management (CAIP-25), and user confirmation:

```typescript
import { TenzroClient, TenzroNotInstalledError } from "tenzro-sdk";

try {
  const client = await TenzroClient.fromInjected();
  const block = await client.getLatestBlock();
} catch (err) {
  if (err instanceof TenzroNotInstalledError) {
    showInstallCta();
  } else {
    throw err;
  }
}
```

`fromInjected()` discovers the Tenzro provider via EIP-6963
(default `rdns: com.tenzro.wallet`, override with the `rdns`
option), wraps it in an `Eip1193Transport`, and returns a
`TenzroClient` whose `rpc.call(...)` becomes `provider.request(...)`.
No extra dependency to install — the EIP-6963 listener is bundled in
the SDK. Node consumers can ignore this entrypoint entirely.

## Catch-up sync

A node lagging behind the network can pull batches of historical blocks via
`getBlockRange`. The call returns up to 256 blocks per request along with a
`nextHeight` + `moreAvailable` cursor so a sync loop steps over pruning gaps:

```typescript
let cur = 0;
while (true) {
  const r = await client.getBlockRange(cur, cur + 255, 256);
  for (const b of r.blocks) {
    /* import block */
  }
  if (!r.moreAvailable) break;
  cur = r.nextHeight;
}
```

`isSyncing()` reports the live gap by comparing the local tip against
peer-reported network tips (gossiped on `tenzro/status`); pair it with
`getBlockRange` to drive a catch-up loop only when needed.

## Settlement rails and routing

`client.device()` carries two related surfaces beyond device binding.

**Which rail a payment settles on.** Supporting x402 and being able to carry a
micropayment are different properties: Base speaks x402 and still cannot carry a
one-cent charge without roughly 10% overhead. `settlementNetworks()` returns
every rail cheapest-first with the smallest worthwhile payment on each;
`routePayment()` answers where a specific charge goes — `accumulate` (below the
micro-settlement floor, hold it in a channel), `primary` (Tenzro Ledger),
`secondary` (cheapest rail carrying the payee's asset), or `no_viable_rail`.

Omit the TNZO price and the node settles on the home chain rather than routing
real money on a guessed exchange rate.

```ts
const rails = await client.device().settlementNetworks();
const decision = await client
  .device()
  .routePayment("1000000000000000000", "USDC", 1_000_000);
```


## Owner-proof on resource mutations

Methods that act on a resource by its identifier also require a signed DID
envelope proving control of the resource. An identifier is not a
credential: a `jti` travels in every audit row, and a `session_id` is a handle
the node hands back.

| Method                               | Proof required                                                                    |
| ------------------------------------ | --------------------------------------------------------------------------------- |
| `revokeJwt`                          | envelope from the token's bearer **or** the controller that authorized it         |
| `revokeDid`                          | node administrator **and** an envelope from the DID (or a machine's controller) |

Each envelope is bound to the method name and to that call's parameters, so one
produced for a given action cannot be replayed as another.

## Reference

[API.md](API.md) lists every class and function the package exports, with each method's signature, parameters, result, errors and the JSON-RPC method it calls. It is generated from the source (`npm run docs`), and `npm test` fails when it is out of date. The RPC methods themselves are documented in the [JSON-RPC reference](https://github.com/tenzro/tenzro-network/blob/main/docs/RPC.md).

## Examples

```bash
npx tsx examples/local-node.ts              # chain id, a balance and a transfer dry run on one node
npx tsx examples/quickstart.ts              # read the chain, run inference, send TNZO with a hardware key
npx tsx examples/intent-routing.ts          # route an intent to a model, or run by intent
```

`npm test` typechecks every example against the current source.

## Reaching the network

The SDK defaults to the preview network, `PREVIEW_NETWORK`: chain id 13380,
RPC at `https://rpc.tenzro.com`, the REST API at `https://api.tenzro.com`, MCP
at `https://mcp.tenzro.com/mcp`, A2A at `https://a2a.tenzro.com` and the relay
at `https://relay.tenzro.com`.

There is no single endpoint. RPC operators bond the `rpc` role and publish
the URL they serve in consensus state; `connectToNetwork()` asks the seed for that
list, keeps the operators that report chain id 13380 and agree on a
checkpoint digest, and moves between them when one cannot be reached.

The default seed, `https://rpc.tenzro.com`, is only a bootstrap hint: once
the operator list is read from chain, the client talks to the staked
operators, and any node of the network serves as a seed. Pass your own seeds
and chain id with `connectToNetwork({ seeds: [...], chainId })`, or one
endpoint with `new TenzroClient({ endpoint, chainId })`.
`TenzroClient.preview()` is the preview network's RPC endpoint and chain id.
Every node also serves MCP at `/mcp` and A2A with its own Agent Card.

## Documentation

- [SDKs on tenzro.com](https://tenzro.com/docs/sdk)
- [API reference](API.md)
- [Tutorials](https://tenzro.com/tutorials)
- [Changelog](CHANGELOG.md)

## Contact

- Website: [tenzro.com](https://tenzro.com)
- Engineering: [eng@tenzro.com](mailto:eng@tenzro.com)
- GitHub: [github.com/tenzro](https://github.com/tenzro)

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
