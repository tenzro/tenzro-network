# Tenzro SDKs

Three SDKs, one shape: a thin core and the same capability packages in
TypeScript, Rust and Python. The core never depends on a capability.

| | TypeScript | Rust (`tenzro-sdk`) | Python (`tenzro`) |
| --- | --- | --- | --- |
| Everything | `tenzro-sdk` | default feature `full` | the `tenzro` distribution |
| Core | `@tenzro/core` | always built | `tenzro` |
| Payments | `@tenzro/payments` | feature `payments` | `tenzro.payments` |
| Settlement | `@tenzro/settlement` | feature `settlement` | `tenzro.settlement` |
| Agents | `@tenzro/agents` | feature `agents` | `tenzro.agents` |
| Bridge | `@tenzro/bridge` | feature `bridge` | `tenzro.bridge` |
| Inference | `@tenzro/inference` | feature `inference` | `tenzro.inference` |
| Chain | `@tenzro/chain` | feature `chain` | `tenzro.chain` |

Every node method is reachable from the core of each SDK by name (discovery
and a by-name call), and the Python client carries one typed method per served
method, generated from the node's method table. The repository's tests check
the SDKs against the node: every served method is bound (`rpc_wiring`), every
transaction type is buildable (`sdk_transaction_coverage`), and discovery and the
by-name call ship on every surface (`surface_parity`).

Each SDK also tests every binding against a mocked node: the method it calls,
the params it sends, which are the ones the node handler reads, and the
result it decodes. Each has a `local_node` example that reads a node's chain
id and a balance and dry-runs a transfer (`TypedTxClient.prepare`).

## Core

- The node client: JSON-RPC over HTTP with discovery (`tenzro_listRpcMethods`)
  and a by-name call, typed errors (`RpcCallError`, `SdkError::Node` and
  `RpcError` for JSON-RPC errors with their code and data, `ApiError` for the
  node's `{"error":{...}}` bodies), the SSE decoder, configuration and types.
- Access and sign-in: a DPoP-bound access token per client, proofs minted by
  the hardware key (`HardwareDpopProver`); HTTP message signatures for agents.
- Signing: the `HybridSigner` interface (composite P-256 and ML-DSA-65
  signatures), the hardware signer over the TPM 2.0 or Secure Enclave
  (`@tenzro/device-key` in Node.js, `tenzro-device-key` in Python; in Rust a
  `HybridSigner` over the `tenzro-device-key` crate) and passkeys. There are
  no software keys.
- Transactions: `TypedTxClient` and the builders for every consensus
  transaction type, checked against the node's signing payload before the
  hardware key signs; wallets, identity and ML-DSA-65 key enrollment.

## Capabilities

- **Payments**: x402 payers (`tenzro-hybrid` from the payer's key,
  `batch-settlement` from a delegated agent's channel), the paying HTTP client,
  node-issued MPP/x402 challenges paid with a hardware-signed credential, and
  the publisher gate that answers a paid path with 402 and serves it only after
  the facilitator settles (TypeScript `web.PublisherGate`, Rust tower layer,
  Python ASGI and WSGI middleware), with the RSL licence and robots.txt line
  from the same policy. TypeScript and Rust add the MPP, Permit2, funding and
  purchase clients.
- **Settlement**: the split engine, settlement plans and the x402 `plan`
  payment, escrow, refunds and the payee's standing split rule.
- **Agents**: delegated agents under Terms granted by one root, actions and
  vouchers within them; TypeScript and Rust add registration, agent wallets
  and bonds, payments, governance, lifecycle and the task market. All three
  carry the NVIDIA OpenShell helpers: sandbox policy to Terms, credentials
  under Terms, and sandbox session records verified offline
  (`sdk/fixtures/openshell`).
- **Bridge**: bridge sends over governed routes, agents' accounts on other
  chains, EIP-7702 set-code transactions; TypeScript and Rust add bridge fees.
- **Inference**: streamed chat completions with reasoning, tool calls and usage
  as events (over `sdk/fixtures/chat-stream`); TypeScript and Rust add models,
  multimodal and media generation, providers, training and the model catalog.
- **Chain**: governance receipts verified offline against a certified state
  root; TypeScript and Rust add tokens, staking, validators, contracts, TEE,
  ZK, storage and files, events with proofs and the network's other registries.

The Python capability packages carry the logic a client must run itself
(signing, verification, payment gates, stream assembly); every other node
method is a typed method on `tenzro.RpcClient`.

## Terminal console

`sdk/tenzro-tui` is an interactive terminal console for a node, built on the
TypeScript SDK (`tenzro-tui`, Node 22 or newer). It reads and never signs or
sends: keys stay in the `tenzro` CLI. It is not published to npm yet; build it
from the repository:

```
cd sdk/tenzro-ts-sdk && npm ci
cd ../tenzro-tui && npm ci && npm run build
node dist/src/cli.js --rpc http://127.0.0.1:8545
```

Five screens, switched with 1 to 5 or Tab: Overview, Wallet, Models,
Validators and Governance. r refreshes, ? shows the help, q quits. The header
shows one status word (OK, WATCH, DOWN or UNKNOWN); `NO_COLOR` or `--no-color`
removes color and the words still carry the meaning. Without a terminal, or
with `--plain`, it prints one text report and exits 0 when the node is OK and 1
otherwise. See [tenzro-tui/README.md](tenzro-tui/README.md).

## Shared vectors

`sdk/fixtures` holds the vectors all three SDKs and the node are tested
against: payment authorizations and the publisher gate's decisions
(`payments/`), settlement plans and splits, agent Terms, EIP-7702, governance
receipts, state and event proofs, and recorded chat streams.
