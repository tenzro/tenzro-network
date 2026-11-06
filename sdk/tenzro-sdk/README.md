# Tenzro SDK for Rust

[![Crates.io](https://img.shields.io/crates/v/tenzro-sdk)](https://crates.io/crates/tenzro-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Docs](https://img.shields.io/docsrs/tenzro-sdk)](https://docs.rs/tenzro-sdk)

The Rust SDK for [Tenzro Network](https://tenzro.com): a typed client for every JSON-RPC method the node serves, transactions signed by your hardware key, inference, payments, agents and settlement.

## Installation

```toml
[dependencies]
tenzro-sdk = "0.9"
```

or

```bash
cargo add tenzro-sdk
```

### Core and capability features

The core is always built: `RpcClient` and `TenzroClient` with discovery and
by-name calls, configuration, errors (`SdkError`, `ApiError`) and types,
access and sign-in, the `HybridSigner` interface and the passkey client,
wallets and the typed transaction builders. Each capability is a cargo feature
that adds its modules, its `TenzroClient` accessors and only the dependencies
they need. `full`, the default, enables them all.

| Feature | Modules |
| --- | --- |
| `payments` | `web` (x402 payers, the publisher gate as a tower layer), `payment`, `permit2`, `funding`, `purchase` |
| `settlement` | `settle` (split engine, settlement plans), `settlement` (escrow) |
| `agents` | `agent`, `agent_payments`, `task` |
| `bridge` | `bridge`, `bridge_fee`, `eip7702`, `agent_accounts` |
| `inference` | `inference`, `chat`, `streaming`, `multimodal`, `media_gen`, `provider`, `training`, `catalog` |
| `chain` | `governance`, `token`, `nft` (offline calldata and decoders for the NFT factory precompile), `staking`, `validator`, `contract`, `tee`, `zk`, `storage`, `files`, `events`, and the other registries |

A thin build names what it uses:

```toml
tenzro-sdk = { version = "0.9", default-features = false, features = ["payments"] }
```

The same split holds in the TypeScript SDK (`@tenzro/core` and one package per
capability) and the Python SDK (`tenzro` and one subpackage per capability).

## Quick Start

```rust,no_run
use std::sync::Arc;
use tenzro_sdk::{Address, TenzroClient, wallet::HybridSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;

    // Read the chain
    let height = client.block_number().await?;
    println!("height {height}");

    // Models the network serves, and one inference request
    let models = client.inference().list_models().await?;
    if let Some(model) = models.first() {
        let result = client.inference().request(&model.model_id, "Hello!", Some(100)).await?;
        println!("{result:?}");
    }
    Ok(())
}

// Send TNZO, signed by a key held in the TPM or Secure Enclave.
async fn send(
    client: &TenzroClient,
    signer: Arc<dyn HybridSigner>,
    to: Address,
) -> tenzro_sdk::SdkResult<String> {
    client.wallet().send_self_custody(&signer, to, 1_000_000_000_000_000_000).await
}
```

## Connecting

```rust,no_run
# async fn run() -> tenzro_sdk::SdkResult<()> {
use tenzro_sdk::{SdkConfig, TenzroClient};

// The preview network: staked RPC operators found on chain, chain id 133801.
let preview = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
// One endpoint of the preview network, with no discovery.
let one = TenzroClient::connect(SdkConfig::preview()).await?;
// A local node: `tenzro dev` serves a single-validator chain, id 1337, on 127.0.0.1:8545.
let local = TenzroClient::new("http://127.0.0.1:8545").await?;
println!("{} {}", local.get_chain_id().await?, local.block_number().await?);
# let _ = (preview, one);
# Ok(())
# }
```

A transaction is signed for the chain id and nonce the node reports; when
either cannot be read the SDK fails rather than sign with a default.

## Signing

Every signature comes from hardware. A `HybridSigner` holds a P-256 key in the TPM 2.0 or the Secure Enclave (or answers with a passkey assertion), and adds the ML-DSA-65 leg the hardware derives; the node checks both as one composite signature and requires both. An account signs nothing until it has enrolled an ML-DSA-65 key; `client.account_keys().send_enrolling(..)` sends a transaction and, when the node answers that no key is enrolled, enrols the hardware's key and sends it again. The SDK never holds a private key and refuses to sign without one. Implement `HybridSigner` over the machine's key with the `tenzro-device-key` crate, which reaches the TPM and the Secure Enclave.

`client.transactions()` builds and signs every consensus transaction type (`TxKind`): the node only encodes the signing payload (`tenzro_getSigningPayload`), and the SDK checks that the encoding is the transaction it built before the signer signs. `client.wallet().send_self_custody(..)` is the shorthand for a TNZO transfer. `client.transactions().prepare(from, &tx)` is a dry run: the node encodes the signing payload, the SDK checks it, and nothing is signed or submitted.

## Signing in

A node's access policy may ask callers to sign in. `client.access().challenge(..)` and `issue(..)` exchange a hardware-signed proof for a DPoP-bound access token (`AccessCredential`); set it on `SdkConfig` and every request carries a fresh DPoP proof. There are no API keys. `client.auth()` onboards people (passkey) and delegates agents under Terms; an action the Terms hold for the root runs through `agent_act` with the root's step-up.

## Agents

An agent acts for a root (a person's passkey or an organisation) within Terms
the root signs. `client.auth()` delegates an agent under Terms and updates
them, and the agent calls `agent_act` on its serving node for each action; an
action the Terms reserve for the root carries the root's step-up.
`client.agent_payments()` pays from the agent's wallet. The controls on an
agent are on chain and readable by anyone:

```rust,no_run
# async fn run(client: tenzro_sdk::TenzroClient) -> tenzro_sdk::SdkResult<()> {
use tenzro_sdk::PageRequest;

let agent = client.agent();
let mut page = agent.list_kill_switch_by_agent("did:tenzro:agent:example", PageRequest::default()).await?;
while let Some(cursor) = page.cursor.clone() {
    for receipt in &page.receipts {
        println!("{} at block {}", receipt.action, receipt.frozen_at_block);
    }
    let next = PageRequest { from_cursor: Some(cursor), ..PageRequest::default() };
    page = agent.list_kill_switch_by_agent("did:tenzro:agent:example", next).await?;
}
let quarantine = agent.get_quarantine("did:tenzro:agent:example").await?;
# let _ = quarantine;
# Ok(())
# }
```

### NVIDIA OpenShell

`tenzro_sdk::openshell` maps an OpenShell sandbox policy to agent Terms
(`openshell_policy_terms`), carries credentials minted under those Terms with
the controller's passkey, names a sandbox session (`openshell_session_id`) and
verifies the supervisor's signed, hash-chained session records offline
(`parse_openshell_records`, `verify_openshell_records`), then lists the
payments the session made (`openshell_payments`). See
[docs/OPENSHELL.md](../../docs/OPENSHELL.md).

## Inference and settlement

`client.inference()` lists the models the network serves, routes a request by
intent and runs one; `client.streaming()` streams chat completions (below), and
`client.provider()` covers serving models as a provider. Every paid call
settles on chain: `client.settlement()` reads payments and escrows and settles
a payment, `client.settle()` builds settlement plans across chains and reads a
plan, its decision and each leg's receipt, and `client.payment()` handles x402
and MPP payments. The publisher gate is a tower layer in `web`.

## Governance

```rust,no_run
# async fn run(client: tenzro_sdk::TenzroClient) -> tenzro_sdk::SdkResult<()> {
let governance = client.governance();
let proposals = governance.list_proposals(20, None, None).await?;
let power = governance.get_voting_power("0x<32-byte account address>").await?;
let levers = governance.list_levers(None).await?; // every governed parameter and its bounds
# let _ = (proposals, power, levers);
# Ok(())
# }
```

Votes and proposals are typed transactions signed with the voter's hardware
key (`client.transactions().send(..)`).

As the node's operator, `client.access().audit_log(&AuditFilter { .. })` reads
the administrative audit log and `verify_audit_log()` checks its chain and
signed checkpoints.

## Errors

A JSON-RPC error the node answers with is `SdkError::Node(NodeError { code,
message, data })`: -32602 is invalid params, -32601 a method this node does not
serve, -32004 a resource or capability it does not have. An error in the
node's HTTP shape (`/v1/...`, and frames inside a stream) is
`SdkError::Api(ApiError)`. `SdkError::RpcError` is a transport or decoding
failure.

```rust,no_run
# async fn run(client: tenzro_sdk::TenzroClient) -> tenzro_sdk::SdkResult<()> {
match client.inference().request("qwen3.5-4b", "Hello", Some(64)).await {
    Ok(result) => println!("{}", result.output),
    Err(e) if e.node_error().is_some_and(|n| n.is_light_build()) => {
        // This node is the light build of tenzro-node and runs no model: ask a provider.
    }
    Err(e) => return Err(e),
}
# Ok(())
# }
```

The SDK never substitutes a default for a value it failed to read: no nonce,
chain id or fee is guessed.

## Streaming chat

`client.streaming()` streams from the node's `POST /v1/chat/completions` on the RPC endpoint. `chat_stream(&request, |event| ..)` calls back with each `ChatStreamEvent` (`Reasoning`, `Content`, `ToolCall`, `Finish`, `Usage`) as it arrives and returns the assembled `ChatCompletion`; `chat_stream_channel(&request)` hands the events over a channel. `ChatRequest` carries `messages`, `tools`, `tool_choice`, `temperature`, `max_tokens`, `reasoning_effort`, `enable_thinking`, `stream_options` and `provider`. A node error, before or during the stream, returns `SdkError::Api(ApiError { message, kind, code })`.

```rust,no_run
# use tenzro_sdk::{SdkConfig, TenzroClient, AccessCredential};
# use tenzro_sdk::{ChatMessage, ChatRequest, ChatStreamEvent};
# async fn run(credential: AccessCredential) -> Result<(), Box<dyn std::error::Error>> {
// The node that issued the access token.
let config = SdkConfig::builder().endpoint("https://node.example").access(credential).build()?;
let client = TenzroClient::connect(config).await?;
let mut request = ChatRequest::new("qwen3.5-4b", vec![ChatMessage::user("Is 17 prime?")]);
request.enable_thinking = Some(true);
let completion = client.streaming().chat_stream(&request, |event| match event {
    ChatStreamEvent::Reasoning { text } | ChatStreamEvent::Content { text } => print!("{text}"),
    _ => {}
}).await?;
# Ok(())
# }
```

The access credential (`AccessCredential`: the token from `client.access().issue(..)` and the `DpopProver` holding its key in hardware) signs every call the client makes, JSON-RPC and streaming alike, with a fresh DPoP proof per request; unset, `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` are forwarded. Use one client per DID.

## Catch-up sync

A node lagging behind the network can pull batches of historical blocks via
`get_block_range`. The call returns up to 256 blocks per request with a
`next_height` + `more_available` cursor for paginating past pruning gaps:

```rust,no_run
# async fn run(client: tenzro_sdk::TenzroClient) -> tenzro_sdk::SdkResult<()> {
let mut cur = 0u64;
loop {
    let r = client.get_block_range(cur, cur + 255, Some(256)).await?;
    for b in &r.blocks { /* import block */ }
    if !r.more_available { break; }
    cur = r.next_height;
}
# Ok(())
# }
```

`client.syncing()` reports the live gap by comparing the local tip against
peer-reported network tips (gossiped on `tenzro/status`); pair it with
`get_block_range` to drive a catch-up loop only when needed.

## Settlement rails and routing

`client.device()` carries two related surfaces beyond device binding.

**Which rail a payment settles on.** Supporting x402 and being able to carry a
micropayment are different properties: Base speaks x402 and still cannot carry a
one-cent charge without roughly 10% overhead. `settlement_networks()` returns
every rail cheapest-first with the smallest worthwhile payment on each;
`route_payment()` answers where a specific charge goes — `accumulate` (below the
micro-settlement floor, hold it in a channel), `primary` (Tenzro Ledger),
`secondary` (cheapest rail carrying the payee's asset), or `no_viable_rail`.

Omit the TNZO price and the node settles on the home chain rather than routing
real money on a guessed exchange rate.

```rust,no_run
# async fn run(client: tenzro_sdk::TenzroClient) -> tenzro_sdk::SdkResult<()> {
let rails = client.device().settlement_networks().await?;
let decision = client
    .device()
    .route_payment("1000000000000000000", Some("USDC"), Some(1_000_000))
    .await?;
# Ok(())
# }
```


## Owner-proof on resource mutations

Methods that act on a resource by its identifier also require a signed DID
envelope proving control of the resource. An identifier is not a
credential: a `jti` travels in every audit row, and a `session_id` is a handle
the node hands back.

| Method                                 | Proof required                                                                    |
| -------------------------------------- | --------------------------------------------------------------------------------- |
| `revoke_jwt`                           | envelope from the token's bearer **or** the controller that authorized it         |
| `revoke_did`                           | node administrator **and** an envelope from the DID (or a machine's controller) |

Each envelope is bound to the method name and to that call's parameters, so one
produced for a given action cannot be replayed as another.

## Reference

Every public type and method is documented on [docs.rs/tenzro-sdk](https://docs.rs/tenzro-sdk), and the code blocks in this README compile as doctests. The RPC methods themselves are documented in the [JSON-RPC reference](https://github.com/tenzro/tenzro-network/blob/main/docs/RPC.md).

## Examples

```bash
cargo run --example local_node          # chain id, a balance and a transfer dry run on one node
cargo run --example basic_usage
cargo run --example wallet_operations
cargo run --example ai_inference
```

## Reaching the network

The SDK defaults to the preview network, `network::PREVIEW_NETWORK`: chain id
133801, RPC at `https://rpc.tenzro.com`, the REST API at
`https://api.tenzro.com`, MCP at `https://mcp.tenzro.com/mcp`, A2A at
`https://a2a.tenzro.com` and the relay at `https://relay.tenzro.com`.

There is no single endpoint. RPC operators bond the `rpc` role and publish
the URL they serve in consensus state; `network::connect_to_network(&NetworkOptions::default())` asks the seed for that
list, keeps the operators that report chain id 133801 and agree on a
checkpoint digest, and moves between them when one cannot be reached.

The default seed, `https://rpc.tenzro.com`, is only a bootstrap hint: once
the operator list is read from chain, the client talks to the staked
operators, and any node of the network serves as a seed. Pass your own seeds
and chain id with `NetworkOptions::new(seeds, chain_id)`, or one endpoint with
`SdkConfig::builder().endpoint(url).chain_id(id)`. `SdkConfig::preview()` is
the preview network's RPC endpoint and chain id. Every node also serves MCP at
`/mcp` and A2A with its own Agent Card.

## Documentation

- [SDKs on tenzro.com](https://tenzro.com/docs/sdk)
- [API reference on docs.rs](https://docs.rs/tenzro-sdk)
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
