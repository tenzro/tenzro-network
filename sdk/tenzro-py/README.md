# Tenzro SDK for Python

The official Tenzro SDK for Python. The `tenzro` package talks to a Tenzro node and signs with the machine's
hardware. It carries:

- **Every RPC method the node serves**, one typed method each, on a synchronous
  (`RpcClient`) and an asynchronous (`AsyncRpcClient`) client. The methods are
  generated from the node's method table, so the SDK never lags the node.
- **Typed transactions** for every consensus transaction type, built
  client-side, checked against the node's signing payload and signed with the
  caller's hardware key.
- **Hardware signing only**: P-256 from the TPM 2.0 (Linux, Windows) or the
  Apple Secure Enclave through the `tenzro-device-key` native module, and the
  ML-DSA-65 leg the hardware derives; the network requires both legs. An
  account signs nothing until it has enrolled an ML-DSA-65 key, and
  `AccountKeysClient.send_enrolling` enrols it on the first send. There is no
  software key and no software fallback.
- **x402 payers** (`tenzro-hybrid` with the payer's key, `batch-settlement`
  from a delegated agent's channel), an HTTP client that pays, and the
  publisher gate as ASGI and WSGI middleware.
- **Settlement plans**: the split engine, plan builders and the x402 `plan`
  payment.
- **Payment operations**: bridge sends, payee refunds and split rules.
- **Streamed chat completions** with reasoning, tool calls and usage as events.
- **Delegated agents**: Terms, `agent_act`, vouchers, and agents' accounts on
  other chains.
- **EIP-7702** set-code transactions for an external secp256k1 signer.
- **Governance receipts** verified offline against a certified state root.

## Install

Not yet published to PyPI — install from source until it is:

```sh
pip install git+https://github.com/tenzro/tenzro-sdk-python            # RPC, builders, verification
pip install "tenzro[device] @ git+https://github.com/tenzro/tenzro-sdk-python"  # plus the TPM / Secure Enclave signer
```

Python 3.10 or newer. Without the `device` extra (or without key hardware) the
SDK reads, builds and verifies, and refuses to sign. Once published, these
become `pip install tenzro` / `pip install "tenzro[device]"`.

## Quickstart

Read from the network: the client finds the staked RPC operators on chain,
keeps those that report the expected chain id and agree on a checkpoint, and
moves between them when one cannot be reached.
The default is the preview network, `tenzro.PREVIEW_NETWORK`: chain id 13380,
RPC at `https://rpc.tenzro.com`, the REST API at `https://api.tenzro.com`, MCP
at `https://mcp.tenzro.com/mcp`, A2A at `https://a2a.tenzro.com` and the relay
at `https://relay.tenzro.com`. The default seed, `https://rpc.tenzro.com`, is
only a bootstrap hint; pass `seeds=[...]` and `chain_id=...` to start from any
node of any network.

```python
from tenzro import NetworkRpcClient

with NetworkRpcClient.connect() as node:
    print(node.get_finalized_block())
    print(node.get_balance(["0x" + "00" * 32]))
    methods = node.list_rpc_methods()        # what this node serves
    print(node.call("eth_blockNumber"))         # any method by name
```

A local node is one `RpcClient`: `tenzro dev` serves a single-validator
chain, id 1337, on `127.0.0.1:8545`.

```python
from tenzro import RpcClient

with RpcClient("http://127.0.0.1:8545") as node:
    print(int(node.eth_chain_id(), 16), node.get_balance(["0x" + "00" * 32]))
```

Each typed method takes the method's `params` (a JSON object or array) and
returns its result; the method names are the RPC names in snake case
(`tenzro_getBalance` is `get_balance`, `eth_chainId` is `eth_chain_id`, the
Solana namespace is `solana_*`). `tenzro.METHODS` maps every RPC name to its
access class on the node (`open`, `owner` or `admin`).

Sign and send a transaction with this machine's hardware key:

```python
from tenzro import NetworkRpcClient, TypedTransaction, TypedTxClient, open_hardware_signer

signer = open_hardware_signer("my-app")          # TPM or Secure Enclave; refuses without one
with NetworkRpcClient.connect() as node:
    receipt = TypedTxClient(node).send(
        signer,
        TypedTransaction(kind="Transfer", fields={"amount": 1000}, to="0x" + "ab" * 32),
    )
```

`TypedTxClient` asks the node for the signing payload, checks it is the
transaction it built (the node never signs), signs the composite message
representative with the hardware key and submits it. `TX_KINDS` lists every
transaction type the network decodes. `TypedTxClient(node).prepare(account, tx)` is a dry
run of the same steps up to the signature: it signs and submits nothing
(`examples/local_node.py` runs one).

Sign in with a DPoP-bound access token minted for the same hardware key:

```python
from tenzro import AccessCredential, HardwareDpopProver, RpcClient

prover = HardwareDpopProver(signer)
node = RpcClient(node_url, credential=AccessCredential(token=access_token, prover=prover))  # the node that issued the token
```

Pay for a resource over x402:

```python
from tenzro.payments import HybridPayer, PayingClient

client = PayingClient(HybridPayer(signer, payer_did="did:tenzro:human:..."), max_amount=10**15)
article = client.get("https://pub.example/articles/2")
```

Charge agents for a path, as a publisher: unpaid requests are answered 402
with the x402 requirements and never reach the application, and a payment is
settled by an x402 facilitator before the handler runs: name any facilitator
(one that relays the payer's own authorization through a node serves). People without
an agent signature browse free unless the policy charges them too.

```python
from tenzro import AsyncRpcClient
from tenzro.payments import AsyncPublisherGate, PaidRoute, PublisherPolicy, async_node_quote
from tenzro.payments.asgi import PublisherGateMiddleware

policy = PublisherPolicy(
    chain_id=13380,
    pay_to="ab" * 32,
    facilitator=facilitator_url,  # base URL of the harness facilitator; the gate posts to its /settle
    routes=(PaidRoute("/articles/*", usd_e6=2_000, permits=("ai-input",), prohibits=("ai-train",), content_usage="train-ai=n"),),
)
gate = AsyncPublisherGate(policy, quote=async_node_quote(AsyncRpcClient(node_url)))
app = PublisherGateMiddleware(app, gate)   # any ASGI app: Starlette, FastAPI, Django
```

`tenzro.payments.wsgi.PublisherGateMiddleware` with `PublisherGate` and
`node_quote` does the same for WSGI (Flask, Django). Any other server calls
`gate.decide(url, headers)` and applies the decision. `rsl_xml(policy, origin)`
and `robots_license_line(origin)` publish the same terms as an RSL licence and
a robots.txt line. The gate decides exactly as the TypeScript and Rust gates
do, on the shared vectors in `sdk/fixtures/payments/x402_gate.json`.

Stream a chat completion from a node that serves the model (or forwards to a
provider that does):

```python
from tenzro import RpcClient
from tenzro.inference import ChatClient

chat = ChatClient(RpcClient(node_url, credential=credential))
request = {"model": "qwen3.5-4b", "messages": [{"role": "user", "content": "Is 17 prime?"}]}
for event in chat.stream(request):
    if event["type"] in ("reasoning", "content"):
        print(event["text"], end="")
```

Read settlement plans, their decisions and each leg's receipt, each with the
state-proof key a light client proves it under:

```python
from tenzro.settlement import get_leg_receipt, get_plan, list_plans

for view in list_plans(node, status="open", limit=10)["plans"]:
    print(view["plan"]["plan_id"], view["leg_ids"])
leg = get_leg_receipt(node, plan_id=plan_id, index=0)
```

Act as a delegated agent, within the Terms its root granted:

```python
from tenzro import RpcClient
from tenzro.agents import agent_act

serving = RpcClient(serving_node_url, credential=agent_credential)
agent_act(serving, {"operation": "transfer", "counterparty": "ab" * 20, "amount": "100"})
```

Read the controls on an agent: kill-switch receipts (a page at a time, in
chain order) and its quarantine state:

```python
from tenzro.agents import agent_quarantine, kill_switches_by_agent

page = kill_switches_by_agent(node, "did:tenzro:agent:...")
while page.get("cursor"):
    page = kill_switches_by_agent(node, "did:tenzro:agent:...", from_cursor=page["cursor"])
print(agent_quarantine(node, "did:tenzro:agent:...")["quarantined"])
```

As the node's operator, read and check its administrative audit log:

```python
from tenzro.admin import audit_log, verify_audit_log

print(audit_log(operator_node, method="tenzro_stopModel", limit=20)["records"])
assert verify_audit_log(operator_node)["ok"]
```

Read governance: proposals, voting power and the governed parameters, then
verify a governance receipt offline:

```python
from tenzro.chain import verify_governance_receipt

print(node.list_proposals({"limit": 20}))
print(node.get_voting_power([{"address": "0x" + "ab" * 32}]))
print(node.list_levers({}))

report = verify_governance_receipt(node.get_governance_receipt({"proposal_id": pid}), certified_state_root)
print(report.proposal["status"], report.executed_height)
```

## Errors

A JSON-RPC error the node answers with raises `RpcError` with its `code`,
`message` and `data`: -32602 is invalid params, -32601 a method this node does
not serve, -32004 a resource or capability it does not have. An error in the
node's HTTP shape (`/v1/...`, and frames inside a stream) raises `ApiError`
with `type` and `code`.

```python
from tenzro import RpcError

try:
    node.chat({"model_id": "qwen3.5-4b", "message": "Hello"})
except RpcError as e:
    if e.light_build:
        ...  # this node is the light build of tenzro-node and runs no model: ask a provider
    else:
        raise
```

The SDK never substitutes a default for a value it failed to read: no nonce,
chain id or fee is guessed, and a signer that is not hardware is refused.

## Core and capabilities

The package root is the thin core; each capability is a subpackage over it,
and the core never imports one. Every subpackage ships in the one
distribution, with the core's only dependency (`httpx`); extras add native
modules (`device`).

| Import | What it holds |
| --- | --- |
| `tenzro` (core) | `RpcClient`, `AsyncRpcClient`, `RpcError`, `ApiError`, `AccessCredential`, `SseDecoder`; the signer interface and hardware signer (`tenzro.signer`), `tenzro.wallet`, the typed transaction builders (`tenzro.typed_tx`), ML-DSA-65 enrollment (`tenzro.account_keys`) |
| `tenzro.payments` | x402 payers (`HybridPayer`, `AgentChannelPayer`, `PayingClient`), the publisher gate (`PublisherGate`, `AsyncPublisherGate`, `tenzro.payments.asgi`, `tenzro.payments.wsgi`), `PublisherPolicy`, `rsl_xml` |
| `tenzro.settlement` | `preview_split`, `split_rule_hash`, `PlanBuilder`, plan payments, refunds, payee split rules; `get_plan`, `get_plan_decision`, `get_leg_receipt`, `list_plans` |
| `tenzro.agents` | `AgentTerms`, `delegate_agent`, `update_agent_terms`, `agent_act`, `agent_voucher`; `kill_switch_receipt`, `kill_switches_by_agent`, `kill_switches_by_controller`, `agent_quarantine`; NVIDIA OpenShell: `openshell_policy_terms`, `mint_openshell_credential`, `openshell_session_id`, `parse_openshell_records`, `verify_openshell_records`, `openshell_payments` |
| `tenzro.admin` | `audit_log`, `verify_audit_log` (operator only) |
| `tenzro.bridge` | bridge sends, agents' accounts on other chains and action digests, EIP-7702 (`tenzro.bridge.eip7702`) |
| `tenzro.inference` | `ChatClient`, `AsyncChatClient`, `ChatStreamAssembler` |
| `tenzro.chain` | `verify_governance_receipt`; ABI: `abi_encode`, `abi_decode`, `encode_function_call`, `function_selector`, `event_topic`; NFTs on the factory precompile: `nft_calldata`, `nft_decode`, `decode_nft_transfer`, `nft_collection_id`, `nft_transaction`, `NftClient` |

The same split holds in the TypeScript SDK (`@tenzro/core` and one package per
capability) and the Rust SDK (one cargo feature per capability).

## Development

```sh
pip install -e . --group dev       # the SDK plus the test dependencies (pytest, cryptography); pip 25.1+
python tools/generate_methods.py   # after the node's method table changes
pytest                             # tests, including the shared vectors in sdk/fixtures
```

The tests run the vectors in `sdk/fixtures` that the node and the other SDKs
are checked against. The repository's tests refuse a Python SDK that
misses a served method (`rpc_wiring`) or a transaction type
(`sdk_transaction_coverage`).

The native signer builds with [maturin](https://www.maturin.rs/) from
`native/`:

```sh
cd native && maturin build --release
```

## License

Apache-2.0. Copyright Tenzro Foundation.
