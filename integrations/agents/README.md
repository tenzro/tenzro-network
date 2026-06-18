# tenzro-agents

Cross-framework Tenzro coordination shims — **one shared core, six thin
adapters.** This is Phase 5 ("Cross-framework SDK shim") of the
[Agent Interoperability Protocol Bridge](../../docs/architecture/agent-interop-protocol-bridge.md).

Tenzro is **not** another agent framework. It is the interop substrate
*beneath* the frameworks: each framework keeps its inner loop (planning,
tool selection, memory), and Tenzro provides the portable pieces the
framework doesn't — a **TDIP DID** identity, **AP2 mandate** authz, and
**ERC-8004 reputation** — carried across LangGraph today and CrewAI
tomorrow without rebuilding trust.

Per Open Question #4 in the bridge doc ("six shims is six places to track
upstream API changes — need a single integration core, not six codebases"),
all framework logic funnels through `tenzro_agents.core`. Each adapter is
~50-150 LOC that translates a framework's native extension point onto the
core primitives.

## Architecture

```
tenzro_agents/
  core.py              # TenzroClient (JSON-RPC), TenzroDidEnvelope (Ed25519),
                       # AP2 mandate helpers, ReputationHook  <- ALL logic here
  langgraph.py         # BaseCallbackHandler subclass
  crewai.py            # @task wrapper + Agent subclass
  letta.py             # tenzro_memory_* tools + archive hook
  openai_sdk.py        # RunHooks wrapper
  adk.py               # BasePlugin
  agent_framework.py   # AgentMiddleware / FunctionMiddleware
```

The core is always importable; **no agent framework is a hard dependency.**
Each adapter imports its framework lazily and raises a clear `ImportError`
only when actually invoked, so `import tenzro_agents` works in any
environment.

### The DID envelope (Layer 1)

`TenzroDidEnvelope` is the auth lingua franca. The canonical preimage layout
is **pinned** and matches the authoritative Rust `tenzro-identity` envelope
module byte-for-byte (reference impl: `crates/tenzro-identity/src/envelope.rs`):

```
DOMAIN_TAG (b"tenzro-did-envelope:v1")
  || u32_be(len(did))    (4 bytes)
  || did_utf8
  || u32_be(len(method)) (4 bytes)
  || method_utf8
  || params_hash (32 raw bytes = SHA-256 of canonical JSON params)
  || timestamp   (u64, big-endian, 8 bytes, Unix milliseconds)
  || nonce       (16 raw bytes)
```

`did` and `method` are `u32` big-endian length-prefixed (required for
cross-language verification — the Rust verifier prepends the same prefixes).

Canonical params JSON = `sort_keys=True` + compact separators + UTF-8.
Signature = Ed25519 over the preimage. The wire envelope is
`{did, method, params_hash (hex), timestamp, nonce (hex), signature (hex)}`.

## Install

```bash
pip install tenzro-agents                      # core only (httpx + PyNaCl)
pip install "tenzro-agents[langgraph]"         # + langchain-core / langgraph
pip install "tenzro-agents[crewai]"            # + crewai
pip install "tenzro-agents[letta]"             # + letta-client
pip install "tenzro-agents[openai]"            # + openai-agents
pip install "tenzro-agents[adk]"               # + google-adk
pip install "tenzro-agents[agent-framework]"   # + agent-framework
pip install "tenzro-agents[all]"               # every adapter
```

## Core usage

```python
import nacl.signing
from tenzro_agents import TenzroClient, checkout_mandate, payment_mandate, cart_item

sk = nacl.signing.SigningKey.generate()
client = TenzroClient(
    "https://rpc.tenzro.network",
    signing_key=sk,
    did="did:tenzro:machine:acme-procurement-bot-7a1b",
)

# Provision once (TDIP DID + MPC wallet + ERC-8004 agent id).
client.participate(node_type="agent", capabilities=["procurement"])

# Build + validate an AP2 mandate pair.
checkout = checkout_mandate(
    principal_did="did:tenzro:human:acme-cfo",
    agent_did=client.did,
    description="procurement run",
    max_amount=3400, accepted_chains=["solana:mainnet"], human_present=False,
)
items = [cart_item(sku="C", description="widgets", quantity=1, unit_price=3400)]
payment = payment_mandate(
    checkout=checkout, agent_did=client.did,
    merchant_did="did:tenzro:machine:vendorC", items=items, chain="solana:mainnet",
)
client.validate_mandate_pair(checkout, payment)   # tenzro_ap2ValidateMandatePair
```

## Per-framework snippets

### LangGraph / LangChain
Native extension point: [`BaseCallbackHandler`](https://reference.langchain.com/python/langchain-core/callbacks/base/BaseCallbackHandler).

```python
from tenzro_agents.langgraph import make_langgraph_callback

cb = make_langgraph_callback(client, did=client.did, subject_agent_id=0x4A2)
graph.invoke(state, config={"callbacks": [cb]})
# emits a DID envelope per node, AP2 check on tool nodes,
# ERC-8004 feedback on graph finish.
```

### CrewAI
Native extension points: `@task` (from `crewai.project`) and the
[`Agent`](https://docs.crewai.com/en/concepts/crews) class
(`execute_task(self, task, context=None, tools=None)`).

```python
from tenzro_agents.crewai import make_tenzro_agent, tenzro_task

agent = make_tenzro_agent(
    client, did=client.did, subject_agent_id=0x4A2,
    role="researcher", goal="find suppliers", backstory="...",
)   # execute_task wrapped: mandate-validate before, reputation-submit after

@tenzro_task(client, subject_agent_id=0x4A2)
@task
def research(self): ...
```

### Letta
Native extension point: [tool registration](https://docs.letta.com/guides/agents/custom-tools)
via `client.tools.upsert_from_function(func=...)`.

```python
from letta_client import Letta
from tenzro_agents.letta import install_tenzro_memory_tools

letta = Letta(api_key="...")
install_tenzro_memory_tools(letta, client, did=client.did, subject_agent_id=0x4A2)
# registers tenzro_memory_grant / tenzro_memory_recall / tenzro_memory_archive;
# the archive tool submits ERC-8004 feedback via the memory-archive hook.
```

### OpenAI Agents SDK
Native extension point: [`RunHooks`](https://openai.github.io/openai-agents-python/ref/lifecycle/).

```python
from agents import Runner
from tenzro_agents.openai_sdk import TenzroOpenAIWrapper

wrapper = TenzroOpenAIWrapper(client, did=client.did, subject_agent_id=0x4A2)
await Runner.run(agent, "research suppliers", hooks=wrapper.run_hooks())
# DID + AP2 validator on on_tool_start, ERC-8004 dispatch on on_agent_end.
```

### Google ADK
Native extension point: the [plugin system](https://google.github.io/adk-docs/plugins/)
(`BasePlugin`).

```python
from google.adk.runners import Runner
from tenzro_agents.adk import tenzro_adk_plugin

runner = Runner(agent=agent, plugins=[tenzro_adk_plugin(client, did=client.did, subject_agent_id=0x4A2)])
# before_tool_callback: DID + AP2 check; after_run_callback: ERC-8004 feedback.
```

### Microsoft Agent Framework
Native extension point: the [middleware pipeline](https://learn.microsoft.com/en-us/agent-framework/agents/middleware/)
(`AgentMiddleware` / `FunctionMiddleware`).

```python
from agent_framework import Agent
from tenzro_agents.agent_framework import make_agent_framework_middleware

agent = Agent(
    client=chat_client, name="procurement",
    middleware=[make_agent_framework_middleware(client, did=client.did, subject_agent_id=0x4A2)],
)
# process(): DID + AP2 before call_next(), ERC-8004 feedback after.
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The envelope round-trip test pins the canonical preimage and verifies the
Ed25519 signature with PyNaCl. Adapter tests import every adapter module
(must succeed without any framework installed) and exercise the real
framework API only when that framework is present (`pytest.importorskip`).

## References

- Bridge design: [`docs/architecture/agent-interop-protocol-bridge.md`](../../docs/architecture/agent-interop-protocol-bridge.md)
- Node RPC method names: `crates/tenzro-node/src/rpc.rs`
- Rust DID envelope reference (authoritative): `crates/tenzro-identity/src/envelope.rs`
- AP2 v0.2: <https://ap2-protocol.org/ap2/specification/> · `crates/tenzro-payments/src/ap2/mod.rs`
- ERC-8004 Trustless Agents: <https://eips.ethereum.org/EIPS/eip-8004>
- LangChain `BaseCallbackHandler`: <https://reference.langchain.com/python/langchain-core/callbacks/base/BaseCallbackHandler>
- CrewAI: <https://docs.crewai.com/en/concepts/crews>
- Letta custom tools: <https://docs.letta.com/guides/agents/custom-tools>
- OpenAI Agents SDK lifecycle: <https://openai.github.io/openai-agents-python/ref/lifecycle/>
- Google ADK plugins: <https://google.github.io/adk-docs/plugins/>
- Microsoft Agent Framework middleware: <https://learn.microsoft.com/en-us/agent-framework/agents/middleware/>
