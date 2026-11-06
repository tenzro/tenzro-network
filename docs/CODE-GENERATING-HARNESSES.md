# Tenzro behind a code-generating harness

Some agent harnesses do not hand a model one tool call at a time. They turn an
MCP server's tool list into a typed API, let the model write a short program
against it, and run that program in a sandbox the harness owns. This page shows
how a node's MCP server fits that shape: what the harness binds, where the
credentials live, which types the generated code is written against, and what
stops a program that calls a paid tool in a loop.

Nothing here runs on the node. The node serves tools; the sandbox, the code and
the model belong to the harness.

## 1. The binding

The harness connects to the node's MCP endpoint over Streamable HTTP
(stateless, JSON replies, revision 2026-07-28) and exposes it to generated code
as one object with a function per tool.

| Endpoint | What `tools/list` returns | For |
| --- | --- | --- |
| `/mcp` | every tool, each with its input schema and output schema | harnesses that generate the whole API up front |
| `/mcp/compact` | two tools, `search` and `call` | harnesses that look tools up as they need them |

On `/mcp/compact`, `search { query, read_only?, limit? }` matches words against
each tool's name, description and JSON-RPC method and returns the matches with
their exact input and output schemas, as `/mcp` lists them. `call { name,
arguments }` invokes one tool. Its arguments are checked against that tool's
input schema first: an unknown tool or arguments the schema refuses come back as
invalid params, with `data.reason` set to `unknown_tool` or
`invalid_arguments`. A `call` then takes the same path as calling the tool on
`/mcp`.

Every tool's output is typed: each tool lists an output schema, and its result is returned as structured content that matches it, so generated code reads fields rather than parsing free text. A `call` on `/mcp/compact` is paid, limited and recorded exactly as the same tool on `/mcp`: the same credentials, agent Terms, spend limits, receipts and audit apply, and a call with a valid access token leaves a signed tool-call record ([AGENT_TRUST.md](AGENT_TRUST.md#tool-call-records)).

A harness can turn either listing into TypeScript declarations. The node's own
test suite does exactly that conversion on every build and fails when a tool
has no description, a name that is not snake_case, or two names that bind to
the same function; [MCP.md](MCP.md) lists every tool with its schema. Tools
that mirror one JSON-RPC method take that method's `params` and return
`{ result }`; [RPC.md](RPC.md) documents each method's params and result.

List-type tools return one page at a time with a `cursor` and a `limit`, so a
program walks a long listing instead of receiving it whole: providers
(`list_providers`), settlements (`list_settlements`), forwarded payment legs
(`list_network_legs`) and execution receipts (`moe_list_receipts`).

## 2. Credentials stay in the harness

Generated code never holds a credential, and no tool asks for one.

- **The caller's token.** The harness signs in once through the node's OAuth
  2.1 flow (`/authorize`, `/token`) with the user's passkey, and attaches the
  resulting token (with its DPoP proof) to every request it forwards. The
  program calls `providers.list(...)`; the binding adds the headers. Every tool
  runs under the caller's own credentials, behind the same access policy and
  method gates as a direct JSON-RPC call.
- **No key material in arguments.** No tool accepts a private key, a seed or a
  secret key as an argument; the node's tests fail if one does. A signature the
  user owes is made on the user's device (passkey or hardware key) and passed
  as a signature, never as a key.
- **An agent's own access.** An agent acting for a person signs in as its own
  DID (`tenzro_issueAccessToken`), and what it does is checked against the
  Terms its controller approved with a passkey. The harness holds that token
  the same way.
- **Third-party API keys.** A credential the agent needs for another service is
  a brokered credential in its Terms: sealed by the controller to each serving
  node's hardware key and attached as one header, by the node's egress path, to
  requests addressed to exactly that host. The agent and its code never see it.

## 3. The TypeScript SDK as the typed API

`tenzro-sdk` (npm) is a typed client for every
JSON-RPC method the node serves, split into one package per capability
(`@tenzro/core`, `@tenzro/payments`, `@tenzro/settlement`, `@tenzro/agents`,
`@tenzro/bridge`, `@tenzro/inference`, `@tenzro/chain`). A harness that runs
TypeScript can give generated code the SDK's types instead of, or next to, the
declarations it derives from the MCP tool list: the same methods, with result
types and the transaction builders that produce what the user's device signs.
Signing in the SDK goes through a `HybridSigner`: a TPM or Secure Enclave key
(`@tenzro/device-key`), or a passkey in a browser; without one, it refuses to
sign.

## 4. Terms as the spending guard

A program can call a paid tool in a tight loop with no model turn in between.
What stops it is the agent's Terms, held in consensus state. The spend caps,
the action limits and revocation are checked on every settlement the agent's
wallet pays through, whichever tool, surface or loop it came from; the scope
fields bound what the agent may do at all:

| Terms field | What it bounds |
| --- | --- |
| `max_transaction_value` | the most one action may move |
| `max_hourly_spend`, `max_daily_spend` | the total over any 60 minutes and any 24 hours |
| `max_actions_per_hour`, `max_actions_per_day` | how many actions, whatever their value |
| `allowed_operations`, `allowed_models`, `allowed_counterparties`, `allowed_payment_protocols`, `allowed_chains` | what the agent may do at all, and with whom |
| `step_up_above` | an action above this needs the controller's passkey approval of that one action |
| `allowed_hours_utc`, `expires_at_ms` | when the agent may act |

A revoked or expired agent is refused the same way. `get_agent_terms` returns
the Terms with what has been spent this hour and today and what remains, so a
program can check its budget before it loops. The controller changes the Terms
with `update_agent_terms`, approved with the controller's passkey or the
machine's hardware key.

## 5. Receipts

A chat completion served by a node with a machine identity carries a signed
receipt (`tenzro_receipt`) naming the model, the serving machine, the request's
nonce, commitments to the input and output, and the units charged. A harness can keep the receipt next to the program's run and
check it later without any Tenzro code; the format and an independent verifier
are in [standards/inference-receipt.md](standards/inference-receipt.md).
