# Delegated Authority Skill

Ask the network whether you may run a tool, before you run it.

Agent harnesses normally hold their approval policy locally — a list of tool
names that should prompt first. That works until the process running the agent
is the thing being constrained: whatever can edit the config can remove the
gate.

Tenzro already answers this question for spending. A delegation grant names the
parties an agent may act as, the templates and commands it may use, the caps it
may spend under, and the actions its controller's oversight claim parks for a
human. This skill applies that same authority to a tool call the network never
sees — an editor write, a shell command, a contract call.

## MCP backend

| Field | Value |
|---|---|
| Server | Tenzro L1 core MCP server |
| Port | 3001 |
| Testnet endpoint | `https://mcp.tenzro.xyz/mcp` |
| Local endpoint | `http://localhost:3001/mcp` |
| Tool | `authorize_tool_call` |
| RPC | `tenzro_authorizeToolCall` |

## The decision

Three outcomes, returned as data rather than as an error:

| decision | meaning |
|---|---|
| `permit` | proceed |
| `require_approval` | a human must approve; `approval_id` is what they act on |
| `deny` | refused; `reason` says why |

`require_approval` being data rather than an error is the point. A harness that
receives it should park the call and surface the id — not retry, and not report
a failure. Approvals are single-use and bound to the action and constraint they
were issued for.

## Grant vocabulary

None is added. The tool is adjudicated as `<class>:<tool>` under the existing
`InvokeResource` action, so a grant that already restricts skills and workflow
templates restricts harness tools the same way.

## What it does not do

It does not run the tool, and it does not make the tool safe. It answers who
said you could, and records that a human was asked when the grant required one.
Enforcement is still the caller's — a harness that asks and then proceeds
regardless has learned nothing.
