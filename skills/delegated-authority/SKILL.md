---
name: delegated-authority
version: 0.1.0
author: Tenzro Network
description: Ask the network whether you may run a tool before you run it. Answers from the delegation grant your controller signed — the parties you may act as, the commands you may use, the caps you may spend under, and the actions your oversight claim parks for a human. Covers permit / require-approval / deny handling and the single-use approval replay.
tags:
  - authority
  - delegation
  - approval
  - human-in-the-loop
  - oversight
  - governance
  - agent-safety
---

# Delegated Authority Skill

## MCP Endpoint

| Field | Value |
|---|---|
| Server | Tenzro L1 core MCP server |
| Testnet endpoint | `https://mcp.tenzro.xyz/mcp` |
| Local endpoint | `http://localhost:3001/mcp` |
| Tool | `authorize_tool_call` |
| Underlying RPC | `tenzro_authorizeToolCall` |

## What this is for

Before running a tool that changes something — an edit, a shell command, a
transfer, a contract call — ask whether you are allowed to.

The answer does not come from local configuration. It comes from the
delegation grant your controller signed: which parties you may act as, which
templates and commands you may use, what you may spend per call, and which
actions their oversight claim requires a human to approve.

This matters because a policy held in a config file cannot constrain the
process running you — anything able to edit that file can remove the gate. A
grant is signed, lives on the network, and answers the same way whether you
are running inside a coding harness or autonomously.

## When to call it

Call it when the tool would **change state or spend**:

- writing or deleting files outside a scratch directory
- shell commands with side effects
- any transfer, contract call, or paid resource invocation
- anything acting on behalf of a party you were delegated

Do **not** call it before reads, searches, or listing operations. A gate on
every read makes the check noise and trains you to ignore it.

## The three answers

```
authorize_tool_call(tool="edit_file")
→ {"decision": "permit", "tool": "edit_file", "resource_id": "tool:edit_file", "wallet_id": "..."}
```

**`permit`** — proceed.

**`require_approval`** — a human must approve first. This is an outcome, not a
failure. Do not retry, do not route around it, and do not report it as an
error. Surface the `approval_id` to the human, stop that line of work, and
continue with something else if there is something else to do.

```
→ {"decision": "require_approval", "approval_id": "apr_...", "reason": "..."}
```

Once approved, replay the *same* call with the id:

```
authorize_tool_call(tool="transfer", amount_wei="5000000000000000000", approval_id="apr_...")
→ {"decision": "permit", ...}
```

Approvals are **single-use** and bound to the action and constraint they were
issued for. A second replay with the same id is refused, and an id issued for
one action does not authorize another.

**`deny`** — you are not permitted. `reason` says why. Report it plainly and
stop. Do not attempt the same thing by another route: a denial that you work
around is a denial that did nothing.

## Spending calls

Pass `amount_wei` when the call spends, so per-call ceilings apply:

```
authorize_tool_call(
    tool="submit_daml_command",
    resource_class="canton",
    amount_wei="1000000000000000000",
    counterparty="0x...",
)
```

Omitting the amount on a spending call asks the wrong question — the ceiling
cannot be checked against an amount you did not name, and a permit you obtained
that way does not cover the spend.

## Resource classes

`resource_class` defaults to `tool`. The tool is adjudicated as
`<class>:<tool>`, the same shape every other resource uses, so an existing
grant restricts tools exactly as it already restricts skills and workflow
templates — no new grant vocabulary.

Use the class that matches what you are doing: `tool` for harness tools,
`skill`, `canton`, `workflow`, and so on for the rest.

## What a denial means

A denial is information about your delegation, not an obstacle. If you were
given a narrow scope, that was deliberate. The useful response is to say what
you were refused and why, so whoever holds the grant can widen it if they meant
to — not to find a path that avoids the check.

## Failure modes worth knowing

- **No credential** → `deny`. Asking without a bearer leaves nothing to
  adjudicate against; the call is refused rather than waved through.
- **Malformed token or an unavailable auth engine** → a JSON-RPC error, not a
  decision. Those are faults, and they must not read as `permit`.
- **A grant with no scope at all** → refused. An empty scope means nothing was
  delegated, not that everything is permitted.
