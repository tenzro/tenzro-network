# ERC-7943 (uRWA) — Universal Real-World Asset Compliance

Tenzro implements ERC-7943, the 2026 canonical standard for tokenized
real-world assets that must respect regulator orders (sanctions freeze,
asset recovery), legal-entity mandates (counterparty defaults, court
orders), and routine compliance (sub-account freezing pending KYC
refresh). The standard reached Final status on 2026-05-27.

## The four mandatory hooks

| Selector | Function | Purpose |
|---|---|---|
| `0x33e4e1d3` | `forcedTransfer(address,address,uint256)` | Privileged transfer executed by the compliance role — asset recovery, court-ordered seizure, post-default re-allocation. Bypasses normal allowance / signing. |
| `0x57c52a45` | `setFrozenTokens(address,uint256)` | Freeze a specific amount on an account; the remainder stays transferable. Used for KYC-refresh-pending where only a sub-balance is quarantined. |
| `0xe4d8156e` | `getFrozenTokens(address)` | Read the frozen amount for an account. |
| `0x1c70d7e6` | `killSwitch()` | Global emergency stop; halts all transfers for the token until cleared by governance. |

Auxiliary read/write selectors: `isKillSwitched(0x3d3b9f47)`,
`clearKillSwitch(0xb22f3ea7)`.

The selectors are byte-identical to the ERC-7943 reference
implementation, so wallets that already speak uRWA dispatch against
Tenzro without recompilation.

## Precompile addresses

The uRWA enforcement hooks live at three EVM precompile addresses:

- `0x101a` — freeze registry (get / set frozen tokens)
- `0x101b` — forced-transfer dispatcher
- `0x101c` — kill-switch registry

The transfer hook on every uRWA-class token consults the freeze + kill
registries pre-debit. If the kill switch is active, all transfers
revert. If frozen tokens exceed the transferable balance, the transfer
reverts.

## RPC surface

| Method | Description |
|---|---|
| `tenzro_urwaIsKillSwitched` | Read the kill-switch state for a given `token_id` (32-byte hex). Returns the active flag plus the canonical selectors + precompile addresses for SDK integrators. |
| `tenzro_urwaGetFrozenTokens` | Read the frozen-amount value for a `(token_id, account)` pair. Returns the frozen amount in token smallest unit. |

Mutations (`forcedTransfer`, `setFrozenTokens`, `killSwitch`,
`clearKillSwitch`) flow through standard EVM transactions to the
precompile addresses; the admin gate enforces operator + governance
authorisation.

## When to use

- **Tokenized money-market funds, treasuries, equities** — any
  RWA-class asset where the issuer may be served a court order,
  sanctions update, or post-default seizure request.
- **NOT for TNZO** — TNZO is a network utility token, not a tokenized
  security, so it does not carry uRWA hooks.

## Auth model

Per the Tenzro admin gate, kill-switch + forced-transfer + freeze
mutations are operator-gated by default. Network-wide compliance
decisions (e.g. a fleet-level kill switch for a token tracked across
multiple operators) MUST flow through the
`tenzro-token::GovernanceEngine` rather than a single operator's admin
token — see *Network-wide resources require governance* in the
governance architecture doc.

## SDK surface

The Rust + TypeScript SDKs will surface `UrwaClient` wrappers with
typed parameter structs over the two read RPCs. The wallet UI surfaces
the kill-switched state inline on tokenized assets so users see why a
transfer cannot proceed.

## Status

Library + precompile selectors + 2 read RPCs live. Mutation transaction
selectors + admin-gated mutation handlers + governance-driven
network-wide kill-switch land in subsequent waves.
