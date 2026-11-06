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

Three EVM precompile addresses are reserved for the uRWA hooks (see
Status):

- `0x101a` — freeze registry (get / set frozen tokens)
- `0x101b` — forced-transfer dispatcher
- `0x101c` — kill-switch registry

## Transfer enforcement

The restriction lives in the VM token ledger, beside the balances it
guards. Each token holds two compliance slots, `token/halted` (the kill
switch) and `token/frozen` (per account), and the ledger's transfer checks
them before the sender is debited; the EVM token-factory precompile's
transfer checks the same slots. While a token's kill switch is active every
holder transfer is refused, and a transfer that would spend into the
sender's frozen amount is refused while the unfrozen remainder still moves.
A token with no kill switch and no frozen amount is unaffected.

Only the token's issuer changes them, with signed `Token` transactions
(`set_halted`, `set_frozen`). Accounts are keyed by their 32-byte ledger
slot; a 20-byte address widens left-aligned, so one frozen amount covers
every VM view of an account.

The issuer's `forced_transfer` is the one move that does not consult the
slots. After it debits the sender, the sender's frozen amount is lowered
to what it still holds.

Not restricted: native TNZO and its wTNZO/SPL views (TNZO is not
a uRWA asset), mints and burns (supply changes, not transfers between
holders).

## RPC surface

| Method | Description |
|---|---|
| `tenzro_urwaIsKillSwitched` | Read the kill-switch state for a given `token_id` (32-byte hex). Returns the active flag plus the canonical selectors + precompile addresses for SDK integrators. |
| `tenzro_urwaGetFrozenTokens` | Read the frozen-amount value for a `(token_id, account)` pair. Returns the frozen amount in token smallest unit. |
| `Token` `set_frozen` | Set the frozen amount for a `(token_id, account)` pair. Signed by the token's issuer. |
| `Token` `set_halted` | Activate or clear a token's kill switch. Signed by the token's issuer. |
| `Token` `forced_transfer` | Move `amount` of `token_id` between accounts, bypassing the kill switch and frozen amount. Signed by the token's issuer. |

Accounts are 20-byte or 32-byte hex addresses.

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

Registry, transfer enforcement in the token registry, and the read and
admin-gated mutation RPCs are live. The precompiles at `0x101a`-`0x101c`
and the governance-driven network-wide kill switch are not implemented.
