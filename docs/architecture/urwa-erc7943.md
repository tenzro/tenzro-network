# ERC-7943 (uRWA) — Universal Real-World Asset Compliance

Tenzro implements ERC-7943, the 2026 canonical standard for tokenized
real-world assets that must respect regulator orders (sanctions freeze,
asset recovery), legal-entity mandates (counterparty defaults, court
orders), and routine compliance (sub-account freezing pending KYC
refresh). The standard reached Final status on 2026-05-27.

## The interface

The five standard ERC-7943 fungible functions, whose selectors XOR to the
interface id:

| Function | Purpose |
|---|---|
| `forcedTransfer(address,address,uint256)` | The issuer moves an amount between accounts: asset recovery, a court order, re-allocation after a default. |
| `setFrozenTokens(address,uint256)` | The issuer freezes an amount on an account; the remainder stays transferable. |
| `getFrozenTokens(address)` | The frozen amount of an account. |
| `canTransact(address)` | Whether an account may transact in the token. |
| `canTransfer(address,address,uint256)` | Whether a transfer would be allowed now. |

Halting every holder transfer of a token (the kill switch) is not part of
ERC-7943. It is the issuer's `set_halted`, a native `Token` transaction.

## EVM interface

The token factory precompile (`0x1002`) serves the ERC-7943 functions keyed
by token id, over the same ledger and the same rule engine as its ERC-20
functions: `canTransact(bytes32,address)`,
`canTransfer(bytes32,address,address,uint256)`,
`getFrozenTokens(bytes32,address)`,
`setFrozenTokens(bytes32,address,uint256)` and
`forcedTransfer(bytes32,address,address,uint256)`, with
`facadeOf(bytes32)` and `supportsInterface(bytes4)`. Every token also
answers at its own facade address with the standard functions, which take
no token id. There is no separate uRWA precompile.

`setFrozenTokens` and `forcedTransfer` act only for an issuer that holds the
power alone under the token's manifest. A power held by a council goes
through the native `Token` transaction.

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
| `tenzro_urwaIsKillSwitched` | Read the kill-switch state for a given `token_id_hex` (32-byte hex). Returns the token id and the active flag. |
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

## Who may act

Only the token's issuer freezes, halts or forces a transfer: with a signed
`Token` transaction or, where the token's manifest gives the issuer the
power alone, through the EVM interface.

## SDK surface

The Rust SDK (`UrwaClient`, `sdk/tenzro-sdk/src/urwa.rs`) and the TypeScript
SDK (`urwa.ts`) wrap the two read RPCs. The issuer's controls are `Token`
transactions built with the SDK's typed transactions.

## Status

Transfer enforcement in the token ledger, the EVM interface in the token
factory precompile and the two read RPCs are live. A network-wide kill
switch driven by governance is not implemented.
