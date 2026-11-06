# Cross-VM Token Architecture

**Status:** matches the code in `crates/tenzro-vm` (EVM precompiles, the SVM
SPL Token program, `token_ledger.rs`, `calls.rs`).

## Summary

Every token has one balance store, keyed by account, and every VM's view of
the token reads and writes that same store (`token_ledger.rs`). TNZO lives in
the native balance map; every other fungible token lives in the token
factory's storage, one slot per (token, account). There is no wrapped balance,
no lock-and-mint and no second copy of any balance that could drift.

- A 20-byte EVM address and the 32-byte key made of that address followed by
  12 zero bytes are the same account, for every token. A key-derived account
  and a delegated agent's wallet both have this form, so one identity has one
  balance per token whichever VM it acts in.
- SVM pubkeys are 32-byte keys in the same store.
- Moving a token between VMs is a transfer between two accounts through the
  token's interface in the sending VM, executed in a block, inside the
  transaction's journal. The sum of balances changes only by the fee the
  sender paid.

| Token | EVM view | SVM view |
|-------|----------|----------|
| TNZO | wTNZO pointer (`0x1001`) | SPL `Transfer` / `TransferChecked` under the wTNZO mint |
| Factory token | token factory (`0x1002`) | SPL `TransferChecked`, mint = token id |

## Contract-call transactions

`TransactionType::ContractCall { calls }` carries an ordered list of up to 16
calls, each naming its VM (`evm`, `svm`), the code it calls, the TNZO
it carries (EVM only) and its calldata. The runtime runs them in order for the
sender, inside the single undo log block execution opens for the transaction
(`calls.rs`):

- Each call sees every earlier call's writes.
- If any call fails, the transaction fails and every call's writes, in every
  VM, are undone; the sender pays the gas used.
- Gas is the sum over the calls; each VM charges the sender for its own at the
  transaction's gas price, so the ledger's per-transaction value rule holds.
- The logs of all calls, in call order, are the transaction's logs, under its
  one transaction id.
- RPC scope checks run once per call, on the call's target
  (`intents_for_transaction`).

A delegated agent's `AgentAct` may carry calls too. They run from the agent's
wallet after the action is accepted, and each is held to the agent's terms on
its own: its VM must be an allowed chain, its target an allowed counterparty
and its value within the limits before it runs, and the TNZO it moved out of
the wallet (fees aside) is checked against the per-transaction and daily
limits after it runs and added to the day's total. The same terms therefore
apply whichever VM a call targets.

## EVM view

Tenzro precompiles run inside revm through `evm::precompile_host`, which
replaces revm's call handler. A precompile sees the calling frame's real
`msg.sender`, `msg.value` and static flag, and touches state only through
revm's journal, so a reverted frame reverts its writes and a read-only
`eth_call` (which never commits) can change nothing. State-changing selectors
are refused outright on the `eth_call` path and under `STATICCALL`.
DELEGATECALL and CALLCODE into a Tenzro precompile revert.

### Precompile addresses

Addresses are 20-byte big-endian numbers.

| Address  | Name | Purpose |
|----------|------|---------|
| `0x0100` | P256VERIFY | EIP-7951 secp256r1 verification |
| `0x1001` | wTNZO pointer | ERC-20 interface over native TNZO |
| `0x1002` | TOKEN_FACTORY | Fungible tokens with their ledger in precompile storage |
| `0x1006` | NFT_FACTORY | ERC-721 / ERC-1155 collections |
| `0x1007` | VRF_VERIFY | RFC 9381 ECVRF proof verification |
| `0x1009` | RANDOMNESS_BEACON | Randomness from finalized chain state |
| `0x1010` | TEE_VERIFY | Strict TEE attestation report verification |
| `0x1011` | ZK_VERIFY | ZK proof attestations recorded in state |
| `0x101a`-`0x101c` | uRWA hooks | ERC-7943 freeze, forced transfer, kill switch (`erc7943.rs`) |

ERC-8004 registries are ordinary predeployed EVM contracts
(`tenzro_identity::erc8004::addresses`), not precompiles, so `0x101a` belongs
only to the uRWA freeze hook. There are no settlement, model-inference,
staking or governance precompiles.

### wTNZO pointer (`0x1001`)

| Function | Behaviour |
|----------|-----------|
| `name()`, `symbol()`, `decimals()` | `"Wrapped TNZO"`, `"wTNZO"`, `18` |
| `totalSupply()` | Native TNZO total supply |
| `balanceOf(address)` | The account's native balance |
| `transfer(address,uint256)` | Native transfer from `msg.sender`; emits `Transfer` |
| `approve(address,uint256)` / `allowance(address,address)` | Allowances in the precompile's storage |
| `transferFrom(address,address,uint256)` | Spends the allowance of `msg.sender`, then a native transfer |

The pointer refuses any call that carries value: native TNZO already is wTNZO.

### Token factory (`0x1002`)

`createToken(string,string,uint8,uint256)` returns a 32-byte token id,
`keccak256(domain || creator || creator_nonce)`, and credits the initial supply
to the creator. `getToken`, `getTokenCount`, `balanceOf(bytes32,address)`,
`transfer(bytes32,address,uint256)`, `approve`, `allowance` and
`transferFrom` operate on the ledger in the factory's storage, for
`msg.sender`. These tokens never touch native TNZO. The same balances are the
SVM view's (see the table above).

### NFT factory (`0x1006`)

The collection creator is the `msg.sender` of `createCollection(string,string,uint8)`.
Only the creator mints (`mint`, `mintBatch`, `mintMulti`) and registers
cross-VM pointers; only an owner transfers
(`transferNft(bytes32,address,uint256)`, from `msg.sender`).

Random mints are commit then reveal. `mintRandom(bytes32,address,uint256)`
records a request in block N and returns its id. From block N+2 anyone may
call `fulfillRandom(bytes32)`; the token id (`mod idSpace`, probing up to 16
ids past a collision) and the rarity byte come from
`keccak256(domain || hash(block N+1) || request id)`. Neither the minter nor
the fulfiller supplies any input to the draw, and the request is fixed before
block N+1 exists. The proposer of block N+1 can still influence its hash.

### Randomness beacon (`0x1009`)

`random(bytes32 seed)` returns
`keccak256(domain || hash(block N-1) || N || caller || counter || seed)`,
where `counter` counts the caller's earlier state-changing requests. No key
is involved, and every validator computes the same value. The proposer of
block N-1 can influence its hash, so high-value draws should commit in one
block and read the beacon in a later one.

### VRF (`0x1007`)

Verification only: `pubkey (32) || proof (80) || alpha_len (32, big-endian) ||
alpha`. On success it returns a 32-byte status of 1 followed by the 64-byte
output; otherwise a 32-byte zero. Gas `50,000 + 3 * alpha_len`. No RPC
generates proofs from a secret key.

### TEE_VERIFY (`0x1010`) and ZK_VERIFY (`0x1011`)

TEE_VERIFY returns 1 only for a report that passes the strict verifier
(certificate chain to a pinned vendor root, never simulated) and whose
timestamp is neither after the block's nor more than 24 hours before it.

ZK_VERIFY reads consensus state. `statementSystems(bytes32 statement)` returns
how many distinct proof systems have an attested proof of `statement`
(`tenzro_zk::statement_commitment(circuit_id, public_inputs)`); a contract that
wants k independent proof systems to agree requires at least k. The precompile
never parses a proof. Attestations are written by the native `AttestZkProof`
transaction, which carries the bincode proof envelope (up to 4 MiB, gas
2,000,000 + 4 per byte) and which every validator re-verifies while executing
the block.

## SVM view

The SVM executor serves the SPL Token program (`SPL_TOKEN_PROGRAM_ID`)
natively, against the same balances. A token account is the owner's own
ledger account. `Transfer` moves wTNZO (amounts convert between 9 and 18
decimals by truncation). `TransferChecked`
(`[source, mint, destination, authority]`, amount and decimals) moves any
mint: the wTNZO mint with 9 decimals, or a factory token whose id is the mint,
in its own base units and with its own decimals. Source and authority must be
the signer. `GetBalance` reads. `MintTo`, `Burn`, `Approve` and `Revoke` are
refused. Any other stored program runs under `svm-full`.

## Security properties

1. One ledger: every view reads and writes the native balance map.
2. Conservation: each cross-VM move debits exactly what it credits, in one
   transaction; the only net change is the fee. A contract call is atomic
   across every VM it touches.
3. Authorization comes from the executing frame's sender, never from calldata.
4. Read-only calls cannot persist: they run against a discarded fork of state
   and state-changing selectors refuse.
5. No precompile performs network I/O or reads the local clock.
