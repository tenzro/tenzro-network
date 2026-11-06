# Use any wallet

Tenzro accepts transactions signed by standard EVM and Solana wallets. Your
wallet keeps your key; the network only verifies the signature. An external
wallet account is a plain account in the one Tenzro ledger: the same balance
is visible from the EVM, SVM and native views. It has no agent authority;
agents are rooted in a passkey or a hardware key and act under their Terms.

## EVM wallets

| Parameter | Value |
|---|---|
| Network name | Tenzro |
| RPC URL | `https://<your-node>/rpc` |
| Chain ID | `<chain-id>`, the one the network's genesis sets (`eth_chainId` returns it): `13380` (`0x3444`) on the preview network, `1337` on a local developer chain |
| Currency symbol | `TNZO` |
| Decimals | 18 |

Accepted transactions (`eth_sendRawTransaction`, RLP hex): legacy with an
EIP-155 chain id (pre-EIP-155 signatures are refused), EIP-2930, EIP-1559 and
EIP-7702. The sender is recovered from the secp256k1 signature; the nonce is
the account's ledger nonce. Fees are quoted and paid in the EVM's native unit
and charged in TNZO at the fee market rate.

The EVM address `0x<20 bytes>` is the ledger account `0x<20 bytes>` followed
by twelve zero bytes.

Methods a wallet or library uses: `eth_chainId`, `net_version`,
`eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount` (`pending`
counts the mempool), `eth_gasPrice`, `eth_maxPriorityFeePerGas`,
`eth_feeHistory`, `eth_estimateGas` (executes the call against a scratch copy
of state), `eth_call` (both without `to` simulate a contract creation;
`eth_call` then returns the code it would deploy), `eth_sendRawTransaction`
(returns the keccak256 hash), `eth_getTransactionReceipt`,
`eth_getBlockReceipts`, `eth_getTransactionByHash` (pending
transactions from the mempool), `eth_getBlockByNumber`, `eth_getBlockByHash`,
`eth_getLogs` (`address`, `topics`, `fromBlock`/`toBlock` up to 10,000 blocks,
or `blockHash`), `eth_getCode`, `eth_getStorageAt`, `web3_clientVersion`.
Native Tenzro transactions, signed by a passkey or a hardware key, use
`tenzro_sendRawTransaction` instead.

Fees: a block's `baseFeePerGas` is the base fee its execution charges.
`eth_gasPrice` is the least price the open lane admits (the base fee or the
admission floor, whichever is higher); `eth_maxPriorityFeePerGas` and every
`eth_feeHistory` reward percentile are that price minus the base fee, so the
EIP-1559 estimates of ethers, viem and MetaMask clear admission. A receipt's
`effectiveGasPrice` is what the ledger charged,
`min(maxFeePerGas, baseFee + maxPriorityFeePerGas)`. A revert in `eth_call`
or `eth_estimateGas` answers error code 3 (`eth_call` with the revert data in
`data`). EIP-7702: an
authorization the sender signs for its own transaction carries the nonce after
the transaction's (viem's `executor: 'self'`); chain id 0 authorizes on every
chain; `eth_estimateGas` takes the signed `authorizationList` and runs the
delegations before the call. Each authorization costs 25,000 intrinsic gas
(12,500 of it refunded when the authority already exists, within the usual
one-fifth refund cap); one that cannot apply (another chain id, a stale nonce,
a signature that does not recover, an authority with contract code) is
skipped and the transaction still runs. Delegations stand even when the call
after them reverts. A gas limit below the intrinsic gas (Prague rules,
including the EIP-7623 calldata floor) is refused at admission.

Block parameters (EIP-1898): `eth_getBalance`, `eth_getTransactionCount`,
`eth_getCode`, `eth_getStorageAt`, `eth_call`, `eth_estimateGas` and
`eth_feeHistory` answer for
the block named by a tag, a hex number, `{blockNumber}` or `{blockHash}`.
Ordered blocks are final, so `latest`, `pending` and `safe` are the executed
tip; `finalized` is the highest checkpoint-certified height. State below the
tip comes from the height-versioned state trie, which keeps the last 10,000
blocks; an older block answers `missing trie node`, and a block past the tip
or an unknown hash `header not found`. Receipts and block headers carry the
Ethereum `logsBloom` of their logs; the block bloom is committed in the block
hash. A block's `receiptsRoot` is the root of the Merkle-Patricia trie of its
receipts (EIP-2718 encodings keyed by the RLP of the transaction index), as
`eth_getBlockReceipts` serves them; it is committed in the block hash, and a
block whose execution does not reproduce it is refused.

`scripts/eth-compat.sh` checks all of this with ethers v6 and viem against an
in-process node (`crates/tenzro-node/tests/eth_compat/compat.mjs`).

ethers or viem, unchanged:

```ts
const wallet = new ethers.Wallet(key, new ethers.JsonRpcProvider("https://<your-node>/rpc"));
const tx = await wallet.sendTransaction({ to, value: ethers.parseEther("1") });
const receipt = await tx.wait();
```

## Solana wallets

| Parameter | Value |
|---|---|
| RPC URL | `https://<your-node>/rpc` |
| Encoding | base64 or base58 wire transactions (`sendTransaction`) |

Legacy and v0 messages are accepted; every account must be listed in the
message (address lookup tables are not supported). Each required signer's
Ed25519 signature is verified over the message, and the fee payer is the first
signer. The signer's 32-byte public key is its ledger account. The recent
blockhash must be one of the last 150 blocks; a signature executes at most
once. Gas is fixed at 1,400,000 units priced at the block base fee, because a
Solana wallet signs no gas terms.

Amounts are shown in units of 10^-9 TNZO (the precision Solana wallets
display); the ledger keeps 18 decimals.

Methods: `sendTransaction`, `simulateTransaction` (executes against a scratch
copy of state), `getSignatureStatuses`, `getLatestBlockhash`,
`isBlockhashValid`, `getBalance`, `getAccountInfo`, `getFeeForMessage`,
`getMinimumBalanceForRentExemption` (0: there is no rent), `getSlot`,
`getBlockHeight`, `getVersion`, `getHealth`.

### EVM alias of a Solana account

The first time a Solana account signs, the ledger records its EVM alias: the
last 20 bytes of keccak256 of its Ed25519 public key. `eth_getBalance` and
`eth_getTransactionCount` for the alias answer for the Solana account, so an
EVM wallet can name it.
