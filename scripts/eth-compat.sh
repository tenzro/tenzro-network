#!/bin/sh
# Ethereum wallet compatibility: ethers v6 and viem drive the node's eth_*
# JSON-RPC (network detection, fee estimation, legacy/EIP-1559/EIP-7702
# transactions incl. an EIP-7702 one with an authorization that does not apply,
# receipts, blocks and their logs blooms, receiptsRoot recomputed from
# eth_getBlockReceipts with an independent trie, eth_call, eth_getCode,
# eth_getLogs, contract-creation eth_call/eth_estimateGas, and
# balance/nonce/code/storage/call/estimateGas/feeHistory at older blocks) against
# an in-process node on chain 13380. Needs Node.js 18+ and npm.
set -eu
cd "$(dirname "$0")/.."
(cd crates/tenzro-node/tests/eth_compat && npm install --no-audit --no-fund --silent)
exec cargo test --locked -p tenzro-node --lib eth_wallets -- --ignored --nocapture
