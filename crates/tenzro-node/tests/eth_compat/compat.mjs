// Drives the node's eth_* JSON-RPC through ethers v6 and viem the way a
// wallet does: network detection, balance and nonce reads, EIP-1559 fee
// estimation, legacy (EIP-155), EIP-1559 and EIP-7702 transactions, receipts,
// blocks, eth_call, eth_getCode and eth_getLogs filters, logs blooms, state
// at older blocks (EIP-1898) and EIP-7702 authorizations that do not apply.
//
// Env: ETH_COMPAT_URL (node RPC), ETH_COMPAT_KEY (funded secp256k1 key),
// ETH_COMPAT_CHAIN_ID (default 13380). Exits non-zero on any failure.

import * as ethers from "ethers";
import { Trie } from "@ethereumjs/trie";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  parseEther,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const URL = process.env.ETH_COMPAT_URL;
const KEY = process.env.ETH_COMPAT_KEY;
const CHAIN_ID = Number(process.env.ETH_COMPAT_CHAIN_ID ?? 13380);
if (!URL || !KEY) {
  console.error("ETH_COMPAT_URL and ETH_COMPAT_KEY are required");
  process.exit(2);
}

// A contract whose every call stores 42, emits LOG1(TOPIC) over it and
// returns it.
const TOPIC = "0x" + "11".repeat(32);
const RUNTIME = "0x602a6000527f" + "11".repeat(32) + "60206000a160206000f3";
const INITCODE = "0x6030600c60003960306000f3" + RUNTIME.slice(2);
const FORTY_TWO = "0x" + "00".repeat(31) + "2a";

const failures = [];
let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`ok   ${name}`);
  } catch (e) {
    failures.push(name);
    const rpc = e?.error ?? e?.info?.error ?? e?.cause?.cause ?? e?.cause;
    const detail = rpc?.message ? ` [${rpc.code ?? ""} ${rpc.message}]` : "";
    console.log(`FAIL ${name}: ${e?.shortMessage ?? e?.message ?? e}${detail}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const DATA32 = /^0x[0-9a-f]{64}$/;
function quantity(v, what) {
  assert(typeof v === "string" && QUANTITY.test(v), `${what} is not a hex quantity: ${JSON.stringify(v)}`);
}

// The 2048-bit log bloom (Yellow Paper 4.3.1) of `logs`, as 0x hex.
function bloomOf(logs) {
  const bits = new Uint8Array(256);
  const add = (hex) => {
    const h = ethers.getBytes(ethers.keccak256(hex));
    for (const i of [0, 2, 4]) {
      const bit = ((h[i] << 8) | h[i + 1]) & 2047;
      bits[255 - (bit >> 3)] |= 1 << (bit & 7);
    }
  };
  for (const l of logs) {
    add(l.address);
    l.topics.forEach(add);
  }
  return ethers.hexlify(bits);
}

let id = 0;
async function raw(method, params = []) {
  const res = await fetch(URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.code} ${body.error.message}`);
  return body.result;
}

// ---------------------------------------------------------------- raw shapes

await check("eth_chainId is the hex chain id", async () => {
  assert((await raw("eth_chainId")) === "0x" + CHAIN_ID.toString(16), "wrong chain id");
});
await check("net_version is the decimal chain id", async () => {
  assert((await raw("net_version")) === String(CHAIN_ID), "wrong net_version");
});
await check("web3_clientVersion is a string", async () => {
  const v = await raw("web3_clientVersion");
  assert(typeof v === "string" && v.length > 0, "empty client version");
});
await check("eth_blockNumber is a hex quantity", async () => quantity(await raw("eth_blockNumber"), "blockNumber"));
await check("eth_gasPrice / eth_maxPriorityFeePerGas are hex quantities", async () => {
  quantity(await raw("eth_gasPrice"), "gasPrice");
  quantity(await raw("eth_maxPriorityFeePerGas"), "maxPriorityFeePerGas");
});
await check("latest block has the fields wallets read", async () => {
  const b = await raw("eth_getBlockByNumber", ["latest", false]);
  for (const k of ["number", "timestamp", "gasLimit", "gasUsed", "baseFeePerGas", "size"]) quantity(b[k], k);
  for (const k of ["hash", "parentHash", "stateRoot", "transactionsRoot", "receiptsRoot", "mixHash", "sha3Uncles"])
    assert(DATA32.test(b[k] ?? ""), `block ${k} is not 32 bytes: ${b[k]}`);
  assert(/^0x[0-9a-f]{40}$/.test(b.miner ?? ""), `block miner is not an address: ${b.miner}`);
  assert(/^0x[0-9a-f]{512}$/.test(b.logsBloom ?? ""), "block logsBloom is not 256 bytes");
  assert(/^0x[0-9a-f]{16}$/.test(b.nonce ?? ""), `block nonce is not 8 bytes: ${b.nonce}`);
  assert(Array.isArray(b.transactions) && Array.isArray(b.uncles), "transactions/uncles not arrays");
});
await check("eth_getBlockByNumber of an unknown height is null", async () => {
  assert((await raw("eth_getBlockByNumber", ["0xffffffff", false])) === null, "not null");
});
await check("eth_getTransactionReceipt / eth_getTransactionByHash of an unknown hash are null", async () => {
  const h = "0x" + "ab".repeat(32);
  assert((await raw("eth_getTransactionReceipt", [h])) === null, "receipt not null");
  assert((await raw("eth_getTransactionByHash", [h])) === null, "transaction not null");
});
await check("eth_feeHistory has the EIP-1559 shape", async () => {
  const f = await raw("eth_feeHistory", ["0x4", "latest", [25, 75]]);
  quantity(f.oldestBlock, "oldestBlock");
  const n = f.gasUsedRatio.length;
  assert(n >= 1 && n <= 4, `gasUsedRatio has ${n} entries`);
  assert(f.baseFeePerGas.length === n + 1, "baseFeePerGas must have one more entry than gasUsedRatio");
  f.baseFeePerGas.forEach((v) => quantity(v, "baseFeePerGas[]"));
  assert(f.gasUsedRatio.every((r) => typeof r === "number"), "gasUsedRatio entries are not numbers");
  assert(Array.isArray(f.reward) && f.reward.length === n, "reward has the wrong length");
  f.reward.forEach((r) => (assert(r.length === 2, "reward row length"), r.forEach((v) => quantity(v, "reward"))));
});

// ---------------------------------------------------------------- ethers v6

const provider = new ethers.JsonRpcProvider(URL);
const wallet = new ethers.Wallet(KEY, provider);
const other = ethers.Wallet.createRandom().address;
let contract;
let contractBlock;
let logBlock;
let logTx;

await check("ethers: network detection", async () => {
  const net = await provider.getNetwork();
  assert(net.chainId === BigInt(CHAIN_ID), `chainId ${net.chainId}`);
});
await check("ethers: balance and pending nonce", async () => {
  assert((await provider.getBalance(wallet.address)) > 0n, "unfunded");
  const n = await provider.getTransactionCount(wallet.address, "pending");
  assert(typeof n === "number", "nonce");
});
await check("ethers: getFeeData gives EIP-1559 fees", async () => {
  const fd = await provider.getFeeData();
  assert(fd.maxFeePerGas !== null && fd.maxPriorityFeePerGas !== null, "no EIP-1559 fees");
  assert(fd.maxFeePerGas >= fd.maxPriorityFeePerGas, "maxFee below priority fee");
});
await check("ethers: estimateGas of a transfer", async () => {
  const g = await provider.estimateGas({ from: wallet.address, to: other, value: 1n });
  assert(g >= 21000n, `estimate ${g}`);
});
await check("ethers: EIP-1559 transfer, receipt and transaction", async () => {
  const before = await provider.getBalance(other);
  const tx = await wallet.sendTransaction({ to: other, value: ethers.parseEther("0.01") });
  const r = await tx.wait(1, 60_000);
  assert(r.status === 1, `status ${r.status}`);
  assert(r.type === 2, `receipt type ${r.type}`);
  assert(r.gasPrice > 0n, "no effectiveGasPrice");
  assert(r.hash === tx.hash, "receipt hash differs from the wallet hash");
  const t = await provider.getTransaction(tx.hash);
  assert(t && t.hash === tx.hash && t.blockNumber === r.blockNumber, "eth_getTransactionByHash");
  assert(t.from.toLowerCase() === wallet.address.toLowerCase(), "transaction from");
  assert((await provider.getBalance(other)) - before === ethers.parseEther("0.01"), "value not credited");
  const blk = await provider.getBlock(r.blockNumber, true);
  assert(blk.transactions.includes(tx.hash), "block does not list the wallet hash");
});
await check("ethers: legacy EIP-155 transfer", async () => {
  const gasPrice = (await provider.getFeeData()).gasPrice;
  const tx = await wallet.sendTransaction({ type: 0, to: other, value: 1n, gasPrice });
  const r = await tx.wait(1, 60_000);
  assert(r.status === 1 && r.type === 0, `status ${r.status} type ${r.type}`);
});
await check("ethers: contract deployment and eth_getCode", async () => {
  const tx = await wallet.sendTransaction({ data: INITCODE });
  const r = await tx.wait(1, 60_000);
  assert(r.status === 1, `status ${r.status}`);
  assert(r.contractAddress, "no contractAddress");
  contract = r.contractAddress;
  contractBlock = r.blockNumber;
  assert((await provider.getCode(contract)).toLowerCase() === RUNTIME, "code differs");
  assert((await provider.getCode(other)) === "0x", "an account without code is not 0x");
});
await check("ethers: eth_call", async () => {
  assert((await provider.call({ to: contract, data: "0x" })) === FORTY_TWO, "call result");
});
await check("eth_call and eth_estimateGas without to simulate a contract creation", async () => {
  const code = await provider.call({ from: wallet.address, data: INITCODE });
  assert(code.toLowerCase() === RUNTIME, `eth_call of init code returned ${code}`);
  const gas = await provider.estimateGas({ from: wallet.address, data: INITCODE });
  assert(gas > 53000n, `creation estimate ${gas} is below the creation intrinsic gas`);
  const r = await (await wallet.sendTransaction({ data: INITCODE, gasLimit: gas })).wait(1, 60_000);
  assert(r.status === 1 && r.contractAddress, `a deployment at the estimate failed: ${r.status}`);
  assert((await provider.getCode(r.contractAddress)).toLowerCase() === RUNTIME, "deployed code differs");
});
await check("ethers: receipt logs", async () => {
  const tx = await wallet.sendTransaction({ to: contract, data: "0x01" });
  const r = await tx.wait(1, 60_000);
  assert(r.status === 1, `status ${r.status}`);
  assert(r.logs.length === 1, `${r.logs.length} logs`);
  const l = r.logs[0];
  assert(l.address.toLowerCase() === contract.toLowerCase(), "log address");
  assert(l.topics.length === 1 && l.topics[0] === TOPIC, "log topics");
  assert(l.data === FORTY_TWO, "log data");
  assert(l.transactionHash === tx.hash && l.blockNumber === r.blockNumber, "log position");
  logBlock = r.blockNumber;
  logTx = tx.hash;
});
await check("ethers: eth_getLogs by address/topic/range/blockHash", async () => {
  const byAddr = await provider.getLogs({ address: contract, fromBlock: 0, toBlock: "latest" });
  assert(byAddr.some((l) => l.transactionHash === logTx), "by address");
  const byTopic = await provider.getLogs({ topics: [TOPIC], fromBlock: logBlock, toBlock: logBlock });
  assert(byTopic.length === 1 && byTopic[0].transactionHash === logTx, "by topic and range");
  const none = await provider.getLogs({ topics: ["0x" + "22".repeat(32)], fromBlock: 0, toBlock: "latest" });
  assert(none.length === 0, "a non-matching topic matched");
  const hash = (await provider.getBlock(logBlock)).hash;
  const byHash = await provider.getLogs({ blockHash: hash });
  assert(byHash.length === 1 && byHash[0].blockHash === hash, "by blockHash");
  const anyOf = await provider.getLogs({ address: [contract, other], topics: [[TOPIC, "0x" + "22".repeat(32)]], fromBlock: logBlock, toBlock: logBlock });
  assert(anyOf.length === 1, "address and topic OR-lists");
});
await check("logsBloom: receipt and block blooms are the blooms of their logs", async () => {
  const receipt = await raw("eth_getTransactionReceipt", [logTx]);
  assert(receipt.logsBloom === bloomOf(receipt.logs), "receipt logsBloom differs from its logs");
  assert(receipt.logsBloom !== "0x" + "00".repeat(256), "receipt logsBloom is empty");
  const block = await raw("eth_getBlockByNumber", ["0x" + logBlock.toString(16), false]);
  const logs = await raw("eth_getLogs", [{ blockHash: block.hash }]);
  assert(logs.length >= 1, "no logs in the log block");
  assert(block.logsBloom === bloomOf(logs), "block logsBloom differs from eth_getLogs of the block");
  const quiet = await raw("eth_getBlockByNumber", ["0x" + contractBlock.toString(16), false]);
  const quietLogs = await raw("eth_getLogs", [{ blockHash: quiet.hash }]);
  assert(quiet.logsBloom === bloomOf(quietLogs), "a block without logs has a non-empty bloom");
});
await check("block parameters: balance, nonce, code, storage, call and fee history at older blocks", async () => {
  const b0 = await provider.getBlockNumber();
  const bal0 = await provider.getBalance(other, b0);
  const n0 = await provider.getTransactionCount(wallet.address, b0);
  const r = await (await wallet.sendTransaction({ to: other, value: 7n })).wait(1, 60_000);
  assert(r.status === 1, `status ${r.status}`);
  assert((await provider.getBalance(other, b0)) === bal0, "the balance at an older block moved");
  assert((await provider.getBalance(other, r.blockNumber)) === bal0 + 7n, "the balance at the transfer block");
  assert((await provider.getBalance(other, r.blockNumber - 1)) === bal0, "the balance just before the transfer");
  assert((await provider.getTransactionCount(wallet.address, b0)) === n0, "the nonce at an older block moved");
  const h0 = (await provider.getBlock(b0)).hash;
  assert(BigInt(await raw("eth_getBalance", [other, { blockHash: h0 }])) === bal0, "EIP-1898 blockHash");
  assert(BigInt(await raw("eth_getBalance", [other, { blockNumber: "0x" + b0.toString(16) }])) === bal0, "EIP-1898 blockNumber");
  assert((await provider.getCode(contract, contractBlock - 1)) === "0x", "code before the deployment block");
  assert((await provider.getCode(contract, contractBlock)).toLowerCase() === RUNTIME, "code at the deployment block");
  assert((await provider.getStorage(contract, 0, contractBlock - 1)) === "0x" + "00".repeat(32), "storage before deployment");
  assert((await provider.call({ to: contract, data: "0x", blockTag: contractBlock - 1 })) === "0x", "eth_call before deployment");
  assert((await provider.call({ to: contract, data: "0x", blockTag: contractBlock })) === FORTY_TWO, "eth_call at deployment");
  const est = async (tag) => BigInt(await raw("eth_estimateGas", [{ from: wallet.address, to: contract, data: "0x01" }, tag]));
  const before = await est("0x" + (contractBlock - 1).toString(16));
  const at = await est({ blockNumber: "0x" + contractBlock.toString(16) });
  assert(before < at, `eth_estimateGas before deployment ${before} is not below the estimate at deployment ${at}`);
  assert(at === (await est("latest")), "eth_estimateGas at deployment differs from latest");
  const f = await raw("eth_feeHistory", ["0x2", "0x" + b0.toString(16), []]);
  assert(BigInt(f.oldestBlock) === BigInt(b0) - 1n, `feeHistory oldestBlock ${f.oldestBlock} for newest ${b0}`);
  for (const [m, p] of [
    ["eth_getBalance", [other, "0xffffffff"]],
    ["eth_getCode", [contract, "0xffffffff"]],
    ["eth_call", [{ to: contract, data: "0x" }, "0xffffffff"]],
    ["eth_estimateGas", [{ to: contract, data: "0x" }, "0xffffffff"]],
    ["eth_feeHistory", ["0x1", "0xffffffff", []]],
    ["eth_getBalance", [other, { blockHash: "0x" + "ab".repeat(32) }]],
  ]) {
    let err;
    try {
      await raw(m, p);
    } catch (e) {
      err = e;
    }
    assert(err && /header not found/.test(err.message), `${m} past the tip answered: ${err?.message ?? "a result"}`);
  }
});

// ---------------------------------------------------------------- viem

const chain = defineChain({
  id: CHAIN_ID,
  name: "Tenzro",
  nativeCurrency: { name: "TNZO", symbol: "TNZO", decimals: 18 },
  rpcUrls: { default: { http: [URL] } },
});
const account = privateKeyToAccount(KEY);
const pub = createPublicClient({ chain, transport: http(URL), pollingInterval: 250 });
const wc = createWalletClient({ chain, account, transport: http(URL) });

await check("viem: chain id, balance, pending nonce", async () => {
  assert((await pub.getChainId()) === CHAIN_ID, "chain id");
  assert((await pub.getBalance({ address: account.address })) > 0n, "balance");
  await pub.getTransactionCount({ address: account.address, blockTag: "pending" });
});
await check("viem: estimateFeesPerGas / getGasPrice / getFeeHistory", async () => {
  const f = await pub.estimateFeesPerGas();
  assert(f.maxFeePerGas >= f.maxPriorityFeePerGas, "fees");
  assert((await pub.getGasPrice()) > 0n, "gas price");
  const h = await pub.getFeeHistory({ blockCount: 3, rewardPercentiles: [50] });
  assert(h.baseFeePerGas.length === h.gasUsedRatio.length + 1, "fee history shape");
});
await check("viem: EIP-1559 transfer and receipt", async () => {
  const hash = await wc.sendTransaction({ to: other, value: parseEther("0.001") });
  const r = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
  assert(r.status === "success" && r.type === "eip1559", `${r.status} ${r.type}`);
  assert(r.effectiveGasPrice > 0n, "effectiveGasPrice");
  const t = await pub.getTransaction({ hash });
  assert(t.hash === hash && t.type === "eip1559", "getTransaction");
});
await check("viem: legacy transfer", async () => {
  const hash = await wc.sendTransaction({ to: other, value: 1n, type: "legacy", gasPrice: await pub.getGasPrice() });
  const r = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
  assert(r.status === "success" && r.type === "legacy", `${r.status} ${r.type}`);
});
await check("viem: call, code, logs", async () => {
  const { data } = await pub.call({ to: contract, data: "0x" });
  assert(data === FORTY_TWO, "call");
  assert((await pub.getCode({ address: contract })).toLowerCase() === RUNTIME, "code");
  const logs = await pub.getLogs({ address: contract, fromBlock: 0n, toBlock: "latest" });
  assert(logs.some((l) => l.transactionHash === logTx), "logs");
  const blk = await pub.getBlock({ blockTag: "latest" });
  assert(blk.baseFeePerGas !== null && blk.baseFeePerGas !== undefined, "baseFeePerGas");
});
await check("viem: creation call and estimateGas at older blocks", async () => {
  const deployed = BigInt(contractBlock);
  const { data } = await pub.call({ account: account.address, data: INITCODE, blockNumber: deployed - 1n });
  assert(data?.toLowerCase() === RUNTIME, `creation call returned ${data}`);
  const create = await pub.estimateGas({ account: account.address, data: INITCODE, blockNumber: deployed });
  assert(create > 53000n, `creation estimate ${create} is below the creation intrinsic gas`);
  const est = (blockNumber) => pub.estimateGas({ account: account.address, to: contract, data: "0x01", blockNumber });
  const before = await est(deployed - 1n);
  const at = await est(deployed);
  assert(before < at, `estimateGas before deployment ${before} is not below the estimate at deployment ${at}`);
});
await check("viem: EIP-7702 delegation", async () => {
  const authorization = await wc.signAuthorization({ contractAddress: contract, executor: "self" });
  const hash = await wc.sendTransaction({ authorizationList: [authorization], to: account.address, data: "0x" });
  const r = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
  const reason = r.status === "success" ? "" : (await raw("eth_getTransactionReceipt", [hash])).revertReason;
  assert(r.status === "success" && r.type === "eip7702", `${r.status} ${r.type} ${reason ?? ""}`);
  const code = await pub.getCode({ address: account.address });
  assert(code?.toLowerCase() === "0xef0100" + contract.slice(2).toLowerCase(), `delegation code ${code}`);
});
await check("viem: an EIP-7702 transaction with an invalid authorization still executes", async () => {
  const fresh = privateKeyToAccount(generatePrivateKey());
  const wrongChain = privateKeyToAccount(generatePrivateKey());
  const valid = await wc.signAuthorization({ account: fresh, contractAddress: contract, chainId: CHAIN_ID, nonce: 0 });
  const invalid = await wc.signAuthorization({ account: wrongChain, contractAddress: contract, chainId: CHAIN_ID + 1, nonce: 0 });
  const hash = await wc.sendTransaction({ authorizationList: [valid, invalid], to: fresh.address, data: "0x" });
  const r = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
  assert(r.status === "success" && r.type === "eip7702", `${r.status} ${r.type}`);
  assert(r.gasUsed >= 21000n + 2n * 25000n, `gasUsed ${r.gasUsed} does not charge both authorizations`);
  const code = await pub.getCode({ address: fresh.address });
  assert(code?.toLowerCase() === "0xef0100" + contract.slice(2).toLowerCase(), `valid authorization not applied: ${code}`);
  assert(((await pub.getCode({ address: wrongChain.address })) ?? "0x") === "0x", "the wrong-chain authorization applied");
  assert((await pub.getTransactionCount({ address: wrongChain.address })) === 0, "the skipped authority's nonce moved");
  assert((await pub.getTransactionCount({ address: fresh.address })) === 1, "the authority's nonce was not spent");
  const before = await pub.getCode({ address: fresh.address, blockNumber: r.blockNumber - 1n });
  assert((before ?? "0x") === "0x", `code before the delegation block: ${before}`);
});

// ---------------------------------------------------------------- receipts root

// A receipt's consensus encoding (EIP-2718), built from the RPC fields alone.
function receiptBytes(r) {
  const body = ethers.encodeRlp([
    r.status === "0x1" ? "0x01" : "0x",
    ethers.toBeArray(BigInt(r.cumulativeGasUsed)),
    bloomOf(r.logs),
    r.logs.map((l) => [l.address, l.topics, l.data]),
  ]);
  const type = Number(r.type);
  return ethers.getBytes(type === 0 ? body : ethers.concat([ethers.toBeHex(type, 1), body]));
}
await check("receiptsRoot: every block's root is the trie of its eth_getBlockReceipts", async () => {
  const tip = await provider.getBlockNumber();
  const types = new Set();
  let checked = 0;
  for (let n = 0; n <= tip; n++) {
    const tag = "0x" + n.toString(16);
    const block = await raw("eth_getBlockByNumber", [tag, false]);
    const receipts = await raw("eth_getBlockReceipts", [tag]);
    const trie = new Trie();
    for (const r of receipts) {
      assert(r.blockHash === block.hash, `receipt of ${r.transactionHash} names another block`);
      types.add(Number(r.type));
      await trie.put(ethers.getBytes(ethers.encodeRlp(ethers.toBeArray(BigInt(r.transactionIndex)))), receiptBytes(r));
    }
    const root = ethers.hexlify(trie.root());
    assert(block.receiptsRoot === root, `block ${n}: receiptsRoot ${block.receiptsRoot}, receipts give ${root}`);
    checked += receipts.length;
  }
  for (const t of [0, 2, 4]) assert(types.has(t), `no type ${t} receipt among the blocks checked`);
  assert(checked > 0, "no receipts checked");
  const one = await raw("eth_getTransactionReceipt", [logTx]);
  const inBlock = await raw("eth_getBlockReceipts", [{ blockHash: one.blockHash }]);
  assert(JSON.stringify(inBlock.find((r) => r.transactionHash === logTx)) === JSON.stringify(one), "eth_getBlockReceipts differs from eth_getTransactionReceipt");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("failed: " + failures.join("; "));
  process.exit(1);
}
