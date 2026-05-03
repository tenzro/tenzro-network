#!/usr/bin/env node
/**
 * LayerZero ETH Bridge: Optimism → Base
 *
 * YOU run this: node scripts/lz-bridge.mjs
 *
 * 1. Generates wallet (key stays in THIS process only)
 * 2. You send ~$2 worth of ETH on Optimism
 * 3. Bridges a small amount of ETH to Base via LayerZero
 * 4. Returns remaining ETH to your wallet
 */

import { execSync } from "child_process";
import { createInterface } from "readline";
import crypto from "crypto";

// ─── Config ─────────────────────────────────────────────────────────────────
const OP_RPC = "https://mainnet.optimism.io";
const OP_CHAIN_ID = 10;
const BRIDGE_ETH = 300000000000000n; // 0.0003 ETH (~$0.50) to bridge
const USER_ADDR = "0xe9bfadd8b7e2a5afb37c6de52fd590da779eba50";
const LZ_API = "https://metadata.layerzero-api.com/v1/metadata/experiment/ofts";

// ─── Helpers ────────────────────────────────────────────────────────────────

function ask(q) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((r) => rl.question(q, (a) => { rl.close(); r(a); }));
}

async function rpc(method, params = []) {
  const res = await fetch(OP_RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new Error(`RPC ${method}: ${j.error.message}`);
  return j.result;
}

function generateWallet() {
  const privateKey = crypto.randomBytes(32);
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(privateKey);
  const pub = ecdh.getPublicKey("hex", "uncompressed");
  const pubBytes = Buffer.from(pub.slice(2), "hex");
  const hash = crypto.createHash("sha3-256").update(pubBytes).digest();
  return { privateKey, address: "0x" + hash.slice(-20).toString("hex") };
}

// ─── RLP + EIP-1559 ─────────────────────────────────────────────────────────

function rlpEncode(items) {
  if (Buffer.isBuffer(items)) {
    if (items.length === 0) return Buffer.from([0x80]);
    if (items.length === 1 && items[0] < 0x80) return items;
    if (items.length <= 55) return Buffer.concat([Buffer.from([0x80 + items.length]), items]);
    const lb = intToBytes(items.length);
    return Buffer.concat([Buffer.from([0xb7 + lb.length]), lb, items]);
  }
  if (Array.isArray(items)) {
    const enc = Buffer.concat(items.map(rlpEncode));
    if (enc.length <= 55) return Buffer.concat([Buffer.from([0xc0 + enc.length]), enc]);
    const lb = intToBytes(enc.length);
    return Buffer.concat([Buffer.from([0xf7 + lb.length]), lb, enc]);
  }
  throw new Error("rlp: bad type");
}
function intToBytes(n) { let h = n.toString(16); if (h.length % 2) h = "0" + h; return Buffer.from(h, "hex"); }
function b(n) { if (n === 0n) return Buffer.alloc(0); let h = n.toString(16); if (h.length % 2) h = "0" + h; return Buffer.from(h, "hex"); }
function hx(s) { if (s.startsWith("0x")) s = s.slice(2); if (!s.length) return Buffer.alloc(0); if (s.length % 2) s = "0" + s; return Buffer.from(s, "hex"); }
function keccak(d) { return crypto.createHash("sha3-256").update(d).digest(); }

async function signAndSend(pk, tx) {
  const fields = [b(BigInt(tx.chainId)), b(BigInt(tx.nonce)), b(BigInt(tx.maxPriorityFeePerGas)),
    b(BigInt(tx.maxFeePerGas)), b(BigInt(tx.gasLimit)), hx(tx.to),
    b(BigInt(tx.value || 0)), hx(tx.data || "0x"), []];
  const unsigned = Buffer.concat([Buffer.from([0x02]), rlpEncode(fields)]);
  const hash = keccak(unsigned);
  const der = Buffer.concat([Buffer.from("302e0201010420","hex"), pk, Buffer.from("a00706052b8104000a","hex")]);
  const sig = crypto.sign(null, hash, {
    key: crypto.createPrivateKey({ key: der, format: "der", type: "sec1" }),
    dsaEncoding: "ieee-p1363",
  });
  const r = sig.slice(0, 32), s = sig.slice(32, 64);
  for (const v of [0n, 1n]) {
    const signed = Buffer.concat([Buffer.from([0x02]), rlpEncode([...fields, b(v), r, s])]);
    try { return await rpc("eth_sendRawTransaction", ["0x" + signed.toString("hex")]); }
    catch (e) { if (v === 1n) throw e; }
  }
}

async function waitTx(hash, label) {
  process.stdout.write(`   Waiting for ${label}...`);
  for (let i = 0; i < 90; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const rcpt = await rpc("eth_getTransactionReceipt", [hash]);
    if (rcpt) {
      if (rcpt.status === "0x1") { console.log(` confirmed! (gas: ${parseInt(rcpt.gasUsed, 16)})`); return rcpt; }
      throw new Error(`${label} reverted`);
    }
    process.stdout.write(".");
  }
  throw new Error(`${label} timeout`);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== LayerZero ETH Bridge: Optimism → Base ===\n");

  // 1. API key
  console.log("1. Fetching LayerZero API key from GCP...");
  const apiKey = execSync(
    "gcloud secrets versions access latest --secret=rivier-layerzero-api-key --project=rivier-ai",
    { encoding: "utf-8" }
  ).trim();
  console.log("   Done.\n");

  // 2. Wallet
  console.log("2. Generating wallet...");
  const wallet = generateWallet();
  console.log(`   Address: ${wallet.address}\n`);

  // 3. Fund
  console.log("3. Send ~$2 worth of ETH to this address on OPTIMISM:");
  console.log(`   ${wallet.address}\n`);
  await ask("   Press Enter after funding... ");
  console.log();

  // 4. Verify
  console.log("4. Checking balance...");
  const ethBal = BigInt(await rpc("eth_getBalance", [wallet.address, "latest"]));
  const ethHuman = Number(ethBal) / 1e18;
  console.log(`   ETH: ${ethHuman.toFixed(6)}\n`);
  if (ethBal < BRIDGE_ETH + 100000000000000n) {
    console.error("   Not enough ETH! Need at least 0.0004 ETH.");
    process.exit(1);
  }

  // 5. LayerZero API
  console.log("5. Calling LayerZero Value Transfer API...");
  const params = new URLSearchParams({
    srcChainName: "optimism", dstChainName: "base", tokenSymbol: "ETH",
    amount: BRIDGE_ETH.toString(),
    senderAddress: wallet.address, recipientAddress: wallet.address,
  });
  const lzRes = await fetch(`${LZ_API}/transfer?${params}`, {
    headers: { "x-layerzero-api-key": apiKey },
  });

  if (!lzRes.ok) {
    const errText = await lzRes.text();
    console.log(`   API error (${lzRes.status}): ${errText}`);
    console.log("   Bridge not available. Returning ETH to you.\n");

    // Return all ETH minus gas
    const gasPrice = BigInt(await rpc("eth_gasPrice", []));
    const nonce = parseInt(await rpc("eth_getTransactionCount", [wallet.address, "latest"]), 16);
    const gasCost = 21000n * gasPrice * 3n;
    const returnAmt = ethBal - gasCost;
    if (returnAmt > 0n) {
      const tx = await signAndSend(wallet.privateKey, {
        chainId: OP_CHAIN_ID, nonce, maxPriorityFeePerGas: 100000n,
        maxFeePerGas: gasPrice * 3n, gasLimit: 21000n,
        to: USER_ADDR, value: returnAmt, data: "0x",
      });
      console.log(`   Return tx: ${tx}`);
      console.log(`   https://optimistic.etherscan.io/tx/${tx}`);
      await waitTx(tx, "return ETH");
    }
    return;
  }

  const lzData = await lzRes.json();
  console.log(`   Contract: ${lzData.populatedTransaction?.to}`);
  console.log(`   Value:    ${lzData.populatedTransaction?.value || 0} wei`);
  console.log(`   Gas:      ${lzData.populatedTransaction?.gasLimit || "auto"}\n`);

  // 6. Bridge
  const gasPrice = BigInt(await rpc("eth_gasPrice", []));
  let nonce = parseInt(await rpc("eth_getTransactionCount", [wallet.address, "latest"]), 16);

  // Approve if needed (shouldn't be for native ETH but just in case)
  if (lzData.approval) {
    console.log("6. Approving...");
    const appTx = await signAndSend(wallet.privateKey, {
      chainId: OP_CHAIN_ID, nonce, maxPriorityFeePerGas: 100000n,
      maxFeePerGas: gasPrice * 3n, gasLimit: 100000n,
      to: lzData.approval.to, value: 0n, data: lzData.approval.data,
    });
    console.log(`   Tx: ${appTx}`);
    await waitTx(appTx, "approval");
    nonce++;
    console.log();
  }

  console.log("6. Submitting bridge transaction...");
  const bridgeTx = await signAndSend(wallet.privateKey, {
    chainId: OP_CHAIN_ID, nonce, maxPriorityFeePerGas: 100000n,
    maxFeePerGas: gasPrice * 3n,
    gasLimit: BigInt(lzData.populatedTransaction.gasLimit || 300000),
    to: lzData.populatedTransaction.to,
    value: BigInt(lzData.populatedTransaction.value || 0),
    data: lzData.populatedTransaction.data,
  });
  console.log(`   Bridge tx: ${bridgeTx}`);
  console.log(`   Etherscan: https://optimistic.etherscan.io/tx/${bridgeTx}`);
  console.log(`   LZ Scan:   https://layerzeroscan.com/tx/${bridgeTx}`);
  await waitTx(bridgeTx, "bridge");
  nonce++;
  console.log();

  // 7. Return remaining ETH
  console.log("7. Returning remaining ETH to you...");
  const newBal = BigInt(await rpc("eth_getBalance", [wallet.address, "latest"]));
  const gasCost = 21000n * gasPrice * 3n;
  const returnAmt = newBal - gasCost;
  if (returnAmt > 0n) {
    const retTx = await signAndSend(wallet.privateKey, {
      chainId: OP_CHAIN_ID, nonce, maxPriorityFeePerGas: 100000n,
      maxFeePerGas: gasPrice * 3n, gasLimit: 21000n,
      to: USER_ADDR, value: returnAmt, data: "0x",
    });
    console.log(`   Return tx: ${retTx}`);
    console.log(`   https://optimistic.etherscan.io/tx/${retTx}`);
    await waitTx(retTx, "return ETH");
    console.log(`   Returned ${(Number(returnAmt)/1e18).toFixed(6)} ETH`);
  } else {
    console.log("   No ETH left to return (used for gas).");
  }

  console.log("\n=== Complete ===");
  console.log(`Bridged ~$0.50 ETH: Optimism → Base`);
  console.log(`Track: https://layerzeroscan.com/tx/${bridgeTx}`);
}

main().catch((e) => { console.error("\nError:", e.message); process.exit(1); });
