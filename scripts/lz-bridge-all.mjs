#!/usr/bin/env node
/**
 * LayerZero Bridge: Optimism → Base (1 USDT) + return remainder
 *
 * All-in-one: generates wallet, waits for funding, bridges, returns change.
 * Private key never leaves this process.
 */

import { execSync } from "child_process";
import { createInterface } from "readline";
import crypto from "crypto";

// ─── Config ─────────────────────────────────────────────────────────────────
const OP_RPC = "https://mainnet.optimism.io";
const OP_CHAIN_ID = 10;
const USDT_OP = "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58";
const BRIDGE_AMOUNT = 1_000_000n; // 1 USDT (6 decimals)
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

async function getUsdtBalance(addr) {
  const data = "0x70a08231" + addr.slice(2).padStart(64, "0");
  const r = await rpc("eth_call", [{ to: USDT_OP, data }, "latest"]);
  return BigInt(r);
}

// ─── Wallet Generation ─────────────────────────────────────────────────────

function generateWallet() {
  const privateKey = crypto.randomBytes(32);
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(privateKey);
  const pub = ecdh.getPublicKey("hex", "uncompressed");
  const pubBytes = Buffer.from(pub.slice(2), "hex");
  const hash = crypto.createHash("sha3-256").update(pubBytes).digest();
  const address = "0x" + hash.slice(-20).toString("hex");
  return { privateKey, address };
}

// ─── RLP + EIP-1559 Signing ─────────────────────────────────────────────────

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
  throw new Error("RLP: bad type");
}

function intToBytes(n) {
  let h = n.toString(16);
  if (h.length % 2) h = "0" + h;
  return Buffer.from(h, "hex");
}

function b2b(n) {
  if (n === 0n) return Buffer.alloc(0);
  let h = n.toString(16);
  if (h.length % 2) h = "0" + h;
  return Buffer.from(h, "hex");
}

function h2b(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (!hex.length) return Buffer.alloc(0);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function keccak256(data) {
  return crypto.createHash("sha3-256").update(data).digest();
}

async function signAndSend(privKey, tx) {
  const fields = [
    b2b(BigInt(tx.chainId)),
    b2b(BigInt(tx.nonce)),
    b2b(BigInt(tx.maxPriorityFeePerGas)),
    b2b(BigInt(tx.maxFeePerGas)),
    b2b(BigInt(tx.gasLimit)),
    h2b(tx.to),
    b2b(BigInt(tx.value || 0)),
    h2b(tx.data || "0x"),
    [],
  ];
  const unsigned = Buffer.concat([Buffer.from([0x02]), rlpEncode(fields)]);
  const msgHash = keccak256(unsigned);

  const derKey = Buffer.concat([
    Buffer.from("302e0201010420", "hex"),
    privKey,
    Buffer.from("a00706052b8104000a", "hex"),
  ]);
  const sig = crypto.sign(null, msgHash, {
    key: crypto.createPrivateKey({ key: derKey, format: "der", type: "sec1" }),
    dsaEncoding: "ieee-p1363",
  });

  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);

  for (const v of [0n, 1n]) {
    const signed = Buffer.concat([
      Buffer.from([0x02]),
      rlpEncode([...fields, b2b(v), r, s]),
    ]);
    try {
      return await rpc("eth_sendRawTransaction", ["0x" + signed.toString("hex")]);
    } catch (e) {
      if (v === 1n) throw e;
    }
  }
}

async function waitTx(hash, label) {
  process.stdout.write(`   Waiting for ${label}...`);
  for (let i = 0; i < 90; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    if (receipt) {
      if (receipt.status === "0x1") {
        console.log(` confirmed! (gas: ${parseInt(receipt.gasUsed, 16)})`);
        return receipt;
      }
      throw new Error(`${label} reverted!`);
    }
    process.stdout.write(".");
  }
  throw new Error(`${label} timeout`);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== LayerZero USDT Bridge: Optimism → Base ===\n");

  // 1. Get API key
  console.log("1. Fetching LayerZero API key...");
  const apiKey = execSync(
    "gcloud secrets versions access latest --secret=rivier-layerzero-api-key --project=rivier-ai",
    { encoding: "utf-8" }
  ).trim();
  console.log("   Done.\n");

  // 2. Generate wallet
  console.log("2. Generating wallet...");
  const wallet = generateWallet();
  console.log(`   Address: ${wallet.address}`);
  console.log(`   (Key in memory only)\n`);

  // 3. Wait for funding
  console.log("3. Send to this address on OPTIMISM:");
  console.log(`   - 10 USDT`);
  console.log(`   - ~0.0005 ETH for gas\n`);
  await ask("   Press Enter after funding... ");
  console.log();

  // 4. Verify funding
  console.log("4. Checking balances...");
  const ethBal = Number(BigInt(await rpc("eth_getBalance", [wallet.address, "latest"]))) / 1e18;
  const usdtBal = Number(await getUsdtBalance(wallet.address)) / 1e6;
  console.log(`   ETH:  ${ethBal.toFixed(6)}`);
  console.log(`   USDT: ${usdtBal.toFixed(2)}\n`);

  if (usdtBal < 1) { console.error("   Not enough USDT!"); process.exit(1); }
  if (ethBal < 0.0001) { console.error("   Not enough ETH for gas!"); process.exit(1); }

  // 5. Call LayerZero API
  console.log("5. Calling LayerZero Value Transfer API...");
  const params = new URLSearchParams({
    srcChainName: "optimism",
    dstChainName: "base",
    tokenSymbol: "USDT",
    amount: BRIDGE_AMOUNT.toString(),
    senderAddress: wallet.address,
    recipientAddress: wallet.address,
  });

  let lzData;
  const lzRes = await fetch(`${LZ_API}/transfer?${params}`, {
    headers: { "x-layerzero-api-key": apiKey },
  });

  if (!lzRes.ok) {
    const errText = await lzRes.text();
    console.log(`   USDT transfer failed (${lzRes.status}): ${errText}`);

    // Try listing available tokens
    console.log("   Listing available OFT tokens...");
    const listRes = await fetch(`${LZ_API}/list`);
    if (listRes.ok) {
      const tokens = await listRes.json();
      console.log(`   Found ${Object.keys(tokens).length} tokens.`);
      // Look for anything USDT/USDC related
      for (const [addr, info] of Object.entries(tokens)) {
        const sym = (info.symbol || "").toLowerCase();
        if (sym.includes("usd") || sym.includes("tether")) {
          console.log(`   ${info.symbol}: ${addr} (${info.chainName || "?"})`);
        }
      }
    }

    // Also try just sending USDT directly as a simple transfer back
    // and skip the bridge if LZ doesn't support this token pair
    console.log("\n   LayerZero OFT API may not support USDT on this route.");
    console.log("   Returning all USDT to your wallet instead.\n");

    await returnAll(wallet);
    return;
  }

  lzData = await lzRes.json();
  console.log(`   Contract: ${lzData.populatedTransaction?.to}`);
  console.log(`   Gas limit: ${lzData.populatedTransaction?.gasLimit}\n`);

  // 6. Approve if needed
  const gasPrice = BigInt(await rpc("eth_gasPrice", []));
  let nonce = parseInt(await rpc("eth_getTransactionCount", [wallet.address, "latest"]), 16);

  if (lzData.approval) {
    console.log("6. Approving token spend...");
    const appTx = await signAndSend(wallet.privateKey, {
      chainId: OP_CHAIN_ID,
      nonce,
      maxPriorityFeePerGas: 100000n,
      maxFeePerGas: gasPrice * 3n,
      gasLimit: 100000n,
      to: lzData.approval.to,
      value: 0n,
      data: lzData.approval.data,
    });
    console.log(`   Tx: ${appTx}`);
    await waitTx(appTx, "approval");
    nonce++;
    console.log();
  } else {
    console.log("6. No approval needed.\n");
  }

  // 7. Bridge tx
  console.log("7. Submitting bridge transaction...");
  const bridgeTx = await signAndSend(wallet.privateKey, {
    chainId: OP_CHAIN_ID,
    nonce,
    maxPriorityFeePerGas: 100000n,
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

  // 8. Return remaining USDT
  await returnRemaining(wallet, nonce, gasPrice);

  console.log("\n=== Complete ===");
  console.log(`Bridge tx: ${bridgeTx}`);
  console.log(`Track: https://layerzeroscan.com/tx/${bridgeTx}`);
}

async function returnRemaining(wallet, nonce, gasPrice) {
  console.log("8. Returning remaining USDT to you...");
  const remaining = await getUsdtBalance(wallet.address);
  const remainHuman = Number(remaining) / 1e6;
  console.log(`   Remaining: ${remainHuman.toFixed(2)} USDT`);

  if (remaining > 0n) {
    const transferData = "0xa9059cbb"
      + USER_ADDR.slice(2).padStart(64, "0")
      + remaining.toString(16).padStart(64, "0");

    const retTx = await signAndSend(wallet.privateKey, {
      chainId: OP_CHAIN_ID,
      nonce,
      maxPriorityFeePerGas: 100000n,
      maxFeePerGas: gasPrice * 3n,
      gasLimit: 100000n,
      to: USDT_OP,
      value: 0n,
      data: transferData,
    });
    console.log(`   Return tx: ${retTx}`);
    console.log(`   Etherscan: https://optimistic.etherscan.io/tx/${retTx}`);
    await waitTx(retTx, "return USDT");
  }
}

async function returnAll(wallet) {
  console.log("Returning all USDT to you...");
  const bal = await getUsdtBalance(wallet.address);
  const balHuman = Number(bal) / 1e6;
  console.log(`   Balance: ${balHuman.toFixed(2)} USDT`);

  if (bal > 0n) {
    const gasPrice = BigInt(await rpc("eth_gasPrice", []));
    const nonce = parseInt(await rpc("eth_getTransactionCount", [wallet.address, "latest"]), 16);

    const transferData = "0xa9059cbb"
      + USER_ADDR.slice(2).padStart(64, "0")
      + bal.toString(16).padStart(64, "0");

    const tx = await signAndSend(wallet.privateKey, {
      chainId: OP_CHAIN_ID,
      nonce,
      maxPriorityFeePerGas: 100000n,
      maxFeePerGas: gasPrice * 3n,
      gasLimit: 100000n,
      to: USDT_OP,
      value: 0n,
      data: transferData,
    });
    console.log(`   Return tx: ${tx}`);
    console.log(`   Etherscan: https://optimistic.etherscan.io/tx/${tx}`);
    await waitTx(tx, "return");
  }
}

main().catch((e) => {
  console.error("\nError:", e.message);
  process.exit(1);
});
