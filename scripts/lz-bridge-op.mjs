#!/usr/bin/env node
/**
 * LayerZero USDT Bridge: Optimism → Base
 * Then return remaining USDT to user on Optimism
 */

import { execSync } from "child_process";
import crypto from "crypto";

// ─── Config ─────────────────────────────────────────────────────────────────
const OP_RPC = "https://mainnet.optimism.io";
const OP_CHAIN_ID = 10;
const USDT_OP = "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58";
const USDT_DECIMALS = 6;
const BRIDGE_AMOUNT = 1_000_000n; // 1 USDT
const USER_ADDR = "0xe9bfadd8b7e2a5afb37c6de52fd590da779eba50";
const WALLET_ADDR = "0x7aff3a7a62d30f6f04c2b2220703baeab3bbe633";
const LZ_API = "https://metadata.layerzero-api.com/v1/metadata/experiment/ofts";

// ─── RPC Helper ─────────────────────────────────────────────────────────────

async function rpc(method, params = []) {
  const res = await fetch(OP_RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
  return json.result;
}

// ─── RLP Encoding ───────────────────────────────────────────────────────────

function rlpEncode(items) {
  if (Buffer.isBuffer(items)) {
    if (items.length === 0) return Buffer.from([0x80]);
    if (items.length === 1 && items[0] < 0x80) return items;
    if (items.length <= 55) return Buffer.concat([Buffer.from([0x80 + items.length]), items]);
    const lenBytes = intToBytes(items.length);
    return Buffer.concat([Buffer.from([0xb7 + lenBytes.length]), lenBytes, items]);
  }
  if (Array.isArray(items)) {
    const encoded = Buffer.concat(items.map(rlpEncode));
    if (encoded.length <= 55) return Buffer.concat([Buffer.from([0xc0 + encoded.length]), encoded]);
    const lenBytes = intToBytes(encoded.length);
    return Buffer.concat([Buffer.from([0xf7 + lenBytes.length]), lenBytes, encoded]);
  }
  throw new Error("RLP: unsupported type");
}

function intToBytes(n) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function bigintToBuf(n) {
  if (n === 0n) return Buffer.alloc(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function hexToBuf(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (!hex.length) return Buffer.alloc(0);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function keccak256(data) {
  return crypto.createHash("sha3-256").update(data).digest();
}

// ─── Sign & Send EIP-1559 tx ────────────────────────────────────────────────

async function signAndSend(privKey, tx) {
  const fields = [
    bigintToBuf(BigInt(tx.chainId)),
    bigintToBuf(BigInt(tx.nonce)),
    bigintToBuf(BigInt(tx.maxPriorityFeePerGas)),
    bigintToBuf(BigInt(tx.maxFeePerGas)),
    bigintToBuf(BigInt(tx.gasLimit)),
    hexToBuf(tx.to),
    bigintToBuf(BigInt(tx.value || 0)),
    hexToBuf(tx.data || "0x"),
    [], // access list
  ];

  const unsigned = Buffer.concat([Buffer.from([0x02]), rlpEncode(fields)]);
  const msgHash = keccak256(unsigned);

  const derPrefix = Buffer.from("302e0201010420", "hex");
  const derSuffix = Buffer.from("a00706052b8104000a", "hex");
  const derKey = Buffer.concat([derPrefix, privKey, derSuffix]);

  const sig = crypto.sign(null, msgHash, {
    key: crypto.createPrivateKey({ key: derKey, format: "der", type: "sec1" }),
    dsaEncoding: "ieee-p1363",
  });

  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);

  // Try v=0 first, then v=1
  for (const v of [0n, 1n]) {
    const signed = Buffer.concat([
      Buffer.from([0x02]),
      rlpEncode([...fields, bigintToBuf(v), r, s]),
    ]);
    try {
      return await rpc("eth_sendRawTransaction", ["0x" + signed.toString("hex")]);
    } catch (e) {
      if (v === 1n) throw e;
    }
  }
}

async function waitForTx(txHash, label) {
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const receipt = await rpc("eth_getTransactionReceipt", [txHash]);
    if (receipt) {
      if (receipt.status === "0x1") {
        console.log(`   ${label} confirmed! Gas used: ${parseInt(receipt.gasUsed, 16)}`);
        return receipt;
      }
      throw new Error(`${label} reverted!`);
    }
  }
  throw new Error(`${label} timed out`);
}

// ─── Reconstruct wallet from the same seed ──────────────────────────────────
// We need the private key — pass it via env var

function getPrivateKey() {
  const pk = process.env.WALLET_PK;
  if (!pk) {
    console.error("Set WALLET_PK env var with the wallet private key (hex, no 0x prefix)");
    process.exit(1);
  }
  return Buffer.from(pk.replace(/^0x/, ""), "hex");
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== LayerZero USDT Bridge: Optimism → Base ===\n");

  const privKey = getPrivateKey();

  // 1. Get API key
  console.log("1. Fetching LayerZero API key from GCP...");
  const apiKey = execSync(
    "gcloud secrets versions access latest --secret=rivier-layerzero-api-key --project=rivier-ai",
    { encoding: "utf-8" }
  ).trim();
  console.log("   Got API key.\n");

  // 2. Check balances
  console.log("2. Checking balances on Optimism...");
  const ethBal = await rpc("eth_getBalance", [WALLET_ADDR, "latest"]);
  const ethAmt = Number(BigInt(ethBal)) / 1e18;
  console.log(`   ETH:  ${ethAmt.toFixed(6)}`);

  const balData = "0x70a08231" + WALLET_ADDR.slice(2).padStart(64, "0");
  const usdtBal = await rpc("eth_call", [{ to: USDT_OP, data: balData }, "latest"]);
  const usdtAmt = Number(BigInt(usdtBal)) / 1e6;
  console.log(`   USDT: ${usdtAmt.toFixed(2)}\n`);

  // 3. Call LayerZero Value Transfer API
  console.log("3. Getting transfer calldata from LayerZero API...");

  const params = new URLSearchParams({
    srcChainName: "optimism",
    dstChainName: "base",
    tokenSymbol: "USDT",
    amount: BRIDGE_AMOUNT.toString(),
    senderAddress: WALLET_ADDR,
    recipientAddress: WALLET_ADDR,
  });

  const lzRes = await fetch(`${LZ_API}/transfer?${params}`, {
    headers: { "x-layerzero-api-key": apiKey },
  });

  if (!lzRes.ok) {
    const errText = await lzRes.text();
    console.error(`   LayerZero API error (${lzRes.status}): ${errText}`);
    console.log("\n   Trying with USDC instead of USDT...");

    // Try USDC
    params.set("tokenSymbol", "USDC");
    const lzRes2 = await fetch(`${LZ_API}/transfer?${params}`, {
      headers: { "x-layerzero-api-key": apiKey },
    });
    if (!lzRes2.ok) {
      const errText2 = await lzRes2.text();
      console.error(`   Also failed with USDC (${lzRes2.status}): ${errText2}`);
      console.log("\n   Listing available OFTs...");
      const listRes = await fetch(`${LZ_API}/list`);
      if (listRes.ok) {
        const tokens = await listRes.json();
        const keys = Object.keys(tokens).slice(0, 10);
        console.log(`   First 10 OFTs: ${JSON.stringify(keys, null, 2)}`);
      }
      process.exit(1);
    }
    var lzData = await lzRes2.json();
  } else {
    var lzData = await lzRes.json();
  }

  console.log(`   Transfer data received.`);
  console.log(`   Contract: ${lzData.populatedTransaction?.to || "unknown"}`);
  console.log(`   Value:    ${lzData.populatedTransaction?.value || "0"} wei\n`);

  // 4. Approve if needed
  const gasPrice = await rpc("eth_gasPrice", []);
  const baseFee = BigInt(gasPrice);
  let nonce = parseInt(await rpc("eth_getTransactionCount", [WALLET_ADDR, "latest"]), 16);

  if (lzData.approval) {
    console.log("4. Approving token spend...");
    const approveTxHash = await signAndSend(privKey, {
      chainId: OP_CHAIN_ID,
      nonce,
      maxPriorityFeePerGas: 100000n,
      maxFeePerGas: baseFee * 3n,
      gasLimit: 100000n,
      to: lzData.approval.to,
      value: 0n,
      data: lzData.approval.data,
    });
    console.log(`   Approve tx: ${approveTxHash}`);
    await waitForTx(approveTxHash, "Approval");
    nonce++;
    console.log();
  } else {
    console.log("4. No approval needed.\n");
  }

  // 5. Submit bridge tx
  console.log("5. Submitting bridge transaction...");
  const bridgeTxHash = await signAndSend(privKey, {
    chainId: OP_CHAIN_ID,
    nonce,
    maxPriorityFeePerGas: 100000n,
    maxFeePerGas: baseFee * 3n,
    gasLimit: BigInt(lzData.populatedTransaction.gasLimit || 300000),
    to: lzData.populatedTransaction.to,
    value: BigInt(lzData.populatedTransaction.value || 0),
    data: lzData.populatedTransaction.data,
  });
  console.log(`   Bridge tx:  ${bridgeTxHash}`);
  console.log(`   OptimScan:  https://optimistic.etherscan.io/tx/${bridgeTxHash}`);
  console.log(`   LZ Scan:    https://scan.layerzero-api.com/v1/messages/tx/${bridgeTxHash}`);
  await waitForTx(bridgeTxHash, "Bridge");
  nonce++;
  console.log();

  // 6. Send remaining USDT back to user
  console.log("6. Sending remaining USDT back to you...");
  const newBal = await rpc("eth_call", [{ to: USDT_OP, data: balData }, "latest"]);
  const remaining = BigInt(newBal);
  const remainingHuman = Number(remaining) / 1e6;
  console.log(`   Remaining USDT: ${remainingHuman.toFixed(2)}`);

  if (remaining > 0n) {
    // transfer(address,uint256)
    const transferData = "0xa9059cbb"
      + USER_ADDR.slice(2).padStart(64, "0")
      + remaining.toString(16).padStart(64, "0");

    const returnTxHash = await signAndSend(privKey, {
      chainId: OP_CHAIN_ID,
      nonce,
      maxPriorityFeePerGas: 100000n,
      maxFeePerGas: baseFee * 3n,
      gasLimit: 100000n,
      to: USDT_OP,
      value: 0n,
      data: transferData,
    });
    console.log(`   Return tx:  ${returnTxHash}`);
    console.log(`   OptimScan:  https://optimistic.etherscan.io/tx/${returnTxHash}`);
    await waitForTx(returnTxHash, "Return USDT");
  }

  console.log("\n=== Done ===");
  console.log(`Bridged 1 USDT: Optimism → Base`);
  console.log(`Returned ${remainingHuman.toFixed(2)} USDT to ${USER_ADDR}`);
  console.log(`Track bridge: https://scan.layerzero-api.com/v1/messages/tx/${bridgeTxHash}`);
}

main().catch((e) => {
  console.error("\nError:", e.message);
  process.exit(1);
});
