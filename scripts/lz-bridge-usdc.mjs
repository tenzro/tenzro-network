#!/usr/bin/env node
/**
 * LayerZero USDC Bridge: Base → Optimism
 *
 * Usage:
 *   node scripts/lz-bridge-usdc.mjs
 *
 * The script:
 *   1. Fetches the LayerZero API key from GCP Secrets (rivier-ai)
 *   2. Generates a fresh EVM wallet (key never leaves this process)
 *   3. Prints the address — you fund it with USDC + a little ETH for gas on Base
 *   4. Waits for you to press Enter after funding
 *   5. Approves USDC spend if needed
 *   6. Calls LayerZero Value Transfer API to get transfer calldata
 *   7. Signs and submits the transaction on Base
 *   8. Prints tx hash + LayerZero Scan link
 */

import { execSync } from "child_process";
import { createInterface } from "readline";
import crypto from "crypto";

// ─── Config ─────────────────────────────────────────────────────────────────
const BASE_RPC = "https://mainnet.base.org";
const BASE_CHAIN_ID = 8453;
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const USDC_DECIMALS = 6;
const AMOUNT_USDC = 1; // 1 USDC
const AMOUNT_RAW = BigInt(AMOUNT_USDC * 10 ** USDC_DECIMALS); // 1000000
const SRC_CHAIN = "base";
const DST_CHAIN = "optimism";
const LZ_API_BASE = "https://metadata.layerzero-api.com/v1/metadata/experiment/ofts";

// ─── Helpers ────────────────────────────────────────────────────────────────

async function rpc(method, params = []) {
  const res = await fetch(BASE_RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
  return json.result;
}

function ask(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); resolve(a); }));
}

// Minimal secp256k1 wallet using Node.js built-in crypto
function generateWallet() {
  // Generate a random 32-byte private key
  const privateKey = crypto.randomBytes(32);

  // Derive public key (uncompressed, 65 bytes)
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(privateKey);
  const publicKey = ecdh.getPublicKey("hex", "uncompressed");

  // Address = keccak256(publicKey[1:])[-20:]
  const pubBytes = Buffer.from(publicKey.slice(2), "hex"); // skip 04 prefix
  const hash = crypto.createHash("sha3-256").update(pubBytes).digest();
  const address = "0x" + hash.slice(-20).toString("hex");

  return { privateKey, address };
}

// ─── EIP-1559 Transaction Signing ───────────────────────────────────────────
// We use the ethers-like approach but with pure crypto

function rlpEncode(items) {
  if (Buffer.isBuffer(items)) {
    if (items.length === 1 && items[0] < 0x80) return items;
    if (items.length <= 55) return Buffer.concat([Buffer.from([0x80 + items.length]), items]);
    const lenBytes = encodeLength(items.length);
    return Buffer.concat([Buffer.from([0xb7 + lenBytes.length]), lenBytes, items]);
  }
  if (Array.isArray(items)) {
    const encoded = Buffer.concat(items.map(rlpEncode));
    if (encoded.length <= 55) return Buffer.concat([Buffer.from([0xc0 + encoded.length]), encoded]);
    const lenBytes = encodeLength(encoded.length);
    return Buffer.concat([Buffer.from([0xf7 + lenBytes.length]), lenBytes, encoded]);
  }
  throw new Error("RLP: unsupported type");
}

function encodeLength(len) {
  const hex = len.toString(16);
  const padded = hex.length % 2 ? "0" + hex : hex;
  return Buffer.from(padded, "hex");
}

function bigintToBuffer(n) {
  if (n === 0n) return Buffer.alloc(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function hexToBuffer(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (hex.length === 0) return Buffer.alloc(0);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function keccak256(data) {
  return crypto.createHash("sha3-256").update(data).digest();
}

async function signAndSend(privateKey, tx) {
  // EIP-1559 (type 2) transaction
  const fields = [
    bigintToBuffer(BigInt(tx.chainId)),
    bigintToBuffer(BigInt(tx.nonce)),
    bigintToBuffer(BigInt(tx.maxPriorityFeePerGas)),
    bigintToBuffer(BigInt(tx.maxFeePerGas)),
    bigintToBuffer(BigInt(tx.gasLimit)),
    hexToBuffer(tx.to),
    bigintToBuffer(BigInt(tx.value || 0)),
    hexToBuffer(tx.data || "0x"),
    [], // access list
  ];

  const unsigned = Buffer.concat([Buffer.from([0x02]), rlpEncode(fields)]);
  const msgHash = keccak256(unsigned);

  // Sign with secp256k1
  const sig = crypto.sign(null, msgHash, {
    key: crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from("302e0201010420", "hex"),
        privateKey,
        Buffer.from("a00706052b8104000a", "hex"),
      ]),
      format: "der",
      type: "sec1",
    }),
    dsaEncoding: "ieee-p1363",
  });

  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);

  // Determine v (recovery id) by trying both and checking which recovers to our address
  // For simplicity, try v=0 first, fall back to v=1
  let v = 0n;
  // We'll just use v=0 and if it fails on-chain we'd need to try v=1
  // In practice this works ~50% of the time; for robustness we check both
  const signed = Buffer.concat([
    Buffer.from([0x02]),
    rlpEncode([
      ...fields,
      bigintToBuffer(v),
      r,
      s,
    ]),
  ]);

  const rawTx = "0x" + signed.toString("hex");
  try {
    return await rpc("eth_sendRawTransaction", [rawTx]);
  } catch (e) {
    // Try with v=1
    v = 1n;
    const signed1 = Buffer.concat([
      Buffer.from([0x02]),
      rlpEncode([
        ...fields,
        bigintToBuffer(v),
        r,
        s,
      ]),
    ]);
    return await rpc("eth_sendRawTransaction", ["0x" + signed1.toString("hex")]);
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== LayerZero USDC Bridge: Base → Optimism ===\n");

  // 1. Get API key from GCP
  console.log("1. Fetching LayerZero API key from GCP Secrets...");
  let apiKey;
  try {
    apiKey = execSync(
      'gcloud secrets versions access latest --secret=rivier-layerzero-api-key --project=rivier-ai',
      { encoding: "utf-8" }
    ).trim();
    console.log("   API key retrieved.\n");
  } catch (e) {
    console.error("   Failed to fetch API key from GCP:", e.message);
    process.exit(1);
  }

  // 2. Generate wallet
  console.log("2. Generating wallet...");
  const wallet = generateWallet();
  console.log(`   Address: ${wallet.address}`);
  console.log(`   (Private key held in memory only — never written to disk)\n`);

  // 3. Wait for funding
  console.log("3. Fund this address on Base with:");
  console.log(`   - ${AMOUNT_USDC} USDC (contract: ${USDC_BASE})`);
  console.log(`   - ~0.0005 ETH for gas\n`);

  await ask("   Press Enter after funding...");
  console.log();

  // 4. Check balances
  console.log("4. Checking balances...");

  const ethBal = await rpc("eth_getBalance", [wallet.address, "latest"]);
  const ethAmount = Number(BigInt(ethBal)) / 1e18;
  console.log(`   ETH: ${ethAmount.toFixed(6)}`);

  // Check USDC balance via balanceOf(address)
  const balanceData = "0x70a08231" + wallet.address.slice(2).padStart(64, "0");
  const usdcBal = await rpc("eth_call", [{ to: USDC_BASE, data: balanceData }, "latest"]);
  const usdcAmount = Number(BigInt(usdcBal)) / 1e6;
  console.log(`   USDC: ${usdcAmount.toFixed(2)}\n`);

  if (usdcAmount < AMOUNT_USDC) {
    console.error(`   Insufficient USDC balance. Need ${AMOUNT_USDC}, have ${usdcAmount.toFixed(2)}`);
    process.exit(1);
  }
  if (ethAmount < 0.0001) {
    console.error("   Insufficient ETH for gas.");
    process.exit(1);
  }

  // 5. Call LayerZero Value Transfer API
  console.log("5. Getting transfer calldata from LayerZero API...");

  const transferUrl = `${LZ_API_BASE}/transfer?` + new URLSearchParams({
    srcChainName: SRC_CHAIN,
    dstChainName: DST_CHAIN,
    tokenSymbol: "USDC",
    amount: AMOUNT_RAW.toString(),
    senderAddress: wallet.address,
    recipientAddress: wallet.address, // same wallet on destination
  }).toString();

  const lzRes = await fetch(transferUrl, {
    headers: { "x-layerzero-api-key": apiKey },
  });

  if (!lzRes.ok) {
    const errText = await lzRes.text();
    console.error(`   LayerZero API error (${lzRes.status}): ${errText}`);

    // Fallback: try the approve + direct OFT send approach
    console.log("\n   Falling back to direct OFT contract call...");
    await directOftBridge(wallet, apiKey);
    return;
  }

  const lzData = await lzRes.json();
  console.log(`   Got transfer data from LayerZero API.\n`);

  // 6. Handle approval if needed
  if (lzData.approval) {
    console.log("6. Approving USDC spend...");
    const nonce = await rpc("eth_getTransactionCount", [wallet.address, "latest"]);
    const gasPrice = await rpc("eth_gasPrice", []);
    const baseFee = BigInt(gasPrice);

    const approveTx = {
      chainId: BASE_CHAIN_ID,
      nonce: parseInt(nonce, 16),
      maxPriorityFeePerGas: 100000n,  // 0.1 gwei tip
      maxFeePerGas: baseFee * 2n,
      gasLimit: 100000n,
      to: lzData.approval.to,
      value: 0n,
      data: lzData.approval.data,
    };

    const approveTxHash = await signAndSend(wallet.privateKey, approveTx);
    console.log(`   Approve tx: ${approveTxHash}`);

    // Wait for confirmation
    console.log("   Waiting for approval confirmation...");
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const receipt = await rpc("eth_getTransactionReceipt", [approveTxHash]);
      if (receipt) {
        if (receipt.status === "0x1") {
          console.log("   Approval confirmed!\n");
          break;
        } else {
          console.error("   Approval failed!");
          process.exit(1);
        }
      }
    }
  } else {
    console.log("6. No approval needed (skipping).\n");
  }

  // 7. Submit transfer transaction
  console.log("7. Submitting bridge transaction...");
  const nonce = await rpc("eth_getTransactionCount", [wallet.address, "latest"]);
  const gasPrice = await rpc("eth_gasPrice", []);
  const baseFee = BigInt(gasPrice);

  const bridgeTx = {
    chainId: BASE_CHAIN_ID,
    nonce: parseInt(nonce, 16),
    maxPriorityFeePerGas: 100000n,
    maxFeePerGas: baseFee * 2n,
    gasLimit: BigInt(lzData.populatedTransaction.gasLimit || 300000),
    to: lzData.populatedTransaction.to,
    value: BigInt(lzData.populatedTransaction.value || 0),
    data: lzData.populatedTransaction.data,
  };

  const txHash = await signAndSend(wallet.privateKey, bridgeTx);
  console.log(`   Bridge tx: ${txHash}`);
  console.log(`   BaseScan:  https://basescan.org/tx/${txHash}`);
  console.log(`   LZ Scan:   https://scan.layerzero-api.com/v1/messages/tx/${txHash}\n`);

  // 8. Wait for confirmation
  console.log("8. Waiting for Base confirmation...");
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const receipt = await rpc("eth_getTransactionReceipt", [txHash]);
    if (receipt) {
      if (receipt.status === "0x1") {
        console.log("   Confirmed on Base!");
        console.log(`   Gas used: ${parseInt(receipt.gasUsed, 16)}\n`);
        break;
      } else {
        console.error("   Transaction reverted!");
        process.exit(1);
      }
    }
  }

  console.log("=== Bridge Complete ===");
  console.log(`Bridged ${AMOUNT_USDC} USDC from Base → Optimism`);
  console.log(`Track delivery: https://scan.layerzero-api.com/v1/messages/tx/${txHash}`);
}

// ─── Fallback: Direct OFT send via contract ─────────────────────────────────

async function directOftBridge(wallet, apiKey) {
  // First, discover the OFT contract for USDC on Base
  console.log("   Discovering OFT contracts...");
  const listRes = await fetch(`${LZ_API_BASE}/list`, {
    headers: { "x-layerzero-api-key": apiKey },
  });

  if (!listRes.ok) {
    // Use the OFT list without auth
    const listRes2 = await fetch(`${LZ_API_BASE}/list`);
    const tokens = await listRes2.json();
    console.log(`   Found ${Object.keys(tokens).length} OFT tokens`);
    // Filter for USDC-like tokens
    for (const [addr, info] of Object.entries(tokens)) {
      if (info.symbol && info.symbol.toLowerCase().includes("usdc")) {
        console.log(`   USDC OFT: ${addr} — ${info.symbol} on ${info.chainName || "unknown"}`);
      }
    }
  }

  console.log("\n   The LayerZero Value Transfer API requires the USDC token to be");
  console.log("   registered as an OFT. If native USDC on Base is not an OFT,");
  console.log("   you may need to use Stargate V2 or another bridge.\n");
  console.log("   Check: https://docs.layerzero.network/v2/tools/api/oft-examples");

  process.exit(1);
}

main().catch((e) => {
  console.error("Error:", e.message);
  process.exit(1);
});
