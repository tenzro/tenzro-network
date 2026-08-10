#!/usr/bin/env node
/**
 * Stargate V2 ETH Bridge: Optimism -> Base
 *
 * YOU run this from your terminal:
 *   node scripts/stargate-bridge.mjs
 *
 * Flow:
 *   1. Generates wallet + SAVES PRIVATE KEY to /tmp/stargate-wallet.key
 *   2. You send ~$2 worth of ETH on Optimism to the printed address
 *   3. Bridges 0.0003 ETH (~$0.50) to Base via Stargate V2
 *   4. Returns remaining ETH to your wallet
 *
 * If anything fails, your private key is saved at /tmp/stargate-wallet.key
 * so you can always recover funds with any Ethereum wallet (MetaMask, etc).
 */

import { createInterface } from "readline";
import crypto from "crypto";
import fs from "fs";

// ─── Config ─────────────────────────────────────────────────────────────────
const OP_RPC = "https://mainnet.optimism.io";
const OP_CHAIN_ID = 10;
const BRIDGE_ETH = 300000000000000n; // 0.0003 ETH (~$0.50)
const USER_ADDR = "0xe9bfadd8b7e2a5afb37c6de52fd590da779eba50";
const KEY_FILE = "/tmp/stargate-wallet.key";

// Stargate V2 StargatePoolNative on Optimism
const STARGATE_POOL = "0xe8CDF27AcD73a434D661C84887215F7598e7d0d3";
const BASE_EID = 30184; // LayerZero Endpoint ID for Base

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

// ─── ABI Encoding for Stargate V2 ──────────────────────────────────────────

function encodeQuoteSend(walletAddr, amountLD) {
  // quoteSend(SendParam, bool) -> (MessagingFee, OFTReceipt)
  // selector: 0x3b6f743b
  const selector = "3b6f743b";

  // SendParam is a tuple with dynamic bytes fields, so we need offset-based encoding
  // SendParam: (uint32 dstEid, bytes32 to, uint256 amountLD, uint256 minAmountLD, bytes extraOptions, bytes composeMsg, bytes oftCmd)
  const to32 = walletAddr.slice(2).padStart(64, "0");
  const amt = amountLD.toString(16).padStart(64, "0");
  const minAmt = (amountLD * 90n / 100n).toString(16).padStart(64, "0"); // 10% slippage

  // SendParam tuple starts at offset 0x40 (since first arg is the tuple, second is bool)
  // Actually, quoteSend((SendParam), bool) — the tuple is a struct passed by value
  // For ABI encoding: tuple offset at 0x40, then bool at 0x20
  // Wait — ABI encodes struct as inline tuple when it's the first arg
  // Let me encode properly:

  // quoteSend(tuple sendParam, bool payInLzToken)
  // sendParam is dynamic (contains bytes), so it's referenced by offset
  // Layout:
  // [0x00] offset to sendParam tuple (0x40)
  // [0x20] payInLzToken = false (0)
  // [0x40] start of sendParam tuple:
  //   [0x40] dstEid (uint32)
  //   [0x60] to (bytes32)
  //   [0x80] amountLD (uint256)
  //   [0xa0] minAmountLD (uint256)
  //   [0xc0] offset to extraOptions (relative to tuple start, 0x40 = 7*32 = 0xe0)
  //   [0xe0] offset to composeMsg
  //   [0x100] offset to oftCmd
  //   [0x120] extraOptions: length=0
  //   [0x140] composeMsg: length=0
  //   [0x160] oftCmd: length=0

  const dstEid = BASE_EID.toString(16).padStart(64, "0");
  const z64 = "0".repeat(64);

  // Offsets for dynamic fields within the tuple (relative to tuple start)
  // 7 fields * 32 bytes = 224 = 0xe0
  const extraOptionsOffset = (7 * 32).toString(16).padStart(64, "0"); // 0xe0
  const composeMsgOffset = (7 * 32 + 32).toString(16).padStart(64, "0"); // 0x100
  const oftCmdOffset = (7 * 32 + 64).toString(16).padStart(64, "0"); // 0x120

  const data = selector
    + (64).toString(16).padStart(64, "0")  // offset to sendParam
    + z64                                   // payInLzToken = false
    // SendParam tuple:
    + dstEid                               // dstEid
    + to32                                  // to (bytes32)
    + amt                                   // amountLD
    + minAmt                                // minAmountLD
    + extraOptionsOffset                    // offset to extraOptions
    + composeMsgOffset                      // offset to composeMsg
    + oftCmdOffset                          // offset to oftCmd
    + z64                                   // extraOptions length = 0
    + z64                                   // composeMsg length = 0
    + z64;                                  // oftCmd length = 0

  return "0x" + data;
}

function encodeSendToken(walletAddr, amountLD, nativeFee) {
  // sendToken(SendParam, MessagingFee, address refundAddress)
  // selector: 0xcbef2aa9
  const selector = "cbef2aa9";

  const to32 = walletAddr.slice(2).padStart(64, "0");
  const amt = amountLD.toString(16).padStart(64, "0");
  const minAmt = (amountLD * 90n / 100n).toString(16).padStart(64, "0");
  const dstEid = BASE_EID.toString(16).padStart(64, "0");
  const z64 = "0".repeat(64);
  const fee = nativeFee.toString(16).padStart(64, "0");
  const refund = walletAddr.slice(2).padStart(64, "0");

  // sendToken((SendParam), (MessagingFee), address)
  // All three args: SendParam is dynamic, MessagingFee is static (2 uint256), address is static
  // Layout:
  // [0x00] offset to SendParam
  // [0x20] offset to MessagingFee  -- MessagingFee contains no dynamic types so could be inline
  // Actually, looking at the Stargate contract more carefully:
  // sendToken(SendParam _sendParam, MessagingFee _fee, address _refundAddress)
  // SendParam has dynamic bytes, so offset-encoded
  // MessagingFee is (uint256, uint256) — static, but since it's a tuple param it may still be offset-encoded
  // address is static

  // Let's use the standard ABI encoding:
  // Arg 1 (SendParam, dynamic): offset
  // Arg 2 (MessagingFee, static tuple): inline? or offset?
  // Per Solidity ABI: tuples that contain only static types are encoded inline
  // But... MessagingFee is a struct, which is encoded as a tuple
  // For function args, each dynamic type gets an offset, static types are inline
  // MessagingFee(uint256, uint256) is static → inline
  // But wait, SendParam is dynamic, so it gets an offset
  // Actually ABI encoding for multiple args:
  // head part: each arg is either its value (if static) or an offset (if dynamic)
  // SendParam → dynamic → offset (32 bytes)
  // MessagingFee → static tuple → inline (64 bytes: nativeFee + lzTokenFee)
  // address → static → inline (32 bytes)
  // Total head: 32 + 64 + 32 = 160 = 0xa0
  // Tail: SendParam data

  const headSize = 32 + 64 + 32; // 160 bytes = 0xa0
  const sendParamOffset = headSize.toString(16).padStart(64, "0");

  // Dynamic field offsets within SendParam (relative to SendParam start)
  const extraOptionsOffset = (7 * 32).toString(16).padStart(64, "0");
  const composeMsgOffset = (7 * 32 + 32).toString(16).padStart(64, "0");
  const oftCmdOffset = (7 * 32 + 64).toString(16).padStart(64, "0");

  const data = selector
    // Head:
    + sendParamOffset                       // offset to SendParam
    + fee                                   // MessagingFee.nativeFee
    + z64                                   // MessagingFee.lzTokenFee = 0
    + refund                                // refundAddress
    // Tail (SendParam):
    + dstEid                               // dstEid
    + to32                                  // to (bytes32)
    + amt                                   // amountLD
    + minAmt                                // minAmountLD
    + extraOptionsOffset                    // offset to extraOptions
    + composeMsgOffset                      // offset to composeMsg
    + oftCmdOffset                          // offset to oftCmd
    + z64                                   // extraOptions length = 0
    + z64                                   // composeMsg length = 0
    + z64;                                  // oftCmd length = 0

  return "0x" + data;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== Stargate V2 ETH Bridge: Optimism -> Base ===\n");

  // 1. Generate wallet and SAVE KEY
  console.log("1. Generating wallet...");
  const wallet = generateWallet();

  // Save private key IMMEDIATELY
  const keyHex = wallet.privateKey.toString("hex");
  fs.writeFileSync(KEY_FILE, keyHex, { mode: 0o600 });
  console.log(`   Address:     ${wallet.address}`);
  console.log(`   Private key: SAVED to ${KEY_FILE}`);
  console.log(`   (Import this key into MetaMask if anything goes wrong)\n`);

  // 2. Wait for funding
  console.log("2. Send ~$2 worth of ETH to this address on OPTIMISM:");
  console.log(`   ${wallet.address}\n`);
  await ask("   Press Enter after funding... ");
  console.log();

  // 3. Check balance
  console.log("3. Checking balance...");
  const ethBal = BigInt(await rpc("eth_getBalance", [wallet.address, "latest"]));
  const ethHuman = Number(ethBal) / 1e18;
  console.log(`   ETH: ${ethHuman.toFixed(6)}\n`);
  if (ethBal < BRIDGE_ETH + 200000000000000n) {
    console.error("   Not enough ETH! Need at least 0.0005 ETH (0.0003 to bridge + gas).");
    process.exit(1);
  }

  // 4. Quote the bridge fee via Stargate quoteSend
  console.log("4. Quoting bridge fee from Stargate V2...");
  const quoteData = encodeQuoteSend(wallet.address, BRIDGE_ETH);
  const quoteResult = await rpc("eth_call", [{
    to: STARGATE_POOL,
    data: quoteData,
  }, "latest"]);

  // Decode MessagingFee from the result
  // quoteSend returns (MessagingFee, OFTReceipt)
  // MessagingFee = (uint256 nativeFee, uint256 lzTokenFee)
  // First 64 bytes = nativeFee
  const nativeFee = BigInt("0x" + quoteResult.slice(2, 66));
  const lzTokenFee = BigInt("0x" + quoteResult.slice(66, 130));
  console.log(`   Native fee:  ${(Number(nativeFee) / 1e18).toFixed(8)} ETH`);
  console.log(`   LZ token fee: ${lzTokenFee}`);

  // Total msg.value = bridge amount + native fee
  const totalValue = BRIDGE_ETH + nativeFee;
  console.log(`   Total value: ${(Number(totalValue) / 1e18).toFixed(8)} ETH`);
  console.log(`   Bridge amt:  ${(Number(BRIDGE_ETH) / 1e18).toFixed(6)} ETH\n`);

  if (ethBal < totalValue + 500000000000000n) {
    console.error(`   Not enough ETH! Need ${(Number(totalValue + 500000000000000n) / 1e18).toFixed(6)} ETH total.`);
    process.exit(1);
  }

  // 5. Submit bridge transaction
  console.log("5. Submitting bridge transaction...");
  const gasPrice = BigInt(await rpc("eth_gasPrice", []));
  const nonce = parseInt(await rpc("eth_getTransactionCount", [wallet.address, "latest"]), 16);

  const sendData = encodeSendToken(wallet.address, BRIDGE_ETH, nativeFee);

  // Estimate gas
  let gasLimit = 300000n;
  try {
    const gasEst = await rpc("eth_estimateGas", [{
      from: wallet.address,
      to: STARGATE_POOL,
      value: "0x" + totalValue.toString(16),
      data: sendData,
    }]);
    gasLimit = BigInt(gasEst) * 130n / 100n; // 30% buffer
    console.log(`   Estimated gas: ${gasLimit}`);
  } catch (e) {
    console.log(`   Gas estimation failed (${e.message}), using default 300000`);
  }

  const bridgeTx = await signAndSend(wallet.privateKey, {
    chainId: OP_CHAIN_ID,
    nonce,
    maxPriorityFeePerGas: 100000n,
    maxFeePerGas: gasPrice * 3n,
    gasLimit,
    to: STARGATE_POOL,
    value: totalValue,
    data: sendData,
  });
  console.log(`   Bridge tx: ${bridgeTx}`);
  console.log(`   Etherscan: https://optimistic.etherscan.io/tx/${bridgeTx}`);
  console.log(`   LZ Scan:   https://layerzeroscan.com/tx/${bridgeTx}`);
  await waitTx(bridgeTx, "bridge");
  console.log();

  // 6. Return remaining ETH
  console.log("6. Returning remaining ETH to you...");
  const newBal = BigInt(await rpc("eth_getBalance", [wallet.address, "latest"]));
  const gasCost = 21000n * gasPrice * 3n;
  const returnAmt = newBal - gasCost;
  if (returnAmt > 0n) {
    const retTx = await signAndSend(wallet.privateKey, {
      chainId: OP_CHAIN_ID,
      nonce: nonce + 1,
      maxPriorityFeePerGas: 100000n,
      maxFeePerGas: gasPrice * 3n,
      gasLimit: 21000n,
      to: USER_ADDR,
      value: returnAmt,
      data: "0x",
    });
    console.log(`   Return tx: ${retTx}`);
    console.log(`   https://optimistic.etherscan.io/tx/${retTx}`);
    await waitTx(retTx, "return ETH");
    console.log(`   Returned ${(Number(returnAmt) / 1e18).toFixed(6)} ETH`);
  } else {
    console.log("   No ETH left to return (all used for gas + bridge).");
  }

  console.log("\n=== Complete ===");
  console.log(`Bridged ~$0.50 ETH: Optimism -> Base`);
  console.log(`Track: https://layerzeroscan.com/tx/${bridgeTx}`);
  console.log(`\nYou can delete the key file: rm ${KEY_FILE}`);
}

main().catch((e) => { console.error("\nError:", e.message); process.exit(1); });
