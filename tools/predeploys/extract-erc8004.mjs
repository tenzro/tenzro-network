#!/usr/bin/env node
//
// extract-erc8004.mjs
//
// Reads a Hardhat / Anvil hardhat_dumpState output from stdin, filters it
// down to the seven ERC-8004 predeploy addresses, and writes a Tenzro
// genesis predeploy JSON to the path passed as the only positional arg.
//
// Anvil / Hardhat 3 hardhat_dumpState format (Anvil-compatible):
//   {
//     "block": { ... },
//     "accounts": {
//       "0x<addr>": {
//         "nonce": <number>,
//         "balance": "0x<hex>",
//         "code": "0x<hex>",
//         "storage": { "0x<slot>": "0x<value>", ... }
//       },
//       ...
//     }
//   }
//
// Output (consumed by crates/tenzro-node/src/genesis.rs via include_str!):
//   {
//     "schema": "tenzro/erc8004-predeploys/v1",
//     "source_commit": "<git rev of vendor/erc8004-evm/>",
//     "addresses": {
//       "safeSingletonFactory": "0x914d7Fec...",
//       "minimalUUPS": "0xd53dE68...",
//       "identityProxy": "0x8004A818...",
//       "reputationProxy": "0x8004B663...",
//       "validationProxy": "0x8004Cb1B...",
//       "identityImpl": "0x7274e874...",
//       "reputationImpl": "0x16e0FA7f...",
//       "validationImpl": "0xDB31f5d9..."
//     },
//     "accounts": {
//       "0x<addr>": {
//         "nonce": <number>,
//         "balance": "0x<hex>",
//         "code": "0x<hex>",
//         "storage": { "0x<32-byte slot>": "0x<32-byte value>", ... }
//       },
//       ...
//     }
//   }

import { readFileSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Stable addresses — these are independent of impl contract bytecode and so do not
// drift across canonical pins. The factory address comes from
// https://github.com/Arachnid/deterministic-deployment-proxy and is the same on
// every EVM chain where it has been deployed. MinimalUUPS is itself deployed via
// CREATE2 from a fixed salt against fixed bytecode in the canonical repo, so its
// address is stable across pins. The three vanity proxies are CREATE2-deployed
// from `TESTNET_VANITY_SALTS` against `MinimalUUPS` proxy bytecode, also stable.
const SAFE_SINGLETON_FACTORY = "0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7";
const MINIMAL_UUPS = "0xd53dE688e0b0ad436FBdbDa00036832FF6499234";
const IDENTITY_PROXY = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const REPUTATION_PROXY = "0x8004B663056A597Dffe9eCcC1965A193B7388713";
const VALIDATION_PROXY = "0x8004Cb1BF31DAf7788923b405b754f57acEB4272";

// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1.
// Each upgradeable proxy stores its current impl address in this slot. We read
// the slot out of the dumped proxy storage to auto-discover the impl addresses
// at the pinned vendor commit, rather than hardcoding canonical-mainnet-only
// addresses that drift whenever Reputation/Validation source changes.
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

// Stable target set — proxies + factory + MinimalUUPS. Implementation addresses
// are discovered dynamically from each proxy's EIP-1967 slot in `main()`.
const STABLE_TARGETS = {
  safeSingletonFactory: SAFE_SINGLETON_FACTORY,
  minimalUUPS: MINIMAL_UUPS,
  identityProxy: IDENTITY_PROXY,
  reputationProxy: REPUTATION_PROXY,
  validationProxy: VALIDATION_PROXY,
};

// Mapping from impl label → proxy label whose EIP-1967 slot we read.
const IMPL_DISCOVERY = {
  identityImpl: "identityProxy",
  reputationImpl: "reputationProxy",
  validationImpl: "validationProxy",
};

function lower(s) {
  return s.toLowerCase();
}

function normaliseHexWord(hex) {
  // Anvil sometimes returns storage values as short hex (e.g. "0x1"). Left-pad
  // to 32 bytes so the Rust loader can treat every slot value as a fixed-width
  // U256 without per-key special-casing.
  if (!hex.startsWith("0x")) hex = "0x" + hex;
  const body = hex.slice(2);
  if (body.length > 64) {
    throw new Error(`storage value longer than 32 bytes: ${hex}`);
  }
  return "0x" + body.padStart(64, "0");
}

function normaliseSlot(hex) {
  if (!hex.startsWith("0x")) hex = "0x" + hex;
  const body = hex.slice(2);
  if (body.length > 64) {
    throw new Error(`storage slot longer than 32 bytes: ${hex}`);
  }
  return "0x" + body.padStart(64, "0");
}

function main() {
  const [outPath] = process.argv.slice(2);
  if (!outPath) {
    console.error("usage: extract-erc8004.mjs <output-path>  (reads dump from stdin)");
    process.exit(2);
  }

  const raw = readFileSync(0, "utf8");
  let dump;
  try {
    dump = JSON.parse(raw);
  } catch (e) {
    console.error("failed to parse hardhat_dumpState payload:", e.message);
    process.exit(1);
  }

  // Anvil + Hardhat 3 dumpState wraps state under varying top-level keys
  // depending on version. Anvil uses `accounts`; some Hardhat builds nest
  // under `state.accounts`. Probe both.
  const accounts =
    dump.accounts ??
    dump.state?.accounts ??
    null;
  if (!accounts) {
    console.error("dumpState payload missing `accounts` field — got keys:", Object.keys(dump).join(","));
    process.exit(1);
  }

  // Build a lower-cased index for case-insensitive lookup.
  const accountIndex = new Map();
  for (const [addr, acc] of Object.entries(accounts)) {
    accountIndex.set(lower(addr), acc);
  }

  // Discover impl addresses by reading the EIP-1967 implementation slot off
  // each proxy in the dump. This adapts to bytecode drift across canonical
  // vendor pins: as long as the deploy + upgrade flow has run, the proxy's
  // EIP-1967 slot holds the live impl address.
  const targets = { ...STABLE_TARGETS };
  for (const [implLabel, proxyLabel] of Object.entries(IMPL_DISCOVERY)) {
    const proxyAddr = STABLE_TARGETS[proxyLabel];
    const proxyAcc = accountIndex.get(lower(proxyAddr));
    if (!proxyAcc) {
      console.error(`proxy ${proxyAddr} (${proxyLabel}) not found in dump — cannot discover ${implLabel}`);
      process.exit(1);
    }
    const slotKey = Object.keys(proxyAcc.storage ?? {}).find(
      (k) => normaliseSlot(k) === EIP1967_IMPL_SLOT,
    );
    if (!slotKey) {
      console.error(`proxy ${proxyAddr} has no EIP-1967 impl slot set — upgrade did not run`);
      process.exit(1);
    }
    const slotValue = normaliseHexWord(proxyAcc.storage[slotKey]);
    // Impl address is the low 20 bytes of the 32-byte slot value.
    const implAddr = "0x" + slotValue.slice(2 + 24);
    targets[implLabel] = implAddr;
  }

  const out = {
    schema: "tenzro/erc8004-predeploys/v1",
    source_commit: detectSourceCommit(),
    addresses: targets,
    accounts: {},
  };

  for (const [label, addr] of Object.entries(targets)) {
    const acc = accountIndex.get(lower(addr));
    if (!acc) {
      console.error(`address ${addr} (${label}) not found in dump`);
      process.exit(1);
    }
    if (!acc.code || acc.code === "0x" || acc.code === "0x0") {
      console.error(`address ${addr} (${label}) has no deployed code — deployment did not complete cleanly`);
      process.exit(1);
    }

    const storage = {};
    if (acc.storage) {
      for (const [slot, value] of Object.entries(acc.storage)) {
        // Skip zero values — they are the EVM default and including them just
        // bloats the genesis JSON.
        const normValue = normaliseHexWord(value);
        if (/^0x0+$/.test(normValue)) continue;
        storage[normaliseSlot(slot)] = normValue;
      }
    }

    out.accounts[addr] = {
      nonce: typeof acc.nonce === "string" ? parseInt(acc.nonce, 16) || 0 : acc.nonce ?? 0,
      balance: typeof acc.balance === "string" ? acc.balance : "0x" + (acc.balance ?? 0n).toString(16),
      code: acc.code,
      storage,
    };
  }

  writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${outPath}: ${Object.keys(out.accounts).length} accounts`);
}

function detectSourceCommit() {
  const here = dirname(fileURLToPath(import.meta.url));
  const vendorDir = resolve(here, "..", "..", "vendor", "erc8004-evm");
  try {
    return execSync("git rev-parse HEAD", { cwd: vendorDir, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return "unknown";
  }
}

main();
