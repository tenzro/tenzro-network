// Runs against the compiled module in dist/ (npm test builds first).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import {
  KEY_METHODS,
  PROVIDER_METHODS,
  STANDARD_WALLET_METHODS,
  WALLET_CAPABILITIES,
  WALLET_METHODS,
  parseNetworkSettings,
  resolveMethodName,
  supportedExecutionPermissions,
} from "../dist/routing.js";
import { SCOPE_METHODS, TENZRO_SCOPES } from "../dist/types.js";

test("reads and signed transactions go to the network", () => {
  assert.deepEqual(resolveMethodName(TENZRO_SCOPES.NATIVE, "tenzro_getBalance"), { rpcMethod: "tenzro_getBalance" });
  assert.deepEqual(resolveMethodName(TENZRO_SCOPES.NATIVE, "tenzro_sendRawTransaction"), { rpcMethod: "tenzro_sendRawTransaction" });
  assert.deepEqual(resolveMethodName(TENZRO_SCOPES.EVM, "eth_sendRawTransaction"), { rpcMethod: "eth_sendRawTransaction" });
  assert.deepEqual(resolveMethodName(TENZRO_SCOPES.SVM, "tenzro_getTokenBalance"), { rpcMethod: "tenzro_getTokenBalance" });
});

test("nothing that needs the user's key is sent to a node", () => {
  for (const method of [...KEY_METHODS, ...WALLET_METHODS]) {
    for (const scope of Object.values(TENZRO_SCOPES)) {
      const r = resolveMethodName(scope, method);
      assert.ok("error" in r, `${scope} ${method} must not be sent`);
      assert.match(r.error.message, /holds no key|open wallet/);
    }
  }
});

test("the advertised methods are only ones the network or the open wallet serves", () => {
  for (const [scope, methods] of Object.entries(SCOPE_METHODS)) {
    for (const m of methods) {
      if (WALLET_METHODS.has(m) || STANDARD_WALLET_METHODS.has(m) || PROVIDER_METHODS.has(m)) continue;
      if (m === "eth_accounts" || m === "eth_requestAccounts") continue;
      assert.ok("rpcMethod" in resolveMethodName(scope, m), `${scope} ${m}`);
    }
    for (const m of KEY_METHODS) assert.ok(!methods.includes(m), `${scope} advertises ${m}`);
  }
});

test("other namespaces and scopes are refused", () => {
  assert.ok("error" in resolveMethodName(TENZRO_SCOPES.NATIVE, "eth_call"));
  assert.ok("error" in resolveMethodName(TENZRO_SCOPES.EVM, "wallet_addEthereumChain"));
  assert.ok("error" in resolveMethodName(TENZRO_SCOPES.SVM, "getSlot"));
  assert.ok("error" in resolveMethodName("eip155:1", "eth_chainId"));
  assert.ok("error" in resolveMethodName(null, "tenzro_getBalance"));
});

test("network settings need https seeds and a chain id", () => {
  assert.deepEqual(parseNetworkSettings({ seeds: ["https://seed.example"], chainId: 1337 }), {
    seeds: ["https://seed.example/"],
    chainId: 1337,
  });
  assert.ok(parseNetworkSettings({ seeds: ["http://localhost:8545"], chainId: 1337 }));
  assert.equal(parseNetworkSettings({ seeds: ["http://seed.example"], chainId: 1337 }), null);
  assert.equal(parseNetworkSettings({ seeds: [], chainId: 1337 }), null);
  assert.equal(parseNetworkSettings({ seeds: ["https://seed.example"] }), null);
  assert.equal(parseNetworkSettings(undefined), null);
});

test("the extension generates and holds no key", () => {
  const dir = new URL("../src/", import.meta.url);
  for (const f of readdirSync(dir)) {
    const src = readFileSync(new URL(f, dir), "utf8");
    assert.doesNotMatch(src, /generateKey|importKey|crypto\.subtle\.sign|indexedDB|dpop|staticBearer|https:\/\/rpc\./i, f);
  }
});

test("ERC-5792 and ERC-7715 methods never reach a node", () => {
  for (const method of [...STANDARD_WALLET_METHODS, ...PROVIDER_METHODS]) {
    for (const scope of Object.values(TENZRO_SCOPES)) {
      assert.ok("error" in resolveMethodName(scope, method), `${scope} ${method} must not be sent`);
    }
  }
});

test("every ERC-5792 and ERC-7715 method is served and advertised on the EVM scope", () => {
  const standard = [
    "wallet_getCapabilities",
    "wallet_sendCalls",
    "wallet_getCallsStatus",
    "wallet_showCallsStatus",
    "wallet_getSupportedExecutionPermissions",
    "wallet_requestExecutionPermissions",
    "wallet_revokeExecutionPermission",
    "wallet_getGrantedExecutionPermissions",
  ];
  for (const m of standard) {
    assert.ok(STANDARD_WALLET_METHODS.has(m) || PROVIDER_METHODS.has(m), m);
    assert.ok(SCOPE_METHODS[TENZRO_SCOPES.EVM].includes(m), m);
  }
});

test("capabilities say what the open wallet does", () => {
  assert.deepEqual(WALLET_CAPABILITIES.atomic, { status: "supported" });
  assert.equal(WALLET_CAPABILITIES.paymasterService.supported, false);
  assert.deepEqual(supportedExecutionPermissions("0x539"), {
    "native-token-periodic": { chainIds: ["0x539"], ruleTypes: ["expiry"] },
  });
});
