// Runs against the compiled module in dist/ (npm test builds first).
import test from "node:test";
import assert from "node:assert/strict";
import { SessionStore, narrowScopes } from "../dist/session-store.js";

const ORIGIN = "https://dapp.example";

const REQUEST = {
  "tenzro:mainnet": {
    methods: ["tenzro_getBalance", "tenzro_getNonce"],
    notifications: ["accountsChanged"],
    accounts: ["tenzro:mainnet:0xaaa", "tenzro:mainnet:0xbbb"],
  },
  "eip155:1337": { methods: ["eth_chainId"], notifications: [] },
};

test("a session is not created until the user confirms", async () => {
  let asked = null;
  const store = new SessionStore(async (origin, requested) => {
    asked = { origin, requested };
    return null;
  });
  await assert.rejects(store.create(ORIGIN, { scopes: REQUEST }), (e) => e.code === 4001);
  assert.equal(asked.origin, ORIGIN);
  assert.equal(store.describe(ORIGIN), undefined);
});

test("a page's requested scopes are never granted verbatim", async () => {
  const store = new SessionStore(async () => ({
    "tenzro:mainnet": {
      methods: ["tenzro_getBalance"],
      notifications: ["accountsChanged"],
      accounts: ["tenzro:mainnet:0xaaa"],
    },
  }));
  const result = await store.create(ORIGIN, { scopes: REQUEST });
  assert.deepEqual(Object.keys(result.scopes), ["tenzro:mainnet"]);
  assert.deepEqual(result.scopes["tenzro:mainnet"].methods, ["tenzro_getBalance"]);
  assert.deepEqual(result.scopes["tenzro:mainnet"].accounts, ["tenzro:mainnet:0xaaa"]);
});

test("a confirmer cannot widen what the page asked for", () => {
  const widened = narrowScopes(
    { "tenzro:mainnet": { methods: ["tenzro_getBalance"], notifications: [] } },
    {
      "tenzro:mainnet": { methods: ["tenzro_getBalance", "tenzro_getNonce"], notifications: ["x"] },
      "eip155:1": { methods: ["eth_sendTransaction"], notifications: [] },
    },
  );
  assert.deepEqual(widened, {
    "tenzro:mainnet": { methods: ["tenzro_getBalance"], notifications: [] },
  });
});

test("approving nothing is a rejection", async () => {
  const store = new SessionStore(async () => ({ "solana:x": { methods: [], notifications: [] } }));
  await assert.rejects(store.create(ORIGIN, { scopes: REQUEST }), (e) => e.code === 4001);
});

test("rpc is refused without a session, outside the granted scope, or for an ungranted method", async () => {
  const store = new SessionStore(async () => REQUEST);
  assert.equal(store.authorize(ORIGIN, "tenzro:mainnet", "tenzro_getBalance").code, 4100);
  await store.create(ORIGIN, { scopes: REQUEST });
  assert.equal(store.authorize(ORIGIN, "tenzro:mainnet", "tenzro_getBalance"), null);
  assert.equal(store.authorize(ORIGIN, "tenzro:mainnet", "tenzro_getTransactionHistory").code, 4100);
  assert.equal(store.authorize(ORIGIN, "solana:mainnet", "solana_signMessage").code, 4100);
  assert.equal(store.authorize(ORIGIN, null, "eth_chainId").code, 4100);
  assert.equal(store.authorize("https://other.example", "tenzro:mainnet", "tenzro_getBalance").code, 4100);
  store.revoke(ORIGIN);
  assert.equal(store.authorize(ORIGIN, "tenzro:mainnet", "tenzro_getBalance").code, 4100);
});
