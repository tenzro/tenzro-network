// EIP-6963 discovery: the Tenzro provider is found by the reverse-DNS form
// of tenzro.com, and a provider announcing any other rdns is not taken.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

test("the Tenzro provider rdns is the reverse-DNS form of tenzro.com", () => {
  assert.equal(sdk.TENZRO_PROVIDER_RDNS, "com.tenzro.wallet");
});

/** A page whose wallets answer a provider request with `rdnsList`. */
function pageWith(rdnsList) {
  const page = new EventTarget();
  page.setTimeout = setTimeout;
  page.clearTimeout = clearTimeout;
  page.addEventListener("eip6963:requestProvider", () => {
    for (const rdns of rdnsList) {
      const detail = { info: { uuid: rdns, name: rdns, icon: "", rdns }, provider: { rdns } };
      page.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
    }
  });
  return page;
}

test("discovery takes the provider announcing com.tenzro.wallet", async (t) => {
  globalThis.window = pageWith(["xyz.tenzro.wallet", "com.tenzro.wallet"]);
  t.after(() => delete globalThis.window);
  const found = await sdk.discoverEip6963Provider({ timeoutMs: 200 });
  assert.equal(found.info.rdns, "com.tenzro.wallet");
});

test("a provider announcing any other rdns is not the Tenzro provider", async (t) => {
  globalThis.window = pageWith(["xyz.tenzro.wallet"]);
  t.after(() => delete globalThis.window);
  await assert.rejects(sdk.discoverEip6963Provider({ timeoutMs: 100 }), { code: "TENZRO_NOT_INSTALLED" });
});
