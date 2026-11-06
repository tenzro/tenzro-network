// Runs against the compiled module in dist/ (npm test builds first).
// The provider the extension announces carries the reverse-DNS form of
// tenzro.com, and discovery takes that provider and no other.
import test from "node:test";
import assert from "node:assert/strict";
import { TENZRO_PROVIDER_RDNS } from "../dist/types.js";
import { discoverEip6963Provider } from "../dist/detect.js";

test("the provider rdns is the reverse-DNS form of tenzro.com", () => {
  assert.equal(TENZRO_PROVIDER_RDNS, "com.tenzro.wallet");
});

/** A page whose wallets answer a provider request with `rdnsList`. */
function pageWith(rdnsList) {
  const page = new EventTarget();
  page.setTimeout = setTimeout;
  page.clearTimeout = clearTimeout;
  page.addEventListener("eip6963:requestProvider", () => {
    for (const rdns of rdnsList) {
      const detail = { info: { uuid: rdns, name: rdns, icon: "", rdns }, provider: {} };
      page.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
    }
  });
  return page;
}

test("discovery takes the provider announcing com.tenzro.wallet", async (t) => {
  globalThis.window = pageWith(["xyz.tenzro.wallet", "com.tenzro.wallet"]);
  t.after(() => delete globalThis.window);
  const found = await discoverEip6963Provider({ timeoutMs: 200 });
  assert.equal(found.info.rdns, "com.tenzro.wallet");
});

test("a provider announcing any other rdns is not taken", async (t) => {
  globalThis.window = pageWith(["xyz.tenzro.wallet"]);
  t.after(() => delete globalThis.window);
  await assert.rejects(discoverEip6963Provider({ timeoutMs: 100 }), { code: "TENZRO_NOT_INSTALLED" });
});
