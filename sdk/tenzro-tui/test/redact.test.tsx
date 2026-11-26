import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { render } from "ink-testing-library";
import { App } from "../src/app.js";
import { emptySnapshot, sdkSource } from "../src/data.js";
import { plainError } from "../src/format.js";
import { plainReport } from "../src/plain.js";
import { redact } from "../src/redact.js";
import { makeTheme } from "../src/theme.js";
import { down, PAYEE, sourceOf } from "./fixtures.js";

const PASSWORD = "hunter2-planted-password";
const TOKEN = "planted-query-token-7f3a";
const JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwbGFudGVkIn0.c2lnbmF0dXJlLXBsYW50ZWQ";
const BEARER = "planted-bearer-credential-91";
const PLANTED = [PASSWORD, TOKEN, JWT, BEARER];
// Port 1 on this machine: nothing listens there.
const URL_WITH_SECRETS = `${["http://operator", PASSWORD].join(":")}@127.0.0.1:1/rpc?token=${TOKEN}&chain=13380`;

function clean(text: string, where: string) {
  for (const secret of PLANTED) assert.ok(!text.includes(secret), `${where} prints ${secret}: ${text}`);
}

test("redact masks credentials in URLs, headers, tokens and pairs", () => {
  assert.equal(redact(URL_WITH_SECRETS), "http://***@127.0.0.1:1/rpc?token=***&chain=13380");
  assert.equal(redact(`Authorization: Bearer ${BEARER}`), "Authorization: Bearer ***");
  assert.equal(redact(`DPoP ${JWT}`), "DPoP ***");
  assert.equal(redact(`got ${JWT} back`), "got *** back");
  assert.equal(redact(`{"password": "${PASSWORD}", "user": "op"}`), `{"password": "***", "user": "op"}`);
  assert.equal(redact(`api_key=${TOKEN}; retry`), "api_key=***; retry");
  assert.equal(redact(`https://node.example/#access_token=${TOKEN}`), "https://node.example/#access_token=***");
});

test("redact leaves public values alone", () => {
  const did = "did:tenzro:machine:265ad18ed76da11bfaa3015b316beb6c6d46de50a286f538866182cbc957b33f";
  for (const s of [PAYEE, did, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "http://127.0.0.1:8545", "https://rpc.tenzro.com/?chain=13380", "Height: 1234567", "node state is Syncing"]) {
    assert.equal(redact(s), s);
  }
});

test("an error that quotes the URL or a credential is masked", () => {
  const url = redact(URL_WITH_SECRETS);
  clean(plainError(new Error("fetch failed", { cause: { code: "ECONNREFUSED" } }), url), "unreachable");
  clean(plainError(new Error("timed out"), url), "timeout");
  clean(plainError(new Error(`Request cannot be constructed from a URL that includes credentials: ${URL_WITH_SECRETS}`), url), "raw error");
  clean(plainError(new Error(`upstream said 500: Bearer ${BEARER} rejected, jwt ${JWT}`), url), "raw error with header");
  clean(plainError(`string failure ${URL_WITH_SECRETS}`, url), "non-error");
});

test("a planted secret in the node URL reaches neither the plain report nor any screen", async () => {
  const source = sdkSource(URL_WITH_SECRETS);
  clean(source.url, "source url");
  // A real collection against the URL: every call fails, and each failure is what a person would see.
  const snap = await source.collect(PAYEE, emptySnapshot);
  assert.equal(snap.status.state, "error");
  clean(JSON.stringify(snap, (_, v) => (typeof v === "bigint" ? v.toString() : v)), "snapshot");
  clean(plainReport(source.url, snap), "plain report");

  const r = render(<App source={{ url: source.url, collect: async () => snap }} theme={makeTheme(false)} initialAccount={PAYEE} refreshMs={60000} size={{ columns: 120, rows: 40 }} />);
  await new Promise((res) => setTimeout(res, 80));
  for (const key of ["1", "2", "3", "4", "5", "?"]) {
    r.stdin.write(key);
    await new Promise((res) => setTimeout(res, 60));
    clean(r.frames.join("\n"), `screen ${key}`);
  }
  assert.match(r.frames.join("\n"), /\*\*\*@127\.0\.0\.1/);
  r.unmount();
});

test("the fixtures' own down state stays masked end to end", async () => {
  const src = sourceOf(() => down(URL_WITH_SECRETS), URL_WITH_SECRETS);
  clean(src.url, "fixture url");
  clean(plainReport(src.url, await src.collect(null, emptySnapshot)), "fixture report");
});
