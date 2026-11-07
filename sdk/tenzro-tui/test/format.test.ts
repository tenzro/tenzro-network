import test from "node:test";
import assert from "node:assert/strict";
import { fit, formatDuration, formatTnzo, isAddress, plainError, shortId } from "../src/format.js";
import { shrinkColumns } from "../src/ui.js";
import { colorEnabled } from "../src/theme.js";

test("formatTnzo groups and trims", () => {
  assert.equal(formatTnzo(0n), "0");
  assert.equal(formatTnzo(10n ** 18n), "1");
  assert.equal(formatTnzo(1234567890123456789012n), "1,234.5678");
  assert.equal(formatTnzo("1000000000000000000000000", 2), "1,000,000");
  assert.equal(formatTnzo(-(10n ** 17n)), "-0.1");
});

test("shortId, fit and duration", () => {
  assert.equal(shortId("abcdef", 3, 3), "abcdef");
  assert.equal(shortId("0123456789abcdef", 4, 4), "0123...cdef");
  assert.equal(fit("abcdefghij", 6), "abc...");
  assert.equal(fit("ab", 4), "ab  ");
  assert.equal(formatDuration(59), "59s");
  assert.equal(formatDuration(3700), "1h 1m");
  assert.equal(formatDuration(90000), "1d 1h");
});

test("isAddress accepts 20 and 32 byte accounts only", () => {
  assert.ok(isAddress("0x" + "ab".repeat(20)));
  assert.ok(isAddress("0x" + "AB".repeat(32)));
  assert.ok(!isAddress("0x" + "ab".repeat(19)));
  assert.ok(!isAddress("abc"));
  assert.ok(!isAddress("0x" + "zz".repeat(20)));
});

test("plainError says what to do when the node is down", () => {
  const e = Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } });
  assert.match(plainError(e, "http://x:1"), /Cannot reach a node at http:\/\/x:1/);
  assert.match(plainError(new Error("timed out"), "u"), /did not answer/);
});

test("NO_COLOR and TERM=dumb switch color off", () => {
  assert.equal(colorEnabled({}, false), true);
  assert.equal(colorEnabled({ NO_COLOR: "1" }, false), false);
  assert.equal(colorEnabled({ NO_COLOR: "" }, false), true);
  assert.equal(colorEnabled({ TERM: "dumb" }, false), false);
  assert.equal(colorEnabled({}, true), false);
});

test("table columns shrink to fit and never below 8", () => {
  const cols = [
    { title: "A", width: 40, get: () => "" },
    { title: "B", width: 30, get: () => "" },
    { title: "C", width: 30, get: () => "" },
  ];
  const out = shrinkColumns(cols, 80);
  assert.ok(out.reduce((n, c) => n + c.width, 0) + 2 + 2 <= 80);
  assert.ok(out.every((c) => c.width >= 8));
});
