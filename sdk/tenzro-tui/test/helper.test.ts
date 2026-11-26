import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { HelperAbsent, HelperError, defaultSocket, socketHelper } from "../src/helper.js";

test("the helper's socket is looked for where the helper listens", () => {
  assert.equal(defaultSocket({ XDG_RUNTIME_DIR: "/run/user/1000" }, "linux", "/home/a"), "/run/user/1000/tenzro/control.sock");
  assert.equal(defaultSocket({}, "linux", "/home/a"), "/home/a/.tenzro/control.sock");
  assert.equal(defaultSocket({ XDG_RUNTIME_DIR: "/run/user/1000" }, "darwin", "/Users/a"), "/Users/a/.tenzro/control.sock");
  assert.equal(defaultSocket({ TENZRO_HOME: "/srv/tz" }, "darwin", "/Users/a"), "/srv/tz/control.sock");
});

test("a call is one JSON-RPC line each way, and a refusal comes back as the helper's message", { skip: process.platform === "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tz-helper-"));
  const where = path.join(dir, "control.sock");
  const seen: unknown[] = [];
  const server = net.createServer((sock) => {
    sock.setEncoding("utf8");
    let buf = "";
    sock.on("data", (chunk: string) => {
      buf += chunk;
      const end = buf.indexOf("\n");
      if (end < 0) return;
      const req = JSON.parse(buf.slice(0, end)) as { id: number; method: string; params: { action?: string } };
      seen.push(req);
      const reply = req.params.action === "stop" ? { jsonrpc: "2.0", id: req.id, result: { service: "stopped", reason: "" } } : { jsonrpc: "2.0", id: req.id, error: { code: -32004, message: "sign in as this node's operator, token=planted-helper-secret" } };
      sock.write(JSON.stringify(reply) + "\n");
    });
  });
  await new Promise<void>((res) => server.listen(where, res));
  try {
    const helper = socketHelper(where);
    assert.deepEqual(await helper.call("control_service", { action: "stop" }), { service: "stopped", reason: "" });
    assert.deepEqual(seen[0], { jsonrpc: "2.0", id: 1, method: "control_service", params: { action: "stop" } });
    await assert.rejects(helper.call("control_service", { action: "restart" }), (e: unknown) => {
      assert.ok(e instanceof HelperError);
      assert.equal(e.code, -32004);
      assert.equal(e.shown, "sign in as this node's operator, token=***");
      return true;
    });
  } finally {
    await new Promise<void>((res) => server.close(() => res()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
  await assert.rejects(socketHelper(where).call("control_summary"), HelperAbsent);
});
