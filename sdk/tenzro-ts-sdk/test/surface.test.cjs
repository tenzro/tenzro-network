// Runs against the compiled package in dist/ (npm test builds first).
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

function recordingTransport() {
  const calls = [];
  return {
    calls,
    transport: {
      async call(method, params) {
        calls.push({ method, params });
        return {};
      },
    },
  };
}

test("crypto client exposes no key-generation or raw-key methods", () => {
  const proto = sdk.CryptoClient.prototype;
  for (const name of ["generateKeypair", "x25519KeyExchange", "encrypt", "decrypt", "deriveKey"]) {
    assert.equal(proto[name], undefined, `${name} must not exist`);
  }
});

test("no client moves keystores over the wire or opens a node-held session", () => {
  assert.equal(sdk.CustodyClient, undefined);
  assert.equal(sdk.WalletClient.prototype.createAccount, undefined);
});

test("a passkey signer never falls back to a software key", () => {
  assert.equal(sdk.SoftwareP256Authenticator, undefined);
  assert.throws(() => sdk.defaultAuthenticator(), /no WebAuthn authenticator/);
});

test("no user operations: accounts act through transactions their keystore authorizes", () => {
  for (const gone of ["createPasskeyWallet", "signWithPasskey", "WebAuthnValidator", "Erc7579ModuleType", "ValidatorError"]) {
    assert.equal(sdk[gone], undefined, gone);
  }
  assert.equal(sdk.PasskeyRpcClient.prototype.grantSessionKey, undefined);
  assert.equal(sdk.PasskeyRpcClient.prototype.listSmartAccounts, undefined);
  assert.equal(sdk.PasskeyRpcClient.prototype.sign, undefined);
});

test("delegateTask speaks A2A v1.0 SendMessage with the version header", async () => {
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push({ url, init });
    return {
      ok: true,
      async text() {
        return JSON.stringify(await this.json());
      },
      async json() {
        return {
          jsonrpc: "2.0",
          id: 1,
          result: { task: { id: "t-1", status: { state: "TASK_STATE_SUBMITTED" } } },
        };
      },
    };
  };
  try {
    const rpc = new sdk.RpcClient("http://node.invalid:8545", "http://node.invalid:8080", 1000);
    const agent = new sdk.AgentClient(rpc);
    const res = await agent.delegateTask("summarise the report");
    assert.equal(res.task.id, "t-1");
    assert.equal(seen[0].url, "http://node.invalid:8080/a2a");
    assert.equal(seen[0].init.headers["A2A-Version"], "1.0");
    const body = JSON.parse(seen[0].init.body);
    assert.equal(body.method, "SendMessage");
    assert.equal(body.params.message.role, "ROLE_USER");
    assert.deepEqual(body.params.message.parts, [{ text: "summarise the report" }]);
    assert.ok(body.params.message.messageId.length > 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("an A2A error envelope is raised, not returned", () => {
  assert.throws(
    () => sdk.decodeA2aEnvelope({ jsonrpc: "2.0", id: 1, error: { code: -32009, message: "version" } }),
    /-32009/,
  );
});

test("agent card path is the A2A v1.0 well-known path", () => {
  assert.equal(sdk.A2A_AGENT_CARD_PATH, "/.well-known/agent-card.json");
  assert.equal(sdk.A2A_PROTOCOL_VERSION, "1.0");
});

test("the DID envelope helpers use the keys and preimage the node verifies", () => {
  assert.equal(sdk.envelopePreimage("SendMessage", "", "did:tenzro:human:x", "00ff", 5, "ab"),
    "tenzro:a2a:SendMessage::did:tenzro:human:x:00ff:5:ab");
  const env = sdk.extractTenzroDidEnvelope({
    "tenzro.a2a.envelope.sender": "did:tenzro:human:x",
    "tenzro.a2a.envelope.public_key": "aa",
    "tenzro.a2a.envelope.signature": "bb",
    "tenzro.a2a.envelope.nonce": "cc",
    "tenzro.a2a.envelope.timestamp": 5,
  });
  assert.equal(env.sender, "did:tenzro:human:x");
  assert.equal(sdk.extractTenzroDidEnvelope({ "tenzro.a2a.envelope.sender": "d" }), null);
  assert.ok(!sdk.TENZRO_DID_ENVELOPE_EXTENSION_URI.endsWith("/v1"));
});

test("machine access asks the node for the challenge, then sends the owner's approval", async () => {
  const rec = recordingTransport();
  const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000, rec.transport);
  const access = new sdk.MachineAccessClient(rpc);
  const terms = {
    grantee_did: "did:tenzro:machine:node",
    resources: [{ kind: "network", cidr: "127.0.0.1/32", port: 5432 }],
    operations: ["connect"],
    expires_at_ms: 1900000000000,
  };
  await access.challenge({ action: "add", ...terms });
  await access.add(terms, { challenge_id: "c1" });
  await access.revoke("g1", { challenge_id: "c2" });
  assert.deepEqual(
    rec.calls.map((c) => c.method),
    ["tenzro_createCustodyChallenge", "tenzro_addMachineAccess", "tenzro_revokeMachineAccess"],
  );
  assert.equal(rec.calls[0].params.operation, "machine_access");
  assert.equal(rec.calls[0].params.machine_access.action, "add");
  assert.deepEqual(rec.calls[1].params.resources, terms.resources);
  assert.equal(rec.calls[1].params.authorization.challenge_id, "c1");
  assert.equal(rec.calls[2].params.grant_id, "g1");
});

test("catalog client reads the node's catalog and publishes nothing itself", async () => {
  const rec = recordingTransport();
  const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000, rec.transport);
  const catalog = new sdk.CatalogClient(rpc);
  await catalog.list("gguf");
  await catalog.entry("m-1");
  assert.deepEqual(
    rec.calls.map((c) => [c.method, c.params]),
    [
      ["tenzro_listCatalog", { engine: "gguf" }],
      ["tenzro_getCatalogEntry", { model: "m-1" }],
    ],
  );
  for (const name of ["publish", "submit", "sign"]) {
    assert.equal(sdk.CatalogClient.prototype[name], undefined, `${name} must not exist`);
  }
});

test("duty client reads duties and checks evidence, and never signs on the node", async () => {
  const rec = recordingTransport();
  const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000, rec.transport);
  const duty = new sdk.DutyClient(rpc);
  const id = "0x" + "aa".repeat(32);
  await duty.list();
  await duty.get(id);
  const items = [{ document: { kind: "delivery", digest: "bb".repeat(32) } }];
  await duty.verifyEvidence(items);
  assert.deepEqual(rec.calls[0], { method: "tenzro_listDuties", params: {} });
  assert.deepEqual(rec.calls[1], { method: "tenzro_getDuty", params: { duty_id: id } });
  assert.deepEqual(rec.calls[2], { method: "tenzro_verifyEvidence", params: { items } });
  for (const name of ["pay", "open", "close", "sign"]) {
    assert.equal(sdk.DutyClient.prototype[name], undefined, `${name} must not exist`);
  }
  for (const gone of ["TaskClient", "PurchaseClient", "TrainingClient", "taskAward"]) {
    assert.equal(sdk[gone], undefined, `${gone} must not exist`);
  }
});

test("platform clients call the node's beacon, DA and fee-market methods", async () => {
  const rec = recordingTransport();
  const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000, rec.transport);
  await new sdk.BeaconClient(rpc).get({ atMs: 5 });
  await new sdk.DaRetentionClient(rpc).object("cd".repeat(32));
  await new sdk.DaRetentionClient(rpc).retention();
  await sdk.getFeeMarket(rpc);
  assert.deepEqual(
    rec.calls.map((c) => c.method),
    [
      "tenzro_getBeacon",
      "tenzro_getDaObject",
      "tenzro_getDaRetention",
      "tenzro_getFeeMarket",
    ],
  );
  assert.deepEqual(rec.calls[0].params, { at_ms: 5 });
});

test("hardware signer refuses without hardware and has no software path", () => {
  assert.equal(typeof sdk.openHardwareSigner, "function");
  for (const name of ["generate", "fromPrivateKey", "importKey", "exportKey"]) {
    assert.equal(sdk.HardwareKeySigner[name], undefined, `${name} must not exist`);
    assert.equal(sdk.HardwareKeySigner.prototype[name], undefined, `${name} must not exist`);
  }
  let native = null;
  try { native = require("@tenzro/device-key"); } catch {}
  if (native && native.platformBackend() !== null) return;
  assert.throws(
    () => sdk.openHardwareSigner({ label: "tenzro-surface-test" }),
    (e) => e.kind === "backend-unavailable" && /no software-key fallback/.test(e.message)
  );
});

test("keystores are read from any node and their changes are typed transactions", async () => {
  const rec = recordingTransport();
  const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000, rec.transport);
  const keystores = new sdk.KeystoreClient(rpc);
  await keystores.getKeystore("0xabc");
  await keystores.resolveCredential("c0de", "wallet.example");
  assert.deepEqual(rec.calls.map((c) => [c.method, c.params]), [
    ["tenzro_getKeystore", { account: "0xabc" }],
    ["tenzro_resolveCredential", { credential_id: "c0de", rp_id: "wallet.example" }],
  ]);
  assert.ok(sdk.TX_KINDS.includes("KeystoreUpdate"));
});

test("governance client reads the levers, all or one area", async () => {
  const rec = recordingTransport();
  const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000, rec.transport);
  const gov = new sdk.GovernanceClient(rpc);
  await gov.listLevers();
  await gov.listLevers("bridge");
  assert.deepEqual(
    rec.calls.map((c) => [c.method, c.params]),
    [
      ["tenzro_listLevers", {}],
      ["tenzro_listLevers", { area: "bridge" }],
    ],
  );
});
