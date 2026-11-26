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
  const node = cardSigner();
  const nodeDid = await node.did();
  const signedCard = await node.sign(plainCard());
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith(sdk.A2A_AGENT_CARD_PATH)) {
      return { ok: true, text: async () => JSON.stringify(signedCard), json: async () => signedCard };
    }
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
    const res = await agent.delegateTask(softSender("did:tenzro:machine:caller"), nodeDid, "summarise the report");
    assert.equal(res.task.id, "t-1");
    assert.equal(seen[0].url, "http://node.invalid:8080/a2a");
    assert.equal(seen[0].init.headers["A2A-Version"], "1.0");
    const body = JSON.parse(seen[0].init.body);
    assert.equal(body.method, "SendMessage");
    assert.equal(body.params.message.role, "ROLE_USER");
    assert.deepEqual(body.params.message.parts, [{ text: "summarise the report" }]);
    assert.ok(body.params.message.messageId.length > 0);
    assert.equal(await verifiedSender(nodeDid, "SendMessage", body.params), "did:tenzro:machine:caller");
    assert.equal(body.params.metadata, undefined, "a message carries the envelope inside");
  } finally {
    globalThis.fetch = realFetch;
  }
});

function plainCard() {
  return {
    name: "Tenzro Network Agent",
    version: "0.2.2",
    supportedInterfaces: [{ url: "https://a2a.example", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    capabilities: { streaming: true, pushNotifications: false },
    skills: [{ id: "wallet", name: "Wallet Operations", tags: ["wallet"] }],
  };
}

/** A software P-256 key standing in for a node's hardware identity key: signs cards the way a node does. */
function cardSigner() {
  const { generateKeyPairSync, sign } = require("node:crypto");
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const xy = Buffer.concat([Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  const did = () => sdk.machineDid(new Uint8Array(xy));
  /** `card` signed by this key, its header claiming to be `claimed`'s key (its own DID by default). */
  const signCard = async (card, claimed) => {
    const { signatures: _s, ...unsigned } = card;
    const header = { alg: "ES256", typ: "JOSE", kid: `${claimed ?? (await did())}#hardware-key`, jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } };
    const protectedB64 = Buffer.from(sdk.canonicalJson(header)).toString("base64url");
    const input = `${protectedB64}.${Buffer.from(sdk.canonicalJson(unsigned)).toString("base64url")}`;
    const signature = sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    return { ...unsigned, signatures: [{ protected: protectedB64, signature }] };
  };
  return { did, sign: signCard };
}

test("the machine DID is the hash of the key's SEC1 form under its domain", async () => {
  const { createHash } = require("node:crypto");
  const xy = new Uint8Array(64).fill(7);
  const expected = createHash("sha256")
    .update(Buffer.concat([Buffer.from("tenzro/machine-did/device-key"), Buffer.from([0, 0, 0, 65, 4]), Buffer.from(xy)]))
    .digest("hex");
  assert.equal(await sdk.machineDid(xy), `did:tenzro:machine:${expected}`);
  await assert.rejects(sdk.machineDid(new Uint8Array(33)), /64 bytes/);
});

test("a card is accepted only when the machine the caller named signed it", async () => {
  const node = cardSigner();
  const other = cardSigner();
  const nodeDid = await node.did();
  const good = await node.sign(plainCard());
  await sdk.verifyAgentCard(good, nodeDid);
  await sdk.verifyAgentCard(JSON.parse(JSON.stringify(good, null, 2)), nodeDid);

  // Signed by another key: every signature verifies, none is the named machine's.
  await assert.rejects(sdk.verifyAgentCard(await other.sign(plainCard()), nodeDid), /not by did:tenzro:machine:/);
  // Signed by another key under the named machine's DID.
  await assert.rejects(sdk.verifyAgentCard(await other.sign(plainCard(), nodeDid), nodeDid), /claims the key of/);
  // A good card, but the caller named another identity.
  const otherDid = await other.did();
  await assert.rejects(sdk.verifyAgentCard(good, otherDid), (e) => e instanceof sdk.AgentCardRefused && e.message.includes(otherDid));
  // Unsigned, emptied and altered cards.
  await assert.rejects(sdk.verifyAgentCard(plainCard(), nodeDid), /no signature/);
  await assert.rejects(sdk.verifyAgentCard({ ...plainCard(), signatures: [] }, nodeDid), /no signature/);
  const moved = JSON.parse(JSON.stringify(good));
  moved.supportedInterfaces[0].url = "https://elsewhere.example";
  await assert.rejects(sdk.verifyAgentCard(moved, nodeDid), /does not verify/);
  const added = JSON.parse(JSON.stringify(good));
  added.skills.push({ id: "inference" });
  await assert.rejects(sdk.verifyAgentCard(added, nodeDid), /does not verify/);
  // One good signature does not carry a broken one beside it; two machines may both sign.
  const second = (await other.sign(plainCard())).signatures[0];
  await sdk.verifyAgentCard({ ...good, signatures: [...good.signatures, second] }, nodeDid);
  const broken = { ...second, signature: Buffer.alloc(64, 7).toString("base64url") };
  await assert.rejects(sdk.verifyAgentCard({ ...good, signatures: [...good.signatures, broken] }, nodeDid), /does not verify/);
});

test("a task is delegated only after the node's card proved its identity; otherwise nothing is sent", async () => {
  const node = cardSigner();
  const other = cardSigner();
  const nodeDid = await node.did();
  const realFetch = globalThis.fetch;
  const run = async (card, namedDid) => {
    const posts = [];
    globalThis.fetch = async (url, init) => {
      if (String(url).endsWith(sdk.A2A_AGENT_CARD_PATH)) return { ok: true, text: async () => JSON.stringify(card), json: async () => card };
      posts.push(JSON.parse(init.body));
      const reply = { jsonrpc: "2.0", id: 1, result: { task: { id: "t-1", status: { state: "TASK_STATE_SUBMITTED" } } } };
      return { ok: true, text: async () => JSON.stringify(reply), json: async () => reply };
    };
    const agent = new sdk.AgentClient(new sdk.RpcClient("http://node.invalid:8545", "http://node.invalid:8080", 1000));
    let error = null;
    try {
      await agent.delegateTask(softSender("did:tenzro:machine:caller"), namedDid, "summarise the report");
    } catch (e) {
      error = e;
    }
    return { posts, error };
  };
  try {
    const ok = await run(await node.sign(plainCard()), nodeDid);
    assert.equal(ok.error, null);
    assert.equal(ok.posts.length, 1);
    assert.equal(ok.posts[0].method, "SendMessage");
    for (const [what, card, named] of [
      ["another key", await other.sign(plainCard()), nodeDid],
      ["another key under the named DID", await other.sign(plainCard(), nodeDid), nodeDid],
      ["another identity named", await node.sign(plainCard()), await other.did()],
      ["unsigned", plainCard(), nodeDid],
    ]) {
      const bad = await run(card, named);
      assert.ok(bad.error instanceof sdk.AgentCardRefused, `${what}: ${bad.error}`);
      assert.deepEqual(bad.posts, [], `${what}: nothing was sent`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

/** A software P-256 key standing in for the hardware account key. */
function softSender(did) {
  const { generateKeyPairSync, sign } = require("node:crypto");
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const xy = Buffer.concat([Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  return {
    did,
    signer: {
      publicKey: () => new Uint8Array(xy),
      sign: async (message) => new Uint8Array(sign("sha256", Buffer.from(message), { key: privateKey, dsaEncoding: "ieee-p1363" })),
    },
  };
}

/** The machine DID of the node test envelopes are addressed to. */
const NODE_DID = "did:tenzro:machine:node";

/** Check an envelope addressed to `audienceDid` the way the node does; the sender DID, or null. */
async function verifiedSender(audienceDid, method, params) {
  const { createPublicKey, verify } = require("node:crypto");
  const holder = method === "SendMessage" || method === "SendStreamingMessage" ? params.message : params;
  const env = sdk.extractTenzroDidEnvelope((holder && holder.metadata) || {});
  if (!env) return null;
  const xy = Buffer.from(env.publicKey, "hex");
  const key = createPublicKey({
    format: "jwk",
    key: { kty: "EC", crv: "P-256", x: xy.subarray(0, 32).toString("base64url"), y: xy.subarray(32).toString("base64url") },
  });
  const preimage = sdk.envelopePreimage(audienceDid, method, sdk.envelopeTaskId(method, params), env.sender, env.nonce, env.timestampMs, await sdk.paramsDigestHex(method, params));
  const ok = verify("sha256", Buffer.from(preimage), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(env.signature, "hex"));
  return ok ? env.sender : null;
}

test("the params digest is the SHA-256 of the canonical form, as the node computes it", async () => {
  assert.equal(await sdk.paramsDigestHex("GetTask", { id: "t-1", historyLength: 3 }), "b9b45dcffe8b8a7288299bd82bdabdcad1c19fed43d1006937db7e3777a8e3f1");
  assert.equal(await sdk.paramsDigestHex("ListTasks", {}), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
  assert.equal(
    await sdk.paramsDigestHex("ListTasks", { pageSize: 10, includeArtifacts: true, contextId: "c\u00e9\n" }),
    "c34b1beab72fb98be2c7b9169a727921ea65a64890f39840a2812ac0935ec973",
  );
  assert.equal(sdk.canonicalJson({ b: [1, "x", null, true], a: { z: 1, y: undefined } }), '{"a":{"z":1},"b":[1,"x",null,true]}');
  assert.throws(() => sdk.canonicalJson({ x: Infinity }), /not finite/);
});

test("every A2A task call carries the sender's signed envelope, bound to the method, the task and the body", async () => {
  const seen = [];
  const realFetch = globalThis.fetch;
  const results = {
    GetTask: { id: "t-1", status: { state: "TASK_STATE_COMPLETED" } },
    CancelTask: { id: "t-1", status: { state: "TASK_STATE_CANCELED" } },
    ListTasks: { tasks: [{ id: "t-1", status: { state: "TASK_STATE_COMPLETED" } }], nextPageToken: "", pageSize: 50, totalSize: 1 },
  };
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    seen.push(body);
    const reply = { jsonrpc: "2.0", id: 1, result: results[body.method] };
    return { ok: true, text: async () => JSON.stringify(reply), json: async () => reply };
  };
  try {
    const agent = new sdk.AgentClient(new sdk.RpcClient("http://node.invalid:8545", "http://node.invalid:8080", 1000));
    const me = softSender("did:tenzro:machine:reader");

    assert.equal((await agent.getA2aTask(me, NODE_DID, "t-1")).id, "t-1");
    const page = await agent.listA2aTasks(me, NODE_DID, { contextId: "ctx", includeArtifacts: true });
    assert.equal(page.totalSize, 1);
    assert.equal((await agent.listA2aTasks(me, NODE_DID)).tasks[0].id, "t-1");
    await agent.cancelA2aTask(me, NODE_DID, "t-1");

    assert.deepEqual(seen.map((b) => b.method), ["GetTask", "ListTasks", "ListTasks", "CancelTask"]);
    for (const body of seen) {
      assert.equal(await verifiedSender(NODE_DID, body.method, body.params), "did:tenzro:machine:reader", body.method);
    }
    assert.equal(seen[1].params.contextId, "ctx");
    assert.equal(seen[1].params.includeArtifacts, true);
    assert.notEqual(seen[1].params.metadata[sdk.ENVELOPE_NONCE_KEY], seen[2].params.metadata[sdk.ENVELOPE_NONCE_KEY]);

    // The envelope serves that call only.
    const get = seen[0].params;
    assert.equal(await verifiedSender(NODE_DID, "CancelTask", get), null, "another method");
    assert.equal(await verifiedSender("did:tenzro:machine:other", "GetTask", get), null, "another node");
    assert.equal(await verifiedSender(NODE_DID, "GetTask", { ...get, id: "t-2" }), null, "another task");
    assert.equal(await verifiedSender(NODE_DID, "GetTask", { ...get, historyLength: 5 }), null, "another body");
    const other = softSender("did:tenzro:machine:other");
    const swapped = { ...get, metadata: { ...get.metadata, [sdk.ENVELOPE_PUBLIC_KEY_KEY]: Buffer.from(other.signer.publicKey()).toString("hex") } };
    assert.equal(await verifiedSender(NODE_DID, "GetTask", swapped), null, "another key");
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
  assert.equal(sdk.envelopePreimage(NODE_DID, "SendMessage", "", "did:tenzro:human:x", "00ff", 5, "ab"),
    "tenzro:a2a:did:tenzro:machine:node:SendMessage::did:tenzro:human:x:00ff:5:ab");
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

test("an account with an ML-DSA-65 key adds its leg over the envelope preimage", async () => {
  const me = softSender("did:tenzro:machine:pq");
  let signed;
  me.signer.mlDsaLeg = async (mPrime) => {
    signed = mPrime;
    return new Uint8Array(3309).fill(7);
  };
  const params = await sdk.signEnvelope(NODE_DID, "GetTask", { id: "t-1" }, me);
  assert.equal(await verifiedSender(NODE_DID, "GetTask", params), me.did);
  const m = params.metadata;
  assert.equal(m[sdk.ENVELOPE_PQ_SIGNATURE_KEY], "07".repeat(3309));
  const preimage = sdk.envelopePreimage(NODE_DID, "GetTask", "t-1", me.did, m[sdk.ENVELOPE_NONCE_KEY], m[sdk.ENVELOPE_TIMESTAMP_KEY],
    await sdk.paramsDigestHex("GetTask", params));
  assert.deepEqual(signed, await sdk.compositeMessageRepresentative(sdk.A2A_ENVELOPE_CONTEXT, new TextEncoder().encode(preimage)));

  const plain = await sdk.signEnvelope(NODE_DID, "GetTask", { id: "t-1" }, softSender("did:tenzro:machine:classical"));
  assert.equal(plain.metadata[sdk.ENVELOPE_PQ_SIGNATURE_KEY], undefined);
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
