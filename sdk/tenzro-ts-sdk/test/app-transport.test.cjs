// The app transport client against a stand-in node: framing, sign-in over
// the session's challenge, listen, open and accept, and checking the node's
// certificate publication.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  AppSession,
  FrameReader,
  WELCOME_PQ_CONTEXT,
  appTransportInfo,
  appTransportUsage,
  encodeFrame,
  publicationPreimage,
  signInHtu,
  verifyPublication,
  verifyWelcome,
  welcomePreimage,
} = require("../dist/index.js");

// The same vector the node's own test pins (crates/tenzro-node/src/pinned_cert.rs).
const VECTOR = {
  issuer: "did:tenzro:machine:a",
  listener: "app-transport",
  signed_at: 1800000005,
  hashes: [
    { sha256: "11".repeat(32), not_before: 1799996400, not_after: 1801119600 },
    { sha256: "22".repeat(32), not_before: 1800428400, not_after: 1801551600 },
  ],
};
const VECTOR_DIGEST = "f0265744139c6181317242e4ea16ffa9228d02f096b2d85dcdc93c552bbfc400";

// The welcome digest the node's frame test pins (crates/tenzro-iroh/src/app_stream.rs).
const WELCOME_DIGEST = "ee32d5fe974bb82fd5895ad0e237a9d282a0cae8a425a75edc4ba7e8fc19dd94";

/** A node's access-token key and the welcomes it signs. */
function nodeKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    nodeKey: publicKey.export({ format: "jwk" }),
    welcome(nonce, did, device, expiresAt) {
      const preimage = welcomePreimage(nonce, did, device, expiresAt);
      const signature = crypto
        .sign("sha256", preimage, { key: privateKey, dsaEncoding: "ieee-p1363" })
        .toString("base64url");
      const digest = crypto.createHash("sha256").update(preimage).digest();
      // A stand-in "ML-DSA" signature: the digest under the context, which
      // the stand-in verifier below recomputes.
      const pq = Buffer.concat([Buffer.from(WELCOME_PQ_CONTEXT), digest]).toString("base64url");
      return { type: "welcome", did, device, expires_at: expiresAt, signature, pq_signature: pq };
    },
  };
}

/** Accepts exactly the stand-in signatures `nodeKeys().welcome` makes. */
const standInPq = {
  publicKey: new Uint8Array([1]),
  verify(publicKey, context, message, signature) {
    return Buffer.from(signature).equals(Buffer.concat([Buffer.from(context), Buffer.from(message)]));
  },
};

/** A pipe: what is written to `writable` comes out of `readable`. */
function pipe() {
  // Room for every chunk a test writes, so a write does not wait for a reader.
  const t = new TransformStream(undefined, { highWaterMark: 64 }, { highWaterMark: 64 });
  return { readable: t.readable, writable: t.writable };
}

/** Two ends of a bidirectional stream. */
function bidi() {
  const up = pipe();
  const down = pipe();
  return [
    { readable: down.readable, writable: up.writable },
    { readable: up.readable, writable: down.writable },
  ];
}

async function send(stream, frame) {
  const w = stream.writable.getWriter();
  await w.write(encodeFrame(frame));
  w.releaseLock();
}

async function readAll(readable) {
  const chunks = [];
  for await (const c of readable) chunks.push(Buffer.from(c));
  return Buffer.concat(chunks);
}

/**
 * A stand-in node session. `serve` gets the node's end: `control` (a frame
 * reader and the stream), `incoming` (streams the device opened, in order)
 * and `offer()` (opens a stream to the device).
 */
function standIn(serve) {
  const toDevice = new TransformStream();
  const deviceOpened = [];
  let wake = () => {};
  const node = {
    async offer() {
      const [device, nodeEnd] = bidi();
      const w = toDevice.writable.getWriter();
      await w.write(device);
      w.releaseLock();
      return nodeEnd;
    },
    async opened() {
      while (deviceOpened.length === 0) await new Promise((r) => (wake = r));
      return deviceOpened.shift();
    },
  };
  let closed;
  const transport = {
    ready: Promise.resolve(),
    closed: new Promise((r) => (closed = r)),
    incomingBidirectionalStreams: toDevice.readable,
    datagrams: (() => {
      // A datagram write completes once the datagram is sent, whether or not the
      // far end is reading yet: the buffer is what lets the stand-in do the same.
      const buffered = () => new TransformStream({}, undefined, { highWaterMark: 16 });
      const toNode = buffered();
      node.sentDatagrams = toNode.readable;
      const fromNode = buffered();
      node.datagramWriter = fromNode.writable.getWriter();
      return { readable: fromNode.readable, writable: toNode.writable };
    })(),
    async createBidirectionalStream() {
      const [device, nodeEnd] = bidi();
      deviceOpened.push(nodeEnd);
      wake();
      return device;
    },
    close() {
      closed();
    },
  };
  const options = [];
  const factory = (url, opts) => {
    options.push({ url, ...opts });
    queueMicrotask(async () => {
      const control = await node.offer();
      await serve({ ...node, control, reader: new FrameReader(control.readable) });
    });
    return transport;
  };
  return { factory, options };
}

function credential(token = "tok") {
  const proofs = [];
  return {
    proofs,
    token,
    prover: {
      async jkt() {
        return "jkt";
      },
      async proof(htm, htu, accessToken) {
        proofs.push({ htm, htu, accessToken });
        return `proof:${htu}`;
      },
    },
  };
}

test("a frame is JSON behind a little-endian length, and too large a frame is refused", () => {
  const wire = encodeFrame({ type: "accept" });
  const body = Buffer.from('{"type":"accept"}');
  assert.deepEqual(Buffer.from(wire.subarray(0, 4)), Buffer.from([body.length, 0, 0, 0]));
  assert.deepEqual(Buffer.from(wire.subarray(4)), body);
  assert.throws(() => encodeFrame({ type: "refused", reason: "x".repeat(16 * 1024) }));
});

test("a frame reader hands over the bytes that follow the frames", async () => {
  const p = pipe();
  const w = p.writable.getWriter();
  const head = encodeFrame({ type: "opened", device: "laptop" });
  // One chunk carries the frame and the first payload bytes together.
  await w.write(new Uint8Array([...head, 1, 2, 3]));
  await w.write(new Uint8Array([4, 5]));
  await w.close();
  const reader = new FrameReader(p.readable);
  assert.deepEqual(await reader.next(), { type: "opened", device: "laptop" });
  assert.deepEqual([...(await readAll(reader.rest()))], [1, 2, 3, 4, 5]);
});

test("a session signs in with a proof made over its own challenge, unpooled", async () => {
  const seen = [];
  const { factory, options } = standIn(async ({ control, reader }) => {
    await send(control, { type: "challenge", nonce: "n1" });
    seen.push(await reader.next());
    await send(control, { type: "welcome", did: "did:a", device: "jkt", expires_at: 99 });
  });
  const cred = credential();
  const hash = { algorithm: "sha-256", value: new Uint8Array(32) };
  const session = await AppSession.connect("https://node/app", cred, {
    webTransport: factory,
    serverCertificateHashes: [hash],
  });
  assert.equal(session.did, "did:a");
  assert.equal(session.expiresAt, 99);
  assert.deepEqual(cred.proofs, [{ htm: "POST", htu: signInHtu("n1"), accessToken: "tok" }]);
  assert.equal(signInHtu("n1"), "tenzro-app://n1");
  assert.deepEqual(seen, [{ type: "hello", access_token: "tok", dpop: "proof:tenzro-app://n1" }]);
  assert.equal(options[0].allowPooling, false);
  assert.deepEqual(options[0].serverCertificateHashes, [hash]);
});

test("a refused sign-in fails with the node's reason", async () => {
  const { factory } = standIn(async ({ control, reader }) => {
    await send(control, { type: "challenge", nonce: "n" });
    await reader.next();
    await send(control, { type: "refused", reason: "sign in with an access token of this node" });
  });
  await assert.rejects(
    AppSession.connect("https://node/app", credential(), { webTransport: factory }),
    /access token of this node/,
  );
});

test("listen, open and accept carry their frames and then the bytes", async () => {
  const { factory } = standIn(async (node) => {
    const { control, reader } = node;
    await send(control, { type: "challenge", nonce: "n" });
    await reader.next();
    await send(control, { type: "welcome", did: "did:a", device: "phone", expires_at: 99 });
    assert.deepEqual(await reader.next(), { type: "listen", from: ["did:b"], apps: [] });
    await send(control, { type: "listening" });

    // The device opens a stream; the node answers and echoes it back.
    const opened = await node.opened();
    const head = new FrameReader(opened.readable);
    assert.deepEqual(await head.next(), {
      type: "open",
      to: "did:b",
      device: null,
      via: null,
      app: "messenger",
    });
    await send(opened, { type: "opened", device: "laptop" });
    const echo = opened.writable.getWriter();
    for await (const chunk of head.rest()) await echo.write(chunk);
    await echo.close();

    // Then offers it a stream from did:b.
    const offered = await node.offer();
    await send(offered, { type: "incoming", from: "did:b", device: "laptop", via: null, app: "files" });
    const answer = new FrameReader(offered.readable);
    assert.deepEqual(await answer.next(), { type: "accept" });
    const w = offered.writable.getWriter();
    await w.write(new Uint8Array([9, 9]));
    await w.close();
  });
  const session = await AppSession.connect("https://node/app", credential(), { webTransport: factory });
  await session.listen({ from: ["did:b"] });

  const stream = await session.open("did:b", "messenger");
  assert.equal(stream.device, "laptop");
  const w = stream.writable.getWriter();
  await w.write(new Uint8Array([1, 2, 3]));
  await w.close();
  assert.deepEqual([...(await readAll(stream.readable))], [1, 2, 3]);

  for await (const incoming of session.incoming()) {
    assert.equal(incoming.from, "did:b");
    assert.equal(incoming.app, "files");
    const accepted = await incoming.accept();
    assert.deepEqual([...(await readAll(accepted.readable))], [9, 9]);
    break;
  }
});

test("a refused open fails with the node's reason", async () => {
  const { factory } = standIn(async (node) => {
    await send(node.control, { type: "challenge", nonce: "n" });
    await node.reader.next();
    await send(node.control, { type: "welcome", did: "did:a", device: "p", expires_at: 9 });
    const opened = await node.opened();
    await new FrameReader(opened.readable).next();
    await send(opened, { type: "refused", reason: "no device of that identity takes this stream" });
  });
  const session = await AppSession.connect("https://node/app", credential(), { webTransport: factory });
  await assert.rejects(session.open("did:b", "messenger"), /no device of that identity/);
});

test("the publication preimage hashes to the digest the node signs", () => {
  const preimage = publicationPreimage(VECTOR.issuer, VECTOR.listener, VECTOR.hashes, VECTOR.signed_at);
  assert.equal(crypto.createHash("sha256").update(preimage).digest("hex"), VECTOR_DIGEST);
});

function signedPublication(overrides = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const body = { ...VECTOR, ...overrides };
  const preimage = publicationPreimage(body.issuer, body.listener, body.hashes, body.signed_at);
  const signature = crypto
    .sign("sha256", preimage, { key: privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64url");
  return {
    publication: { ...body, kid: "kid", signature },
    nodeKey: publicKey.export({ format: "jwk" }),
  };
}

test("a publication gives the hashes valid now, and only from the node it names", async () => {
  const { publication, nodeKey } = signedPublication();
  const expect = { issuer: VECTOR.issuer, listener: "app-transport", nodeKey, now: 1800000100 };

  const pinned = await verifyPublication(publication, expect);
  assert.equal(pinned.length, 1, "the next certificate is not valid yet");
  assert.deepEqual([...pinned[0].value], new Array(32).fill(0x11));

  // Later, once the next certificate's validity has started, both are kept.
  const later = await verifyPublication(publication, { ...expect, now: 1800428500, maxAgeSecs: 1e9 });
  assert.equal(later.length, 2);

  await assert.rejects(verifyPublication(publication, { ...expect, issuer: "did:tenzro:machine:b" }));
  await assert.rejects(verifyPublication(publication, { ...expect, listener: "paired-devices" }));
  await assert.rejects(verifyPublication(publication, { ...expect, now: 1800000005 + 86401 }), /too old/);
  await assert.rejects(verifyPublication(publication, { ...expect, now: 1799990000 }), /future/);

  const other = signedPublication();
  await assert.rejects(verifyPublication(publication, { ...expect, nodeKey: other.nodeKey }), /not signed/);

  const tampered = { ...publication, hashes: [{ ...publication.hashes[0], not_after: 1901119600 }] };
  await assert.rejects(verifyPublication(tampered, expect), /not signed/);
});

test("a publication whose certificates have all ended pins nothing", async () => {
  const { publication, nodeKey } = signedPublication();
  await assert.rejects(
    verifyPublication(publication, {
      issuer: VECTOR.issuer,
      listener: "app-transport",
      nodeKey,
      now: 1801551600,
      maxAgeSecs: 1e9,
    }),
    /no certificate/,
  );
});

test("the welcome preimage hashes to the digest the node signs", () => {
  const preimage = welcomePreimage("n1", "did:tenzro:human:a", "phone", 1800000000);
  assert.equal(crypto.createHash("sha256").update(preimage).digest("hex"), WELCOME_DIGEST);
});

test("a welcome passes only with the node's signatures over this session's nonce", async () => {
  const node = nodeKeys();
  const welcome = node.welcome("n1", "did:a", "phone", 99);
  const keys = { nodeKey: node.nodeKey, pq: standInPq };
  await verifyWelcome(welcome, "n1", keys);
  await assert.rejects(verifyWelcome(welcome, "n2", keys), /not signed by the node's key/);
  await assert.rejects(
    verifyWelcome({ ...welcome, expires_at: 100 }, "n1", keys),
    /not signed by the node's key/,
  );
  await assert.rejects(
    verifyWelcome(welcome, "n1", { nodeKey: nodeKeys().nodeKey }),
    /not signed by the node's key/,
  );
  await assert.rejects(
    verifyWelcome({ ...welcome, pq_signature: "AAAA" }, "n1", keys),
    /ML-DSA-65/,
  );
});

test("a session with the node's keys refuses a welcome another key signed, at sign-in and renewal", async () => {
  const node = nodeKeys();
  const impostor = nodeKeys();
  const signIn = (signer) =>
    standIn(async ({ control, reader }) => {
      await send(control, { type: "challenge", nonce: "n1" });
      await reader.next();
      await send(control, signer.welcome("n1", "did:a", "phone", 99));
      await reader.next();
      await send(control, impostor.welcome("n1", "did:a", "phone", 199));
    });
  const welcomeKeys = { nodeKey: node.nodeKey, pq: standInPq };
  await assert.rejects(
    AppSession.connect("https://node/app", credential(), {
      webTransport: signIn(impostor).factory,
      welcomeKeys,
    }),
    /not signed by the node's key/,
  );
  const session = await AppSession.connect("https://node/app", credential(), {
    webTransport: signIn(node).factory,
    welcomeKeys,
  });
  assert.equal(session.expiresAt, 99);
  await assert.rejects(session.renew(credential()), /not signed by the node's key/);
  assert.equal(session.expiresAt, 99, "a renewal that does not verify changes nothing");
});

test("the info and usage bindings call the node's methods", async () => {
  const calls = [];
  const rpc = {
    async call(method, params) {
      calls.push([method, params]);
      return { method };
    },
  };
  assert.deepEqual(await appTransportInfo(rpc), { method: "tenzro_getAppTransportInfo" });
  assert.deepEqual(await appTransportUsage(rpc), { method: "tenzro_getAppTransportUsage" });
  assert.deepEqual(calls, [
    ["tenzro_getAppTransportInfo", {}],
    ["tenzro_getAppTransportUsage", {}],
  ]);
});

test("a node that asks payment gets the payer's credential on a second hello", async () => {
  const hellos = [];
  const quoted = [];
  const { factory } = standIn(async ({ control, reader }) => {
    await send(control, { type: "challenge", nonce: "n1" });
    hellos.push(await reader.next());
    await send(control, { type: "payment_required", challenge: "{\"amount\":\"30\"}", price: "3", asset: "TNZO" });
    hellos.push(await reader.next());
    await send(control, { type: "welcome", did: "did:a", device: "phone", expires_at: 99 });
  });
  const session = await AppSession.connect("https://node/app", credential(), {
    webTransport: factory,
    pay: async (challenge, price, asset) => {
      quoted.push({ challenge, price, asset });
      return "credential";
    },
  });
  assert.equal(session.did, "did:a");
  assert.deepEqual(quoted, [{ challenge: '{"amount":"30"}', price: "3", asset: "TNZO" }]);
  assert.equal(hellos[0].payment, undefined);
  assert.equal(hellos[1].payment, "credential");

  const { factory: asks } = standIn(async ({ control, reader }) => {
    await send(control, { type: "challenge", nonce: "n1" });
    await reader.next();
    await send(control, { type: "payment_required", challenge: "{}", price: "3", asset: "TNZO" });
  });
  await assert.rejects(
    AppSession.connect("https://node/app", credential(), { webTransport: asks }),
    /give a payer/,
  );
});

test("datagrams carry their flow id ahead of the payload, both ways", async () => {
  let node;
  const { factory } = standIn(async (n) => {
    node = n;
    await send(n.control, { type: "challenge", nonce: "n1" });
    await n.reader.next();
    await send(n.control, { type: "welcome", did: "did:a", device: "phone", expires_at: 99 });
  });
  const session = await AppSession.connect("https://node/app", credential(), { webTransport: factory });
  const reading = node.sentDatagrams.getReader().read();
  await session.sendDatagram(7, new Uint8Array([1, 2, 3]));
  const sent = await reading;
  assert.deepEqual([...sent.value], [7, 0, 0, 0, 1, 2, 3]);
  const writing = node.datagramWriter.write(new Uint8Array([9, 0, 0, 0, 4, 5]));
  const got = await session.datagrams().next();
  await writing;
  assert.equal(got.value.flow, 9);
  assert.deepEqual([...got.value.payload], [4, 5]);
});
