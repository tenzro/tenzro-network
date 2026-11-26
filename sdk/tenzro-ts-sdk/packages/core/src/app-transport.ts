/**
 * The app transport: a device of an application signs in to a Tenzro node
 * over WebTransport and opens streams to devices of other identities, which
 * the node carries and counts against the identity that opened them.
 *
 * Whatever travels inside a stream is the application's own: seal it end to
 * end before writing it. The node only moves the bytes.
 *
 * Preview: the node serves this only when its operator turned it on, and the
 * wire format may still change.
 */
import type { AccessCredential } from "./access";
import type { RpcClient } from "./rpc";

/** One certificate a client may pin. */
export interface PinnedHash {
  /** SHA-256 of the certificate's DER encoding, hex. */
  sha256: string;
  /** Start of its validity, seconds since the epoch. */
  not_before: number;
  /** End of its validity, seconds since the epoch. */
  not_after: number;
}

/** The certificates of one listener of a node, signed by that node. */
export interface CertificatePublication {
  /** The node that serves the listener. */
  issuer: string;
  /** Which of the node's listeners these certificates belong to. */
  listener: string;
  /** The certificate served now, then the one served next. */
  hashes: PinnedHash[];
  /** When the node signed this, seconds since the epoch. */
  signed_at: number;
  /** Key id of the signing key: the one the node's access tokens name. */
  kid: string;
  /** ECDSA P-256 signature (`r || s`, base64url) over the publication. */
  signature: string;
}

/** Where devices reach a node's app transport, from `tenzro_getAppTransportInfo`. */
export interface AppTransportInfo {
  /** The URL to open a session at. */
  url: string;
  /** The certificates to pin, signed by the node; `null` when it serves a
   * certificate the runtime trusts on its own. */
  publication: CertificatePublication | null;
}

/** What the app transport carried for one identity. */
export interface AppTransportCounts {
  /** Streams it opened that reached their target. */
  streams: number;
  /** Bytes carried from it. */
  bytes_sent: number;
  /** Bytes carried to it. */
  bytes_received: number;
}

/** `tenzro_getAppTransportUsage`: the caller's own counts, or every identity's
 * when the caller administers the node. */
export type AppTransportUsage =
  | { did: string; usage: AppTransportCounts }
  | { all: { did: string; usage: AppTransportCounts }[] };

/**
 * Where devices reach the node's app transport, and the certificates to pin.
 *
 * @throws Error when the node runs no app transport.
 */
export function appTransportInfo(rpc: RpcClient): Promise<AppTransportInfo> {
  return rpc.call<AppTransportInfo>("tenzro_getAppTransportInfo", {});
}

/**
 * What the node's app transport carried for the signed-in caller, or for
 * every identity when the caller administers the node.
 *
 * @throws Error when the caller is not signed in or the node runs no app transport.
 */
export function appTransportUsage(rpc: RpcClient): Promise<AppTransportUsage> {
  return rpc.call<AppTransportUsage>("tenzro_getAppTransportUsage", {});
}

/** What {@link verifyPublication} expects of a publication. */
export interface PublicationExpectation {
  /** The node the caller means to reach. */
  issuer: string;
  /** The listener the caller means to reach; `app-transport` for this one. */
  listener: string;
  /** The node's access-token key, as the JWK it publishes. */
  nodeKey: JsonWebKey;
  /** The time to judge by, seconds since the epoch; now when absent. */
  now?: number;
  /** How old a publication may be, seconds; a day when absent. */
  maxAgeSecs?: number;
}

/** A certificate hash in the form WebTransport takes it. */
export interface CertificateHash {
  algorithm: "sha-256";
  value: Uint8Array;
}

const PUBLICATION_DOMAIN = "tenzro/pinned-cert/v1";
const DAY_SECS = 24 * 60 * 60;
const CLOCK_SKEW_SECS = 5 * 60;

/** Frames above this size are refused, as the node refuses them. */
export const MAX_FRAME_BYTES = 16 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function u64(value: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

function hexBytes(hex: string, length: number): Uint8Array<ArrayBuffer> {
  if (hex.length !== length * 2 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`expected ${length} bytes of hex, got ${hex}`);
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * The bytes a publication's signature covers: the domain, the issuer and the
 * listener each behind its length, the signing time, then every hash with
 * its validity; integers are 64-bit big-endian. The node signs their SHA-256.
 */
export function publicationPreimage(
  issuer: string,
  listener: string,
  hashes: PinnedHash[],
  signedAt: number,
): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [encoder.encode(PUBLICATION_DOMAIN)];
  for (const text of [issuer, listener]) {
    const bytes = encoder.encode(text);
    parts.push(u64(bytes.length), bytes);
  }
  parts.push(u64(signedAt), u64(hashes.length));
  for (const h of hashes) {
    parts.push(hexBytes(h.sha256, 32), u64(h.not_before), u64(h.not_after));
  }
  return concat(parts);
}

/**
 * Checks a node's certificate publication and returns the hashes to pin.
 *
 * A publication carries no expiry of its own: it is refused when it names
 * another node or listener, when its signature is not the node's, when it was
 * signed in the future or longer ago than `maxAgeSecs`, and each hash is
 * kept only while its certificate is valid. Pass the result to
 * {@link AppSession.connect}.
 *
 * @throws Error when the publication is not one to trust.
 */
export async function verifyPublication(
  publication: CertificatePublication,
  expect: PublicationExpectation,
): Promise<CertificateHash[]> {
  const now = expect.now ?? Math.floor(Date.now() / 1000);
  if (publication.issuer !== expect.issuer) {
    throw new Error(`publication is from ${publication.issuer}, not ${expect.issuer}`);
  }
  if (publication.listener !== expect.listener) {
    throw new Error(`publication is for ${publication.listener}, not ${expect.listener}`);
  }
  if (publication.signed_at > now + CLOCK_SKEW_SECS) {
    throw new Error("publication is signed in the future");
  }
  if (now - publication.signed_at > (expect.maxAgeSecs ?? DAY_SECS)) {
    throw new Error("publication is too old; fetch it again");
  }
  const key = await crypto.subtle.importKey(
    "jwk",
    expect.nodeKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const preimage = publicationPreimage(
    publication.issuer,
    publication.listener,
    publication.hashes,
    publication.signed_at,
  );
  const signed = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    fromBase64Url(publication.signature),
    preimage,
  );
  if (!signed) throw new Error("publication is not signed by the node's key");
  const current = publication.hashes.filter(
    (h) => h.not_before <= now + CLOCK_SKEW_SECS && now < h.not_after,
  );
  if (current.length === 0) throw new Error("no certificate in the publication is valid now");
  return current.map((h) => ({ algorithm: "sha-256", value: hexBytes(h.sha256, 32) }));
}

const WELCOME_DOMAIN = "tenzro/app-transport/welcome/v1";

/** FIPS 204 context of a welcome's ML-DSA-65 signature. */
export const WELCOME_PQ_CONTEXT = "tenzro/app-transport/welcome";

/**
 * The bytes a welcome's signatures cover: the domain, then the session's
 * nonce, the DID and the device each behind its length, then `expires_at`;
 * integers are 64-bit big-endian. The node signs their SHA-256.
 */
export function welcomePreimage(
  nonce: string,
  did: string,
  device: string,
  expiresAt: number,
): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [encoder.encode(WELCOME_DOMAIN)];
  for (const text of [nonce, did, device]) {
    const bytes = encoder.encode(text);
    parts.push(u64(bytes.length), bytes);
  }
  parts.push(u64(expiresAt));
  return concat(parts);
}

/** Checks ML-DSA-65 signatures; the SDK ships no implementation of its own. */
export interface MlDsaVerifier {
  /** The node's ML-DSA-65 key: `#pq-key-1` of its DID document. */
  publicKey: Uint8Array;
  /** Whether `signature` is `publicKey`'s over `message` under `context`. */
  verify(
    publicKey: Uint8Array,
    context: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): boolean | Promise<boolean>;
}

/** The node keys {@link verifyWelcome} checks a welcome against. */
export interface WelcomeKeys {
  /** The node's access-token key, as the JWK it publishes. */
  nodeKey: JsonWebKey;
  /** Checks the ML-DSA-65 signature too, when given. */
  pq?: MlDsaVerifier;
}

type Welcome = Extract<Frame, { type: "welcome" }>;

/**
 * Checks that a welcome was signed by the node over this session's `nonce`:
 * by its access-token key and, when `keys.pq` is given, by its ML-DSA-65 key.
 *
 * @throws Error when a signature is not the node's.
 */
export async function verifyWelcome(welcome: Welcome, nonce: string, keys: WelcomeKeys): Promise<void> {
  const preimage = welcomePreimage(nonce, welcome.did, welcome.device, welcome.expires_at);
  const key = await crypto.subtle.importKey(
    "jwk",
    keys.nodeKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signed = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    fromBase64Url(welcome.signature),
    preimage,
  );
  if (!signed) throw new Error("the welcome is not signed by the node's key");
  if (keys.pq) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
    const pqSigned = await keys.pq.verify(
      keys.pq.publicKey,
      encoder.encode(WELCOME_PQ_CONTEXT),
      digest,
      fromBase64Url(welcome.pq_signature),
    );
    if (!pqSigned) throw new Error("the welcome is not signed by the node's ML-DSA-65 key");
  }
}

/** What is said on a session's control stream and at the head of a stream. */
export type Frame =
  | { type: "challenge"; nonce: string }
  | { type: "hello"; access_token: string; dpop: string; payment?: string; binding?: string }
  | { type: "payment_required"; challenge: string; price: string; asset: string }
  | {
      type: "welcome";
      did: string;
      device: string;
      expires_at: number;
      signature: string;
      pq_signature: string;
    }
  | { type: "listen"; from: string[]; apps: string[] }
  | { type: "listening" }
  | { type: "open"; to: string; device: string | null; via: string | null; app: string }
  | { type: "incoming"; from: string; device: string; via: string | null; app: string; flow?: number }
  | { type: "accept" }
  | { type: "decline" }
  | { type: "opened"; device: string; flow?: number }
  | { type: "refused"; reason: string };

/** A frame on the wire: a little-endian 32-bit length, then that much JSON. */
export function encodeFrame(frame: Frame): Uint8Array {
  const body = encoder.encode(JSON.stringify(frame));
  if (body.length > MAX_FRAME_BYTES) {
    throw new Error(`frame of ${body.length} bytes exceeds ${MAX_FRAME_BYTES}`);
  }
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, body.length, true);
  out.set(body, 4);
  return out;
}

/** Reads frames off a stream, then hands over what follows them. */
export class FrameReader {
  private buffered: Uint8Array = new Uint8Array(0);
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  private async fill(length: number): Promise<boolean> {
    while (this.buffered.length < length) {
      const { value, done } = await this.reader.read();
      if (done) return false;
      this.buffered = concat([this.buffered, value]);
    }
    return true;
  }

  /** The next frame, or `null` when the stream ended first. */
  async next(): Promise<Frame | null> {
    if (!(await this.fill(4))) return null;
    const length = new DataView(
      this.buffered.buffer,
      this.buffered.byteOffset,
      4,
    ).getUint32(0, true);
    if (length > MAX_FRAME_BYTES) throw new Error(`frame of ${length} bytes exceeds ${MAX_FRAME_BYTES}`);
    if (!(await this.fill(4 + length))) return null;
    const body = this.buffered.subarray(4, 4 + length);
    this.buffered = this.buffered.slice(4 + length);
    return JSON.parse(decoder.decode(body)) as Frame;
  }

  /** The rest of the stream as bytes, starting with any already read. */
  rest(): ReadableStream<Uint8Array> {
    const reader = this.reader;
    let first: Uint8Array | null = this.buffered.length > 0 ? this.buffered : null;
    this.buffered = new Uint8Array(0);
    return new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (first) {
          controller.enqueue(first);
          first = null;
          return;
        }
        const { value, done } = await reader.read();
        if (done) controller.close();
        else controller.enqueue(value);
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    });
  }
}

/** The part of a WebTransport bidirectional stream used here. */
export interface BidiStream {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

/** The part of a browser `WebTransport` session used here. */
export interface WebTransportLike {
  readonly ready: Promise<unknown>;
  readonly closed: Promise<unknown>;
  readonly incomingBidirectionalStreams: ReadableStream<BidiStream>;
  readonly datagrams: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
  createBidirectionalStream(): Promise<BidiStream>;
  close(info?: { closeCode?: number; reason?: string }): void;
}

/** Makes a session the way the browser's `WebTransport` constructor does. */
export type WebTransportFactory = (
  url: string,
  options: {
    serverCertificateHashes?: CertificateHash[];
    allowPooling: boolean;
  },
) => WebTransportLike;

function browserWebTransport(): WebTransportFactory {
  const ctor = (globalThis as { WebTransport?: new (url: string, options: object) => WebTransportLike })
    .WebTransport;
  if (!ctor) throw new Error("this runtime has no WebTransport");
  return (url, options) => new ctor(url, options);
}

/** A stream between two devices, once the far device took it. */
export interface AppStream {
  /** The device at the other end. */
  device: string;
  /** The flow datagrams to and from that device travel under while the
   * stream lasts; `null` for a stream through another node. */
  flow: number | null;
  /** Bytes from the other device. */
  readable: ReadableStream<Uint8Array>;
  /** Bytes to the other device. Close it to say you are done sending. */
  writable: WritableStream<Uint8Array>;
}

/** A stream another device opened to this one, waiting for an answer. */
export interface IncomingStream {
  /** The identity that opened it. */
  from: string;
  /** The device it was opened from. */
  device: string;
  /** The node that carried it here, when not the one this device uses. */
  via: string | null;
  /** The application label it was opened with. */
  app: string;
  /** Takes the stream. */
  accept(): Promise<AppStream>;
  /** Turns it down. */
  decline(): Promise<void>;
}

/** Options of {@link AppSession.connect}. */
export interface ConnectOptions {
  /** The certificates to pin, from {@link verifyPublication}; leave out when
   * the node serves a certificate the runtime trusts. */
  serverCertificateHashes?: CertificateHash[];
  /** Makes the session; the browser's `WebTransport` when absent. */
  webTransport?: WebTransportFactory;
  /** The node's keys: every welcome is checked against them when given. */
  welcomeKeys?: WelcomeKeys;
  /**
   * Pays when the node's access policy asks payment for carriage: returns a
   * payment credential (JSON) for `challenge` (JSON), whose amount is the
   * most the session may be charged at `price` of `asset` per mebibyte.
   * Without it such a sign-in fails.
   */
  pay?: (challenge: string, price: string, asset: string) => Promise<string>;
}

/** The URI a sign-in proof names: the session's nonce. */
export function signInHtu(nonce: string): string {
  return `tenzro-app://${nonce}`;
}

async function writeFrame(writer: WritableStreamDefaultWriter<Uint8Array>, frame: Frame): Promise<void> {
  await writer.write(encodeFrame(frame));
}

/**
 * A device's session with a node's app transport.
 *
 * @example
 * const info = await rpc.call("tenzro_getAppTransportInfo", {});
 * const hashes = await verifyPublication(info.publication, { issuer, listener: "app-transport", nodeKey });
 * const session = await AppSession.connect(info.url, credential, {
 *   serverCertificateHashes: hashes,
 *   welcomeKeys: { nodeKey },
 * });
 * await session.listen({ from: [friendDid] });
 * const stream = await session.open(friendDid, "messenger");
 */
export class AppSession {
  private constructor(
    private readonly transport: WebTransportLike,
    private readonly control: FrameReader,
    private readonly controlWriter: WritableStreamDefaultWriter<Uint8Array>,
    private readonly incomingStreams: ReadableStreamDefaultReader<BidiStream>,
    private readonly nonce: string,
    /** The identity the node took this device for. */
    public readonly did: string,
    /** This device, as the node names it. */
    public readonly device: string,
    private expires: number,
    private readonly welcomeKeys: WelcomeKeys | undefined,
  ) {}

  /** When the session ends unless renewed, seconds since the epoch. */
  get expiresAt(): number {
    return this.expires;
  }

  /**
   * Opens a session at `url` and signs in with `credential`.
   *
   * @throws Error when the node refuses the sign-in.
   */
  static async connect(
    url: string,
    credential: AccessCredential,
    options: ConnectOptions = {},
  ): Promise<AppSession> {
    const make = options.webTransport ?? browserWebTransport();
    // A pooled session would share its connection with other pages, and a
    // pinned certificate is not allowed on one.
    const transport = make(url, {
      serverCertificateHashes: options.serverCertificateHashes,
      allowPooling: false,
    });
    await transport.ready;
    const incoming = transport.incomingBidirectionalStreams.getReader();
    const first = await incoming.read();
    if (first.done) throw new Error("the node closed the session");
    const control = new FrameReader(first.value.readable);
    const controlWriter = first.value.writable.getWriter();
    const challenge = await control.next();
    if (challenge?.type !== "challenge") throw new Error("the node sent no challenge");
    const hello = async (payment?: string): Promise<Frame> => ({
      type: "hello",
      access_token: credential.token,
      dpop: await credential.prover.proof("POST", signInHtu(challenge.nonce), credential.token),
      ...(payment === undefined ? {} : { payment }),
    });
    await writeFrame(controlWriter, await hello());
    let answer = await control.next();
    if (answer?.type === "payment_required") {
      if (!options.pay) {
        transport.close();
        throw new Error(`the node asks ${answer.price} ${answer.asset} a mebibyte for carriage; give a payer`);
      }
      const payment = await options.pay(answer.challenge, answer.price, answer.asset);
      await writeFrame(controlWriter, await hello(payment));
      answer = await control.next();
    }
    if (answer?.type !== "welcome") {
      transport.close();
      throw new Error(answer?.type === "refused" ? answer.reason : "the node refused the sign-in");
    }
    if (options.welcomeKeys) {
      try {
        await verifyWelcome(answer, challenge.nonce, options.welcomeKeys);
      } catch (e) {
        transport.close();
        throw e;
      }
    }
    return new AppSession(
      transport,
      control,
      controlWriter,
      incoming,
      challenge.nonce,
      answer.did,
      answer.device,
      answer.expires_at,
      options.welcomeKeys,
    );
  }

  /** The control stream's last exchange; each waits for the one before. */
  private turn: Promise<unknown> = Promise.resolve();

  private ask(frame: Frame): Promise<Frame> {
    const exchange = this.turn.then(async () => {
      await writeFrame(this.controlWriter, frame);
      const answer = await this.control.next();
      if (!answer) throw new Error("the session ended");
      return answer;
    });
    this.turn = exchange.catch(() => undefined);
    return exchange;
  }

  /**
   * Says who may open streams to this device from now on: the identities in
   * `from`, and anyone opening with a label in `apps`. Until it is called,
   * nobody can.
   */
  async listen(who: { from?: string[]; apps?: string[] }): Promise<void> {
    const answer = await this.ask({ type: "listen", from: who.from ?? [], apps: who.apps ?? [] });
    if (answer.type !== "listening") throw new Error("the node did not take the listen");
  }

  /**
   * Keeps the session past its token's end with a fresh token for the same
   * identity and device.
   *
   * @throws Error when the node refuses it; the session then ends.
   */
  async renew(credential: AccessCredential): Promise<void> {
    const answer = await this.ask({
      type: "hello",
      access_token: credential.token,
      dpop: await credential.prover.proof("POST", signInHtu(this.nonce), credential.token),
    });
    if (answer.type !== "welcome") throw new Error("the node refused the renewal");
    if (this.welcomeKeys) await verifyWelcome(answer, this.nonce, this.welcomeKeys);
    this.expires = answer.expires_at;
  }

  /**
   * Opens a stream to a device of `to`, with the application label `app`.
   *
   * @throws Error when no device of `to` takes it.
   */
  async open(to: string, app: string, target: { device?: string; via?: string } = {}): Promise<AppStream> {
    const stream = await this.transport.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    await writeFrame(writer, {
      type: "open",
      to,
      device: target.device ?? null,
      via: target.via ?? null,
      app,
    });
    writer.releaseLock();
    const reader = new FrameReader(stream.readable);
    const answer = await reader.next();
    if (answer?.type !== "opened") {
      throw new Error(answer?.type === "refused" ? answer.reason : "the stream was not opened");
    }
    return {
      device: answer.device,
      flow: answer.flow ?? null,
      readable: reader.rest(),
      writable: stream.writable,
    };
  }

  /**
   * Sends `payload` as a datagram on `flow` (an {@link AppStream.flow}). A
   * datagram may be lost, and the node drops one its meter has no room for.
   */
  async sendDatagram(flow: number, payload: Uint8Array): Promise<void> {
    const datagram = new Uint8Array(4 + payload.length);
    new DataView(datagram.buffer).setUint32(0, flow, true);
    datagram.set(payload, 4);
    const writer = this.transport.datagrams.writable.getWriter();
    try {
      await writer.write(datagram);
    } finally {
      writer.releaseLock();
    }
  }

  /** Datagrams from the devices at the other ends of this session's flows. */
  async *datagrams(): AsyncGenerator<{ flow: number; payload: Uint8Array }> {
    const reader = this.transport.datagrams.readable.getReader();
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) return;
        if (next.value.length < 4) continue;
        const view = new DataView(next.value.buffer, next.value.byteOffset, next.value.byteLength);
        yield { flow: view.getUint32(0, true), payload: next.value.subarray(4) };
      }
    } finally {
      reader.releaseLock();
    }
  }

  /** The streams other devices open to this one, as they arrive. */
  async *incoming(): AsyncGenerator<IncomingStream> {
    for (;;) {
      const next = await this.incomingStreams.read();
      if (next.done) return;
      const stream = next.value;
      const reader = new FrameReader(stream.readable);
      const head = await reader.next();
      if (head?.type !== "incoming") continue;
      const answer = async (frame: Frame) => {
        const writer = stream.writable.getWriter();
        await writeFrame(writer, frame);
        writer.releaseLock();
      };
      yield {
        from: head.from,
        device: head.device,
        via: head.via,
        app: head.app,
        accept: async () => {
          await answer({ type: "accept" });
          return {
            device: head.device,
            flow: head.flow ?? null,
            readable: reader.rest(),
            writable: stream.writable,
          };
        },
        decline: async () => {
          await answer({ type: "decline" });
          await stream.writable.close();
        },
      };
    }
  }

  /** Ends the session. */
  close(): void {
    this.transport.close();
  }
}
