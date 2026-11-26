/**
 * Run manifests, implemented from `docs/standards/run-manifest.md`: what a
 * harness run (`@tenzrolabs/harness`) consumed and produced, digested and
 * anchored as a version of the account's `<account hex>/runs` entry in the
 * generic registry. The chain keeps every version and never reads the
 * manifest; anyone holding it recomputes the digest and compares the anchor.
 */
import { parseExact } from "@tenzro/core";
import { registryPutTx } from "./pricing";

/** Domain tag the preimage starts with. */
export const RUN_MANIFEST_DOMAIN = "tenzro/run-manifest/v1";
/** The registry kind a run manifest is anchored under. */
export const REGISTRY_KIND_RUN_MANIFEST = "run-manifest";
/** Largest manifest, as JSON text in UTF-8 bytes. */
export const RUN_MANIFEST_MAX_BYTES = 65_536;
/** Largest number of inputs, of outputs, of claims and of interactions. */
export const RUN_MANIFEST_MAX_INPUTS = 64;
export const RUN_MANIFEST_MAX_OUTPUTS = 64;
export const RUN_MANIFEST_MAX_CLAIMS = 32;
export const RUN_MANIFEST_MAX_INTERACTIONS = 256;
/** Longest text field, in UTF-8 bytes. */
export const RUN_MANIFEST_MAX_TEXT = 256;

const U64_MAX = 2n ** 64n - 1n;
const I64_MAX = 2n ** 63n - 1n;
const ZERO = "0".repeat(64);

/**
 * Why a manifest has no digest: `malformed` when a field is missing, has the
 * wrong type or breaks a rule; `too_large` when it passes a bound;
 * `no_output` when it names no output, so states no useful output.
 */
export class RunManifestError extends Error {
  constructor(
    readonly reason: "malformed" | "too_large" | "no_output",
    message: string,
  ) {
    super(`not a run manifest: ${message}`);
  }
}

const malformed = (why: string) => new RunManifestError("malformed", why);
type Json = Record<string, unknown>;
const utf8 = (s: string) => new TextEncoder().encode(s);

function object(value: unknown, what: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw malformed(`${what} is not an object`);
  return value as Json;
}

function text(at: Json, key: string, what: string, nonEmpty = true): Uint8Array {
  const value = at[key];
  if (typeof value !== "string") throw malformed(`\`${what}\` is not a string`);
  // TextEncoder would write a lone surrogate as U+FFFD; such text is not UTF-8.
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) {
    throw malformed(`\`${what}\` holds a lone surrogate`);
  }
  const bytes = utf8(value);
  if (nonEmpty && bytes.length === 0) throw malformed(`\`${what}\` is empty`);
  if (bytes.length > RUN_MANIFEST_MAX_TEXT) throw new RunManifestError("too_large", `\`${what}\` is longer than ${RUN_MANIFEST_MAX_TEXT} bytes`);
  return bytes;
}

function digest(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value) || value === ZERO) {
    throw malformed(`\`${what}\` is not a non-zero 64-character lower-case hex digest`);
  }
  return Uint8Array.from(value.match(/../g)!, (h) => parseInt(h, 16));
}

function whole(value: unknown, max: bigint, what: string): bigint {
  const n = typeof value === "bigint" ? value : typeof value === "number" && Number.isSafeInteger(value) ? BigInt(value) : undefined;
  if (n === undefined || n < 0n || n > max) throw malformed(`\`${what}\` is not a whole number`);
  return n;
}

function list(at: Json, key: string, max: number): unknown[] {
  const value = at[key];
  if (!Array.isArray(value)) throw malformed(`\`${key}\` is not a list`);
  if (value.length > max) throw new RunManifestError("too_large", `\`${key}\` has more than ${max} entries`);
  return value;
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

const field = (bytes: Uint8Array) => [u32le(bytes.length), bytes];

function named(entries: unknown[], what: string, withBytes: boolean): Uint8Array[] {
  const seen = new Set<string>();
  return entries.flatMap((entry, i) => {
    const e = object(entry, `${what}[${i}]`);
    const name = text(e, "name", `${what}[${i}].name`);
    const key = new TextDecoder().decode(name);
    if (seen.has(key)) throw malformed(`\`${what}\` names \`${key}\` twice`);
    seen.add(key);
    const parts = [...field(name), ...field(digest(e.digest, `${what}[${i}].digest`))];
    if (withBytes) parts.push(u64le(whole(e.bytes, U64_MAX, `${what}[${i}].bytes`)));
    return parts;
  });
}

/**
 * The bytes the digest is taken over. `manifest` is the manifest's JSON text,
 * or the value `parseExact` made of it.
 */
export function runManifestPreimage(manifest: unknown): Uint8Array {
  if (typeof manifest === "string" && utf8(manifest).length > RUN_MANIFEST_MAX_BYTES) {
    throw new RunManifestError("too_large", `the manifest is longer than ${RUN_MANIFEST_MAX_BYTES} bytes`);
  }
  const m = object(typeof manifest === "string" ? parseExact(manifest) : manifest, "the manifest");
  const started = whole(m.started_at_ms, I64_MAX, "started_at_ms");
  const ended = whole(m.ended_at_ms, I64_MAX, "ended_at_ms");
  if (ended < started) throw malformed("`ended_at_ms` is before `started_at_ms`");
  const inputs = list(m, "inputs", RUN_MANIFEST_MAX_INPUTS);
  const outputs = list(m, "outputs", RUN_MANIFEST_MAX_OUTPUTS);
  const claims = list(m, "claims", RUN_MANIFEST_MAX_CLAIMS);
  const interactions = list(m, "interactions", RUN_MANIFEST_MAX_INTERACTIONS);
  if (outputs.length === 0) throw new RunManifestError("no_output", "`outputs` is empty");
  const parts: Uint8Array[] = [
    utf8(RUN_MANIFEST_DOMAIN),
    ...field(text(m, "run_id", "run_id")),
    ...field(text(m, "operator_did", "operator_did")),
    ...field(digest(m.harness_module, "harness_module")),
    u64le(started),
    u64le(ended),
    u32le(inputs.length),
    ...named(inputs, "inputs", false),
    u32le(outputs.length),
    ...named(outputs, "outputs", true),
    u32le(claims.length),
    ...claims.flatMap((claim, i) => {
      const c = object(claim, `claims[${i}]`);
      const value = text(c, "value", `claims[${i}].value`);
      if (!/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(new TextDecoder().decode(value))) {
        throw malformed(`\`claims[${i}].value\` is not a decimal number`);
      }
      return [...field(text(c, "metric", `claims[${i}].metric`)), ...field(value), ...field(text(c, "unit", `claims[${i}].unit`, false))];
    }),
    u32le(interactions.length),
    ...interactions.flatMap((d, i) => field(digest(d, `interactions[${i}]`))),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The manifest's digest, lower-case hex: the registry anchor of its run. */
export async function runManifestDigest(manifest: unknown): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(runManifestPreimage(manifest))));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The registry id an account anchors its runs under. */
export function runsRegistryId(accountHex: string): string {
  const account = accountHex.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(account)) throw malformed("the account is not 64 hex characters");
  return `${account}/runs`;
}

/**
 * The transaction that anchors `manifest` as the next version of the
 * account's runs entry. The manifest itself stays off chain.
 */
export async function runManifestPutTx(accountHex: string, manifest: unknown) {
  return registryPutTx(runsRegistryId(accountHex), REGISTRY_KIND_RUN_MANIFEST, await runManifestDigest(manifest), new Uint8Array());
}
