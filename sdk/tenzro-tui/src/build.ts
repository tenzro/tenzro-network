// Which build this console is. The digest covers every file of the built
// console, so a person given the digest of a release (the signed release
// notice states it for the bundle named `tenzro-tui`; here it is an input,
// never fetched) can tell whether the console in front of them is that
// release or something else.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Every regular file under `dir`, as a path relative to it with "/" separators. A link is not followed. */
function files(dir: string, under = ""): string[] {
  return fs
    .readdirSync(path.join(dir, under), { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? files(dir, path.posix.join(under, e.name)) : e.isFile() ? [path.posix.join(under, e.name)] : []));
}

const sha256Hex = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");

/**
 * The bundle digest of `dir`, as the release notice states it: one line per
 * regular file, `<sha256 of the file>  <path>\n`, with the paths sorted by
 * their bytes, and the SHA-256 of those lines together. The same as running
 * `find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum | sha256sum`
 * inside `dir`. Renaming, adding, removing or changing any file changes it.
 * @throws when `dir` holds no file: an empty tree has no digest
 */
export function digestOf(dir: string): string {
  const paths = files(dir).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  if (paths.length === 0) throw new Error(`${dir} holds no file, so it has no digest`);
  return sha256Hex(paths.map((rel) => `${sha256Hex(fs.readFileSync(path.join(dir, rel)))}  ${rel}\n`).join(""));
}

/** The directory holding the running console's own built source files. */
export function ownDir(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

/** Whether `expected` (64 hex digits, any case) is the digest `actual`. */
export function sameDigest(expected: string, actual: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(expected.trim()) && expected.trim().toLowerCase() === actual;
}
