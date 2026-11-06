import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

function sources(dir: string): string[] {
  return readdirSync(join(root, dir)).flatMap((name) => {
    const rel = join(dir, name);
    if (statSync(join(root, rel)).isDirectory()) return sources(rel);
    return /\.(ts|tsx|css|html)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [rel] : [];
  });
}

const invoked = new Set(
  [...read("src/lib/api.ts").matchAll(/invoke(?:<[^>]*>)?\(\s*"([a-z_]+)"/g)].map((m) => m[1]),
);
const handler = read("src-tauri/src/lib.rs").split("generate_handler![")[1].split("])")[0];
const registered = new Set(
  [...handler.matchAll(/([a-z_]+(?:::[a-z_]+)*)\s*,/g)].map((m) => m[1].split("::").pop()!),
);
const webview = new Set(
  [...read("src-tauri/build.rs").split("WEBVIEW_COMMANDS")[1].split("];")[0].matchAll(/"([a-z_]+)"/g)].map(
    (m) => m[1],
  ),
);
const granted = new Set(
  [...read("src-tauri/capabilities/default.json").matchAll(/"allow-([a-z-]+)"/g)].map((m) =>
    m[1].replace(/-/g, "_"),
  ),
);

describe("the UI and the app agree on commands", () => {
  it("finds the commands the UI sends", () => {
    expect(invoked.size).toBeGreaterThan(30);
  });

  it("every command the UI sends is registered, declared and granted", () => {
    for (const cmd of invoked) {
      expect(registered, `${cmd} is not registered`).toContain(cmd);
      expect(webview, `${cmd} is not declared for the webview`).toContain(cmd);
      expect(granted, `${cmd} is not granted`).toContain(cmd);
    }
  });

  it("the app exposes nothing the UI does not use", () => {
    for (const cmd of webview) expect(invoked, `${cmd} is declared but unused`).toContain(cmd);
  });
});

describe("UI rules", () => {
  const files = sources("src").map((p) => [p, read(p)] as const);

  it("uses no emoji", () => {
    for (const [p, text] of files) {
      expect(/\p{Extended_Pictographic}/u.test(text), `${p} contains an emoji`).toBe(false);
    }
  });

  it("uses no italic accents", () => {
    for (const [p, text] of files) {
      expect(/italic|<em[\s>]|<i[\s>]/.test(text), `${p} sets italic text`).toBe(false);
    }
  });
});
