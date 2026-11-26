// The local helper (`tenzro control`): the operator's own service on this
// machine, reached over a socket only that user can open. Each connection
// carries JSON-RPC, one message per line. The console asks it to act (a
// planned stop) instead of holding any way to act itself.

import net from "node:net";
import os from "node:os";
import path from "node:path";
import { redact, type Shown } from "./redact.js";

export interface Helper {
  /** Where the helper is looked for. */
  path: string;
  /** One call. Rejects with the helper's message, or with `HelperAbsent` when nothing listens. */
  call<T>(method: string, params?: Record<string, unknown>): Promise<T>;
}

/** Nothing is listening on the helper's socket. */
export class HelperAbsent extends Error {
  constructor(where: string) {
    super(`no helper is listening on ${where}`);
    this.name = "HelperAbsent";
  }
}

/** A refusal or failure the helper answered with, safe to show. */
export class HelperError extends Error {
  readonly shown: Shown;
  constructor(public code: number, message: string) {
    super(message);
    this.name = "HelperError";
    this.shown = redact(message);
  }
}

/** Where the helper listens: the user's runtime directory on Linux when the session has one, otherwise the Tenzro home. */
export function defaultSocket(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform, home: string = os.homedir()): string {
  const runtime = env.XDG_RUNTIME_DIR;
  if (platform !== "darwin" && runtime) return path.join(runtime, "tenzro", "control.sock");
  return path.join(env.TENZRO_HOME || path.join(home, ".tenzro"), "control.sock");
}

const CALL_TIMEOUT_MS = 10000;

export function socketHelper(where: string): Helper {
  return {
    path: where,
    call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        const sock = net.createConnection(where);
        let buf = "";
        let settled = false;
        const finish = (f: () => void) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          sock.destroy();
          f();
        };
        const timer = setTimeout(() => finish(() => reject(new Error("the helper did not answer in time"))), CALL_TIMEOUT_MS);
        sock.setEncoding("utf8");
        sock.on("connect", () => sock.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) + "\n"));
        sock.on("data", (chunk: string) => {
          buf += chunk;
          const end = buf.indexOf("\n");
          if (end < 0) return;
          finish(() => {
            try {
              const msg = JSON.parse(buf.slice(0, end)) as { result?: T; error?: { code?: number; message?: string } };
              if (msg.error) reject(new HelperError(msg.error.code ?? 0, msg.error.message ?? "the helper refused"));
              else resolve(msg.result as T);
            } catch {
              reject(new Error("the helper answered with something that is not JSON-RPC"));
            }
          });
        });
        sock.on("error", (e: NodeJS.ErrnoException) =>
          finish(() => reject(e.code === "ENOENT" || e.code === "ECONNREFUSED" ? new HelperAbsent(where) : e)),
        );
        sock.on("end", () => finish(() => reject(new Error("the helper closed the connection without answering"))));
      });
    },
  };
}
