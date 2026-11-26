#!/usr/bin/env node
import React from "react";
import { render } from "ink";
import { App } from "./app.js";
import { digestOf, ownDir, sameDigest } from "./build.js";
import { emptySnapshot, headline, sdkSource } from "./data.js";
import { isAddress } from "./format.js";
import { defaultSocket, socketHelper } from "./helper.js";
import { plainReport } from "./plain.js";
import { redact } from "./redact.js";
import { rehearsalHelper, rehearsalSource } from "./rehearsal.js";
import { colorEnabled, makeTheme } from "./theme.js";

const VERSION = "0.1.0";

const HELP = `tenzro-tui: an interactive console for a Tenzro node, built on tenzro-sdk

Usage: tenzro-tui [options]

  --rpc <url>        node JSON-RPC endpoint (default: $TENZRO_RPC_URL, else http://127.0.0.1:8545)
  --api <url>        node REST endpoint, when it is not derived from --rpc
  --address <0x...>  the account the Wallet screen shows (default: $TENZRO_ADDRESS, else the node's payee)
  --control <path>   socket of the local helper (tenzro control), asked to act for a planned stop
  --shared <file>    keep acknowledgements in <file>, shared with every console that names it
                     (default: the helper's own place for this user)
  --build-digest     print the SHA-256 digest of this console's own built files and exit
  --expect-build <d> refuse to start unless that digest is <d> (the digest of the release you meant to run)
  --rehearse         practise on a scripted node: no node and no helper is contacted, nothing is stopped
  --plain            print one text report and exit; used automatically when output is not a terminal
  --no-color         no color (NO_COLOR is honored too)
  -h, --help         this help
  -V, --version      version

Keys: 1-9 screens, Tab next, Up/Down move, r refresh, e account, a acknowledge, / find, ? help, q quit.
This console reads. The one thing it can ask for is a planned stop (S), which goes to the local
helper after the checks pass and STOP is typed. Keys and signing stay in the tenzro CLI.
`;

interface Args {
  rpc: string;
  api?: string;
  address: string | null;
  control: string;
  shared: string | null;
  rehearse: boolean;
  buildDigest: boolean;
  expectBuild: string | null;
  plain: boolean;
  noColor: boolean;
  help: boolean;
  version: boolean;
}

export function parseArgs(argv: string[], env: NodeJS.ProcessEnv): Args | string {
  const a: Args = {
    rpc: env.TENZRO_RPC_URL || "http://127.0.0.1:8545",
    address: env.TENZRO_ADDRESS || null,
    control: defaultSocket(env),
    shared: null,
    rehearse: false,
    buildDigest: false,
    expectBuild: null,
    plain: false,
    noColor: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i]!;
    const need = (): string | null => (i + 1 < argv.length ? argv[++i]! : null);
    switch (x) {
      case "--rpc": {
        const v = need();
        if (!v) return "--rpc needs a URL";
        a.rpc = v;
        break;
      }
      case "--api": {
        const v = need();
        if (!v) return "--api needs a URL";
        a.api = v;
        break;
      }
      case "--address": {
        const v = need();
        if (!v) return "--address needs an account address";
        a.address = v;
        break;
      }
      case "--control": {
        const v = need();
        if (!v) return "--control needs a socket path";
        a.control = v;
        break;
      }
      case "--shared": {
        const v = need();
        if (!v) return "--shared needs a file path";
        a.shared = v;
        break;
      }
      case "--rehearse":
        a.rehearse = true;
        break;
      case "--build-digest":
        a.buildDigest = true;
        break;
      case "--expect-build": {
        const v = need();
        if (!v) return "--expect-build needs a digest";
        a.expectBuild = v;
        break;
      }
      case "--plain":
        a.plain = true;
        break;
      case "--no-color":
        a.noColor = true;
        break;
      case "-h":
      case "--help":
        a.help = true;
        break;
      case "-V":
      case "--version":
        a.version = true;
        break;
      default:
        return `unknown option ${x}`;
    }
  }
  if (a.address && !isAddress(a.address)) return "--address must be 0x followed by 40 or 64 hex digits";
  try {
    new URL(a.rpc);
  } catch {
    return redact(`--rpc is not a URL: ${a.rpc}`);
  }
  return a;
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2), process.env);
  if (typeof parsed === "string") {
    process.stderr.write(`tenzro-tui: ${parsed}\nTry: tenzro-tui --help\n`);
    return 2;
  }
  if (parsed.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (parsed.version) {
    process.stdout.write(`tenzro-tui ${VERSION}\n`);
    return 0;
  }
  if (parsed.buildDigest || parsed.expectBuild !== null) {
    const digest = digestOf(ownDir());
    if (parsed.buildDigest) {
      process.stdout.write(`${digest}\n`);
      return 0;
    }
    if (!sameDigest(parsed.expectBuild!, digest)) {
      process.stderr.write(`tenzro-tui: this is not the build you expected.\n  expected ${parsed.expectBuild}\n  this one ${digest}\nNothing was started.\n`);
      return 3;
    }
  }
  const source = parsed.rehearse ? rehearsalSource() : sdkSource(parsed.rpc, parsed.api);
  const interactive = process.stdout.isTTY === true && process.stdin.isTTY === true && !parsed.plain;
  if (!interactive) {
    let snap = await source.collect(parsed.address, emptySnapshot);
    if (!parsed.address && snap.status.state === "ok" && snap.status.value.payee) {
      snap = await source.collect(snap.status.value.payee, snap);
    }
    if (parsed.rehearse) process.stdout.write("REHEARSAL: a scripted node, not a real one\n");
    process.stdout.write(plainReport(source.url, snap));
    return headline(snap).word === "OK" ? 0 : 1;
  }
  const theme = makeTheme(colorEnabled(process.env, parsed.noColor));
  const app = render(<App source={source} theme={theme} initialAccount={parsed.address} helper={parsed.rehearse ? rehearsalHelper() : socketHelper(parsed.control)} {...(parsed.rehearse ? { banner: "REHEARSAL" } : { shared: parsed.shared })} />, { alternateScreen: true, exitOnCtrlC: true });
  await app.waitUntilExit();
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`tenzro-tui: ${redact(e instanceof Error ? e.message : String(e))}\n`);
    process.exit(1);
  },
);
