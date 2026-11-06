#!/usr/bin/env node
import React from "react";
import { render } from "ink";
import { App } from "./app.js";
import { emptySnapshot, headline, sdkSource } from "./data.js";
import { isAddress } from "./format.js";
import { plainReport } from "./plain.js";
import { colorEnabled, makeTheme } from "./theme.js";

const VERSION = "0.1.0";

const HELP = `tenzro-tui: an interactive console for a Tenzro node, built on tenzro-sdk

Usage: tenzro-tui [options]

  --rpc <url>        node JSON-RPC endpoint (default: $TENZRO_RPC_URL, else http://127.0.0.1:8545)
  --api <url>        node REST endpoint, when it is not derived from --rpc
  --address <0x...>  the account the Wallet screen shows (default: $TENZRO_ADDRESS, else the node's payee)
  --plain            print one text report and exit; used automatically when output is not a terminal
  --no-color         no colour (NO_COLOR is honoured too)
  -h, --help         this help
  -V, --version      version

Keys: 1-5 screens, Tab next, Up/Down move, r refresh, e account, ? help, q quit.
This console only reads. Keys and signing stay in the tenzro CLI.
`;

interface Args {
  rpc: string;
  api?: string;
  address: string | null;
  plain: boolean;
  noColor: boolean;
  help: boolean;
  version: boolean;
}

export function parseArgs(argv: string[], env: NodeJS.ProcessEnv): Args | string {
  const a: Args = {
    rpc: env.TENZRO_RPC_URL || "http://127.0.0.1:8545",
    address: env.TENZRO_ADDRESS || null,
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
    return `--rpc is not a URL: ${a.rpc}`;
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
  const source = sdkSource(parsed.rpc, parsed.api);
  const interactive = process.stdout.isTTY === true && process.stdin.isTTY === true && !parsed.plain;
  if (!interactive) {
    let snap = await source.collect(parsed.address, emptySnapshot);
    if (!parsed.address && snap.status.state === "ok" && snap.status.value.payee) {
      snap = await source.collect(snap.status.value.payee, snap);
    }
    process.stdout.write(plainReport(parsed.rpc, snap));
    return headline(snap).word === "OK" ? 0 : 1;
  }
  const theme = makeTheme(colorEnabled(process.env, parsed.noColor));
  const app = render(<App source={source} theme={theme} initialAccount={parsed.address} />, { alternateScreen: true, exitOnCtrlC: true });
  await app.waitUntilExit();
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`tenzro-tui: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  },
);
