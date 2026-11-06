# tenzro-tui

An interactive terminal console for a Tenzro node, built on `tenzro-sdk`. It reads
the node and shows what an operator asks first: is it running, is it at the tip of
the chain, what does it hold, who validates, what is being decided.

It only reads. Sending, signing and every key operation stay in the `tenzro` CLI,
where the key is held by the machine's hardware. Nothing secret is ever shown.

## Run

    # from a checkout of the repository; the package is not published yet
    (cd ../tenzro-ts-sdk && npm ci)      # the SDK it depends on by path
    npm ci                               # builds the SDK, then installs this package
    npm run build
    node dist/src/cli.js --rpc http://127.0.0.1:8545

Node 22 or newer (ink 8 requires it).

    --rpc <url>        node JSON-RPC (default $TENZRO_RPC_URL, else http://127.0.0.1:8545)
    --api <url>        node REST endpoint, when it is not the default for --rpc
    --address <0x...>  account for the Wallet screen (default $TENZRO_ADDRESS, else the node's payee)
    --plain            one text report, then exit (automatic when output is not a terminal)
    --no-color         no colour (NO_COLOR is honoured as well)

`--plain` exits 0 when the node is OK and 1 otherwise, so scripts can use it.

## Screens and keys

| Key | Screen |
| --- | --- |
| 1 | Overview: node state, version, uptime, roles, disk; chain id, height, finalized, sync, peers; identity |
| 2 | Wallet: balance and nonce of one account (press e to choose it) |
| 3 | Models: what the node holds, engine, visibility, loaded, serving |
| 4 | Validators: the registered set and self stake |
| 5 | Governance: proposals, kind, status, track, tally |

Tab and Shift-Tab (or Right and Left) change screen. Up/Down or j/k move in a list.
r refreshes now (it also refreshes every 5 s). ? shows the help overlay. Esc closes
it or cancels an edit. q or Ctrl-C quits and restores the terminal.

The header always shows one status word: OK, WATCH, DOWN or UNKNOWN. Colour is a
second channel only; with NO_COLOR the words, bold and reverse video carry the
meaning. When the node stops answering, the last values stay on screen marked STALE.
The console needs a window of at least 80x24 and says so below that.

## Tests

    npm test

Unit tests cover formatting, the key table (a key bound twice fails the build) and
the screens at 80x24 and 120x40 (navigation, scrolling, help, account entry, node
down, stale data, too-small window, no colour codes without colour).

## Not yet here

Logs, a send flow, provider and validator actions, and a mouse. The package is
private until `tenzro-sdk` 0.9.0 is on npm; it depends on the sibling SDK by path.
