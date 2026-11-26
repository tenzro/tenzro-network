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
    --no-color         no color (NO_COLOR is honored as well)

`--plain` exits 0 when the node is OK and 1 otherwise, so scripts can use it.

## Screens and keys

| Key | Screen |
| --- | --- |
| 1 | Overview: node state, version, uptime, roles, disk; chain id, height, finalized, sync, peers; identity |
| 2 | Wallet: balance and nonce of one account (press e to choose it) |
| 3 | Models: what the node holds, engine, visibility, loaded, serving |
| 4 | Validators: the registered set and self stake |
| 5 | Governance: proposals, kind, status, track, tally |
| 6 | Health: what needs attention, worst first (press a to acknowledge one with a reason) |
| 7 | Peers: this node and every peer it has heard from, with roles, tier, anchor and region |
| 8 | Logs: alerts raised, cleared and acknowledged in this console session |
| 9 | Settings: how this console was started |

Tab and Shift-Tab (or Right and Left) change screen. Up/Down or j/k move in a list.
r refreshes now (it also refreshes every 5 s). ? shows the help overlay. Esc closes
it or cancels an edit. q or Ctrl-C quits and restores the terminal.

The header always shows one status word: OK, WATCH, DOWN or UNKNOWN. Color is a
second channel only; with NO_COLOR the words, bold and reverse video carry the
meaning. When the node stops answering, the last values stay on screen marked STALE.
The console needs a window of at least 80x24 and says so below that.

## Alerts

The Health screen lists what is wrong with the node. The list is the node's own
conditions (`tenzro_listConditions`) when the node serves them, each occurrence told
apart by its id and the time it opened. What that list does not carry the console
reads itself: the node not running, not healthy, or catching up, and that it does
not answer at all. For a node that serves no list the console also applies its own
rules for disk pressure, no peers and finality not advancing. Alerts have three levels: PAGE,
WARN and INFO. A finding becomes an alert when it holds for two refreshes running
and clears when it is gone for two, so it does not flicker. An acknowledgement needs
a typed reason and stays with the alert until it clears; a later occurrence is new.
When no fresh answer has arrived for three refresh periods the console raises a
PAGE alert of its own, because nothing on screen can then be vouched for. The
header counts the alerts nobody has acknowledged. Acknowledgements are never written
to the node. They live in the console session, unless the console is started with
`--shared <file>`: it then keeps them in that file too (mode 0600, rewritten whole
by a rename), and every console that names the same file shows an alert another has
acknowledged as acknowledged, with its reason. A shared acknowledgement counts only
when it was given after the alert opened and at its current level or a worse one.
A rehearsal never reads or writes the file.

## Planned stop

S starts a planned stop of the node. The console first checks, and shows, that the
node is answering, that no page-level alert is open and unacknowledged, that the node
is not catching up, and, for a validator, that the set keeps quorum plus one without
it. The count is the `Active` entries of the node's validator list: registrations, not
which of them are up, and not their stake. A check that fails blocks the stop. When
all pass the console asks for the word STOP to be typed, and only then asks the
operator's local helper (`tenzro control`, found at its own socket or `--control`)
to stop the node service. With no helper running it stops nothing and prints the
command to run instead.

Once the node's own checks pass, the console also asks up to three other operators
how the network looks to them. It asks only endpoints the chain's operator list
names (`tenzro_listRoleEndpoints`, role `rpc`), never one with credentials in its URL
and never this node's own; it makes three open reads (`eth_syncing`, `net_peerCount`,
`tenzro_getFinalizedBlock`), follows no redirect, waits at most 3 seconds and reads
at most 4096 bytes per answer. The stop goes on only when a majority of those that
answered are not catching up, have peers, and are within 50 blocks of this node's
finalized height. If operators are listed and none answers, the stop is blocked.

/ opens a finder over the same key table the footer and the help are drawn from:
type part of a name, move with Up/Down, press Enter.

## Runbooks

Three runbooks open from the finder (type `runbook`): genesis assembly, validator
entry after genesis, and the upgrade window. Each is a list of steps in the shape of
a Tenzro Control setup-plan step (`id`, `title`, `what`, `why`, `gate`, `skippable`,
`caution`, `state`, `progress`, `result`). The console runs none of them: a step says
what to do and why, and its state is `pending` unless the console could read it from
the node it is pointed at.

## Replay

The console keeps the last 720 answers it collected (an hour at the usual refresh).
[ steps back through them and ] forward; every screen is then drawn from that earlier
answer with the alerts that were open at the time, under a REPLAY banner with its
time. Nothing can be decided from the past: stop, acknowledge, account entry and
refresh are held until ] has stepped past the newest answer back to now.

## Rehearsal

`tenzro-tui --rehearse` runs the console against a scripted node: it is healthy, then
stops following the network for a while (a page-level alert, a blocked stop), then
recovers, and the script repeats. No node and no helper is contacted, and a stop
confirmed in rehearsal stops nothing. The header shows REHEARSAL throughout.

## Which build this is

`tenzro-tui --build-digest` prints the digest of the console's own built files, in
the form the signed release notice states for the bundle named `tenzro-tui`: the
SHA-256 of one `<sha256>  <path>` line per file, paths sorted, which
`find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum | sha256sum` gives
inside the directory too. `tenzro-tui --expect-build <digest>` starts only when that
digest is the one given, and otherwise prints both and exits 3. The expected digest
is something you bring (from the notice of the release you meant to install); the
console fetches it from nowhere.

## Tests

    npm test

Unit tests cover formatting, the key table (a key bound twice fails the build) and
the screens at 80x24 and 120x40 (navigation, scrolling, help, account entry, node
down, stale data, too-small window, no color codes without color).

## Not included

The node's own log (the Logs screen shows only this console's session), a send flow,
provider and validator actions other than the planned stop, and a mouse. The package
is private until `tenzro-sdk` 0.9.0 is on npm; it depends on the sibling SDK by path.
