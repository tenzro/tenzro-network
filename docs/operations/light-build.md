## Node tiers

Tenzro runs on every class of machine, from small embedded and edge devices
to the largest GPU servers, from one codebase. The network's tiers are edge
(light) nodes on small machines, which run agents today and are designed to
host orchestration; standard nodes on CPU servers; GPU providers; and
validators. They are built from the release
variants below: the light build serves edge nodes and validators, the
standard build serves CPU servers, and the standard build with a GPU backend
serves GPU providers.

One `tenzro-node` source builds for three tiers. A tier is a build (which
cargo features are compiled in) and a resource preset (what the node takes of
the machine at run time). The build decides which roles a node can fill; the
preset only sizes it.

| Tier | Machines | Build | Roles it refuses |
|---|---|---|---|
| edge | Small, embedded and edge devices: single-board computers (the Raspberry Pi is the reference device), Jetson-class modules, mini PCs, NAS boxes, gateways | `scripts/build-tier.sh edge` (light build, `edge` profile) | `ai`, `compute`, `tee` |
| validator | Servers that validate, store and relay | `scripts/build-tier.sh validator` (light build, release profile) | `ai`, `compute`, `tee` |
| provider | Servers that also serve models | `scripts/build-tier.sh provider [cuda\|rocm\|vulkan\|metal\|...]` (standard build plus a GPU backend) | none; a GPU build with no usable GPU refuses to start |

### Light build for small machines

The standard build compiles the model engines in: llama.cpp/ggml, media
generation, LoRA training, the ONNX runtimes and their decoders and
tokenizers. They come with the `inference` cargo feature of `tenzro-node`,
which is on by default and turns on the `engine` feature of `tenzro-model`.
Every fleet and test script builds with it, unchanged.

The light build leaves it out:

```
cargo build --release -p tenzro-node --no-default-features
```

It keeps identity (including the remote-TPM client for a machine with no TPM
of its own), payments, the agent surfaces, RPC, MCP and A2A, consensus,
storage, block sync and the `light`, `micro`, `fullnode`, `rpc`, `storage` and
`validator` roles. A chat, completion, embedding, rerank, segmentation,
detection, forecast, transcription, speech or media-render call for a model a
provider on the network serves is forwarded to that provider as the standard
build forwards it. What would run a model on the node itself is refused with
error -32004 naming the light build: loading and unloading models, training,
MoE expert hosting, the layer pipeline, realtime speech turns, and a modality
call no provider offers.

Started with `ai`, `compute` or `tee` (on the command line or in the
configuration file), the light build exits before it opens any key or file:

```
this tenzro-node is the light build (built without the `inference` feature) and cannot serve the ai role: it runs models on this machine. ...
```

### Resource presets

`--tier` (`TENZRO_TIER`, or `tier = "..."` in the configuration file) takes
`auto` (the default), `edge`, `validator` or `provider`. `auto` picks
`provider` for roles that run models, `edge` on a machine with at most 8 GiB
of memory (`[memory] total_gb` when set, else detected), and `validator`
otherwise.

| Setting | edge | validator, provider | Override |
|---|---|---|---|
| Store memory (block cache with the memtables charged to it) | 1/16 of the memory pool, 32 MiB to 256 MiB | 1/32 of the pool, 256 MiB to 4 GiB | `[storage] memory_mb` |
| Write buffer per column family | 16 MiB | 64 MiB | `[storage] write_buffer_mb` |
| Background flush and compaction jobs | 1 | 2 | `[storage] background_jobs` |
| Background write rate | 16 MiB/s | 64 MiB/s | `[storage] background_write_mb_per_sec` |
| Open files | 256 | 1000 | `[storage] max_open_files` |
| Runtime worker threads | 2 (1 on a one-core machine) | 2 | `--worker-threads` / `TENZRO_WORKER_THREADS` |
| Runtime blocking threads | 32 | 512 | |

The memory pool is what the node's memory budget lends out: on a machine with
less than twice the 16 GiB default reserve, three quarters of it. So the edge
store takes 96 MiB on a 2 GB board, 192 MiB on 4 GB and 256 MiB from 8 GB up.
The validator and provider presets are the defaults every node had before the
tiers.

History retention is a network parameter (governance), not a preset: every
non-archival node keeps the governed window, prunes to it and compacts when
the data volume passes `[storage] prune_watermark_pct` (75%), and refuses
non-essential data past `refuse_watermark_pct` (90%). On a small SD card or
eMMC those watermarks are what keep the node inside its disk.

The background tasks a node starts are already gated by role: audit
watchers, fee-rate reporting, SLA probes and attestations, data-availability
retention and the optimistic reviewer return at once on a node whose roles do
not use them. The light build additionally starts none of the model runtimes,
the standby loop, the residency schedule, the autotune sampler,
session continuity or the MoE repair loop.

### Raspberry Pi and other edge devices

- **Processor.** `scripts/build-tier.sh edge` builds for any aarch64 (or
  x86_64) machine. `--cpu cortex-a76` tunes it for a Pi 5; the result uses
  instructions a Pi 4 (Cortex-A72) does not have and does not run there.
  `--cpu cortex-a72` builds for a Pi 4. `--size` optimizes for size.
- **C library.** A binary built on Ubuntu 24.04 (glibc 2.39) needs glibc
  2.38 or later: it runs on Raspberry Pi OS based on Debian 13 (glibc 2.41),
  not on Raspberry Pi OS Bookworm (glibc 2.36). For Bookworm, build on
  Bookworm or with a toolchain pinned to glibc 2.36.
- **Page size.** The Pi 5 kernel uses 16K pages by default. The node uses the
  system allocator, and nothing in its dependencies assumes 4K pages.
- **Identity.** A Pi has no TPM. It keeps its identity key in another
  machine's TPM through `tenzro-node tpm serve` on that machine. The provider
  listens on loopback only unless its file names the addresses to serve on,
  such as `listen = ["100.64.0.7:7400"]` for its private-network (VPN) address. On the Pi,
  `tenzro-node tpm key-holder` runs as its own service: it makes this boot's
  transport key in memory (never on disk) and the operator approves it with
  a passkey grant (`tpm grant-request`, then `tpm grant-install`); the node
  starts with `--tpm-key-holder <socket> --tpm-label <label>`. The node can
  restart without a new grant; a reboot needs one.

  **Validators.** The same delegation can hold a validator's consensus key.
  The P-256 leg is a key in the provider's TPM and the ML-DSA-65 leg is
  derived there for each use, so a machine with no TPM of its own can take
  the validator role. The provider file must enrol the client with
  `derived = true`. The limits: every signature is a round trip to the
  provider, queued behind its other TPM commands, so the provider must stay
  reachable; a grant lasts at most the provider's `max_grant_hours` (720 by
  default), and after a reboot of the key holder, or when the grant ends,
  the validator cannot sign until the operator installs a new one. The
  ML-DSA-87 / P-384 consensus scheme is not available this way: it needs a
  TPM in the validator's own machine that implements ML-DSA and P-384. A
  passkey never holds a consensus key: the operator's passkey grants and
  approves, and the key stays in a TPM or Secure Enclave.

  **Session delegation.** A TPM command takes seconds, so the key holder does
  not ask the provider for every signature. With `tenzro-node tpm key-holder
  --identity <did> --label <label>` it asks the provider once per session for
  a delegation: a statement signed by the identity key (its Ed25519 and its
  ML-DSA-65 leg) that binds a session key pair the holder made in its own
  locked memory, for a bounded time and under the identity's current key
  version. The holder then signs each message with the session key
  (`OP_SESSION_SIGN`, no round trip), and a peer traces the signature to the
  identity key through the delegation. The session key is made at start,
  wiped on drop, never written and never exported; it is a credential for
  one delegation, not an identity key. The delegation ends at its expiry, at
  its revocation, at the end of the grant it was issued under, or when the
  identity rotates to a new key version, whichever comes first. The holder
  renews before expiry (`--session-renew-before-secs`), checks the provider
  for revocation and rotation every `--session-check-secs`, and a provider
  that cannot be reached changes nothing until the delegation expires, after
  which signing fails closed. A cold start with the provider down is refused.
  After a reboot the holder has a new transport key; the operator makes one
  new passkey grant (`tpm grant-request`, `tpm grant-install`) and the
  session starts from it with nothing else to do. The grant and the session
  key are kept in memory only. `tpm session-status` prints the delegation's
  end and id; `tpm revoke --config <provider file> --delegation <id>`
  revokes one.

  The provider issues delegations when its file names an `issuer_file`, a
  JSON file the identity's on-chain key update rewrites:
  `{"identities": {"<did>": {"version": 2, "label": "<key label>"}}}`. The
  provider derives the identity key under that label in its TPM; no handle or
  key id is configured anywhere. The limits are provider-file values, not
  constants: `delegation_max_lifetime_secs`, `delegation_min_lifetime_secs`,
  `revocation_file`, and for the TPM command queue `tpm_queue_max_waiting`,
  `tpm_queue_max_wait_secs`, `tpm_retries`, `tpm_backoff_base_ms`,
  `tpm_backoff_cap_ms`. The provider runs one TPM command at a time; a
  request that finds the line full, or that waits its limit, is refused with
  `tpm busy: ... retry in N ms`, and the key holder waits that long and asks
  again (`--busy-retries`, `--request-timeout-secs`).
- **Memory.** The light node's resident memory measured 130 to 210 MiB idle
  and up to about 230 MiB under RPC load (below), within a 2 GB board's
  budget beside the operating system (about 200 to 250 MiB idle on Raspberry
  Pi OS Lite 64-bit).
- **Storage.** Use an SSD or NVMe where the board takes one: the store's
  compaction is paced, but an SD card's random-write rate is low.

Not built yet: 32-bit ARM (armv7) and RISC-V (riscv64). Their dependency
trees resolve; what has not been checked by a build is RocksDB on a 32-bit
target, the native code in aws-lc-sys, ring and blst on them, and the zero-
knowledge verifiers (risc0, plonky3, halo2) on 32-bit.

### Measurements

Measured on an aarch64 host (20 cores, Ubuntu 24.04) on 2026-10-18, against a
private network of three nodes on software TPMs (one validator, one full node
serving the relay, and the node under test with `--roles light` and
`[memory] total_gb` set to emulate a smaller machine). The node under test
started from an empty data directory; sync time is from process start to the
validator's height at that moment. Idle and loaded samples are 60 s each;
the load is 40 JSON-RPC reads per second. The host was running other builds,
so CPU and sync figures carry noise of tens of percent.

Run A had a dev calendar (an epoch every few seconds, with an epoch snapshot
each); run B the default calendar (day-long epochs). Both produce about one
block a second. RSS is resident memory, mean / maximum over the sample.

| Build | Binary (stripped) | Emulated memory | Store | Sync | Idle RSS | Idle CPU | Loaded RSS | Loaded CPU |
|---|---|---|---|---|---|---|---|---|
| Standard (all engines), A | 132.4 MB | 4 GB | 192 MiB, 1 job | 7.7 blocks/s | 232 / 262 MiB | 57% | 262 / 268 MiB | 97% |
| Standard (all engines), B | 132.4 MB | 4 GB | 192 MiB, 1 job | 5.4 blocks/s | 157 / 172 MiB | 77% | 173 / 177 MiB | 97% |
| Light, before the presets, A | 86.8 MB | 4 GB | 256 MiB, 2 jobs | 9.2 blocks/s | 173 / 183 MiB | 89% | 185 / 188 MiB | 83% |
| Light, before the presets, B | 86.8 MB | 4 GB | 256 MiB, 2 jobs | 7.1 blocks/s | 144 / 167 MiB | 70% | 166 / 169 MiB | 96% |
| Light, edge preset, A | 86.8 MB | 4 GB | 192 MiB, 1 job | 6.1 blocks/s | 153 / 189 MiB | 51% | 190 / 193 MiB | 104% |
| Light, edge preset, B | 86.8 MB | 4 GB | 192 MiB, 1 job | 6.7 blocks/s | 140 / 151 MiB | 99% | 152 / 157 MiB | 96% |
| Light, edge preset, A | 86.8 MB | 2 GB | 96 MiB, 1 job | 6.8 blocks/s | 173 / 210 MiB | 40% | 204 / 209 MiB | 101% |
| Light, edge preset, B | 86.8 MB | 2 GB | 96 MiB, 1 job | 7.5 blocks/s | 154 / 171 MiB | 71% | 170 / 174 MiB | 94% |
| Light, validator preset, A | 86.8 MB | 16 GB | 384 MiB, 2 jobs | 7.5 blocks/s | 199 / 220 MiB | 86% | 222 / 225 MiB | 97% |
| Edge profile, `--cpu cortex-a76`, A | 85.5 MB | 4 GB | 192 MiB, 1 job | 8.5 blocks/s | 181 / 218 MiB | 41% | 218 / 222 MiB | 107% |
| Edge profile, `--size`, A | 62.2 MB | 4 GB | 192 MiB, 1 job | 7.6 blocks/s | 180 / 190 MiB | 24% | 215 / 229 MiB | 94% |
| Edge profile, `--size`, B | 62.2 MB | 4 GB | 192 MiB, 1 job | 5.4 blocks/s | 132 / 168 MiB | 46% | 166 / 172 MiB | 88% |

What the numbers show:

- The light build is 35% smaller than the standard build (86.8 MB against
  132.4 MB stripped; the standard test-build binary with line tables is
  979 MB) and holds 15 to 80 MiB less resident memory in the same role.
- In a sync this short the store's cache never fills, so the presets change
  resident memory less than the noise; what they bound is the ceiling the
  store can grow to over a long run (96 MiB on a 2 GB board instead of 256).
- `--size` saves another 28% of the binary with no loss in sync or RPC load
  that this host can resolve.
- A light node following a chain that makes a block a second keeps about one
  core busy on that host. That is block import, not idle overhead, and is the
  figure to watch on a Pi 4.

On the same network the validator (light build, validator role) held
237 MiB on average with peaks of 614 MiB at epoch boundaries and 38% of a
core; the full node serving the relay held 365 MiB and 85% of a core.

Check a build against its budget with `scripts/edge-budget.sh <binary>
[<measurement>]` (the release gate runs it as row L4): 100 MB stripped, and
256 MiB idle and 320 MiB loaded resident memory for a `--roles light` node.
