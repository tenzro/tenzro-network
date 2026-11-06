# Running a node on a unified-memory host

Applies to NVIDIA Grace-Blackwell unified-memory systems, Apple Silicon, and AMD
APUs — any part where the GPU pool **is** system memory rather than a separate
device.

On a discrete card, over-committing GPU memory is a bounded failure: CUDA
raises, one job dies, the process lives. On a coherent-memory part there is no
separate pool to exhaust, so the same over-commit is served by the kernel until
the machine runs out and the **global OOM killer** starts choosing victims
across every cgroup — including the node, and including whatever else the
operator was running. The blast radius is the machine, not the request.

Everything below comes out of a real over-commit on a 121 GB unified-memory host.

---

## 1. The models are not what fills the machine

A full five-modality serving set is comfortable on 121 GB:

| Slot               | Model                                  |   Resident |
| ------------------ | -------------------------------------- | ---------: |
| Text               | Qwen3.6-35B-A3B MTP, 32 concurrent     |     ~28 GB |
| Embeddings         | Qwen3-Embedding-4B (ONNX, fp32)        |     ~16 GB |
| Image **or** video | one diffusion pipeline at a time       |     ~21 GB |
| Timeseries         | TimesFM 2.5 200M                       |      ~1 GB |
| —                  | node process (RocksDB, runtimes, mesh) |     ~17 GB |
|                    | **Total**                              | **~83 GB** |

What took the machine down was not the models. It was `cargo nextest run
--workspace` on the same box: every test binary statically embeds llama.cpp, and
**13 concurrent GNU `ld` processes ran at 12–13 GB RSS each — roughly 85 GB of
linker**. The node was OOM-killed twice as collateral.

**Do not build the workspace on a node that is serving.** If you must, see §4.

---

## 3. Give the node a floor and the OOM killer a preference

The node runs as a systemd **user** unit. The memory controller is
delegated to the user manager on a stock Ubuntu 24.04+ install (check with
`cat /sys/fs/cgroup/user.slice/user-1000.slice/cgroup.subtree_control`), so
`MemoryMin` / `MemoryHigh` / `MemoryMax` and a negative `OOMScoreAdjust` all
work without root.

`~/.config/systemd/user/tenzro-node.service.d/memory.conf`:

```ini
[Service]
# Never reclaimed under pressure — a runaway build cannot page the served
# models back out.
MemoryMin=32G

# The node was killed twice at oom_score_adj:200 — the kernel valued it no more
# than a linker. Bias selection away from the thing serving the network.
OOMScoreAdjust=-500
```

Verify a limit actually took, rather than trusting the unit file:

```bash
systemctl --user show tenzro-node.service -p MemoryMin -p OOMScoreAdjust
```

---

## 4. Contain builds instead of trusting them

Interactive shells are where `cargo` gets launched, and on GNOME they live under
`app-org.gnome.Terminal.slice`. Cap that slice to the headroom the models leave:

`~/.config/systemd/user/app-org.gnome.Terminal.slice.d/memory.conf`:

```ini
[Slice]
MemoryHigh=24G     # reclaim pressure first
MemoryMax=30G      # then kill the build, and only the build
```

Confirm the ceiling is live:

```bash
cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/\
app-org.gnome.Terminal.slice/memory.max
```

Then cut the peak itself, with `mold` and a job cap:

```toml
# ~/.cargo/config.toml
[build]
jobs = 12          # one linker per job; 20 cores will start 20 of them
```

```bash
# ~/.bashrc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold"
```

**The linker flag must be an environment variable, not `~/.cargo/config.toml`.**
The repository's own `.cargo/config.toml` pins
`[target.aarch64-unknown-linux-gnu] rustflags = []`, and repo config outranks
user config for the same key — a `rustflags` entry in the user file is silently
ignored. Environment variables outrank both. `-fuse-ld=mold` is deliberately
kept out of the committed config so builders without mold (including CI) are
unaffected.

---

## 5. Reading the aftermath

The kernel names the victim, but the victim is rarely the cause. Get the whole
task list from the last OOM event, sorted by RSS, rather than the single
`Killed process` line:

```bash
journalctl -b -1 -k | rg "Out of memory: Killed"          # every victim
journalctl -b -1 -k | rg -A400 "invoked oom-killer" | tail -120   # task dump
```

Two readings that matter:

- **RSS in the task dump is in pages, not kB.** Multiply by 4096. A row reading
  `3182742` is 12.7 GB, not 3 GB.
- **Repeated kills of the same service are a symptom, not the fault.** In the
  incident, `stellar-core` was killed six times and the node twice, while the
  actual consumer — thirteen linkers — was never killed at all until the end,
  because each individual `ld` looked no worse than its neighbours.

---

## 5a. Prefix-reuse checkpoints share the pool

A model with recurrent layers (Qwen 3.5/3.8, Granite 4 H, Mamba, RWKV), or a
sliding-window model served with `BATCH_SWA_FULL=0`, keeps checkpoints of its
recurrent state or window per slot so a returning conversation can resume
instead of prefilling from zero (`docs/AI.md` §2.6.1). On a unified-memory host
those checkpoints and the KV cache come out of the same memory, so the batch
engine sizes them together at load:

- It measures one checkpoint and one token of KV on the live context, and reads
  free memory from the backend's device list.
- Checkpoints get half of what is free past a reserve (a tenth of total memory,
  at least 2 GiB), split across slots, at most 32 per slot.
- If that leaves a slot fewer than its two most useful checkpoints (the last
  turn start and one token before the prompt's end), it gives up context until
  it does — never below a quarter of the requested context or 8K tokens — and
  logs `context A -> B tokens, so every slot can keep its checkpoints`.
- The load line `... checkpoints per slot of N bytes each (M bytes budgeted,
  shared with the KV cache)` is what it settled on.

`BATCH_PROMPT_CHECKPOINTS=<n>` caps checkpoints per slot (`0` turns them off
and gives the memory back to context). Fewer slots (`BATCH_MAX_SLOTS`) buy
more checkpoints each. Where the device list misreads a host,
`BATCH_CHECKPOINT_MEMORY=<bytes>` fixes the checkpoint budget and
`BATCH_UNIFIED_MEMORY=1` (or `0`) says whether it shares memory with the KV
cache. Load the other models first: free memory is read when
the batch engine starts, so a pipeline loaded afterwards eats into what the
checkpoints were promised.

---

## 6. Checklist before serving

- [ ] `--gpu-vram-gb` sized to one pipeline, not to the machine
- [ ] `MemoryMin` + negative `OOMScoreAdjust` on the node unit
- [ ] `MemoryHigh`/`MemoryMax` on the shell slice, sized to leftover headroom
- [ ] `mold` exported as a target-scoped env var; `jobs` capped
- [ ] No other memory-hungry service sharing the box (a second chain daemon,
      an IDE indexer, a container build)
- [ ] `free -g` after all models load shows real headroom, not just `available`
      inflated by page cache — mmap'd GGUF weights count as cache
